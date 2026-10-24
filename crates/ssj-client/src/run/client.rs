//! The client of a running session: the loop that passes bytes, acknowledges, and reconnects.

mod link;
mod pump;

use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, Instant};

use quinn::Endpoint;
use ssj_proto::compress::Compressor;
use ssj_proto::{ClientFrame, ExitStatus, Hello, ReplayBuffer, WindowSize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::{interval, sleep, timeout};

use super::wire::{FrameReader, Out, hello_name, write_frames};
use super::{Announce, FLUSH_TIMEOUT, Finished, INPUT_BUFFER, Io, Params, Reader};
use crate::echo::Echo;
use crate::netwatch::Cause;
use crate::status::dropped_notice;
use crate::tracker::Tracker;
use crate::vlog;

/// Pauses between attempts to reconnect, the last one repeats.
const BACKOFF: [Duration; 5] = [
    Duration::from_millis(250),
    Duration::from_millis(500),
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(3),
];
/// A new lookup of the server address happens before every attempt after this many failed ones.
const RESOLVE_EVERY: usize = 3;
const PING_EVERY: Duration = Duration::from_secs(1);
/// Output that is acknowledged at once. Less waits for a frame that goes out anyway.
const ACK_BYTES: u64 = 4096;
/// Input is compressed only while at least this many bytes wait for the server to take them.
const COMPRESS_BACKLOG: u64 = 256 * 1024;
/// Chunks shorter than this are not worth compressing.
const COMPRESS_MIN_CHUNK: usize = 1024;
/// How long a status waits for a sequence of the remote side to end before it cancels it.
const SEQUENCE_PATIENCE: Duration = Duration::from_secs(2);

/// The next cause from the watch, or never if there is none.
async fn next_cause(net: &mut Option<mpsc::UnboundedReceiver<Cause>>) -> Option<Cause> {
    match net {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
}

fn exit_code(status: ExitStatus) -> u8 {
    match status {
        ExitStatus::Code(code) => code,
        ExitStatus::Signal(signal) => 128u8.saturating_add(signal),
    }
}

/// One connection to the server with its reader and writer.
struct Link {
    /// The QUIC connection, if the link is one.
    quic: Option<quinn::Connection>,
    out: mpsc::UnboundedSender<ClientFrame>,
    writer: JoinHandle<()>,
    reader: FrameReader,
    last_heard: Instant,
    /// When the oldest ping that no pong has answered went out. Frames of the server that arrive
    /// meanwhile show that its direction works and say nothing about ours.
    ping_since: Option<Instant>,
    _guard: Option<Box<dyn Send + Sync>>,
}

impl Link {
    fn new(
        quic: Option<quinn::Connection>,
        out: Out,
        reader: Reader,
        guard: Option<Box<dyn Send + Sync>>,
    ) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        Self {
            quic,
            out: tx,
            writer: tokio::spawn(write_frames(out, rx)),
            reader: FrameReader::new(reader),
            last_heard: Instant::now(),
            ping_since: None,
            _guard: guard,
        }
    }

    fn send(&self, frame: ClientFrame) {
        let _ = self.out.send(frame);
    }

    /// Sends a ping and remembers when, until the pong comes.
    fn ping(&mut self) {
        self.ping_since.get_or_insert_with(Instant::now);
        self.send(ClientFrame::Ping);
    }

    /// Lets the writer deliver what is queued, then ends the link.
    async fn finish(self) {
        drop(self.out);
        let _ = timeout(FLUSH_TIMEOUT * 2, self.writer).await;
    }
}

/// Makes the program in the session draw its screen again, by changing the size of the terminal
/// for a moment: debug lines that were written over the screen are then gone.
async fn redraw(size: WindowSize, out: &mpsc::UnboundedSender<ClientFrame>) {
    let narrower =
        WindowSize::new(size.rows(), size.cols().saturating_sub(1).max(1)).filter(|n| *n != size);
    if let Some(narrower) = narrower {
        let _ = out.send(ClientFrame::Resize(narrower));
        sleep(Duration::from_millis(60)).await;
    }
    let _ = out.send(ClientFrame::Resize(size));
}

enum Attempt {
    Linked(Link),
    /// Try again at once on the same transport.
    Again,
    /// Try again later.
    Retry,
    /// The session cannot continue.
    Fatal(String),
}

enum Pumped {
    Done(Finished),
    Lost,
    /// A better connection opened while this one worked: go on over it, as after a reconnect.
    Switch(Link, usize),
}

/// QUIC being tried on a new network, within a time limit.
type Upgrade =
    Pin<Box<dyn Future<Output = Result<Result<Link, String>, tokio::time::error::Elapsed>> + Send>>;

/// A connection that is being opened.
type LinkFuture = Pin<Box<dyn Future<Output = Result<Link, String>> + Send>>;

struct Client {
    /// The UDP socket, made when the first UDP attempt needs it.
    endpoint: Option<Endpoint>,
    params: Params,
    /// The tier that is tried now.
    current: usize,
    /// A connection that opened by itself and is to carry the session, with its tier.
    prepared: Option<(Link, usize)>,
    /// The link that a switch leaves, held until the server has answered on the new one. With
    /// nobody attached for a moment the server would treat the shell as unattended and forget its
    /// output, and a transfer would lose what it wrote meanwhile.
    retiring: Option<Link>,
    /// Failed attempts on the current tier since the last success.
    failures: usize,
    /// Whether a connection was ever made, so that the order of the tiers is settled.
    linked_once: bool,
    /// What the last failed attempt said, for the status message.
    note: Option<String>,
    io: Io,
    input: ReplayBuffer,
    /// Since when input is typed that the server has not acknowledged.
    input_since: Option<Instant>,
    output_offset: u64,
    /// Output that the server has been told about.
    acked_output: u64,
    echo: Echo,
    compress: bool,
    compressor: Compressor,
    stdin_open: bool,
    chunk: Vec<u8>,
    size: WindowSize,
    /// Whether a `Start` may have reached the server already.
    started: bool,
    net: Option<mpsc::UnboundedReceiver<Cause>>,
    tracker: Tracker,
    /// The message that should be on the screen, and the one that is.
    status_wanted: Option<String>,
    status_shown: Option<String>,
    /// Since when the status waits for the end of a sequence of the remote side.
    status_blocked_since: Option<Instant>,
}

/// Runs one session until it ends, and returns how it ended.
pub async fn run_session(params: Params, io: Io) -> Result<Finished, String> {
    if params.tiers.is_empty() {
        return Err("no way to reach the server".to_owned());
    }
    let size = io.size;
    let echo = Echo::new(params.local_echo, size.cols());
    let compress = params.compress;
    let mut io = io;
    let net = Some(std::mem::replace(&mut io.net, mpsc::unbounded_channel().1));
    Client {
        endpoint: None,
        params,
        current: 0,
        prepared: None,
        retiring: None,
        failures: 0,
        linked_once: false,
        note: None,
        io,
        net,
        tracker: Tracker::new(),
        status_wanted: None,
        status_shown: None,
        status_blocked_since: None,
        input: ReplayBuffer::new(INPUT_BUFFER),
        input_since: None,
        output_offset: 0,
        acked_output: 0,
        echo,
        compress,
        compressor: Compressor::new(),
        stdin_open: true,
        chunk: vec![0u8; 16 * 1024],
        size,
        started: false,
    }
    .run()
    .await
}

impl Client {
    async fn run(mut self) -> Result<Finished, String> {
        let mut attempts = 0usize;
        loop {
            let hello = self.next_hello();
            if attempts > 0 && attempts.is_multiple_of(RESOLVE_EVERY) {
                self.refresh_address().await;
            }
            vlog!(
                2,
                "attempt {}: {} over {}",
                attempts + 1,
                hello_name(&hello),
                self.params.tiers[self.current].name()
            );
            let attempt = self.establish_watched(&hello).await;
            // the server has answered on the new link or the attempt failed: the old one can go.
            self.retiring = None;
            match attempt {
                Attempt::Fatal(message) => {
                    vlog!(1, "cannot continue: {message}");
                    self.clear_status_at_end().await;
                    return Err(message);
                }
                Attempt::Linked(mut link) => {
                    attempts = 0;
                    match self.carry(&mut link, &hello).await? {
                        Pumped::Done(finished) => {
                            vlog!(1, "session ended: {finished:?}");
                            link.finish().await;
                            self.clear_status_at_end().await;
                            return Ok(finished);
                        }
                        Pumped::Lost => vlog!(1, "connection lost, reconnecting"),
                        Pumped::Switch(better, tier) => {
                            vlog!(1, "switching to {}", self.params.tiers[tier].name());
                            self.prepared = Some((better, tier));
                            self.retiring = Some(link);
                            continue;
                        }
                    }
                }
                // the answer was fine and only the kind of hello was wrong: no pause, no other
                // tier.
                Attempt::Again => continue,
                Attempt::Retry => {
                    if self.try_next_tier() {
                        continue;
                    }
                }
            }
            attempts += 1;
            self.report_failure(attempts).await;
            let pause = BACKOFF[attempts.saturating_sub(1).min(BACKOFF.len() - 1)];
            if let Some(finished) = self.wait_offline(pause).await? {
                self.clear_status_at_end().await;
                return Ok(finished);
            }
        }
    }

    /// The hello for the next connection: a resume once the session runs, else a join or a start.
    fn next_hello(&self) -> Hello {
        if self.started {
            Hello::Resume {
                size: self.size,
                output_offset: self.output_offset,
            }
        } else if self.params.attach {
            Hello::Attach { size: self.size }
        } else {
            Hello::Start {
                size: self.size,
                env: self.params.env.clone(),
                agent: self.params.agent.is_some(),
            }
        }
    }

    /// Runs the session over a new link until the link ends.
    async fn carry(&mut self, link: &mut Link, hello: &Hello) -> Result<Pumped, String> {
        if !self.linked_once {
            self.announce(hello).await;
        }
        self.failures = 0;
        self.linked_once = true;
        self.started = true;
        vlog!(
            1,
            "session running over {}",
            self.params.tiers[self.current].name()
        );
        self.clear_status().await;
        let pumped = self.pump(link).await;
        // what was shown ahead of the server goes, whatever happens next.
        let taken_back = self.echo.cancel();
        let _ = self.io.output.write_all(&taken_back).await;
        let _ = self.io.output.flush().await;
        pumped
    }

    /// Writes the line that says the session began, if one is wanted.
    async fn announce(&mut self, hello: &Hello) {
        let Some(Announce {
            destination,
            name,
            started,
        }) = &self.params.announce
        else {
            return;
        };
        // without the message of the day of a login, nothing else says when the session begins.
        // The terminal is raw by now, hence the carriage return.
        let what = if *started || matches!(hello, Hello::Start { .. }) {
            "started session"
        } else {
            "attached to session"
        };
        let id = self.params.connect.id.as_str();
        let session = name
            .as_ref()
            .map_or_else(|| id.to_owned(), |name| format!("{name} ({id})"));
        let line = format!(
            "[{what} {session} on {destination} over {}]\r\n",
            self.params.tiers[self.current].name()
        );
        let _ = self.io.output.write_all(line.as_bytes()).await;
        let _ = self.io.output.flush().await;
    }

    /// Says that an attempt failed, in the debug output and in the status.
    async fn report_failure(&mut self, attempts: usize) {
        vlog!(
            1,
            "attempt {attempts} failed{}",
            self.note
                .as_ref()
                .map_or_else(String::new, |note| format!(": {note}"))
        );
        let text = match self.note.take() {
            Some(note) => format!("connection lost, reconnecting (attempt {attempts}, {note})"),
            None => format!("connection lost, reconnecting (attempt {attempts})"),
        };
        self.show_status(&text).await;
    }

    async fn show_status(&mut self, text: &str) {
        self.status_wanted = Some(text.to_owned());
        self.sync_status(false).await;
    }

    async fn clear_status(&mut self) {
        self.status_wanted = None;
        self.sync_status(false).await;
    }

    /// Ends the display for good, even inside a sequence: nothing more will arrive to finish it.
    async fn clear_status_at_end(&mut self) {
        self.status_wanted = None;
        self.sync_status(true).await;
    }

    /// Writes the status change that is waiting, unless that would split a sequence of the remote
    /// side or a character. It is retried after every piece of output.
    async fn sync_status(&mut self, force: bool) {
        if self.status_wanted == self.status_shown {
            self.status_blocked_since = None;
            return;
        }
        if !force && self.tracker.in_sequence() {
            self.status_blocked_since.get_or_insert_with(Instant::now);
            return;
        }
        self.status_blocked_since = None;
        let bytes = match &self.status_wanted {
            Some(text) => self.io.status.show(text),
            None => self.io.status.clear(self.tracker.title()),
        };
        let _ = self.io.output.write_all(&bytes).await;
        let _ = self.io.output.flush().await;
        self.status_shown = self.status_wanted.clone();
    }

    /// Lets a waiting status through when the remote side stopped in the middle of a sequence for
    /// good. The terminal is given a CAN, which ends the sequence in every terminal, and the rest
    /// of it is dropped when it arrives. A sequence that is merely slow is not touched.
    async fn unstick_status(&mut self) {
        let waited = self
            .status_blocked_since
            .is_some_and(|since| since.elapsed() >= SEQUENCE_PATIENCE);
        if waited && self.tracker.in_sequence() {
            let _ = self.io.output.write_all(b"\x18").await;
            let _ = self.io.output.flush().await;
            self.tracker.cancel_sequence();
            self.sync_status(false).await;
        }
    }

    /// Writes the notice for `dropped` forgotten bytes into the output.
    async fn note_gap(&mut self, dropped: u64) {
        let _ = self.io.output.write_all(&dropped_notice(dropped)).await;
        let _ = self.io.output.flush().await;
        // the rest of an open sequence is gone, so the tracker must not wait for it.
        self.tracker.abandon_sequence();
        self.sync_status(false).await;
    }

    /// Takes typed input into the buffer while there is no connection.
    ///
    /// Returns when the pause is over, or earlier if the user leaves with the escape.
    async fn wait_offline(&mut self, pause: Duration) -> Result<Option<Finished>, String> {
        let pause = sleep(pause);
        tokio::pin!(pause);
        let mut tick = interval(PING_EVERY);
        loop {
            let room = self.input.free().saturating_sub(1).min(self.chunk.len());
            tokio::select! {
                _ = &mut pause => return Ok(None),
                _ = tick.tick() => self.unstick_status().await,
                read = self.io.input.read(&mut self.chunk[..room]), if self.stdin_open && room > 0 => {
                    match read {
                        Ok(n) if n > 0 => {
                            let typed = self.chunk[..n].to_vec();
                            if let Some(finished) = self.handle_typed(&typed, None).await? {
                                return Ok(Some(finished));
                            }
                        }
                        _ => self.stdin_open = false,
                    }
                }
                Some(size) = self.io.resizes.recv() => self.size = size,
                Some(()) = self.io.hangups.recv() => {
                    vlog!(1, "told to end while the connection is down: the session keeps running");
                    return Ok(Some(Finished::HungUp));
                }
                cause = next_cause(&mut self.net) => match cause {
                    // the network is different now, so waiting longer makes no sense.
                    Some(_) => {
                        self.rebind();
                        return Ok(None);
                    }
                    None => self.net = None,
                },
            }
        }
    }

    /// The frame for typed bytes: compressed when the uplink is what holds the input back (a
    /// paste over a slow link), plain otherwise. Typing is a few bytes and never compressed.
    /// Tells the server how much output was shown: at once when it is a lot, or when `force` says
    /// that a frame goes out anyway, and otherwise not yet.
    ///
    /// An acknowledgement alone is a small packet that nobody answers. On the TCP transport the
    /// next small packet behind it, such as a keystroke, can wait for the acknowledgement timer of
    /// the other side, which runs for 40 to 100 ms (see `bench/wprobe.py`). Sent in the write of
    /// the keystroke, it costs nothing.
    fn ack_output(&mut self, out: &mpsc::UnboundedSender<ClientFrame>, force: bool) {
        let unacked = self.output_offset.saturating_sub(self.acked_output);
        if unacked > 0 && (force || unacked >= ACK_BYTES) {
            let _ = out.send(ClientFrame::OutputAck(self.output_offset));
            self.acked_output = self.output_offset;
        }
    }

    fn input_frame(&mut self, bytes: &[u8]) -> ClientFrame {
        let waiting = self.input.end() - self.input.start();
        if self.compress
            && waiting >= COMPRESS_BACKLOG
            && bytes.len() >= COMPRESS_MIN_CHUNK
            && let Some(packed) = self.compressor.compress(bytes)
        {
            vlog!(
                2,
                "compressed {} bytes of input to {}",
                bytes.len(),
                packed.len()
            );
            return ClientFrame::Compressed(packed);
        }
        ClientFrame::Input(bytes.to_vec())
    }

    /// Applies typed bytes: input for the shell, up to the detach key, which leaves the session.
    async fn handle_typed(
        &mut self,
        typed: &[u8],
        link: Option<&mpsc::UnboundedSender<ClientFrame>>,
    ) -> Result<Option<Finished>, String> {
        let key_at = self
            .params
            .detach_key
            .and_then(|key| typed.iter().position(|byte| *byte == key));
        let bytes = &typed[..key_at.unwrap_or(typed.len())];
        if !bytes.is_empty() {
            let stored = self.input.push(bytes);
            self.input_since.get_or_insert_with(Instant::now);
            if stored < bytes.len() {
                // the reads leave room for what is free, so this does not happen.
                return Err("the input buffer overflowed".to_owned());
            }
            if let Some(link) = link {
                // the acknowledgement of the output goes out in the same write.
                self.ack_output(link, true);
                let frame = self.input_frame(bytes);
                let _ = link.send(frame);
                // only with a connection: without one the echo cannot come.
                let drawn = self.echo.typed(bytes, Instant::now());
                if !drawn.is_empty() {
                    let _ = self.io.output.write_all(&drawn).await;
                    let _ = self.io.output.flush().await;
                }
            }
        }
        if key_at.is_none() {
            return Ok(None);
        }
        if let Some(link) = link {
            let _ = link.send(ClientFrame::Detach);
        }
        Ok(Some(Finished::Detached))
    }
}
