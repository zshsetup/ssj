//! The task that owns all state of a session: each turn it works out what to wait for, waits for
//! the first event, and hands it to the method for its kind.

use std::future::pending;
use std::io;
use std::process::ExitStatus;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use ssj_net::channels::{Channels, Piece};
use ssj_proto::compress::Compressor;
use ssj_proto::frame::MAX_DATA_LEN;
use ssj_proto::resume::{Action, ServerView, negotiate};
use ssj_proto::{Env, ErrorCode, Hello, ReplayBuffer, ServerFrame, Welcome, WindowSize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Semaphore, mpsc};
use tokio::time::{Instant, sleep, sleep_until};

use super::connection::start_connection;
use super::{
    Active, Connection, Control, READ_CHUNK, Running, Session, SessionCommand, SessionConfig,
    SessionEnd, SessionEvent, SlowClient, Tagged, dropped_notice, hang_up, listen_for_agent,
    spawn_shell, wire_exit,
};
use crate::backend::{Backend, Shell, ShellWriter};
use crate::control_socket::SocketFile;

/// Output is compressed only while at least this many bytes are not acknowledged by the client
/// (waiting or on the way), which means that the link is slower than the shell.
const COMPRESS_BACKLOG: u64 = 256 * 1024;
/// The most output that goes out unacknowledged over a stream, such as the channel of an `ssh`
/// session. `ssh` holds 2 MiB in a channel and stalls at that, and the output that waits in its
/// pipes and sockets delays the acknowledgements: 10 MB took 0.45 s with the whole replay buffer
/// in flight, and 0.2 s with 1 MiB.
const STREAM_INFLIGHT: u64 = 1024 * 1024;
/// Chunks shorter than this are not worth compressing.
const COMPRESS_MIN_CHUNK: usize = 1024;
/// How long an acknowledgement of input waits for output to go with it. It matters little when it
/// comes: it only lets the client forget what it keeps for a reconnect. A standalone one is a
/// small packet that nobody answers, which the next small packet can queue behind for 40 to
/// 100 ms on the TCP transport.
const ACK_DELAY: Duration = Duration::from_secs(1);
/// Input that is acknowledged at once.
const ACK_BYTES: u64 = 4096;

/// Container for the state of a running session.
pub(super) struct Actor<B: Backend> {
    backend: B,
    config: SessionConfig,
    events: Option<mpsc::UnboundedSender<SessionEvent>>,
    commands: Option<mpsc::UnboundedReceiver<SessionCommand>>,
    conns: mpsc::Receiver<Connection>,
    control_tx: mpsc::Sender<Tagged>,
    control_rx: mpsc::Receiver<Tagged>,
    output: ReplayBuffer,
    input_received: u64,
    /// Since when input has been consumed without an acknowledgement.
    ack_since: Option<Instant>,
    pending_input: PendingInput,
    shell: Option<Running<B::Shell>>,
    active: Option<Active>,
    /// The newest connection that has not said hello yet. It replaces the active one only when it
    /// does: a client that opens a second connection beside a working one (a spare) must not end
    /// the working one by connecting.
    incoming: Option<Active>,
    generation: u64,
    detached_since: Option<Instant>,
    /// The newest size of a burst of resizes, applied when no other message is queued.
    pending_resize: Option<WindowSize>,
    /// A deliberate detach changes the timeout until the next connection.
    detached_on_purpose: bool,
    /// Since when the connection is gone although the exit status was sent.
    exit_lost: Option<Instant>,
    /// Since when a connected client has left the output buffer full.
    full_since: Option<Instant>,
    buf: Vec<u8>,
    compressor: Compressor,
    /// The socket of the forwarded agent, once the client has asked for it.
    agent_listener: Option<(UnixListener, SocketFile)>,
    next_channel: u32,
    /// Whether a client ever completed its handshake.
    ever_connected: bool,
}

/// The chunk of input that is being written to the shell.
#[derive(Default)]
struct PendingInput {
    data: Vec<u8>,
    /// Bytes of `data` that the shell has taken.
    offset: usize,
    /// The budget of the connection that sent the chunk, which gets the bytes back.
    budget: Option<Arc<Semaphore>>,
}

impl PendingInput {
    fn done(&self) -> bool {
        self.offset >= self.data.len()
    }

    /// Drops the chunk and returns its bytes to the budget of the connection.
    fn release(&mut self) {
        if let Some(budget) = self.budget.take() {
            budget.add_permits(self.data.len());
        }
        self.data.clear();
        self.offset = 0;
    }
}

/// What one turn of the loop waits for.
struct Turn {
    /// Room for output of the shell.
    read_len: usize,
    /// Nobody makes the job wait, so the oldest output may be forgotten.
    away: bool,
    /// When a client that keeps the buffer full counts as away.
    away_deadline: Option<Instant>,
    /// A frame is ready for the connection.
    send_due: bool,
    /// When an acknowledgement of input stops waiting for output to go with it.
    ack_deadline: Option<Instant>,
    /// When the session ends for want of a client.
    deadline: Option<Instant>,
    /// When a finished session stops waiting for the client to confirm the exit status.
    grace_deadline: Option<Instant>,
}

enum Event {
    Connection(Option<Connection>),
    Control(Option<Tagged>),
    Input(Option<Vec<u8>>),
    ShellOutput(io::Result<usize>),
    InputWritten(io::Result<usize>),
    Exited(io::Result<ExitStatus>),
    CanSend(Result<mpsc::OwnedPermit<ServerFrame>, mpsc::error::SendError<()>>),
    DetachedTimeout,
    ExitGrace,
    AwayTimer,
    AckTimer,
    Command(Option<SessionCommand>),
    AgentConnected(io::Result<UnixStream>),
}

impl<B: Backend> Actor<B> {
    /// Takes over the parts of the session, and starts the shell if it starts before any client.
    pub(super) async fn start(
        session: Session<B>,
        conns: mpsc::Receiver<Connection>,
    ) -> Result<Self, SessionEnd> {
        let Session {
            backend,
            config,
            events,
            commands,
        } = session;
        let (control_tx, control_rx) = mpsc::channel(64);
        let mut actor = Self {
            backend,
            output: ReplayBuffer::new(config.replay_capacity),
            config,
            events,
            commands,
            conns,
            control_tx,
            control_rx,
            input_received: 0,
            ack_since: None,
            pending_input: PendingInput::default(),
            shell: None,
            active: None,
            incoming: None,
            generation: 0,
            detached_since: Some(Instant::now()),
            pending_resize: None,
            detached_on_purpose: false,
            exit_lost: None,
            full_since: None,
            buf: vec![0u8; READ_CHUNK],
            compressor: Compressor::new(),
            agent_listener: None,
            next_channel: 0,
            ever_connected: false,
        };
        if let Some(start) = actor.config.prestart.clone() {
            actor
                .start_shell(start.size, &start.env, start.agent)
                .await
                .map_err(SessionEnd::Failed)?;
        }
        Ok(actor)
    }

    pub(super) async fn run(mut self) -> SessionEnd {
        loop {
            let turn = self.turn();
            if self.control_rx.is_empty()
                && let Some(size) = self.pending_resize.take()
            {
                self.resize(size);
            }
            let event = self.next_event(&turn).await;
            if let Some(end) = self.handle(event, &turn).await {
                return end;
            }
        }
    }

    /// Works out what this turn waits for, after skipping the output that nobody waits for.
    fn turn(&mut self) -> Turn {
        let config = &self.config;
        // backpressure holds only while somebody is there to acknowledge the output. With nobody
        // there (no connection, or one that stays silent while the buffer is full) the job must
        // go on, so the oldest output is forgotten, as a `tmux` session does.
        if config.slow_client == SlowClient::Drop
            && let Some(a) = self.active.as_mut().filter(|a| a.hello_done)
        {
            a.gap += skip_ahead(
                &mut a.output_sent,
                a.replay_end,
                &self.output,
                config.live_backlog,
            );
        }
        let active = self.active.as_ref().filter(|a| a.hello_done);
        if active.is_some() && self.output.free() == 0 {
            self.full_since.get_or_insert_with(Instant::now);
        } else {
            self.full_since = None;
        }
        // with `Drop` the job never waits, so it always counts as away: the oldest output is
        // forgotten instead.
        let away = config.slow_client == SlowClient::Drop
            || active.is_none()
            || self
                .full_since
                .is_some_and(|t| t.elapsed() >= config.away_after);
        // a shell that was started for a client that has yet to come waits when the buffer is
        // full: the first `Start` joins it only if nothing was forgotten
        let away = away && !(self.config.prestart.is_some() && !self.ever_connected);
        let read_len = if away {
            self.buf.len()
        } else {
            self.output.free().min(self.buf.len())
        };
        let exit_due = match (self.shell.as_ref(), active) {
            (Some(s), Some(a)) => ready_for_exit(s, a, &self.output),
            _ => false,
        };
        let data_pending = active.is_some_and(|a| {
            a.pong_due
                || a.gap > 0
                || (a.output_sent < self.output.end() && room_to_send(a, &self.output, config))
                || exit_due
        });
        // an acknowledgement of input waits a moment for output to go with it: the echo of what
        // was typed follows within milliseconds, and two small packets in a row are held apart
        // by a hop with Nagle's algorithm until the other side's delayed ACK, which is 40 ms on
        // Linux.
        let ack_pending = active.is_some_and(|a| a.input_acked < self.input_received);
        let ack_deadline = ack_pending.then(|| {
            self.ack_since
                .map_or_else(Instant::now, |since| since + ACK_DELAY)
        });
        let ack_big = self
            .active
            .as_ref()
            .is_some_and(|a| self.input_received.saturating_sub(a.input_acked) >= ACK_BYTES);
        let ack_due = ack_pending
            && (data_pending || ack_big || ack_deadline.is_some_and(|d| d <= Instant::now()));
        Turn {
            read_len,
            away,
            away_deadline: self
                .full_since
                .filter(|_| !away)
                .map(|t| t + config.away_after),
            send_due: data_pending || ack_due,
            ack_deadline: ack_deadline.filter(|_| !ack_due),
            deadline: self.deadline(),
            grace_deadline: self
                .exit_lost
                .filter(|_| self.active.is_none())
                .map(|since| since + config.exit_grace),
        }
    }

    /// When the session ends without a client: a deliberate detach waits for `max_detached`, a
    /// lost connection for `detached_timeout`, and before the first client at most for
    /// `first_client_timeout`.
    fn deadline(&self) -> Option<Instant> {
        let since = self.detached_since.filter(|_| self.active.is_none())?;
        let config = &self.config;
        let limit = if self.detached_on_purpose {
            config.max_detached
        } else {
            config.detached_timeout
        };
        let first = config.first_client_timeout;
        let limit = if self.ever_connected {
            limit?
        } else {
            limit.map_or(first, |l| l.min(first))
        };
        Some(since + limit)
    }

    async fn next_event(&mut self, turn: &Turn) -> Event {
        let want_input = self.pending_input.done();
        let (reader, writer, exit) = match self.shell.as_mut() {
            Some(s) => (
                (!s.reader_eof && turn.read_len > 0).then_some(&mut s.reader),
                (!want_input).then_some(&mut s.writer),
                s.exit.as_mut(),
            ),
            None => (None, None, None),
        };
        let (input, out) = match self.active.as_mut() {
            Some(a) if a.hello_done => (
                want_input.then_some(&mut a.input),
                turn.send_due.then(|| a.out.clone()),
            ),
            _ => (None, None),
        };
        let buf = &mut self.buf[..turn.read_len];
        let typed = &self.pending_input.data[self.pending_input.offset..];
        let commands = self.commands.as_mut();
        let agent = self.agent_listener.as_ref();
        tokio::select! {
            conn = self.conns.recv() => Event::Connection(conn),
            command = async { match commands { Some(rx) => rx.recv().await, None => pending().await } } => Event::Command(command),
            tagged = self.control_rx.recv() => Event::Control(tagged),
            data = async { match input { Some(rx) => rx.recv().await, None => pending().await } } => Event::Input(data),
            n = async { match reader { Some(r) => r.read(buf).await, None => pending().await } } => Event::ShellOutput(n),
            n = async { match writer { Some(w) => w.write(typed).await, None => pending().await } } => Event::InputWritten(n),
            status = async { match exit { Some(e) => e.await, None => pending().await } } => Event::Exited(status),
            permit = async { match out { Some(tx) => tx.reserve_owned().await, None => pending().await } } => Event::CanSend(permit),
            () = wait_until(turn.deadline) => Event::DetachedTimeout,
            () = wait_until(turn.grace_deadline) => Event::ExitGrace,
            () = wait_until(turn.away_deadline) => Event::AwayTimer,
            () = wait_until(turn.ack_deadline) => Event::AckTimer,
            stream = async { match agent { Some((l, _)) => l.accept().await.map(|(s, _)| s), None => pending().await } } => Event::AgentConnected(stream),
        }
    }

    /// Acts on an event. Returns how the session ended, if it did.
    async fn handle(&mut self, event: Event, turn: &Turn) -> Option<SessionEnd> {
        match event {
            Event::Command(None) => self.commands = None,
            Event::Command(Some(command)) => return self.on_command(command).await,
            Event::Connection(None) => return Some(SessionEnd::Closed),
            Event::Connection(Some(conn)) => {
                self.generation += 1;
                self.incoming = Some(start_connection(
                    conn,
                    self.generation,
                    self.control_tx.clone(),
                    self.config.hello_timeout,
                    self.config.lost_after,
                ));
            }
            Event::DetachedTimeout => return Some(SessionEnd::DetachedTimeout),
            // the next turn of the loop sees that the client is away now.
            Event::AwayTimer | Event::AckTimer => {}
            Event::Control(None) => unreachable!("the actor holds a sender"),
            Event::Control(Some(tagged)) => return self.on_control(tagged).await,
            Event::AgentConnected(stream) => self.on_agent_connected(stream).await,
            Event::Input(None) => {}
            Event::Input(Some(data)) => {
                self.pending_input = PendingInput {
                    data,
                    offset: 0,
                    budget: self.active.as_ref().map(|a| a.budget.clone()),
                };
            }
            Event::InputWritten(written) => self.on_input_written(written),
            Event::ShellOutput(read) => self.on_shell_output(read, turn),
            Event::Exited(result) => {
                let s = self.shell.as_mut().expect("exit only while a shell exists");
                s.exit = None;
                match result {
                    Ok(status) => s.status = Some(status),
                    Err(err) => return Some(SessionEnd::Failed(err)),
                }
            }
            Event::ExitGrace => {
                // nobody came back for the status: the client has it or never will.
                let status = self.shell.as_ref().and_then(|s| s.status);
                let status = status.expect("the grace period starts after the status is known");
                return Some(SessionEnd::ShellExited(status));
            }
            Event::CanSend(Err(_)) => self.lose(),
            Event::CanSend(Ok(permit)) => {
                if let Some(frame) = self.next_frame() {
                    permit.send(frame);
                }
            }
        }
        None
    }

    async fn on_command(&mut self, command: SessionCommand) -> Option<SessionEnd> {
        match command {
            SessionCommand::Kill => {
                hang_up(self.shell.take(), self.active.as_ref()).await;
                return Some(SessionEnd::Killed);
            }
            SessionCommand::Detach => {
                if let Some(a) = self.active.take_if(|a| a.hello_done) {
                    let _ = a.out.try_send(ServerFrame::Detached);
                    // the transport closes the endpoint right after the event, and the frame
                    // needs a moment to leave first.
                    sleep(Duration::from_millis(300)).await;
                    drop(a);
                    self.detached();
                }
            }
        }
        None
    }

    /// Acts on a message of a connection. Messages of a connection that was replaced are ignored.
    async fn on_control(&mut self, tagged: Tagged) -> Option<SessionEnd> {
        let Tagged {
            generation,
            control,
        } = tagged;
        if self
            .incoming
            .as_ref()
            .is_some_and(|i| i.generation == generation)
        {
            if !matches!(control, Control::Hello(_)) {
                // it failed before its hello: the active connection is not touched.
                if let (Control::Violation(code), Some(i)) = (&control, &self.incoming) {
                    let _ = i.out.try_send(ServerFrame::Error(*code));
                }
                self.incoming = None;
                return None;
            }
            // the client is here: the connection before it is replaced.
            self.lose();
            self.announce_exit_again();
            self.active = self.incoming.take();
            self.detached_since = None;
            self.detached_on_purpose = false;
        }
        if self.active.as_ref().map(|a| a.generation) != Some(generation) {
            return None;
        }
        match control {
            Control::Hello(hello) => return self.on_hello(hello).await,
            Control::Resize(size) => self.pending_resize = Some(size),
            Control::OutputAck(offset) => {
                // output that this connection has not sent cannot be acknowledged, and dropping
                // it would leave the send position behind the buffer.
                let unsent = self.active.as_ref().is_some_and(|a| offset > a.output_sent);
                if unsent || self.output.ack(offset).is_err() {
                    self.violation(ErrorCode::Violation);
                }
            }
            Control::Close => return self.on_gone(true),
            Control::Lost => return self.on_gone(false),
            Control::Ping => {
                if let Some(a) = self.active.as_mut() {
                    a.pong_due = a.hello_done;
                }
            }
            Control::AgentOffer => {
                if let Some(a) = self.active.as_mut().filter(|a| a.hello_done)
                    && self.agent_listener.is_some()
                {
                    a.agent = Some(Channels::new());
                }
            }
            Control::Agent(id, data) => {
                if let Some(a) = self.active.as_mut()
                    && let Some(channels) = a.agent.as_mut()
                    && channels.is_open(id)
                    && !channels.send(id, data)
                {
                    tell_channel_closed(&a.out, id);
                }
            }
            Control::AgentClose(id) => {
                if let Some(channels) = self.active.as_mut().and_then(|a| a.agent.as_mut()) {
                    channels.close(id);
                }
            }
            Control::Hangup => {
                hang_up(self.shell.take(), None).await;
                return Some(SessionEnd::Killed);
            }
            Control::Detach => {
                self.active = None;
                self.detached();
            }
            Control::Violation(code) => self.violation(code),
        }
        None
    }

    /// Answers the hello of the client, and starts, resizes, or redraws the shell for it.
    async fn on_hello(&mut self, hello: Hello) -> Option<SessionEnd> {
        // the shell was started before any client came, so the first `Start` joins it: nothing
        // was consumed, and the size is applied.
        let joins = self.config.prestart.is_some()
            && !self.ever_connected
            && self.input_received == 0
            && self.output.start() == 0;
        let negotiated = match hello {
            Hello::Start { size, .. } if joins => Ok((
                Welcome {
                    input_offset: 0,
                    output_offset: 0,
                },
                Action::Resize(size),
            )),
            hello => {
                let view = ServerView {
                    shell_started: self.shell.is_some(),
                    output: &self.output,
                    input_received: self.input_received,
                };
                negotiate(hello, &view)
            }
        };
        let (welcome, action) = match negotiated {
            Ok(negotiated) => negotiated,
            Err(code) => {
                self.violation(code);
                return None;
            }
        };
        if let Err(err) = self.act(action).await {
            if let Some(a) = &self.active {
                let _ = a.out.try_send(ServerFrame::Error(ErrorCode::Internal));
            }
            return Some(SessionEnd::Failed(err));
        }
        // the size of the hello is newer than any waiting one.
        self.pending_resize = None;
        self.ever_connected = true;
        self.tell(SessionEvent::Connected);
        let a = self
            .active
            .as_mut()
            .expect("the hello came on the active connection");
        a.hello_done = true;
        a.output_sent = welcome.output_offset;
        a.replay_end = self.output.end();
        a.input_acked = welcome.input_offset;
        let _ = a.out.try_send(ServerFrame::Welcome(welcome));
        None
    }

    /// Does to the shell what the hello asks for.
    async fn act(&mut self, action: Action) -> io::Result<()> {
        match action {
            Action::Spawn { size, env, agent } => self.start_shell(size, &env, agent).await?,
            Action::Resize(size) => self.resize(size),
            Action::Redraw(size) => {
                // A program redraws when the size changes, so it is made to change and to change
                // back. The pause lets it see the first size before the second.
                let narrower = WindowSize::new(size.rows(), size.cols().saturating_sub(1).max(1))
                    .filter(|n| *n != size);
                if let Some(narrower) = narrower {
                    self.resize(narrower);
                    sleep(Duration::from_millis(60)).await;
                }
                self.resize(size);
            }
        }
        Ok(())
    }

    /// Starts the shell, and the socket for the agent of the client when it is asked for.
    async fn start_shell(&mut self, size: WindowSize, env: &Env, agent: bool) -> io::Result<()> {
        if agent && let Some(path) = &self.config.agent_socket {
            self.agent_listener = listen_for_agent(path);
        }
        let socket = self
            .agent_listener
            .as_ref()
            .and(self.config.agent_socket.as_deref());
        let (running, dropped) =
            spawn_shell(&self.backend, &self.config, size, env, socket).await?;
        self.shell = Some(running);
        // it comes before the output of the shell, which is not read yet.
        self.output.push_evicting(&dropped_notice(&dropped));
        Ok(())
    }

    fn resize(&self, size: WindowSize) {
        if let Some(s) = &self.shell {
            let _ = s.writer.resize(size);
        }
    }

    /// Lets the connection go after a close (`closed`) or a loss. A close after the exit status
    /// ends the session.
    fn on_gone(&mut self, closed: bool) -> Option<SessionEnd> {
        let finished = self.shell.as_ref().is_some_and(|s| s.exit_queued);
        self.lose();
        if finished && closed {
            let status = self.shell.as_ref().and_then(|s| s.status);
            let status = status.expect("exit is queued after the status is known");
            return Some(SessionEnd::ShellExited(status));
        }
        self.announce_exit_again();
        None
    }

    /// The status of the shell may not have arrived at the connection that is gone or replaced: it
    /// goes out again to the next connection, and a close confirms it.
    fn announce_exit_again(&mut self) {
        if let Some(s) = self.shell.as_mut().filter(|s| s.exit_queued) {
            s.exit_queued = false;
            self.exit_lost = Some(Instant::now());
        }
    }

    async fn on_agent_connected(&mut self, stream: io::Result<UnixStream>) {
        let Ok(stream) = stream else {
            // for example out of descriptors: do not spin on it.
            sleep(Duration::from_millis(100)).await;
            return;
        };
        // without a client that serves the agent, the program sees a closed socket.
        if let Some(a) = self.active.as_mut()
            && let Some(channels) = a.agent.as_mut()
        {
            self.next_channel = self.next_channel.wrapping_add(1);
            let out = a.out.clone();
            channels.open(self.next_channel, stream, move |id, piece| {
                let out = out.clone();
                async move {
                    let frame = match piece {
                        Piece::Open => ServerFrame::AgentOpen(id),
                        Piece::Data(data) => ServerFrame::Agent(id, data),
                        Piece::Closed => ServerFrame::AgentClose(id),
                    };
                    out.send(frame).await.is_ok()
                }
            });
        }
    }

    fn on_input_written(&mut self, written: io::Result<usize>) {
        match written {
            // the shell closed its input, so the output side will report the end.
            Err(_) => self.pending_input.release(),
            Ok(n) => {
                self.pending_input.offset += n;
                self.input_received += n as u64;
                self.ack_since.get_or_insert_with(Instant::now);
                if self.pending_input.done() {
                    self.pending_input.release();
                }
            }
        }
    }

    fn on_shell_output(&mut self, read: io::Result<usize>, turn: &Turn) {
        let s = self.shell.as_mut().expect("read only while a shell exists");
        let mut n = match read {
            Ok(0) | Err(_) => {
                s.reader_eof = true;
                return;
            }
            Ok(n) => n,
        };
        // A terminal hands out its data in small pieces (1 KiB on macOS), and a pass through the
        // loop for each would cap the throughput. So take what is ready now, without waiting, up
        // to the room that is left.
        while n < turn.read_len {
            match read_ready(&mut s.reader, &mut self.buf[n..turn.read_len]) {
                Some(Ok(more)) if more > 0 => n += more,
                Some(_) => {
                    s.reader_eof = true;
                    break;
                }
                None => break,
            }
        }
        let forgotten = self.output.push_evicting(&self.buf[..n]);
        debug_assert!(
            forgotten == 0 || turn.away,
            "output dropped under backpressure"
        );
        // a connection that was still owed the forgotten bytes cannot go on: its client resumes
        // on a new connection and learns what it missed.
        let owed = self
            .active
            .as_ref()
            .is_some_and(|a| a.hello_done && a.output_sent < self.output.start());
        // with `Drop` the connection goes on and is told about the gap.
        if forgotten > 0 && owed && self.config.slow_client == SlowClient::Wait {
            self.lose();
        }
    }

    /// The frame that goes out next: a pong, an acknowledgement, a gap, output, or the exit
    /// status, in this order.
    fn next_frame(&mut self) -> Option<ServerFrame> {
        let a = self.active.as_mut()?;
        let frame = if a.pong_due {
            a.pong_due = false;
            ServerFrame::Pong
        } else if a.input_acked < self.input_received {
            a.input_acked = self.input_received;
            self.ack_since = None;
            ServerFrame::InputAck(self.input_received)
        } else if a.gap > 0 {
            ServerFrame::Gap(std::mem::take(&mut a.gap))
        } else if a.output_sent < self.output.end() && room_to_send(a, &self.output, &self.config) {
            let chunk = self
                .output
                .read_from(a.output_sent, MAX_DATA_LEN)
                .expect("sent offset lies inside the buffer");
            // how much the client has not taken yet: what waits to be sent and what was sent and
            // is not acknowledged. Compressing costs time, and it only pays when the link is what
            // holds the output back. A link that keeps up has little of this, because the
            // acknowledgements come back at once.
            let waiting = self.output.end() - self.output.start();
            a.output_sent += chunk.len() as u64;
            let packed = (self.config.compress
                && waiting >= COMPRESS_BACKLOG
                && chunk.len() >= COMPRESS_MIN_CHUNK)
                .then(|| self.compressor.compress(&chunk))
                .flatten();
            match packed {
                Some(packed) => ServerFrame::Compressed(packed),
                None => ServerFrame::Output(chunk),
            }
        } else {
            let s = self
                .shell
                .as_mut()
                .filter(|s| ready_for_exit(s, a, &self.output))?;
            s.exit_queued = true;
            ServerFrame::Exit(wire_exit(s.status.expect("ready implies a status")))
        };
        Some(frame)
    }

    /// Ends the connection, reports it if the client had completed its handshake, and starts the
    /// wait for the client to come back.
    fn lose(&mut self) {
        if self.active.take().is_some_and(|a| a.hello_done) {
            self.tell(SessionEvent::Disconnected);
        }
        self.detached_since = Some(Instant::now());
    }

    /// Tells the client what it did wrong, and ends the connection.
    fn violation(&mut self, code: ErrorCode) {
        if let Some(a) = &self.active {
            let _ = a.out.try_send(ServerFrame::Error(code));
        }
        self.lose();
    }

    /// Notes that the client left on purpose, after the connection was dropped.
    fn detached(&mut self) {
        self.detached_since = Some(Instant::now());
        self.detached_on_purpose = true;
        self.tell(SessionEvent::Detached);
    }

    fn tell(&self, event: SessionEvent) {
        if let Some(events) = &self.events {
            let _ = events.send(event);
        }
    }
}

/// Sleeps until `deadline`, or for ever without one.
async fn wait_until(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => sleep_until(deadline).await,
        None => pending().await,
    }
}

/// Moves the send position of a connection forward when too much output waits for it, or when
/// the buffer has forgotten what it was to send. Returns the number of bytes skipped.
///
/// Output from before `replay_end` is not counted as waiting: a client that joins gets the replay
/// at the speed of its link, and only what the shell writes afterwards is limited to `live` bytes.
/// Whether more output may go out: the transport can carry about twice its congestion window
/// without an acknowledgement (the room for what is lost and reordered), and `live_backlog` at
/// least, so Ctrl-C does not wait behind more than that. A stream has no window and gets
/// `STREAM_INFLIGHT`.
fn room_to_send(a: &Active, output: &ReplayBuffer, config: &SessionConfig) -> bool {
    let window = a
        .window
        .as_ref()
        .map_or(STREAM_INFLIGHT, |w| 2 * w.load(Ordering::Relaxed));
    let allowed = window.max(config.live_backlog as u64);
    a.output_sent.saturating_sub(output.start()) < allowed
}

fn skip_ahead(sent: &mut u64, replay_end: u64, output: &ReplayBuffer, live: usize) -> u64 {
    let end = output.end();
    let mut target = (*sent).max(output.start());
    let waiting = end - target.max(replay_end).min(end);
    if waiting > live as u64 {
        target = end - live as u64;
    }
    if target > *sent {
        // do not start inside a character of several bytes.
        let head = output.read_from(target, 3).unwrap_or_default();
        target += head.iter().take_while(|b| **b & 0xc0 == 0x80).count() as u64;
        let skipped = target - *sent;
        *sent = target;
        return skipped;
    }
    0
}

/// Reads what is ready now, or returns `None` when nothing is, without waiting.
fn read_ready<R: AsyncRead + Unpin>(reader: &mut R, buf: &mut [u8]) -> Option<io::Result<usize>> {
    use std::task::{Context, Poll, Waker};
    let mut read_buf = tokio::io::ReadBuf::new(buf);
    // the waker is not needed: the select loop polls the reader again with its own.
    let mut cx = Context::from_waker(Waker::noop());
    match std::pin::Pin::new(reader).poll_read(&mut cx, &mut read_buf) {
        Poll::Ready(Ok(())) => Some(Ok(read_buf.filled().len())),
        Poll::Ready(Err(err)) => Some(Err(err)),
        Poll::Pending => None,
    }
}

/// The shell is gone, all its output is read and queued, and the exit was not announced yet.
fn ready_for_exit<S: Shell>(shell: &Running<S>, active: &Active, output: &ReplayBuffer) -> bool {
    shell.status.is_some()
        && shell.reader_eof
        && !shell.exit_queued
        && active.output_sent == output.end()
}

/// Tells the client that channel `id` is closed, without waiting for room in the queue.
fn tell_channel_closed(out: &mpsc::Sender<ServerFrame>, id: u32) {
    let out = out.clone();
    tokio::spawn(async move {
        let _ = out.send(ServerFrame::AgentClose(id)).await;
    });
}
