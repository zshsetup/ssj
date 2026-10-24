//! The loop of a working connection: bytes between the terminal and the server, the reactions to
//! a changed network, and the watch over a silent stream.

use std::io;
use std::time::{Duration, Instant};

use ssj_proto::compress::inflate;
use ssj_proto::{ClientFrame, ServerFrame, WindowSize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::{JoinError, JoinSet};
use tokio::time::error::Elapsed;
use tokio::time::{interval, sleep_until, timeout};

use super::{Client, Link, Pumped, Upgrade, exit_code, next_cause, redraw};
use crate::agent::Forward;
use crate::debounce::Debounce;
use crate::netwatch::Cause;
use crate::run::Finished;
use crate::run::wire::server_frame_name;
use crate::vlog;

/// How long after the last debug line on the terminal the screen is drawn again.
const REDRAW_AFTER_LOG: Duration = Duration::from_millis(400);
/// Time QUIC gets to open on a new network while the session runs over a stream transport.
const UPGRADE_TIMEOUT: Duration = Duration::from_millis(1500);
/// A resize is sent when no newer one has come for this long.
const RESIZE_QUIET: Duration = Duration::from_millis(50);
const PING_EVERY: Duration = Duration::from_secs(1);
/// Most output that is written to the terminal in one go.
const OUTPUT_BATCH: usize = 256 * 1024;
/// The client says that the server is silent after four round trips, but not sooner than this
/// and not later than the maximum, so that a good link reports a stall quickly and a slow link
/// does not report one all the time.
const STALL_MIN: Duration = Duration::from_secs(2);
const STALL_MAX: Duration = Duration::from_secs(10);
/// A stream that has heard nothing for this long gets a spare: a second connection is opened
/// beside it, and the session moves to whichever works. Giving the stream up only after
/// [`crate::run::STREAM_DEAD_AFTER`] would leave a flaky link (a train) without a session for
/// that long, and the stream itself may be in the long backoff of TCP when the network is back.
const SPARE_AFTER: Duration = Duration::from_secs(3);
/// Time a spare gets to open. A connection that was started on a dead path has lost its first
/// packets and retries them after 1 and 3 seconds, and then needs the login: it opens about 6
/// seconds after it was started, so a shorter time would end the spares that are about to work.
/// The fresh ones that come every second find a returning network sooner.
const SPARE_TIMEOUT: Duration = Duration::from_secs(10);
/// Spares that open at the same time. A connection started on a dead path loses its first packets
/// and may not open for seconds, so a new one starts every second while the stream lags, and the
/// first to open wins (the same idea as asking two servers and taking the faster answer).
const SPARES_AT_ONCE: usize = 6;
/// Pause after a spare that failed outright, so that a broken login does not become a loop.
const SPARE_PAUSE: Duration = Duration::from_secs(2);
/// A change of network produces many notifications. One reaction follows when they stop.
const CHANGE_QUIET: Duration = Duration::from_millis(300);
/// Time the server gets to answer after the client moved to a new network path, before the client
/// starts a new connection. A wake from sleep leaves less hope for the old path.
const PROBE_AFTER_CHANGE: Duration = Duration::from_secs(1);
const PROBE_AFTER_WAKE: Duration = Duration::from_secs(1);

/// A spare connection as it ends: opened, failed, or out of time.
type Spare = Result<Result<Link, String>, Elapsed>;

/// Container for what one run of [`Client::pump`] keeps between its events.
struct Pump {
    stalled: bool,
    /// A change of the network that is waiting for the notifications to stop.
    change: Option<(Cause, tokio::time::Instant)>,
    /// When the server has to have answered after the client moved to a new path.
    probe: Option<tokio::time::Instant>,
    /// When the probe went out, and how many notices the change brought, for the debug output.
    probed_at: Option<Instant>,
    notices: usize,
    resizes: Debounce,
    /// QUIC tried again on a new network while the session runs over a stream.
    upgrade: Option<Upgrade>,
    /// Second connections over the same stream transport, opened while the stream is silent.
    spares: JoinSet<Spare>,
    spare_not_before: Instant,
    /// When to make the program draw again, after debug lines were written over the screen.
    redraw_at: Option<tokio::time::Instant>,
    /// The channels to the agent, which live as long as the link.
    agent: Option<Forward>,
}

impl Client {
    /// Passes bytes between the terminal and the server until the session ends or the link breaks.
    pub(super) async fn pump(&mut self, link: &mut Link) -> Result<Pumped, String> {
        let mut ping = interval(PING_EVERY);
        let mut pump = Pump {
            stalled: false,
            change: None,
            probe: None,
            probed_at: None,
            notices: 0,
            resizes: Debounce::new(RESIZE_QUIET),
            upgrade: None,
            spares: JoinSet::new(),
            spare_not_before: Instant::now(),
            redraw_at: None,
            agent: self
                .params
                .agent
                .clone()
                .map(|socket| Forward::new(socket, link.out.clone())),
        };
        loop {
            let room = self.input.free().min(self.chunk.len());
            if crate::log::take_terminal_lines() {
                pump.redraw_at = Some(tokio::time::Instant::now() + REDRAW_AFTER_LOG);
            }
            let echo_due = self.echo.due().map(tokio::time::Instant::from_std);
            let resize_due = pump.resizes.due();
            let change_at = pump.change.map(|(_, at)| at);
            let (probe, redraw_at) = (pump.probe, pump.redraw_at);
            let relay_ready = self.params.relay_ready.clone();
            let done = tokio::select! {
                read = self.io.input.read(&mut self.chunk[..room]), if self.stdin_open && room > 0 => {
                    self.on_typed(read, link).await?
                }
                frame = link.reader.next() => self.on_frame(frame?, link, &mut pump).await?,
                Some(()) = self.io.hangups.recv() => Some(self.on_hangup(link)),
                Some(size) = self.io.resizes.recv() => {
                    self.on_resize(size, &mut pump);
                    None
                }
                () = sleep_until(echo_due.unwrap_or_else(far)), if echo_due.is_some() => {
                    self.expire_echo().await;
                    None
                }
                () = sleep_until(resize_due.unwrap_or_else(far)), if resize_due.is_some() => {
                    if let Some(size) = pump.resizes.take(tokio::time::Instant::now()) {
                        link.send(ClientFrame::Resize(size));
                    }
                    None
                }
                cause = next_cause(&mut self.net) => {
                    self.on_cause(cause, &mut pump);
                    None
                }
                () = sleep_until(change_at.unwrap_or_else(far)), if change_at.is_some() => {
                    self.on_network_settled(link, &mut pump);
                    None
                }
                () = sleep_until(probe.unwrap_or_else(far)), if probe.is_some() => {
                    // the new path did not bring an answer, so the old connection is not worth
                    // keeping.
                    vlog!(1, "no answer after the network change: giving up the connection and reconnecting");
                    Some(Pumped::Lost)
                }
                result = async { pump.upgrade.as_mut().expect("guarded").await }, if pump.upgrade.is_some() => {
                    self.on_upgrade(result, &mut pump)
                }
                () = async { relay_ready.as_ref().expect("guarded").notified().await }, if relay_ready.is_some() && self.current != 0 => {
                    self.on_relay_ready(&mut pump);
                    None
                }
                Some(joined) = pump.spares.join_next(), if !pump.spares.is_empty() => {
                    self.on_spare(joined, link, &mut pump)
                }
                () = sleep_until(redraw_at.unwrap_or_else(far)), if redraw_at.is_some() => {
                    pump.redraw_at = None;
                    redraw(self.size, &link.out).await;
                    None
                }
                _ = ping.tick() => self.on_tick(link, &mut pump).await,
            };
            if let Some(done) = done {
                return Ok(done);
            }
        }
    }

    /// Takes what was read from the terminal.
    async fn on_typed(
        &mut self,
        read: io::Result<usize>,
        link: &mut Link,
    ) -> Result<Option<Pumped>, String> {
        match read {
            Ok(n) if n > 0 => {
                let typed = self.chunk[..n].to_vec();
                Ok(self
                    .handle_typed(&typed, Some(&link.out))
                    .await?
                    .map(Pumped::Done))
            }
            // end of input: the shell keeps running, like with `ssh`.
            _ => {
                self.stdin_open = false;
                Ok(None)
            }
        }
    }

    /// Acts on a frame of the server, or on the end of its stream (`None`).
    async fn on_frame(
        &mut self,
        frame: Option<ServerFrame>,
        link: &mut Link,
        pump: &mut Pump,
    ) -> Result<Option<Pumped>, String> {
        let Some(frame) = frame else {
            vlog!(1, "the server closed the connection");
            return Ok(Some(Pumped::Lost));
        };
        link.last_heard = Instant::now();
        if pump.probe.take().is_some()
            && let Some(sent) = pump.probed_at.take()
        {
            vlog!(
                1,
                "the server answered on the new network after {:?}: the connection stays",
                sent.elapsed()
            );
        }
        if std::mem::take(&mut pump.stalled) {
            self.clear_status().await;
        }
        vlog!(3, "<- {}", server_frame_name(&frame));
        // compressed output is the same as plain output once it is inflated.
        let frame = match frame {
            ServerFrame::Compressed(packed) => ServerFrame::Output(
                inflate(&packed)
                    .map_err(|e| format!("the server sent bad compressed output: {e:?}"))?,
            ),
            other => other,
        };
        match frame {
            ServerFrame::Output(data) => self.show_output(data, link).await?,
            ServerFrame::InputAck(offset) => {
                self.input
                    .ack(offset)
                    .map_err(|_| "the server acknowledged input that was never sent".to_owned())?;
                self.input_since = (self.input.end() > self.input.start()).then(Instant::now);
            }
            ServerFrame::Pong => link.ping_since = None,
            ServerFrame::AgentOpen(id) => match pump.agent.as_mut() {
                Some(agent) => agent.open(id).await,
                // nothing was offered, so a server that opens a channel is wrong.
                None => link.send(ClientFrame::AgentClose(id)),
            },
            ServerFrame::Agent(id, data) => {
                if let Some(agent) = pump.agent.as_mut() {
                    agent.data(id, &data);
                }
            }
            ServerFrame::AgentClose(id) => {
                if let Some(agent) = pump.agent.as_mut() {
                    agent.close(id);
                }
            }
            ServerFrame::Gap(skipped) => self.on_gap(skipped, link).await?,
            ServerFrame::Detached => {
                vlog!(1, "`ssj detach` was run for this session: leaving it");
                return Ok(Some(Pumped::Done(Finished::Detached)));
            }
            ServerFrame::Exit(status) => {
                link.send(ClientFrame::Close);
                return Ok(Some(Pumped::Done(Finished::Exited(exit_code(status)))));
            }
            ServerFrame::Error(code) => {
                return Err(format!("the server ended the session: {code:?}"));
            }
            ServerFrame::Welcome(_) => return Err("the server sent a second welcome".to_owned()),
            // turned into output above.
            ServerFrame::Compressed(_) => unreachable!("inflated above"),
        }
        Ok(None)
    }

    /// Writes output to the terminal, with the frames that are waiting behind it.
    async fn show_output(&mut self, mut data: Vec<u8>, link: &mut Link) -> Result<(), String> {
        // frames that are here already go to the terminal in one write. A terminal hands out its
        // output in small pieces, and one write (a trip through the blocking pool) for each would
        // cap the throughput.
        while data.len() < OUTPUT_BATCH && link.reader.take_ready_output(&mut data) {}
        // the rest of a sequence that was cancelled on the terminal is dropped.
        let skipped = self.tracker.skip_prefix(&data);
        let shown = &data[skipped..];
        let (before, after) = self.echo.output(shown, Instant::now());
        let written = async {
            self.io.output.write_all(&before).await?;
            self.io.output.write_all(shown).await?;
            self.io.output.write_all(&after).await?;
            self.io.output.flush().await
        };
        if written.await.is_err() {
            return Err("cannot write to the terminal".to_owned());
        }
        self.tracker.feed(shown);
        // a status that was held back because of a sequence can go out now.
        self.sync_status(false).await;
        self.output_offset += data.len() as u64;
        if !link.reader.frame_ready() {
            self.ack_output(&link.out, false);
        }
        Ok(())
    }

    /// Takes the output that the server skipped because this client was too slow to take it.
    async fn on_gap(&mut self, skipped: u64, link: &mut Link) -> Result<(), String> {
        // what was shown ahead of the server goes first, then the notice.
        vlog!(
            1,
            "the server skipped {skipped} bytes of output (slow link)"
        );
        let taken_back = self.echo.cancel();
        let _ = self.io.output.write_all(&taken_back).await;
        self.output_offset = self
            .output_offset
            .checked_add(skipped)
            .ok_or("the server skipped more output than there can be")?;
        self.note_gap(skipped).await;
        self.ack_output(&link.out, true);
        Ok(())
    }

    /// Leaves or ends the session after the terminal was closed or `ssj` was told to end.
    fn on_hangup(&mut self, link: &Link) -> Pumped {
        if self.params.hangup_detaches {
            // the connection of an `ssh` session ended, which is a loss and not a wish.
            vlog!(
                1,
                "the terminal was closed inside an ssh session: leaving the session running"
            );
            link.send(ClientFrame::Detach);
            return Pumped::Done(Finished::Detached);
        }
        vlog!(
            1,
            "the terminal was closed or ssj was told to end: ending the session"
        );
        link.send(ClientFrame::Hangup);
        Pumped::Done(Finished::HungUp)
    }

    fn on_resize(&mut self, size: WindowSize, pump: &mut Pump) {
        vlog!(2, "the terminal is now {}x{}", size.cols(), size.rows());
        self.size = size;
        self.echo.resize(size.cols());
        pump.resizes.push(size, tokio::time::Instant::now());
    }

    /// Takes back what was shown ahead of the server and never echoed, as with a password prompt.
    async fn expire_echo(&mut self) {
        let taken_back = self.echo.expire(Instant::now());
        let _ = self.io.output.write_all(&taken_back).await;
        let _ = self.io.output.flush().await;
    }

    /// Notes a sign of a changed network. The reaction waits until the signs stop.
    fn on_cause(&mut self, cause: Option<Cause>, pump: &mut Pump) {
        let Some(cause) = cause else {
            self.net = None;
            return;
        };
        pump.notices += 1;
        vlog!(2, "network change notice {}: {cause:?}", pump.notices);
        let strongest = pump.change.map_or(cause, |(old, _)| old.max(cause));
        pump.change = Some((strongest, tokio::time::Instant::now() + CHANGE_QUIET));
    }

    /// Moves to the new network once its signs stopped, and asks the server whether it hears us.
    fn on_network_settled(&mut self, link: &mut Link, pump: &mut Pump) {
        let (cause, _) = pump.change.take().expect("guarded");
        let transport = self.params.tiers[self.current].name();
        vlog!(
            1,
            "network change ({cause:?}, {} notices): {}",
            pump.notices,
            if link.quic.is_some() {
                "moving the UDP socket and probing the server".to_owned()
            } else {
                format!("the {transport} stream has no socket to move, probing the server")
            }
        );
        pump.notices = 0;
        self.rebind();
        // a faster network may have appeared: QUIC is tried on it while the stream works.
        if self.current != 0 && pump.upgrade.is_none() && self.params.tiers[0].is_quic() {
            vlog!(1, "trying QUIC on the new network");
            let attempt = self.prepare_link(0);
            pump.upgrade = Some(Box::pin(timeout(UPGRADE_TIMEOUT, attempt)));
        }
        link.ping();
        pump.probed_at = Some(Instant::now());
        let wait = if cause == Cause::Woke {
            PROBE_AFTER_WAKE
        } else {
            PROBE_AFTER_CHANGE
        };
        pump.probe = Some(tokio::time::Instant::now() + wait);
    }

    /// Tries QUIC through the relay, which came up after the session began on a stream.
    fn on_relay_ready(&mut self, pump: &mut Pump) {
        if pump.upgrade.is_none() && self.params.tiers[0].is_quic() {
            vlog!(1, "the relay is up: trying QUIC through it");
            let attempt = self.prepare_link(0);
            pump.upgrade = Some(Box::pin(timeout(UPGRADE_TIMEOUT, attempt)));
        }
    }

    /// Moves to QUIC if it opened on the new network.
    fn on_upgrade(&mut self, result: Spare, pump: &mut Pump) -> Option<Pumped> {
        pump.upgrade = None;
        match result {
            Ok(Ok(better)) => {
                vlog!(1, "QUIC works: moving the session to it");
                return Some(Pumped::Switch(better, 0));
            }
            Ok(Err(error)) => vlog!(1, "QUIC does not work on the new network: {error}"),
            Err(_) => vlog!(
                1,
                "QUIC has no answer on the new network: staying on {}",
                self.params.tiers[self.current].name()
            ),
        }
        None
    }

    /// Moves to a spare connection that opened, unless the stream answers again.
    fn on_spare(
        &mut self,
        joined: Result<Spare, JoinError>,
        link: &Link,
        pump: &mut Pump,
    ) -> Option<Pumped> {
        match joined {
            Ok(Ok(Ok(better))) => {
                // the stream may have come back while the spare was opening, and then it is the
                // better one: nothing is in flight on it that a move would have to repeat.
                if self.lag(link) < SPARE_AFTER / 2 {
                    vlog!(
                        1,
                        "a spare connection is open, but the stream answers again: keeping the stream"
                    );
                    pump.spares.abort_all();
                } else {
                    vlog!(1, "a spare connection is open: moving to it");
                    return Some(Pumped::Switch(better, self.current));
                }
            }
            Ok(Ok(Err(error))) => {
                vlog!(1, "a spare connection failed: {error}");
                pump.spare_not_before = Instant::now() + SPARE_PAUSE;
            }
            Ok(Err(_)) => vlog!(1, "a spare connection did not open in time"),
            Err(_) => {}
        }
        None
    }

    /// Pings in quiet times, watches a silent stream, and tells the user about a silent server.
    async fn on_tick(&mut self, link: &mut Link, pump: &mut Pump) -> Option<Pumped> {
        // a frame that arrived a moment ago shows that the connection works, so a ping is for the
        // quiet times. It also takes the acknowledgement of the output with it, so that none goes
        // out alone.
        if link.last_heard.elapsed() >= PING_EVERY / 2 {
            self.ack_output(&link.out, true);
            link.ping();
        }
        self.unstick_status().await;
        if link.quic.is_none()
            && let Some(done) = self.watch_stream(link, pump)
        {
            return Some(done);
        }
        let silent = link.last_heard.elapsed();
        let stall_after = link.quic.as_ref().map_or(STALL_MIN, |conn| {
            (conn.rtt() * 4).clamp(STALL_MIN, STALL_MAX)
        });
        if silent > stall_after {
            pump.stalled = true;
            // the number changes in steps of five seconds, so the title does not flicker.
            let text = if silent < Duration::from_secs(10) {
                "no response from the server".to_owned()
            } else {
                format!(
                    "no response from the server for {}s",
                    silent.as_secs() / 5 * 5
                )
            };
            self.show_status(&text).await;
        }
        None
    }

    /// Gives up a stream that stays silent, and opens spares beside one that lags.
    ///
    /// QUIC finds a returning network by itself and survives long outages. A stream has no way to
    /// notice that its path is gone, and the `ssh` behind it would hang, so a long silence ends it
    /// and a new one is made.
    fn watch_stream(&mut self, link: &Link, pump: &mut Pump) -> Option<Pumped> {
        // the server may be heard while it hears nothing: a ping or typed input without an
        // answer is as bad as silence.
        let lag = self.lag(link);
        // not while a spare is opening, which would lose its progress, but not for ever: a
        // transport that never opens has to give way to the next one.
        let patience = if pump.spares.is_empty() {
            self.params.stream_dead_after
        } else {
            self.params.stream_dead_after * 3
        };
        if lag > patience {
            vlog!(1, "no answer for {lag:?} on a stream: giving it up");
            return Some(Pumped::Lost);
        }
        if lag > SPARE_AFTER
            && pump.spares.len() < SPARES_AT_ONCE
            && pump.upgrade.is_none()
            && Instant::now() >= pump.spare_not_before
        {
            vlog!(
                1,
                "no answer for {lag:?} on a stream: opening a spare connection ({} open)",
                pump.spares.len()
            );
            let attempt = self.prepare_link(self.current);
            pump.spares.spawn(timeout(SPARE_TIMEOUT, attempt));
        } else if lag < SPARE_AFTER / 2 && !pump.spares.is_empty() {
            vlog!(
                1,
                "the stream answers again: dropping the spare connections"
            );
            pump.spares.abort_all();
            while pump.spares.try_join_next().is_some() {}
        }
        None
    }
}

/// A deadline for a timer whose branch is switched off, so that it never fires.
fn far() -> tokio::time::Instant {
    tokio::time::Instant::now() + Duration::from_secs(86_400)
}
