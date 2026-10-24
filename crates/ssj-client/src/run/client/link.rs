//! How the client gets a connection: the tiers in order, the race of two, and the welcome.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use quinn::Endpoint;
use ssj_net::relay::{EnvelopeSocket, RelayKeys};
use ssj_net::{SERVER_NAME, client_tls, quic_client};
use ssj_proto::bootstrap::sanitize;
use ssj_proto::frame::MAX_DATA_LEN;
use ssj_proto::resume::check_welcome;
use ssj_proto::{ClientFrame, ErrorCode, Hello, ReplayBuffer, ServerFrame, Welcome};
use tokio::io::AsyncWriteExt;
use tokio::time::{sleep, timeout};

use super::{Attempt, Client, Link, LinkFuture, next_cause};
use crate::run::wire::{Out, hello_name};
use crate::run::{INPUT_BUFFER, Tier};
use crate::vlog;

/// Head start of QUIC over the stream transport when both are tried. A QUIC handshake needs one
/// round trip, so a transport that has not answered by then is likely blocked.
const RACE_STAGGER: Duration = Duration::from_millis(300);
/// Failed attempts on a tier that worked before, until the next tier is tried.
const TIER_PATIENCE: usize = 3;
/// Longest note about a failed attempt in the status message.
const NOTE_CHARS: usize = 60;
/// Time a lookup may take before the old address is kept.
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(2);

/// The first answer of the server on a new connection.
type Reply = Result<Option<ServerFrame>, String>;

/// The address that binds a UDP socket of the same family as `peer`.
fn wildcard(peer: &SocketAddr) -> SocketAddr {
    if peer.is_ipv4() {
        SocketAddr::from(([0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0u16; 8], 0))
    }
}

impl Client {
    /// Moves the UDP socket to the current network. QUIC then probes the new path at once, and
    /// the server follows the new address.
    pub(super) fn rebind(&mut self) {
        let Some(endpoint) = &self.endpoint else {
            return;
        };
        let Some((addr, keys)) = self.params.tiers.iter().find_map(|t| match t {
            Tier::Udp { addr, .. } => Some((*addr, None)),
            Tier::Relay { addr, keys } => Some((*addr, Some(keys.clone()))),
            Tier::Stream { .. } => None,
        }) else {
            return;
        };
        if let Some(keys) = keys {
            let moved = EnvelopeSocket::bind(wildcard(&addr), addr, &keys)
                .and_then(|socket| endpoint.rebind_abstract(socket));
            vlog!(
                1,
                "moved the UDP socket to the current network: {}",
                moved.map_or_else(|e| e.to_string(), |()| "ok".to_owned())
            );
            return;
        }
        match std::net::UdpSocket::bind(wildcard(&addr)) {
            Ok(socket) => {
                let local = socket.local_addr().ok();
                let result = endpoint.rebind(socket);
                vlog!(
                    1,
                    "moved the UDP socket to the current network (local {local:?}): {}",
                    result.map_or_else(|e| e.to_string(), |()| "ok".to_owned())
                );
            }
            Err(err) => vlog!(1, "cannot open a new UDP socket: {err}"),
        }
    }

    /// Looks up the address of the server again, since a move or a long sleep may have changed
    /// it. A failed lookup keeps the old address.
    pub(super) async fn refresh_address(&mut self) {
        let Some(Tier::Udp {
            addr,
            resolver: Some(resolver),
        }) = self.params.tiers.get_mut(self.current)
        else {
            return;
        };
        let Ok(Ok(found)) = timeout(RESOLVE_TIMEOUT, resolver()).await else {
            return;
        };
        if found != *addr {
            vlog!(
                1,
                "the address of the server changed from {addr} to {found}"
            );
            let family_changed = found.is_ipv4() != addr.is_ipv4();
            *addr = found;
            if family_changed {
                // the socket must be of the same family as the address.
                self.rebind();
            }
        }
    }

    /// After a failed attempt: whether the next tier should be tried at once.
    ///
    /// Before the first connection every failure moves on, and a pause follows only after the last
    /// tier. After a connection was made, the tier that worked is kept for a few failures, since
    /// the network is the likelier culprit.
    pub(super) fn try_next_tier(&mut self) -> bool {
        let count = self.params.tiers.len();
        if count < 2 {
            return false;
        }
        if !self.linked_once {
            self.current = (self.current + 1) % count;
            vlog!(
                1,
                "next transport: {}",
                self.params.tiers[self.current].name()
            );
            return self.current != 0;
        }
        self.failures += 1;
        if self.failures >= TIER_PATIENCE {
            self.failures = 0;
            self.current = (self.current + 1) % count;
            vlog!(
                1,
                "after {TIER_PATIENCE} failures, the next transport: {}",
                self.params.tiers[self.current].name()
            );
        }
        false
    }

    /// The UDP socket, made on first use.
    fn udp_endpoint(
        &mut self,
        addr: SocketAddr,
        relay: Option<&RelayKeys>,
    ) -> Result<Endpoint, String> {
        if let Some(endpoint) = &self.endpoint {
            return Ok(endpoint.clone());
        }
        let mut endpoint = match relay {
            Some(keys) => EnvelopeSocket::bind(wildcard(&addr), addr, keys)
                .and_then(|socket| {
                    Endpoint::new_with_abstract_socket(
                        quinn::EndpointConfig::default(),
                        None,
                        socket,
                        std::sync::Arc::new(quinn::TokioRuntime),
                    )
                })
                .map_err(|e| format!("cannot open a UDP socket: {e}"))?,
            None => Endpoint::client(wildcard(&addr))
                .map_err(|e| format!("cannot open a UDP socket: {e}"))?,
        };
        endpoint.set_default_client_config(quic_client(client_tls(
            &self.params.identity,
            self.params.connect.fingerprint,
        )));
        self.endpoint = Some(endpoint.clone());
        Ok(endpoint)
    }

    /// Starts opening the connection of tier `idx`. The returned future owns what it needs, so
    /// that several of them can run side by side.
    /// How long the connection has not worked in both directions: the longer of the silence of the
    /// server and the wait for an answer to a ping or to typed input.
    pub(super) fn lag(&self, link: &Link) -> Duration {
        [link.ping_since, self.input_since]
            .into_iter()
            .flatten()
            .map(|since| since.elapsed())
            .max()
            .unwrap_or_default()
            .max(link.last_heard.elapsed())
    }

    pub(super) fn prepare_link(&mut self, idx: usize) -> LinkFuture {
        let (udp, keys) = match &self.params.tiers[idx] {
            Tier::Udp { addr, .. } => (Some(*addr), None),
            Tier::Relay { addr, keys } => (Some(*addr), Some(keys.clone())),
            Tier::Stream { .. } => (None, None),
        };
        vlog!(
            1,
            "connecting over {}{}",
            self.params.tiers[idx].name(),
            udp.map_or_else(String::new, |addr| format!(" to {addr}"))
        );
        let opened = Instant::now();
        if let Some(addr) = udp {
            let connecting = self.udp_endpoint(addr, keys.as_ref()).and_then(|endpoint| {
                endpoint
                    .connect(addr, SERVER_NAME)
                    .map_err(|e| format!("udp: {e}"))
            });
            return Box::pin(async move {
                let conn = connecting?.await.map_err(|e| format!("udp: {e}"))?;
                let (send, recv) = conn.open_bi().await.map_err(|e| format!("udp: {e}"))?;
                vlog!(
                    2,
                    "QUIC handshake done in {:?}, round trip {:?}, remote {}",
                    opened.elapsed(),
                    conn.rtt(),
                    conn.remote_address()
                );
                Ok(Link::new(Some(conn), Out::Quic(send), Box::new(recv), None))
            });
        }
        let Tier::Stream { name, dial } = &mut self.params.tiers[idx] else {
            unreachable!("not a UDP tier");
        };
        let name = *name;
        let dialing = dial();
        Box::pin(async move {
            let stream = dialing.await.map_err(|e| format!("{name}: {e}"))?;
            vlog!(2, "{name} stream open after {:?}", opened.elapsed());
            Ok(Link::new(
                None,
                Out::Stream(stream.writer),
                stream.reader,
                stream.guard,
            ))
        })
    }

    /// Opens a connection and returns it with the tier it belongs to.
    ///
    /// With QUIC first and a stream transport behind it, both are tried and the first connection
    /// that opens wins: QUIC gets a head start of [`RACE_STAGGER`] when it is the transport in use,
    /// and the stream starts at once when the session is on it already, so that a network where
    /// UDP does not work costs a fraction of a second and not the whole timeout of QUIC.
    async fn race(&mut self) -> Result<(Link, usize), String> {
        let racing = self.params.tiers.len() > 1 && self.params.tiers[0].is_quic();
        if !racing {
            let idx = self.current;
            return self.prepare_link(idx).await.map(|link| (link, idx));
        }
        let (primary, secondary) = (0, self.current.max(1));
        let stagger = if self.current > 0 {
            Duration::ZERO
        } else {
            RACE_STAGGER
        };
        // before the first connection QUIC is given up on quickly; later it may be slow to return.
        let udp_cap = if self.linked_once {
            self.params.attempt_timeout
        } else {
            self.params.first_attempt_timeout
        };
        let udp = self.prepare_link(primary);
        let mut first: Option<LinkFuture> = Some(Box::pin(async move {
            timeout(udp_cap, udp)
                .await
                .unwrap_or_else(|_| Err("udp: no answer".to_owned()))
        }));
        let mut second: Option<LinkFuture> = None;
        let mut second_started = false;
        let delay = sleep(stagger);
        tokio::pin!(delay);
        let mut errors: Vec<String> = Vec::new();
        loop {
            // the second one starts at once when the first is out.
            if first.is_none() && !second_started {
                second = Some(self.prepare_link(secondary));
                second_started = true;
            }
            if first.is_none() && second.is_none() {
                return Err(errors.join("; "));
            }
            tokio::select! {
                result = async { first.as_mut().expect("guarded").await }, if first.is_some() => {
                    match result {
                        Ok(link) => return Ok((link, primary)),
                        Err(error) => {
                            vlog!(1, "{error}");
                            errors.push(error);
                            first = None;
                        }
                    }
                }
                result = async { second.as_mut().expect("guarded").await }, if second.is_some() => {
                    match result {
                        Ok(link) => return Ok((link, secondary)),
                        Err(error) => {
                            vlog!(1, "{error}");
                            errors.push(error);
                            second = None;
                        }
                    }
                }
                () = &mut delay, if !second_started => {
                    second = Some(self.prepare_link(secondary));
                    second_started = true;
                }
            }
        }
    }

    /// Makes an attempt to connect that a change of the network cuts short and starts again.
    pub(super) async fn establish_watched(&mut self, hello: &Hello) -> Attempt {
        let mut net = self.net.take();
        let attempt = loop {
            tokio::select! {
                attempt = self.establish(hello) => break attempt,
                cause = next_cause(&mut net) => match cause {
                    Some(cause) => {
                        vlog!(1, "network change detected while connecting ({cause:?})");
                        self.rebind();
                    }
                    None => net = None,
                },
            }
        };
        self.net = net;
        attempt
    }

    /// Connects, sends the hello, and resends the input that the server has not consumed.
    async fn establish(&mut self, hello: &Hello) -> Attempt {
        let (link, reply) = match self.send_hello(hello).await {
            Ok(sent) => sent,
            Err(attempt) => return attempt,
        };
        let welcome = match self.read_welcome(hello, reply) {
            Ok(welcome) => welcome,
            Err(attempt) => return attempt,
        };
        if let Err(message) = self.take_welcome(hello, welcome).await {
            return Attempt::Fatal(message);
        }
        self.send_input_again(&link, welcome.input_offset);
        if self.params.agent.is_some() {
            link.send(ClientFrame::AgentOffer);
        }
        Attempt::Linked(link)
    }

    /// Opens a connection, or takes the prepared one, and sends the hello on it. Returns the link
    /// with the first answer of the server.
    async fn send_hello(&mut self, hello: &Hello) -> Result<(Link, Reply), Attempt> {
        let limit = self.params.attempt_timeout;
        let prepared = self.prepared.take();
        let attempt = timeout(limit, async {
            let (mut link, idx) = match prepared {
                Some(prepared) => prepared,
                None => self.race().await?,
            };
            vlog!(2, "sending {}", hello_name(hello));
            link.send(ClientFrame::Hello(hello.clone()));
            let reply = link.reader.next().await;
            Ok::<_, String>((link, idx, reply))
        })
        .await;
        match attempt {
            Ok(Ok((link, idx, reply))) => {
                self.current = idx;
                Ok((link, reply))
            }
            Ok(Err(note)) => {
                vlog!(1, "connecting failed: {note}");
                self.note = Some(sanitize(note.as_bytes(), NOTE_CHARS));
                Err(Attempt::Retry)
            }
            Err(_) => {
                vlog!(1, "no answer within {limit:?}");
                self.note = Some(format!(
                    "{}: no answer",
                    self.params.tiers[self.current].name()
                ));
                Err(Attempt::Retry)
            }
        }
    }

    /// Takes the welcome out of the first answer, or says what to do instead.
    fn read_welcome(&mut self, hello: &Hello, reply: Reply) -> Result<Welcome, Attempt> {
        match reply {
            Ok(Some(ServerFrame::Welcome(welcome))) => Ok(welcome),
            // nobody has started the shell yet, so this client does it.
            Ok(Some(ServerFrame::Error(ErrorCode::NotStarted)))
                if matches!(hello, Hello::Attach { .. }) && !self.started =>
            {
                vlog!(1, "no running session to join: starting a new one");
                self.params.attach = false;
                Err(Attempt::Again)
            }
            // the first start may not have arrived, so it is tried again as a start.
            Ok(Some(ServerFrame::Error(ErrorCode::NotStarted)))
                if matches!(
                    hello,
                    Hello::Resume {
                        output_offset: 0,
                        ..
                    }
                ) && self.input.end() == 0 =>
            {
                self.started = false;
                Err(Attempt::Again)
            }
            Ok(Some(ServerFrame::Error(ErrorCode::ReplayGap))) => Err(Attempt::Fatal(
                "the server no longer has the output since the connection was lost".to_owned(),
            )),
            Ok(Some(ServerFrame::Error(code))) => Err(Attempt::Fatal(format!(
                "the server refused the session: {code:?}"
            ))),
            Err(message) => Err(Attempt::Fatal(message)),
            Ok(_) => Err(Attempt::Retry),
        }
    }

    /// Takes over the offsets of the welcome, after checking them against what the client sent.
    async fn take_welcome(&mut self, hello: &Hello, welcome: Welcome) -> Result<(), String> {
        if matches!(hello, Hello::Attach { .. }) {
            // a client without history takes over the offsets of the server.
            self.output_offset = welcome.output_offset;
            self.acked_output = welcome.output_offset;
            self.input = ReplayBuffer::starting_at(INPUT_BUFFER, welcome.input_offset);
            if welcome.output_offset > 0 {
                // the replay starts in the middle of the stream: cancel a sequence it may cut
                // and reset the colors, so that the first line does not inherit a state.
                let _ = self.io.output.write_all(b"\x18\x1b[0m").await;
                let _ = self.io.output.flush().await;
            }
        }
        vlog!(
            2,
            "welcome: the server has {} bytes of our input and sends output from {}",
            welcome.input_offset,
            welcome.output_offset
        );
        let id = self.params.connect.id.as_str();
        match hello {
            Hello::Attach { .. } => {
                vlog!(1, "joined the running session {id}");
                vlog!(
                    2,
                    "the server replays its output from offset {}",
                    welcome.output_offset
                );
            }
            Hello::Resume { output_offset, .. } => {
                vlog!(1, "resumed the session {id}");
                vlog!(2, "resumed at output offset {output_offset}");
            }
            Hello::Start { .. } => vlog!(1, "started the session {id}"),
        }
        if check_welcome(hello, welcome, self.input.start(), self.input.end()).is_err() {
            return Err("the server answered with unexpected offsets".to_owned());
        }
        if self.input.ack(welcome.input_offset).is_err() {
            return Err("the server consumed input that was never sent".to_owned());
        }
        // the server forgot output while the client was away. The stream goes on at the new
        // offset, and the gap is shown in the output where it happened, with its exact size.
        if let Hello::Resume { output_offset, .. } = hello
            && welcome.output_offset > *output_offset
        {
            vlog!(
                1,
                "the server forgot {} bytes of output while the client was away",
                welcome.output_offset - output_offset
            );
            self.output_offset = welcome.output_offset;
            self.note_gap(welcome.output_offset - output_offset).await;
        }
        Ok(())
    }

    /// Sends everything after the offset of the server again, including what was typed offline.
    fn send_input_again(&mut self, link: &Link, mut offset: u64) {
        while let Ok(chunk) = self.input.read_from(offset, MAX_DATA_LEN) {
            if chunk.is_empty() {
                break;
            }
            offset += chunk.len() as u64;
            vlog!(2, "sending {} bytes of input again", chunk.len());
            link.send(ClientFrame::Input(chunk));
        }
        self.input_since = (self.input.end() > self.input.start()).then(Instant::now);
    }
}
