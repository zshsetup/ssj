//! The client against an in-process server whose connections the test can kill.

use std::ffi::OsString;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use quinn::Endpoint;
use ssj_client::netwatch::Cause;
use ssj_client::run::{Dial, Finished, Io, Params, Resolver, Stream, Tier, run_session};
use ssj_client::status::Status;
use ssj_net::{Identity, quic_server, server_tls};
use ssj_proto::bootstrap::Connect;
use ssj_proto::{Env, EnvFilter, SessionId, WindowSize};
use ssj_server::backend::Direct;
use ssj_server::session::{Session, SessionConfig, SessionEnd, SessionEvent, SpawnTemplate};
use ssj_server::transport::serve_observed;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, WriteHalf};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};

struct Server {
    addr: SocketAddr,
    /// The TCP listener of the server.
    tcp_addr: SocketAddr,
    fingerprint: ssj_net::Fingerprint,
    endpoint: Endpoint,
    config: quinn::ServerConfig,
    connections: mpsc::UnboundedReceiver<quinn::Connection>,
    events: mpsc::UnboundedReceiver<SessionEvent>,
    session: JoinHandle<SessionEnd>,
}

fn start_server(script: &str, client_pin: ssj_net::Fingerprint) -> Server {
    start_server_sized(script, client_pin, 256 * 1024)
}

fn start_server_sized(
    script: &str,
    client_pin: ssj_net::Fingerprint,
    replay_capacity: usize,
) -> Server {
    start_server_with(
        script,
        client_pin,
        replay_capacity,
        ssj_server::session::SlowClient::Wait,
        1 << 20,
    )
}

fn start_server_with(
    script: &str,
    client_pin: ssj_net::Fingerprint,
    replay_capacity: usize,
    slow_client: ssj_server::session::SlowClient,
    live_backlog: usize,
) -> Server {
    start_server_full(
        script,
        client_pin,
        replay_capacity,
        slow_client,
        live_backlog,
        false,
    )
}

fn start_server_full(
    script: &str,
    client_pin: ssj_net::Fingerprint,
    replay_capacity: usize,
    slow_client: ssj_server::session::SlowClient,
    live_backlog: usize,
    compress: bool,
) -> Server {
    let identity = Identity::generate();
    let config = quic_server(server_tls(&identity, client_pin));
    let endpoint = Endpoint::server(config.clone(), "127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = endpoint.local_addr().unwrap();
    let session_config = SessionConfig {
        id: SessionId::parse("abcdef012345").unwrap(),
        template: SpawnTemplate {
            program: "/bin/sh".into(),
            args: vec!["-c".into(), script.into()],
            env: vec![(OsString::from("PATH"), OsString::from("/usr/bin:/bin"))],
            cwd: None,
        },
        accept_env: EnvFilter::default_patterns(),
        replay_capacity,
        away_after: Duration::from_secs(30),
        detached_timeout: None,
        max_detached: None,
        hello_timeout: Duration::from_secs(5),
        lost_after: Duration::from_secs(60),
        exit_grace: Duration::from_secs(60),
        slow_client,
        live_backlog,
        compress,
        agent_socket: None,
        prestart: None,
        first_client_timeout: Duration::from_secs(3600),
    };
    let (conns, conns_rx) = mpsc::channel(4);
    let (observer, connections) = mpsc::unbounded_channel();
    let (events_tx, events) = mpsc::unbounded_channel();
    let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    tcp.set_nonblocking(true).unwrap();
    let tcp_addr = tcp.local_addr().unwrap();
    tokio::spawn(serve_tls(
        tokio::net::TcpListener::from_std(tcp).unwrap(),
        ssj_net::TlsAcceptor::from(Arc::new(ssj_net::server_tls(&identity, client_pin))),
        conns.clone(),
    ));
    tokio::spawn(serve_observed(
        endpoint.clone(),
        conns,
        Duration::from_secs(5),
        Some(observer),
    ));
    let session = tokio::spawn(
        Session::new(Direct, session_config)
            .with_events(events_tx)
            .run(conns_rx),
    );
    Server {
        addr,
        tcp_addr,
        fingerprint: identity.fingerprint(),
        endpoint,
        config,
        connections,
        events,
        session,
    }
}

/// UDP forwarder that can swallow all packets from the server to the client.
struct Proxy {
    addr: SocketAddr,
    drop_replies: Arc<AtomicBool>,
}

async fn start_proxy(server: SocketAddr) -> Proxy {
    let front = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let back = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    back.connect(server).await.unwrap();
    let addr = front.local_addr().unwrap();
    let drop_replies = Arc::new(AtomicBool::new(false));
    let dropping = drop_replies.clone();
    tokio::spawn(async move {
        let (mut from_client, mut from_server) = (vec![0u8; 65536], vec![0u8; 65536]);
        let mut client = None;
        loop {
            tokio::select! {
                Ok((n, peer)) = front.recv_from(&mut from_client) => {
                    client = Some(peer);
                    let _ = back.send(&from_client[..n]).await;
                }
                Ok(n) = back.recv(&mut from_server) => {
                    if let (Some(peer), false) = (client, dropping.load(Ordering::Relaxed)) {
                        let _ = front.send_to(&from_server[..n], peer).await;
                    }
                }
            }
        }
    });
    Proxy { addr, drop_replies }
}

/// TCP forwarder that can end all connections, or keep them open and swallow everything.
struct TcpProxy {
    addr: SocketAddr,
    kill: tokio::sync::watch::Sender<u64>,
    swallow: Arc<AtomicBool>,
    /// The connections made so far, and how many of the oldest are swallowed.
    made: Arc<AtomicUsize>,
    blind: Arc<AtomicUsize>,
    /// How many of the oldest connections hold back what they carry (it is not lost).
    held: Arc<AtomicUsize>,
    /// How many of the oldest connections swallow what the client sends (and carry the rest).
    blind_up: Arc<AtomicUsize>,
}

impl TcpProxy {
    /// Swallows what the client sends on the connections that exist now, while what the server
    /// sends still arrives: a path that works in one direction only.
    fn blind_the_upstream_of_the_existing(&self) {
        self.blind_up
            .store(self.made.load(Ordering::Relaxed), Ordering::Relaxed);
    }

    /// Makes the connections that exist now carry nothing for the moment. What they were given
    /// waits, and goes through when [`TcpProxy::release_the_held`] is called.
    fn hold_the_existing(&self) {
        self.held
            .store(self.made.load(Ordering::Relaxed), Ordering::Relaxed);
    }

    fn release_the_held(&self) {
        self.held.store(0, Ordering::Relaxed);
    }

    /// Swallows what the connections that exist now carry, and nothing of the later ones.
    fn blind_the_existing(&self) {
        self.blind
            .store(self.made.load(Ordering::Relaxed), Ordering::Relaxed);
    }
}

async fn start_tcp_proxy(server: SocketAddr) -> TcpProxy {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (kill, killed) = tokio::sync::watch::channel(0u64);
    let swallow = Arc::new(AtomicBool::new(false));
    let swallowing = swallow.clone();
    let made = Arc::new(AtomicUsize::new(0));
    let blind = Arc::new(AtomicUsize::new(0));
    let held = Arc::new(AtomicUsize::new(0));
    let blind_up = Arc::new(AtomicUsize::new(0));
    let blind_up_by_proxy = blind_up.clone();
    let (made_by_proxy, blind_by_proxy, held_by_proxy) =
        (made.clone(), blind.clone(), held.clone());
    tokio::spawn(async move {
        while let Ok((client, _)) = listener.accept().await {
            let number = made_by_proxy.fetch_add(1, Ordering::Relaxed);
            let blind = blind_by_proxy.clone();
            let held = held_by_proxy.clone();
            let blind_up_here = blind_up_by_proxy.clone();
            let mut killed = killed.clone();
            // only a kill from now on ends this connection.
            killed.borrow_and_update();
            let swallowing = swallowing.clone();
            tokio::spawn(async move {
                let Ok(upstream) = tokio::net::TcpStream::connect(server).await else {
                    return;
                };
                let (mut cr, mut cw) = client.into_split();
                let (mut ur, mut uw) = upstream.into_split();
                let swallowing_up = swallowing.clone();
                let blind_up = blind.clone();
                let held_up = held.clone();
                let up = async move {
                    let mut buf = vec![0u8; 16 * 1024];
                    while let Ok(n) = cr.read(&mut buf).await {
                        if n == 0 {
                            break;
                        }
                        while number < held_up.load(Ordering::Relaxed) {
                            sleep(Duration::from_millis(20)).await;
                        }
                        let swallowed = swallowing_up.load(Ordering::Relaxed)
                            || number < blind_up.load(Ordering::Relaxed)
                            || number < blind_up_here.load(Ordering::Relaxed);
                        if !swallowed && uw.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                };
                let down = async move {
                    let mut buf = vec![0u8; 16 * 1024];
                    while let Ok(n) = ur.read(&mut buf).await {
                        if n == 0 {
                            break;
                        }
                        while number < held.load(Ordering::Relaxed) {
                            sleep(Duration::from_millis(20)).await;
                        }
                        let swallowed = swallowing.load(Ordering::Relaxed)
                            || number < blind.load(Ordering::Relaxed);
                        if !swallowed && cw.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                };
                tokio::select! {
                    () = up => {}
                    () = down => {}
                    _ = killed.changed() => {}
                }
            });
        }
    });
    TcpProxy {
        addr,
        kill,
        swallow,
        made,
        blind,
        held,
        blind_up,
    }
}

/// Records the messages of the client.
struct Recorded(Arc<Mutex<Vec<String>>>);

impl Status for Recorded {
    fn show(&mut self, text: &str) -> Vec<u8> {
        self.0.lock().unwrap().push(text.to_owned());
        Vec::new()
    }

    fn clear(&mut self, _title: Option<&str>) -> Vec<u8> {
        self.0.lock().unwrap().push("<clear>".to_owned());
        Vec::new()
    }
}

struct Terminal {
    typed: WriteHalf<DuplexStream>,
    shown: tokio::io::ReadHalf<DuplexStream>,
    status: Arc<Mutex<Vec<String>>>,
    client: JoinHandle<Result<Finished, String>>,
    seen: String,
    /// Sends a change of the network to the client.
    net: mpsc::UnboundedSender<Cause>,
    resizes: mpsc::UnboundedSender<WindowSize>,
    /// The terminal was closed.
    hangup: mpsc::UnboundedSender<()>,
}

fn start_client(server: &Server, identity: Identity) -> Terminal {
    start_client_at(server, identity, server.addr)
}

fn start_client_at(server: &Server, identity: Identity, addr: SocketAddr) -> Terminal {
    start_client_with(server, identity, addr, false)
}

fn start_client_with(
    server: &Server,
    identity: Identity,
    addr: SocketAddr,
    attach: bool,
) -> Terminal {
    start_client_full(server, identity, addr, attach, None, Duration::from_secs(8))
}

/// A client that reaches the server over TLS on TCP at `via`.
fn start_client_tcp(
    server: &Server,
    identity: Identity,
    via: SocketAddr,
    stream_dead_after: Duration,
) -> Terminal {
    let dial = tcp_dial(server, &identity, via);
    start_client_tiers(
        server,
        identity,
        vec![Tier::Stream { name: "tcp", dial }],
        Duration::from_secs(8),
        stream_dead_after,
    )
}

/// Accepts TLS on TCP and hands each stream to the session: a stand-in for a stream transport.
async fn serve_tls(
    listener: tokio::net::TcpListener,
    acceptor: ssj_net::TlsAcceptor,
    conns: mpsc::Sender<ssj_server::session::Connection>,
) {
    loop {
        let Ok((tcp, _)) = listener.accept().await else {
            continue;
        };
        let (acceptor, conns) = (acceptor.clone(), conns.clone());
        tokio::spawn(async move {
            let _ = tcp.set_nodelay(true);
            if let Ok(tls) = acceptor.accept(tcp).await {
                let _ = conns.send(ssj_server::stream::bridge(tls)).await;
            }
        });
    }
}

/// Opens TLS on TCP to `via`, as a stream transport would.
fn tcp_dial(server: &Server, identity: &Identity, via: SocketAddr) -> Dial {
    let connector =
        ssj_net::TlsConnector::from(Arc::new(ssj_net::client_tls(identity, server.fingerprint)));
    Box::new(move || {
        let connector = connector.clone();
        Box::pin(async move {
            let tcp = tokio::net::TcpStream::connect(via)
                .await
                .map_err(|e| e.to_string())?;
            let tls = connector
                .connect(ssj_net::server_name(), tcp)
                .await
                .map_err(|e| e.to_string())?;
            let (reader, writer) = tokio::io::split(tls);
            Ok(Stream {
                reader: Box::new(reader),
                writer: Box::new(writer),
                guard: None,
            })
        })
    })
}

fn start_client_full(
    server: &Server,
    identity: Identity,
    addr: SocketAddr,
    attach: bool,
    resolver: Option<Resolver>,
    attempt_timeout: Duration,
) -> Terminal {
    start_client_inner(
        server,
        identity,
        vec![Tier::Udp { addr, resolver }],
        attempt_timeout,
        ssj_client::run::STREAM_DEAD_AFTER,
        attach,
        false,
    )
}

fn start_client_tiers(
    server: &Server,
    identity: Identity,
    tiers: Vec<Tier>,
    attempt_timeout: Duration,
    stream_dead_after: Duration,
) -> Terminal {
    start_client_inner(
        server,
        identity,
        tiers,
        attempt_timeout,
        stream_dead_after,
        false,
        false,
    )
}

fn start_client_inner(
    server: &Server,
    identity: Identity,
    tiers: Vec<Tier>,
    attempt_timeout: Duration,
    stream_dead_after: Duration,
    attach: bool,
    hangup_detaches: bool,
) -> Terminal {
    let (typed_tx, typed_rx) = tokio::io::duplex(1 << 20);
    let (shown_tx, shown_rx) = tokio::io::duplex(1 << 20);
    let (_, typed) = tokio::io::split(typed_tx);
    let (typed_rx, _) = tokio::io::split(typed_rx);
    let (_, shown_tx) = tokio::io::split(shown_tx);
    let (shown, _) = tokio::io::split(shown_rx);
    let (resizes_tx, resizes) = mpsc::unbounded_channel();
    let status = Arc::new(Mutex::new(Vec::new()));
    let (net, net_rx) = mpsc::unbounded_channel();
    let (hangup, hangups) = mpsc::unbounded_channel();
    let io = Io {
        input: Box::new(typed_rx),
        output: Box::new(shown_tx),
        size: WindowSize::new(24, 80).unwrap(),
        resizes,
        status: Box::new(Recorded(status.clone())),
        net: net_rx,
        hangups,
    };
    let params = Params {
        identity,
        relay_ready: None,
        connect: Connect {
            id: ssj_proto::SessionId::parse("abcdef012345").unwrap(),
            udp: Some(server.addr.port()),
            fingerprint: server.fingerprint,
            new: false,
            name: None,
            socket: None,
        },
        tiers,
        attempt_timeout,
        first_attempt_timeout: attempt_timeout,
        stream_dead_after,
        env: Env::default(),
        detach_key: Some(0x1c),
        hangup_detaches,
        local_echo: false,
        compress: false,
        agent: None,
        announce: None,
        attach,
    };
    let client = tokio::spawn(run_session(params, io));
    Terminal {
        typed,
        shown,
        status,
        client,
        seen: String::new(),
        net,
        resizes: resizes_tx,
        hangup,
    }
}

impl Terminal {
    async fn type_line(&mut self, line: &str) {
        self.typed
            .write_all(format!("{line}\n").as_bytes())
            .await
            .unwrap();
    }

    async fn wait_for(&mut self, needle: &str) {
        let deadline = Duration::from_secs(30);
        timeout(deadline, async {
            while !self.seen.contains(needle) {
                let mut chunk = [0u8; 4096];
                let n = self.shown.read(&mut chunk).await.unwrap();
                assert!(n > 0, "the client closed the terminal");
                self.seen.push_str(&String::from_utf8_lossy(&chunk[..n]));
            }
        })
        .await
        .unwrap_or_else(|_| panic!("never saw {needle:?} in {:?}", self.seen));
    }

    /// Reads until nothing new has arrived for a while, so that repeated lines would show up.
    async fn settle(&mut self) {
        loop {
            let mut chunk = [0u8; 4096];
            match timeout(Duration::from_millis(600), self.shown.read(&mut chunk)).await {
                Ok(Ok(n)) if n > 0 => self.seen.push_str(&String::from_utf8_lossy(&chunk[..n])),
                _ => break,
            }
        }
        // a client that gave up would also make the output stop.
        assert!(
            !self.client.is_finished(),
            "the client ended early: {:?}",
            self.status()
        );
    }

    /// The `got:` lines the shell printed, in order.
    fn got_lines(&self) -> Vec<String> {
        self.seen
            .lines()
            .map(str::trim)
            .filter(|l| l.starts_with("got:"))
            .map(str::to_owned)
            .collect()
    }

    fn status(&self) -> Vec<String> {
        self.status.lock().unwrap().clone()
    }
}

/// The newest connection that is still open, waiting for the client to make one if needed.
async fn live_connection(server: &mut Server) -> quinn::Connection {
    timeout(Duration::from_secs(15), async {
        loop {
            let conn = server.connections.recv().await.expect("the server ended");
            if conn.close_reason().is_none() {
                return conn;
            }
        }
    })
    .await
    .expect("no live connection to kill")
}

const ECHO_LINES: &str = "stty -echo; while read l; do echo \"got:$l\"; done";

#[tokio::test]
async fn killed_connections_lose_and_repeat_no_line() {
    let client_id = Identity::generate();
    let mut server = start_server(ECHO_LINES, client_id.fingerprint());
    let mut terminal = start_client(&server, client_id);

    for i in 0..60 {
        terminal.type_line(&format!("l{i}")).await;
        if i == 15 || i == 40 {
            sleep(Duration::from_millis(100)).await;
            live_connection(&mut server)
                .await
                .close(9u8.into(), b"killed by the test");
        }
        sleep(Duration::from_millis(5)).await;
    }
    terminal.wait_for("got:l59").await;
    terminal.settle().await;

    let expected: Vec<String> = (0..60).map(|i| format!("got:l{i}")).collect();
    assert_eq!(terminal.got_lines(), expected);
    let status = terminal.status();
    assert!(
        status.iter().any(|s| s.contains("reconnecting")),
        "{status:?}"
    );
    assert_eq!(
        status.last().map(String::as_str),
        Some("<clear>"),
        "{status:?}"
    );
}

#[tokio::test]
async fn input_typed_while_the_server_is_unreachable_arrives_once_it_returns() {
    let client_id = Identity::generate();
    let mut server = start_server(ECHO_LINES, client_id.fingerprint());
    let mut terminal = start_client(&server, client_id);

    terminal.type_line("before").await;
    terminal.wait_for("got:before").await;

    // the server stops accepting connections and drops the current one.
    server.endpoint.set_server_config(None);
    server
        .connections
        .recv()
        .await
        .unwrap()
        .close(9u8.into(), b"killed by the test");
    sleep(Duration::from_millis(200)).await;
    for i in 0..10 {
        terminal.type_line(&format!("off{i}")).await;
    }
    sleep(Duration::from_millis(1500)).await;
    assert!(
        !terminal.status().is_empty(),
        "the client did not notice the outage"
    );

    server
        .endpoint
        .set_server_config(Some(server.config.clone()));
    terminal.wait_for("got:off9").await;
    terminal.settle().await;

    let mut expected = vec!["got:before".to_owned()];
    expected.extend((0..10).map(|i| format!("got:off{i}")));
    assert_eq!(terminal.got_lines(), expected);
    let attempts: Vec<_> = terminal
        .status()
        .into_iter()
        .filter(|s| s.contains("attempt"))
        .collect();
    // a silent server gives no refusal, so an attempt lasts until its timeout.
    assert!(!attempts.is_empty(), "{attempts:?}");
}

#[tokio::test]
async fn a_closed_terminal_ends_the_session_and_its_shell() {
    let client_id = Identity::generate();
    let mut server = start_server(ECHO_LINES, client_id.fingerprint());
    let mut terminal = start_client(&server, client_id);
    terminal.type_line("hello").await;
    terminal.wait_for("got:hello").await;

    // SIGHUP of the terminal: the server hangs up the shell, and nothing is left running.
    terminal.hangup.send(()).unwrap();
    let finished = timeout(Duration::from_secs(10), terminal.client)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(finished, Ok(Finished::HungUp));
    let end = timeout(Duration::from_secs(10), &mut server.session)
        .await
        .expect("the session ends")
        .unwrap();
    assert!(matches!(end, SessionEnd::Killed), "{end:?}");
}

// inside an `ssh` session the end of the terminal is more likely a lost connection than a wish.
#[tokio::test]
async fn inside_ssh_a_closed_terminal_detaches_and_the_session_keeps_running() {
    let client_id = Identity::generate();
    let mut server = start_server(ECHO_LINES, client_id.fingerprint());
    let mut terminal = start_client_inner(
        &server,
        client_id,
        vec![Tier::Udp {
            addr: server.addr,
            resolver: None,
        }],
        Duration::from_secs(8),
        ssj_client::run::STREAM_DEAD_AFTER,
        false,
        true,
    );
    terminal.type_line("hello").await;
    terminal.wait_for("got:hello").await;

    terminal.hangup.send(()).unwrap();
    let finished = timeout(Duration::from_secs(10), terminal.client)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(finished, Ok(Finished::Detached));
    // the server saw a deliberate detach, and the shell is still there.
    loop {
        let event = timeout(Duration::from_secs(10), server.events.recv())
            .await
            .expect("an event")
            .expect("the session runs");
        if event == SessionEvent::Detached {
            break;
        }
    }
    assert!(!server.session.is_finished());
}

#[tokio::test]
async fn a_closed_terminal_while_offline_leaves_the_session_for_a_later_return() {
    let client_id = Identity::generate();
    let server = start_server(ECHO_LINES, client_id.fingerprint());
    let mut terminal = start_client(&server, client_id);
    terminal.type_line("hello").await;
    terminal.wait_for("got:hello").await;
    // the connection is cut and the client waits to reconnect.
    server.endpoint.close(0u8.into(), b"gone");
    timeout(Duration::from_secs(20), async {
        while !terminal.status().iter().any(|s| s.contains("reconnecting")) {
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the client notices");

    terminal.hangup.send(()).unwrap();
    let finished = timeout(Duration::from_secs(10), terminal.client)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(finished, Ok(Finished::HungUp));
    // nobody could tell the server, so the shell still runs.
    assert!(!server.session.is_finished());
}

#[tokio::test]
async fn the_detach_key_detaches_and_the_session_keeps_running() {
    let client_id = Identity::generate();
    let mut server = start_server(ECHO_LINES, client_id.fingerprint());
    let mut terminal = start_client(&server, client_id);
    terminal.type_line("hello").await;
    terminal.wait_for("got:hello").await;

    terminal.typed.write_all(b"\x1c").await.unwrap();

    let finished = timeout(Duration::from_secs(10), terminal.client)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(finished, Ok(Finished::Detached));
    // other events (the client connecting) come first.
    let detached = timeout(Duration::from_secs(10), async {
        while let Some(event) = server.events.recv().await {
            if event == SessionEvent::Detached {
                return true;
            }
        }
        false
    })
    .await
    .unwrap();
    assert!(detached);
    assert!(
        timeout(Duration::from_millis(500), &mut server.session)
            .await
            .is_err(),
        "the session ended"
    );
}

#[tokio::test]
async fn the_detach_key_works_without_a_connection_so_the_user_is_never_stuck() {
    let client_id = Identity::generate();
    let mut server = start_server(ECHO_LINES, client_id.fingerprint());
    let mut terminal = start_client(&server, client_id);
    terminal.type_line("hello").await;
    terminal.wait_for("got:hello").await;

    server.endpoint.set_server_config(None);
    server
        .connections
        .recv()
        .await
        .unwrap()
        .close(9u8.into(), b"killed by the test");
    sleep(Duration::from_millis(500)).await;
    terminal.typed.write_all(b"\n\x1c").await.unwrap();

    let finished = timeout(Duration::from_secs(10), terminal.client)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(finished, Ok(Finished::Detached));
    // there was no connection to tell, so the server is not told.
    while let Ok(event) = server.events.try_recv() {
        assert_ne!(event, SessionEvent::Detached);
    }
}

// the server consumed input whose acknowledgement never reached the client. After the
// reconnect the client must not send it a second time, and must get the output it missed.
#[tokio::test]
async fn input_consumed_before_the_loss_is_not_sent_twice() {
    let client_id = Identity::generate();
    let mut server = start_server(ECHO_LINES, client_id.fingerprint());
    let proxy = start_proxy(server.addr).await;
    let mut terminal = start_client_at(&server, client_id, proxy.addr);

    terminal.type_line("a0").await;
    terminal.wait_for("got:a0").await;

    proxy.drop_replies.store(true, Ordering::Relaxed);
    for i in 0..10 {
        terminal.type_line(&format!("b{i}")).await;
    }
    // the server has consumed and answered them by now, but the client heard nothing.
    sleep(Duration::from_millis(800)).await;
    assert!(!terminal.seen.contains("got:b0"));
    server
        .connections
        .recv()
        .await
        .unwrap()
        .close(9u8.into(), b"killed by the test");
    proxy.drop_replies.store(false, Ordering::Relaxed);

    terminal.wait_for("got:b9").await;
    terminal.settle().await;
    let mut expected = vec!["got:a0".to_owned()];
    expected.extend((0..10).map(|i| format!("got:b{i}")));
    assert_eq!(terminal.got_lines(), expected);
    let status = terminal.status();
    assert!(
        status.iter().any(|s| s.contains("reconnecting")),
        "no reconnect happened: {status:?}"
    );
}

#[tokio::test]
async fn silent_server_is_reported_and_the_report_goes_away_when_it_answers() {
    let client_id = Identity::generate();
    let server = start_server(ECHO_LINES, client_id.fingerprint());
    let proxy = start_proxy(server.addr).await;
    let mut terminal = start_client_at(&server, client_id, proxy.addr);
    terminal.type_line("one").await;
    terminal.wait_for("got:one").await;

    proxy.drop_replies.store(true, Ordering::Relaxed);
    sleep(Duration::from_secs(8)).await;
    let during = terminal.status();
    assert!(
        during.iter().any(|s| s.contains("no response")),
        "{during:?}"
    );

    proxy.drop_replies.store(false, Ordering::Relaxed);
    terminal.type_line("two").await;
    terminal.wait_for("got:two").await;
    let after = terminal.status();
    assert_eq!(
        after.last().map(String::as_str),
        Some("<clear>"),
        "{after:?}"
    );
    // the same connection came back, so there was no reconnect.
    assert!(
        !after.iter().any(|s| s.contains("reconnecting")),
        "{after:?}"
    );
}

// A client that restarts has no offsets. It joins with `Attach`, takes over the offsets of the
// server, and the shell goes on where it was.
#[tokio::test]
async fn attaching_client_continues_a_running_session_and_survives_a_later_loss() {
    let client_id = Identity::generate();
    let mut server = start_server(ECHO_COUNTING, client_id.fingerprint());
    let mut first = start_client(&server, client_id_clone(&client_id));
    first.type_line("one").await;
    first.wait_for("got:one:1").await;
    first.typed.write_all(b"\x1c").await.unwrap();
    let finished = timeout(Duration::from_secs(10), first.client)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(finished, Ok(Finished::Detached));

    let mut second = start_client_with(&server, client_id, server.addr, true);
    second.type_line("two").await;
    second.wait_for("got:two:2").await;
    // the second client has the history of the first one only as far as the replay reaches.
    assert!(second.seen.contains("got:two:2"));

    // and it reconnects like any client.
    live_connection(&mut server)
        .await
        .close(9u8.into(), b"killed by the test");
    second.type_line("three").await;
    second.wait_for("got:three:3").await;
    second.settle().await;
    assert!(second.status().iter().any(|s| s.contains("reconnecting")));
    let lines = second.got_lines();
    assert_eq!(
        lines.iter().filter(|l| l.starts_with("got:three")).count(),
        1
    );
}

const ECHO_COUNTING: &str =
    "stty -echo; n=0; while read l; do n=$((n+1)); echo \"got:$l:$n\"; done";

/// A second handle to the same identity, since the first one moves into a client.
fn client_id_clone(identity: &Identity) -> Identity {
    Identity {
        cert: identity.cert.clone(),
        key: identity.key.clone_key(),
    }
}

/// Waits until `check` is true, polling, and says how long it took.
async fn wait_until(limit: Duration, mut check: impl FnMut() -> bool) -> Option<Duration> {
    let start = std::time::Instant::now();
    while start.elapsed() < limit {
        if check() {
            return Some(start.elapsed());
        }
        sleep(Duration::from_millis(50)).await;
    }
    None
}

#[tokio::test]
async fn a_change_of_the_network_moves_the_same_connection_to_a_new_address() {
    let client_id = Identity::generate();
    let mut server = start_server(ECHO_LINES, client_id.fingerprint());
    let mut terminal = start_client(&server, client_id);
    terminal.type_line("before").await;
    terminal.wait_for("got:before").await;
    let conn = live_connection(&mut server).await;
    let old_address = conn.remote_address();

    terminal.net.send(Cause::NetworkChanged).unwrap();
    let moved = wait_until(Duration::from_secs(5), || {
        conn.remote_address() != old_address
    })
    .await;

    assert!(moved.is_some(), "the server still sees {old_address}");
    // the same connection, not a new one, and the session goes on.
    assert!(conn.close_reason().is_none());
    terminal.type_line("after").await;
    terminal.wait_for("got:after").await;
    terminal.settle().await;
    assert_eq!(terminal.got_lines(), ["got:before", "got:after"]);
    assert!(
        !terminal.status().iter().any(|s| s.contains("reconnecting")),
        "{:?}",
        terminal.status()
    );
}

#[tokio::test]
async fn silence_after_a_change_starts_a_new_connection_quickly_and_loses_nothing() {
    for (cause, limit) in [
        (Cause::Woke, Duration::from_millis(2800)),
        (Cause::NetworkChanged, Duration::from_millis(3800)),
    ] {
        let client_id = Identity::generate();
        let mut server = start_server(ECHO_LINES, client_id.fingerprint());
        let proxy = start_proxy(server.addr).await;
        let mut terminal = start_client_at(&server, client_id, proxy.addr);
        terminal.type_line("one").await;
        terminal.wait_for("got:one").await;
        // held until the end: the id comes from an address, which a new connection could reuse.
        let first = live_connection(&mut server).await;

        // the path is dead and nothing tells the connection so.
        proxy.drop_replies.store(true, Ordering::Relaxed);
        terminal.type_line("two").await;
        sleep(Duration::from_millis(300)).await;
        assert!(!terminal.status().iter().any(|s| s.contains("reconnecting")));

        terminal.net.send(cause).unwrap();
        let reconnecting = wait_until(limit, || {
            terminal.status().iter().any(|s| s.contains("reconnecting"))
        })
        .await;
        assert!(
            reconnecting.is_some(),
            "{cause:?}: no new connection within {limit:?}: {:?}",
            terminal.status()
        );

        proxy.drop_replies.store(false, Ordering::Relaxed);
        terminal.wait_for("got:two").await;
        terminal.settle().await;
        assert_eq!(terminal.got_lines(), ["got:one", "got:two"], "{cause:?}");
        assert_ne!(
            live_connection(&mut server).await.stable_id(),
            first.stable_id(),
            "{cause:?}: it must be a new connection"
        );
    }
}

// an attempt that hangs on a dead path is the slowest part of a reconnect: the handshake packets
// are repeated with growing pauses, so a path that comes back is found late.
#[tokio::test]
async fn a_change_of_the_network_cuts_short_an_attempt_that_hangs() {
    let client_id = Identity::generate();
    let server = start_server(ECHO_LINES, client_id.fingerprint());
    let proxy = start_proxy(server.addr).await;
    let mut terminal = start_client_at(&server, client_id, proxy.addr);
    terminal.type_line("before").await;
    terminal.wait_for("got:before").await;

    // the path dies, the first change finds nothing on the new path, and every attempt after
    // that is answered by nobody.
    proxy.drop_replies.store(true, Ordering::Relaxed);
    terminal.type_line("during").await;
    terminal.net.send(Cause::NetworkChanged).unwrap();
    let reconnecting = wait_until(Duration::from_secs(5), || {
        terminal.status().iter().any(|s| s.contains("reconnecting"))
    })
    .await;
    assert!(reconnecting.is_some(), "{:?}", terminal.status());
    // an attempt is in progress and keeps repeating its handshake into the void.
    sleep(Duration::from_millis(1500)).await;

    proxy.drop_replies.store(false, Ordering::Relaxed);
    let before = std::time::Instant::now();
    terminal.net.send(Cause::NetworkChanged).unwrap();
    terminal.wait_for("got:during").await;

    assert!(
        before.elapsed() < Duration::from_millis(1500),
        "{:?}",
        before.elapsed()
    );
}

#[tokio::test]
async fn a_silent_server_is_reported_after_a_short_time_and_not_at_once() {
    let client_id = Identity::generate();
    let server = start_server(ECHO_LINES, client_id.fingerprint());
    let proxy = start_proxy(server.addr).await;
    let mut terminal = start_client_at(&server, client_id, proxy.addr);
    terminal.type_line("one").await;
    terminal.wait_for("got:one").await;

    proxy.drop_replies.store(true, Ordering::Relaxed);
    let reported = wait_until(Duration::from_secs(6), || {
        terminal.status().iter().any(|s| s.contains("no response"))
    })
    .await;

    let after = reported.expect("a stall must be reported");
    // not at once (a blip is not a stall), but long before the old five seconds plus a tick.
    assert!(after >= Duration::from_millis(1500), "{after:?}");
    assert!(after <= Duration::from_millis(3600), "{after:?}");
    // the message does not repeat on every ping.
    sleep(Duration::from_secs(3)).await;
    let shown = terminal
        .status()
        .iter()
        .filter(|s| s.contains("no response"))
        .count();
    assert!(shown <= 2, "{:?}", terminal.status());
}

const OPEN_SEQUENCE: &str = "printf '\\033]52;c;AAAA'; read x; printf 'BBBB\\007done\\n'";

// writing a title into the middle of a clipboard sequence would show the rest as garbage. So the
// status first waits. A sequence that stays open for good is cancelled with CAN, the status goes
// out, and the rest of the sequence is dropped when it arrives.
#[tokio::test]
async fn a_status_waits_in_a_stuck_sequence_and_then_cancels_it() {
    let client_id = Identity::generate();
    let server = start_server(OPEN_SEQUENCE, client_id.fingerprint());
    let proxy = start_proxy(server.addr).await;
    let mut terminal = start_client_at(&server, client_id, proxy.addr);
    terminal.wait_for("AAAA").await;

    proxy.drop_replies.store(true, Ordering::Relaxed);
    // the stall shows after a few seconds, and the sequence is given two more.
    sleep(Duration::from_millis(1500)).await;
    assert!(
        terminal.status().is_empty(),
        "the status was written inside a sequence at once: {:?}",
        terminal.status()
    );
    sleep(Duration::from_secs(8)).await;
    let calls = terminal.status();
    assert!(
        calls.iter().any(|s| s.contains("no response")),
        "the status never got through: {calls:?}"
    );

    proxy.drop_replies.store(false, Ordering::Relaxed);
    terminal.type_line("go").await;
    terminal.wait_for("done").await;
    let after_cancel = terminal
        .seen
        .split('\u{18}')
        .nth(1)
        .expect("a CAN was written");
    assert!(
        !after_cancel.contains("BBBB") && !after_cancel.contains('\u{7}'),
        "the rest of the sequence appeared as text: {after_cancel:?}"
    );
}

fn counted(from: u32, to: u32) -> String {
    (from..=to).map(|i| format!("{i}\n")).collect()
}

// the job writes far more than the server keeps while the client is away. When the client comes
// back, the terminal shows how much was lost, once and exactly, and everything after the gap is
// intact. The second burst of output proves that the client acknowledges with the new offsets: with
// the old ones, the server would wait for acknowledgements that never move its buffer.
#[tokio::test]
async fn output_dropped_while_away_is_reported_exactly_once_and_the_rest_is_intact() {
    let marker = std::path::PathBuf::from(format!("/tmp/ssjt-gap-{}", std::process::id()));
    let _ = std::fs::remove_file(&marker);
    let count = "awk 'BEGIN { for (i = 1; i <= 400000; i++) print i }'";
    let script = format!(
        "stty -echo -opost; echo first; sleep 1; {count}; echo DONE; touch {m}; read x; {count}; echo END",
        m = marker.display()
    );
    let client_id = Identity::generate();
    let mut server = start_server_sized(&script, client_id.fingerprint(), 64 * 1024);
    let mut terminal = start_client(&server, client_id);
    terminal.wait_for("first").await;

    // away: the server refuses connections and the current one ends.
    server.endpoint.set_server_config(None);
    live_connection(&mut server)
        .await
        .close(9u8.into(), b"killed by the test");
    timeout(Duration::from_secs(40), async {
        while !marker.exists() {
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the job must finish while the client is away");
    sleep(Duration::from_millis(500)).await;

    server
        .endpoint
        .set_server_config(Some(server.config.clone()));
    terminal.wait_for("DONE\n").await;
    terminal.type_line("go").await;
    terminal.wait_for("END\n").await;

    let seen = terminal.seen.clone();
    let prefix = "\x18\x1b[0m\r\n[ssj: ";
    let suffix = " bytes of output were dropped]\r\n";
    assert_eq!(seen.matches("[ssj:").count(), 1, "one notice");
    let at = seen.find(prefix).expect("the notice");
    // what came before the gap is what the client had seen before it left.
    assert_eq!(&seen[..at], "first\n");
    let after = &seen[at + prefix.len()..];
    let digits = after.find(suffix).expect("the end of the notice");
    let dropped: usize = after[..digits].parse().unwrap();
    assert!(dropped > 1_000_000, "{dropped}");

    // exactly the forgotten bytes are missing from the stream, and nothing else.
    let expected = format!(
        "first\n{}DONE\n{}END\n",
        counted(1, 400_000),
        counted(1, 400_000)
    );
    let rest = &after[digits + suffix.len()..];
    // the client had seen "first\n", which is six bytes.
    let want = &expected[6 + dropped..];
    let first_difference = rest.bytes().zip(want.bytes()).position(|(a, b)| a != b);
    assert!(
        rest == want,
        "the bytes after the gap differ: first difference at {first_difference:?}, lengths {} and {}",
        rest.len(),
        want.len()
    );
    let finished = timeout(Duration::from_secs(10), terminal.client)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(finished, Ok(Finished::Exited(0)));
    let _ = std::fs::remove_file(&marker);
}

#[tokio::test]
async fn the_address_is_looked_up_again_after_every_third_failed_attempt() {
    let client_id = Identity::generate();
    let mut server = start_server(ECHO_LINES, client_id.fingerprint());
    let old = start_proxy(server.addr).await;
    let new = start_proxy(server.addr).await;
    let lookups = Arc::new(AtomicUsize::new(0));
    let resolver: Resolver = Box::new({
        let (lookups, new_addr) = (lookups.clone(), new.addr);
        move || {
            lookups.fetch_add(1, Ordering::Relaxed);
            Box::pin(async move { Ok(new_addr) })
        }
    });
    let mut terminal = start_client_full(
        &server,
        client_id,
        old.addr,
        false,
        Some(resolver),
        Duration::from_millis(400),
    );
    terminal.type_line("before").await;
    terminal.wait_for("got:before").await;

    // the connection ends, and the old address stops answering from then on.
    live_connection(&mut server)
        .await
        .close(9u8.into(), b"killed by the test");
    sleep(Duration::from_millis(100)).await;
    old.drop_replies.store(true, Ordering::Relaxed);
    terminal.type_line("after").await;
    terminal.wait_for("got:after").await;
    terminal.settle().await;

    assert_eq!(terminal.got_lines(), ["got:before", "got:after"]);
    // exactly after the third failure, not earlier and not at every attempt.
    assert_eq!(lookups.load(Ordering::Relaxed), 1);
    let last_attempt = terminal
        .status()
        .iter()
        .filter_map(|s| s.split("attempt ").nth(1))
        .filter_map(|n| n.split([',', ')']).next()?.parse::<usize>().ok())
        .max();
    assert_eq!(last_attempt, Some(3), "{:?}", terminal.status());
}

#[tokio::test]
async fn a_failed_lookup_keeps_the_old_address() {
    let client_id = Identity::generate();
    let mut server = start_server(ECHO_LINES, client_id.fingerprint());
    let proxy = start_proxy(server.addr).await;
    let lookups = Arc::new(AtomicUsize::new(0));
    let resolver: Resolver = Box::new({
        let lookups = lookups.clone();
        move || {
            lookups.fetch_add(1, Ordering::Relaxed);
            Box::pin(async { Err("no such host".to_owned()) })
        }
    });
    let mut terminal = start_client_full(
        &server,
        client_id,
        proxy.addr,
        false,
        Some(resolver),
        Duration::from_millis(400),
    );
    terminal.type_line("before").await;
    terminal.wait_for("got:before").await;

    live_connection(&mut server)
        .await
        .close(9u8.into(), b"killed by the test");
    sleep(Duration::from_millis(100)).await;
    proxy.drop_replies.store(true, Ordering::Relaxed);
    // three attempts fail, then the lookup fails, and the old address works again.
    assert!(
        wait_until(Duration::from_secs(10), || lookups.load(Ordering::Relaxed)
            >= 1)
        .await
        .is_some()
    );
    proxy.drop_replies.store(false, Ordering::Relaxed);
    terminal.type_line("after").await;
    terminal.wait_for("got:after").await;
}

#[tokio::test]
async fn a_burst_of_resizes_reaches_the_shell_as_the_last_size() {
    let client_id = Identity::generate();
    let server = start_server(
        "trap 'stty size' WINCH; echo ready; while :; do read l; echo \"got:$l\"; done",
        client_id.fingerprint(),
    );
    let mut terminal = start_client(&server, client_id);
    terminal.wait_for("ready").await;
    for rows in 30..70 {
        terminal
            .resizes
            .send(WindowSize::new(rows, 100).unwrap())
            .unwrap();
    }
    terminal.type_line("wake").await;
    terminal.wait_for("69 100").await;
    terminal.settle().await;
    // the sizes in between did not each reach the terminal of the shell.
    let reached = terminal.seen.matches(" 100").count();
    assert!(
        reached < 10,
        "{reached} resizes reached the shell: {:?}",
        terminal.seen
    );
}

#[tokio::test]
async fn tcp_loses_and_repeats_no_line_when_its_connection_is_killed() {
    let client_id = Identity::generate();
    let server = start_server(ECHO_LINES, client_id.fingerprint());
    let proxy = start_tcp_proxy(server.tcp_addr).await;
    let mut terminal = start_client_tcp(
        &server,
        client_id,
        proxy.addr,
        ssj_client::run::STREAM_DEAD_AFTER,
    );

    for i in 0..60 {
        terminal.type_line(&format!("l{i}")).await;
        if i == 15 || i == 40 {
            sleep(Duration::from_millis(100)).await;
            proxy.kill.send_modify(|generation| *generation += 1);
        }
        sleep(Duration::from_millis(5)).await;
    }
    terminal.wait_for("got:l59").await;
    terminal.settle().await;

    let expected: Vec<String> = (0..60).map(|i| format!("got:l{i}")).collect();
    assert_eq!(terminal.got_lines(), expected);
    assert!(
        terminal.status().iter().any(|s| s.contains("reconnecting")),
        "{:?}",
        terminal.status()
    );
}

// A path that stops without a sign (a dead `ssh`, a firewall) leaves the TCP connection open, and
// only the silence shows it.
#[tokio::test]
async fn a_silent_tcp_path_is_given_up_after_a_while_and_replaced() {
    let client_id = Identity::generate();
    let server = start_server(ECHO_LINES, client_id.fingerprint());
    let proxy = start_tcp_proxy(server.tcp_addr).await;
    let mut terminal = start_client_tcp(&server, client_id, proxy.addr, Duration::from_secs(4));
    terminal.type_line("before").await;
    terminal.wait_for("got:before").await;

    proxy.swallow.store(true, Ordering::Relaxed);
    terminal.type_line("during").await;
    let silent = wait_until(Duration::from_secs(4), || {
        terminal.status().iter().any(|s| s.contains("no response"))
    })
    .await;
    assert!(silent.is_some(), "{:?}", terminal.status());
    // the client gives the connection up, and its new attempts are swallowed too. The spares that
    // it opens meanwhile delay this until three times the limit.
    let gave_up = wait_until(Duration::from_secs(20), || {
        terminal.status().iter().any(|s| s.contains("reconnecting"))
    })
    .await;
    assert!(gave_up.is_some(), "{:?}", terminal.status());

    proxy.swallow.store(false, Ordering::Relaxed);
    proxy.kill.send_modify(|generation| *generation += 1);
    terminal.wait_for("got:during").await;
    terminal.settle().await;
    assert_eq!(terminal.got_lines(), ["got:before", "got:during"]);
}

// A stream that goes silent gets a spare connection after a few seconds, and the session moves to
// it, long before the stream would be given up for good. The old connection stays swallowed.
#[tokio::test]
async fn a_silent_stream_is_replaced_by_a_spare_long_before_it_is_given_up() {
    let client_id = Identity::generate();
    let server = start_server(ECHO_LINES, client_id.fingerprint());
    let proxy = start_tcp_proxy(server.tcp_addr).await;
    // the stream would be given up after a minute.
    let mut terminal = start_client_tcp(&server, client_id, proxy.addr, Duration::from_secs(60));
    terminal.type_line("before").await;
    terminal.wait_for("got:before").await;

    proxy.blind_the_existing();
    terminal.type_line("during").await;
    let began = std::time::Instant::now();
    terminal.wait_for("got:during").await;
    assert!(
        began.elapsed() < Duration::from_secs(20),
        "the session waited {:?}",
        began.elapsed()
    );
    terminal.settle().await;
    assert_eq!(terminal.got_lines(), ["got:before", "got:during"]);
}

// The move to a spare happens while the user types and the shell answers. Every line must arrive
// once and in order, whether it was typed before the stream went silent, while it was silent, or
// after the move.
#[tokio::test]
async fn typing_through_the_move_to_a_spare_loses_and_repeats_no_line() {
    let client_id = Identity::generate();
    let server = start_server(ECHO_LINES, client_id.fingerprint());
    let proxy = start_tcp_proxy(server.tcp_addr).await;
    let mut terminal = start_client_tcp(&server, client_id, proxy.addr, Duration::from_secs(60));

    // 100 lines, 100 ms apart: the stream goes silent at line 20 and the spare takes over a few
    // seconds later, in the middle of the typing.
    for i in 0..100 {
        terminal.type_line(&format!("l{i}")).await;
        if i == 20 {
            proxy.blind_the_existing();
        }
        sleep(Duration::from_millis(100)).await;
    }
    terminal.wait_for("got:l99").await;
    terminal.settle().await;

    let expected: Vec<String> = (0..100).map(|i| format!("got:l{i}")).collect();
    assert_eq!(terminal.got_lines(), expected);
    assert!(
        proxy.made.load(Ordering::Relaxed) >= 2,
        "the spare connection was never made"
    );
}

// The same for output: a job that prints all the time while the stream goes silent and the spare
// takes over. Nothing the job wrote may be missing or twice.
#[tokio::test]
async fn output_through_the_move_to_a_spare_loses_and_repeats_no_line() {
    let client_id = Identity::generate();
    let server = start_server(
        "stty -opost -echo; i=1; while [ $i -le 200 ]; do echo out$i; i=$((i+1)); sleep 0.05; done; echo FINISHED; read x",
        client_id.fingerprint(),
    );
    let proxy = start_tcp_proxy(server.tcp_addr).await;
    let mut terminal = start_client_tcp(&server, client_id, proxy.addr, Duration::from_secs(60));

    terminal.wait_for("out20").await;
    proxy.blind_the_existing();
    terminal.wait_for("FINISHED").await;
    terminal.settle().await;

    let lines: Vec<&str> = terminal
        .seen
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("out"))
        .collect();
    let expected: Vec<String> = (1..=200).map(|i| format!("out{i}")).collect();
    assert_eq!(lines, expected);
    assert!(proxy.made.load(Ordering::Relaxed) >= 2, "no spare was made");
}

// The old connection is not dead, only slow: what it carries arrives late, after the spare has
// taken over. The server must ignore the late input of the old connection, and the client must
// not see the late output twice.
#[tokio::test]
async fn an_old_connection_that_delivers_late_does_not_repeat_a_line() {
    let client_id = Identity::generate();
    let server = start_server(ECHO_LINES, client_id.fingerprint());
    let proxy = start_tcp_proxy(server.tcp_addr).await;
    let mut terminal = start_client_tcp(&server, client_id, proxy.addr, Duration::from_secs(60));

    // the old connection holds back everything from line 20 on. The spare takes over a few
    // seconds later, and the old connection is let go at line 70, when its input and its output
    // arrive late.
    for i in 0..100 {
        terminal.type_line(&format!("l{i}")).await;
        if i == 20 {
            proxy.hold_the_existing();
        }
        if i == 70 {
            assert!(
                proxy.made.load(Ordering::Relaxed) >= 2,
                "the spare had not taken over"
            );
            proxy.release_the_held();
        }
        sleep(Duration::from_millis(100)).await;
    }
    terminal.wait_for("got:l99").await;
    terminal.settle().await;

    let expected: Vec<String> = (0..100).map(|i| format!("got:l{i}")).collect();
    assert_eq!(terminal.got_lines(), expected);
}

// The server is heard, but it hears nothing: a job prints all the time, so the stream is never
// silent, and what the user types does not arrive. The client sees that its input and its pings
// stay unanswered, opens a spare, and moves to it.
#[tokio::test]
async fn a_stream_that_works_in_one_direction_only_is_replaced_by_a_spare() {
    let client_id = Identity::generate();
    let server = start_server(
        "stty -opost -echo; (while true; do echo tick; sleep 0.2; done) & while read l; do echo \"got:$l\"; done",
        client_id.fingerprint(),
    );
    let proxy = start_tcp_proxy(server.tcp_addr).await;
    let mut terminal = start_client_tcp(&server, client_id, proxy.addr, Duration::from_secs(60));
    terminal.type_line("before").await;
    terminal.wait_for("got:before").await;

    proxy.blind_the_upstream_of_the_existing();
    terminal.type_line("during").await;
    let began = std::time::Instant::now();
    terminal.wait_for("got:during").await;
    assert!(
        began.elapsed() < Duration::from_secs(20),
        "the input waited {:?}",
        began.elapsed()
    );
    assert!(proxy.made.load(Ordering::Relaxed) >= 2, "no spare was made");
}

// A terminal that reads nothing for a while is a client that is too slow. The job must not wait
// for it. When the terminal reads again, the client shows how much it missed, and the end of the
// output is intact.
#[tokio::test]
async fn a_client_that_is_too_slow_does_not_hold_the_job_up_and_shows_what_it_missed() {
    let marker = std::path::PathBuf::from(format!("/tmp/ssjt-slow-{}", std::process::id()));
    let _ = std::fs::remove_file(&marker);
    let script = format!(
        "stty -opost -echo; awk 'BEGIN {{ for (i = 1; i <= 3000000; i++) print i }}'; echo FINISHED; touch {}; read x",
        marker.display()
    );
    let client_id = Identity::generate();
    let server = start_server_with(
        &script,
        client_id.fingerprint(),
        4 * 1024 * 1024,
        ssj_server::session::SlowClient::Drop,
        64 * 1024,
    );
    let mut terminal = start_client(&server, client_id);

    // the terminal reads nothing, and the job ends all the same.
    timeout(Duration::from_secs(60), async {
        while !marker.exists() {
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the job waited for the slow client");

    terminal.wait_for("FINISHED").await;
    assert!(
        terminal.seen.contains("bytes of output were dropped"),
        "no notice of the skipped output"
    );
    let _ = std::fs::remove_file(&marker);
}

// compressed output goes through the real client and reaches the terminal exactly as written,
// every line in its place.
#[tokio::test]
async fn compressed_output_reaches_the_terminal_intact() {
    let script = "stty -opost -echo; awk 'BEGIN { for (i = 1; i <= 50000; i++) print \"line \" i \" of the build log\" }'; echo FINISHED; read x";
    let client_id = Identity::generate();
    let server = start_server_full(
        script,
        client_id.fingerprint(),
        4 * 1024 * 1024,
        ssj_server::session::SlowClient::Wait,
        1 << 20,
        true,
    );
    let mut terminal = start_client(&server, client_id);
    // a terminal that reads late makes the link the limit.
    sleep(Duration::from_secs(1)).await;
    terminal.wait_for("FINISHED").await;
    let expected: String = (1..=50_000)
        .map(|i| format!("line {i} of the build log\n"))
        .collect();
    assert!(
        terminal.seen.starts_with(&expected),
        "the output differs from what the shell wrote (got {} bytes, expected {})",
        terminal.seen.len(),
        expected.len()
    );
}

/// QUIC first and TCP behind it, as `ssj` has them when the host offers both.
fn start_client_udp_and_tcp(
    server: &Server,
    identity: Identity,
    udp: SocketAddr,
    tcp: SocketAddr,
) -> Terminal {
    let dial = tcp_dial(server, &identity, tcp);
    start_client_tiers(
        server,
        identity,
        vec![
            Tier::Udp {
                addr: udp,
                resolver: None,
            },
            Tier::Stream { name: "tcp", dial },
        ],
        Duration::from_secs(8),
        ssj_client::run::STREAM_DEAD_AFTER,
    )
}

// with UDP blocked, the first connection must not wait for QUIC to give up: TCP starts after a
// short head start, and the first connection that opens wins.
#[tokio::test]
async fn tcp_takes_over_at_once_when_udp_gets_no_answer() {
    let client_id = Identity::generate();
    let server = start_server(ECHO_LINES, client_id.fingerprint());
    let proxy = start_proxy(server.addr).await;
    proxy.drop_replies.store(true, Ordering::Relaxed);
    let begun = std::time::Instant::now();
    let mut terminal = start_client_udp_and_tcp(&server, client_id, proxy.addr, server.tcp_addr);
    terminal.type_line("one").await;
    terminal.wait_for("got:one").await;
    assert!(
        begun.elapsed() < Duration::from_millis(2500),
        "the first line took {:?}",
        begun.elapsed()
    );
    terminal.settle().await;
    assert_eq!(terminal.got_lines(), ["got:one"]);
}

// after a change of the network that left UDP dead, the new connection must not spend the time
// of a whole QUIC attempt before TCP is tried.
#[tokio::test]
async fn after_a_change_that_kills_udp_tcp_carries_the_session_within_seconds() {
    let client_id = Identity::generate();
    let server = start_server(ECHO_LINES, client_id.fingerprint());
    let proxy = start_proxy(server.addr).await;
    let mut terminal = start_client_udp_and_tcp(&server, client_id, proxy.addr, server.tcp_addr);
    terminal.type_line("one").await;
    terminal.wait_for("got:one").await;

    // the path is dead for QUIC, and the client is told that the network changed.
    proxy.drop_replies.store(true, Ordering::Relaxed);
    terminal.type_line("two").await;
    let changed = std::time::Instant::now();
    terminal.net.send(Cause::NetworkChanged).unwrap();
    terminal.wait_for("got:two").await;
    assert!(
        changed.elapsed() < Duration::from_millis(4000),
        "the session needed {:?}",
        changed.elapsed()
    );
    terminal.settle().await;
    assert_eq!(terminal.got_lines(), ["got:one", "got:two"]);
}

// A session on TCP moves to QUIC when a change of the network brings a path where QUIC works.
#[tokio::test]
async fn a_session_on_tcp_moves_to_quic_when_the_network_changes_and_quic_works() {
    let client_id = Identity::generate();
    let server = start_server(ECHO_LINES, client_id.fingerprint());
    let udp = start_proxy(server.addr).await;
    let tcp = start_tcp_proxy(server.tcp_addr).await;
    udp.drop_replies.store(true, Ordering::Relaxed);
    let mut terminal = start_client_udp_and_tcp(&server, client_id, udp.addr, tcp.addr);
    terminal.type_line("one").await;
    terminal.wait_for("got:one").await;

    // the faster network appears.
    udp.drop_replies.store(false, Ordering::Relaxed);
    terminal.net.send(Cause::NetworkChanged).unwrap();
    sleep(Duration::from_millis(2500)).await;

    // a session still on TCP would lose its connection now and say so.
    tcp.kill.send_modify(|generation| *generation += 1);
    terminal.type_line("two").await;
    terminal.wait_for("got:two").await;
    terminal.settle().await;
    assert_eq!(terminal.got_lines(), ["got:one", "got:two"]);
    assert!(
        !terminal.status().iter().any(|s| s.contains("reconnecting")),
        "{:?}",
        terminal.status()
    );
}
