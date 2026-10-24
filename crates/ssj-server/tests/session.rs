use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

use ssj_proto::{
    ClientFrame, Env, EnvFilter, ErrorCode, ExitStatus, Hello, ServerFrame, SessionId, WindowSize,
    decode_server,
};
use ssj_server::backend::Direct;
use ssj_server::session::{
    Connection, Session, SessionCommand, SessionConfig, SessionEnd, SessionEvent, SpawnTemplate,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, ReadHalf, WriteHalf};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::timeout;

fn size() -> WindowSize {
    WindowSize::new(24, 80).unwrap()
}

fn config(script: &str) -> SessionConfig {
    SessionConfig {
        id: SessionId::parse("abcdef012345").unwrap(),
        template: SpawnTemplate {
            program: "/bin/sh".into(),
            args: vec!["-c".into(), script.into()],
            env: vec![(OsString::from("PATH"), OsString::from("/usr/bin:/bin"))],
            cwd: None,
        },
        accept_env: EnvFilter::default_patterns(),
        replay_capacity: 64 * 1024,
        away_after: Duration::from_secs(30),
        detached_timeout: None,
        max_detached: None,
        hello_timeout: Duration::from_secs(2),
        lost_after: Duration::from_secs(60),
        exit_grace: Duration::from_secs(60),
        slow_client: ssj_server::session::SlowClient::Wait,
        live_backlog: 1 << 20,
        compress: false,
        agent_socket: None,
        prestart: None,
        first_client_timeout: Duration::from_secs(3600),
    }
}

struct Harness {
    conns: mpsc::Sender<Connection>,
    session: JoinHandle<SessionEnd>,
}

fn start(config: SessionConfig) -> Harness {
    let (conns, rx) = mpsc::channel(4);
    let session = tokio::spawn(Session::new(Direct, config).run(rx));
    Harness { conns, session }
}

struct Client {
    reader: ReadHalf<DuplexStream>,
    writer: WriteHalf<DuplexStream>,
    buf: Vec<u8>,
    /// How many frames arrived compressed. They are inflated in `next`, like a client does.
    compressed: usize,
}

#[derive(Default, Debug)]
struct Seen {
    output: Vec<u8>,
    input_acks: Vec<u64>,
    exit: Option<ExitStatus>,
    error: Option<ErrorCode>,
    welcome: Option<ssj_proto::Welcome>,
    closed: bool,
    pongs: usize,
    gaps: Vec<u64>,
    detached: bool,
    /// Frames of the agent channels, in the order they came.
    agent: Vec<ServerFrame>,
}

impl Harness {
    async fn connect(&self) -> Client {
        let (client_end, server_end) = tokio::io::duplex(64 * 1024);
        let (server_reader, server_writer) = tokio::io::split(server_end);
        self.conns
            .send(Connection {
                reader: Box::new(server_reader),
                writer: Box::new(server_writer),
            })
            .await
            .unwrap();
        let (reader, writer) = tokio::io::split(client_end);
        Client {
            reader,
            writer,
            buf: Vec::new(),
            compressed: 0,
        }
    }

    async fn end(self) -> SessionEnd {
        timeout(Duration::from_secs(10), self.session)
            .await
            .unwrap()
            .unwrap()
    }
}

impl Client {
    async fn send(&mut self, frame: ClientFrame) {
        let mut bytes = Vec::new();
        frame.encode(&mut bytes).unwrap();
        self.writer.write_all(&bytes).await.unwrap();
    }

    async fn send_raw(&mut self, bytes: &[u8]) {
        self.writer.write_all(bytes).await.unwrap();
    }

    /// Next frame, or `None` when the server closed the connection.
    async fn next(&mut self) -> Option<ServerFrame> {
        loop {
            if let Some((frame, used)) = decode_server(&self.buf).expect("server sent a bad frame")
            {
                self.buf.drain(..used);
                return Some(match frame {
                    ServerFrame::Compressed(packed) => {
                        self.compressed += 1;
                        ServerFrame::Output(
                            ssj_proto::compress::inflate(&packed)
                                .expect("a valid compressed frame"),
                        )
                    }
                    other => other,
                });
            }
            let mut chunk = [0u8; 8192];
            match timeout(Duration::from_secs(10), self.reader.read(&mut chunk))
                .await
                .expect("timed out")
            {
                Ok(0) | Err(_) => return None,
                Ok(n) => self.buf.extend_from_slice(&chunk[..n]),
            }
        }
    }

    /// Reads frames until `done` is true for what was seen so far or the connection closes.
    async fn read_until(&mut self, mut done: impl FnMut(&Seen) -> bool) -> Seen {
        let mut seen = Seen::default();
        while !done(&seen) {
            match self.next().await {
                None => {
                    seen.closed = true;
                    break;
                }
                Some(ServerFrame::Output(data)) => seen.output.extend_from_slice(&data),
                Some(ServerFrame::InputAck(offset)) => seen.input_acks.push(offset),
                Some(ServerFrame::Exit(status)) => seen.exit = Some(status),
                Some(ServerFrame::Error(code)) => seen.error = Some(code),
                Some(ServerFrame::Welcome(welcome)) => seen.welcome = Some(welcome),
                Some(ServerFrame::Pong) => seen.pongs += 1,
                Some(ServerFrame::Gap(skipped)) => seen.gaps.push(skipped),
                Some(ServerFrame::Detached) => seen.detached = true,
                Some(
                    frame @ (ServerFrame::AgentOpen(_)
                    | ServerFrame::Agent(..)
                    | ServerFrame::AgentClose(_)),
                ) => seen.agent.push(frame),
                // inflated by `next`
                Some(ServerFrame::Compressed(_)) => unreachable!("inflated in next"),
            }
        }
        seen
    }

    async fn start(&mut self) -> ssj_proto::Welcome {
        self.start_with(Env::default()).await
    }

    async fn start_with(&mut self, env: Env) -> ssj_proto::Welcome {
        self.send(ClientFrame::Hello(Hello::Start {
            size: size(),
            env,
            agent: false,
        }))
        .await;
        self.read_until(|s| s.welcome.is_some())
            .await
            .welcome
            .expect("welcome")
    }
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|w| w == needle.as_bytes())
}

#[tokio::test]
async fn shell_input_output_and_exit_code_travel_through_the_session() {
    let harness = start(config("read x; echo got:$x; exit 4"));
    let mut client = harness.connect().await;
    let welcome = client.start().await;
    assert_eq!((welcome.input_offset, welcome.output_offset), (0, 0));

    client.send(ClientFrame::Input(b"hello\n".to_vec())).await;
    let seen = client.read_until(|s| s.exit.is_some()).await;

    assert!(
        contains(&seen.output, "got:hello"),
        "{:?}",
        String::from_utf8_lossy(&seen.output)
    );
    assert_eq!(seen.input_acks.last(), Some(&6));
    assert_eq!(seen.exit, Some(ExitStatus::Code(4)));

    client.send(ClientFrame::Close).await;
    assert!(
        matches!(harness.end().await, SessionEnd::ShellExited(status) if status.code() == Some(4))
    );
}

#[tokio::test]
async fn resuming_after_a_lost_connection_has_no_gap_and_no_duplicate() {
    let script = "i=0; while [ $i -lt 3000 ]; do echo line$i; i=$((i+1)); done; sleep 1";
    let expected: Vec<u8> = (0..3000)
        .flat_map(|i| format!("line{i}\r\n").into_bytes())
        .collect();
    let harness = start(config(script));

    let mut first = harness.connect().await;
    first.start().await;
    let part = first.read_until(|s| s.output.len() >= 5000).await;
    let seen = part.output.len() as u64;
    assert!(seen < expected.len() as u64);
    drop(first);

    let mut second = harness.connect().await;
    second
        .send(ClientFrame::Hello(Hello::Resume {
            size: size(),
            output_offset: seen,
        }))
        .await;
    let rest = second.read_until(|s| s.exit.is_some()).await;

    assert_eq!(rest.welcome.unwrap().output_offset, seen);
    let (first_part, gaps) = (part.output.len(), rest.gaps);
    let got = [part.output, rest.output].concat();
    // on a mismatch, show where it starts and not the thousands of bytes.
    let at = got.iter().zip(&expected).position(|(a, b)| a != b);
    assert!(
        got == expected,
        "differs at {at:?} (first connection {first_part} bytes, gaps {gaps:?}, got {} of {} \
         bytes): got {:?}, expected {:?}",
        got.len(),
        expected.len(),
        String::from_utf8_lossy(
            &got[at.unwrap_or(0).saturating_sub(20)..got.len().min(at.unwrap_or(0) + 40)]
        ),
        String::from_utf8_lossy(
            &expected[at.unwrap_or(0).saturating_sub(20)..expected.len().min(at.unwrap_or(0) + 40)]
        ),
    );
}

// A program that echoes while it receives a large paste: if reading output and writing input
// ever waited for each other, this would hang.
#[tokio::test]
async fn large_paste_into_a_chatty_program_does_not_deadlock() {
    let mut cfg = config("cat");
    cfg.replay_capacity = 16 * 1024;
    let harness = start(cfg);
    let mut client = harness.connect().await;
    client.start().await;

    const LINES: usize = 12_000;
    let line = format!("{}\n", "x".repeat(79));
    let total_input = (LINES * line.len()) as u64;

    let Client {
        mut reader,
        writer,
        mut buf,
        ..
    } = client;
    let writer = std::sync::Arc::new(tokio::sync::Mutex::new(writer));
    let paste_writer = writer.clone();
    let sender = tokio::spawn(async move {
        for _ in 0..LINES / 400 {
            let mut bytes = Vec::new();
            ClientFrame::Input(line.repeat(400).into_bytes())
                .encode(&mut bytes)
                .unwrap();
            paste_writer.lock().await.write_all(&bytes).await.unwrap();
        }
    });

    // read and acknowledge output until the server has consumed the whole paste.
    let (mut received, mut acked_input) = (0u64, 0u64);
    timeout(Duration::from_secs(60), async {
        let mut chunk = [0u8; 16 * 1024];
        while acked_input < total_input {
            let n = reader.read(&mut chunk).await.unwrap();
            assert!(n > 0, "server closed the connection");
            buf.extend_from_slice(&chunk[..n]);
            while let Some((frame, used)) = decode_server(&buf).unwrap() {
                buf.drain(..used);
                match frame {
                    ServerFrame::Output(data) => received += data.len() as u64,
                    ServerFrame::InputAck(offset) => acked_input = offset,
                    _ => {}
                }
            }
            let mut bytes = Vec::new();
            ClientFrame::OutputAck(received).encode(&mut bytes).unwrap();
            writer.lock().await.write_all(&bytes).await.unwrap();
        }
    })
    .await
    .expect("the session stopped moving data");
    sender.await.unwrap();

    assert_eq!(acked_input, total_input);
    assert!(
        received > total_input,
        "the shell echoed less than it was given"
    );
}

#[tokio::test]
async fn new_connection_takes_over_from_the_old_one() {
    let harness = start(config("cat"));
    let mut old = harness.connect().await;
    old.start().await;

    let mut new = harness.connect().await;
    new.send(ClientFrame::Hello(Hello::Attach { size: size() }))
        .await;
    new.read_until(|s| s.welcome.is_some()).await;

    // the old connection is closed, the new one drives the same shell.
    let old_end = old.read_until(|_| false).await;
    assert!(old_end.closed);
    new.send(ClientFrame::Input(b"ping\n".to_vec())).await;
    let seen = new.read_until(|s| contains(&s.output, "ping")).await;
    assert!(contains(&seen.output, "ping"));
}

#[tokio::test]
async fn broken_clients_lose_their_connection_but_not_the_session() {
    let harness = start(config("cat"));
    let mut owner = harness.connect().await;
    owner.start().await;
    drop(owner);

    let hello = ClientFrame::Hello(Hello::Attach { size: size() });
    let mut oversized = 0xffff_ffffu32.to_be_bytes().to_vec();
    oversized.push(0x02);
    let cases: Vec<(&str, Vec<ClientFrame>, Vec<u8>, ErrorCode)> = vec![
        (
            "garbage before hello",
            vec![],
            b"\xff\xff\xff\xff garbage".to_vec(),
            ErrorCode::BadHello,
        ),
        (
            "input before hello",
            vec![ClientFrame::Input(b"x".to_vec())],
            vec![],
            ErrorCode::BadHello,
        ),
        (
            "second hello",
            vec![hello.clone(), hello.clone()],
            vec![],
            ErrorCode::Violation,
        ),
        (
            "ack of unsent output",
            vec![hello.clone(), ClientFrame::OutputAck(u64::MAX)],
            vec![],
            ErrorCode::Violation,
        ),
        (
            "oversized frame",
            vec![hello.clone()],
            oversized,
            ErrorCode::Violation,
        ),
    ];
    for (name, frames, raw, code) in cases {
        let mut bad = harness.connect().await;
        for frame in frames {
            bad.send(frame).await;
        }
        bad.send_raw(&raw).await;
        let seen = bad.read_until(|_| false).await;
        assert_eq!(seen.error, Some(code), "{name}");
        assert!(seen.closed, "{name}");
    }

    let mut good = harness.connect().await;
    good.send(ClientFrame::Hello(Hello::Attach { size: size() }))
        .await;
    good.send(ClientFrame::Input(b"still alive\n".to_vec()))
        .await;
    let seen = good
        .read_until(|s| contains(&s.output, "still alive"))
        .await;
    assert!(contains(&seen.output, "still alive"));
}

// A second connection that has not said hello (a spare that is still opening, or a client that
// connects and stays silent) does not end the working connection.
#[tokio::test]
async fn a_connection_without_a_hello_does_not_replace_the_working_one() {
    let mut cfg = config("cat");
    cfg.hello_timeout = Duration::from_millis(500);
    let harness = start(cfg);
    let mut working = harness.connect().await;
    working.start().await;

    let mut silent = harness.connect().await;
    working
        .send(ClientFrame::Input(b"still here\n".to_vec()))
        .await;
    let seen = working
        .read_until(|s| contains(&s.output, "still here"))
        .await;
    assert!(contains(&seen.output, "still here"), "{:?}", seen.error);
    assert!(!seen.closed);

    // the silent one is sent away after the hello timeout, and the working one goes on.
    let gone = silent.read_until(|_| false).await;
    assert_eq!(gone.error, Some(ErrorCode::BadHello));
    working
        .send(ClientFrame::Input(b"and again\n".to_vec()))
        .await;
    let seen = working
        .read_until(|s| contains(&s.output, "and again"))
        .await;
    assert!(contains(&seen.output, "and again"));
}

#[tokio::test]
async fn hello_must_arrive_in_time() {
    let mut cfg = config("cat");
    cfg.hello_timeout = Duration::from_millis(300);
    let harness = start(cfg);
    let mut silent = harness.connect().await;

    let seen = silent.read_until(|_| false).await;

    assert_eq!(seen.error, Some(ErrorCode::BadHello));
    assert!(seen.closed);
}

#[tokio::test]
async fn only_accepted_client_variables_reach_the_shell() {
    let harness = start(config("env"));
    let mut client = harness.connect().await;
    let env = Env::new(vec![
        ("TERM".into(), "xterm-test".into()),
        ("LD_PRELOAD".into(), "/tmp/evil.so".into()),
        ("FOO".into(), "bar".into()),
    ])
    .unwrap();
    client.start_with(env).await;

    let seen = client.read_until(|s| s.exit.is_some()).await;
    let text = String::from_utf8_lossy(&seen.output);

    assert!(text.contains("TERM=xterm-test"), "{text}");
    assert!(!text.contains("LD_PRELOAD="), "{text}");
    assert!(!text.contains("FOO=bar"), "{text}");
    // and the user is told which ones were left out, before the output of the shell.
    let notice =
        "ssj: the host does not accept LD_PRELOAD, FOO (accept_env in its server.toml)\r\n";
    assert!(text.starts_with(notice), "{text}");
}

#[tokio::test]
async fn nothing_is_said_when_the_host_takes_all_variables() {
    let harness = start(config("echo ready"));
    let mut client = harness.connect().await;
    let env = Env::new(vec![
        ("TERM".into(), "xterm-test".into()),
        ("LC_THEME".into(), "dark".into()),
    ])
    .unwrap();
    client.start_with(env).await;

    let seen = client.read_until(|s| s.exit.is_some()).await;

    assert_eq!(String::from_utf8_lossy(&seen.output), "ready\r\n");
}

#[tokio::test]
async fn exit_while_disconnected_is_reported_after_the_client_returns() {
    let harness = start(config("printf done; exit 5"));
    let mut first = harness.connect().await;
    first.start().await;
    drop(first);
    tokio::time::sleep(Duration::from_millis(500)).await;

    let mut second = harness.connect().await;
    second
        .send(ClientFrame::Hello(Hello::Resume {
            size: size(),
            output_offset: 0,
        }))
        .await;
    let seen = second.read_until(|s| s.exit.is_some()).await;

    assert!(contains(&seen.output, "done"));
    assert_eq!(seen.exit, Some(ExitStatus::Code(5)));
    second.send(ClientFrame::Close).await;
    assert!(
        matches!(harness.end().await, SessionEnd::ShellExited(status) if status.code() == Some(5))
    );
}

// A client that never acknowledges must not make the server buffer without limit.
#[tokio::test]
async fn unacknowledged_output_is_capped_by_the_replay_buffer() {
    let mut cfg = config("yes");
    cfg.replay_capacity = 8 * 1024;
    let harness = start(cfg);
    let mut client = harness.connect().await;
    client.start().await;

    let mut total = 0usize;
    let _ = timeout(Duration::from_secs(1), async {
        loop {
            match client.next().await {
                Some(ServerFrame::Output(data)) => total += data.len(),
                Some(_) => {}
                None => break,
            }
        }
    })
    .await;

    // fixed numbers on purpose: the cap must not move together with the configured capacity.
    assert!(
        total <= 8 * 1024,
        "{total} bytes arrived without any acknowledgement"
    );
    assert!(total >= 4 * 1024, "only {total} bytes arrived");
}

#[tokio::test]
async fn detached_session_ends_after_the_timeout() {
    let mut cfg = config("cat");
    cfg.detached_timeout = Some(Duration::from_millis(300));

    // never connected
    let harness = start(cfg.clone());
    assert!(matches!(harness.end().await, SessionEnd::DetachedTimeout));

    // connected, then lost
    let harness = start(cfg);
    let mut client = harness.connect().await;
    client.start().await;
    drop(client);
    assert!(matches!(harness.end().await, SessionEnd::DetachedTimeout));
}

#[tokio::test]
async fn deliberate_detach_disables_the_timeout_until_the_next_connection() {
    let mut cfg = config("cat");
    cfg.detached_timeout = Some(Duration::from_millis(300));
    let (events_tx, mut events) = mpsc::unbounded_channel();
    let (conns, rx) = mpsc::channel(4);
    let mut session = tokio::spawn(Session::new(Direct, cfg).with_events(events_tx).run(rx));
    let harness = Harness {
        conns,
        session: tokio::spawn(async { SessionEnd::Closed }),
    };

    let mut client = harness.connect().await;
    client.start().await;
    client.send(ClientFrame::Detach).await;
    assert_eq!(next_event(&mut events).await, SessionEvent::Connected);
    assert_eq!(next_event(&mut events).await, SessionEvent::Detached);

    // several times the timeout later the session still runs.
    assert!(
        timeout(Duration::from_millis(1200), &mut session)
            .await
            .is_err()
    );

    // a new client attaches and uses the same shell.
    let mut again = harness.connect().await;
    again
        .send(ClientFrame::Hello(Hello::Attach { size: size() }))
        .await;
    again.send(ClientFrame::Input(b"back\n".to_vec())).await;
    again.read_until(|s| contains(&s.output, "back")).await;

    // an involuntary loss brings the timeout back.
    drop(again);
    let end = timeout(Duration::from_secs(5), session)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(end, SessionEnd::DetachedTimeout));
}

// the answer must not wait for the shell: the point of a ping is to show that the path works
// while the shell is busy or stuck.
#[tokio::test]
async fn ping_is_answered_while_the_shell_is_stuck() {
    let harness = start(config("sleep 30"));
    let mut client = harness.connect().await;
    client.start().await;

    // pings that arrive together may share one pong, so each ping waits for its answer.
    for _ in 0..2 {
        client.send(ClientFrame::Ping).await;
        let seen = client.read_until(|s| s.pongs >= 1).await;
        assert_eq!(seen.pongs, 1);
    }
}

async fn next_event(events: &mut mpsc::UnboundedReceiver<SessionEvent>) -> SessionEvent {
    timeout(Duration::from_secs(5), events.recv())
        .await
        .unwrap()
        .unwrap()
}

#[tokio::test]
async fn events_follow_the_state_of_the_client() {
    let (events_tx, mut events) = mpsc::unbounded_channel();
    let (conns, rx) = mpsc::channel(4);
    let _session = tokio::spawn(
        Session::new(Direct, config("cat"))
            .with_events(events_tx)
            .run(rx),
    );
    let harness = Harness {
        conns,
        session: tokio::spawn(async { SessionEnd::Closed }),
    };

    // a connection that never completes its hello is not reported.
    let mut bad = harness.connect().await;
    bad.send_raw(b"\xff\xff\xff\xff garbage").await;
    bad.read_until(|_| false).await;

    let mut client = harness.connect().await;
    client.start().await;
    assert_eq!(next_event(&mut events).await, SessionEvent::Connected);

    drop(client);
    assert_eq!(next_event(&mut events).await, SessionEvent::Disconnected);

    let mut again = harness.connect().await;
    again
        .send(ClientFrame::Hello(Hello::Attach { size: size() }))
        .await;
    assert_eq!(next_event(&mut events).await, SessionEvent::Connected);
    again.send(ClientFrame::Detach).await;
    // a deliberate detach is its own event and not also a loss.
    assert_eq!(next_event(&mut events).await, SessionEvent::Detached);
}

#[tokio::test]
async fn the_detach_command_tells_the_client_to_leave_and_the_shell_keeps_running() {
    let mut cfg = config("cat");
    cfg.detached_timeout = Some(Duration::from_millis(300));
    let (commands, commands_rx) = mpsc::unbounded_channel();
    let (events_tx, mut events) = mpsc::unbounded_channel();
    let (conns, rx) = mpsc::channel(4);
    let mut session = tokio::spawn(
        Session::new(Direct, cfg)
            .with_commands(commands_rx)
            .with_events(events_tx)
            .run(rx),
    );
    let harness = Harness {
        conns,
        session: tokio::spawn(async { SessionEnd::Closed }),
    };
    let mut client = harness.connect().await;
    client.start().await;
    assert_eq!(next_event(&mut events).await, SessionEvent::Connected);

    commands.send(SessionCommand::Detach).unwrap();
    let seen = client.read_until(|s| s.detached).await;
    assert!(seen.detached);
    assert_eq!(next_event(&mut events).await, SessionEvent::Detached);

    // on purpose, so the timeout does not apply, and the shell is still there.
    assert!(
        timeout(Duration::from_millis(1200), &mut session)
            .await
            .is_err()
    );
    let mut again = harness.connect().await;
    again
        .send(ClientFrame::Hello(Hello::Attach { size: size() }))
        .await;
    let seen = again.read_until(|s| s.welcome.is_some()).await;
    assert!(seen.welcome.is_some());
}

#[tokio::test]
async fn an_attach_makes_the_program_redraw_by_changing_the_size_and_back() {
    // the shell reports the size at every SIGWINCH, and sees one within 10 ms: the server waits
    // 60 ms between the two sizes, and two signals that come before the shell looks are one.
    // The output is longer than the replay buffer, so the replay cannot draw the screen.
    let script = "trap 'echo size:$(stty size)' WINCH; head -c 20000 /dev/zero | tr '\\0' x; echo; \
        echo ready; while true; do sleep 0.01; done";
    let mut cfg = config(script);
    cfg.replay_capacity = 8 * 1024;
    // the test client does not acknowledge, so the job must not wait for it.
    cfg.slow_client = ssj_server::session::SlowClient::Drop;
    let (conns, rx) = mpsc::channel(4);
    let session = tokio::spawn(Session::new(Direct, cfg).run(rx));
    let harness = Harness {
        conns,
        session: tokio::spawn(async { SessionEnd::Closed }),
    };
    let mut first = harness.connect().await;
    first.start().await;
    first.read_until(|s| contains(&s.output, "ready")).await;
    first.send(ClientFrame::Detach).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    // the same size as before: only the narrower size in between makes the program notice.
    let mut second = harness.connect().await;
    second
        .send(ClientFrame::Hello(Hello::Attach { size: size() }))
        .await;
    let seen = second
        .read_until(|s| contains(&s.output, "size:24 80"))
        .await;
    let text = String::from_utf8_lossy(&seen.output).into_owned();
    assert!(text.contains("size:24 79"), "{text:?}");
    assert!(
        text.find("size:24 79") < text.find("size:24 80"),
        "{text:?}"
    );
    session.abort();
}

// the replay of all the output draws the screen, so an attach does not wait for a redraw.
#[tokio::test]
async fn an_attach_to_a_session_with_all_its_output_gets_the_welcome_at_once() {
    let script = "echo ready; while true; do sleep 0.01; done";
    let (conns, rx) = mpsc::channel(4);
    let session = tokio::spawn(Session::new(Direct, config(script)).run(rx));
    let harness = Harness {
        conns,
        session: tokio::spawn(async { SessionEnd::Closed }),
    };
    let mut first = harness.connect().await;
    first.start().await;
    first.read_until(|s| contains(&s.output, "ready")).await;
    first.send(ClientFrame::Detach).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    let mut second = harness.connect().await;
    let asked = std::time::Instant::now();
    second
        .send(ClientFrame::Hello(Hello::Attach { size: size() }))
        .await;
    let seen = second.read_until(|s| s.welcome.is_some()).await;
    assert!(seen.welcome.is_some());
    assert!(
        asked.elapsed() < Duration::from_millis(50),
        "{:?}",
        asked.elapsed()
    );
    session.abort();
}

#[tokio::test]
async fn kill_hangs_up_the_shell_and_tells_the_client() {
    let (commands, commands_rx) = mpsc::unbounded_channel();
    let (conns, rx) = mpsc::channel(4);
    let session = tokio::spawn(
        Session::new(Direct, config("sleep 60"))
            .with_commands(commands_rx)
            .run(rx),
    );
    let harness = Harness {
        conns,
        session: tokio::spawn(async { SessionEnd::Closed }),
    };
    let mut client = harness.connect().await;
    client.start().await;

    let started = std::time::Instant::now();
    commands.send(SessionCommand::Kill).unwrap();
    let seen = client.read_until(|s| s.exit.is_some()).await;

    // SIGHUP from the closing terminal, not the five seconds of patience.
    assert_eq!(seen.exit, Some(ExitStatus::Signal(1)));
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "{:?}",
        started.elapsed()
    );
    let end = timeout(Duration::from_secs(10), session)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(end, SessionEnd::Killed));
}

#[tokio::test]
async fn kill_works_without_a_client_and_without_a_shell() {
    for connect_first in [false, true] {
        let (commands, commands_rx) = mpsc::unbounded_channel();
        let (conns, rx) = mpsc::channel(4);
        let session = tokio::spawn(
            Session::new(Direct, config("cat"))
                .with_commands(commands_rx)
                .run(rx),
        );
        let harness = Harness {
            conns,
            session: tokio::spawn(async { SessionEnd::Closed }),
        };
        let _client = if connect_first {
            let mut client = harness.connect().await;
            client.start().await;
            Some(client)
        } else {
            None
        };
        commands.send(SessionCommand::Kill).unwrap();
        let end = timeout(Duration::from_secs(10), session)
            .await
            .unwrap()
            .unwrap();
        assert!(
            matches!(end, SessionEnd::Killed),
            "connect_first={connect_first}"
        );
    }
}

#[tokio::test]
async fn max_detached_limits_a_deliberate_detach_and_not_a_loss() {
    // no timeout for lost connections, a short limit for deliberate detaches.
    let mut cfg = config("cat");
    cfg.detached_timeout = None;
    cfg.max_detached = Some(Duration::from_millis(400));

    let harness = start(cfg.clone());
    let mut client = harness.connect().await;
    client.start().await;
    drop(client);
    // the loss is not limited.
    assert!(
        timeout(Duration::from_millis(1200), harness.session)
            .await
            .is_err()
    );

    let harness = start(cfg);
    let mut client = harness.connect().await;
    client.start().await;
    client.send(ClientFrame::Detach).await;
    assert!(matches!(harness.end().await, SessionEnd::DetachedTimeout));
}

const JOB_LINES: u32 = 1_500_000;
const REPLAY: usize = 64 * 1024;

/// What the job (`awk` counting up to 1500000, then `DONE`) writes into the terminal.
///
/// The job turns off the output processing of the terminal. Otherwise the driver of macOS turns
/// `\n` into `\r\n` and sometimes writes the `\r` twice when the reader is slower than the
/// writer, which is a quirk of that system and would make exact comparisons flaky.
fn job_output() -> Vec<u8> {
    let mut out = Vec::new();
    for i in 1..=JOB_LINES {
        out.extend_from_slice(format!("{i}\n").as_bytes());
    }
    out.extend_from_slice(b"DONE\n");
    out
}

/// A file that the job creates after its last line, so that a test can tell that it finished.
fn marker() -> std::path::PathBuf {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let path = std::path::PathBuf::from(format!(
        "/tmp/ssjt-job-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_file(&path);
    path
}

fn job_config(marker: &std::path::Path, replay_capacity: usize) -> SessionConfig {
    let mut cfg = config(&format!(
        "stty -opost; awk 'BEGIN {{ for (i = 1; i <= {JOB_LINES}; i++) print i }}'; echo DONE; touch {}",
        marker.display()
    ));
    cfg.replay_capacity = replay_capacity;
    cfg
}

async fn wait_for_file(path: &std::path::Path) {
    timeout(Duration::from_secs(40), async {
        while !path.exists() {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("the job did not finish: {} was not created", path.display()));
    // the last bytes are still on their way from the terminal into the buffer.
    tokio::time::sleep(Duration::from_millis(400)).await;
}

/// Reads until the shell exits and acknowledges everything like a client does. Returns the offset
/// of the welcome, the output that followed, and the exit status.
async fn drain(client: &mut Client) -> (u64, Vec<u8>, Option<ExitStatus>) {
    let (mut first, mut offset, mut out, mut exit) = (None, 0u64, Vec::new(), None);
    while let Some(frame) = client.next().await {
        match frame {
            ServerFrame::Welcome(welcome) => {
                first = Some(welcome.output_offset);
                offset = welcome.output_offset;
            }
            ServerFrame::Output(data) => {
                offset += data.len() as u64;
                out.extend_from_slice(&data);
                client.send(ClientFrame::OutputAck(offset)).await;
            }
            ServerFrame::Exit(status) => {
                exit = Some(status);
                break;
            }
            _ => {}
        }
    }
    (first.expect("a welcome"), out, exit)
}

// the job writes ten megabytes while the client is away. With backpressure it would stop after
// the first buffer full and wait for a client that is not there.
#[tokio::test]
async fn a_job_runs_to_its_end_while_no_client_is_connected() {
    let marker = marker();
    let harness = start(job_config(&marker, REPLAY));
    let mut first = harness.connect().await;
    first.start().await;
    drop(first);

    wait_for_file(&marker).await;

    let mut second = harness.connect().await;
    second
        .send(ClientFrame::Hello(Hello::Resume {
            size: size(),
            output_offset: 0,
        }))
        .await;
    let (welcome_offset, output, exit) = drain(&mut second).await;

    let expected = job_output();
    // exactly the newest buffer full is left, and the client can work out what it missed.
    assert_eq!(welcome_offset as usize, expected.len() - REPLAY);
    assert_eq!(output.len(), REPLAY);
    // no byte is missing or repeated after the gap.
    assert!(
        output == expected[welcome_offset as usize..],
        "the bytes after the gap differ"
    );
    assert_eq!(exit, Some(ExitStatus::Code(0)));
    let _ = std::fs::remove_file(&marker);
}

// an acknowledgement of output that the connection has not sent yet is a violation of the
// connection, and must not make the session fail when it sends on.
#[tokio::test]
async fn an_ack_of_output_that_was_not_sent_ends_the_connection_and_not_the_session() {
    let marker = marker();
    let harness = start(job_config(&marker, 1024 * 1024));
    let mut client = harness.connect().await;
    client.start().await;

    // the client reads nothing, so little is sent while the buffer fills up.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    client.send(ClientFrame::OutputAck(512 * 1024)).await;
    // the error frame may not fit into the full queue of this client, so only the end counts.
    let seen = client.read_until(|_| false).await;
    assert!(seen.closed);

    // the session lives: a new client attaches and gets output.
    let mut again = harness.connect().await;
    again
        .send(ClientFrame::Hello(Hello::Attach { size: size() }))
        .await;
    let seen = again.read_until(|s| !s.output.is_empty()).await;
    assert!(!seen.output.is_empty());
}

// while somebody acknowledges, nothing may be forgotten, however slow that client is.
#[tokio::test]
async fn a_connected_client_gets_backpressure_and_loses_nothing() {
    let marker = marker();
    let harness = start(job_config(&marker, REPLAY));
    let mut client = harness.connect().await;
    client.start().await;

    // the client is connected but acknowledges nothing for a while.
    let mut received = 0usize;
    while let Ok(Some(frame)) = timeout(Duration::from_millis(1500), client.next()).await {
        if let ServerFrame::Output(data) = frame {
            received += data.len();
        }
    }
    assert_eq!(
        received, REPLAY,
        "the server sends one buffer full and waits"
    );
    assert!(
        !marker.exists(),
        "the job must be held back by the full buffer"
    );

    // now it acknowledges, and everything arrives.
    client.send(ClientFrame::OutputAck(received as u64)).await;
    let (_, rest, exit) = {
        let (mut offset, mut out, mut exit) = (received as u64, Vec::new(), None);
        while let Some(frame) = client.next().await {
            match frame {
                ServerFrame::Output(data) => {
                    offset += data.len() as u64;
                    out.extend_from_slice(&data);
                    client.send(ClientFrame::OutputAck(offset)).await;
                }
                ServerFrame::Exit(status) => {
                    exit = Some(status);
                    break;
                }
                _ => {}
            }
        }
        (0, out, exit)
    };
    let expected = job_output();
    assert_eq!(received + rest.len(), expected.len());
    assert!(rest == expected[received..], "bytes were lost or repeated");
    assert_eq!(exit, Some(ExitStatus::Code(0)));
    assert!(marker.exists());
    let _ = std::fs::remove_file(&marker);
}

// A connection can die without the server hearing of it: the client sleeps, the network drops.
// Such a client acknowledges nothing, and the job must not wait for it forever.
#[tokio::test]
async fn a_connected_client_that_stays_silent_is_treated_as_away() {
    let marker = marker();
    let mut cfg = job_config(&marker, REPLAY);
    cfg.away_after = Duration::from_millis(400);
    let harness = start(cfg);
    let mut client = harness.connect().await;
    client.start().await;
    let mut seen_bytes = 0u64;

    wait_for_file(&marker).await;

    // the connection was cut by the server, since it still owed the client bytes that are gone.
    // What the client got before that is a prefix of the stream.
    let mut closed = false;
    while let Ok(frame) = timeout(Duration::from_secs(10), client.next()).await {
        match frame {
            Some(ServerFrame::Output(data)) => seen_bytes += data.len() as u64,
            Some(_) => {}
            None => {
                closed = true;
                break;
            }
        }
    }
    assert!(closed, "the connection of a silent client must be ended");

    let mut again = harness.connect().await;
    again
        .send(ClientFrame::Hello(Hello::Resume {
            size: size(),
            output_offset: seen_bytes,
        }))
        .await;
    let (welcome_offset, output, exit) = drain(&mut again).await;
    let expected = job_output();
    assert!(
        welcome_offset > seen_bytes,
        "output must have been forgotten in between"
    );
    assert!(output == expected[welcome_offset as usize..]);
    assert_eq!(exit, Some(ExitStatus::Code(0)));
    let _ = std::fs::remove_file(&marker);
}

// A client that joins later gets everything the server still holds, however much was forgotten.
#[tokio::test]
async fn attach_after_forgotten_output_gets_everything_that_is_left() {
    let marker = marker();
    let harness = start(job_config(&marker, 256 * 1024));
    let mut first = harness.connect().await;
    first.start().await;
    drop(first);
    wait_for_file(&marker).await;

    let mut joiner = harness.connect().await;
    joiner
        .send(ClientFrame::Hello(Hello::Attach { size: size() }))
        .await;
    let (welcome_offset, output, exit) = drain(&mut joiner).await;

    let expected = job_output();
    let held = 256 * 1024;
    assert_eq!(welcome_offset as usize, expected.len() - held);
    assert!(output == expected[expected.len() - held..]);
    assert_eq!(exit, Some(ExitStatus::Code(0)));
    let _ = std::fs::remove_file(&marker);
}

#[tokio::test]
async fn a_burst_of_resizes_leaves_the_last_size_on_the_terminal() {
    let harness = start(config("read x; stty size; exit 0"));
    let mut client = harness.connect().await;
    client.start().await;
    for rows in 30..80 {
        client
            .send(ClientFrame::Resize(WindowSize::new(rows, 100).unwrap()))
            .await;
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    client.send(ClientFrame::Input(b"go\n".to_vec())).await;
    let seen = client.read_until(|s| s.exit.is_some()).await;
    assert!(
        contains(&seen.output, "79 100"),
        "{:?}",
        String::from_utf8_lossy(&seen.output)
    );
}

#[tokio::test]
async fn a_client_that_goes_silent_is_given_up_and_the_detached_timeout_starts() {
    let mut cfg = config("cat");
    cfg.lost_after = Duration::from_millis(400);
    cfg.detached_timeout = Some(Duration::from_millis(600));
    let harness = start(cfg);
    let mut client = harness.connect().await;
    // measured from before the hello: the silence starts with it, and a busy machine can delay
    // the answer.
    let started = tokio::time::Instant::now();
    client.start().await;

    // the client stays connected but sends nothing; the session ends by its detached timeout,
    // which counts from the moment the connection was given up.
    assert!(matches!(harness.end().await, SessionEnd::DetachedTimeout));
    let waited = started.elapsed();
    assert!(
        waited >= Duration::from_millis(900),
        "the connection was not waited for: {waited:?}"
    );
}

#[tokio::test]
async fn a_client_that_pings_is_not_given_up() {
    let mut cfg = config("cat");
    cfg.lost_after = Duration::from_millis(400);
    cfg.detached_timeout = Some(Duration::from_millis(600));
    let harness = start(cfg);
    let mut client = harness.connect().await;
    client.start().await;

    // silence of 1.5 s in total, but never 400 ms at a time.
    for _ in 0..15 {
        client.send(ClientFrame::Ping).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let seen = client.read_until(|s| s.pongs >= 15).await;
    assert!(seen.pongs >= 15 && !seen.closed, "{seen:?}");
    assert!(!harness.session.is_finished());
}

// the exit status was sent, but the connection broke before the client confirmed it. The client
// may not have seen it, so the session stays and sends it again to the next connection.
#[tokio::test]
async fn an_exit_status_that_may_not_have_arrived_is_sent_again() {
    let harness = start(config("printf done; exit 6"));
    let mut first = harness.connect().await;
    first.start().await;
    let seen = first.read_until(|s| s.exit.is_some()).await;
    assert_eq!(seen.exit, Some(ExitStatus::Code(6)));
    // no close: the connection just goes.
    drop(first);
    tokio::time::sleep(Duration::from_millis(300)).await;

    let mut second = harness.connect().await;
    second
        .send(ClientFrame::Hello(Hello::Resume {
            size: size(),
            output_offset: seen.output.len() as u64,
        }))
        .await;
    let again = second.read_until(|s| s.exit.is_some()).await;
    assert_eq!(again.exit, Some(ExitStatus::Code(6)));
    second.send(ClientFrame::Close).await;
    assert!(
        matches!(harness.end().await, SessionEnd::ShellExited(status) if status.code() == Some(6))
    );
}

#[tokio::test]
async fn nobody_returns_for_the_exit_status_so_the_session_ends_after_the_grace_period() {
    let mut cfg = config("exit 9");
    cfg.exit_grace = Duration::from_millis(400);
    let harness = start(cfg);
    let mut first = harness.connect().await;
    first.start().await;
    first.read_until(|s| s.exit.is_some()).await;
    drop(first);
    assert!(
        matches!(harness.end().await, SessionEnd::ShellExited(status) if status.code() == Some(9))
    );
}

fn drop_config(marker: &std::path::Path, replay_capacity: usize, live: usize) -> SessionConfig {
    let mut cfg = job_config(marker, replay_capacity);
    cfg.slow_client = ssj_server::session::SlowClient::Drop;
    cfg.live_backlog = live;
    cfg
}

/// Reads frames the way a client does and checks that every byte it gets lies where the stream
/// has it: the gaps and the output together walk through `expected` without a repeat.
async fn read_and_place(
    client: &mut Client,
    mut offset: u64,
    expected: &[u8],
) -> (u64, Vec<u64>, Option<ExitStatus>) {
    let (mut received, mut gaps, mut exit) = (0u64, Vec::new(), None);
    while let Some(frame) = client.next().await {
        match frame {
            ServerFrame::Output(data) => {
                let at = offset as usize;
                assert!(
                    data == expected[at..at + data.len()],
                    "output at offset {offset} is not what the stream holds there"
                );
                offset += data.len() as u64;
                received += data.len() as u64;
                client.send(ClientFrame::OutputAck(offset)).await;
            }
            ServerFrame::Gap(skipped) => {
                gaps.push(skipped);
                offset += skipped;
                client.send(ClientFrame::OutputAck(offset)).await;
            }
            ServerFrame::Exit(status) => {
                exit = Some(status);
                break;
            }
            _ => {}
        }
    }
    assert_eq!(
        offset as usize,
        expected.len(),
        "the walk must end at the end of the stream"
    );
    (received, gaps, exit)
}

// A client that is connected and takes nothing, like a link that is far too slow, must not stop
// the job. The job ends, and the client then gets the newest output and is told what it missed.
#[tokio::test]
async fn a_connected_client_that_takes_nothing_does_not_hold_the_job_up() {
    let marker = marker();
    let live = 256 * 1024;
    let harness = start(drop_config(&marker, 4 * 1024 * 1024, live));
    let mut client = harness.connect().await;
    client.start().await;

    // the client reads nothing, and the job still finishes.
    wait_for_file(&marker).await;

    let expected = job_output();
    let (received, gaps, exit) = read_and_place(&mut client, 0, &expected).await;
    assert_eq!(exit, Some(ExitStatus::Code(0)));
    assert!(
        !gaps.is_empty(),
        "a job of 10 MB cannot fit in a backlog of 256 KiB"
    );
    // what arrives plus what was skipped is the whole stream, and the end of it is intact.
    assert_eq!(received + gaps.iter().sum::<u64>(), expected.len() as u64);
    assert!(received >= live as u64 / 2, "{received}");
    let _ = std::fs::remove_file(&marker);
}

// what the shell wrote before a client joined is replay. It is delivered whole, even though it is
// more than the backlog that a connected client may have.
#[tokio::test]
async fn the_replay_for_a_client_that_joins_is_not_skipped() {
    let marker = marker();
    let harness = start(drop_config(&marker, 16 * 1024 * 1024, 64 * 1024));
    let mut first = harness.connect().await;
    first.start().await;
    drop(first);
    wait_for_file(&marker).await;

    let mut joiner = harness.connect().await;
    joiner
        .send(ClientFrame::Hello(Hello::Resume {
            size: size(),
            output_offset: 0,
        }))
        .await;
    let welcome = joiner
        .read_until(|s| s.welcome.is_some())
        .await
        .welcome
        .unwrap();
    let expected = job_output();
    assert_eq!(welcome.output_offset, 0, "the whole output is still held");
    let (received, gaps, exit) = read_and_place(&mut joiner, 0, &expected).await;
    assert!(gaps.is_empty(), "the replay was cut: {gaps:?}");
    assert_eq!(received as usize, expected.len());
    assert_eq!(exit, Some(ExitStatus::Code(0)));
    let _ = std::fs::remove_file(&marker);
}

// the skip never starts inside a character of several bytes.
#[tokio::test]
async fn a_skip_does_not_cut_a_character_in_two() {
    let marker = marker();
    let mut cfg = config(&format!(
        "stty -opost; i=0; while [ $i -lt 200000 ]; do printf '\\303\\251\\303\\251\\303\\251\\n'; i=$((i+1)); done; touch {}",
        marker.display()
    ));
    cfg.replay_capacity = 4 * 1024 * 1024;
    cfg.slow_client = ssj_server::session::SlowClient::Drop;
    cfg.live_backlog = 100_001;
    let harness = start(cfg);
    let mut client = harness.connect().await;
    client.start().await;
    wait_for_file(&marker).await;
    let mut offset = 0u64;
    let mut starts_ok = true;
    let mut after_gap = false;
    let mut gaps_seen = 0;
    while let Ok(Some(frame)) = timeout(Duration::from_secs(2), client.next()).await {
        match frame {
            ServerFrame::Gap(skipped) => {
                offset += skipped;
                after_gap = true;
                gaps_seen += 1;
            }
            ServerFrame::Output(data) => {
                if after_gap {
                    // the first byte after a gap is not a continuation byte.
                    starts_ok &= data[0] & 0xc0 != 0x80;
                    after_gap = false;
                }
                offset += data.len() as u64;
                client.send(ClientFrame::OutputAck(offset)).await;
            }
            _ => {}
        }
    }
    assert!(gaps_seen > 0, "nothing was skipped, so nothing was tested");
    assert!(starts_ok, "a skip started inside a character");
    let _ = std::fs::remove_file(&marker);
}

// while the link is the limit, output that compresses is sent compressed, and it arrives exactly
// as the shell wrote it. Without the setting nothing is compressed.
#[tokio::test]
async fn output_is_compressed_while_the_link_holds_it_back_and_arrives_intact() {
    for (compress, expect_packed) in [(true, true), (false, false)] {
        let marker = marker();
        let mut cfg = drop_config(&marker, 16 * 1024 * 1024, 8 * 1024 * 1024);
        cfg.slow_client = ssj_server::session::SlowClient::Wait;
        cfg.compress = compress;
        let harness = start(cfg);
        let mut client = harness.connect().await;
        client.start().await;
        // the client takes nothing while the job runs, so output piles up: a slow link.
        wait_for_file_or_full(&marker).await;

        let expected = job_output();
        let (received, gaps, exit) = read_and_place(&mut client, 0, &expected).await;
        assert!(gaps.is_empty());
        assert_eq!(received as usize, expected.len());
        assert_eq!(exit, Some(ExitStatus::Code(0)));
        assert_eq!(
            client.compressed > 0,
            expect_packed,
            "compress = {compress}"
        );
        let _ = std::fs::remove_file(&marker);
    }
}

/// With `Wait` the job stops when the buffer is full, so the marker may not appear before the
/// client reads. Give the job time to fill the buffer, then go on.
async fn wait_for_file_or_full(marker: &std::path::Path) {
    for _ in 0..40 {
        if marker.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

// input that the client compressed is the same as plain input once the server has inflated it,
// and the input offset counts the plain bytes.
#[tokio::test]
async fn compressed_input_reaches_the_shell_as_plain_input() {
    let harness = start(config(
        "stty raw -echo; echo ready; head -c 20000 | wc -c; exit 0",
    ));
    let mut client = harness.connect().await;
    client.start().await;
    // the terminal must be raw before the input comes, or the line discipline cuts it.
    client.read_until(|s| contains(&s.output, "ready")).await;
    let text: Vec<u8> = (0..20_000u32)
        .map(|i| b"abcdefghij"[(i % 10) as usize])
        .collect();
    let mut compressor = ssj_proto::compress::Compressor::new();
    let packed = compressor.compress(&text).expect("text compresses");
    assert!(packed.len() < 1000);
    client.send(ClientFrame::Compressed(packed)).await;
    let seen = client.read_until(|s| s.exit.is_some()).await;
    assert!(
        contains(&seen.output, "20000"),
        "{:?}",
        String::from_utf8_lossy(&seen.output)
    );
    assert_eq!(seen.input_acks.last(), Some(&20_000));
}

#[tokio::test]
async fn bad_compressed_input_and_compressed_input_before_the_hello_are_refused() {
    let harness = start(config("sleep 5"));
    let mut client = harness.connect().await;
    client.start().await;
    client.send(ClientFrame::Compressed(vec![0xff; 40])).await;
    let seen = client.read_until(|s| s.error.is_some() || s.closed).await;
    assert!(seen.error.is_some() || seen.closed);

    let mut early = harness.connect().await;
    early.send(ClientFrame::Compressed(vec![1, 2, 3])).await;
    let seen = early.read_until(|s| s.error.is_some() || s.closed).await;
    assert!(
        seen.error == Some(ErrorCode::BadHello) || seen.closed,
        "{seen:?}"
    );
}

fn agent_config(script: &str, name: &str) -> (SessionConfig, std::path::PathBuf) {
    let path = std::path::PathBuf::from(format!("/tmp/ssj-t-{}-{name}.agent", std::process::id()));
    let mut config = config(script);
    config.agent_socket = Some(path.clone());
    (config, path)
}

async fn start_with_agent(client: &mut Client) {
    client
        .send(ClientFrame::Hello(Hello::Start {
            size: size(),
            env: Env::default(),
            agent: true,
        }))
        .await;
    client.read_until(|s| s.welcome.is_some()).await;
    client.send(ClientFrame::AgentOffer).await;
}

#[tokio::test]
async fn the_shell_finds_the_agent_socket_and_its_bytes_travel_over_a_channel() {
    use tokio::net::UnixStream;
    let (config, path) = agent_config("echo sock=$SSH_AUTH_SOCK; sleep 5", "travel");
    let harness = start(config);
    let mut client = harness.connect().await;
    start_with_agent(&mut client).await;
    let seen = client
        .read_until(|s| contains(&s.output, &format!("sock={}", path.display())))
        .await;
    assert!(contains(&seen.output, &format!("sock={}", path.display())));
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );

    let mut program = UnixStream::connect(&path).await.unwrap();
    let seen = client.read_until(|s| !s.agent.is_empty()).await;
    let ServerFrame::AgentOpen(id) = seen.agent[0] else {
        panic!("{seen:?}");
    };

    program.write_all(b"request").await.unwrap();
    let seen = client.read_until(|s| !s.agent.is_empty()).await;
    assert_eq!(seen.agent, [ServerFrame::Agent(id, b"request".to_vec())]);

    client.send(ClientFrame::Agent(id, b"reply".to_vec())).await;
    let mut got = [0u8; 5];
    program.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"reply");

    drop(program);
    let seen = client.read_until(|s| !s.agent.is_empty()).await;
    assert_eq!(seen.agent, [ServerFrame::AgentClose(id)]);
    drop(harness);
}

#[tokio::test]
async fn a_client_can_close_a_channel() {
    use tokio::net::UnixStream;
    let (config, path) = agent_config("sleep 5", "close");
    let harness = start(config);
    let mut client = harness.connect().await;
    start_with_agent(&mut client).await;
    // the socket appears with the shell.
    let mut program = loop {
        if let Ok(stream) = UnixStream::connect(&path).await {
            break stream;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    let seen = client.read_until(|s| !s.agent.is_empty()).await;
    let ServerFrame::AgentOpen(id) = seen.agent[0] else {
        panic!("{seen:?}");
    };
    client.send(ClientFrame::AgentClose(id)).await;
    assert_eq!(program.read(&mut [0u8; 8]).await.unwrap(), 0);
}

#[tokio::test]
async fn without_an_offer_the_agent_socket_is_closed_at_once() {
    use tokio::net::UnixStream;
    let (config, path) = agent_config("sleep 5", "refuse");
    let harness = start(config);
    let mut client = harness.connect().await;
    client
        .send(ClientFrame::Hello(Hello::Start {
            size: size(),
            env: Env::default(),
            agent: true,
        }))
        .await;
    client.read_until(|s| s.welcome.is_some()).await;
    let mut program = loop {
        if let Ok(stream) = UnixStream::connect(&path).await {
            break stream;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    assert_eq!(program.read(&mut [0u8; 8]).await.unwrap(), 0);
}

#[tokio::test]
async fn no_agent_is_set_up_unless_the_client_asks_for_it() {
    let (config, path) = agent_config("echo sock=[$SSH_AUTH_SOCK]; sleep 5", "none");
    let harness = start(config);
    let mut client = harness.connect().await;
    client.start().await;
    let seen = client.read_until(|s| contains(&s.output, "sock=[")).await;
    assert!(
        contains(&seen.output, "sock=[]"),
        "{:?}",
        String::from_utf8_lossy(&seen.output)
    );
    assert!(!path.exists());
}

fn prestarted(script: &str) -> SessionConfig {
    let mut cfg = config(script);
    cfg.prestart = Some(ssj_proto::bootstrap::Prestart {
        size: WindowSize::new(30, 100).unwrap(),
        env: Env::default(),
        agent: false,
    });
    cfg
}

#[tokio::test]
async fn a_prestarted_shell_runs_before_the_client_and_the_first_start_joins_it() {
    let harness = start(prestarted("echo ready-early; read x; echo got:$x; exit 4"));
    // the shell has run its startup before anybody connects.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let mut client = harness.connect().await;
    let welcome = client.start().await;
    assert_eq!((welcome.input_offset, welcome.output_offset), (0, 0));

    client.send(ClientFrame::Input(b"late\n".to_vec())).await;
    let seen = client.read_until(|s| s.exit.is_some()).await;
    // the output of the shell from before the connection is in the stream from offset 0.
    assert!(
        contains(&seen.output, "ready-early"),
        "{:?}",
        String::from_utf8_lossy(&seen.output)
    );
    assert!(contains(&seen.output, "got:late"));
    assert_eq!(seen.exit, Some(ExitStatus::Code(4)));
}

#[tokio::test]
async fn a_prestarted_shell_that_writes_more_than_the_buffer_waits_for_the_first_start() {
    let mut cfg = prestarted("head -c 300000 /dev/zero | tr '\\0' a; echo done-writing; sleep 5");
    cfg.replay_capacity = 16 * 1024;
    cfg.slow_client = ssj_server::session::SlowClient::Drop;
    let harness = start(cfg);
    tokio::time::sleep(Duration::from_millis(500)).await;
    let mut client = harness.connect().await;
    // nothing was forgotten, so the first start still joins
    let welcome = client.start().await;
    assert_eq!((welcome.input_offset, welcome.output_offset), (0, 0));
    let seen = client
        .read_until(|s| contains(&s.output, "done-writing"))
        .await;
    assert!(seen.error.is_none());
}

#[tokio::test]
async fn joining_a_prestarted_shell_applies_the_size_of_the_hello() {
    let harness = start(prestarted("read x; stty size; sleep 5"));
    let mut client = harness.connect().await;
    // the hello says 24 rows and 80 columns, the bootstrap said 30 and 100.
    client.start().await;
    client.send(ClientFrame::Input(b"go\n".to_vec())).await;
    let seen = client.read_until(|s| contains(&s.output, "24 80")).await;
    assert!(contains(&seen.output, "24 80"));
}

#[tokio::test]
async fn only_the_first_start_joins_and_an_attach_joins_too() {
    let harness = start(prestarted("cat"));
    let mut first = harness.connect().await;
    first.start().await;
    first.send(ClientFrame::Input(b"x\n".to_vec())).await;
    first.read_until(|s| contains(&s.output, "x")).await;
    drop(first);

    // a client that connected once is not a first start any more.
    let mut again = harness.connect().await;
    again
        .send(ClientFrame::Hello(Hello::Start {
            size: size(),
            env: Env::default(),
            agent: false,
        }))
        .await;
    let seen = again.read_until(|s| s.error.is_some() || s.closed).await;
    assert_eq!(seen.error, Some(ErrorCode::AlreadyStarted));

    // and a fresh session can be joined with an attach, as a named or reused session is.
    let harness = start(prestarted("echo here; sleep 5"));
    let mut attach = harness.connect().await;
    attach
        .send(ClientFrame::Hello(Hello::Attach { size: size() }))
        .await;
    let seen = attach.read_until(|s| contains(&s.output, "here")).await;
    assert!(seen.welcome.is_some());
}

#[tokio::test]
async fn a_session_that_nobody_joins_ends_with_its_shell() {
    let mut cfg = prestarted("sleep 60");
    cfg.first_client_timeout = Duration::from_millis(300);
    let harness = start(cfg);
    assert!(matches!(harness.end().await, SessionEnd::DetachedTimeout));

    // also without a prestart, and a shorter detached timeout wins.
    let mut cfg = config("cat");
    cfg.first_client_timeout = Duration::from_secs(3600);
    cfg.detached_timeout = Some(Duration::from_millis(200));
    let harness = start(cfg);
    assert!(matches!(harness.end().await, SessionEnd::DetachedTimeout));
}

#[tokio::test]
async fn the_first_client_timeout_stops_counting_once_a_client_has_joined() {
    let mut cfg = prestarted("sleep 5");
    cfg.first_client_timeout = Duration::from_millis(300);
    let harness = start(cfg);
    let mut client = harness.connect().await;
    client.start().await;
    // longer than the timeout, and the session is still there.
    tokio::time::sleep(Duration::from_millis(900)).await;
    drop(client);
    tokio::time::sleep(Duration::from_millis(900)).await;
    assert!(!harness.session.is_finished());
}

#[tokio::test]
async fn a_shell_that_leaves_a_background_program_on_the_terminal_still_ends_the_session() {
    // the program keeps the terminal open, so the output never reaches its end.
    let harness = start(config("sleep 30 & echo before; exit 3"));
    let mut client = harness.connect().await;
    client.start().await;
    let seen = client.read_until(|s| s.exit.is_some()).await;
    assert!(contains(&seen.output, "before"));
    assert_eq!(seen.exit, Some(ExitStatus::Code(3)));
    client.send(ClientFrame::Close).await;
    assert!(matches!(harness.end().await, SessionEnd::ShellExited(_)));
}

#[tokio::test]
async fn a_hangup_ends_the_session_and_hangs_up_the_shell() {
    let marker = std::env::temp_dir().join(format!("ssj-hangup-{}", std::process::id()));
    let _ = std::fs::remove_file(&marker);
    // the shell notes the SIGHUP that closing its terminal sends.
    let script = format!(
        "trap 'echo hup > {}; exit 0' HUP; echo ready; while :; do sleep 0.05; done",
        marker.display()
    );
    let harness = start(config(&script));
    let mut client = harness.connect().await;
    client.start().await;
    client.read_until(|s| contains(&s.output, "ready")).await;
    client.send(ClientFrame::Hangup).await;
    assert!(matches!(harness.end().await, SessionEnd::Killed));
    // the end of the session waited for the shell, which has run its trap.
    assert_eq!(std::fs::read_to_string(&marker).unwrap().trim(), "hup");
    let _ = std::fs::remove_file(&marker);
}
