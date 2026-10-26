//! The time a transport gets in the first connection.

use std::ffi::OsString;
use std::time::Duration;

use ssj_client::run::{Dial, Io, Params, Stream, Tier, run_session};
use ssj_client::status::Status;
use ssj_net::Identity;
use ssj_proto::bootstrap::Connect;
use ssj_proto::{Env, EnvFilter, SessionId, WindowSize};
use ssj_server::backend::Direct;
use ssj_server::session::{Connection, Session, SessionConfig, SlowClient, SpawnTemplate};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::time::{sleep, timeout};

struct Quiet;

impl Status for Quiet {
    fn show(&mut self, _: &str) -> Vec<u8> {
        Vec::new()
    }
    fn clear(&mut self, _title: Option<&str>) -> Vec<u8> {
        Vec::new()
    }
}

/// A stream to the session that takes `delay` to open, as an `ssh` handshake does.
fn slow_dial(conns: mpsc::Sender<Connection>, delay: Duration) -> Dial {
    Box::new(move || {
        let conns = conns.clone();
        Box::pin(async move {
            sleep(delay).await;
            let (client_end, server_end) = tokio::io::duplex(64 * 1024);
            let (server_reader, server_writer) = tokio::io::split(server_end);
            conns
                .send(Connection {
                    reader: Box::new(server_reader),
                    writer: Box::new(server_writer),
                    window: None,
                })
                .await
                .map_err(|e| e.to_string())?;
            let (reader, writer) = tokio::io::split(client_end);
            Ok(Stream {
                reader: Box::new(reader),
                writer: Box::new(writer),
                guard: None,
            })
        })
    })
}

#[tokio::test]
async fn a_stream_that_is_slow_to_open_is_not_given_up_after_the_short_first_time() {
    let (conns, conns_rx) = mpsc::channel::<Connection>(4);
    let config = SessionConfig {
        id: SessionId::parse("abcdef012345").unwrap(),
        template: SpawnTemplate {
            program: "/bin/sh".into(),
            args: vec!["-c".into(), "echo up-and-running; sleep 30".into()],
            env: vec![(OsString::from("PATH"), OsString::from("/usr/bin:/bin"))],
            cwd: None,
        },
        accept_env: EnvFilter::default_patterns(),
        replay_capacity: 64 * 1024,
        away_after: Duration::from_secs(30),
        detached_timeout: None,
        max_detached: None,
        hello_timeout: Duration::from_secs(5),
        lost_after: Duration::from_secs(60),
        exit_grace: Duration::from_secs(60),
        slow_client: SlowClient::Wait,
        live_backlog: 1 << 20,
        compress: false,
        agent_socket: None,
        prestart: None,
        first_client_timeout: Duration::from_secs(3600),
    };
    let session = tokio::spawn(Session::new(Direct, config).run(conns_rx));

    // the first transport needs 1.2 s, the first attempt may take 0.3 s, and a second transport
    // that never works is behind it.
    let failing: Dial = Box::new(|| Box::pin(async { Err("no second way".to_owned()) }));
    let (_typed_tx, typed_rx) = tokio::io::duplex(1 << 10);
    let (shown_tx, mut shown_rx) = tokio::io::duplex(1 << 20);
    let (_resizes_tx, resizes) = mpsc::unbounded_channel();
    let (_net_tx, net) = mpsc::unbounded_channel();
    let identity = Identity::generate();
    let io = Io {
        input: Box::new(typed_rx),
        output: Box::new(shown_tx),
        size: WindowSize::new(24, 80).unwrap(),
        resizes,
        status: Box::new(Quiet),
        net,
        hangups: mpsc::unbounded_channel().1,
    };
    let params = Params {
        connect: Connect {
            id: SessionId::parse("abcdef012345").unwrap(),
            udp: None,
            fingerprint: identity.fingerprint(),
            new: false,
            name: None,
            socket: None,
        },
        identity,
        relay_ready: None,
        tiers: vec![
            Tier::Stream {
                name: "tcp",
                dial: slow_dial(conns, Duration::from_millis(1200)),
            },
            Tier::Stream {
                name: "stdio",
                dial: failing,
            },
        ],
        attempt_timeout: Duration::from_secs(8),
        first_attempt_timeout: Duration::from_millis(300),
        stream_dead_after: Duration::from_secs(60),
        env: Env::default(),
        detach_key: None,
        hangup_detaches: false,
        attach: false,
        local_echo: false,
        compress: false,
        agent: None,
        announce: None,
    };
    let client = tokio::spawn(run_session(params, io));

    let mut seen = String::new();
    timeout(Duration::from_secs(10), async {
        while !seen.contains("up-and-running") {
            let mut chunk = [0u8; 1024];
            let n = shown_rx.read(&mut chunk).await.unwrap();
            assert!(n > 0, "the client ended: {seen:?}");
            seen.push_str(&String::from_utf8_lossy(&chunk[..n]));
        }
    })
    .await
    .expect("the session shows its output over the first transport");

    client.abort();
    session.abort();
    let _ = shown_rx.shutdown().await;
}
