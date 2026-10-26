//! The agent of the client, used by a program in the session through the forwarded socket.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use ssj_client::run::{Dial, Io, Params, Stream, Tier, run_session};
use ssj_client::status::Status;
use ssj_net::Identity;
use ssj_proto::bootstrap::Connect;
use ssj_proto::{Env, EnvFilter, SessionId, WindowSize};
use ssj_server::backend::Direct;
use ssj_server::session::{Connection, Session, SessionConfig, SlowClient, SpawnTemplate};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;
use tokio::time::{sleep, timeout};

const IDENTITIES_ANSWER: [u8; 9] = [0, 0, 0, 5, 12, 0, 0, 0, 0];
const FAILURE: [u8; 5] = [0, 0, 0, 1, 5];

struct Quiet;

impl Status for Quiet {
    fn show(&mut self, _: &str) -> Vec<u8> {
        Vec::new()
    }
    fn clear(&mut self, _title: Option<&str>) -> Vec<u8> {
        Vec::new()
    }
}

/// An agent that answers every request it gets with an empty list of keys and counts them.
fn fake_agent(path: &Path) -> Arc<AtomicUsize> {
    let listener = UnixListener::bind(path).unwrap();
    let requests = Arc::new(AtomicUsize::new(0));
    let counted = requests.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let counted = counted.clone();
            tokio::spawn(async move {
                let mut head = [0u8; 4];
                while stream.read_exact(&mut head).await.is_ok() {
                    let mut body = vec![0u8; u32::from_be_bytes(head) as usize];
                    if stream.read_exact(&mut body).await.is_err() {
                        return;
                    }
                    counted.fetch_add(1, Ordering::SeqCst);
                    if stream.write_all(&IDENTITIES_ANSWER).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    requests
}

fn request(kind: u8) -> Vec<u8> {
    vec![0, 0, 0, 1, kind]
}

async fn wait_for_socket(path: &Path) -> UnixStream {
    timeout(Duration::from_secs(20), async {
        loop {
            if let Ok(stream) = UnixStream::connect(path).await {
                return stream;
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the agent socket of the session")
}

#[tokio::test]
async fn a_program_in_the_session_reaches_the_agent_of_the_client_but_only_for_signing() {
    let tag = std::process::id();
    let local = PathBuf::from(format!("/tmp/ssj-t-{tag}-local.sock"));
    let remote = PathBuf::from(format!("/tmp/ssj-t-{tag}-remote.agent"));
    let requests = fake_agent(&local);

    let (conns, conns_rx) = mpsc::channel::<Connection>(4);
    let config = SessionConfig {
        id: SessionId::parse("abcdef012345").unwrap(),
        template: SpawnTemplate {
            program: "/bin/sh".into(),
            args: vec!["-c".into(), "sleep 30".into()],
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
        agent_socket: Some(remote.clone()),
        prestart: None,
        first_client_timeout: Duration::from_secs(3600),
    };
    let session = tokio::spawn(Session::new(Direct, config).run(conns_rx));

    let dial: Dial = Box::new(move || {
        let conns = conns.clone();
        Box::pin(async move {
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
    });
    let (typed_tx, typed_rx) = tokio::io::duplex(1 << 16);
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
        tiers: vec![Tier::Stream {
            name: "stdio",
            dial,
        }],
        attempt_timeout: Duration::from_secs(8),
        first_attempt_timeout: Duration::from_secs(8),
        stream_dead_after: Duration::from_secs(60),
        env: Env::default(),
        detach_key: None,
        hangup_detaches: false,
        attach: false,
        local_echo: false,
        compress: false,
        agent: Some(local.clone()),
        announce: None,
    };
    let client = tokio::spawn(run_session(params, io));
    // nobody reads the terminal here, so keep it from filling up.
    tokio::spawn(
        async move { while shown_rx.read(&mut [0u8; 4096]).await.is_ok_and(|n| n > 0) {} },
    );

    let mut program = wait_for_socket(&remote).await;
    // listing the keys reaches the agent.
    program.write_all(&request(11)).await.unwrap();
    let mut answer = [0u8; 9];
    timeout(Duration::from_secs(10), program.read_exact(&mut answer))
        .await
        .expect("an answer")
        .unwrap();
    assert_eq!(answer, IDENTITIES_ANSWER);
    assert_eq!(requests.load(Ordering::SeqCst), 1);

    // removing all keys (type 19) never reaches it.
    program.write_all(&request(19)).await.unwrap();
    let mut refused = [0u8; 5];
    timeout(Duration::from_secs(10), program.read_exact(&mut refused))
        .await
        .expect("an answer")
        .unwrap();
    assert_eq!(refused, FAILURE);
    assert_eq!(requests.load(Ordering::SeqCst), 1);

    // a second program has its own channel.
    let mut other = UnixStream::connect(&remote).await.unwrap();
    other.write_all(&request(13)).await.unwrap();
    timeout(Duration::from_secs(10), other.read_exact(&mut answer))
        .await
        .expect("an answer")
        .unwrap();
    assert_eq!(requests.load(Ordering::SeqCst), 2);

    client.abort();
    session.abort();
    let _ = std::fs::remove_file(&local);
    let _ = std::fs::remove_file(&remote);
    drop(typed_tx);
}
