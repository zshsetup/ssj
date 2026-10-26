mod common;

use std::sync::Arc;
use std::time::Duration;

use quinn::udp::RecvMeta;
use quinn::{AsyncUdpSocket, Endpoint, EndpointConfig, TokioRuntime};
use ssj_net::relay::{
    Direction, EnvelopeSocket, IDLE, RelayKeys, SECRET_LEN, Sealer, StreamSocket, forward,
};
use ssj_net::{Identity, SERVER_NAME, client_tls, quic_client, quic_server, server_tls};
use tokio::io::{AsyncWriteExt, duplex, split};
use tokio::net::UdpSocket;

use common::localhost;

const SECRET: [u8; SECRET_LEN] = [42; SECRET_LEN];

/// A relay on a local UDP port whose stream goes to a server endpoint through a pipe.
struct Setup {
    relay: std::net::SocketAddr,
    server: Endpoint,
    client_id: Identity,
    server_id: Identity,
}

async fn setup() -> Setup {
    let (server_id, client_id) = (Identity::generate(), Identity::generate());
    // the pipe stands for the ssh channel behind the jump
    let (near, far) = duplex(256 * 1024);
    let (relay_reader, relay_writer) = split(near);
    let (server_reader, server_writer) = split(far);

    let socket = StreamSocket::new(server_reader, server_writer);
    let server = Endpoint::new_with_abstract_socket(
        EndpointConfig::default(),
        Some(quic_server(server_tls(&server_id, client_id.fingerprint()))),
        socket,
        Arc::new(TokioRuntime),
    )
    .unwrap();

    let udp = Arc::new(UdpSocket::bind(localhost()).await.unwrap());
    let relay = udp.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = forward(udp, &SECRET, relay_reader, relay_writer, IDLE).await;
    });
    Setup {
        relay,
        server,
        client_id,
        server_id,
    }
}

fn client_endpoint(setup: &Setup, keys: &RelayKeys) -> Endpoint {
    let socket = EnvelopeSocket::bind(localhost(), setup.relay, keys).unwrap();
    let mut endpoint = Endpoint::new_with_abstract_socket(
        EndpointConfig::default(),
        None,
        socket,
        Arc::new(TokioRuntime),
    )
    .unwrap();
    endpoint.set_default_client_config(quic_client(client_tls(
        &setup.client_id,
        setup.server_id.fingerprint(),
    )));
    endpoint
}

/// Accepts connections and echoes the first stream of each.
fn echo(server: Endpoint) {
    tokio::spawn(async move {
        while let Some(incoming) = server.accept().await {
            tokio::spawn(async move {
                let Ok(conn) = incoming.await else { return };
                while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                    tokio::spawn(async move {
                        let mut data = Vec::new();
                        let _ = recv.read_to_end(1 << 24).await.map(|d| data = d);
                        let _ = send.write_all(&data).await;
                        let _ = send.finish();
                        let _ = send.stopped().await;
                    });
                }
            });
        }
    });
}

async fn round_trip(conn: &quinn::Connection, data: &[u8]) -> Vec<u8> {
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    send.write_all(data).await.unwrap();
    send.finish().unwrap();
    recv.read_to_end(1 << 24).await.unwrap()
}

#[tokio::test]
async fn quic_runs_through_the_relay() {
    let setup = setup().await;
    echo(setup.server.clone());
    let keys = RelayKeys::client(&SECRET);
    let client = client_endpoint(&setup, &keys);
    let conn = client
        .connect(setup.relay, SERVER_NAME)
        .unwrap()
        .await
        .unwrap();
    let data: Vec<u8> = (0..1_000_000u32).map(|i| (i % 251) as u8).collect();
    assert_eq!(round_trip(&conn, &data).await, data);
}

#[tokio::test]
async fn the_session_follows_the_client_to_a_new_socket() {
    let setup = setup().await;
    echo(setup.server.clone());
    let keys = RelayKeys::client(&SECRET);
    let client = client_endpoint(&setup, &keys);
    let conn = client
        .connect(setup.relay, SERVER_NAME)
        .unwrap()
        .await
        .unwrap();
    assert_eq!(round_trip(&conn, b"before").await, b"before");

    // another address, as after a change of the network
    let moved = EnvelopeSocket::bind(localhost(), setup.relay, &keys).unwrap();
    client.rebind_abstract(moved).unwrap();
    assert_eq!(round_trip(&conn, b"after").await, b"after");
}

#[tokio::test]
async fn a_client_without_the_secret_gets_nothing() {
    let setup = setup().await;
    echo(setup.server.clone());
    let wrong = RelayKeys::client(&[0; SECRET_LEN]);
    let client = client_endpoint(&setup, &wrong);
    let attempt = tokio::time::timeout(
        Duration::from_millis(800),
        client.connect(setup.relay, SERVER_NAME).unwrap(),
    )
    .await;
    assert!(
        attempt.is_err(),
        "the relay must drop what it cannot verify"
    );
}

#[tokio::test]
async fn a_raw_packet_to_the_relay_gets_no_answer() {
    let setup = setup().await;
    let probe = UdpSocket::bind(localhost()).await.unwrap();
    probe.send_to(&[0xc0; 1200], setup.relay).await.unwrap();
    let mut buf = [0u8; 2048];
    let answer = tokio::time::timeout(Duration::from_millis(300), probe.recv_from(&mut buf)).await;
    assert!(answer.is_err());
}

#[tokio::test]
async fn the_stream_socket_reports_the_end_of_its_stream() {
    let (mut near, far) = duplex(1024);
    let (reader, writer) = split(far);
    let socket = StreamSocket::new(reader, writer);
    near.write_all(&[0, 0]).await.unwrap();
    drop(near);
    tokio::time::timeout(Duration::from_secs(2), socket.ended())
        .await
        .expect("the end of the stream is noticed");
}

/// Prints how fast the server can send through the relay. Run it with `--release --ignored
/// --nocapture`.
#[tokio::test]
#[ignore = "a measurement"]
async fn measure_the_speed_of_the_relay() {
    let setup = setup().await;
    let server = setup.server.clone();
    tokio::spawn(async move {
        while let Some(incoming) = server.accept().await {
            tokio::spawn(async move {
                let conn = incoming.await.unwrap();
                let (mut send, _recv) = conn.accept_bi().await.unwrap();
                let chunk = vec![7u8; 64 * 1024];
                for _ in 0..(200 * 1024 * 1024 / chunk.len()) {
                    send.write_all(&chunk).await.unwrap();
                }
                send.finish().unwrap();
                let _ = send.stopped().await;
            });
        }
    });
    let keys = RelayKeys::client(&SECRET);
    let client = client_endpoint(&setup, &keys);
    let conn = client
        .connect(setup.relay, SERVER_NAME)
        .unwrap()
        .await
        .unwrap();
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    send.write_all(b"go").await.unwrap();
    let began = std::time::Instant::now();
    let mut total = 0usize;
    let mut buf = vec![0u8; 256 * 1024];
    while let Some(n) = recv.read(&mut buf).await.unwrap() {
        total += n;
    }
    let secs = began.elapsed().as_secs_f64();
    eprintln!(
        "{} MB in {secs:.2} s: {:.1} MB/s",
        total / 1_000_000,
        total as f64 / secs / 1e6
    );
}

/// A path that reorders packets must not reach QUIC reordered: QUIC takes it for loss.
#[tokio::test]
async fn datagrams_that_the_path_reordered_reach_quic_in_order() {
    let relay = UdpSocket::bind(localhost()).await.unwrap();
    let keys = RelayKeys::client(&SECRET);
    let socket = EnvelopeSocket::bind(localhost(), relay.local_addr().unwrap(), &keys).unwrap();
    let to = socket.local_addr().unwrap();
    let sealer = Sealer::new(&SECRET, Direction::ToClient);
    let mut sealed = Vec::new();
    let mut sent = Vec::new();
    for payload in 1u8..=6 {
        sealer.seal(&[payload; 40], &mut sealed);
        sent.push(sealed.clone());
    }
    for index in [0, 2, 1, 4, 3, 5] {
        relay.send_to(&sent[index], to).await.unwrap();
    }

    let mut seen = Vec::new();
    while seen.len() < 6 {
        let mut storage = [[0u8; 2048]; 8];
        let mut bufs: Vec<_> = storage
            .iter_mut()
            .map(|b| std::io::IoSliceMut::new(b))
            .collect();
        let mut meta = [RecvMeta::default(); 8];
        let got = tokio::time::timeout(
            Duration::from_secs(5),
            std::future::poll_fn(|cx| socket.poll_recv(cx, &mut bufs, &mut meta)),
        )
        .await
        .expect("datagrams arrive")
        .unwrap();
        for (buf, m) in bufs.iter().zip(&meta).take(got) {
            seen.push(buf[0]);
            assert_eq!(m.len, 40);
        }
    }
    assert_eq!(seen, [1, 2, 3, 4, 5, 6]);
}
