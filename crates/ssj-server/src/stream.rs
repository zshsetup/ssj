//! Turns a connected byte stream (TLS over TCP, or the unix socket of `--stdio`) into the pair of
//! halves that the session core works with.

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, copy, duplex, split};
use tokio::time::timeout;

use crate::session::Connection;

/// Memory between the stream and the session. A full buffer pushes back on the peer.
const BRIDGE_BUFFER: usize = 64 * 1024;
/// Time the peer gets to read the last bytes and close its side before the stream is dropped.
///
/// Closing a socket that still has unread input resets the connection, and the reset can destroy
/// data that the peer has not read yet, such as the exit status.
const DRAIN: Duration = Duration::from_secs(2);

/// Runs `stream` behind in-memory halves. Must run inside the tokio runtime.
///
/// When the session drops its halves, the stream is shut down in order: the data already written
/// is delivered, and the peer gets a short time to close first.
pub fn bridge<S>(stream: S) -> Connection
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let (near, far) = duplex(BRIDGE_BUFFER);
    let (reader, writer) = split(near);
    tokio::spawn(pump(stream, far));
    Connection {
        reader: Box::new(reader),
        writer: Box::new(writer),
        window: None,
    }
}

async fn pump<S>(stream: S, far: tokio::io::DuplexStream)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut from_peer, mut to_peer) = split(stream);
    let (mut from_session, mut to_session) = split(far);

    let mut session_done = Box::pin(async {
        let _ = copy(&mut from_session, &mut to_peer).await;
        // flushes, and sends the end of the stream (close_notify for TLS)
        let _ = to_peer.shutdown().await;
    });
    let mut peer_done = Box::pin(async {
        let _ = copy(&mut from_peer, &mut to_session).await;
        let _ = to_session.shutdown().await;
    });

    tokio::select! {
        () = &mut session_done => {
            // the session is done: read and discard what the peer still sends until it closes.
            drop(peer_done);
            let _ = timeout(DRAIN, async {
                let mut sink = [0u8; 4096];
                while matches!(from_peer.read(&mut sink).await, Ok(n) if n > 0) {}
            })
            .await;
        }
        () = &mut peer_done => {
            // the peer is gone, and the session sees the end of the stream and lets go.
            let _ = timeout(DRAIN, session_done).await;
        }
    }
}
