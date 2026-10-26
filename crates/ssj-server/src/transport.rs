//! Turns QUIC connections into the byte streams that the session core works with.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use ssj_net::INITIAL_CONGESTION_WINDOW;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tokio::time::timeout;

use crate::session::Connection;

/// How long the peer gets to deliver pending data before the connection is closed.
const DRAIN: Duration = Duration::from_secs(5);

/// How often the congestion window of a connection is read.
const WINDOW_POLL: Duration = Duration::from_millis(50);

/// Keeps `window` at the congestion window of the connection until the connection ends.
async fn track_window(connection: quinn::Connection, window: Arc<AtomicU64>) {
    let mut tick = tokio::time::interval(WINDOW_POLL);
    loop {
        tick.tick().await;
        if connection.close_reason().is_some() {
            return;
        }
        window.store(connection.stats().path.cwnd, Ordering::Relaxed);
    }
}

/// Receiving side of the stream of a client.
pub struct QuicReader {
    recv: quinn::RecvStream,
    _conn: quinn::Connection,
}

/// Sending side of the stream of a client. Closes the connection after the data was delivered.
pub struct QuicWriter {
    send: Option<quinn::SendStream>,
    conn: quinn::Connection,
}

impl AsyncRead for QuicReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for QuicWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let send = self.send.as_mut().expect("present until drop");
        Pin::new(send).poll_write(cx, buf).map_err(io::Error::from)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let send = self.send.as_mut().expect("present until drop");
        Pin::new(send).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let send = self.send.as_mut().expect("present until drop");
        Pin::new(send).poll_shutdown(cx)
    }
}

impl Drop for QuicWriter {
    fn drop(&mut self) {
        let Some(mut send) = self.send.take() else {
            return;
        };
        let conn = self.conn.clone();
        tokio::spawn(async move {
            let _ = send.finish();
            // closing at once would discard data that is still on its way.
            let _ = timeout(DRAIN, send.stopped()).await;
            conn.close(0u8.into(), b"done");
        });
    }
}

/// Accepts validated connection attempts and hands each client stream to the session.
///
/// A client that does not open its stream within `stream_timeout` is dropped. Returns when the
/// endpoint is closed or the session no longer takes connections.
pub async fn serve(
    endpoint: quinn::Endpoint,
    conns: mpsc::Sender<Connection>,
    stream_timeout: Duration,
) {
    serve_observed(endpoint, conns, stream_timeout, None).await;
}

/// Like [`serve`], and publishes a handle of every accepted QUIC connection on `observer`.
///
/// The handle lets tests end a connection from the server side.
pub async fn serve_observed(
    endpoint: quinn::Endpoint,
    conns: mpsc::Sender<Connection>,
    stream_timeout: Duration,
    observer: Option<mpsc::UnboundedSender<quinn::Connection>>,
) {
    serve_with(endpoint, conns, stream_timeout, observer, true).await;
}

/// Like [`serve`] for an endpoint whose packets come out of a pipe (behind a relay): nobody can
/// forge a source address there, so the retry that validates one only costs a round trip.
pub async fn serve_piped(
    endpoint: quinn::Endpoint,
    conns: mpsc::Sender<Connection>,
    stream_timeout: Duration,
) {
    serve_with(endpoint, conns, stream_timeout, None, false).await;
}

async fn serve_with(
    endpoint: quinn::Endpoint,
    conns: mpsc::Sender<Connection>,
    stream_timeout: Duration,
    observer: Option<mpsc::UnboundedSender<quinn::Connection>>,
    validate: bool,
) {
    loop {
        let incoming = if validate {
            ssj_net::accept_validated(&endpoint).await
        } else {
            endpoint.accept().await
        };
        let Some(incoming) = incoming else {
            break;
        };
        let to_session = conns.clone();
        let observer = observer.clone();
        tokio::spawn(async move {
            // the handshake includes the check of the pinned client certificate.
            let Ok(connection) = incoming.await else {
                return;
            };
            let Ok(Ok((send, recv))) = timeout(stream_timeout, connection.accept_bi()).await else {
                return;
            };
            if let Some(observer) = observer {
                let _ = observer.send(connection.clone());
            }
            let window = Arc::new(AtomicU64::new(INITIAL_CONGESTION_WINDOW));
            tokio::spawn(track_window(connection.clone(), window.clone()));
            let reader = QuicReader {
                recv,
                _conn: connection.clone(),
            };
            let writer = QuicWriter {
                send: Some(send),
                conn: connection,
            };
            let _ = to_session
                .send(Connection {
                    reader: Box::new(reader),
                    writer: Box::new(writer),
                    window: Some(window),
                })
                .await;
        });
        if conns.is_closed() {
            break;
        }
    }
}
