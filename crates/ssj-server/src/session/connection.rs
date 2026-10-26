//! The tasks that read and write one connection, and pass its frames to the session as messages.

use std::sync::Arc;
use std::time::Duration;

use ssj_proto::compress::inflate;
use ssj_proto::frame::MAX_FRAME_LEN;
use ssj_proto::{ClientFrame, ErrorCode, ServerFrame, decode_client};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Semaphore, mpsc};
use tokio::time::{Instant, timeout, timeout_at};

use super::{AbortOnDrop, Active, Connection, Control, INPUT_BUDGET, READ_CHUNK, Tagged};

/// Frames waiting for the writer of the connection.
const OUT_QUEUE: usize = 2;
/// The most that one write of queued frames takes.
const COALESCE_MAX: usize = 64 * 1024;

pub(super) fn start_connection(
    conn: Connection,
    generation: u64,
    control: mpsc::Sender<Tagged>,
    hello_timeout: Duration,
    lost_after: Duration,
) -> Active {
    let (out_tx, out_rx) = mpsc::channel(OUT_QUEUE);
    let (input_tx, input_rx) = mpsc::unbounded_channel();
    let budget = Arc::new(Semaphore::new(INPUT_BUDGET));
    let reader = tokio::spawn(read_connection(
        generation,
        conn.reader,
        control.clone(),
        input_tx,
        budget.clone(),
        Instant::now() + hello_timeout,
        lost_after,
    ));
    let writer = tokio::spawn(write_connection(generation, conn.writer, out_rx, control));
    Active {
        generation,
        out: out_tx,
        input: input_rx,
        budget,
        hello_done: false,
        pong_due: false,
        output_sent: 0,
        window: conn.window,
        input_acked: 0,
        replay_end: 0,
        gap: 0,
        agent: None,
        _reader: AbortOnDrop(reader),
        writer: Some(writer),
    }
}

async fn read_connection(
    generation: u64,
    mut reader: Box<dyn AsyncRead + Send + Unpin>,
    control: mpsc::Sender<Tagged>,
    input: mpsc::UnboundedSender<Vec<u8>>,
    budget: Arc<Semaphore>,
    hello_deadline: Instant,
    lost_after: Duration,
) {
    let send = |control_event| async {
        let _ = control
            .send(Tagged {
                generation,
                control: control_event,
            })
            .await;
    };
    let mut pending = Vec::new();
    let mut chunk = vec![0u8; READ_CHUNK];
    let mut got_hello = false;
    loop {
        let read = if got_hello {
            match timeout(lost_after, reader.read(&mut chunk)).await {
                Ok(result) => result,
                Err(_) => return send(Control::Lost).await,
            }
        } else {
            match timeout_at(hello_deadline, reader.read(&mut chunk)).await {
                Ok(result) => result,
                Err(_) => return send(Control::Violation(ErrorCode::BadHello)).await,
            }
        };
        match read {
            Ok(0) | Err(_) => return send(Control::Lost).await,
            Ok(n) => pending.extend_from_slice(&chunk[..n]),
        }
        loop {
            let (frame, used) = match decode_client(&pending) {
                Ok(Some(decoded)) => decoded,
                Ok(None) => break,
                Err(_) => {
                    let code = if got_hello {
                        ErrorCode::Violation
                    } else {
                        ErrorCode::BadHello
                    };
                    return send(Control::Violation(code)).await;
                }
            };
            pending.drain(..used);
            // compressed input is the same as plain input once it is inflated.
            let frame = match frame {
                ClientFrame::Compressed(packed) if got_hello => match inflate(&packed) {
                    Ok(data) => ClientFrame::Input(data),
                    Err(_) => return send(Control::Violation(ErrorCode::Violation)).await,
                },
                other => other,
            };
            match (frame, got_hello) {
                (ClientFrame::Hello(hello), false) => {
                    got_hello = true;
                    send(Control::Hello(hello)).await;
                }
                (ClientFrame::Hello(_), true) => {
                    return send(Control::Violation(ErrorCode::Violation)).await;
                }
                (_, false) => return send(Control::Violation(ErrorCode::BadHello)).await,
                (ClientFrame::Input(data), true) => {
                    // waits only for a client that sends far more than it may.
                    match budget.acquire_many(data.len() as u32).await {
                        Ok(permit) => permit.forget(),
                        Err(_) => return,
                    }
                    if input.send(data).is_err() {
                        return;
                    }
                }
                (ClientFrame::Resize(size), true) => send(Control::Resize(size)).await,
                (ClientFrame::OutputAck(offset), true) => send(Control::OutputAck(offset)).await,
                (ClientFrame::Close, true) => return send(Control::Close).await,
                (ClientFrame::Detach, true) => return send(Control::Detach).await,
                (ClientFrame::Hangup, true) => return send(Control::Hangup).await,
                (ClientFrame::Ping, true) => send(Control::Ping).await,
                (ClientFrame::AgentOffer, true) => send(Control::AgentOffer).await,
                (ClientFrame::Agent(id, data), true) => send(Control::Agent(id, data)).await,
                (ClientFrame::AgentClose(id), true) => send(Control::AgentClose(id)).await,
                // inflated above, and refused before the hello.
                (ClientFrame::Compressed(_), _) => {
                    return send(Control::Violation(ErrorCode::BadHello)).await;
                }
            }
        }
        // a header that announces more than a frame may hold is rejected by the decoder, so
        // the pending bytes stay below one frame plus one read.
        debug_assert!(pending.len() < MAX_FRAME_LEN + 4 + READ_CHUNK);
    }
}

async fn write_connection(
    generation: u64,
    mut writer: Box<dyn AsyncWrite + Send + Unpin>,
    mut frames: mpsc::Receiver<ServerFrame>,
    control: mpsc::Sender<Tagged>,
) {
    let mut bytes = Vec::new();
    while let Some(frame) = frames.recv().await {
        bytes.clear();
        if frame.encode(&mut bytes).is_err() {
            break;
        }
        // frames that are queued at the same moment go out in one write: a small acknowledgement
        // and the data behind it are one packet, not two that a hop with Nagle's algorithm holds
        // apart. The yield gives the sender the time to queue the second frame.
        tokio::task::yield_now().await;
        let mut failed = false;
        while bytes.len() < COALESCE_MAX {
            match frames.try_recv() {
                Ok(next) => {
                    if next.encode(&mut bytes).is_err() {
                        failed = true;
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        if failed {
            break;
        }
        // no timeout: the stream may legitimately stall while the network is down.
        if writer.write_all(&bytes).await.is_err() || writer.flush().await.is_err() {
            let _ = control
                .send(Tagged {
                    generation,
                    control: Control::Lost,
                })
                .await;
            return;
        }
    }
    let _ = writer.shutdown().await;
}
