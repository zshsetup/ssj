//! The part of the control socket that runs inside the server.

use std::sync::Arc;
use std::time::Instant;

use ssj_proto::control::{
    MAX_LINE, Reply, Request, SessionInfo, SessionState, format_reply, parse_request,
};
use ssj_proto::{PROTOCOL, SessionId, SessionName};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Mutex, mpsc};
use tokio::time::timeout;

use crate::control_socket::IO_TIMEOUT;
use crate::frontend::Frontend;
use crate::session::SessionCommand;
use crate::stream::bridge;

/// What the control socket needs to know and to do.
pub struct Context {
    pub id: SessionId,
    pub name: Option<SessionName>,
    pub started: Instant,
    pub state: std::sync::Mutex<SessionState>,
    pub frontend: Mutex<Frontend>,
    pub commands: mpsc::UnboundedSender<SessionCommand>,
}

impl Context {
    pub fn set_state(&self, state: SessionState) {
        *self.state.lock().expect("not poisoned") = state;
    }

    async fn dispatch(&self, request: Request) -> Reply {
        match request {
            Request::Status => Reply::Info(SessionInfo {
                id: self.id.clone(),
                name: self.name.clone(),
                state: *self.state.lock().expect("not poisoned"),
                age_secs: self.started.elapsed().as_secs(),
                protocol: PROTOCOL,
            }),
            Request::Kill => {
                let _ = self.commands.send(SessionCommand::Kill);
                Reply::Ok
            }
            Request::Detach => {
                if *self.state.lock().expect("not poisoned") == SessionState::Connected {
                    let _ = self.commands.send(SessionCommand::Detach);
                    Reply::Ok
                } else {
                    Reply::Error("no client is connected".to_owned())
                }
            }
            // handled by the caller, since the connection itself is needed.
            Request::Stream | Request::Datagrams => Reply::Error("not a stream".to_owned()),
            Request::Attach(pin) => match self.frontend.lock().await.open(pin).await {
                Ok(connect) => Reply::Connect(connect),
                Err(err) => Reply::Error(err.to_string()),
            },
        }
    }
}

/// Accepts requests on the socket until the task is dropped.
pub async fn serve_control(listener: UnixListener, context: Arc<Context>) {
    while let Ok((stream, _)) = listener.accept().await {
        tokio::spawn(handle(stream, context.clone()));
    }
}

async fn handle(stream: UnixStream, context: Arc<Context>) {
    // the directory is private already, and this is the second lock on the door.
    match stream.peer_cred() {
        Ok(cred) if cred.uid() == rustix::process::getuid().as_raw() => {}
        _ => return,
    }
    let (reader, mut writer) = stream.into_split();
    let mut line = Vec::new();
    let mut lines = BufReader::new(reader.take(MAX_LINE as u64));
    let read = timeout(IO_TIMEOUT, lines.read_until(b'\n', &mut line)).await;
    let reply = match read {
        Ok(Ok(n)) if n > 0 && line.ends_with(b"\n") => match parse_request(&line) {
            Ok(Request::Stream) => {
                // the connection becomes the byte stream of a client; the client sends nothing
                // before the answer, so no input is lost with the buffer of the reader.
                let reader = lines.into_inner().into_inner();
                if writer
                    .write_all(format_reply(&Reply::Ok).as_bytes())
                    .await
                    .is_err()
                {
                    return;
                }
                if let Ok(stream) = reader.reunite(writer) {
                    let conns = context.frontend.lock().await.conns();
                    let _ = conns.send(bridge(stream)).await;
                }
                return;
            }
            Ok(Request::Datagrams) => {
                // like a stream, and the packets of a relay come over it
                if !context.frontend.lock().await.can_open_piped() {
                    Reply::Error("no client was attached".to_owned())
                } else {
                    let reader = lines.into_inner().into_inner();
                    if writer
                        .write_all(format_reply(&Reply::Ok).as_bytes())
                        .await
                        .is_err()
                    {
                        return;
                    }
                    if let Ok(stream) = reader.reunite(writer) {
                        let _ = context.frontend.lock().await.open_piped(stream);
                    }
                    return;
                }
            }
            Ok(request) => context.dispatch(request).await,
            Err(_) => Reply::Error("unknown request".to_owned()),
        },
        _ => Reply::Error("no complete request".to_owned()),
    };
    let _ = writer.write_all(format_reply(&reply).as_bytes()).await;
    let _ = writer.shutdown().await;
}
