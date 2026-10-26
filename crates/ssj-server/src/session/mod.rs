//! The session of one server process: the shell, its buffered output, and the current connection.
//!
//! A single task owns all state. Connections come in as byte streams, so the logic does not
//! depend on QUIC. Reading the shell, writing to it, and talking to the client never wait for
//! each other, which is what prevents deadlocks when a large paste meets a chatty program.

use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::Duration;

use ssj_net::channels::Channels;
use ssj_proto::bootstrap::Prestart;
use ssj_proto::{
    Env, EnvFilter, ErrorCode, ExitStatus as WireExit, Hello, ServerFrame, SessionId, WindowSize,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::UnixListener;
use tokio::sync::{Semaphore, mpsc};
use tokio::task::JoinHandle;

use crate::backend::{Backend, Shell, SpawnSpec};
use crate::control_socket::SocketFile;

mod actor;
mod connection;

use actor::Actor;

/// Bytes of the shell output read at once.
const READ_CHUNK: usize = 64 * 1024;
/// Input bytes a connection may have queued for the shell.
///
/// The reader must keep parsing while the shell is busy, because acknowledgements of output are
/// in the same byte stream as the input and are what lets the shell continue. The client limits
/// its unacknowledged input to less than this, so the reader does not block on the budget.
pub const INPUT_BUDGET: usize = 2 * 1024 * 1024;

/// Byte stream pair of one client connection.
pub struct Connection {
    pub reader: Box<dyn AsyncRead + Send + Unpin>,
    pub writer: Box<dyn AsyncWrite + Send + Unpin>,
    /// How many bytes of output the transport can have in flight without an acknowledgement, kept
    /// up to date by the transport (the congestion window of QUIC). A transport that has no such
    /// number, as a byte stream, leaves it out and limits itself.
    pub window: Option<Arc<AtomicU64>>,
}

/// Program and fixed environment of the shell. The environment of the client is added to it.
#[derive(Clone, Debug)]
pub struct SpawnTemplate {
    pub program: PathBuf,
    pub args: Vec<OsString>,
    pub env: Vec<(OsString, OsString)>,
    pub cwd: Option<PathBuf>,
}

/// What the server does with output that a connected client has not taken yet.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SlowClient {
    /// The job never waits for the link. The server keeps at most `live_backlog` bytes of unsent
    /// output and skips the oldest of the rest, and the client is told how much it missed.
    #[default]
    Drop,
    /// The job waits until the client has taken the output (as with `ssh`), so nothing is lost
    /// while the client is connected, and a slow link slows the job down.
    Wait,
}

/// Container for the settings that a session starts with.
#[derive(Clone, Debug)]
pub struct SessionConfig {
    pub id: SessionId,
    pub template: SpawnTemplate,
    /// Variables of the client that reach the shell.
    pub accept_env: EnvFilter,
    /// Output bytes kept until the client acknowledges them.
    pub replay_capacity: usize,
    pub slow_client: SlowClient,
    /// Compress output for a client when the link holds it back (see [`COMPRESS_BACKLOG`]).
    pub compress: bool,
    /// With [`SlowClient::Drop`]: the most output that may wait to be sent to a connected client.
    /// What the shell wrote before the client connected (the replay) does not count.
    pub live_backlog: usize,
    /// The shell is started when the session starts, with this size, environment, and agent flag,
    /// and the first `Start` hello of a client only joins it (see [`Prestart`]).
    pub prestart: Option<Prestart>,
    /// A session that no client has joined yet ends after this long, so that a client which
    /// gave up while connecting does not leave a shell behind. It applies on top of
    /// `detached_timeout`, which only counts from the first connection.
    pub first_client_timeout: Duration,
    /// Where the socket for the agent of the client is made when the client asks for it.
    /// `None` refuses agent forwarding.
    pub agent_socket: Option<PathBuf>,
    /// How long a connected client may leave the output buffer full without acknowledging
    /// anything before the server treats it as away (a connection that died without telling).
    pub away_after: Duration,
    /// End of the session after this long without a connection. `None` waits forever.
    pub detached_timeout: Option<Duration>,
    /// Limit for the wait after a deliberate detach. `None` waits forever.
    pub max_detached: Option<Duration>,
    /// Time a new connection has to send its first frame.
    pub hello_timeout: Duration,
    /// A connection that sends nothing for this long, not even a ping, is given up. The client
    /// pings every second, so silence means that it is gone (a closed laptop, a lost phone), and
    /// QUIC alone would keep the connection for ever.
    pub lost_after: Duration,
    /// How long a finished session waits for a client that lost the connection while the exit
    /// status was on its way. The client confirms the status with a close, and without it the
    /// session cannot know that the status arrived.
    pub exit_grace: Duration,
}

/// Why the session ended.
#[derive(Debug)]
pub enum SessionEnd {
    /// The shell exited and the client has been told.
    ShellExited(ExitStatus),
    /// No client connected for the configured time.
    DetachedTimeout,
    /// The shell could not be started or failed.
    Failed(io::Error),
    /// The sender of connections was dropped.
    Closed,
    /// A command ended the session by hanging up the terminal of the shell.
    Killed,
}

/// Changes of the state of the session that the transport needs to know about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionEvent {
    /// A client completed its handshake.
    Connected,
    /// The connected client was lost and may come back.
    Disconnected,
    /// The client left on purpose. The transport closes its endpoint and drops the pinned client.
    Detached,
}

/// Orders to the running session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionCommand {
    /// Hangs up the terminal of the shell, as closing a terminal window would, and ends.
    Kill,
    /// Tells the connected client to leave and keeps the shell running, as after the detach key.
    Detach,
}

/// Manages the shell of one session across the connections of its client.
pub struct Session<B: Backend> {
    backend: B,
    config: SessionConfig,
    events: Option<mpsc::UnboundedSender<SessionEvent>>,
    commands: Option<mpsc::UnboundedReceiver<SessionCommand>>,
}

enum Control {
    Hello(Hello),
    Resize(WindowSize),
    OutputAck(u64),
    Close,
    Detach,
    Hangup,
    Ping,
    AgentOffer,
    Agent(u32, Vec<u8>),
    AgentClose(u32),
    Lost,
    Violation(ErrorCode),
}

struct Tagged {
    generation: u64,
    control: Control,
}

/// Aborts the task when dropped, so a replaced connection stops reading at once.
struct AbortOnDrop(JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct Active {
    generation: u64,
    out: mpsc::Sender<ServerFrame>,
    input: mpsc::UnboundedReceiver<Vec<u8>>,
    /// Bytes that may still be queued in `input`.
    budget: Arc<Semaphore>,
    hello_done: bool,
    /// A `Ping` was received and its `Pong` is not sent yet.
    pong_due: bool,
    /// Output offset up to which frames were queued for this connection.
    output_sent: u64,
    /// How much unacknowledged output the transport can carry (see [`Connection::window`]).
    window: Option<Arc<AtomicU64>>,
    /// Input offset that was last acknowledged to this client.
    input_acked: u64,
    /// Output offset when the client joined: what lies before it is replay and is not skipped
    /// for being slow.
    replay_end: u64,
    /// Bytes of output skipped and not announced to the client yet.
    gap: u64,
    /// The channels to the agent of the client, if this connection serves it.
    agent: Option<Channels>,
    _reader: AbortOnDrop,
    writer: Option<JoinHandle<()>>,
}

impl Drop for Active {
    fn drop(&mut self) {
        // frames already queued get a few seconds to leave, then the task is stopped.
        if let Some(writer) = self.writer.take() {
            tokio::spawn(async move {
                let abort = writer.abort_handle();
                if tokio::time::timeout(Duration::from_secs(5), writer)
                    .await
                    .is_err()
                {
                    abort.abort();
                }
            });
        }
    }
}

struct Running<S: Shell> {
    reader: S::Reader,
    writer: S::Writer,
    exit: Option<crate::backend::ExitFuture>,
    status: Option<ExitStatus>,
    reader_eof: bool,
    exit_queued: bool,
}

impl<B: Backend> Session<B> {
    pub fn new(backend: B, config: SessionConfig) -> Self {
        Self {
            backend,
            config,
            events: None,
            commands: None,
        }
    }

    /// Takes [`SessionCommand`]s from `commands`.
    pub fn with_commands(mut self, commands: mpsc::UnboundedReceiver<SessionCommand>) -> Self {
        self.commands = Some(commands);
        self
    }

    /// Reports [`SessionEvent`]s on `events`.
    pub fn with_events(mut self, events: mpsc::UnboundedSender<SessionEvent>) -> Self {
        self.events = Some(events);
        self
    }

    /// Runs the session until it ends, taking the connections of its client from `conns`.
    pub async fn run(self, conns: mpsc::Receiver<Connection>) -> SessionEnd {
        match Actor::start(self, conns).await {
            Ok(actor) => actor.run().await,
            Err(end) => end,
        }
    }
}

fn wire_exit(status: ExitStatus) -> WireExit {
    use std::os::unix::process::ExitStatusExt;
    match (status.code(), status.signal()) {
        (Some(code), _) => WireExit::Code(code as u8),
        (None, Some(signal)) => WireExit::Signal(signal as u8),
        (None, None) => WireExit::Code(255),
    }
}

/// Makes the socket for the agent of the client. Without it the shell has no agent.
fn listen_for_agent(path: &Path) -> Option<(UnixListener, SocketFile)> {
    use std::os::unix::fs::PermissionsExt;
    // a leftover of a server that did not end cleanly.
    let _ = std::fs::remove_file(path);
    let listener = UnixListener::bind(path).ok()?;
    let file = SocketFile(path.to_owned());
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).ok()?;
    Some((listener, file))
}

/// Hangs up the terminal of the shell, as closing a terminal window would, and tells the connected
/// client that the shell is gone.
async fn hang_up<S: Shell>(shell: Option<Running<S>>, client: Option<&Active>) {
    if let Some(Running {
        reader,
        writer,
        exit,
        ..
    }) = shell
    {
        // closing the terminal makes the kernel send SIGHUP to the shell.
        drop(reader);
        drop(writer);
        if let Some(exit) = exit {
            let _ = tokio::time::timeout(Duration::from_secs(5), exit).await;
        }
    }
    if let Some(a) = client.filter(|a| a.hello_done) {
        let _ = a.out.try_send(ServerFrame::Exit(WireExit::Signal(1)));
    }
}

async fn spawn_shell<B: Backend>(
    backend: &B,
    config: &SessionConfig,
    size: WindowSize,
    client_env: &Env,
    agent_socket: Option<&Path>,
) -> io::Result<(Running<B::Shell>, Vec<String>)> {
    let (accepted, dropped) = config.accept_env.apply(client_env);
    let mut env = config.template.env.clone();
    for (name, value) in accepted.iter() {
        env.retain(|(existing, _)| existing != name);
        env.push((name.into(), value.into()));
    }
    if let Some(socket) = agent_socket {
        env.retain(|(existing, _)| existing != "SSH_AUTH_SOCK");
        env.push(("SSH_AUTH_SOCK".into(), socket.into()));
    }
    let spec = SpawnSpec {
        program: config.template.program.clone(),
        args: config.template.args.clone(),
        env,
        cwd: config.template.cwd.clone(),
        size,
    };
    let parts = backend.spawn(&config.id, spec).await?.split();
    let running = Running {
        reader: parts.reader,
        writer: parts.writer,
        exit: Some(parts.exit),
        status: None,
        reader_eof: false,
        exit_queued: false,
    };
    Ok((running, dropped))
}

/// The line that tells the user which variables of the client the host did not take, or nothing
/// when it took all of them. It goes into the output of the session, since that is the one way to
/// reach a client of any version; the names are valid ones, so they hold no control characters.
fn dropped_notice(dropped: &[String]) -> Vec<u8> {
    const SHOWN: usize = 6;
    if dropped.is_empty() {
        return Vec::new();
    }
    let mut names = dropped
        .iter()
        .take(SHOWN)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    if dropped.len() > SHOWN {
        names.push_str(&format!(", and {} more", dropped.len() - SHOWN));
    }
    format!("ssj: the host does not accept {names} (accept_env in its server.toml)\r\n")
        .into_bytes()
}
