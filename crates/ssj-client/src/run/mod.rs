//! The session of the client: connect, pass bytes between terminal and server, and reconnect.

mod client;
mod connect;
mod sessions;
mod wire;

use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::process::ExitCode;
use std::time::Duration;

use ssj_net::Identity;
use ssj_net::relay::RelayKeys;
use ssj_proto::bootstrap::Connect;
use ssj_proto::{Env, WindowSize};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::mpsc;

use crate::cli::{Args, Command};
use crate::config::Config;
use crate::netwatch::Cause;
use crate::status::Status;
use crate::terminal::exit_on_interrupt;
use crate::vlog;

use connect::connect_session;
use sessions::{DETACH, complete, kill_session, list_sessions, send_order};

pub use client::run_session;
pub use sessions::{format_age, list_lines, sessions_json};

/// Unacknowledged input the client keeps. Must stay below the input budget of the server.
const INPUT_BUFFER: usize = 1 << 20;
/// Time to deliver the last frames before the process ends.
const FLUSH_TIMEOUT: Duration = Duration::from_secs(2);
/// Time for one attempt to connect and to get the welcome.
pub const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(8);
/// Time QUIC gets before the first connection when a stream transport runs beside it.
/// Later it may be slow to return, and gets the full time.
pub const FIRST_ATTEMPT_TIMEOUT: Duration = Duration::from_millis(1500);
/// A stream that stays silent this long is given up. The server answers a ping every second.
pub const STREAM_DEAD_AFTER: Duration = Duration::from_secs(10);

/// How the session ended.
#[derive(Debug, PartialEq, Eq)]
pub enum Finished {
    /// The shell ended with this exit code.
    Exited(u8),
    /// The user left on purpose and the session keeps running.
    Detached,
    /// The terminal was closed or `ssj` was told to end, and the server was asked to end the
    /// session (it could not be, if the connection was down).
    HungUp,
}

/// Looks up the address of the server again.
pub type Resolver =
    Box<dyn FnMut() -> Pin<Box<dyn Future<Output = Result<SocketAddr, String>> + Send>> + Send>;

/// Read half of a byte stream.
pub type Reader = Box<dyn AsyncRead + Send + Unpin>;
/// Write half of a byte stream.
pub type Writer = Box<dyn AsyncWrite + Send + Unpin>;

/// An open byte stream to the server on a transport other than QUIC.
pub struct Stream {
    pub reader: Reader,
    pub writer: Writer,
    /// Something that must live as long as the stream, such as the `ssh` process behind it.
    pub guard: Option<Box<dyn Send + Sync>>,
}

/// Opens a new stream to the server.
pub type Dial =
    Box<dyn FnMut() -> Pin<Box<dyn Future<Output = Result<Stream, String>> + Send>> + Send>;

/// One way to reach the server.
pub enum Tier {
    /// QUIC over UDP.
    Udp {
        addr: SocketAddr,
        /// Finds the address again when it may have changed. `None` keeps `addr` for good.
        resolver: Option<Resolver>,
    },
    /// QUIC over UDP to a relay on a jump host, which passes the packets on over `ssh`.
    Relay {
        /// The relay.
        addr: SocketAddr,
        keys: RelayKeys,
    },
    /// A byte stream: the `ssh` channel itself.
    Stream { name: &'static str, dial: Dial },
}

impl Tier {
    fn name(&self) -> &'static str {
        match self {
            Self::Udp { .. } => "udp",
            Self::Relay { .. } => "relay",
            Self::Stream { name, .. } => name,
        }
    }

    /// Whether the tier is QUIC, directly or through a relay.
    fn is_quic(&self) -> bool {
        matches!(self, Self::Udp { .. } | Self::Relay { .. })
    }
}

/// Everything needed to talk to a started server.
pub struct Params {
    pub identity: Identity,
    pub connect: Connect,
    /// The ways to reach the server, in the order to try them.
    pub tiers: Vec<Tier>,
    /// Notified when the first tier, a relay that was still starting, can be tried: a session that
    /// began on a stream moves to it.
    pub relay_ready: Option<std::sync::Arc<tokio::sync::Notify>>,
    /// Time for one attempt to connect and to get the welcome.
    pub attempt_timeout: Duration,
    /// Time the first tier gets in the first connection, before the next one is tried.
    pub first_attempt_timeout: Duration,
    /// Silence after which a stream (TCP or `ssh` channel) is given up.
    pub stream_dead_after: Duration,
    pub env: Env,
    /// A control byte that detaches wherever it is typed.
    pub detach_key: Option<u8>,
    /// A closed terminal or `SIGHUP` detaches and does not end the session: `ssj` runs inside an
    /// `ssh` session, whose end is more likely a lost connection than a wish.
    pub hangup_detaches: bool,
    /// Join a running session instead of starting one.
    pub attach: bool,
    /// Show typed characters before the server echoes them (see [`crate::echo`]).
    pub local_echo: bool,
    /// Compress input while the link is the limit (the server decides for its output).
    pub compress: bool,
    /// The socket of the local ssh agent, to offer it to the session.
    pub agent: Option<PathBuf>,
    /// What the line that says the session began (`[started session ...]`) names, or `None` for no
    /// line (`-q`, or no terminal).
    pub announce: Option<Announce>,
}

/// What the first line of a session names besides its id.
#[derive(Clone, Debug)]
pub struct Announce {
    pub destination: String,
    /// The name of the session, when it has one.
    pub name: Option<String>,
    /// Whether the server made the session for this client. A server that does not say counts as
    /// no: the line then says `attached to`.
    pub started: bool,
}

/// The terminal side of a session, so that tests can stand in for it.
pub struct Io {
    pub input: Box<dyn AsyncRead + Send + Unpin>,
    pub output: Box<dyn AsyncWrite + Send + Unpin>,
    pub size: WindowSize,
    /// New window sizes.
    pub resizes: mpsc::UnboundedReceiver<WindowSize>,
    pub status: Box<dyn Status>,
    /// Changes of the network and wakes from sleep. A channel that never sends is fine.
    pub net: mpsc::UnboundedReceiver<Cause>,
    /// The terminal was closed (SIGHUP) or `ssj` was told to end (SIGTERM). A channel that never
    /// sends is fine.
    pub hangups: mpsc::UnboundedReceiver<()>,
}

/// Runs the client for a parsed command line and returns the exit code.
pub fn run(args: Args) -> ExitCode {
    if let Err(err) = crate::log::init(args.verbose, args.log_file.as_deref()) {
        eprintln!("ssj: cannot open the log file: {err}");
        return ExitCode::from(1);
    }
    vlog!(1, "ssj {} starting", env!("CARGO_PKG_VERSION"));
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("ssj: cannot start the runtime: {err}");
            return ExitCode::from(1);
        }
    };
    let code = runtime.block_on(session(args));
    // the read of stdin runs on a worker thread that never returns on a terminal, so waiting for
    // the runtime to finish would hang forever.
    runtime.shutdown_background();
    ExitCode::from(code)
}

async fn session(mut args: Args) -> u8 {
    exit_on_interrupt();
    let config = match Config::load() {
        Ok(config) => config,
        Err(message) => {
            eprintln!("ssj: {message}");
            return 2;
        }
    };
    args.apply_config(&config);
    // the server compresses its output when the user asked for compression (or for none)
    if let Some(choice) = args.compress {
        args.server_args
            .extend(["--compress".to_owned(), ssj_net::word(choice)]);
    }
    if let Some(command) = &args.remote_command {
        // `ssh host command` runs the command in a shell, and so does this: the login shell of the
        // host with `-c`.
        for word in [
            "--shell-arg",
            "-l",
            "--shell-arg",
            "-c",
            "--shell-arg",
            command,
        ] {
            args.server_args.push(word.to_owned());
        }
    }
    if let Some(choice) = args.congestion {
        ssj_net::set_congestion(choice);
        args.server_args
            .extend(["--congestion".to_owned(), ssj_net::word(choice)]);
    }
    if args.batch {
        // nobody can answer a prompt of a background refresh, and nobody waits for it.
        args.ssh_command
            .extend(["-o", "BatchMode=yes", "-o", "ConnectTimeout=2"].map(str::to_owned));
    }
    match args.command.clone() {
        Command::Complete { host, connected } => complete(host.as_deref(), connected),
        Command::Connect => {
            // a name or `auto_attach` may mean a session that runs already; the server decides,
            // and the client starts with an attach, which a new session answers with `NotStarted`.
            let mut extra = Vec::new();
            if let Some(name) = &args.name {
                extra.extend(["--name".to_owned(), name.as_str().to_owned()]);
            } else if args.auto_attach {
                extra.push("--reuse".to_owned());
            }
            let attach = !extra.is_empty();
            connect_session(args, &config, &extra, attach, true).await
        }
        Command::Attach(id) => {
            let mut extra = vec!["--attach".to_owned()];
            extra.extend(id);
            connect_session(args, &config, &extra, true, false).await
        }
        Command::List => list_sessions(&args).await,
        Command::Kill(ids) => kill_session(&args, ids).await,
        Command::Detach(ids) => send_order(&args, ids, &DETACH).await,
        Command::Edit => crate::edit::run(&args).await,
        Command::Install => match connect::install_everywhere(&args).await {
            Ok(done) => {
                for line in done {
                    println!("installed {line}");
                }
                0
            }
            Err(message) => {
                eprintln!("ssj: {message}");
                1
            }
        },
    }
}

/// Reports SIGHUP (the terminal went away) and SIGTERM (`kill`): `ssj` then ends the session, as
/// `ssh` would end its shell. Losing the connection is a different thing and keeps the session.
fn hangup_signals() -> mpsc::UnboundedReceiver<()> {
    let (tx, rx) = mpsc::unbounded_channel();
    for kind in [SignalKind::hangup(), SignalKind::terminate()] {
        if let Ok(mut signal) = signal(kind) {
            let tx = tx.clone();
            tokio::spawn(async move {
                while signal.recv().await.is_some() {
                    if tx.send(()).is_err() {
                        break;
                    }
                }
            });
        }
    }
    rx
}

/// Prints a line about the session, unless `-q` is given. After a hangup the terminal is gone, and
/// `eprintln!` would panic on the error, so the write ignores errors.
fn say(args: &Args, text: &str) {
    if !args.quiet {
        let _ = std::io::Write::write_fmt(&mut std::io::stderr(), format_args!("{text}\n"));
    }
}

/// Like [`say`], for the lines that only make sense for a person at a terminal: a script that
/// reads the output of a command does not want them.
fn notice(args: &Args, text: &str) {
    use std::io::IsTerminal;
    if std::io::stdin().is_terminal() {
        say(args, text);
    }
}
