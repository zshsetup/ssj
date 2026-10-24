//! Start of the server: the bootstrap process that `ssh` runs, and the daemon it creates.
//!
//! The bootstrap process reads the pinned client fingerprint from stdin, starts the daemon, waits
//! for the line with port and server fingerprint, prints it, and exits. The daemon then holds no
//! file of the `ssh` channel, so `ssh` ends while the session keeps running.

use std::ffi::OsString;
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Command, ExitCode, Stdio};
use std::sync::Arc;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use ssj_proto::SessionId;
use ssj_proto::bootstrap::{
    MAX_START_LINE, Prestart, format_connect, format_pin, parse_connect, parse_pin, parse_start,
};
use ssj_proto::control::{Reply, SessionState, format_reply};
use tokio::net::UnixListener;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::{Mutex, mpsc as tokio_mpsc};

use crate::backend::Direct;
use crate::cli::Args;
use crate::config::Config;
use crate::control_cli;
use crate::control_server::{Context, serve_control};
use crate::control_socket;
use crate::control_socket::{SocketFile, agent_path, control_dir, ensure_private_dir, socket_path};
use crate::daemon;
use crate::frontend::Frontend;
use crate::session::{
    Session, SessionCommand, SessionConfig, SessionEnd, SessionEvent, SpawnTemplate,
};

/// Longest line the bootstrap accepts from stdin or from the daemon.
pub(crate) const MAX_LINE: usize = 512;
const PIN_TIMEOUT: Duration = Duration::from_secs(10);
const START_TIMEOUT: Duration = Duration::from_secs(15);
/// Time for the optional second line after the pin line. The client writes both at once, so this
/// only matters for a person who types the pin by hand.
const START_LINE_TIMEOUT: Duration = Duration::from_secs(2);
/// A session that no client joins within this time ends with its shell (see
/// `SessionConfig::first_client_timeout`). The client has to get through `ssh`, UDP that may be
/// blocked, and the transports after it.
const FIRST_CLIENT_TIMEOUT: Duration = Duration::from_secs(120);
const HELLO_TIMEOUT: Duration = Duration::from_secs(10);
/// Silence after which a connection is given up, see `SessionConfig::lost_after`.
const LOST_AFTER: Duration = Duration::from_secs(60);
/// How long a finished session waits for the confirmation of its exit status.
const EXIT_GRACE: Duration = Duration::from_secs(60);

/// Reads one line of at most [`MAX_LINE`] bytes in a thread, so that the wait has a limit.
pub(crate) fn read_line_with_timeout(
    source: impl Read + Send + 'static,
    limit: Duration,
) -> Option<Vec<u8>> {
    read_longer_line_with_timeout(source, limit, MAX_LINE)
}

/// Like [`read_line_with_timeout`] for a line of at most `max` bytes.
pub(crate) fn read_longer_line_with_timeout(
    source: impl Read + Send + 'static,
    limit: Duration,
    max: usize,
) -> Option<Vec<u8>> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut line = Vec::new();
        let mut reader = BufReader::new(source.take(max as u64));
        let result = reader.read_until(b'\n', &mut line).map(|_| line);
        let _ = tx.send(result);
    });
    rx.recv_timeout(limit).ok()?.ok()
}

/// What the client writes to the stdin of the server: the pin line, and after it the optional line
/// with what the shell of a fresh session needs.
pub(crate) struct BootstrapInput {
    pub pin: [u8; 32],
    /// The line as it came, for the daemon. `None` if it was missing or not valid.
    pub start_line: Option<Vec<u8>>,
    pub start: Option<Prestart>,
}

/// Reads the pin line, then the start line if there is one. The reading runs in a thread, so
/// that the wait has a limit.
pub(crate) fn read_bootstrap_input(
    source: impl Read + Send + 'static,
) -> Result<BootstrapInput, &'static str> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut reader = BufReader::new(source);
        let mut pin = Vec::new();
        let first = (&mut reader)
            .take(MAX_LINE as u64)
            .read_until(b'\n', &mut pin)
            .map(|_| pin);
        let failed = first.is_err();
        let _ = tx.send(first);
        if failed {
            return;
        }
        let mut start = Vec::new();
        let second = (&mut reader)
            .take(MAX_START_LINE as u64)
            .read_until(b'\n', &mut start)
            .map(|_| start);
        let _ = tx.send(second);
    });
    let pin_line = rx
        .recv_timeout(PIN_TIMEOUT)
        .ok()
        .and_then(Result::ok)
        .ok_or("no pin line on stdin")?;
    let pin = parse_pin(&pin_line).map_err(|_| "stdin does not hold a valid SSJ PIN line")?;
    let start_line = rx
        .recv_timeout(START_LINE_TIMEOUT)
        .ok()
        .and_then(Result::ok)
        .filter(|line| !line.is_empty());
    // a start line that is wrong only costs the head start of the shell.
    let start = start_line
        .as_deref()
        .and_then(|line| parse_start(line).ok());
    let start_line = start.as_ref().and(start_line);
    Ok(BootstrapInput {
        pin,
        start_line,
        start,
    })
}

fn fail(message: &str, code: u8) -> ExitCode {
    eprintln!("ssj-server: {message}");
    ExitCode::from(code)
}

/// What the arguments ask for among the running sessions.
enum Existing {
    /// Start a new session.
    None,
    /// Join this one.
    Join(control_socket::Found),
    /// Several sessions have no client and the caller wants to choose.
    Choose(Vec<control_socket::Found>),
}

/// The running session that the arguments ask for, if there is one: the one with the name, or with
/// `--reuse` the only session of this protocol that has no client. A name is unique per user.
fn existing_session(args: &Args) -> Result<Existing, String> {
    if args.name.is_none() && !args.reuse {
        return Ok(Existing::None);
    }
    let sessions = control_socket::control_dir()
        .map(|dir| control_socket::find_sessions(&dir))
        .unwrap_or_default();
    if let Some(name) = &args.name {
        let found = sessions
            .into_iter()
            .find(|f| f.info.name.as_ref() == Some(name));
        return match found {
            Some(f) if f.info.protocol != ssj_proto::PROTOCOL => Err(format!(
                "the name {} is used by a session of protocol {}",
                name.as_str(),
                f.info.protocol
            )),
            Some(found) => Ok(Existing::Join(found)),
            None => Ok(Existing::None),
        };
    }
    let mut free: Vec<_> = sessions
        .into_iter()
        .filter(|f| {
            f.info.protocol == ssj_proto::PROTOCOL && f.info.state != SessionState::Connected
        })
        .collect();
    Ok(match free.len() {
        0 => Existing::None,
        1 => Existing::Join(free.pop().expect("one")),
        _ if args.choose => Existing::Choose(free),
        _ => Existing::None,
    })
}

/// The process started by `ssh`.
pub fn run_parent(args: &Args) -> ExitCode {
    daemon::close_inherited_descriptors();
    // the daemon reads the file again; a broken one is reported here, where the client sees it.
    if let Err(message) = Config::load() {
        return fail(&message, 2);
    }
    if daemon::is_root() {
        eprintln!("ssj-server: warning: running as root, the session shell will be a root shell");
    }
    let input = match read_bootstrap_input(std::io::stdin()) {
        Ok(input) => input,
        Err(message) => return fail(message, 2),
    };
    let pin = input.pin;
    // a named session, or the only free one, is joined instead of starting another.
    match existing_session(args) {
        Err(message) => return fail(&message, 1),
        Ok(Existing::Join(found)) => {
            return control_cli::attach_session(&found, pin, !args.no_hold);
        }
        Ok(Existing::Choose(free)) => {
            let mut out = std::io::stdout();
            for found in free {
                let _ = out.write_all(format_reply(&Reply::Info(found.info)).as_bytes());
            }
            return ExitCode::from(ssj_proto::bootstrap::CHOICE_EXIT_CODE);
        }
        Ok(Existing::None) => {}
    }

    let exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(err) => return fail(&format!("cannot find the own executable: {err}"), 1),
    };
    // the daemon gets the same arguments, and an id that it shows in `ps` and that the client
    // prints in its log.
    let mut child_args: Vec<OsString> = std::env::args_os().skip(1).collect();
    child_args.push("--daemon-child".into());
    if let Ok(id) = daemon::random_session_id() {
        child_args.extend(["--session-id".into(), id.into()]);
    }
    let child = Command::new(exe)
        .args(child_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    let mut child = match child {
        Ok(child) => child,
        Err(err) => return fail(&format!("cannot start the server process: {err}"), 1),
    };
    let mut stdin = child.stdin.take().expect("piped");
    let written =
        stdin
            .write_all(format_pin(&pin).as_bytes())
            .and_then(|_| match &input.start_line {
                Some(line) => stdin.write_all(line),
                None => Ok(()),
            });
    if written.is_err() {
        return fail("the server process did not start", 1);
    }
    drop(stdin);

    let stdout = child.stdout.take().expect("piped");
    let Some(reply) = read_line_with_timeout(stdout, START_TIMEOUT) else {
        let _ = child.kill();
        return report_child_failure(&mut child);
    };
    let Some(mut connect) = parse_connect(&reply).ok().flatten() else {
        // a child that printed something else may still run, and waiting for it would hang.
        let _ = child.kill();
        return report_child_failure(&mut child);
    };
    // this server made the session, and only it can tell the client so.
    connect.new = true;
    connect.name = args.name.clone();
    let mut out = std::io::stdout();
    if out
        .write_all(format_connect(&connect).as_bytes())
        .and_then(|_| out.flush())
        .is_err()
    {
        return ExitCode::from(1);
    }
    match connect.socket.as_deref() {
        Some(path) if !args.no_hold => control_cli::hold_for_stream(std::path::Path::new(path)),
        _ => ExitCode::SUCCESS,
    }
}

fn report_child_failure(child: &mut std::process::Child) -> ExitCode {
    let mut message = Vec::new();
    if let Some(stderr) = child.stderr.take() {
        let _ = stderr.take(4096).read_to_end(&mut message);
    }
    let _ = child.wait();
    let _ = std::io::stderr().write_all(&message);
    ExitCode::from(1)
}

/// Environment of the shell before the variables of the client: the own one without leftovers
/// of the bootstrap session.
fn base_env() -> Vec<(OsString, OsString)> {
    std::env::vars_os()
        .filter(|(name, _)| {
            let name = name.to_string_lossy();
            !(name.starts_with("SSH_")
                || name.starts_with("XDG_SESSION_")
                || name.starts_with("SSJ_"))
        })
        .collect()
}

/// The daemon: runs the session until it ends.
pub fn run_child(args: Args) -> ExitCode {
    daemon::close_inherited_descriptors();
    let config = match Config::load() {
        Ok(config) => config.with(&args.settings),
        Err(message) => return fail(&message, 2),
    };
    ssj_net::set_congestion(config.congestion);
    daemon::detach_from_session();
    if let Err(err) = daemon::disable_core_dumps() {
        eprintln!("ssj-server: cannot disable core dumps: {err}");
    }
    let input = match read_bootstrap_input(std::io::stdin()) {
        Ok(input) => input,
        Err(message) => return fail(message, 2),
    };
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => return fail(&format!("cannot start the runtime: {err}"), 1),
    };
    runtime.block_on(run_session(args, config, input))
}

async fn run_session(args: Args, settings: Config, input: BootstrapInput) -> ExitCode {
    let pin = input.pin;
    let id = args.session_id.clone().or_else(|| {
        daemon::random_session_id()
            .ok()
            .and_then(|id| SessionId::parse(&id))
    });
    let Some(id) = id else {
        return fail("cannot create a session id", 1);
    };
    let (conns, conns_rx) = tokio_mpsc::channel(4);
    let mut frontend = Frontend::new(
        id.clone(),
        settings.port_range.clone(),
        conns,
        HELLO_TIMEOUT,
    )
    .with_udp(args.udp)
    // QUIC takes no more unacknowledged output than may wait for a connected client.
    .with_send_window(settings.live_backlog as u64);
    let mut connect = match frontend.open(pin).await {
        Ok(connect) => connect,
        Err(err) => return fail(&err.to_string(), 1),
    };

    // the control socket exists before the client hears about the session.
    let socket = match prepare_control_socket(&id) {
        Ok(socket) => socket,
        Err(err) => return fail(&format!("cannot create the control socket: {err}"), 1),
    };
    let (listener, socket_file) = socket;
    connect.socket = control_socket::socket_field(&socket_file.0);

    let mut out = std::io::stdout();
    let _ = out.write_all(format_connect(&connect).as_bytes());
    let _ = out.flush();
    // from here on the daemon holds nothing of the `ssh` channel.
    if let Err(err) = daemon::silence_stdio() {
        eprintln!("ssj-server: cannot release stdio: {err}");
    }

    let shell = settings
        .shell
        .clone()
        .or_else(|| std::env::var_os("SHELL").map(Into::into))
        .unwrap_or_else(|| "/bin/sh".into());
    let shell_args = if args.shell_args.is_empty() {
        vec!["-l".into()]
    } else {
        args.shell_args.clone()
    };
    let config = SessionConfig {
        id: id.clone(),
        template: SpawnTemplate {
            program: shell,
            args: shell_args,
            env: base_env(),
            cwd: None,
        },
        accept_env: settings.accept_env.clone(),
        replay_capacity: settings.replay_capacity,
        away_after: settings.away_after,
        slow_client: settings.slow_client,
        live_backlog: settings.live_backlog,
        // the directory exists: the control socket was made in it.
        agent_socket: control_dir().ok().map(|dir| agent_path(&dir, id.as_str())),
        compress: settings.compress == ssj_net::Compress::Auto,
        prestart: input.start,
        first_client_timeout: FIRST_CLIENT_TIMEOUT,
        detached_timeout: settings.detached_timeout,
        max_detached: settings.max_detached,
        hello_timeout: HELLO_TIMEOUT,
        lost_after: LOST_AFTER,
        exit_grace: EXIT_GRACE,
    };

    let (events, mut events_rx) = tokio_mpsc::unbounded_channel();
    let (commands, commands_rx) = tokio_mpsc::unbounded_channel();
    let context = Arc::new(Context {
        id,
        name: args.name.clone(),
        started: Instant::now(),
        state: std::sync::Mutex::new(SessionState::Disconnected),
        frontend: Mutex::new(frontend),
        commands: commands.clone(),
    });
    tokio::spawn(serve_control(listener, context.clone()));

    let watching = context.clone();
    tokio::spawn(async move {
        while let Some(event) = events_rx.recv().await {
            match event {
                SessionEvent::Connected => watching.set_state(SessionState::Connected),
                SessionEvent::Disconnected => watching.set_state(SessionState::Disconnected),
                SessionEvent::Detached => {
                    watching.set_state(SessionState::Detached);
                    // nobody can connect anymore, and the next attach opens a new endpoint.
                    watching.frontend.lock().await.close();
                }
            }
        }
    });

    // closing like a terminal: the same as `ssj kill`. SIGHUP is ignored, since the end of the
    // `ssh` channel of the bootstrap can send it.
    for kind in [SignalKind::terminate(), SignalKind::interrupt()] {
        if let Ok(mut signal) = signal(kind) {
            let commands = commands.clone();
            tokio::spawn(async move {
                while signal.recv().await.is_some() {
                    let _ = commands.send(SessionCommand::Kill);
                }
            });
        }
    }
    if let Ok(mut hangup) = signal(SignalKind::hangup()) {
        tokio::spawn(async move { while hangup.recv().await.is_some() {} });
    }

    let end = Session::new(Direct, config)
        .with_events(events)
        .with_commands(commands_rx)
        .run(conns_rx)
        .await;
    if matches!(end, SessionEnd::Killed) {
        // the exit status for a connected client is queued, and needs a moment to leave.
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    context.frontend.lock().await.close_and_flush().await;
    match end {
        SessionEnd::Failed(_) => ExitCode::from(1),
        _ => ExitCode::SUCCESS,
    }
}

/// Binds the socket in the private directory, for this user only.
fn prepare_control_socket(id: &SessionId) -> std::io::Result<(UnixListener, SocketFile)> {
    use std::os::unix::fs::PermissionsExt;
    let dir = control_dir()?;
    ensure_private_dir(&dir)?;
    let path = socket_path(&dir, id.as_str());
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path)?;
    let file = SocketFile(path.clone());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    Ok((listener, file))
}
