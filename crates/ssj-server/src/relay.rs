//! `ssj-server --relay`: the jump host of a client that cannot reach the server by UDP.
//!
//! The client speaks to a UDP port of this host, and the relay passes the packets to the server
//! over an `ssh` command that it runs (see `ssj_net::relay`). Like the server, it starts as a
//! bootstrap process that `ssh` runs and a daemon that stays when `ssh` ends:
//!
//! 1. The client writes `SSJ RELAY <secret>`. The daemon binds a port and says `SSJ RELAY-PORT <n>`.
//! 2. The client, once it knows the session on the server, writes `SSJ LEG <command>`. The daemon
//!    runs the command, which ends in `ssj-server --datagrams` on the host behind this one, and
//!    answers `OK` when the command carries packets, or `ERR <reason>`.
//! 3. The daemon forwards until the command ends or no packet comes for [`IDLE`].

use std::ffi::OsString;
use std::io::{Read, Write};
use std::process::{Command, ExitCode, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ssj_net::relay::{SECRET_LEN, forward};
use ssj_proto::bootstrap::{
    MAX_LEG_LINE, find_sync, format_relay_port, parse_leg, parse_relay_port, parse_relay_secret,
    sanitize,
};
use ssj_proto::control::{Reply, format_reply};
use tokio::io::AsyncReadExt;
use tokio::net::UdpSocket;

use crate::cli::Args;
use crate::config::Config;
use crate::daemon;
use crate::launch::{read_line_with_timeout, read_longer_line_with_timeout};
use crate::listen::bind_in_range;

/// How long a relay lives without a packet of its client. A client that comes back later finds the
/// port closed and takes the `ssh` channel, which a jump host in the way allows anyway.
pub const IDLE: Duration = Duration::from_secs(8 * 60 * 60);
const SECRET_TIMEOUT: Duration = Duration::from_secs(10);
const PORT_TIMEOUT: Duration = Duration::from_secs(15);
/// The client sends the command after it has the answer of the server behind this host, which can
/// take a login with a passphrase.
const LEG_LINE_TIMEOUT: Duration = Duration::from_secs(120);
/// Time for the command to start carrying packets: a login to the next host.
const LEG_START_TIMEOUT: Duration = Duration::from_secs(45);
/// Error output of the command that is kept for the message after a failure.
const STDERR_KEPT: usize = 2048;
/// Characters of that output shown to the user.
const SHOWN: usize = 300;

fn fail(message: &str) -> ExitCode {
    eprintln!("ssj-server: {message}");
    ExitCode::from(1)
}

fn say(text: &str) -> std::io::Result<()> {
    let mut out = std::io::stdout();
    out.write_all(text.as_bytes())?;
    out.flush()
}

/// The process that `ssh` runs. It starts the daemon, passes the lines between the daemon and the
/// client, and ends when the daemon has said whether the command carries packets.
pub fn run_parent() -> ExitCode {
    daemon::close_inherited_descriptors();
    if let Err(message) = Config::load() {
        return fail(&message);
    }
    let Some(secret_line) = read_line_with_timeout(std::io::stdin(), SECRET_TIMEOUT) else {
        return fail("no relay line on stdin");
    };
    if parse_relay_secret(&secret_line).is_err() {
        return fail("stdin does not hold a valid SSJ RELAY line");
    }
    let exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(err) => return fail(&format!("cannot find the own executable: {err}")),
    };
    let mut child_args: Vec<OsString> = std::env::args_os().skip(1).collect();
    child_args.push("--daemon-child".into());
    let child = Command::new(exe)
        .args(child_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    let mut child = match child {
        Ok(child) => child,
        Err(err) => return fail(&format!("cannot start the relay process: {err}")),
    };
    let mut to_child = child.stdin.take().expect("piped");
    if to_child.write_all(&secret_line).is_err() {
        return fail("the relay process did not start");
    }
    let from_child = SharedPipe(Arc::new(Mutex::new(child.stdout.take().expect("piped"))));

    // the daemon says its port, or why it has none
    let Some(port_line) = read_line_with_timeout(from_child.clone(), PORT_TIMEOUT) else {
        return report_failure(&mut child);
    };
    if !matches!(parse_relay_port(&port_line), Ok(Some(_))) {
        return report_failure(&mut child);
    }
    if say(&String::from_utf8_lossy(&port_line)).is_err() {
        return ExitCode::from(1);
    }

    // the command for the leg goes to the daemon, and its answer to the client
    let Some(leg_line) =
        read_longer_line_with_timeout(std::io::stdin(), LEG_LINE_TIMEOUT, MAX_LEG_LINE)
    else {
        return fail("no command for the leg on stdin");
    };
    if to_child.write_all(&leg_line).is_err() {
        return report_failure(&mut child);
    }
    drop(to_child);
    let Some(answer) = read_line_with_timeout(from_child, LEG_START_TIMEOUT * 2) else {
        return report_failure(&mut child);
    };
    if say(&String::from_utf8_lossy(&answer)).is_err() {
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

/// Passes the error output of the daemon on, which says what went wrong.
fn report_failure(child: &mut std::process::Child) -> ExitCode {
    let mut message = Vec::new();
    if let Some(stderr) = child.stderr.take() {
        let _ = stderr.take(4096).read_to_end(&mut message);
    }
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::io::stderr().write_all(&message);
    ExitCode::from(1)
}

/// The daemon: binds the port, runs the command of the leg, and forwards.
pub fn run_child(args: &Args) -> ExitCode {
    daemon::close_inherited_descriptors();
    let config = match Config::load() {
        Ok(config) => config.with(&args.settings),
        Err(message) => return fail(&message),
    };
    daemon::detach_from_session();
    if let Err(err) = daemon::disable_core_dumps() {
        eprintln!("ssj-server: cannot disable core dumps: {err}");
    }
    let Some(secret_line) = read_line_with_timeout(std::io::stdin(), SECRET_TIMEOUT) else {
        return fail("no relay line on stdin");
    };
    let Ok(secret) = parse_relay_secret(&secret_line) else {
        return fail("stdin does not hold a valid SSJ RELAY line");
    };
    let socket = match bind_in_range(&config.port_range) {
        Ok(socket) => socket,
        Err(err) => return fail(&format!("cannot bind a UDP port: {err}")),
    };
    let Ok(port) = socket.local_addr().map(|addr| addr.port()) else {
        return fail("the UDP socket has no address");
    };
    if socket.set_nonblocking(true).is_err() {
        return fail("cannot set up the UDP socket");
    }
    if say(&format_relay_port(port)).is_err() {
        return ExitCode::from(1);
    }
    let Some(leg_line) =
        read_longer_line_with_timeout(std::io::stdin(), LEG_LINE_TIMEOUT, MAX_LEG_LINE)
    else {
        return fail("no command for the leg on stdin");
    };
    let command = match parse_leg(&leg_line) {
        Ok(command) => command,
        Err(_) => return fail("stdin does not hold a valid SSJ LEG line"),
    };
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => return fail(&format!("cannot start the runtime: {err}")),
    };
    runtime.block_on(relay(socket, secret, command))
}

async fn relay(
    socket: std::net::UdpSocket,
    secret: [u8; SECRET_LEN],
    command: Vec<String>,
) -> ExitCode {
    ssj_net::relay::widen_buffers(&socket);
    let Ok(socket) = UdpSocket::from_std(socket) else {
        return fail("cannot set up the UDP socket");
    };
    let mut leg = match tokio::process::Command::new(&command[0])
        .args(&command[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
    {
        Ok(child) => child,
        Err(err) => {
            let _ = say(&format_reply(&Reply::Error(format!(
                "cannot run {}: {err}",
                command[0]
            ))));
            return ExitCode::from(1);
        }
    };
    // the command talks to a person if it is let: it must not read a terminal, and it must not
    // block on a full pipe of error output.
    let stderr = Arc::new(Mutex::new(Vec::new()));
    if let Some(mut pipe) = leg.stderr.take() {
        let kept = stderr.clone();
        tokio::spawn(async move {
            let mut chunk = [0u8; 1024];
            while let Ok(n) = pipe.read(&mut chunk).await {
                if n == 0 {
                    break;
                }
                let mut kept = kept.lock().expect("not poisoned");
                let room = STDERR_KEPT.saturating_sub(kept.len());
                kept.extend_from_slice(&chunk[..n.min(room)]);
            }
        });
    }
    let (Some(input), Some(mut output)) = (leg.stdin.take(), leg.stdout.take()) else {
        return fail("the command has no pipes");
    };

    // the packets start after the sync header, and anything before it is text of a login shell
    let started = tokio::time::timeout(LEG_START_TIMEOUT, async {
        let mut seen = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            if let Some(at) = find_sync(&seen) {
                return Some(seen.split_off(at));
            }
            // a header cannot be longer than what is kept
            if seen.len() > 8192 {
                return None;
            }
            match output.read(&mut chunk).await {
                Ok(0) | Err(_) => return None,
                Ok(n) => seen.extend_from_slice(&chunk[..n]),
            }
        }
    })
    .await;
    let Ok(Some(rest)) = started else {
        let reason = {
            let text = stderr.lock().expect("not poisoned");
            match sanitize(&text, SHOWN).trim() {
                "" => "the command did not start the server side of the relay".to_owned(),
                shown => shown.to_owned(),
            }
        };
        let _ = say(&format_reply(&Reply::Error(reason)));
        let _ = leg.start_kill();
        return ExitCode::from(1);
    };
    if say(&format_reply(&Reply::Ok)).is_err() {
        return ExitCode::from(1);
    }
    // the client has its answer, and nothing of the `ssh` channel is needed any more
    let _ = daemon::silence_stdio();

    let reader = AsyncReadExt::chain(std::io::Cursor::new(rest), output);
    let _ = forward(Arc::new(socket), &secret, reader, input, IDLE).await;
    let _ = leg.start_kill();
    let _ = leg.wait().await;
    ExitCode::SUCCESS
}

/// A pipe that two readers use one after the other. A thread that reads a line takes what it is
/// given, so the pipe is shared and each read locks it.
#[derive(Clone)]
struct SharedPipe(Arc<Mutex<std::process::ChildStdout>>);

impl Read for SharedPipe {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.lock().expect("not poisoned").read(buf)
    }
}
