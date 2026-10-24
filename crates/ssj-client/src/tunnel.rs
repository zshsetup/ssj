//! The transports that go through `ssh` itself: the control socket of the session and TCP with
//! TLS, both through `ssh -W`, and the stdin and stdout of `ssj-server --stdio`.

use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ssj_proto::SessionId;
use ssj_proto::bootstrap::{MAX_OUTPUT, SYNC_HEADER, find_sync, sanitize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::time::timeout;

use crate::bootstrap::remote_command;
use crate::cli::Args;
use crate::run::{Dial, Stream, Tier};

/// Text of the error output of `ssh` that is kept for the message after a failure.
const STDERR_KEPT: usize = 2048;
/// Characters of the error output shown.
const SHOWN: usize = 120;
/// Time `ssh -G` gets.
const CONFIG_TIMEOUT: Duration = Duration::from_secs(2);

/// The `ssh` command for a connection that stays open: no escape character, no terminal, and no
/// questions, since a reconnect cannot ask for a passphrase. An agent or a shared connection
/// (`ControlMaster`) provides the authentication.
fn ssh_base(args: &Args) -> Command {
    let mut ssh = Command::new(&args.ssh_command[0]);
    ssh.args(&args.ssh_command[1..])
        .args(args.ssh_port_args())
        .args(["-e", "none", "-T", "-o", "BatchMode=yes"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    ssh
}

/// A way to reach the server, without the details.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Udp,
    Stdio,
}

/// The transports to try, in order, for the choice of the user and what is known about the path.
///
/// `udp` says whether the server offers UDP. The `ssh` channel is always there. With a jump host
/// in the way UDP is left out, since datagrams do not travel through it. UDP, when the user chose
/// it and it is not available, leaves the list empty, so that the caller can say why.
pub fn tier_order(choice: crate::cli::Transport, jump: bool, udp: bool) -> Vec<Kind> {
    use crate::cli::Transport;
    match choice {
        Transport::Udp if udp => vec![Kind::Udp],
        Transport::Udp => Vec::new(),
        Transport::Stdio => vec![Kind::Stdio],
        Transport::Auto if udp && !jump => vec![Kind::Udp, Kind::Stdio],
        Transport::Auto => vec![Kind::Stdio],
    }
}

/// What `ssh -G` says about the destination that matters here.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SshConfig {
    /// The `HostName` after the aliases of the configuration, which is where UDP goes.
    pub hostname: Option<String>,
    /// A jump host or a proxy command is in the way. UDP does not travel through one.
    pub jump: bool,
    /// The jump hosts of `ProxyJump` in order, as written. Empty for none and for a proxy command.
    pub proxy_jump: Vec<String>,
    /// A `ProxyCommand` is in the way, which cannot be followed.
    pub proxy_command: bool,
    /// The user and the port that `ssh` would use for the destination.
    pub user: Option<String>,
    pub port: Option<u16>,
    /// `ForwardAgent yes`: `ssh` offers the agent to the host.
    pub forward_agent: bool,
    /// The patterns of `SendEnv`: `ssh` sends these variables to the host, and `ssj` sends them as
    /// well. A pattern that `ssj` would not take is left out.
    pub send_env: Vec<String>,
}

/// Reads the output of `ssh -G`: lines of a lowercase key and a value.
pub fn parse_ssh_config(config: &str) -> SshConfig {
    let mut out = SshConfig::default();
    for line in config.lines() {
        let mut words = line.splitn(2, ' ');
        let (Some(key), Some(value)) = (words.next(), words.next()) else {
            continue;
        };
        let value = value.trim();
        match key {
            "hostname" if out.hostname.is_none() && !value.is_empty() => {
                out.hostname = Some(value.to_owned());
            }
            "proxyjump" if !value.is_empty() && value != "none" => {
                out.jump = true;
                out.proxy_jump = value
                    .split(',')
                    .map(str::trim)
                    .filter(|hop| !hop.is_empty())
                    .map(str::to_owned)
                    .collect();
            }
            "proxycommand" if !value.is_empty() && value != "none" => {
                out.jump = true;
                out.proxy_command = true;
            }
            "user" if out.user.is_none() && !value.is_empty() => {
                out.user = Some(value.to_owned());
            }
            "port" if out.port.is_none() => out.port = value.parse().ok(),
            "forwardagent" => out.forward_agent = value == "yes",
            "sendenv" if ssj_proto::EnvFilter::new(vec![value.to_owned()]).is_ok() => {
                out.send_env.push(value.to_owned());
            }
            _ => {}
        }
    }
    out
}

/// Whether the configuration of `ssh` goes through a jump host or a proxy command.
pub fn jump_in_config(config: &str) -> bool {
    parse_ssh_config(config).jump
}

/// Asks `ssh -G` about the destination, once for the whole connection. `None` if `ssh` cannot say.
pub async fn ssh_config(args: &Args) -> Option<SshConfig> {
    ssh_config_of(args, &args.destination, &args.ssh_port_args()).await
}

/// Like [`ssh_config`] for another destination, such as a jump host, with its own port options.
pub async fn ssh_config_of(
    args: &Args,
    destination: &str,
    port_args: &[String],
) -> Option<SshConfig> {
    let mut ssh = Command::new(&args.ssh_command[0]);
    ssh.args(&args.ssh_command[1..])
        .args(port_args)
        .args(["-G", "--"])
        .arg(destination)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let child = ssh.spawn().ok()?;
    match timeout(CONFIG_TIMEOUT, child.wait_with_output()).await {
        Ok(Ok(output)) if output.status.success() => {
            Some(parse_ssh_config(&String::from_utf8_lossy(&output.stdout)))
        }
        _ => None,
    }
}

/// Collects the error output of a process in the background, so that its pipe never fills up and
/// the text is there when the process fails.
pub(crate) struct Stderr(Arc<Mutex<Vec<u8>>>, Option<tokio::task::JoinHandle<()>>);

impl Stderr {
    pub(crate) fn collect(child: &mut Child) -> Self {
        let kept = Arc::new(Mutex::new(Vec::new()));
        let mut reader = None;
        if let Some(mut stderr) = child.stderr.take() {
            let kept = kept.clone();
            reader = Some(tokio::spawn(async move {
                let mut chunk = [0u8; 512];
                while let Ok(n) = stderr.read(&mut chunk).await {
                    if n == 0 {
                        break;
                    }
                    let mut kept = kept.lock().expect("not poisoned");
                    let room = STDERR_KEPT.saturating_sub(kept.len());
                    kept.extend_from_slice(&chunk[..n.min(room)]);
                }
            }));
        }
        Self(kept, reader)
    }

    /// What was kept, once the process has closed its error output (a moment at most).
    pub(crate) async fn finished(&mut self) -> Vec<u8> {
        if let Some(reader) = self.1.take() {
            let _ = timeout(Duration::from_secs(2), reader).await;
        }
        self.0.lock().expect("not poisoned").clone()
    }

    /// The text for a message, safe to show on a terminal.
    fn text(&self) -> String {
        let kept = self.0.lock().expect("not poisoned");
        sanitize(kept.trim_ascii(), SHOWN)
            .replace('?', " ")
            .trim()
            .to_owned()
    }
}

/// What an `ssh` process shows when it fails, or the reason given.
async fn explain(stderr: &Stderr, fallback: &str) -> String {
    // the text may still be on its way from the pipe.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let text = stderr.text();
    if text.is_empty() {
        fallback.to_owned()
    } else {
        text
    }
}

/// Reads `stdout` until the sync header; returns the bytes after it. `seen` holds what was read
/// already. An empty error means that the output ended.
async fn read_until_sync(
    stdout: &mut ChildStdout,
    mut seen: Vec<u8>,
    limit: Duration,
) -> Result<Vec<u8>, String> {
    timeout(limit, async {
        let mut chunk = [0u8; 4096];
        loop {
            if let Some(end) = find_sync(&seen) {
                return Ok(seen.split_off(end));
            }
            if seen.len() > MAX_OUTPUT {
                return Err("the host sent no stream".to_owned());
            }
            match stdout.read(&mut chunk).await {
                Ok(0) | Err(_) => return Err(String::new()),
                Ok(n) => seen.extend_from_slice(&chunk[..n]),
            }
        }
    })
    .await
    .unwrap_or_else(|_| Err("no answer".to_owned()))
}

/// The `ssh` that started the server, kept open after it printed the connect line: the server
/// process waits on it for [`ssj_proto::bootstrap::STREAM_LINE`] and then carries the session
/// like `--stdio`, so that a transport other than QUIC does not need another login.
pub struct Held {
    child: Child,
    stdin: ChildStdin,
    stdout: ChildStdout,
    /// What came after the connect line, if anything.
    seen: Vec<u8>,
    stderr: Stderr,
}

impl Held {
    pub(crate) fn new(
        child: Child,
        stdin: ChildStdin,
        stdout: ChildStdout,
        seen: Vec<u8>,
        stderr: Stderr,
    ) -> Self {
        Self {
            child,
            stdin,
            stdout,
            seen,
            stderr,
        }
    }

    /// Asks the server process for the stream, and returns it once the stream begins.
    async fn open(self, limit: Duration) -> Result<Stream, String> {
        let Self {
            child,
            mut stdin,
            mut stdout,
            seen,
            stderr,
        } = self;
        if stdin
            .write_all(ssj_proto::bootstrap::STREAM_LINE.as_bytes())
            .await
            .and(stdin.flush().await)
            .is_err()
        {
            return Err("the first connection is closed".to_owned());
        }
        match read_until_sync(&mut stdout, seen, limit).await {
            Ok(rest) => Ok(Stream {
                reader: Box::new(std::io::Cursor::new(rest).chain(stdout)),
                writer: Box::new(stdin),
                guard: Some(Box::new(child)),
            }),
            Err(reason) if reason.is_empty() => {
                Err(explain(&stderr, "the first connection is closed").await)
            }
            Err(reason) => Err(reason),
        }
    }
}

/// Lets the first stream of `tier` run over the kept `ssh` instead of a new login. The stream
/// after it, and the stream when the kept `ssh` has ended (a server that does not hold it, or
/// a wait that was too long), is made by the dial of the tier as before.
pub fn with_held(tier: Tier, held: Held, limit: Duration) -> Tier {
    let Tier::Stream { name, mut dial } = tier else {
        return tier;
    };
    let mut held = Some(held);
    let dial: Dial = Box::new(move || {
        let fallback = dial();
        match held.take() {
            Some(held) => Box::pin(async move {
                match held.open(limit).await {
                    Ok(stream) => {
                        crate::vlog!(1, "the stream runs over the first connection");
                        Ok(stream)
                    }
                    Err(reason) => {
                        crate::vlog!(
                            1,
                            "the first connection cannot carry it ({reason}): a new login"
                        );
                        fallback.await
                    }
                }
            }),
            None => fallback,
        }
    });
    Tier::Stream { name, dial }
}

/// The stream of `ssj-server --stdio` on the `ssh` channel.
pub fn stdio_tier(args: &Args, id: &SessionId, limit: Duration) -> Tier {
    let (args, id) = (args.clone(), id.clone());
    let dial: Dial = Box::new(move || {
        let (args, id) = (args.clone(), id.clone());
        Box::pin(async move { dial_stdio(&args, &id, limit).await })
    });
    Tier::Stream {
        name: "stdio",
        dial,
    }
}

async fn dial_stdio(args: &Args, id: &SessionId, limit: Duration) -> Result<Stream, String> {
    if args.destination.starts_with('-') {
        return Err("the destination must not start with '-'".to_owned());
    }
    let command = remote_command(args, &["--stdio".to_owned(), id.as_str().to_owned()]);
    let mut ssh = ssh_base(args);
    ssh.arg("--").arg(&args.destination).arg(command);
    let mut child = ssh
        .spawn()
        .map_err(|e| format!("cannot run {}: {e}", args.ssh_command[0]))?;
    let stderr = Stderr::collect(&mut child);
    let mut stdout: ChildStdout = child.stdout.take().expect("piped");
    let stdin = child.stdin.take().expect("piped");

    // shell startup files may print text first, so the stream starts at the sync header.
    let rest = match read_until_sync(&mut stdout, Vec::new(), limit).await {
        Ok(rest) => rest,
        Err(reason) if reason.is_empty() => {
            return Err(explain(&stderr, "the connection ended").await);
        }
        Err(reason) => return Err(reason),
    };
    let _ = SYNC_HEADER;
    let reader = std::io::Cursor::new(rest).chain(stdout);
    Ok(Stream {
        reader: Box::new(reader),
        writer: Box::new(stdin),
        guard: Some(Box::new(child)),
    })
}
