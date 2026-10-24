//! UDP to the first jump host, which passes the packets on over `ssh` (see `ssj_net::relay`).
//!
//! Two steps, so that the second can wait for the server: [`begin`] runs `ssj-server --relay` on the
//! jump host through `ssh` and learns its UDP port, in parallel with the start of the session on
//! the destination. [`Started::finish`] then tells the relay the command that reaches the
//! destination from the jump host, which needs the session.

use std::process::Stdio;
use std::time::Duration;

use ssj_proto::SessionId;
use ssj_proto::bootstrap::{MAX_OUTPUT, format_leg, format_relay_secret, parse_relay_port};
use ssj_proto::control::{Reply, parse_reply};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::time::timeout;

use crate::bootstrap::{MISSING_EXIT_CODE, MISSING_MARKER, remote_command};
use crate::cli::Args;
use crate::tunnel::{SshConfig, Stderr};

/// Time for the login to the jump host and the port of the relay.
const BEGIN_TIMEOUT: Duration = Duration::from_secs(30);
/// Time for the relay to reach the destination: a login from the jump host.
const FINISH_TIMEOUT: Duration = Duration::from_secs(60);

/// A jump host as `ssh` is told about it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hop {
    /// `user@host`, or `host`, as `ssh` takes it before the command.
    pub destination: String,
    pub port: Option<u16>,
}

impl Hop {
    /// Reads an entry of `ProxyJump`: `[ssh://][user@]host[:port]`, with an IPv6 address in
    /// brackets when a port follows. `None` for what `ssh` would not take as a host either.
    pub fn parse(spec: &str) -> Option<Self> {
        let spec = spec.trim().strip_prefix("ssh://").unwrap_or(spec.trim());
        let (user, rest) = match spec.rsplit_once('@') {
            Some((user, rest)) => (Some(user), rest),
            None => (None, spec),
        };
        let (host, port) = if let Some(inner) = rest.strip_prefix('[') {
            let (host, after) = inner.split_once(']')?;
            let port = match after.strip_prefix(':') {
                Some(port) => Some(port.parse().ok()?),
                None if after.is_empty() => None,
                None => return None,
            };
            (host, port)
        } else if rest.matches(':').count() == 1 {
            let (host, port) = rest.split_once(':')?;
            (host, Some(port.parse().ok()?))
        } else {
            (rest, None)
        };
        let plain = |text: &str| {
            !text.is_empty()
                && !text.starts_with('-')
                && text
                    .chars()
                    .all(|c| c.is_ascii_graphic() && !matches!(c, '\'' | '"' | '\\' | '`' | '$'))
        };
        if !plain(host) || user.is_some_and(|user| !plain(user)) {
            return None;
        }
        Some(Self {
            destination: match user {
                Some(user) => format!("{user}@{host}"),
                None => host.to_owned(),
            },
            port,
        })
    }

    /// The host without the user.
    pub fn host(&self) -> &str {
        self.destination
            .rsplit_once('@')
            .map_or(self.destination.as_str(), |(_, host)| host)
    }

    /// The options that tell `ssh` the port, to go before the destination.
    pub fn port_args(&self) -> Vec<String> {
        self.port
            .map_or_else(Vec::new, |port| vec!["-p".to_owned(), port.to_string()])
    }
}

/// Why the relay did not start.
#[derive(Debug, PartialEq, Eq)]
pub enum Failure {
    /// The server file is not on the jump host.
    Missing,
    Failed(String),
}

/// A relay that has a UDP port and waits for the command to the destination.
pub struct Started {
    child: Child,
    stdin: ChildStdin,
    stdout: ChildStdout,
    stderr: Stderr,
    /// What was read after the line with the port.
    pending: Vec<u8>,
    pub port: u16,
}

/// Runs the relay on the jump host and returns once it has said its port. `agent` offers the
/// agent of this machine to the jump host, for the login from there to the destination.
pub async fn begin(
    args: &Args,
    hop: &Hop,
    secret: &[u8; 32],
    agent: bool,
) -> Result<Started, Failure> {
    let command = remote_command(args, &["--relay".to_owned()]);
    let mut ssh = Command::new(&args.ssh_command[0]);
    ssh.args(&args.ssh_command[1..]).args(hop.port_args());
    if agent {
        ssh.arg("-A");
    }
    // no questions: a passphrase is asked once, by the login to the destination
    ssh.args(["-e", "none", "-T", "-o", "BatchMode=yes", "--"])
        .arg(&hop.destination)
        .arg(&command)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = ssh
        .spawn()
        .map_err(|e| Failure::Failed(format!("cannot run {}: {e}", args.ssh_command[0])))?;
    let mut stdin = child.stdin.take().expect("piped");
    let mut stdout = child.stdout.take().expect("piped");
    let mut stderr = Stderr::collect(&mut child);

    let read = timeout(BEGIN_TIMEOUT, async {
        stdin
            .write_all(format_relay_secret(secret).as_bytes())
            .await
            .ok()?;
        stdin.flush().await.ok()?;
        let mut out = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            match parse_relay_port(&out) {
                Ok(Some(port)) => return Some((port, out)),
                Ok(None) => {}
                Err(_) => return None,
            }
            if out.len() >= MAX_OUTPUT {
                return None;
            }
            match stdout.read(&mut chunk).await {
                Ok(0) | Err(_) => return None,
                Ok(n) => out.extend_from_slice(&chunk[..n]),
            }
        }
    })
    .await;
    match read {
        Ok(Some((port, pending))) => Ok(Started {
            child,
            stdin,
            stdout,
            stderr,
            pending,
            port,
        }),
        Ok(None) => {
            drop(stdin);
            let status = timeout(Duration::from_secs(5), child.wait()).await;
            let mut rest = Vec::new();
            let _ = (&mut stdout)
                .take(MAX_OUTPUT as u64)
                .read_to_end(&mut rest)
                .await;
            let missing = matches!(&status, Ok(Ok(s)) if s.code() == Some(MISSING_EXIT_CODE))
                && rest
                    .split(|b| *b == b'\n')
                    .any(|line| line == MISSING_MARKER.as_bytes());
            if missing {
                return Err(Failure::Missing);
            }
            let text = String::from_utf8_lossy(&stderr.finished().await)
                .trim()
                .to_owned();
            Err(Failure::Failed(if text.is_empty() {
                format!("{} ended without a relay", args.ssh_command[0])
            } else {
                ssj_proto::bootstrap::sanitize(text.as_bytes(), 200)
            }))
        }
        Err(_) => Err(Failure::Failed(
            "the relay did not start in time".to_owned(),
        )),
    }
}

impl Started {
    /// Tells the relay the command that reaches the destination, and waits until it carries
    /// packets. The `ssh` to the jump host ends then.
    pub async fn finish(mut self, command: &[String]) -> Result<(), String> {
        let line = format_leg(command).ok_or("the command for the relay is too long")?;
        let answer = timeout(FINISH_TIMEOUT, async {
            self.stdin
                .write_all(line.as_bytes())
                .await
                .map_err(|_| "the relay is gone".to_owned())?;
            self.stdin
                .flush()
                .await
                .map_err(|_| "the relay is gone".to_owned())?;
            let mut out = std::mem::take(&mut self.pending);
            let mut chunk = [0u8; 1024];
            loop {
                for line in out.split(|b| *b == b'\n') {
                    match parse_reply(line) {
                        Ok(Reply::Ok) => return Ok(()),
                        Ok(Reply::Error(text)) => return Err(text),
                        _ => {}
                    }
                }
                if out.len() >= MAX_OUTPUT {
                    return Err("the relay said too much".to_owned());
                }
                match self.stdout.read(&mut chunk).await {
                    Ok(0) | Err(_) => {
                        let text = String::from_utf8_lossy(&self.stderr.finished().await)
                            .trim()
                            .to_owned();
                        return Err(if text.is_empty() {
                            "the relay ended without an answer".to_owned()
                        } else {
                            ssj_proto::bootstrap::sanitize(text.as_bytes(), 200)
                        });
                    }
                    Ok(n) => out.extend_from_slice(&chunk[..n]),
                }
            }
        })
        .await;
        let _ = self.child.start_kill();
        answer.unwrap_or_else(|_| Err("the relay did not reach the host in time".to_owned()))
    }
}

/// The command, run on the jump host, that reaches `ssj-server --datagrams` of the session on the
/// destination. `target` is what `ssh -G` says about the destination, `rest` the jump hosts after
/// the first one.
pub fn leg_command(
    args: &Args,
    target: &SshConfig,
    destination: &str,
    rest: &[String],
    session: &SessionId,
    agent: bool,
) -> Vec<String> {
    let mut command: Vec<String> = ["ssh", "-e", "none", "-T", "-o", "BatchMode=yes"]
        .map(str::to_owned)
        .to_vec();
    if agent {
        command.push("-A".to_owned());
    }
    if !rest.is_empty() {
        command.extend(["-J".to_owned(), rest.join(",")]);
    }
    if let Some(port) = target.port {
        command.extend(["-p".to_owned(), port.to_string()]);
    }
    let host = target.hostname.as_deref().unwrap_or(destination);
    command.push("--".to_owned());
    command.push(match &target.user {
        Some(user) => format!("{user}@{host}"),
        None => host.to_owned(),
    });
    let extra = ["--datagrams".to_owned(), session.as_str().to_owned()];
    command.push(remote_command(args, &extra));
    command
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_hop_is_read_the_way_proxyjump_writes_it() {
        let hop = |spec: &str| Hop::parse(spec);
        let plain = |destination: &str, port| {
            Some(Hop {
                destination: destination.to_owned(),
                port,
            })
        };
        assert_eq!(hop("jump"), plain("jump", None));
        assert_eq!(hop("tim@jump"), plain("tim@jump", None));
        assert_eq!(hop("tim@jump:2222"), plain("tim@jump", Some(2222)));
        assert_eq!(hop("ssh://tim@jump:2222"), plain("tim@jump", Some(2222)));
        assert_eq!(
            hop("jump.example.org:22"),
            plain("jump.example.org", Some(22))
        );
        assert_eq!(hop("[::1]:2222"), plain("::1", Some(2222)));
        assert_eq!(hop("tim@[2001:db8::1]"), plain("tim@2001:db8::1", None));
        assert_eq!(hop("2001:db8::1"), plain("2001:db8::1", None));
    }

    #[test]
    fn what_ssh_would_not_take_as_a_host_is_refused() {
        for bad in [
            "",
            "-oProxyCommand=x",
            "tim@-jump",
            "jump:port",
            "jump:99999",
            "[::1",
            "[::1]x",
            "a b",
            "$(x)",
            "it's",
        ] {
            assert_eq!(Hop::parse(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn the_host_and_the_port_options_of_a_hop() {
        let hop = Hop::parse("tim@jump:2222").unwrap();
        assert_eq!(hop.host(), "jump");
        assert_eq!(hop.port_args(), ["-p", "2222"]);
        assert!(Hop::parse("jump").unwrap().port_args().is_empty());
    }
}
