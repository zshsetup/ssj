//! Command line of `ssj-server`. The client builds it, so the help is for people who debug.

use std::ffi::OsString;
use std::ops::RangeInclusive;
use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;
use ssj_net::{Compress, Congestion};
use ssj_proto::{SessionId, SessionName, is_selector};

use crate::session::SlowClient;

/// Bounds for the output buffer: a size below the lower one cannot hold a screenful of output, and
/// the upper one keeps a runaway setting from using all the memory of a shared host.
pub const MIN_REPLAY_CAPACITY: usize = 64 * 1024;
/// Largest size of the replay buffer that a setting may ask for.
pub const MAX_REPLAY_CAPACITY: usize = 1 << 30;

/// Lowest port the server may use, so that it never needs privileges.
pub const MIN_PORT: u16 = 1024;

/// What the process is asked to do.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub enum Mode {
    /// Start a new session.
    #[default]
    Serve,
    /// Ask a running session to accept a new client. The pin comes on stdin.
    Attach(Option<String>),
    /// Print the running sessions.
    List,
    /// Print the version and the protocol.
    Version,
    /// Read a `server.toml` from stdin, print `OK` if it is valid, or the first error.
    CheckConfig,
    /// Print the `server.toml` that a new user starts with.
    ConfigTemplate,
    /// End a running session.
    /// End these sessions, or the only one when none is named.
    Kill(Vec<String>),
    /// Make the connected client leave; the session keeps running.
    Detach(Vec<String>),
    /// Carry the stream of a client over stdin and stdout, for hosts that allow only the `ssh`
    /// channel.
    Stdio(Option<String>),
    /// Carry the QUIC packets of a client behind a relay over stdin and stdout.
    Datagrams(Option<String>),
    /// Forward the QUIC packets of a client to a server behind this host.
    Relay,
}

/// Container for the parsed command line of `ssj-server`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Args {
    pub mode: Mode,
    /// Name of the session: a new session gets it, and a running one of that name is joined.
    pub name: Option<SessionName>,
    /// Join the only session that has no client, if there is one, instead of starting another.
    pub reuse: bool,
    /// With `reuse` and several sessions without a client, list them and exit with
    /// [`ssj_proto::bootstrap::CHOICE_EXIT_CODE`] instead of starting another.
    pub choose: bool,
    /// Arguments of the shell. The default is `-l`.
    pub shell_args: Vec<OsString>,
    /// Whether UDP (QUIC) is offered.
    pub udp: bool,
    /// Whether the process that `ssh` runs ends after the connect line, and not waits there for a
    /// client that wants the stream over the same channel.
    pub no_hold: bool,
    /// Set by the bootstrap process when it starts the real server.
    pub daemon_child: bool,
    /// The id of the session, chosen by the bootstrap process so that it shows in the arguments of
    /// the daemon (`ps`) and in the log of the client.
    pub session_id: Option<SessionId>,
    /// The settings that the command line gives. The config file fills in the others.
    pub settings: Settings,
}

/// Container for the settings that `server.toml` has as well, see [`crate::config::Config`] for
/// their meaning. `None` leaves the setting to the file.
#[derive(clap::Args, Clone, Debug, Default, PartialEq, Eq)]
pub struct Settings {
    /// UDP ports the server may use, or 0 for any
    #[arg(long, value_name = "LOW:HIGH", value_parser = parse_port_range)]
    pub port_range: Option<RangeInclusive<u16>>,
    /// Seconds without a client, or none
    #[arg(long, value_name = "SECONDS", value_parser = parse_timeout)]
    pub detached_timeout: Option<Timeout>,
    /// Limit in seconds even after a deliberate detach, or none
    #[arg(long, value_name = "SECONDS", value_parser = parse_timeout)]
    pub max_detached: Option<Timeout>,
    /// Bytes of output kept for a client that is away
    #[arg(long, value_name = "BYTES", value_parser = parse_replay_capacity)]
    pub replay_capacity: Option<usize>,
    /// Seconds a silent client may block the output
    #[arg(long, value_name = "SECONDS", value_parser = parse_away_after)]
    pub away_after: Option<Duration>,
    /// What happens to output that a slow client has not taken
    #[arg(long, value_name = "WAY")]
    pub slow_client: Option<SlowClient>,
    /// Bytes that may wait for a connected client
    #[arg(long, value_name = "BYTES", value_parser = parse_live_backlog)]
    pub live_backlog: Option<usize>,
    /// Compress output when the link is the limit
    #[arg(long, value_name = "WHEN")]
    pub compress: Option<Compress>,
    /// How fast to send
    #[arg(long, value_name = "WAY")]
    pub congestion: Option<Congestion>,
    /// Absolute path of the shell
    #[arg(long, value_name = "PATH")]
    pub shell: Option<PathBuf>,
}

/// Seconds, with `None` for no limit.
pub type Timeout = Option<Duration>;

/// The options as `clap` reads them, before the mode is found.
#[derive(Parser)]
#[command(
    name = "ssj-server",
    about = "The server of ssj, which the client starts through ssh",
    disable_version_flag = true,
    args_override_self = true
)]
struct Options {
    /// Ask a running session to accept a new client; the pin comes on stdin
    #[arg(long, value_name = "ID", num_args = 0..=1, value_parser = selector, group = "mode")]
    attach: Option<Option<String>>,
    /// End these sessions, or the only one
    #[arg(long, value_name = "ID", num_args = 0.., value_parser = selector, group = "mode")]
    kill: Option<Vec<String>>,
    /// Make the clients of these sessions leave, or of the only one
    #[arg(long, value_name = "ID", num_args = 0.., value_parser = selector, group = "mode")]
    detach: Option<Vec<String>>,
    /// Carry the stream of a client over stdin and stdout
    #[arg(long, value_name = "ID", num_args = 0..=1, value_parser = selector, group = "mode")]
    stdio: Option<Option<String>>,
    /// Carry the QUIC packets of a client behind a relay over stdin and stdout
    #[arg(long, hide = true, value_name = "ID", num_args = 0..=1, value_parser = selector, group = "mode")]
    datagrams: Option<Option<String>>,
    /// Forward the QUIC packets of a client to a server behind this host (see `ssj-net`'s `relay`)
    #[arg(long, hide = true, group = "mode")]
    relay: bool,
    /// Print the running sessions
    #[arg(long, group = "mode")]
    list: bool,
    /// Print the version and the protocol
    #[arg(long, group = "mode")]
    version: bool,
    /// Read a server.toml from stdin and print OK or the first error
    #[arg(long, group = "mode")]
    check_config: bool,
    /// Print the server.toml that a new user starts with
    #[arg(long, group = "mode")]
    config_template: bool,
    /// Join the session of this name, or start it with the name
    #[arg(long, value_parser = parse_name)]
    name: Option<SessionName>,
    /// Join the only session without a client
    #[arg(long)]
    reuse: bool,
    /// With --reuse and several sessions without a client, list them
    #[arg(long)]
    choose: bool,
    /// Offer no UDP port
    #[arg(long)]
    no_udp: bool,
    /// End the process on the ssh channel after the connect line, so that no stream can use it
    #[arg(long)]
    no_hold: bool,
    /// Argument of the shell (repeatable)
    #[arg(long, value_name = "ARG", allow_hyphen_values = true)]
    shell_arg: Vec<OsString>,
    #[arg(long, hide = true)]
    daemon_child: bool,
    #[arg(long, hide = true, value_parser = parse_session_id)]
    session_id: Option<SessionId>,
    #[command(flatten)]
    settings: Settings,
}

fn selector(text: &str) -> Result<String, String> {
    if is_selector(text) {
        Ok(text.to_owned())
    } else {
        Err("not a valid session id or name".to_owned())
    }
}

fn parse_name(text: &str) -> Result<SessionName, &'static str> {
    SessionName::parse(text).ok_or("1 to 32 characters of letters, digits, '.', '_', '-'")
}

fn parse_session_id(text: &str) -> Result<SessionId, &'static str> {
    SessionId::parse(text).ok_or("not a session id")
}

/// Parses the arguments, without the name of the program. Help goes to the output and ends the
/// program.
pub fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Args, String> {
    let words = std::iter::once(OsString::from("ssj-server")).chain(args);
    let options = match Options::try_parse_from(words) {
        Ok(options) => options,
        Err(error) if error.use_stderr() => {
            return Err(error.render().to_string().trim_end().to_owned());
        }
        Err(error) => error.exit(),
    };
    let mode = if let Some(id) = options.attach {
        Mode::Attach(id)
    } else if let Some(ids) = options.kill {
        Mode::Kill(ids)
    } else if let Some(ids) = options.detach {
        Mode::Detach(ids)
    } else if let Some(id) = options.stdio {
        Mode::Stdio(id)
    } else if let Some(id) = options.datagrams {
        Mode::Datagrams(id)
    } else if options.relay {
        Mode::Relay
    } else if options.list {
        Mode::List
    } else if options.version {
        Mode::Version
    } else if options.check_config {
        Mode::CheckConfig
    } else if options.config_template {
        Mode::ConfigTemplate
    } else {
        Mode::Serve
    };
    Ok(Args {
        mode,
        name: options.name,
        reuse: options.reuse,
        choose: options.choose,
        shell_args: options.shell_arg,
        udp: !options.no_udp,
        no_hold: options.no_hold,
        daemon_child: options.daemon_child,
        session_id: options.session_id,
        settings: options.settings,
    })
}

/// `LOW:HIGH`, or `0` for any port the kernel picks.
pub fn parse_port_range(text: &str) -> Result<RangeInclusive<u16>, String> {
    if text == "0" {
        return Ok(0..=0);
    }
    let (low, high) = text.split_once(':').ok_or("expected LOW:HIGH")?;
    let (low, high): (u16, u16) = (
        low.parse().map_err(|_| "LOW is not a port number")?,
        high.parse().map_err(|_| "HIGH is not a port number")?,
    );
    if low < MIN_PORT {
        return Err(format!("ports below {MIN_PORT} need privileges"));
    }
    if low > high {
        return Err("LOW is greater than HIGH".to_owned());
    }
    Ok(low..=high)
}

/// A number of bytes within the allowed bounds.
pub fn parse_replay_capacity(text: &str) -> Result<usize, String> {
    let size: usize = text
        .parse()
        .map_err(|_| "expected a number of bytes".to_owned())?;
    check_replay_capacity(size)
}

pub fn check_replay_capacity(size: usize) -> Result<usize, String> {
    if (MIN_REPLAY_CAPACITY..=MAX_REPLAY_CAPACITY).contains(&size) {
        Ok(size)
    } else {
        Err(format!(
            "must be between {MIN_REPLAY_CAPACITY} and {MAX_REPLAY_CAPACITY} bytes"
        ))
    }
}

/// Bounds of `live_backlog`: what may wait for a connected client before output is skipped.
const MIN_LIVE_BACKLOG: usize = 16 * 1024;
const MAX_LIVE_BACKLOG: usize = 64 << 20;

/// A number of bytes within the bounds of `live_backlog`.
fn parse_live_backlog(text: &str) -> Result<usize, String> {
    let size: usize = text
        .parse()
        .map_err(|_| "expected a number of bytes".to_owned())?;
    check_live_backlog(size)
}

pub fn check_live_backlog(size: usize) -> Result<usize, String> {
    if (MIN_LIVE_BACKLOG..=MAX_LIVE_BACKLOG).contains(&size) {
        Ok(size)
    } else {
        Err(format!(
            "must be between {MIN_LIVE_BACKLOG} and {MAX_LIVE_BACKLOG} bytes"
        ))
    }
}

/// Whole seconds, at least one.
pub fn parse_away_after(text: &str) -> Result<Duration, String> {
    match text.parse::<u64>() {
        Ok(secs) if secs > 0 => Ok(Duration::from_secs(secs)),
        _ => Err("expected a number of seconds above 0".to_owned()),
    }
}

pub fn parse_timeout(text: &str) -> Result<Option<Duration>, String> {
    match text {
        "none" | "0" => Ok(None),
        secs => secs
            .parse()
            .map(|s| Some(Duration::from_secs(s)))
            .map_err(|_| "expected seconds or none".to_owned()),
    }
}
