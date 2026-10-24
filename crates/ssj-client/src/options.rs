//! The command line of `ssj` as `clap` sees it, which `ssj-assets` also turns into the
//! completions and the man page.

use std::path::PathBuf;

use clap::{Args, CommandFactory, Parser, Subcommand, ValueHint};
use ssj_net::{Compress, Congestion};
use ssj_proto::SessionName;

use crate::cli::{LocalEcho, Relay, Transport, parse_detach_key};

/// A control byte, or `None` for no key.
type Key = Option<u8>;
/// The words of a command.
type Words = Vec<String>;

/// The command for parsing, the help, the man page, and the completions. A repeated option takes
/// the last value.
pub fn command() -> clap::Command {
    Cli::command().mut_subcommands(|sub| sub.args_override_self(true))
}

/// Container for the command line of `ssj`.
#[derive(Parser, Debug)]
#[command(
    name = "ssj",
    version,
    about = "A roaming remote shell that survives jumps",
    long_about = None,
    disable_help_subcommand = true,
    arg_required_else_help = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<CommandLine>,

    /// Print the cached session names for tab completion, of one host or of all
    #[arg(long, value_name = "HOST", num_args = 0..=1, default_missing_value = "", hide = true)]
    pub complete: Option<String>,

    /// With --complete: only the sessions that have a client
    #[arg(long, hide = true)]
    pub connected: bool,
}

/// The commands of `ssj`.
#[derive(Subcommand, Debug)]
pub enum CommandLine {
    /// Start a session on a host, or join one
    ///
    /// Every word after the destination belongs to the command that runs in the session instead of
    /// the shell, options included, as with ssh: `ssj connect host ls -l`.
    Connect {
        #[command(flatten)]
        ssh: Ssh,
        #[command(flatten)]
        server: Server,
        #[command(flatten)]
        upload: Upload,
        #[command(flatten)]
        session: Session,
        #[command(flatten)]
        connection: Connection,
        /// [user@]host[:port] or ssh://[user@]host[:port], and a command to run instead of the
        /// shell
        #[arg(
            required = true,
            num_args = 1..,
            trailing_var_arg = true,
            value_names = ["DESTINATION", "COMMAND"],
            value_hint = ValueHint::Hostname
        )]
        line: Vec<String>,
    },
    /// List the sessions of a host
    ///
    /// Each line has the id, the state, the age, the protocol, and the name of a session. A
    /// terminal gets a header.
    List {
        #[command(flatten)]
        ssh: Ssh,
        #[command(flatten)]
        server: Server,
        /// Print the sessions as JSON
        #[arg(long)]
        json: bool,
        /// Never prompt, give up after 2 seconds (for background refreshes)
        #[arg(long, hide = true)]
        batch: bool,
        #[command(flatten)]
        host: Host,
    },
    /// Join a running session
    ///
    /// ID is an id or a name. Without it the only session is joined, and with several a menu asks
    /// which one.
    Attach {
        #[command(flatten)]
        ssh: Ssh,
        #[command(flatten)]
        server: Server,
        #[command(flatten)]
        upload: Upload,
        #[command(flatten)]
        session: Session,
        #[command(flatten)]
        host: Host,
        /// The id or the name of a session
        #[arg(value_name = "ID", value_parser = selector)]
        id: Option<String>,
    },
    /// End sessions
    ///
    /// Each ID is an id or a name. Without an ID the only session is ended after a question, and
    /// with several sessions a menu asks which one. A name that is also the id of another session
    /// gets a menu as well.
    Kill {
        #[command(flatten)]
        ssh: Ssh,
        #[command(flatten)]
        server: Server,
        /// Do not ask before ending the only session of the host
        #[arg(short = 'f', long)]
        force: bool,
        #[command(flatten)]
        host: Host,
        /// The ids or the names of sessions
        #[arg(id = "id", value_name = "ID", value_parser = selector)]
        ids: Vec<String>,
    },
    /// Make the clients of sessions leave
    ///
    /// The sessions keep running. Each ID is an id or a name. Without an ID the only session that
    /// has a client is detached, and with several a menu asks which one.
    Detach {
        #[command(flatten)]
        ssh: Ssh,
        #[command(flatten)]
        server: Server,
        #[command(flatten)]
        host: Host,
        /// The ids or the names of sessions
        #[arg(id = "id", value_name = "ID", value_parser = selector)]
        ids: Vec<String>,
    },
    /// Put the server file on a host
    ///
    /// The file is downloaded from the release of this version, or given with --server-binary.
    Install {
        #[command(flatten)]
        ssh: Ssh,
        #[command(flatten)]
        upload: Upload,
        #[command(flatten)]
        host: Host,
    },
    /// Edit client.toml, or server.toml on a host
    ///
    /// The editor is $EDITOR. The text is checked before it is saved, server.toml by the server
    /// on the host.
    Edit {
        #[command(flatten)]
        ssh: Ssh,
        #[command(flatten)]
        server: Server,
        /// [user@]host[:port], or ssh://[user@]host[:port]
        #[arg(value_name = "DESTINATION", value_hint = ValueHint::Hostname)]
        destination: Option<String>,
    },
}

/// Container for the destination of a command.
#[derive(Args, Debug)]
pub struct Host {
    /// [user@]host[:port], or ssh://[user@]host[:port]
    #[arg(value_name = "DESTINATION", value_hint = ValueHint::Hostname)]
    pub destination: String,
}

/// Container for the options of every command that reaches a host.
#[derive(Args, Debug)]
pub struct Ssh {
    /// Print what is happening: -v for the steps, -vv for details, -vvv for every frame
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Write the -v output to this file and not to the terminal
    #[arg(long, value_name = "FILE", value_hint = ValueHint::FilePath)]
    pub log_file: Option<PathBuf>,

    /// Command that replaces ssh, split at whitespace
    #[arg(
        long,
        value_name = "COMMAND",
        allow_hyphen_values = true,
        value_parser = parse_ssh_command
    )]
    pub ssh_command: Option<Words>,
}

/// Container for the options of the commands that run the server on the host.
#[derive(Args, Debug)]
pub struct Server {
    /// Path of the server file on the host
    #[arg(long, value_name = "PATH", value_hint = ValueHint::AnyPath)]
    pub server_path: Option<String>,

    /// Extra argument for ssj-server (repeatable)
    #[arg(long, value_name = "ARG", allow_hyphen_values = true)]
    pub server_arg: Vec<String>,
}

/// Container for where the server file comes from when it is installed.
#[derive(Args, Debug)]
pub struct Upload {
    /// Where the release files are, such as https://host/owner/ssj/releases/download/v0.2.1
    #[arg(long, value_name = "URL")]
    pub download_url: Option<String>,

    /// The server file to upload instead of the one from the release
    #[arg(long, value_name = "FILE", value_hint = ValueHint::FilePath)]
    pub server_binary: Option<PathBuf>,
}

/// Container for the options of a client in a session.
#[derive(Args, Debug)]
pub struct Session {
    /// Do not print the lines about connecting, disconnecting, and detaching
    #[arg(short = 'q', long)]
    pub quiet: bool,

    /// How to reach the server
    #[arg(long, value_name = "WAY")]
    pub transport: Option<Transport>,

    /// Whether UDP goes to the first jump host, which passes it on over ssh (default: none)
    #[arg(long, value_name = "WAY")]
    pub relay: Option<Relay>,

    /// Show typed characters before the server echoes them
    #[arg(long, value_name = "WHEN")]
    pub local_echo: Option<LocalEcho>,

    /// How fast to send (default: auto)
    #[arg(long, value_name = "WAY")]
    pub congestion: Option<Congestion>,

    /// Compress input and output while the link is the limit
    #[arg(long, value_name = "WHEN")]
    pub compress: Option<Compress>,

    /// UDP ports the server may use, such as 60000-61000, or 0 for any
    #[arg(long, value_name = "RANGE")]
    pub port_range: Option<String>,

    /// Install the server on the host without asking
    #[arg(long, overrides_with = "no_install")]
    pub install: bool,

    /// Never install the server
    #[arg(long, overrides_with = "install")]
    pub no_install: bool,

    /// Host name or address for UDP when it differs from the destination
    #[arg(long, value_name = "HOST", value_hint = ValueHint::Hostname)]
    pub udp_host: Option<String>,

    /// A key that detaches anywhere, such as ctrl-] (default: ctrl-\\)
    #[arg(long, value_name = "KEY", value_parser = parse_detach_key)]
    pub detach_key: Option<Key>,
}

/// Container for the options of a new session.
#[derive(Args, Debug)]
pub struct Connection {
    /// Join the session of this name, or start it
    #[arg(long, value_name = "NAME", value_parser = parse_name)]
    pub name: Option<SessionName>,

    /// Join the only session without a client
    #[arg(long, overrides_with = "no_auto_attach")]
    pub auto_attach: bool,

    /// Always start a new session (the default)
    #[arg(long, overrides_with = "auto_attach")]
    pub no_auto_attach: bool,

    /// Let programs on the host use your ssh agent (SSH_AUTH_SOCK) for signing
    #[arg(short = 'A', long, overrides_with = "no_forward_agent")]
    pub forward_agent: bool,

    /// Do not forward the agent (the default)
    #[arg(long, overrides_with = "forward_agent")]
    pub no_forward_agent: bool,

    /// How long a session lives without a client
    #[arg(long, value_name = "TIME")]
    pub detached_timeout: Option<String>,

    /// Environment variable pattern to send as well as the SendEnv of ssh (repeatable)
    #[arg(long, value_name = "PATTERN")]
    pub send_env: Vec<String>,
}

fn selector(text: &str) -> Result<String, &'static str> {
    if ssj_proto::is_selector(text) {
        Ok(text.to_owned())
    } else {
        Err("not a valid session id or name")
    }
}

fn parse_name(text: &str) -> Result<SessionName, &'static str> {
    SessionName::parse(text).ok_or("1 to 32 characters of letters, digits, '.', '_', '-'")
}

/// Splits the command at whitespace.
pub fn parse_ssh_command(text: &str) -> Result<Words, &'static str> {
    let words: Words = text.split_whitespace().map(str::to_owned).collect();
    if words.is_empty() {
        Err("is empty")
    } else {
        Ok(words)
    }
}
