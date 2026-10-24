//! Command line of `ssj`.

use std::path::PathBuf;

use clap::FromArgMatches;
use ssj_net::Compress;
use ssj_proto::{EnvFilter, PROTOCOL, SessionName};

use crate::config::AutoInstall;
use crate::options::{Cli, CommandLine, Connection, Server, Session, Ssh, Upload};

/// Where the server file is, as seen on the remote host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServerPath {
    /// `~/.local/share/ssj/bin/ssj-server-p<N>` following `XDG_DATA_HOME`, expanded remotely.
    Default,
    /// Taken literally and quoted for the remote shell.
    Custom(String),
}

/// How the client reaches the server.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    /// UDP first, then the `ssh` channel itself.
    #[default]
    Auto,
    Udp,
    Stdio,
}

/// Whether UDP goes to the first jump host and from there over `ssh`, for a destination behind one.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Relay {
    /// Everything goes over the `ssh` channel through the jump host.
    #[default]
    None,
    /// A relay on the first jump host if it has the server, else as `none`, without asking.
    Auto,
    /// A relay on the first jump host; if it lacks the server, ask to install it (see
    /// `auto_install`), and use the `ssh` channel if that is declined.
    First,
}

/// Whether typed characters are shown before the server has echoed them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LocalEcho {
    /// Typed characters appear when the server echoes them.
    #[default]
    Off,
    /// Typed characters appear at once, faint, until the server echoes them.
    Auto,
}

/// What the client is asked to do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    /// Start a new session.
    Connect,
    /// Join a running session as a new client.
    Attach(Option<String>),
    /// Print the sessions on the host.
    List,
    /// Put the server on the host.
    Install,
    /// End a session on the host.
    /// The ids or names to end; none means the only session, or a choice from a menu.
    Kill(Vec<String>),
    /// Make the client of a session on the host leave; the session keeps running.
    /// The ids or names to detach; none means the only session, or a choice from a menu.
    Detach(Vec<String>),
    /// Edit `client.toml` here, or `server.toml` on the host if there is a destination.
    Edit,
    /// Print the cached session names of a host, or of all hosts, for tab completion.
    Complete {
        host: Option<String>,
        /// Only the sessions that have a client.
        connected: bool,
    },
}

/// Container for the parsed command line of `ssj`.
#[derive(Clone, Debug)]
pub struct Args {
    pub command: Command,
    /// `[user@]host` for `ssh`: the destination without the port and without brackets.
    pub destination: String,
    /// Port of the `ssh` server, when the destination names one.
    pub ssh_port: Option<u16>,
    /// Name of the session: it is joined if it runs and started otherwise.
    pub name: Option<SessionName>,
    /// Command that replaces `ssh`, split at whitespace.
    pub ssh_command: Vec<String>,
    pub server_path: ServerPath,
    /// Extra arguments for `ssj-server`.
    pub server_args: Vec<String>,
    /// A command to run in the session instead of the shell, as `ssh host command` does.
    pub remote_command: Option<String>,
    /// Host name or address for the UDP connection when it differs from the destination.
    pub udp_host: Option<String>,
    /// The patterns of the config file. They come on top of the `SendEnv` of `ssh`.
    pub send_env: EnvFilter,
    /// The patterns of `--send-env`, on top of the others.
    pub send_env_add: Vec<String>,
    /// Overrides the setting of the config file.
    pub auto_install: Option<AutoInstall>,
    /// Where the release files are; the default comes from the repository of the package.
    pub download_url: Option<String>,
    /// The server file to upload instead of the one from the release.
    pub server_binary: Option<PathBuf>,
    /// A control byte that detaches wherever it is typed; `None` turns it off.
    pub detach_key: Option<u8>,
    pub transport: Transport,
    pub relay: Relay,
    /// Join the only session without a client instead of starting another one.
    pub auto_attach: bool,
    /// Programs on the host may use the ssh agent of this machine.
    pub forward_agent: bool,
    pub local_echo: LocalEcho,
    /// Compression of input and output; `None` leaves it to the files.
    pub compress: Option<Compress>,
    /// `None` leaves it to the files and the default.
    pub congestion: Option<ssj_net::Congestion>,
    /// `list` prints JSON.
    pub json: bool,
    /// How much to tell (`-v` counted), 0 to 3.
    pub verbose: u8,
    /// No lines about connecting, disconnecting, and detaching (`-q`).
    pub quiet: bool,
    /// `kill` does not ask before it ends the only session of the host (`-f`).
    pub force: bool,
    /// Where the output of `-v` goes instead of the terminal.
    pub log_file: Option<PathBuf>,
    /// Never prompt and give up early: for refreshes that nobody waits for.
    pub batch: bool,
    /// Which of `ssh_command` and `detach_key` (and the others below) the command line set, since the
    /// config file only fills in the rest.
    pub explicit: Explicit,
}

/// Marks the options that the command line set, so that the config file does not replace them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Explicit {
    pub ssh_command: bool,
    pub detach_key: bool,
    pub transport: bool,
    pub relay: bool,
    pub auto_attach: bool,
    pub forward_agent: bool,
    pub local_echo: bool,
}

impl Args {
    /// The arguments before the command line fills them in.
    fn blank() -> Self {
        Self {
            command: Command::Connect,
            destination: String::new(),
            ssh_port: None,
            name: None,
            ssh_command: vec!["ssh".to_owned()],
            server_path: ServerPath::Default,
            server_args: Vec::new(),
            remote_command: None,
            udp_host: None,
            send_env: EnvFilter::none(),
            send_env_add: Vec::new(),
            auto_install: None,
            download_url: None,
            server_binary: None,
            detach_key: Some(DEFAULT_DETACH_KEY),
            transport: Transport::Auto,
            relay: Relay::None,
            auto_attach: false,
            forward_agent: false,
            local_echo: LocalEcho::Off,
            compress: None,
            congestion: None,
            json: false,
            verbose: 0,
            quiet: false,
            force: false,
            log_file: None,
            batch: false,
            explicit: Explicit::default(),
        }
    }

    /// Fills in what the command line left open from the config file.
    pub fn apply_config(&mut self, config: &crate::config::Config) {
        if !self.explicit.ssh_command {
            self.ssh_command = config.ssh_command.clone();
        }
        if !self.explicit.detach_key {
            self.detach_key = config.detach_key;
        }
        if !self.explicit.auto_attach {
            self.auto_attach = config.auto_attach;
        }
        if !self.explicit.forward_agent {
            self.forward_agent = config.forward_agent;
        }
        if self.congestion.is_none() {
            self.congestion = config.congestion;
        }
        if self.compress.is_none() {
            self.compress = config.compress;
        }
        if !self.explicit.local_echo {
            self.local_echo = config.local_echo;
        }
        if !self.explicit.transport {
            self.transport = config.transport;
        }
        if !self.explicit.relay {
            self.relay = config.relay;
        }
        self.send_env = config.send_env.clone();
        if self.auto_install.is_none() {
            self.auto_install = Some(config.auto_install);
        }
    }

    /// The options that tell `ssh` the port, to go before the destination.
    pub fn ssh_port_args(&self) -> Vec<String> {
        self.ssh_port
            .map_or_else(Vec::new, |port| vec!["-p".to_owned(), port.to_string()])
    }

    /// Host part of the destination, without the user.
    pub fn host(&self) -> &str {
        self.destination
            .rsplit_once('@')
            .map_or(&self.destination, |(_, host)| host)
    }
}

/// The detach key when none is chosen: `ctrl-\\`.
pub const DEFAULT_DETACH_KEY: u8 = 0x1c;

/// A control key as `ctrl-]` or `^]` (letters in either case, and `[ \ ] ^ _`), or `none`. Enter,
/// Tab, and Escape are refused, since they are part of every line and every key sequence.
pub fn parse_detach_key(text: &str) -> Result<Option<u8>, String> {
    if text == "none" {
        return Ok(None);
    }
    let key = text.strip_prefix('^').or_else(|| {
        text.get(..5)
            .filter(|p| p.eq_ignore_ascii_case("ctrl-"))
            .map(|_| &text[5..])
    });
    let error = || "expected ctrl-A to ctrl-Z, ctrl-\\, ctrl-], ctrl-^, ctrl-_, or none".to_owned();
    let [byte] = key.ok_or_else(error)?.as_bytes() else {
        return Err(error());
    };
    let byte = match byte.to_ascii_uppercase() {
        letter @ b'A'..=b'Z' => letter - b'@',
        symbol @ (b'\\' | b']' | b'^' | b'_') => symbol - b'@',
        _ => return Err(error()),
    };
    if matches!(byte, 0x09 | 0x0a | 0x0d) {
        return Err("Tab and Enter cannot detach".to_owned());
    }
    Ok(Some(byte))
}

/// Parses the arguments of the command line.
///
/// As with `ssh`, everything after the destination of `connect` belongs to the command that runs
/// in the session, options included (`ssj connect host ls -l`).
pub fn parse(args: impl IntoIterator<Item = String>) -> Result<Args, String> {
    let words = std::iter::once("ssj".to_owned()).chain(args);
    let cli = match crate::options::command()
        .try_get_matches_from(words)
        .and_then(|matches| Cli::from_arg_matches(&matches))
    {
        Ok(cli) => cli,
        Err(error) if error.use_stderr() => {
            return Err(error.render().to_string().trim_end().to_owned());
        }
        // help and version go to the output and end the program.
        Err(error) => error.exit(),
    };
    let mut args = Args::blank();
    let Some(line) = cli.command else {
        args.command = Command::Complete {
            host: cli.complete.filter(|host| !host.is_empty()),
            connected: cli.connected,
        };
        return Ok(args);
    };
    let destination = match line {
        CommandLine::Connect {
            ssh,
            server,
            upload,
            session,
            connection,
            line,
        } => {
            let (destination, mut remote) = line.split_first().expect("a required destination");
            // a `--` right after the destination is dropped: `ssj connect host -- ls -l`
            if remote.first().is_some_and(|word| word == "--") {
                remote = &remote[1..];
            }
            if !remote.is_empty() {
                let command = remote.join(" ");
                if command.trim().is_empty() {
                    return Err("the command is empty".to_owned());
                }
                if connection.name.is_some() || connection.auto_attach {
                    return Err(
                        "a command cannot be combined with --name or --auto-attach, since \
                                a session that runs already would not run it"
                            .to_owned(),
                    );
                }
                args.remote_command = Some(command);
            }
            ssh.apply(&mut args);
            server.apply(&mut args);
            upload.apply(&mut args);
            session.apply(&mut args);
            connection.apply(&mut args)?;
            Some(destination.clone())
        }
        CommandLine::List {
            ssh,
            server,
            json,
            batch,
            host,
        } => {
            ssh.apply(&mut args);
            server.apply(&mut args);
            (args.command, args.json, args.batch) = (Command::List, json, batch);
            Some(host.destination)
        }
        CommandLine::Attach {
            ssh,
            server,
            upload,
            session,
            host,
            id,
        } => {
            ssh.apply(&mut args);
            server.apply(&mut args);
            upload.apply(&mut args);
            session.apply(&mut args);
            args.command = Command::Attach(id);
            Some(host.destination)
        }
        CommandLine::Kill {
            ssh,
            server,
            force,
            host,
            ids,
        } => {
            ssh.apply(&mut args);
            server.apply(&mut args);
            (args.command, args.force) = (Command::Kill(ids), force);
            Some(host.destination)
        }
        CommandLine::Detach {
            ssh,
            server,
            host,
            ids,
        } => {
            ssh.apply(&mut args);
            server.apply(&mut args);
            args.command = Command::Detach(ids);
            Some(host.destination)
        }
        CommandLine::Install { ssh, upload, host } => {
            ssh.apply(&mut args);
            upload.apply(&mut args);
            args.command = Command::Install;
            Some(host.destination)
        }
        CommandLine::Edit {
            ssh,
            server,
            destination,
        } => {
            ssh.apply(&mut args);
            server.apply(&mut args);
            args.command = Command::Edit;
            destination
        }
    };
    // `ssj edit` alone is the editor for the local file.
    if let Some(destination) = destination {
        let parsed = ssj_proto::destination::parse(&destination)
            .map_err(|e| format!("invalid destination {destination:?}: {e}"))?;
        (args.destination, args.ssh_port) = (parsed.target(), parsed.port);
    }
    Ok(args)
}

impl Ssh {
    fn apply(self, args: &mut Args) {
        args.verbose = self.verbose.min(3);
        args.log_file = self.log_file;
        if let Some(command) = self.ssh_command {
            (args.ssh_command, args.explicit.ssh_command) = (command, true);
        }
    }
}

impl Server {
    fn apply(self, args: &mut Args) {
        if let Some(path) = self.server_path {
            args.server_path = ServerPath::Custom(path);
        }
        args.server_args.extend(self.server_arg);
    }
}

impl Upload {
    fn apply(self, args: &mut Args) {
        args.download_url = self.download_url;
        args.server_binary = self.server_binary;
    }
}

impl Session {
    fn apply(self, args: &mut Args) {
        args.quiet = self.quiet;
        if let Some(transport) = self.transport {
            (args.transport, args.explicit.transport) = (transport, true);
        }
        if let Some(relay) = self.relay {
            (args.relay, args.explicit.relay) = (relay, true);
        }
        if let Some(echo) = self.local_echo {
            (args.local_echo, args.explicit.local_echo) = (echo, true);
        }
        args.congestion = self.congestion;
        args.compress = self.compress;
        if let Some(range) = self.port_range {
            args.server_args.extend(["--port-range".to_owned(), range]);
        }
        args.auto_install = match (self.install, self.no_install) {
            (true, _) => Some(AutoInstall::Always),
            (_, true) => Some(AutoInstall::Never),
            _ => None,
        };
        args.udp_host = self.udp_host;
        if let Some(key) = self.detach_key {
            (args.detach_key, args.explicit.detach_key) = (key, true);
        }
    }
}

impl Connection {
    fn apply(self, args: &mut Args) -> Result<(), String> {
        args.name = self.name;
        if self.auto_attach || self.no_auto_attach {
            (args.auto_attach, args.explicit.auto_attach) = (self.auto_attach, true);
        }
        if self.forward_agent || self.no_forward_agent {
            (args.forward_agent, args.explicit.forward_agent) = (self.forward_agent, true);
        }
        if let Some(timeout) = self.detached_timeout {
            args.server_args
                .extend(["--detached-timeout".to_owned(), timeout]);
        }
        // only checked here: the patterns are added to the others when the session starts.
        EnvFilter::new(self.send_env.clone()).map_err(|e| format!("--send-env: {e:?}"))?;
        args.send_env_add = self.send_env;
        Ok(())
    }
}

/// Name of the server file for this protocol version.
pub fn default_server_file() -> String {
    format!("ssj-server-p{PROTOCOL}")
}
