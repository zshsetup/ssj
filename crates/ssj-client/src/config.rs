//! The config file `client.toml`.
//!
//! Flags on the command line override the file.

use ssj_config::parsed;
use ssj_net::{Compress, Congestion};
use ssj_proto::EnvFilter;

use crate::cli::{LocalEcho, Relay, Transport, parse_detach_key};
use crate::options::parse_ssh_command;

/// What to do when the server is not installed on the host.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ssj_config::serde::Deserialize)]
#[serde(crate = "ssj_config::serde", rename_all = "lowercase")]
pub enum AutoInstall {
    /// Ask on a terminal. Without a terminal, do not install.
    #[default]
    Ask,
    /// Install without asking.
    Always,
    /// Never install; say how to do it by hand.
    Never,
}

/// A byte typed at the terminal, or `None` for none.
type Key = Option<u8>;

/// Settings of ssj, read at every start. Flags on the command line override them.
#[derive(Clone, Debug, PartialEq, Eq, confique::Config)]
#[config(layer_attr(serde(deny_unknown_fields)))]
pub struct Config {
    /// "ask", "always", or "never": what to do when the host has no server.
    #[config(default = "ask")]
    pub auto_install: AutoInstall,
    /// A key such as "ctrl-]" that detaches anywhere, or "none". The program does not receive it.
    #[config(default = "ctrl-\\", deserialize_with = detach_key)]
    pub detach_key: Key,
    /// Replaces ssh, such as "ssh -J jump".
    #[config(default = "ssh", deserialize_with = ssh_command)]
    pub ssh_command: Vec<String>,
    /// More variables to send, besides TERM and the SendEnv of ssh.
    #[config(default = [], deserialize_with = send_env)]
    pub send_env: EnvFilter,
    /// "auto", "udp", or "stdio": how to reach the server.
    #[config(default = "auto")]
    pub transport: Transport,
    /// "none", "auto", or "first": for a host behind a jump host (ProxyJump), whether UDP goes to
    /// the first jump host, which passes it on over ssh. "auto" needs the server on the jump host
    /// and does nothing without it; "first" asks to install it.
    #[config(default = "none")]
    pub relay: Relay,
    /// `ssj connect host` joins the only session without a client.
    #[config(default = false)]
    pub auto_attach: bool,
    /// Let programs on the host use your ssh agent (-A).
    #[config(default = false)]
    pub forward_agent: bool,
    /// "off" or "auto": show typed characters at once, before the server echoes them.
    #[config(default = "off")]
    pub local_echo: LocalEcho,
    /// "off" or "auto": compress while the link is the limit. Not set: the server decides.
    /// Compressing text of an attacker together with a secret can leak the secret.
    pub compress: Option<Compress>,
    /// "auto", "bbr", or "cubic": how fast to send. Not set: the server decides. Auto starts
    /// with CUBIC, the fastest on a clean link, and moves to BBR when packets are lost without a
    /// queue (Wi-Fi, mobile, long paths), where CUBIC crawls.
    pub congestion: Option<Congestion>,
}

parsed!(detach_key, String => Key, |s| parse_detach_key(&s));
parsed!(ssh_command, String => Vec<String>, |s| parse_ssh_command(&s).map_err(str::to_owned));
parsed!(send_env, Vec<String> => EnvFilter, |p| EnvFilter::new(p).map_err(|e| format!("{e:?}")));

impl Default for Config {
    fn default() -> Self {
        Self::from_text("").expect("the defaults are valid")
    }
}

impl Config {
    /// Parses the text of a config file and rejects unknown keys and bad values.
    pub fn from_text(text: &str) -> Result<Self, String> {
        ssj_config::parse(text)
    }

    /// Reads `$XDG_CONFIG_HOME/ssj/client.toml` if it exists.
    pub fn load() -> Result<Self, String> {
        match ssj_config::read_file("client.toml")? {
            None => Ok(Self::default()),
            Some((path, text)) => {
                Self::from_text(&text).map_err(|e| format!("{}: {e}", path.display()))
            }
        }
    }

    /// The text a new file starts with.
    pub fn template() -> String {
        ssj_config::template::<Self>()
    }
}
