//! Lines on the control socket of a running server.
//!
//! One request line, one reply line. The peer is the same user, but the parsing is as strict as
//! for any other input.

use crate::bootstrap::{BootstrapError, Connect, format_connect, parse_connect};
use crate::types::{SessionId, SessionName};

/// Longest line in either direction.
pub const MAX_LINE: usize = 512;

/// Failure to read a line of the control socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlError {
    Malformed,
}

impl From<BootstrapError> for ControlError {
    fn from(_: BootstrapError) -> Self {
        Self::Malformed
    }
}

/// Request that a client of the control socket sends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Request {
    /// Replaces the pinned client and opens a new endpoint.
    Attach([u8; 32]),
    Status,
    /// Turns the connection into the byte stream of a client (the `ssh` channel as transport).
    /// The reply `OK` comes first, and everything after it is frames.
    Stream,
    /// Turns the connection into a carrier of QUIC packets, one frame each (see `ssj-net`'s
    /// `relay`), for a client behind a relay. The endpoint uses the certificate of the last
    /// `Attach`, so that the fingerprint that the client got from it is the right one.
    Datagrams,
    /// Ends the session as if the terminal had been closed.
    Kill,
    /// Detaches the connected client: it leaves and the session keeps running.
    Detach,
}

/// State of a session in a listing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionState {
    /// A client is connected.
    Connected,
    /// The client was lost and may come back before the timeout.
    Disconnected,
    /// The client left on purpose and the session waits without a timeout.
    Detached,
}

impl SessionState {
    /// Returns the word of the state, as the listings show it.
    pub fn word(self) -> &'static str {
        match self {
            Self::Connected => "connected",
            Self::Disconnected => "disconnected",
            Self::Detached => "detached",
        }
    }

    fn from_word(word: &str) -> Option<Self> {
        Some(match word {
            "connected" => Self::Connected,
            "disconnected" => Self::Disconnected,
            "detached" => Self::Detached,
            _ => return None,
        })
    }
}

/// Container for one session in a listing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionInfo {
    pub id: SessionId,
    pub name: Option<SessionName>,
    pub state: SessionState,
    pub age_secs: u64,
    pub protocol: u16,
}

/// Answer of the server on the control socket.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reply {
    Connect(Connect),
    Info(SessionInfo),
    Ok,
    /// Short message from the server. Printable ASCII only.
    Error(String),
}

/// Formats a request as a line of the control socket.
pub fn format_request(request: &Request) -> String {
    match request {
        Request::Attach(pin) => crate::bootstrap::format_pin(pin).replace("SSJ PIN ", "ATTACH "),
        Request::Status => "STATUS\n".to_owned(),
        Request::Stream => "STREAM\n".to_owned(),
        Request::Datagrams => "DATAGRAMS\n".to_owned(),
        Request::Kill => "KILL\n".to_owned(),
        Request::Detach => "DETACH\n".to_owned(),
    }
}

/// Parses one request line, with or without the final newline.
pub fn parse_request(line: &[u8]) -> Result<Request, ControlError> {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    // the control socket speaks exact lines of one line each. `parse_pin` below would take a
    // carriage return and a second line feed in front of the end, and the line would not be the
    // one that is formatted again.
    if line.iter().any(|b| matches!(b, b'\r' | b'\n')) {
        return Err(ControlError::Malformed);
    }
    match line {
        b"STATUS" => Ok(Request::Status),
        b"STREAM" => Ok(Request::Stream),
        b"DATAGRAMS" => Ok(Request::Datagrams),
        b"KILL" => Ok(Request::Kill),
        b"DETACH" => Ok(Request::Detach),
        _ => {
            let hex = line
                .strip_prefix(b"ATTACH ")
                .ok_or(ControlError::Malformed)?;
            let mut pin_line = b"SSJ PIN ".to_vec();
            pin_line.extend_from_slice(hex);
            Ok(Request::Attach(crate::bootstrap::parse_pin(&pin_line)?))
        }
    }
}

/// Formats a reply as a line of the control socket.
pub fn format_reply(reply: &Reply) -> String {
    match reply {
        Reply::Connect(connect) => format_connect(connect),
        Reply::Info(info) => format!(
            "SSJ SESSION {} {} {} {} {}\n",
            info.id.as_str(),
            info.state.word(),
            info.age_secs,
            info.protocol,
            info.name.as_ref().map_or("-", SessionName::as_str)
        ),
        Reply::Ok => "OK\n".to_owned(),
        Reply::Error(text) => {
            let printable: String = text
                .chars()
                .filter(|c| c.is_ascii_graphic() || *c == ' ')
                .take(200)
                .collect();
            format!("ERR {printable}\n")
        }
    }
}

/// Parses one reply line, with or without the final newline.
pub fn parse_reply(line: &[u8]) -> Result<Reply, ControlError> {
    let mut complete = line.to_vec();
    if !complete.ends_with(b"\n") {
        complete.push(b'\n');
    }
    // exactly one line, so that nothing can be hidden behind it.
    if complete[..complete.len() - 1]
        .iter()
        .any(|b| matches!(b, b'\n' | b'\r'))
    {
        return Err(ControlError::Malformed);
    }
    if complete.starts_with(b"SSJ CONNECT ") {
        return Ok(Reply::Connect(
            parse_connect(&complete)?.ok_or(ControlError::Malformed)?,
        ));
    }
    let text = std::str::from_utf8(&complete[..complete.len() - 1])
        .map_err(|_| ControlError::Malformed)?;
    if text == "OK" {
        return Ok(Reply::Ok);
    }
    if let Some(message) = text.strip_prefix("ERR ") {
        let printable = message.chars().all(|c| c.is_ascii_graphic() || c == ' ');
        return if printable && message.len() <= 200 {
            Ok(Reply::Error(message.to_owned()))
        } else {
            Err(ControlError::Malformed)
        };
    }
    let fields: Vec<&str> = text
        .strip_prefix("SSJ SESSION ")
        .ok_or(ControlError::Malformed)?
        .split(' ')
        .collect();
    let [id, state, age, protocol, name] = fields[..] else {
        return Err(ControlError::Malformed);
    };
    let plain_number = |s: &str| {
        !s.is_empty()
            && s.len() <= 10
            && s.bytes().all(|b| b.is_ascii_digit())
            && (s == "0" || !s.starts_with('0'))
    };
    if !plain_number(age) || !plain_number(protocol) {
        return Err(ControlError::Malformed);
    }
    Ok(Reply::Info(SessionInfo {
        id: SessionId::parse(id).ok_or(ControlError::Malformed)?,
        name: match name {
            "-" => None,
            name => Some(SessionName::parse(name).ok_or(ControlError::Malformed)?),
        },
        state: SessionState::from_word(state).ok_or(ControlError::Malformed)?,
        age_secs: age.parse().map_err(|_| ControlError::Malformed)?,
        protocol: protocol.parse().map_err(|_| ControlError::Malformed)?,
    }))
}
