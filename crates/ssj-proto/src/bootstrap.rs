//! The line that `ssj-server` prints for the client, and safe handling of other remote text.
//!
//! The output of the remote side also contains banners and output of shell startup files, which
//! are not trusted. Only an exact, complete line is accepted.

use crate::env::Env;
use crate::frame::{ClientFrame, Hello, decode_client};
use crate::types::{SessionId, SessionName, WindowSize};

/// Start of the line that carries the connection data.
pub const PREFIX: &str = "SSJ CONNECT ";
/// Start of the line that the client writes to the stdin of `ssj-server`.
pub const PIN_PREFIX: &str = "SSJ PIN ";
/// Start of the optional second line that the client writes to the stdin of `ssj-server`: what a
/// fresh session needs to start its shell at once.
pub const START_PREFIX: &str = "SSJ START ";
/// Longest second line the server reads: the hex of the largest frame, and the prefix.
pub const MAX_START_LINE: usize = 2 * crate::frame::MAX_FRAME_LEN + 64;
/// First bytes of the stream when the `ssh` channel itself carries the session (`--stdio`). The
/// client skips everything before it, since shell startup files may print text first.
pub const SYNC_HEADER: &[u8] = b"\0SSJ_SYNC_STREAM\n";
/// Position after the first sync header in `bytes`, if it is there.
pub fn find_sync(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(SYNC_HEADER.len())
        .position(|w| w == SYNC_HEADER)
        .map(|at| at + SYNC_HEADER.len())
}

/// The second line of the input of the server when the client has no `SSJ START` line to send. A
/// server waits a moment for a second line, and a client that keeps the `ssh` channel open cannot
/// end that wait by closing its input. Older servers take it for a broken start line and ignore it.
pub const NO_START_LINE: &str = "SSJ START -\n";
/// What the client writes to the server after the `SSJ CONNECT` line to carry the session over
/// that same `ssh` channel: the stream of `--stdio` follows. Without it (the input ends, or
/// nothing comes for [`HOLD_TIMEOUT`]) the server process ends.
pub const STREAM_LINE: &str = "SSJ STREAM\n";
/// How long the server process stays on the `ssh` channel after the connect line, waiting for
/// [`STREAM_LINE`]. A client that gets QUIC to work closes the channel at once.
pub const HOLD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

/// Exit code of `ssj-server --reuse --choose` when several sessions have no client: it prints their
/// `SSJ SESSION` lines instead of picking one or starting another, and the client asks the user.
pub const CHOICE_EXIT_CODE: u8 = 67;

/// The client stops reading the output of `ssh` after this many bytes.
pub const MAX_OUTPUT: usize = 64 * 1024;

/// How to reach a running server: its session, the UDP port (it may be off), and the fingerprint
/// of its certificate. A server without a port is reached only through the `ssh` channel
/// (`ssj-server --stdio`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Connect {
    pub id: SessionId,
    pub udp: Option<u16>,
    pub fingerprint: [u8; 32],
    /// The server made the session for this client, which a fifth field `new` on the line says.
    /// `false` for a session that ran, and for a server that does not say.
    pub new: bool,
    /// The name of the session, when it has one (`name=NAME` on the line).
    pub name: Option<SessionName>,
    /// The control socket of the session on the host (`socket=PATH` on the line). The server
    /// bridges it to the `ssh` channel itself; older clients reached it through `ssh -W`.
    pub socket: Option<String>,
}

/// Whether `path` can stand on the line and after `ssh -W`: absolute, and without whitespace, a
/// colon (which `ssh` would read as a port), or a control character.
pub fn is_socket_path(path: &str) -> bool {
    path.starts_with('/')
        && !path
            .chars()
            .any(|c| c.is_whitespace() || c == ':' || c.is_control())
}

/// Failure to read a line of the bootstrap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootstrapError {
    /// A line starts with the prefix but has wrong fields.
    Malformed,
    /// More than one line starts with the prefix.
    Ambiguous,
}

/// Formats the line, including the final newline:
/// `SSJ CONNECT <id> <udp:PORT|none> none <fingerprint> [new] [name=NAME] [socket=PATH]`. The third
/// field was the TCP port of earlier servers, and is `none` for compatibility.
pub fn format_connect(connect: &Connect) -> String {
    let udp = match connect.udp {
        Some(port) => format!("udp:{port}"),
        None => "none".to_owned(),
    };
    let mut line = format!("{PREFIX}{} {udp} none ", connect.id.as_str());
    line.push_str(&hex::encode(connect.fingerprint));
    if connect.new {
        line.push_str(" new");
    }
    if let Some(name) = &connect.name {
        line.push_str(" name=");
        line.push_str(name.as_str());
    }
    if let Some(socket) = &connect.socket {
        line.push_str(" socket=");
        line.push_str(socket);
    }
    line.push('\n');
    line
}

/// Looks for the connection line in the output read so far.
///
/// Returns `Ok(None)` while no complete line carries the prefix. Only lines that end with a
/// newline count, and the prefix must be at the very start of the line.
pub fn parse_connect(output: &[u8]) -> Result<Option<Connect>, BootstrapError> {
    let mut found = None;
    let mut lines = output.split(|&b| b == b'\n').peekable();
    while let Some(line) = lines.next() {
        // the last segment has no newline behind it, so it is not complete yet.
        if lines.peek().is_none() {
            break;
        }
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(fields) = line.strip_prefix(PREFIX.as_bytes()) else {
            continue;
        };
        if found.replace(parse_fields(fields)?).is_some() {
            return Err(BootstrapError::Ambiguous);
        }
    }
    Ok(found)
}

fn parse_fields(fields: &[u8]) -> Result<Connect, BootstrapError> {
    let mut parts = fields.split(|&b| b == b' ');
    let (Some(id), Some(udp), Some(tcp), Some(fingerprint)) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(BootstrapError::Malformed);
    };
    // what may follow, each once and in this order: `new`, `name=NAME`, and `socket=PATH`.
    let mut rest = parts.peekable();
    let new = rest.next_if(|field| *field == b"new").is_some();
    let mut value = |key: &[u8]| {
        rest.next_if(|field| field.starts_with(key))
            .map(|field| std::str::from_utf8(&field[key.len()..]).ok())
    };
    let name = match value(b"name=") {
        Some(text) => Some(
            text.and_then(SessionName::parse)
                .ok_or(BootstrapError::Malformed)?,
        ),
        None => None,
    };
    let socket = match value(b"socket=") {
        Some(text) => Some(
            text.filter(|path| is_socket_path(path))
                .ok_or(BootstrapError::Malformed)?
                .to_owned(),
        ),
        None => None,
    };
    if rest.next().is_some() {
        return Err(BootstrapError::Malformed);
    }
    let id = std::str::from_utf8(id)
        .ok()
        .and_then(SessionId::parse)
        .ok_or(BootstrapError::Malformed)?;
    // the port of TCP from earlier servers is read for its form and then left alone.
    parse_transport(tcp, b"tcp:")?;
    Ok(Connect {
        id,
        udp: parse_transport(udp, b"udp:")?,
        fingerprint: parse_fingerprint(fingerprint)?,
        new,
        name,
        socket,
    })
}

fn parse_transport(text: &[u8], kind: &[u8]) -> Result<Option<u16>, BootstrapError> {
    if text == b"none" {
        return Ok(None);
    }
    let port = text.strip_prefix(kind).ok_or(BootstrapError::Malformed)?;
    parse_port(port).map(Some)
}

fn parse_port(text: &[u8]) -> Result<u16, BootstrapError> {
    let plain =
        (1..=5).contains(&text.len()) && text.iter().all(u8::is_ascii_digit) && text[0] != b'0';
    if !plain {
        return Err(BootstrapError::Malformed);
    }
    std::str::from_utf8(text)
        .ok()
        .and_then(|t| t.parse::<u16>().ok())
        .ok_or(BootstrapError::Malformed)
}

/// Decodes lowercase hex, the only form that the lines use, so that each value has one spelling.
fn parse_hex(text: &[u8]) -> Result<Vec<u8>, BootstrapError> {
    if text.iter().any(u8::is_ascii_uppercase) {
        return Err(BootstrapError::Malformed);
    }
    hex::decode(text).map_err(|_| BootstrapError::Malformed)
}

fn parse_fingerprint(text: &[u8]) -> Result<[u8; 32], BootstrapError> {
    parse_hex(text)?
        .try_into()
        .map_err(|_| BootstrapError::Malformed)
}

/// Start of the line that asks `ssj-server --relay` for a relay: the secret that the client and the
/// relay share (see `ssj_net::relay`).
pub const RELAY_PREFIX: &str = "SSJ RELAY ";
/// Start of the line with which the relay says its UDP port.
pub const RELAY_PORT_PREFIX: &str = "SSJ RELAY-PORT ";
/// Start of the line that tells the relay the command that reaches the server behind it, as hex
/// words separated by commas. The relay answers `OK` once the command carries packets, or `ERR`.
pub const LEG_PREFIX: &str = "SSJ LEG ";
/// Longest `SSJ LEG` line the relay reads.
pub const MAX_LEG_LINE: usize = 16 * 1024;

/// Formats the line `SSJ RELAY <64 hex digits>`, including the newline.
pub fn format_relay_secret(secret: &[u8; 32]) -> String {
    format!("{RELAY_PREFIX}{}\n", hex::encode(secret))
}

/// Parses the line of [`format_relay_secret`].
pub fn parse_relay_secret(line: &[u8]) -> Result<[u8; 32], BootstrapError> {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let hex = line
        .strip_prefix(RELAY_PREFIX.as_bytes())
        .ok_or(BootstrapError::Malformed)?;
    parse_fingerprint(hex)
}

/// Formats the line `SSJ RELAY-PORT <port>`, including the newline.
pub fn format_relay_port(port: u16) -> String {
    format!("{RELAY_PORT_PREFIX}{port}\n")
}

/// Finds the line of [`format_relay_port`] in the output of the relay, which may have text before
/// it. A line without its newline is not complete yet.
pub fn parse_relay_port(output: &[u8]) -> Result<Option<u16>, BootstrapError> {
    let Some(end) = output.iter().rposition(|b| *b == b'\n') else {
        return Ok(None);
    };
    let Some(line) = output[..end]
        .split(|b| *b == b'\n')
        .find(|line| line.starts_with(RELAY_PORT_PREFIX.as_bytes()))
    else {
        return Ok(None);
    };
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let digits = &line[RELAY_PORT_PREFIX.len()..];
    let plain = !digits.is_empty()
        && digits.len() <= 5
        && digits.iter().all(u8::is_ascii_digit)
        && (digits == b"0" || digits[0] != b'0');
    if !plain {
        return Err(BootstrapError::Malformed);
    }
    std::str::from_utf8(digits)
        .ok()
        .and_then(|text| text.parse().ok())
        .map(Some)
        .ok_or(BootstrapError::Malformed)
}

/// Formats the line `SSJ LEG <hex>[,<hex>...]` for a command, or `None` if there is no word, a word
/// is empty, or the line would be longer than [`MAX_LEG_LINE`].
pub fn format_leg(command: &[String]) -> Option<String> {
    if command.is_empty() || command.iter().any(String::is_empty) {
        return None;
    }
    let words: Vec<String> = command.iter().map(hex::encode).collect();
    let line = format!("{LEG_PREFIX}{}\n", words.join(","));
    (line.len() <= MAX_LEG_LINE).then_some(line)
}

/// Parses the line of [`format_leg`] into the words of the command.
pub fn parse_leg(line: &[u8]) -> Result<Vec<String>, BootstrapError> {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let words = line
        .strip_prefix(LEG_PREFIX.as_bytes())
        .ok_or(BootstrapError::Malformed)?;
    words
        .split(|b| *b == b',')
        .map(|word| {
            let bytes = parse_hex(word)?;
            String::from_utf8(bytes)
                .ok()
                .filter(|text| !text.is_empty())
                .ok_or(BootstrapError::Malformed)
        })
        .collect()
}

/// Makes remote text safe to show on a terminal.
///
/// Control characters (including escape sequences) and bidirectional formatting characters are
/// replaced by `?`. The result has at most `max_chars` characters.
pub fn sanitize(text: &[u8], max_chars: usize) -> String {
    let lossy = String::from_utf8_lossy(text);
    let mut out = String::new();
    for (count, c) in lossy.chars().enumerate() {
        if count == max_chars {
            out.push_str("...");
            break;
        }
        let unsafe_char = c.is_control()
            || matches!(c, '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}');
        out.push(if unsafe_char { '?' } else { c });
    }
    out
}

/// Formats the line with the certificate fingerprint of the client, including the newline.
pub fn format_pin(fingerprint: &[u8; 32]) -> String {
    format!("{PIN_PREFIX}{}\n", hex::encode(fingerprint))
}

/// Parses one line `SSJ PIN <64 lowercase hex digits>` with an optional `\r` before the newline.
pub fn parse_pin(line: &[u8]) -> Result<[u8; 32], BootstrapError> {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let hex = line
        .strip_prefix(PIN_PREFIX.as_bytes())
        .ok_or(BootstrapError::Malformed)?;
    parse_fingerprint(hex)
}

/// What the shell of a fresh session needs, sent before the client has connected, so that the
/// shell can run its startup files while the connection is made.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Prestart {
    pub size: WindowSize,
    pub env: Env,
    /// The client offers its ssh agent, so the shell gets a socket for it.
    pub agent: bool,
}

/// Formats the line `SSJ START <hex of a Start hello frame>`, including the newline. `None` if the
/// frame cannot be encoded.
pub fn format_start(start: &Prestart) -> Option<String> {
    let mut frame = Vec::new();
    ClientFrame::Hello(Hello::Start {
        size: start.size,
        env: start.env.clone(),
        agent: start.agent,
    })
    .encode(&mut frame)
    .ok()?;
    let line = format!("{START_PREFIX}{}\n", hex::encode(frame));
    debug_assert!(line.len() <= MAX_START_LINE);
    Some(line)
}

/// Parses the line made by [`format_start`], with an optional `\r` before the newline. The frame
/// is decoded by the same code that decodes a `Hello`, so it has the same limits.
pub fn parse_start(line: &[u8]) -> Result<Prestart, BootstrapError> {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let hex = line
        .strip_prefix(START_PREFIX.as_bytes())
        .ok_or(BootstrapError::Malformed)?;
    let frame = parse_hex(hex)?;
    match decode_client(&frame) {
        Ok(Some((ClientFrame::Hello(Hello::Start { size, env, agent }), used)))
            if used == frame.len() =>
        {
            Ok(Prestart { size, env, agent })
        }
        _ => Err(BootstrapError::Malformed),
    }
}
