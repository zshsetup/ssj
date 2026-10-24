//! `ssj-server --list`, `--attach`, and `--kill`: short-lived processes that talk to a running one.

use std::io::Write;
use std::process::ExitCode;
use std::time::Duration;

use ssj_proto::PROTOCOL;
use ssj_proto::bootstrap::{CHOICE_EXIT_CODE, parse_pin};
use ssj_proto::control::{Reply, Request, format_reply};

use crate::cli::{Args, Mode};
use crate::control_socket::{Found, ask, control_dir, find_sessions};
use crate::launch::read_line_with_timeout;

const PIN_TIMEOUT: Duration = Duration::from_secs(10);

fn fail(message: &str) -> ExitCode {
    eprintln!("ssj-server: {message}");
    ExitCode::from(1)
}

/// Picks the session an order is meant for, by id or by name.
///
/// Without a selector, the only session of this protocol is meant. Sessions of other protocols
/// belong to other versions of the server and are never touched.
pub fn choose(sessions: Vec<Found>, selector: Option<&str>) -> Result<Found, String> {
    if let Some(selector) = selector {
        let mut matching = matches(&sessions, selector);
        if matching.len() > 1 {
            // a name is unique among the sessions that are made with it, but it may be the id of
            // another session, and the caller has to say which one it means.
            let ids: Vec<&str> = matching.iter().map(|f| f.info.id.as_str()).collect();
            return Err(format!(
                "{selector} matches several sessions ({}), name one by its id",
                ids.join(", ")
            ));
        }
        let found = matching
            .pop()
            .cloned()
            .ok_or_else(|| format!("no running session {selector}"))?;
        return if found.info.protocol == PROTOCOL {
            Ok(found)
        } else {
            Err(format!(
                "session {selector} speaks protocol {}, this server speaks {PROTOCOL}",
                found.info.protocol
            ))
        };
    }
    let mut mine: Vec<Found> = sessions
        .into_iter()
        .filter(|f| f.info.protocol == PROTOCOL)
        .collect();
    match mine.len() {
        0 => Err("no running session".to_owned()),
        1 => Ok(mine.remove(0)),
        _ => {
            let shown: Vec<String> = mine
                .iter()
                .map(|f| match &f.info.name {
                    Some(name) => format!("{} ({})", f.info.id.as_str(), name.as_str()),
                    None => f.info.id.as_str().to_owned(),
                })
                .collect();
            Err(format!(
                "several sessions are running ({}), name one",
                shown.join(", ")
            ))
        }
    }
}

/// Asks the session to accept the client with the pin, and prints the line to connect.
pub fn attach_session(found: &Found, pin: [u8; 32], hold: bool) -> ExitCode {
    match ask(&found.path, &Request::Attach(pin)) {
        Ok(Reply::Connect(mut connect)) => {
            // the client joins by an id or a selector, and learns the name and the socket here.
            connect.name.clone_from(&found.info.name);
            connect.socket = crate::control_socket::socket_field(&found.path);
            let mut out = std::io::stdout();
            let _ = out.write_all(format_reply(&Reply::Connect(connect)).as_bytes());
            let _ = out.flush();
            if hold {
                hold_for_stream(&found.path)
            } else {
                ExitCode::SUCCESS
            }
        }
        Ok(Reply::Error(text)) => fail(&text),
        Ok(_) => fail("unexpected reply"),
        Err(err) => fail(&err.to_string()),
    }
}

/// Stays on the `ssh` channel after the connect line. A client whose QUIC does not open writes
/// [`STREAM_LINE`], and the channel then carries the session, as `--stdio` does, without a second
/// login. A client that is done with the channel closes it, or says nothing for [`HOLD_TIMEOUT`].
pub fn hold_for_stream(path: &std::path::Path) -> ExitCode {
    let deadline = std::time::Instant::now() + ssj_proto::bootstrap::HOLD_TIMEOUT;
    // a line before it, such as the start line that `--attach` does not read, is skipped.
    for _ in 0..3 {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        match read_line_with_timeout(std::io::stdin(), left) {
            Some(line) if line == ssj_proto::bootstrap::STREAM_LINE.as_bytes() => {
                return stdio(path);
            }
            Some(line) if !line.is_empty() => {}
            _ => break,
        }
    }
    ExitCode::SUCCESS
}

/// Reads the pin line of the client from stdin.
pub fn read_pin() -> Result<[u8; 32], String> {
    let line =
        read_line_with_timeout(std::io::stdin(), PIN_TIMEOUT).ok_or("no pin line on stdin")?;
    parse_pin(&line).map_err(|_| "stdin does not hold a valid SSJ PIN line".to_owned())
}

/// The sessions that a selector can mean: the one with that id and the ones with that name.
fn matches<'a>(sessions: &'a [Found], selector: &str) -> Vec<&'a Found> {
    sessions
        .iter()
        .filter(|f| {
            f.info.id.as_str() == selector
                || f.info.name.as_ref().is_some_and(|n| n.as_str() == selector)
        })
        .collect()
}

/// With `--choose`, several sessions are listed for the caller to choose from, and the exit code
/// says so, instead of the error that asks for a name or an id. That happens for no selector and
/// for one that fits several sessions.
fn several_to_choose(args: &Args, selector: Option<&str>, sessions: &[Found]) -> Option<ExitCode> {
    if !args.choose {
        return None;
    }
    let mine: Vec<&Found> = match selector {
        Some(selector) => matches(sessions, selector)
            .into_iter()
            .filter(|f| f.info.protocol == PROTOCOL)
            .collect(),
        None => sessions
            .iter()
            .filter(|f| f.info.protocol == PROTOCOL)
            .collect(),
    };
    if mine.len() < 2 {
        return None;
    }
    let mut out = std::io::stdout();
    for found in mine {
        let _ = out.write_all(format_reply(&Reply::Info(found.info.clone())).as_bytes());
    }
    Some(ExitCode::from(CHOICE_EXIT_CODE))
}

/// Sends the same order to each named session, or to the only one when none is named, and reports
/// the ones that could not be reached. The exit code is 1 if any failed.
fn send_order(sessions: &[Found], ids: &[String], order: &Request) -> ExitCode {
    let selectors: Vec<Option<&str>> = if ids.is_empty() {
        vec![None]
    } else {
        ids.iter().map(|id| Some(id.as_str())).collect()
    };
    let mut code = ExitCode::SUCCESS;
    for selector in selectors {
        let outcome = match choose(sessions.to_vec(), selector) {
            Err(message) => Err(message),
            Ok(found) => match ask(&found.path, order) {
                Ok(Reply::Ok) => Ok(()),
                Ok(Reply::Error(text)) => Err(text),
                Ok(_) => Err("unexpected reply".to_owned()),
                Err(err) => Err(err.to_string()),
            },
        };
        match outcome {
            Ok(()) => println!("OK"),
            Err(message) => code = fail(&message),
        }
    }
    code
}

pub fn run(args: &Args) -> ExitCode {
    let sessions = match control_dir() {
        Ok(dir) => find_sessions(&dir),
        Err(err) => return fail(&err.to_string()),
    };
    let selector = match &args.mode {
        Mode::Kill(ids) | Mode::Detach(ids) if ids.len() > 1 => None,
        Mode::Kill(ids) | Mode::Detach(ids) => Some(ids.first().map(String::as_str)),
        Mode::Attach(id) => Some(id.as_deref()),
        _ => None,
    };
    if let Some(selector) = selector
        && let Some(code) = several_to_choose(args, selector, &sessions)
    {
        return code;
    }
    match &args.mode {
        Mode::List => {
            let mut out = std::io::stdout();
            for found in sessions {
                let _ = out.write_all(format_reply(&Reply::Info(found.info)).as_bytes());
            }
            ExitCode::SUCCESS
        }
        Mode::Kill(ids) => send_order(&sessions, ids, &Request::Kill),
        Mode::Detach(ids) => send_order(&sessions, ids, &Request::Detach),
        Mode::Attach(selector) => {
            let pin = match read_pin() {
                Ok(pin) => pin,
                Err(message) => return fail(&message),
            };
            match choose(sessions, selector.as_deref()) {
                Err(message) => fail(&message),
                Ok(found) => attach_session(&found, pin, !args.no_hold),
            }
        }
        Mode::Stdio(id) => match choose(sessions, id.as_deref()) {
            Err(message) => fail(&message),
            Ok(found) => stdio(&found.path),
        },
        Mode::Datagrams(id) => match choose(sessions, id.as_deref()) {
            Err(message) => fail(&message),
            Ok(found) => carry(&found.path, &Request::Datagrams),
        },
        Mode::Serve | Mode::Relay | Mode::Version | Mode::CheckConfig | Mode::ConfigTemplate => {
            unreachable!("handled by the caller")
        }
    }
}

/// Time the server gets to deliver the last bytes after the client closed its side.
const STDIO_DRAIN: Duration = Duration::from_secs(2);

/// Joins stdin and stdout to the session: the control socket turns into the byte stream.
pub(crate) fn stdio(path: &std::path::Path) -> ExitCode {
    carry(path, &Request::Stream)
}

/// Like [`stdio`] for any request that turns the control socket into a stream.
fn carry(path: &std::path::Path, request: &Request) -> ExitCode {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => return fail(&format!("cannot start the runtime: {err}")),
    };
    let code = runtime.block_on(stdio_session(path, request));
    // the read of stdin runs on a thread that does not return on a terminal or a pipe that stays
    // open, so waiting for the runtime would hang.
    runtime.shutdown_background();
    code
}

async fn stdio_session(path: &std::path::Path, request: &Request) -> ExitCode {
    use ssj_proto::bootstrap::SYNC_HEADER;
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, copy};
    use tokio::net::UnixStream;

    let stream = match UnixStream::connect(path).await {
        Ok(stream) => stream,
        Err(err) => return fail(&err.to_string()),
    };
    let (read, mut write) = stream.into_split();
    if write
        .write_all(ssj_proto::control::format_request(request).as_bytes())
        .await
        .is_err()
    {
        return fail("the session does not answer");
    }
    // the answer is one line, and the stream follows it at once.
    let mut from_session = BufReader::new(read);
    let mut line = Vec::new();
    let answer = tokio::time::timeout(
        crate::control_socket::IO_TIMEOUT,
        (&mut from_session)
            .take(ssj_proto::control::MAX_LINE as u64)
            .read_until(b'\n', &mut line),
    )
    .await;
    if !matches!(answer, Ok(Ok(n)) if n > 0)
        || !matches!(ssj_proto::control::parse_reply(&line), Ok(Reply::Ok))
    {
        return fail("the session refused the stream");
    }

    let mut stdout = tokio::io::stdout();
    if stdout.write_all(SYNC_HEADER).await.is_err() || stdout.flush().await.is_err() {
        return ExitCode::from(1);
    }
    let mut stdin = tokio::io::stdin();
    let mut down = Box::pin(async {
        let _ = copy(&mut from_session, &mut stdout).await;
        let _ = stdout.flush().await;
    });
    let mut up = Box::pin(async {
        let _ = copy(&mut stdin, &mut write).await;
        let _ = write.shutdown().await;
    });
    tokio::select! {
        // the session closed the stream, which is the normal end.
        () = &mut down => {}
        // the client closed its side; the session may still have bytes for it.
        () = &mut up => {
            let _ = tokio::time::timeout(STDIO_DRAIN, down).await;
        }
    }
    ExitCode::SUCCESS
}
