//! Runs the real client against the real server through a stand-in for `ssh`.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

const FAKE_SSH: &str = "#!/bin/sh\n# usage: fake-ssh [options] -- destination command\nwhile [ \"$1\" != \"--\" ]; do shift; done\nshift\nshift\nexec sh -c \"$*\"\n";

/// Starts processes one at a time.
///
/// A test binary starts processes from several threads. On macOS a pipe is created and then marked
/// as not inheritable in a second step, and a process that another thread starts in between
/// inherits the pipe. The reading side of the test then waits for the end of a pipe that an
/// unrelated daemon keeps open. Taking a lock around the start avoids that.
pub trait SpawnLocked {
    fn spawn_locked(&mut self) -> std::io::Result<std::process::Child>;
}

impl SpawnLocked for std::process::Command {
    fn spawn_locked(&mut self) -> std::io::Result<std::process::Child> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _guard = LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        self.spawn()
    }
}

/// The server that the tests run.
///
/// Every test is a process of its own under nextest, and each one runs `cargo build`, which links
/// `target/debug/ssj-server` anew even when nothing changed: for a moment the path does not exist,
/// and a server started then fails with "No such file or directory". So each process links the
/// file once under a name of its own (a hard link is the same file and takes no space), and the
/// builds of the other tests do not reach it.
fn server_binary() -> PathBuf {
    static BINARY: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    BINARY
        .get_or_init(|| {
            let status = Command::new(env!("CARGO"))
                .args(["build", "-p", "ssj-server"])
                .status()
                .unwrap();
            assert!(status.success());
            let built = Path::new(env!("CARGO_BIN_EXE_ssj")).with_file_name("ssj-server");
            let dir = built.with_file_name(format!("e2e-server-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            let own = dir.join("ssj-server");
            let _ = std::fs::remove_file(&own);
            // the build of another test may be between removing the old link and making the
            // new one
            let started = Instant::now();
            loop {
                match std::fs::hard_link(&built, &own) {
                    Ok(()) => return own,
                    Err(err)
                        if err.kind() == std::io::ErrorKind::NotFound
                            && started.elapsed() < Duration::from_secs(60) =>
                    {
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    Err(err) => panic!("{}: {err}", built.display()),
                }
            }
        })
        .clone()
}

/// An empty directory for the config of the client. A test that does not give its own one would
/// read the file of the person who runs it, and `auto_attach = true` there changes what a plain
/// `ssj host` does.
fn no_config() -> &'static Path {
    static DIR: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    DIR.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!("ssj-e2e-noconfig-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    })
}

/// The options that the command of `words`, the first word, reads, among those that the helpers
/// give every line: a command refuses the options of the connection, so each line gets only its
/// own.
fn reads(words: &[&str], option: &str) -> bool {
    let command = ssj_client::options::command();
    let long = option.trim_start_matches("--");
    command.find_subcommand(words[0]).is_some_and(|found| {
        found
            .get_arguments()
            .any(|arg| arg.get_long() == Some(long))
    })
}

/// The options of the helpers that the command of `words` reads.
fn given(words: &[&str], options: &[&str]) -> Vec<String> {
    options
        .chunks(2)
        .filter(|pair| reads(words, pair[0]))
        .flatten()
        .map(|w| (*w).to_owned())
        .collect()
}

fn fake_ssh(script: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    // the first build of the server takes a minute on a slow machine, and a test that times itself
    // must not count it.
    server_binary();
    let dir = loop {
        let dir =
            std::env::temp_dir().join(format!("ssj-e2e-{}-{}", std::process::id(), rand_suffix()));
        match std::fs::create_dir(&dir) {
            Ok(()) => break dir,
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(err) => panic!("{}: {err}", dir.display()),
        }
    };
    let path = dir.join("fake-ssh");
    std::fs::write(&path, script).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

/// A number that no other test of this process gets. The clock is not enough: on macOS it counts
/// microseconds, and two tests that start together would write their files into the same place.
fn rand_suffix() -> u128 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    u128::from(COUNTER.fetch_add(1, Ordering::Relaxed))
}

/// A UDP port for a server that is free now.
///
/// The ports come from a range below the ephemeral ports of macOS (from 49152) and of Linux (from
/// 32768). A port from the ephemeral range can be taken at any moment by the client socket of
/// another test, and then the packets for the server go to the wrong socket and a handshake waits
/// forever. Each test process starts at a different place of the range.
fn free_port() -> u16 {
    use std::net::UdpSocket;
    use std::sync::atomic::{AtomicU16, Ordering};

    static NEXT: AtomicU16 = AtomicU16::new(0);
    let base = 20_000 + (std::process::id() % 400) as u16 * 25;
    loop {
        let port = base + NEXT.fetch_add(1, Ordering::Relaxed) % 5_000;
        // free on both families, since the server listens on a dual stack socket. Each socket is
        // closed before the next is tried: on Linux a `::` socket cannot share the port with an
        // open `0.0.0.0` one, and on macOS it can.
        let v4_free = UdpSocket::bind(("0.0.0.0", port)).is_ok();
        // a host without IPv6 (a container) has nothing to conflict with on that family.
        let v6_free = match UdpSocket::bind(("::", port)) {
            Ok(_) => true,
            Err(err) => err.kind() != std::io::ErrorKind::AddrInUse,
        };
        if v4_free && v6_free {
            return port;
        }
    }
}

/// Runs `ssj` with `input` on stdin and a shell command for the server, and waits for it.
fn run_client(ssh: &Path, shell_args: &[&str], input: &str) -> Output {
    run_client_with(ssh, shell_args, input, &[])
}

/// Like [`run_client`] with more arguments for the client.
fn run_client_with(ssh: &Path, shell_args: &[&str], input: &str, client_args: &[&str]) -> Output {
    run_client_to(
        ssh,
        shell_args,
        input,
        client_args,
        "user@localhost",
        Some("127.0.0.1"),
    )
}

/// Like [`run_client_with`] for another destination, and with or without the UDP address.
fn run_client_to(
    ssh: &Path,
    shell_args: &[&str],
    input: &str,
    client_args: &[&str],
    destination: &str,
    udp_host: Option<&str>,
) -> Output {
    let port = free_port();
    let mut command = Command::new(env!("CARGO_BIN_EXE_ssj"));
    command.env("XDG_CONFIG_HOME", no_config()).arg("connect");
    command
        .args(["--ssh-command", ssh.to_str().unwrap()])
        .args(["--server-path", server_binary().to_str().unwrap()])
        .args(["--port-range", &format!("{port}:{port}")]);
    if let Some(host) = udp_host {
        command.args(["--udp-host", host]);
    }
    command.args([
        "--detached-timeout",
        "5",
        "--server-arg",
        "--max-detached",
        "--server-arg",
        "30",
        "--server-arg",
        "--shell",
        "--server-arg",
        "/bin/sh",
    ]);
    for arg in shell_args {
        command.args(["--server-arg", "--shell-arg", "--server-arg", arg]);
    }
    let mut child = command
        .args(client_args)
        .arg(destination)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn_locked()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();

    let start = Instant::now();
    loop {
        if child.try_wait().unwrap().is_some() {
            return child.wait_with_output().unwrap();
        }
        if start.elapsed() > Duration::from_secs(60) {
            child.kill().unwrap();
            panic!(
                "the client did not finish: {:?}",
                child.wait_with_output().unwrap()
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn shell_command_runs_through_bootstrap_quic_and_pty_and_its_exit_code_is_returned() {
    let output = run_client(
        &fake_ssh(FAKE_SSH),
        &["-c", "read x; echo got:$x; exit 3"],
        "xyz\n",
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        stdout.contains("got:xyz"),
        "stdout: {stdout:?} stderr: {stderr:?}"
    );
    assert_eq!(output.status.code(), Some(3), "stderr: {stderr:?}");
}

/// Runs `ssj connect user@localhost <words>` with a shell of /bin/sh on the host.
fn run_with_command(ssh: &Path, words: &[&str]) -> Output {
    let port = free_port();
    let child = Command::new(env!("CARGO_BIN_EXE_ssj"))
        .env("XDG_CONFIG_HOME", no_config())
        .arg("connect")
        .args(["--ssh-command", ssh.to_str().unwrap()])
        .args(["--server-path", server_binary().to_str().unwrap()])
        .args(["--port-range", &format!("{port}:{port}")])
        .args(["--udp-host", "127.0.0.1"])
        .args(LEAK_GUARD)
        .args(["--server-arg", "--shell", "--server-arg", "/bin/sh"])
        .arg("user@localhost")
        .args(words)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn_locked()
        .unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn a_command_after_the_destination_runs_in_the_session_and_its_exit_code_is_returned() {
    // the same way as `ssh host command`: through the shell of the host, so pipes and && work.
    let ssh = fake_ssh(FAKE_SSH);
    for (words, expected_code, expected_text) in [
        (vec!["--", "echo one-two | tr o 0; exit 3"], 3, "0ne-tw0"),
        (vec!["--", "printf", "'%s-%s'", "a", "b"], 0, "a-b"),
        (vec!["--", "exit", "7"], 7, ""),
        // without the dashes, the options after the host belong to the command.
        (vec!["echo", "plain"], 0, "plain"),
        (vec!["echo", "-n", "dashless"], 0, "dashless"),
    ] {
        let output = run_with_command(&ssh, &words);
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains(expected_text), "{words:?}: {stdout:?}");
        assert_eq!(
            output.status.code(),
            Some(expected_code),
            "{words:?}: {stdout:?} {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn every_ssh_that_runs_a_command_gets_no_escape_character() {
    let log = fake_ssh("").with_file_name("args.log");
    let script = format!(
        "#!/bin/sh\necho \"$*\" >> {}\n{}",
        log.display(),
        &FAKE_SSH["#!/bin/sh\n".len()..]
    );
    let output = run_client(&fake_ssh(&script), &["-c", "exit 0"], "");
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let logged = std::fs::read_to_string(&log).unwrap();
    let calls: Vec<&str> = logged.lines().collect();
    assert!(!calls.is_empty());
    for call in calls {
        // only the query of the configuration (`-G`) does not open a session.
        if call.split(' ').any(|word| word == "-G") {
            continue;
        }
        let before_destination = call.split(" -- ").next().unwrap();
        assert!(before_destination.contains("-e none"), "{call}");
    }
}

#[test]
fn piped_script_runs_in_an_interactive_shell() {
    let output = run_client(
        &fake_ssh(FAKE_SSH),
        &["-i"],
        "echo hello-from-shell\nexit 5\n",
    );
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("hello-from-shell"), "{stdout:?}");
    assert_eq!(output.status.code(), Some(5));
}

// text from the remote side may carry terminal escape sequences and must not reach the screen.
#[test]
fn failed_bootstrap_shows_remote_text_without_control_characters() {
    let ssh =
        fake_ssh("#!/bin/sh\nprintf '\\033[2J\\033]0;pwned\\007remote said no\\n' >&2\nexit 1\n");
    let output = run_client(&ssh, &["-c", "true"], "");
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(1));
    assert!(stderr.contains("remote said no"), "{stderr:?}");
    assert!(
        !stderr.chars().any(|c| c.is_control() && c != '\n'),
        "{stderr:?}"
    );
}

/// Runs the client on a pseudo-terminal, as a user would, with `extra` words in front. It types
/// `stty size` and `exit 7`, and returns what the terminal showed and the exit code.
fn terminal_session(extra: &[&str]) -> (String, Option<i32>) {
    use std::io::{Read, Write};
    use std::sync::mpsc;

    let ssh = fake_ssh(FAKE_SSH);
    let port = free_port();
    let (pty, pts) = pty_process::blocking::open().unwrap();
    pty.resize(pty_process::Size::new(31, 97)).unwrap();
    let mut child = pty_process::blocking::Command::new(env!("CARGO_BIN_EXE_ssj"))
        .env("XDG_CONFIG_HOME", no_config())
        .arg("connect")
        .args(extra)
        .args(["--ssh-command", ssh.to_str().unwrap()])
        .args(["--server-path", server_binary().to_str().unwrap()])
        .args([
            "--udp-host",
            "127.0.0.1",
            "--port-range",
            &format!("{port}:{port}"),
        ])
        .args([
            "--detached-timeout",
            "5",
            "--server-arg",
            "--max-detached",
            "--server-arg",
            "30",
            "--server-arg",
            "--shell",
            "--server-arg",
            "/bin/sh",
        ])
        .args([
            "--server-arg",
            "--shell-arg",
            "--server-arg",
            "-i",
            "me@localhost",
        ])
        .spawn(pts)
        .unwrap();

    // one handle to read on a thread and one to write.
    let fd: std::os::fd::OwnedFd = pty.into();
    let mut reader = std::fs::File::from(fd.try_clone().unwrap());
    let mut pty = std::fs::File::from(fd);
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok(n) = reader.read(&mut buf) {
            if n == 0 || tx.send(buf[..n].to_vec()).is_err() {
                break;
            }
        }
    });
    let mut seen = String::new();
    // alternatives are separated by `|`: the prompt is `$ ` for a user and `# ` for root.
    let mut wait_for = |needle: &str| {
        let deadline = Instant::now() + Duration::from_secs(20);
        while !needle.split('|').any(|n| seen.contains(n)) {
            let left = deadline.saturating_duration_since(Instant::now());
            match rx.recv_timeout(left) {
                Ok(bytes) => seen.push_str(&String::from_utf8_lossy(&bytes)),
                Err(_) => panic!("never saw {needle:?} in {seen:?}"),
            }
        }
    };

    wait_for("$|# ");
    pty.write_all(b"stty size\n").unwrap();
    wait_for("31 97");
    pty.write_all(b"exit 7\n").unwrap();

    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "the client hangs after the shell exited"
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    // what the client printed on its way out
    while let Ok(bytes) = rx.recv_timeout(Duration::from_millis(500)) {
        seen.push_str(&String::from_utf8_lossy(&bytes));
    }
    (seen, status.code())
}

#[test]
fn client_on_a_terminal_passes_the_window_size_and_exits_without_hanging() {
    let (seen, code) = terminal_session(&[]);
    assert!(seen.contains("31 97"), "{seen:?}");
    assert_eq!(code, Some(7));
    // without the message of the day, these lines say when the session begins and ends.
    assert!(
        seen.contains("[started session ") && seen.contains(" on me@localhost over udp]"),
        "{seen:?}"
    );
    assert!(
        seen.contains("[disconnected from me@localhost]"),
        "{seen:?}"
    );
}

#[test]
fn the_first_line_names_the_session_when_it_has_a_name() {
    let (seen, code) = terminal_session(&["--name", "work"]);
    assert_eq!(code, Some(7));
    assert!(
        seen.contains("[started session work (") && seen.contains(") on me@localhost over udp]"),
        "{seen:?}"
    );
}

#[test]
fn quiet_leaves_out_the_lines_about_connecting_and_disconnecting() {
    let (seen, code) = terminal_session(&["-q"]);
    assert_eq!(code, Some(7));
    assert!(!seen.contains("[started"), "{seen:?}");
    assert!(!seen.contains("[disconnected"), "{seen:?}");
}

/// A new directory with a short path (a socket path is short). The process ids come round on a
/// machine that runs the tests often, and a directory of an earlier run with the same name has the
/// state of that run in it, so the directory is created exclusively and the next name is tried if
/// one exists.
fn short_dir() -> PathBuf {
    loop {
        let dir = PathBuf::from(format!(
            "/tmp/ssjt-c-{}-{}",
            std::process::id(),
            rand_suffix()
        ));
        match std::fs::create_dir(&dir) {
            Ok(()) => return dir,
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(err) => panic!("{}: {err}", dir.display()),
        }
    }
}

/// Runs `ssj` with the given words and stdin, against the server in the same runtime directory.
/// Every session of these tests ends by itself after a minute, so that a test that fails before
/// it kills its session does not leave a server process behind for hours.
const LEAK_GUARD: [&str; 8] = [
    "--server-arg",
    "--max-detached",
    "--server-arg",
    "60",
    "--server-arg",
    "--detached-timeout",
    "--server-arg",
    "60",
];

fn ssj(runtime: &Path, ssh: &Path, words: &[&str], input: &str) -> Output {
    let (word, rest) = words.split_first().expect("a command word");
    let mut child = Command::new(env!("CARGO_BIN_EXE_ssj"))
        .env("XDG_CONFIG_HOME", no_config())
        .env("XDG_RUNTIME_DIR", runtime)
        .env("XDG_CACHE_HOME", runtime)
        .arg(word)
        .args(given(
            words,
            &[
                "--ssh-command",
                ssh.to_str().unwrap(),
                "--server-path",
                server_binary().to_str().unwrap(),
                "--udp-host",
                "127.0.0.1",
            ],
        ))
        .args(given(words, &LEAK_GUARD))
        .args(rest)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn_locked()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    let start = Instant::now();
    loop {
        if child.try_wait().unwrap().is_some() {
            return child.wait_with_output().unwrap();
        }
        assert!(
            start.elapsed() < Duration::from_secs(60),
            "ssj {words:?} did not finish"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Types `send` into `ssj` and waits until its output contains `expect` before the next step,
/// like a person who reads the screen. Returns the output when the client has ended.
fn ssj_typing(runtime: &Path, ssh: &Path, words: &[&str], steps: &[(&str, &str)]) -> Output {
    use std::io::Read;
    use std::sync::{Arc, Mutex};

    let (word, rest) = words.split_first().expect("a command word");
    let mut child = Command::new(env!("CARGO_BIN_EXE_ssj"))
        .env("XDG_CONFIG_HOME", no_config())
        .env("XDG_RUNTIME_DIR", runtime)
        .env("XDG_CACHE_HOME", runtime)
        .arg(word)
        .args(given(
            words,
            &[
                "--ssh-command",
                ssh.to_str().unwrap(),
                "--server-path",
                server_binary().to_str().unwrap(),
                "--udp-host",
                "127.0.0.1",
            ],
        ))
        .args(given(words, &LEAK_GUARD))
        .args(rest)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn_locked()
        .unwrap();
    let seen = Arc::new(Mutex::new(String::new()));
    let mut stdout = child.stdout.take().unwrap();
    let collector = seen.clone();
    let reader = std::thread::spawn(move || {
        let mut buf = [0u8; 1024];
        while let Ok(n) = stdout.read(&mut buf) {
            if n == 0 {
                break;
            }
            collector
                .lock()
                .unwrap()
                .push_str(&String::from_utf8_lossy(&buf[..n]));
        }
    });
    let mut stdin = child.stdin.take().unwrap();
    for (send, expect) in steps {
        stdin.write_all(send.as_bytes()).unwrap();
        let start = Instant::now();
        while !seen.lock().unwrap().contains(expect) {
            assert!(
                start.elapsed() < Duration::from_secs(30),
                "never saw {expect:?} in {:?}",
                seen.lock().unwrap()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    let start = Instant::now();
    while child.try_wait().unwrap().is_none() {
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "ssj {words:?} did not finish"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = reader.join();
    let mut output = child.wait_with_output().unwrap();
    output.stdout = seen.lock().unwrap().clone().into_bytes();
    output
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[test]
fn list_attach_detach_attach_kill_through_the_client() {
    use ssj_proto::bootstrap::format_pin;

    let runtime = short_dir();
    let ssh = fake_ssh(FAKE_SSH);
    let script = "stty -echo; n=0; while read l; do n=$((n+1)); echo \"got:$l:$n\"; done";

    // a session whose first client never shows up, as after a crash of the client.
    let port = free_port();
    let mut daemon = Command::new(server_binary())
        .env("XDG_RUNTIME_DIR", &runtime)
        .args([
            "--port-range",
            &format!("{port}:{port}"),
            "--detached-timeout",
            "60",
        ])
        .args([
            "--shell",
            "/bin/sh",
            "--shell-arg",
            "-c",
            "--shell-arg",
            script,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn_locked()
        .unwrap();
    let dummy = ssj_net::Identity::generate();
    daemon
        .stdin
        .take()
        .unwrap()
        .write_all(format_pin(&dummy.fingerprint()).as_bytes())
        .unwrap();
    assert!(daemon.wait_with_output().unwrap().status.success());

    let listed = ssj(&runtime, &ssh, &["list", "user@localhost"], "");
    let listing = text(&listed.stdout);
    assert!(listed.status.success(), "{}", text(&listed.stderr));
    assert!(
        listing.contains("disconnected")
            && listing.contains(&format!("protocol {}", ssj_proto::PROTOCOL)),
        "{listing}"
    );
    let id = listing.split_whitespace().next().unwrap().to_owned();

    // the same list as JSON, and the cache that completion reads.
    let json = ssj(&runtime, &ssh, &["list", "--json", "user@localhost"], "");
    let json = text(&json.stdout);
    assert!(
        json.starts_with("[{\"id\":\"") && json.contains("\"state\":\"disconnected\""),
        "{json}"
    );
    let cached = ssj(&runtime, &ssh, &["--complete", "user@localhost"], "");
    assert!(text(&cached.stdout).lines().any(|l| l == id), "{cached:?}");

    // the first attach types a line and leaves with the detach key.
    let first = ssj_typing(
        &runtime,
        &ssh,
        &["attach", "user@localhost", &id],
        &[
            (
                "hello
",
                "got:hello:1",
            ),
            ("\x1c", ""),
        ],
    );
    assert!(
        text(&first.stdout).contains("got:hello:1"),
        "{} / {}",
        text(&first.stdout),
        text(&first.stderr)
    );
    assert_eq!(first.status.code(), Some(0));
    assert!(
        text(&first.stderr).contains("detached"),
        "{}",
        text(&first.stderr)
    );

    // the second one finds the shell as it was.
    let second = ssj_typing(
        &runtime,
        &ssh,
        &["attach", "user@localhost"],
        &[("again\n", "got:again:2"), ("\x1c", "")],
    );
    assert!(
        text(&second.stdout).contains("got:again:2"),
        "{} / {}",
        text(&second.stdout),
        text(&second.stderr)
    );

    let listing = text(&ssj(&runtime, &ssh, &["list", "user@localhost"], "").stdout);
    assert!(listing.contains("detached"), "{listing}");

    let killed = ssj(&runtime, &ssh, &["kill", "-f", "user@localhost"], "");
    assert!(killed.status.success(), "{}", text(&killed.stderr));
    assert!(text(&killed.stdout).contains("session ended"));
    let start = Instant::now();
    loop {
        let listing = text(&ssj(&runtime, &ssh, &["list", "user@localhost"], "").stdout);
        if listing.contains("no sessions") {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(8),
            "still listed: {listing}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Waits until `ssj list` shows a session in `state` and returns its id.
fn wait_for_state(runtime: &Path, ssh: &Path, state: &str) -> String {
    let start = Instant::now();
    loop {
        let listing = text(&ssj(runtime, ssh, &["list", "user@localhost"], "").stdout);
        if listing.contains(state) {
            return listing.split_whitespace().next().unwrap().to_owned();
        }
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "no session {state}: {listing}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn detach_from_another_terminal_lets_the_client_leave_and_the_shell_stays() {
    let runtime = short_dir();
    let ssh = fake_ssh(FAKE_SSH);
    let marker = runtime.join("typed");
    let script = format!(
        "stty -echo; n=0; while read l; do n=$((n+1)); echo \"got:$l:$n\"; touch {}; done",
        marker.display()
    );
    let helper = {
        let (runtime, ssh) = (runtime.clone(), ssh.clone());
        std::thread::spawn(move || {
            let start = Instant::now();
            while !runtime.join("typed").exists() {
                assert!(start.elapsed() < Duration::from_secs(20), "nothing typed");
                std::thread::sleep(Duration::from_millis(50));
            }
            // the client is connected and has typed: this is the other terminal.
            ssj(&runtime, &ssh, &["detach", "user@localhost"], "")
        })
    };
    let first = ssj_typing(
        &runtime,
        &ssh,
        &["connect", "user@localhost", "--", &script],
        &[("one\n", "got:one:1")],
    );
    let detached = helper.join().unwrap();
    assert!(detached.status.success(), "{}", text(&detached.stderr));
    assert!(text(&detached.stdout).contains("detached"));
    assert_eq!(first.status.code(), Some(0), "{}", text(&first.stderr));
    assert!(
        text(&first.stderr).contains("detached"),
        "{}",
        text(&first.stderr)
    );

    // the shell kept its state for the next client.
    wait_for_state(&runtime, &ssh, "detached");
    let again = ssj_typing(
        &runtime,
        &ssh,
        &["attach", "user@localhost"],
        &[("two\n", "got:two:2"), ("\x1c", "")],
    );
    assert!(text(&again.stdout).contains("got:two:2"));

    // nobody is connected now.
    let nobody = ssj(&runtime, &ssh, &["detach", "user@localhost"], "");
    assert_eq!(nobody.status.code(), Some(1));
    assert!(
        text(&nobody.stderr).contains("no client is connected"),
        "{}",
        text(&nobody.stderr)
    );
    let _ = ssj(&runtime, &ssh, &["kill", "-f", "user@localhost"], "");
}

#[test]
fn the_detach_key_leaves_in_the_middle_of_a_line() {
    let runtime = short_dir();
    let ssh = fake_ssh(FAKE_SSH);
    let output = ssj_typing(
        &runtime,
        &ssh,
        &["connect", "--detach-key", "ctrl-]", "user@localhost"],
        // typed in the middle of a line.
        &[("half a line\x1d", "")],
    );
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    assert!(
        text(&output.stderr).contains("detached"),
        "{}",
        text(&output.stderr)
    );
    let id = wait_for_state(&runtime, &ssh, "detached");
    assert!(!id.is_empty());
    let _ = ssj(&runtime, &ssh, &["kill", "-f", "user@localhost"], "");
}

#[test]
fn kill_ends_several_sessions_in_one_call() {
    let runtime = short_dir();
    let ssh = fake_ssh(FAKE_SSH);
    let mut ids = Vec::new();
    for _ in 0..3 {
        let output = ssj_typing(
            &runtime,
            &ssh,
            &["connect", "--detach-key", "ctrl-]", "user@localhost"],
            &[("x\x1d", "")],
        );
        assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    }
    let listing = text(&ssj(&runtime, &ssh, &["list", "user@localhost"], "").stdout);
    for line in listing.lines() {
        ids.push(line.split_whitespace().next().unwrap().to_owned());
    }
    assert_eq!(ids.len(), 3, "{listing}");

    // two of the three, in one call; a name that does not exist is reported and does not stop it.
    let killed = ssj(
        &runtime,
        &ssh,
        &["kill", "user@localhost", &ids[0], "nosuchsession", &ids[1]],
        "",
    );
    assert_eq!(killed.status.code(), Some(1), "{}", text(&killed.stdout));
    assert!(
        text(&killed.stderr).contains("no running session nosuchsession"),
        "{}",
        text(&killed.stderr)
    );
    let start = Instant::now();
    loop {
        let listing = text(&ssj(&runtime, &ssh, &["list", "user@localhost"], "").stdout);
        if listing.lines().count() == 1 && listing.contains(&ids[2]) {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(8),
            "still listed: {listing}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }

    let rest = ssj(&runtime, &ssh, &["kill", "user@localhost", &ids[2]], "");
    assert!(rest.status.success(), "{}", text(&rest.stderr));
}

#[test]
fn attach_and_kill_without_a_session_say_so() {
    let runtime = short_dir();
    let ssh = fake_ssh(FAKE_SSH);
    for words in [
        vec!["attach", "user@localhost"],
        vec!["kill", "user@localhost"],
        vec!["kill", "user@localhost", "abcdef012345"],
    ] {
        let output = ssj(&runtime, &ssh, &words, "");
        assert_eq!(output.status.code(), Some(1), "{words:?}");
        assert!(
            text(&output.stderr).contains("no running session"),
            "{words:?}: {}",
            text(&output.stderr)
        );
    }
    let listed = ssj(&runtime, &ssh, &["list", "user@localhost"], "");
    assert!(text(&listed.stdout).contains("no sessions"));
}

/// Directories for one test host: where the data (installed files) and the sockets go.
struct Host {
    data: PathBuf,
    config: PathBuf,
    runtime: PathBuf,
}

fn host() -> Host {
    Host {
        data: short_dir(),
        config: short_dir(),
        runtime: short_dir(),
    }
}

impl Host {
    fn installed(&self) -> PathBuf {
        self.data
            .join(format!("ssj/bin/ssj-server-p{}", ssj_proto::PROTOCOL))
    }

    /// Runs `ssj` as a script would, without a terminal, with the words as given.
    fn ssj(&self, ssh: &Path, words: &[&str], input: &str) -> Output {
        self.ssj_with(Path::new(env!("CARGO_BIN_EXE_ssj")), ssh, words, input)
    }

    /// Like [`Host::ssj`] with another build of the client.
    fn ssj_with(&self, exe: &Path, ssh: &Path, words: &[&str], input: &str) -> Output {
        let (word, rest) = words.split_first().expect("a command word");
        let mut child = Command::new(exe)
            .env("XDG_DATA_HOME", &self.data)
            .env("XDG_CONFIG_HOME", &self.config)
            .env("XDG_RUNTIME_DIR", &self.runtime)
            .env("XDG_CACHE_HOME", &self.runtime)
            .arg(word)
            .args(given(
                words,
                &[
                    "--ssh-command",
                    ssh.to_str().unwrap(),
                    "--udp-host",
                    "127.0.0.1",
                ],
            ))
            .args(given(words, &LEAK_GUARD))
            .args(rest)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn_locked()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
        let start = Instant::now();
        while child.try_wait().unwrap().is_none() {
            assert!(
                start.elapsed() < Duration::from_secs(60),
                "ssj {words:?} did not finish"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        child.wait_with_output().unwrap()
    }

    /// The words that start a short session without naming the server file.
    fn session_words(&self, extra: &[&str]) -> Vec<String> {
        let port = free_port();
        let mut words = vec!["connect".to_owned()];
        words.extend(extra.iter().map(|w| (*w).to_owned()));
        for arg in [
            "--port-range",
            &format!("{port}:{port}"),
            "--detached-timeout",
            "5",
            "--server-arg",
            "--max-detached",
            "--server-arg",
            "30",
            "--server-arg",
            "--shell",
            "--server-arg",
            "/bin/sh",
            "--server-arg",
            "--shell-arg",
            "--server-arg",
            "-c",
            "--server-arg",
            "--shell-arg",
            "--server-arg",
            "read x; echo got:$x; exit 3",
        ] {
            words.push(arg.to_owned());
        }
        words.push("user@localhost".to_owned());
        words
    }
}

fn words(owned: &[String]) -> Vec<&str> {
    owned.iter().map(String::as_str).collect()
}

#[test]
fn install_uploads_checks_and_makes_the_default_path_work() {
    let host = host();
    let ssh = fake_ssh(FAKE_SSH);
    let dir = server_binary();

    let output = host.ssj(
        &ssh,
        &[
            "install",
            "--server-binary",
            dir.to_str().unwrap(),
            "user@localhost",
        ],
        "",
    );
    assert!(output.status.success(), "{}", text(&output.stderr));
    assert!(
        text(&output.stdout).contains("installed "),
        "{}",
        text(&output.stdout)
    );

    // a private, executable file that reports the protocol.
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(host.installed())
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o700);
    let version = Command::new(host.installed())
        .arg("--version")
        .output()
        .unwrap();
    assert!(text(&version.stdout).contains(&format!("protocol {}", ssj_proto::PROTOCOL)));
    // no temporary files stay behind.
    let names: Vec<String> = std::fs::read_dir(host.data.join("ssj/bin"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, [format!("ssj-server-p{}", ssj_proto::PROTOCOL)]);

    // an installed file of the same protocol is replaced, and the output says which one.
    let again = host.ssj(
        &ssh,
        &[
            "install",
            "--server-binary",
            dir.to_str().unwrap(),
            "user@localhost",
        ],
        "",
    );
    assert!(again.status.success(), "{}", text(&again.stderr));
    assert!(
        text(&again.stdout).contains("(replaced ssj-server "),
        "{}",
        text(&again.stdout)
    );

    // and a session starts through the default path, without --server-path.
    let session = host.session_words(&[]);
    let output = host.ssj(&ssh, &words(&session), "go\n");
    assert!(
        text(&output.stdout).contains("got:go"),
        "{} / {}",
        text(&output.stdout),
        text(&output.stderr)
    );
    assert_eq!(output.status.code(), Some(3));
}

#[test]
fn missing_server_is_installed_on_demand_with_the_flag() {
    let host = host();
    let ssh = fake_ssh(FAKE_SSH);
    let dir = server_binary();
    let session = host.session_words(&["--install", "--server-binary", dir.to_str().unwrap()]);

    let output = host.ssj(&ssh, &words(&session), "go\n");

    assert!(
        text(&output.stderr).contains("installed "),
        "{}",
        text(&output.stderr)
    );
    assert!(
        text(&output.stdout).contains("got:go"),
        "{} / {}",
        text(&output.stdout),
        text(&output.stderr)
    );
    assert_eq!(output.status.code(), Some(3));
    assert!(host.installed().exists());
}

#[test]
fn without_a_terminal_a_missing_server_is_not_installed_unasked() {
    let host = host();
    let ssh = fake_ssh(FAKE_SSH);
    let dir = server_binary();
    let session = host.session_words(&["--server-binary", dir.to_str().unwrap()]);

    let output = host.ssj(&ssh, &words(&session), "");

    assert_eq!(output.status.code(), Some(1));
    let stderr = text(&output.stderr);
    assert!(
        stderr.contains("not installed")
            && stderr.contains("no terminal")
            && stderr.contains("--install"),
        "{stderr}"
    );
    assert!(!host.installed().exists());
}

#[test]
fn a_missing_server_is_a_reason_to_install_for_auto_attach_and_name_but_not_for_attach() {
    let host = host();
    let ssh = fake_ssh(FAKE_SSH);
    let dir = server_binary();
    for flags in [&["--auto-attach"][..], &["--name", "work"][..]] {
        let mut extra = vec!["--server-binary", dir.to_str().unwrap()];
        extra.extend_from_slice(flags);
        let session = host.session_words(&extra);

        let output = host.ssj(&ssh, &words(&session), "");

        // no terminal, so nobody can be asked: the message is the one of the install policy.
        let stderr = text(&output.stderr);
        assert_eq!(output.status.code(), Some(1), "{flags:?}: {stderr}");
        assert!(
            stderr.contains("no terminal") && stderr.contains("--install"),
            "{flags:?}: {stderr}"
        );
        assert!(
            !stderr.contains("no session runs there"),
            "{flags:?}: {stderr}"
        );
    }
    // an explicit attach has no session to find without a server, and says so.
    let attached = host.ssj(&ssh, &["attach", "user@localhost"], "");
    assert!(
        text(&attached.stderr).contains("no session runs there"),
        "{}",
        text(&attached.stderr)
    );
}

#[test]
fn the_config_file_and_the_flags_decide_in_this_order() {
    let host = host();
    let ssh = fake_ssh(FAKE_SSH);
    let dir = server_binary();
    std::fs::create_dir_all(host.config.join("ssj")).unwrap();
    let config = host.config.join("ssj/client.toml");
    let write = |text: &str| {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(&config, text).unwrap();
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
    };

    // "never" in the config stops an installation that would otherwise happen.
    write("auto_install = \"never\"\n");
    let session = host.session_words(&["--server-binary", dir.to_str().unwrap()]);
    let output = host.ssj(&ssh, &words(&session), "go\n");
    assert_eq!(output.status.code(), Some(1));
    assert!(
        text(&output.stderr).contains("ssj install"),
        "{}",
        text(&output.stderr)
    );
    assert!(!host.installed().exists());

    // the flag wins over the config.
    let session = host.session_words(&["--install", "--server-binary", dir.to_str().unwrap()]);
    assert_eq!(
        host.ssj(&ssh, &words(&session), "go\n").status.code(),
        Some(3)
    );
    assert!(host.installed().exists());
    std::fs::remove_file(host.installed()).unwrap();

    // "always" in the config installs without a flag.
    write("auto_install = \"always\"\n");
    let session = host.session_words(&["--server-binary", dir.to_str().unwrap()]);
    assert_eq!(
        host.ssj(&ssh, &words(&session), "go\n").status.code(),
        Some(3)
    );
    assert!(host.installed().exists());
    std::fs::remove_file(host.installed()).unwrap();

    // and --no-install wins over "always".
    let session = host.session_words(&["--no-install", "--server-binary", dir.to_str().unwrap()]);
    assert_eq!(
        host.ssj(&ssh, &words(&session), "go\n").status.code(),
        Some(1)
    );
    assert!(!host.installed().exists());

    // a broken config is an error, not a silent default.
    write("auto_instal = \"always\"\n");
    let output = host.ssj(&ssh, &["list", "user@localhost"], "");
    assert_eq!(output.status.code(), Some(2));
    assert!(
        text(&output.stderr).contains("unknown field"),
        "{}",
        text(&output.stderr)
    );
}

// A transfer that is changed on the way must never replace or create the server file.
#[test]
fn damaged_upload_is_rejected_and_installs_nothing() {
    let host = host();
    let ssh = fake_ssh(
        "#!/bin/sh\nwhile [ \"$1\" != \"--\" ]; do shift; done\nshift\nshift\n{ cat; printf x; } | sh -c \"$*\"\n",
    );
    let dir = server_binary();

    let output = host.ssj(
        &ssh,
        &[
            "install",
            "--server-binary",
            dir.to_str().unwrap(),
            "user@localhost",
        ],
        "",
    );

    assert_eq!(output.status.code(), Some(1));
    assert!(
        text(&output.stderr).contains("does not match its digest"),
        "{}",
        text(&output.stderr)
    );
    assert!(!host.installed().exists());
    let leftovers = std::fs::read_dir(host.data.join("ssj/bin"))
        .map(|d| d.count())
        .unwrap_or(0);
    assert_eq!(leftovers, 0, "the temporary file must be removed");
}

#[test]
fn unsupported_systems_and_a_missing_server_file_are_explained() {
    let host = host();
    let freebsd = fake_ssh("#!/bin/sh\necho 'SSJ TARGET FreeBSD amd64'\n");
    let dir = server_binary();
    let output = host.ssj(
        &freebsd,
        &[
            "install",
            "--server-binary",
            dir.to_str().unwrap(),
            "user@localhost",
        ],
        "",
    );
    assert_eq!(output.status.code(), Some(1));
    assert!(
        text(&output.stderr).contains("no server for the system"),
        "{}",
        text(&output.stderr)
    );

    let ssh = fake_ssh(FAKE_SSH);
    let missing = short_dir().join("ssj-server");
    let output = host.ssj(
        &ssh,
        &[
            "install",
            "--server-binary",
            missing.to_str().unwrap(),
            "user@localhost",
        ],
        "",
    );
    assert_eq!(output.status.code(), Some(1));
    let stderr = text(&output.stderr);
    assert!(
        stderr.contains("cannot read") && stderr.contains("ssj-server"),
        "{stderr}"
    );
}

#[test]
fn a_host_that_prints_without_end_does_not_hang_the_client() {
    let host = host();
    let ssh = fake_ssh("#!/bin/sh\nexec yes\n");
    let began = std::time::Instant::now();
    let output = host.ssj(&ssh, &["list", "user@localhost"], "");
    assert_ne!(output.status.code(), Some(0));
    assert!(
        began.elapsed() < Duration::from_secs(60),
        "the client waited for a process that never ends"
    );
}

#[test]
fn listing_and_attaching_to_a_host_without_the_server_say_so() {
    let host = host();
    let ssh = fake_ssh(FAKE_SSH);

    let listed = host.ssj(&ssh, &["list", "user@localhost"], "");
    assert_eq!(listed.status.code(), Some(0));
    assert!(
        text(&listed.stdout).contains("not installed"),
        "{}",
        text(&listed.stdout)
    );

    for command in ["attach", "kill"] {
        let output = host.ssj(&ssh, &[command, "user@localhost"], "");
        assert_eq!(output.status.code(), Some(1), "{command}");
        assert!(
            text(&output.stderr).contains("not installed"),
            "{command}: {}",
            text(&output.stderr)
        );
        assert!(!host.installed().exists(), "{command} must never install");
    }
}

/// Starts `ssj` on a pseudo-terminal, so that it can ask questions, and follows what it shows.
struct OnTerminal {
    child: std::process::Child,
    typed: std::fs::File,
    shown: std::sync::mpsc::Receiver<Vec<u8>>,
    seen: String,
}

fn on_terminal(host: &Host, ssh: &Path, words: &[String]) -> OnTerminal {
    use std::io::Read;

    let (pty, pts) = pty_process::blocking::open().unwrap();
    pty.resize(pty_process::Size::new(24, 80)).unwrap();
    let child = pty_process::blocking::Command::new(env!("CARGO_BIN_EXE_ssj"))
        .env("XDG_DATA_HOME", &host.data)
        .env("XDG_CONFIG_HOME", &host.config)
        .env("XDG_RUNTIME_DIR", &host.runtime)
        .env("XDG_CACHE_HOME", &host.runtime)
        .arg(&words[0])
        .args(given(
            &words.iter().map(String::as_str).collect::<Vec<_>>(),
            &[
                "--ssh-command",
                ssh.to_str().unwrap(),
                "--udp-host",
                "127.0.0.1",
            ],
        ))
        .args(&words[1..])
        .spawn(pts)
        .unwrap();
    let fd: std::os::fd::OwnedFd = pty.into();
    let mut reader = std::fs::File::from(fd.try_clone().unwrap());
    let typed = std::fs::File::from(fd);
    let (tx, shown) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok(n) = reader.read(&mut buf) {
            if n == 0 || tx.send(buf[..n].to_vec()).is_err() {
                break;
            }
        }
    });
    OnTerminal {
        child,
        typed,
        shown,
        seen: String::new(),
    }
}

impl OnTerminal {
    fn wait_for(&mut self, needle: &str) {
        let deadline = Instant::now() + Duration::from_secs(30);
        while !self.seen.contains(needle) {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.shown.recv_timeout(left) {
                Ok(bytes) => self.seen.push_str(&String::from_utf8_lossy(&bytes)),
                Err(_) => panic!("never saw {needle:?} in {:?}", self.seen),
            }
        }
    }

    fn exit_code(&mut self) -> Option<i32> {
        let start = Instant::now();
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status.code();
            }
            assert!(
                start.elapsed() < Duration::from_secs(30),
                "the client did not end: {:?}",
                self.seen
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

#[test]
fn on_a_terminal_the_user_is_asked_and_can_decline() {
    let host = host();
    let ssh = fake_ssh(FAKE_SSH);
    let dir = server_binary();
    let mut terminal = on_terminal(
        &host,
        &ssh,
        &host.session_words(&["--server-binary", dir.to_str().unwrap()]),
    );

    terminal.wait_for("Install it now? [Y/n]");
    terminal.typed.write_all(b"n").unwrap();

    assert_eq!(terminal.exit_code(), Some(1));
    assert!(!host.installed().exists());
}

#[test]
fn on_a_terminal_the_user_can_agree_and_the_session_starts() {
    let host = host();
    let ssh = fake_ssh(FAKE_SSH);
    let dir = server_binary();
    let mut terminal = on_terminal(
        &host,
        &ssh,
        &host.session_words(&["--server-binary", dir.to_str().unwrap()]),
    );

    terminal.wait_for("Install it now? [Y/n]");
    terminal.typed.write_all(b"y").unwrap();
    terminal.wait_for("installed ");
    terminal.typed.write_all(b"go\n").unwrap();
    terminal.wait_for("got:go");

    assert_eq!(terminal.exit_code(), Some(3));
    assert!(host.installed().exists());
}

// the default is yes: Enter alone installs, as the capital in `[Y/n]` says.
#[test]
fn on_a_terminal_enter_alone_installs() {
    let host = host();
    let ssh = fake_ssh(FAKE_SSH);
    let dir = server_binary();
    let mut terminal = on_terminal(
        &host,
        &ssh,
        &host.session_words(&["--server-binary", dir.to_str().unwrap()]),
    );

    terminal.wait_for("Install it now? [Y/n]");
    terminal.typed.write_all(b"y").unwrap();
    terminal.wait_for("installed ");
    terminal.typed.write_all(b"go\n").unwrap();
    terminal.wait_for("got:go");

    assert_eq!(terminal.exit_code(), Some(3));
    assert!(host.installed().exists());
}

// the prompt takes one key: n and Esc decline, and nothing is uploaded.
#[test]
fn n_and_escape_decline() {
    for answer in ["n", "\x1b"] {
        let host = host();
        let ssh = fake_ssh(FAKE_SSH);
        let dir = server_binary();
        let mut terminal = on_terminal(
            &host,
            &ssh,
            &host.session_words(&["--server-binary", dir.to_str().unwrap()]),
        );
        terminal.wait_for("[Y/n]");
        terminal.typed.write_all(answer.as_bytes()).unwrap();
        assert_eq!(terminal.exit_code(), Some(1), "{answer:?}");
        assert!(!host.installed().exists(), "{answer:?}");
    }
}

/// A stand-in for `ssh` that also does what the transports need: `-W host:port` and `-W PATH` join
/// stdin and stdout to a TCP connection or a unix socket, and `-G` prints a configuration. `extra` runs first, with `$1` as
/// the first argument, and may end the script.
fn transport_ssh(config: &str, extra: &str) -> PathBuf {
    let relay = "import os, socket, sys, threading\n\
if sys.argv[1].startswith('/'):\n    s = socket.socket(socket.AF_UNIX)\n    s.connect(sys.argv[1])\n\
else:\n    host, port = sys.argv[1].rsplit(':', 1)\n    s = socket.create_connection((host, int(port)))\n\
def up():\n    while True:\n        d = os.read(0, 65536)\n        if not d:\n            break\n        s.sendall(d)\n    s.shutdown(socket.SHUT_WR)\n\
threading.Thread(target=up, daemon=True).start()\n\
while True:\n    d = s.recv(65536)\n    if not d:\n        break\n    os.write(1, d)\n";
    let relay_path = fake_ssh("").with_file_name("relay.py");
    std::fs::write(&relay_path, relay).unwrap();
    fake_ssh(&format!(
        "#!/bin/sh\n\
forward=\n\
case \"$*\" in *-G*) printf '%s' '{config}'; exit 0;; esac\n\
for a in \"$@\"; do [ \"$a\" = -W ] && want=1; done\n\
while [ \"$1\" != \"--\" ]; do\n\
  if [ \"$1\" = -W ]; then shift; forward=\"$1\"; fi\n\
  shift\n\
done\n\
shift; shift\n\
{extra}\n\
if [ -n \"$forward\" ]; then exec python3 -I {} \"$forward\"; fi\n\
exec sh -c \"$*\"\n",
        relay_path.display()
    ))
}

const NO_UDP: [&str; 2] = ["--server-arg", "--no-udp"];
/// The server ends the first `ssh` after the connect line, so a stream needs its own login.
const NO_HOLD: [&str; 2] = ["--server-arg", "--no-hold"];

fn assert_session(output: &Output) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stdout.contains("got:xyz"),
        "stdout: {stdout:?} stderr: {stderr:?}"
    );
    assert_eq!(output.status.code(), Some(3), "stderr: {stderr:?}");
}

const ASK: [&str; 2] = ["-c", "read x; echo got:$x; exit 3"];

#[test]
fn verbose_output_goes_to_the_log_file_and_names_the_steps() {
    let ssh = transport_ssh("", "");
    let log = std::env::temp_dir().join(format!("ssj-e2e-log-{}", std::process::id()));
    let _ = std::fs::remove_file(&log);
    let output = run_client_with(
        &ssh,
        &ASK,
        "xyz\n",
        &[
            "-vvv",
            "--transport",
            "udp",
            "--log-file",
            log.to_str().unwrap(),
        ],
    );
    assert_session(&output);
    // nothing of the log is on the terminal.
    assert!(!String::from_utf8_lossy(&output.stderr).contains("[ssj "));
    let text = std::fs::read_to_string(&log).unwrap();
    for step in [
        "starting the server on",
        "the server runs: session",
        "transports in order: udp",
        "QUIC handshake done",
        "welcome: the server has 0 bytes",
        "started the session",
        "session running over udp",
        "-> input 4 bytes",
        "<- exit",
        "session ended",
    ] {
        assert!(text.contains(step), "{step}\n{text}");
    }
    // the content of the session is never logged.
    assert!(!text.contains("xyz"));
    let _ = std::fs::remove_file(&log);

    // without -v nothing is written.
    let quiet = run_client_with(&ssh, &ASK, "xyz\n", &["--transport", "udp"]);
    assert!(!String::from_utf8_lossy(&quiet.stderr).contains("[ssj "));
}

#[test]
fn the_ssh_channel_alone_carries_a_session() {
    let ssh = transport_ssh("", "");
    let output = run_client_with(
        &ssh,
        &ASK,
        "xyz\n",
        &["--transport", "stdio", "--server-arg", "--no-udp"],
    );
    assert_session(&output);
}

// shell startup files print text before the stream, and the client must find the start of it.
#[test]
fn text_printed_before_the_stream_is_skipped() {
    let ssh = transport_ssh(
        "",
        "case \"$*\" in *--stdio*) echo 'Welcome to the host'; echo 'SSJ CONNECT noise'; printf '\\033[2Jx';; esac",
    );
    let output = run_client_with(&ssh, &ASK, "xyz\n", &["--transport", "stdio"]);
    assert_session(&output);
}

#[test]
fn a_blocked_udp_port_falls_back_to_the_ssh_channel() {
    // nothing answers on this address (reserved for documentation)
    let ssh = transport_ssh("", "");
    let started = Instant::now();
    let output = run_client_with(&ssh, &ASK, "xyz\n", &["--udp-host", "192.0.2.1"]);
    assert_session(&output);
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "{:?}",
        started.elapsed()
    );
}

/// An `extra` for [`transport_ssh`] that notes the target of every use of `-W` in a file.
fn note_forwarding(marker: &Path) -> String {
    format!(
        "if [ -n \"$forward\" ]; then echo \"$forward\" >> {}; fi",
        marker.display()
    )
}

#[test]
fn udp_is_used_when_it_works_and_a_jump_host_leaves_it_out() {
    for (config, order) in [("", "udp, stdio"), ("proxyjump bastion\n", "stdio")] {
        let ssh = transport_ssh(config, "");
        let output = run_client_with(&ssh, &ASK, "xyz\n", &["-v"]);
        assert_session(&output);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(&format!("transports in order: {order}\n")),
            "config {config:?}: {stderr}"
        );
    }
}

// with UDP blocked, the first `ssh` that started the server carries the session: no second login.
#[test]
fn the_first_ssh_carries_the_session_when_udp_is_blocked() {
    let log = fake_ssh("").with_file_name("logins");
    let ssh = transport_ssh("", &format!("echo \"$*\" >> {}", log.display()));
    let output = run_client_with(&ssh, &ASK, "xyz\n", &NO_UDP);
    assert_session(&output);
    let logins = std::fs::read_to_string(&log).unwrap();
    assert_eq!(logins.lines().count(), 1, "{logins}");
}

// a server that does not keep the channel open is served by a second login, as before.
#[test]
fn a_server_that_ends_the_first_ssh_gets_a_second_login() {
    let log = fake_ssh("").with_file_name("logins");
    let ssh = transport_ssh("", &format!("echo \"$*\" >> {}", log.display()));
    let output = run_client_with(&ssh, &ASK, "xyz\n", &[NO_UDP, NO_HOLD].concat());
    assert_session(&output);
    let logins = std::fs::read_to_string(&log).unwrap();
    assert!(logins.lines().count() >= 2, "{logins}");
}

#[test]
fn a_chosen_transport_that_the_server_does_not_offer_is_an_error() {
    let ssh = transport_ssh("", "");
    let output = run_client_with(
        &ssh,
        &ASK,
        "",
        &["--transport", "udp", "--server-arg", "--no-udp"],
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stderr:?}");
    assert!(stderr.contains("no UDP port"), "{stderr:?}");
}

#[test]
fn the_port_of_the_destination_goes_to_ssh_and_not_into_the_host_name() {
    let log = fake_ssh("").with_file_name("args.log");
    let script = format!(
        "#!/bin/sh\necho \"$*\" >> {}\n{}",
        log.display(),
        &FAKE_SSH["#!/bin/sh\n".len()..]
    );
    let output = run_client_to(
        &fake_ssh(&script),
        &["-c", "exit 0"],
        "",
        &[],
        "ssh://tim@localhost:2222",
        Some("127.0.0.1"),
    );
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let logged = std::fs::read_to_string(&log).unwrap();
    for call in logged.lines() {
        let (options, target) = call.split_once(" -- ").unwrap();
        assert!(options.contains("-p 2222"), "{call}");
        assert!(target.starts_with("tim@localhost"), "{call}");
        assert!(!target.contains(":2222"), "{call}");
    }
}

// the destination may be a name from the `ssh` configuration that DNS does not know. UDP goes to
// the `HostName` that `ssh -G` reports.
#[test]
fn udp_goes_to_the_host_name_of_the_ssh_configuration() {
    let marker = fake_ssh("").with_file_name("forwarded");
    let ssh = transport_ssh("hostname 127.0.0.1\n", &note_forwarding(&marker));
    let output = run_client_to(&ssh, &ASK, "xyz\n", &[], "tim@no-such-alias.invalid", None);
    assert_session(&output);
    assert!(!marker.exists(), "UDP was not used");
}

#[test]
fn a_named_session_is_started_and_joined_again_by_its_name() {
    let runtime = short_dir();
    let ssh = fake_ssh(FAKE_SSH);
    let shell = [
        "--server-arg",
        "--shell",
        "--server-arg",
        "/bin/sh",
        "--server-arg",
        "--shell-arg",
        "--server-arg",
        "-c",
        "--server-arg",
        "--shell-arg",
        "--server-arg",
        "stty -echo; n=0; while read l; do n=$((n+1)); echo \"got:$l:$n\"; done",
    ];
    let mut words = vec!["connect", "--name", "work"];
    words.extend(shell);
    words.push("user@localhost");

    // the first call starts the session, the shell counts its lines.
    let first = ssj_typing(
        &runtime,
        &ssh,
        &words,
        &[("one\n", "got:one:1"), ("\x1c", "")],
    );
    assert!(
        text(&first.stdout).contains("got:one:1"),
        "{} / {}",
        text(&first.stdout),
        text(&first.stderr)
    );
    assert_eq!(first.status.code(), Some(0), "{}", text(&first.stderr));

    // the server notes the detach a moment after the client has gone
    wait_for_state(&runtime, &ssh, "detached");
    let listing = text(&ssj(&runtime, &ssh, &["list", "user@localhost"], "").stdout);
    assert!(
        listing.contains("detached") && listing.contains("work"),
        "{listing}"
    );

    // the same call finds the session and the counter goes on.
    let second = ssj_typing(
        &runtime,
        &ssh,
        &["connect", "--name", "work", "user@localhost"],
        &[("two\n", "got:two:2"), ("\x1c", "")],
    );
    assert!(
        text(&second.stdout).contains("got:two:2"),
        "{} / {}",
        text(&second.stdout),
        text(&second.stderr)
    );
    assert_eq!(second.status.code(), Some(0), "{}", text(&second.stderr));
    assert_eq!(
        text(&ssj(&runtime, &ssh, &["list", "user@localhost"], "").stdout)
            .lines()
            .filter(|l| l.contains("work"))
            .count(),
        1
    );

    // the name works for attach and kill as well.
    let third = ssj_typing(
        &runtime,
        &ssh,
        &["attach", "user@localhost", "work"],
        &[("three\n", "got:three:3"), ("\x1c", "")],
    );
    assert!(
        text(&third.stdout).contains("got:three:3"),
        "{}",
        text(&third.stderr)
    );
    let killed = ssj(&runtime, &ssh, &["kill", "user@localhost", "work"], "");
    assert!(killed.status.success(), "{}", text(&killed.stderr));
}

#[test]
fn auto_attach_joins_the_only_session_without_a_client() {
    let runtime = short_dir();
    let ssh = fake_ssh(FAKE_SSH);
    let shell = [
        "--server-arg",
        "--shell",
        "--server-arg",
        "/bin/sh",
        "--server-arg",
        "--shell-arg",
        "--server-arg",
        "-c",
        "--server-arg",
        "--shell-arg",
        "--server-arg",
        "stty -echo; n=0; while read l; do n=$((n+1)); echo \"got:$l:$n\"; done",
    ];
    let mut words = vec!["connect", "--auto-attach"];
    words.extend(shell);
    words.push("user@localhost");
    let first = ssj_typing(
        &runtime,
        &ssh,
        &words,
        &[("one\n", "got:one:1"), ("\x1c", "")],
    );
    assert!(
        text(&first.stdout).contains("got:one:1"),
        "{}",
        text(&first.stderr)
    );

    let second = ssj_typing(
        &runtime,
        &ssh,
        &["connect", "--auto-attach", "user@localhost"],
        &[("two\n", "got:two:2"), ("\x1c", "")],
    );
    assert!(
        text(&second.stdout).contains("got:two:2"),
        "{} / {}",
        text(&second.stdout),
        text(&second.stderr)
    );
    let killed = ssj(&runtime, &ssh, &["kill", "-f", "user@localhost"], "");
    assert!(killed.status.success(), "{}", text(&killed.stderr));
}

/// Types a command one key at a time on a terminal and returns everything the terminal received.
fn typed_on_a_terminal(local_echo: &str) -> String {
    use std::io::{Read, Write};
    use std::sync::mpsc;

    let ssh = fake_ssh(FAKE_SSH);
    let port = free_port();
    let (pty, pts) = pty_process::blocking::open().unwrap();
    pty.resize(pty_process::Size::new(24, 80)).unwrap();
    let mut child = pty_process::blocking::Command::new(env!("CARGO_BIN_EXE_ssj"))
        .env("XDG_CONFIG_HOME", no_config())
        .arg("connect")
        .args(["--ssh-command", ssh.to_str().unwrap()])
        .args(["--server-path", server_binary().to_str().unwrap()])
        .args(["--udp-host", "127.0.0.1", "--local-echo", local_echo])
        .args(["--port-range", &format!("{port}:{port}")])
        .args(["--detached-timeout", "5", "--server-arg", "--max-detached"])
        .args(["--server-arg", "30", "--server-arg", "--shell"])
        .args(["--server-arg", "/bin/sh", "--server-arg", "--shell-arg"])
        // `cat` on the terminal: the line discipline of the server echoes every key at once, the
        // same on every system, where an interactive shell draws its own line (and `ash` asks the
        // terminal for the cursor position, which local echo takes as a reason not to predict)
        .args(["--server-arg", "-c", "--server-arg", "--shell-arg"])
        .args(["--server-arg", "echo ready; cat", "me@localhost"])
        .spawn(pts)
        .unwrap();
    let fd: std::os::fd::OwnedFd = pty.into();
    let mut reader = std::fs::File::from(fd.try_clone().unwrap());
    let mut pty = std::fs::File::from(fd);
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok(n) = reader.read(&mut buf) {
            if n == 0 || tx.send(buf[..n].to_vec()).is_err() {
                break;
            }
        }
    });
    let mut seen = String::new();
    let wait_for = |seen: &mut String, needle: &str| {
        let deadline = Instant::now() + Duration::from_secs(20);
        while !needle.split('|').any(|n| seen.contains(n)) {
            let left = deadline.saturating_duration_since(Instant::now());
            match rx.recv_timeout(left) {
                Ok(bytes) => seen.push_str(&String::from_utf8_lossy(&bytes)),
                Err(_) => panic!("never saw {needle:?} in {seen:?}"),
            }
        }
    };
    wait_for(&mut seen, "ready");
    // the first key of a line is not predicted, the rest are.
    for line in ["abcdefgh\n", "ijklmnop\n"] {
        for byte in line.bytes() {
            pty.write_all(&[byte]).unwrap();
            std::thread::sleep(Duration::from_millis(40));
        }
    }
    // each line comes back twice: echoed key by key by the terminal, then printed whole by `cat`.
    wait_for(&mut seen, "\r\nijklmnop\r\n");
    pty.write_all(&[4]).unwrap();
    let start = Instant::now();
    while child.try_wait().unwrap().is_none() {
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "the client hangs"
        );
        while let Ok(bytes) = rx.try_recv() {
            seen.push_str(&String::from_utf8_lossy(&bytes));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    while let Ok(bytes) = rx.try_recv() {
        seen.push_str(&String::from_utf8_lossy(&bytes));
    }
    seen
}

#[test]
fn local_echo_shows_typed_characters_ahead_and_leaves_the_session_intact() {
    let on = typed_on_a_terminal("auto");
    // characters were drawn faint ahead of the server, and each was taken back.
    assert!(on.contains("\x1b[2m"), "{on:?}");
    assert!(on.contains("\x08\x1b[K"), "{on:?}");
    let off = typed_on_a_terminal("off");
    assert!(!off.contains("\x1b[2m"), "{off:?}");
}

// ---- `ssj edit` ----

/// An editor that runs `body` with the file as `$1`.
fn editor_script(body: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let dir = short_dir();
    let path = dir.join("editor");
    std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

/// Runs `ssj edit ...` with the editor and with `config` as the config directory.
fn ssj_edit(config: &Path, editor: &Path, words: &[&str], input: &str) -> Output {
    let ssh = fake_ssh(FAKE_SSH);
    let (word, rest) = words.split_first().expect("a command word");
    let mut command = Command::new(env!("CARGO_BIN_EXE_ssj"));
    command
        .env("XDG_CONFIG_HOME", config)
        .env("XDG_CACHE_HOME", config)
        .env("EDITOR", editor)
        .env_remove("VISUAL")
        .arg(word)
        .args(given(
            words,
            &[
                "--ssh-command",
                ssh.to_str().unwrap(),
                "--server-path",
                server_binary().to_str().unwrap(),
            ],
        ))
        .args(rest);
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn_locked()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn edit_without_a_host_changes_client_toml_and_saves_it_privately() {
    use std::os::unix::fs::PermissionsExt;
    let config = short_dir();
    let editor = editor_script(r#"echo 'compress = "auto"' >> "$1""#);
    let output = ssj_edit(&config, &editor, &["edit"], "");
    assert!(output.status.success(), "{}", text(&output.stderr));
    assert!(
        text(&output.stdout).contains("saved"),
        "{}",
        text(&output.stdout)
    );
    let file = config.join("ssj/client.toml");
    let saved = std::fs::read_to_string(&file).unwrap();
    // the template of a new file is kept, and the edit is at the end.
    assert!(saved.contains("#auto_install"), "{saved}");
    assert!(saved.ends_with("compress = \"auto\"\n"), "{saved}");
    assert_eq!(
        std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(
        ssj_client::config::Config::from_text(&saved)
            .unwrap()
            .compress
            == Some(ssj_net::Compress::Auto)
    );

    // a second edit starts from the file.
    let again =
        editor_script(r#"grep -q 'compress = "auto"' "$1" && echo 'local_echo = "auto"' >> "$1""#);
    let output = ssj_edit(&config, &again, &["edit"], "");
    assert!(output.status.success(), "{}", text(&output.stderr));
    assert!(
        std::fs::read_to_string(&file)
            .unwrap()
            .contains("local_echo")
    );
}

#[test]
fn an_edit_that_changes_nothing_is_not_saved() {
    let config = short_dir();
    let editor = editor_script("true");
    let output = ssj_edit(&config, &editor, &["edit"], "");
    assert!(output.status.success(), "{}", text(&output.stderr));
    assert!(text(&output.stdout).contains("no changes"));
    assert!(!config.join("ssj/client.toml").exists());
}

#[test]
fn an_invalid_file_is_refused_before_it_is_saved_and_can_be_discarded() {
    let config = short_dir();
    let editor = editor_script(r#"echo 'compres = "auto"' >> "$1""#);
    let output = ssj_edit(&config, &editor, &["edit"], "n\n");
    assert!(output.status.success(), "{}", text(&output.stderr));
    assert!(
        text(&output.stderr).contains("not valid") && text(&output.stderr).contains("compres"),
        "{}",
        text(&output.stderr)
    );
    assert!(text(&output.stdout).contains("no changes"));
    assert!(!config.join("ssj/client.toml").exists());
}

#[test]
fn an_invalid_file_can_be_edited_again_and_then_saved() {
    let config = short_dir();
    let marker = config.join("second-run");
    // the first run writes a typo, the second one fixes it.
    let editor = editor_script(&format!(
        r#"if [ -e '{m}' ]; then sed 's/compres /compress /' "$1" > "$1.new" && mv "$1.new" "$1"; else touch '{m}'; echo 'compres = "auto"' >> "$1"; fi"#,
        m = marker.display()
    ));
    let output = ssj_edit(&config, &editor, &["edit"], "y\n");
    assert!(output.status.success(), "{}", text(&output.stderr));
    assert!(text(&output.stderr).contains("not valid"));
    let saved = std::fs::read_to_string(config.join("ssj/client.toml")).unwrap();
    assert!(saved.contains("compress = \"auto\""), "{saved}");
}

#[test]
fn edit_with_a_host_changes_server_toml_there_after_the_server_has_checked_it() {
    use std::os::unix::fs::PermissionsExt;
    let config = short_dir();
    let editor = editor_script(r#"echo 'live_backlog = 300000' >> "$1""#);
    let output = ssj_edit(&config, &editor, &["edit", "user@localhost"], "");
    assert!(output.status.success(), "{}", text(&output.stderr));
    assert!(
        text(&output.stdout).contains("saved server.toml"),
        "{}",
        text(&output.stdout)
    );
    let file = config.join("ssj/server.toml");
    let saved = std::fs::read_to_string(&file).unwrap();
    assert!(
        saved.contains("#port_range") && saved.ends_with("live_backlog = 300000\n"),
        "{saved}"
    );
    assert_eq!(
        std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
        0o600
    );
    // no client.toml was made, and no temporary file stays behind.
    assert!(!config.join("ssj/client.toml").exists());
    let names: Vec<String> = std::fs::read_dir(config.join("ssj"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, ["server.toml"]);

    // a key that only the client knows is refused by the server, and the file stays as it was.
    let bad = editor_script(r#"echo 'transport = "tcp"' >> "$1""#);
    let output = ssj_edit(&config, &bad, &["edit", "user@localhost"], "n\n");
    assert!(
        text(&output.stderr).contains("unknown field"),
        "{}",
        text(&output.stderr)
    );
    assert_eq!(std::fs::read_to_string(&file).unwrap(), saved);
}

#[test]
fn edit_is_the_editor_command_only_alone_or_before_a_host() {
    // `ssj edit a b` has one word too many.
    let config = short_dir();
    let editor = editor_script("true");
    let output = ssj_edit(&config, &editor, &["edit", "a", "b"], "");
    assert!(!output.status.success());
}

/// The lines of a template with the comment sign taken off the settings.
fn uncommented(template: &str) -> String {
    template
        .lines()
        .filter_map(|line| line.strip_prefix('#'))
        .filter(|line| !line.starts_with(' ') && line.split_once(" = ").is_some())
        .map(|line| format!("{line}\n"))
        .collect()
}

#[test]
fn the_templates_of_the_two_files_hold_valid_settings_only() {
    use ssj_client::config::Config;
    let client_template = Config::template();
    let server_template = ssj_server::config::Config::template();
    // as they are, both are empty files.
    assert!(Config::from_text(&client_template).is_ok());
    // with every setting switched on, the client and the server accept every line.
    let client = uncommented(&client_template);
    assert!(client.lines().count() >= 8, "{client}");
    Config::from_text(&client).unwrap();
    let server = uncommented(&server_template);
    assert!(server.lines().count() >= 10, "{server}");
    for text in [server_template.as_str(), server.as_str()] {
        let mut child = Command::new(server_binary())
            .arg("--check-config")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn_locked()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(text.as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success(), "{}", text_of(&output.stderr));
    }
}

fn text_of(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[test]
fn a_file_that_changed_while_it_was_edited_is_not_overwritten_and_the_text_is_kept() {
    let config = short_dir();
    let dir = config.join("ssj");
    std::fs::create_dir_all(&dir).unwrap();
    for (name, words, other_edit) in [
        ("client.toml", vec!["edit"], r#"compress = "auto""#),
        (
            "server.toml",
            vec!["edit", "user@localhost"],
            "away_after = 5",
        ),
    ] {
        let file = dir.join(name);
        std::fs::write(&file, "").unwrap();
        // the file exists and is empty; another editor saves while this one is open.
        let editor = editor_script(&format!(
            "echo '{other_edit}' >> '{}'\nsleep 0.2\necho '# my change' >> \"$1\"",
            file.display()
        ));
        let output = ssj_edit(&config, &editor, &words, "");
        let message = text(&output.stderr);
        assert!(!output.status.success(), "{name}: {message}");
        assert!(
            message.contains("changed while you were editing"),
            "{name}: {message}"
        );
        // the file keeps what the other editor wrote.
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            format!("{other_edit}\n"),
            "{name}"
        );
        // and the text of this editor is in the file whose name is shown.
        let kept = message
            .split_whitespace()
            .find(|word| word.contains("ssj-edit-kept-"))
            .unwrap_or_else(|| panic!("{name}: no copy named in {message}"))
            .trim_end_matches(';')
            .trim_end_matches('.');
        let copy = std::fs::read_to_string(kept).unwrap();
        assert!(copy.contains("# my change"), "{name}: {copy}");
        let _ = std::fs::remove_file(kept);
        // no lock or temporary file stays behind.
        let names: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n != "client.toml" && n != "server.toml" && n != ".client.toml.lock")
            .collect();
        assert!(names.is_empty(), "{name}: {names:?}");
        std::fs::remove_file(&file).unwrap();
    }
}

#[test]
fn a_lock_that_is_held_on_the_host_stops_the_save_and_is_named() {
    let config = short_dir();
    let lock = config.join("ssj/.server.toml.lock");
    std::fs::create_dir_all(&lock).unwrap();
    let editor = editor_script(r#"echo 'away_after = 5' >> "$1""#);
    let output = ssj_edit(&config, &editor, &["edit", "user@localhost"], "");
    assert!(!output.status.success());
    let message = text(&output.stderr);
    assert!(
        message.contains("holds") && message.contains(".server.toml.lock"),
        "{message}"
    );
    assert!(!config.join("ssj/server.toml").exists());
    // the lock of somebody else is left alone.
    assert!(lock.is_dir());
}

/// A detached session on the host of the test, made as after the detach key.
fn detached_session(host: &Host, ssh: &Path) {
    let output = ssj_typing(
        &host.runtime,
        ssh,
        &["connect", "--detach-key", "ctrl-]", "user@localhost"],
        &[("x\x1d", "")],
    );
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    // the server notes the detach a moment after the client has gone
    wait_for_state(&host.runtime, ssh, "detached");
}

fn sessions_listed(host: &Host, ssh: &Path) -> usize {
    text(&ssj(&host.runtime, ssh, &["list", "user@localhost"], "").stdout)
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with("no sessions"))
        .count()
}

fn wait_for_sessions(host: &Host, ssh: &Path, wanted: usize) {
    let start = Instant::now();
    while sessions_listed(host, ssh) != wanted {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "the host has {} sessions, not {wanted}",
            sessions_listed(host, ssh)
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn kill_words(host: &Host, extra: &[&str]) -> Vec<String> {
    let mut words = vec![
        extra[0].to_owned(),
        "--server-path".to_owned(),
        server_binary().to_str().unwrap().to_owned(),
    ];
    words.extend(extra[1..].iter().map(|w| (*w).to_owned()));
    let _ = host;
    words
}

#[test]
fn kill_without_an_id_asks_before_it_ends_the_only_session() {
    let host = host();
    let ssh = fake_ssh(FAKE_SSH);
    detached_session(&host, &ssh);
    assert_eq!(sessions_listed(&host, &ssh), 1);

    // no is the answer of n, no, and any other word, and Enter is yes
    for answer in [b"n\n".as_slice(), b"no\n", b"nope\n"] {
        let mut terminal =
            on_terminal(&host, &ssh, &kill_words(&host, &["kill", "user@localhost"]));
        terminal.wait_for("End the session ");
        terminal.wait_for("[Y/n]");
        terminal.typed.write_all(answer).unwrap();
        assert_eq!(terminal.exit_code(), Some(1), "{answer:?}");
        assert_eq!(sessions_listed(&host, &ssh), 1, "{answer:?}");
    }

    let mut terminal = on_terminal(&host, &ssh, &kill_words(&host, &["kill", "user@localhost"]));
    terminal.wait_for("[Y/n]");
    terminal.typed.write_all(b"\n").unwrap();
    assert_eq!(terminal.exit_code(), Some(0));
    wait_for_sessions(&host, &ssh, 0);
}

#[test]
fn kill_with_f_does_not_ask() {
    let host = host();
    let ssh = fake_ssh(FAKE_SSH);
    detached_session(&host, &ssh);
    let mut terminal = on_terminal(
        &host,
        &ssh,
        &kill_words(&host, &["kill", "-f", "user@localhost"]),
    );
    assert_eq!(terminal.exit_code(), Some(0));
    assert!(!terminal.seen.contains("[Y/n]"), "{:?}", terminal.seen);
    wait_for_sessions(&host, &ssh, 0);
}

#[test]
fn kill_without_an_id_and_without_a_terminal_needs_f() {
    let host = host();
    let ssh = fake_ssh(FAKE_SSH);
    detached_session(&host, &ssh);

    let refused = ssj(&host.runtime, &ssh, &["kill", "user@localhost"], "");
    assert_eq!(refused.status.code(), Some(1));
    assert!(
        text(&refused.stderr).contains("no terminal to ask")
            && text(&refused.stderr).contains("-f"),
        "{}",
        text(&refused.stderr)
    );
    assert_eq!(sessions_listed(&host, &ssh), 1);

    let forced = ssj(&host.runtime, &ssh, &["kill", "-f", "user@localhost"], "");
    assert_eq!(forced.status.code(), Some(0), "{}", text(&forced.stderr));
    wait_for_sessions(&host, &ssh, 0);
}

#[test]
fn a_command_word_with_help_shows_its_own_help() {
    for word in [
        "connect", "list", "attach", "kill", "detach", "install", "edit",
    ] {
        for flag in ["--help", "-h"] {
            let output = Command::new(env!("CARGO_BIN_EXE_ssj"))
                .args([word, flag])
                .output()
                .unwrap();
            let shown = text(&output.stdout);
            assert_eq!(output.status.code(), Some(0), "{word} {flag}");
            assert!(shown.contains(&format!("Usage: ssj {word}")), "{shown}");
        }
    }
    assert!(
        text(
            &Command::new(env!("CARGO_BIN_EXE_ssj"))
                .args(["kill", "--help"])
                .output()
                .unwrap()
                .stdout
        )
        .contains("--force")
    );
}

/// A stand-in for `ssh` that is also found under the name `ssh` (the relay runs that name), and
/// that says a jump host stands in front of every destination but the jump host itself.
const JUMP_SSH: &str = "#!/bin/sh
for a in \"$@\"; do
  if [ \"$a\" = \"-G\" ]; then
    for dest in \"$@\"; do :; done
    echo \"hostname 127.0.0.1\"
    echo \"user tim\"
    echo \"port 22\"
    if [ \"$dest\" != \"jumphost\" ]; then echo \"proxyjump jumphost\"; fi
    exit 0
  fi
done
while [ \"$1\" != \"--\" ]; do shift; done
shift
shift
exec sh -c \"$*\"
";

/// Runs `ssj connect target -- <command>` behind the jump host of [`JUMP_SSH`], with the relay
/// setting `relay`.
fn run_behind_jump(relay: &str, command: &str) -> Output {
    let dir = fake_ssh("").with_file_name(format!("jump-{}", rand_suffix()));
    std::fs::create_dir_all(&dir).unwrap();
    let ssh = dir.join("ssh");
    std::fs::write(&ssh, JUMP_SSH).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&ssh, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let port = free_port();
    let path = format!(
        "{}:{}",
        dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let child = Command::new(env!("CARGO_BIN_EXE_ssj"))
        .env("XDG_CONFIG_HOME", no_config())
        .env("PATH", path)
        .arg("connect")
        .args(["--ssh-command", ssh.to_str().unwrap()])
        .args(["--server-path", server_binary().to_str().unwrap()])
        .args(["--port-range", &format!("{port}:{}", port + 10)])
        .args(["--relay", relay, "-vv"])
        .args(LEAK_GUARD)
        .args(["--server-arg", "--shell", "--server-arg", "/bin/sh"])
        .args(["target", "--", command])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn_locked()
        .unwrap();
    let started = Instant::now();
    let pid = child.id();
    std::thread::scope(|scope| {
        let waiting = scope.spawn(move || child.wait_with_output().unwrap());
        while !waiting.is_finished() {
            assert!(
                started.elapsed() < Duration::from_secs(60),
                "the client did not finish (pid {pid})"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        waiting.join().unwrap()
    })
}

#[test]
fn a_destination_behind_a_jump_host_is_reached_over_udp_through_the_relay() {
    let output = run_behind_jump("first", "echo through-the-relay; exit 5");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stdout.contains("through-the-relay"),
        "{stdout:?} {stderr:?}"
    );
    assert_eq!(output.status.code(), Some(5), "{stdout:?} {stderr:?}");
    assert!(
        stderr.contains("transports in order: relay, stdio"),
        "{stderr}"
    );
    assert!(stderr.contains("connecting over relay"), "{stderr}");
    assert!(
        !stderr.contains("next transport"),
        "the relay must carry the session: {stderr}"
    );
}

#[test]
fn without_the_relay_setting_a_jump_host_leaves_the_ssh_channel() {
    let output = run_behind_jump("none", "echo plain; exit 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stdout.contains("plain"), "{stdout:?} {stderr:?}");
    assert!(stderr.contains("transports in order: stdio"), "{stderr}");
}
