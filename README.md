# ssj

Session survives jumps: a remote shell for flaky networks.

- The session survives roaming, IP changes, sleep, and packet loss.
- The native scrollback of the local terminal keeps working.
- The server runs without root and without a daemon.
- Transport: QUIC over UDP, with a fallback to the `ssh` channel itself.

See `SPEC.md` for the design and the threat model.

## Prerequisites

- `ssh` access to the host. It is used for the bootstrap and for the install, so no root, no
  daemon, and no open port are needed.
- macOS (arm64) or Linux (x86_64 or arm64) on both sides.
- To build from source: a Rust toolchain (edition 2024).

## Installation

### The client

Download the archive for your system from the
[releases](https://github.com/zshsetup/ssj/releases) page, check it against `SHA256SUMS`, and
unpack it:

```shell
curl -LO https://github.com/zshsetup/ssj/releases/latest/download/ssj-VERSION-TARGET.tar.gz
tar xzf ssj-VERSION-TARGET.tar.gz
```

| `TARGET` | System |
| ----------------------------- | -------------------------------- |
| `aarch64-apple-darwin` | macOS on Apple silicon |
| `x86_64-unknown-linux-musl` | Linux x86_64, static (any distro) |
| `aarch64-unknown-linux-musl` | Linux arm64, static (any distro) |
| `x86_64-unknown-linux-gnu` | Linux x86_64, glibc |
| `aarch64-unknown-linux-gnu` | Linux arm64, glibc |

What is in the archive and where each file goes:

```text
ssj-VERSION-TARGET/
├── ssj                        # the client: a directory on your PATH, e.g. ~/.local/bin/
├── ssj.1                      # man page: a man1 directory, e.g. ~/.local/share/man/man1/
├── completions/
│   ├── ssj.bash               # Bash: `source` it from ~/.bashrc
│   ├── _ssj                   # Zsh: a directory in your fpath
│   └── ssj.fish               # Fish: ~/.config/fish/completions/
├── SHA256SUMS                 # checksum of `ssj`
├── README.md
└── LICENSE
```

Session ids and names are completed from a list that `ssj list` keeps in
`$XDG_CACHE_HOME/ssj/sessions/`. It is refreshed in the background without prompts, and a
session that was never listed on a host is not offered.

To build from source instead:

```shell
cargo install --path crates/ssj-client
cargo install --path crates/ssj-server
```

`cargo run -p ssj-assets -- DIR` writes the man page and the completions of a source build to
`DIR`, in the layout of the release archive.

### The server on the host

```shell
ssj install user@host
```

The server file lands on the host here:

```text
~/.local/share/ssj/bin/
└── ssj-server-p1              # `p1` is the protocol version; other versions sit side by side
```

Running it again upgrades a host: it replaces the file of the same protocol with the one of your
client's version and says which version it replaced. Sessions that run keep their old process
until they end, and new ones use the new file. `--install` only fills in a missing file and never
replaces one.

Where `ssj install` takes the file from:

- By default, a download of the file for the host from the release of the same version, over
  HTTPS. `--download-url` names another place.
- With `--server-binary FILE`, exactly that file, with no download. Take it from the release
  assets (`ssj-server-<TARGET>`) when the client cannot reach GitHub.

Which build the host gets: `ssj` asks the host for its system and libc. Linux with glibc 2.17 or
newer gets the `gnu` build, and any other Linux (musl, such as Alpine, or an older glibc) the
static `musl` build. macOS has one build.

Safety of the transfer:

- The download is checked against `SHA256SUMS`.
- The upload is checked with SHA-256 on the host, tested by running it, and only then moved into
  place, so a broken transfer never replaces a working server.

### Installing on first use

When the server is missing, `ssj connect user@host` offers to install it, as set by `auto_install` in
`$XDG_CONFIG_HOME/ssj/client.toml`:

| `auto_install` | Behavior |
| -------------- | ------------------------------------------------------------------------ |
| `ask` (default) | On a terminal you are asked `[Y/n]`: Enter or `y` installs, and any other key does not. Without a terminal nothing is installed, and the message tells you what to do. |
| `always` | Installs without asking. |
| `never` | Never installs. |

- `--install` and `--no-install` override the setting for one run.
- `ssj attach`, `ssj list`, `ssj kill`, and `ssj detach` never install anything.

## Usage

### Commands

| Command | What it does |
| ---------------------------------------- | ---------------------------------------------------------------- |
| `ssj connect user@host` | Starts a session. |
| `ssj connect --name work user@host` | Joins the session `work`, or starts it. |
| `ssj attach user@host [ID]` | Joins a running session, for example after a restart. `ID` is an id or a name. |
| `ssj list user@host` | Lists sessions with state, age, and name, under a header on a terminal. `--json` prints JSON. |
| `ssj kill [-f] user@host [ID...]` | Ends one or more sessions. `ID` is an id or a name. Without an `ID` the only session is ended after a question (`-f` skips it), and several sessions get a menu. |
| `ssj detach user@host [ID...]` | Makes the clients leave; the sessions keep running. |
| `ssj connect user@host make -j8` | Runs a command in a session that survives jumps (see below). Every word after the host belongs to the command, options included, as with `ssh`; `--` before the command is accepted but not needed. |
| `ssj install user@host` | Puts the server file on the host (downloads it, or uploads `--server-binary`). |
| `ssj edit` | Edits `client.toml` in `$EDITOR`. |
| `ssj edit user@host` | Edits `server.toml` on the host in `$EDITOR`. |

### Options

The options of a command follow its word: `ssj connect -A user@host`, `ssj list user@host --json`.

| Option | What it does |
| ---------------------------------------- | ---------------------------------------------------------------- |
| `user@host:2222`, `ssh://user@host:2222` | Port of the ssh server. |
| `--transport auto\|udp\|stdio` | `auto` is the default; `stdio` is the `ssh` channel. |
| `--relay none\|auto\|first` | UDP to the first jump host, which passes it on over `ssh`; `none` is the default. |
| `--ssh-command 'ssh -J jump'` | Replaces `ssh`. |
| `--server-path ~/bin/ssj-server` | Server file on the host, when it is not in the default place. |
| `--udp-host 203.0.113.7` | UDP address, when it differs from the host name. |
| `--port-range 62000:62100` | UDP ports the server may use. |
| `--install`, `--no-install` | Install the missing server, or never. |
| `--auto-attach` | Join the only session without a client, or choose from a menu. |
| `-A` | Agent forwarding. |
| `--local-echo auto`, `--compress auto` | See "Local echo" and "Compression". |
| `-v`, `-vv`, `-vvv`, `--log-file FILE` | Debug output. |
| `-q`, `--quiet` | No lines about connecting, disconnecting, and detaching. |

Run `ssj connect --help` (or the help of another command) or `man ssj` for the full list.

## Sessions

### Ending and leaving

Without the message of the day of a login, nothing else says when a session begins. On a terminal
`ssj` prints `[started session work (ID) on user@host over udp]` first (`attached to session` when
the session ran already; the name is left out when the session has none), `[disconnected from user@host]`
when the shell ends, and `[detached from session; it keeps running: ssj attach user@host]` when you
leave on purpose. `-q` turns these lines off.

Ending a session stops the shell. Leaving it keeps the shell running.

| Action | Effect |
| ------------------------------------------- | ------------------------------------------------------------------- |
| `exit`, Ctrl-D on an empty line | Ends the session. `ssj` exits with the shell code. |
| `ssj kill [-f] user@host [ID...]` | Ends the sessions from another terminal. |
| The detach key (`ctrl-\` by default), anywhere | Detaches on purpose, also in the middle of a line or a program. The shell keeps running. |
| `ssj detach user@host [ID...]` | The same, from another terminal, for the clients of those sessions. |
| Closing the terminal, `SIGHUP`, `SIGTERM` | Ends the session, as with `ssh`. `ssj` exits with 129. Inside an `ssh` session it detaches instead. |
| `kill -9` of `ssj`, a lost connection | Leaves it. The shell keeps running. |

### The detach key

`ctrl-\` detaches from anywhere: at a prompt, in the middle of a line, and inside a full-screen
program. The program does not receive the key.

- Set another with `--detach-key ctrl-]`, or `detach_key = "ctrl-]"` in `client.toml`.
- Allowed keys: `ctrl-A` to `ctrl-Z`, `ctrl-\`, `ctrl-]`, `ctrl-^`, `ctrl-_`, or `none`, which
  turns it off. Tab and Enter are refused.
- From another terminal, `ssj detach user@host [ID...]` makes the connected clients leave and
  prints that it did. The shell keeps running, and `ssj attach` brings you back.

### Inside an `ssh` session

When the connection of an `ssh` session ends, the terminal of `ssj` is closed.

- Inside an `ssh` session (`SSH_TTY` is set) this leaves the session running, since the end of
  the connection is more likely a loss than a wish. The next `ssj attach` brings you back.

### Choosing a session

When you leave out the id and several sessions fit, `ssj` asks on a terminal instead of guessing
or failing.

- `ssj attach`, `ssj kill`, and `ssj detach` show the sessions of the host (youngest first) as a
  menu.
- `ssj connect --auto-attach` shows those without a client, with a last line that starts a new one.
- Keys: arrow keys or `j` and `k`, Enter to choose, `q` or Esc to cancel. Ctrl-C ends `ssj`.
- Without a terminal nothing is asked: `--auto-attach` starts a session as before, and the other
  commands name the sessions in their error.
- `ssj kill` without an id asks `End the session ...? [Y/n]` when only one session runs (Enter is yes,
  and `-f` does not ask). With several sessions the menu is the question. Without a terminal and
  without `-f` it refuses to end a session that you did not name.
- An id or a name is exact. A session has one name, and `--name` joins the session of that name
  instead of making another, but a name can be the id of a different session. A selector that fits
  two sessions is never guessed: a terminal gets the menu of the two, and a script gets an error
  that names both ids.

Joining a session with `ssj attach` redraws the screen of the program in it, since the new client
has no history: the shell shows its prompt again, and a full-screen program draws itself.

### Timeouts and detached sessions

| Situation | What happens |
| ------------------------------------------- | ---------------------------------------------------------------- |
| `exit`, Ctrl+D, closed window, `kill ssj` | The session and its shell end, as with `ssh`. |
| The detach key | The shell runs until you attach again or end it with `ssj kill`. There is no timeout. The server closes its UDP port, so a detached session listens on nothing; attaching goes through `ssh` and opens a new port. |
| Lost connection (network change, sleeping laptop, `SIGKILL`) | The server waits for the client and ends the session after `detached_timeout` (off by default, in `server.toml`). |

- `ssj list user@host` shows every session with its state and age.
- `max_detached` in `server.toml` sets an upper limit that also applies to deliberate detaches.

### Running a command

`ssj connect user@host COMMAND...` runs the command in the session instead of the shell, as
`ssh user@host COMMAND` does, and ends with its exit code.

- The login shell of the host runs it (`$SHELL -l -c 'COMMAND'`), so pipes, `&&`, and `cd` work.
- A long `make` or a `tail -f` survives a network change or a closed laptop like any other
  session. You can join it from another terminal (it has a name in `ssj list`).
- As with `ssh`, everything after the host belongs to the command, options included:
  `ssj connect host ls -l`, `ssj connect host make -j4`. Options of `ssj` go before the host
  (`ssj connect --local-echo auto host make -j4`). A `--` after the host is optional.
- The other commands (`list`, `attach`, `kill`, `detach`, `install`, `edit`) take their options
  before or after the host: `ssj list host --json`. A command takes only the options that it
  reads (`ssj kill --help`, and the man page lists them); a setting for every connection, such as
  `--send-env`, belongs in `client.toml` (`ssj edit`).
- The command has a terminal, as with `ssh -t`: its output has carriage returns, and a program
  can ask for the terminal size. Standard input goes to it as typed.
- `--name` and `--auto-attach` are refused with a command, since a session that runs already
  would not run it.
- Every line starts with a command, so a host may have any name: `ssj connect list` connects to
  the host `list`.

## Connection

### Connection problems

| Event | What you see |
| ----------------------------- | --------------------------------------------------------------- |
| The server stops answering | The window title shows `no response from the server` after a short time that depends on the speed of the link. |
| The connection is lost | The title shows `connection lost, reconnecting`. The session keeps running, and what you type meanwhile is sent when the connection is back. The detach key works even without a connection. |

- On the `ssh` channel transport, a connection that is slow to answer (3 seconds without an
  answer to a ping or to what you typed) gets spares: `ssj` opens new connections beside it, up to
  six at once, and moves to the first that works. On a train this brings the session back in a
  few seconds, where `ssh` can need half a minute. The server must be installed from the same
  release (`ssj install`).
- `ssj` notices when the network changes or the machine wakes from sleep (through the network
  state of macOS or netlink on Linux, and a clock check everywhere) and moves to the new path at
  once instead of waiting for a timeout.
- The message is written to the window title, so it never draws over the program in the
  terminal. If the output stops in the middle of an escape sequence, the message waits. When the
  sequence is still open after two seconds, `ssj` cancels it on the terminal and drops the rest
  of it when it arrives, so no half sequence appears as text.

### Blocked UDP and jump hosts

`ssj` tries UDP first. When UDP is blocked, or `ssh` goes through a jump host, it falls back:

| Order | Transport | How |
| ----- | --------- | ---------------------------- |
| 1 | `udp` | QUIC over UDP. |
| 2 | `stdio` | The `ssh` channel itself, for hosts that forward nothing. |

- The first `stdio` connection reuses the `ssh` that started the server. The ones after it start
  a new `ssh` and cannot ask for a passphrase, so use an agent or a shared connection
  (`ControlMaster auto`, `ControlPersist 10m` in your `ssh` configuration).
- `socket` and `tcp` of earlier versions are gone: `stdio` was as fast on a test host, and
  `transport = "socket"` or `"tcp"` in `client.toml` is now an error. Use `"stdio"` or `"auto"`.
- Choose a transport with `--transport` or `transport` in `client.toml`. See the specification
  for the details.

#### UDP through a jump host

When a host is behind a jump host (`ProxyJump`), the stretch that breaks is usually the one from
your laptop to the first jump host. With `relay`, `ssj` speaks UDP over that stretch and the jump
host passes the packets on over `ssh`:

```toml
relay = "auto"      # "none" (the default), "auto", or "first"
```

- `auto` uses the relay when the first jump host has `ssj-server`, and does nothing otherwise.
  `first` offers to install the server there (like `auto_install`), and says when it is not used.
  `--relay` sets it for one connection.
- The jump host forwards packets and cannot read them: the session keeps its end-to-end
  certificates, and the pin still comes through the `ssh` to the destination.
- The login from the jump host to the destination uses the keys of the jump host, or your agent
  if `ForwardAgent` is on for it. It never asks, so log in once from the jump host to accept the
  host key.
- If the relay does not come up, the session runs over the `ssh` channel, as before.

### Congestion control

`congestion = "auto"` is the default. `ssj` sends like CUBIC, which is fastest on a clean link
(wired, a LAN, the loopback), and moves to BBR when packets are lost although no queue has built
up in front of the loss, as on Wi-Fi, mobile, and long paths with random loss.

- There CUBIC slows down at every loss (0.3 MB/s at 80 ms and 1 % loss against 7 MB/s with BBR).
- After 30 seconds without loss it goes back.
- `congestion = "bbr"` or `"cubic"` (or `--congestion`) forces one of them.
- The client passes its choice to the server it starts, and each side sends with its own.

### A slow connection

With `ssh`, a slow link slows the job down: the shell waits in `write` until the link has taken
its output, and after Ctrl-C the output that is already queued still has to arrive.

| `slow_client` | Behavior |
| ------------- | --------------------------------------------------------------------------------- |
| `drop` (default) | The job always runs at full speed. The server keeps at most `live_backlog` bytes (1 MiB) of output that the connected client has not taken yet. When the link is slower than the job, the oldest of the rest is skipped, the terminal shows `[ssj: N bytes of output were dropped]`, and Ctrl-C stops the output within that backlog. What the shell wrote before you connected (the replay after `attach` or a reconnect) is not skipped. |
| `wait` | The job waits for the client, as with `ssh`, and nothing is lost while you are connected. `away_after` only applies to this setting. |

Set it in `server.toml`, or with `--slow-client wait`.

### Jobs while you are away

A job keeps running while no client is connected.

- The server keeps the newest `replay_capacity` bytes of its output (4 MiB by default).
- If the job writes more while you are away, the oldest output is forgotten, and when you come
  back the terminal shows `[ssj: N bytes of output were dropped]` with the exact number.
- Set a higher `replay_capacity` to keep more.

## Features

### Agent forwarding

`ssj connect -A host` (or `forward_agent = true` in `client.toml`) lets programs on the host, such as
`git` or a second `ssh`, use the ssh agent of your machine.

- The host never gets the keys, but anybody who can use the `SSH_AUTH_SOCK` of the shell there can
  have the agent sign while you are connected. Use it only on hosts you trust.
- Only listing the keys and signing are passed on. Adding, removing, and locking keys, and keys
  with destination constraints, do not work.

### Local echo

On a slow link a typed character shows only after the server has echoed it. With
`--local-echo auto` (or `local_echo = "auto"` in `client.toml`) `ssj` shows it at once, dimmed,
and the real echo replaces it. It is off by default, because it is a guess.

| It predicts | It stops or shows nothing |
| -------------------------------------------------------------- | ------------------------------------------------------------------- |
| Printable ASCII and letters of one column (umlauts, ß, accented Latin letters, Greek, Cyrillic) at the end of a plain shell line. | Arrow keys, control keys, backspace, and wide characters (Chinese, Japanese, Korean, emoji), until the next Enter. |
| | After Enter, until the server has echoed one typed character, so a password prompt is never shown. |
| | A full-screen program or a cursor movement in the output. |
| | A shell that redraws the whole line for every key (some zsh setups). |

- If the shell on the host is not set to UTF-8 and echoes a letter differently, the prediction is
  taken back and stops, as for any echo that differs.
- It takes its drawing back before it shows any output, and after two seconds without an echo.
- The client has no copy of the screen, so it keeps three columns free at the right edge, where
  a wrap would scroll the screen. A prompt with wide characters can make its estimate of the
  column wrong, and then a prediction near the edge can leave a stray dimmed character until the
  shell redraws the line.

### Compression

`compress = "auto"` (in `client.toml` or `server.toml`, or `--compress auto`) compresses input and
output (zstd) while the link is the limit.

- A build log or a pasted text shrinks to a fifth or less.
- Typing is never compressed, and each frame is compressed alone.
- It is off by default: compressing text of an attacker together with a secret can leak the
  secret through the size of the data, as with `ssh -C`. See the specification before turning it
  on for a shell where you paste secrets or print them next to text from others.

### Debug output

`ssj connect -v host` tells the steps, as `ssh -v` does, each with the time since the start.

| Level | What it shows |
| ------ | ------------------------------------------------------------------------------ |
| `-v` | The bootstrap through `ssh`, the transports in order, the one tried now and why it failed, a detected change of the network, the socket moving to the new network, a lost connection and each attempt to reconnect, forgotten output, and the end of the session. |
| `-vv` | Also the `ssh` command line (never the pin), the address lookup, the round trip of the QUIC handshake, the offsets of the welcome, window size changes, compression, and agent channels. |
| `-vvv` | Also every frame that is sent or received, by kind and size and never by content. |

- The log names the session id, and the server process shows the same id in its arguments, so
  `ps ax | grep <id>` finds the server process of a session.
- After a change of the network the log says how many notices came, whether a socket was moved,
  and whether the server answered the probe.
- The lines go to the standard error output. A program such as `vim` draws over them, so
  `--log-file FILE` writes them to a file (mode 0600) instead.
- Nothing typed or printed in the session is logged.

## Configuration

Both files are flat `key = value` lines of TOML, without tables.

- A typo in a key is an error with the line number.
- A file that others can write is refused.
- Flags on the command line override the file.

`$XDG_CONFIG_HOME/ssj/client.toml`:

```toml
auto_install = "ask"                  # "ask", "always", or "never"
detach_key = "ctrl-\\"                # a key such as "ctrl-]" that detaches anywhere, or "none"
ssh_command = "ssh -J jump"           # replaces ssh
send_env = []                         # more variables to send, besides TERM and the SendEnv of ssh
transport = "auto"                    # "auto", "udp", or "stdio"
relay = "none"                        # "none", "auto", or "first": UDP to the first jump host
auto_attach = false                   # `ssj connect host` joins the only session without a client
local_echo = "off"                    # "off" or "auto": show typed characters at once
compress = "off"                      # "off" or "auto": compress while the link is the limit
congestion = "auto"                   # "auto", "bbr", or "cubic": how fast to send
forward_agent = false                 # let programs on the host use your ssh agent (-A)
```

`$XDG_CONFIG_HOME/ssj/server.toml` on the host:

```toml
port_range = "60000:61000"            # UDP ports the server may use, "0" for any
detached_timeout = "none"             # seconds without a client (default: none)
max_detached = "none"                 # limit even after a deliberate detach
replay_capacity = 4194304             # bytes of output kept for a client that is away
slow_client = "drop"                  # "drop": the job never waits for the link; "wait": like ssh
compress = "off"                      # "off" or "auto": compress output when the link is the limit
congestion = "auto"                   # "auto", "bbr", or "cubic"
live_backlog = 1048576                # bytes that may wait for a connected client (drop)
away_after = 10                       # seconds a silent client may block the output (wait)
shell = "/bin/zsh"                    # default: $SHELL
accept_env = ["TERM", "LANG", "LC_*"] # variables of the client the shell gets
```

`accept_env` can only be set in the file, never on the command line, because the command line of
the server is built by the client.

### Editing the config files

`ssj edit` opens `client.toml` in `$EDITOR` (then `$VISUAL`, then `vi`; a command with arguments
such as `code -w` works, but it is split like shell words and not run by a shell). `ssj edit user@host` does the same for `server.toml` on the host.

- A new file starts with every setting as a comment.
- The text is judged as soon as the editor ends: the client checks `client.toml` itself, and
  `ssj-server --check-config` on the host checks `server.toml`. A typo in a key is shown and
  never saved. You can then edit again or discard the change, as with `visudo`.
- A file is saved by renaming (mode 0600), so a reader never sees half of it.
- If somebody else changed the file while your editor was open, nothing is overwritten: the error
  names a file with your text.
- Sessions that run keep their settings; new ones use the file.
- A host called `edit` is reached as `ssj connect edit` (or `user@edit`); `ssj edit` alone is the
  editor of `client.toml`, and `ssj edit edit` edits `server.toml` on the host `edit`.

### Files

Paths follow the XDG Base Directory specification:

```text
$XDG_CONFIG_HOME/ssj/
├── client.toml                # settings of the client
└── server.toml                # settings of the server (on the host)
$XDG_STATE_HOME/ssj/           # state of the server
$XDG_CACHE_HOME/ssj/sessions/  # session names for tab completion
$XDG_RUNTIME_DIR/ssj/          # control sockets; without it $XDG_STATE_HOME/ssj/run/<host>/,
                               #   or /tmp/ssj-<uid>/ if the path is too long for a socket
~/.local/share/ssj/bin/        # server files (ssj-server-p<N>) on the host
```

## Security notes

- Authentication is done by `ssh`. `ssj` stores no passwords or keys. Each session uses fresh
  certificates on both sides, which are pinned through the `ssh` bootstrap, and nothing is
  written to disk.
- Only the holder of the pinned client key can open a session. An open UDP port allows handshake
  attempts only, and these are limited by address validation and strict resource limits.
- A session without timeout is a running shell in the background. Use `ssj list` to find
  forgotten sessions.
- Terminal escape sequences in the output of the remote host (such as clipboard writes) reach
  your terminal, as with `ssh`.

## Protocol versions

A client and a server talk only if they speak the same protocol version.

- The server file on a host is named `ssj-server-p<N>` after the protocol, so servers of
  different protocols can sit side by side.
- After an upgrade that changes the protocol, run `ssj install HOST` for each host. The old
  server keeps serving its running sessions.
- Releases without a row in this table speak the protocol of the row above them.

| Protocol | First release | Change |
| -------- | ------------- | ----------------------------------------------------------------------------------------------------------------------- |
| 1 | 0.1.0 | First published format. It includes the `Gap`, `Compressed`, and `Detached` frames and the frames of agent forwarding. |
| 2 | 0.2.0 | The frames are encoded with `postcard`. |

## Development

| Task | How |
| --------- | ----------------------------------------------------------------------------------------- |
| Tests | `cargo nextest run --workspace` (about 25 seconds on a laptop). |
| Benchmark | `bench/bench.py --host user@host`, or `bench/docker-bench.sh` between two containers. |

- The tests start real programs and wait for real clocks, so they run with
  [`cargo nextest`](https://nexte.st). It runs each test in its own process and stops and names a
  test that hangs. The settings are in `.config/nextest.toml`; CI uses the `ci` profile, which
  retries a failed test once and lists it as flaky. `cargo test` works too, but it does not stop
  a hanging test.
- `bench/bench.py` compares `ssh`, `mosh`, `et`, `tssh`, and `ssj` over UDP and the `ssh` channel: bulk output,
  keystroke latency, an 8 MiB paste, the time to log in, and the recovery from outages. Tools that
  are not installed are skipped. See the Benchmark section of the specification. It needs Python 3 and the release builds in
  `target/release`.
- `bench/docker-bench.sh` runs it between two Docker containers with a simulated link
  (`NETEM="delay 40ms loss 1%" bench/docker-bench.sh`), which is the setup to believe. See the
  specification for the options and the numbers.
- `NETEM=train bench/docker-bench.sh --train --outages 5,15` simulates a ride on a train: bursts of
  loss, jitter, and blackouts of 5 and 15 seconds. It prints the keystroke latency and the time to
  the first echo after each blackout, for `ssh` and for every transport of `ssj`.

## License

MIT
