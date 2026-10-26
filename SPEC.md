# *s*ession *s*urvives *j*umps

We want a secure shell (ssh) alternative with the following properties.

## Requirements

1. Non-failure as in `mosh`: the session survives roaming, IP changes, sleep, and packet loss.
1. Full scroll mode as in eternal terminal (`et`): the native scrollback of the local terminal
   works, so the stream is forwarded as bytes and not as synchronized screen state.
1. No root on the remote server: no privileged port, no daemon, no setuid binary.
1. UDP transport for speed.
1. Written in memory safe Rust. The workspace lint `unsafe_code` is `deny`, so `unsafe` needs an
   explicit `#[allow(unsafe_code)]` with a safety comment. There is one such place:
   `daemon::close_inherited_descriptors`, which calls `rustix::io::close`. Dependencies such as
   `ring`, `rustix`, and `tokio` contain `unsafe` code, which is audited through the checks listed
   under Security and not avoided.
1. No new security vulnerabilities: no home-made cryptography, and no weaker trust model than `ssh`.

## Architecture

Workspace layout follows the guidelines (`crates/`, edition 2024, shared `Cargo.toml` values in
the workspace root):

- `crates/ssj-proto`: wire format, framing, and session state machine (no IO).
- `crates/ssj-net`: QUIC transport shared by client and server: pinned mutual TLS, address
  validation (retry), and the transport limits.
- `crates/ssj-server`: runs on the remote host as the unprivileged user, owns the session.
  The shell lives behind the `Backend` and `Shell` traits (`backend` module), so where it runs
  can change without touching the session logic. v1 has one backend, `Direct`, which runs the
  shell as a child of the server on a PTY (via `pty-process`).
- `crates/ssj-client`: local terminal, bootstrap, and reconnect logic.
- `crates/ssj-holder` (optional, later): the holder process of the `holder` backend described
  below. It is a separate binary with no network code.

### Bootstrap

1. Client generates an ephemeral keypair and self-signed certificate.
1. Client runs `ssh user@host <server path>` (see Installation of the server; existing `ssh`
   handles authentication, host keys, and jump hosts) and sends the fingerprint of its certificate on stdin. Stdin is used because argv
   is visible to other users in `ps`.
1. Server generates its own ephemeral keypair and certificate, binds a UDP port from a high
   range, prints the session id, the port, and the server
   certificate fingerprint on stdout (`SSJ CONNECT <id> <udp:PORT|none> none <fingerprint> [new] [name=NAME] [socket=PATH]`; the third field was the TCP port of earlier servers, and the client reads and ignores it), and detaches from the `ssh`
   channel. The optional field `new` says that this server has just made the session; a session
   that ran leaves it out, and the client then reads the first line as `attached to session`. The
   optional field `name=NAME` gives the name of the session, so that `ssj attach HOST` and a join
   by an id show it too; each field stands once, `new` first, and anything else is an error. The range defaults to 60000 to 61000 and is set with `--port-range LOW:HIGH`, which
   the client also accepts and passes on to `ssj-server`. `--port-range 0` takes any port that the
   kernel gives, for hosts where the range is full or filtered anyway.
1. Client reads the line, closes the `ssh` connection, and connects over the best transport (see
   Transports).

The shell of a fresh session starts during the bootstrap:

- After the pin line the client writes a second line, `SSJ START <hex>`, where the hex is a
  `Hello::Start` frame (window size, selected environment, agent flag), the frame that the client
  sends later anyway, decoded by the same code and under the same limits. A server that does not
  find the line, or finds a broken one, ignores it, and the shell starts with the `Hello` as before.
  Only a plain connect sends it, not `ssj attach` and not a join of a running session.
- The daemon starts the shell at once, with `accept_env` applied as for a `Hello`, and the shell
  runs its startup files while the client makes the handshake. What the shell prints waits in the
  replay buffer.
- The first `Start` hello of a client then joins the running shell: the welcome is 0 and 0 as for
  any start, and the size of the hello is applied. An `Attach` joins it too. After a client has
  connected once, a `Start` is refused with `AlreadyStarted` as before.
- A session that no client has joined ends after 120 seconds with its shell, so that a client that
  gave up while connecting leaves nothing behind. A `detached_timeout` that is shorter wins. After
  the first connection only `detached_timeout` and `max_detached` count.
- A client that uses `--auto-attach` while another client of the same user is still connecting may
  join the session that the other one started, which then fails with `AlreadyStarted`.

No bearer secret exists. Both fingerprints are public values that need integrity, not
confidentiality, and the authenticated `ssh` channel provides that. The server expires the
pinned client fingerprint if no client connects within a short timeout.

### Transport

Decided: QUIC via `quinn` and `rustls` with mutual TLS. Each side accepts only the certificate
whose fingerprint was exchanged during bootstrap, so a host that can reach the UDP port but did
not take part in the bootstrap cannot open a session.

- Provides UDP, TLS 1.3, loss recovery, congestion control, and connection migration, so none of
  these are implemented by us.
- The idle timeout is disabled or very long, and the application layer adds keepalives.
- If the QUIC connection dies, the client reconnects with the session ID and resumes the stream.

Rejected alternative: custom reliable stream over UDP with Noise (`snow`). More control, but more
code to audit.

Findings of the M0 spike, whose code and tests now live in `crates/ssj-net`:

- Pinning in a custom `rustls` verifier works for both directions. A peer presenting the pinned
  certificate with a different private key is rejected by the handshake signature check.
- With the idle timeout disabled and a 1 second keepalive, one connection survived a 90 second
  total network blackout and delivered its pending data 0.4 seconds after the network returned.
  Reconnecting is therefore the fallback and not the normal path.
- A client that changes its source address keeps the same connection (QUIC migration).
- A client that lost its connection without a close can be replaced: the server closes the old
  connection when a newer authenticated one arrives.

### Session persistence

- The server process outlives the connection. It keeps the PTY and its child shell running.
- The server buffers output not yet acknowledged by the client, bounded in size (`replay_capacity`,
  default 4 MiB). On reconnect, the client sends the last received offset and the server replays
  from there. If the server had to forget output in the meantime, see Output while nobody listens.
- Client input is also numbered and acknowledged, so no keystroke is lost or duplicated.
- The server exits when the shell exits or after a configurable detached timeout (default: no
  timeout for the shell, on for the pinned client fingerprint before the first connect).

### Protocol version

There is no backward compatibility, which keeps the code small. Every binary speaks exactly one
protocol version, and two peers talk only if their versions are equal.

- The protocol version is an integer `N` with a single source, the constant `PROTOCOL` in
  `ssj-proto`. It appears in the ALPN identifier `ssj/N` (the only one a peer offers or accepts)
  and in the name of the server file (see Installation of the server).
- `N` is increased whenever the wire format or its meaning changes in a way that an older peer
  would not understand: a changed or removed frame, a changed field, a new frame, a new
  handshake step. Changes that do not touch the wire format (client behavior, terminal handling,
  messages) leave `N` alone.
- A golden test keeps this honest: it encodes every frame variant and compares the bytes with the
  stored file `tests/golden/protocol-<N>.bin`. A change of the wire format makes the test fail
  until the developer increases `PROTOCOL` and stores a new golden file. Increasing `PROTOCOL`
  without a new file fails the same test, because the file is missing.
- The README lists the protocol of every release that broke the wire format ("Protocol versions"). A
  developer who increases `PROTOCOL` adds a row there.
- The bootstrap line `SSJ CONNECT` has no version of its own and is covered by `N`.
- A frame is a big endian `u32` length and a body in the format of `postcard`: the frame types
  derive `serde`, so the body is the index of the variant and its fields, integers as varints and
  byte strings with their length in front. The decoder rejects a length of 0 or above 128 KiB from
  the header, a body with bytes after the frame, and the values that the types do not exclude: a
  data chunk that is empty or above 32 KiB, an empty `Gap`, a window size outside 1 to 4096, and
  an environment that `Env` refuses. `Output` is the first variant of the server frames, so that
  `peek_server` finds its data from the first byte of the body. Protocol 2 replaced the format of
  protocol 1, which was written by hand with a type byte and fixed-width integers.

### Reconnect (client)

QUIC keeps one connection alive through long outages, so most disconnects need no action by the
client. A new connection is made only when the old one ends (the server closed it, or the path
was lost for good). Then:

1. The client shows the status `connection lost, reconnecting (attempt N)` and tries again after
   0.25, 0.5, 1, 2, and then every 3 seconds. One attempt lasts at most 8 seconds.
1. Each attempt sends `Resume` with the output offset the client has processed. The server answers
   with the input offset it has consumed. The client drops that input from its buffer and sends
   the rest again, so nothing is lost and nothing is repeated, including keystrokes typed during
   the outage. They wait in the bounded input buffer.
1. If the server forgot output while the client was away, the answer starts at the oldest byte that
   is left, the client prints a notice with the exact number of bytes that it missed, and goes on.
   If the session is gone, or the server claims the client has seen bytes that never existed
   (`ReplayGap`), the client stops with a clear message.
1. If the first `Start` may not have arrived, the client tries `Resume` first and falls back to
   `Start` when the server answers `NotStarted`.
1. While there is no connection, the detach key still works, so the user is never stuck. The server is not
   told, and the session keeps running with its timeout.

The client sends a `Ping` every second in which nothing has come for half a second (a frame that arrived a moment ago shows that the connection works, and a ping next to a keystroke is what a stream transport must avoid, see below). It reports a stall when no frame has come for four round
trips of the connection, but not sooner than 2 seconds and not later than 10, so a good link
reports quickly and a slow link does not report all the time. The message is `no response from the server`, with the time added in steps of five seconds after ten seconds, and it is removed with
the next frame.

Network changes and wakes from sleep:

- A source sends a cause on one channel: `NetworkChanged` or `Woke` (stronger). Sources are a clock
  watch that runs everywhere (a timer that fires 3 seconds late means that the process was
  suspended, judged on whichever of the wall clock and the monotonic clock saw more time pass),
  the dynamic store of SystemConfiguration on macOS, and a netlink socket for link, address, and
  route changes on Linux. The platform sources sit behind the cargo feature `netwatch`, on by
  default. A source that fails to start only makes the reaction slower.
- Notifications are collected until they stop for 300 milliseconds, since a change of network
  produces many. Then the client moves its UDP socket to a new one (`Endpoint::rebind`), so QUIC
  probes the new path at once and the server follows the new address, and sends a `Ping`. If
  nothing comes back within 1 second (also after a wake), the old connection is dropped and a
  new one is made with `Resume`.
- A cause during the pause between attempts ends the pause. A cause during an attempt that hangs
  ends that attempt and starts a new one on the new socket.
- No source can be tested without a real change of the network. The clock watch, the collecting,
  and the reaction are tested with injected causes. The macOS source starts in a test, and
  `cargo nextest run -p ssj-client --test netwatch --run-ignored only` waits for a real change. The Linux source
  has been compiled but not run. `cargo run -p ssj-client --example netwatch` prints what the
  sources report.

After every third failed attempt the client looks up the address of the server again (2 seconds at
most), so that a changed address is found after a move or a long sleep. A failed lookup keeps the
old address. If the address family changes, the UDP socket is replaced by one of the new family.

Window sizes are collected: the client sends a size when no newer one has come for 50 milliseconds
(trailing edge), and the server applies only the newest size of the messages that are queued, so
dragging a window edge does not send a signal to the shell for every step.

Status messages go to the window title. The client follows the output of the server just far
enough to know whether it stopped inside an escape sequence or inside a multi-byte character, and
holds the message back until it did not. A sequence that is still open two seconds after the
message became due (the link stalled in the middle of it) is cancelled: the client writes CAN to
the terminal, which ends the sequence in every terminal, shows the message, and drops the rest of
that sequence from the output when it arrives (up to its final byte, or the last byte of the
character). Nothing else is changed or dropped, and a half title is never taken for the title.
When the message goes,
the title stack of xterm is popped and the last title that the remote side set (read from OSC 0
and OSC 2 in the output) is set by name, since not every terminal has the stack. At the end of the
session the message is removed even inside a sequence. Without a terminal, the messages go to
stderr as lines.

### Transports

UDP can be blocked, and a host behind a jump host cannot be reached by datagrams at all. The
session core works on any pair of byte streams, so two transports carry the same frames, in
this order of preference:

1. **UDP**: QUIC, as described above. Fastest, and the only one that survives a changing path
   without a new connection.
1. **The `ssh` channel**: `ssj-server --stdio <id>` connects to the control socket, sends
   `STREAM`, and after the answer `OK` the socket is the byte stream of a client. The process
   copies it to stdout and from stdin. Shell startup files may print text first, so the stream
   begins after the 17 bytes `\0SSJ_SYNC_STREAM\n`, and the client skips everything before them.
   No TLS runs inside, since `ssh` already authenticates and encrypts, and the socket allows only
   the same user.

**The first `ssh` carries the first stream.** After the line `SSJ CONNECT` the server process stays
on the `ssh` channel (at most 20 seconds) and reads from stdin. The input of the client has a
second line always: `SSJ START …`, or `SSJ START -` when there is nothing to start, so that the
server does not wait for one. If the client writes `SSJ STREAM`, the process becomes `--stdio`
for the session (the sync header and the stream follow), and the first stream transport of the
client uses this channel instead of a second login. If the client closes the channel, the process
ends. A server that ends at once (`--no-hold`, or an older one) makes the client log in again, so
the wire protocol is unchanged. Later streams, spares and mirrors open their own logins.

The choice is `--transport auto|udp|stdio` or `transport` in `client.toml`. `auto`
races UDP against the first stream (the `ssh` channel): QUIC starts first, the stream starts 300
milliseconds later if QUIC has not opened, and the first connection that opens carries the
session. Before the first connection QUIC is given 1.5 seconds and the stream, which needs a whole
`ssh` handshake that takes seconds on a distant host, gets 8 seconds. A reconnect
races the same way: when the session runs on a stream, the stream starts at once and
QUIC beside it, so a network where UDP works again is found without a delay and a network where it
does not costs nothing. A change of the network while the session is on a stream also tries QUIC
(1.5 seconds) on the new path, without touching the working connection; if it opens, the client
resumes over it and drops the stream (`Pumped::Switch`). Auto leaves out UDP when `ssh -G` shows a
`proxyjump` or `proxycommand` for the host, unless a relay is used (below). After a connection was made, its transport is kept
for three failed attempts before the next partner is tried, since the network is the likelier
culprit. The server offers what it is told to
(`--no-udp`); the `ssh` channel is always there.

### UDP through a jump host (`relay`)

A host behind a jump host cannot be reached by datagrams, but the path that is usually flaky is
the one from the client to the first jump host. With `relay = "auto"` or `"first"` (the default is
`none`) and a `proxyjump` in `ssh -G`, the client speaks UDP to the first jump host, which passes
the packets to the server over `ssh`. The QUIC connection stays between the client and the
server, with the pinned certificates of the direct case, so the jump host sees ciphertext only
and can drop packets, not read or change them. Hosts after the first jump host stay on `ssh`
(`ssh -J rest host`); a first jump host behind a jump host of its own gets no relay, and a
`proxycommand` cannot be followed.

1. **The relay on the jump host.** Beside the connection to the destination, the client runs
   `ssj-server --relay` on the first jump host through `ssh` (`BatchMode`, so it never asks), and
   writes `SSJ RELAY <64 hex digits>`: a secret of 32 random bytes. The server binds a UDP port
   from its `port_range` and answers `SSJ RELAY-PORT <n>`. The process behind the `ssh` stays as a
   daemon when `ssh` ends, like a session.
1. **The leg to the destination.** Once the client has the session from the destination, it
   writes `SSJ LEG <hex>[,<hex>...]` to the relay: the words of a command, each in hex, that the
   relay runs without a shell. The command is `ssh [-A] [-J rest] [-p port] -- user@host <server> --datagrams <session>`. `--datagrams` sends `DATAGRAMS` on the control socket and
   after `OK` the socket carries QUIC packets as frames (two bytes of length, the packet), after
   the sync header of `--stdio`. The relay answers `OK` when the sync header has come, or
   `ERR <reason>` with the error output of the command. The client tries the relay tier without
   waiting for the answer: its first packets wait in the socket of the relay.
1. **The endpoint on the destination.** `DATAGRAMS` opens a second QUIC endpoint on the frames,
   with the certificate and the client pin of the last `ATTACH`, so the fingerprint that the
   client holds (it came through the end-to-end `ssh`, never through the jump host) is the right
   one. Datagrams that do not fit are dropped, as a network drops them. The endpoint closes when
   the stream ends, and the address validation (`Retry`) is skipped, since nobody can forge an
   address in a pipe.
1. **The envelope.** Between the client and the relay each datagram has a counter (8 bytes) and
   a tag (16 bytes, HMAC-SHA256 over the direction, the counter and the packet, with the secret).
   The relay forwards only packets with a valid tag whose counter was not used (a window of 4096
   behind the newest), and answers to the address of the newest. A client that comes from
   another address (a new network) is followed, and a recorded packet cannot send the answers
   elsewhere. QUIC keeps the 1200-byte packets it starts with (no path MTU search), so the
   envelope stays below the smallest MTU.
1. **Order and repetition.** A path with jitter reorders packets, and QUIC takes that for loss:
   it keeps only 64 ranges of received packets for its acknowledgements and drops the oldest
   ones, so what arrived is reported as lost and sent again, and the throughput of a bulk
   transfer stops at about 12 MB/s with 3 ms of jitter, whatever the windows. The client therefore
   puts the packets it receives back in the order of their counters before QUIC sees them
   (`ssj_net::resequence`): a packet behind a hole waits for the hole to fill, for twice the
   longest time that a hole took lately, at least 2 ms and at most 40 ms, and then goes on
   with the hole given up (at most 512 packets wait). A packet that comes after its hole was given
   up passes at once. Datagrams of up to 300 bytes (acknowledgements, keystrokes, a line of
   output) are sent twice, the second time 5 ms after the first, by the client and by the relay;
   the counter is the same, so the receiver drops the one that comes second, and a single loss
   costs no round trip. On the testbed (`tc netem`, 3 % loss) the 95th percentile of the echo of a
   typed line fell from 250 ms to 75 ms, and the median did not move.
1. **Lifetime.** The relay ends when the leg ends (the session ended, or `ssh` died) or when
   it has heard nothing from the client for 8 hours. After that the client finds the port closed
   and the `ssh` channel carries the session as without a relay. The relay tier is first in the
   list, the `ssh` channel behind it, so a relay that does not come up costs the time of the first
   attempt and not the session.

The leg uses the configuration of `ssh` on the jump host, and an agent only if `ForwardAgent` is
set for the jump host or the destination: the jump host is trusted with the login to the
destination as it is with `ProxyJump`, but never with the session. `relay = "first"` asks to
install the server on the jump host when it is missing (`auto_install`), and says if the relay is
not used; `auto` skips without a word (`-v` says why). The checks of the host key of the destination
are those of the jump host: with `BatchMode` an unknown key fails (log in once from the jump host),
and the failure is shown.

A stream has no keepalive of QUIC: if the path dies without a sign (a firewall, a hung `ssh`),
the connection stays open. The client pings every second, shows "no response" after 2 seconds,
and gives a stream up after 10 seconds of silence. Then it makes a new one and resumes with the
offsets, as after any loss.

The lag of a stream is the longest of three times: the silence of the server, the age of a ping
that no pong has answered, and the age of typed input that the server has not acknowledged. The
second and the third matter because the two directions of the TCP connection under `ssh` recover on their own
retransmission timers after an outage: the server can be heard again while it hears nothing, and
the keystrokes wait for the timer of the client. A stream with a lag of 3 seconds (`SPARE_AFTER`)
gets spares: a second connection over the same transport is opened beside it, a new one every
second while the lag lasts, up to six at once (`SPARES_AT_ONCE`), and the session moves to the
first one that opens, with the same resume as after a loss. This is for a flaky link such as a
train, where waiting for the 10 seconds and then for a login loses more time than the outage
itself, and where the old connection may sit in its long retransmission backoff when the
network is back. The new ones every second hedge: a connection that was started on a dead path
has lost its first packets and retries them at growing intervals, so a fresh one finds a returning
network sooner. A spare gets 10 seconds to open (one that was started on a dead path retries its first
packets after 1 and 3 seconds and then needs the login, so it opens about 6 seconds after the
start, and a shorter limit ended the spares that were about to work), and one that fails outright
pauses the next for 2 seconds. When the stream answers again (lag under 1.5 seconds) the spares are dropped, and a spare
that opens at that moment is dropped too. A stream is not given up while spares are opening, but
at the latest after three times the limit (30 seconds), so that a transport that never opens still
gives way to the next one.

The server replaces the working connection only when the new one sends its hello. A connection
that has been accepted and has said nothing is kept as `incoming`, and a failure or the hello
timeout of it leaves the working one alone; before this, a spare that merely completed its TLS
handshake ended the stream it was meant to back up. Servers older than 0.1.0 (the release
candidates) do the old thing, so a host needs `ssj install` for spares to be harmless; the protocol
version is the same.
The tests (`reconnect.rs`, `session.rs`, `transports.rs`) type a hundred lines and print two
hundred through the move with the old connection swallowed, held back and delivered late, or
working in one direction only, and they check that a silent second connection does not end the
working one.

The first stream is the `ssh` that started the server (see above). Every later one starts a new `ssh`, which
cannot ask for a passphrase (`BatchMode=yes`), so they need an agent or a shared connection
(`ControlMaster auto`, `ControlPersist`) when the key has a passphrase. The same holds for the
reconnects of a session that started over UDP and later fell back.

Small packets. Under `ssh` the second of two small writes in the direction to the client can wait
for the acknowledgement timer of the receiver (40 to 100 ms on Linux), so `ssj` never lets a small
packet that nobody answers stand in front of the next one:

- The server sends the `InputAck` in the write of the echo (queued frames go out in one write,
  after a yield that lets the sender queue the second one). Alone it goes out after one second
  or when 4 KiB of input are unacknowledged.
- The client sends the `OutputAck` in the write of the next keystroke or of the next ping, and
  alone only when 4 KiB of output are unacknowledged.
- The client pings when nothing has come for half a second, not every second.

UDP never showed the effect. `bench/wprobe.py` shows it without `ssj`.

### Destination, address, and names

The destination is `[user@]host[:port]` or `ssh://[user@]host[:port]`, with IPv6 addresses in
brackets (`[2001:db8::1]:22`) or bare (`2001:db8::1`, without a port). The text goes to `ssh` and
to DNS, so only the characters of names and addresses are accepted (letters, digits, `.`, `_`,
`-`, and for the user `+`), and never a leading `-` or `.`. The client gives `ssh` the user and
host, and the port as `-p`.

The address of the server for UDP is, in this order: `--udp-host`; the `HostName` that `ssh -G`
reports for the destination (the destination may be an alias from the `ssh` configuration);
the host part of the destination. DNS is asked again during reconnects, see above. `ssh -G` also
shows a jump host or proxy command, which makes `auto` leave out UDP.

A session may have a name (`ssj connect --name work user@host`): 1 to 32 characters of letters, digits,
`.`, `_`, `-`, not starting with `.` or `-`. The server keeps it and `ssj list` shows it. Names are
unique per user and host. The command joins the session of that name if it runs and starts one
otherwise; the client always begins with an attach, and a session without a shell answers
`NotStarted`, on which the client sends a start. `ssj attach`, `ssj kill`, and `ssj detach` take an id or a name.
`auto_attach = true` in `client.toml` (or `--auto-attach`) makes a plain `ssj connect user@host` join the
only session that has no client connected, and start a new one when there is none or more than one
(a session with a client is never taken away). On a terminal, several sessions without a client are not a reason to start another: the client shows a menu (see "Choosing a session"). The names and the state travel in the line `SSJ SESSION <id> <state> <age> <protocol> <name|->` of the control socket, which is not part of the
protocol between client and server.

### Debug lines on the screen

`-v` writes its lines to the terminal, over whatever the program in the session has drawn. The
client therefore makes the program draw again 400 milliseconds after the last such line (level 1
and 2; level 3 logs every frame, which would never settle), by the same trick as an attach: a
narrower window for 60 ms, then the real size. `--log-file` keeps the screen intact and needs no
redraw.

### Choosing a session

- `--reuse`, a bare `--attach`, `--kill`, and `--detach` of `ssj-server` take `--choose`. With it,
  and without a name or an id, several sessions of this protocol (for `--reuse` only those
  without a client) are not an error and not a reason to start another: the server prints their
  `SSJ SESSION` lines on stdout and exits with code 67 (`CHOICE_EXIT_CODE`). The client sends
  `--choose` only when stdin and stderr are terminals and it is not a background refresh.

- The client shows the sessions, the youngest first, in a menu on stderr (drawn by `dialoguer`): arrows,
  `j`/`k`, Enter, and `q` or Escape to cancel. Ctrl-C ends the client with exit code 130. For
  `--auto-attach` the last line starts a new session. It then runs the server again with
  `--attach ID` (or without `--reuse` for a new session), which costs a second `ssh` call.
  `detach` offers only sessions with a client, and joins the only one without asking.

- A server of an earlier release does not know `--choose` and answers with an unknown argument,
  which the client shows. There is no fallback: install the server of the same release.

- `ssj kill` and `ssj detach` take any number of ids or names after the destination, in one call
  to the host (`--kill ID ID...`). Each is answered on its own: a session that cannot be reached is
  reported on stderr, the others are still handled, and the exit code is 1 if any failed.

- `ssj kill [-f] DESTINATION` without an id: with a terminal, the only session is ended after
  `End the session <NAME> (<ID>) on <DESTINATION> (<STATE>, <AGE>)? [Y/n]` (Enter and `y`
  agree, anything else does not, and `-f` skips the question), and several sessions go into the menu, which is the consent.
  Without a terminal the client refuses unless `-f` is given, and says "no running session" first
  if there is none. An id given on the command line is never asked about.

- A selector (id or name) that fits two sessions, which happens when a session is named like the id
  of another, is an error that names both ids (`matches several sessions`). With `--choose` the
  server lists the two sessions and exits with the code of a choice, and a client at a terminal
  shows the menu, for `kill`, `detach`, and `attach`.

- `ssj <command> --help` shows the help of the command.

- The completion offers further ids for `kill` and `detach`, and `detach` offers only sessions
  that had a client at the last refresh of the cache (`ssj --complete HOST --connected`). The
  cache file marks them: a line is `name` or `name connected`.

### Command line, completions, and release files

- The client parses its command line with `clap` (derive). The definition lives in
  `crates/ssj-client/src/options.rs`, and every value has its type there (a parser of its own for
  the detach key, the session name, and the `ssh` command). A word is a command (`list`, `attach`,
  `kill`, `detach`, `install`) only when a destination follows it, so a host named `list` still
  works. An option given twice takes the last value, except `--server-arg` and `--send-env`, which
  collect.
- `ssj-server` parses its command line with `clap` (derive) as well. Each setting that
  `server.toml` has is an `Option` there, and `Config::with` puts the given ones over the file. The
  bootstrap process starts the daemon with its own arguments and `--daemon-child --session-id ID`,
  and the daemon reads the file itself.
- The options with a fixed set of values (`--transport`, `--local-echo`, `--compress`,
  `--congestion`, and `--slow-client` of the server) are enums with `clap::ValueEnum` and
  `serde::Deserialize`, so one definition serves the command line, the config files, and the
  completions: the three shells offer the values after a space and after `=` (Zsh with the doc
  comment of each value), and clap and serde reject anything else with the list.
- Every line of `ssj` starts with a command (`connect`, `list`, `attach`, `kill`, `detach`,
  `install`, `edit`), so a host may have any name. The commands are a `clap` derive in
  `options.rs` (`Cli`, `CommandLine`): each takes the groups of options that it reads (`Ssh`,
  `Server`, `Upload`, `Session`, `Connection`), and `clap` refuses any other option, and any
  option before the command word. The parser, the help of each command (`ssj kill --help`), the
  man page, and the completions come from that one definition. `ssj-assets` copies the tree
  without the hidden options (`completion_tree`), since the generators list those too, and
  `clap_complete` writes from it the options of each command, their values (the fixed ones of
  `--transport`, `--local-echo`, `--congestion`, and `--compress`, and files for `--log-file`,
  `--server-path`, and `--server-binary`), and the commands for the first
  word. What `clap` cannot know is added by `ssj-assets` to each file:
  the hosts of `~/.ssh/config` for the destination and for `--udp-host` (`_ssh_hosts` in Zsh,
  `_known_hosts_real` of bash-completion in Bash when it is loaded, `__fish_print_hostnames` in
  Fish), the sessions of the host for `attach` (one), `kill`, and `detach` (any number), and the
  sessions for `--name`.
- The shells complete the same: the commands for the first word, the hosts for the word after a
  command, the sessions after the host of a command that takes them, the options of a command,
  and the values of options. After the destination of `connect` the words belong to the command
  that runs on the host: files, since its layout (`~/.local/share/...`) is mostly the one of this
  machine, and no options (`ssj connect host ls -l`). Zsh does it with a rest
  that completes nothing (so that its `_arguments` does not offer the options before a dash), Bash
  through the default completion that follows an empty answer, Fish by its default for words that
  no rule takes.
- Options with a free text (`--ssh-command`, `--download-url`, and the like) complete nothing in
  all three shells, files included. An option that the command does not read
  completes nothing, and no sessions are offered while the value of an option is being typed.
- The Zsh function ends with the status of the completion (`return ret`). A function that ends with 1
  is run again for each further matcher of the `matcher-list` style, as oh-my-zsh sets it, and the
  words of all runs are shown: `ssj connect -` listed every option three times, and hosts with a dash,
  which the later matchers take for the typed `-`. The Zsh tests use that style and a host
  `box-c`, and require that each option is shown exactly once.
- One table in `completions.rs` (`positions`) says for every position what it offers and what it
  does not: the start, each command with its host, ids, options, and the values of every option,
  `connect`, a host that is no command, and `--`. The same table runs in Bash (with `COMP_WORDS`),
  Fish (with `complete -C`), and Zsh (with the completion system in a pseudo terminal, `zpty`, so
  that the functions of `clap` run for real). The options that each command reads are written out
  again there, from the code of the commands, and not taken from the table that `ssj-assets` reads.
- The crate `ssj-assets` makes the man page (`ssj.1`, with a section on running a command and a
  FILES section for `client.toml` and `server.toml`) and the completions for Bash, Zsh, and Fish
  from the parser of the client; the release workflow writes them with
  `cargo run -p ssj-assets -- DIR`, and its tests run the completions in the shells. The options
  for internal use (`--complete`, `--batch`) are left out.
- `ssj list` prints one line for each session (id, state, age, protocol, name). On a terminal a
  header line (`ID STATE AGE PROTOCOL NAME`) comes first; a pipe gets the rows alone.
- `ssj list --json` prints a JSON array of `{"id", "name", "state", "age_secs", "protocol"}`.
  The name is `null` for an unnamed session.
- Completion of session ids and names reads a cache, never the network. Every `ssj list` writes
  `$XDG_CACHE_HOME/ssj/sessions/<destination>.list` (default `~/.cache`): a first line
  `@<destination>`, an optional `@port=<n>`, then one id or name per line. The directory is mode
  0700, the file is replaced by rename. `ssj --complete [DESTINATION]` prints the names of one host
  or of all, and starts `ssj --batch list <destination>` in the background for each list older
  than 10 seconds. `--batch` adds `-o BatchMode=yes -o ConnectTimeout=2` to the `ssh` command, so
  that a refresh never asks for a passphrase or a key, and takes a lock (`flock`) on a file next to the
  list so that one refresh per host runs at a time; the lock goes with the process. Lines read
  back from the cache are checked again: a name must be a valid selector, and the destination must
  parse as one without a port, since it reaches `ssh` later.
- The id or name comes after the destination (`ssj attach host ID`), so the completion knows the
  host and offers only the names of its sessions. Without a host (`--name`) it offers the names of
  all hosts with a list.
- A release publishes one archive per client platform, `ssj-<version>-<target>.tar.gz`, that holds
  a directory with `ssj`, `ssj.1`, `completions/`, `README.md`, `LICENSE`, and a `SHA256SUMS` of
  the client. The release also lists the server files `ssj-server-<target>` of all five builds as
  separate assets, which `ssj install` downloads, a `SHA256SUMS` of everything, and the build
  provenance attestation for all of them.

### Benchmark

`bench/bench.py` (Python 3, standard library only) runs `ssh` and `ssj` over UDP and the `ssh`
channel against one host, each client on a pseudo terminal as a user runs it:

- bulk output: `dd | tr` of 256 MiB by default, in MB/s, the best of three rounds;
- keystroke latency: one byte at a time into a raw `cat`, the median, 95th percentile, and maximum
  of the round trip;
- a paste of 8 MiB into `head -c`, in seconds;
- `--startup N`: the time from starting the client until the shell answers a command, and the
  time to the end after `exit`;
- `--train`: outages in the typing (see below).

**Clients.** `bench/clients.py` lists them, one entry each; `bench.py --list-clients` shows what
each lacks on this machine. They are `ssh`, `ssh-C`, `udp` and `stdio` (each also compressed, as
`udp-z` and `stdio-z`), and the tools ssj is compared with: `mosh`, `et` (Eternal Terminal), and
`tssh` in four modes (`tssh-tcp`, `tssh`, `tssh-udp-over-tcp`, `tssh-kcp`). A client whose tools are
missing is skipped and the reason is printed. `--only a,b` picks clients. To add a tool, add an entry
to `CLIENTS`: its name, a function that builds the command line, the executables it needs on this
machine and on the host, and whether it delivers every byte (`mosh` shows the latest screen and
skips what went by, so its bulk rate says nothing about the transport). Every `ssj` row runs with
`--no-auto-attach`, so a setting in `client.toml` cannot join a session that an earlier run left, and
with `slow_client = "wait"`, so every byte arrives.

**Against a real host.** `bench.py --host user@host --ssj PATH --server PATH-ON-THE-HOST`. A server
path that starts with `~` is read on the host.

**In containers.** `bench/docker-bench.sh [bench.py options]` is the benchmark to believe. A client
and a server container share a Docker network (Ubuntu 24.04 by default, `IMAGE=`), the link is
simulated on their network interfaces (`NETEM="delay 40ms loss 1%"`, empty for none; offloads are
off so that the loss hits packets of normal size), and `sshd` runs in the server container, so the
hop to the server port is local, as on a host. The binaries are the static musl builds.
`EXTRA="mosh et tssh"` installs the other tools in both containers (`bench/install-extras.sh`).
More switches: `CAPTURE=1` records the hop from `sshd` to the server and writes every packet to a
file, `CLIENT_LOG=1` runs the client with `-vvv` and keeps the log (`target/ssj-client-log.txt`),
`TRACE=1` prints the socket options of `sshd`, and `PROBE=1` runs `bench/wprobe.py`.
`TARGET_VOLUME` and `CLIENT_BIN` pick another build, which is how a release is compared with the
working tree; when two trees are built in one volume, touch the sources first, since cargo goes by
modification times. `CLIENT=host` runs the client on the machine you sit at, against the server
container behind a published port (UDP cannot reach the container: `--only ssh,stdio`, and leave
`NETEM` empty). `bench.py --jitter-ms` adds a random gap between the keystrokes and the `stalls`
column counts the echoes that took 10 ms more than the median (a run in which every echo is slow
shows none, so read the median too).

`bench/linux-bench.sh` runs the same inside one container with the link on the loopback; there the
hop from `sshd` to the server port meets the delay and the loss a second time, so use it for
nothing but a quick check. `bench/check.py` checks the JSON of a clean and a lossy run against wide
limits (UDP keystroke median under 5 ms, the `ssh` channel under 10 ms, at most 1 percent stalls,
UDP at least three times as fast as `ssh` at 1 percent loss); the workflow `bench.yml` runs both
and the check on a GitHub runner.

**The train ride.** `NETEM=train bench/docker-bench.sh --train --outages 5,15 --quiet 10` simulates
the link of a train. `NETEM=train` is a delay of 80 ms with 40 ms of jitter and bursts of loss
(`loss gemodel 1% 20% 70% 0.5%`, about 4 percent in all). `bench.py --train` types at the pace of
a person and cuts a blackout into the typing for each of `--outages`: `iptables` drops every packet
of `eth0` in both directions while the interface and its address stay, as in a tunnel, nothing
tells the programs that the network is gone, and the keys typed meanwhile wait. At the end of the
outage the script types a marker, and the time until its echo is the recovery. The table shows the
keystroke latency outside the outages (median, 95th percentile, maximum), the echoes that did not
arrive, and the recovery after each outage.

**Results.** Each number is one run on one machine (the Linux ones in a container on an aarch64
virtual machine, with `sshd` in the same container), so differences of a few percent are noise.

Outages on the train link (80 ms delay, 160 ms round trip; seconds from the end of the outage to
the echo of the marker, outages of 5 and 15 s, three runs of eight outages per transport on 0.2.0):

| Client | Recovery | Slower than 1 s |
| ------ | -------- | --------------- |
| `ssh` (earlier runs, outages of 5 to 20 s) | 1.2 to 27.6 s | all |
| `ssj` over UDP | 0.25 to 0.4 s, once 0.87 s | 2 of 24 (1.4 and 2.2 s) |
| `ssj` over the `ssh` channel | 0.12 to 0.21 s | none |

`ssh` waits for the retransmission timer of its TCP connection, which backed off during the outage.
A stream of `ssj` with a lag of 3 seconds gets spares (see Transports), which may be why the `ssh`
channel recovers so much faster than `ssh`; this was not checked. The 1.4 to 2.2 s recoveries of UDP are the probe timeout of QUIC, which doubles after
every unanswered probe; on this link a bad burst (70 percent loss) can eat two probes in a row. The
log of a keystroke that took 1.29 s fits that (the answer came 1.29 s later, after a ping that was
answered after 0.65 s), but no log of a slow recovery after an outage was caught. An earlier run of
the `ssh` channel had one recovery of 6.7 s with two retypes, one in 32 outages.

A standby connection that stays open, with the output and the typed input mirrored on it, was built
and measured against this (24 outages per tree): it did not shorten the slow cases, the `ssh`
channel had two of 24 above 1 s (2.7 s and 4.4 s with a retype) where the tree without it had none,
and it cost a second session connection on the host for every client. It was not merged (see
Considered and not planned).

A real host (Linux x86-64 on a LAN, a round trip of about 0.7 ms) with OpenSSH 9.6:

| | `ssh` | `ssj` UDP | `ssj` `ssh` channel |
| --- | ---: | ---: | ---: |
| bulk (MB/s) | 113 to 117 | 108 | 127 to 134 |
| keystroke median (ms) | 7.5 to 9 | 1.0 to 1.3 | 1.3 |
| first prompt of a login shell (s) | 0.57 | 0.59 | 0.59 |
| `ls` as the command (s) | 0.19 | 0.19 | 0.18 |

The login shell of that host takes 0.55 s to show a prompt, which is the floor for every client.
With a command and no shell the cost of `ssj` over `ssh` is 20 ms: the server start and the
handshake. The first `ssh` carries the first stream, so a fallback to the `ssh` channel costs no
second login (before this the command took 0.42 s on that channel).

On a link of 40 ms each way and 1 % loss (real packets, no loopback) one run gave: `ssh` 0.2 MB/s,
`ssj` UDP 6.2 MB/s, `ssj` UDP with compression 25.9 MB/s, and the `ssh` channel 0.2 to 0.3 MB/s,
and a keystroke median of 105 ms for `ssh` and 93 to 97 ms for `ssj` (the round trip is 80 ms).
Without a link (1 GB/s on the bridge): `ssh` 171 MB/s and 15 ms, `ssj` UDP 184 MB/s and 0.87 ms,
the `ssh` channel 187 MB/s and 1.4 ms.

On a lossy link the congestion control of the server decides the rate of the TCP under `ssh` and
of the `ssh` channel, since the server sends the output. With
`net.ipv4.tcp_congestion_control=bbr` on the server (40 ms, 1 % loss) `ssh` went from 0.3 to
6.7 MB/s and the `ssh` channel from 0.4 to 9.2. That is a setting for the administrator of the
host: `ssj` runs without root and does not change it. Compression helps without it.

The tables below are from the container and loopback runs of an earlier version, with the removed
`tcp` rows left out. The bulk column is MB/s, the latency is the median in milliseconds, and the
paste is 8 MiB (2 MiB on the slow link, 4 MiB on the lossy one) in seconds. `udp-z` is `ssj` with
`compress = "auto"`, and `ssh-C` is `ssh -C`.

Loopback, zeros (`--raw-bulk`, 256 MiB; this measures the transport and the program):

| client | glibc bulk | glibc latency | glibc paste | musl bulk | musl latency | musl paste | macOS bulk | macOS latency | macOS paste |
| ------ | ---------- | ------------- | ----------- | --------- | ------------ | ---------- | ---------- | ------------- | ----------- |
| ssh | 175 | 9.7 | 0.11 | 177 | 10.7 | 0.11 | 87 | 8.6 | 1.24 |
| ssh -C | 131 | 9.7 | 0.13 | 147 | 9.9 | 0.13 | 88 | 8.3 | 1.25 |
| udp | 190 | 0.96 | 0.10 | 167 | 0.83 | 0.08 | 75 | 0.40 | 1.25 |
| udp-z | 169 | 0.96 | 0.07 | 151 | 0.84 | 0.08 | 70 | 0.40 | 1.25 |
| stdio | 198 | 1.61 | 0.09 | 146 | 1.40 | 0.10 | 59 | 0.55 | 1.51 |

Slow link (`tc netem rate 8mbit delay 25ms` on a loopback with an MTU of 1500, log-like text, 8
MiB; the link carries about 1 MB/s):

| client | glibc bulk | glibc latency | glibc paste | musl bulk | musl latency | musl paste |
| ------ | ---------- | ------------- | ----------- | --------- | ------------ | ---------- |
| ssh | 0.8 | 59.7 | 2.52 | 0.8 | 67.3 | 2.50 |
| ssh -C | 3.4 | 62.1 | 0.41 | 2.9 | 63.7 | 0.41 |
| udp | 0.9 | 58.5 | 2.37 | 0.9 | 58.4 | 2.36 |
| udp-z | 5.5 | 59.1 | 0.63 | 2.9 | 57.1 | 0.62 |
| stdio | 0.8 | 62.4 | 2.69 | 0.8 | 62.7 | 2.55 |

Lossy link (`delay 40ms loss 1%`, MTU 1500, zeros; only the rows without compression mean
anything, because zeros compress a thousand to one):

| client | glibc bulk | glibc latency | musl bulk | musl latency |
| ------ | ---------- | ------------- | --------- | ------------ |
| ssh | 0.2 | 103 | 0.3 | 104 |
| udp | 0.7 | 92 | 0.5 | 91 |
| stdio | 0.3 | 86 | 0.2 | 88 |

Reading them:

- The latency of `ssh` is dominated by its keystroke timing obfuscation (OpenSSH 9.5 and later
  sends keystrokes in 20 ms ticks while typing), so the comparison there says little about the
  transport. `ssj` answers a key in under a millisecond on the loopback, and in one round trip
  plus a millisecond on a link with a delay.
- On Linux `ssj` over UDP is as fast as `ssh` for bulk output (glibc 190 against 175, musl 167
  against 177) and as fast for a paste. The musl and glibc builds of the server are within noise
  of each other, so the choice of the default build for automatic installs does not depend on
  speed; musl stays the default because it runs on every distribution.
- On macOS the pseudo terminal hands out its data in pieces of exactly 1024 bytes (Linux: up to
  4 KiB), so every kilobyte of output is one pass through the event loop of the server. The shell
  alone reaches 115 MB/s there, `ssh` 87, and `ssj` 75. The gap to `ssh` on macOS is about 14
  percent.
- On a slow link compression is what matters. Without it `ssj` and `ssh` both fill the link
  (0.8 to 0.9 MB/s). With it `ssj` carries log-like text at 3 to 5 MB/s, as `ssh -C` does, and a
  paste in a quarter of the time. `ssh -C` compresses a paste better (0.41 s against 0.63 s)
  because its zlib stream keeps its dictionary across the whole connection, which `ssj` does not
  do on purpose (see Compression).
- On a lossy link QUIC beats TCP: with 1 percent loss `ssj` over UDP gets two to three times the
  throughput of `ssh`. The first measurement of this showed the opposite, and the reason was the
  test: the loopback has an MTU of 64 KiB, so a TCP segment is 40 times larger than a QUIC
  packet and the same loss rate hits it much less often. With an MTU of 1500 the comparison is
  fair.

What the measurements changed (each found with `sample`, CPU times from `ps`, and counters):

- Both programs use a single-threaded runtime. With several threads every wake-up for a small
  chunk of output crossed threads, and the server used two cores for 47 MB/s; it now uses less
  than one core for 75.
- The client writes all output frames that are already waiting to the terminal in one write
  (up to 256 KiB). Each write goes through the blocking pool of tokio, and with frames of 2 KiB
  that cost 4.8 s of a 5.9 s transfer. Before this, the throughput also depended on the size of
  the replay buffer, because acknowledgements were sent only when the reader was empty.
- The frame reader looks at a frame without decoding it (`peek_server`), reads straight into its
  buffer (with `read_buf`, since the future is dropped by `select!`: a read into a buffer padded
  with zeros would leave the zeros behind), and drops used bytes once per read.
- The replay buffer reserves its memory once and copies blocks and not bytes. The tracker skips
  plain text without stepping through it.
- The QUIC endpoints ask the peer to acknowledge every eighth packet (ACK frequency extension)
  and not every second one, which saved about 10 percent on macOS and nothing for latency.
- The server lets QUIC hold unacknowledged output of at most twice the congestion window, and at
  least `live_backlog` (the window is read from QUIC every 50 ms; QUIC itself may hold 16 MiB).
  Without a limit QUIC took the output as fast as it came, up to the whole receive window of the
  client, so a slow link had megabytes queued below the buffer of the server. Nothing could be
  skipped or compressed there, and compression sent exactly as many bytes as no compression.
  A fixed limit of `live_backlog` was the ceiling of a link with jitter or a long round trip:
  with 1 MiB, 60 ms and some reordering the throughput stayed at 4.7 MB/s however fast the link.
- The client acknowledges its output once 64 KiB are behind, even when more frames wait; before,
  it did so only when the reader was empty, which a bulk transfer never is.

Nothing is gated yet.

#### Congestion control (`congestion`)

The default is `auto` (`ssj_net::adaptive`): a controller that holds a CUBIC and a BBR of
`quinn` (initial window 256 KiB each), feeds both with every event, and lets one send. It starts
with CUBIC. A loss (not an ECN mark) counts as random when the smoothed round-trip time is at most
15 percent above the lowest smoothed time of the last 30 seconds, plus 2 ms and the spread of
the round-trip time, so no queue has built up in front of it (the lowest time that ever was
measured is no floor on a path with jitter: it is one lucky sample far below the usual time). A
random loss is not passed on to CUBIC or to BBR: CUBIC that cut its window for it needed seconds
to grow back, and BBR went into recovery and fell to its smallest window. Four of them
within 10 seconds move the connection to BBR, and 30 seconds without any loss move it back (a
loss caused by a queue never moves it, since CUBIC is the fair one there). `congestion = "bbr"`
or `"cubic"` in either config file, or `--congestion`, forces one. The client
passes its value to the server it starts (`--congestion`), and each side uses it for what it sends
(output for the server, input for the client). `bench/bench.py --congestion` and
`SCENARIOS="lossy slow clean fast"` measured both in a Linux container with `tc netem` (MB/s of
the bulk output of `ssj` over UDP, one run each):

| Link | Cubic | BBR |
| --- | ---: | ---: |
| 1 % loss, 40 ms each way (MTU 1500) | 0.5 | 7.1 |
| 8 Mbit/s, 25 ms each way | 0.9 | 0.8 |
| 100 Mbit/s, 10 ms each way | 10.9 | 10.8 |
| 1 Gbit/s, 1 ms each way | 109.8 | 92.2 |
| loopback | 190 | 48 (and a 256 MB transfer did not finish in 300 s) |

Under loss the typing latency at the 95th percentile was 89 ms instead of 194 ms. On a clean link
there is no difference up to 100 Mbit/s. BBR of `quinn` loses 15 % at a gigabit and breaks down on
a loopback with a round trip of 50 microseconds, which is not a link a user roams on, and `ssj`
over the loopback is a test setup only. Choose `cubic` for such a network.

#### Start and end of a session

`bench/bench.py --startup 5 --netem "delay 50ms"` (a round trip of 100 ms, Linux container, `ssh`
as the base) times the start until the shell answers a command, and the end after `exit`:

| | ready | exit |
| --- | ---: | ---: |
| `ssh` | 1.34 s | 0.16 s |
| `ssj` UDP | 1.80 s | 0.27 s |
| `ssj` stdio (a second `ssh`) | 2.83 s | 0.16 s |

- With a login shell that takes 0.4 s to start (`STARTUP_RC_DELAY=0.4`), `ssh` needs 1.66 s and
  `ssj` over UDP 1.79 s, because the shell starts during the handshake and not after the `Hello`. Without a delay nothing
  changes (1.79 s against 1.35 s for `ssh`).
- The bootstrap is one `ssh`, and its handshake is most of the time. `ssj` adds a retry and the
  QUIC handshake (two round trips), then `Hello` and `Welcome` (one more), then the shell starts.
- The `ssh` channel opened a second `ssh` connection, which cost as much as the first; since 0.2.0 it
  reuses the `ssh` that started the server. The table is from before that.
- The login `ssh` starts before `ssh -G` is done, since the `SendEnv` patterns are needed only when
  the input is written after the login.
- Before this was measured, the end of a UDP session took two seconds: the server process ended
  before its close message left, and the client waited for an answer that never came. The server
  now waits for the close message to leave (at most one second, after the client has gone).
- `ssh -G` runs once, beside the login of the bootstrap, since the `SendEnv` patterns go with it; the
  `HostName` and the jump host come from the same answer. The lookup of the address for UDP runs
  while the bootstrap `ssh` runs, and no longer after it.

### Compression (`compress`)

Optional and off by default (`compress = "auto"` in `client.toml` or `server.toml`, or
`--compress auto`; the client passes its value to the server it starts). It exists for slow links:
a build log or a pasted text shrinks to a fifth or less.

- Both directions have a compressed frame: `Compressed` of the server for output and
  `Compressed` of the client for input. The body is a zstd frame of what the plain frame
  would hold, at most 32 KiB, and the offsets count the plain bytes. The algorithm is zstd
  at level 3 (the C library through the `zstd` crate; `ring` needs a C compiler anyway, and
  `cargo zigbuild` builds both). Each frame is compressed on its own, with no dictionary and no
  state from earlier frames, so a frame can be sent or left out and a new connection can start
  anywhere. The receiver is strict, because the bytes come from the other side: the frame must
  state its content size, the size may not exceed 32 KiB (checked before anything is allocated, so
  a bomb is refused from its header), the decoder window is limited to 128 KiB, and a frame that
  is not valid is a protocol violation.
- Why zstd 3 and no dictionary (measured on colored `ls -lR`, `git log -p`, `cargo` output,
  source, `ps`, and test logs; 32 KiB frames; Apple silicon): the packed size relative to the
  original is 26.0 percent for deflate level 1 (419 MB/s to compress, 578 to decompress), 20.1
  for deflate 6 (131, 715), 22.2 for zstd 1 (834, 2161), and 21.5 for zstd 3 (692, 2133). With
  frames of 4 KiB: 30.3 percent for deflate 1, 28.1 for zstd 3. A dictionary trained on the other
  files did not help (21.5 percent with a 64 KiB dictionary, at half the speed) and was worse for
  some kinds of output: terminal traffic is too varied for one built-in dictionary.
  Both sides always understand compressed frames; the setting only decides what a side sends.
- A side compresses a chunk only when at least 256 KiB are not acknowledged by the peer yet (the
  link is the limit; a link that keeps up has acknowledgements back before so much builds up), the
  chunk is at least 1 KiB (a terminal program gets at most 4 KiB per read on Linux), and the result
  is at least an eighth smaller. Typing stays plain because no backlog builds. The server counts what
  waits and what was sent without an acknowledgement of the client, the same for every transport.
  For QUIC the server also limits what the transport may hold unacknowledged to twice the
  congestion window, and at least `live_backlog` (1 MiB by default). Otherwise QUIC would take
  all output at once, up to the receive window of the
  client, and nothing would ever wait in the buffer of the server, where it can be compressed or
  skipped (this was found when `--compress auto` sent as many bytes as no compression). A fast link never
  pays the CPU time, and typing is never compressed, because a keystroke is a few bytes and no
  backlog builds.
- The risk: compressing text of an attacker together with a secret leaks the secret through the
  size of what is sent (CRIME and BREACH). The attacker must get chosen text into the same
  compressed frame as the secret, see the sizes on the network, and repeat that with other
  guesses. `ssj` limits this in four ways. Compression is opt-in. Typed input, which is where
  passwords are, is never compressed. A frame is compressed alone, so the guess and the secret
  must lie in the same 32 KiB, not anywhere in the session. And it applies only while the link is
  the limit. What remains: a large paste that contains both a secret and text from somebody else
  while the uplink is saturated, and command output that mixes a secret with text from somebody
  else, both seen by an observer who can make the user repeat it. `ssh -C` has the same exposure.
  Padding frames to a multiple of a block would blunt the size signal and is not done.

### Installation of the server

The server needs no root: it is one file in the home directory of the user.

Location and name:

- `$XDG_DATA_HOME/ssj/bin/ssj-server-p<N>` (default `~/.local/share/ssj/bin/`), where `N` is the
  protocol version, not the version of the binary. A host that serves clients of different
  protocol versions therefore has several files side by side, one per protocol, and each client
  uses its own.
- Installing a newer release with the same protocol replaces the file of that protocol by atomic
  rename, which does not disturb a running session, since the running process keeps its old file.
  `ssj install` prints the version it replaced; `--install` never replaces a file.
- The client starts the server by this absolute path and does not rely on `PATH`, because the
  `PATH` of a non-interactive `ssh` command often lacks `~/.local/bin`. `--server-path` overrides
  the location for servers installed elsewhere (for example by an administrator).
- A session stays on the protocol it was started with. After updating the client to a newer
  protocol, the old sessions are attached with an older client or ended. `ssj list` shows the
  protocol of each session, and the attach error says which release to use.
- The server files of older protocols stay on the host (`ssj-server-pN`, a few megabytes each);
  remove one by hand when no session runs on its protocol (`ssj list` shows the protocol of each).

Two ways to get it there:

1. Explicit: `ssj install user@host` uploads the matching binary.
1. On first use: when `ssj connect user@host` finds no server file for its protocol, the wrapper of the
   remote command reports `SSJ MISSING` with exit code 66, which the client tells apart from every
   other failure. What happens next follows the policy `auto_install`:
   - `ask` (default): on a terminal, the client asks `Install it now? [Y/n]`: Enter or `y`
     installs, and any other key, or a missing terminal, does not. Without a terminal there is nobody to ask, so nothing is installed and the message
     names `ssj install` and `--install`.
   - `always`: installs without asking. `never`: never installs and says how to do it by hand.
   - The flags `--install` and `--no-install` override the config file for one run.
   - `attach`, `list`, `kill`, and `detach` never install. Without a server there are no sessions.

How the upload works:

1. The client asks the host for its system (`uname -sm`, in a line of its own that must appear
   exactly once) and maps it to a build: Linux x86_64 and aarch64 get the static `musl` build,
   macOS arm64 gets the native one. Anything else is refused with a clear message.
1. The client takes the file named by `--server-binary`, whatever the build is. Without it, the
   client fetches `ssj-server-<build>` and `SHA256SUMS` over HTTPS from `--download-url`
   (default: `<repository>/releases/download/v<version>` with the repository named in
   `Cargo.toml`). The client never looks for a server file next to itself or in a directory.
   It uses `ureq` with `rustls`
   and `ring` and the root certificates of `webpki-roots`. Only `https://` addresses are taken,
   redirects must stay on HTTPS, a download may not exceed 64 MiB, and the file must match its
   line in `SHA256SUMS`, which the client checks before it uploads anything. The sums come from
   the same place as the file, so they catch damage and a wrong file and not a hostile server; the
   attestation of the release covers that.
1. It sends the SHA-256 digest of the file on the first line of stdin, followed by the file. The
   remote script writes to a temporary file (`umask 077`), computes the digest again with
   `sha256sum` or `shasum -a 256`, and compares. It then makes the file executable and runs
   `--version` on it, which catches `noexec` mounts. Only after both checks it moves the file into
   place by atomic rename. Any failure removes the temporary file.
1. The file name contains the protocol, so a present file is by definition the right one.

Trust in the server file:

- The digest that the client sends protects the transfer against damage and truncation. It does
  not protect against a swapped local file, since the client computes it from the same file that
  it uploads. The trust anchor is the file that the user names, or the release of the same version.
- A client could carry the digests of the server files of its release and refuse a different file.
  This was built and removed again: it needs the release pipeline to patch each client binary
  after the servers are built (and, on macOS, to sign it again), and it adds a crate and a tool for
  a protection that the checksums and the attestation of the release already give for the whole
  set of files.
- Checksums (`SHA256SUMS`) and a build provenance attestation are published with every release,
  see Supply chain. Verify the downloaded files against them before putting a server file next to
  the client.

Failure cases, each with a clear message:

- The directory is on a `noexec` mount. The client reports the directory and suggests
  `--server-path` or another `XDG_DATA_HOME`.
- The remote has no `sha256sum` or `shasum`. The install is refused, since it cannot be verified.
- No write permission or no space. The upload is deleted.
- The remote architecture is not in the list.

Security notes:

- Executing an uploaded file adds no privilege: it runs as the same user that `ssh` already gives
  a shell to.
- The digest check protects against corruption and a tampered download. It does not protect
  against a compromised release, so releases are published with checksums and artifact
  attestations (see Supply chain).
- The client never executes a downloaded binary locally and never installs anything on the local
  machine except through the normal installation of the client.

### Attach and restart

Cases by what restarts:

- Network change, sleep, or packet loss: the same connection or a reconnect continues the
  session, as described above.
- Client restart (crash, reboot, closed terminal): the session is still alive on the server, but
  the new client has a new ephemeral identity, so a plain reconnect fails the pinning check. The
  client re-attaches through `ssh`.
- Server process crash or host reboot: the shell is lost, since the PTY closes with the process.
  The only protection is to run the shell inside a multiplexer such as `tmux`. This is the same
  limit as in `mosh` and `et`.

Re-attach:

1. Each session has an ID and a control socket (mode `0600`, in the runtime directory). The
   server checks the peer credentials of every connection to the socket and accepts only its own
   uid.
1. The client runs `ssh user@host ssj-server --attach [ID]` and sends its new fingerprint on
   stdin, as in the normal bootstrap. Without an ID, it attaches to the only session, or fails
   and lists the sessions if there are several.
1. The `--attach` process connects to the control socket and asks the running server to replace
   the pinned client fingerprint. Authorization comes from `ssh`: only a process of the same user
   can reach the socket.
1. The server prints the `SSJ CONNECT` line again, with new ports and a new fingerprint. The old connection, if any, is
   closed with reason `replaced`.
1. After the handshake, the client sends its window size. On `Attach` the server makes the
   program redraw although the size is the same (`Action::Redraw`): it sets the window one column
   narrower, waits 60 ms so that the program sees that size, and sets the real size, so the
   program gets two `SIGWINCH`. A client that attaches has no history, since the server forgets
   output that the last client acknowledged, so without this the screen stays empty until the
   program prints. The server replays the unacknowledged tail of the output buffer.

If the session has no shell yet, because its first client never connected, `Attach` is answered
with `NotStarted` and the client sends `Start` instead, which also delivers its environment.

When `Attach` replaces the endpoint, the old one is closed first. Its UDP port stays busy until
QUIC has drained the connections, so the server waits for that and retries a busy port for up to
two seconds. Without this a narrow port range would refuse an immediate re-attach.

The client keeps the session ID and host in `$XDG_STATE_HOME/ssj/` as a hint. The ID is not a
secret. `ssj list user@host` shows the sessions of a host.

### Ending and leaving a session

Ending a session and leaving it are different actions, and only the first one ends the shell.

Ending (the session is over):

- The shell exits: `exit`, Ctrl-D on an empty line, or the shell dying from a signal. The server
  sends the exit status, the client prints nothing of its own and exits with the same code, and
  the server process ends. This is what a user expects from `ssh`. The server ends when the client
  confirms the status with `Close`. If the connection breaks without it, the status may not have
  arrived, so the session stays, sends the status again to the next connection, and ends when that
  client closes, or after `exit_grace` (60 seconds) without a client.
- `ssj kill user@host [ID]` ends a session from another terminal. The server sends `SIGHUP` to the
  process group of the shell, as a closing terminal would, and ends after the shell has exited.
- `SIGTERM` or `SIGINT` to the server process does the same as `ssj kill`.
- Closing the terminal window, or `SIGHUP` or `SIGTERM` to the client (`kill ssj`): inside an
  `ssh` session (`SSH_TTY` is set, `Params::hangup_detaches`) the client sends `Detach` and exits
  as after the detach key, since the end of that connection is more likely a loss than a wish. Otherwise the
  client sends `Hangup` and exits with code 129. The server hangs up the terminal of the shell, as a
  closing terminal would for `ssh`, and ends after the shell has exited. Without a connection
  (while the client is reconnecting) nothing can be told, and the session stays. The server
  never takes the loss of a connection for this, since it may come back.
- `SIGHUP` to the server process is ignored, because it is sent when the `ssh` channel of the
  bootstrap closes.

Leaving (the shell keeps running):

- A connection that is lost (a network change, a sleeping laptop, a client that is killed with
  `SIGKILL` or crashes) is an involuntary disconnect. The session survives, because surviving is
  the purpose of the tool, and the detached timeout applies. The server cannot tell these from a
  client that never returns, so `ssj list` and `ssj kill` clean up after a client that did.
- The detach key detaches on purpose: the client sends `Detach`, prints `[detached from session; it keeps running: ssj attach <DESTINATION>]`, and exits with code 0.
  The key works anywhere, also in the middle of a line or of a full-screen program
  (`--detach-key KEY` or `detach_key` in `client.toml`). It is a control byte, `ctrl-A` to
  `ctrl-Z` or `ctrl-\`, `ctrl-]`, `ctrl-^`, `ctrl-_` (also written `^]`), or `none`, which turns it
  off. The default is `ctrl-\`. The byte is not sent to the program. Tab and Enter (`ctrl-I`, `ctrl-J`,
  `ctrl-M`) are refused, and `ctrl-[` (Escape) is not accepted, since every line and key sequence
  uses them. Typed bytes before the key in the same read are sent first.
- The client prints two more lines, so that the start and the end of a session are visible
  without the message of the day of a login: `[started session <NAME> (<ID>) on <DESTINATION> over <TRANSPORT>]`
  once the first connection is up. The name and the brackets around the id are left out when the
  session has no name the user gave. The first word is `started` for a session that the server made for this client (its `CONNECT`
  line says `new`) and `attached to` for one that ran. The line goes in front of the output of the session,
  and `[disconnected from <DESTINATION>]` after the shell has ended. The first goes to the
  terminal in raw mode, ahead of the output of the session, and the second to the standard error
  output. These two appear only when the standard input is a terminal (the detach line appears
  always), and `-q` (`--quiet`) turns all three off. Errors are not affected, and a hangup prints
  nothing, since the terminal is gone.
- `ssj detach DESTINATION [ID...]` detaches the connected client from another terminal. It runs
  `ssj-server --detach [ID...]`, which sends `DETACH` on the control socket. The server answers
  `ERR no client is connected` when the state is not connected. Otherwise the session sends the
  frame `Detached` to the client, waits 300 ms so that the frame can leave before the
  endpoint is closed, and then does what `Detach` does. The client leaves with exit code 0 and
  the same message as after the detach key.
- `Detach` keeps the session running and **disables the detached timeout** until a client
  attaches again. The reason is intent: a user who detaches on purpose wants to come back later,
  for example to a long job, so the server must not end the shell behind their back. After the
  next attach, losing the connection involuntarily brings the timeout back.
- On `Detach` the server also closes its UDP endpoint and drops the pinned client fingerprint.
  The key of the client exists only in the memory of the client process, which has exited, so
  the pin could never match again anyway. A detached session therefore listens on no port. The
  next attach goes through `ssh`, as described under Attach and restart, and opens a new port
  with a new pin.
- An involuntary disconnect is different: the client may still be alive and reconnect, so the
  endpoint stays open until the detached timeout ends the session.
- This is not a vulnerability in either case. Only a holder of the pinned key can open a session,
  and the open port of an involuntary disconnect is limited to handshake attempts, which are
  bounded by retry and by the limits listed under Hardening requirements. What a session without
  timeout costs is a live shell in the background, such as resources and forgotten jobs.
  `ssj list user@host` shows all sessions with their state and age, and the server config can set
  `max_detached` as a hard upper limit even for deliberate detaches (default: none).

Frames: `Detach` is a client frame of its own. `Close` means that the client is done, for
example after it received the exit status, and a `Close` before the exit is treated as a lost
connection.

### Agent forwarding (`-A`)

Opt-in: `-A` / `--forward-agent` on the command line, or `forward_agent = true` in `client.toml`
(`--no-forward-agent` overrides the file). Without it nothing of the agent is offered, and the
server makes no socket. The client needs `SSH_AUTH_SOCK` and stops with a message if it is not set.

- `Hello::Start` carries a flag `agent`. When set, the server makes a socket
  `<control dir>/<session id>.agent` (mode 0600, in the private control directory) before it starts
  the shell and sets `SSH_AUTH_SOCK` for the shell to its path. The socket is removed when the
  session ends.
- A client that serves its agent sends the frame `AgentOffer` after each `Hello` (also `Resume` and
  `Attach`, which carry no flag). Only then does the server open channels. A program that connects
  while no connection offers the agent sees the socket closed at once.
- A connection of a program to the socket becomes a channel with a number chosen by the server:
  `AgentOpen(id)`, then `Agent(id, bytes)` in both directions, and `AgentClose(id)` from whoever
  sees its side end. The client connects to its agent on `AgentOpen`. Channel frames are not part of
  the offsets: they are not replayed, and all channels end with the connection. A program in the
  middle of a request gets an error and asks again after the reconnect.
- At most 32 channels are open at once, and each has a short queue, so a program that floods the
  socket loses its channel and nothing else.
- The client passes on only `REQUEST_IDENTITIES` and `SIGN_REQUEST`. Every other request (adding,
  removing, or locking keys, extensions) gets `SSH_AGENT_FAILURE` without reaching the agent. A
  stream that is not made of valid messages closes the channel. Keys that need an extension such
  as `session-bind@openssh.com` (destination constraints) do not work through the forwarding.
- The host never sees a private key, but anyone who can use the socket there (the user, and root)
  can have the agent sign while the session is connected, as with `ssh -A`. Keys added with
  `ssh-add -c` ask the user for each use.

### Surviving a server process restart (optional, later)

By default the shell is a child of `ssj-server` and ends with it. Two optional backends keep it
alive. Neither is part of v1.

Multiplexer backend (`--persist zellij` or `--persist tmux`):

- `ssj-server` starts the shell as `zellij attach --create ssj-<ID>` (or the `tmux` equivalent).
  The multiplexer has its own daemon, so the shell survives a crash or upgrade of `ssj-server`.
  Re-attach then reconnects to the multiplexer session.
- Zellij is used as an external program and not as a library. It is an application with its own
  client and server processes and no stable embedding interface.
- Cost: the multiplexer redraws the screen and keeps its own scrollback. This breaks the full
  scroll mode of the terminal (requirement 2), so the backend is opt-in and the UI of the
  multiplexer should be reduced to the minimum (no status bar, no pane frames).
- A host reboot still ends the session, since the multiplexer is gone too.

Holder backend (`--persist holder`), added as a second implementation of `Backend` with
`SURVIVES_SERVER_RESTART` set to true and a working `attach`:

- A small separate process `ssj-holder` owns the PTY and the shell. It does nothing except pass
  bytes between the PTY and a Unix socket, with no screen emulation, so native scrollback is
  kept.
- `ssj-server` connects to the holder as a client. A crash or upgrade of the network-facing
  server leaves the holder and the shell running, and the new server reconnects to it.
- The holder has no network code and a very small attack surface. It also keeps the replay
  buffer, so output produced while no server runs is not lost.
- Same limit: a host reboot ends the session.

Optional, later: on a binary upgrade the server re-executes itself and passes the PTY file
descriptor to the new process. This is a cheaper variant of the holder, for upgrades only and
not for crashes. Rebuilding a PTY from a file descriptor needs `unsafe` in `pty-process`
(`Pty::from_fd`), which `deny(unsafe_code)` rules out in our crates without a reason. The holder backend does
not have this problem, so it is preferred.

### Session core (server)

One task owns the state of a session: the shell, the output buffer, and the current connection.
Connections arrive as byte streams, so the logic does not depend on QUIC and is tested with
in-memory streams and real shells.

- A connection that sends nothing for 60 seconds, not even a ping, is given up like a lost one:
  the detached timeout starts, and the client resumes when it returns. QUIC alone would keep the
  connection of a vanished client for ever (no idle timeout), and the session would never count
  as detached.
- Reading the shell, writing to it, and talking to the client never wait for each other. The
  shell is split into reader, writer, and exit parts for this reason.
- The reader of a connection keeps parsing frames while the shell is busy. Acknowledgements of
  output travel in the same byte stream as the input and are what lets a chatty program
  continue, so holding them behind a blocked input frame is a deadlock (found by the paste
  test). Input is queued with a byte budget of 2 MiB per connection, which is above the 1 MiB
  that the client may leave unacknowledged. A client that sends more waits, and only it.
- While a client acknowledges its output, the shell is read only as far as the replay buffer has
  room, so a client that is slow cannot make the server buffer more than the capacity, and
  nothing is lost (backpressure as in `ssh`). Output while nobody listens works differently, see
  the next section.
- The client leaves in two ways (see Ending and leaving a session). `Detach` keeps the session
  and disables the detached timeout. A lost connection, or a `Close` before the exit, keeps the
  session with the timeout. The session ends when the shell has exited and the exit was queued for
  the client and the connection then ends. If the connection is lost right after the exit was
  queued but before it arrived, the client finds no server on its next attempt and reports the
  end of the session without the exit code.
- A new connection replaces the old one. Frames queued for the old one get five seconds to leave.

### Output while nobody listens

A session exists so that a long job (a build, a training run) goes on while the client is away.
Backpressure would defeat that: after one buffer full of output the shell would block in its
`write` until a client acknowledged something. So the server forgets the oldest output instead
whenever nobody is there to acknowledge it, which is the case when

- no client is connected (lost connection or deliberate detach), or
- (`slow_client = "wait"` only) a client is connected but has acknowledged nothing for `away_after` (10 seconds by default, set in `server.toml` or with `--away-after`) while the buffer
  stayed full. A connection can die without the server hearing of it (a laptop that sleeps), so
  silence with a full buffer counts as away.

### A slow connected client (`slow_client`)

The same reasoning holds for a client that is connected but slow: a job must not run at the speed
of the link, and the output that is queued for a slow link is what makes Ctrl-C feel late. So by
default (`slow_client = "drop"`) the server does not wait for a connected client either:

- The PTY is always read, and the output always goes into the replay buffer, which forgets its
  oldest bytes when it is full.
- For each connection the server keeps the offset up to which output was queued. When more than
  `live_backlog` bytes (1 MiB by default, 16 KiB to 64 MiB) were written since that offset, or when
  the buffer forgot bytes that were not sent yet, the offset moves forward and the skipped bytes
  are announced with `Gap(N)`, a server frame that tells the client to add N to its output
  offset. The connection stays open: nothing is resumed or reconnected.
- The offset moves to a character boundary: continuation bytes of UTF-8 at the new position are
  skipped as well.
- What lies before the offset at which the client joined (the replay for `Resume` and `Attach`) is
  not counted, so a client that comes back gets the replay at the speed of its link. Only output
  that the shell wrote afterwards is limited. If the client falls so far behind that more than
  `live_backlog` of the new output waits, the skip may also jump over the rest of the replay.
- The client handles `Gap(N)` like a gap after a reconnect: it takes back what it showed ahead
  of the server (local echo), adds N to its offset, writes the notice (CAN, color reset, the line
  `[ssj: N bytes of output were dropped]`), and acknowledges the new offset.
- `slow_client = "wait"` is the earlier behavior and the one of `ssh`: while a client is connected
  the server stops reading the PTY when the buffer is full, so nothing is lost and a slow link
  slows the job down. A client that acknowledges nothing for `away_after` (10 seconds) counts as
  away, because a connection can die unnoticed. In this mode a connection that is owed bytes that
  were forgotten is closed.

With `drop` the scrollback is complete only if the link keeps up with the job. Interactive use
and normal output are unaffected; a flood (`cat` of a large file) over a slow link is cut, with
the notice, instead of being delivered late.

Rules (nobody listens, and `wait` mode):

- The reading of the PTY never stops while nobody listens. The newest `replay_capacity` bytes are
  kept, and the start of the buffer moves forward by exactly the number of bytes that were lost.
- A connection that is still owed bytes that were forgotten is closed, since it cannot be served
  anymore. Its client resumes on a new connection.
- `Resume` with an offset before the start of the buffer is not an error. The `Welcome` carries the
  start of the buffer as its output offset, and the offset may only move forward. The client takes
  it over, and the difference is the number of bytes it missed.
- The client writes the notice into the output at that place: a CAN byte (it cancels an escape
  sequence the terminal may be in the middle of, since the rest of it was lost), the reset of
  colors and styles (`ESC [ 0 m`), and the line `[ssj: N bytes of output were dropped]`, with N
  exact. The notice comes from the client and not from the server, because bytes that the server
  inserted into the stream would shift the offsets of both sides.
- `Attach` is not affected: it replays everything the server still holds (the buffer is
  `replay_capacity` large, and output that a client acknowledged is gone), starting at a character
  boundary. The client begins the replay with CAN and the reset of colors, since it starts in the
  middle of the stream.
- The output of a job that nobody read is lost for good, as in `tmux` with a limited history. Setting
  `replay_capacity` higher keeps more of it, at the price of memory on the host.
- A `Resume` offset beyond the end of the output is still refused with `ReplayGap`.
- On macOS, the terminal driver can write a carriage return twice (`\r\r\n`) when the reader is
  slower than the writer. This is a property of that system and happens without `ssj` too, so the
  tests of exact byte streams turn the output processing of the terminal off (`stty -opost`).

### Running a command (`ssj connect DESTINATION -- COMMAND...`)

The session starts the command and not an interactive shell, and ends with its exit code.

- The client passes `--shell-arg -l --shell-arg -c --shell-arg <command>` to the server, so the
  login shell of the host (`--shell`, else `$SHELL`) runs `$SHELL -l -c '<command>'`, as `sshd`
  does for `ssh host command`. The words are joined with spaces and the shell of the host reads
  the result, so one quoted word is a whole shell command line.
- The command has a terminal like every session (the output of `ssh -t host command`): the
  session survives a lost connection, the command can be joined again with `ssj attach`, and the
  exit status is that of the shell.
- Where the command starts, as with `ssh`: the destination of `connect` is its first word that is
  not an option (or the value of one), and every word after it, options included, belongs to the
  command: `ssj connect host ls -l`, and `ssj connect host --name x` runs `--name x` on the host.
  A `--` directly after the destination is dropped, so `ssj connect host -- ls -l` works too.
  Options of `connect` stand before the destination.
- The other commands take their options before or after the destination
  (`ssj list host --json`), and only those that they read: any other, such as `--send-env` for
  `list`, is an error of `clap`. A setting for every connection belongs in `client.toml`.
- `ssj list` without a destination is an error that names it; `ssj edit` alone is the editor of
  `client.toml`.
- `--name` and `--auto-attach` are refused with a command, and the command is ignored by an
  `attach`, since the shell of a session that runs already is not started again.

### Editing the config files (`ssj edit`)

`ssj edit` edits `client.toml`, and `ssj edit [user@]host` edits `server.toml` on the host. The
word `edit` alone is the command (a host with that name is `ssj connect edit`, or `user@edit`); with a destination it
follows the rule of the other commands.

- The editor is `$EDITOR`, else `$VISUAL`, else `vi`, split into shell words (`dialoguer`, no shell
  runs) so that it may have arguments.
- The text is edited in a private temporary file (mode 0600, name `edit-<random>.toml`, made by `dialoguer`),
  which is removed at the end. A file that does not exist starts as a template with every setting
  as a comment. Both templates are generated by `confique` from the `Config` structs (doc comments
  and defaults): the client writes its own (`Config::template`), and for `server.toml` it asks the
  host with `ssj-server --config-template`. A test checks that every line is valid when it is
  switched on. A text that is unchanged is not saved.
- Validation happens at once after the editor ends and before anything is saved. The local file is
  parsed by the client (`Config::from_text`). The remote file goes to `ssj-server --check-config`
  on the host, which reads the text on stdin and prints `OK` or the first error with exit code 1,
  since only that server knows its keys (and the host may run another version than the client
  expects). An invalid text is shown with its error, and the user can edit again (default) or
  discard it. A missing server is reported with the hint to run `ssj install`.
- Saving writes a file next to the target (`.client.toml.<pid>` / `.server.toml.<pid>`, mode
  0600\) and renames it over the target. On the host a small `sh` script does that, with
  `umask 077`, and the server reads the file when a session starts, so running sessions keep their
  settings.
- Reading the current text of `server.toml` on the host is `cat` of
  `${XDG_CONFIG_HOME:-$HOME/.config}/ssj/server.toml` through `ssh`.
- Two editors at the same time must not lose each other's work, so a save is a compare and swap.
  The editor remembers the SHA-256 of the bytes it started from (of nothing, for a file that does
  not exist), and the file is replaced only if it still has that digest. Comparison and
  replacement are one step under a lock: a `flock` on `.client.toml.lock` here, and on the host a
  lock directory `.server.toml.lock` (`mkdir` is atomic; five tries one second apart, then the
  error names the directory, which can be removed if no editor runs; the script removes it when it
  ends, also when `ssh` hangs up). The lock is held for the save only, not while the editor is
  open, so a crashed editor leaves no stale lock, and the digest is what covers the long wait.
- If the file changed meanwhile, nothing is overwritten. The edited text is written to a private
  file `ssj-edit-kept-<pid>-<n>.toml` in the temporary directory, whose name the error shows, and
  the command ends with an error. Merging is by hand.

### Debug output (`-v`)

`-v`, `-vv`, and `-vvv` (`--verbose`, counted, at most three) switch on `log.rs`, and
`--log-file FILE` sends the lines to a file (append, mode 0600) instead of the standard error
output. A line is `[ssj <seconds since the start>s] <text>`; on a terminal it ends in `\r\n`, since
the terminal is in raw mode during a session. The `vlog!(level, ...)` macro does not format when
the level is off. The levels are described in the README. The pin and the content of the session
never appear in the output: frames are named by kind and size. The server writes no log.

### Local echo (`local_echo`)

Optional and off by default (`--local-echo auto`, or `local_echo = "auto"` in `client.toml`). It
lives in the client alone (`echo.rs`) and changes nothing on the wire. A typed character is drawn
faint at once and taken back before any byte of the server reaches the terminal, so the real echo
always draws over a clean place.

- Predicted: printable ASCII and characters that take one column in every terminal (`narrow`):
  Latin-1 and Latin Extended letters and signs (ä, ö, ü, ß, é, ñ), Greek, and Cyrillic. Not
  predicted: the no-break space, soft hyphen, combining marks, and wide characters (CJK, emoji),
  which stop the prediction until Enter. Input and output are decoded as UTF-8 even when a
  character arrives in pieces; invalid UTF-8 stops the prediction.
- Epoch rule: after Enter nothing is drawn until the server has echoed one typed character, so a
  password prompt is never drawn. The output must be the echo of what was typed apart from colors,
  titles, and a few mode switches; any other character or sequence drops the trust. A wide
  character in the output makes the column unknown until the next carriage return.
- Nothing is drawn within three columns of the right edge, in the middle of an escape sequence or
  of a character of the output, for a paste of more than 16 bytes, or when 64 predictions wait. A
  prediction that stays unanswered for two seconds is taken back.

### Environment forwarding

Works like `SendEnv` and `AcceptEnv` in `ssh`: the client selects variables, the server filters
them.

- Client: `ssj` sends what `ssh` sends, and `TERM`. The patterns (shell-style `*` and `?`) are:
  - the `SendEnv` of `ssh` for the destination, from its command line, `~/.ssh/config`, and the
    system files, read with `ssh -G` (2 seconds at most; an answer counts only with a `hostname`
    line). When `ssh` gives no answer (another command, an error), `LANG` and `LC_*` stand in for it, so that
    the host does not lose the locale. An answer without a `SendEnv` sends no locale, as `ssh` does;
  - `send_env` of `client.toml` (a list, empty by default), on top;
  - every `--send-env PATTERN` of the command line (repeatable), on top, as `-o SendEnv` is in
    `ssh`.
    `TERM` is always sent, as `ssh` sends it with the request for the terminal: a shell without it
    takes the terminal for a dumb one, and the prompt and the line editor draw wrongly.
- Server: the accepted names come from the server config file (`server.toml` in the config
  directory below, key `accept_env`), default: `TERM`, `LANG`, and `LC_*`. They are never taken
  from the command line that the client passes through `ssh`, since that would let the client
  override the filter. When the server drops variables that the client sent, it writes one line
  to the start of the output of the session, before the shell's output (`ssj: the host does not accept FOO, BAR (accept_env in its server.toml)`; six names at most, then "and N more"). The
  output is the one way to reach a client of any version, and a session that is joined later has
  the line in its replay.
- The variables travel in the session start frame inside the encrypted QUIC connection, never in
  the `ssh` bootstrap command.
- They are applied once, when the shell is created. After a reconnect the client does not resend
  them, because the running shell cannot change its environment.
- Validation on the server: names match `[A-Za-z_][A-Za-z0-9_]*`, values contain no NUL byte,
  and the limits are 64 variables, 256 bytes per name, 8 KiB per value, and 64 KiB in total. A
  violation rejects the whole set and the session start fails with a clear message.
- Loader and startup variables (`LD_*`, `DYLD_*`, `BASH_ENV`, `ENV`, `PROMPT_COMMAND`, and
  `SSH_*`) are never matched by a wildcard. They are accepted only when named exactly in
  `accept_env`.

The filter is protection against mistakes and unexpected variables, not a privilege boundary.
A client with the pinned key already has a full shell as the same user.

### Files and paths

Paths follow the XDG Base Directory specification, on Linux and on macOS alike.

- Config: `$XDG_CONFIG_HOME/ssj/` (default `~/.config/ssj/`), holding `server.toml` and
  `client.toml`.
- State: `$XDG_STATE_HOME/ssj/` (default `~/.local/state/ssj/`), holding the optional log file.
- A variable with a relative path is invalid and ignored, as the specification requires.
- Runtime: `$XDG_RUNTIME_DIR/ssj/` holds one control socket per session. macOS has no
  `XDG_RUNTIME_DIR`, so the fallback is `$XDG_STATE_HOME/ssj/run/<host>/`. The host name is in the
  path because a home directory can be shared by several hosts, and a socket of another host
  would look dead and be removed. A path that is too long for a socket (about 100 bytes) moves to
  `/tmp/ssj-<uid>/`. The directory must be owned by the user, must not be a symbolic link, and
  must not be accessible to others, or the server refuses to use it. The socket contains no
  secret, and it is removed when the session ends.
- Nothing is written to the cache directory. Session keys stay in memory.
- Created directories get mode `0700` and files mode `0600`. The server refuses to read a config
  file that is writable by group or others.

### Scrollback

Output bytes are written unchanged to the local terminal. No screen emulation on the client, so
scrollback, selection, and search of the terminal emulator work. The cost is that local echo
prediction as in `mosh` is out of scope.

## Security

- Authentication relies on the `ssh` bootstrap. No password or key handling in `ssj`. Every `ssh`
  the client starts gets `-e none`, so that a `~` in the data it sends is never an escape.
- Each session has its own ephemeral certificates on both sides. Nothing is stored on disk.
- No secret is printed or logged. Only certificate fingerprints cross the `ssh` channel.
- The server accepts one client per session and rejects every handshake that does not present
  the pinned client certificate. QUIC still answers unauthenticated packets (Initial packets and
  version negotiation), so the UDP port of a session is detectable by a scan. This reveals no
  secret, since the fingerprint is public, and the exposure is limited by the rules below.
- Replay and tampering protection come from the transport (TLS 1.3 / AEAD).
- Resource limits: bounded replay buffer, bounded packet sizes, and bounded handshake rate.
- Pinning is implemented in a custom `rustls` certificate verifier that compares the fingerprint
  and still verifies the handshake signature. A fingerprint comparison alone would let anyone who
  has seen the public certificate impersonate that side.
- TLS session resumption and 0-RTT are disabled, since 0-RTT data can be replayed.
- A maintained crate is preferred over code of our own where it does the same job. Dependencies
  are checked with `cargo audit` and `cargo deny` in CI.
- Fuzz the frame parser in `ssj-proto`.

## Hardening requirements

Network edge (server):

- Address validation by stateless retry for every new handshake, which removes spoofed-source
  floods and the amplification of the first flight (`Incoming::retry` in `quinn`). The cost is one
  round trip on the first connect only.
- Bounded handshake load: low `max_incoming` and incoming buffer sizes, and `refuse` or `ignore`
  for sources that fail handshakes repeatedly.
- Bounded streams and windows: explicit limits for concurrent streams, stream receive windows, and
  datagram size, set so that a peer cannot make the server buffer more than the replay buffer.
- ALPN `ssj/1` is required on both sides, so no other TLS or QUIC client can complete a handshake.
- One live connection per session. A newer authenticated connection replaces the older one.
- Large pastes: the initial congestion window is 256 KiB, so slow start does not cost several
  round trips. Measured at 100 ms round trip on localhost: 64 KiB in 0.08 s, 1 MiB in 0.34 s, and
  8 MiB in 1.2 s. The receive window of the server is 1 MiB per stream and 2 MiB per connection.

Input path (client):

- The client cuts input, such as a paste, into frames of at most 32 KiB. This is a courtesy to the
  stream and not the safety measure, since the server enforces the limits again on every frame.
- The unacknowledged input is kept in a bounded buffer (1 MiB by default). When it is full, the
  client stops reading from the terminal until the server acknowledges input, so a huge paste
  waits in the terminal and not in memory.
- Backpressure is chained: a full PTY blocks the server, which stops reading the stream, which
  fills the window of QUIC, which blocks the client.

Session and shell (server):

- The shell is the one of `--shell`, else `$SHELL`, which `sshd` sets to the login shell of the
  user from the password database. The client never selects the shell, the command, the
  environment, or the working directory (`--server-arg` runs as the user and is theirs to give).
- The shell starts with a clean environment. `SSH_*` and `XDG_SESSION_*` variables inherited
  from the bootstrap session are removed, because they describe a connection that no longer
  exists. The only variables the client can add are the ones allowed by the rules under
  Environment forwarding.
- Window size, frame lengths, and offsets are range checked. An offset outside the retained
  replay buffer closes the connection.
- While a client is connected and acknowledging, a full replay buffer stops the reading from the
  PTY (backpressure as in `ssh`) and no output is dropped. While nobody listens, the oldest output
  is forgotten instead (see Output while nobody listens), so that a detached job is never frozen.
- The server disables core dumps (`RLIMIT_CORE` 0). Private keys are not zeroed: both sides need
  their key for every reconnect until the session ends, and the copy inside the TLS library
  cannot be reached.
- Detach redirects stdio to `/dev/null`, so the `ssh` channel closes and its output cannot leak.
  The server ignores `SIGHUP` and calls `setsid`. Both server processes (the one `ssh` starts and
  the daemon) close every descriptor above 2 first thing, from the list in `/proc/self/fd` or
  `/dev/fd`, or by counting up to the limit of open files (at most 65536) when there is no list.
  This is the only place with `unsafe` in the workspace, and it is sound because nothing owns a descriptor
  yet. So neither the daemon nor the shell holds a socket or file of an unusual parent.
- Log output goes to stderr only until detach, and afterwards nowhere unless a log file in the state
  directory is configured. Terminal content is never logged.
- Port selection: random free port from the range, retried on conflict. On shared hosts the range
  is shared by all users, so exhaustion produces a clear error.

Bootstrap (client):

- The client starts `ssh` with an argument vector and never through a shell. A host argument that
  starts with `-` is rejected, to prevent option injection such as `-oProxyCommand`.
- `ssh` runs without a terminal, so output is not altered and stdin is not echoed.
- The client accepts exactly one line with a fixed prefix, `SSJ CONNECT <id> <udp:PORT|none> none <fingerprint> [new] [name=NAME] [socket=PATH]`, of
  bounded length, and ignores other output such as banners and `.bashrc` noise. Remote text is
  never printed to the terminal unfiltered, because it could contain escape sequences.
- The server reads the client fingerprint from stdin with a length limit and a timeout.
- The status line of the client (such as "reconnecting") is drawn by the client itself and never
  contains text from the server.

Supply chain:

- `Cargo.lock` is committed, and CI runs `cargo audit` and `cargo deny` on every push and weekly.
  `deny.toml` limits licenses and registries and bans `openssl`, `native-tls`, and `aws-lc`, so the
  crypto provider stays `ring`. `cargo geiger` was tried to track `unsafe` in dependencies but
  fails to read the current lockfile, so new dependencies are reviewed by hand instead.
- Release binaries get checksums and GitHub artifact attestations, because they run on remote
  hosts.
- The protocol version is part of the ALPN string (see Protocol version). Peers with different
  versions refuse each other with a clear message.

Inherent to any remote shell and not mitigated: terminal escape sequences in the output of the
remote host (title changes, clipboard writes through OSC 52). This is the same exposure as `ssh`.

## Threat model

Bootstrap phase (over `ssh`):

- The trust is that of `ssh`. An attacker who defeats the `ssh` host key check can swap the
  fingerprints and sit in the middle of the UDP session as well. `ssj` adds no new weakness here
  and cannot fix a wrong host key.

UDP phase:

- An attacker on the path cannot impersonate either side, because each side accepts only the
  pinned certificate of the other. They cannot read, modify, or replay traffic.
- They can drop, delay, or reorder packets, or inject junk that is rejected. This is a denial of
  service, and the reconnect and replay logic recovers once the path clears.
- They can observe metadata: IP addresses, UDP port, packet sizes, and timing. Typing patterns
  can leak, as with `ssh`.
- An off-path attacker cannot hijack a roaming connection, because a new path must prove
  possession of the session keys.
- A local user on the remote host can occupy a UDP port before the server binds it. The client
  then fails the pin check, so the effect is a denial of service only.

## Platforms

- Client: macOS (arm64 only) and Linux.
- Server: macOS (arm64 only) and Linux.
- Linux targets: glibc and musl, each on x86_64 and arm64 (four release binaries).
- macOS target: arm64 only (one release binary).
- Release binaries are cross-compiled with `cargo-zigbuild` (Linux targets) and built natively
  on macOS. Each target ships `ssj` and `ssj-server`.
- Automatic installs pick the build by the libc of the host. The probe that asks for the system
  (`uname -sm`) also asks `getconf GNU_LIBC_VERSION`: a Linux host with glibc 2.17 or newer gets the
  `gnu` build (linked by `zig` against glibc 2.17, `.2.17` in the release workflow), and every other
  Linux host (musl, an older glibc, no answer) gets the static `musl` build, which runs on any
  distribution. The hosts that match are nearly all of them; the choice is the `gnu` build because
  it is the native one there. Whether it is faster is not established: the work is network I/O and
  encryption, and `ring` brings its own assembly for the ciphers.
- Server code uses only portable POSIX calls (via `rustix`), so no Linux-only APIs such as
  `epoll` or `/proc` outside of optional, feature-gated code.

## Out of scope for v1

- Port forwarding and X11 forwarding.
- `sftp` or `scp` replacements.
- Windows client and server.

## Considered and not planned

- Skipping the QUIC retry for new clients: it costs one round trip, and skipping it would let a spoofed address amplify traffic up to three times.
- Larger UDP socket buffers: at 180 MB/s on a clean link the default buffer drops 0.9 percent of the datagrams, and throughput is on par with `ssh`. A request above `net.core.rmem_max` is clamped, and that equals the default (212992) on a stock Linux.
- Zeroing the private keys after the handshake: each side needs its key for every reconnect, and the key copy inside the TLS library cannot be reached from safe code.
- Offering two protocol versions in the ALPN list: against the decision to keep the code small.
- Power-state APIs for sleep and wake: they need a run loop or D-Bus for no gain, since waking always brings the interfaces back and fires the network watch.
- Extra OSCs sent by `ssj` itself (desktop notification, progress indicator, badge): kept out for now.
- `ControlMaster` for the second `ssh` of the stdio transport: a stale master socket after a network change hangs new `ssh` calls, which is what `ssj` exists to avoid.
- A server-side terminal emulator or `smcup` tracking: against the dumb-pipe rule. Full-screen programs are covered by the escape rule.
- Hole punching for hosts behind NAT: the `ssh` channel covers them.
- A standby connection with the session mirrored on it, a path probe, and staggered copies of the
  input (built for 0.2.0, about 1,500 lines): 24 outages per tree gave no faster recovery and two
  slow ones with it, against none without. Dropped; the spares of a stream cover the cases it was for.
- The transports `socket` (the control socket through `ssh -W`) and `tcp` (TLS through `ssh -W`):
  removed in 0.2.0. On a test host a stream through `ssh -W` and one through `ssh host ssj-server --stdio` both opened in 0.16 s, since `sshd` runs the command without the login files of the
  shell, so neither had an advantage. The line `SSJ CONNECT` still names the control socket
  (`socket=PATH`) and has a third field `none` where earlier servers wrote the TCP port.
- A manifest of server digests inside the client: built and removed again as too complex for what the release checksums and attestation already give.

## Decisions

- The detached timeout has no default. A lost client leaves a live shell behind, and `ssj list`
  and `ssj kill` are the tools to find and end it. A user who wants a limit sets
  `detached_timeout`.
- `ssj-server` runs as root with a warning on stderr (root is never needed, but refusing helps
  nobody who has a reason).
- The client CLI uses `clap`. The man page and the completions are made from the same `clap`
  command as the parser (`ssj-assets`), so they cannot drift from it.
- One protocol version per binary, with no backward compatibility. Old server files stay
  side by side (`ssj-server-p<N>`). Revisit at the first protocol bump.
