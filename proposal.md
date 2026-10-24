# Proposal: UDP on the flaky leg of a ProxyJump, and ssh as a drop-in

Status: draft, nothing here is implemented. Written against 0.2.0 (protocol 2).

Two ideas that share one piece of groundwork (a protocol 3 that is not tied to a pty):

1. **Relay through the first jump host**: the session speaks UDP (QUIC) across the
   flaky network to the first jump host, and ssh's stdio from there to the backend.
2. **`ssj ssh`, a drop-in for `ssh`**: raw (pty-less) sessions so that tools such as
   Zed, rsync and git get resumable connections.

## 1. Use case and problem

Typical setup:

```
laptop ---- flaky internet ----> VPS (jump) ---- clean link ----> backend
```

The backends only offer ssh. Today, when `ssh -G` reports a `ProxyJump`, ssj uses
the ssh stdio tier for the whole path, so the flaky leg is plain TCP inside ssh.
A short outage or a change of address then stalls the connection or kills it, which
is what the UDP tier avoids on a direct connection (roaming, QUIC loss recovery,
sub-second resume). We want UDP on the flaky leg only; the clean leg may stay on
ssh stdio.

### Goals

- A session to a backend behind one or more jumps survives outages and roaming on
  the first leg the same way a direct UDP session does.
- The jump host is not trusted with plaintext and holds no secrets that matter
  after the session ends.
- No change for direct hosts. If anything in the relay path fails, fall back to
  today's behaviour (ssh stdio through the jump).
- Only the first jump gets UDP. Further jumps stay inside the ssh stdio leg
  (`ssh -J rest backend`).

### Non-goals

- UDP on the clean leg, or TCP/socket transports (removed in 0.2.0).
- Relaying through hosts that have no `ssj-server`. They keep the current path.

## 2. Options considered

**A. Terminate at the jump (session on the jump).** The jump runs `ssh backend`
inside a pty session. Simple, but the backend credentials must be on the jump, the
jump sees everything, and the session lives on the wrong machine. Rejected.

**B. Stream relay.** QUIC from the client ends at the jump, which bridges the
session stream to `ssh backend ssj-server --stdio`. Reuses existing frames, but the
jump sees plaintext and has to be trusted like a shell on the backend. Possible as
an opt-in fallback, not the default.

**C. Opaque datagram relay (recommended).** The QUIC connection stays end to end
between client and backend, with the existing pinned mutual TLS. The jump only
forwards packets: UDP towards the client, length-framed datagrams inside an ssh
stdio stream towards the backend.

```
client quinn <-UDP+envelope-> jump relay <-datagrams in ssh stdio-> backend quinn
        \________________ one QUIC connection, end-to-end TLS ________________/
```

The jump never holds keys for the session, cannot read or modify it, and can only
drop it. The clean leg is a reliable stream, so nested loss recovery does not
matter there.

**D. Reverse leg.** The backend dials out to the jump. Removes the question of how
the jump authenticates to the backend, but needs outbound connectivity from the
backend and a listening port on the jump. Keep as a variant if the credential
question below has no good answer.

## 3. Design of C

### Bootstrap

1. Client runs `ssh -G backend`; a `proxyjump` with at least one hop selects the
   relay path (a `ProxyCommand` stays on the old path, since it can't be interpreted).
2. Two ssh invocations, started in parallel:
   - **To the backend through the jump** (as today, end-to-end authenticated):
     `ssj-server connect` prints the usual line with the backend's certificate
     fingerprint and token. This is the only source of trust for the pin.
   - **To the first jump:** `ssj-server relay --to backend` starts a per-session
     relay, opens a UDP port, and prints `SSJ RELAY <port> <relay-secret>`.
     The relay starts the leg with `ssh [-J rest] backend ssj-server stdio-datagrams`.
3. The client dials QUIC at `jump:port`. The relay forwards packets; the backend's
   certificate pin (from step 2, first ssh) authenticates the real peer.
4. If any step fails, or QUIC does not come up within the existing probe time, use
   the ssh stdio tier through the jump, as now. The held first ssh already makes
   this fallback free.

### Relay envelope

Every datagram between client and relay carries a small envelope:
`[session id 8][MAC 16][payload]`, keyed from a secret derived during bootstrap.

- The relay can tell sessions on one port apart and accept a client that roams to a
  new address, because it can verify the MAC without understanding QUIC.
- Spoofed packets are dropped, which also stops the relay from being used to
  redirect or amplify traffic.
- The overhead (24 bytes) is taken from the QUIC max datagram size, so the MTU
  stays the same as without the envelope.

### Which hop gets the relay

We do not assume the first jump is the only host reachable over UDP, but the first
hop is enough for the main case: the flaky part is the leg that crosses the
client's access network, which is always client to first hop. Later hops are
normally server to server on clean links, where UDP adds little and each extra
relay adds latency and a failure point.

A chain also does not prove that UDP is blocked: jumps are used for audit, policy
or authentication too. If the backend's UDP port is reachable, direct UDP to the
farthest reachable host beats a relay.

- **Version 1:** relay on the first hop only; everything beyond it stays an ssh leg
  (`ssh -J rest backend`).
- **Per-host setting** `relay = auto | first | last | none`, default `first`.
  `none` keeps today's ssh stdio, `last` uses the farthest hop that answers.
- **`auto` (later, only if a real chain needs it):** start the control ssh to each
  candidate hop in parallel and race the QUIC handshakes, then use the farthest hop
  that answers. This costs one extra ssh and one server process per hop, so it only
  makes sense for chains of two or three, and hops without `ssj-server` are skipped.
- ssh through the whole chain is used only for authentication, the certificate pin
  and the stdio fallback. The pin always comes from that end-to-end ssh, so it does
  not depend on which hop hosts the relay.

### Library work

- Client and backend need a custom `AsyncUdpSocket` for quinn (envelope on the
  client, length-framed datagrams over stdio on the backend). **To verify:** exact
  trait shape in the quinn version we use, and what is lost without GSO/GRO.
- `ssj-server relay` is a new, small mode: a UDP socket, an ssh child, and a loop
  copying between them, with its own idle timeout and session cap.
- `ssj-net` gets the wrapped sockets. `ssj-proto` is unaffected except for the
  new `SSJ RELAY` bootstrap line.

### Authentication of the clean leg (open question)

The relay's `ssh backend` needs credentials from the jump:

1. The jump's own `~/.ssh/config` and keys, if it has them (try this first).
2. Agent forwarding from the client: pass `-A` to the jump ssh when
   `forwardagent yes` is in `ssh -G`. The leg only needs the agent while it
   authenticates, which happens inside the 20 s hold window.
3. Variant D (reverse leg) if neither is acceptable.

If the leg breaks later and can't be rebuilt, the client's reconnect falls back to a
full bootstrap. The session itself lives on the backend and is not lost.

### Security notes

- The jump sees only ciphertext, packet sizes and timing.
- A malicious jump can drop or delay the connection. It cannot MITM, because the
  pin comes through the end-to-end ssh to the backend and never through the jump.
- The relay secret only authorizes forwarding to that session's backend.

## 4. Testing and measurement

- Docker topology client / flaky / jump / clean / backend, based on the existing
  train-link harness (`bench/`): outage recovery, keystroke latency under loss,
  roaming (address change mid-session), bulk throughput.
- Compare three configurations: ssh `-J` (reference), ssj stdio through the jump
  (today), ssj relay (this proposal). Success means the relay matches a direct
  UDP session on the first leg.
- Failure cases: no `ssj-server` on the jump, UDP blocked, leg authentication
  failing, jump restart mid-session, relay idle timeout.
- Fuzz the envelope parser.

## 5. Shared groundwork: protocol 3

Both ideas need the session layer to stop assuming a terminal.

- Channel ids on the output stream (stdout / stderr), EOF half-close and an
  exit-status frame.
- A per-session `pty` property. With `pty = true` everything stays as it is today
  (redraw on resume, escape tracking, local echo, status text, `slow_client = drop`).
  With `pty = false` there is none of that: bounded backpressure instead of
  dropping, and a resume that fails if the replay buffer can't cover the gap.
- Going from protocol 2 to 3 makes this 0.3.0. The existing outage and latency
  benchmarks must show no change on the pty path.

## 6. `ssj ssh`: drop-in for ssh

### Shape

- `ssj ssh [ssh options] host [command...]` is the explicit entry point.
- The same binary named `ssh` (argv[0]) behaves identically.
- `ssj dropin enable|disable` creates or removes `~/.local/bin/ssh -> ssj`.
- The real ssh is found by skipping ourselves in `PATH` (override: `SSJ_REAL_SSH`).
  The bootstrap always calls it by absolute path, and an env var guards loops.
- We do **not** embed an SSH implementation. Authentication, host keys, `-J`, `-F`,
  `ControlPath` and agents stay the real ssh's job.

### Dispatch

| Invocation | Handled by |
|---|---|
| no command, stdin is a tty, or `-t` | existing pty session |
| command, no tty | raw session (`pty = false`) |
| `-L -R -D -W -N -M -O -f -s -V -G -Q`, anything unparsed | `exec` real ssh unchanged |
| remote has no `ssj-server` | real ssh (see below) |

The bootstrap command is `command -v ssj-server && exec ssj-server ... || exec "$SHELL" -c '<cmd>'`,
with a random nonce on the hello line so the client can tell the two outcomes
apart. If there is no nonce, that first ssh is simply the plain connection and
nothing is lost. Installing the server stays explicit (`ssj install HOST`).

### Semantics to define

- **Hang instead of fail.** A normal ssh dies with the network; a resumable session
  waits. Non-interactive use needs a give-up time (from `ServerAliveInterval` x
  `ServerAliveCountMax` or `ConnectTimeout` when set, otherwise about 60 s), after
  which the exit status is 255 as ssh would give.
- **Exit status** passes through; signals map to 128+n.
- **stdin** belongs to the user's command; the bootstrap ssh must not read it.
- **Orphans:** a command whose client has gone away is reaped after a timeout.
- **Zed:** its own heartbeat (5 s x 5 misses) declares the connection dead after
  about 25 s, so ssj only hides outages shorter than that unless Zed's settings
  change. Check which ssh invocations Zed actually makes (ControlMaster, `-N`,
  `-O`) before promising anything.

## 7. Phases

1. Protocol 3 and a pty-less backend (`Pipes` implementing `Backend`), raw client
   front end, exit codes, tests (1 GB byte-exact `cat` through outages).
2. `ssj ssh` argument grammar, dispatch table, fallback, `ssj dropin`.
3. Relay: quinn custom sockets, envelope, `ssj-server relay`, bootstrap, fallback.
4. Benchmarks on the jump topology; docs (README, SPEC, "Considered and not planned").

Phases 1-2 and 3 are independent; 3 could ship first if the jump case matters more.

## 8. Open questions

- How should the jump authenticate to the backend: its own keys, agent forwarding, or
  a reverse leg?
- Silent fallback to plain ssh when the remote has no `ssj-server`, or warn once?
- Give-up default of about 60 s for non-interactive sessions?
- Does the jump host run `ssj-server` already (it must, for the relay)?
- Is `relay = first` the right default, or is `auto` needed for some of your chains?
