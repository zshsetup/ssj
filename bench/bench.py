#!/usr/bin/env python3
# ruff: noqa: T201
"""Compares remote shells: ssh, mosh, et, tssh, and ssj over UDP, TCP, and the ssh channel.

It measures bulk output, keystroke latency, and a large paste. Each client runs on a pseudo
terminal, as a user would run it, and nothing in the measurements knows which client it is: the
clients are the entries of bench/clients.py. Those that are not installed (here, or on the host)
are skipped with a message, and --only picks some by name. --list-clients shows them all.

    bench/bench.py --host me@localhost --ssj target/release/ssj \
        --server target/release/ssj-server [--netem "delay 40ms loss 1%"] [--json]

--train replaces the measurements with a ride on a train: the link loses packets in bursts all the
time (give it with --netem or NETEM=train of docker-bench.sh), and --outages seconds-long blackouts,
in which every packet is dropped in both directions while the interface stays up, are cut into the
typing. It reports the keystroke latency outside the outages and the time from the end of each
outage to the first echo. Blackouts need Linux, root, and iptables.

--roam replaces the measurements with the roaming of a phone that changes from one network to
another: the client's address changes (a second address is added to eth0 and the first is
removed), so a connection that is tied to the address is gone, and one that is not goes on. It
reports the time from each change to the first echo, and whether the session is the same one
afterwards (a counter that runs in the shell goes on) and how much of its output was lost.
Roaming needs Linux, root, and `ip`, and a container with sysctl
net.ipv4.conf.all.promote_secondaries=1 (bench/docker-bench.sh sets it).

--netem needs Linux and root (it runs `tc qdisc` on the loopback device) and applies to ssh and
ssj alike, so use it with --host localhost. Nothing is gated: the script prints numbers.
"""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import ipaddress
import itertools
import json
import os
import pty
import random
import re
import select
import statistics
import struct
import subprocess
import sys
import termios
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import clients as client_registry

if TYPE_CHECKING:
    from collections.abc import Sequence

MARK = "END" + "42"  # the command shows END$((6*7)), the output shows END42
# What is typed to measure an echo is not ASCII (two bytes of UTF-8 each): the escape sequences of
# a client that redraws the screen (mosh) contain ASCII letters and digits, and never these.
TYPED = tuple(letter.encode() for letter in "αβγδεζηθικλμνξοπρστυφχψω")


class Args(argparse.Namespace):
    """The command line, with the type of every option."""

    host: str
    ssj: str
    server: str
    ssh_command: str
    congestion: str | None
    only: str | None
    list_clients: bool
    text_bulk: bool
    allow_drop: bool
    bulk_mb: int
    raw_bulk: bool
    paste_mb: int
    samples: int
    jitter_ms: int
    rounds: int
    startup: int | None
    train: bool
    outages: str
    quiet: float
    roam: bool
    roams: int
    recovery_limit: float
    roam_wait: float
    netem: str | None
    json: bool


class Terminal:
    """A client process on a pseudo terminal."""

    def __init__(self, argv: Sequence[str]) -> None:
        """Starts `argv` on a new pseudo terminal."""
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            # a terminal of 24 lines and 80 columns; one with no size makes mosh abort
            fcntl.ioctl(0, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
            os.execvp(argv[0], list(argv))
        self.buffer = b""
        self.seen = b""
        # everything that was printed, if a measurement wants to look back at it
        self.record: bytearray | None = None
        # when the client started, and the keystrokes that took more than a second to echo, as
        # (seconds after the start, milliseconds): they can be found in the log of the client
        self.started = time.monotonic()
        self.slow: list[tuple[float, int]] = []

    def send(self, data: str | bytes) -> None:
        """Writes `data` to the terminal, and reads what the client prints meanwhile."""
        if isinstance(data, str):
            data = data.encode()
        view = memoryview(data)
        while view:
            # keep reading while writing, so that a full output queue cannot block the paste
            readable, writable, _ = select.select([self.fd], [self.fd], [], 5)
            if readable:
                self.read_some()
            if writable:
                view = view[os.write(self.fd, view[:65536]) :]

    def read_some(self) -> bytes:
        """Reads what the client printed, and answers a request for the cursor position."""
        try:
            chunk = os.read(self.fd, 1 << 20)
        except OSError:
            chunk = b""
        # a terminal answers a request for the cursor position, and busybox `ash` waits for it
        for _ in range(chunk.count(b"\x1b[6n")):
            os.write(self.fd, b"\x1b[24;80R")
        self.buffer += chunk
        self.seen = (self.seen + chunk)[-300:]
        if self.record is not None:
            self.record += chunk
        return chunk

    def wait_for(self, text: str, timeout: float = 300) -> int:
        """Reads until `text` is printed. Returns the number of bytes before it."""
        needle = text.encode()
        end = time.monotonic() + timeout
        total = 0
        while True:
            at = self.buffer.find(needle)
            if at >= 0:
                total += at
                self.buffer = self.buffer[at + len(needle) :]
                return total
            # keep a tail so that a marker across two reads is found
            keep = len(needle) - 1
            total += max(0, len(self.buffer) - keep)
            self.buffer = self.buffer[-keep:] if keep else b""
            if time.monotonic() > end:
                raise TimeoutError(f"no {text!r}, the last output was {self.seen[-300:]!r}")
            readable, _, _ = select.select([self.fd], [], [], 1)
            if readable and not self.read_some():
                raise EOFError(f"the client ended, the last output was {self.seen[-300:]!r}")

    def close(self) -> None:
        """Ends the shell, and waits for the client to end (or kills it)."""
        with contextlib.suppress(OSError):
            os.write(self.fd, b"\nexit\n")
        # a process cannot end while its output is queued on the terminal, so keep reading
        killed = False
        end = time.monotonic() + 5
        while True:
            done, _ = os.waitpid(self.pid, os.WNOHANG)
            if done:
                break
            if not killed and time.monotonic() > end:
                os.kill(self.pid, 9)
                killed = True
            readable, _, _ = select.select([self.fd], [], [], 0.05)
            if readable and not self.read_some():
                time.sleep(0.05)
        self.buffer = b""
        os.close(self.fd)


def session(argv: Sequence[str]) -> Terminal:
    """Starts a client and returns it when the shell answers."""
    terminal = Terminal(argv)
    # The shell is ready when it answers a command. A client that is not connected yet may drop
    # what is typed (et does), so the command is typed again until the shell answers.
    end = time.monotonic() + 60
    while True:
        terminal.send("echo READY$((6*7))\n")
        try:
            terminal.wait_for("READY42", min(5, max(0.1, end - time.monotonic())))
        except TimeoutError:
            if time.monotonic() > end:
                raise
        else:
            return terminal


TEXT_LINE = "2026-10-18 12:00:%02d INFO worker-%d handled request id=%d status=200 bytes=%d"


def bulk(
    argv: Sequence[str], megabytes: int, raw: bool = False, text: bool = False
) -> dict[str, Any]:
    """Seconds for the shell to print `megabytes` of output."""
    terminal = session(argv)
    if text:
        # lines like a log, which compress about the way build and server output does
        lines = megabytes * 1048576 // 80
        terminal.send(
            f"awk 'BEGIN {{ for (i = 0; i < {lines}; i++) "
            f'printf "{TEXT_LINE}\\n", i % 60, i % 8, (i * 7919) % 100000, (i * 31) % 5000 }}\''
            f"; echo {MARK[:3]}$((6*7))\n"
        )
    else:
        # `tr` makes text of the zeros, and it is slower than the transports on some systems, so
        # the numbers would show `tr`. With `raw` the zeros go to the terminal as they are.
        producer = "" if raw else " | tr '\\0' a"
        terminal.send(
            f"dd if=/dev/zero bs=1048576 count={megabytes} 2>/dev/null{producer};"
            f" echo {MARK[:3]}$((6*7))\n"
        )
    start = time.monotonic()
    terminal.wait_for(MARK)
    seconds = time.monotonic() - start
    terminal.close()
    return {"megabytes_per_second": round(megabytes / seconds, 1), "seconds": round(seconds, 2)}


def latency(argv: Sequence[str], samples: int, jitter_ms: int = 0) -> dict[str, Any]:
    """The time from a keystroke to its echo."""
    terminal = session(argv)
    terminal.send("stty raw -echo; cat\n")
    time.sleep(0.5)
    terminal.buffer = b""
    times = []
    for index in range(samples):
        byte = TYPED[index % len(TYPED)]
        start = time.monotonic()
        terminal.send(byte)
        while byte not in terminal.buffer:
            readable, _, _ = select.select([terminal.fd], [], [], 5)
            if not readable or not terminal.read_some():
                raise TimeoutError("no echo")
        times.append((time.monotonic() - start) * 1000)
        terminal.buffer = b""
        # a gap that varies, so that keystrokes meet the pings and acknowledgements at random
        time.sleep(0.01 + random.random() * jitter_ms / 1000)
    os.write(terminal.fd, b"\x04")
    terminal.close()
    times.sort()
    return {
        "median_ms": round(statistics.median(times), 2),
        "p95_ms": round(times[int(len(times) * 0.95) - 1], 2),
        "max_ms": round(times[-1], 2),
        "samples": samples,
        # echoes that took more than 10 ms over the median: a stall and not a slow link
        "stalls": sum(1 for t in times if t > statistics.median(times) + 10),
    }


def paste(argv: Sequence[str], megabytes: int, text: bool = False) -> dict[str, Any]:
    """Seconds for the shell to take `megabytes` of input."""
    terminal = session(argv)
    size = megabytes * 1048576
    terminal.send(f"stty raw -echo; head -c {size} > /dev/null; echo {MARK[:3]}$((6*7))\n")
    time.sleep(0.5)
    terminal.buffer = b""
    start = time.monotonic()
    if text:
        lines = [
            (TEXT_LINE % (i % 60, i % 8, (i * 7919) % 100000, (i * 31) % 5000)) + "\n"
            for i in range(size // 80 + 1)
        ]
        payload = "".join(lines).encode()[:size]
    else:
        payload = b"x" * size
    terminal.send(payload)
    terminal.wait_for(MARK)
    seconds = time.monotonic() - start
    terminal.close()
    return {"seconds": round(seconds, 2), "megabytes_per_second": round(megabytes / seconds, 1)}


def startup(argv: Sequence[str], runs: int) -> dict[str, Any]:
    """Seconds from starting the client until the shell answers a command, and until it is gone."""
    ready, ended = [], []
    for _ in range(runs):
        begin = time.monotonic()
        terminal = session(argv)
        ready.append(time.monotonic() - begin)
        begin = time.monotonic()
        terminal.close()
        ended.append(time.monotonic() - begin)
    return {
        "ready_s": round(statistics.median(ready), 2),
        "exit_s": round(statistics.median(ended), 2),
    }


def blackout(on: bool) -> None:
    """Drops every packet of eth0 in both directions, or lets them pass again.

    The interface and its address stay, as when a train enters a tunnel: nothing tells the
    programs that the network is gone.
    """
    action = "-I" if on else "-D"
    for chain, flag in (("INPUT", "-i"), ("OUTPUT", "-o")):
        subprocess.run(["iptables", "-w", action, chain, flag, "eth0", "-j", "DROP"], check=False)


def type_and_wait(terminal: Terminal, byte: bytes, timeout: float = 60) -> float | None:
    """Types a byte and returns the milliseconds until its echo, or None if none came."""
    start = time.monotonic()
    terminal.send(byte)
    while byte not in terminal.buffer:
        left = timeout - (time.monotonic() - start)
        if left <= 0:
            return None
        readable, _, _ = select.select([terminal.fd], [], [], min(left, 1))
        if readable and not terminal.read_some():
            return None
    terminal.buffer = b""
    return (time.monotonic() - start) * 1000


LETTERS = itertools.cycle(TYPED)
# the longest wait for a sign of life after a blackout or a change of the address
RECOVERY_LIMIT = 120
# two symbols that no status message and no letter of the typing contains
MARKER = "◆◇".encode()


def type_for(terminal: Terminal, seconds: float, times: list[float]) -> int:
    """Types at the pace of a person for `seconds`. Returns the number of lost echoes."""
    lost = 0
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        began = time.monotonic()
        took = type_and_wait(terminal, next(LETTERS))
        if took is None:
            lost += 1
        else:
            times.append(took)
            if took > SLOW_KEYSTROKE_MS:
                terminal.slow.append((round(began - terminal.started, 1), round(took)))
        time.sleep(0.05 + random.random() * 0.15)
    return lost


# seconds without an echo after which the marker is typed again (for clients that drop input)
RETYPE_AFTER = 3
# a keystroke that takes longer than this to echo is reported with its time
SLOW_KEYSTROKE_MS = 1000


def recovery_time(terminal: Terminal, limit: float) -> tuple[float | None, int]:
    """Types a marker and returns the seconds until its echo, or None if none came in `limit`.

    The marker is typed when the network is back, and its echo is the sign of life. Anything
    else the client prints meanwhile (a status in the window title) does not count. A client may
    drop what is typed while it reconnects (tssh does), so the marker is typed again every
    RETYPE_AFTER seconds; the second number is how many times that was needed. A client that holds
    what is typed (ssj must) never needs it: a retype for it is a recovery that took too long.
    """
    terminal.buffer = b""
    began = last = time.monotonic()
    retyped = 0
    terminal.send(MARKER)
    while time.monotonic() - began < limit:
        if MARKER in terminal.buffer:
            return round(time.monotonic() - began, 2), retyped
        if time.monotonic() - last > RETYPE_AFTER:
            terminal.send(MARKER)
            last = time.monotonic()
            retyped += 1
        readable, _, _ = select.select([terminal.fd], [], [], 0.2)
        if readable and not terminal.read_some():
            return None, retyped
    return None, retyped


def go_through_blackout(terminal: Terminal, seconds: int, limit: float) -> tuple[float | None, int]:
    """Types during a blackout, and returns the seconds from its end to the echo of a marker."""
    blackout(True)
    try:
        # the user goes on typing, and the keys wait in the client.
        for _ in range(3):
            terminal.send(next(LETTERS))
            time.sleep(seconds / 3)
    finally:
        blackout(False)
    return recovery_time(terminal, limit)


def train(
    argv: Sequence[str], outages: Sequence[int], quiet: float, limit: float
) -> dict[str, Any]:
    """Types for `quiet` seconds, then goes through a blackout, for each of the `outages`."""
    terminal = session(argv)
    terminal.send("stty raw -echo; cat\n")
    time.sleep(0.5)
    terminal.buffer = b""
    times: list[float] = []
    lost = 0
    recoveries: list[dict[str, Any]] = []
    for seconds in outages:
        lost += type_for(terminal, quiet, times)
        recovery, retyped = go_through_blackout(terminal, seconds, limit)
        recoveries.append({"outage_s": seconds, "recovery_s": recovery, "retyped": retyped})
        if recovery is None:
            break
        time.sleep(0.5)
        terminal.buffer = b""
    slow = terminal.slow
    terminal.close()
    times.sort()
    result: dict[str, Any] = {
        "outages": recoveries,
        "lost_echoes": lost,
        "samples": len(times),
        "slow_keystrokes": slow,
    }
    if times:
        result["median_ms"] = round(statistics.median(times), 2)
        result["p95_ms"] = round(times[max(0, int(len(times) * 0.95) - 1)], 2)
        result["max_ms"] = round(times[-1], 2)
    return result


def retyped_note(entry: dict[str, Any]) -> str:
    """Says that the marker had to be typed again: the client dropped what was typed."""
    return f" (retyped {entry['retyped']}x)" if entry.get("retyped") else ""


def print_slow(results: dict[str, Any]) -> None:
    """Prints the keystrokes that took more than a second, with the time they were typed."""
    for name, r in results.items():
        if r.get("slow_keystrokes"):
            keys = ", ".join(f"{ms} ms at {at}s" for at, ms in r["slow_keystrokes"])
            print(f"{name:9} slow keystrokes (seconds after the start of the client): {keys}")


def print_train(results: dict[str, Any]) -> None:
    """Prints the results of --train as a table."""
    print(
        f"{'':9} {'median ms':>10} {'p95 ms':>8} {'max ms':>8} {'lost':>5}"
        "  seconds from the end of an outage to the first echo"
    )
    for name, r in results.items():
        ends = "  ".join(
            f"{o['outage_s']}s: {'never' if o['recovery_s'] is None else o['recovery_s']}"
            f"{retyped_note(o)}"
            for o in r["outages"]
        )
        print(
            f"{name:9} {r.get('median_ms', '-'):>10} {r.get('p95_ms', '-'):>8}"
            f" {r.get('max_ms', '-'):>8} {r['lost_echoes']:>5}  {ends}"
        )
    print_slow(results)


# A counter in the background of the shell. After a change of the address it shows whether the
# session is the same one (the counter goes on, and a new shell has none) and what went by while the
# client was cut off. It stops by itself after ten minutes, for clients that leave the session
# running on the host. Only capital letters, digits, and a dot, so that the typing cannot be taken
# for it.
TICKER = "(i=0; while [ $i -lt 1200 ]; do i=$((i+1)); echo TICK$i.; sleep 0.5; done) &"
TICKS = re.compile(rb"TICK(\d+)\.")


def ticks(text: bytes | bytearray) -> list[int]:
    """The numbers of the counter that `text` contains."""
    return [int(number) for number in TICKS.findall(bytes(text))]


class Roamer:
    """Changes the address of a network device, as a phone does that joins another network.

    A second address of the same network is added, and then the first is removed: a connection
    that belongs to the first address is gone, and one that is tied to a key and not to an address
    can go on from the second. It changes the address of this machine, so it is only for a
    container (the Docker script sets the sysctl that the removal needs, and the file /.dockerenv
    is how the script knows it is in one).
    """

    def __init__(self, device: str = "eth0") -> None:
        """Finds the address of `device` and picks the one to move to."""
        if not Path("/.dockerenv").exists() and not os.environ.get("SSJ_BENCH_ROAM"):
            raise SystemExit(
                "--roam changes the address of eth0, so it runs in a container only"
                " (bench/docker-bench.sh); set SSJ_BENCH_ROAM=1 to run it here anyway"
            )
        self.device = device
        out = subprocess.run(
            ["ip", "-4", "-o", "addr", "show", "dev", device],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        found = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/(\d+)", out)
        if not found:
            raise SystemExit(f"{device} has no IPv4 address")
        self.current, self.prefix = found.group(1), found.group(2)
        network = ipaddress.ip_interface(f"{self.current}/{self.prefix}").network
        # an address of the same network that a container of a bridge does not get
        candidates = [network[-6], network[-7]]
        self.spare = str(next(a for a in candidates if str(a) != self.current))
        # the kernel promotes a second address if the setting of the device or of "all" is on
        if not any(
            Path(f"/proc/sys/net/ipv4/conf/{name}/promote_secondaries").read_text().strip() == "1"
            for name in ("all", device)
        ):
            raise SystemExit(
                "run the container with --sysctl net.ipv4.conf.all.promote_secondaries=1,"
                " or the second address goes with the first"
            )
        self.moves = 0

    def move(self) -> None:
        """Gives the device the other address."""
        for action, address in (("add", self.spare), ("del", self.current)):
            subprocess.run(
                ["ip", "addr", action, f"{address}/{self.prefix}", "dev", self.device], check=True
            )
        self.current, self.spare = self.spare, self.current
        self.moves += 1

    def restore(self) -> None:
        """Moves back to the address that the device had at the start."""
        if self.moves % 2:
            self.move()


def roam(argv: Sequence[str], roamer: Roamer, args: Args) -> dict[str, Any]:
    """Types for `quiet` seconds, then changes the address, `changes` times.

    With `wait`, the user types nothing for that long after a change: a client that is stuck by
    what is typed on a connection that is gone shows up as one that recovers after a wait.
    """
    changes, quiet, limit, wait = args.roams, args.quiet, args.recovery_limit, args.roam_wait
    terminal = session(argv)
    terminal.record = bytearray()
    terminal.send(f"stty raw -echo; {TICKER} cat\n")
    time.sleep(0.5)
    terminal.buffer = b""
    times: list[float] = []
    lost = 0
    moves: list[dict[str, Any]] = []
    for _ in range(changes):
        lost += type_for(terminal, quiet, times)
        before = ticks(terminal.record)
        roamer.move()
        mark = len(terminal.record)
        time.sleep(wait)
        recovery, retyped = recovery_time(terminal, limit)
        if recovery is not None:
            recovery = round(recovery + wait, 2)
        kept = None
        if recovery is not None:
            # the counter goes on if it is the same shell, and its numbers are higher
            end = time.monotonic() + 5
            while time.monotonic() < end and not ticks(terminal.record[mark:]):
                readable, _, _ = select.select([terminal.fd], [], [], 0.2)
                if readable and not terminal.read_some():
                    break
            kept = bool(before) and any(n > max(before) for n in ticks(terminal.record[mark:]))
        moves.append({"recovery_s": recovery, "kept_session": kept, "retyped": retyped})
        if recovery is None:
            break
        time.sleep(0.5)
        terminal.buffer = b""
    seen = sorted(set(ticks(terminal.record)))
    slow = terminal.slow
    terminal.close()
    times.sort()
    result: dict[str, Any] = {
        "changes": moves,
        "lost_echoes": lost,
        "samples": len(times),
        "slow_keystrokes": slow,
        # numbers of the counter that never arrived: output that the client did not replay
        "missed_ticks": seen[-1] - seen[0] + 1 - len(seen) if seen else None,
    }
    if times:
        result["median_ms"] = round(statistics.median(times), 2)
        result["p95_ms"] = round(times[max(0, int(len(times) * 0.95) - 1)], 2)
        result["max_ms"] = round(times[-1], 2)
    return result


def print_roam(results: dict[str, Any], lossy: set[str]) -> None:
    """Prints the results of --roam as a table."""
    print(
        f"{'':9} {'median ms':>10} {'p95 ms':>8} {'lost':>5} {'missed':>7}"
        "  seconds from a change of the address to the first echo (and: same session?)"
    )
    for name, r in results.items():
        ends = "  ".join(
            "never"
            if m["recovery_s"] is None
            else f"{m['recovery_s']}{' same' if m['kept_session'] else ' NEW'}{retyped_note(m)}"
            for m in r["changes"]
        )
        label = name + ("*" if name in lossy else "")
        missed = "-" if r["missed_ticks"] is None else r["missed_ticks"]
        print(
            f"{label:9} {r.get('median_ms', '-'):>10} {r.get('p95_ms', '-'):>8}"
            f" {r['lost_echoes']:>5} {missed:>7}  {ends}"
        )
    print_slow(results)


def netem(args: Args, action: str) -> None:
    """Adds or removes the simulated link on the loopback device."""
    if not args.netem:
        return
    command = ["tc", "qdisc", action, "dev", "lo", "root"]
    if action == "add":
        command += ["netem", *args.netem.split()]
    # root (a container) needs no sudo
    prefix = [] if os.geteuid() == 0 else ["sudo", "-n"]
    subprocess.run(prefix + command, check=False)


def measure(argv: Sequence[str], args: Args, roamer: Roamer | None) -> dict[str, Any]:
    """Runs the measurements that the options ask for on one client."""
    if args.startup:
        return startup(argv, args.startup)
    if roamer:
        return roam(argv, roamer, args)
    if args.train:
        outages = [int(part) for part in args.outages.split(",")]
        return train(argv, outages, args.quiet, args.recovery_limit)
    rounds = [bulk(argv, args.bulk_mb, args.raw_bulk, args.text_bulk) for _ in range(args.rounds)]
    pastes = [paste(argv, args.paste_mb, args.text_bulk) for _ in range(args.rounds)]
    return {
        "bulk": max(rounds, key=lambda r: r["megabytes_per_second"]),
        "latency": latency(argv, args.samples, args.jitter_ms),
        "paste": max(pastes, key=lambda r: r["megabytes_per_second"]),
    }


def parse_args() -> Args:
    """Reads the command line."""
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--host", default="localhost")
    parser.add_argument("--ssj", default="target/release/ssj")
    parser.add_argument("--server", default="target/release/ssj-server")
    parser.add_argument("--ssh-command", default="ssh")
    parser.add_argument("--congestion", choices=["bbr", "cubic"], help="for ssj (default: its own)")
    parser.add_argument(
        "--only",
        help="clients to measure, comma separated (default: all that are installed;"
        " see --list-clients)",
    )
    parser.add_argument(
        "--list-clients", action="store_true", help="show the clients and what each one lacks"
    )
    parser.add_argument("--text-bulk", action="store_true", help="log-like text for bulk and paste")
    parser.add_argument(
        "--allow-drop", action="store_true", help="let ssj skip output on a slow link"
    )
    parser.add_argument("--bulk-mb", type=int, default=256)
    parser.add_argument("--raw-bulk", action="store_true", help="bulk output without tr")
    parser.add_argument("--paste-mb", type=int, default=8)
    parser.add_argument("--samples", type=int, default=300)
    parser.add_argument(
        "--jitter-ms", type=int, default=0, help="random extra gap between keystrokes"
    )
    parser.add_argument(
        "--rounds", type=int, default=3, help="the best bulk and paste round counts"
    )
    parser.add_argument(
        "--startup", type=int, metavar="RUNS", help="only time the start and the end, RUNS times"
    )
    parser.add_argument("--train", action="store_true", help="a ride with blackouts (see above)")
    parser.add_argument(
        "--outages", default="5,15", help="seconds of the blackouts of --train, comma separated"
    )
    parser.add_argument(
        "--quiet", type=float, default=10, help="seconds of typing before each blackout"
    )
    parser.add_argument(
        "--roam", action="store_true", help="a change of the client's address (see above)"
    )
    parser.add_argument("--roams", type=int, default=2, help="changes of the address of --roam")
    parser.add_argument(
        "--roam-wait",
        type=float,
        default=0,
        help="seconds without typing after each change of --roam (default: type at once)",
    )
    parser.add_argument(
        "--recovery-limit",
        type=float,
        default=RECOVERY_LIMIT,
        help="seconds to wait for an echo after a blackout or a change (default: %(default)s)",
    )
    parser.add_argument("--netem", help='for example "delay 40ms loss 1%%" (Linux, root)')
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(namespace=Args())
    args.ssj = str(Path(args.ssj).resolve())
    # a path on the host (`~/...`) stays as it is; a local file is made absolute
    if Path(args.server).exists():
        args.server = str(Path(args.server).resolve())
    return args


def main() -> None:
    """Runs the measurements and prints them."""
    args = parse_args()
    options = client_registry.Options(
        host=args.host,
        ssh_command=args.ssh_command,
        ssj=args.ssj,
        server=args.server,
        congestion=args.congestion,
        allow_drop=args.allow_drop,
    )
    if args.list_clients:
        runnable, skipped = client_registry.choose(None, options)
        for client in client_registry.CLIENTS:
            state = "ok" if client.name in runnable else "lacks " + ", ".join(skipped[client.name])
            print(f"{client.name:9} {client.about}\n{'':9} {state}")
        return
    names = args.only.split(",") if args.only else None
    chosen, skipped = client_registry.choose(names, options)
    for name, lacks in skipped.items():
        print(f"{name}: skipped, lacks {', '.join(lacks)}", file=sys.stderr)
    if not chosen:
        raise SystemExit("no client to measure")
    lossy = {c.name for c in client_registry.CLIENTS if not c.delivers_every_byte}
    roamer = Roamer() if args.roam else None
    results = {}
    netem(args, "add")
    try:
        for name, argv in chosen.items():
            print(f"{name} ...", file=sys.stderr)
            try:
                results[name] = measure(argv, args, roamer)
            except (EOFError, TimeoutError, OSError) as error:
                # one client that fails does not take the numbers of the others with it
                print(f"{name}: failed: {error}", file=sys.stderr)
                results[name] = {"error": str(error)}
    finally:
        netem(args, "del")
        if roamer:
            roamer.restore()
    report(results, args, lossy)


def report(results: dict[str, Any], args: Args, lossy: set[str]) -> None:
    """Prints the results as JSON or as the table of the measurement."""
    if args.json:
        print(json.dumps(results, indent=2))
        return
    for name in [name for name, r in results.items() if "error" in r]:
        print(f"{name:9} failed: {results.pop(name)['error'][:150]}")
    if args.startup:
        print(f"{'':9} {'ready s':>8} {'exit s':>8}")
        for name, r in results.items():
            print(f"{name:9} {r['ready_s']:>8} {r['exit_s']:>8}")
        return
    if args.roam:
        print_roam(results, lossy)
        return
    if args.train:
        print_train(results)
        return
    print(
        f"{'':9} {'bulk MB/s':>10} {'median ms':>10} {'p95 ms':>8} {'max ms':>8}"
        f" {'stalls':>7} {'paste s':>8}"
    )
    for name, r in results.items():
        label = name + ("*" if name in lossy else "")
        print(
            f"{label:9} {r['bulk']['megabytes_per_second']:>10} {r['latency']['median_ms']:>10}"
            f" {r['latency']['p95_ms']:>8} {r['latency']['max_ms']:>8} {r['latency']['stalls']:>7}"
            f" {r['paste']['seconds']:>8}"
        )
    if lossy & set(results):
        print(
            "* shows the latest screen and skips output in between: its bulk rate is not a transfer"
        )


if __name__ == "__main__":
    main()
