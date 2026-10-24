#!/usr/bin/env python3
# ruff: noqa: T201
"""Compares a host behind a jump host over a flaky link.

The clients are ssh -J, ssj over the ssh channel, and ssj with the relay (UDP to the jump host).

It runs in the client container of bench/docker-jump-bench.sh, which sets up the link. Each
client runs a command on the backend through the jump host, with no terminal:

- first connect: the time until the output of `echo ok` arrives, and for the relay the time until
  the session has moved to it (it starts on the ssh channel and moves when the leg is up);
- bulk from the start: `yes | head -c N`, with the login in the time, as a script would run it;
- bulk after idle: the same after `sleep`, timed from the first byte. The relay has taken over
  by then, so it carries all of it; ssh and ssj over the ssh channel have nothing to switch to
  and show the same test as a reference.

    bench/jump_bench.py --ssh-config /root/.ssh/config --ssj /target/release/ssj \
        --server /target/release/ssj-server [--bulk-mb 30] [--runs 3] [--json]
"""

from __future__ import annotations

import argparse
import json
import os
import re
import statistics
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

DESTINATION = "backend"
LINE = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
LOG_LINE = re.compile(r"\[ssj\s+([0-9.]+)s\] (.*)")
# how long a command may run; a client that hangs is killed, and its log is kept
LIMIT = 120.0
TIMEOUT_LOGS = "/tmp/jump-bench-timeouts"  # noqa: S108
# more than the leg takes to come up on the slowest link
SETTLE = 8


@dataclass
class Result:
    """What one run of a client gave."""

    first_byte: float | None
    total: float
    size: int
    status: int | None
    log: str


def command_line(client: str, args: argparse.Namespace, remote: str) -> list[str]:
    """The command line that runs `remote` on the backend with `client`."""
    ssh = f"ssh -F {args.ssh_config}"
    if client == "ssh":
        return [*ssh.split(), args.destination, remote]
    if client == "ssh_tty":
        # with a terminal, like ssj: the same pty on the backend
        return [*ssh.split(), "-tt", args.destination, remote]
    relay = "first" if client == "relay" else "none"
    return [
        args.ssj,
        "connect",
        "--ssh-command",
        ssh,
        "--server-path",
        args.server,
        "--relay",
        relay,
        # ssh delivers every byte, so ssj must too: with `drop` (the default) it skips output that a
        # slow client cannot take, which is right for a terminal and wrong for a transfer
        "--server-arg",
        "--slow-client",
        "--server-arg",
        args.slow_client,
        "-vv",
        args.destination,
        "--",
        remote,
    ]


def run(argv: list[str]) -> Result:
    """Runs a client without a terminal and times its output."""
    began = time.monotonic()
    child = subprocess.Popen(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if child.stdout is None or child.stderr is None:
        msg = "the pipes are not there"
        raise RuntimeError(msg)
    err: list[bytes] = []
    thread = threading.Thread(target=lambda: err.append(child.stderr.read()))  # type: ignore[union-attr]
    thread.start()
    timer = threading.Timer(LIMIT, child.kill)
    timer.start()
    first: float | None = None
    size = 0
    while True:
        chunk = os.read(child.stdout.fileno(), 1 << 20)
        if not chunk:
            break
        if first is None:
            first = time.monotonic() - began
        size += len(chunk)
    total = time.monotonic() - began
    status = child.wait()
    timer.cancel()
    thread.join()
    log = b"".join(err).decode(errors="replace")
    if total >= LIMIT:
        folder = Path(TIMEOUT_LOGS)
        folder.mkdir(parents=True, exist_ok=True)
        path = folder / f"{int(time.time())}.log"
        path.write_text(" ".join(argv) + "\n" + log)
        print(f"timed out after {LIMIT:.0f} s, log in {path}", file=sys.stderr)
    return Result(first, total, size, status, log)


def log_time(log: str, text: str) -> float | None:
    """The time in the log of ssj at which a line with `text` was written first."""
    for line in log.splitlines():
        found = LOG_LINE.match(line)
        if found and text in found.group(2):
            return float(found.group(1))
    return None


def median(values: list[float]) -> float | None:
    """The median, or `None` without values."""
    return statistics.median(values) if values else None


def first_connect(client: str, args: argparse.Namespace) -> dict[str, Any]:
    """The time to the first output, and for ssj the time until the relay carries the session."""
    arrived, switched = [], []
    for _ in range(args.runs * 2):
        result = run(command_line(client, args, "echo ok"))
        if result.first_byte is not None:
            arrived.append(result.first_byte)
    out: dict[str, Any] = {"output_s": median(arrived), "runs": len(arrived)}
    if client in ("stdio", "relay"):
        for _ in range(args.runs):
            result = run(command_line(client, args, f"sleep {SETTLE}; echo ok"))
            when = log_time(result.log, "session running over relay")
            if when is not None:
                switched.append(when)
        out["on_relay_s"] = median(switched)
        out["switched"] = f"{len(switched)}/{args.runs}"
    return out


def bulk(client: str, args: argparse.Namespace, wait: int) -> dict[str, Any]:
    """The speed of a large output, after `wait` seconds of idle."""
    size = args.bulk_mb * 1_000_000
    # random bytes by default: ssj compresses output that the link holds back, and text flatters it
    remote = f"yes {LINE} | head -c {size}" if args.text else f"head -c {size} /dev/urandom"
    if wait:
        remote = f"sleep {wait}; {remote}"
    speeds, totals = [], []
    for _ in range(args.runs):
        result = run(command_line(client, args, remote))
        # ssj skips output for a client that cannot keep up (`slow_client = drop`), so fewer
        # bytes than were sent can arrive; the rate counts what did
        if result.status != 0 or result.size == 0:
            continue
        totals.append(result.total)
        if result.first_byte is not None:
            span = result.total - result.first_byte
            speeds.append(result.size / max(span, 1e-6) / 1e6)
    return {
        "mb_s": median(speeds),
        "total_s": median(totals),
        "completed": f"{len(totals)}/{args.runs}",
    }


def main() -> None:
    """Runs every client and prints the table."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--ssh-config", required=True)
    parser.add_argument("--destination", default=DESTINATION)
    parser.add_argument("--ssj", required=True)
    parser.add_argument("--server", required=True)
    parser.add_argument("--bulk-mb", type=int, default=30)
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument(
        "--text", action="store_true", help="compressible output instead of random bytes"
    )
    parser.add_argument("--slow-client", default="wait", choices=["wait", "drop"])
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    results: dict[str, Any] = {}
    for client in ("ssh", "ssh_tty", "stdio", "relay"):
        results[client] = {
            "first": first_connect(client, args),
            "bulk_from_start": bulk(client, args, 0),
            "bulk_after_switch": bulk(client, args, SETTLE),
        }
    if args.json:
        json.dump(results, sys.stdout, indent=2)
        print()
        return
    names = {
        "ssh": "ssh -J",
        "ssh_tty": "ssh -tt -J",
        "stdio": "ssj, ssh channel",
        "relay": "ssj, relay",
    }

    def cell(value: float | None, unit: str = "s") -> str:
        return "-" if value is None else f"{value:.2f}{unit}"

    heads = (
        f"{'first output':>13} {'on relay':>9} {'bulk from start':>16} {'bulk after 8 s idle':>20}"
    )
    print(f"{'':20} {heads}")
    for client, name in names.items():
        r = results[client]
        print(
            f"{name:20} {cell(r['first']['output_s']):>13} "
            f"{cell(r['first'].get('on_relay_s')):>9} "
            f"{cell(r['bulk_from_start']['mb_s'], ' MB/s'):>16} "
            f"{cell(r['bulk_after_switch']['mb_s'], ' MB/s'):>20}"
        )
    print(
        "completed bulk runs (start / after idle): "
        + ", ".join(
            f"{names[c]} {results[c]['bulk_from_start']['completed']} / "
            f"{results[c]['bulk_after_switch']['completed']}"
            for c in names
        )
    )
    print(f"relay switched in {results['relay']['first'].get('switched')} runs")


if __name__ == "__main__":
    main()
