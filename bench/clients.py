"""The clients that bench.py measures, one entry each.

A client is a command line that starts an interactive shell on a pseudo terminal, so bench.py
treats ssh, mosh, et, tssh, and ssj alike. To measure another tool, add an entry to `CLIENTS`:
its name, a function that builds the command line, the executables it needs on this machine and
on the host, and whether it delivers every byte of output.
"""

from __future__ import annotations

import shlex
import shutil
import subprocess
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable


@dataclass(frozen=True)
class Options:
    """What the command line of a client may depend on."""

    host: str
    ssh_command: str
    ssj: str
    server: str
    congestion: str | None = None
    allow_drop: bool = False


@dataclass(frozen=True)
class Client:
    """One tool, in one mode, as a user starts it."""

    name: str
    about: str
    command: Callable[[Options], list[str]]
    # the executable on this machine; None is the ssj client (the --ssj option)
    local: str | None = None
    # executables that have to be on the host
    remote: tuple[str, ...] = ()
    # False for a tool that shows the latest screen and skips what went by in between (mosh), so
    # its bulk output rate says nothing about the transport
    delivers_every_byte: bool = True


def ssh(options: Options, *extra: str) -> list[str]:
    """`ssh` as the user runs it, on a terminal and without a question."""
    return [*shlex.split(options.ssh_command), "-tt", *extra, "-o", "BatchMode=yes", options.host]


def ssj(options: Options, *extra: str) -> list[str]:
    """The ssj client, with a path to its server file."""
    argv = [
        options.ssj,
        "connect",
        "--server-path",
        options.server,
        "--ssh-command",
        options.ssh_command,
        # a session that an earlier run left behind must not be joined, whatever client.toml says
        "--no-auto-attach",
    ]
    if not options.allow_drop:
        # every byte must arrive for the numbers to mean the same for every client
        argv += ["--server-arg", "--slow-client", "--server-arg", "wait"]
    if options.congestion:
        argv += ["--congestion", options.congestion]
    return [*argv, *extra, options.host]


def tssh(options: Options, *extra: str) -> list[str]:
    """The tssh client. It takes the options of `ssh`, so the ssh command's options carry over."""
    # the first word of the ssh command is `ssh` itself
    return [
        "tssh",
        *shlex.split(options.ssh_command)[1:],
        *extra,
        "-o",
        "BatchMode=yes",
        options.host,
    ]


def mosh(options: Options) -> list[str]:
    """mosh, without its local echo, which would answer a keystroke before the host does."""
    return [
        # mosh refuses a terminal that is not UTF-8, and a client without a TERM (a container)
        "env",
        "LC_ALL=C.UTF-8",
        "TERM=xterm-256color",
        "mosh",
        "--predict=never",
        f"--ssh={options.ssh_command} -o BatchMode=yes",
        options.host,
    ]


COMPRESS = ["--compress", "auto"]

CLIENTS: tuple[Client, ...] = (
    Client("ssh", "OpenSSH", ssh, local="ssh"),
    Client("ssh-C", "OpenSSH with compression", lambda o: ssh(o, "-C"), local="ssh"),
    Client("udp", "ssj over QUIC", lambda o: ssj(o, "--transport", "udp")),
    Client("udp-z", "ssj over QUIC, compressed", lambda o: ssj(o, *COMPRESS, "--transport", "udp")),
    Client("stdio", "ssj over the ssh channel", lambda o: ssj(o, "--transport", "stdio")),
    Client(
        "stdio-z",
        "ssj over the ssh channel, compressed",
        lambda o: ssj(o, *COMPRESS, "--transport", "stdio"),
    ),
    Client(
        "mosh",
        "mosh (state synchronization over UDP)",
        mosh,
        local="mosh",
        remote=("mosh-server",),
        delivers_every_byte=False,
    ),
    Client(
        "et",
        "Eternal Terminal (reconnecting TCP, etserver on port 2022)",
        lambda o: ["et", o.host],
        local="et",
        remote=("etserver",),
    ),
    Client("tssh-tcp", "tssh in its default TCP mode, as ssh", tssh, local="tssh"),
    Client(
        "tssh",
        "tssh in UDP mode, over QUIC (needs tsshd on the host)",
        lambda o: tssh(o, "--udp"),
        local="tssh",
        remote=("tsshd",),
    ),
    Client(
        "tssh-udp-over-tcp",
        "tssh in UDP mode with UdpProxyMode=TCP, for a host that blocks UDP (needs tsshd)",
        lambda o: tssh(o, "--udp", "-o", "UdpProxyMode=TCP"),
        local="tssh",
        remote=("tsshd",),
    ),
    Client(
        "tssh-kcp",
        "tssh in UDP mode, over KCP (needs tsshd on the host)",
        lambda o: tssh(o, "--udp", "--kcp"),
        local="tssh",
        remote=("tsshd",),
    ),
)

BY_NAME = {client.name: client for client in CLIENTS}


def tools_on_host(options: Options, names: Iterable[str]) -> set[str]:
    """Which of the executables `names` the host has on the path of a non-interactive login."""
    wanted = sorted(set(names))
    if not wanted:
        return set()
    script = f'for t in {" ".join(wanted)}; do command -v "$t" >/dev/null 2>&1 && echo "$t"; done'
    # `sh -c`, so that the login shell of the host (it may be fish) does not read the loop
    command = [
        *shlex.split(options.ssh_command),
        "-o",
        "BatchMode=yes",
        options.host,
        f"sh -c {shlex.quote(script)}",
    ]
    try:
        out = subprocess.run(
            command, capture_output=True, text=True, timeout=60, check=False
        ).stdout
    except (OSError, subprocess.TimeoutExpired):
        return set()
    return set(out.split())


def missing(client: Client, options: Options, on_host: set[str]) -> list[str]:
    """What the client lacks, in words. Empty if it can run."""
    lacks = []
    program = options.ssj if client.local is None else client.local
    if shutil.which(program) is None:
        lacks.append(f"{program} on this machine")
    lacks += [f"{tool} on {options.host}" for tool in client.remote if tool not in on_host]
    return lacks


def choose(
    names: list[str] | None, options: Options
) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    """The command lines of the clients to measure, and what the others lack.

    With `names`, exactly those (an unknown name is an error, a missing tool is reported). With
    None, every client that can run, so a machine without mosh or et measures the rest.
    """
    if names is None:
        picked = list(CLIENTS)
    else:
        unknown = [name for name in names if name not in BY_NAME]
        if unknown:
            raise SystemExit(f"unknown client {unknown}; known: {', '.join(BY_NAME)}")
        picked = [BY_NAME[name] for name in names]
    on_host = tools_on_host(options, (tool for client in picked for tool in client.remote))
    runnable, skipped = {}, {}
    for client in picked:
        lacks = missing(client, options, on_host)
        if lacks:
            skipped[client.name] = lacks
        else:
            runnable[client.name] = client.command(options)
    return runnable, skipped
