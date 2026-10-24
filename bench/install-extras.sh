#!/bin/sh
# Installs the other remote shells that bench/bench.py can measure, in a container of
# bench/docker-bench.sh (Debian or Ubuntu, as root). It runs in the client and in the server
# container, and installs both halves of each tool.
#
#   EXTRA="mosh et tssh" sh bench/install-extras.sh [server]
#
# EXTRA lists the tools; `server` also starts the daemon that a tool needs (etserver). A tool that
# does not install is reported on stderr and left out: bench.py skips a client that is missing.
#
# - mosh: the package (mosh-server needs UDP ports 60000-61000 between the two containers).
# - et: the PPA of the project, which has builds for amd64 and arm64.
# - tssh: the release archives of tssh and tsshd (tssh --udp needs tsshd on the host).
set -u

EXTRA=${EXTRA:-}
[ -n "$EXTRA" ] || exit 0

quiet() { "$@" >/dev/null 2>&1; }

install_mosh() {
    quiet apt-get install -y -qq mosh
}

install_et() {
    quiet apt-get install -y -qq software-properties-common &&
        quiet add-apt-repository -y ppa:jgmath2000/et &&
        quiet apt-get update -qq &&
        quiet apt-get install -y -qq et
}

# prints the latest release tag of a GitHub repository, such as v0.1.26
latest() {
    curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/$1/releases/latest" |
        sed 's|.*/tag/||'
}

install_release() { # repository, program
    arch=$(uname -m)
    tag=$(latest "$1") || return 1
    work=$(mktemp -d)
    curl -fsSL "https://github.com/$1/releases/download/$tag/$2_${tag#v}_linux_$arch.tar.gz" |
        tar xz -C "$work" &&
        find "$work" -type f -name "$2" -exec install -m 755 {} /usr/local/bin/ \;
    status=$?
    rm -rf "$work"
    return $status
}

install_tssh() {
    install_release trzsz/trzsz-ssh tssh && install_release trzsz/tsshd tsshd
}

# curl is how the archives come, and ca-certificates is what makes https work
case " $EXTRA " in
*" tssh "*) quiet apt-get install -y -qq curl ca-certificates ;;
esac

for tool in $EXTRA; do
    case $tool in
    mosh | et | tssh) "install_$tool" || echo "bench: $tool did not install" >&2 ;;
    *) echo "bench: unknown tool $tool (mosh, et, tssh)" >&2 ;;
    esac
done

if [ "${1:-}" = server ] && command -v etserver >/dev/null 2>&1; then
    etserver >/tmp/etserver.log 2>&1 &
fi
exit 0
