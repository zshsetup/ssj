#!/bin/sh
# shellcheck disable=SC2016,SC2329
# (the commands for the containers are built in single quotes on purpose, and `cleanup` runs from
# the trap)
# Runs bench/bench.py between two containers, a client and a server, on one docker network.
#
# The link is simulated on the network interfaces of the two containers, so only the traffic
# between them is delayed or dropped. On the loopback (bench/linux-bench.sh) the TCP transport
# crosses the simulated link twice, since the hop from sshd to the server port is on the
# loopback too, and its numbers are not those of a real host.
#
#   bench/docker-bench.sh [bench.py arguments]
#
#   NETEM="delay 40ms loss 1%"    the link; empty for none; `train` is a ride on a train: delay with
#                                 jitter and bursts of loss (about 4 percent in all). With
#                                 `--train` bench.py adds blackouts, in which every packet is
#                                 dropped for some seconds
#   IMAGE=ubuntu:24.04            the system of both containers (the version of sshd matters)
#   BUILD=1                       build the static musl binaries first (default), 0 to reuse
#   CLIENT=host                   run the client on this machine and not in a container: the Mac or
#                                 Linux machine you sit at, with its own TCP stack, against the
#                                 server container behind a published port. UDP cannot reach the
#                                 container, so use --only ssh,stdio. The link (NETEM) then
#                                 delays only what the server sends, so leave it empty.
#   TARGET_VOLUME=ssj-target-musl the docker volume with release/ssj-server (and release/ssj for
#                                 the container client); another one holds another build
#   CLIENT_BIN=target/release/ssj the client of CLIENT=host
#   CAPTURE=1                     record the hop from sshd to the server port on the server's
#                                 loopback and print its last packets (for TCP stalls)
#   CLIENT_LOG=1                  run the client with -vvv and print the lines of its log (the
#                                 frames, with times) into target/ssj-client-log.txt
#   PROBE=1                       no ssj: measure what `ssh -W` does to two small writes in a row
#                                 (bench/wprobe.py), at several gaps
#   CPUS=1                        limit each container to this many CPUs (a small cloud machine)
#   SERVER_SYSCTL=net.ipv4.tcp_congestion_control=bbr
#                                 sysctl of the server container (the sender of the output, so the
#                                 congestion control of the TCP that `ssh` carries)
#   UDPSTAT=1                     print the UDP counters of the client container before and after
#                                 (RcvbufErrors counts datagrams that a full socket buffer dropped)
#   TRACE=1                       print the socket options that sshd sets (TCP_NODELAY and such)
#   EXTRA="mosh et tssh"          also install these tools in both containers (bench/install-extras.sh)
#                                 so that bench.py measures them next to ssh and ssj. Without it the
#                                 containers have only ssh, and bench.py skips the other clients.
#
# Roaming (a change of the address of the client container, which needs this script):
#   bench/docker-bench.sh --roam --only ssh,udp,stdio,mosh,et,tssh
# The client container runs with net.ipv4.conf.all.promote_secondaries=1, so that removing its first
# address leaves the second.
#
# Examples: NETEM=train bench/docker-bench.sh --train --outages 5,15 --only ssh,udp,stdio
#           bench/docker-bench.sh --raw-bulk --bulk-mb 64 --samples 100
#           NETEM="delay 20ms" bench/docker-bench.sh --only ssh,udp,stdio --json
set -e
cd "$(dirname "$0")/.."
IMAGE=${IMAGE:-ubuntu:24.04}
NETEM=${NETEM-delay 40ms loss 1%}
[ "$NETEM" = train ] && NETEM='delay 80ms 40ms loss gemodel 1% 20% 70% 0.5%'
BUILD=${BUILD:-1}
CAPTURE=${CAPTURE:-0}
TRACE=${TRACE:-0}
UDPSTAT=${UDPSTAT:-0}
CPUS=${CPUS:-}
SERVER_SYSCTL=${SERVER_SYSCTL:-}
cpu_args=
server_args=
[ -n "$SERVER_SYSCTL" ] && server_args="--sysctl $SERVER_SYSCTL"
[ -n "$CPUS" ] && cpu_args="--cpus $CPUS"
CLIENT_LOG=${CLIENT_LOG:-0}
PROBE=${PROBE:-0}
EXTRA=${EXTRA:-}
CLIENT=${CLIENT:-container}
TARGET_VOLUME=${TARGET_VOLUME:-ssj-target-musl}
CLIENT_BIN=${CLIENT_BIN:-target/release/ssj}
name=ssjbench-$$
# inside the checkout, since docker on a Mac or under colima only shares some directories
mkdir -p target
keys=$(mktemp -d "$PWD/target/ssjbench-keys.XXXXXX")

cleanup() {
    docker rm -f "$name-server" >/dev/null 2>&1 || true
    docker network rm "$name" >/dev/null 2>&1 || true
    rm -rf "$keys"
}
trap cleanup EXIT INT TERM

if [ "$BUILD" = 1 ]; then
    # static binaries run on any image, whatever its libc
    docker run --rm -v "$PWD":/src:ro -v "$TARGET_VOLUME":/target -e CARGO_TARGET_DIR=/target \
        -w /src rust:alpine sh -c \
        'apk add --no-cache musl-dev gcc >/dev/null && cargo build --release -p ssj-client -p ssj-server 2>&1 | tail -1'
fi

ssh-keygen -q -t ed25519 -N "" -f "$keys/id"
docker network create "$name" >/dev/null

# the simulated link on the egress of an interface; offloads are off, so that the loss hits
# packets of the size of a real link and not segments of 64 KiB
link='
if [ -n "$NETEM" ]; then
    ethtool -K eth0 tso off gso off gro off >/dev/null 2>&1 || true
    tc qdisc add dev eth0 root netem $NETEM
fi'
install='apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq iproute2 ethtool openssh-server openssh-client python3 tcpdump strace iptables >/dev/null 2>&1'
capture=
probe_servers=
if [ "$PROBE" = 1 ]; then
    probe_servers='for v in "5551 60000 1 plain" "5552 60000 1 pad2" "5553 0 1 up-plain" "5554 0 1 up-pad2" "5555 0 1 up-pad1"; do python3 /src/bench/wprobe.py server $v & done'
fi
sshd='/usr/sbin/sshd -D -e'
[ "$TRACE" = 1 ] && sshd='strace -f -o /strace.txt -e trace=setsockopt /usr/sbin/sshd -D -e'
[ "$CAPTURE" = 1 ] && capture='tcpdump -i lo -n -tt -s 128 -w /cap.pcap "tcp and not port 22" >/dev/null 2>&1 &'

publish=
[ "$CLIENT" = host ] && publish='-p 127.0.0.1::22'
# shellcheck disable=SC2086
docker run -d --name "$name-server" $cpu_args $server_args $publish --network "$name" --hostname server --cap-add NET_ADMIN --cap-add SYS_PTRACE -v "$PWD":/src:ro \
    -e NETEM="$NETEM" -e EXTRA="$EXTRA" -v "$TARGET_VOLUME":/target:ro -v "$keys/id.pub":/id.pub:ro "$IMAGE" sh -c "
$install
sh /src/bench/install-extras.sh server
mkdir -p /run/sshd /root/.ssh
ssh-keygen -A >/dev/null
cat /id.pub > /root/.ssh/authorized_keys
chmod 700 /root/.ssh && chmod 600 /root/.ssh/authorized_keys
sed -i '/^#*AllowTcpForwarding/d' /etc/ssh/sshd_config
echo 'AllowTcpForwarding yes' >> /etc/ssh/sshd_config
$link
$capture
$probe_servers
exec $sshd" >/dev/null

if [ "$CLIENT" = host ]; then
    port=$(docker port "$name-server" 22/tcp | head -1 | sed 's/.*://')
    cat > "$keys/ssh_config" <<CONFIG
Host 127.0.0.1
  Port $port
  IdentityFile $keys/id
  IdentitiesOnly yes
  StrictHostKeyChecking no
  UserKnownHostsFile /dev/null
  LogLevel ERROR
CONFIG
    n=0
    until ssh -F "$keys/ssh_config" -o BatchMode=yes -o ConnectTimeout=3 root@127.0.0.1 true 2>/dev/null; do
        n=$((n + 1)); [ $n -gt 60 ] && { echo 'the server container does not answer' >&2; exit 1; }
        sleep 1
    done
    echo "link: ${NETEM:-none}; client: this machine, $(uname -sm), $(ssh -V 2>&1)"
    python3 bench/bench.py --host root@127.0.0.1 --ssh-command "ssh -F $keys/ssh_config" \
        --ssj "$CLIENT_BIN" --server /target/release/ssj-server "$@"
    exit $?
fi

# shellcheck disable=SC2086
docker run --rm $cpu_args --network "$name" --cap-add NET_ADMIN -e NETEM="$NETEM" -e EXTRA="$EXTRA" \
    --sysctl net.ipv4.conf.all.promote_secondaries=1 \
    -v "$PWD":/src:ro -v "$PWD/target":/out -v "$TARGET_VOLUME":/target:ro -v "$keys/id":/id:ro "$IMAGE" sh -c "
$install
sh /src/bench/install-extras.sh
mkdir -p /root/.ssh
cp /id /root/.ssh/id_ed25519 && chmod 600 /root/.ssh/id_ed25519
printf 'Host server\n  StrictHostKeyChecking no\n  UserKnownHostsFile /dev/null\n  LogLevel ERROR\n' > /root/.ssh/config
$link
n=0
until ssh -o BatchMode=yes -o ConnectTimeout=3 root@server true 2>/dev/null; do
    n=\$((n + 1)); [ \$n -gt 60 ] && { echo 'the server container does not answer' >&2; exit 1; }
    sleep 1
done
echo \"link: \${NETEM:-none}; \$(ssh -V 2>&1)\"
if [ \"$PROBE\" = 1 ]; then
    sleep 2
    for v in \"5551 plain: the server sends two small writes 60 ms apart\" \"5552 pad2: ... and pads the second\" \"5553 up-plain: the client sends two small writes 60 ms apart\" \"5554 up-pad2: ... and pads the second\" \"5555 up-pad1: ... and pads the first\"; do
        port=\${v%% *}; rest=\${v#* }; echo \"\$rest\"
        python3 /src/bench/wprobe.py client root@server \$port 300 \${rest%%:*} 60000
    done
    exit 0
fi
ssj=/target/release/ssj
udpstat() { if [ \"$UDPSTAT\" = 1 ]; then echo \"\$1: \$(grep -E '^Udp:' /proc/net/snmp | tail -1 | tr '\\n' ' ')\"; fi; }
udpstat before
if [ \"$CLIENT_LOG\" = 1 ]; then
    # the options of ssj follow its command word
    printf '#!/bin/sh\ncmd=\$1; shift\nexec /target/release/ssj \"\$cmd\" -vvv --log-file /tmp/ssj-log.\$\$ \"\$@\"\n' > /usr/local/bin/ssj-log
    chmod +x /usr/local/bin/ssj-log
    ssj=/usr/local/bin/ssj-log
fi
cd /src && python3 bench/bench.py --host root@server --ssj \$ssj \
    --server /target/release/ssj-server $*
status=\$?
udpstat after
if [ \"$CLIENT_LOG\" = 1 ]; then
    for f in /tmp/ssj-log.*; do echo \"== \$f\"; cat \"\$f\"; done > /out/ssj-client-log.txt
fi
exit \$status"
status=$?
if [ "$PROBE" = 1 ]; then
    docker logs "$name-server" 2>&1 | grep -v "^$" | tail -15
fi
if [ "$TRACE" = 1 ]; then
    docker exec "$name-server" sh -c 'sleep 1; grep -E "NODELAY|TOS" /strace.txt | sort | uniq -c | sort -rn | head -20'
fi
if [ "$CAPTURE" = 1 ]; then
    # every packet of the hop, including the empty ones (the acknowledgements), into a file
    docker exec "$name-server" sh -c 'kill -INT $(pidof tcpdump); sleep 1; tcpdump -r /cap.pcap -nn -tt -q 2>/dev/null' > "${CAPTURE_FILE:-/tmp/ssjbench-capture.txt}"
    echo "capture: ${CAPTURE_FILE:-/tmp/ssjbench-capture.txt}"
fi
exit $status
