#!/bin/sh
# Compares ssh -J, ssj over the ssh channel, and ssj with the relay for a host behind a jump host,
# over a flaky link between the client and the jump host.
#
#   client --- (flaky link) --- jump --- (clean link) --- backend
#
# The client container reaches the backend only through the jump host. The link is simulated on the
# egress of the client and of the jump host (`tc netem`), so a delay of 30 ms is 60 ms round trip.
#
#   bench/docker-jump-bench.sh [CONDITION...]
#
# A condition is the netem settings of the link, or `none`, with `@RATE` after them for a bottleneck
# of that bandwidth (see `set_link`). The default list is none, a long link, a long link with
# bursts of loss, a Wi-Fi like link, and a mobile like link. Arguments for bench/jump_bench.py go
# in BENCH_ARGS, such as BENCH_ARGS="--bulk-mb 10 --runs 2".
#
#   BUILD=0                       reuse the build in the docker volume
#   HOLD=1                        set up the first condition and wait, for looking around with docker exec
#   TARGET_VOLUME=ssj-target-musl the docker volume with release/ssj and release/ssj-server
#   UDP=0                         skip the raw UDP reference (iperf3 through a UDP forwarder on the jump host)
#   IMAGE=ubuntu:24.04
set -e
cd "$(dirname "$0")/.."
IMAGE=${IMAGE:-ubuntu:24.04}
BUILD=${BUILD:-1}
TARGET_VOLUME=${TARGET_VOLUME:-ssj-target-musl}
BENCH_ARGS=${BENCH_ARGS:-}
[ $# -gt 0 ] || set -- \
    none \
    "delay 30ms 3ms" \
    "delay 30ms 3ms loss gemodel 1% 10% 70% 0.1%" \
    "delay 15ms 5ms loss gemodel 0.5% 25% 50% 0.1% reorder 0.5% 50% @100mbit" \
    "delay 60ms 15ms distribution normal loss gemodel 1% 20% 60% 0.2% @20mbit"
name=ssjjump-$$
mkdir -p target
keys=$(mktemp -d "$PWD/target/ssjjump-keys.XXXXXX")

cleanup() {
    for c in client jump backend; do docker rm -f "$name-$c" >/dev/null 2>&1 || true; done
    docker network rm "$name-flaky" "$name-clean" >/dev/null 2>&1 || true
    rm -rf "$keys"
}
trap cleanup EXIT INT TERM

if [ "$BUILD" = 1 ]; then
    docker run --rm -v "$PWD":/src:ro -v "$TARGET_VOLUME":/target -e CARGO_TARGET_DIR=/target \
        -w /src rust:alpine sh -c \
        'apk add --no-cache musl-dev gcc >/dev/null && cargo build --release -p ssj-client -p ssj-server 2>&1 | tail -1'
fi

ssh-keygen -q -t ed25519 -N "" -f "$keys/id"
docker network create "$name-flaky" >/dev/null
docker network create "$name-clean" >/dev/null

# the tools are in an image of their own, which is built once
base=ssjbench-base2:$(echo "$IMAGE" | tr '/:' '--')
if ! docker image inspect "$base" >/dev/null 2>&1; then
    printf 'FROM %s\nRUN apt-get update -qq && apt-get install -y -qq iproute2 ethtool openssh-server openssh-client python3 iperf3 socat && rm -rf /var/lib/apt/lists/*\n' "$IMAGE" |
        docker build -q -t "$base" - >/dev/null
fi
IMAGE=$base
install=:
# keys and the configuration of ssh, for the client and for the jump host (which logs in to the
# backend for the relay)
login='
mkdir -p /root/.ssh
cp /id /root/.ssh/id_ed25519 && chmod 600 /root/.ssh/id_ed25519
printf "Host *\n  StrictHostKeyChecking no\n  UserKnownHostsFile /dev/null\n  LogLevel ERROR\n  User root\n" > /root/.ssh/config'
# the client reaches the backend through the jump host
client_login="$login
printf 'Host backend\n  ProxyJump jump\n' >> /root/.ssh/config"
sshd='
mkdir -p /run/sshd /root/.ssh
ssh-keygen -A >/dev/null
cat /id.pub > /root/.ssh/authorized_keys
chmod 700 /root/.ssh && chmod 600 /root/.ssh/authorized_keys
sed -i "/^#*AllowTcpForwarding/d" /etc/ssh/sshd_config
echo "AllowTcpForwarding yes" >> /etc/ssh/sshd_config'

docker run -d --name "$name-backend" --network "$name-clean" --network-alias backend --hostname backend \
    --cap-add NET_ADMIN -v "$PWD":/src:ro -v "$TARGET_VOLUME":/target:ro -v "$keys/id.pub":/id.pub:ro \
    "$IMAGE" sh -c "$install
$sshd
exec /usr/sbin/sshd -D -e" >/dev/null
# the first network is eth0, which is the flaky side
docker run -d --name "$name-jump" --network "$name-flaky" --network-alias jump --hostname jump \
    --cap-add NET_ADMIN -v "$PWD":/src:ro -v "$TARGET_VOLUME":/target:ro -v "$keys/id.pub":/id.pub:ro \
    -v "$keys/id":/id:ro "$IMAGE" sh -c "$install
$sshd
$login
exec /usr/sbin/sshd -D -e" >/dev/null
docker network connect "$name-clean" "$name-jump"
# the logs of runs that time out are kept on this machine, in target/jump-bench-timeouts
mkdir -p target/jump-bench-timeouts
docker run -d --name "$name-client" --network "$name-flaky" --hostname client --cap-add NET_ADMIN \
    -v "$PWD/target/jump-bench-timeouts":/tmp/jump-bench-timeouts \
    -v "$PWD":/src:ro -v "$TARGET_VOLUME":/target:ro -v "$keys/id":/id:ro \
    "$IMAGE" sh -c "$install
$client_login
exec sleep 100000" >/dev/null

n=0
until docker exec "$name-client" ssh -o BatchMode=yes -o ConnectTimeout=3 backend true >/dev/null 2>&1; do
    n=$((n + 1))
    if [ $n -gt 60 ]; then
        echo 'the containers do not answer' >&2
        for c in jump backend client; do echo "== $c"; docker logs "$name-$c" 2>&1 | tail -5; done
        exit 1
    fi
    sleep 2
done

# A condition is the netem settings, optionally followed by `@RATE` for a bottleneck with that
# bandwidth: "delay 30ms 5ms loss gemodel 1% 10% 70% 0.1% @50mbit". The queue of netem is made
# large, since its default of 1000 packets drops what a long link holds. The bottleneck is a token
# bucket after the delay, as a real link has, and it drops what its own queue cannot hold.
set_link() {
    netem=${1%%@*}
    rate=
    case $1 in *@*) rate=${1#*@} ;; esac
    case $netem in *limit*) ;; *) netem="$netem limit 100000" ;; esac
    for c in client jump; do
        docker exec "$name-$c" sh -c "tc qdisc del dev eth0 root 2>/dev/null || true
if [ '$1' != none ]; then
    ethtool -K eth0 tso off gso off gro off >/dev/null 2>&1 || true
    tc qdisc add dev eth0 root handle 1: netem $netem
    if [ -n '$rate' ]; then
        tc qdisc add dev eth0 parent 1:1 handle 10: tbf rate $rate burst 64kb latency 200ms
    fi
fi"
    done
}

if [ "${HOLD:-0}" = 1 ]; then
    set_link "$1"
    echo "containers: $name-client, $name-jump, $name-backend (link: $1); stop with Ctrl-C or kill"
    sleep 7200
    exit 0
fi

# the most that UDP carries through the jump host: iperf3 from the client to the backend, with the
# packets passed on by socat on the jump host, which is what the relay does without the ssh leg
udp_reference() {
    docker exec -d "$name-backend" iperf3 -s -p 5201 >/dev/null
    docker exec -d "$name-jump" sh -c 'socat TCP4-LISTEN:5201,fork,reuseaddr TCP4:backend:5201 &
exec socat UDP4-LISTEN:5201,fork,reuseaddr UDP4:backend:5201'
    sleep 1
    # as fast as it goes (the receiver rate is what gets through, the loss is the overload), and at
    # a rate of 100 MB/s, which the forwarder keeps up with on a clean link
    for rate in 0 800M; do
        echo "raw UDP through the jump host (iperf3 -u -b $rate, 1200-byte datagrams, 5 s):"
        docker exec "$name-client" iperf3 -u -c jump -p 5201 -b "$rate" -l 1200 -t 5 2>&1 |
            sed -n 's/^\[ *[0-9]*\] *\(.*receiver\)$/  \1/p' || true
    done
    docker exec "$name-jump" sh -c 'for p in $(pidof socat); do kill $p; done' 2>/dev/null || true
    docker exec "$name-backend" sh -c 'for p in $(pidof iperf3); do kill $p; done' 2>/dev/null || true
}

for condition in "$@"; do
    set_link "$condition"
    echo
    echo "== link between client and jump host: $condition (each way)"
    [ "${UDP:-1}" = 0 ] || udp_reference
    # shellcheck disable=SC2086
    docker exec "$name-client" python3 /src/bench/jump_bench.py --ssh-config /root/.ssh/config \
        --ssj /target/release/ssj --server /target/release/ssj-server $BENCH_ARGS
done
