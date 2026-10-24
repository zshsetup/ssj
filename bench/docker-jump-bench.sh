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
# A condition is the netem settings of the link, or `none` (the default list is none,
# "delay 30ms", "delay 30ms loss 1%", "delay 30ms loss 3%"). Arguments for bench/jump_bench.py go in
# BENCH_ARGS, such as BENCH_ARGS="--bulk-mb 10 --runs 2".
#
#   BUILD=0                       reuse the build in the docker volume
#   HOLD=1                        set up the first condition and wait, for looking around with docker exec
#   TARGET_VOLUME=ssj-target-musl the docker volume with release/ssj and release/ssj-server
#   IMAGE=ubuntu:24.04
set -e
cd "$(dirname "$0")/.."
IMAGE=${IMAGE:-ubuntu:24.04}
BUILD=${BUILD:-1}
TARGET_VOLUME=${TARGET_VOLUME:-ssj-target-musl}
BENCH_ARGS=${BENCH_ARGS:-}
[ $# -gt 0 ] || set -- none "delay 30ms" "delay 30ms loss 1%" "delay 30ms loss 3%"
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
base=ssjbench-base:$(echo "$IMAGE" | tr '/:' '--')
if ! docker image inspect "$base" >/dev/null 2>&1; then
    printf 'FROM %s\nRUN apt-get update -qq && apt-get install -y -qq iproute2 ethtool openssh-server openssh-client python3 && rm -rf /var/lib/apt/lists/*\n' "$IMAGE" |
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
docker run -d --name "$name-client" --network "$name-flaky" --hostname client --cap-add NET_ADMIN \
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

set_link() {
    for c in client jump; do
        docker exec "$name-$c" sh -c "tc qdisc del dev eth0 root 2>/dev/null || true
if [ '$1' != none ]; then
    ethtool -K eth0 tso off gso off gro off >/dev/null 2>&1 || true
    tc qdisc add dev eth0 root netem $1
fi"
    done
}

if [ "${HOLD:-0}" = 1 ]; then
    set_link "$1"
    echo "containers: $name-client, $name-jump, $name-backend (link: $1); stop with Ctrl-C or kill"
    sleep 7200
    exit 0
fi

for condition in "$@"; do
    set_link "$condition"
    echo
    echo "== link between client and jump host: $condition (each way)"
    # shellcheck disable=SC2086
    docker exec "$name-client" python3 /src/bench/jump_bench.py --ssh-config /root/.ssh/config \
        --ssj /target/release/ssj --server /target/release/ssj-server $BENCH_ARGS
done
