#!/bin/sh
# Runs bench/jump_bench.py from a container against real hosts, with the ssh agent of this machine.
#
#   bench/docker-real-bench.sh [CONDITION]
#
# The container has the ssh configuration of the real chain (webtropia, merk-ail-1, merk-ail-3), the
# known hosts of this machine (read only), and the agent socket that colima forwards when it was
# started with `colima start --ssh-agent`. CONDITION is netem settings (see docker-jump-bench.sh) to
# make the path worse than it is; the default adds nothing.
#
#   DESTINATION=merk-ail-3              the host to reach
#   SERVER_PATH=~/ssj-server-relay-test ssj-server on every host of the chain, as ssh runs it
#   BENCH_ARGS="--bulk-mb 20 --runs 3"  arguments of bench/jump_bench.py
#   HOLD=1                              set up the container and wait, for looking around with docker exec
#   TARGET_VOLUME=ssj-target-musl       the docker volume with release/ssj (BUILD=1 builds it)
set -e
cd "$(dirname "$0")/.."
DESTINATION=${DESTINATION:-merk-ail-3}
SERVER_PATH=${SERVER_PATH:-'~/ssj-server-relay-test'}
BENCH_ARGS=${BENCH_ARGS:---bulk-mb 20 --runs 3}
TARGET_VOLUME=${TARGET_VOLUME:-ssj-target-musl}
condition=${1:-none}
image=ssjbench-base2:ubuntu-24.04
agent=/run/host-services/ssh-auth.sock
name=ssjreal-$$

if [ "${BUILD:-0}" = 1 ]; then
    docker run --rm -v "$PWD":/src:ro -v "$TARGET_VOLUME":/target -e CARGO_TARGET_DIR=/target \
        -w /src rust:alpine sh -c \
        'apk add --no-cache musl-dev gcc >/dev/null && cargo build --release -p ssj-client 2>&1 | tail -1'
fi

trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT INT TERM

docker run -d --name "$name" --hostname bench --cap-add NET_ADMIN \
    -v "$PWD":/src:ro -v "$TARGET_VOLUME":/target:ro \
    -v "$HOME/.ssh/known_hosts":/known_hosts:ro \
    -v "$agent":/agent.sock -e SSH_AUTH_SOCK=/agent.sock \
    "$image" sleep 100000 >/dev/null

docker exec "$name" sh -c 'mkdir -p /root/.ssh && cp /known_hosts /root/.ssh/known_hosts
cat > /root/.ssh/config <<EOF
Host *
  StrictHostKeyChecking yes
  LogLevel ERROR
  ServerAliveInterval 30
  ForwardAgent yes
Host webtropia
  HostName vps2622140.fastwebserver.de
  User audivir
Host merk-ail-1
  HostName localhost
  Port 2001
  ProxyJump webtropia
  HostKeyAlias merk-ail-1
  User tihoph
Host merk-ail-3
  HostName 192.168.50.3
  ProxyJump merk-ail-1
  User tihoph
EOF'

if ! docker exec "$name" ssh-add -l >/dev/null 2>&1; then
    echo 'the agent has no keys: run ssh-add on this machine first' >&2
    exit 1
fi
if ! docker exec "$name" ssh -o BatchMode=yes -o ConnectTimeout=20 "$DESTINATION" true; then
    echo "cannot log in to $DESTINATION from the container" >&2
    exit 1
fi

if [ "$condition" != none ]; then
    docker exec "$name" sh -c "ethtool -K eth0 tso off gso off gro off >/dev/null 2>&1 || true
tc qdisc add dev eth0 root netem $condition limit 100000"
fi
if [ "${HOLD:-0}" = 1 ]; then
    echo "container: $name (stop with Ctrl-C or kill)"
    sleep 7200
    exit 0
fi
echo "== real path to $DESTINATION, extra: $condition"
# shellcheck disable=SC2086
docker exec "$name" python3 /src/bench/jump_bench.py --ssh-config /root/.ssh/config \
    --destination "$DESTINATION" --ssj /target/release/ssj --server "$SERVER_PATH" $BENCH_ARGS
