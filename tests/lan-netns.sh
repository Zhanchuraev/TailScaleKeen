#!/bin/sh
# Linux opt-in packet test. Run with sudo sh tests/lan-netns.sh.
set -eu
cd "$(dirname "$0")/.."
exec unshare --mount --net --propagation private sh -eu <<'ROUTER'
# Keep named namespaces, the xtables lock, and all links private to this run.
mount -t tmpfs tmpfs /run
mkdir /run/netns
ip link set lo up
sysctl -qw net.ipv4.ip_forward=1

lan() {
    bridge=$1 name=$2 gateway=$3 address=$4 mac=$5
    ip netns add "$name"
    ip link add "$bridge" type bridge
    ip addr add "$gateway/26" dev "$bridge"
    ip link set "$bridge" up
    ip link add "port-$name" type veth peer name eth0 netns "$name"
    ip link set "port-$name" master "$bridge"
    ip link set "port-$name" up
    ip -n "$name" link set eth0 address "$mac"
    ip -n "$name" addr add "$address/26" dev eth0
    ip -n "$name" link set eth0 up
    ip -n "$name" route add default via "$gateway"
}
lan br0 home 192.0.2.1 192.0.2.2 02:00:00:00:00:01
lan br1 guest 192.0.2.65 192.0.2.66 02:00:00:00:00:02

ip netns add remote
ip link add opkgtun0 type veth peer name eth0 netns remote
ip addr add 203.0.113.1/30 dev opkgtun0
ip link set opkgtun0 up
ip -n remote addr add 203.0.113.2/30 dev eth0
ip -n remote link set eth0 up
ip -n remote link set lo up
ip -n remote addr add 198.51.100.37/32 dev lo
ip -n remote route add default via 203.0.113.1
for table in main 52; do
    ip route add 198.51.100.37/32 via 203.0.113.2 dev opkgtun0 onlink table "$table"
done

probe() { ip netns exec "$1" ping -n -c 1 -W 2 198.51.100.37; }
probe home
probe guest
export PYTHONDONTWRITEBYTECODE=1
mkdir /run/tailscalekeen-test
python3 - <<'PY'
from pathlib import Path
from panel import lan_access
from panel.core import Runner, write_json

state = Path("/run/tailscalekeen-test")
lan_access.HOOK = state / "hook"
access = lan_access.LanAccess(state, Runner(), None, "opkgtun0")
host = "198.51.100.37/32"
device = "192.0.2.2 02:00:00:00:00:01"
policy = access.plan({"mode": "selected", "bridges": ["br0"], "devices": [device],
                      "subnets": [host], "grants": {device: [host]}},
                     {"backend_state": "Running", "online": True, "prefs": {}})
access.sync(policy, access.current())
write_json(access.path, policy)
access.verify_routes([host])
access.recover()
assert access.route_rules(policy) == access.live_rules()
PY
probe home
if probe guest; then
    echo 'Unexpected access from excluded br1' >&2
    exit 1
fi
# A filter counter proves the negative result came from the intended rule.
iptables -t filter -L TSKL_FWD -nvx | awk '$3 == "DROP" && $1 > 0 { matched=1 } END { exit !matched }'
ROUTER
