#!/usr/bin/env bash
# MOAVI Desk protocol benchmark - the WAN emulator's transparent bridge.
#
#   wan-bridge.sh setup <client_if> <lan_if>   bridge the two NICs as br-wan
#   wan-bridge.sh teardown                     remove br-wan (profiles are removed with it)
#   wan-bridge.sh status
#
# <client_if> faces the test client (the "WAN" side), <lan_if> faces the desktops and the
# MOAVI engine. The bridge has no IP of its own; give the emulator a separate management NIC
# (or an IP on br-wan) if you want to ssh into it.
#
# Offloads (GRO/GSO/TSO/LRO) are switched off on both ports: with them on, netem shapes and
# tcpdump records 64 KB super-frames instead of the packets that really cross the wire, and
# both the shaping and the byte counts are wrong.
set -euo pipefail

ENV_FILE=/etc/moavi-bench.env
BR=br-wan

need() { command -v "$1" >/dev/null || { echo "missing: $1 (apt install $2)" >&2; exit 1; }; }

no_offload() {
    for f in gro gso tso lro ufo tx-udp-segmentation; do
        ethtool -K "$1" "$f" off 2>/dev/null || true
    done
}

case "${1:-}" in
setup)
    [ $# -eq 3 ] || { echo "usage: $0 setup <client_if> <lan_if>" >&2; exit 2; }
    need ip iproute2; need ethtool ethtool; need tc iproute2
    CLIENT_IF=$2; LAN_IF=$3
    for i in "$CLIENT_IF" "$LAN_IF"; do
        ip link show "$i" >/dev/null || { echo "no such interface: $i" >&2; exit 1; }
    done
    ip link show "$BR" >/dev/null 2>&1 || ip link add "$BR" type bridge
    # no STP: a two-port bridge has no loop, and STP would hold forwarding for 30 s
    ip link set "$BR" type bridge stp_state 0 forward_delay 0
    for i in "$CLIENT_IF" "$LAN_IF"; do
        ip addr flush dev "$i"
        ip link set "$i" master "$BR"
        ip link set "$i" promisc on
        no_offload "$i"
        ip link set "$i" up
    done
    no_offload "$BR"
    ip link set "$BR" up
    # bridged frames must not be pushed through iptables (br_netfilter would add CPU cost
    # and, with a firewall loaded, could drop RDP/UDP)
    sysctl -qw net.bridge.bridge-nf-call-iptables=0 2>/dev/null || true
    sysctl -qw net.bridge.bridge-nf-call-ip6tables=0 2>/dev/null || true
    printf 'CLIENT_IF=%s\nLAN_IF=%s\nBR=%s\n' "$CLIENT_IF" "$LAN_IF" "$BR" > "$ENV_FILE"
    echo "br-wan: $CLIENT_IF (client side) <-> $LAN_IF (desktop side); saved to $ENV_FILE"
    echo "next: wan-profile.sh lan"
    ;;
teardown)
    [ -f "$ENV_FILE" ] && . "$ENV_FILE"
    for i in ${CLIENT_IF:-} ${LAN_IF:-}; do
        tc qdisc del dev "$i" root 2>/dev/null || true
        ip link set "$i" nomaster 2>/dev/null || true
    done
    ip link del "$BR" 2>/dev/null || true
    rm -f "$ENV_FILE"
    echo "br-wan removed"
    ;;
status)
    [ -f "$ENV_FILE" ] || { echo "not set up (no $ENV_FILE)"; exit 1; }
    . "$ENV_FILE"
    ip -br link show master "$BR"
    for i in "$CLIENT_IF" "$LAN_IF"; do echo "== $i"; tc qdisc show dev "$i"; done
    ;;
*)
    sed -n '2,13p' "$0"; exit 2 ;;
esac
