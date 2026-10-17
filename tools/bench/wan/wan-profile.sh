#!/usr/bin/env bash
# MOAVI Desk protocol benchmark - switch the WAN emulator's network profile.
#
#   wan-profile.sh <name>      apply a profile from profiles.conf (lan, branch, home, bad, ...)
#   wan-profile.sh off         remove shaping (raw bridge, no limit)
#   wan-profile.sh show        print the profile in force and the qdisc counters
#   wan-profile.sh list        list the profiles
#   wan-profile.sh check <ip>  ping <ip> through the bridge and compare the RTT with the profile
#
# The same netem qdisc goes on the egress of both bridge ports, so the client->desktop and
# the desktop->client direction are shaped alike: rate each way, rtt/2 delay each way, loss
# each way. The queue (netem "limit") holds the delay line plus about 50 ms at the line rate;
# netem's default of 1000 packets would be 4 s of queue at 3 Mbit and measure bufferbloat
# instead of the protocol.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
CONF=${MOAVI_BENCH_PROFILES:-$HERE/profiles.conf}
ENV_FILE=/etc/moavi-bench.env
STATE=/run/moavi-bench.profile
QUEUE_MS=50

load_env() {
    [ -f "$ENV_FILE" ] || { echo "run wan-bridge.sh setup first (no $ENV_FILE)" >&2; exit 1; }
    . "$ENV_FILE"
}

profile_line() {
    awk -v n="$1" '!/^[[:space:]]*#/ && NF >= 4 && $1 == n { print; found=1 } END { exit !found }' "$CONF"
}

apply() {
    local name=$1 line rate rtt loss jitter one_way limit
    line=$(profile_line "$name") || { echo "unknown profile: $name (see: $0 list)" >&2; exit 2; }
    read -r _ rate rtt loss jitter <<<"$line"
    jitter=${jitter:-0}
    one_way=$(awk -v r="$rtt" 'BEGIN { printf "%.3f", r / 2 }')
    # packets of 1500 bytes in flight over (one-way delay + jitter + QUEUE_MS) at the rate
    limit=$(awk -v r="$rate" -v d="$one_way" -v j="$jitter" -v q="$QUEUE_MS" \
        'BEGIN { n = r * 1e6 * (d + j + q) / 1000 / (1500 * 8); n = int(n) + 1; if (n < 100) n = 100; print n }')
    local args=(rate "${rate}mbit" delay "${one_way}ms")
    if awk -v j="$jitter" 'BEGIN { exit !(j > 0) }'; then
        args+=("${jitter}ms" distribution normal)
    fi
    if awk -v l="$loss" 'BEGIN { exit !(l > 0) }'; then
        args+=(loss "${loss}%")
    fi
    args+=(limit "$limit")
    for i in "$CLIENT_IF" "$LAN_IF"; do
        tc qdisc replace dev "$i" root netem "${args[@]}"
    done
    printf '%s %s %s %s %s\n' "$name" "$rate" "$rtt" "$loss" "$jitter" > "$STATE"
    echo "profile $name: ${rate} Mbit/s each way, RTT ${rtt} ms, loss ${loss}% each way, jitter ${jitter} ms (limit $limit pkts)"
}

case "${1:-}" in
list)
    awk '!/^[[:space:]]*#/ && NF >= 4 { printf "%-8s %6s Mbit/s  RTT %4s ms  loss %4s%%  jitter %s ms\n", $1, $2, $3, $4, ($5 == "" ? 0 : $5) }' "$CONF"
    ;;
off)
    load_env
    for i in "$CLIENT_IF" "$LAN_IF"; do tc qdisc del dev "$i" root 2>/dev/null || true; done
    echo "off - - - -" > "$STATE"
    echo "shaping removed"
    ;;
show)
    load_env
    echo "profile: $(cat "$STATE" 2>/dev/null || echo '(none applied)')"
    for i in "$CLIENT_IF" "$LAN_IF"; do echo "== $i"; tc -s qdisc show dev "$i"; done
    ;;
check)
    [ $# -eq 2 ] || { echo "usage: $0 check <ip on the other side of the bridge>" >&2; exit 2; }
    read -r name _ rtt _ <"$STATE" 2>/dev/null || { echo "no profile applied" >&2; exit 1; }
    echo "profile $name expects RTT ~${rtt} ms (plus the LAN's own)"
    ping -c 20 -i 0.2 "$2" | tail -2
    ;;
""|-h|--help)
    sed -n '2,15p' "$0"; exit 2 ;;
*)
    load_env
    apply "$1"
    ;;
esac
