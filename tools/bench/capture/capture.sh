#!/usr/bin/env bash
# MOAVI Desk protocol benchmark - record one session on the WAN emulator.
#
#   capture.sh <protocol> <client_ip> [seconds]
#
#   protocol   rdp | rdpgw | spice | novnc | webrdp, or blast | hdx for a comparison run
#              (the label picks which port classes count; see benchstat.py)
#   client_ip  the test client's IP - only its traffic is recorded
#   seconds    stop after this long; default: run until Ctrl-C
#
#   MOAVI_BENCH_SERVERS="ip ip ..."  record only the client's traffic with these hosts (the
#              desktop, the MOAVI engine, the PVE nodes, the gateway) - recommended, so the
#              client's own web browsing on 443 does not count as noVNC / browser RDP bytes
#
# Writes runs/<UTC time>_<protocol>_<profile>/ with
#   capture.pcap   headers only (snaplen 128); the wire length of every frame is kept
#   run.json       protocol, profile in force, client, interface, capture start/stop (UTC epoch)
# Copy the guest's bench-out folder (markers.json, counters.csv) into the same folder
# afterwards; benchstat.py cuts the capture into workloads with markers.json.
#
# The capture runs on the client-side bridge port: a frame leaving towards the client is
# recorded after netem (what the WAN link really carries), a frame from the client before
# it (what the client really sent).
set -euo pipefail

ENV_FILE=/etc/moavi-bench.env
STATE=/run/moavi-bench.profile
OUT_ROOT=${MOAVI_BENCH_RUNS:-$(pwd)/runs}

[ $# -ge 2 ] || { sed -n '2,24p' "$0"; exit 2; }
PROTO=$1; CLIENT=$2; SECS=${3:-}
case "$PROTO" in rdp|rdpgw|spice|novnc|webrdp|blast|hdx) ;; *) echo "protocol: rdp | rdpgw | spice | novnc | webrdp | blast | hdx" >&2; exit 2;; esac
command -v tcpdump >/dev/null || { echo "missing: tcpdump (apt install tcpdump)" >&2; exit 1; }
[ -f "$ENV_FILE" ] || { echo "run wan-bridge.sh setup first (no $ENV_FILE)" >&2; exit 1; }
. "$ENV_FILE"

PROFILE=off; RATE=; RTT=; LOSS=; JITTER=
[ -f "$STATE" ] && read -r PROFILE RATE RTT LOSS JITTER < "$STATE"
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
DIR="$OUT_ROOT/${STAMP}_${PROTO}_${PROFILE}"
mkdir -p "$DIR"

num() { case "$1" in ''|-) echo null;; *) echo "$1";; esac; }
write_meta() {
    cat > "$DIR/run.json" <<EOF
{
  "protocol": "$PROTO",
  "profile": "$PROFILE",
  "profile_rate_mbit": $(num "$RATE"),
  "profile_rtt_ms": $(num "$RTT"),
  "profile_loss_pct": $(num "$LOSS"),
  "profile_jitter_ms": $(num "$JITTER"),
  "client_ip": "$CLIENT",
  "filter": "$FILTER",
  "interface": "$CLIENT_IF",
  "capture_start": $START,
  "capture_stop": ${STOP:-null},
  "emulator": "$(hostname)"
}
EOF
}

FILTER="host $CLIENT"
if [ -n "${MOAVI_BENCH_SERVERS:-}" ]; then
    FILTER="$FILTER and ($(echo $MOAVI_BENCH_SERVERS | sed 's/ / or host /g; s/^/host /'))"
fi
echo "filter: $FILTER"
START=$(date -u +%s.%N); STOP=
write_meta
echo "recording $PROTO under profile $PROFILE -> $DIR"
echo "now start Invoke-BenchWorkload.ps1 in the desktop; ${SECS:+stops after $SECS s, }Ctrl-C to stop"

ARGS=(-i "$CLIENT_IF" -s 128 -n -w "$DIR/capture.pcap" "$FILTER")
set +e
if [ -n "$SECS" ]; then
    timeout --signal=INT "$SECS" tcpdump "${ARGS[@]}"
else
    trap ':' INT
    tcpdump "${ARGS[@]}"
fi
set -e
STOP=$(date -u +%s.%N)
write_meta
echo "done: $DIR"
echo "copy the guest's bench-out\\* into it, then: python3 benchstat.py run \"$DIR\""
