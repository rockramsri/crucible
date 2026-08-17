#!/usr/bin/env bash
#
# Watches the running ZAP full scan. Emits a HEARTBEAT line every INTERVAL
# seconds with live phase/progress, a SCAN_STUCK line if it stalls, and a
# SCAN_DONE line (then exits) when the report is written / container exits.
#
set -uo pipefail
INTERVAL="${INTERVAL:-300}"                 # seconds between checks (default 5 min)
ZAP_IMAGE="${ZAP_IMAGE:-ghcr.io/zaproxy/zaproxy:stable}"
REPORT="${REPORT:-juiceshop_zap_full.json}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIR="${ROOT}/data/zap/juiceshop"

prev_msgs="-1"
stall=0
seen_zap=0
startup_waits=0
STARTUP_MAX="${STARTUP_MAX:-20}"            # up to 20 x 15s = 5 min for ZAP to appear

while true; do
  ts="$(date '+%Y-%m-%d %H:%M:%S')"
  Z="$(docker ps -q --filter ancestor="${ZAP_IMAGE}" | head -1)"

  if [ -z "${Z}" ]; then
    if [ "${seen_zap}" = "0" ]; then
      # ZAP hasn't come up yet — still in the scan's startup window
      startup_waits=$((startup_waits+1))
      if [ "${startup_waits}" -ge "${STARTUP_MAX}" ]; then
        echo "[${ts}] SCAN_ENDED_NO_REPORT (ZAP never started within startup window)"
        break
      fi
      echo "[${ts}] HEARTBEAT waiting for ZAP container to start..."
      sleep 15; continue
    fi
    # We saw ZAP running before and now it's gone => finished or died
    if [ -f "${DIR}/${REPORT}" ]; then
      echo "[${ts}] SCAN_DONE report=${DIR}/${REPORT} size=$(wc -c < "${DIR}/${REPORT}" | tr -d ' ')B"
    else
      echo "[${ts}] SCAN_ENDED_NO_REPORT (ZAP container gone but no report file — likely crashed/OOM)"
    fi
    break
  fi
  seen_zap=1

  P="$(docker top "${Z}" 2>/dev/null | grep -oE '[-]port [0-9]+' | grep -oE '[0-9]+' | head -1)"
  if [ -z "${P}" ]; then
    echo "[${ts}] HEARTBEAT zap=starting (api port not up yet)"
    sleep "${INTERVAL}"; continue
  fi

  q() { docker exec "${Z}" curl -s "http://localhost:${P}/JSON/$1" 2>/dev/null; }
  ascan="$(q ascan/view/scans/)"
  pq="$(q pscan/view/recordsToScan/ | grep -oE '[0-9]+')"
  alerts="$(q core/view/numberOfAlerts/ | grep -oE '[0-9]+')"
  msgs="$(q core/view/numberOfMessages/ | grep -oE '[0-9]+')"
  aprog="$(printf '%s' "${ascan}" | grep -oE '"progress":"[0-9]+"' | grep -oE '[0-9]+' | head -1)"
  [ -z "${aprog}" ] && aprog="not-started"

  echo "[${ts}] HEARTBEAT activeScan=${aprog}% passiveQueue=${pq:-?} alerts=${alerts:-?} msgs=${msgs:-?}"

  # stall detection: total requests unchanged across two consecutive checks
  if [ "${msgs:-0}" = "${prev_msgs}" ]; then
    stall=$((stall+1))
    if [ "${stall}" -ge 1 ]; then
      echo "[${ts}] SCAN_STUCK requests stalled at ${msgs} (activeScan=${aprog}%) — may need attention"
    fi
  else
    stall=0
  fi
  prev_msgs="${msgs:-0}"

  sleep "${INTERVAL}"
done
