#!/usr/bin/env bash
#
# One-shot: start OWASP Juice Shop in an isolated Docker network and run a
# ZAP scan against it, writing a JSON report under data/zap/juiceshop/.
#
# Safe by design:
#   - Juice Shop is bound to 127.0.0.1 only (not exposed to your LAN).
#   - ZAP only attacks the juiceshop container over a private Docker network.
#   - Nothing touches your host beyond CPU/RAM and the JSON report file.
#
# Two profiles:
#   SCAN=baseline  -> passive only, traditional spider, ~1-2 min. Fast JSON to
#                     build the validator pipeline against.
#   SCAN=full      -> TUNED full active scan (real attacks). Bounded so it
#                     actually finishes: spiders capped, passive-wait capped,
#                     active-scan capped. ~20-35 min instead of running forever.
#
# Why the caps matter (learned the hard way): with no -m the client spider runs
# UNBOUNDED on Juice Shop's SPA (+ wanders into external CDNs the browser loads),
# so the active scan never starts. -m/-T/scanner.* keep it bounded and on-track.
#
# Usage (from repo root):
#   SCAN=baseline ./scripts/run_zap_juiceshop.sh
#   SCAN=full     ./scripts/run_zap_juiceshop.sh
#   CLEANUP=1 SCAN=full ./scripts/run_zap_juiceshop.sh   # remove juiceshop when done
#
set -euo pipefail

# ---- config (override via env if you like) --------------------------------
NETWORK="${NETWORK:-pentest}"
JUICE_NAME="${JUICE_NAME:-juiceshop}"
HOST_PORT="${HOST_PORT:-3000}"
JUICE_IMAGE="${JUICE_IMAGE:-bkimminich/juice-shop}"
ZAP_IMAGE="${ZAP_IMAGE:-ghcr.io/zaproxy/zaproxy:stable}"
SCAN="${SCAN:-full}"                        # full | baseline
CLEANUP="${CLEANUP:-0}"                      # 1 = remove juiceshop at the end
BOOT_TIMEOUT="${BOOT_TIMEOUT:-120}"         # seconds to wait for Juice Shop

# scan bounds (minutes) — tune here
SPIDER_MINS="${SPIDER_MINS:-5}"             # caps BOTH traditional + client spider (-m)
FULL_PASSIVE_WAIT_MINS="${FULL_PASSIVE_WAIT_MINS:-5}"   # -T for full
BASE_PASSIVE_WAIT_MINS="${BASE_PASSIVE_WAIT_MINS:-2}"   # -T for baseline
ASCAN_MINS="${ASCAN_MINS:-25}"              # total active-scan cap
ASCAN_RULE_MINS="${ASCAN_RULE_MINS:-3}"     # per-rule active-scan cap
ASCAN_THREADS="${ASCAN_THREADS:-2}"         # attack threads/host — LOW so we don't OOM/overload
CONN_TIMEOUT_SECS="${CONN_TIMEOUT_SECS:-10}" # avoids Juice Shop socket.io 20s hangs

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT}/data/zap/juiceshop"
mkdir -p "${OUT_DIR}"
TARGET="http://${JUICE_NAME}:3000"          # ZAP reaches Juice Shop by container name

# ---- tiny logging helpers -------------------------------------------------
step() { printf "\n\033[1;36m==> %s\033[0m\n" "$*"; }
info() { printf "    %s\n" "$*"; }
die()  { printf "\n\033[1;31mERROR: %s\033[0m\n" "$*" >&2; exit 1; }

# ---- 0. preflight + choose profile ----------------------------------------
step "Preflight checks"
command -v docker >/dev/null 2>&1 || die "docker CLI not found."
docker info >/dev/null 2>&1 || die "Docker daemon is not running. Start Docker Desktop and re-run."
info "Docker is up."

case "$SCAN" in
  full)
    ZAP_SCRIPT="zap-full-scan.py"
    REPORT="${REPORT:-juiceshop_zap_full.json}"
    ZAP_FLAGS=(-t "${TARGET}" -j -m "${SPIDER_MINS}" -T "${FULL_PASSIVE_WAIT_MINS}" -J "${REPORT}" -I
      -z "-config connection.timeoutInSecs=${CONN_TIMEOUT_SECS} -config scanner.maxScanDurationInMins=${ASCAN_MINS} -config scanner.maxRuleDurationInMins=${ASCAN_RULE_MINS} -config scanner.threadPerHost=${ASCAN_THREADS} -config scanner.hostPerScan=1")
    ;;
  baseline)
    ZAP_SCRIPT="zap-baseline.py"
    REPORT="${REPORT:-juiceshop_zap_baseline.json}"
    # No -j: traditional spider + passive only = fast. -T caps the passive wait.
    ZAP_FLAGS=(-t "${TARGET}" -T "${BASE_PASSIVE_WAIT_MINS}" -J "${REPORT}" -I)
    ;;
  *) die "SCAN must be 'full' or 'baseline' (got '${SCAN}')." ;;
esac
info "Scan mode: ${SCAN} (${ZAP_SCRIPT})  ->  report: ${REPORT}"

# ---- 1. do not clobber an in-flight scan or a live Juice Shop -------------
step "Preflight: existing Juice Shop / ZAP"
zap_running="$(docker ps -q --filter ancestor="${ZAP_IMAGE}" 2>/dev/null || true)"
if [ -n "${zap_running}" ]; then
  die "A ZAP scan is already running (${zap_running}). Not starting a second one."
fi

JUICE_RUNNING=0
if docker ps --format '{{.Names}}' | grep -qx "${JUICE_NAME}"; then
  if curl -sf "http://localhost:${HOST_PORT}" >/dev/null 2>&1; then
    info "Reusing healthy '${JUICE_NAME}' on 127.0.0.1:${HOST_PORT} (will not docker rm)."
    JUICE_RUNNING=1
  else
    die "'${JUICE_NAME}' is up but not responding on :${HOST_PORT}. Not killing it (a live validation may be using it)."
  fi
fi

# ---- 2–5. network + Juice Shop (skip start when already healthy) ----------
step "Ensuring Docker network '${NETWORK}' exists"
if docker network inspect "${NETWORK}" >/dev/null 2>&1; then
  info "Network already exists — reusing it."
else
  docker network create "${NETWORK}" >/dev/null
  info "Created network '${NETWORK}'."
fi

if [ "${JUICE_RUNNING}" = "1" ]; then
  # Attach to the scan network if a previous run left juiceshop on another net.
  if ! docker inspect "${JUICE_NAME}" --format '{{json .NetworkSettings.Networks}}' \
      | grep -q "\"${NETWORK}\""; then
    info "Connecting '${JUICE_NAME}' to network '${NETWORK}'."
    docker network connect "${NETWORK}" "${JUICE_NAME}" >/dev/null
  fi
  info "Juice Shop is ready (reused)."
else
  if docker ps -a --format '{{.Names}}' | grep -qx "${JUICE_NAME}"; then
    info "Removing stopped '${JUICE_NAME}' container."
    docker rm -f "${JUICE_NAME}" >/dev/null
  fi
  if lsof -iTCP:"${HOST_PORT}" -sTCP:LISTEN -n -P >/dev/null 2>&1; then
    die "Port ${HOST_PORT} is in use by something else. Free it or set HOST_PORT=<other>."
  fi
  info "Port ${HOST_PORT} is free."

  step "Starting Juice Shop (${JUICE_IMAGE})"
  docker run -d --name "${JUICE_NAME}" --network "${NETWORK}" \
    -p 127.0.0.1:"${HOST_PORT}":3000 "${JUICE_IMAGE}" >/dev/null
  info "Container started. Local (host) access: http://localhost:${HOST_PORT}"

  step "Waiting for Juice Shop to become ready (max ${BOOT_TIMEOUT}s)"
  deadline=$(( $(date +%s) + BOOT_TIMEOUT ))
  until curl -sf "http://localhost:${HOST_PORT}" >/dev/null 2>&1; do
    if [ "$(date +%s)" -ge "${deadline}" ]; then
      docker logs --tail 30 "${JUICE_NAME}" || true
      die "Juice Shop did not come up within ${BOOT_TIMEOUT}s (logs above)."
    fi
    sleep 2
  done
  info "Juice Shop is ready."
fi

# ---- 6. run the ZAP scan --------------------------------------------------
step "Running ZAP ${SCAN} scan against ${TARGET}"
info "Report will be written to: ${OUT_DIR}/${REPORT}"
if [ "${SCAN}" = "full" ]; then
  info "Bounds: spiders<=${SPIDER_MINS}m, active-scan<=${ASCAN_MINS}m, per-rule<=${ASCAN_RULE_MINS}m, passive-wait<=${FULL_PASSIVE_WAIT_MINS}m, threads/host=${ASCAN_THREADS}"
  info "(Full scan performs real active attacks; expect ~20-35 min.)"
fi
info "ZAP cmd: ${ZAP_SCRIPT} ${ZAP_FLAGS[*]}"

# ZAP writes to /zap/wrk; mount our report dir there. Capture exit code so a
# WARN/FAIL code doesn't abort before we print the summary.
set +e
docker run --rm --network "${NETWORK}" \
  -v "${OUT_DIR}:/zap/wrk/:rw" \
  "${ZAP_IMAGE}" "${ZAP_SCRIPT}" "${ZAP_FLAGS[@]}"
ZAP_EXIT=$?
set -e

# ---- 7. summary + optional cleanup ---------------------------------------
step "Done"
if [ -f "${OUT_DIR}/${REPORT}" ]; then
  info "Report: ${OUT_DIR}/${REPORT}"
else
  info "WARNING: expected report not found at ${OUT_DIR}/${REPORT}"
fi
info "ZAP exit code: ${ZAP_EXIT}  (0=pass, 1=FAIL alerts, 2=WARN alerts [expected for Juice Shop], 3=error)"

if [ "${CLEANUP}" = "1" ]; then
  info "Cleaning up: removing '${JUICE_NAME}' container."
  docker rm -f "${JUICE_NAME}" >/dev/null 2>&1 || true
  info "Network '${NETWORK}' left in place (reused by future runs)."
else
  info "Juice Shop is still running. Stop it with:  docker rm -f ${JUICE_NAME}"
fi
