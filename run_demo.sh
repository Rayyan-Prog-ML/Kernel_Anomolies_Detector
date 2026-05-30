#!/bin/bash
# ─────────────────────────────────────────────────────────────────
#  run_demo.sh — Kernel Sentinel: Automated Two-Terminal Demo
# ─────────────────────────────────────────────────────────────────
set -e
cd "$(dirname "$0")"

# ── Colors ────────────────────────────────────────────────────────
RED='\033[0;31m'; YEL='\033[0;33m'; GRN='\033[0;32m'
CYN='\033[0;36m'; BLD='\033[1m';    RST='\033[0m'
banner() { echo -e "\n${BLD}${CYN}══ $1 ══${RST}"; }
info()   { echo -e "${GRN}[INFO]${RST} $1"; }
warn()   { echo -e "${YEL}[WARN]${RST} $1"; }
err()    { echo -e "${RED}[ERR ]${RST} $1"; exit 1; }

ATTACK="${1:-all}"

# ── Pre-flight checks ─────────────────────────────────────────────
banner "Pre-flight"
[ -x bin/dashboard         ] || err "bin/dashboard not found — run 'make' first"
[ -x bin/observer          ] || err "bin/observer not found  — run 'make' first"
[ -x bin/attack_forkbomb   ] || err "bin/attack_forkbomb not found"
[ -x bin/attack_ransomware ] || err "bin/attack_ransomware not found"
[ -x bin/attack_memspike   ] || err "bin/attack_memspike not found"
info "All binaries present."

# ── Clean stale pipe ──────────────────────────────────────────────
rm -f /tmp/sentinel_pipe
mkdir -p logs

# ── TERMINAL 1: start dashboard (stays alive entire session) ──────
banner "Starting Dashboard — will stay open until all attacks finish"
bin/dashboard &
DASH_PID=$!
info "Dashboard PID: $DASH_PID"

# Make sure dashboard is up and pipe is ready before anything else
info "Waiting for dashboard to initialize..."
for i in $(seq 1 10); do
    [ -p /tmp/sentinel_pipe ] && break
    sleep 1
    if [ $i -eq 10 ]; then
        err "Dashboard did not create /tmp/sentinel_pipe after 10s — aborting"
    fi
done
info "Dashboard ready (pipe confirmed)."

# ── Trap: kill dashboard on unexpected exit ───────────────────────
cleanup() {
    warn "Interrupted — shutting down dashboard..."
    kill $DASH_PID 2>/dev/null || true
    wait $DASH_PID 2>/dev/null || true
    rm -f /tmp/sentinel_pipe
    exit 1
}
trap cleanup INT TERM

# ── Function: run one attack + observer, dashboard stays ──────────
run_attack() {
    local attack_bin=$1
    local args=$2
    local name
    name=$(basename "$attack_bin")

    banner "Attack: $name"

    # Launch attack
    $attack_bin $args &
    ATTACK_PID=$!
    info "$name PID: $ATTACK_PID"

    # Give attack time to initialize before observer attaches
    sleep 3

    # Attach observer — writes events to dashboard via pipe
    info "Attaching observer to PID $ATTACK_PID ..."
    bin/observer $ATTACK_PID &
    OBS_PID=$!

    # Wait for observer window (30s attach window + buffer)
    sleep 35

    # Stop observer cleanly
    kill $OBS_PID 2>/dev/null || true
    wait $OBS_PID 2>/dev/null || true

    # Let attack finish naturally (don't force kill — dashboard reads its exit)
    wait $ATTACK_PID 2>/dev/null || true

    info "$name done."
    sleep 2   # brief pause so dashboard can flush events before next attack
}

# ── Attack selection ──────────────────────────────────────────────
case "$ATTACK" in
  fork)
    run_attack bin/attack_forkbomb "25 15000"
    ;;
  ransom)
    run_attack bin/attack_ransomware "60"
    ;;
  mem)
    run_attack bin/attack_memspike "150"
    ;;
  all)
    run_attack bin/attack_forkbomb   "25 15000"
    run_attack bin/attack_ransomware "60"
    run_attack bin/attack_memspike   "150"
    ;;
  *)
    err "Unknown attack: $ATTACK. Choose: fork | ransom | mem | all"
    ;;
esac

# ── All attacks done — let dashboard show final summary ───────────
banner "All Attacks Completed"
info "Dashboard is showing final summary — press Ctrl+C when done viewing."

# Keep dashboard alive until user manually exits
wait $DASH_PID 2>/dev/null || true

# ── Teardown ──────────────────────────────────────────────────────
banner "Session End"
trap - INT TERM
rm -f /tmp/sentinel_pipe
info "Log saved to: logs/sentinel.log"
info "Demo complete!"
