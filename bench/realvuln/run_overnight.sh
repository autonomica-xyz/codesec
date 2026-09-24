#!/usr/bin/env bash
# Smoke, then the scored Wave 1 matrix. Intended to run unattended.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=run_common.sh
source "$SCRIPT_DIR/run_common.sh"

LOGDIR="${OVERNIGHT_LOGDIR:-${CODESEC_REALVULN_RUNS:-$CODESEC_ROOT/bench/realvuln-runs}/overnight}"
mkdir -p "$LOGDIR"
echo $$ > "$LOGDIR/overnight.pid"
date -Is | tee -a "$LOGDIR/overnight.stamp"

if [[ "${PROVIDER:-zai}" == "zai" ]]; then
  : "${ZAI_API_KEY:?ZAI_API_KEY is required}"
fi
export THINKING="${THINKING:-off}"
export PATH="${PI_BIN_DIR:-$HOME/.local/share/pi-node/node-v22.23.2-linux-arm64/bin}:$PATH"

here
command -v pi >/dev/null
[[ -x "$CODESEC_BIN" ]]

SMOKE_H="$REALVULN_ROOT/scan-results/realvuln-intentionally-vulnerable-python-application/${FINAL_SCANNER}/run-1.json"
SMOKE_V="$REALVULN_ROOT/scan-results/realvuln-intentionally-vulnerable-python-application/${PI_SCANNER}/run-1.json"
if [[ "${SKIP_SMOKE:-0}" == 1 || ( -f "$SMOKE_H" && -f "$SMOKE_V" ) ]]; then
  echo "[overnight] smoke skip (already scored)"
else
  echo "[overnight] smoke start $(date -Is)"
  WAVE=smoke TRIALS=1 "$SCRIPT_DIR/run_matrix.sh"
  echo "[overnight] smoke ok $(date -Is)"
fi

echo "[overnight] wave1 start $(date -Is)"
WAVE=wave1 SKIP_EXISTING=1 "$SCRIPT_DIR/run_matrix.sh"
echo "[overnight] wave1 ok $(date -Is)"
date -Is | tee -a "$LOGDIR/overnight.stamp"
