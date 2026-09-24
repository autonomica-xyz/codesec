#!/usr/bin/env bash
# One codesec (H) trial. Args: <opaque_id>
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=run_common.sh
source "$SCRIPT_DIR/run_common.sh"

OPAQUE="${1:?usage: run_h.sh <opaque_id>}"
MAP="$OPERATOR_DIR/${OPAQUE}.json"
[[ -f "$MAP" ]] || { echo "missing operator map $MAP" >&2; exit 1; }

here
"$PYTHON" -m bench.realvuln.blind_prepare prepare --map "$MAP"

TARGET="$(map_get "$MAP" target)"
SLUG="$(map_get "$MAP" slug)"
TRIAL="$(map_get "$MAP" trial)"
DIGEST="$(map_get "$MAP" digest)"
[[ -d "$TARGET" ]] || { echo "missing target $TARGET" >&2; exit 1; }
test "$(basename "$TARGET")" = target

RUN_ROOT="$RUNS_ROOT/$OPAQUE"
refuse_existing "$RUN_ROOT"
HUNT_OUT="$(scan_out "$SLUG" "$HUNT_SCANNER" "$TRIAL")"
FINAL_OUT="$(scan_out "$SLUG" "$FINAL_SCANNER" "$TRIAL")"
refuse_existing "$HUNT_OUT"
refuse_existing "$FINAL_OUT"
mkdir -p "$(dirname "$HUNT_OUT")" "$(dirname "$FINAL_OUT")"
CODESEC_LOG="$RUNS_ROOT/${OPAQUE}.codesec.log"

RECON=20
HOURS=2
if [[ "$SLUG" == "realvuln-pygoat" ]]; then
  RECON=40
  HOURS=3
fi

if [[ "$PROVIDER" == "zai" ]]; then
  : "${ZAI_API_KEY:?ZAI_API_KEY is required}"
else
  export UNSLOTH_API_KEY="${UNSLOTH_API_KEY:-local}"
  export CODESEC_API_KEY="${CODESEC_API_KEY:-$UNSLOTH_API_KEY}"
fi
[[ -x "$CODESEC_BIN" ]] || { echo "codesec not found: $CODESEC_BIN" >&2; exit 1; }

START="$(date +%s)"
status=0
"$CODESEC_BIN" run \
  --repo "$TARGET" \
  --run-id "$OPAQUE" \
  --run-root "$RUN_ROOT" \
  --provider "$PROVIDER" \
  --model "$MODEL" \
  --engine local \
  --prior off \
  --max-concurrency "${CODESEC_MAX_CONCURRENCY:-4}" \
  --max-recon-tasks "$RECON" \
  --max-hours "$HOURS" \
  2>&1 | tee "$CODESEC_LOG" || status=$?
END="$(date +%s)"
if [[ -d "$RUN_ROOT" ]]; then
  mv -f "$CODESEC_LOG" "$RUN_ROOT/codesec.log"
  CODESEC_LOG="$RUN_ROOT/codesec.log"
fi

if [[ "$status" -ne 0 && ! -f "$RUN_ROOT/results/report/report.json" ]]; then
  echo "codesec failed without a report (status $status)" >&2
  exit "$status"
fi

FINAL_DIGEST="$(digest_tree "$TARGET")"
if [[ "$FINAL_DIGEST" != "$DIGEST" ]]; then
  echo "corpus digest changed; invalidating trial" >&2
  exit 2
fi

"$PYTHON" -m bench.realvuln.adapt_to_semgrep \
  --from-codesec "$RUN_ROOT" \
  --map "$MAP" \
  --hunt-out "$HUNT_OUT" \
  --final-out "$FINAL_OUT" \
  --dropped-out "$RUN_ROOT/adapter_dropped.json" \
  --metrics-out "$REALVULN_ROOT/scan-results/$SLUG/${FINAL_SCANNER}/run-${TRIAL}.metrics.json" \
  --identity-out "$RUN_ROOT/identity_leak.txt"

{
  echo "opaque=$OPAQUE"
  echo "slug=$SLUG"
  echo "trial=$TRIAL"
  echo "arm=h"
  echo "status=$status"
  echo "wall_s=$((END - START))"
  echo "recon=$RECON"
  echo "max_hours=$HOURS"
  echo "model=$MODEL"
  echo "provider=$PROVIDER"
  echo "scanner_tag=$SCANNER_TAG"
  echo "thinking=unset-sdk"
} > "$RUN_ROOT/benchmark_meta.txt"

echo "H complete: $FINAL_OUT"
exit 0
