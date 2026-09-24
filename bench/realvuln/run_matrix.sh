#!/usr/bin/env bash
# Interleaved Wave 1 (or WAVE=smoke) matrix. Sequential H then V per trial.
# Usage:
#   ZAI_API_KEY=... bench/realvuln/run_matrix.sh
#   WAVE=smoke TRIALS=1 ZAI_API_KEY=... bench/realvuln/run_matrix.sh
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=run_common.sh
source "$SCRIPT_DIR/run_common.sh"

WAVE="${WAVE:-wave1}"
here

if [[ "$WAVE" == "smoke" ]]; then
  mapfile -t SLUGS < <(printf '%s\n' "realvuln-intentionally-vulnerable-python-application")
  TRIALS="${TRIALS:-1}"
else
  mapfile -t SLUGS < "$SCRIPT_DIR/subset.txt"
  TRIALS="${TRIALS:-3}"
fi

if [[ "${PROVIDER:-zai}" == "zai" ]]; then
  : "${ZAI_API_KEY:?ZAI_API_KEY is required}"
fi
arm_done() {
  local slug="$1" arm="$2" t="$3"
  if [[ "$arm" == h ]]; then
    [[ -f "$(scan_out "$slug" "$FINAL_SCANNER" "$t")" ]] \
      && [[ -f "$(scan_out "$slug" "$HUNT_SCANNER" "$t")" ]]
  else
    [[ -f "$(scan_out "$slug" "$PI_SCANNER" "$t")" ]]
  fi
}
SKIP_EXISTING="${SKIP_EXISTING:-1}"
mkdir -p "$OPERATOR_DIR"

echo "[matrix] codesec=$CODESEC_ROOT realvuln=$REALVULN_ROOT wave=$WAVE trials=$TRIALS skip_existing=$SKIP_EXISTING provider=$PROVIDER model=$MODEL tag=$SCANNER_TAG"
echo "[matrix] slugs: ${SLUGS[*]}"

FAIL_LOG="$RUNS_ROOT/failed-trials.txt"
mkdir -p "$RUNS_ROOT"

run_trial() {
  local slug="$1" arm="$2" t="$3"
  local opaque st
  opaque="$("$PYTHON" -m bench.realvuln.blind_prepare allocate \
    --slug "$slug" --trial "$t" --arm "$arm" | head -1)"
  echo "[matrix] $arm slug=$slug trial=$t opaque=$opaque"
  set +e
  if [[ "$arm" == h ]]; then
    "$SCRIPT_DIR/run_h.sh" "$opaque"
  else
    "$SCRIPT_DIR/run_v.sh" "$opaque"
  fi
  st=$?
  set -e
  if [[ "$st" -ne 0 ]]; then
    echo "[matrix] FAIL $arm slug=$slug trial=$t opaque=$opaque status=$st"
    echo "$arm $slug $t $opaque $st" >> "$FAIL_LOG"
    return 0
  fi
}

for slug in "${SLUGS[@]}"; do
  for t in $(seq 1 "$TRIALS"); do
    for arm in h v; do
      if [[ "$SKIP_EXISTING" == 1 ]] && arm_done "$slug" "$arm" "$t"; then
        echo "[matrix] skip $arm slug=$slug trial=$t (already scored)"
        continue
      fi
      run_trial "$slug" "$arm" "$t"
    done
  done
done

# One retry pass for failures that still have no scored artifact.
if [[ -f "$FAIL_LOG" ]]; then
  echo "[matrix] retrying failed trials once"
  retry_src="$FAIL_LOG.retry.$$"
  cp "$FAIL_LOG" "$retry_src"
  : > "$FAIL_LOG"
  while read -r arm slug t opaque st; do
    [[ -n "${arm:-}" ]] || continue
    if arm_done "$slug" "$arm" "$t"; then
      echo "[matrix] skip retry $arm slug=$slug trial=$t (now scored)"
      continue
    fi
    run_trial "$slug" "$arm" "$t"
  done < "$retry_src"
  rm -f "$retry_src"
fi

if [[ "$WAVE" != "smoke" ]]; then
  "$PYTHON" -m bench.realvuln.aggregate \
    --realvuln "$REALVULN_ROOT" \
    --subset "$SCRIPT_DIR/subset.txt" \
    --tag "$SCANNER_TAG" \
    --json-out "$RUNS_ROOT/aggregate-${SCANNER_TAG}.json"
fi
echo "[matrix] done"
