#!/usr/bin/env bash
# One-A6000 Titus -> OpenMythos repository trial.
# Usage: run_duo.sh <titus.gguf> <openmythos.gguf> <tag>
set -euo pipefail

TITUS_GGUF="${1:?usage: run_duo.sh <titus.gguf> <openmythos.gguf> <tag>}"
OPENMYTHOS_GGUF="${2:?usage: run_duo.sh <titus.gguf> <openmythos.gguf> <tag>}"
TAG="${3:?usage: run_duo.sh <titus.gguf> <openmythos.gguf> <tag>}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SOURCE="$SCRIPT_DIR/devshop"
MANIFEST="$SCRIPT_DIR/manifests/devshop.json"
RUN_ID="${RUN_ID:-duo_devshop_${TAG}}"
RUNS_BASE="${BENCH_RUNS_ROOT:-$PROJECT_ROOT/runs}"
RUN_ROOT="$RUNS_BASE/$RUN_ID"
WORK_BASE="${BENCH_WORK_ROOT:-$PROJECT_ROOT/work}"
BENCH_LOGS="${BENCH_LOGS_ROOT:-$PROJECT_ROOT/runlogs}"
LLAMA_SERVER="${CODESEC_LLAMA_SERVER:-llama-server}"
CODESEC_BIN="${CODESEC_BIN:-$PROJECT_ROOT/.venv/bin/codesec}"
WORK_PARENT=""

mkdir -p "$RUNS_BASE" "$WORK_BASE" "$BENCH_LOGS"

cleanup() {
  if [[ "${KEEP_WORKDIR:-0}" == "0" && -n "$WORK_PARENT" &&
        "$WORK_PARENT" == "$WORK_BASE"/duo-"$RUN_ID"-* ]]; then
    sudo rm -rf -- "$WORK_PARENT"
  fi
}
trap cleanup EXIT

digest_tree() {
  (
    cd "$1"
    find . -type f -print0 | sort -z | xargs -0 sha256sum
  ) | sha256sum | awk '{print $1}'
}

[[ -f "$TITUS_GGUF" ]] || {
  echo "[duo] missing Titus GGUF: $TITUS_GGUF" >&2
  exit 1
}
[[ -f "$OPENMYTHOS_GGUF" ]] || {
  echo "[duo] missing OpenMythos GGUF: $OPENMYTHOS_GGUF" >&2
  exit 1
}
[[ -x "$CODESEC_BIN" ]] || {
  echo "[duo] codesec executable not found: $CODESEC_BIN" >&2
  exit 1
}
[[ ! -e "$RUN_ROOT" ]] || {
  echo "[duo] refusing to reuse run root: $RUN_ROOT" >&2
  exit 1
}
if find "$SOURCE" -type f -name 'ground_truth.json' -print -quit | grep -q .; then
  echo "[duo] answer key found inside scan source" >&2
  exit 1
fi

WORK_PARENT="$(mktemp -d "$WORK_BASE/duo-${RUN_ID}-XXXXXXXX")"
TARGET="$WORK_PARENT/devshop"
cp -a "$SOURCE" "$TARGET"
SOURCE_SHA256="$(digest_tree "$TARGET")"
sudo chown -R root:root "$TARGET"
sudo chmod -R a-w "$TARGET"

export CODESEC_TITUS_GGUF="$TITUS_GGUF"
export CODESEC_OPENMYTHOS_GGUF="$OPENMYTHOS_GGUF"
export CODESEC_LLAMA_SERVER="$LLAMA_SERVER"

echo "[duo] running ${RUN_ID}: Titus -> OpenMythos"
status=0
"$CODESEC_BIN" run \
  --pipeline duo-v1 \
  --runtime managed \
  --llama-server "$LLAMA_SERVER" \
  --run-root "$RUN_ROOT" \
  --run-id "$RUN_ID" \
  --repo "$TARGET" \
  --max-concurrency "${MAX_CONCURRENCY:-4}" \
  --max-recon-tasks "${MAX_RECON_TASKS:-20}" \
  2>&1 | tee "$BENCH_LOGS/codesec-${RUN_ID}.log" || status=$?

FINAL_SHA256="$(digest_tree "$TARGET")"
if [[ "$FINAL_SHA256" != "$SOURCE_SHA256" ]]; then
  echo "[duo] corpus changed during run; invalidating result" >&2
  exit 2
fi
if [[ "$status" -ne 0 ]]; then
  echo "[duo] codesec exited with status ${status}" >&2
  exit "$status"
fi

(
  cd "$PROJECT_ROOT"
  python3 -m bench.score_repo \
    "$RUN_ROOT" \
    "$MANIFEST" \
    --stages \
    --json-out "$RUN_ROOT/benchmark-score.json"
) | tee "$RUN_ROOT/benchmark-score.txt"
echo "[duo] complete: $RUN_ROOT"
