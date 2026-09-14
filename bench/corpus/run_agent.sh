#!/usr/bin/env bash
# Run the full codesec pipeline against an isolated, read-only corpus copy.
# Usage: run_agent.sh "<unsloth/Model[:QUANT]>" <tag>
set -euo pipefail

MODEL_FULL="${1:?usage: run_agent.sh <unsloth/Model[:QUANT]> <tag>}"
SUFFIX="${2:?usage: run_agent.sh <unsloth/Model[:QUANT]> <tag>}"
ROOT="${BENCH_ROOT:-$HOME/codesec}"
SOURCE="$ROOT/bench/corpus/devshop"
MANIFEST="$ROOT/bench/corpus/manifests/devshop.json"
RUNID="${RUN_ID:-corpus_${SUFFIX}_v2}"
RESULTS="$ROOT/results/$RUNID"
WORK_ROOT="$ROOT/work"
PORT="${CORPUS_PORT:-8888}"
KEYNAME="codesec-corpus"
ALIAS="${MODEL_FULL%%:*}"
LOG="$ROOT/runlogs-v2"
SERVER_PID=""
WORK_PARENT=""

mkdir -p "$LOG" "$WORK_ROOT"

cleanup() {
  if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill -TERM -- "-$SERVER_PID" 2>/dev/null || kill -TERM "$SERVER_PID" 2>/dev/null || true
    for _ in $(seq 1 20); do
      kill -0 "$SERVER_PID" 2>/dev/null || break
      sleep 1
    done
    kill -KILL -- "-$SERVER_PID" 2>/dev/null || true
  fi
  if [[ "${KEEP_WORKDIR:-1}" == "0" && -n "$WORK_PARENT" &&
        "$WORK_PARENT" == "$WORK_ROOT"/bench-"$RUNID"-* ]]; then
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

[[ -d "$SOURCE" ]] || {
  echo "[agent] missing corpus source: $SOURCE" >&2
  exit 1
}
[[ -f "$MANIFEST" ]] || {
  echo "[agent] missing external manifest: $MANIFEST" >&2
  exit 1
}
[[ ! -e "$RESULTS" ]] || {
  echo "[agent] refusing to overwrite existing run: $RESULTS" >&2
  exit 1
}
if find "$SOURCE" -type f -name 'ground_truth.json' -print -quit | grep -q .; then
  echo "[agent] answer key found inside scan source" >&2
  exit 1
fi
if curl --silent --max-time 2 "http://127.0.0.1:${PORT}/v1/models" >/dev/null 2>&1; then
  echo "[agent] refusing to take over occupied port ${PORT}" >&2
  exit 1
fi

WORK_PARENT="$(mktemp -d "$WORK_ROOT/bench-${RUNID}-XXXXXXXX")"
TARGET="$WORK_PARENT/devshop"
cp -a "$SOURCE" "$TARGET"
SOURCE_SHA256="$(digest_tree "$TARGET")"
sudo chown -R root:root "$TARGET"
sudo chmod -R a-w "$TARGET"

echo "[agent] loading ${MODEL_FULL} (parallel=4, context=65536)"
setsid unsloth run \
  --model "$MODEL_FULL" \
  --max-seq-length 65536 \
  --parallel 4 \
  --disable-tools \
  --port "$PORT" \
  --host 127.0.0.1 \
  --api-only \
  --api-key-name "$KEYNAME" \
  >"$LOG/unsloth-${SUFFIX}.log" 2>&1 &
SERVER_PID=$!

KEY=""
for _ in $(seq 1 240); do
  KEY="$(grep -oE "sk-unsloth-[a-f0-9]+" "$LOG/unsloth-${SUFFIX}.log" 2>/dev/null | head -1 || true)"
  if [[ -n "$KEY" ]] && \
     curl --silent --fail --max-time 3 \
       -H "Authorization: Bearer ${KEY}" \
       "http://127.0.0.1:${PORT}/v1/models" | grep -Fq "$ALIAS"; then
    break
  fi
  kill -0 "$SERVER_PID" 2>/dev/null || {
    echo "[agent] model launcher exited before readiness" >&2
    tail -20 "$LOG/unsloth-${SUFFIX}.log" >&2
    exit 1
  }
  sleep 2
done
curl --silent --fail --max-time 3 \
  -H "Authorization: Bearer ${KEY}" \
  "http://127.0.0.1:${PORT}/v1/models" | grep -Fq "$ALIAS" || {
    echo "[agent] ${MODEL_FULL} did not become ready" >&2
    tail -20 "$LOG/unsloth-${SUFFIX}.log" >&2
    exit 1
  }

LLAMA_PID="$(pgrep -f "llama-server.*--alias ${ALIAS}" | head -1 || true)"
if [[ -z "$LLAMA_PID" ]]; then
  LLAMA_PID="$SERVER_PID"
fi
mkdir -p "$RESULTS"
python3 "$ROOT/bench/probe/runtime_metadata.py" \
  --out "$RESULTS/benchmark_meta.json" \
  --requested-model "$MODEL_FULL" \
  --served-model "$ALIAS" \
  --server-pid "$LLAMA_PID" \
  --launcher-path unsloth \
  --dataset-sha256 "$SOURCE_SHA256" \
  --run-id "$RUNID" \
  --target-path "$TARGET"

LLAMA_PORT="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["server_port"])' "$RESULTS/benchmark_meta.json")"
curl --silent --fail --max-time 3 \
  "http://127.0.0.1:${LLAMA_PORT}/v1/models" | grep -Fq "$ALIAS" || {
    echo "[agent] direct llama.cpp endpoint is not ready" >&2
    exit 1
  }

echo "[agent] running codesec as ${RUNID}"
status=0
(
  cd "$ROOT"
  "$ROOT/.venv/bin/codesec" run \
    --repo "$TARGET" \
    --run-id "$RUNID" \
    --engine local \
    --base-url "http://127.0.0.1:${LLAMA_PORT}" \
    --model "$ALIAS" \
    --api-key "" \
    --max-concurrency 4 \
    --max-recon-tasks 20
) 2>&1 | tee "$LOG/codesec-${SUFFIX}.log" || status=$?

FINAL_SHA256="$(digest_tree "$TARGET")"
if [[ "$FINAL_SHA256" != "$SOURCE_SHA256" ]]; then
  echo "[agent] corpus changed during run; invalidating result" >&2
  exit 2
fi
if [[ "$status" -ne 0 ]]; then
  echo "[agent] codesec exited with status ${status}" >&2
  exit "$status"
fi

python3 "$ROOT/bench/score_repo.py" \
  "$RESULTS" \
  "$MANIFEST" \
  --stages \
  --json-out "$RESULTS/benchmark_score.json" \
  | tee "$RESULTS/benchmark_score.txt"
echo "[agent] complete: $RESULTS"
