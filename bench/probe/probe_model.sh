#!/usr/bin/env bash
# Load one model on the A6000 and run the repeated detection probe.
# Usage: probe_model.sh "<unsloth/Model[:QUANT]>" <tag> [repeats]
set -euo pipefail

MODEL_FULL="${1:?usage: probe_model.sh <unsloth/Model[:QUANT]> <tag> [repeats]}"
SUFFIX="${2:?usage: probe_model.sh <unsloth/Model[:QUANT]> <tag> [repeats]}"
REPEATS="${3:-5}"
PORT="${PROBE_PORT:-8888}"
KEYNAME="codesec-probe"
BENCH="${BENCH_ROOT:-$HOME/codesec}/bench/probe"
LOG="$BENCH/logs-v2"
RESULTS="$BENCH/results-v2"
ALIAS="${MODEL_FULL%%:*}"
SERVER_PID=""

mkdir -p "$LOG" "$RESULTS"

cleanup() {
  if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill -TERM -- "-$SERVER_PID" 2>/dev/null || kill -TERM "$SERVER_PID" 2>/dev/null || true
    for _ in $(seq 1 20); do
      kill -0 "$SERVER_PID" 2>/dev/null || break
      sleep 1
    done
    kill -KILL -- "-$SERVER_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

if curl --silent --max-time 2 "http://127.0.0.1:${PORT}/v1/models" >/dev/null 2>&1; then
  echo "[probe] refusing to take over occupied port ${PORT}" >&2
  exit 1
fi

echo "[probe] loading ${MODEL_FULL} (parallel=4, context=32768)"
setsid unsloth run \
  --model "$MODEL_FULL" \
  --max-seq-length 32768 \
  --parallel 4 \
  --disable-tools \
  --port "$PORT" \
  --host 127.0.0.1 \
  --api-only \
  --api-key-name "$KEYNAME" \
  >"$LOG/unsloth-${SUFFIX}.log" 2>&1 &
SERVER_PID=$!

KEY=""
for _ in $(seq 1 180); do
  KEY="$(grep -oE "sk-unsloth-[a-f0-9]+" "$LOG/unsloth-${SUFFIX}.log" 2>/dev/null | head -1 || true)"
  if [[ -n "$KEY" ]] && \
     curl --silent --fail --max-time 3 \
       -H "Authorization: Bearer ${KEY}" \
       "http://127.0.0.1:${PORT}/v1/models" | grep -Fq "$ALIAS"; then
    break
  fi
  kill -0 "$SERVER_PID" 2>/dev/null || {
    echo "[probe] model launcher exited before readiness" >&2
    tail -20 "$LOG/unsloth-${SUFFIX}.log" >&2
    exit 1
  }
  sleep 2
done

if [[ -z "$KEY" ]]; then
  echo "[probe] failed to obtain a server key for ${MODEL_FULL}" >&2
  tail -20 "$LOG/unsloth-${SUFFIX}.log" >&2
  exit 1
fi
curl --silent --fail --max-time 3 \
  -H "Authorization: Bearer ${KEY}" \
  "http://127.0.0.1:${PORT}/v1/models" | grep -Fq "$ALIAS" || {
    echo "[probe] ${MODEL_FULL} did not become ready" >&2
    tail -20 "$LOG/unsloth-${SUFFIX}.log" >&2
    exit 1
  }

LLAMA_PID="$(pgrep -f "llama-server.*--alias ${ALIAS}" | head -1 || true)"
if [[ -z "$LLAMA_PID" ]]; then
  LLAMA_PID="$SERVER_PID"
fi
META="$RESULTS/${SUFFIX}.runtime.json"
python3 "$BENCH/runtime_metadata.py" \
  --out "$META" \
  --requested-model "$MODEL_FULL" \
  --served-model "$ALIAS" \
  --server-pid "$LLAMA_PID" \
  --launcher-path unsloth

LLAMA_PORT="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["server_port"])' "$META")"
curl --silent --fail --max-time 3 \
  "http://127.0.0.1:${LLAMA_PORT}/v1/models" | grep -Fq "$ALIAS" || {
    echo "[probe] direct llama.cpp endpoint is not ready" >&2
    exit 1
  }

echo "[probe] running ${REPEATS} repeats x 44 cases"
python3 "$BENCH/run_probe.py" \
  --model "$ALIAS" \
  --proto openai \
  --base-url "http://127.0.0.1:${LLAMA_PORT}" \
  --api-key "" \
  --out "$RESULTS/${SUFFIX}.jsonl" \
  --concurrency 4 \
  --repeats "$REPEATS" \
  --attempts 2 \
  --temperature 0 \
  --seed 20260724 \
  --thinking disabled \
  --metadata-json "$META"

python3 "$BENCH/score_probe.py" "$RESULTS/${SUFFIX}.jsonl" \
  | tee "$RESULTS/${SUFFIX}.score.txt"
echo "[probe] complete: $RESULTS/${SUFFIX}.jsonl"
