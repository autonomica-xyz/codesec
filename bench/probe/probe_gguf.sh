#!/usr/bin/env bash
# Download one pinned GGUF to tmpfs, fully offload it, and run the detection probe.
# Usage:
#   probe_gguf.sh <repo> <gguf-file> <alias> <tag> [repeats]
#
# Optional environment:
#   CTX=32768 PARALLEL=4 PROBE_CONCURRENCY=4 PROBE_PORT=8888
#   THINKING=disabled MAX_TOKENS=512 SPEC_TYPE=none SPEC_DRAFT_N_MAX=4
#   SWA_CHECKPOINTS=0 GPU_LAYERS=999 MIN_VRAM_RATIO=70 KEEP_MODEL=0
set -euo pipefail

MODEL_REPO="${1:?usage: probe_gguf.sh <repo> <gguf-file> <alias> <tag> [repeats]}"
MODEL_FILE="${2:?usage: probe_gguf.sh <repo> <gguf-file> <alias> <tag> [repeats]}"
ALIAS="${3:?usage: probe_gguf.sh <repo> <gguf-file> <alias> <tag> [repeats]}"
SUFFIX="${4:?usage: probe_gguf.sh <repo> <gguf-file> <alias> <tag> [repeats]}"
REPEATS="${5:-5}"

PORT="${PROBE_PORT:-8888}"
CTX="${CTX:-32768}"
PARALLEL="${PARALLEL:-4}"
PROBE_CONCURRENCY="${PROBE_CONCURRENCY:-$PARALLEL}"
THINKING="${THINKING:-disabled}"
MAX_TOKENS="${MAX_TOKENS:-512}"
GPU_LAYERS="${GPU_LAYERS:-999}"
MIN_VRAM_RATIO="${MIN_VRAM_RATIO:-70}"
SPEC_TYPE="${SPEC_TYPE:-none}"
SPEC_DRAFT_N_MAX="${SPEC_DRAFT_N_MAX:-4}"
SWA_CHECKPOINTS="${SWA_CHECKPOINTS:-0}"
KEEP_MODEL="${KEEP_MODEL:-0}"

BENCH="${BENCH_ROOT:-$HOME/codesec}/bench/probe"
LOG="$BENCH/logs-current"
RESULTS="$BENCH/results-current"
LLAMA="${LLAMA_SERVER:-$HOME/.unsloth/llama.cpp/build/bin/llama-server}"
MODEL_DIR=""
SERVER_PID=""

if [[ ! "$SUFFIX" =~ ^[a-zA-Z0-9._-]+$ ]]; then
  echo "[probe] tag contains unsupported characters: $SUFFIX" >&2
  exit 2
fi
if [[ "$MODEL_FILE" == */* || "$MODEL_FILE" == "." || "$MODEL_FILE" == ".." ]]; then
  echo "[probe] GGUF filename must be a repository-root basename" >&2
  exit 2
fi
if [[ "$THINKING" != "disabled" && "$THINKING" != "enabled" ]]; then
  echo "[probe] THINKING must be disabled or enabled" >&2
  exit 2
fi
if [[ ! "$MIN_VRAM_RATIO" =~ ^[0-9]+$ \
      || "$MIN_VRAM_RATIO" -lt 1 \
      || "$MIN_VRAM_RATIO" -gt 100 ]]; then
  echo "[probe] MIN_VRAM_RATIO must be an integer from 1 to 100" >&2
  exit 2
fi

LLAMA_BIN_DIR="$(dirname "$(readlink -f "$LLAMA")")"
CUDA_BACKEND="$LLAMA_BIN_DIR/libggml-cuda.so"
CUDA_LIBRARY_DIR="${CUDA_LIBRARY_DIR:-/usr/local/cuda/targets/x86_64-linux/lib}"
if [[ ! -f "$CUDA_BACKEND" || ! -d "$CUDA_LIBRARY_DIR" ]]; then
  echo "[probe] CUDA llama.cpp runtime is incomplete" >&2
  exit 1
fi
export GGML_BACKEND_PATH="${GGML_BACKEND_PATH:-$CUDA_BACKEND}"
export LD_LIBRARY_PATH="$CUDA_LIBRARY_DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

mkdir -p "$LOG" "$RESULTS"
MODEL_DIR="$(mktemp -d "/dev/shm/codesec-probe-${SUFFIX}.XXXXXX")"

cleanup() {
  if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill -TERM -- "-$SERVER_PID" 2>/dev/null \
      || kill -TERM "$SERVER_PID" 2>/dev/null \
      || true
    for _ in $(seq 1 20); do
      kill -0 "$SERVER_PID" 2>/dev/null || break
      sleep 1
    done
    kill -KILL -- "-$SERVER_PID" 2>/dev/null || true
  fi
  if [[ "$KEEP_MODEL" != "1" \
        && "$MODEL_DIR" == /dev/shm/codesec-probe-"$SUFFIX".* \
        && -d "$MODEL_DIR" ]]; then
    rm -rf -- "$MODEL_DIR"
  fi
}
trap cleanup EXIT

if curl --silent --max-time 2 "http://127.0.0.1:${PORT}/v1/models" \
  >/dev/null 2>&1; then
  echo "[probe] refusing to take over occupied port ${PORT}" >&2
  exit 1
fi

MODEL_REVISION="$(
  python3 - "$MODEL_REPO" <<'PY'
import json
import sys
import urllib.parse
import urllib.request

repo = urllib.parse.quote(sys.argv[1], safe="/")
with urllib.request.urlopen(
    f"https://huggingface.co/api/models/{repo}", timeout=30
) as response:
    revision = json.load(response).get("sha")
if not revision:
    raise SystemExit("model API did not return a revision")
print(revision)
PY
)"

echo "[probe] downloading ${MODEL_REPO}@${MODEL_REVISION}:${MODEL_FILE}"
HF_HOME="$MODEL_DIR/hf" uvx --from huggingface-hub hf download \
  "$MODEL_REPO" "$MODEL_FILE" \
  --revision "$MODEL_REVISION" \
  --local-dir "$MODEL_DIR"
MODEL_PATH="$MODEL_DIR/$MODEL_FILE"
if [[ ! -s "$MODEL_PATH" ]]; then
  echo "[probe] download did not produce ${MODEL_PATH}" >&2
  exit 1
fi

SERVER_ARGS=(
  -m "$MODEL_PATH"
  -a "$ALIAS"
  --host 127.0.0.1
  --port "$PORT"
  -ngl "$GPU_LAYERS"
  -t 8
  -tb 8
  -np "$PARALLEL"
  -fa on
  -c "$CTX"
  -ctk q8_0
  -ctv q8_0
  --jinja
)
if [[ "$SPEC_TYPE" != "none" ]]; then
  SERVER_ARGS+=(--spec-type "$SPEC_TYPE" --spec-draft-n-max "$SPEC_DRAFT_N_MAX")
fi
if [[ "$SWA_CHECKPOINTS" != "0" ]]; then
  SERVER_ARGS+=(--swa-checkpoints "$SWA_CHECKPOINTS")
fi

echo "[probe] loading ${MODEL_FILE} (full offload, parallel=${PARALLEL}, context=${CTX})"
setsid "$LLAMA" "${SERVER_ARGS[@]}" >"$LOG/llama-${SUFFIX}.log" 2>&1 &
SERVER_PID=$!

for _ in $(seq 1 240); do
  if curl --silent --fail --max-time 3 \
      "http://127.0.0.1:${PORT}/v1/models" | grep -Fq "$ALIAS"; then
    break
  fi
  kill -0 "$SERVER_PID" 2>/dev/null || {
    echo "[probe] llama-server exited before readiness" >&2
    tail -40 "$LOG/llama-${SUFFIX}.log" >&2
    exit 1
  }
  sleep 2
done
curl --silent --fail --max-time 3 \
  "http://127.0.0.1:${PORT}/v1/models" | grep -Fq "$ALIAS" || {
    echo "[probe] ${MODEL_FILE} did not become ready" >&2
    tail -40 "$LOG/llama-${SUFFIX}.log" >&2
    exit 1
  }

MODEL_MIB="$(( $(stat -c %s "$MODEL_PATH") / 1024 / 1024 ))"
MIN_VRAM_MIB="$(( MODEL_MIB * MIN_VRAM_RATIO / 100 ))"
LOADED_VRAM_MIB="$(
  nvidia-smi \
    --query-compute-apps=pid,used_memory \
    --format=csv,noheader,nounits \
  | awk -F, -v pid="$SERVER_PID" '
      $1 + 0 == pid {gsub(/[[:space:]]/, "", $2); print $2 + 0}
    '
)"
if [[ -z "$LOADED_VRAM_MIB" || "$LOADED_VRAM_MIB" -lt "$MIN_VRAM_MIB" ]]; then
  echo "[probe] CUDA/full-offload gate failed: model=${MODEL_MIB} MiB, "\
"process VRAM=${LOADED_VRAM_MIB:-0} MiB, required>=${MIN_VRAM_MIB} MiB" >&2
  tail -60 "$LOG/llama-${SUFFIX}.log" >&2
  exit 1
fi
echo "[probe] CUDA/full-offload gate passed (${LOADED_VRAM_MIB} MiB VRAM)"

META="$RESULTS/${SUFFIX}.runtime.json"
python3 "$BENCH/runtime_metadata.py" \
  --out "$META" \
  --requested-model "${MODEL_REPO}@${MODEL_REVISION}:${MODEL_FILE}" \
  --served-model "$ALIAS" \
  --server-pid "$SERVER_PID" \
  --launcher-path unsloth

echo "[probe] running ${REPEATS} repeats x 44 cases"
python3 "$BENCH/run_probe.py" \
  --model "$ALIAS" \
  --proto openai \
  --base-url "http://127.0.0.1:${PORT}" \
  --api-key "" \
  --out "$RESULTS/${SUFFIX}.jsonl" \
  --concurrency "$PROBE_CONCURRENCY" \
  --repeats "$REPEATS" \
  --attempts 2 \
  --max-tokens "$MAX_TOKENS" \
  --temperature 0 \
  --seed 20260724 \
  --thinking "$THINKING" \
  --metadata-json "$META"

python3 "$BENCH/score_probe.py" "$RESULTS/${SUFFIX}.jsonl" \
  | tee "$RESULTS/${SUFFIX}.score.txt"
echo "[probe] complete: $RESULTS/${SUFFIX}.jsonl"
