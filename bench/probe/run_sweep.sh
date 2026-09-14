#!/usr/bin/env bash
# Sweep the model ladder through the same repeated, thinking-disabled protocol.
set -uo pipefail
cd "$(dirname "$0")"

REPEATS="${1:-5}"
LADDER=(
  "unsloth/Qwen3.5-2B-GGUF|qwen35-2b"
  "unsloth/Qwen3.5-4B-GGUF|qwen35-4b"
  "unsloth/Qwen3-8B-GGUF|qwen3-8b"
  "unsloth/gemma-4-12b-it-GGUF|gemma4-12b"
  "unsloth/Qwen3.6-27B-MTP-GGUF|qwen36-27b"
  "unsloth/Qwen3-Coder-30B-A3B-Instruct-GGUF|qwen3coder-30b"
  "unsloth/Qwen3.6-35B-A3B-GGUF|qwen36-35b"
)

mkdir -p logs-v2 results-v2
status=0
for entry in "${LADDER[@]}"; do
  IFS='|' read -r model tag <<<"$entry"
  echo "===== $tag ($model) ====="
  if ! ./probe_model.sh "$model" "$tag" "$REPEATS" \
      2>&1 | tee "logs-v2/probe-${tag}.log"; then
    echo "[sweep] $tag failed; preserving failure and continuing" >&2
    status=1
  fi
done

python3 compare.py --dir results-v2 | tee results-v2/comparison.txt || status=1
exit "$status"
