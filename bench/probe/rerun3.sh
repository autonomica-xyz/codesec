#!/usr/bin/env bash
# Re-run only the models that failed (thinking budget) with the fixed runner.
set -uo pipefail
cd "$(dirname "$0")"
LADDER=(
  "unsloth/Qwen3-8B-GGUF|qwen3-8b"
  "unsloth/gemma-4-12b-it-GGUF|gemma4-12b"
  "unsloth/Qwen3.6-27B-MTP-GGUF|qwen36-27b"
)
for entry in "${LADDER[@]}"; do
  IFS='|' read -r model tag <<< "$entry"
  echo "================ RERUN: $tag ($model) ================"
  ./probe_model.sh "$model" "$tag" || echo "[rerun] $tag FAILED"
done
echo "================ RERUN DONE ================"
python3 compare.py --dir results
