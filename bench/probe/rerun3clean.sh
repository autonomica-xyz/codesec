#!/usr/bin/env bash
cd "$(dirname "$0")"
for entry in "unsloth/Qwen3-8B-GGUF|qwen3-8b" "unsloth/gemma-4-12b-it-GGUF|gemma4-12b" "unsloth/Qwen3.6-27B-MTP-GGUF|qwen36-27b"; do
  IFS='|' read -r model tag <<< "$entry"
  echo "=== CLEAN(thinking-off): $tag ==="
  ./probe_model.sh "$model" "$tag" || echo "$tag failed"
done
echo DONE3 > logs/rerun3clean.done
