#!/usr/bin/env bash
cd "$(dirname "$0")"
for entry in "unsloth/gemma-4-12b-it-GGUF|gemma4-12b" "unsloth/Qwen3.6-27B-MTP-GGUF|qwen36-27b"; do
  IFS='|' read -r model tag <<< "$entry"
  echo "=== $tag ==="
  ./probe_model.sh "$model" "$tag" || echo "$tag failed"
done
echo DONE2 > logs/rerun2.done
