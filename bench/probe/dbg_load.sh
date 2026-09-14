#!/usr/bin/env bash
# File-based loader: invoked as `bash dbg_load.sh <model>`, so this process's
# cmdline is just the script path -> pkill -f patterns below can't self-match.
set -uo pipefail
MODEL="${1:-unsloth/gemma-4-12b-it-GGUF}"
pkill -f "llama-server" 2>/dev/null || true
pkill -f "bin/unsloth run" 2>/dev/null || true
sleep 6
cd ~/codesec/bench/probe
TAG=$(echo "$MODEL" | sed 's#.*/##;s/-GGUF//')
setsid bash -c "unsloth run --model '${MODEL}' --max-seq-length 32768 --parallel 2 --disable-tools --port 8888 --host 127.0.0.1 --api-only --api-key-name dbg > logs/dbg-${TAG}.log 2>&1" </dev/null >/dev/null 2>&1 &
echo "loading $MODEL -> logs/dbg-${TAG}.log"
