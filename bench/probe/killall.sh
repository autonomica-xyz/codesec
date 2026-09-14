#!/usr/bin/env bash
pkill -f "rerun" 2>/dev/null || true
pkill -f "probe_model" 2>/dev/null || true
pkill -f "run_probe" 2>/dev/null || true
pkill -f "llama-server" 2>/dev/null || true
pkill -f "bin/unsloth run" 2>/dev/null || true
sleep 5
nvidia-smi --query-gpu=memory.used --format=csv,noheader
