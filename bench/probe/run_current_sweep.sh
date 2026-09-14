#!/usr/bin/env bash
# Current-generation/security model sweep for the RTX A6000 probe host.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPEATS="${1:-5}"

SPEC_TYPE=draft-mtp \
  "$HERE/probe_gguf.sh" \
  Jackrong/Qwopus3.6-27B-v2-MTP-GGUF \
  Qwopus3.6-27B-v2-MTP-Q8_0.gguf \
  qwopus36-27b-v2 \
  qwopus36-27b-v2-q8 \
  "$REPEATS"

SPEC_TYPE=ngram-mod SPEC_DRAFT_N_MAX=5 SWA_CHECKPOINTS=5 \
  "$HERE/probe_gguf.sh" \
  reduxdev/OpenMythos-GGUF \
  OpenMythos-27B-Q6_K.gguf \
  openmythos-27b \
  openmythos-27b-q6 \
  "$REPEATS"

"$HERE/probe_gguf.sh" \
  AlicanKiraz0/Titus-CybersecurityLLM-v1.0-Q4_K_M-No-MTP-GGUF \
  Titus-CybersecurityLLM-v1.0.Q4_K_M.gguf \
  titus-cybersecurity-35b \
  titus-cybersecurity-35b-q4 \
  "$REPEATS"

CTX=8192 \
  "$HERE/probe_gguf.sh" \
  mradermacher/CyberPal2.0-20B-GGUF \
  CyberPal2.0-20B.Q6_K.gguf \
  cyberpal2-20b \
  cyberpal2-20b-q6 \
  "$REPEATS"
