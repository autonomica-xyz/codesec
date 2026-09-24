#!/usr/bin/env bash
# One vanilla Pi (V) trial. Args: <opaque_id>
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=run_common.sh
source "$SCRIPT_DIR/run_common.sh"

OPAQUE="${1:?usage: run_v.sh <opaque_id>}"
MAP="$OPERATOR_DIR/${OPAQUE}.json"
[[ -f "$MAP" ]] || { echo "missing operator map $MAP" >&2; exit 1; }

here
"$PYTHON" -m bench.realvuln.blind_prepare prepare --map "$MAP"

TARGET="$(map_get "$MAP" target)"
SLUG="$(map_get "$MAP" slug)"
TRIAL="$(map_get "$MAP" trial)"
DIGEST="$(map_get "$MAP" digest)"
[[ -d "$TARGET" ]] || { echo "missing target $TARGET" >&2; exit 1; }
test "$(basename "$TARGET")" = target

RUN_ROOT="$RUNS_ROOT/$OPAQUE"
refuse_existing "$RUN_ROOT"
OUT="$(scan_out "$SLUG" "$PI_SCANNER" "$TRIAL")"
refuse_existing "$OUT"
mkdir -p "$RUN_ROOT/pi-home" "$RUN_ROOT/pi-session" "$(dirname "$OUT")"

if [[ "$PROVIDER" == "zai" ]]; then
  : "${ZAI_API_KEY:?ZAI_API_KEY is required}"
else
  export UNSLOTH_API_KEY="${UNSLOTH_API_KEY:-local}"
fi
command -v pi >/dev/null || { echo "pi CLI not on PATH" >&2; exit 1; }

PROMPT="$(sed "s|__FINDINGS_PATH__|$RUN_ROOT/findings.json|g" \
  "$SCRIPT_DIR/pi_audit_prompt.md")"
CAP=2700
[[ "$SLUG" == "realvuln-pygoat" ]] && CAP=5400

export PI_CODING_AGENT_DIR="$RUN_ROOT/pi-home"
# Isolated home: no host skills/settings.
"$PYTHON" - "$PROVIDER" "$MODEL" <<'PY'
import json, os, pathlib, sys
home = pathlib.Path(os.environ["PI_CODING_AGENT_DIR"])
provider, model = sys.argv[1], sys.argv[2]
if provider == "zai":
    key = os.environ["ZAI_API_KEY"]
    (home / "auth.json").write_text(json.dumps({"zai": {"type": "api_key", "key": key}}) + "\n")
else:
    base = os.environ.get("PI_LOCAL_BASE_URL", "http://127.0.0.1:8888/v1")
    key = os.environ.get("UNSLOTH_API_KEY", "local")
    (home / "auth.json").write_text(json.dumps({provider: {"type": "api_key", "key": key}}) + "\n")
    (home / "models.json").write_text(json.dumps({
        "providers": {
            provider: {
                "baseUrl": base,
                "api": "openai-completions",
                "apiKey": key,
                "models": [{
                    "id": model,
                    "name": model,
                    "reasoning": False,
                    "input": ["text"],
                    "contextWindow": 131072,
                    "maxTokens": 16384,
                }],
            }
        }
    }, indent=2) + "\n")
(home / "auth.json").chmod(0o600)
PY

START="$(date +%s)"
status=0
(
  cd "$TARGET"
  test "$(basename "$PWD")" = target
  timeout --signal=TERM --kill-after=30s "$CAP" \
    pi -p \
      --provider "$PROVIDER" \
      --model "$MODEL" \
      --thinking "$THINKING" \
      --no-skills --no-extensions \
      --no-context-files --no-prompt-templates \
      --no-approve \
      --session-dir "$RUN_ROOT/pi-session" \
      -- \
      "$PROMPT"
) 2>&1 | tee "$RUN_ROOT/pi.log" || status=$?
END="$(date +%s)"

FINAL_DIGEST="$(digest_tree "$TARGET")"
if [[ "$FINAL_DIGEST" != "$DIGEST" ]]; then
  echo "corpus digest changed; invalidating trial" >&2
  exit 2
fi

if [[ ! -f "$RUN_ROOT/findings.json" ]]; then
  echo "missing findings.json (pi status $status)" >&2
  exit 3
fi

"$PYTHON" -m bench.realvuln.adapt_to_semgrep \
  --from-pi "$RUN_ROOT/findings.json" \
  --map "$MAP" \
  --out "$OUT" \
  --dropped-out "$RUN_ROOT/adapter_dropped.json" \
  --metrics-out "$REALVULN_ROOT/scan-results/$SLUG/${PI_SCANNER}/run-${TRIAL}.metrics.json" \
  --identity-out "$RUN_ROOT/identity_leak.txt"

{
  echo "opaque=$OPAQUE"
  echo "slug=$SLUG"
  echo "trial=$TRIAL"
  echo "arm=v"
  echo "status=$status"
  echo "wall_s=$((END - START))"
  echo "timeout_s=$CAP"
  echo "model=$MODEL"
  echo "thinking=$THINKING"
  echo "pi_version=$(pi --version 2>/dev/null || true)"
} > "$RUN_ROOT/benchmark_meta.txt"

echo "V complete: $OUT"
exit 0
