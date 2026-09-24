#!/usr/bin/env bash
# One-time prep: codesec venv, RealVuln clone + seven apps, counts file.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=run_common.sh
source "$SCRIPT_DIR/run_common.sh"

here
if [[ ! -x "$CODESEC_ROOT/.venv/bin/python3" ]]; then
  python3 -m venv "$CODESEC_ROOT/.venv"
fi
# shellcheck disable=SC1091
source "$CODESEC_ROOT/.venv/bin/activate"
pip install -e "$CODESEC_ROOT[dev]"

if [[ ! -d "$REALVULN_ROOT/.git" ]]; then
  git clone https://github.com/kolega-ai/Real-Vuln-Benchmark "$REALVULN_ROOT"
fi
git -C "$REALVULN_ROOT" rev-parse HEAD | tee "$SCRIPT_DIR/realvuln.sha"
python3 "$REALVULN_ROOT/clone_repos.py" --repo \
  realvuln-intentionally-vulnerable-python-application \
  realvuln-vampi \
  realvuln-damn-vulnerable-flask-application \
  realvuln-python-insecure-app \
  realvuln-dvpwa \
  realvuln-lets-be-bad-guys \
  realvuln-pygoat
python3 "$REALVULN_ROOT/clone_repos.py" --status

"$PYTHON" -m bench.realvuln.derive_counts \
  --realvuln "$REALVULN_ROOT" \
  --out "$SCRIPT_DIR/subset-counts.json"

echo
echo "Phase 0 clone/counts done."
echo "Next (manual):"
echo "  export ZAI_API_KEY=..."
echo "  $CODESEC_BIN auth-check --provider zai --model glm-5.3"
echo "  pi auth check --provider zai --model glm-5.3"
echo "  WAVE=smoke TRIALS=1 $SCRIPT_DIR/run_matrix.sh"
echo "  $SCRIPT_DIR/run_matrix.sh"
