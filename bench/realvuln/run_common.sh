# sourced by run_h.sh / run_v.sh / run_matrix.sh
# shellcheck shell=bash
set -euo pipefail

CODESEC_ROOT="${CODESEC_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
REALVULN_ROOT="${REALVULN_ROOT:-/home/user/g/Real-Vuln-Benchmark}"
CODESEC_BIN="${CODESEC_BIN:-$CODESEC_ROOT/.venv/bin/codesec}"
PYTHON="${PYTHON:-$CODESEC_ROOT/.venv/bin/python3}"
if [[ ! -x "$PYTHON" ]]; then
  PYTHON="$(command -v python3)"
fi
export PYTHONPATH="${CODESEC_ROOT}${PYTHONPATH:+:$PYTHONPATH}"
RUNS_ROOT="${CODESEC_REALVULN_RUNS:-$CODESEC_ROOT/bench/realvuln-runs}"
OPERATOR_DIR="$RUNS_ROOT/operator"
THINKING="${THINKING:-off}"
MODEL="${MODEL:-glm-5.3}"
PROVIDER="${PROVIDER:-zai}"
# Distinct Semgrep slugs so a local Unsloth matrix cannot overwrite Z.AI glm-5.3.
SCANNER_TAG="${SCANNER_TAG:-glm53}"
HUNT_SCANNER="codesec-${SCANNER_TAG}-hunt"
FINAL_SCANNER="codesec-${SCANNER_TAG}-final"
PI_SCANNER="pi-${SCANNER_TAG}"

here() { cd "$CODESEC_ROOT"; }

digest_tree() {
  (
    cd "$1"
    find . -type f -print0 | sort -z | xargs -0 sha256sum
  ) | sha256sum | awk '{print $1}'
}

map_get() {
  "$PYTHON" -c 'import json,sys; print(json.load(open(sys.argv[1])).get(sys.argv[2]) or "")' "$1" "$2"
}

refuse_existing() {
  local path="$1"
  if [[ -e "$path" ]]; then
    echo "refusing to overwrite $path" >&2
    exit 1
  fi
}

scan_out() {
  local slug="$1" scanner="$2" trial="$3"
  echo "$REALVULN_ROOT/scan-results/$slug/$scanner/run-${trial}.json"
}
