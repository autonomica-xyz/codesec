#!/usr/bin/env bash
# serve.sh — run the devshop bench target on 127.0.0.1:${PORT:-5199}.
#
# Standalone launcher for the live-target path (W6 canary markers, W7
# live-probe Hunt). It does NOT modify the corpus tree: the app is imported
# via PYTHONPATH while the working directory (and therefore devshop.db,
# uploads/) lives under $RUN_DIR.
#
# Env knobs:
#   PORT                listen port                (default 5199)
#   DEVSHOP_RUN_DIR     writable runtime dir       (default ${TMPDIR:-/tmp}/devshop-live)
#   DEVSHOP_VENV        venv for app deps          (default ${XDG_CACHE_HOME:-$HOME/.cache}/codesec-devshop-venv)
#   DEVSHOP_USER        seeded username            (default bench)
#   DEVSHOP_PASSWORD    seeded password            (default devshop-bench-passw0rd)
#
# Auth notes:
#   * POST /login with form fields username/password sets a Flask session
#     cookie; the seeded user above is created on every startup if absent.
#   * POST /register creates fresh users and returns an api_key; the
#     X-Api-Key header is required by /api/notes/<id>.
#   * The defaults match bench/corpus/manifests/devshop.json "live".
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT="${PORT:-5199}"
HOST="127.0.0.1"
RUN_DIR="${DEVSHOP_RUN_DIR:-${TMPDIR:-/tmp}/devshop-live}"
VENV="${DEVSHOP_VENV:-${XDG_CACHE_HOME:-$HOME/.cache}/codesec-devshop-venv}"
BENCH_USER="${DEVSHOP_USER:-bench}"
BENCH_PASSWORD="${DEVSHOP_PASSWORD:-devshop-bench-passw0rd}"

# --- pick an interpreter with the app deps -----------------------------------
# Prefer the repo venv / system python3 when they already have Flask & co;
# otherwise build a dedicated venv once.
PYBIN=""
REPO_VENV_PY="$HERE/../../../.venv/bin/python"
for cand in "$REPO_VENV_PY" "$(command -v python3 || true)"; do
    if [ -n "$cand" ] && [ -x "$cand" ] && \
       "$cand" -c "import flask, bcrypt, jwt, yaml" >/dev/null 2>&1; then
        PYBIN="$cand"
        break
    fi
done
if [ -z "$PYBIN" ]; then
    if [ ! -x "$VENV/bin/python" ]; then
        echo "[serve.sh] creating venv at $VENV" >&2
        python3 -m venv "$VENV"
    fi
    REQ_STAMP="$VENV/.reqs-$(cksum "$HERE/requirements.txt" | awk '{print $1"-"$2}')"
    if [ ! -f "$REQ_STAMP" ]; then
        echo "[serve.sh] installing $HERE/requirements.txt" >&2
        "$VENV/bin/pip" install -q -r "$HERE/requirements.txt"
        rm -f "$VENV"/.reqs-* 2>/dev/null || true
        touch "$REQ_STAMP"
    fi
    PYBIN="$VENV/bin/python"
fi

# --- writable runtime dir: devshop.db + uploads live here, not in the corpus -
mkdir -p "$RUN_DIR/uploads"
cd "$RUN_DIR"
export PYTHONPATH="$HERE"
export UPLOAD_DIR="$RUN_DIR/uploads"

# --- init schema + seed the bench user ---------------------------------------
DEVSHOP_USER="$BENCH_USER" DEVSHOP_PASSWORD="$BENCH_PASSWORD" "$PYBIN" - <<'PYEOF'
import os, sqlite3
from db import init, create_note
import auth

init()
user = os.environ["DEVSHOP_USER"]
pw = os.environ["DEVSHOP_PASSWORD"]
with sqlite3.connect("devshop.db") as c:
    row = c.execute("SELECT api_key FROM users WHERE username = ?", (user,)).fetchone()
if row:
    api_key = row[0]
else:
    api_key = auth.register_user(user, pw)["api_key"]
# One seed note so /notes/<id> and /admin/report have content.
with sqlite3.connect("devshop.db") as c:
    if not c.execute("SELECT 1 FROM notes LIMIT 1").fetchone():
        create_note(user, "welcome", "seeded bench note")
print(f"[serve.sh] seeded user {user!r} (api_key {api_key[:8]}...)")
PYEOF

echo "[serve.sh] devshop on http://$HOST:$PORT (run dir: $RUN_DIR)" >&2
exec "$PYBIN" - "$HOST" "$PORT" <<'PYEOF'
import sys
from app import app
app.run(host=sys.argv[1], port=int(sys.argv[2]), debug=False, use_reloader=False)
PYEOF
