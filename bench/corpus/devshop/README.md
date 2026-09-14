# devshop

Small SaaS-ish API: notes, auth, file uploads, coupons, admin panel. v0.3 (WIP).

This directory is benchmark input only. The answer key lives outside this
tree, and benchmark runners materialize a fresh read-only copy for every run.

## Run
```bash
pip install -r requirements.txt
python -c "from db import init; init()"
python app.py    # :5000
```

Routes: `/notes` (GET/POST), `/notes/<id>` (GET/DELETE), `/api/notes/<id>` (X-Api-Key),
`/search`, `/preview`, `/link-preview`, `/ping`, `/backup`, `/calc`, `/import`,
`/files` (GET/POST), `/files/raw`, `/go`, `/login`, `/register`, `/admin/users/<id>`
(PATCH), `/admin/report`, `/coupon/redeem`, `/transfer`, `/export/<fmt>`.

Trust boundary: all routes accept unauthenticated input unless gated. Notes are
owned per-user; the admin panel is for operators.
