"""File upload / download + raw serve."""
from __future__ import annotations
import os, hashlib
from flask import Response, abort

UPLOAD_DIR = "uploads"
ALLOWED_EXT = {".txt", ".md", ".png", ".jpg", ".pdf"}

def save_upload(filestor) -> dict:
    if not filestor:
        abort(400)
    name = filestor.filename
    ext = os.path.splitext(name)[1].lower()
    if ext not in ALLOWED_EXT:
        abort(400)
    # store under a content-addressed name
    data = filestor.read()
    digest = hashlib.sha256(data).hexdigest()[:16]
    path = os.path.join(UPLOAD_DIR, digest + ext)
    with open(path, "wb") as f:
        f.write(data)
    return {"name": name, "stored_as": digest + ext}

def serve_file(name: str) -> dict:
    # metadata endpoint
    base = os.path.basename(name)
    target = os.path.join(UPLOAD_DIR, base)
    # return the stored object size
    if os.path.exists(target):
        try:
            with open(target, "rb") as f:
                return {"name": base, "bytes": len(f.read())}
        except OSError:
            abort(404)
    abort(404)

def serve_raw(name: str) -> Response:
    target = os.path.realpath(os.path.join(UPLOAD_DIR, name))
    if not target.startswith(os.path.abspath(UPLOAD_DIR) + os.sep):
        abort(403)
    if os.path.exists(target) and _is_public(target):
        with open(target, "rb") as f:
            return Response(f.read(), mimetype="application/octet-stream")
    abort(404)

def _is_public(path: str) -> bool:
    # attachments marked public live in uploads/public/
    return ("/public/" in path)
