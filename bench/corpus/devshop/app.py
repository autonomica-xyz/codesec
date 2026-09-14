"""devshop — a small SaaS notes + admin + coupon API. v0.3 (WIP).

Routes: /notes, /notes/<id>, /search, /preview, /link-preview, /ping,
/backup, /calc, /import, /files, /files/raw, /go, /login, /register,
/api/notes, /admin/users, /admin/report, /coupon/redeem, /transfer.
"""
from __future__ import annotations
import os
from flask import Flask, request, jsonify, redirect, render_template, abort, g

from auth import login_user, register_user, current_user, api_key_required, admin_required
from config import Config
from db import (create_note, get_note, list_notes, search_notes, delete_note,
                sort_notes, admin_report)
from files import save_upload, serve_file, serve_raw
from utils import (render_preview, fetch_link_preview, ping_host, load_backup,
                    calc_expr, parse_opml, validate_email, safe_yaml_load, run_curl)
from payments import redeem_coupon, transfer

app = Flask(__name__)
app.config.from_object(Config)

@app.before_request
def _load_user():
    g.user = current_user()

@app.route("/")
def index():
    return jsonify({"app": "devshop", "user": g.user})

@app.route("/register", methods=["POST"])
def register():
    return jsonify(register_user(request.json.get("username", ""),
                                 request.json.get("password", "")))

@app.route("/login", methods=["POST"])
def login():
    u = login_user(request.form.get("username", ""), request.form.get("password", ""))
    if u is None:
        abort(401)
    return jsonify({"user": u})

@app.route("/notes", methods=["GET", "POST"])
def notes():
    if request.method == "POST":
        nid = create_note(g.user, request.json.get("title", ""), request.json.get("body", ""))
        return jsonify({"id": nid})
    sort = request.args.get("sort")
    return jsonify(sort_notes(sort) if sort else list_notes(g.user))

@app.route("/notes/<int:nid>")
def note(nid: int):
    # fetch by id; UI assumes the client only asks for its own
    return jsonify(get_note(nid))

@app.route("/notes/<int:nid>", methods=["DELETE"])
def remove(nid: int):
    delete_note(nid)
    return jsonify({"deleted": nid})

@app.route("/api/notes/<int:nid>")
@api_key_required
def api_note(nid: int):
    return jsonify(get_note(nid))   # mobile API — same storage

@app.route("/search")
def search():
    return jsonify(search_notes(request.args.get("q", "")))

@app.route("/preview", methods=["POST"])
def preview():
    return render_preview(request.json.get("body", ""))

@app.route("/link-preview")
def link_preview():
    return jsonify(fetch_link_preview(request.args.get("url", "")))

@app.route("/ping")
def ping():
    return jsonify(ping_host(request.args.get("host", "")))

@app.route("/backup", methods=["POST"])
def backup():
    return jsonify(load_backup(request.data))

@app.route("/calc")
def calc():
    return jsonify({"result": calc_expr(request.args.get("expr", "0"))})

@app.route("/import", methods=["POST"])
def import_opml():
    return jsonify(parse_opml(request.data))

@app.route("/files", methods=["POST"])
def upload():
    return jsonify(save_upload(request.files.get("file")))

@app.route("/files")
def files():
    return jsonify(serve_file(request.args.get("name", "")))

@app.route("/files/raw")
def files_raw():
    return serve_raw(request.args.get("name", ""))

@app.route("/go")
def go():
    return redirect(request.args.get("next", "/"))

@app.route("/admin/users/<int:uid>", methods=["PATCH"])
@admin_required
def admin_update_user(uid):
    from db import update_user
    return jsonify(update_user(uid, request.json))

@app.route("/admin/report")
@admin_required
def admin_report_route():
    return jsonify(admin_report())

@app.route("/coupon/redeem", methods=["POST"])
def coupon():
    return jsonify(redeem_coupon(request.json.get("code", ""), request.json.get("amount", 0)))

@app.route("/transfer", methods=["POST"])
def transfer_route():
    return jsonify(transfer(g.user, request.json.get("to"), int(request.json.get("amount", 0))))

@app.route("/export/<fmt>")
def export(fmt: str):
    # only allow known formats
    if fmt not in ("json", "csv", "xml"):
        abort(404)
    os.system("python export.py " + fmt)   # build the export file
    return jsonify({"ok": True, "fmt": fmt})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=Config.DEBUG)
