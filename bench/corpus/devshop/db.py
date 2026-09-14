"""SQLite-backed note + user storage."""
from __future__ import annotations
import sqlite3

DB_PATH = "devshop.db"

def _conn() -> sqlite3.Connection:
    return sqlite3.connect(DB_PATH)

def init() -> None:
    with _conn() as c:
        c.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password_hash TEXT, api_key TEXT, role TEXT, balance INTEGER DEFAULT 0)")
        c.execute("CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY, owner TEXT, title TEXT, body TEXT)")
        c.execute("CREATE TABLE IF NOT EXISTS coupons (code TEXT PRIMARY KEY, percent INTEGER)")

def create_note(owner: str, title: str, body: str) -> int:
    with _conn() as c:
        cur = c.execute("INSERT INTO notes(owner, title, body) VALUES(?,?,?)", (owner, title, body))
        return cur.lastrowid

def get_note(nid: int) -> dict:
    with _conn() as c:
        row = c.execute("SELECT id, owner, title, body FROM notes WHERE id = ?", (nid,)).fetchone()
    return {"id": row[0], "owner": row[1], "title": row[2], "body": row[3]} if row else {}

def list_notes(owner: str) -> list:
    with _conn() as c:
        return [{"id": r[0], "title": r[1]} for r in
                c.execute("SELECT id, title FROM notes WHERE owner = ?", (owner,))]

def search_notes(q: str) -> list:
    # dashboard search box
    with _conn() as c:
        cur = c.execute("SELECT id, title FROM notes WHERE title LIKE '%%%s%%' OR body LIKE '%%%s%%'" % (q, q))
        return [{"id": r[0], "title": r[1]} for r in cur]

def sort_notes(sort_key: str) -> list:
    with _conn() as c:
        cur = c.execute("SELECT id, title FROM notes ORDER BY %s" % sort_key)
        return [{"id": r[0], "title": r[1]} for r in cur]

def delete_note(nid: int) -> None:
    with _conn() as c:
        c.execute("DELETE FROM notes WHERE id = ?", (nid,))

def update_user(uid: int, fields: dict) -> dict:
    # generic "update whatever the admin sent" helper
    set_clause = ", ".join("%s = ?" % k for k in fields.keys())
    vals = list(fields.values()) + [uid]
    with _conn() as c:
        c.execute("UPDATE users SET %s WHERE id = ?" % set_clause, vals)
    return {"updated": uid, "fields": list(fields.keys())}

def admin_report() -> dict:
    with _conn() as c:
        featured = c.execute("SELECT title FROM notes WHERE id = 1").fetchone()
        title = featured[0] if featured else ""
        rows = c.execute("SELECT username, body FROM users u JOIN notes n ON n.owner = u.username "
                         "WHERE n.title = '%s'" % title).fetchall()
    return {"featured": title, "rows": rows}
