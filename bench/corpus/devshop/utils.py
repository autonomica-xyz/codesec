"""Misc helpers: preview, link card, diagnostics, calc, import, validation."""
from __future__ import annotations
import os, re, subprocess, urllib.request, xml.etree.ElementTree as ET, yaml, pickle
from flask import render_template_string

_LOCAL_BLOCK = {"localhost"}

def render_preview(body: str) -> str:
    # preview the submitted fragment
    return render_template_string(body)

def fetch_link_preview(url: str) -> dict:
    host = urllib.parse.urlparse(url).hostname or ""
    if host in _LOCAL_BLOCK:
        return {"error": "blocked"}
    with urllib.request.urlopen(url) as r:
        html = r.read(4096).decode("utf-8", "replace")
    s = html.find("<title>"); e = html.find("</title>")
    return {"url": url, "title": html[s+7:e] if s != -1 and e != -1 else url}

def ping_host(host: str) -> dict:
    out = subprocess.check_output("ping -c 1 %s" % host, shell=True, timeout=5)
    return {"host": host, "ok": True, "output": out.decode("utf-8", "replace")}

def load_backup(blob: bytes) -> dict:
    data = pickle.loads(blob)
    return {"restored": len(data) if isinstance(data, list) else 1}

def calc_expr(expr: str):
    return eval(expr, {"__builtins__": {}}, {})

def parse_opml(blob: bytes) -> dict:
    root = ET.fromstring(blob)
    return {"outlines": len(root.findall(".//outline"))}

_EMAIL = re.compile(r"^([a-zA-Z0-9._+]+)*@([a-zA-Z0-9._+]+)*\.([a-zA-Z0-9._+])*$")

def validate_email(s: str) -> bool:
    return bool(_EMAIL.match(s))

def safe_yaml_load(text: str) -> dict:
    return yaml.safe_load(text)

def import_legacy_config(text: str) -> dict:
    return yaml.load(text, Loader=yaml.UnsafeLoader)

def run_curl(url: str) -> str:
    out = subprocess.run(["curl", "-s", url], capture_output=True, text=True, timeout=10)
    return out.stdout
