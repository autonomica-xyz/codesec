#!/usr/bin/env python3
"""Score a codesec run vs the devnotes vuln-eval ground truth.

Detection quality only. A finding maps to a real bug when file matches AND
(vuln_class alias OR a text keyword in description/evidence OR a known CWE).
Multiple findings on one bug count once for recall.

  python3 score.py <results_run_dir>
"""
from __future__ import annotations
import json, glob, os, re, sys

# (id, file, [class aliases], [text keywords], cwe)
# grounded in the actual confirmed findings the models emitted.
PRIMARY = [
    ("ssti",              "utils.py", ["ssti","server_side_template","template_injection"], ["render_template_string","render_preview"], "CWE-94"),
    ("ssrf",              "utils.py", ["ssrf","server_side_request_forgery"], ["fetch_link_preview","link-preview","urlopen"], "CWE-918"),
    ("command_injection", "utils.py", ["command_injection","os_command_injection","shell_injection","cmd_injection"], ["ping_host","ping -c","check_output"], "CWE-78"),
    ("pickle_deserialization","utils.py",["insecure_deserialization","deserialization_pickle","pickle","deserialization"], ["pickle.loads","load_backup"], "CWE-502"),
    ("eval_rce",          "utils.py", ["code_injection","eval","expression_injection","rce"], ["eval_math","eval("], "CWE-94"),
    ("path_traversal",    "utils.py", ["path_traversal","directory_traversal","lfi","arbitrary_file_read"], ["download_attachment"], "CWE-22"),
    ("sqli_search_notes", "db.py",    ["sql_injection","sqli"], ["search_notes","/notes?q","like"], "CWE-89"),
    ("sqli_auth_login",   "auth.py",  ["sql_injection","sqli","auth_bypass","authentication_bypass","auth"], ["login_user","/login"], "CWE-89"),
    ("open_redirect",     "app.py",   ["open_redirect","unvalidated_redirect","redirect"], ["/go","next"], "CWE-601"),
    ("idor_notes",        "",         ["idor","broken_access_control","access_control","bola"], ["notes/<","get_note","delete_note","user_id","authorization"], ""),
    ("xss_comment",       "",         ["xss","cross_site_scripting"], ["|safe","comment.html","comment route"], "CWE-79"),
]
SECONDARY = [
    ("md5_weak_hash",        "auth.py",  ["weak_crypto","md5","weak_hash","insecure_hash"], ["md5","hashlib.md5"], "CWE-327"),
    ("hardcoded_credentials","auth.py",  ["hardcoded_credentials","hardcoded_password","insecure_configuration"], ["sync_password","admin123","sup3rstr0ng"], "CWE-798"),
    ("debug_mode",           "config.py",["debug_mode","debug_enabled"], ["debug=true","werkzeug","debugger","debug = true"], "CWE-489"),
    ("hardcoded_secret_key", "config.py",[], ["secret_key","secret key"], "CWE-798"),
    ("insecure_cookie",      "config.py",["insecure_cookie"], ["session_cookie_secure","cookie_secure","secure flag"], "CWE-614"),
]
# Real-ish but limited exploitability in this target; tracked, not counted against recall.
BORDERLINE = [
    ("xxe_parse_opml",   "utils.py", ["xxe","xml_external_entity"], ["parse_opml","et.fromstring","elementtree"], "CWE-611"),
    ("sqli_delete_note", "db.py",    ["sql_injection","sqli"], ["delete_note"], "CWE-89"),  # <int:nid> coerces -> not injectable
]
TIERS = [("primary", PRIMARY), ("secondary", SECONDARY), ("borderline", BORDERLINE)]


def _norm(s): return re.sub(r"[^a-z0-9]", "", (s or "").lower())
def _text(f): return " ".join(str(f.get(k,"")) for k in ("description","evidence_snippet","file")).lower()

def _score(f, entry):
    """Match strength: direct vuln_class alias (100) >> CWE (50) > keyword (10).
    Picks the most specific GT so a creds-finding-that-mentions-MD5 doesn't
    get stolen by md5, and a shared CWE-94 doesn't send eval->ssti."""
    gid, gfile, aliases, kws, gcwe = entry
    ffile = str(f.get("file", ""))
    if gfile and os.path.basename(ffile) != gfile and gfile not in ffile:
        return -1
    vc, cwe, txt = f.get("vuln_class","") or "", f.get("cwe","") or "", _text(f)
    s = 0
    if vc and any(_norm(a) and _norm(a) in _norm(vc) for a in aliases):
        s += 100
    if cwe and gcwe and cwe == gcwe:
        s += 50
    s += 10 * sum(1 for k in kws if k.lower() in txt)
    return s

def match(f):
    best, best_s = None, 0
    for _, entries in TIERS:
        for e in entries:
            s = _score(f, e)
            if s > best_s:
                best, best_s = e[0], s
    return best


def load_run(run):
    hunts, verdicts = {}, {}
    for fn in glob.glob(os.path.join(run, "**", "*.jsonl"), recursive=True):
        st = os.path.basename(os.path.dirname(fn))
        for line in open(fn):
            try: o = json.loads(line)
            except: continue
            if o.get("kind") == "final_payload":
                p = o["payload"]
                if st == "hunt":
                    for f in p.get("findings", []) or []: hunts[f.get("finding_id")] = f
                elif st == "validate" and p.get("verdict"):
                    verdicts[p.get("finding_id")] = p["verdict"]
    return hunts, verdicts


def main():
    run = sys.argv[1]
    hunts, verdicts = load_run(run)
    confirmed = {i: f for i, f in hunts.items() if verdicts.get(i) == "confirmed"}
    rej = sum(1 for v in verdicts.values() if v == "rejected")

    print(f"\n# {os.path.basename(run.rstrip('/'))}")
    print(f"   findings: hunt={len(hunts)}  confirmed={len(confirmed)}  rejected={rej}")

    real_ids = [g[0] for _, e in TIERS[:2] for g in e]
    raw_hit, conf_hit = set(), set()
    mapped, fps = 0, []
    for fid, f in hunts.items():
        gid = match(f)
        if gid in real_ids:
            raw_hit.add(gid)
            if verdicts.get(fid) == "confirmed": conf_hit.add(gid)
    for fid, f in confirmed.items():
        gid = match(f)
        if gid: mapped += 1
        else: fps.append((fid, f.get("vuln_class"), os.path.basename(str(f.get("file",""))), f.get("description","")[:70]))

    n_real = len(real_ids)
    print(f"\n   RECALL (distinct real bugs)   raw-hunt: {len(raw_hit)}/{n_real} ({100*len(raw_hit)/n_real:.0f}%)   "
          f"confirmed: {len(conf_hit)}/{n_real} ({100*len(conf_hit)/n_real:.0f}%)")
    miss = [b for b in real_ids if b not in conf_hit]
    print(f"   missed (not confirmed): {miss if miss else 'none'}")

    bl = [g[0] for g in BORDERLINE]
    bl_hit = {match(f) for f in hunts.values()} & set(bl)
    print(f"   borderline caught (not counted in recall): {sorted(bl_hit)}")

    prec = mapped / len(confirmed) if confirmed else 0
    print(f"   PRECISION (confirmed -> real bug): {mapped}/{len(confirmed)} ({100*prec:.0f}%)")
    if fps:
        print(f"   true false-positives (confirmed, no real bug): {len(fps)}")
        for fid, vc, fl, d in fps[:10]: print(f"      - {vc} @ {fl}: {d}")


if __name__ == "__main__":
    main()
