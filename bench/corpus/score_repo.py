#!/usr/bin/env python3
"""Score a codesec agent run against a corpus ground-truth manifest.

  python3 score_repo.py <results_run_dir> <ground_truth.json>
"""
from __future__ import annotations
import json, re, os, sys, glob

def _norm(s): return re.sub(r"[^a-z0-9]", "", (s or "").lower())
def _text(f): return " ".join(str(f.get(k,"")) for k in ("description","evidence_snippet","file")).lower()

def _score(f, e):
    ffile = str(f.get("file","")); fname = os.path.basename(ffile)
    gfile = e.get("file","")
    if gfile and fname != gfile and gfile not in ffile:
        return -1
    vc = f.get("vuln_class","") or ""; cwe = f.get("cwe","") or ""; txt = _text(f)
    s = 0
    if vc and any(_norm(a) and _norm(a) in _norm(vc) for a in e.get("classes",[])):
        s += 100
    if cwe and e.get("cwe") and cwe == e["cwe"]:
        s += 50
    s += 10 * sum(1 for k in e.get("funcs",[]) if k.lower() in txt)
    return s

def match(f, entries):
    best, bs = None, 0
    for e in entries:
        s = _score(f, e)
        if s > bs: bs, best = s, e["id"]
    return best if bs > 0 else None

def load_run(run):
    hunts, verdicts = {}, {}
    for fn in glob.glob(os.path.join(run,"**","*.jsonl"),recursive=True):
        st = os.path.basename(os.path.dirname(fn))
        for line in open(fn):
            try: o=json.loads(line)
            except: continue
            if o.get("kind")=="final_payload":
                p=o["payload"]
                if st=="hunt":
                    for f in p.get("findings",[]) or []: hunts[f.get("finding_id")]=f
                elif st=="validate" and p.get("verdict"):
                    verdicts[p.get("finding_id")]=p["verdict"]
    return hunts, verdicts

def main():
    run, manifest = sys.argv[1], json.load(open(sys.argv[2]))
    entries = manifest["entries"]
    vuln_ids = [e["id"] for e in entries if e["vuln"]]
    decoy_ids = [e["id"] for e in entries if not e["vuln"]]
    hunts, verdicts = load_run(run)
    confirmed = {i:f for i,f in hunts.items() if verdicts.get(i)=="confirmed"}

    raw_hit, conf_hit, decoy_flagged = set(), set(), []
    for fid,f in hunts.items():
        gid = match(f, entries)
        if gid in vuln_ids:
            raw_hit.add(gid)
            if verdicts.get(fid)=="confirmed": conf_hit.add(gid)
        elif gid in decoy_ids:
            decoy_flagged.append((fid, f.get("vuln_class"), gid))
    # precision: confirmed findings -> real bug (not a decoy)
    conf_real = sum(1 for f in confirmed.values() if match(f, entries) in vuln_ids)

    tiers = {}
    for e in entries:
        if e["vuln"]: tiers.setdefault(e["tier"], []).append(e["id"])

    print(f"\n# {os.path.basename(run.rstrip('/'))}  vs  {manifest['target']}")
    print(f"   hunt={len(hunts)} confirmed={len(confirmed)} rejected={sum(1 for v in verdicts.values() if v=='rejected')}")
    print(f"\n   RECALL  distinct real bugs:  raw-hunt {len(raw_hit)}/{len(vuln_ids)} ({100*len(raw_hit)/len(vuln_ids):.0f}%)   "
          f"confirmed {len(conf_hit)}/{len(vuln_ids)} ({100*len(conf_hit)/len(vuln_ids):.0f}%)")
    for t in ["T1","T2","T3","secondary"]:
        ids = tiers.get(t, [])
        if not ids: continue
        ch = sum(1 for i in ids if i in conf_hit)
        print(f"     {t:9s} {ch}/{len(ids)} confirmed")
    miss = [i for i in vuln_ids if i not in conf_hit]
    if miss: print(f"   MISSED: {miss}")
    print(f"\n   PRECISION  confirmed -> real bug: {conf_real}/{len(confirmed)} ({100*conf_real/max(1,len(confirmed)):.0f}%)")
    if decoy_flagged:
        print(f"   decoys flagged as vulnerable (false positives): {len(decoy_flagged)}")
        for fid,vc,g in decoy_flagged[:10]: print(f"      - {vc} -> {g}")

if __name__=="__main__":
    main()
