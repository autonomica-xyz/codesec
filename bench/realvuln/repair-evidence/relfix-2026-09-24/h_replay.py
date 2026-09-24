"""Step H diagnostic: replay the saved matrix H outputs through the
canonicalized evidence-to-report mapping (offline, deterministic) and
measure FP/TP deltas, the reserved diagnostic half, and the true-positive
controls (especially unsafe pickle loading). No model calls; no changes to
the saved artifacts (a transformed copy is scored in memory).
"""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, "/home/user/g/Real-Vuln-Benchmark")

from bench.realvuln.aggregate import _normalised_from_semgrep, _real_scorer
from bench.realvuln.experiment import load_manifest

from codesec.stages.report import _canonical_cwe
from types import SimpleNamespace

EXP = ROOT / "bench/realvuln-runs/experiments/matrix-20260923-01"
manifest = load_manifest(EXP)
lgt, match, NF = _real_scorer(Path(manifest["realvuln_root"]))


def doc_with_canonical(doc):
    """Apply the report-stage canonicalization to a committed export."""
    changed = []
    for r in doc.get("results", []):
        meta = (r.get("extra") or {}).get("metadata") or {}
        cwe = meta.get("cwe", [None])[0]
        if not cwe:
            continue
        f = SimpleNamespace(
            vuln_class=meta.get("vuln_class"),
            description=(r.get("extra") or {}).get("message", ""),
            evidence=meta.get("evidence", "") or "",
            raw_json={"cwe": cwe},
        )
        canon = _canonical_cwe(f)
        if canon and canon != cwe:
            meta["cwe"] = [canon]
            meta["cwe_before_canonicalization"] = cwe
            changed.append((r["path"], r["start"]["line"], cwe, canon))
    return changed


def score(doc):
    findings = _normalised_from_semgrep(doc, NF)
    gt = None
    return findings


rows = []
for cell in manifest["expected_cells"]:
    if cell["arm"] != "h":
        continue
    committed = EXP / "committed" / cell["cell_id"]
    mp = committed / "completion.json"
    if not mp.is_file():
        continue
    marker = json.loads(mp.read_text())
    doc = json.loads((committed / marker["primary_path"]).read_text())
    doc_before = json.loads(json.dumps(doc))  # deep copy for the baseline
    changed = doc_with_canonical(doc)
    gt = lgt(str(Path(manifest["realvuln_root"]) / "ground-truth"
                 / cell["repo"] / "ground-truth.json"))
    before = Counter(m.classification.upper()
                     for m in match(_normalised_from_semgrep(doc_before, NF), gt))
    after = Counter(m.classification.upper()
                    for m in match(_normalised_from_semgrep(doc, NF), gt))
    rows.append({
        "repo": cell["repo"], "trial": cell["trial"],
        "tp_before": before["TP"], "fp_before": before["FP"],
        "tp_after": after["TP"], "fp_after": after["FP"],
        "changed": changed,
    })

total = Counter()
for r in rows:
    total["tp_before"] += r["tp_before"]
    total["fp_before"] += r["fp_before"]
    total["tp_after"] += r["tp_after"]
    total["fp_after"] += r["fp_after"]

print("== replay totals (H arm, 18 cells):")
print(f"   before: TP={total['tp_before']} FP={total['fp_before']}")
print(f"   after : TP={total['tp_after']} FP={total['fp_after']}")
print(f"   delta : TP {total['tp_after']-total['tp_before']:+d}, "
      f"FP {total['fp_after']-total['fp_before']:+d}")
print("\n== per-claim changes:")
for r in rows:
    for (file, line, old, new) in r["changed"]:
        print(f"   {r['repo']} t{r['trial']} {file}:{line} {old} -> {new}")

# TP controls: unsafe pickle loading must remain TP.
controls = []
for r in rows:
    for (file, line, old, new) in r["changed"]:
        controls.append((r["repo"], file, line, old, new))
pickle_controls = [c for c in controls if c[3] in ("CWE-502",)]
print(f"\npickle-deserialization controls touched: {len(pickle_controls)} "
      f"(must be 0)")

# Reserved diagnostic half: did any rule fire on the reserved claims?
split = json.loads(
    (ROOT / "bench/realvuln/repair-evidence/relfix-2026-09-24/h-split.json")
    .read_text())
diag_fired = []
for claim in split["diagnostic_half"]:
    for r in rows:
        for (file, line, old, new) in r["changed"]:
            if (r["repo"] == claim["repo"] and file == claim["file"]
                    and line == claim["line"]):
                diag_fired.append((claim, old, new))
print(f"reserved-diagnostic claims touched: {len(diag_fired)}")
for claim, old, new in diag_fired:
    print("   ", claim, old, "->", new)

out = {
    "totals": dict(total),
    "rows": rows,
    "reserved_diagnostic_touched": [
        {"claim": c, "old": o, "new": n} for c, o, n in diag_fired],
    "pickle_controls_touched": len(pickle_controls),
}
(ROOT / "bench/realvuln/repair-evidence/relfix-2026-09-24/h-replay.json"
 ).write_text(json.dumps(out, indent=1, default=str))
print("\nwrote h-replay.json")
