"""Step G.1: deterministic selection manifest for the FP review sample.

From the saved matrix's H official scored FPs: sort by repo/trial/finding
ID, deduplicate identical (file, line, CWE) claims (retaining occurrence
counts), then with seed 20260924 choose up to four claims per repo
(max 24). Up to one Pi FP per repo as a comparison sample. The manifest is
written BEFORE any source inspection.
"""
from __future__ import annotations

import json
import random
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, "/home/user/g/Real-Vuln-Benchmark")

from bench.realvuln.aggregate import _normalised_from_semgrep, _real_scorer
from bench.realvuln.experiment import cell_id_of, load_manifest

EXP = ROOT / "bench/realvuln-runs/experiments/matrix-20260923-01"
SEED = 20260924
MAX_PER_REPO = 4
MAX_TOTAL = 24

manifest = load_manifest(EXP)
load_ground_truth, match_findings, NormalisedFinding = _real_scorer(
    Path(manifest["realvuln_root"])
)

fps: list[dict] = []
for cell in manifest["expected_cells"]:
    committed = EXP / "committed" / cell["cell_id"]
    marker_path = committed / "completion.json"
    if not marker_path.is_file():
        continue
    marker = json.loads(marker_path.read_text())
    doc = json.loads((committed / marker["primary_path"]).read_text())
    gt = load_ground_truth(str(
        Path(manifest["realvuln_root"]) / "ground-truth" / cell["repo"]
        / "ground-truth.json"))
    findings = _normalised_from_semgrep(doc, NormalisedFinding)
    matches = match_findings(findings, gt)
    for finding, m in zip(findings, matches):
        if m.classification.upper() != "FP":
            continue
        fps.append({
            "repo": cell["repo"], "trial": cell["trial"], "arm": cell["arm"],
            "finding_id": finding.finding_id or "",
            "file": finding.file, "line": finding.line, "cwe": finding.cwe,
            "match_reason": (
                "unmatched" if m.ground_truth_entry is None else
                ("duplicate_positive_match" if m.ground_truth_entry.get(
                    "is_vulnerable") else "labeled_decoy")
            ),
            "gt_id": m.ground_truth_id,
        })

# Deduplicate identical file/location/CWE claims within (repo, arm),
# retaining occurrence counts.
def key(f):
    return (f["repo"], f["arm"], f["file"], f["line"], f["cwe"])

claims: dict[tuple, dict] = {}
for f in sorted(fps, key=lambda f: (f["repo"], f["trial"], f["finding_id"])):
    k = key(f)
    if k not in claims:
        claims[k] = {
            "repo": f["repo"], "arm": f["arm"], "file": f["file"],
            "line": f["line"], "cwe": f["cwe"],
            "occurrences": 0, "trials": set(), "finding_ids": [],
            "match_reasons": set(), "gt_ids": set(),
        }
    c = claims[k]
    c["occurrences"] += 1
    c["trials"].add(f["trial"])
    c["finding_ids"].append(f["finding_id"])
    c["match_reasons"].add(f["match_reason"])
    if f["gt_id"]:
        c["gt_ids"].add(f["gt_id"])

for c in claims.values():
    c["trials"] = sorted(c["trials"])
    c["match_reasons"] = sorted(c["match_reasons"])
    c["gt_ids"] = sorted(c["gt_ids"])

manifest_out = {
    "seed": SEED, "created_before_source_inspection": True,
    "h_fp_occurrences_total": len(fps),
    "h_unique_claims_total": len(claims),
    "selection": {}, "pi_comparison": {}, "undersupply": [],
}
by_repo: dict[str, list[dict]] = defaultdict(list)
for c in claims.values():
    by_repo[f'{c["repo"]}#{c["arm"]}'].append(c)

rng = random.Random(SEED)
selected = []
for repo_key in sorted(set(k.split("#")[0] for k in by_repo)):
    h_claims = [c for k, cs in by_repo.items()
                if k.startswith(repo_key + "#") and cs[0]["arm"] == "h"
                for c in cs]
    pool = sorted(h_claims, key=lambda c: (
        c["file"], c["line"], c["cwe"]))
    take = pool[:MAX_PER_REPO] if len(pool) <= MAX_PER_REPO else (
        sorted(rng.sample(pool, MAX_PER_REPO),
               key=lambda c: (c["file"], c["line"], c["cwe"])))
    if len(pool) < MAX_PER_REPO:
        manifest_out["undersupply"].append(
            {"repo": repo_key, "available": len(pool),
             "note": "fewer unique H FP claims than the per-repo cap"})
    manifest_out["selection"][repo_key] = [
        {k: c[k] for k in (
            "file", "line", "cwe", "occurrences", "trials", "finding_ids",
            "match_reasons", "gt_ids")}
        for c in take]
    selected.extend(take)
    pi_claims = [c for k, cs in by_repo.items()
                 if k.startswith(repo_key + "#") and cs[0]["arm"] == "v"
                 for c in cs]
    if pi_claims:
        pick = sorted(pi_claims, key=lambda c: (
            c["file"], c["line"], c["cwe"]))[0]
        manifest_out["pi_comparison"][repo_key] = {
            k: pick[k] for k in (
                "file", "line", "cwe", "occurrences", "trials",
                "finding_ids", "match_reasons", "gt_ids")}

manifest_out["selected_h_claims"] = len(selected)
manifest_out["sampled_h_occurrences"] = sum(c["occurrences"] for c in selected)
out = ROOT / "bench/realvuln/repair-evidence/relfix-2026-09-24/fp-sample-manifest.json"
out.write_text(json.dumps(manifest_out, indent=1))
print(f"H FP occurrences: {len(fps)}; unique claims: {len(claims)}")
print(f"selected: {manifest_out['selected_h_claims']} claims, "
      f"{manifest_out['sampled_h_occurrences']} occurrences")
print(f"pi comparison claims: {len(manifest_out['pi_comparison'])}")
print("wrote", out)
