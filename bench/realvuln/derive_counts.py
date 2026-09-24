#!/usr/bin/env python3
"""Rewrite subset-counts.json from the pinned RealVuln checkout."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from bench.realvuln.common import (
    DEFAULT_REALVULN,
    HERE,
    SMOKE_SLUG,
    WAVE1_SLUGS,
    write_json,
)


def _count(gt_path: Path) -> dict:
    gt = json.loads(gt_path.read_text())
    findings = gt.get("findings") or []
    # P08 fix: non-scoring entries are excluded from BOTH the vulnerable
    # and the decoy counts (the previous helper counted them twice — once
    # in vulns/traps and again in non_scoring).
    scored = [f for f in findings if f.get("scoring", "scored") != "non_scoring"]
    non_scoring = [f for f in findings if f.get("scoring") == "non_scoring"]
    return {
        "vulns": sum(1 for f in scored if f.get("is_vulnerable")),
        "traps": sum(1 for f in scored if not f.get("is_vulnerable")),
        "non_scoring": len(non_scoring),
        "non_scoring_vulnerable": sum(
            1 for f in non_scoring if f.get("is_vulnerable")
        ),
        "commit_sha": gt.get("commit_sha") or "",
        "benchmark_version": gt.get("benchmark_version"),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--realvuln", default=str(DEFAULT_REALVULN), type=Path)
    parser.add_argument("--out", default=str(HERE / "subset-counts.json"), type=Path)
    args = parser.parse_args(argv)
    root = args.realvuln.resolve()
    sha = subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", "HEAD"], text=True
    ).strip()
    smoke = {SMOKE_SLUG: _count(root / "ground-truth" / SMOKE_SLUG / "ground-truth.json")}
    wave1 = {
        slug: _count(root / "ground-truth" / slug / "ground-truth.json")
        for slug in WAVE1_SLUGS
    }
    totals = {
        "vulns": sum(v["vulns"] for v in wave1.values()),
        "traps": sum(v["traps"] for v in wave1.values()),
        "non_scoring": sum(v["non_scoring"] for v in wave1.values()),
    }
    write_json(
        Path(args.out),
        {
            "realvuln_git_sha": sha,
            "smoke": smoke,
            "wave1": wave1,
            "wave1_totals": totals,
        },
    )
    print(json.dumps({"sha": sha, "wave1_totals": totals}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
