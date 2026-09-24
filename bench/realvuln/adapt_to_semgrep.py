#!/usr/bin/env python3
"""Convert Pi findings or a codesec run root into Semgrep JSON for RealVuln."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from bench.score_repo import load_stage_outputs
from bench.realvuln.common import (
    extract_cwe,
    extract_json_object,
    load_json,
    normalize_relpath,
    slug_aliases,
    write_json,
)


def _semgrep_result(finding: dict, target: Path | None) -> dict | None:
    path = normalize_relpath(finding.get("file") or finding.get("path") or "", target)
    start = finding.get("line_start") or finding.get("line") or (
        (finding.get("start") or {}).get("line") if isinstance(finding.get("start"), dict) else None
    )
    end = finding.get("line_end") or start
    try:
        start_i = int(start)
        end_i = int(end)
    except (TypeError, ValueError):
        return None
    if start_i < 1 or end_i < 1:
        return None
    cwe = extract_cwe(finding.get("cwe") or finding.get("CWE"))
    extra_meta = finding.get("extra", {}).get("metadata") if isinstance(finding.get("extra"), dict) else {}
    if not cwe:
        cwe = extract_cwe((extra_meta or {}).get("cwe"))
    if not path or not cwe:
        return None
    severity = str(finding.get("severity") or "WARNING").upper()
    if severity.lower() in {"critical", "high"}:
        severity = "ERROR"
    elif severity.lower() in {"medium"}:
        severity = "WARNING"
    else:
        severity = "INFO"
    return {
        "check_id": finding.get("finding_id") or finding.get("title") or cwe,
        "path": path,
        "start": {"line": start_i},
        "end": {"line": end_i},
        "extra": {
            "message": finding.get("description") or finding.get("title") or "",
            "severity": severity,
            "metadata": {
                "cwe": [cwe],
                "finding_id": finding.get("finding_id"),
                "vuln_class": finding.get("vuln_class"),
            },
        },
    }


def _canary_hit(result: dict, canary: dict | None) -> bool:
    if not canary:
        return False
    if result.get("path") != canary.get("file"):
        return False
    line = int(result["start"]["line"])
    start = int(canary["line"])
    end = int(canary.get("line_end") or start)
    return not (line > end + 10 or line < start - 10)


def _filter(results: list[dict], canary: dict | None) -> tuple[list[dict], list[dict], bool]:
    kept: list[dict] = []
    dropped: list[dict] = []
    hit = False
    for item in results:
        if item is None:
            dropped.append({"reason": "unparseable"})
            continue
        if _canary_hit(item, canary):
            hit = True
            dropped.append({"reason": "canary", "path": item.get("path"), "line": item["start"]["line"]})
            continue
        kept.append(item)
    return kept, dropped, hit


def _wrap(results: list[dict]) -> dict:
    return {"version": "codesec-realvuln-1", "results": results}


def from_pi(path: Path, target: Path | None) -> tuple[list[dict], list[dict]]:
    raw = path.read_text()
    try:
        payload = extract_json_object(raw)
    except (json.JSONDecodeError, ValueError) as exc:
        raise SystemExit(f"unparseable findings.json: {exc}") from exc
    findings = payload.get("findings")
    if findings is None:
        raise SystemExit("findings.json missing findings array")
    kept: list[dict] = []
    dropped: list[dict] = []
    for finding in findings:
        converted = _semgrep_result(finding, target)
        if converted is None:
            dropped.append({"reason": "missing path/line/cwe", "raw": finding})
        else:
            kept.append(converted)
    return kept, dropped


def from_codesec(run_root: Path, target: Path | None) -> tuple[list[dict], list[dict], list[dict], list[dict]]:
    stages = load_stage_outputs(run_root)
    hunt_kept: list[dict] = []
    hunt_drop: list[dict] = []
    for finding in stages["hunt"].values():
        converted = _semgrep_result(finding, target)
        if converted is None:
            hunt_drop.append({"reason": "missing path/line/cwe", "raw": finding})
        else:
            hunt_kept.append(converted)
    final_kept: list[dict] = []
    final_drop: list[dict] = []
    for finding in stages["report"].get("findings") or []:
        converted = _semgrep_result(finding, target)
        if converted is None:
            final_drop.append({"reason": "missing path/line/cwe", "raw": finding})
        else:
            final_kept.append(converted)
    return hunt_kept, hunt_drop, final_kept, final_drop


def identity_hits(text: str, slug: str) -> list[str]:
    hits: list[str] = []
    lower = text.lower()
    for alias in slug_aliases(slug):
        if alias.lower() in lower:
            hits.append(alias)
    return sorted(set(hits))


def scan_identity(paths: list[Path], slug: str) -> list[str]:
    found: list[str] = []
    for path in paths:
        if not path.exists():
            continue
        if path.is_dir():
            for child in path.rglob("*"):
                if child.is_file() and child.stat().st_size < 4_000_000:
                    try:
                        text = child.read_text(errors="ignore")
                    except OSError:
                        continue
                    for hit in identity_hits(text, slug):
                        found.append(f"{child}:{hit}")
        else:
            text = path.read_text(errors="ignore")
            for hit in identity_hits(text, slug):
                found.append(f"{path}:{hit}")
    return found


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--from-pi", type=Path)
    src.add_argument("--from-codesec", type=Path)
    parser.add_argument("--map", required=True, type=Path)
    parser.add_argument("--out", type=Path, help="Pi / single-output path")
    parser.add_argument("--hunt-out", type=Path)
    parser.add_argument("--final-out", type=Path)
    parser.add_argument("--dropped-out", type=Path)
    parser.add_argument("--metrics-out", type=Path)
    parser.add_argument("--identity-out", type=Path)
    args = parser.parse_args(argv)

    payload = load_json(args.map)
    target = Path(payload["target"]) if payload.get("target") else None
    canary = payload.get("canary")
    slug = payload["slug"]

    metrics = {
        "slug": slug,
        "opaque_id": payload.get("opaque_id"),
        "arm": payload.get("arm"),
        "trial": payload.get("trial"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "canary_hit": False,
    }

    if args.from_pi:
        if not args.out:
            raise SystemExit("--out is required with --from-pi")
        kept, dropped = from_pi(args.from_pi, target)
        kept, extra, hit = _filter(kept, canary)
        dropped.extend(extra)
        if args.out.exists():
            raise SystemExit(f"refusing to overwrite {args.out}")
        write_json(args.out, _wrap(kept))
        metrics.update(
            {
                "kept": len(kept),
                "dropped": len(dropped),
                "canary_hit": hit,
                "source": "pi",
            }
        )
        identity_paths = [args.from_pi]
    else:
        if not args.hunt_out or not args.final_out:
            raise SystemExit("--hunt-out and --final-out required with --from-codesec")
        hunt, hunt_drop, final, final_drop = from_codesec(args.from_codesec, target)
        hunt, hunt_extra, hunt_hit = _filter(hunt, canary)
        final, final_extra, final_hit = _filter(final, canary)
        for dest, blob in ((args.hunt_out, hunt), (args.final_out, final)):
            if dest.exists():
                raise SystemExit(f"refusing to overwrite {dest}")
            write_json(dest, _wrap(blob))
        dropped = hunt_drop + hunt_extra + final_drop + final_extra
        hit = hunt_hit or final_hit
        metrics.update(
            {
                "kept_hunt": len(hunt),
                "kept_final": len(final),
                "dropped": len(dropped),
                "canary_hit": hit,
                "source": "codesec",
            }
        )
        identity_paths = [args.from_codesec]

    if args.dropped_out:
        write_json(args.dropped_out, {"dropped": dropped})
    if args.identity_out:
        hits = scan_identity(identity_paths, slug)
        args.identity_out.write_text("\n".join(hits) + ("\n" if hits else ""))
        metrics["identity_leak"] = bool(hits)
        metrics["identity_hits"] = hits[:50]
    if args.metrics_out:
        write_json(args.metrics_out, metrics)
    print(json.dumps({k: metrics[k] for k in metrics if k != "identity_hits"}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
