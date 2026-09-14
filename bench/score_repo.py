#!/usr/bin/env python3
"""Score candidate, validation, trace, and final pipeline outputs.

Usage:
  python3 -m bench.score_repo <report.json|results_run_dir> <manifest.json>
  python3 -m bench.score_repo <results_run_dir> <manifest.json> --stages
"""

from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path
from typing import Callable


def _norm(value) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value or "").lower())


def _overlaps(finding: dict, entry: dict) -> bool:
    try:
        finding_start = int(finding["line_start"])
        finding_end = int(finding.get("line_end", finding_start))
        truth_start = int(entry["line_start"])
        truth_end = int(entry.get("line_end", truth_start))
    except (KeyError, TypeError, ValueError):
        return False
    return not (finding_end < truth_start or truth_end < finding_start)


def _score(finding: dict, entry: dict) -> int:
    finding_file = os.path.basename(str(finding.get("file", "")))
    if finding_file != entry.get("file"):
        return -1
    if not _overlaps(finding, entry):
        return -1

    score = 1000  # exact file + source-line overlap is mandatory
    finding_class = _norm(finding.get("vuln_class"))
    aliases = [_norm(alias) for alias in entry.get("classes", [])]
    if finding_class and any(
        alias and (alias in finding_class or finding_class in alias)
        for alias in aliases
    ):
        score += 100
    finding_cwe = str(finding.get("cwe") or "").upper()
    truth_cwe = str(entry.get("cwe") or "").upper()
    if finding_cwe and truth_cwe and finding_cwe == truth_cwe:
        score += 50
    return score


def match(
    finding: dict,
    entries: list[dict],
    *,
    used_ids: set[str] | None = None,
) -> str | None:
    used = used_ids or set()
    candidates = [
        (_score(finding, entry), entry["id"])
        for entry in entries
        if entry["id"] not in used
    ]
    score, entry_id = max(candidates, default=(-1, None))
    return entry_id if score >= 1000 else None


def evaluate(report: dict, manifest: dict) -> dict:
    entries = manifest["entries"]
    by_id = {entry["id"]: entry for entry in entries}
    findings = report.get("findings", []) or []
    used: set[str] = set()
    matched: list[tuple[dict, str | None]] = []

    # Strongest edges first prevents a generic overlapping report from taking
    # an entry away from a class/CWE-exact report at the same source location.
    edges = sorted(
        (
            (_score(finding, entry), index, entry["id"])
            for index, finding in enumerate(findings)
            for entry in entries
        ),
        reverse=True,
    )
    assignment: dict[int, str] = {}
    assigned_findings: set[int] = set()
    for score, index, entry_id in edges:
        if score < 1000 or index in assigned_findings or entry_id in used:
            continue
        assignment[index] = entry_id
        assigned_findings.add(index)
        used.add(entry_id)

    for index, finding in enumerate(findings):
        matched.append((finding, assignment.get(index)))

    positive_ids = {entry["id"] for entry in entries if entry["vuln"]}
    decoy_ids = {entry["id"] for entry in entries if not entry["vuln"]}
    hit_ids = {entry_id for entry_id in used if entry_id in positive_ids}
    flagged_decoys = {entry_id for entry_id in used if entry_id in decoy_ids}
    true_positive_findings = sum(
        entry_id in positive_ids for _, entry_id in matched
    )
    false_positive_findings = len(findings) - true_positive_findings
    precision = (
        true_positive_findings / len(findings) if findings else 0.0
    )
    recall = len(hit_ids) / len(positive_ids) if positive_ids else 0.0
    specificity = (
        (len(decoy_ids) - len(flagged_decoys)) / len(decoy_ids)
        if decoy_ids
        else 0.0
    )
    by_tier = {}
    for tier in sorted(
        {entry["tier"] for entry in entries if entry["vuln"]}
    ):
        tier_ids = {
            entry["id"]
            for entry in entries
            if entry["vuln"] and entry["tier"] == tier
        }
        by_tier[tier] = {
            "hit": len(tier_ids & hit_ids),
            "total": len(tier_ids),
        }
    return {
        "findings": len(findings),
        "true_positive_findings": true_positive_findings,
        "false_positive_findings": false_positive_findings,
        "hit_ids": sorted(hit_ids),
        "missed_ids": sorted(positive_ids - hit_ids),
        "flagged_decoys": sorted(flagged_decoys),
        "precision": precision,
        "recall": recall,
        "specificity": specificity,
        "by_tier": by_tier,
        "matches": [
            {
                "finding_id": finding.get("finding_id"),
                "entry_id": entry_id,
                "is_true_positive": entry_id in positive_ids,
            }
            for finding, entry_id in matched
        ],
    }


def _results_root(path: Path) -> Path:
    if (path / "results").is_dir():
        return path / "results"
    return path


def load_stage_outputs(path: Path) -> dict:
    """Load authoritative final payloads from one results/run root."""
    root = _results_root(path)
    hunts: dict[str, dict] = {}
    validations: dict[str, dict] = {}
    traces: dict[str, dict] = {}

    for artifact in sorted(root.rglob("*.jsonl")):
        stage = artifact.parent.name
        if stage not in {"hunt", "validate", "trace"}:
            continue
        for line in artifact.read_text().splitlines():
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if record.get("kind") != "final_payload":
                continue
            payload = record.get("payload") or {}
            if stage == "hunt":
                for finding in payload.get("findings", []) or []:
                    finding_id = finding.get("finding_id")
                    if finding_id:
                        hunts[finding_id] = finding
            elif stage == "validate" and payload.get("finding_id"):
                validations[payload["finding_id"]] = payload
            elif stage == "trace" and payload.get("finding_id"):
                traces[payload["finding_id"]] = payload

    report_path = root / "report" / "report.json"
    report = json.loads(report_path.read_text()) if report_path.is_file() else {
        "findings": []
    }
    review_path = root / "report" / "review_queue.json"
    review = json.loads(review_path.read_text()) if review_path.is_file() else {
        "findings": []
    }
    return {
        "hunt": hunts,
        "validate": validations,
        "trace": traces,
        "report": report,
        "review": review,
    }


def _manifest_for_stage(
    manifest: dict,
    predicate: Callable[[dict], bool],
) -> dict:
    return {
        **manifest,
        "entries": [
            {**entry, "vuln": bool(predicate(entry))}
            for entry in manifest["entries"]
        ],
    }


def _assign_findings(
    findings: list[dict],
    entries: list[dict],
) -> dict[int, str]:
    edges = sorted(
        (
            (_score(finding, entry), index, entry["id"])
            for index, finding in enumerate(findings)
            for entry in entries
        ),
        reverse=True,
    )
    assignment: dict[int, str] = {}
    used: set[str] = set()
    for score, index, entry_id in edges:
        if score < 1000 or index in assignment or entry_id in used:
            continue
        assignment[index] = entry_id
        used.add(entry_id)
    return assignment


def _trace_metrics(outputs: dict, manifest: dict) -> dict:
    findings = list(outputs["hunt"].values())
    assignment = _assign_findings(findings, manifest["entries"])
    finding_by_entry = {
        entry_id: findings[index]
        for index, entry_id in assignment.items()
    }
    eligible = {
        entry["id"]: entry["reachability"]
        for entry in manifest["entries"]
        if entry.get("vuln")
        and entry.get("reachability") in {"reachable", "unreachable"}
    }
    decisions: list[dict] = []
    correct = 0
    decided = 0
    for entry_id, expected in sorted(eligible.items()):
        finding = finding_by_entry.get(entry_id)
        trace = (
            outputs["trace"].get(finding.get("finding_id"))
            if finding is not None
            else None
        )
        actual = None
        if trace is not None:
            status = trace.get("status")
            if status in {"reachable", "unreachable", "uncertain"}:
                actual = status
            elif trace.get("reachable") is True:
                actual = "reachable"
            elif trace.get("reachable") is False:
                actual = "unreachable"
        is_decided = actual in {"reachable", "unreachable"}
        is_correct = is_decided and actual == expected
        decided += int(is_decided)
        correct += int(is_correct)
        decisions.append(
            {
                "entry_id": entry_id,
                "finding_id": (
                    finding.get("finding_id") if finding is not None else None
                ),
                "expected": expected,
                "actual": actual or "missing",
                "correct": is_correct,
            }
        )
    total = len(eligible)
    return {
        "eligible": total,
        "decided": decided,
        "correct": correct,
        "coverage": decided / total if total else 0.0,
        "accuracy": correct / decided if decided else 0.0,
        "end_to_end_accuracy": correct / total if total else 0.0,
        "decisions": decisions,
    }


def evaluate_stages(path: Path, manifest: dict) -> dict:
    outputs = load_stage_outputs(path)
    candidate_findings = list(outputs["hunt"].values())
    confirmed_findings = [
        finding
        for finding_id, finding in outputs["hunt"].items()
        if (outputs["validate"].get(finding_id) or {}).get("verdict")
        == "confirmed"
    ]
    candidate_manifest = _manifest_for_stage(
        manifest, lambda entry: bool(entry.get("vuln"))
    )
    final_manifest = _manifest_for_stage(
        manifest,
        lambda entry: (
            entry.get("expected_stage") == "final"
            if "expected_stage" in entry
            else bool(entry.get("vuln"))
        ),
    )
    return {
        "candidate": evaluate(
            {"findings": candidate_findings}, candidate_manifest
        ),
        "confirmed": evaluate(
            {"findings": confirmed_findings}, candidate_manifest
        ),
        "trace": _trace_metrics(outputs, manifest),
        "final": evaluate(outputs["report"], final_manifest),
        "review_count": len(outputs["review"].get("findings", []) or []),
        "stage_counts": {
            "candidate": len(candidate_findings),
            "validated": len(outputs["validate"]),
            "confirmed": len(confirmed_findings),
            "traced": len(outputs["trace"]),
            "final": len(outputs["report"].get("findings", []) or []),
        },
    }


def _resolve_report(path: Path) -> Path:
    if path.is_file():
        return path
    candidate = _results_root(path) / "report" / "report.json"
    if not candidate.is_file():
        raise FileNotFoundError(f"final report not found: {candidate}")
    return candidate


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("report")
    parser.add_argument("manifest")
    parser.add_argument("--json-out")
    parser.add_argument(
        "--stages",
        action="store_true",
        help="score Hunt, validation, trace, and final outputs",
    )
    args = parser.parse_args()

    manifest = json.loads(Path(args.manifest).read_text())
    if args.stages:
        result = evaluate_stages(Path(args.report), manifest)
        counts = result["stage_counts"]
        print(f"\n# stage evaluation vs {manifest['target']}")
        print(
            f"  candidate n={counts['candidate']} "
            f"precision={result['candidate']['precision']:.1%} "
            f"recall={result['candidate']['recall']:.1%}"
        )
        print(
            f"  confirmed n={counts['confirmed']} "
            f"precision={result['confirmed']['precision']:.1%} "
            f"recall={result['confirmed']['recall']:.1%}"
        )
        print(
            f"  trace decided={result['trace']['decided']}/"
            f"{result['trace']['eligible']} "
            f"accuracy={result['trace']['accuracy']:.1%}"
        )
        print(
            f"  final n={counts['final']} "
            f"precision={result['final']['precision']:.1%} "
            f"recall={result['final']['recall']:.1%}"
        )
        if args.json_out:
            Path(args.json_out).write_text(
                json.dumps(result, indent=2) + "\n"
            )
        return

    report_path = _resolve_report(Path(args.report))
    report = json.loads(report_path.read_text())
    result = evaluate(report, manifest)
    print(f"\n# {report.get('run_id', report_path.parent.parent.name)} vs {manifest['target']}")
    print(
        f"  final findings={result['findings']}  "
        f"precision={result['precision']:.1%}  "
        f"recall={result['recall']:.1%}  "
        f"decoy-specificity={result['specificity']:.1%}"
    )
    for tier, values in result["by_tier"].items():
        print(f"  {tier:10s} {values['hit']}/{values['total']}")
    print(f"  missed: {result['missed_ids'] or 'none'}")
    print(f"  false positives: {result['false_positive_findings']}")
    print(f"  flagged decoys: {result['flagged_decoys'] or 'none'}")
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
