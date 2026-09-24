#!/usr/bin/env python3
"""Pool RealVuln TP/FP/FN/TN into the frozen strict-micro F3 headline."""

from __future__ import annotations

import argparse
import json
import sys
import os
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from bench.realvuln.common import (
    DEFAULT_REALVULN,
    FAMOUS_SLUGS,
    HERE,
    OBSCURE_SLUGS,
    SCANNERS,
    WAVE1_SLUGS,
    f3_score,
    write_json,
)


def _import_realvuln(root: Path) -> None:
    sys.path.insert(0, str(root))


def _score_one(realvuln: Path, slug: str, scanner: str, result_path: Path) -> dict:
    from parsers import get_parser
    from scorer.matcher import load_ground_truth, match_findings
    from scorer.metrics import compute_scorecard

    gt = load_ground_truth(str(realvuln / "ground-truth" / slug / "ground-truth.json"))
    families = json.loads((realvuln / "config" / "cwe-families.json").read_text())
    findings = get_parser(scanner).parse(str(result_path))
    results = match_findings(findings, gt)
    card = compute_scorecard(gt["repo_id"], scanner, datetime.now(timezone.utc).isoformat(), results, families)
    return {
        "slug": slug,
        "scanner": scanner,
        "file": str(result_path),
        "tp": card.tp,
        "fp": card.fp,
        "fn": card.fn,
        "tn": card.tn,
        "precision": card.precision,
        "recall": card.recall,
        "f3_score": card.f3_score,
    }


def _pool(rows: list[dict]) -> dict:
    tp = sum(r["tp"] for r in rows)
    fp = sum(r["fp"] for r in rows)
    fn = sum(r["fn"] for r in rows)
    tn = sum(r["tn"] for r in rows)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f3_score": f3_score(precision, recall),
        "n_repos": len({r["slug"] for r in rows}),
    }


def _run_index(path: Path) -> int | None:
    name = path.name
    if name.startswith("run-") and name.endswith(".json"):
        try:
            return int(name[4:-5])
        except ValueError:
            return None
    return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--realvuln", default=str(DEFAULT_REALVULN), type=Path)
    parser.add_argument("--subset", default=str(HERE / "subset.txt"), type=Path)
    parser.add_argument("--json-out", type=Path)
    parser.add_argument(
        "--tag",
        default="glm53",
        help="Scanner tag: glm53 or unsloth-qwen38-q4 (builds codesec-TAG-hunt/final and pi-TAG).",
    )
    parser.add_argument(
        "--experiment",
        type=Path,
        help="Aggregate a frozen experiment directory (P08 ledger-driven "
             "mode; mutually exclusive with --tag/--subset usage).",
    )
    args = parser.parse_args(argv)
    if args.experiment is not None:
        return cmd_aggregate_experiment(args)

    scanners = (
        f"codesec-{args.tag}-hunt",
        f"codesec-{args.tag}-final",
        f"pi-{args.tag}",
    )
    realvuln = args.realvuln.resolve()
    _import_realvuln(realvuln)
    slugs = [line.strip() for line in args.subset.read_text().splitlines() if line.strip()]
    per_trial: dict[int, dict[str, list[dict]]] = defaultdict(lambda: defaultdict(list))
    missing: list[str] = []

    for slug in slugs:
        for scanner in scanners:
            scan_dir = realvuln / "scan-results" / slug / scanner
            files = sorted(scan_dir.glob("run-*.json")) if scan_dir.is_dir() else []
            if not files:
                missing.append(f"{slug}/{scanner}")
                continue
            for path in files:
                trial = _run_index(path)
                if trial is None:
                    continue
                row = _score_one(realvuln, slug, scanner, path)
                row["trial"] = trial
                per_trial[trial][scanner].append(row)

    trials_out = []
    for trial in sorted(per_trial):
        trial_block = {"trial": trial, "scanners": {}}
        for scanner, rows in per_trial[trial].items():
            headline = _pool(rows)
            famous = _pool([r for r in rows if r["slug"] in FAMOUS_SLUGS])
            obscure = _pool([r for r in rows if r["slug"] in OBSCURE_SLUGS])
            trial_block["scanners"][scanner] = {
                "micro": headline,
                "famous": famous,
                "obscure": obscure,
                "per_slug": rows,
            }
        trials_out.append(trial_block)

    means: dict[str, dict] = {}
    for scanner in scanners:
        micros = [
            t["scanners"][scanner]["micro"]
            for t in trials_out
            if scanner in t["scanners"]
        ]
        if not micros:
            continue
        f3s = [m["f3_score"] for m in micros]
        means[scanner] = {
            "f3_mean": round(sum(f3s) / len(f3s), 1),
            "f3_min": min(f3s),
            "f3_max": max(f3s),
            "precision_mean": round(sum(m["precision"] for m in micros) / len(micros), 4),
            "recall_mean": round(sum(m["recall"] for m in micros) / len(micros), 4),
            "trials": len(micros),
        }

    report = {
        "slugs": slugs,
        "wave1": list(WAVE1_SLUGS),
        "missing": missing,
        "trials": trials_out,
        "means": means,
    }
    text = json.dumps(report, indent=2) + "\n"
    if args.json_out:
        write_json(args.json_out, report)
    print(text, end="")
    if means:
        print("# means (strict micro F3, 0-100)", file=sys.stderr)
        for scanner, row in means.items():
            print(
                f"{scanner}: F3 {row['f3_mean']} "
                f"(range {row['f3_min']}-{row['f3_max']}) "
                f"P={row['precision_mean']} R={row['recall_mean']}",
                file=sys.stderr,
            )
    return 1 if missing else 0


# ============================================================================
# P08: manifest-driven experiment aggregation
# ============================================================================

from collections import Counter

from bench.realvuln.adapter import AdapterInputError
from bench.realvuln.common import RUNS_ROOT as _RUNS_ROOT


class AggregationError(RuntimeError):
    pass


#: Official decision rule (frozen; implemented EXACTLY as written):
#: (F3_H >= F3_V + 5 OR (R_H >= R_V - .05 AND P_H >= P_V + .10))
#: AND fewer H FPs on >=4/6 repos in >=2/3 trials (strictly fewer; ties
#: never count).
FP_WIN_REPO_THRESHOLD = 4
FP_WIN_TRIAL_THRESHOLD = 2


def _fake_scorer_factory():
    """Tiny injectable scorer for tests: matches by (file, line, cwe)."""

    class _Match:
        def __init__(self, classification, gt_id=None, entry=None):
            self.classification = classification
            self.ground_truth_id = gt_id
            self.ground_truth_entry = entry

    def load_ground_truth(gt_path):
        return json.loads(Path(gt_path).read_text())

    def match_findings(findings, gt):
        entries = (gt.get("findings") or [])
        scored = [
            e for e in entries
            if e.get("scoring", "scored") != "non_scoring"
        ]
        results = []
        used = set()
        non_scoring_entries = [
            e for e in entries
            if e.get("scoring", "scored") == "non_scoring"
        ]

        def _file(f):
            return f["file"] if isinstance(f, dict) else f.file

        def _line(f):
            return f["line"] if isinstance(f, dict) else f.line

        class _NS:
            classification = "NS"

            def __init__(self, entry):
                self.ground_truth_id = entry["id"]
                self.ground_truth_entry = entry

        for finding in findings:
            # Findings landing on a non-scoring entry are withheld (NS).
            withheld = None
            for entry in non_scoring_entries:
                if (str(entry.get("file")) == _file(finding)
                        and abs(int(entry["location"]["start_line"]) - _line(finding)) <= 10):
                    withheld = entry
                    break
            if withheld is not None:
                results.append(_NS(withheld))
                continue
            best = None
            best_distance = None
            for entry in scored:
                if str(entry.get("file")) != _file(finding):
                    continue
                distance = abs(
                    int(entry["location"]["start_line"]) - _line(finding)
                )
                if distance <= 10 and (
                    best is None or distance < best_distance
                ):
                    best = entry
                    best_distance = distance
            if best is not None and best["id"] not in used:
                used.add(best["id"])
                classification = "TP" if best.get("is_vulnerable") else "FP"
                results.append(_Match(classification, best["id"], best))
            elif best is not None:
                results.append(_Match("FP", best["id"], best))
            else:
                results.append(_Match("FP", None, None))
        for entry in scored:
            if entry["id"] not in used:
                if entry.get("is_vulnerable"):
                    results.append(_Match("FN", entry["id"], entry))
                else:
                    results.append(_Match("TN", entry["id"], entry))
        return results

    return load_ground_truth, match_findings


def _real_scorer(realvuln: Path):
    sys.path.insert(0, str(realvuln))
    from parsers.base import NormalisedFinding
    from scorer.matcher import load_ground_truth, match_findings
    return load_ground_truth, match_findings, NormalisedFinding


def _normalised_from_semgrep(document: dict, NormalisedFinding):
    out = []
    for r in document.get("results", []):
        meta = (r.get("extra") or {}).get("metadata") or {}
        out.append(NormalisedFinding(
            file=r["path"],
            cwe=(meta.get("cwe") or ["CWE-0"])[0],
            line=r["start"]["line"],
            function=None,
            severity=None,
            rule_id=r.get("check_id"),
            message=(r.get("extra") or {}).get("message", ""),
            scanner="experiment-export",
            finding_id=meta.get("finding_id"),
        ))
    return out


def _cell_counts(matches, gt) -> dict:
    counts = Counter(m.classification.upper() for m in matches)
    return {
        "tp": counts["TP"], "fp": counts["FP"],
        "fn": counts["FN"], "tn": counts["TN"],
    }


def _fp_taxonomy(matches) -> dict:
    taxonomy = {"labeled_decoy": 0, "duplicate_positive_match": 0, "unmatched": 0}
    matched_vulnerable_ids = {
        m.ground_truth_id for m in matches if m.classification.upper() == "TP"
    }
    for m in matches:
        if m.classification.upper() != "FP":
            continue
        entry = m.ground_truth_entry
        if entry is None:
            taxonomy["unmatched"] += 1
        elif entry.get("is_vulnerable"):
            taxonomy["duplicate_positive_match"] += 1
        else:
            taxonomy["labeled_decoy"] += 1
    return taxonomy


def aggregate_experiment(
    exp_path: Path,
    *,
    realvuln: Path | None = None,
    scorer=None,
) -> dict:
    """Aggregate a frozen experiment from manifest.expected_cells.

    No glob discovery. Every expected cell must be accounted for by a
    committed artifact or a terminal ledger state; otherwise the report
    carries ``headline: null`` (progress report) and the CLI exits nonzero.
    """
    from bench.realvuln.experiment import arm_done, load_manifest
    from bench.realvuln.ledger import AttemptLedger

    exp_path = Path(exp_path).resolve()
    manifest = load_manifest(exp_path)
    ledger = AttemptLedger(
        exp_path / "operator" / "attempts.jsonl",
        experiment_id=manifest["experiment_id"],
        config_hash=manifest["manifest_sha256"],
    )
    manifest_root = (
        manifest.get("realvuln_root")
        or manifest.get("settings", {}).get("realvuln_root")
    )
    realvuln = (
        realvuln
        or (Path(manifest_root) if manifest_root else None)
        or Path(os.environ.get("REALVULN_ROOT", str(DEFAULT_REALVULN)))
    ).resolve()
    if scorer is None:
        scorer = _real_scorer(realvuln)
    load_ground_truth, match_findings = scorer[0], scorer[1]
    NormalisedFinding = scorer[2] if len(scorer) > 2 else None

    repos = sorted({c["repo"] for c in manifest["expected_cells"]})
    trials = sorted({c["trial"] for c in manifest["expected_cells"]})

    problems: list[str] = []
    cells_report: dict[str, dict] = {}
    repo_counts: dict[tuple, dict] = {}
    fp_taxonomy_total = Counter()

    # Usage accounting from trusted gateway terminal records: a request
    # whose upstream usage payload was captured vs one where usage is
    # genuinely missing (never reported as zero cost).
    usage_records = 0
    usage_missing = 0
    requests_path = exp_path / "operator" / "gateway" / "requests.jsonl"
    if requests_path.exists():
        for line in requests_path.read_text().splitlines():
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if record.get("kind") != "terminal":
                continue
            if record.get("experiment_id") != manifest["experiment_id"]:
                continue
            usage_records += 1
            if not record.get("usage"):
                usage_missing += 1

    # duplicate cell ids in the manifest are a protocol error
    ids = [c["cell_id"] for c in manifest["expected_cells"]]
    if len(ids) != len(set(ids)):
        problems.append("duplicate cell assignments in manifest")

    for cell in manifest["expected_cells"]:
        key = (cell["repo"], cell["trial"], cell["arm"])
        committed = exp_path / "committed" / cell["cell_id"]
        done = arm_done(
            committed, manifest=manifest, arm=cell["arm"],
            repo=cell["repo"], trial=cell["trial"],
        )
        entry: dict = {"cell_id": cell["cell_id"], "arm": cell["arm"]}
        if done["done"]:
            document = json.loads(
                (committed / done["marker"]["primary_path"]).read_text()
            )
            entry["source"] = "committed"
            # Committed-but-ledgerless is invalid: the marker's attempt
            # must have a terminal record in this experiment's ledger.
            state = ledger.terminal_state(cell["cell_id"])
            if state is None:
                problems.append(
                    f"cell {cell['cell_id']}: committed artifact has no "
                    "terminal ledger state — invalid"
                )
            elif state.get("attribution_inconsistent"):
                problems.append(
                    f"cell {cell['cell_id']}: inconsistent inference "
                    "attribution — invalid"
                )
            elif done["marker"].get("attempt_id") and (
                state.get("attempt_id")
                != done["marker"].get("attempt_id")
            ):
                problems.append(
                    f"cell {cell['cell_id']}: committed attempt "
                    f"{done['marker'].get('attempt_id')} is not the "
                    f"operational primary ({state.get('attempt_id')})"
                )
            if state is not None and state.get("status") != "completed":
                # A degraded terminal state (timeout-recovered output,
                # nonzero exit) is committed evidence, but it must be
                # reported — never silently upgraded to clean.
                entry["degraded"] = state.get("status")
                entry["reason_code"] = state.get("reason_code")
        else:
            state = ledger.terminal_state(cell["cell_id"])
            if state is None:
                problems.append(
                    f"cell {cell['cell_id']} ({cell['repo']} t{cell['trial']} "
                    f"{cell['arm']}) has no terminal ledger state"
                )
                entry["source"] = "unaccounted"
                document = None
            elif state["status"] == "setup_failed":
                attempts = ledger.attempts(cell["cell_id"])
                if not any(a.get("made_inference_requests") for a in attempts):
                    problems.append(
                        f"cell {cell['cell_id']}: unrecoverable setup failure "
                        "with zero inference — experiment incomplete"
                    )
                entry["source"] = "setup_failed"
                document = None
            elif state["status"] in {"failed_no_output", "failed_output"}:
                if state["status"] == "failed_no_output":
                    entry["output_failure"] = True
                if state["status"] == "failed_output" and not done["done"]:
                    entry["output_failure"] = True
                entry["source"] = "operational_failure"
                # Operational primary with no valid snapshot: empty
                # predictions (all scored positives FN, decoys TN). Never
                # labeled agent-authored.
                document = {"results": []}
            elif state["status"] == "invalidated":
                problems.append(
                    f"cell {cell['cell_id']}: protocol breach recorded — "
                    "comparison invalidated"
                )
                entry["source"] = "invalidated"
                document = None
            else:
                problems.append(
                    f"cell {cell['cell_id']}: terminal state "
                    f"{state['status']} without committed output"
                )
                entry["source"] = state["status"]
                document = None

        if document is not None:
            gt = load_ground_truth(
                str(realvuln / "ground-truth" / cell["repo"] / "ground-truth.json")
            )
            findings = (
                _normalised_from_semgrep(document, NormalisedFinding)
                if NormalisedFinding else [
                    {
                        "file": r["path"],
                        "line": r["start"]["line"],
                        "cwe": ((r.get("extra") or {}).get("metadata")
                                or {}).get("cwe", [None])[0],
                    }
                    for r in document.get("results", [])
                ]
            )
            matches = match_findings(findings, gt)
            counts = _cell_counts(matches, gt)
            entry["counts"] = counts
            entry["fp_taxonomy"] = _fp_taxonomy(matches)
            for k, v in _fp_taxonomy(matches).items():
                fp_taxonomy_total[k] += v
            entry["agent_authored"] = entry["source"] == "committed"
            repo_counts[key] = counts
        cells_report[f"{cell['repo']}#t{cell['trial']}#{cell['arm']}"] = entry

    # ---- per-trial pooling over the EXACT repo list ----------------------
    per_trial: dict[int, dict[str, dict]] = {}
    for trial in trials:
        per_trial[trial] = {}
        for arm in ("h", "v"):
            rows = [
                (repo, repo_counts.get((repo, trial, arm)))
                for repo in repos
            ]
            missing = [repo for repo, c in rows if c is None]
            if missing:
                problems.append(
                    f"trial {trial} arm {arm}: no counts for {missing} "
                    "(cannot pool a partial trial)"
                )
                continue
            per_trial[trial][arm] = _pool([
                {"slug": repo, **counts} for repo, counts in rows
            ])

    complete = all(
        arm in per_trial.get(trial, {}) for trial in trials for arm in ("h", "v")
    )
    headline = None
    decision = {
        "precedence": None,
        "positive_rule": None,
        "rule_booleans": None,
        "negative_condition_original": None,
    }

    if problems or not complete:
        decision["precedence"] = "invalid_or_incomplete"
    else:
        f3_h = [per_trial[t]["h"]["f3_score"] for t in trials]
        f3_v = [per_trial[t]["v"]["f3_score"] for t in trials]
        p_h = sum(per_trial[t]["h"]["precision"] for t in trials) / len(trials)
        p_v = sum(per_trial[t]["v"]["precision"] for t in trials) / len(trials)
        r_h = sum(per_trial[t]["h"]["recall"] for t in trials) / len(trials)
        r_v = sum(per_trial[t]["v"]["recall"] for t in trials) / len(trials)
        mean_f3_h = round(sum(f3_h) / len(f3_h), 1)
        mean_f3_v = round(sum(f3_v) / len(f3_v), 1)

        fp_wins_per_trial = {}
        for trial in trials:
            wins = 0
            for repo in repos:
                c_h = repo_counts.get((repo, trial, "h"), {})
                c_v = repo_counts.get((repo, trial, "v"), {})
                if c_h.get("fp", 0) < c_v.get("fp", 0):  # strictly fewer
                    wins += 1
            fp_wins_per_trial[trial] = wins
        f3_rule = mean_f3_h >= mean_f3_v + 5
        pr_rule = (
            r_h >= r_v - 0.05 and p_h >= p_v + 0.10
        )
        fp_rule = (
            sum(
                1 for t in trials
                if fp_wins_per_trial[t] >= FP_WIN_REPO_THRESHOLD
            ) >= FP_WIN_TRIAL_THRESHOLD
        )
        positive = (f3_rule or pr_rule) and fp_rule
        decision.update({
            "precedence": "positive" if positive else "does_not_meet_success_criterion",
            "positive_rule": positive,
            "rule_booleans": {
                "f3_h_geq_f3v_plus_5": f3_rule,
                "recall_h_geq_recall_v_minus_0.05": r_h >= r_v - 0.05,
                "precision_h_geq_precision_v_plus_0.10": p_h >= p_v + 0.10,
                "fewer_h_fp_repos_geq_4_of_6_in_geq_2_of_3_trials": fp_rule,
                "fp_win_repos_per_trial": fp_wins_per_trial,
            },
            "negative_condition_original": (
                "H final has fewer FPs than Pi on fewer than 4 slugs in "
                "fewer than 2 trials (the original report's negative "
                "condition), reported separately from the mechanically "
                "computed rule"
            ),
        })
        headline = {
            "mean_f3_h": mean_f3_h,
            "mean_f3_v": mean_f3_v,
            "trial_f3_h": f3_h,
            "trial_f3_v": f3_v,
            "precision_h": round(p_h, 4),
            "precision_v": round(p_v, 4),
            "recall_h": round(r_h, 4),
            "recall_v": round(r_v, 4),
        }

    # ---- complete-pair diagnostics (never the primary) -------------------
    pair_diag = {"note": "survivorship-prone subset; diagnostic only",
                 "sample_sizes": {}, "excluded": []}
    for trial in trials:
        complete_repos = [
            repo for repo in repos
            if (repo, trial, "h") in repo_counts
            and (repo, trial, "v") in repo_counts
        ]
        pair_diag["sample_sizes"][f"trial{trial}"] = len(complete_repos)
        pair_diag["excluded"].extend(
            f"{repo}#t{trial}" for repo in repos if repo not in complete_repos
        )

    # Clean-completion + recovery accounting from the ledger.
    terminal_statuses = Counter()
    for cell in manifest["expected_cells"]:
        state = ledger.terminal_state(cell["cell_id"])
        if state is not None:
            terminal_statuses[state.get("status", "?")] += 1
    report = {
        "experiment_id": manifest["experiment_id"],
        "manifest_sha256": manifest["manifest_sha256"],
        "expected_cells": len(manifest["expected_cells"]),
        "repos": repos,
        "trials": trials,
        "cells": cells_report,
        "per_trial": per_trial,
        "headline": headline,
        "decision": decision,
        "problems": problems,
        "fp_taxonomy_total": dict(fp_taxonomy_total),
        "terminal_status_counts": dict(terminal_statuses),
        "clean_completion_rate": round(
            terminal_statuses["completed"] / len(manifest["expected_cells"]),
            4,
        ) if manifest["expected_cells"] else None,
        "complete_pair_diagnostic": pair_diag,
        "usage": {
            "records_found": usage_records,
            "records_missing_unknown": usage_missing,
            "note": "missing usage is unknown, never zero cost",
        },
    }
    return report


def cmd_aggregate_experiment(args: argparse.Namespace) -> int:
    report = aggregate_experiment(Path(args.experiment))
    text = json.dumps(report, indent=2) + "\n"
    if args.json_out:
        write_json(Path(args.json_out), report)
    print(text, end="")
    incomplete = report["headline"] is None
    if incomplete or report["problems"]:
        print(
            f"# aggregation incomplete: {len(report['problems'])} problem(s); "
            "headline withheld",
            file=sys.stderr,
        )
        for problem in report["problems"][:10]:
            print(f"  - {problem}", file=sys.stderr)
        return 1
    print(
        f"# headline: H F3 {report['headline']['mean_f3_h']} vs "
        f"V F3 {report['headline']['mean_f3_v']} — "
        f"decision: {report['decision']['precedence']}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
