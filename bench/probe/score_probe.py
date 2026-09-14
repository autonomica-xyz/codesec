#!/usr/bin/env python3
"""Validate and score one probe run.

Usage:
  python3 -m bench.probe.score_probe results/model.jsonl
"""

from __future__ import annotations

import argparse
import collections
import json
import math
import random
import statistics
from dataclasses import dataclass
from pathlib import Path

try:
    from .cases import CASES, dataset_sha256
except ImportError:  # direct script execution
    from cases import CASES, dataset_sha256


class RunValidationError(ValueError):
    """A result file is incomplete, duplicated, or schema-invalid."""


@dataclass(frozen=True)
class RunData:
    path: Path
    metadata: dict
    rows: list[dict]


def load_run(
    filename: str | Path,
    *,
    expected_ids: set[str] | None = None,
    expected_cases: list[dict] | None = None,
    require_complete_predictions: bool = False,
) -> RunData:
    """Load a structurally complete run.

    Prediction/format failures are retained as undecidable rows by default so
    detection quality can be measured on the semantic answers the model did
    provide. Set ``require_complete_predictions`` for operational gates that
    require every response to satisfy the machine-readable contract.
    """
    path = Path(filename)
    values = [
        json.loads(line)
        for line in path.read_text().splitlines()
        if line.strip()
    ]
    meta_rows = [row for row in values if row.get("kind") == "run_meta"]
    if len(meta_rows) > 1:
        raise RunValidationError("multiple run_meta records")
    metadata = meta_rows[0] if meta_rows else {
        "kind": "run_meta",
        "schema_version": 1,
        "repeats": 1,
        "model": path.stem,
    }
    rows = [
        row
        for row in values
        if row.get("kind") in (None, "case_result")
    ]
    repeats = int(metadata.get("repeats", 1))
    if repeats < 1:
        raise RunValidationError("metadata repeats must be positive")
    truth_by_id = (
        {case["id"]: case for case in expected_cases}
        if expected_cases is not None
        else {}
    )
    if expected_cases is not None:
        expected_ids = set(truth_by_id)

    seen: set[tuple[str, int]] = set()
    errors: list[str] = []
    if (
        expected_cases is not None
        and int(metadata.get("schema_version", 1)) >= 2
        and metadata.get("dataset_sha256") != dataset_sha256(expected_cases)
    ):
        errors.append("dataset hash does not match expected cases")
    for row in rows:
        case_id = row.get("id")
        repeat = row.get("repeat", 0)
        if not isinstance(case_id, str) or not isinstance(repeat, int):
            errors.append("result has invalid id/repeat")
            continue
        key = (case_id, repeat)
        if key in seen:
            errors.append(f"duplicate result {case_id}/repeat={repeat}")
        seen.add(key)
        if not row.get("ok") and require_complete_predictions:
            errors.append(f"invalid result {case_id}/repeat={repeat}")
        elif type(row.get("pred_vuln")) is not bool:
            if row.get("ok") or require_complete_predictions:
                errors.append(
                    f"missing boolean prediction {case_id}/repeat={repeat}"
                )
        if type(row.get("vuln")) is not bool:
            errors.append(f"missing boolean truth {case_id}/repeat={repeat}")
        truth = truth_by_id.get(case_id)
        if truth is not None and any(
            row.get(field) != truth.get(field)
            for field in ("tier", "vuln", "cwe")
        ):
            errors.append(
                f"embedded truth mismatch {case_id}/repeat={repeat}"
            )

    if expected_ids is not None:
        expected = {
            (case_id, repeat)
            for repeat in range(repeats)
            for case_id in expected_ids
        }
        missing = sorted(expected - seen)
        unexpected = sorted(seen - expected)
        if missing:
            errors.append(f"missing {len(missing)} expected results: {missing[:5]}")
        if unexpected:
            errors.append(
                f"unexpected {len(unexpected)} results: {unexpected[:5]}"
            )
    if errors:
        raise RunValidationError("; ".join(errors))
    return RunData(path=path, metadata=metadata, rows=rows)


def decidable_rows(rows: list[dict]) -> list[dict]:
    """Return rows containing an explicit semantic vulnerability verdict."""
    return [
        row
        for row in rows
        if row.get("ok") is True and type(row.get("pred_vuln")) is bool
    ]


def coverage_stats(rows: list[dict]) -> dict:
    """Report semantic-answer coverage independently from detection quality."""
    decidable = len(decidable_rows(rows))
    total = len(rows)
    return {
        "total": total,
        "decidable": decidable,
        "invalid": total - decidable,
        "coverage": decidable / total if total else 0.0,
    }


def _mcc_from_counts(tp: int, fn: int, fp: int, tn: int) -> float:
    denominator = (tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)
    return (
        (tp * tn - fp * fn) / math.sqrt(denominator)
        if denominator
        else 0.0
    )


def mcc_missing_answer_bounds(rows: list[dict]) -> tuple[float, float]:
    """Bound full-coverage MCC over every possible missing binary verdict."""
    scored = decidable_rows(rows)
    base = metrics(scored)
    undecidable = [
        row
        for row in rows
        if not (
            row.get("ok") is True
            and type(row.get("pred_vuln")) is bool
        )
    ]
    missing_positive = sum(row["vuln"] for row in undecidable)
    missing_negative = len(undecidable) - missing_positive
    possible = [
        _mcc_from_counts(
            base["tp"] + added_tp,
            base["fn"] + missing_positive - added_tp,
            base["fp"] + added_fp,
            base["tn"] + missing_negative - added_fp,
        )
        for added_tp in range(missing_positive + 1)
        for added_fp in range(missing_negative + 1)
    ]
    return min(possible), max(possible)


def metrics(rows: list[dict]) -> dict:
    tp = sum(1 for row in rows if row["vuln"] and row["pred_vuln"])
    fn = sum(1 for row in rows if row["vuln"] and not row["pred_vuln"])
    fp = sum(1 for row in rows if not row["vuln"] and row["pred_vuln"])
    tn = sum(1 for row in rows if not row["vuln"] and not row["pred_vuln"])
    recall = tp / (tp + fn) if tp + fn else 0.0
    precision = tp / (tp + fp) if tp + fp else 0.0
    specificity = tn / (tn + fp) if tn + fp else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall
        else 0.0
    )
    accuracy = (tp + tn) / len(rows) if rows else 0.0
    balanced_accuracy = (recall + specificity) / 2
    mcc = _mcc_from_counts(tp, fn, fp, tn)
    cwe_correct = sum(
        1
        for row in rows
        if row["vuln"]
        and row["pred_vuln"]
        and (row.get("pred_cwe") or "").upper()
        == (row.get("cwe") or "").upper()
    )
    return {
        "n": len(rows),
        "tp": tp,
        "fn": fn,
        "fp": fp,
        "tn": tn,
        "accuracy": accuracy,
        "recall": recall,
        "precision": precision,
        "specificity": specificity,
        "f1": f1,
        "balanced_accuracy": balanced_accuracy,
        "mcc": mcc,
        "cwe_exact": cwe_correct / tp if tp else 0.0,
    }


def clustered_bootstrap_ci(
    rows: list[dict],
    metric: str,
    *,
    samples: int = 5000,
    seed: int = 20260724,
) -> tuple[float, float]:
    by_case: dict[str, list[dict]] = collections.defaultdict(list)
    for row in rows:
        by_case[row["id"]].append(row)
    case_ids = sorted(by_case)
    rng = random.Random(seed)
    estimates = []
    for _ in range(samples):
        selected = [rng.choice(case_ids) for _ in case_ids]
        sample_rows = [
            row
            for case_id in selected
            for row in by_case[case_id]
        ]
        estimates.append(metrics(sample_rows)[metric])
    estimates.sort()
    return (
        estimates[int(samples * 0.025)],
        estimates[int(samples * 0.975) - 1],
    )


def _tier_recall(rows: list[dict], tier: str) -> float:
    subset = [row for row in rows if row["tier"] == tier]
    return metrics(subset)["recall"] if subset else 0.0


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("result")
    parser.add_argument("--bootstrap-samples", type=int, default=5000)
    args = parser.parse_args()

    expected = {case["id"] for case in CASES}
    run = load_run(args.result, expected_cases=CASES)
    scored_rows = decidable_rows(run.rows)
    coverage = coverage_stats(run.rows)
    if not scored_rows:
        raise RunValidationError("run has no decidable predictions to score")
    overall = metrics(scored_rows)
    ci = clustered_bootstrap_ci(
        scored_rows, "mcc", samples=args.bootstrap_samples
    )
    model = run.metadata.get("model", run.path.stem)
    repeats = int(run.metadata.get("repeats", 1))
    print(f"\n# {model} — {len(expected)} cases × {repeats} repeats")
    print(
        "  "
        f"MCC={overall['mcc']:.3f} (95% CI {ci[0]:.3f}..{ci[1]:.3f})  "
        f"bal-acc={overall['balanced_accuracy']:.1%}  "
        f"F1={overall['f1']:.3f}  recall={overall['recall']:.1%}  "
        f"precision={overall['precision']:.1%}  "
        f"specificity={overall['specificity']:.1%}"
    )
    print(
        f"  semantic coverage={coverage['decidable']}/{coverage['total']} "
        f"({coverage['coverage']:.1%}); invalid={coverage['invalid']}"
    )
    if coverage["invalid"]:
        low, high = mcc_missing_answer_bounds(run.rows)
        print(
            f"  full-coverage MCC sensitivity if missing answers were "
            f"binary verdicts: {low:.3f}..{high:.3f}"
        )
    print(
        f"  TP={overall['tp']} FN={overall['fn']} "
        f"FP={overall['fp']} TN={overall['tn']}  "
        f"CWE-exact={overall['cwe_exact']:.1%}"
    )
    print(
        "  tiers: "
        + " ".join(
            f"{tier}={_tier_recall(scored_rows, tier):.1%}"
            for tier in ("T1", "T2", "T3")
        )
    )
    per_repeat = [
        metrics(
            [
                row
                for row in scored_rows
                if row.get("repeat", 0) == repeat
            ]
        )["mcc"]
        for repeat in range(repeats)
    ]
    if repeats > 1:
        print(
            f"  repeat MCC: mean={statistics.mean(per_repeat):.3f} "
            f"stdev={statistics.stdev(per_repeat):.3f} "
            f"values={[round(value, 3) for value in per_repeat]}"
        )
    positives = sum(case["vuln"] for case in CASES) * repeats
    total = len(CASES) * repeats
    always_positive_f1 = 2 * positives / (total + positives)
    print(
        f"  trivial always-vulnerable baseline: "
        f"F1={always_positive_f1:.3f}, bal-acc=0.500, MCC=0.000"
    )


if __name__ == "__main__":
    main()
