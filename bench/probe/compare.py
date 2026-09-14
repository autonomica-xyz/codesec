#!/usr/bin/env python3
"""Validate and compare compatible probe runs."""

from __future__ import annotations

import argparse
import glob
import os
import random
from pathlib import Path

try:
    from .cases import CASES
    from .score_probe import (
        RunData,
        coverage_stats,
        decidable_rows,
        load_run,
        metrics,
    )
except ImportError:  # direct script execution
    from cases import CASES
    from score_probe import (
        RunData,
        coverage_stats,
        decidable_rows,
        load_run,
        metrics,
    )


class CompatibilityError(ValueError):
    """Runs cannot be compared because their protocols differ."""


def validate_compatible(metadata: list[dict]) -> None:
    if len(metadata) < 2:
        return
    schema_versions = {item.get("schema_version", 1) for item in metadata}
    if len(schema_versions) != 1:
        raise CompatibilityError("runs use different result schema versions")
    hashes = {item.get("dataset_sha256") for item in metadata}
    if None in hashes or len(hashes) != 1:
        raise CompatibilityError("runs use different or missing dataset hashes")
    repeats = {item.get("repeats", 1) for item in metadata}
    if len(repeats) != 1:
        raise CompatibilityError("runs use different repeat counts")
    protocols = {item.get("protocol") for item in metadata}
    if len(protocols) != 1:
        raise CompatibilityError("runs use different API protocols")
    settings = {
        (
            item.get("settings", {}).get("thinking"),
            item.get("settings", {}).get("temperature"),
            item.get("settings", {}).get("max_tokens"),
            item.get("settings", {}).get("seed"),
            item.get("settings", {}).get("attempts"),
            item.get("settings", {}).get("concurrency"),
        )
        for item in metadata
    }
    if len(settings) != 1:
        raise CompatibilityError(
            "runs use different thinking/sampling/token protocols"
        )


def paired_bootstrap_difference(
    reference: RunData,
    candidate: RunData,
    *,
    metric: str = "mcc",
    samples: int = 5000,
    seed: int = 20260724,
) -> tuple[float, float, float]:
    reference_rows = {
        (row["id"], row.get("repeat", 0)): row
        for row in decidable_rows(reference.rows)
    }
    candidate_rows = {
        (row["id"], row.get("repeat", 0)): row
        for row in decidable_rows(candidate.rows)
    }
    common_keys = sorted(reference_rows.keys() & candidate_rows.keys())
    if not common_keys:
        raise CompatibilityError("runs have no mutually decidable predictions")
    by_ref = {}
    by_candidate = {}
    for case_id in {key[0] for key in common_keys}:
        keys = [key for key in common_keys if key[0] == case_id]
        by_ref[case_id] = [reference_rows[key] for key in keys]
        by_candidate[case_id] = [candidate_rows[key] for key in keys]
    case_ids = sorted(by_ref)
    rng = random.Random(seed)
    differences = []
    for _ in range(samples):
        chosen = [rng.choice(case_ids) for _ in case_ids]
        ref_rows = [row for case_id in chosen for row in by_ref[case_id]]
        candidate_rows = [
            row for case_id in chosen for row in by_candidate[case_id]
        ]
        differences.append(
            metrics(ref_rows)[metric] - metrics(candidate_rows)[metric]
        )
    differences.sort()
    return (
        differences[int(samples * 0.025)],
        differences[int(samples * 0.975) - 1],
        sum(value <= 0 for value in differences) / samples,
    )


def _display_name(run: RunData) -> str:
    return str(run.metadata.get("model") or run.path.stem)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("files", nargs="*")
    parser.add_argument("--dir", help="Compare all *.jsonl files here.")
    parser.add_argument("--bootstrap-samples", type=int, default=5000)
    args = parser.parse_args()
    files = args.files or sorted(
        glob.glob(os.path.join(args.dir, "*.jsonl"))
    )
    if not files:
        parser.error("no result files")

    expected = {case["id"] for case in CASES}
    runs = [load_run(path, expected_cases=CASES) for path in files]
    validate_compatible([run.metadata for run in runs])
    ranked = sorted(
        (
            (run, metrics(decidable_rows(run.rows)))
            for run in runs
            if decidable_rows(run.rows)
        ),
        key=lambda pair: pair[1]["mcc"],
        reverse=True,
    )
    if not ranked:
        raise CompatibilityError("no run has a decidable prediction")

    print(
        f"\n{'model':38s} {'MCC':>6s} {'bal':>6s} {'F1':>6s} "
        f"{'rec':>6s} {'prec':>6s} {'spec':>6s} {'CWE':>6s} "
        f"{'cover':>7s} {'fmt':>6s}"
    )
    print("-" * 107)
    for run, result in ranked:
        coverage = coverage_stats(run.rows)
        exact_format = sum(
            bool(row.get("format_exact", row.get("first_pass_ok", False)))
            for row in run.rows
        ) / len(run.rows)
        print(
            f"{_display_name(run)[:38]:38s} "
            f"{result['mcc']:6.3f} "
            f"{result['balanced_accuracy']:6.1%} "
            f"{result['f1']:6.3f} "
            f"{result['recall']:6.1%} "
            f"{result['precision']:6.1%} "
            f"{result['specificity']:6.1%} "
            f"{result['cwe_exact']:6.1%} "
            f"{coverage['coverage']:7.1%} "
            f"{exact_format:6.1%}"
        )

    if len(ranked) > 1:
        winner = ranked[0][0]
        print(
            f"\nPaired clustered bootstrap on mutually decidable rows: "
            f"{_display_name(winner)} minus candidate MCC"
        )
        for candidate, _ in ranked[1:]:
            low, high, probability_nonpositive = paired_bootstrap_difference(
                winner,
                candidate,
                samples=args.bootstrap_samples,
            )
            print(
                f"  {_display_name(candidate):38s} "
                f"95% CI {low:+.3f}..{high:+.3f}; "
                f"P(diff<=0)={probability_nonpositive:.3f}"
            )


if __name__ == "__main__":
    main()
