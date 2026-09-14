#!/usr/bin/env python3
"""Derive a current-schema probe artifact from preserved raw responses."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

try:
    from .cases import CASES
    from .run_probe import (
        PredictionError,
        _prediction_payload,
        parse_detection_verdict,
        parse_prediction,
    )
    from .score_probe import load_run
except ImportError:  # direct script execution
    from cases import CASES
    from run_probe import (
        PredictionError,
        _prediction_payload,
        parse_detection_verdict,
        parse_prediction,
    )
    from score_probe import load_run


def _raw_attempts(row: dict) -> list[str]:
    attempts = row.get("raw_responses")
    if isinstance(attempts, list):
        return [value for value in attempts if isinstance(value, str)]
    raw = row.get("raw_response")
    return [raw] if isinstance(raw, str) else []


def reparse_row(row: dict) -> dict:
    base = {
        key: row[key]
        for key in ("kind", "id", "repeat", "tier", "vuln", "cwe")
        if key in row
    }
    raw_responses = _raw_attempts(row)
    failures: list[str] = []
    for index, raw in enumerate(raw_responses, start=1):
        try:
            prediction = parse_detection_verdict(raw)
        except Exception as exc:
            failures.append(f"{type(exc).__name__}: {exc}")
            continue

        _, format_exact = _prediction_payload(raw)
        contract_ok = False
        contract_error = None
        try:
            prediction = parse_prediction(raw)
            contract_ok = True
        except PredictionError as exc:
            contract_error = f"{type(exc).__name__}: {exc}"
        return {
            **base,
            "ok": True,
            "contract_ok": contract_ok,
            "contract_error": contract_error,
            "attempts": index,
            "first_pass_ok": index == 1,
            "format_exact": format_exact,
            "pred_vuln": prediction["vulnerable"],
            "pred_cwe": prediction["cwe"],
            "conf": prediction["confidence"],
            "reason": prediction["reason"],
            "raw_response": raw,
            "raw_responses": raw_responses[:index],
            "dt": row.get("dt"),
        }

    error = failures[-1] if failures else "PredictionError: no raw response"
    return {
        **base,
        "ok": False,
        "attempts": len(raw_responses),
        "raw_response": raw_responses[-1] if raw_responses else None,
        "raw_responses": raw_responses,
        "error": error,
        "errors": failures or [error],
        "dt": row.get("dt"),
    }


def reparse_run(source: Path, output: Path) -> None:
    if source.resolve() == output.resolve():
        raise ValueError("source and output must be different files")
    if output.exists():
        raise FileExistsError(f"refusing to overwrite {output}")

    run = load_run(source, expected_cases=CASES)
    source_bytes = source.read_bytes()
    source_schema = int(run.metadata.get("schema_version", 1))
    metadata = dict(run.metadata)
    metadata["schema_version"] = 3
    metadata["derivation"] = {
        "kind": "semantic_reparse",
        "source_file": source.name,
        "source_sha256": hashlib.sha256(source_bytes).hexdigest(),
        "source_schema_version": source_schema,
    }
    rows = [reparse_row(row) for row in run.rows]

    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x") as stream:
        stream.write(json.dumps(metadata, ensure_ascii=False) + "\n")
        for row in rows:
            stream.write(json.dumps(row, ensure_ascii=False) + "\n")

    load_run(output, expected_cases=CASES)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    reparse_run(args.source, args.output)


if __name__ == "__main__":
    main()
