from __future__ import annotations

import json

import pytest

from bench.probe.run_probe import (
    PredictionError,
    classify_case,
    parse_prediction,
)
from bench.probe.reparse_run import reparse_row, reparse_run
from bench.probe.score_probe import (
    RunValidationError,
    coverage_stats,
    decidable_rows,
    load_run,
    mcc_missing_answer_bounds,
    metrics,
)
from bench.probe.compare import CompatibilityError, validate_compatible


def test_parse_prediction_accepts_the_declared_contract():
    prediction = parse_prediction(
        '{"vulnerable": true, "cwe": "CWE-89", '
        '"confidence": 0.9, "reason": "SQL input reaches query construction."}'
    )

    assert prediction == {
        "vulnerable": True,
        "cwe": "CWE-89",
        "confidence": 0.9,
        "reason": "SQL input reaches query construction.",
    }


def test_parse_prediction_accepts_a_single_whole_response_json_fence():
    prediction = parse_prediction(
        '```json\n{"vulnerable": false, "cwe": null, '
        '"confidence": 0.8, "reason": "Parameterized query."}\n```'
    )

    assert prediction["vulnerable"] is False
    assert prediction["cwe"] is None


@pytest.mark.parametrize(
    "response",
    [
        "",
        '{"vulnerable": "false", "cwe": null, "confidence": 0.8, "reason": "safe"}',
        '{"vulnerable": false, "cwe": null, "confidence": 2, "reason": "safe"}',
        '{"vulnerable": true, "cwe": "89", "confidence": 0.8, "reason": "SQLi"}',
        '{"vulnerable": false, "cwe": null, "confidence": 0.8}',
        'Here is the answer:\n```json\n{"vulnerable": false, "cwe": null, '
        '"confidence": 0.8, "reason": "safe"}\n```',
    ],
)
def test_parse_prediction_rejects_malformed_or_mistyped_outputs(response):
    with pytest.raises(PredictionError):
        parse_prediction(response)


@pytest.mark.parametrize(
    "response",
    [
        '{"vulnerable": false, "cwe": "CWE-89", "confidence": 0.5, "reason": "safe"}',
        '{"vulnerable": true, "cwe": null, "confidence": 0.5, "reason": "bug"}',
    ],
)
def test_parse_prediction_requires_cwe_exactly_for_vulnerable_calls(response):
    with pytest.raises(PredictionError):
        parse_prediction(response)


def test_classify_case_preserves_invalid_output_as_an_error():
    case = {
        "id": "case_1",
        "tier": "T1",
        "vuln": True,
        "cwe": "CWE-89",
        "code": "dangerous(query)",
    }

    result = classify_case(case, repeat=0, call=lambda _code: "not json")

    assert result["ok"] is False
    assert result["raw_response"] == "not json"
    assert result["error"].startswith("PredictionError:")
    assert "pred_vuln" not in result


def test_classify_case_keeps_semantic_verdict_when_auxiliary_schema_is_invalid():
    case = {
        "id": "case_1",
        "tier": "T1",
        "vuln": True,
        "cwe": "CWE-89",
        "code": "dangerous(query)",
    }
    response = '{"vulnerable": true, "cwe": null}'

    result = classify_case(case, repeat=0, call=lambda _code: response)

    assert result["ok"] is True
    assert result["pred_vuln"] is True
    assert result["contract_ok"] is False
    assert result["pred_cwe"] is None
    assert result["attempts"] == 1


def test_classify_case_records_nonexact_but_unambiguous_format():
    case = {
        "id": "case_1",
        "tier": "decoy",
        "vuln": False,
        "cwe": None,
        "code": "safe(query)",
    }
    response = (
        '```json\n{"vulnerable": false, "cwe": null, "confidence": 0.9, '
        '"reason": "Safe."}\n```'
    )

    result = classify_case(case, repeat=0, call=lambda _code: response)

    assert result["ok"] is True
    assert result["contract_ok"] is True
    assert result["first_pass_ok"] is True
    assert result["format_exact"] is False
    assert result["attempts"] == 1


def test_classify_case_accepts_template_think_prefix_as_nonexact_format():
    case = {
        "id": "case_1",
        "tier": "T1",
        "vuln": True,
        "cwe": "CWE-89",
        "code": "dangerous(query)",
    }
    response = (
        "<think>\nThe template exposed a reasoning channel.\n</think>\n\n"
        '{"vulnerable": true, "cwe": "CWE-89", "confidence": 0.9, '
        '"reason": "Untrusted input reaches the query."}'
    )

    result = classify_case(case, repeat=0, call=lambda _code: response)

    assert result["ok"] is True
    assert result["contract_ok"] is True
    assert result["pred_vuln"] is True
    assert result["format_exact"] is False
    assert result["attempts"] == 1


def test_parse_prediction_rejects_arbitrary_prose_before_json():
    response = (
        "Analysis complete.\n"
        '{"vulnerable": false, "cwe": null, "confidence": 0.9, '
        '"reason": "Safe."}'
    )

    with pytest.raises(PredictionError):
        parse_prediction(response)


def test_reparse_row_uses_first_semantically_decidable_raw_attempt():
    valid = (
        "<think></think>\n"
        '{"vulnerable": true, "cwe": "CWE-89", "confidence": 0.9, '
        '"reason": "SQL injection."}'
    )
    row = {
        "kind": "case_result",
        "id": "case_1",
        "repeat": 0,
        "tier": "T1",
        "vuln": True,
        "cwe": "CWE-89",
        "raw_responses": ["not JSON", valid, '{"vulnerable": false}'],
        "dt": 1.2,
    }

    reparsed = reparse_row(row)

    assert reparsed["ok"] is True
    assert reparsed["pred_vuln"] is True
    assert reparsed["attempts"] == 2
    assert reparsed["first_pass_ok"] is False
    assert reparsed["format_exact"] is False
    assert reparsed["raw_responses"] == ["not JSON", valid]


def test_reparse_run_records_source_hash_and_does_not_overwrite(tmp_path):
    from bench.probe.cases import CASES, dataset_sha256

    source = tmp_path / "old.jsonl"
    output = tmp_path / "new.jsonl"
    meta = {
        "kind": "run_meta",
        "schema_version": 2,
        "repeats": 1,
        "dataset_sha256": dataset_sha256(CASES),
    }
    rows = []
    for case in CASES:
        rows.append(
            {
                "kind": "case_result",
                "id": case["id"],
                "repeat": 0,
                "tier": case["tier"],
                "vuln": case["vuln"],
                "cwe": case["cwe"],
                "ok": False,
                "raw_response": '{"vulnerable": false}',
                "raw_responses": ['{"vulnerable": false}'],
            }
        )
    source.write_text(
        "\n".join(json.dumps(value) for value in [meta, *rows]) + "\n"
    )

    reparse_run(source, output)
    derived = json.loads(output.read_text().splitlines()[0])

    assert derived["schema_version"] == 3
    assert derived["derivation"]["source_file"] == "old.jsonl"
    assert derived["derivation"]["source_schema_version"] == 2
    assert len(derived["derivation"]["source_sha256"]) == 64
    with pytest.raises(FileExistsError):
        reparse_run(source, output)


def test_load_run_rejects_missing_case_results(tmp_path):
    output = tmp_path / "partial.jsonl"
    output.write_text(
        '{"kind":"run_meta","schema_version":2,"repeats":1}\n'
        '{"kind":"case_result","id":"a","repeat":0,"ok":true,'
        '"vuln":true,"cwe":"CWE-89","pred_vuln":true,"pred_cwe":"CWE-89"}\n'
    )

    with pytest.raises(RunValidationError, match="missing"):
        load_run(output, expected_ids={"a", "b"})


def test_detection_quality_uses_decidable_rows_and_reports_coverage(tmp_path):
    output = tmp_path / "one-format-error.jsonl"
    output.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "kind": "run_meta",
                        "schema_version": 1,
                        "repeats": 1,
                    }
                ),
                json.dumps(
                    {
                        "kind": "case_result",
                        "id": "a",
                        "repeat": 0,
                        "tier": "T1",
                        "vuln": True,
                        "cwe": "CWE-89",
                        "ok": True,
                        "pred_vuln": True,
                        "pred_cwe": "CWE-89",
                    }
                ),
                json.dumps(
                    {
                        "kind": "case_result",
                        "id": "b",
                        "repeat": 0,
                        "tier": "decoy",
                        "vuln": False,
                        "cwe": None,
                        "ok": False,
                        "error": "PredictionError: malformed JSON",
                    }
                ),
            ]
        )
        + "\n"
    )

    run = load_run(output, expected_ids={"a", "b"})
    scored = decidable_rows(run.rows)

    assert metrics(scored)["recall"] == 1.0
    assert coverage_stats(run.rows) == {
        "total": 2,
        "decidable": 1,
        "invalid": 1,
        "coverage": 0.5,
    }
    assert mcc_missing_answer_bounds(run.rows) == (0.0, 1.0)


def test_load_run_can_still_require_every_prediction_to_be_decidable(tmp_path):
    output = tmp_path / "invalid.jsonl"
    output.write_text(
        '{"kind":"run_meta","schema_version":1,"repeats":1}\n'
        '{"kind":"case_result","id":"a","repeat":0,"tier":"T1",'
        '"vuln":true,"cwe":"CWE-89","ok":false,'
        '"error":"PredictionError: malformed JSON"}\n'
    )

    with pytest.raises(RunValidationError, match="invalid result"):
        load_run(
            output,
            expected_ids={"a"},
            require_complete_predictions=True,
        )


def test_load_run_rejects_embedded_truth_that_disagrees_with_dataset(tmp_path):
    output = tmp_path / "tampered.jsonl"
    output.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "kind": "run_meta",
                        "schema_version": 2,
                        "repeats": 1,
                    }
                ),
                json.dumps(
                    {
                        "kind": "case_result",
                        "id": "a",
                        "repeat": 0,
                        "tier": "T1",
                        "vuln": False,
                        "cwe": "CWE-94",
                        "ok": True,
                        "pred_vuln": False,
                    }
                ),
            ]
        )
        + "\n"
    )
    expected = [
        {"id": "a", "tier": "T1", "vuln": True, "cwe": "CWE-94"}
    ]

    with pytest.raises(RunValidationError, match="truth"):
        load_run(output, expected_cases=expected)


def test_load_run_rejects_dataset_hash_mismatch(tmp_path):
    output = tmp_path / "wrong-dataset.jsonl"
    output.write_text(
        '{"kind":"run_meta","schema_version":2,"repeats":1,'
        '"dataset_sha256":"wrong"}\n'
        '{"kind":"case_result","id":"a","repeat":0,"tier":"T1",'
        '"ok":true,"vuln":true,"cwe":"CWE-94","pred_vuln":true}\n'
    )
    expected = [
        {
            "id": "a",
            "tier": "T1",
            "lang": "py",
            "vuln": True,
            "cwe": "CWE-94",
            "code": "eval(user_input)",
        }
    ]

    with pytest.raises(RunValidationError, match="dataset hash"):
        load_run(output, expected_cases=expected)


def test_compare_rejects_different_dataset_hashes():
    metadata = [
        {"model": "one", "dataset_sha256": "aaa", "repeats": 3},
        {"model": "two", "dataset_sha256": "bbb", "repeats": 3},
    ]

    with pytest.raises(CompatibilityError, match="dataset"):
        validate_compatible(metadata)


def test_compare_rejects_different_result_schema_versions():
    metadata = [
        {"schema_version": 2, "dataset_sha256": "same"},
        {"schema_version": 3, "dataset_sha256": "same"},
    ]

    with pytest.raises(CompatibilityError, match="schema"):
        validate_compatible(metadata)


def test_compare_rejects_different_sampling_or_retry_settings():
    base = {
        "dataset_sha256": "same",
        "repeats": 5,
        "settings": {
            "thinking": "disabled",
            "temperature": 0,
            "max_tokens": 512,
            "seed": 20260724,
            "attempts": 2,
            "concurrency": 4,
        },
    }
    changed = json.loads(json.dumps(base))
    changed["settings"]["seed"] += 1

    with pytest.raises(CompatibilityError, match="protocol"):
        validate_compatible([base, changed])
