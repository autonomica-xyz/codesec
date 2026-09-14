from __future__ import annotations

import pytest

from codesec.contracts import (
    StageContractError,
    validate_dedupe_partition,
    validate_hunt_output,
    filter_task_batch,
    validate_task_batch,
    validate_trace_output,
    validate_validation_output,
)


def test_dedupe_partition_rejects_missing_findings() -> None:
    groups = [
        {
            "group_id": "g_1",
            "member_finding_ids": ["f_1"],
            "canonical_finding_id": "f_1",
        }
    ]

    with pytest.raises(StageContractError, match=r"missing=\['f_2'\]"):
        validate_dedupe_partition({"f_1", "f_2"}, groups)


def test_dedupe_partition_requires_one_valid_canonical_per_group() -> None:
    groups = [
        {
            "group_id": "g_1",
            "member_finding_ids": ["f_1"],
            "canonical_finding_id": "f_2",
        }
    ]

    with pytest.raises(StageContractError, match="canonical.*member"):
        validate_dedupe_partition({"f_1"}, groups)


def test_hunt_output_must_match_the_requested_task(tmp_path) -> None:
    payload = {
        "task_id": "different_task",
        "findings": [],
        "gaps_observed": [],
    }

    with pytest.raises(StageContractError, match="task_id"):
        validate_hunt_output("expected_task", payload, tmp_path)


def test_hunt_output_rejects_files_outside_the_repository(tmp_path) -> None:
    outside = tmp_path.parent / "outside.py"
    outside.write_text("dangerous_call()\n")
    payload = {
        "task_id": "task",
        "findings": [
            {
                "finding_id": "f_1",
                "file": "../outside.py",
                "line_start": 1,
                "line_end": 1,
                "evidence_snippet": "dangerous_call()",
            }
        ],
        "gaps_observed": [],
    }

    with pytest.raises(StageContractError, match="outside repository"):
        validate_hunt_output("task", payload, tmp_path)


def test_hunt_output_rejects_invalid_source_ranges(tmp_path) -> None:
    (tmp_path / "app.py").write_text("first\nsecond\n")
    payload = {
        "task_id": "task",
        "findings": [
            {
                "finding_id": "f_1",
                "file": "app.py",
                "line_start": 2,
                "line_end": 4,
                "evidence_snippet": "second",
            }
        ],
        "gaps_observed": [],
    }

    with pytest.raises(StageContractError, match="source range"):
        validate_hunt_output("task", payload, tmp_path)


def test_hunt_output_rejects_duplicate_or_reserved_finding_ids(
    tmp_path,
) -> None:
    (tmp_path / "app.py").write_text("sink()\n")
    finding = {
        "finding_id": "f_same",
        "file": "app.py",
        "line_start": 1,
        "line_end": 1,
        "evidence_snippet": "sink()",
    }
    payload = {
        "task_id": "task",
        "findings": [finding, finding],
        "gaps_observed": [],
    }

    with pytest.raises(StageContractError, match="duplicate finding IDs"):
        validate_hunt_output("task", payload, tmp_path)

    with pytest.raises(StageContractError, match="already exist"):
        validate_hunt_output(
            "task",
            {**payload, "findings": [finding]},
            tmp_path,
            reserved_finding_ids={"f_same"},
        )


def test_task_batch_requires_unique_ids_and_real_repository_files(
    tmp_path,
) -> None:
    (tmp_path / "app.py").write_text("print('ok')\n")
    tasks = [
        {
            "task_id": "t_same",
            "target_files": ["app.py"],
        },
        {
            "task_id": "t_same",
            "target_files": ["missing.py"],
        },
    ]

    with pytest.raises(StageContractError, match="duplicate task IDs"):
        validate_task_batch(tasks, tmp_path)

    with pytest.raises(StageContractError, match="does not exist"):
        validate_task_batch([tasks[1] | {"task_id": "t_other"}], tmp_path)


def test_validation_output_must_match_the_requested_finding() -> None:
    with pytest.raises(StageContractError, match="finding_id"):
        validate_validation_output(
            "f_expected",
            {"finding_id": "f_other", "verdict": "confirmed"},
        )


def test_validation_rejection_requires_concrete_alternative() -> None:
    with pytest.raises(StageContractError, match="alternative_explanation"):
        validate_validation_output(
            "f_1",
            {
                "finding_id": "f_1",
                "verdict": "rejected",
                "rationale": "The claim is not supported by the surrounding code.",
            },
        )


def test_validation_uncertainty_requires_a_suggested_test() -> None:
    with pytest.raises(StageContractError, match="suggested_test"):
        validate_validation_output(
            "f_1",
            {
                "finding_id": "f_1",
                "verdict": "needs_more_info",
                "rationale": "Deployment configuration determines the outcome.",
                "alternative_explanation": "A production feature flag may disable it.",
            },
        )


def test_reachable_trace_requires_concrete_path_evidence(tmp_path) -> None:
    payload = {
        "finding_id": "f_1",
        "status": "reachable",
        "reachable": True,
        "entry_points": [],
        "external_inputs": [],
        "call_chain": [],
    }

    with pytest.raises(StageContractError, match="reachable trace"):
        validate_trace_output("f_1", payload, tmp_path)


def test_trace_status_and_reachable_flag_must_agree(tmp_path) -> None:
    with pytest.raises(StageContractError, match="status"):
        validate_trace_output(
            "f_1",
            {
                "finding_id": "f_1",
                "status": "uncertain",
                "reachable": False,
                "rationale": "No definitive caller information is available.",
            },
            tmp_path,
        )


def test_unreachable_trace_requires_a_concrete_blocker(tmp_path) -> None:
    with pytest.raises(StageContractError, match="blocker"):
        validate_trace_output(
            "f_1",
            {
                "finding_id": "f_1",
                "status": "unreachable",
                "reachable": False,
                "rationale": "No route was identified.",
                "blockers": [],
            },
            tmp_path,
        )


def test_reachable_trace_must_end_at_authoritative_sink(tmp_path) -> None:
    (tmp_path / "route.py").write_text("entry()\ncall_sink()\n")
    (tmp_path / "sink.py").write_text("safe()\ndangerous()\n")
    payload = {
        "finding_id": "f_1",
        "status": "reachable",
        "reachable": True,
        "rationale": "The route passes input to a sink.",
        "entry_points": [{"kind": "http", "location": "route.py:1"}],
        "external_inputs": ["query"],
        "call_chain": [
            {"file": "route.py", "function": "entry", "line": 1},
            {"file": "sink.py", "function": "safe", "line": 1},
        ],
    }

    with pytest.raises(StageContractError, match="authoritative sink"):
        validate_trace_output(
            "f_1",
            payload,
            tmp_path,
            expected_sink_file="sink.py",
            expected_sink_range=(2, 2),
        )


def test_filter_task_batch_drops_missing_and_keeps_real(tmp_path) -> None:
    (tmp_path / "app.py").write_text("print('ok')\n")
    tasks = [
        {"task_id": "t_ok", "target_files": ["app.py"]},
        {"task_id": "t_miss", "target_files": ["missing.py"]},
        {"task_id": "t_ok", "target_files": ["app.py"]},
        {"task_id": "t_empty", "target_files": []},
    ]
    kept = filter_task_batch(tasks, tmp_path)
    assert [t["task_id"] for t in kept] == ["t_ok"]


def _valid_hunt_payload(file: str = "a.py") -> dict:
    return {
        "task_id": "t_1",
        "findings": [
            {
                "finding_id": "f_1",
                "file": file,
                "line_start": 1,
                "line_end": 1,
                "vuln_class": "sqli",
                "severity": "high",
                "title": "unsafe query",
                "description": "d" * 40,
                "evidence_snippet": "cursor.execute(q)",
            }
        ],
    }


def test_hunt_output_sanitizes_optional_buckets(tmp_path) -> None:
    (tmp_path / "a.py").write_text("line\n")
    payload = _valid_hunt_payload()
    payload["hardening"] = [
        {"file": "a.py", "note": "missing rate limit"},
        {"note": "no file"},          # missing file → kept (note present)
        {"file": "", "note": ""},     # empty → dropped
        "not-a-dict",
        {"file": 12, "note": None},   # coerced to str
    ]
    payload["uncovered"] = [
        {"surface": "admin panel", "attack_class": "idor"},
        {"attack_class": "xss"},      # no surface → dropped
        42,
    ]
    payload["other"] = "untouched"

    validate_hunt_output("t_1", payload, tmp_path)

    assert payload["hardening"] == [
        {"file": "a.py", "note": "missing rate limit"},
        {"note": "no file"},
        {"file": "12", "note": None},
    ]
    assert payload["uncovered"] == [
        {"surface": "admin panel", "attack_class": "idor"}
    ]
    assert payload["other"] == "untouched"


def test_hunt_output_non_list_optional_bucket_becomes_empty(tmp_path) -> None:
    (tmp_path / "a.py").write_text("line\n")
    payload = _valid_hunt_payload()
    payload["hardening"] = "oops"
    payload["uncovered"] = {"surface": "x"}

    validate_hunt_output("t_1", payload, tmp_path)  # never raises

    assert payload["hardening"] == []
    assert payload["uncovered"] == []
