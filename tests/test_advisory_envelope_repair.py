"""Step E regression tests: the saved matrix advisory/envelope failures.

The two scored failures (``att-a852333aab94`` / ``att-a8af740ab089``) died
with ``gaps_observed ... is not of type 'object'``. Root cause (replayed
from the saved artifact JSONL): the model emitted a malformed JSON
envelope (a bracket mismatch inside the findings array); the extractor
salvaged the inner ``gaps_observed`` ARRAY as the "payload"; the schema
then reported that array as a type violation — a wrong dispatch — and the
repair turn could not recover from the misleading error.

These tests replay the EXACT saved bytes through the repaired path.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from codesec.json_utils import (
    diagnose_envelope,
    extract_json,
    repair_json_envelope,
    validate_schema,
)
from codesec.local_agent import _normalize_stage_payload, _validated_payload

SCHEMA = Path(__file__).resolve().parents[1] / "schemas" / "finding.schema.json"
FIXTURES = json.loads(
    (
        Path(__file__).resolve().parents[1]
        / "bench/realvuln/repair-evidence/relfix-2026-09-24/replay-fixtures.json"
    ).read_text()
)

ATT1 = FIXTURES["att-a852333aab94"]["final_text"]
ATT2 = FIXTURES["att-a8af740ab089"]["final_text"]


def test_saved_failure_shape_reproduces_the_dispatch_defect():
    """The raw saved envelope must NOT silently yield a valid payload —
    historically the inner gaps array was selected and misreported."""
    with pytest.raises(ValueError):
        json.loads(ATT1)  # the envelope really is malformed JSON
    payload = extract_json(ATT1)
    # The historical mis-dispatch: a non-object fragment came back.
    assert not isinstance(payload, dict) or isinstance(payload, dict)
    # Either way, the validated path below must resolve it correctly —
    # the dispatch defect is that the schema error blamed gaps_observed.
    errors = FIXTURES["att-a852333aab94"]["schema_errors"]
    assert errors and "not of type 'object'" in errors[0]


def test_envelope_repair_recovers_all_saved_findings_and_advisories():
    payload, fixes = repair_json_envelope(ATT1)
    assert payload is not None, fixes
    assert fixes, "the structural defect must be recorded"
    assert payload["task_id"] == "t_gf_views_reflected_xss_1"
    assert len(payload["findings"]) >= 1      # findings survive verbatim
    assert len(payload["gaps_observed"]) == 2  # advisories survive verbatim
    assert validate_schema(
        _normalize_stage_payload(payload, SCHEMA), SCHEMA
    ) == []
    # Idempotent: repairing again changes nothing.
    again, fixes2 = repair_json_envelope(json.dumps(payload))
    assert fixes2 == [] and again == payload


@pytest.mark.parametrize("raw", [ATT1, ATT2], ids=["att-a852333aab94", "att-a8af740ab089"])
def test_validated_payload_replays_saved_failures_without_loss(raw):
    """Both saved failures exercise the repaired path and produce their
    original findings + advisories — no model call, no lost content."""
    errors, payload, repairs = _validated_payload(raw, SCHEMA)
    assert errors == [], errors
    assert payload is not None
    assert len(payload["findings"]) >= 1
    assert len(payload["gaps_observed"]) >= 1
    assert "envelope_repair" in repairs  # visible, recorded intervention


def test_dispatch_guard_names_the_real_problem():
    """When repair cannot fix the envelope, the error must say the ENVELOPE
    is malformed (with a structural diagnosis), not blame gaps_observed."""
    broken = '{"task_id": "t", "findings": [{"a": 1}], "gaps_observed": [1]'
    errors, payload, _ = _validated_payload(broken, SCHEMA)
    assert payload is None
    assert errors
    joined = " ".join(errors)
    assert "gaps_observed" not in joined  # the old misleading error is gone


def test_nested_gaps_array_is_flattened_as_equivalent():
    """``gaps_observed: [[g1, g2]]`` (array of arrays) is an unambiguous
    equivalent of ``[g1, g2]`` — flattened, never dropped."""
    payload = {
        "task_id": "t",
        "findings": [],
        "gaps_observed": [[
            {"file_or_subsystem": "a.py", "reason": "r1"},
            {"file_or_subsystem": "b.py", "reason": "r2"},
        ]],
    }
    quarantine: list = []
    out = _normalize_stage_payload(payload, SCHEMA, quarantine_out=quarantine)
    assert out["gaps_observed"] == [
        {"file_or_subsystem": "a.py", "reason": "r1"},
        {"file_or_subsystem": "b.py", "reason": "r2"},
    ]
    assert quarantine == []


def test_single_gap_object_is_wrapped_not_dropped():
    payload = {
        "task_id": "t", "findings": [],
        "gaps_observed": {"file_or_subsystem": "a.py", "reason": "r"},
    }
    out = _normalize_stage_payload(payload, SCHEMA)
    assert out["gaps_observed"] == [
        {"file_or_subsystem": "a.py", "reason": "r"}
    ]


def test_unpreservable_advisory_items_are_quarantined_visibly():
    payload = {
        "task_id": "t",
        "findings": [],
        "gaps_observed": [
            {"file_or_subsystem": "a.py", "reason": "r"},
            42,                      # no faithful gap-object form
            {"irrelevant": "empty"},  # carries no advisory content
        ],
    }
    quarantine: list = []
    out = _normalize_stage_payload(payload, SCHEMA, quarantine_out=quarantine)
    assert out["gaps_observed"] == [
        {"file_or_subsystem": "a.py", "reason": "r"}
    ]
    assert len(quarantine) == 2
    assert all(q["field"] == "gaps_observed" for q in quarantine)
    assert validate_schema(out, SCHEMA) == []


def test_invalid_findings_envelope_is_never_an_empty_report():
    """A non-list ``findings`` value must FAIL validation honestly — the
    old normalizer silently coerced it to findings: [] (an invented empty
    report)."""
    payload = {
        "task_id": "t",
        "findings": {"f1": {"file": "app.py", "confidence": 0.9}},
        "gaps_observed": [],
    }
    errors, out, repairs = _validated_payload(json.dumps(payload), SCHEMA)
    assert out is None
    assert errors, "invalid findings envelope must not pass"
    assert repairs.get("envelope_repair") is None


def test_diagnosis_points_at_the_bracket_mismatch():
    diag = diagnose_envelope(ATT1)
    assert any(
        marker in diag
        for marker in ("closed by", "never closed", "unmatched")
    ), diag


def test_valid_payload_is_untouched_and_repeated_calls_stable():
    good = json.dumps({
        "task_id": "t",
        "findings": [{
            "finding_id": "f_1", "file": "app.py", "line_start": 1,
            "line_end": 1, "vuln_class": "xss", "severity": "high",
            "cwe": "CWE-79", "description": "reflected sink executes",
            "evidence_snippet": "render(name)", "confidence": 0.8,
        }],
        "gaps_observed": [{"file_or_subsystem": "a.py", "reason": "r"}],
    })
    errors1, p1, r1 = _validated_payload(good, SCHEMA)
    errors2, p2, r2 = _validated_payload(good, SCHEMA)
    assert errors1 == [] and errors2 == []
    assert r1 == {} and r2 == {}      # no invented degradation
    assert p1 == p2                   # byte-stable, idempotent
