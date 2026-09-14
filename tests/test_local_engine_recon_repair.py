"""Regression: local-engine recon repair must not latch onto tool-call JSON."""

from __future__ import annotations

import json
from pathlib import Path

from codesec.json_utils import extract_json, validate_schema
from codesec.local_agent import _looks_like_tool_markup, _normalize_stage_payload, _validate

ROOT = Path(__file__).resolve().parents[1]
RECON_SCHEMA = ROOT / "schemas" / "recon_output.schema.json"


def _sample_recon_with_bad_tasks() -> str:
    return json.dumps(
        {
            "subsystems": [
                {
                    "name": "api",
                    "path": "api",
                    "language": "rust",
                    "purpose": "API contract and types",
                    "external_dependencies": ["prost"],
                }
            ],
            "architecture": {
                "build_commands": ["cargo build"],
                "entry_points": [
                    {"kind": "http_route", "location": "server/src/lib.rs:1"}
                ],
                "trust_boundaries": [
                    {"name": "http", "description": "HTTP to storage"}
                ],
            },
            "initial_tasks": [
                {
                    "task_id": "t1",
                    "attack_class": "ssrf",
                    "scope_hint": "check webhook url handling in server code",
                    "target_files": ["server/src/lib.rs"],
                    "subsystem": "server",
                    "priority": 2,
                }
            ],
        }
    )


def test_extract_json_rejects_pure_tool_markup():
    markup = (
        "<|message_model|>Bash<|content_invoke_tool_json|>"
        '{"name":"Bash","args":{"command":"cat /tmp/x.json"}}'
        "<|end_message|>"
    )
    assert _looks_like_tool_markup(markup)
    try:
        extract_json(markup)
        assert False, "expected ValueError"
    except ValueError as e:
        msg = str(e).lower()
        assert ("tool-call" in msg) or ("could not extract" in msg) or ("only tool" in msg)


def test_extract_json_prefers_recon_over_nested_tool_shape():
    good = _sample_recon_with_bad_tasks()
    mixed = (
        '<|message_model|>Bash<|content_invoke_tool_json|>'
        '{"name":"Bash","args":{"command":"cat x"}}'
        "<|end_message|>\n" + good
    )
    got = extract_json(mixed)
    assert "subsystems" in got


def test_normalize_maps_subsystem_to_rationale_and_passes_schema():
    payload = extract_json(_sample_recon_with_bad_tasks())
    norm = _normalize_stage_payload(payload, RECON_SCHEMA)
    errs = validate_schema(norm, RECON_SCHEMA)
    assert errs == []
    task0 = norm["initial_tasks"][0]
    assert "rationale" in task0
    assert "subsystem" not in task0
    assert task0["source"] == "recon"


def test_validate_accepts_near_valid_recon():
    errs = _validate(_sample_recon_with_bad_tasks(), RECON_SCHEMA)
    assert errs == []


def test_hunt_pure_task_echo_normalizes_to_empty_findings():
    """Model re-emits input task fields instead of HuntOutput — must not fail schema."""
    schema = ROOT / "schemas" / "finding.schema.json"
    task_echo = {
        "task_id": "t_auth_impls_auth_bypass_2",
        "attack_class": "auth_bypass",
        "priority": 2,
        "rationale": "JWT auth may skip validation on bad tokens",
        "scope_hint": "check auth-impls JWT verification path carefully",
        "target_files": ["auth-impls/src/lib.rs"],
    }
    errs = _validate(json.dumps(task_echo), schema)
    assert errs == [], errs
    # also mixed: findings + leaked task fields
    mixed = {
        "task_id": "t1",
        "attack_class": "ssrf",
        "priority": 1,
        "rationale": "why",
        "scope_hint": "where the ssrf might be in server handlers",
        "target_files": ["server/src/lib.rs"],
        "findings": [
            {
                "finding_id": "f_ssrf_1",
                "file": "server/src/lib.rs",
                "line_start": 10,
                "line_end": 20,
                "vuln_class": "ssrf",
                "severity": "high",
                "description": "Unvalidated URL is fetched server-side without allowlist checks present.",
                "evidence_snippet": "client.get(user_url).await",
                "confidence": 0.7,
            }
        ],
        "gaps_observed": [],
    }
    assert _validate(json.dumps(mixed), schema) == []


# ---------------------------------------------------------------------------
# Regression tests for PR-review issues (P1 + 2×P2)
# ---------------------------------------------------------------------------


def test_extract_json_preserves_top_level_array_of_objects():
    """P2: extract_json must return a valid top-level array of objects, not its
    first element.  Full-text-first behaviour must not be broken by the
    candidate-ranking system."""
    text = json.dumps([{"a": 1}, {"b": 2}])
    result = extract_json(text)
    assert result == [{"a": 1}, {"b": 2}], f"expected list, got {result!r}"


def test_extract_json_preserves_simple_top_level_array():
    """P2: plain arrays of scalars must also round-trip unchanged."""
    assert extract_json("[1, 2, 3]") == [1, 2, 3]
    assert extract_json("[]") == []


def test_extract_json_does_not_corrupt_markup_in_string_values():
    """P2: when the full text is valid JSON, markup-like substrings inside
    string values must be preserved (not stripped by _strip_tool_markup)."""
    payload = {
        "description": "Uses <|end_message|> and invoke_tool_json internally",
        "severity": "high",
    }
    result = extract_json(json.dumps(payload))
    assert result == payload, f"corrupted: {result!r}"
    assert "invoke_tool_json" in result["description"]
    assert "<|end_message|>" in result["description"]


def test_normalize_does_not_fabricate_missing_architecture():
    """P1: when the model omits architecture entirely, _normalize must NOT
    fabricate an empty one — the validator should flag it so the model is
    asked to repair."""
    recon_no_arch = json.dumps({
        "subsystems": [
            {"name": "api", "path": "api", "language": "rust", "purpose": "API layer"}
        ],
        "initial_tasks": [
            {
                "task_id": "t1",
                "attack_class": "ssrf",
                "scope_hint": "check url handling in server code paths",
                "target_files": ["server/src/lib.rs"],
                "priority": 2,
            }
        ],
    })
    payload = extract_json(recon_no_arch)
    norm = _normalize_stage_payload(payload, RECON_SCHEMA)
    # architecture key should NOT exist (was never in the input)
    assert "architecture" not in norm, f"fabricated: {norm.get('architecture')}"
    errs = validate_schema(norm, RECON_SCHEMA)
    assert any("architecture" in e for e in errs), f"expected architecture error, got {errs}"


def test_validate_flags_missing_architecture():
    """P1: _validate on recon missing architecture must return a non-empty
    error list (so the pipeline requests a repair turn)."""
    recon_no_arch = json.dumps({
        "subsystems": [
            {"name": "api", "path": "api", "language": "rust", "purpose": "API layer"}
        ],
        "initial_tasks": [
            {
                "task_id": "t1",
                "attack_class": "ssrf",
                "scope_hint": "check url handling in server code paths",
                "target_files": ["server/src/lib.rs"],
                "priority": 2,
            }
        ],
    })
    errs = _validate(recon_no_arch, RECON_SCHEMA)
    assert errs != [], "missing architecture should produce validation errors"
    assert any("architecture" in e for e in errs)


def test_normalize_still_fills_partial_architecture():
    """P1 companion: when architecture IS present (even partially), the
    normalizer should still fill missing required arrays."""
    recon_partial_arch = json.dumps({
        "subsystems": [
            {"name": "api", "path": "api", "language": "rust", "purpose": "API layer"}
        ],
        "architecture": {"build_commands": ["cargo build"]},
        "initial_tasks": [
            {
                "task_id": "t1",
                "attack_class": "ssrf",
                "scope_hint": "check url handling in server code paths",
                "target_files": ["server/src/lib.rs"],
                "priority": 2,
            }
        ],
    })
    errs = _validate(recon_partial_arch, RECON_SCHEMA)
    assert errs == [], f"partial architecture should normalize fine, got {errs}"
