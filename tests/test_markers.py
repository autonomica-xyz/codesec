"""Tests for codesec.markers — deterministic canary markers (W6)."""

from __future__ import annotations

import json
from pathlib import Path

from codesec.json_utils import validate_schema
from codesec.markers import marker_token, markers_for

SCHEMAS = Path(__file__).resolve().parent.parent / "schemas"


def _finding(**over):
    f = {
        "finding_id": "f_1",
        "file": "utils.py",
        "line_start": 8,
        "line_end": 10,
        "vuln_class": "ssti",
        "cwe": "CWE-94",
        "description": "user body reaches render_template_string",
    }
    f.update(over)
    return f


def test_token_is_deterministic_and_identity_bound():
    f = _finding()
    assert marker_token(f) == marker_token(dict(f))
    assert len(marker_token(f)) == 8
    # identity is (file, line_start, title/description) — changing any
    # component changes the token.
    assert marker_token(_finding(file="other.py")) != marker_token(f)
    assert marker_token(_finding(line_start=9)) != marker_token(f)
    assert marker_token(_finding(description="different")) != marker_token(f)
    # title wins over description when present (spec: file:line_start:title)
    with_title = dict(f, title="t")
    assert marker_token(with_title) != marker_token(f)
    assert marker_token(with_title) == marker_token(dict(with_title))


def test_generic_marker_always_present():
    for vc, cwe in [("sqli", "CWE-89"), ("idor", "CWE-639"), ("timing", None)]:
        m = markers_for(_finding(vuln_class=vc, cwe=cwe))["markers"]
        assert m["generic"]["expect"] == m["generic"]["send"]
        assert m["generic"]["send"].startswith("ev")


def test_ssti_marker_is_arithmetic_pair():
    m = markers_for(_finding())["markers"]["ssti"]
    assert m["expect"] == str(m["a"] * m["b"])
    assert m["send"] == f"{m['a']}*{m['b']}"
    assert 10 <= m["a"] <= 99 and 10 <= m["b"] <= 99


def test_xss_marker_only_for_xss_classes():
    assert "xss" in markers_for(_finding(vuln_class="xss", cwe="CWE-79"))["markers"]
    m = markers_for(_finding(vuln_class="cross_site_scripting", cwe=None))["markers"]
    assert m["xss"]["expect"].startswith("<evx")
    assert "xss" not in markers_for(_finding(vuln_class="sqli", cwe="CWE-89"))["markers"]


def test_redirect_marker_only_for_redirect_classes():
    m = markers_for(_finding(vuln_class="open_redirect", cwe="CWE-601"))["markers"]
    host = m["redirect_host"]["expect"]
    assert host.endswith(".invalid") and host.startswith("evredir-")
    assert host in m["redirect_host"]["send"]
    assert "redirect_host" not in markers_for(_finding())["markers"]


def test_markers_shape():
    m = markers_for(_finding())
    assert m["finding_id"] == "f_1"
    assert m["token"] == marker_token(_finding())
    assert set(m["markers"]) == {"generic", "ssti"}


def _reachable_payload(**over):
    p = {
        "finding_id": "f_1",
        "status": "reachable",
        "reachable": True,
        "confidence": 0.6,
        "rationale": "payload reaches the sink through the preview route",
        "entry_points": [{"kind": "http_route", "location": "app.py:preview"}],
        "call_chain": [
            {"file": "app.py", "function": "preview", "line": 72},
            {"file": "utils.py", "function": "render_preview", "line": 8},
        ],
        "external_inputs": ["body"],
    }
    p.update(over)
    return p


def test_schema_accepts_verified_marker_on_reachable():
    p = _reachable_payload(
        marker={"kind": "ssti", "token": "70*95", "verified": True,
                "where": "response body"}
    )
    assert validate_schema(p, SCHEMAS / "trace.schema.json") == []


def test_schema_rejects_unverified_marker_on_reachable():
    for marker in (
        {"kind": "ssti", "token": "70*95", "verified": False, "where": "body"},
        {"kind": "ssti", "token": "70*95", "where": "body"},  # verified absent
    ):
        errors = validate_schema(
            _reachable_payload(marker=marker), SCHEMAS / "trace.schema.json"
        )
        assert errors, f"expected schema errors for marker={marker}"


def test_schema_accepts_marker_on_uncertain_and_unreachable():
    base = {
        "finding_id": "f_1",
        "confidence": 0.4,
        "rationale": "marker never came back through the live target",
        "uncertainty": {
            "kind": "source_evidence",
            "reason_code": "missing_runtime_evidence",
        },
        "blockers": [{"kind": "other", "location": "live",
                      "description": "no reflection observed"}],
    }
    for status, reachable in (("uncertain", None), ("unreachable", False)):
        p = dict(base, status=status, reachable=reachable,
                 marker={"kind": "generic", "token": "evx", "verified": False,
                         "where": "response body"})
        assert validate_schema(p, SCHEMAS / "trace.schema.json") == []


def test_marker_payload_is_json_serializable():
    json.dumps(markers_for(_finding()))
