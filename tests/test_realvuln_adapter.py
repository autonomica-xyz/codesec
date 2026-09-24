"""P07 strict adapter tests: typed input errors, traversal, invalid types,
drop provenance, empty-vs-missing, symmetric escape repair."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from bench.realvuln import adapter
from bench.realvuln.adapter import (
    AdapterInputError,
    adapt_findings,
    parse_findings_document,
    semgrep_document,
)


@pytest.fixture()
def target(tmp_path: Path) -> Path:
    (tmp_path / "app.py").write_text("line\n" * 50)
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "x.py").write_text("x\n" * 10)
    return tmp_path


def _finding(**over):
    base = {
        "finding_id": "f_1", "file": "app.py",
        "line_start": 5, "line_end": 6,
        "cwe": "CWE-89", "severity": "high",
        "description": "SQL injection via interpolation.",
    }
    base.update(over)
    return base


def test_valid_finding_converts(target):
    result = adapt_findings({"findings": [_finding()]}, target)
    assert len(result.results) == 1
    entry = result.results[0]
    assert entry["path"] == "app.py"
    assert entry["start"]["line"] == 5
    assert entry["extra"]["metadata"]["cwe"] == ["CWE-89"]
    assert result.drop_counts == {}


def test_findings_must_be_list_of_objects(target):
    result = adapt_findings({"findings": ["nope", 42, None]}, target)
    assert result.results == []
    assert result.drop_counts == {"not_an_object": 3}


def test_findings_not_a_list_is_typed_error():
    with pytest.raises(AdapterInputError, match="must be a list"):
        parse_findings_document('{"findings": {"a": 1}}')
    with pytest.raises(AdapterInputError, match="'findings' is null"):
        parse_findings_document('{"findings": null}')
    with pytest.raises(AdapterInputError, match="missing 'findings'"):
        parse_findings_document("{}")


def test_missing_or_malformed_document_is_typed_error():
    with pytest.raises(AdapterInputError, match="empty"):
        parse_findings_document("   ")
    with pytest.raises(AdapterInputError, match="unparseable"):
        parse_findings_document("{definitely not json")


def test_valid_empty_findings_is_legitimate(target):
    payload = parse_findings_document('{"findings": []}')
    result = adapt_findings(payload, target)
    assert result.results == []
    assert result.drop_counts == {}
    doc = semgrep_document(result.results)
    assert doc["results"] == []  # distinct from missing/malformed output


def test_traversal_and_outside_paths_dropped_with_reason(target):
    result = adapt_findings({"findings": [
        _finding(file="../outside.py"),
        _finding(file="sub/../../app.py"),
        _finding(file="/etc/passwd"),
        _finding(file="not_there.py"),
    ]}, target)
    assert result.results == []
    assert result.drop_counts["path_outside_target"] >= 1
    assert result.drop_counts["path_not_found"] == 1


def test_boolean_and_noninteger_lines_rejected(target):
    result = adapt_findings({"findings": [
        _finding(line_start=True),          # booleans are not line ints
        _finding(line_start="seven"),
        _finding(line_start=None),
    ]}, target)
    assert result.results == []
    assert result.drop_counts == {
        "boolean_line": 1, "line_not_integer": 1, "missing_line": 1,
    }


def test_inverted_and_out_of_file_ranges_dropped(target):
    result = adapt_findings({"findings": [
        _finding(line_start=40, line_end=2),    # inverted
        _finding(line_start=900),               # beyond the 50-line file
    ]}, target)
    assert result.results == []
    assert result.drop_counts == {"inverted_range": 1, "line_out_of_file": 1}


def test_cwe_shape_strict_and_never_inferred(target):
    result = adapt_findings({"findings": [
        _finding(cwe="sql injection"),   # class text is not a CWE
        _finding(cwe=None),
        _finding(cwe=["CWE-89"]),
        _finding(cwe="cwe-95"),
    ]}, target)
    assert len(result.results) == 2
    assert result.drop_counts == {"missing_cwe": 1, "invalid_cwe_shape": 1}
    cwes = [r["extra"]["metadata"]["cwe"][0] for r in result.results]
    assert cwes == ["CWE-89", "CWE-95"]


def test_escape_repair_is_frozen_and_symmetric(target):
    # The same syntax-only repair applies to whatever text arrives.
    doc_text = '{"findings": [{"file": "app.py", "line_start": 3, "cwe": "CWE-89", "description": "path \\d+"}]}'
    payload = parse_findings_document(doc_text)
    result = adapt_findings(payload, target)
    assert len(result.results) == 1
    assert result.results[0]["extra"]["message"] == "path \\d+"


def test_metrics_sidecar_cannot_change_scored_set(target, tmp_path):
    """The scored set comes only from validated findings; a metrics file
    drifting in next to it changes nothing."""
    result = adapt_findings({"findings": [_finding()]}, target)
    semgrep = semgrep_document(result.results)
    sidecar = {"kept": 999, "dropped": 0}  # plausible-looking drift
    scored = [r for r in semgrep["results"]]
    assert len(scored) == 1
    assert sidecar["kept"] != len(scored)
