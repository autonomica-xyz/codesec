"""Bypass-hint loader and matcher (W4)."""

from __future__ import annotations

import logging
from pathlib import Path

from codesec.hints import hints_for, load_hints


def test_load_default_repo_hints() -> None:
    hints = load_hints()
    assert hints  # config/bypass_hints.yaml ships with the repo
    assert "CWE-89" in hints
    assert all(
        isinstance(v, list) and all(isinstance(h, str) for h in v)
        for v in hints.values()
    )


def test_load_missing_file_warns_and_returns_empty(
    tmp_path: Path, caplog
) -> None:
    with caplog.at_level(logging.WARNING):
        assert load_hints(tmp_path / "nope.yaml") == {}
    assert "bypass hints" in caplog.text


def test_load_malformed_yaml_warns_and_returns_empty(
    tmp_path: Path, caplog
) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("{unclosed: [")
    with caplog.at_level(logging.WARNING):
        assert load_hints(bad) == {}
    assert "bypass hints" in caplog.text


def test_load_non_mapping_returns_empty(tmp_path: Path, caplog) -> None:
    bad = tmp_path / "list.yaml"
    bad.write_text("- just\n- a\n- list\n")
    with caplog.at_level(logging.WARNING):
        assert load_hints(bad) == {}
    assert "bypass hints" in caplog.text


def test_load_skips_non_list_entries(tmp_path: Path) -> None:
    mixed = tmp_path / "mixed.yaml"
    mixed.write_text("CWE-89:\n  - sql hint\nnotalist: 42\n")
    assert load_hints(mixed) == {"CWE-89": ["sql hint"]}


def test_cwe_exact_match_first() -> None:
    hints = {"CWE-89": ["sql hint a", "sql hint b"], "other": ["other hint"]}
    assert hints_for(hints, cwe="CWE-89") == ["sql hint a", "sql hint b"]


def test_substring_match_vuln_class_and_attack_class() -> None:
    hints = {
        "idor": ["try other tenants' IDs"],
        "ssrf": ["try cloud metadata"],
    }
    assert hints_for(hints, vuln_class="idor_note") == ["try other tenants' IDs"]
    # case-insensitive on both sides
    assert hints_for(hints, attack_class="SSRF") == ["try cloud metadata"]


def test_cwe_match_then_substring_appends() -> None:
    hints = {
        "CWE-918": ["try decimal IP"],
        "ssrf": ["try redirect chain"],
        "unrelated": ["never"],
    }
    out = hints_for(hints, cwe="CWE-918", vuln_class="ssrf")
    assert out == ["try decimal IP", "try redirect chain"]


def test_dedupes_across_keys() -> None:
    hints = {
        "CWE-89": ["h1", "h2", "h3"],
        "sqli": ["h2", "h4"],
    }
    out = hints_for(hints, cwe="CWE-89", vuln_class="sqli_blind")
    assert out == ["h1", "h2", "h3", "h4"]


def test_six_hint_cap() -> None:
    hints = {
        "CWE-89": ["h1", "h2", "h3", "h4"],
        "sqli": ["h4", "h5", "h6", "h7", "h8"],
    }
    out = hints_for(hints, cwe="CWE-89", vuln_class="sqli_blind")
    assert out == ["h1", "h2", "h3", "h4", "h5", "h6"]


def test_no_match_returns_empty() -> None:
    assert hints_for({"CWE-89": ["x"]}, cwe="CWE-79", vuln_class="xss") == []
    assert hints_for({"idor": ["x"]}) == []
