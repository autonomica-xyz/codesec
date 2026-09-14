"""Fingerprint stability + recentering tests (W16)."""

from __future__ import annotations

from pathlib import Path

from codesec.fingerprint import finding_fp, recenter, window_hash


def _write(repo: Path, name: str, lines: list[str]) -> None:
    path = repo / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n")


def test_window_hash_stable_under_whitespace_only_changes(tmp_path: Path) -> None:
    lines = [f"line {i}" for i in range(1, 61)]
    _write(tmp_path, "a.py", lines)
    before = window_hash(tmp_path, "a.py", 30, 32)

    lines[29] = "   line 30   "
    lines[31] = "\tline 32"
    _write(tmp_path, "a.py", lines)

    assert before is not None
    assert window_hash(tmp_path, "a.py", 30, 32) == before


def test_window_hash_changes_when_a_cited_line_changes(tmp_path: Path) -> None:
    lines = [f"line {i}" for i in range(1, 61)]
    _write(tmp_path, "a.py", lines)
    before = window_hash(tmp_path, "a.py", 30, 32)

    lines[30] = "line 31 edited"
    _write(tmp_path, "a.py", lines)

    assert window_hash(tmp_path, "a.py", 30, 32) != before


def test_window_hash_changes_when_context_changes(tmp_path: Path) -> None:
    lines = [f"line {i}" for i in range(1, 61)]
    _write(tmp_path, "a.py", lines)
    before = window_hash(tmp_path, "a.py", 30, 32)

    lines[10] = "context line edited"  # inside the +/-20 window, outside the cite
    _write(tmp_path, "a.py", lines)

    assert window_hash(tmp_path, "a.py", 30, 32) != before


def test_window_hash_none_for_missing_file_and_bad_range(tmp_path: Path) -> None:
    _write(tmp_path, "a.py", ["x"])
    assert window_hash(tmp_path, "missing.py", 1, 2) is None
    assert window_hash(tmp_path, "a.py", 5, 2) is None
    assert window_hash(tmp_path, "a.py", 0, 1) is None


def test_finding_fp_is_deterministic_and_scoped(tmp_path: Path) -> None:
    fp1 = finding_fp("sqli", "a.py", "w1")
    assert fp1 == finding_fp("sqli", "a.py", "w1")
    assert fp1 != finding_fp("command_injection", "a.py", "w1")
    assert fp1 != finding_fp("sqli", "b.py", "w1")
    assert fp1 != finding_fp("sqli", "a.py", "w2")
    assert len(fp1) == 64


def test_recenter_unchanged(tmp_path: Path) -> None:
    _write(tmp_path, "a.py", [f"line {i}" for i in range(1, 61)])
    expected = window_hash(tmp_path, "a.py", 30, 32)
    got = recenter(tmp_path, "a.py", 30, 32, expected)
    assert got == {
        "line_start": 30,
        "line_end": 32,
        "window_hash": expected,
        "drifted": False,
    }


def test_recenter_recovers_drifted_window(tmp_path: Path) -> None:
    lines = [f"line {i}" for i in range(1, 81)]
    _write(tmp_path, "a.py", lines)
    expected = window_hash(tmp_path, "a.py", 40, 42)

    # Three lines inserted above the cite: the whole window shifts down.
    _write(tmp_path, "a.py", lines[:10] + ["new a", "new b", "new c"] + lines[10:])

    got = recenter(tmp_path, "a.py", 40, 42, expected)
    assert got is not None
    assert got["drifted"] is True
    assert got["line_start"] == 43
    assert got["line_end"] == 45
    assert got["window_hash"] == expected


def test_recenter_drift_beyond_band_is_unmatchable(tmp_path: Path) -> None:
    lines = [f"line {i}" for i in range(1, 101)]
    _write(tmp_path, "a.py", lines)
    expected = window_hash(tmp_path, "a.py", 60, 62)

    _write(tmp_path, "a.py", ["pad"] * 20 + lines)  # shifted by 20 > band 15

    assert recenter(tmp_path, "a.py", 60, 62, expected, band=15) is None
    got = recenter(tmp_path, "a.py", 60, 62, expected, band=25)
    assert got is not None and got["line_start"] == 80


def test_recenter_returns_none_when_content_changed(tmp_path: Path) -> None:
    lines = [f"line {i}" for i in range(1, 61)]
    _write(tmp_path, "a.py", lines)
    expected = window_hash(tmp_path, "a.py", 30, 32)

    lines[31] = "completely rewritten"
    _write(tmp_path, "a.py", lines)

    assert recenter(tmp_path, "a.py", 30, 32, expected) is None


def test_recenter_missing_file(tmp_path: Path) -> None:
    assert recenter(tmp_path, "gone.py", 1, 2, "whatever") is None
