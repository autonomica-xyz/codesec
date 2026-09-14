"""Content fingerprints for findings — stable across runs, tolerant of drift.

A finding's identity is the code window it cites, not its line numbers.
`window_hash` hashes the referenced lines plus `ctx` lines of surrounding
context (whitespace-trimmed, so reformatting alone never invalidates it).
`finding_fp` folds the vuln class and file into that window so the same
snippet in a different file or class is a different finding.

`recenter` re-derives the window at the stored coordinates and, when the
content has drifted, searches a +/-`band` region for an identical window —
this is how the cross-run catalogue (W8) distinguishes "same bug, moved"
from "code changed, needs revalidation".
"""

from __future__ import annotations

import hashlib
from pathlib import Path

# Context lines included on each side of a cited range. Keep in sync with
# the `ctx` default on window_hash(); recenter() relies on it.
DEFAULT_CTX = 20


def _read_lines(repo_root: Path, file: str) -> list[str] | None:
    try:
        path = (repo_root / file).resolve()
        if not path.is_file():
            return None
        return path.read_text(errors="replace").splitlines()
    except OSError:
        return None


def _window_text(
    lines: list[str], line_start: int, line_end: int, ctx: int
) -> str | None:
    """Trimmed, clamped text of lines [line_start-ctx, line_end+ctx]
    (1-based, inclusive). None when the cited range is malformed."""
    if not (1 <= line_start <= line_end):
        return None
    lo = max(1, line_start - ctx)
    hi = min(len(lines), line_end + ctx)
    if lo > hi:
        return None
    return "\n".join(line.strip() for line in lines[lo - 1 : hi])


def _hash_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def window_hash(
    repo_root: Path,
    file: str,
    line_start: int,
    line_end: int,
    ctx: int = DEFAULT_CTX,
) -> str | None:
    """sha256 of the cited lines +/-`ctx`, each line whitespace-trimmed.

    None when the file is missing or the range is malformed. Stable under
    whitespace-only edits; changes when any line in the window changes.
    """
    lines = _read_lines(repo_root, file)
    if lines is None:
        return None
    try:
        start = int(line_start)
        end = int(line_end)
    except (TypeError, ValueError):
        return None
    text = _window_text(lines, start, end, ctx)
    return _hash_text(text) if text is not None else None


def finding_fp(vuln_class: str, file: str, window: str) -> str:
    """Finding identity: sha256(vuln_class + file + window_hash)."""
    return _hash_text(f"{vuln_class}\x00{file}\x00{window}")


def recenter(
    repo_root: Path,
    file: str,
    line_start: int,
    line_end: int,
    expected_window_hash: str,
    band: int = 15,
) -> dict | None:
    """Re-derive a stored window against current file content.

    Returns {"line_start", "line_end", "window_hash", "drifted"}:
    - drifted=False: the stored coordinates still hash to the expected
      window.
    - drifted=True: the identical window content was found within
      +/-`band` lines; coordinates are the re-centered range.
    - None: file missing, or no identical window inside the band
      (content changed — the caller treats this as unmatchable).
    """
    lines = _read_lines(repo_root, file)
    if lines is None:
        return None

    def at(start: int, end: int) -> str | None:
        if not (1 <= start <= end <= len(lines)):
            return None
        text = _window_text(lines, start, end, DEFAULT_CTX)
        return _hash_text(text) if text is not None else None

    current = at(line_start, line_end)
    if current == expected_window_hash:
        return {
            "line_start": line_start,
            "line_end": line_end,
            "window_hash": current,
            "drifted": False,
        }
    span = line_end - line_start
    for delta in range(1, band + 1):
        for sign in (1, -1):
            start = line_start + sign * delta
            end = start + span
            hashed = at(start, end)
            if hashed == expected_window_hash:
                return {
                    "line_start": start,
                    "line_end": end,
                    "window_hash": hashed,
                    "drifted": True,
                }
    return None
