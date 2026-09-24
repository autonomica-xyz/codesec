#!/usr/bin/env python3
"""Strict findings→Semgrep adapter validation (P07).

Tightened rules beyond the historical adapter:

- ``findings`` must be a list of OBJECTS (anything else is a typed error,
  not a silent empty result);
- normalized paths must stay inside the target (no traversal, no absolute
  escapes); nonexistent files are dropped with a stable reason;
- booleans are not line integers (``True`` is not 1); inverted or
  out-of-file ranges are dropped;
- CWE shape must be ``CWE-<n>`` (case-normalized), never inferred from GT;
- every dropped item is counted with a stable reason string;
- the frozen syntax-only JSON escape repair is applied symmetrically to
  both arms; no other repair exists;
- a valid ``findings: []`` is a legitimate empty prediction and is
  DIFFERENT from missing/malformed output (which raises).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from bench.realvuln.common import (
    CWE_RE,
    normalize_relpath,
    repair_json_escapes,
)

CWE_STRICT_RE = re.compile(r"^CWE-[0-9]+$")

DROP_REASONS = (
    "not_an_object",
    "missing_path",
    "path_outside_target",
    "path_not_found",
    "missing_line",
    "boolean_line",
    "line_not_integer",
    "line_out_of_file",
    "inverted_range",
    "missing_cwe",
    "invalid_cwe_shape",
)


class AdapterInputError(RuntimeError):
    """The findings document itself is malformed (distinct from empty)."""


@dataclass
class AdapterResult:
    results: list[dict] = field(default_factory=list)
    dropped: list[dict] = field(default_factory=list)

    @property
    def drop_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for item in self.dropped:
            reason = item.get("reason", "unknown")
            counts[reason] = counts.get(reason, 0) + 1
        return counts


def parse_findings_document(text: str) -> dict:
    """Parse the findings document with the frozen, symmetric escape
    repair. Raises AdapterInputError for missing/malformed documents."""
    stripped = text.strip()
    if not stripped:
        raise AdapterInputError("empty findings document")
    try:
        payload = json.loads(stripped)
    except json.JSONDecodeError:
        try:
            payload = json.loads(repair_json_escapes(stripped))
        except json.JSONDecodeError as exc:
            raise AdapterInputError(f"unparseable findings document: {exc}")
    if not isinstance(payload, dict):
        raise AdapterInputError("top-level document must be an object")
    if "findings" not in payload:
        raise AdapterInputError("document missing 'findings' array")
    if payload["findings"] is None:
        raise AdapterInputError("'findings' is null (must be a list)")
    if not isinstance(payload["findings"], list):
        raise AdapterInputError(
            f"'findings' must be a list, got {type(payload['findings']).__name__}"
        )
    return payload


def _file_line_count(target: Path, rel: str) -> int | None:
    path = target / rel
    try:
        if not path.is_file():
            return None
        return len(path.read_text(errors="replace").splitlines())
    except OSError:
        return None


def _strict_int(value, *, reject_bool: bool = True):
    if reject_bool and isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().lstrip("-").isdigit():
        return int(value.strip())
    return None


def convert_finding(finding: dict, target: Path) -> tuple[dict | None, dict | None]:
    """Convert one finding object; returns (result, drop). Never invents
    locations or CWEs; GT is never consulted."""
    raw_path = (
        finding.get("file")
        or finding.get("path")
        or (
            (finding.get("start") or {}).get("file")
            if isinstance(finding.get("start"), dict)
            else None
        )
    )
    rel = normalize_relpath(str(raw_path or ""), target)
    if not raw_path:
        return None, {"reason": "missing_path", "raw": finding}
    if rel is None or ".." in Path(rel).parts:
        return None, {
            "reason": "path_outside_target",
            "raw_path": str(raw_path)[:200],
        }
    line_count = _file_line_count(target, rel)
    if line_count is None:
        return None, {"reason": "path_not_found", "path": rel}
    line_raw = finding.get("line_start")
    if line_raw is None:
        line_raw = finding.get("line")
    if line_raw is None:
        return None, {"reason": "missing_line", "path": rel}
    if isinstance(line_raw, bool):
        return None, {"reason": "boolean_line", "path": rel}
    start = _strict_int(line_raw)
    if start is None:
        return None, {"reason": "line_not_integer", "path": rel,
                      "raw": str(line_raw)[:50]}
    end = _strict_int(finding.get("line_end")) or start
    if end is None:
        return None, {"reason": "line_not_integer", "path": rel}
    if start < 1 or end < 1 or start > line_count or end > line_count:
        return None, {
            "reason": "line_out_of_file",
            "path": rel,
            "line": start,
            "file_lines": line_count,
        }
    if end < start:
        return None, {"reason": "inverted_range", "path": rel,
                      "start": start, "end": end}
    cwe_raw = finding.get("cwe") or finding.get("CWE")
    cwe = None
    if isinstance(cwe_raw, list):
        for item in cwe_raw:
            match = CWE_RE.search(str(item or ""))
            if match:
                cwe = match.group(1).upper()
                break
    elif cwe_raw:
        match = CWE_RE.search(str(cwe_raw))
        cwe = match.group(1).upper() if match else None
    if not cwe_raw:
        return None, {"reason": "missing_cwe", "path": rel, "line": start}
    if not cwe or not CWE_STRICT_RE.match(cwe):
        # A non-empty raw value that yields no strict CWE-<n> is a SHAPE
        # error; the CWE is never inferred from GT or context.
        return None, {"reason": "invalid_cwe_shape", "path": rel,
                      "cwe": str(cwe_raw)[:50]}
    severity = str(finding.get("severity") or "WARNING").upper()
    if severity.lower() in {"critical", "high"}:
        severity = "ERROR"
    elif severity.lower() == "medium":
        severity = "WARNING"
    else:
        severity = "INFO"
    result = {
        "check_id": finding.get("finding_id") or cwe,
        "path": rel,
        "start": {"line": start},
        "end": {"line": end},
        "extra": {
            "message": str(finding.get("description") or finding.get("title") or ""),
            "severity": severity,
            "metadata": {
                "cwe": [cwe],
                "finding_id": finding.get("finding_id"),
                "vuln_class": finding.get("vuln_class"),
            },
        },
    }
    return result, None


def adapt_findings(payload: dict, target: Path) -> AdapterResult:
    """Validate + convert a parsed findings document against the real
    prepared target tree."""
    out = AdapterResult()
    for finding in payload["findings"]:
        if not isinstance(finding, dict):
            out.dropped.append({"reason": "not_an_object",
                                "raw": str(finding)[:200]})
            continue
        result, drop = convert_finding(finding, target)
        if drop is not None:
            out.dropped.append(drop)
        else:
            out.results.append(result)
    return out


def semgrep_document(results: list[dict]) -> dict:
    return {"version": "codesec-realvuln-2", "results": results}
