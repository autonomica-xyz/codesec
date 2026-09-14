"""Per-CWE bypass hints (W4).

Hint sources are keyed by CWE id ("CWE-89") or free-form attack-class
substrings, loaded from config/bypass_hints.yaml. A malformed file is
ignored with a warning, never aborts.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Mapping

import yaml

log = logging.getLogger(__name__)

_MAX_HINTS = 6
_DEFAULT_PATH = (
    Path(__file__).resolve().parent.parent / "config" / "bypass_hints.yaml"
)


def load_hints(path: Path | str | None = None) -> dict[str, list[str]]:
    """Load bypass hints. None → <repo>/config/bypass_hints.yaml.
    Malformed file → log a warning and return {} (run without hints)."""
    p = Path(path) if path is not None else _DEFAULT_PATH
    try:
        raw = yaml.safe_load(p.read_text())
    except (OSError, yaml.YAMLError) as e:
        log.warning(
            "bypass hints unusable (%s): %s — running without hints", p, e
        )
        return {}
    if not isinstance(raw, dict):
        log.warning(
            "bypass hints malformed (%s): top level is not a mapping — "
            "running without hints", p,
        )
        return {}
    out: dict[str, list[str]] = {}
    for key, value in raw.items():
        if isinstance(value, list):
            out[str(key)] = [str(v) for v in value if v is not None]
        else:
            log.warning("bypass hints: skipping non-list entry %r", key)
    return out


def hints_for(
    hints: Mapping[str, list[str]],
    *,
    cwe: str | None = None,
    vuln_class: str | None = None,
    attack_class: str | None = None,
) -> list[str]:
    """Return ≤6 deduplicated hints: exact CWE-key match first, then
    case-insensitive substring match of the key against vuln_class /
    attack_class."""
    out: list[str] = []
    seen: set[str] = set()

    def _add(key: str) -> None:
        for hint in hints.get(key) or []:
            if hint not in seen:
                seen.add(hint)
                out.append(hint)
            if len(out) >= _MAX_HINTS:
                return

    if cwe:
        _add(cwe)
    needles = [n.lower() for n in (vuln_class, attack_class) if n]
    for key in hints:
        if len(out) >= _MAX_HINTS:
            break
        if key == cwe:
            continue
        lowered = key.lower()
        if any(lowered in n for n in needles):
            _add(key)
    return out[:_MAX_HINTS]
