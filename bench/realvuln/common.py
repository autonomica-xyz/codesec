"""Shared constants and helpers for the RealVuln glm-5.3 harness."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from pathlib import Path


CODESEC_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_REALVULN = Path(os.environ.get("REALVULN_ROOT", "/home/user/g/Real-Vuln-Benchmark"))
RUNS_ROOT = CODESEC_ROOT / "bench" / "realvuln-runs"
OPERATOR_DIR = RUNS_ROOT / "operator"
HERE = Path(__file__).resolve().parent

SMOKE_SLUG = "realvuln-intentionally-vulnerable-python-application"
WAVE1_SLUGS = (
    "realvuln-vampi",
    "realvuln-damn-vulnerable-flask-application",
    "realvuln-python-insecure-app",
    "realvuln-dvpwa",
    "realvuln-lets-be-bad-guys",
    "realvuln-pygoat",
)
FAMOUS_SLUGS = (
    "realvuln-vampi",
    "realvuln-damn-vulnerable-flask-application",
    "realvuln-pygoat",
)
OBSCURE_SLUGS = (
    "realvuln-python-insecure-app",
    "realvuln-dvpwa",
    "realvuln-lets-be-bad-guys",
)

SCANNERS = (
    "codesec-glm53-hunt",
    "codesec-glm53-final",
    "pi-glm53",
)

CWE_RE = re.compile(r"(CWE-\d+)", re.IGNORECASE)
JSON_FENCE_RE = re.compile(r"```(?:json)?\s*(\{.*\})\s*```", re.DOTALL)

RSYNC_EXCLUDES = (
    ".git/",
    ".github/",
    ".gitignore",
    ".gitattributes",
    ".gitmodules",
    "__pycache__/",
    "*.pyc",
    ".venv/",
    "node_modules/",
    ".idea/",
    ".vscode/",
)

DROP_NAME_RE = re.compile(
    r"(?i)^(README.*|CHANGELOG.*|CONTRIBUTING.*|SECURITY\.md|AUTHORS.*|"
    r"NOTICE.*|.*walkthrough.*|.*solution.*|.*writeup.*|\.env\.example)$"
)
DROP_DIR_NAMES = frozenset({"docs", "documentation", "challenges", "lessons"})

GLOBAL_ALIASES = (
    "realvuln",
    "owasp",
    "juice shop",
    "juiceshop",
    "intentionally vulnerable",
    "pygoat",
    "vampi",
    "dvpwa",
    "lets-be-bad-guys",
    "damn vulnerable flask",
)


def slug_aliases(slug: str) -> tuple[str, ...]:
    tail = slug.removeprefix("realvuln-")
    aliases = {slug.lower(), tail.lower(), tail.replace("-", " ").lower()}
    aliases.update(GLOBAL_ALIASES)
    return tuple(sorted(aliases))


def digest_tree(root: Path) -> str:
    """SHA-256 over sorted path+file hashes. Matches the corpus runners."""
    listing = subprocess.check_output(
        ["bash", "-lc", "find . -type f -print0 | sort -z | xargs -0 sha256sum"],
        cwd=str(root),
    )
    return hashlib.sha256(listing).hexdigest()


def load_json(path: Path) -> dict:
    return json.loads(path.read_text())


def write_json(path: Path, payload: dict, mode: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n")
    if mode is not None:
        os.chmod(path, mode)


def extract_cwe(value) -> str | None:
    if value is None:
        return None
    if isinstance(value, list):
        for item in value:
            found = extract_cwe(item)
            if found:
                return found
        return None
    match = CWE_RE.search(str(value))
    return match.group(1).upper() if match else None


def normalize_relpath(raw: str, target: Path | None = None) -> str | None:
    text = str(raw or "").strip().replace("\\", "/")
    if not text or text.startswith(".."):
        return None
    path = Path(text)
    if path.is_absolute():
        if target is None:
            return None
        try:
            text = path.resolve().relative_to(target.resolve()).as_posix()
        except ValueError:
            return None
    text = text.lstrip("./")
    if not text or text.startswith("../"):
        return None
    return text


def repair_json_escapes(text: str) -> str:
    """Turn illegal JSON backslash sequences (e.g. ``\\w`` in a regex) into
    literal backslashes. Valid JSON escapes are left alone."""
    out: list[str] = []
    i = 0
    n = len(text)
    hexdigits = "0123456789abcdefABCDEF"
    while i < n:
        ch = text[i]
        if ch != "\\" or i + 1 >= n:
            out.append(ch)
            i += 1
            continue
        nxt = text[i + 1]
        if nxt in '"\\/bfnrt':
            out.append(text[i : i + 2])
            i += 2
            continue
        if (
            nxt == "u"
            and i + 6 <= n
            and all(c in hexdigits for c in text[i + 2 : i + 6])
        ):
            out.append(text[i : i + 6])
            i += 6
            continue
        out.append("\\\\" + nxt)
        i += 2
    return "".join(out)


def extract_json_object(text: str) -> dict:
    """Accept a sole JSON object, bare or in one markdown fence."""
    stripped = text.strip()
    fence = JSON_FENCE_RE.search(stripped)
    if fence:
        stripped = fence.group(1).strip()
    try:
        payload = json.loads(stripped)
    except json.JSONDecodeError:
        payload = json.loads(repair_json_escapes(stripped))
    if not isinstance(payload, dict):
        raise ValueError("top-level JSON must be an object")
    return payload


def f3_score(precision: float, recall: float) -> float:
    denom = 9.0 * precision + recall
    if denom <= 0:
        return 0.0
    return round((10.0 * precision * recall / denom) * 100, 1)


# ---- P06 identity-mention measurement --------------------------------------
# Measured ONLY on equivalent model-authored output fields (finding
# descriptions / evidence / titles for H; the corresponding message/finding
# text fields for V). Tool output, paths, framework logs, and operator
# metadata are excluded by construction: callers pass exactly the model
# text fields.

def measure_identity_mentions(
    texts_by_field: dict[str, list[str]],
    aliases: tuple[str, ...] | list[str],
) -> dict:
    """Count identity mentions per model-authored field.

    ``texts_by_field`` maps a field name (e.g. ``description``,
    ``evidence``) to the list of model-authored strings for that field.
    Returns per-field mention counts and the total, comparable across arms
    because both arms are measured on their equivalent fields. Recognition
    of public educational apps is expected and reported, never used to
    exclude a trial post hoc."""
    alias_res = [
        (alias, re.compile(re.escape(alias), re.I))
        for alias in sorted(set(aliases), key=len, reverse=True)
    ]
    per_field: dict[str, int] = {}
    for field, texts in texts_by_field.items():
        count = 0
        for text in texts:
            if not text:
                continue
            if any(pattern.search(str(text)) for _a, pattern in alias_res):
                count += 1
        per_field[field] = count
    return {
        "per_field": per_field,
        "total_mentions": sum(per_field.values()),
        "texts_measured": sum(len(v) for v in texts_by_field.values()),
    }
