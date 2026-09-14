"""Upstream novelty check (W15).

Runs orchestrator-side only — never inside agent sandboxes. Given
`--upstream <git-url-or-path>`, the report stage annotates each confirmed
finding with the file's upstream history and a fixed|unfixed|unknown
verdict; `fixed` findings drop out of the main table into a footnote.
"""

from __future__ import annotations

import hashlib
import logging
import re
import subprocess
from pathlib import Path

log = logging.getLogger(__name__)

# Commit subjects that suggest a security fix landed upstream.
_FIX_RE = re.compile(
    r"\b(fix(?:e[sd])?|cve-\d|security|secur|patch|vuln|exploit|harden)\b",
    re.IGNORECASE,
)

_CLONE_TIMEOUT_S = 300
_LOG_TIMEOUT_S = 60


def ensure_checkout(upstream: str, cache_dir: Path) -> Path | None:
    """Resolve a git URL or local path to a usable checkout.

    Local directories are used in place. URLs are cloned once into
    `cache_dir` (keyed by URL hash) and reused on later runs.
    Returns None when the upstream cannot be obtained — callers degrade
    to "no annotation" rather than failing the report.
    """
    candidate = Path(upstream).expanduser()
    if candidate.is_dir():
        return candidate

    cache_dir.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha1(upstream.encode()).hexdigest()[:12]
    dest = cache_dir / f"upstream-{digest}"
    if (dest / ".git").exists():
        return dest
    try:
        subprocess.run(
            ["git", "clone", "--depth", "100", upstream, str(dest)],
            check=True,
            capture_output=True,
            text=True,
            timeout=_CLONE_TIMEOUT_S,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as e:
        detail = ""
        if isinstance(e, subprocess.CalledProcessError):
            detail = (e.stderr or "").strip()[:200]
        log.warning("upstream clone of %s failed: %s %s", upstream, e, detail)
        return None
    return dest


def file_history(repo: Path, rel_file: str, limit: int = 50) -> list[str]:
    """`git log --oneline -<limit> -- <file>` — newest first."""
    try:
        out = subprocess.run(
            ["git", "-C", str(repo), "log", "--oneline", f"-{limit}",
             "--", rel_file],
            check=True,
            capture_output=True,
            text=True,
            timeout=_LOG_TIMEOUT_S,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as e:
        log.warning("git log failed for %s in %s: %s", rel_file, repo, e)
        return []
    return [line for line in out.stdout.splitlines() if line.strip()]


def _norm(text: str) -> str:
    return " ".join(text.split())


def _pattern_present(file_text: str, evidence: str) -> bool:
    """Is the finding's evidence snippet still visible in the file?

    Matches the whole normalized snippet first, then any substantial
    normalized line, so reindented-but-unchanged code still counts.
    """
    if not evidence or not evidence.strip():
        return False
    norm_file = _norm(file_text)
    snippet = _norm(evidence)
    if len(snippet) >= 12 and snippet in norm_file:
        return True
    return any(
        len(line) >= 12 and line in norm_file
        for line in (_norm(raw) for raw in evidence.splitlines())
    )


def _ever_present(repo: Path, rel_file: str, evidence: str) -> bool | None:
    """Did the evidence pattern ever exist in upstream history?

    Pickaxe (`git log -S<anchor>`) over the longest substantial evidence
    line. Returns None when the check can't run (no git, timeout) —
    callers must treat that as "can't prove", not as absent.
    """
    # Pickaxe is a literal substring match: use the longest raw line
    # stripped of edge whitespace so differing indentation still hits.
    lines = [raw.strip() for raw in (evidence or "").splitlines()]
    anchor = max(lines, key=len, default="")
    if len(anchor) < 12:
        anchor = (evidence or "").strip()
    if len(anchor) < 12:
        return None
    try:
        out = subprocess.run(
            ["git", "-C", str(repo), "log", "--oneline",
             f"-S{anchor}", "--", rel_file],
            check=True,
            capture_output=True,
            text=True,
            timeout=_LOG_TIMEOUT_S,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired,
            OSError):
        return None
    return bool(out.stdout.strip())


def classify(repo: Path, rel_file: str, evidence: str,
             history: list[str]) -> str:
    """Light heuristic: pattern still present → unfixed; absent with a
    fix-looking commit in history AND the pattern ever present upstream →
    fixed; otherwise unknown. The pickaxe guard keeps divergent-fork
    findings (pattern never existed upstream) out of the 'fixed' footnote
    section — absent alone proves nothing."""
    path = repo / rel_file
    if not path.is_file():
        return "unknown"
    try:
        file_text = path.read_text(errors="replace")
    except OSError:
        return "unknown"
    if _pattern_present(file_text, evidence):
        return "unfixed"
    if any(_FIX_RE.search(line) for line in history):
        return "fixed" if _ever_present(repo, rel_file, evidence) else "unknown"
    return "unknown"


def status_for_finding(repo: Path, rel_file: str, evidence: str,
                       limit: int = 50) -> dict:
    """One call per confirmed finding: history lines + classification."""
    history = file_history(repo, rel_file, limit)
    return {
        "status": classify(repo, rel_file, evidence, history),
        "history": history,
    }
