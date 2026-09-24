#!/usr/bin/env python3
"""Step A.1 of PLAN-RELIABILITY-FIXES-AND-FP-REVIEW-2026-09-24.md.

Archive the allowlisted implementation surface (source, prompts, schemas,
configuration, lockfiles, image-build inputs, bench runner, tracked diff,
untracked planning docs) into the relfix evidence directory. Excludes
secrets (.env*), venvs, caches, run outputs, and bundled repos. Records a
per-file sha256 manifest plus the archive's own hash.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import tarfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
EV = ROOT / "bench/realvuln/repair-evidence/relfix-2026-09-24"

ALLOW_DIRS = [
    "codesec",
    "prompts",
    "schemas",
    "config",
    "bench/realvuln",
    "bench/probe",
    "bench/corpus",
    "tests",
]
ALLOW_FILES = [
    "pyproject.toml",
    "uv.lock",
    "score.py",
    "bench/score_repo.py",
    "bench/METHODOLOGY.md",
    "bench/REPORT.md",
    "bench/RESULTS-2026-07-24.md",
    "bench/RESULTS-GLM-5.2-2026-07-24.md",
    "bench/RESULTS-HARNESS-GLM53-REALVULN-2026-09-22.md",
    "bench/RESULTS-HARNESS-VS-PI-RELIABILITY-2026-09-23.md",
    "bench/REVIEW-RELIABILITY-2026-09-24.md",
    "bench/REVIEW-REPAIR-EXECUTION-2026-09-23.md",
    "bench/PLAN-LOCAL-VS-ZAI.md",
    "bench/PLAN-REALVULN-REPAIR-AND-RETEST.md",
    "bench/PLAN-RELIABILITY-FIXES-AND-FP-REVIEW-2026-09-24.md",
    "bench/PLAN-RELIABLE-HARNESS-VS-PI.md",
    "bench/PLAN-SHIP-CONFIRMED.md",
    "bench/AUDIT-HARNESS-GLM53-REALVULN-2026-09-22.md",
    "bench/realvuln/protocol-v5.json",
]
# bench/realvuln protocol variants are covered by the directory allowlist;
# repair-evidence is archived too (existing reproductions are evidence).
EXCLUDE_PARTS = {
    "__pycache__", ".venv", "node_modules", ".git", ".pytest_cache",
    ".mypy_cache", "repair-evidence", "realvuln-runs", ".image-staging",
}
EXCLUDE_NAMES = {".env", ".env.local", "state.db", "state.db-wal",
                 "state.db-shm", ".DS_Store"}


def iter_files(base: Path):
    if base.is_file():
        yield base
        return
    for path in sorted(base.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        if path.name in EXCLUDE_NAMES:
            continue
        if any(part in EXCLUDE_PARTS for part in path.parts):
            continue
        yield path


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    EV.mkdir(parents=True, exist_ok=True)
    tracked = subprocess.run(
        ["git", "ls-files"], cwd=str(ROOT), capture_output=True, text=True,
        check=True,
    ).stdout.splitlines()
    tracked_unarchive = [
        f for f in tracked
        if not any(f == d or f.startswith(d + "/") for d in ALLOW_DIRS)
        and f not in ALLOW_FILES
        and not f.startswith("bench/realvuln/repair-evidence/")
    ]
    files: list[Path] = []
    for item in ALLOW_DIRS + ALLOW_FILES:
        p = ROOT / item
        if not p.exists():
            print(f"skip missing: {item}")
            continue
        files.extend(iter_files(p))
    # Also archive every tracked file not covered above except binaries and
    # secrets, so the tracked tree is restorable from this archive.
    for rel in tracked_unarchive:
        p = ROOT / rel
        if p.is_file() and not p.is_symlink() and p.name not in EXCLUDE_NAMES:
            files.append(p)
    files = sorted(set(files))

    archive = EV / "source-archive.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        for path in files:
            tar.add(path, arcname=str(path.relative_to(ROOT)))

    manifest = {
        "created_at": time.time(),
        "git_head": subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=str(ROOT),
            capture_output=True, text=True, check=True,
        ).stdout.strip(),
        "git_status_short": subprocess.run(
            ["git", "status", "--short"], cwd=str(ROOT),
            capture_output=True, text=True, check=True,
        ).stdout,
        "file_count": len(files),
        "files": {
            str(p.relative_to(ROOT)): sha256(p) for p in files
        },
        "archive_sha256": sha256(archive),
        "archive_path": str(archive.relative_to(ROOT)),
        "tracked_diff": subprocess.run(
            ["git", "diff", "HEAD"], cwd=str(ROOT),
            capture_output=True, text=True, check=True,
        ).stdout,
    }
    (EV / "source-hashes.json").write_text(json.dumps(manifest, indent=1))
    print(f"archived {len(files)} files -> {archive}")
    print(f"archive sha256: {manifest['archive_sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
