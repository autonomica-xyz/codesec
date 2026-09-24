"""Snapshot retention for externally-written findings files (P05/P07).

The V arm (vanilla Pi) writes its findings file from outside our control. A
truncated overwrite must never destroy the previous valid snapshot, and a
file must never be accepted while it is still being written.

Contract (used by the V-arm supervisor in the experiment runner):

- ``retain_snapshot(path)`` reads the CURRENT file once, validates the exact
  bytes it read (complete JSON and, when given, the supplied schema), then
  stores THOSE bytes atomically under ``<path>.snapshots/`` (or an explicit
  ``snapshot_dir``) with a monotonic timestamp, sha256, and capture
  metadata. A concurrent rewrite of the source between validation and
  storage can never make the stored bytes differ from the recorded hash.
  Failed reads leave any previous snapshot untouched.
- ``latest_valid_snapshot(path)`` re-validates every retained snapshot —
  the referenced file must exist, its bytes must hash to the recorded
  sha256, parse as JSON, and pass the schema — then returns the newest
  capture at or before ``deadline_ts``. A corrupt or tampered snapshot is
  skipped, never trusted on metadata alone; a post-deadline capture is
  never eligible.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path


def _snapshot_dir(path: Path) -> Path:
    return path.parent / f"{path.name}.snapshots"


def _default_schema(payload) -> list[str]:
    """Minimal findings-document shape used when no validator is given."""
    if not isinstance(payload, dict):
        return ["top-level JSON must be an object"]
    if not isinstance(payload.get("findings"), list):
        return ["findings must be a list"]
    return []


def retain_snapshot(
    path: Path,
    *,
    schema_validator=None,
    tags: dict | None = None,
    snapshot_dir: Path | None = None,
    validate_schema: bool = False,
) -> Path | None:
    """Capture the current file if it is complete and valid.

    Stores exactly the bytes that were validated (atomic tmp+rename), so a
    concurrent rewrite can never make the stored bytes differ from the
    recorded hash. Returns the snapshot path, or None when the file was
    missing, partial, or invalid (previous snapshots are left intact)."""
    path = Path(path)
    try:
        raw = path.read_bytes()
    except OSError:
        return None
    try:
        payload = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None  # partial/in-flight write — keep the previous snapshot
    validator = schema_validator or (_default_schema if validate_schema else None)
    if validator is not None:
        errors = validator(payload)
        if errors:
            return None
    digest = hashlib.sha256(raw).hexdigest()
    snap_dir = Path(snapshot_dir) if snapshot_dir is not None else _snapshot_dir(path)
    snap_dir.mkdir(parents=True, exist_ok=True)
    captured_at = time.time()
    snapshot = snap_dir / f"{int(captured_at * 1000):013d}-{digest[:12]}.json"
    tmp = snap_dir / f".{snapshot.name}.tmp"
    tmp.write_bytes(raw)
    os.replace(tmp, snapshot)
    meta = snap_dir / f"{snapshot.name}.meta.json"
    meta.write_text(json.dumps({
        "captured_at": captured_at,
        "source": str(path),
        "sha256": digest,
        "bytes": len(raw),
        "tags": tags or {},
    }, indent=1, sort_keys=True) + "\n")
    return snapshot


def _snapshot_is_valid(
    snap_path: Path,
    meta: dict,
    schema_validator,
) -> bool:
    """Re-validate a retained snapshot: file present, bytes hash to the
    recorded sha256, parse as JSON, and pass the schema when given."""
    try:
        raw = snap_path.read_bytes()
    except OSError:
        return False
    if hashlib.sha256(raw).hexdigest() != meta.get("sha256"):
        return False
    try:
        payload = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return False
    if schema_validator is not None and schema_validator(payload):
        return False
    return True


def latest_valid_snapshot(
    path: Path,
    *,
    deadline_ts: float | None = None,
    schema_validator=None,
    snapshot_dir: Path | None = None,
    validate_schema: bool = False,
) -> dict | None:
    """Newest retained snapshot captured at or before ``deadline_ts``
    (wall clock), re-validated on selection (hash + JSON + schema).
    Returns {'path', 'captured_at', 'sha256'} or None."""
    path = Path(path)
    snap_dir = Path(snapshot_dir) if snapshot_dir is not None else _snapshot_dir(path)
    if not snap_dir.exists():
        return None
    validator = schema_validator or (_default_schema if validate_schema else None)
    best: dict | None = None
    for meta_path in snap_dir.glob("*.meta.json"):
        try:
            meta = json.loads(meta_path.read_text())
        except (json.JSONDecodeError, OSError):
            continue
        captured_at = float(meta.get("captured_at", 0))
        if deadline_ts is not None and captured_at > deadline_ts:
            continue  # post-deadline captures are never used
        snap_path = snap_dir / meta_path.name[: -len(".meta.json")]
        if not _snapshot_is_valid(snap_path, meta, validator):
            continue  # never trust metadata alone
        if best is None or captured_at > best["captured_at"]:
            best = {
                "path": str(snap_path),
                "captured_at": captured_at,
                "sha256": meta.get("sha256"),
            }
    return best
