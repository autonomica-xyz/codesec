"""Shared test helper: minimal REAL admission evidence for machinery tests.

Freeze now verifies admission evidence references (plan step D). Machinery
tests (ledger/commit/aggregate/executor) are calibration-purpose freezes:
they need one small, genuinely-verified isolation evidence document —
exactly what production calibration freezes must supply, at test scale.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


def add_calibration_admission(tmp_path: Path, spec: dict,
                              image_id: str | None = None) -> dict:
    """Attach a valid calibration-purpose admission block to ``spec``."""
    image_id = image_id or (spec.get("image") or {}).get(
        "image_id", "sha256:" + "ab" * 32
    )
    iso = tmp_path / "test-iso-evidence.json"
    iso.write_text(json.dumps({
        "ran_at": 1.0,
        "passed": True,
        "checks": [{"name": "host_home_absent", "passed": True}],
        "image_id": image_id,
    }))
    spec["purpose"] = "calibration"
    spec["admission"] = {
        "isolation_evidence": {
            "path": str(iso),
            "sha256": hashlib.sha256(iso.read_bytes()).hexdigest(),
        },
    }
    return spec
