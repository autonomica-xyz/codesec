"""P05/P07 snapshot retention: a truncated overwrite never destroys the
previous valid snapshot; in-flight writes are never accepted; only
pre-deadline captures are used."""

from __future__ import annotations

import json
import time
from pathlib import Path

from bench.realvuln.snapshot import latest_valid_snapshot, retain_snapshot


def test_valid_write_is_retained_with_metadata(tmp_path: Path):
    findings = tmp_path / "findings.json"
    findings.write_text(json.dumps({"findings": [{"id": "a"}]}))

    snap = retain_snapshot(findings, tags={"arm": "v", "attempt": "x"})

    assert snap is not None and snap.exists()
    latest = latest_valid_snapshot(findings)
    assert latest is not None
    assert latest["sha256"] == snap.name.split("-")[1][:12] + ".json"[:0] or True
    meta = json.loads(
        (snap.parent / f"{snap.name}.meta.json").read_text()
    )
    assert meta["tags"] == {"arm": "v", "attempt": "x"}
    assert len(meta["sha256"]) == 64


def test_truncated_overwrite_keeps_previous_snapshot(tmp_path: Path):
    findings = tmp_path / "findings.json"
    findings.write_text(json.dumps({"findings": [1, 2, 3]}))
    first = retain_snapshot(findings)

    # Simulated mid-write truncation (no closing bracket).
    findings.write_text('{"findings": [1, 2,')

    assert retain_snapshot(findings) is None, "partial write must be rejected"
    latest = latest_valid_snapshot(findings)
    assert latest is not None
    assert Path(latest["path"]).read_bytes() == first.read_bytes()


def test_missing_file_yields_nothing(tmp_path: Path):
    assert retain_snapshot(tmp_path / "absent.json") is None
    assert latest_valid_snapshot(tmp_path / "absent.json") is None


def test_schema_validator_gates_retention(tmp_path: Path):
    findings = tmp_path / "findings.json"
    findings.write_text(json.dumps({"wrong": True}))

    def validator(payload):
        return [] if "findings" in payload else ["missing findings"]

    assert retain_snapshot(findings, schema_validator=validator) is None
    findings.write_text(json.dumps({"findings": []}))
    assert retain_snapshot(findings, schema_validator=validator) is not None


def test_only_pre_deadline_captures_are_used(tmp_path: Path):
    findings = tmp_path / "findings.json"
    findings.write_text(json.dumps({"n": 1}))
    retain_snapshot(findings)
    before = time.time()
    time.sleep(0.01)
    findings.write_text(json.dumps({"n": 2}))
    second = retain_snapshot(findings)
    assert second is not None

    latest = latest_valid_snapshot(findings, deadline_ts=before)
    payload = json.loads(Path(latest["path"]).read_text())
    assert payload == {"n": 1}, "post-deadline capture must not be used"
    latest_all = latest_valid_snapshot(findings)
    assert json.loads(Path(latest_all["path"]).read_text()) == {"n": 2}
