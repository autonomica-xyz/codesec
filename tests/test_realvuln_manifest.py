"""P07 manifest / freeze / commit / arm_done failure-injection tests."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from bench.realvuln import experiment as exp_mod
from bench.realvuln.experiment import (
    arm_done,
    build_schedule,
    cell_id_of,
    cmd_freeze,
    commit_cell_outputs,
    expected_cells_from_schedule,
    load_manifest,
)


def _spec(tmp_path: Path, repos=("realvuln-a", "realvuln-b")) -> dict:
    return {
        "protocol_version": 2,
        "repos": list(repos),
        "seed": 20260922,
        "benchmark_pin": "7a710251f55c17d32d3adcb13d37468e2e3b9e4a",
        "realvuln_root": str(tmp_path / "rv"),
        "settings": {
            "gateway_url": "http://gateway:8800/v1",
            "model": "glm-5.3",
            "temperature": 0.6,
            "max_output_tokens_per_request": 32768,
            "wall_ceiling_s": 7200,
        },
        "effective_request": {
            "model": "glm-5.3",
            "request_params": {
                "thinking": {"type": "enabled"},
                "reasoning_effort": "low",
            },
            "temperature": 0.6,
            "max_tokens": 32768,
            "context_limit": 262144,
            "stream": True,
            "fingerprint_sha256": "0" * 64,
        },
        "report": {"policy": "confirmed_reachable", "renderer": "deterministic"},
        "budgets": {"wall_ceiling_s": 7200},
        "failure_scoring": {},
        "primary_metric": "strict micro F3 mean over three trials",
        "thresholds": {},
        "image": {"tag": "codesec-iso", "image_id": "sha256:" + "ab" * 32},
        "isolation_evidence_sha256": "0" * 64,
    }


def _spec_with_admission(tmp_path: Path, repos=("realvuln-a", "realvuln-b")) -> dict:
    from tests._admission import add_calibration_admission

    return add_calibration_admission(tmp_path, _spec(tmp_path, repos))


def _freeze(tmp_path: Path, monkeypatch) -> Path:
    """Freeze with the environment-dependent admission checks stubbed —
    the unit tests exercise the manifest machinery, not the live docker /
    benchmark checkout (those are covered by the real preflight gates)."""
    import bench.realvuln.isolation as iso

    monkeypatch.setattr(iso, "verify_pin", lambda *a, **k: {
        "head": "pinned", "pinned": "pinned", "untracked": []})
    monkeypatch.setattr(
        iso, "resolve_image_id",
        lambda image: image if str(image).startswith("sha256:")
        else "sha256:" + "ab" * 32,
    )
    monkeypatch.setattr(
        exp_mod, "_image_profile_endpoints",
        lambda image: {"http://gateway:8800/v1"})
    spec_path = tmp_path / "protocol-v2.json"
    spec_path.write_text(json.dumps(_spec_with_admission(tmp_path)))
    exp = tmp_path / "exp"
    class _Args:
        spec, output = str(spec_path), str(exp)
    assert cmd_freeze(_Args()) == 0
    return exp


def test_freeze_refuses_existing_output(tmp_path, monkeypatch):
    exp = _freeze(tmp_path, monkeypatch)
    spec_path = tmp_path / "protocol-v2.json"
    class _Args:
        spec, output = str(spec_path), str(exp)
    with pytest.raises(SystemExit, match="refuses an existing output"):
        cmd_freeze(_Args())


def test_freeze_rejects_incomplete_spec(tmp_path):
    """The freeze gate refuses a spec missing required keys — a partial
    contract must never produce a manifest."""
    spec_path = tmp_path / "bad.json"
    spec_path.write_text(json.dumps({"repos": ["realvuln-a"]}))
    class _Args:
        spec, output = str(spec_path), str(tmp_path / "exp")
    with pytest.raises(SystemExit, match="freeze validation"):
        cmd_freeze(_Args())


def test_manifest_hash_and_load_roundtrip(tmp_path, monkeypatch):
    exp = _freeze(tmp_path, monkeypatch)
    manifest = load_manifest(exp)
    assert manifest["protocol_version"] == 2
    assert manifest["experiment_id"] == "exp"
    assert manifest["retry_rules"]["first_inference_attempt_is_operational_primary"]
    # Tampering breaks the hash.
    manifest_path = exp / "operator" / "manifest.json"
    payload = json.loads(manifest_path.read_text())
    payload["settings"]["gateway_url"] = "http://evil:1/v1"
    manifest_path.write_text(json.dumps(payload, sort_keys=True))
    with pytest.raises(exp_mod.ExperimentError, match="hash mismatch"):
        load_manifest(exp)


def test_schedule_is_counterbalanced_and_seeded(tmp_path):
    repos = [f"realvuln-{name}" for name in (
        "vampi", "dvfa", "pia", "dvpwa", "lbgg", "pygoat")]
    schedule = build_schedule(repos, seed=20260922)
    assert len(schedule) == 18  # 6 repos x 3 trials
    h_first = sum(1 for b in schedule if b["arm_sequence"][0] == "h")
    assert h_first == 9, "9 H-first and 9 V-first blocks"
    per_repo = {}
    for block in schedule:
        per_repo.setdefault(block["repo"], []).append(block["trial"])
    assert all(sorted(t) == [1, 2, 3] for t in per_repo.values())
    # Deterministic under the recorded seed.
    assert build_schedule(repos, seed=20260922) == schedule
    assert build_schedule(repos, seed=1) != schedule


def test_expected_cells_cover_every_repo_trial_arm(tmp_path):
    schedule = build_schedule(["realvuln-a", "realvuln-b"])
    cells = expected_cells_from_schedule(schedule)
    assert len(cells) == 12
    ids = [c["cell_id"] for c in cells]
    assert len(set(ids)) == 12, "cell ids are unique"


# ---- commit / arm_done failure injection ------------------------------------

def _cell(repo="realvuln-a", trial=1, arm="h"):
    return {
        "repo": repo, "trial": trial, "arm": arm,
        "cell_id": cell_id_of(repo, trial, arm),
    }


def _manifest_with_cells(cells):
    return {
        "experiment_id": "exp", "manifest_sha256": "mhash1",
        "expected_cells": cells,
    }


def _write_findings(path: Path, findings) -> Path:
    path.write_text(json.dumps({"version": "x", "results": findings}))
    return path


def test_commit_then_arm_done_verifies_hashes(tmp_path):
    cell = _cell()
    manifest = _manifest_with_cells([cell])
    staging = tmp_path / "out"
    staging.mkdir()
    files = {
        "primary": _write_findings(staging / "primary.semgrep.json", []),
        "secondary": _write_findings(
            staging / "secondary-confirmed.semgrep.json", []),
    }
    marker = commit_cell_outputs(
        exp=tmp_path, manifest=manifest, cell=cell, attempt_id="att-1",
        export_dir=staging, files=files,
    )
    committed = tmp_path / "committed" / cell["cell_id"]
    result = arm_done(committed, manifest=manifest, arm="h",
                      repo=cell["repo"], trial=1)
    assert result["done"], result


def test_truncated_artifact_is_not_completion(tmp_path):
    cell = _cell()
    manifest = _manifest_with_cells([cell])
    staging = tmp_path / "out"
    staging.mkdir()
    files = {
        "primary": _write_findings(staging / "primary.semgrep.json", []),
        "secondary": _write_findings(
            staging / "secondary-confirmed.semgrep.json", []),
    }
    commit_cell_outputs(
        exp=tmp_path, manifest=manifest, cell=cell, attempt_id="att-1",
        export_dir=staging, files=files,
    )
    committed = tmp_path / "committed" / cell["cell_id"]
    artifact = committed / "primary.semgrep.json"
    artifact.write_text('{"results": [')  # truncated overwrite later
    result = arm_done(committed, manifest=manifest, arm="h",
                      repo=cell["repo"], trial=1)
    assert not result["done"]
    assert "truncated" in result["reason"]


def test_wrong_experiment_hash_invalidates_completion(tmp_path):
    cell = _cell()
    manifest = _manifest_with_cells([cell])
    staging = tmp_path / "out"
    staging.mkdir()
    files = {
        "primary": _write_findings(staging / "primary.semgrep.json", []),
        "secondary": _write_findings(
            staging / "secondary-confirmed.semgrep.json", []),
    }
    commit_cell_outputs(
        exp=tmp_path, manifest=manifest, cell=cell, attempt_id="att-1",
        export_dir=staging, files=files,
    )
    other = dict(manifest, manifest_sha256="different-config")
    result = arm_done(
        tmp_path / "committed" / cell["cell_id"], manifest=other,
        arm="h", repo=cell["repo"], trial=1,
    )
    assert not result["done"]
    assert result["reason"] == "config hash mismatch"


def test_missing_completion_marker_is_not_completion(tmp_path):
    cell = _cell()
    manifest = _manifest_with_cells([cell])
    committed = tmp_path / "committed" / cell["cell_id"]
    committed.mkdir(parents=True)
    _write_findings(committed / "primary.semgrep.json", [])
    result = arm_done(committed, manifest=manifest, arm="h",
                      repo=cell["repo"], trial=1)
    assert not result["done"]
    assert result["reason"] == "missing completion marker"


def test_double_commit_of_one_cell_is_rejected(tmp_path):
    cell = _cell()
    manifest = _manifest_with_cells([cell])
    staging = tmp_path / "out"
    staging.mkdir()
    files = {
        "primary": _write_findings(staging / "primary.semgrep.json", []),
        "secondary": _write_findings(
            staging / "secondary-confirmed.semgrep.json", []),
    }
    commit_cell_outputs(
        exp=tmp_path, manifest=manifest, cell=cell, attempt_id="att-1",
        export_dir=staging, files=files,
    )
    # A second controller cannot commit the same cell again.
    with pytest.raises(exp_mod.ExperimentError, match="cannot commit one cell twice"):
        commit_cell_outputs(
            exp=tmp_path, manifest=manifest, cell=cell, attempt_id="att-2",
            export_dir=staging, files=files,
        )


def test_crash_during_completion_write_leaves_no_marker(tmp_path, monkeypatch):
    """Completion marker is written last via atomic rename; a simulated
    crash before the rename leaves the cell retry-eligible, not falsely
    done."""
    cell = _cell()
    manifest = _manifest_with_cells([cell])
    staging = tmp_path / "out"
    staging.mkdir()
    files = {
        "primary": _write_findings(staging / "primary.semgrep.json", []),
        "secondary": _write_findings(
            staging / "secondary-confirmed.semgrep.json", []),
    }

    real_rename = __import__("os").rename

    def crashing_rename(src, dst):
        if str(dst).endswith("completion.json"):
            raise OSError("simulated crash before marker rename")
        return real_rename(src, dst)

    monkeypatch.setattr("os.rename", crashing_rename)
    with pytest.raises(OSError, match="simulated crash"):
        commit_cell_outputs(
            exp=tmp_path, manifest=manifest, cell=cell, attempt_id="att-1",
            export_dir=staging, files=files,
        )
    monkeypatch.setattr("os.rename", real_rename)
    committed = tmp_path / "committed" / cell["cell_id"]
    if committed.exists():
        result = arm_done(committed, manifest=manifest, arm="h",
                          repo=cell["repo"], trial=1)
        assert not result["done"]


# ---- executor failure injection (fake arms, no inference) --------------------

def _exp_with_frozen_manifest(tmp_path: Path, monkeypatch,
                              repos=("realvuln-a",)):
    rv = _mini_realvuln(tmp_path, repos)
    import bench.realvuln.isolation as iso

    monkeypatch.setattr(iso, "verify_pin", lambda *a, **k: {
        "head": "pinned", "pinned": "pinned", "untracked": []})
    monkeypatch.setattr(
        iso, "resolve_image_id", lambda image: "sha256:" + "ab" * 32)
    monkeypatch.setattr(
        exp_mod, "_image_profile_endpoints",
        lambda image: {"http://gateway:8800/v1"})
    spec_path = tmp_path / "protocol-v2.json"
    spec = _spec_with_admission(tmp_path, repos=repos)
    spec["realvuln_root"] = str(rv)
    spec_path.write_text(json.dumps(spec))
    exp = tmp_path / "exp"

    class _Args:
        spec, output = str(spec_path), str(exp)
    assert cmd_freeze(_Args()) == 0
    return exp, load_manifest(exp)


def _mini_realvuln(tmp_path: Path, repos) -> Path:
    rv = tmp_path / "rv"
    for repo in repos:
        (rv / "repos" / repo).mkdir(parents=True, exist_ok=True)
        (rv / "repos" / repo / "app.py").write_text("x = 1\n")
        gt_dir = rv / "ground-truth" / repo
        gt_dir.mkdir(parents=True, exist_ok=True)
        (gt_dir / "ground-truth.json").write_text(json.dumps({
            "repo_id": repo, "commit_sha": "deadbeef",
            "findings": [{"id": "x", "is_vulnerable": True,
                          "file": "app.py",
                          "location": {"start_line": 1, "end_line": 1},
                          "primary_cwe": "CWE-95"}],
        }))
    return rv


def _fake_arm_report(output_dir: Path, findings=None):
    report_dir = output_dir / "run" / "results" / "report"
    report_dir.mkdir(parents=True, exist_ok=True)
    report = {
        "run_id": "x", "target": {"repo_path": "/work/target"},
        "summary": {"total": len(findings or []), "by_severity": {}},
        "findings": findings or [],
    }
    (report_dir / "report.json").write_text(json.dumps(report))
    (report_dir / "confirmed.json").write_text(json.dumps(report))


async def test_executor_failure_before_output_ledgers_no_output(tmp_path, monkeypatch):
    from bench.realvuln import executor as ex_mod
    from bench.realvuln.ledger import AttemptLedger

    exp, manifest = _exp_with_frozen_manifest(tmp_path, monkeypatch)
    ledger = AttemptLedger(
        exp / "operator" / "attempts.jsonl",
        experiment_id=manifest["experiment_id"],
        config_hash=manifest["manifest_sha256"],
    )

    def failing_arm(**kwargs):
        return {"exit_code": 1, "stdout_tail": "", "stderr_tail": "boom",
                "duration_s": 1.0, "cmd": []}

    monkeypatch.setattr(ex_mod, "run_arm_container", failing_arm)
    cell = {
        "repo": "realvuln-a", "trial": 1, "arm": "h",
        "cell_id": cell_id_of("realvuln-a", 1, "h"),
    }
    outcome = ex_mod.execute_block(
        exp=exp, manifest=manifest, ledger=ledger, cell=cell, block={},
    )
    assert outcome["ok"] is False
    assert "missing_output" in outcome["reason"]
    state = ledger.terminal_state(cell["cell_id"])
    assert state["status"] == "failed_no_output"
    assert not (exp / "committed" / cell["cell_id"]).exists()
    assert not ledger.cell_accounted(cell["cell_id"]) or state["status"] in {
        "failed_no_output"
    }


async def test_executor_nonzero_exit_with_valid_report_is_committed_visible(
    tmp_path, monkeypatch
):
    """A nonzero arm exit that still produced a valid report is an
    operational failure WITH output: committed, ledgered failed_output,
    never silently retried."""
    from bench.realvuln import executor as ex_mod
    from bench.realvuln.ledger import AttemptLedger

    exp, manifest = _exp_with_frozen_manifest(tmp_path, monkeypatch)
    ledger = AttemptLedger(
        exp / "operator" / "attempts.jsonl",
        experiment_id=manifest["experiment_id"],
        config_hash=manifest["manifest_sha256"],
    )

    def arm(**kwargs):
        output_dir = kwargs["exp"] / "attempts" / kwargs["attempt_id"] / "output"
        _fake_arm_report(output_dir, findings=[{
            "finding_id": "f_1", "file": "app.py", "line_start": 1,
            "line_end": 1, "cwe": "CWE-95", "severity": "high",
            "description": "eval of user input in app.py handler.",
        }])
        return {"exit_code": 3, "stdout_tail": "", "stderr_tail": "deadline",
                "duration_s": 7200.0, "cmd": []}

    monkeypatch.setattr(ex_mod, "run_arm_container", arm)
    cell = {
        "repo": "realvuln-a", "trial": 1, "arm": "h",
        "cell_id": cell_id_of("realvuln-a", 1, "h"),
    }
    outcome = ex_mod.execute_block(
        exp=exp, manifest=manifest, ledger=ledger, cell=cell, block={},
    )
    assert outcome["ok"] is True
    assert outcome["status"] == "failed_output"
    state = ledger.terminal_state(cell["cell_id"])
    assert state["exit_status"] == 3
    committed = exp / "committed" / cell["cell_id"]
    assert (committed / "completion.json").is_file()
    primary = json.loads((committed / "primary.semgrep.json").read_text())
    assert len(primary["results"]) == 1
    # Idempotent resume: the same cell is not re-executed.
    ran = {"n": 0}

    def no_rearm(**kwargs):  # pragma: no cover — must not run
        ran["n"] += 1
        raise AssertionError("committed cell must not re-run")

    monkeypatch.setattr(ex_mod, "run_arm_container", no_rearm)
    outcome2 = ex_mod.execute_block(
        exp=exp, manifest=manifest, ledger=ledger, cell=cell, block={},
    )
    assert outcome2.get("already_committed") is True
    assert ran["n"] == 0


async def test_executor_valid_empty_output_is_completed(tmp_path, monkeypatch):
    from bench.realvuln import executor as ex_mod
    from bench.realvuln.ledger import AttemptLedger

    exp, manifest = _exp_with_frozen_manifest(tmp_path, monkeypatch)
    ledger = AttemptLedger(
        exp / "operator" / "attempts.jsonl",
        experiment_id=manifest["experiment_id"],
        config_hash=manifest["manifest_sha256"],
    )

    def arm(**kwargs):
        output_dir = kwargs["exp"] / "attempts" / kwargs["attempt_id"] / "output"
        _fake_arm_report(output_dir, findings=[])
        return {"exit_code": 0, "stdout_tail": "", "stderr_tail": "",
                "duration_s": 10.0, "cmd": []}

    monkeypatch.setattr(ex_mod, "run_arm_container", arm)
    cell = {
        "repo": "realvuln-a", "trial": 1, "arm": "v",
        "cell_id": cell_id_of("realvuln-a", 1, "v"),
    }
    # V arm: write a findings.json (valid empty list).
    original = ex_mod.run_arm_container

    def v_arm(**kwargs):
        result = original(**kwargs)
        output_dir = kwargs["exp"] / "attempts" / kwargs["attempt_id"] / "output"
        (output_dir / "findings.json").write_text('{"findings": []}')
        return result

    monkeypatch.setattr(ex_mod, "run_arm_container", v_arm)
    outcome = ex_mod.execute_block(
        exp=exp, manifest=manifest, ledger=ledger, cell=cell, block={},
    )
    assert outcome["ok"] is True
    assert outcome["status"] == "completed"
    committed = exp / "committed" / cell["cell_id"]
    primary = json.loads((committed / "primary.semgrep.json").read_text())
    assert primary["results"] == []


# ---- executor acceptance: deadline recovery + attribution -----------------

def _gateway_record(exp: Path, attempt_id: str) -> None:
    """Simulate the trusted gateway admission record for an attempt."""
    recs = exp / "operator" / "gateway"
    recs.mkdir(parents=True, exist_ok=True)
    with (recs / "requests.jsonl").open("a") as fh:
        fh.write(json.dumps({
            "kind": "admission", "attempt_id": attempt_id,
        }) + "\n")


async def test_executor_timeout_exports_h_checkpoint(tmp_path, monkeypatch):
    """R1: a timed-out H attempt exports the last valid checkpoint — the
    cell is committed but NEVER recorded as a clean completion."""
    from bench.realvuln import executor as ex_mod
    from bench.realvuln.ledger import AttemptLedger

    exp, manifest = _exp_with_frozen_manifest(tmp_path, monkeypatch)
    ledger = AttemptLedger(
        exp / "operator" / "attempts.jsonl",
        experiment_id=manifest["experiment_id"],
        config_hash=manifest["manifest_sha256"],
    )

    def arm(**kwargs):
        output_dir = kwargs["exp"] / "attempts" / kwargs["attempt_id"] / "output"
        report_dir = output_dir / "run" / "results" / "report"
        report_dir.mkdir(parents=True)
        # Only the mid-run checkpoint exists — the final report was never
        # written before the wall cap. The checkpoint is written WHILE
        # WORK IS ELIGIBLE (the synthesis reserve guarantees this in real
        # runs) so the operator-owned watcher captures it before the cap.
        (report_dir / "report.checkpoint.json").write_text(json.dumps({
            "run_id": "x", "findings": [{
                "finding_id": "f_1", "file": "app.py", "line_start": 1,
                "line_end": 1, "cwe": "CWE-95", "severity": "high",
                "description": "eval",
            }],
        }))
        _gateway_record(kwargs["exp"], kwargs["attempt_id"])
        import time as _time
        _time.sleep(ex_mod.SNAPSHOT_POLL_S + 0.5)
        return {"exit_code": None, "timed_out": True, "container": "c1",
                "stdout_tail": "", "stderr_tail": "", "duration_s": 7200.0,
                "cmd": []}

    monkeypatch.setattr(ex_mod, "run_arm_container", arm)
    cell = {"repo": "realvuln-a", "trial": 1, "arm": "h",
            "cell_id": cell_id_of("realvuln-a", 1, "h")}
    outcome = ex_mod.execute_block(
        exp=exp, manifest=manifest, ledger=ledger, cell=cell, block={})
    assert outcome["ok"] is True
    assert outcome["status"] == "failed_output"
    state = ledger.terminal_state(cell["cell_id"])
    assert state["status"] == "failed_output"
    assert state["reason_code"] == "deadline_recovered_output"
    assert state["made_inference_requests"] is True
    assert state["export_provenance"]["checkpoint_only"] is True
    committed = exp / "committed" / cell["cell_id"]
    assert (committed / "primary.semgrep.json").is_file()


async def test_executor_v_truncated_write_recovers_snapshot(
    tmp_path, monkeypatch
):
    """R1/R2: a valid V findings file captured mid-run, then overwritten by
    a truncated final write, recovers the retained pre-deadline snapshot."""
    import time as _time
    from bench.realvuln import executor as ex_mod
    from bench.realvuln.ledger import AttemptLedger

    exp, manifest = _exp_with_frozen_manifest(tmp_path, monkeypatch)
    ledger = AttemptLedger(
        exp / "operator" / "attempts.jsonl",
        experiment_id=manifest["experiment_id"],
        config_hash=manifest["manifest_sha256"],
    )

    def arm(**kwargs):
        output_dir = kwargs["exp"] / "attempts" / kwargs["attempt_id"] / "output"
        output_dir.mkdir(parents=True, exist_ok=True)
        findings = output_dir / "findings.json"
        findings.write_text(json.dumps({"findings": [{
            "finding_id": "f_1", "file": "app.py", "line_start": 1,
            "line_end": 1, "cwe": "CWE-95", "severity": "high",
            "description": "eval", "evidence": "eval(x)",
        }]}))
        # Let the snapshot watcher capture the valid version, then
        # simulate the kill-mid-write truncation.
        _time.sleep(ex_mod.SNAPSHOT_POLL_S + 1.0)
        findings.write_text('{"findings": [{"file": "app.py"')  # truncated
        _gateway_record(kwargs["exp"], kwargs["attempt_id"])
        return {"exit_code": None, "timed_out": True, "container": "c1",
                "stdout_tail": "", "stderr_tail": "", "duration_s": 7200.0,
                "cmd": []}

    monkeypatch.setattr(ex_mod, "run_arm_container", arm)
    cell = {"repo": "realvuln-a", "trial": 1, "arm": "v",
            "cell_id": cell_id_of("realvuln-a", 1, "v")}
    outcome = ex_mod.execute_block(
        exp=exp, manifest=manifest, ledger=ledger, cell=cell, block={})
    assert outcome["ok"] is True
    state = ledger.terminal_state(cell["cell_id"])
    assert state["status"] == "failed_output"
    assert state["export_provenance"]["v_source"] == "retained_snapshot"
    committed = exp / "committed" / cell["cell_id"]
    primary = json.loads((committed / "primary.semgrep.json").read_text())
    assert len(primary["results"]) == 1  # the recovered finding


async def test_executor_timeout_no_output_is_terminal_failure(
    tmp_path, monkeypatch
):
    """A timed-out attempt with no usable output is a terminal
    failed_no_output — never silently retried into a fresh cell."""
    from bench.realvuln import executor as ex_mod
    from bench.realvuln.ledger import AttemptLedger

    exp, manifest = _exp_with_frozen_manifest(tmp_path, monkeypatch)
    ledger = AttemptLedger(
        exp / "operator" / "attempts.jsonl",
        experiment_id=manifest["experiment_id"],
        config_hash=manifest["manifest_sha256"],
    )

    def arm(**kwargs):
        _gateway_record(kwargs["exp"], kwargs["attempt_id"])
        return {"exit_code": None, "timed_out": True, "container": "c1",
                "stdout_tail": "", "stderr_tail": "", "duration_s": 7200.0,
                "cmd": []}

    monkeypatch.setattr(ex_mod, "run_arm_container", arm)
    cell = {"repo": "realvuln-a", "trial": 1, "arm": "h",
            "cell_id": cell_id_of("realvuln-a", 1, "h")}
    outcome = ex_mod.execute_block(
        exp=exp, manifest=manifest, ledger=ledger, cell=cell, block={})
    assert outcome["ok"] is False
    state = ledger.terminal_state(cell["cell_id"])
    assert state["status"] == "failed_no_output"
    assert state["reason_code"] == "deadline_no_output"
    # The inference-bearing primary is fixed: a second run cannot claim.
    outcome2 = ex_mod.execute_block(
        exp=exp, manifest=manifest, ledger=ledger, cell=cell, block={})
    assert outcome2.get("already_accounted") is True


async def test_executor_setup_failure_allows_one_retry(tmp_path, monkeypatch):
    """A pre-inference (setup) failure may retry once inside the cell; the
    retried attempt becomes the primary."""
    from bench.realvuln import executor as ex_mod
    from bench.realvuln.ledger import AttemptLedger

    exp, manifest = _exp_with_frozen_manifest(tmp_path, monkeypatch)
    ledger = AttemptLedger(
        exp / "operator" / "attempts.jsonl",
        experiment_id=manifest["experiment_id"],
        config_hash=manifest["manifest_sha256"],
    )
    calls = {"n": 0}

    def arm(**kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            raise ex_mod.isolation.IsolationError("docker exploded")
        output_dir = kwargs["exp"] / "attempts" / kwargs["attempt_id"] / "output"
        _fake_arm_report(output_dir, findings=[])
        from tests._h_health import write_healthy_h_state

        write_healthy_h_state(output_dir)
        _gateway_record(kwargs["exp"], kwargs["attempt_id"])
        return {"exit_code": 0, "stdout_tail": "", "stderr_tail": "",
                "duration_s": 1.0, "cmd": []}

    monkeypatch.setattr(ex_mod, "run_arm_container", arm)
    cell = {"repo": "realvuln-a", "trial": 1, "arm": "h",
            "cell_id": cell_id_of("realvuln-a", 1, "h")}
    first = ex_mod.execute_block(
        exp=exp, manifest=manifest, ledger=ledger, cell=cell, block={})
    assert first["ok"] is False
    second = ex_mod.execute_block(
        exp=exp, manifest=manifest, ledger=ledger, cell=cell, block={})
    assert second["ok"] is True
    assert calls["n"] == 2
    state = ledger.terminal_state(cell["cell_id"])
    assert state["status"] == "completed"
    assert state["attempt_id"] == second["attempt_id"]


async def test_executor_unknown_attribution_invalidates_cell(
    tmp_path, monkeypatch
):
    """An attempt whose inference attribution is unknown (no trusted
    gateway records at all) invalidates the cell — never retried, so a
    hidden first inference can never be duplicated by a second primary."""
    from bench.realvuln import executor as ex_mod
    from bench.realvuln.ledger import AttemptLedger

    exp, manifest = _exp_with_frozen_manifest(tmp_path, monkeypatch)
    ledger = AttemptLedger(
        exp / "operator" / "attempts.jsonl",
        experiment_id=manifest["experiment_id"],
        config_hash=manifest["manifest_sha256"],
    )

    def arm(**kwargs):
        # No gateway record written and no records file exists ->
        # attribution is genuinely unknown (None, never coerced False).
        output_dir = kwargs["exp"] / "attempts" / kwargs["attempt_id"] / "output"
        _fake_arm_report(output_dir, findings=[])
        return {"exit_code": 1, "stdout_tail": "", "stderr_tail": "",
                "duration_s": 1.0, "cmd": []}

    monkeypatch.setattr(ex_mod, "run_arm_container", arm)
    cell = {"repo": "realvuln-a", "trial": 1, "arm": "h",
            "cell_id": cell_id_of("realvuln-a", 1, "h")}
    outcome = ex_mod.execute_block(
        exp=exp, manifest=manifest, ledger=ledger, cell=cell, block={})
    # Output may commit for forensic preservation, but the attempt end
    # carries unknown attribution — verify/aggregate flag the cell.
    state = ledger.terminal_state(cell["cell_id"])
    assert state["made_inference_requests"] is None
    assert state["attribution_inconsistent"] is True
    # A second run must refuse: unknown attribution invalidates the cell.
    outcome2 = ex_mod.execute_block(
        exp=exp, manifest=manifest, ledger=ledger, cell=cell, block={})
    # The committed marker short-circuits first; if it were absent the
    # attribution-inconsistent terminal state would refuse the claim.
    assert (
        outcome2.get("already_committed") is True
        or outcome2.get("already_accounted") is True
    )
    calls = {"n": 0}

    def counting_arm(**kwargs):
        calls["n"] += 1
        raise ex_mod.isolation.IsolationError("x")

    monkeypatch.setattr(ex_mod, "run_arm_container", counting_arm)
    ex_mod.execute_block(
        exp=exp, manifest=manifest, ledger=ledger, cell=cell, block={})
    assert calls["n"] == 0  # never re-executed
