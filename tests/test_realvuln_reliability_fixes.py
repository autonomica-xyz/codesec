"""Reliability-fix regression tests (2026-09-24 review, plan steps B–E).

Every test here encodes the CORRECT behavior for a defect reproduced in
``bench/realvuln/repair-evidence/review-2026-09-24/reproduce.py``. They are
red before the repairs and must stay green after.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from bench.realvuln import executor as ex_mod
from bench.realvuln.aggregate import aggregate_experiment, _fake_scorer_factory
from bench.realvuln.experiment import (
    cell_id_of,
    cmd_freeze,
    cmd_verify,
    commit_cell_outputs,
    load_manifest,
)
from bench.realvuln.ledger import AttemptLedger

FAKE_SCORER = _fake_scorer_factory()


# ---------------------------------------------------------------------------
# Shared fixtures: a tiny two-repo frozen experiment with a fake scorer
# ---------------------------------------------------------------------------

def _mini_realvuln(tmp_path: Path, repos) -> Path:
    rv = tmp_path / "rv"
    for repo in repos:
        (rv / "repos" / repo).mkdir(parents=True, exist_ok=True)
        (rv / "repos" / repo / "app.py").write_text("x = 1\n")
        (rv / "ground-truth" / repo).mkdir(parents=True, exist_ok=True)
        (rv / "ground-truth" / repo / "ground-truth.json").write_text(
            json.dumps({
                "repo_id": repo, "commit_sha": "deadbeef",
                "findings": [{
                    "id": f"{repo}-v", "is_vulnerable": True,
                    "primary_cwe": "CWE-89", "file": "app.py",
                    "location": {"start_line": 1, "end_line": 1},
                }],
            })
        )
    return rv


def _spec(tmp_path: Path, repos, **overrides) -> dict:
    spec = {
        "protocol_version": 2,
        "repos": list(repos), "trials": [1], "seed": 7,
        "benchmark_pin": "0" * 40,
        "realvuln_root": str(_mini_realvuln(tmp_path, repos)),
        "settings": {
            "gateway_url": "http://gateway:8800/v1",
            "model": "glm-5.3", "temperature": 0.6,
            "max_output_tokens_per_request": 32768,
            "wall_ceiling_s": 60,
        },
        "effective_request": {
            "model": "glm-5.3",
            "request_params": {"thinking": {"type": "enabled"},
                               "reasoning_effort": "low"},
            "temperature": 0.6, "max_tokens": 32768,
            "context_limit": 262144, "stream": True,
            "fingerprint_sha256": "0" * 64,
        },
        "report": {"policy": "confirmed_reachable"},
        "budgets": {}, "failure_scoring": {}, "thresholds": {},
        "primary_metric": "strict micro F3",
        "image": {"tag": "codesec-iso", "image_id": "sha256:" + "ab" * 32},
        "isolation_evidence_sha256": "0" * 64,
    }
    spec.update(overrides)
    return spec


def _freeze(tmp_path: Path, spec: dict, monkeypatch, name: str = "exp") -> Path:
    import bench.realvuln.isolation as iso

    if "admission" not in spec:
        # Machinery tests freeze as calibration purpose with minimal REAL
        # isolation evidence; scored-admission tests supply their own.
        from tests._admission import add_calibration_admission

        spec = add_calibration_admission(tmp_path, spec)
    monkeypatch.setattr(iso, "verify_pin", lambda *a, **k: {
        "head": "p", "pinned": "p", "untracked": []})
    monkeypatch.setattr(
        iso, "resolve_image_id", lambda image: "sha256:" + "ab" * 32)
    import bench.realvuln.experiment as exp_mod

    monkeypatch.setattr(
        exp_mod, "_image_profile_endpoints",
        lambda image: {"http://gateway:8800/v1"})
    spec_path = tmp_path / f"spec-{name}.json"
    spec_path.write_text(json.dumps(spec))
    exp = tmp_path / name

    class _Args:
        pass

    _Args.spec, _Args.output = str(spec_path), str(exp)
    assert cmd_freeze(_Args()) == 0
    return exp


def _ledger(exp: Path, manifest: dict) -> AttemptLedger:
    return AttemptLedger(
        exp / "operator" / "attempts.jsonl",
        experiment_id=manifest["experiment_id"],
        config_hash=manifest["manifest_sha256"],
    )


def _commit_cell(exp, manifest, repo, trial, arm, findings=("f1",),
                 status="completed", attempt_id=None) -> str:
    cell_id = cell_id_of(repo, trial, arm)
    attempt_id = attempt_id or f"att-{repo}-{trial}-{arm}"
    staging = exp / "staging" / attempt_id
    staging.mkdir(parents=True, exist_ok=True)
    doc = {"version": "x", "results": [
        {"path": "app.py", "start": {"line": 1}, "end": {"line": 1},
         "extra": {"metadata": {"cwe": ["CWE-89"]}, "message": "m"}}
        for _ in findings
    ]}
    (staging / "primary.semgrep.json").write_text(json.dumps(doc))
    files = {"primary": staging / "primary.semgrep.json"}
    if arm == "h":
        (staging / "secondary-confirmed.semgrep.json").write_text(
            json.dumps(doc))
        files["secondary"] = staging / "secondary-confirmed.semgrep.json"
    ledger = _ledger(exp, manifest)
    ledger.append({"type": "attempt_start", "cell_id": cell_id,
                   "attempt_id": attempt_id})
    commit_cell_outputs(
        exp=exp, manifest=manifest,
        cell={"repo": repo, "trial": trial, "arm": arm, "cell_id": cell_id},
        attempt_id=attempt_id, export_dir=staging, files=files,
    )
    ledger.append({"type": "attempt_end", "cell_id": cell_id,
                   "attempt_id": attempt_id, "status": status,
                   "made_inference_requests": True})
    return cell_id


class _VerifyArgs:
    def __init__(self, exp):
        self.experiment = str(exp)


# ---------------------------------------------------------------------------
# Review finding 1 (P1): post-deadline output must not be eligible
# ---------------------------------------------------------------------------

def _finding_doc() -> dict:
    return {"findings": [{
        "finding_id": "f_1", "file": "app.py", "line_start": 1,
        "line_end": 1, "cwe": "CWE-89", "severity": "high",
        "description": "sqli", "evidence": "execute(q)",
    }]}


@pytest.mark.parametrize("arm", ["h", "v"])
def test_post_deadline_output_is_not_exported(tmp_path, arm):
    """A valid finding file first appearing AFTER the cutoff is never
    eligible for either arm (review probe: both arms exported 1)."""
    from bench.realvuln.executor import export_arm_outputs
    from bench.realvuln.snapshot import WorkDeadline

    manifest = {"settings": {}, "experiment_id": "exp"}
    exp = tmp_path / "exp"
    output_dir = exp / "attempts" / "att" / "output"
    target_dir = tmp_path / "target"
    target_dir.mkdir()
    (target_dir / "app.py").write_text("x = 1\n")
    if arm == "h":
        path = output_dir / "run" / "results" / "report" / "report.json"
    else:
        path = output_dir / "findings.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(_finding_doc()))
    deadline = WorkDeadline(total_seconds=60.0)
    deadline._expire_for_test()
    with pytest.raises(Exception):
        export_arm_outputs(
            exp=exp, manifest=manifest, cell={"arm": arm}, attempt_id="att",
            output_dir=output_dir, target_dir=target_dir, deadline=deadline,
        )


# ---------------------------------------------------------------------------
# Review findings 2+3 (P1): invalidation, artifact corruption and marker
# identity must block BOTH verify and aggregation
# ---------------------------------------------------------------------------

def _complete_matrix(exp, manifest, repos):
    for repo in repos:
        _commit_cell(exp, manifest, repo, 1, "h")
        _commit_cell(exp, manifest, repo, 1, "v")


def test_late_invalidation_blocks_verify_and_aggregate(tmp_path, monkeypatch):
    repos = ["realvuln-a", "realvuln-b"]
    exp = _freeze(tmp_path, _spec(tmp_path, repos), monkeypatch)
    manifest = load_manifest(exp)
    _complete_matrix(exp, manifest, repos)

    cell = manifest["expected_cells"][0]
    ledger = _ledger(exp, manifest)
    ledger.append({
        "type": "attempt_end", "cell_id": cell["cell_id"],
        "attempt_id": "review-invalidation", "status": "invalidated",
        "made_inference_requests": False,
        "reason_code": "review_simulated_protocol_breach",
    })
    assert cmd_verify(_VerifyArgs(exp)) == 1
    report = aggregate_experiment(exp, scorer=FAKE_SCORER)
    assert report["problems"], "late invalidation must block the headline"
    assert report["headline"] is None


def test_corrupt_committed_artifact_blocks_aggregation(tmp_path, monkeypatch):
    """Truncating a committed artifact of a failed-output cell is an
    INTEGRITY failure — not empty predictions and not a headline."""
    repos = ["realvuln-a", "realvuln-b"]
    exp = _freeze(tmp_path, _spec(tmp_path, repos), monkeypatch)
    manifest = load_manifest(exp)
    _complete_matrix(exp, manifest, repos)
    # Make one H cell a failed-output cell (timeout-recovered output).
    cell = manifest["expected_cells"][0]
    ledger = _ledger(exp, manifest)
    ends = [r for r in ledger.records(cell["cell_id"])
            if r.get("type") == "attempt_end"]
    assert ends
    with (exp / "operator" / "attempts.jsonl").open() as fh:
        lines = fh.readlines()
    rewritten = []
    for line in lines:
        record = json.loads(line)
        if record.get("attempt_id") == ends[0]["attempt_id"] and \
                record.get("type") == "attempt_end":
            record["status"] = "failed_output"
            record["reason_code"] = "deadline_recovered_output"
        rewritten.append(json.dumps(record))
    (exp / "operator" / "attempts.jsonl").write_text(
        "\n".join(rewritten) + "\n")
    # Corrupt the committed primary artifact.
    marker = json.loads(
        (exp / "committed" / cell["cell_id"] / "completion.json").read_text())
    (exp / "committed" / cell["cell_id"] / marker["primary_path"]) \
        .write_text("{")
    assert cmd_verify(_VerifyArgs(exp)) == 1
    report = aggregate_experiment(exp, scorer=FAKE_SCORER)
    assert any("integrity" in p.lower() for p in report["problems"]), \
        report["problems"]
    assert report["headline"] is None


@pytest.mark.parametrize(
    "field,new_value",
    [
        ("repo", "WRONG-REPO"),
        ("cell_id", "WRONG-CELL"),
        ("experiment_id", "WRONG-EXPERIMENT"),
        ("trial", 99),
        ("arm", "v"),
        ("manifest_sha256", "0" * 64),
    ],
)
def test_wrong_marker_identity_blocks_both(tmp_path, monkeypatch, field,
                                           new_value):
    repos = ["realvuln-a"]
    exp = _freeze(tmp_path, _spec(tmp_path, repos), monkeypatch)
    manifest = load_manifest(exp)
    _complete_matrix(exp, manifest, repos)
    cell = manifest["expected_cells"][0]
    marker_path = exp / "committed" / cell["cell_id"] / "completion.json"
    marker = json.loads(marker_path.read_text())
    if field == "trial":
        marker["trial"] = 99
    elif field == "arm":
        marker["arm"] = "v" if cell["arm"] == "h" else "h"
    else:
        marker[field] = new_value
    marker_path.write_text(json.dumps(marker))
    assert cmd_verify(_VerifyArgs(exp)) == 1
    report = aggregate_experiment(exp, scorer=FAKE_SCORER)
    assert report["problems"]
    assert report["headline"] is None


def test_wrong_selected_attempt_blocks_both(tmp_path, monkeypatch):
    """A marker naming an attempt that is not the operational primary is
    invalid even when its file hashes are intact."""
    repos = ["realvuln-a"]
    exp = _freeze(tmp_path, _spec(tmp_path, repos), monkeypatch)
    manifest = load_manifest(exp)
    _commit_cell(exp, manifest, repos[0], 1, "h", attempt_id="att-primary")
    _commit_cell(exp, manifest, repos[0], 1, "v", attempt_id="att-v")
    # The marker's committed attempt stays att-primary, but add a later
    # inference-bearing attempt_end for the same cell whose id differs from
    # the marker — the selected attempt must be the first inference-bearing
    # one; a mismatch is a wrong-primary problem.
    ledger = _ledger(exp, manifest)
    # (already valid) — now forge the H marker to point at a second,
    # later attempt that also has a terminal record:
    h_cell = cell_id_of(repos[0], 1, "h")
    ledger.append({"type": "attempt_end", "cell_id": h_cell,
                   "attempt_id": "att-later", "status": "completed",
                   "made_inference_requests": True})
    marker_path = exp / "committed" / h_cell / "completion.json"
    marker = json.loads(marker_path.read_text())
    marker["attempt_id"] = "att-later"
    marker_path.write_text(json.dumps(marker))
    assert cmd_verify(_VerifyArgs(exp)) == 1
    report = aggregate_experiment(exp, scorer=FAKE_SCORER)
    assert any("primary" in p for p in report["problems"])
    assert report["headline"] is None


def test_missing_artifact_of_failed_output_cell_is_integrity_failure(
    tmp_path, monkeypatch
):
    """Missing (not just corrupt) committed evidence for a failed-output
    cell blocks aggregation — it never silently becomes empty predictions."""
    repos = ["realvuln-a", "realvuln-b"]
    exp = _freeze(tmp_path, _spec(tmp_path, repos), monkeypatch)
    manifest = load_manifest(exp)
    _complete_matrix(exp, manifest, repos)
    cell = manifest["expected_cells"][0]
    ledger = _ledger(exp, manifest)
    ends = [r for r in ledger.records(cell["cell_id"])
            if r.get("type") == "attempt_end"]
    with (exp / "operator" / "attempts.jsonl").open() as fh:
        lines = fh.readlines()
    rewritten = []
    for line in lines:
        record = json.loads(line)
        if record.get("attempt_id") == ends[0]["attempt_id"] and \
                record.get("type") == "attempt_end":
            record["status"] = "failed_output"
            record["reason_code"] = "deadline_recovered_output"
        rewritten.append(json.dumps(record))
    (exp / "operator" / "attempts.jsonl").write_text(
        "\n".join(rewritten) + "\n")
    (exp / "committed" / cell["cell_id"] / "completion.json").unlink()
    report = aggregate_experiment(exp, scorer=FAKE_SCORER)
    assert report["problems"]
    assert report["headline"] is None


def test_genuine_no_output_failure_still_gets_empty_predictions(
    tmp_path, monkeypatch
):
    """The honest case stays honest: an inference-bearing failed_no_output
    cell with NO committed artifacts scores as empty predictions and does
    not block the headline."""
    repos = ["realvuln-a", "realvuln-b"]
    exp = _freeze(tmp_path, _spec(tmp_path, repos), monkeypatch)
    manifest = load_manifest(exp)
    for repo in repos:
        _commit_cell(exp, manifest, repo, 1, "h")
    # realvuln-a v commits normally; realvuln-b v is the no-output case.
    _commit_cell(exp, manifest, repos[0], 1, "v")
    # realvuln-b v: inference happened, no output ever committed.
    v_cell = cell_id_of(repos[1], 1, "v")
    ledger = _ledger(exp, manifest)
    ledger.append({"type": "attempt_start", "cell_id": v_cell,
                   "attempt_id": "att-vx"})
    ledger.append({"type": "attempt_end", "cell_id": v_cell,
                   "attempt_id": "att-vx", "status": "failed_no_output",
                   "reason_code": "deadline_no_output",
                   "made_inference_requests": True})
    report = aggregate_experiment(exp, scorer=FAKE_SCORER)
    assert report["problems"] == [], report["problems"]
    assert report["headline"] is not None
    entry = report["cells"][f"{repos[1]}#t1#v"]
    assert entry["output_failure"] is True
    assert entry["counts"] == {"tp": 0, "fp": 0, "fn": 1, "tn": 0}


def test_retained_output_of_failed_cell_is_scored_and_degraded(
    tmp_path, monkeypatch
):
    repos = ["realvuln-a", "realvuln-b"]
    exp = _freeze(tmp_path, _spec(tmp_path, repos), monkeypatch)
    manifest = load_manifest(exp)
    _commit_cell(exp, manifest, repos[0], 1, "h",
                 status="failed_output")
    _commit_cell(exp, manifest, repos[0], 1, "v")
    _commit_cell(exp, manifest, repos[1], 1, "h")
    _commit_cell(exp, manifest, repos[1], 1, "v")
    report = aggregate_experiment(exp, scorer=FAKE_SCORER)
    assert report["problems"] == []
    assert report["headline"] is not None
    entry = report["cells"][f"{repos[0]}#t1#h"]
    assert entry.get("degraded") == "failed_output"
    assert entry["counts"]["tp"] == 1  # output still scored


def test_resume_cannot_replace_inference_bearing_failure(
    tmp_path, monkeypatch
):
    """After a first inference-bearing failure the primary is fixed: a
    later successful attempt cannot take over the cell."""
    repos = ["realvuln-a", "realvuln-b"]
    exp = _freeze(tmp_path, _spec(tmp_path, repos), monkeypatch)
    manifest = load_manifest(exp)
    v_cell = cell_id_of(repos[0], 1, "v")
    ledger = _ledger(exp, manifest)
    ledger.append({"type": "attempt_start", "cell_id": v_cell,
                   "attempt_id": "att-first"})
    ledger.append({"type": "attempt_end", "cell_id": v_cell,
                   "attempt_id": "att-first", "status": "failed_no_output",
                   "reason_code": "deadline_no_output",
                   "made_inference_requests": True})
    # A later controller tries to commit a successful attempt for the cell.
    staging = exp / "staging-late"
    staging.mkdir()
    doc = {"version": "x", "results": [
        {"path": "app.py", "start": {"line": 1}, "end": {"line": 1},
         "extra": {"metadata": {"cwe": ["CWE-89"]}, "message": "m"}}]}
    (staging / "primary.semgrep.json").write_text(json.dumps(doc))
    ledger.append({"type": "attempt_start", "cell_id": v_cell,
                   "attempt_id": "att-second"})
    commit_cell_outputs(
        exp=exp, manifest=manifest,
        cell={"repo": repos[0], "trial": 1, "arm": "v", "cell_id": v_cell},
        attempt_id="att-second", export_dir=staging,
        files={"primary": staging / "primary.semgrep.json"},
    )
    ledger.append({"type": "attempt_end", "cell_id": v_cell,
                   "attempt_id": "att-second", "status": "completed",
                   "made_inference_requests": True})
    assert cmd_verify(_VerifyArgs(exp)) == 1
    report = aggregate_experiment(exp, scorer=FAKE_SCORER)
    assert any("primary" in p for p in report["problems"])
    assert report["headline"] is None


# ---------------------------------------------------------------------------
# Review finding 4 (P1): freeze must verify real admission evidence
# ---------------------------------------------------------------------------

def _real_evidence_files(tmp_path: Path) -> dict:
    """A small set of REAL gate-evidence documents (contents actually
    verified by the admission check, not just hashed)."""
    from bench.realvuln.experiment import runtime_identity

    runtime_hash = runtime_identity()["runtime_tree_sha256"]
    iso = tmp_path / "iso-evidence.json"
    iso.write_text(json.dumps({
        "ran_at": 1.0,
        "passed": True,
        "checks": [{"name": "host_home_absent", "passed": True}],
        "image_id": "sha256:" + "ab" * 32,
    }))
    calib = tmp_path / "calibration.json"
    calib.write_text(json.dumps({
        "kind": "calibration-record",
        "status": "completed",
        "experiment_ids": ["calib-deadline-1", "calib-neterror-1"],
        "image_id": "sha256:" + "ab" * 32,
        "runtime_tree_sha256": runtime_hash,
    }))
    pre = tmp_path / "preflight.json"
    pre.write_text(json.dumps({
        "kind": "preflight-record", "passed": True,
        "gates": [{"name": "g", "status": "passed"}],
        "runtime_tree_sha256": runtime_hash,
    }))
    return {"isolation": iso, "calibration": calib, "preflight": pre}


def _admission_spec(tmp_path: Path, repos) -> dict:
    spec = _spec(tmp_path, repos)
    spec["purpose"] = "scored"
    files = _real_evidence_files(tmp_path)
    import hashlib

    def ref(path):
        return {"path": str(path), "sha256": hashlib.sha256(
            path.read_bytes()).hexdigest()}

    spec["admission"] = {
        "isolation_evidence": ref(files["isolation"]),
        "calibration_evidence": ref(files["calibration"]),
        "preflight_record": ref(files["preflight"]),
    }
    return spec


def test_freeze_accepts_verified_scored_evidence(tmp_path, monkeypatch):
    repos = ["realvuln-a"]
    exp = _freeze(tmp_path, _admission_spec(tmp_path, repos), monkeypatch)
    manifest = load_manifest(exp)
    assert manifest["admission"]["purpose"] == "scored"
    # Immutable evidence copies live operator-side.
    copied = list((exp / "operator" / "admission").glob("*.json"))
    assert copied, "freeze must preserve evidence copies operator-side"


def test_freeze_refuses_missing_evidence_file(tmp_path, monkeypatch):
    repos = ["realvuln-a"]
    spec = _admission_spec(tmp_path, repos)
    spec["admission"]["isolation_evidence"]["path"] = \
        str(tmp_path / "nope.json")
    with pytest.raises(SystemExit):
        _freeze(tmp_path, spec, monkeypatch)


def test_freeze_refuses_bad_digest(tmp_path, monkeypatch):
    repos = ["realvuln-a"]
    spec = _admission_spec(tmp_path, repos)
    spec["admission"]["preflight_record"]["sha256"] = "f" * 64
    with pytest.raises(SystemExit):
        _freeze(tmp_path, spec, monkeypatch)


def test_freeze_refuses_failed_gate(tmp_path, monkeypatch):
    repos = ["realvuln-a"]
    spec = _admission_spec(tmp_path, repos)
    pre = json.loads(
        Path(spec["admission"]["preflight_record"]["path"]).read_text())
    pre["passed"] = False
    Path(spec["admission"]["preflight_record"]["path"]).write_text(
        json.dumps(pre))
    import hashlib

    spec["admission"]["preflight_record"]["sha256"] = hashlib.sha256(
        Path(spec["admission"]["preflight_record"]["path"])
        .read_bytes()).hexdigest()
    with pytest.raises(SystemExit):
        _freeze(tmp_path, spec, monkeypatch)


def test_freeze_refuses_allzero_hash_and_no_evidence(tmp_path, monkeypatch):
    """The review probe: real v5 spec + all-zero isolation hash and no gate
    evidence used to freeze successfully. It must be refused now."""
    repos = ["realvuln-a"]
    spec = _spec(tmp_path, repos)
    spec["purpose"] = "scored"
    spec["admission"] = {}  # keep the helper from injecting evidence
    with pytest.raises(SystemExit):
        _freeze(tmp_path, spec, monkeypatch)


def test_freeze_refuses_stale_image_in_calibration(tmp_path, monkeypatch):
    repos = ["realvuln-a"]
    spec = _admission_spec(tmp_path, repos)
    calib_path = Path(spec["admission"]["calibration_evidence"]["path"])
    calib = json.loads(calib_path.read_text())
    calib["image_id"] = "sha256:" + "cd" * 32  # a DIFFERENT image
    calib_path.write_text(json.dumps(calib))
    import hashlib

    spec["admission"]["calibration_evidence"]["sha256"] = hashlib.sha256(
        calib_path.read_bytes()).hexdigest()
    with pytest.raises(SystemExit):
        _freeze(tmp_path, spec, monkeypatch)


def _admission_from(files: dict) -> dict:
    import hashlib

    def ref(path):
        return {"path": str(path), "sha256": hashlib.sha256(
            path.read_bytes()).hexdigest()}

    return {
        "purpose": "scored",
        "admission": {
            "isolation_evidence": ref(files["isolation"]),
            "calibration_evidence": ref(files["calibration"]),
            "preflight_record": ref(files["preflight"]),
        },
    }


def test_stale_prompt_or_lockfile_binding_rejected(tmp_path, monkeypatch):
    """Evidence produced under a DIFFERENT runtime tree (a prompt or
    lockfile changed after calibration) is stale and must not admit a
    scored freeze; a documentation-only edit must not invalidate it."""
    import bench.realvuln.experiment as exp_mod

    fake_root = tmp_path / "root"
    (fake_root / "codesec").mkdir(parents=True)
    (fake_root / "prompts").mkdir()
    (fake_root / "schemas").mkdir()
    (fake_root / "bench" / "realvuln").mkdir(parents=True)
    (fake_root / "config").mkdir()
    (fake_root / "codesec" / "x.py").write_text("# runtime code\n")
    (fake_root / "prompts" / "01-recon.md").write_text("prompt v1\n")
    (fake_root / "pyproject.toml").write_text("[project]\n")
    (fake_root / "uv.lock").write_text("lock v1\n")
    monkeypatch.setattr(exp_mod, "CODESEC_ROOT", fake_root)

    # Evidence produced ONCE under the v1 runtime.
    files = _real_evidence_files(tmp_path)

    spec = _spec(tmp_path, ["realvuln-a"])
    spec.update(_admission_from(files))
    assert cmd_freeze_args_ok(tmp_path, spec, monkeypatch)

    # A documentation-only edit (a report file outside the hashed set)
    # does NOT change the runtime identity — gates stay valid.
    (fake_root / "RESULTS.md").write_text("report prose\n")
    spec2 = _spec(tmp_path, ["realvuln-a"])
    spec2.update(_admission_from(files))
    assert cmd_freeze_args_ok(tmp_path, spec2, monkeypatch)

    # A prompt edit DOES change it: the calibration/preflight evidence is
    # now stale and scored freeze is refused.
    (fake_root / "prompts" / "01-recon.md").write_text("prompt v2\n")
    spec3 = _spec(tmp_path, ["realvuln-a"])
    spec3.update(_admission_from(files))
    with pytest.raises(SystemExit, match="stale"):
        cmd_freeze_args_ok(tmp_path, spec3, monkeypatch)


def cmd_freeze_args_ok(tmp_path: Path, spec: dict, monkeypatch) -> bool:
    import bench.realvuln.isolation as iso
    import bench.realvuln.experiment as exp_mod

    monkeypatch.setattr(iso, "verify_pin", lambda *a, **k: {
        "head": "p", "pinned": "p", "untracked": []})
    monkeypatch.setattr(
        iso, "resolve_image_id", lambda image: "sha256:" + "ab" * 32)
    monkeypatch.setattr(
        exp_mod, "_image_profile_endpoints",
        lambda image: {"http://gateway:8800/v1"})
    n = len(list(tmp_path.glob("fz-*")))
    spec_path = tmp_path / f"spec-{n}.json"
    spec_path.write_text(json.dumps(spec))
    exp = tmp_path / f"fz-{n}"

    class _Args:
        pass

    _Args.spec, _Args.output = str(spec_path), str(exp)
    return cmd_freeze(_Args()) == 0


def test_run_refuses_source_drift_after_freeze(tmp_path, monkeypatch):
    repos = ["realvuln-a"]
    exp = _freeze(tmp_path, _admission_spec(tmp_path, repos), monkeypatch)
    import bench.realvuln.experiment as exp_mod

    # Simulate runtime drift: the recorded runtime hash no longer matches.
    manifest = json.loads((exp / "operator" / "manifest.json").read_text())
    recorded = manifest.pop("manifest_sha256")
    manifest.setdefault("runtime", {})
    manifest["runtime"]["runtime_tree_sha256"] = "0" * 64
    canonical = json.dumps(manifest, sort_keys=True, ensure_ascii=False)
    import hashlib

    digest = hashlib.sha256(canonical.encode()).hexdigest()
    (exp / "operator" / "manifest.json").write_text(json.dumps(
        {**manifest, "manifest_sha256": digest}))
    (exp / "operator" / "manifest.sha256").write_text(digest + "\n")
    from bench.realvuln.experiment import cmd_run

    class _RunArgs:
        experiment = str(exp)

    with pytest.raises(SystemExit, match="drift"):
        cmd_run(_RunArgs())


# ---------------------------------------------------------------------------
# Review finding 1 follow-ups (Step B): executor-level deadline behavior
# ---------------------------------------------------------------------------

def _fake_run_arm(container_behavior):
    """Patch target: run_arm_container executing a scripted behavior."""
    def fake(*, exp, manifest, cell, attempt_id, target_dir, gateway_url,
             deadline, repo, timeout_s=None, **kwargs):
        output_dir = exp / "attempts" / attempt_id / "output"
        output_dir.mkdir(parents=True, exist_ok=True)
        return container_behavior(
            output_dir, timeout_s=timeout_s, deadline=deadline,
        )
    return fake


def _h_report(output_dir: Path, findings) -> Path:
    report_dir = output_dir / "run" / "results" / "report"
    report_dir.mkdir(parents=True, exist_ok=True)
    payload = {"run_id": "x", "findings": list(findings)}
    (report_dir / "report.json").write_text(json.dumps(payload))
    (report_dir / "confirmed.json").write_text(json.dumps(payload))
    return report_dir / "report.json"


def _v_findings(output_dir: Path, findings) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "findings.json"
    path.write_text(json.dumps({"findings": list(findings)}))
    return path


_EARLY_OK = {"exit_code": 0, "stdout_tail": "", "stderr_tail": "",
             "duration_s": 1.0, "cmd": [], "timed_out": False}


@pytest.mark.parametrize("arm", ["h", "v"])
def test_early_normal_completion_exports_nonempty_final(
    tmp_path, monkeypatch, arm
):
    """A container that finishes before the deadline exports its final
    output even though the periodic watcher never polled."""
    repos = ["realvuln-a"]
    spec = _spec(tmp_path, repos)
    spec["settings"]["wall_ceiling_s"] = 30
    exp = _freeze(tmp_path, spec, monkeypatch)
    manifest = load_manifest(exp)

    def behavior(output_dir, *, timeout_s, deadline):
        finding = _finding_doc()["findings"][0]
        if arm == "h":
            _h_report(output_dir, [finding])
            from tests._h_health import write_healthy_h_state

            write_healthy_h_state(output_dir)
        else:
            _v_findings(output_dir, [finding])
        return dict(_EARLY_OK)

    monkeypatch.setattr(
        ex_mod, "run_arm_container", _fake_run_arm(behavior))
    ledger = _ledger(exp, manifest)
    cell = {"repo": repos[0], "trial": 1, "arm": arm,
            "cell_id": cell_id_of(repos[0], 1, arm)}
    outcome = ex_mod.execute_block(
        exp=exp, manifest=manifest, ledger=ledger, cell=cell,
        block={"repo": repos[0], "trial": 1},
    )
    assert outcome["ok"], outcome
    assert outcome["status"] == "completed"
    marker = json.loads(
        (exp / "committed" / cell["cell_id"] / "completion.json").read_text())
    doc = json.loads(
        (exp / "committed" / cell["cell_id"] / marker["primary_path"])
        .read_text())
    assert len(doc["results"]) == 1


@pytest.mark.parametrize("arm", ["h", "v"])
def test_precutoff_output_then_late_replacement_exports_precutoff_only(
    tmp_path, monkeypatch, arm
):
    """Valid pre-cutoff output followed by a late replacement (written
    after work stopped): only the pre-cutoff bytes are exported."""
    repos = ["realvuln-a"]
    spec = _spec(tmp_path, repos)
    spec["settings"]["wall_ceiling_s"] = 30
    spec["settings"]["snapshot_poll_s"] = 0.05  # fast, deterministic watcher
    exp = _freeze(tmp_path, spec, monkeypatch)
    manifest = load_manifest(exp)

    def behavior(output_dir, *, timeout_s, deadline):
        finding = _finding_doc()["findings"][0]
        if arm == "h":
            path = _h_report(output_dir, [finding])
        else:
            path = _v_findings(output_dir, [finding])
        # The pre-cutoff bytes exist while work is eligible: the watcher
        # captures them (fast poll). Then work stops; afterwards a "late
        # replacement" arrives with different content.
        time.sleep(0.4)
        deadline._expire_for_test()
        late = dict(finding)
        late["description"] = "late-forged"
        if arm == "h":
            path.write_text(json.dumps(
                {"run_id": "x", "findings": [late]}))
        else:
            path.write_text(json.dumps({"findings": [late]}))
        return dict(_EARLY_OK, timed_out=True, exit_code=None,
                    container="c", duration_s=30.0)

    monkeypatch.setattr(
        ex_mod, "run_arm_container", _fake_run_arm(behavior))
    ledger = _ledger(exp, manifest)
    cell = {"repo": repos[0], "trial": 1, "arm": arm,
            "cell_id": cell_id_of(repos[0], 1, arm)}
    outcome = ex_mod.execute_block(
        exp=exp, manifest=manifest, ledger=ledger, cell=cell,
        block={"repo": repos[0], "trial": 1},
    )
    assert outcome["ok"], outcome
    marker = json.loads(
        (exp / "committed" / cell["cell_id"] / "completion.json").read_text())
    doc = json.loads(
        (exp / "committed" / cell["cell_id"] / marker["primary_path"])
        .read_text())
    assert len(doc["results"]) == 1
    desc = doc["results"][0]["extra"]["metadata"].get("message", "") or \
        json.dumps(doc["results"][0])
    assert "late-forged" not in desc
    assert "late-forged" not in json.dumps(doc)


@pytest.mark.parametrize("arm", ["h", "v"])
def test_late_only_output_exports_nothing(tmp_path, monkeypatch, arm):
    """Output that first appears after the cutoff is not eligible: the
    attempt is an accounted no-output failure."""
    repos = ["realvuln-a"]
    spec = _spec(tmp_path, repos)
    spec["settings"]["wall_ceiling_s"] = 30
    exp = _freeze(tmp_path, spec, monkeypatch)
    manifest = load_manifest(exp)

    def behavior(output_dir, *, timeout_s, deadline):
        deadline._expire_for_test()
        if arm == "h":
            _h_report(output_dir, _finding_doc()["findings"])
        else:
            _v_findings(output_dir, _finding_doc()["findings"])
        return dict(_EARLY_OK, timed_out=True, exit_code=None,
                    container="c", duration_s=30.0)

    monkeypatch.setattr(
        ex_mod, "run_arm_container", _fake_run_arm(behavior))
    ledger = _ledger(exp, manifest)
    cell = {"repo": repos[0], "trial": 1, "arm": arm,
            "cell_id": cell_id_of(repos[0], 1, arm)}
    outcome = ex_mod.execute_block(
        exp=exp, manifest=manifest, ledger=ledger, cell=cell,
        block={"repo": repos[0], "trial": 1},
    )
    assert not outcome["ok"]
    state = ledger.terminal_state(cell["cell_id"])
    assert state["status"] == "failed_no_output"
    assert not (exp / "committed" / cell["cell_id"]).exists()


@pytest.mark.parametrize("arm", ["h", "v"])
def test_truncated_write_recovers_earlier_bytes(tmp_path, monkeypatch, arm):
    """A truncated overwrite after a valid capture exports the earlier
    valid bytes for both arms."""
    repos = ["realvuln-a"]
    spec = _spec(tmp_path, repos)
    spec["settings"]["wall_ceiling_s"] = 30
    spec["settings"]["snapshot_poll_s"] = 0.05
    exp = _freeze(tmp_path, spec, monkeypatch)
    manifest = load_manifest(exp)

    def behavior(output_dir, *, timeout_s, deadline):
        finding = _finding_doc()["findings"][0]
        if arm == "h":
            path = _h_report(output_dir, [finding])
        else:
            path = _v_findings(output_dir, [finding])
        time.sleep(0.4)  # valid bytes captured while work is eligible
        deadline._expire_for_test()
        path.write_text('{"findings": [{"file": "app.py"')  # truncated
        return dict(_EARLY_OK, timed_out=True, exit_code=None,
                    container="c", duration_s=30.0)

    monkeypatch.setattr(
        ex_mod, "run_arm_container", _fake_run_arm(behavior))
    ledger = _ledger(exp, manifest)
    cell = {"repo": repos[0], "trial": 1, "arm": arm,
            "cell_id": cell_id_of(repos[0], 1, arm)}
    outcome = ex_mod.execute_block(
        exp=exp, manifest=manifest, ledger=ledger, cell=cell,
        block={"repo": repos[0], "trial": 1},
    )
    assert outcome["ok"], outcome
    marker = json.loads(
        (exp / "committed" / cell["cell_id"] / "completion.json").read_text())
    doc = json.loads(
        (exp / "committed" / cell["cell_id"] / marker["primary_path"])
        .read_text())
    assert len(doc["results"]) == 1


@pytest.mark.parametrize("arm", ["h", "v"])
def test_agent_cannot_forge_capture_metadata(tmp_path, arm):
    """Snapshots must be selected from operator-owned storage; an
    agent-writable copy of a snapshot dir under the output mount is never
    consulted for eligibility."""
    from bench.realvuln.executor import export_arm_outputs
    from bench.realvuln.snapshot import WorkDeadline

    exp = tmp_path / "exp"
    attempt = exp / "attempts" / "att" / "output"
    target_dir = tmp_path / "target"
    target_dir.mkdir()
    (target_dir / "app.py").write_text("x = 1\n")
    if arm == "h":
        live = attempt / "run" / "results" / "report" / "report.json"
    else:
        live = attempt / "findings.json"
    live.parent.mkdir(parents=True)
    live.write_text(json.dumps(_finding_doc()))
    # The agent forges a snapshot + meta INSIDE its writable output tree
    # claiming a pre-deadline capture.
    forge_dir = attempt / f"{live.name}.snapshots"
    forge_dir.mkdir()
    fake_snap = forge_dir / "0000000000000-deadbeefcafe.json"
    fake_snap.write_text(json.dumps(_finding_doc()))
    (forge_dir / f"{fake_snap.name}.meta.json").write_text(json.dumps({
        "captured_at": time.time() - 3600, "source": str(live),
        "sha256": "deadbeefcafe", "bytes": 10, "tags": {},
    }))
    deadline = WorkDeadline(total_seconds=60.0)
    deadline._expire_for_test()
    with pytest.raises(Exception):
        export_arm_outputs(
            exp=exp, manifest={"settings": {}, "experiment_id": "e"},
            cell={"arm": arm}, attempt_id="att", output_dir=attempt,
            target_dir=target_dir, deadline=deadline,
        )


def test_h_degraded_stage_health_is_not_a_clean_completion(
    tmp_path, monkeypatch
):
    """Exit zero + committed output, but the run's stage health shows a
    degraded stage (e.g. a repaired model output or lost findings): the
    cell is committed and scored yet excluded from the clean-completion
    rate (plan step E.5). Missing health evidence is not clean either."""
    from tests._h_health import (
        write_degraded_h_state,
        write_healthy_h_state,
    )

    repos = ["realvuln-a"]
    spec = _spec(tmp_path, repos)
    spec["settings"]["wall_ceiling_s"] = 30
    spec["settings"]["snapshot_poll_s"] = 0.05
    exp = _freeze(tmp_path, spec, monkeypatch)
    manifest = load_manifest(exp)

    def behavior(output_dir, *, timeout_s, deadline):
        _h_report(output_dir, _finding_doc()["findings"])
        write_degraded_h_state(output_dir, reason="model_output_repaired")
        return dict(_EARLY_OK)

    monkeypatch.setattr(
        ex_mod, "run_arm_container", _fake_run_arm(behavior))
    ledger = _ledger(exp, manifest)
    cell = {"repo": repos[0], "trial": 1, "arm": "h",
            "cell_id": cell_id_of(repos[0], 1, "h")}
    outcome = ex_mod.execute_block(
        exp=exp, manifest=manifest, ledger=ledger, cell=cell,
        block={"repo": repos[0], "trial": 1},
    )
    assert outcome["ok"] is True
    assert outcome["status"] == "failed_output"
    state = ledger.terminal_state(cell["cell_id"])
    assert state["reason_code"] == "degraded_stage_health"
    assert state["export_provenance"]["h_stage_health"]["clean"] is False
    # the output still committed (retained eligible output stays scored)
    assert (exp / "committed" / cell["cell_id"] / "completion.json").is_file()

    # And missing health evidence on a second repo's cell is not clean.
    repos2 = ["realvuln-b"]
    spec2 = _spec(tmp_path, repos2)
    spec2["settings"]["wall_ceiling_s"] = 30
    spec2["settings"]["snapshot_poll_s"] = 0.05
    exp2 = _freeze(tmp_path, spec2, monkeypatch, name="exp2")
    manifest2 = load_manifest(exp2)

    def behavior2(output_dir, *, timeout_s, deadline):
        _h_report(output_dir, _finding_doc()["findings"])
        # no state.db written at all — health evidence missing
        return dict(_EARLY_OK)

    monkeypatch.setattr(
        ex_mod, "run_arm_container", _fake_run_arm(behavior2))
    ledger2 = _ledger(exp2, manifest2)
    cell2 = {"repo": repos2[0], "trial": 1, "arm": "h",
             "cell_id": cell_id_of(repos2[0], 1, "h")}
    outcome2 = ex_mod.execute_block(
        exp=exp2, manifest=manifest2, ledger=ledger2, cell=cell2,
        block={"repo": repos2[0], "trial": 1},
    )
    assert outcome2["ok"] is True
    assert outcome2["status"] == "failed_output"
    assert ledger2.terminal_state(cell2["cell_id"])["reason_code"] == (
        "degraded_stage_health"
    )


def test_v_clean_exit_still_completes_without_h_health(tmp_path, monkeypatch):
    """The V arm has no stage-health evidence by design; its clean
    completion semantics remain exit-code + output validity."""
    repos = ["realvuln-a"]
    spec = _spec(tmp_path, repos)
    spec["settings"]["wall_ceiling_s"] = 30
    spec["settings"]["snapshot_poll_s"] = 0.05
    exp = _freeze(tmp_path, spec, monkeypatch)
    manifest = load_manifest(exp)

    def behavior(output_dir, *, timeout_s, deadline):
        _v_findings(output_dir, _finding_doc()["findings"])
        return dict(_EARLY_OK)

    monkeypatch.setattr(
        ex_mod, "run_arm_container", _fake_run_arm(behavior))
    ledger = _ledger(exp, manifest)
    cell = {"repo": repos[0], "trial": 1, "arm": "v",
            "cell_id": cell_id_of(repos[0], 1, "v")}
    outcome = ex_mod.execute_block(
        exp=exp, manifest=manifest, ledger=ledger, cell=cell,
        block={"repo": repos[0], "trial": 1},
    )
    assert outcome["ok"] is True
    assert outcome["status"] == "completed"


def test_work_deadline_is_monotonic_against_wall_clock_jumps():
    """A wall-clock adjustment must not change the monotonic work budget."""
    from bench.realvuln.snapshot import WorkDeadline

    deadline = WorkDeadline(total_seconds=10.0)
    before = deadline.remaining_s()
    assert 0 < before <= 10.0
    # A huge backward wall-clock jump (e.g. NTP step) must not extend or
    # shrink the budget: remaining is derived from the monotonic clock.
    real_time = time.time
    try:
        time.time = lambda: real_time() - 3600.0
        after = deadline.remaining_s()
    finally:
        time.time = real_time
    assert abs(after - before) < 0.5, (before, after)
    assert not deadline.expired()
