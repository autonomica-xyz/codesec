"""WS1 exit gate: miniature synthetic experiment through the real
freeze → run → verify → aggregate machinery, covering success, no output,
checkpoint-only recovery, malformed output, timeout, crash recovery and
claim/refusal semantics — all without docker (arms are stubbed, the
control plane is real)."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from bench.realvuln import executor as ex_mod
from bench.realvuln.aggregate import aggregate_experiment
from bench.realvuln.experiment import (
    cell_id_of,
    cmd_freeze,
    cmd_run,
    cmd_verify,
    load_manifest,
)
from bench.realvuln.ledger import AttemptLedger


def _mini_realvuln(tmp_path: Path, repos) -> Path:
    rv = tmp_path / "rv"
    for repo in repos:
        (rv / "repos" / repo).mkdir(parents=True, exist_ok=True)
        (rv / "repos" / repo / "app.py").write_text("x = 1\n" * 80)
        (rv / "ground-truth" / repo).mkdir(parents=True)
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


def _spec(tmp_path: Path, repos) -> dict:
    return {
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


def _freeze(tmp_path: Path, spec: dict, monkeypatch) -> Path:
    import bench.realvuln.isolation as iso

    monkeypatch.setattr(iso, "verify_pin", lambda *a, **k: {
        "head": "p", "pinned": "p", "untracked": []})
    monkeypatch.setattr(
        iso, "resolve_image_id", lambda image: "sha256:" + "ab" * 32)
    import bench.realvuln.experiment as exp_mod

    monkeypatch.setattr(
        exp_mod, "_image_profile_endpoints",
        lambda image: {"http://gateway:8800/v1"})
    spec_path = tmp_path / "spec.json"
    spec_path.write_text(json.dumps(spec))
    exp = tmp_path / "exp"

    class _Args:
        pass

    _Args.spec, _Args.output = str(spec_path), str(exp)
    assert cmd_freeze(_Args()) == 0
    return exp


def _gateway_record(exp: Path, attempt_id: str) -> None:
    exp_id = load_manifest(exp)["experiment_id"]
    recs = exp / "operator" / "gateway"
    recs.mkdir(parents=True, exist_ok=True)
    with (recs / "requests.jsonl").open("a") as fh:
        fh.write(json.dumps({
            "kind": "admission", "attempt_id": attempt_id,
            "experiment_id": exp_id,
        }) + "\n")
        fh.write(json.dumps({
            "kind": "terminal", "attempt_id": attempt_id,
            "experiment_id": exp_id,
            "status": "forwarded", "stream_complete": True,
            "usage": {"prompt_tokens": 10, "completion_tokens": 4},
        }) + "\n")


def _write_h_report(output_dir: Path, findings) -> None:
    report_dir = output_dir / "run" / "results" / "report"
    report_dir.mkdir(parents=True)
    payload = {"run_id": "x", "findings": findings}
    (report_dir / "report.json").write_text(json.dumps(payload))
    (report_dir / "confirmed.json").write_text(json.dumps(payload))


def _finding() -> dict:
    return {
        "finding_id": "f_1", "file": "app.py", "line_start": 1,
        "line_end": 1, "cwe": "CWE-89", "severity": "high",
        "description": "sqli", "evidence": "execute(q)",
    }


def test_miniature_experiment_end_to_end(tmp_path, monkeypatch):
    """One pass through freeze/run/verify/aggregate where every failure
    class appears exactly once."""
    repos = ["realvuln-a", "realvuln-b", "realvuln-c"]
    spec = _spec(tmp_path, repos)
    exp = _freeze(tmp_path, spec, monkeypatch)
    manifest = load_manifest(exp)

    def fake_arm(**kwargs):
        cell = kwargs["cell"]
        exp_dir = kwargs["exp"]
        attempt_id = kwargs["attempt_id"]
        out = exp_dir / "attempts" / attempt_id / "output"
        out.mkdir(parents=True, exist_ok=True)
        _gateway_record(exp_dir, attempt_id)
        key = (cell["repo"], cell["arm"])
        if key == ("realvuln-a", "h"):      # clean success
            _write_h_report(out, [_finding()])
            return {"exit_code": 0, "stdout_tail": "", "stderr_tail": "",
                    "duration_s": 5.0, "cmd": []}
        if key == ("realvuln-a", "v"):      # timeout; valid file then
            findings = out / "findings.json"  # truncated final write
            findings.write_text(json.dumps({"findings": [_finding()]}))
            time.sleep(ex_mod.SNAPSHOT_POLL_S + 1.0)
            findings.write_text('{"findings": [{"file": "app.py"')
            return {"exit_code": None, "timed_out": True, "container": "c",
                    "stdout_tail": "", "stderr_tail": "", "duration_s": 60.0,
                    "cmd": []}
        if key == ("realvuln-b", "h"):      # timeout; checkpoint only
            report_dir = out / "run" / "results" / "report"
            report_dir.mkdir(parents=True)
            (report_dir / "report.checkpoint.json").write_text(
                json.dumps({"run_id": "x", "findings": [_finding()]}))
            return {"exit_code": None, "timed_out": True, "container": "c",
                    "stdout_tail": "", "stderr_tail": "", "duration_s": 60.0,
                    "cmd": []}
        if key == ("realvuln-b", "v"):      # inference happened, no output
            return {"exit_code": None, "timed_out": True, "container": "c",
                    "stdout_tail": "", "stderr_tail": "", "duration_s": 60.0,
                    "cmd": []}
        if key == ("realvuln-c", "h"):      # malformed output file
            report_dir = out / "run" / "results" / "report"
            report_dir.mkdir(parents=True)
            (report_dir / "report.json").write_text('{"findings": [')
            return {"exit_code": 0, "stdout_tail": "", "stderr_tail": "",
                    "duration_s": 5.0, "cmd": []}
        # realvuln-c v: clean success
        (out / "findings.json").write_text(
            json.dumps({"findings": [_finding()]}))
        return {"exit_code": 0, "stdout_tail": "", "stderr_tail": "",
                "duration_s": 5.0, "cmd": []}

    monkeypatch.setattr(ex_mod, "run_arm_container", fake_arm)

    class _RunArgs:
        experiment = str(exp)

    rc = cmd_run(_RunArgs())
    # b/v (failed_no_output) and c/h (malformed) are terminal failures.
    assert rc == 1

    # Crash-recovery: append an open attempt for the failed v cell, then
    # re-run — the reconcile path closes it as inference-bearing terminal.
    ledger = AttemptLedger(
        exp / "operator" / "attempts.jsonl",
        experiment_id=manifest["experiment_id"],
        config_hash=manifest["manifest_sha256"],
    )
    crashed_cell = cell_id_of("realvuln-b", 1, "v")
    ledger.append({"type": "attempt_start", "cell_id": crashed_cell,
                   "attempt_id": "att-ghost"})
    _gateway_record(exp, "att-ghost")
    rc2 = cmd_run(_RunArgs())
    assert rc2 == 1
    attempts = ledger.attempts(crashed_cell)
    ghost = [a for a in attempts if a["attempt_id"] == "att-ghost"]
    assert ghost and ghost[0]["reason_code"] == "controller_interrupted"
    assert ghost[0]["status"] == "failed_no_output"

    class _VerifyArgs:
        experiment = str(exp)

    assert cmd_verify(_VerifyArgs()) == 0

    report = aggregate_experiment(
        exp, scorer=__import__(
            "bench.realvuln.aggregate", fromlist=["x"]
        )._fake_scorer_factory(),
    )
    assert report["problems"] == [], report["problems"]
    statuses = report["terminal_status_counts"]
    assert statuses.get("completed") == 2          # a/h, c/v
    assert statuses.get("failed_output") == 2      # a/v recovered, b/h ckpt
    assert statuses.get("failed_no_output") == 2   # b/v, c/h
    cells = report["cells"]
    assert cells["realvuln-a#t1#v"]["degraded"] == "failed_output"
    assert cells["realvuln-b#t1#v"]["output_failure"] is True
    assert cells["realvuln-c#t1#h"]["output_failure"] is True
    # Scoring: a/h TP; b/h checkpoint TP; c/h empty → FN; c/v TP; a/v TP;
    # b/v empty → FN. Per-trial H: tp=2 fn=1; V: tp=2 fn=1.
    assert report["per_trial"][1]["h"]["tp"] == 2
    assert report["per_trial"][1]["h"]["fn"] == 1
    assert report["per_trial"][1]["v"]["tp"] == 2
    assert report["headline"] is not None
    assert report["clean_completion_rate"] == round(2 / 6, 4)
    assert report["usage"]["records_found"] >= 6


def test_invalidated_cell_blocks_claim_and_flags_aggregation(
    tmp_path, monkeypatch
):
    """A protocol-breach invalidation is terminal AND surfaced."""
    repos = ["realvuln-a"]
    spec = _spec(tmp_path, repos)
    exp = _freeze(tmp_path, spec, monkeypatch)
    manifest = load_manifest(exp)
    ledger = AttemptLedger(
        exp / "operator" / "attempts.jsonl",
        experiment_id=manifest["experiment_id"],
        config_hash=manifest["manifest_sha256"],
    )
    cell_id = cell_id_of("realvuln-a", 1, "h")
    ledger.append({"type": "attempt_start", "cell_id": cell_id,
                   "attempt_id": "att-bad"})
    ledger.append({"type": "attempt_end", "cell_id": cell_id,
                   "attempt_id": "att-bad", "status": "invalidated",
                   "reason_code": "config_mismatch",
                   "made_inference_requests": True})
    with pytest.raises(Exception):
        ledger.claim_cell(cell_id, "att-new")
    report = aggregate_experiment(
        exp, scorer=__import__(
            "bench.realvuln.aggregate", fromlist=["x"]
        )._fake_scorer_factory(),
    )
    assert report["headline"] is None
    assert any("invalidated" in p for p in report["problems"])
