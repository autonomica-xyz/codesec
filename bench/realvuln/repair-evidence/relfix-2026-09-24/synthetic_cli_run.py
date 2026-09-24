"""Step F.3: miniature synthetic experiment through the REAL CLI.

Executed as a subprocess from the evidence runner. The control plane
(freeze → run → verify → aggregate, resume) is the real CLI code; only the
container boundary is scripted (the arm behavior table below), matching
the offline synthetic test suite. Covers: clean success, early output +
late replacement, eligible recovery after truncation, no-output failure,
late invalidation, and committed-artifact corruption — with exit codes
for every command.
"""
from __future__ import annotations

import io
import json
import contextlib
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT))

from bench.realvuln import executor as ex_mod
from bench.realvuln import experiment as exp_mod
from bench.realvuln.aggregate import cmd_aggregate_experiment
from bench.realvuln.experiment import cell_id_of

REPOS = ["realvuln-alpha", "realvuln-beta"]
FINDING = {
    "finding_id": "f_1", "file": "app.py", "line_start": 1, "line_end": 1,
    "cwe": "CWE-89", "severity": "high", "description": "sqli",
    "evidence": "execute(q)",
}


def _finding_doc():
    return {"findings": [dict(FINDING)]}


def _write_h(output_dir: Path, findings) -> Path:
    report_dir = output_dir / "run" / "results" / "report"
    report_dir.mkdir(parents=True, exist_ok=True)
    payload = {"run_id": "x", "findings": list(findings)}
    (report_dir / "report.json").write_text(json.dumps(payload))
    (report_dir / "confirmed.json").write_text(json.dumps(payload))
    return report_dir / "report.json"


def _write_v(output_dir: Path, findings) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "findings.json"
    path.write_text(json.dumps({"findings": list(findings)}))
    return path


def _healthy(output_dir: Path):
    sys.path.insert(0, str(ROOT / "tests"))
    from _h_health import write_healthy_h_state

    write_healthy_h_state(output_dir)


def _gateway_record(exp: Path, attempt_id: str) -> None:
    from bench.realvuln.experiment import load_manifest

    exp_id = load_manifest(exp)["experiment_id"]
    recs = exp / "operator" / "gateway"
    recs.mkdir(parents=True, exist_ok=True)
    with (recs / "requests.jsonl").open("a") as fh:
        fh.write(json.dumps({
            "kind": "admission", "attempt_id": attempt_id,
            "experiment_id": exp_id}) + "\n")


OK = {"exit_code": 0, "stdout_tail": "", "stderr_tail": "",
      "duration_s": 1.0, "cmd": [], "timed_out": False}
TIMEOUT = {"exit_code": None, "timed_out": True, "container": "c1",
           "stdout_tail": "", "stderr_tail": "", "duration_s": 60.0,
           "cmd": []}


def arm_behavior(**kwargs):
    exp = kwargs["exp"]
    cell = kwargs["cell"]
    attempt_id = kwargs["attempt_id"]
    deadline = kwargs["deadline"]
    output_dir = exp / "attempts" / attempt_id / "output"
    output_dir.mkdir(parents=True, exist_ok=True)
    key = (cell["repo"], cell["arm"])
    if key == ("realvuln-alpha", "h"):        # clean success
        _write_h(output_dir, [FINDING])
        _healthy(output_dir)
        _gateway_record(exp, attempt_id)
        return dict(OK)
    if key == ("realvuln-alpha", "v"):        # valid output then LATE replacement
        path = _write_v(output_dir, [FINDING])
        time.sleep(ex_mod.SNAPSHOT_POLL_S + 0.5)  # eligible capture
        deadline._expire_for_test()
        late = dict(FINDING, description="late-forged")
        path.write_text(json.dumps({"findings": [late]}))
        _gateway_record(exp, attempt_id)
        return dict(TIMEOUT)
    if key == ("realvuln-beta", "h"):         # timeout; checkpoint recovery
        report_dir = output_dir / "run" / "results" / "report"
        report_dir.mkdir(parents=True, exist_ok=True)
        (report_dir / "report.checkpoint.json").write_text(json.dumps(
            {"run_id": "x", "findings": [FINDING]}))
        time.sleep(ex_mod.SNAPSHOT_POLL_S + 0.5)
        _gateway_record(exp, attempt_id)
        return dict(TIMEOUT)
    if key == ("realvuln-beta", "v"):         # inference, NO output ever
        _gateway_record(exp, attempt_id)
        return dict(TIMEOUT)
    raise AssertionError(f"unexpected cell {key}")


def run_cli(func, **kwargs):
    stdout = io.StringIO()
    args = type("_Args", (), kwargs)()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stdout):
        code = func(args)
    return {"exit": code, "out": stdout.getvalue().strip()[-600:]}


def main() -> int:
    tmp = Path(sys.argv[1])
    tmp.mkdir(parents=True, exist_ok=True)
    rv = tmp / "rv"
    for repo in REPOS:
        (rv / "repos" / repo).mkdir(parents=True, exist_ok=True)
        (rv / "repos" / repo / "app.py").write_text("x = 1\n" * 40)
        (rv / "ground-truth" / repo).mkdir(parents=True, exist_ok=True)
        (rv / "ground-truth" / repo / "ground-truth.json").write_text(json.dumps({
            "repo_id": repo, "commit_sha": "deadbeef",
            "findings": [{"id": f"{repo}-v", "is_vulnerable": True,
                          "primary_cwe": "CWE-89", "file": "app.py",
                          "acceptable_cwes": ["CWE-89"],
                          "location": {"start_line": 1, "end_line": 1}}],
        }))
    iso = tmp / "iso-evidence.json"
    iso.write_text(json.dumps({
        "ran_at": 1.0, "passed": True,
        "checks": [{"name": "host_home_absent", "passed": True}],
        "image_id": "sha256:" + "ab" * 32,
    }))
    import hashlib

    spec = {
        "protocol_version": 2, "purpose": "calibration",
        "repos": REPOS, "trials": [1], "seed": 7,
        "benchmark_pin": "0" * 40, "realvuln_root": str(rv),
        "settings": {
            "gateway_url": "http://gateway:8800/v1",
            "model": "glm-5.3", "temperature": 0.6,
            "max_output_tokens_per_request": 32768,
            "wall_ceiling_s": 60, "snapshot_poll_s": 0.05,
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
        "image": {"tag": "t", "image_id": "sha256:" + "ab" * 32},
        "admission": {"isolation_evidence": {
            "path": str(iso),
            "sha256": hashlib.sha256(iso.read_bytes()).hexdigest(),
        }},
    }
    spec_path = tmp / "spec.json"
    spec_path.write_text(json.dumps(spec))
    exp = tmp / "exp"

    # Freeze with the environment checks stubbed exactly like the offline
    # suite (no docker in this synthetic run); the CONTROL PLANE is real.
    import unittest.mock as mock
    import bench.realvuln.isolation as iso_mod

    results = {"freeze": None, "run": None, "verify": None,
               "aggregate": None, "mutations": {}}
    with mock.patch.object(iso_mod, "verify_pin",
                           return_value={"head": "p", "pinned": "p",
                                         "untracked": []}), \
         mock.patch.object(iso_mod, "resolve_image_id",
                           return_value="sha256:" + "ab" * 32), \
         mock.patch.object(exp_mod, "_image_profile_endpoints",
                           return_value={"http://gateway:8800/v1"}), \
         mock.patch.object(ex_mod, "run_arm_container", arm_behavior):
        results["freeze"] = run_cli(
            exp_mod.cmd_freeze, spec=str(spec_path), output=str(exp))
        results["run"] = run_cli(exp_mod.cmd_run, experiment=str(exp))
        results["verify"] = run_cli(exp_mod.cmd_verify, experiment=str(exp))
        results["aggregate"] = run_cli(
            cmd_aggregate_experiment, experiment=str(exp),
            json_out=str(tmp / "aggregate.json"))

        # Mutation 1: late invalidation after completed cells.
        import shutil
        c1 = tmp / "copy-invalidation"
        shutil.copytree(exp, c1)
        from bench.realvuln.ledger import AttemptLedger
        manifest = exp_mod.load_manifest(c1)
        ledger = AttemptLedger(
            c1 / "operator" / "attempts.jsonl",
            experiment_id=manifest["experiment_id"],
            config_hash=manifest["manifest_sha256"])
        ledger.append({
            "type": "attempt_end",
            "cell_id": manifest["expected_cells"][0]["cell_id"],
            "attempt_id": "probe-invalidation", "status": "invalidated",
            "made_inference_requests": False, "reason_code": "probe"})
        results["mutations"]["late_invalidation"] = {
            "verify": run_cli(exp_mod.cmd_verify, experiment=str(c1)),
            "aggregate": run_cli(cmd_aggregate_experiment, experiment=str(c1),
                                 json_out=str(tmp / "agg-inv.json")),
        }

        # Mutation 2: corrupt a committed artifact.
        c2 = tmp / "copy-corrupt"
        shutil.copytree(exp, c2)
        cell = exp_mod.load_manifest(c2)["expected_cells"][0]
        marker = json.loads(
            (c2 / "committed" / cell["cell_id"] / "completion.json").read_text())
        (c2 / "committed" / cell["cell_id"] / marker["primary_path"]) \
            .write_text("{")
        results["mutations"]["corrupt_committed"] = {
            "verify": run_cli(exp_mod.cmd_verify, experiment=str(c2)),
            "aggregate": run_cli(cmd_aggregate_experiment, experiment=str(c2),
                                 json_out=str(tmp / "agg-corrupt.json")),
        }

    print(json.dumps(results, indent=1)[:4000])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
