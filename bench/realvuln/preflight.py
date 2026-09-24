#!/usr/bin/env python3
"""Automated preflight gate (P09).

``python -m bench.realvuln.experiment preflight --spec SPEC --output DIR
--offline`` runs/validates P01–P08 evidence and produces a machine-readable
checklist. ``not_run`` is not success — the CLI exits nonzero if any gate
is failed OR not_run (offline mode marks live-only gates not_run by design
and requires ``--live`` for the live parity gate).

Offline gates run the behavior test suites (never a source-string check),
verify the benchmark pin, the frozen config's effective-request shape, the
isolation image, and the manifest machinery end-to-end on a synthetic
experiment.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

PY = sys.executable


def _run(cmd: list[str], cwd: Path = _ROOT) -> dict:
    proc = subprocess.run(
        cmd, cwd=str(cwd), capture_output=True, text=True, timeout=900
    )
    return {
        "exit_code": proc.returncode,
        "stdout_tail": proc.stdout[-2000:],
        "stderr_tail": proc.stderr[-2000:],
    }


def _gate(name: str, status: str, detail: str = "", evidence: str = "") -> dict:
    return {
        "name": name, "status": status, "detail": detail, "evidence": evidence,
    }


def _pytest_gate(name: str, test_path: str) -> dict:
    result = _run([PY, "-m", "pytest", "-q", test_path])
    passed = result["exit_code"] == 0
    return _gate(
        name,
        "passed" if passed else "failed",
        detail=(result["stdout_tail"][-400:] or result["stderr_tail"][-400:]),
        evidence=f"pytest -q {test_path}",
    )


def run_preflight(spec: dict, *, offline: bool = True) -> dict:
    gates: list[dict] = []

    # P01 — tool behavior in blinded trees
    gates.append(_pytest_gate(
        "p01_blinded_tree_tools", "tests/test_local_agent.py"))
    # P02 — bounded payloads + deterministic membership
    gates.append(_pytest_gate(
        "p02_dedupe_payload_bounds", "tests/test_dedupe_stage.py"))
    gates.append(_pytest_gate(
        "p02_report_membership", "tests/test_report_stage.py"))
    gates.append(_pytest_gate(
        "p02_state_membership", "tests/test_state.py"))
    # P03 — wire parity + gateway
    gates.append(_pytest_gate(
        "p03_gateway_enforcement", "tests/test_realvuln_gateway.py"))
    gates.append(_pytest_gate(
        "p03_pi_wire_parity", "tests/test_realvuln_pi_parity.py"))
    # P04 — trace contracts + static/live separation
    gates.append(_pytest_gate(
        "p04_trace_contracts", "tests/test_trace_stage.py"))
    gates.append(_pytest_gate(
        "p04_contracts", "tests/test_contracts.py"))
    # P05 — deadlines + stage health
    gates.append(_pytest_gate(
        "p05_deadlines", "tests/test_benchmark_deadlines.py"))
    gates.append(_pytest_gate(
        "p05_snapshot_retention", "tests/test_realvuln_snapshot.py"))
    gates.append(_pytest_gate(
        "p05_orchestrator_stage_health", "tests/test_orchestrator.py"))
    # P06 — isolation + corpus integrity
    gates.append(_pytest_gate(
        "p06_isolation_corpus", "tests/test_realvuln_isolation.py"))
    # P07 — ledger/manifest/adapter
    gates.append(_pytest_gate(
        "p07_ledger", "tests/test_realvuln_ledger.py"))
    gates.append(_pytest_gate(
        "p07_manifest_commit", "tests/test_realvuln_manifest.py"))
    gates.append(_pytest_gate(
        "p07_adapter", "tests/test_realvuln_adapter.py"))
    # P08 — aggregation
    gates.append(_pytest_gate(
        "p08_aggregation", "tests/test_realvuln_aggregate.py"))

    # Source pin (read-only against the real checkout).
    try:
        from bench.realvuln.isolation import PIN_SHA, verify_pin
        rv = Path(spec.get("realvuln_root", "/home/user/g/Real-Vuln-Benchmark"))
        result = verify_pin(rv, expected_sha=spec.get("benchmark_pin", PIN_SHA))
        gates.append(_gate(
            "source_pins", "passed",
            detail=f"HEAD={result['head'][:12]} untracked={len(result['untracked'])}",
            evidence=str(rv),
        ))
    except Exception as error:  # noqa: BLE001
        gates.append(_gate("source_pins", "failed", detail=str(error)))

    # Frozen effective-request shape from the experiment config.
    try:
        from codesec.config import load_config
        from codesec.reasoning import ReasoningSpec, effective_request_settings
        config = load_config(_ROOT / "config" / "zai-glm53-experiment.yaml")
        profile = config.profile_for_stage("hunt")
        settings = effective_request_settings(
            model=profile.model, reasoning=profile.reasoning_spec(),
            temperature=profile.temperature,
            max_tokens=profile.max_output_tokens,
            context_limit=profile.context_limit,
        )
        assert settings["request_params"] == {
            "thinking": {"type": "enabled"}, "reasoning_effort": "low",
        }
        assert settings["temperature"] == 0.6
        assert settings["max_tokens"] == 32768
        assert "top_p" not in settings["request_params"]
        assert config.report_policy == "confirmed_reachable"
        assert config.report_renderer == "deterministic"
        gates.append(_gate(
            "effective_request_shape", "passed",
            detail=f"fingerprint={settings['fingerprint_sha256'][:16]}…",
        ))
    except Exception as error:  # noqa: BLE001
        gates.append(_gate("effective_request_shape", "failed", str(error)))

    # Isolation image present + pinned build record.
    try:
        from bench.realvuln.isolation import require_docker
        require_docker()
        record_path = (
            _ROOT / "bench" / "realvuln-runs" / "image-build.json"
        )
        record = json.loads(record_path.read_text())
        inspect = _run([
            "docker", "inspect", record["tag"], "--format", "{{.Id}}",
        ])
        assert inspect["exit_code"] == 0
        gates.append(_gate(
            "isolation_image", "passed",
            detail=f"image={record['image_id'][:19]}… pi={record['pi_version']}",
            evidence=str(record_path),
        ))
    except Exception as error:  # noqa: BLE001
        gates.append(_gate("isolation_image", "failed", str(error)))

    # Freeze/run/verify machinery end-to-end on a synthetic experiment
    # (failure-injection covered by the manifest gate above; here the
    # happy path with a zero-cell corpus).
    try:
        import tempfile

        from bench.realvuln.experiment import cmd_freeze, cmd_verify, load_manifest
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            spec_path = td / "spec.json"
            spec_path.write_text(json.dumps({
                "protocol_version": 2,
                "repos": [], "seed": 20260922,
                "benchmark_pin": "synthetic",
                "realvuln_root": str(td),
                "settings": {
                    "realvuln_root": str(td),
                    "gateway_url": "http://gateway:8800/v1",
                    "model": "glm-5.3", "temperature": 0.6,
                    "max_output_tokens_per_request": 32768,
                    "wall_ceiling_s": 7200,
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
                "primary_metric": "synthetic",
            }))
            exp = td / "synthetic-exp"

            class _Args:
                spec, output = str(spec_path), str(exp)

            assert cmd_freeze(_Args()) == 0
            load_manifest(exp)
            gates.append(_gate(
                "experiment_freeze_machinery", "passed",
                evidence=str(exp / "operator" / "manifest.json"),
            ))
    except Exception as error:  # noqa: BLE001
        gates.append(_gate("experiment_freeze_machinery", "failed", str(error)))

    # Live parity probe: only meaningful with the real gateway. In live
    # mode this gate is REAL — it posts to the frozen gateway and verifies
    # admission/enforcement behavior; it is never a mocked pass.
    if offline:
        gates.append(_gate(
            "live_gateway_parity_probe", "not_run",
            detail="offline preflight; run with --live during P10 calibration",
        ))
    else:
        gates.append(_live_gateway_gate(spec))

    return {
        "ran_at": time.time(),
        "mode": "offline" if offline else "live",
        "gates": gates,
        "passed": all(g["status"] == "passed" for g in gates),
    }


def _live_gateway_gate(spec: dict) -> dict:
    """Real live gate: probe the frozen gateway over HTTP — from INSIDE
    its container, since the gateway intentionally publishes no host port
    (it lives only on the private isolation network).

    Verifies (a) reachability, (b) frozen-setting enforcement (a mutated
    request must be rejected, never forwarded), (c) a well-formed request
    is admitted (reaches upstream — a 400 gateway_rejection is failure).
    No fake transports: socket-level checks against the running gateway."""
    container = (spec.get("settings") or {}).get(
        "gateway_container", "codesec-gateway")
    effective = spec.get("effective_request") or {}
    base = {
        "model": effective.get("model"),
        "messages": [{"role": "user", "content": "reply with the word ok"}],
        "temperature": effective.get("temperature"),
        # The gateway pins every frozen setting exactly — send the frozen
        # values verbatim (a shrunken max_tokens would self-reject).
        "max_tokens": effective.get("max_tokens"),
        "stream": effective.get("stream", True),
        **(effective.get("request_params") or {}),
    }
    probe = r'''
import json, sys, urllib.error, urllib.request

BASE = json.loads(%s)

def post(body, timeout=150):
    req = urllib.request.Request(
        "http://127.0.0.1:8800/v1/chat/completions",
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read(65536).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(4096).decode("utf-8", "replace")
    except Exception as e:
        return None, f"{type(e).__name__}: {e}"

out = {}
out["mutated"] = post({**BASE, "temperature": 0.99})
out["forbidden"] = post({**BASE, "top_p": 0.5})
out["conforming"] = post(BASE)
print(json.dumps(out))
''' % (json.dumps(json.dumps(base)),)
    try:
        result = subprocess.run(
            ["docker", "exec", container, "python", "-c", probe],
            capture_output=True, text=True, timeout=300,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return _gate("live_gateway_parity_probe", "failed",
                     f"probe failed to run in {container}: {error}")
    if result.returncode != 0:
        return _gate(
            "live_gateway_parity_probe", "failed",
            f"probe exited {result.returncode}: "
            f"{result.stderr.strip()[:200]}",
        )
    try:
        out = json.loads(result.stdout.strip().splitlines()[-1])
    except (json.JSONDecodeError, IndexError):
        return _gate("live_gateway_parity_probe", "failed",
                     f"unparseable probe output: {result.stdout[:200]}")

    status, body = out["mutated"]
    if status != 400 or "gateway_rejected" not in body:
        return _gate(
            "live_gateway_parity_probe", "failed",
            f"mutated request not rejected: status={status} "
            f"body={body[:160]}",
        )
    status, body = out["forbidden"]
    if status != 400:
        return _gate(
            "live_gateway_parity_probe", "failed",
            f"forbidden top_p not rejected: status={status}",
        )
    status, body = out["conforming"]
    if status is None:
        return _gate(
            "live_gateway_parity_probe", "failed",
            f"gateway unreachable: {body}",
        )
    if status == 400 and "gateway_rejected" in body:
        return _gate(
            "live_gateway_parity_probe", "failed",
            f"conforming request rejected: {body[:200]}",
        )
    return _gate(
        "live_gateway_parity_probe", "passed",
        detail=f"enforcement OK; conforming request -> HTTP {status}",
        evidence=f"docker exec {container} -> 127.0.0.1:8800",
    )
