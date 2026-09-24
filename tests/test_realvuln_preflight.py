"""P09 preflight gate behavior: statuses are earned, not assumed."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from bench.realvuln.preflight import run_preflight


def test_offline_preflight_reports_not_run_for_live_gate():
    report = run_preflight({"repos": []}, offline=True)
    statuses = {g["name"]: g["status"] for g in report["gates"]}
    assert statuses["live_gateway_parity_probe"] == "not_run"
    # not_run is not success
    assert report["passed"] is False


def test_offline_preflight_gates_have_evidence():
    report = run_preflight({"repos": []}, offline=True)
    pytest_gates = [
        g for g in report["gates"] if g["name"].startswith("p0")
    ]
    assert len(pytest_gates) >= 14
    for gate in pytest_gates:
        assert gate["status"] in {"passed", "failed"}, gate
        assert gate["evidence"].startswith("pytest"), gate


def test_offline_preflight_passes_when_all_offline_gates_pass():
    report = run_preflight({"repos": []}, offline=True)
    offline_gates = [
        g for g in report["gates"] if g["name"] != "live_gateway_parity_probe"
    ]
    assert all(g["status"] == "passed" for g in offline_gates), json.dumps(
        [g for g in offline_gates if g["status"] != "passed"], indent=1
    )
