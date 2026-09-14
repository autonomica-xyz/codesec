from __future__ import annotations

from pathlib import Path

from codesec.config import HarnessConfig, StageConfig
from codesec.runner import AgentRunError
from codesec.state import StateDB
from codesec.stages import trace as trace_stage
from codesec.stages._common import StageContext


def _trace_context(repo: Path) -> StageContext:
    config = HarnessConfig(
        stages={
            "trace": StageConfig(
                name="trace",
                model="reviewer",
                concurrency=1,
                tools=["Read"],
                max_turns=2,
                permission_mode="acceptEdits",
                repair_attempts=0,
            )
        }
    )
    return StageContext(run_id="run", repo_path=repo, config=config)


async def test_trace_agent_failure_is_uncertain_not_unreachable(
    tmp_path: Path, monkeypatch
) -> None:
    db = StateDB(tmp_path / "state.db")
    db.create_run(str(tmp_path), "run")
    db.add_task(
        "run",
        {
            "task_id": "t_1",
            "attack_class": "sqli",
            "scope_hint": "inspect the query construction",
            "target_files": ["app.py"],
            "rationale": "untrusted input reaches a database query",
            "priority": 1,
            "source": "recon",
        },
    )
    db.add_finding(
        "run",
        "t_1",
        {
            "finding_id": "f_1",
            "file": "app.py",
            "line_start": 1,
            "line_end": 1,
            "vuln_class": "sqli",
            "severity": "high",
            "description": "untrusted input reaches a database query",
            "evidence_snippet": "execute(query)",
            "confidence": 0.9,
        },
    )
    db.set_finding_validation(
        "run",
        "f_1",
        "confirmed",
        {"finding_id": "f_1", "verdict": "confirmed"},
    )
    db.add_dedupe_group(
        "run",
        {
            "group_id": "g_1",
            "root_cause": "untrusted input reaches a database query",
            "canonical_finding_id": "f_1",
            "member_finding_ids": ["f_1"],
        },
    )
    db.assign_finding_group("run", "f_1", "g_1", True)

    async def fail_agent(**kwargs):
        raise AgentRunError("truncated output")

    monkeypatch.setattr(trace_stage, "run_agent", fail_agent)

    reachable = await trace_stage.run_trace(_trace_context(tmp_path), db)
    trace = db.get_trace("run", "f_1")

    assert reachable == 0
    assert trace["status"] == "uncertain"
    assert trace["reachable"] is None
    assert db.get_reachable_canonical_findings("run") == []


# --- W6 canary markers --------------------------------------------------------

from codesec.runner import AgentResult


def _seeded_trace_db(tmp_path: Path) -> StateDB:
    """One confirmed canonical finding in file app.py lines 5..10."""
    (tmp_path / "app.py").write_text("x = 1\n" * 40)
    db = StateDB(tmp_path / "state.db")
    db.create_run(str(tmp_path), "run")
    db.add_task(
        "run",
        {
            "task_id": "t_1",
            "attack_class": "ssti",
            "scope_hint": "inspect the preview renderer",
            "target_files": ["app.py"],
            "rationale": "untrusted input reaches a template render",
            "priority": 1,
            "source": "recon",
        },
    )
    db.add_finding(
        "run",
        "t_1",
        {
            "finding_id": "f_1",
            "file": "app.py",
            "line_start": 5,
            "line_end": 10,
            "vuln_class": "ssti",
            "severity": "high",
            "description": "untrusted input reaches a template render",
            "evidence_snippet": "render_template_string(body)",
            "confidence": 0.9,
        },
    )
    db.set_finding_validation(
        "run", "f_1", "confirmed", {"finding_id": "f_1", "verdict": "confirmed"}
    )
    db.add_dedupe_group(
        "run",
        {
            "group_id": "g_1",
            "root_cause": "untrusted input reaches a template render",
            "canonical_finding_id": "f_1",
            "member_finding_ids": ["f_1"],
        },
    )
    db.assign_finding_group("run", "f_1", "g_1", True)
    return db


def _reachable_payload(**over):
    p = {
        "finding_id": "f_1",
        "status": "reachable",
        "reachable": True,
        "confidence": 0.6,
        "rationale": "attacker-controlled body reaches the sink via /preview",
        "entry_points": [{"kind": "http_route", "location": "app.py:preview"}],
        "call_chain": [
            {"file": "app.py", "function": "preview", "line": 2},
            {"file": "app.py", "function": "render", "line": 7},
        ],
        "external_inputs": ["body"],
    }
    p.update(over)
    return p


def _ctx_with_live(repo: Path) -> StageContext:
    ctx = _trace_context(repo)
    ctx.live_target = {"url": "http://127.0.0.1:5199", "credentials": {}}
    return ctx


def _agent_returning(payload, captured):
    async def fake_agent(**kwargs):
        captured.update(kwargs)
        return AgentResult(
            payload=payload,
            cost_usd=0,
            input_tokens=1,
            output_tokens=1,
            cache_read_tokens=0,
            cache_creation_tokens=0,
            num_turns=1,
            duration_ms=1,
            session_id=None,
            artifact_path=kwargs["artifact_dir"] / f"{kwargs['artifact_name']}.jsonl",
            repair_used=False,
        )

    return fake_agent


async def test_trace_mints_markers_only_when_live_target(tmp_path, monkeypatch):
    captured = {}
    unreachable = _reachable_payload(
        status="unreachable", reachable=False, entry_points=[],
        call_chain=[], external_inputs=[],
        blockers=[{"kind": "sanitizer", "location": "app.py:3",
                   "description": "escapes input"}],
    )
    monkeypatch.setattr(
        trace_stage, "run_agent", _agent_returning(unreachable, captured)
    )

    # No live target -> no markers key in the trace input.
    repo1 = tmp_path / "repo1"
    repo1.mkdir()
    db1 = _seeded_trace_db(repo1)
    await trace_stage.run_trace(_trace_context(repo1), db1)
    assert "markers" not in captured["user_input"]

    # Live target -> deterministic markers + live_target in the input.
    captured.clear()
    repo2 = tmp_path / "repo2"
    repo2.mkdir()
    db2 = _seeded_trace_db(repo2)
    await trace_stage.run_trace(_ctx_with_live(repo2), db2)
    markers = captured["user_input"]["markers"]
    assert markers["finding_id"] == "f_1"
    assert "ssti" in markers["markers"] and "generic" in markers["markers"]
    assert captured["user_input"]["live_target"]["url"] == "http://127.0.0.1:5199"


async def test_trace_reachable_requires_verified_marker_in_live_mode(
    tmp_path, monkeypatch
):
    repo = tmp_path / "repo"
    repo.mkdir()
    db = _seeded_trace_db(repo)
    # reachable verdict but no verified marker -> contract violation -> uncertain
    monkeypatch.setattr(
        trace_stage, "run_agent", _agent_returning(_reachable_payload(), {})
    )

    reachable = await trace_stage.run_trace(_ctx_with_live(repo), db)

    assert reachable == 0
    trace = db.get_trace("run", "f_1")
    assert trace["status"] == "uncertain"
    assert trace["reachable"] is None
    assert "canary marker" in trace["rationale"]


async def test_trace_verified_marker_keeps_reachable_and_floors_confidence(
    tmp_path, monkeypatch
):
    repo = tmp_path / "repo"
    repo.mkdir()
    db = _seeded_trace_db(repo)
    payload = _reachable_payload(
        confidence=0.6,
        marker={"kind": "ssti", "token": "70*95", "verified": True,
                "where": "response body"},
    )
    monkeypatch.setattr(trace_stage, "run_agent", _agent_returning(payload, {}))

    reachable = await trace_stage.run_trace(_ctx_with_live(repo), db)

    assert reachable == 1
    trace = db.get_trace("run", "f_1")
    assert trace["status"] == "reachable"
    assert trace["confidence"] >= 0.9


async def test_trace_marker_contract_violation_counts_uncertain_only(
    tmp_path, monkeypatch, caplog
):
    """A contract-violating trace is recorded as uncertain — it must not
    also increment the failed counter."""
    import logging

    repo = tmp_path / "repo"
    repo.mkdir()
    db = _seeded_trace_db(repo)
    monkeypatch.setattr(
        trace_stage, "run_agent", _agent_returning(_reachable_payload(), {})
    )

    with caplog.at_level(logging.INFO, logger="codesec.stages.trace"):
        await trace_stage.run_trace(_ctx_with_live(repo), db)

    summary = next(
        r.getMessage() for r in caplog.records
        if "reachable=" in r.getMessage()
    )
    assert "uncertain=1" in summary
    assert "failed=0" in summary
