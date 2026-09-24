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

    # No live target -> static mode: markers present-and-null (P04) and
    # live_target null so no template example can be mistaken for a target.
    repo1 = tmp_path / "repo1"
    repo1.mkdir()
    db1 = _seeded_trace_db(repo1)
    await trace_stage.run_trace(_trace_context(repo1), db1)
    assert captured["user_input"]["evidence_mode"] == "static"
    assert captured["user_input"]["markers"] is None
    assert captured["user_input"]["live_target"] is None

    # Live target -> deterministic markers + live_target in the input.
    captured.clear()
    repo2 = tmp_path / "repo2"
    repo2.mkdir()
    db2 = _seeded_trace_db(repo2)
    await trace_stage.run_trace(_ctx_with_live(repo2), db2)
    assert captured["user_input"]["evidence_mode"] == "live"
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


# --- P04: trace contract fixtures --------------------------------------------
import pytest


def _agent_returning_dispatch(payloads, captured_inputs=None, calls_holder=None):
    """Fake run_agent yielding one payload per call (initial + repairs)."""
    async def fake_agent(**kwargs):
        if captured_inputs is not None:
            captured_inputs.append(kwargs["user_input"])
        if calls_holder is not None:
            calls_holder["n"] += 1
        payload = next(payloads)
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

from codesec.contracts import StageContractError, validate_trace_output


def _expect_contract_error(payload, repo, sink=("app.py", 5, 10), fid="f_1"):
    with pytest.raises(StageContractError) as excinfo:
        validate_trace_output(
            fid, payload, repo,
            expected_sink_file=sink[0],
            expected_sink_range=(sink[1], sink[2]),
        )
    return str(excinfo.value)


def test_p04_valid_multiframe_entry_to_sink_chain(tmp_path):
    (tmp_path / "app.py").write_text("line\n" * 40)
    payload = {
        "finding_id": "f_1",
        "status": "reachable", "reachable": True, "confidence": 0.8,
        "entry_points": [{"kind": "http_route", "location": "app.py:3",
                          "auth_required": False,
                          "controllable_by": "anonymous_user"}],
        "call_chain": [
            {"file": "app.py", "function": "route", "line": 3},
            {"file": "app.py", "function": "handler", "line": 8},
            {"file": "app.py", "function": "sink", "line": 7},
        ],
        "external_inputs": ["q"],
        "rationale": "External input flows from the route to the sink.",
        "boundary_frames": [
            {"boundary": "flask.routing",
             "location": "werkzeug routing",
             "assumption": "Framework dispatches /route to route()."}
        ],
    }
    validate_trace_output("f_1", payload, tmp_path,
                          expected_sink_file="app.py",
                          expected_sink_range=(5, 10))


def test_p04_direct_one_frame_route_is_valid(tmp_path):
    (tmp_path / "app.py").write_text("line\n" * 40)
    payload = {
        "finding_id": "f_1",
        "status": "reachable", "reachable": True, "confidence": 0.7,
        "entry_points": [{"kind": "http_route", "location": "app.py:6",
                          "auth_required": False,
                          "controllable_by": "anonymous_user"}],
        "call_chain": [{"file": "app.py", "function": "handler", "line": 6}],
        "external_inputs": ["q"],
        "rationale": "The handler itself interpolates the input at the sink.",
    }
    validate_trace_output("f_1", payload, tmp_path,
                          expected_sink_file="app.py",
                          expected_sink_range=(5, 10))


def test_p04_reversed_chain_fails_sink_check(tmp_path):
    (tmp_path / "app.py").write_text("line\n" * 40)
    payload = {
        "finding_id": "f_1",
        "status": "reachable", "reachable": True, "confidence": 0.7,
        "entry_points": [{"kind": "http_route", "location": "app.py:3"}],
        "call_chain": [
            {"file": "app.py", "function": "sink", "line": 7},    # first = sink
            {"file": "app.py", "function": "route", "line": 3},   # last = entry
        ],
        "external_inputs": ["q"],
        "rationale": "Serialized backward by mistake.",
    }
    msg = _expect_contract_error(payload, tmp_path)
    assert "does not end at the authoritative sink" in msg


def test_p04_wrong_sink_range_fails(tmp_path):
    (tmp_path / "app.py").write_text("line\n" * 40)
    payload = {
        "finding_id": "f_1",
        "status": "reachable", "reachable": True, "confidence": 0.7,
        "entry_points": [{"kind": "http_route", "location": "app.py:3"}],
        "call_chain": [
            {"file": "app.py", "function": "route", "line": 3},
            {"file": "app.py", "function": "other", "line": 30},
        ],
        "external_inputs": ["q"],
        "rationale": "Final frame is outside the supplied sink range.",
    }
    assert "does not end at the authoritative sink" in _expect_contract_error(
        payload, tmp_path
    )


def test_p04_out_of_repo_dependency_frame_rejected_in_chain(tmp_path):
    (tmp_path / "app.py").write_text("line\n" * 40)
    payload = {
        "finding_id": "f_1",
        "status": "reachable", "reachable": True, "confidence": 0.7,
        "entry_points": [{"kind": "http_route", "location": "app.py:3"}],
        "call_chain": [
            {"file": "app.py", "function": "route", "line": 3},
            {"file": "../../site-packages/flask/app.py",
             "function": "dispatch", "line": 1},
            {"file": "app.py", "function": "sink", "line": 7},
        ],
        "external_inputs": ["q"],
        "rationale": "Dependency path listed as an executable repo frame.",
    }
    msg = _expect_contract_error(payload, tmp_path)
    assert "outside repository or missing" in msg
    assert "boundary_frames" in msg


def test_p04_missing_file_frame_rejected(tmp_path):
    (tmp_path / "app.py").write_text("line\n" * 40)
    payload = {
        "finding_id": "f_1",
        "status": "reachable", "reachable": True, "confidence": 0.7,
        "entry_points": [{"kind": "http_route", "location": "app.py:3"}],
        "call_chain": [
            {"file": "app.py", "function": "route", "line": 3},
            {"file": "does_not_exist.py", "function": "x", "line": 1},
        ],
        "external_inputs": ["q"],
        "rationale": "Frame references a file that is not in the repo.",
    }
    assert "outside repository or missing" in _expect_contract_error(
        payload, tmp_path
    )


def test_p04_invalid_line_rejected_with_file_length(tmp_path):
    (tmp_path / "app.py").write_text("line\n" * 40)
    payload = {
        "finding_id": "f_1",
        "status": "reachable", "reachable": True, "confidence": 0.7,
        "entry_points": [{"kind": "http_route", "location": "app.py:3"}],
        "call_chain": [
            {"file": "app.py", "function": "route", "line": 3},
            {"file": "app.py", "function": "sink", "line": 9999},
        ],
        "external_inputs": ["q"],
        "rationale": "Line number beyond the end of the file.",
    }
    assert "line is invalid" in _expect_contract_error(payload, tmp_path)


def test_p04_uncertain_requires_typed_uncertainty(tmp_path):
    payload = {
        "finding_id": "f_1",
        "status": "uncertain", "reachable": None, "confidence": 0.2,
        "rationale": "Cannot resolve the framework boundary from source.",
        "blockers": [{"kind": "other", "location": "flask",
                      "description": "routing internals unknown"}],
    }
    assert "lacks a typed uncertainty" in _expect_contract_error(
        payload, tmp_path
    )
    payload["uncertainty"] = {
        "kind": "source_evidence",
        "reason_code": "framework_boundary_unresolved",
    }
    validate_trace_output("f_1", payload, tmp_path)


def test_p04_auth_gated_route_is_still_reachable(tmp_path):
    (tmp_path / "app.py").write_text("line\n" * 40)
    payload = {
        "finding_id": "f_1",
        "status": "reachable", "reachable": True, "confidence": 0.75,
        "entry_points": [{"kind": "http_route", "location": "app.py:3",
                          "auth_required": True,
                          "controllable_by": "authenticated_user"}],
        "call_chain": [
            {"file": "app.py", "function": "route", "line": 3},
            {"file": "app.py", "function": "sink", "line": 6},
        ],
        "external_inputs": ["bio"],
        "rationale": "Reachable after login; authentication does not gate exploitability.",
    }
    validate_trace_output("f_1", payload, tmp_path,
                          expected_sink_file="app.py",
                          expected_sink_range=(5, 10))


def test_p04_dead_branch_with_concrete_blocker_is_unreachable(tmp_path):
    (tmp_path / "app.py").write_text("line\n" * 40)
    payload = {
        "finding_id": "f_1",
        "status": "unreachable", "reachable": False, "confidence": 0.8,
        "entry_points": [],
        "call_chain": [],
        "external_inputs": [],
        "blockers": [{"kind": "dead_code", "location": "app.py:12",
                      "description": "route disabled behind flag off by default"}],
        "rationale": "The vulnerable branch is unreachable in shipped configuration.",
    }
    validate_trace_output("f_1", payload, tmp_path,
                          expected_sink_file="app.py",
                          expected_sink_range=(5, 10))


async def test_p04_static_trace_needs_no_marker(tmp_path, monkeypatch):
    """A reachable static trace with no marker field is accepted in
    static mode (the audit's 45 server.local downgrades)."""
    repo = tmp_path / "repo"
    repo.mkdir()
    db = _seeded_trace_db(repo)
    payload = {
        "finding_id": "f_1",
        "status": "reachable", "reachable": True, "confidence": 0.8,
        "entry_points": [{"kind": "http_route", "location": "app.py:6",
                          "controllable_by": "anonymous_user"}],
        "call_chain": [{"file": "app.py", "function": "handler", "line": 7}],
        "external_inputs": ["q"],
        "rationale": "Static source trace from route handler into the sink.",
    }
    monkeypatch.setattr(trace_stage, "run_agent", _agent_returning(payload, {}))

    reachable = await trace_stage.run_trace(_trace_context(repo), db)
    trace = db.get_trace("run", "f_1")

    assert reachable == 1
    assert trace["status"] == "reachable"
    assert "marker" not in trace


async def test_p04_live_trace_still_requires_verified_marker(
    tmp_path, monkeypatch
):
    repo = tmp_path / "repo"
    repo.mkdir()
    db = _seeded_trace_db(repo)
    payload = _reachable_payload()  # reachable, marker.verified falsy/absent
    calls = iter([payload, _reachable_payload(), _reachable_payload()])

    agent = _agent_returning_dispatch(calls)

    monkeypatch.setattr(trace_stage, "run_agent", agent)

    await trace_stage.run_trace(_ctx_with_live(repo), db)
    trace = db.get_trace("run", "f_1")

    # Live-mode controls remain enforced: unverified marker can never
    # produce a reachable verdict, even after semantic repairs.
    assert trace["status"] == "uncertain"
    assert trace["uncertainty"]["kind"] == "operational"
    assert db.get_reachable_canonical_findings("run") == []


async def test_p04_semantic_repair_recovers_invalid_trace(
    tmp_path, monkeypatch
):
    repo = tmp_path / "repo"
    repo.mkdir()
    db = _seeded_trace_db(repo)
    bad = {
        "finding_id": "f_1",
        "status": "reachable", "reachable": True, "confidence": 0.7,
        "entry_points": [{"kind": "http_route", "location": "app.py:3"}],
        "call_chain": [
            {"file": "app.py", "function": "sink", "line": 7},
            {"file": "app.py", "function": "route", "line": 3},
        ],  # reversed chain
        "external_inputs": ["q"],
        "rationale": "Initially serialized backward by mistake.",
    }
    good = {
        "finding_id": "f_1",
        "status": "reachable", "reachable": True, "confidence": 0.7,
        "entry_points": [{"kind": "http_route", "location": "app.py:3",
                          "controllable_by": "anonymous_user"}],
        "call_chain": [
            {"file": "app.py", "function": "route", "line": 3},
            {"file": "app.py", "function": "sink", "line": 7},
        ],
        "external_inputs": ["q"],
        "rationale": "Repaired: serialized entry-to-sink at the sink.",
    }
    payloads = iter([bad, good])
    captured_inputs = []

    agent = _agent_returning_dispatch(payloads, captured_inputs)

    monkeypatch.setattr(trace_stage, "run_agent", agent)

    reachable = await trace_stage.run_trace(_trace_context(repo), db)
    trace = db.get_trace("run", "f_1")

    assert reachable == 1
    assert trace["status"] == "reachable"
    # The repair message is structured: finding id, failed invariant,
    # authoritative sink, and the invalid payload.
    repair_input = captured_inputs[1]
    assert repair_input["repair"]["finding_id"] == "f_1"
    assert "does not end at the authoritative sink" in repair_input["repair"]["failed_invariant"]
    assert repair_input["repair"]["authoritative_sink"] == {
        "file": "app.py", "line_start": 5, "line_end": 10,
    }
    assert repair_input["repair"]["invalid_payload"] == bad
    events = db.get_stage_events("run", "trace")
    assert any(e["category"] == "semantic_repair" for e in events)


async def test_p04_repair_exhaustion_types_the_reason_code(
    tmp_path, monkeypatch
):
    repo = tmp_path / "repo"
    repo.mkdir()
    db = _seeded_trace_db(repo)
    bad = {
        "finding_id": "f_1",
        "status": "reachable", "reachable": True, "confidence": 0.7,
        "entry_points": [{"kind": "http_route", "location": "app.py:3"}],
        "call_chain": [
            {"file": "app.py", "function": "route", "line": 3},
            {"file": "nope.py", "function": "sink", "line": 7},
        ],
        "external_inputs": ["q"],
        "rationale": "Points at a frame outside the repository.",
    }
    calls = {"n": 0}

    agent = _agent_returning_dispatch(iter([bad, dict(bad), dict(bad)]), calls_holder=calls)

    monkeypatch.setattr(trace_stage, "run_agent", agent)

    await trace_stage.run_trace(_trace_context(repo), db)
    trace = db.get_trace("run", "f_1")

    # 1 initial + 2 semantic repairs — the budget is two.
    assert calls["n"] == 3
    assert trace["status"] == "uncertain"
    assert trace["uncertainty"]["kind"] == "operational"
    assert trace["uncertainty"]["reason_code"] == "missing_repo_frame"
    assert trace["reachable"] is None
    events = db.get_stage_events("run", "trace")
    assert any(
        e["category"] == "degraded" and e.get("reason_code") == "missing_repo_frame"
        for e in events
    )


async def test_p04_repair_interrupted_by_engine_failure(tmp_path, monkeypatch):
    """A repair call that fails mid-loop stores an operational uncertain
    trace (engine_failure) — never a promoted reachable verdict."""
    repo = tmp_path / "repo"
    repo.mkdir()
    db = _seeded_trace_db(repo)
    bad = {
        "finding_id": "f_1",
        "status": "reachable", "reachable": True, "confidence": 0.7,
        "entry_points": [{"kind": "http_route", "location": "app.py:3"}],
        "call_chain": [{"file": "app.py", "function": "route", "line": 3},
                       {"file": "nope.py", "function": "sink", "line": 7}],
        "external_inputs": ["q"],
        "rationale": "Points at a frame outside the repository.",
    }

    def agent(**kwargs):
        base = _agent_returning(dict(bad), {})

        async def wrapped(**kw):
            if "repair" not in kw["user_input"]:
                return await base(**kw)
            raise AgentRunError("deadline hit during semantic repair")

        return wrapped

    monkeypatch.setattr(trace_stage, "run_agent", agent())

    await trace_stage.run_trace(_trace_context(repo), db)
    trace = db.get_trace("run", "f_1")

    assert trace["status"] == "uncertain"
    assert trace["uncertainty"] == {
        "kind": "operational", "reason_code": "engine_failure",
    }
    events = db.get_stage_events("run", "trace")
    assert any(
        e["category"] == "failed"
        and e.get("reason_code") == "engine_failure"
        and e.get("during") == "semantic_repair"
        for e in events
    )


async def test_p04_static_prompt_selected_and_live_prompt_has_markers(
    tmp_path,
):
    """ctx.prompt picks the static base in static mode and the .live.md
    variant in live mode; the static file contains no marker/live-host
    examples."""
    static_ctx = _trace_context(tmp_path)
    assert static_ctx.evidence_mode == "static"
    static_prompt = static_ctx.prompt("06-trace").read_text()
    assert "STATIC (source-only)" in static_prompt
    assert "server.local" not in static_prompt
    assert "markers" in static_prompt  # documents markers: null

    live_ctx = _ctx_with_live(tmp_path)
    assert live_ctx.evidence_mode == "live"
    live_prompt = live_ctx.prompt("06-trace").read_text()
    assert "Canary-marker rules" in live_prompt
    assert "authoritative_sink" in live_prompt
    for name in ("01-recon", "02-hunt", "03-validate", "03-arbiter", "06-trace"):
        static_text = static_ctx.prompt(name).read_text()
        assert "server.local" not in static_text, name
