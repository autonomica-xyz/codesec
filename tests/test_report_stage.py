from __future__ import annotations

import json
from pathlib import Path

import pytest

from codesec.config import HarnessConfig, StageConfig
from codesec.runner import AgentResult, AgentRunError
from codesec.state import StateDB
from codesec.stages import report as report_stage
from codesec.stages._common import StageContext


def _report_context(repo: Path, tmp_path: Path, *, grade: bool = False) -> StageContext:
    return StageContext(
        run_id="run",
        repo_path=repo,
        config=HarnessConfig(
            stages={
                "report": StageConfig(
                    name="report",
                    model="writer",
                    concurrency=1,
                    tools=["Read"],
                    max_turns=2,
                    permission_mode="acceptEdits",
                    repair_attempts=0,
                    options={"grade": grade},
                )
            }
        ),
        run_results_root=tmp_path / "results",
        run_work_root=tmp_path / "work",
    )


def _seed_reachable_finding(
    db: StateDB, finding_id: str, *, severity: str = "high"
) -> None:
    if not db.get_all_tasks("run"):
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
            "finding_id": finding_id,
            "file": "app.py",
            "line_start": 2,
            "line_end": 2,
            "vuln_class": "sql_injection",
            "severity": severity,
            "description": "Untrusted input reaches the query executor.",
            "evidence_snippet": "execute(query)",
            "confidence": 0.9,
        },
    )
    db.set_finding_validation(
        "run", finding_id, "confirmed",
        {"finding_id": finding_id, "verdict": "confirmed"},
    )
    gid = f"g_{finding_id[2:]}"
    db.add_dedupe_group(
        "run",
        {
            "group_id": gid,
            "root_cause": "untrusted input reaches SQL execution",
            "canonical_finding_id": finding_id,
            "member_finding_ids": [finding_id],
        },
    )
    db.assign_finding_group("run", finding_id, gid, True)
    db.add_trace(
        "run",
        finding_id,
        {
            "finding_id": finding_id,
            "reachable": True,
            "confidence": 0.9,
            "rationale": "HTTP input reaches the query executor.",
            "entry_points": [{"kind": "http_route", "location": "app.py:1"}],
            "external_inputs": ["q"],
            "call_chain": [
                {"file": "app.py", "function": "route", "line": 1},
                {"file": "app.py", "function": "execute", "line": 2},
            ],
        },
    )


async def test_deterministic_report_owns_membership_and_review_queue(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("query = request.args['q']\nexecute(query)\n")
    db = StateDB(tmp_path / "state.db")
    db.create_run(str(repo), "run")
    task = {
        "task_id": "t_1",
        "attack_class": "sqli",
        "scope_hint": "inspect the query construction",
        "target_files": ["app.py"],
        "rationale": "untrusted input reaches a database query",
        "priority": 1,
        "source": "recon",
    }
    db.add_task("run", task)
    db.update_task_status("run", "t_1", "done")
    for finding_id, line in (("f_reachable", 2), ("f_review", 1)):
        db.add_finding(
            "run",
            "t_1",
            {
                "finding_id": finding_id,
                "file": "app.py",
                "line_start": line,
                "line_end": line,
                "vuln_class": "sql_injection",
                "severity": "high",
                "cwe": "CWE-89",
                "description": (
                    "Untrusted query input reaches SQL execution without "
                    "parameter binding."
                ),
                "evidence_snippet": "execute(query)",
                "confidence": 0.9,
            },
        )
    db.set_finding_validation(
        "run",
        "f_reachable",
        "confirmed",
        {"finding_id": "f_reachable", "verdict": "confirmed"},
    )
    db.set_finding_validation(
        "run",
        "f_review",
        "needs_more_info",
        {"finding_id": "f_review", "verdict": "needs_more_info"},
    )
    db.add_dedupe_group(
        "run",
        {
            "group_id": "g_1",
            "root_cause": "untrusted input reaches SQL execution",
            "canonical_finding_id": "f_reachable",
            "member_finding_ids": ["f_reachable"],
        },
    )
    db.assign_finding_group("run", "f_reachable", "g_1", True)
    db.add_trace(
        "run",
        "f_reachable",
        {
            "finding_id": "f_reachable",
            "reachable": True,
            "confidence": 0.9,
            "rationale": "HTTP input reaches the query executor.",
            "entry_points": [
                {
                    "kind": "http_route",
                    "location": "app.py:1",
                    "controllable_by": "anonymous_user",
                }
            ],
            "external_inputs": ["q"],
            "call_chain": [
                {"file": "app.py", "function": "route", "line": 1},
                {"file": "app.py", "function": "execute", "line": 2},
            ],
        },
    )
    ctx = StageContext(
        run_id="run",
        repo_path=repo,
        config=HarnessConfig(),
        run_results_root=tmp_path / "results",
        run_work_root=tmp_path / "work",
    )

    report_path = await report_stage.run_deterministic_report(ctx, db)
    report = json.loads(report_path.read_text())
    review = json.loads(
        (tmp_path / "results" / "report" / "review_queue.json").read_text()
    )

    assert [finding["finding_id"] for finding in report["findings"]] == [
        "f_reachable"
    ]
    assert report["summary"] == {"total": 1, "by_severity": {"high": 1}}
    assert [item["finding_id"] for item in review["findings"]] == ["f_review"]


async def test_deterministic_report_needs_validation_and_hardening(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("query = request.args['q']\nexecute(query)\n")
    db = StateDB(tmp_path / "state.db")
    db.create_run(str(repo), "run")
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
            "finding_id": "f_blocked",
            "file": "app.py",
            "line_start": 2,
            "line_end": 2,
            "vuln_class": "sql_injection",
            "severity": "high",
            "description": "Possibly injectable query construction.",
            "evidence_snippet": "execute(query)",
            "confidence": 0.4,
        },
    )
    db.set_finding_validation(
        "run",
        "f_blocked",
        "needs_more_info",
        {
            "finding_id": "f_blocked",
            "verdict": "needs_more_info",
            "blockers": ["cannot tell whether `execute` parameterizes"],
            "validation_plan": {"local": "run the query path with a quote"},
        },
    )
    db.record_hardening_notes(
        "run",
        "t_1",
        [{"file": "app.py", "note": "no request size limit on the route"}],
    )
    ctx = StageContext(
        run_id="run",
        repo_path=repo,
        config=HarnessConfig(),
        run_results_root=tmp_path / "results",
        run_work_root=tmp_path / "work",
    )

    report_path = await report_stage.run_deterministic_report(ctx, db)
    report = json.loads(report_path.read_text())

    assert report["findings"] == []
    assert report["needs_validation"] == [
        {
            "finding_id": "f_blocked",
            "file": "app.py",
            "vuln_class": "sql_injection",
            "blockers": ["cannot tell whether `execute` parameterizes"],
            "validation_plan": {"local": "run the query path with a quote"},
        }
    ]
    assert "severity" not in report["needs_validation"][0]
    assert report["hardening"] == [
        {
            "task_id": "t_1",
            "file": "app.py",
            "note": "no request size limit on the route",
        }
    ]
    from codesec.json_utils import validate_schema
    errors = validate_schema(report, ctx.schema("report"))
    assert errors == []


async def test_deterministic_report_arbiter_severity_and_production_viable(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("query = request.args['q']\nexecute(query)\n")
    db = StateDB(tmp_path / "state.db")
    db.create_run(str(repo), "run")
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
    trace = {
        "reachable": True,
        "confidence": 0.9,
        "rationale": "HTTP input reaches the query executor.",
        "entry_points": [{"kind": "http_route", "location": "app.py:1"}],
        "external_inputs": ["q"],
        "call_chain": [
            {"file": "app.py", "function": "route", "line": 1},
            {"file": "app.py", "function": "execute", "line": 2},
        ],
    }
    cases = [
        # arbiter overrules the finding's own severity
        ("f_arbiter", "critical",
         {"verdict": "confirmed", "arbiter_severity": "medium",
          "severity_reasoning": "requires authenticated admin session"},
         "medium", None),
        # production_viable 'no' drops the finding severity one step
        ("f_pv", "high",
         {"verdict": "confirmed",
          "production_viable": {"verdict": "no",
                                "reason": "sink is assert-guarded"}},
         "medium", {"verdict": "no", "reason": "sink is assert-guarded"}),
        # arbiter + production_viable: drop applies on top of the arbiter
        ("f_both", "high",
         {"verdict": "confirmed", "arbiter_severity": "low",
          "severity_reasoning": "local-only path",
          "production_viable": {"verdict": "no"}},
         "informational", {"verdict": "no"}),
    ]
    for finding_id, sev, validation, _expected_sev, _pv in cases:
        db.add_finding(
            "run",
            "t_1",
            {
                "finding_id": finding_id,
                "file": "app.py",
                "line_start": 2,
                "line_end": 2,
                "vuln_class": "sql_injection",
                "severity": sev,
                "description": "Untrusted input reaches the query executor.",
                "evidence_snippet": "execute(query)",
                "confidence": 0.9,
            },
        )
        db.set_finding_validation(
            "run", finding_id, "confirmed",
            {"finding_id": finding_id, **validation},
        )
        gid = f"g_{finding_id[2:]}"
        db.add_dedupe_group(
            "run",
            {
                "group_id": gid,
                "root_cause": "untrusted input reaches SQL execution",
                "canonical_finding_id": finding_id,
                "member_finding_ids": [finding_id],
            },
        )
        db.assign_finding_group("run", finding_id, gid, True)
        db.add_trace("run", finding_id, {"finding_id": finding_id, **trace})
    ctx = StageContext(
        run_id="run",
        repo_path=repo,
        config=HarnessConfig(),
        run_results_root=tmp_path / "results",
        run_work_root=tmp_path / "work",
    )

    report_path = await report_stage.run_deterministic_report(ctx, db)
    report = json.loads(report_path.read_text())

    entries = {e["finding_id"]: e for e in report["findings"]}
    for finding_id, _sev, _v, expected_sev, expected_pv in cases:
        assert entries[finding_id]["severity"] == expected_sev
        if expected_pv is None:
            assert "production_viable" not in entries[finding_id]
        else:
            assert entries[finding_id]["production_viable"] == expected_pv
    assert report["summary"]["by_severity"] == {
        "medium": 2,
        "informational": 1,
    }


async def test_report_grader_demotes_and_annotates(
    tmp_path: Path, monkeypatch
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("query = request.args['q']\nexecute(query)\n")
    db = StateDB(tmp_path / "state.db")
    db.create_run(str(repo), "run")
    _seed_reachable_finding(db, "f_1")

    calls = []

    async def fake_grade(**kwargs):
        calls.append(kwargs)
        return AgentResult(
            payload={
                "evidence_score": 4,
                "issues": ["no demonstrated impact beyond a crash"],
                "demote_severity": True,
                "reason": "evidence supports a crash, not data access",
            },
            cost_usd=None,
            input_tokens=None,
            output_tokens=None,
            cache_read_tokens=None,
            cache_creation_tokens=None,
            num_turns=1,
            duration_ms=None,
            session_id=None,
            artifact_path=tmp_path / "grade.jsonl",
            repair_used=False,
        )

    monkeypatch.setattr(report_stage, "run_agent", fake_grade)
    ctx = _report_context(repo, tmp_path, grade=True)

    report_path = await report_stage.run_deterministic_report(ctx, db)
    report = json.loads(report_path.read_text())

    entry = report["findings"][0]
    assert calls[0]["allowed_tools"] == []
    assert calls[0]["stage"] == "report-grade"
    assert entry["severity"] == "medium"  # demoted one step from high
    assert entry["grading"] == {
        "evidence_score": 4,
        "issues": ["no demonstrated impact beyond a crash"],
        "demoted": True,
        "reason": "evidence supports a crash, not data access",
    }
    assert report["summary"]["by_severity"] == {"medium": 1}


async def test_report_grader_failure_ships_ungraded(
    tmp_path: Path, monkeypatch
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("query = request.args['q']\nexecute(query)\n")
    db = StateDB(tmp_path / "state.db")
    db.create_run(str(repo), "run")
    _seed_reachable_finding(db, "f_1")

    async def fail_grade(**kwargs):
        raise AgentRunError("grader output garbage")

    monkeypatch.setattr(report_stage, "run_agent", fail_grade)
    ctx = _report_context(repo, tmp_path, grade=True)

    report_path = await report_stage.run_deterministic_report(ctx, db)
    report = json.loads(report_path.read_text())

    entry = report["findings"][0]
    assert entry["severity"] == "high"
    assert "grading" not in entry


async def test_report_grader_off_by_default(
    tmp_path: Path, monkeypatch
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("query = request.args['q']\nexecute(query)\n")
    db = StateDB(tmp_path / "state.db")
    db.create_run(str(repo), "run")
    _seed_reachable_finding(db, "f_1")

    async def fail_if_called(**kwargs):
        raise AssertionError("grader must not run when report.grade is off")

    monkeypatch.setattr(report_stage, "run_agent", fail_if_called)
    ctx = _report_context(repo, tmp_path, grade=False)

    report_path = await report_stage.run_deterministic_report(ctx, db)
    report = json.loads(report_path.read_text())

    assert "grading" not in report["findings"][0]


def _seed_confirmed_canonical(
    db: StateDB,
    finding_id: str,
    *,
    line: int = 2,
    trace: dict | None = ...,
) -> None:
    if not db.get_all_tasks("run"):
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
        db.update_task_status("run", "t_1", "done")
    db.add_finding(
        "run",
        "t_1",
        {
            "finding_id": finding_id,
            "file": "app.py",
            "line_start": line,
            "line_end": line,
            "vuln_class": "sql_injection",
            "severity": "high",
            "cwe": "CWE-89",
            "description": (
                "Untrusted query input reaches SQL execution without "
                "parameter binding."
            ),
            "evidence_snippet": "execute(query)",
            "confidence": 0.9,
        },
    )
    db.set_finding_validation(
        "run",
        finding_id,
        "confirmed",
        {"finding_id": finding_id, "verdict": "confirmed"},
    )
    gid = f"g_{finding_id}"
    db.add_dedupe_group(
        "run",
        {
            "group_id": gid,
            "root_cause": "untrusted input reaches SQL execution",
            "canonical_finding_id": finding_id,
            "member_finding_ids": [finding_id],
        },
    )
    db.assign_finding_group("run", finding_id, gid, True)
    if trace is not ... and trace is not None:
        db.add_trace("run", finding_id, {"finding_id": finding_id, **trace})


async def test_deterministic_report_ships_untraced_and_unreachable(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("query = request.args['q']\nexecute(query)\n")
    db = StateDB(tmp_path / "state.db")
    db.create_run(str(repo), "run")
    _seed_confirmed_canonical(db, "f_untraced", line=1, trace=None)
    _seed_confirmed_canonical(
        db,
        "f_unreachable",
        line=2,
        trace={
            "reachable": False,
            "confidence": 0.2,
            "rationale": "no HTTP path reaches this helper",
            "entry_points": [],
            "call_chain": [],
        },
    )
    ctx = StageContext(
        run_id="run",
        repo_path=repo,
        config=HarnessConfig(),
        run_results_root=tmp_path / "results",
        run_work_root=tmp_path / "work",
    )
    report_path = await report_stage.run_deterministic_report(ctx, db)
    report = json.loads(report_path.read_text())
    review = json.loads(
        (tmp_path / "results" / "report" / "review_queue.json").read_text()
    )
    by_id = {item["finding_id"]: item for item in report["findings"]}
    assert set(by_id) == {"f_untraced", "f_unreachable"}
    assert by_id["f_untraced"]["trace"]["status"] == "untraced"
    assert by_id["f_untraced"]["trace"]["entry_points"] == []
    assert by_id["f_untraced"]["trace"]["call_chain"] == []
    assert by_id["f_unreachable"]["trace"]["status"] == "unreachable"
    reasons = {item["finding_id"]: item["reason"] for item in review["findings"]}
    assert reasons["f_untraced"] == "trace_untraced"
    assert reasons["f_unreachable"] == "trace_unreachable"
    from codesec.json_utils import validate_schema
    assert validate_schema(report, ctx.schema("report")) == []


async def test_run_report_reconciles_empty_agent_findings(
    tmp_path: Path, monkeypatch
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("query = request.args['q']\nexecute(query)\n")
    db = StateDB(tmp_path / "state.db")
    db.create_run(str(repo), "run")
    _seed_confirmed_canonical(db, "f_kept", line=2, trace=None)

    async def empty_agent(**kwargs):
        return AgentResult(
            payload={
                "run_id": "run",
                "target": {"repo_path": str(repo)},
                "summary": {"total": 0, "by_severity": {}},
                "findings": [],
            },
            cost_usd=None,
            input_tokens=None,
            output_tokens=None,
            cache_read_tokens=None,
            cache_creation_tokens=None,
            num_turns=1,
            duration_ms=None,
            session_id=None,
            artifact_path=tmp_path / "report_agent.jsonl",
            repair_used=False,
        )

    monkeypatch.setattr(report_stage, "run_agent", empty_agent)
    ctx = _report_context(repo, tmp_path, grade=False)
    report_path = await report_stage.run_report(ctx, db)
    report = json.loads(report_path.read_text())
    assert [item["finding_id"] for item in report["findings"]] == ["f_kept"]
    assert report["findings"][0]["trace"]["status"] == "untraced"
    assert report["summary"]["total"] == 1
    review = json.loads(
        (tmp_path / "results" / "report" / "review_queue.json").read_text()
    )
    assert review["findings"][0]["reason"] == "trace_untraced"


# ---- P02: explicit report policy + deterministic renderer --------------

def _policy_seed_db(tmp_path: Path):
    """Confirmed canonicals in every trace state + one needs_more_info."""
    repo = tmp_path / "repo"
    repo.mkdir(exist_ok=True)
    (repo / "app.py").write_text("eval(request.args['p'])\n")
    db = StateDB(tmp_path / "state.db")
    db.create_run(str(repo), "run")
    db.add_task("run", {
        "task_id": "t_1", "attack_class": "rce", "scope_hint": "eval sink",
        "target_files": ["app.py"], "rationale": "input reaches eval",
        "priority": 1, "source": "recon",
    })
    states = {
        "f_reach": "reachable",
        "f_uncertain": "uncertain",
        "f_unreach": "unreachable",
        "f_untraced": None,
    }
    for fid, state in states.items():
        db.add_finding("run", "t_1", {
            "finding_id": fid,
            "file": "app.py",
            "line_start": 1,
            "line_end": 1,
            "vuln_class": "command_injection",
            "severity": "high",
            "cwe": "CWE-95",
            "description": "Request parameter reaches eval() without any validation.",
            "evidence_snippet": "eval(request.args['p'])",
            "confidence": 0.9,
        })
        db.set_finding_validation(
            "run", fid, "confirmed", {"finding_id": fid, "verdict": "confirmed"}
        )
        db.add_dedupe_group("run", {
            "group_id": f"g_{fid[2:]}",
            "root_cause": "parameter reaches eval in app.py",
            "canonical_finding_id": fid,
            "member_finding_ids": [fid],
        })
        db.assign_finding_group("run", fid, f"g_{fid[2:]}", True)
        if state is not None:
            payload = {
                "finding_id": fid,
                "status": state,
                "confidence": 0.8,
                "rationale": "trace rationale",
                "entry_points": [
                    {"kind": "http_route", "location": "app.py:1",
                     "controllable_by": "anonymous_user"}
                ],
                "external_inputs": ["p"],
                "call_chain": [
                    {"file": "app.py", "function": "route", "line": 1},
                    {"file": "app.py", "function": "handler", "line": 1},
                ],
            }
            if state == "uncertain":
                payload["reachable"] = None
            db.add_trace("run", fid, payload)
    db.add_finding("run", "t_1", {
        "finding_id": "f_needsinfo",
        "file": "app.py", "line_start": 2, "line_end": 2,
        "vuln_class": "xss", "severity": "low",
        "description": "Insufficient evidence to settle this candidate finding.",
        "evidence_snippet": "render(p)",
    })
    db.set_finding_validation(
        "run", "f_needsinfo", "needs_more_info",
        {"finding_id": "f_needsinfo", "verdict": "needs_more_info"},
    )
    return db


def _policy_ctx(tmp_path: Path, policy: str, renderer: str = "deterministic"):
    return StageContext(
        run_id="run",
        repo_path=tmp_path / "repo",
        config=HarnessConfig(
            stages={
                "report": StageConfig(
                    name="report",
                    model="writer",
                    concurrency=1,
                    tools=["Read"],
                    max_turns=2,
                    permission_mode="acceptEdits",
                    repair_attempts=0,
                )
            },
            report_policy=policy,
            report_renderer=renderer,
        ),
        run_results_root=tmp_path / "results",
        run_work_root=tmp_path / "work",
    )


async def test_policy_memberships_for_every_trace_state(tmp_path):
    from codesec.state import StateDB as _SDB

    db = _policy_seed_db(tmp_path)

    all_ids = sorted(f.finding_id for f, _ in db.get_report_findings("run", "confirmed_all"))
    reach_ids = sorted(f.finding_id for f, _ in db.get_report_findings("run", "confirmed_reachable"))
    excl_ids = sorted(f.finding_id for f, _ in db.get_report_findings("run", "confirmed_except_unreachable"))

    assert all_ids == ["f_reach", "f_uncertain", "f_unreach", "f_untraced"]
    assert reach_ids == ["f_reach"]
    assert excl_ids == ["f_reach", "f_uncertain", "f_untraced"]

    snap = db.report_membership_snapshot("run")
    assert snap["by_trace_status"] == {
        "reachable": ["f_reach"],
        "uncertain": ["f_uncertain"],
        "unreachable": ["f_unreach"],
        "untraced": ["f_untraced"],
    }


async def test_deterministic_report_confirmed_reachable_policy(tmp_path):
    db = _policy_seed_db(tmp_path)
    ctx = _policy_ctx(tmp_path, "confirmed_reachable")

    report_path = await report_stage.run_deterministic_report(ctx, db)
    report = json.loads(report_path.read_text())

    # Primary excludes unreachable AND uncertain AND untraced.
    assert [e["finding_id"] for e in report["findings"]] == ["f_reach"]
    assert report["summary"]["total"] == 1
    # Secondary keeps every confirmed canonical with labels.
    confirmed = json.loads(
        (tmp_path / "results" / "report" / "confirmed.json").read_text()
    )
    assert sorted(e["finding_id"] for e in confirmed["findings"]) == [
        "f_reach", "f_uncertain", "f_unreach", "f_untraced"
    ]
    # Review queue explains every exclusion with explicit reasons.
    review = json.loads(
        (tmp_path / "results" / "report" / "review_queue.json").read_text()
    )
    reasons = {
        entry["finding_id"]: entry.get(
            "reasons", [entry.get("reason")]
        )
        for entry in review["findings"]
    }
    assert "excluded_by_policy:confirmed_reachable" in reasons["f_uncertain"]
    assert "excluded_by_policy:confirmed_reachable" in reasons["f_unreach"]
    assert "trace_uncertain" in reasons["f_uncertain"]
    assert "trace_unreachable" in reasons["f_unreach"]
    assert "trace_untraced" in reasons["f_untraced"]
    assert "validation_needs_more_info" in reasons["f_needsinfo"]
    assert review["report_policy"] == "confirmed_reachable"
    assert review["membership"]["confirmed_canonical_ids"] == [
        "f_reach", "f_uncertain", "f_unreach", "f_untraced"
    ]


async def test_deterministic_report_default_policy_keeps_all(tmp_path):
    db = _policy_seed_db(tmp_path)
    ctx = _policy_ctx(tmp_path, "confirmed_all")

    report_path = await report_stage.run_deterministic_report(ctx, db)
    report = json.loads(report_path.read_text())

    assert sorted(e["finding_id"] for e in report["findings"]) == [
        "f_reach", "f_uncertain", "f_unreach", "f_untraced"
    ]


async def test_deterministic_renderer_makes_zero_model_calls(tmp_path):
    db = _policy_seed_db(tmp_path)
    ctx = _policy_ctx(tmp_path, "confirmed_reachable")

    async def fail_agent(**kwargs):
        raise AssertionError("deterministic renderer must not call models")

    import codesec.stages.report as report_mod
    original = report_mod.run_agent
    report_mod.run_agent = fail_agent
    try:
        report_path = await report_stage.run_deterministic_report(ctx, db)
    finally:
        report_mod.run_agent = original

    report = json.loads(report_path.read_text())
    assert report["findings"], "renderer must not emit an empty success"
    ids = [e["finding_id"] for e in report["findings"]]
    assert ids == sorted(ids), "stable ordering by finding id"


async def test_renderer_failure_is_error_not_empty_success(tmp_path, monkeypatch):
    db = _policy_seed_db(tmp_path)
    ctx = _policy_ctx(tmp_path, "confirmed_reachable")

    def broken_validate(payload, schema_file):
        return ["injected failure: schema violated"]

    monkeypatch.setattr(report_stage, "validate_schema", broken_validate)

    from codesec.contracts import StageContractError
    with pytest.raises(StageContractError):
        await report_stage.run_deterministic_report(ctx, db)

    out_dir = tmp_path / "results" / "report"
    assert not (out_dir / "report.json").exists() or json.loads(
        (out_dir / "report.json").read_text()
    )["findings"], "no empty report may be written on failure"


async def test_agent_report_cannot_relocate_confirmed_finding(
    tmp_path, monkeypatch
):
    """A schema-valid LLM report response cannot change canonical file,
    line, or CWE — those come from the DB, not prose."""
    db = _policy_seed_db(tmp_path)
    ctx = _policy_ctx(tmp_path, "confirmed_all", renderer="agent")

    async def lying_agent(**kwargs):
        return AgentResult(
            payload={
                "run_id": "run",
                "target": {"repo_path": str(tmp_path / "repo")},
                "summary": {"total": 0, "by_severity": {}},
                "findings": [
                    {
                        "finding_id": "f_reach",
                        "title": "relocated finding",
                        "severity": "critical",
                        "vuln_class": "made_up_class",
                        "file": "elsewhere.py",
                        "line_start": 999,
                        "line_end": 1000,
                        "description": "A completely rewritten description of the issue.",
                        "evidence": "fabricated evidence",
                        "trace": {"entry_points": [], "call_chain": []},
                        "recommendation": "do something",
                    }
                ],
            },
            cost_usd=0.0, input_tokens=1, output_tokens=1,
            cache_read_tokens=None, cache_creation_tokens=None,
            num_turns=1, duration_ms=1, session_id=None,
            artifact_path=tmp_path / "x.jsonl", repair_used=False,
        )

    import codesec.stages.report as report_mod
    monkeypatch.setattr(report_mod, "run_agent", lying_agent)

    report_path = await report_stage.run_report(ctx, db)
    report = json.loads(report_path.read_text())
    entry = report["findings"][0]

    assert entry["file"] == "app.py"
    assert entry["line_start"] == 1
    assert entry["vuln_class"] == "command_injection"
    assert entry["cwe"] == "CWE-95"
    # Omitted members must be restored from the DB membership.
    assert {e["finding_id"] for e in report["findings"]} == {
        "f_reach", "f_uncertain", "f_unreach", "f_untraced"
    }
