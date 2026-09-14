from __future__ import annotations

import json
from pathlib import Path

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
