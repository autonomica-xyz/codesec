"""Dead-end visibility: rejected findings reach the task-generating stages."""

from __future__ import annotations

from pathlib import Path

from codesec.config import HarnessConfig, StageConfig
from codesec.state import StateDB
from codesec.stages import feedback as feedback_stage
from codesec.stages import gapfill as gapfill_stage
from codesec.stages._common import StageContext, refuted_patterns_digest


class _FakeResult:
    def __init__(self, payload: dict, tmp: Path):
        self.payload = payload
        self.artifact_path = tmp / "out.jsonl"
        self.cost_usd = None
        self.input_tokens = 0
        self.output_tokens = 0
        self.cache_read_tokens = 0
        self.cache_creation_tokens = 0
        self.num_turns = 1
        self.duration_ms = 0


def _context(tmp_path: Path, stage: str) -> StageContext:
    return StageContext(
        run_id="run",
        repo_path=tmp_path,
        config=HarnessConfig(
            stages={
                stage: StageConfig(
                    name=stage,
                    model="sonnet",
                    concurrency=1,
                    tools=["Read"],
                    max_turns=2,
                    permission_mode="acceptEdits",
                    repair_attempts=0,
                )
            }
        ),
        run_results_root=tmp_path / "results",
        run_work_root=tmp_path / "work",
    )


def _db_with_rejected_finding(tmp_path: Path) -> StateDB:
    db = StateDB(tmp_path / "state.db")
    db.create_run(str(tmp_path), "run")
    db.add_task(
        "run",
        {
            "task_id": "t_1",
            "attack_class": "sqli",
            "scope_hint": "query sink",
            "target_files": ["app.py"],
            "rationale": "request input reaches query",
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
            "line_end": 2,
            "vuln_class": "sql_injection",
            "severity": "high",
            "description": "input reaches query",
            "evidence_snippet": "execute(sql %s user)",
            "confidence": 0.9,
        },
    )
    db.set_finding_validation(
        "run", "f_1", "rejected",
        {
            "finding_id": "f_1",
            "verdict": "rejected",
            "rationale": "the query is parameterized at the callsite; "
                         "the tainted branch is unreachable",
            "validator_confidence": 0.9,
        },
    )
    return db


def test_digest_lists_rejected_findings_with_reason(tmp_path: Path) -> None:
    db = _db_with_rejected_finding(tmp_path)
    digest = refuted_patterns_digest(db, "run")
    assert digest == [
        {
            "vuln_class": "sql_injection",
            "file": "app.py",
            "rejected_because": (
                "the query is parameterized at the callsite; the tainted "
                "branch is unreachable"
            ),
        }
    ]


async def test_gapfill_input_carries_refuted_patterns(
    tmp_path: Path, monkeypatch
) -> None:
    db = _db_with_rejected_finding(tmp_path)
    db.update_task_status("run", "t_1", "done")
    seen: dict[str, object] = {}

    async def fake_run_agent(*, user_input, **kw):
        seen.update(user_input)
        return _FakeResult(
            {"new_tasks": [], "coverage_analysis": {}}, tmp_path
        )

    monkeypatch.setattr(gapfill_stage, "run_agent", fake_run_agent)
    await gapfill_stage.run_gapfill(_context(tmp_path, "gapfill"), db)

    assert seen["refuted_patterns"] == [
        {
            "vuln_class": "sql_injection",
            "file": "app.py",
            "rejected_because": (
                "the query is parameterized at the callsite; the tainted "
                "branch is unreachable"
            ),
        }
    ]


async def test_feedback_input_carries_refuted_patterns(
    tmp_path: Path, monkeypatch
) -> None:
    db = _db_with_rejected_finding(tmp_path)
    # Feedback only runs with a reachable canonical finding; keep f_1
    # rejected and add a separate confirmed+traced finding f_2.
    db.add_task(
        "run",
        {
            "task_id": "t_2",
            "attack_class": "command_injection",
            "scope_hint": "shell sink",
            "target_files": ["run.py"],
            "rationale": "request input reaches shell",
            "priority": 1,
            "source": "recon",
        },
    )
    db.add_finding(
        "run",
        "t_2",
        {
            "finding_id": "f_2",
            "file": "run.py",
            "line_start": 1,
            "line_end": 2,
            "vuln_class": "command_injection",
            "severity": "critical",
            "description": "input reaches shell",
            "evidence_snippet": "subprocess.run(cmd, shell=True)",
            "confidence": 0.9,
        },
    )
    db.set_finding_validation(
        "run", "f_2", "confirmed",
        {"finding_id": "f_2", "verdict": "confirmed",
         "rationale": "ok", "validator_confidence": 0.9},
    )
    db.assign_finding_group("run", "f_2", "g_2", True)
    db.add_trace(
        "run", "f_2",
        {"status": "reachable", "reachable": True, "confidence": 0.9,
         "entry_points": [], "rationale": "route /x reaches sink"},
    )
    seen: dict[str, object] = {}

    async def fake_run_agent(*, user_input, **kw):
        seen.update(user_input)
        return _FakeResult({"new_hunt_tasks": []}, tmp_path)

    monkeypatch.setattr(feedback_stage, "run_agent", fake_run_agent)
    await feedback_stage.run_feedback(_context(tmp_path, "feedback"), db)

    assert "refuted_patterns" in seen
