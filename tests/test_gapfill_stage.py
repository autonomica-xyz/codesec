from pathlib import Path

import pytest

from codesec.config import HarnessConfig, StageConfig
from codesec.runner import AgentRunError
from codesec.state import StateDB
from codesec.stages import gapfill as gapfill_stage
from codesec.stages._common import StageContext


def _context(tmp_path: Path) -> StageContext:
    return StageContext(
        run_id="run",
        repo_path=tmp_path,
        config=HarnessConfig(
            stages={
                "gapfill": StageConfig(
                    name="gapfill",
                    model="titus",
                    concurrency=1,
                    tools=["Read"],
                    max_turns=2,
                    permission_mode="acceptEdits",
                    repair_attempts=0,
                )
            }
        ),
    )


async def test_gapfill_records_not_applicable_checkpoint(tmp_path: Path) -> None:
    db = StateDB(tmp_path / "state.db")
    db.create_run(str(tmp_path), "run")

    added = await gapfill_stage.run_gapfill(_context(tmp_path), db)

    assert added == 0
    assert db.artifact_count("run", "gapfill") == 1


async def test_gapfill_agent_failure_is_not_silently_complete(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db = StateDB(tmp_path / "state.db")
    db.create_run(str(tmp_path), "run")
    db.add_task(
        "run",
        {
            "task_id": "t_1",
            "attack_class": "sqli",
            "scope_hint": "query",
            "target_files": ["app.py"],
            "rationale": "request reaches query",
            "priority": 1,
            "source": "recon",
        },
    )
    db.update_task_status("run", "t_1", "done")

    async def fail(**kwargs):
        raise AgentRunError("invalid output")

    monkeypatch.setattr(gapfill_stage, "run_agent", fail)

    with pytest.raises(AgentRunError, match="invalid output"):
        await gapfill_stage.run_gapfill(_context(tmp_path), db)

    assert db.artifact_count("run", "gapfill") == 0


# ---------- W9: coverage-critic inputs + negative-knowledge filter ----------

def _write(repo: Path, name: str, text: str = "x\n") -> None:
    path = repo / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def test_drop_refuted_tasks_blocks_re_derived_work() -> None:
    refuted = [{"vuln_class": "sqli", "file": "db.py",
                "rejected_because": "param is bound"}]
    tasks = [
        {"task_id": "t_gf_1", "attack_class": "sqli",
         "target_files": ["db.py"], "rationale": "try sqli again"},
        {"task_id": "t_gf_2", "attack_class": "xss",
         "target_files": ["db.py"], "rationale": "different class"},
        {"task_id": "t_gf_3", "attack_class": "sqli",
         "target_files": ["other.py"], "rationale": "different file"},
        {"task_id": "t_gf_4", "attack_class": "sqli",
         "target_files": ["db.py"],
         "rationale": "new evidence: `request.args` merged after binding"},
        {"task_id": "t_gf_5", "attack_class": "sqli",
         "target_files": ["db.py"],
         "rationale": "however, the admin path bypasses the sanitizer"},
    ]
    kept, dropped = gapfill_stage.drop_refuted_tasks(tasks, refuted)
    assert dropped == 1
    assert [t["task_id"] for t in kept] == [
        "t_gf_2", "t_gf_3", "t_gf_4", "t_gf_5"
    ]


def test_cites_new_evidence_heuristic() -> None:
    assert gapfill_stage.cites_new_evidence("uses `request.args` now")
    assert gapfill_stage.cites_new_evidence("However the path changed")
    assert gapfill_stage.cites_new_evidence("a regression in v2")
    assert not gapfill_stage.cites_new_evidence("try the same thing")
    assert not gapfill_stage.cites_new_evidence("")


def test_entry_point_coverage_counts_tasks(tmp_path: Path) -> None:
    from codesec.state import Task

    recon = {
        "architecture": {
            "entry_points": [
                {"kind": "http_route", "location": "app.py:42",
                 "auth_required": False},
                {"kind": "cli", "location": "tools/cli.py:10",
                 "auth_required": True},
                {"kind": "hook", "location": "on_webhook"},
            ],
            "external_inputs": [
                {"name": "username", "kind": "http_param",
                 "controllable_by": "anonymous_user"},
                {"name": "X-Token", "kind": "http_header",
                 "controllable_by": "authenticated_user"},
            ],
        }
    }

    def task(tid, files, hint, rationale=""):
        return Task(task_id=tid, run_id="r", source="recon",
                    attack_class="x", scope_hint=hint,
                    target_files=files, rationale=rationale,
                    priority=3, status="done", raw_json={})

    tasks = [
        task("t1", ["app.py"], "route reads username"),
        task("t2", ["tools"], "other hint mentions on_webhook symbol"),
    ]
    cov = gapfill_stage.entry_point_coverage(recon, tasks)
    by_loc = {e["location"]: e["tasks_touching"]
            for e in cov["entry_points"]}
    assert by_loc == {"app.py:42": 1, "tools/cli.py:10": 1,
                      "on_webhook": 1}
    by_name = {e["name"]: e["tasks_touching"]
               for e in cov["external_inputs"]}
    assert by_name == {"username": 1, "X-Token": 0}


async def test_run_gapfill_inputs_and_refuted_post_filter(
    tmp_path: Path, monkeypatch
) -> None:
    import json
    from types import SimpleNamespace

    _write(tmp_path, "app.py", "h\n" * 5)
    _write(tmp_path, "db.py", "q\n" * 5)

    db = StateDB(tmp_path / "state.db")
    db.create_run(str(tmp_path), "run")
    db.save_recon_output("run", {
        "subsystems": [{"name": "web", "path": "", "language": "py",
                        "purpose": "app"}],
        "architecture": {
            "build_commands": [], "trust_boundaries": [],
            "entry_points": [
                {"kind": "http_route", "location": "app.py:2"},
            ],
            "external_inputs": [
                {"name": "q", "kind": "http_param"},
            ],
        },
        "initial_tasks": [],
    })
    db.add_task("run", {
        "task_id": "t_1", "attack_class": "xss", "scope_hint": "app.py",
        "target_files": ["app.py"], "rationale": "r", "priority": 1,
        "source": "recon",
    })
    db.update_task_status("run", "t_1", "done")
    db.add_finding("run", "t_1", {
        "finding_id": "f_bad", "file": "db.py", "line_start": 1,
        "line_end": 2, "vuln_class": "sqli", "severity": "high",
        "description": "d", "evidence_snippet": "e",
    })
    db.set_finding_validation(
        "run", "f_bad", "rejected",
        {"finding_id": "f_bad", "verdict": "rejected",
         "rationale": "param is bound"},
    )
    db.record_uncovered_surfaces("run", "t_1", [
        {"surface": "admin", "attack_class": "idor",
         "starting_path": "app.py:4", "reason": "not assigned"},
    ])

    captured = {}

    async def fake_agent(**kwargs):
        captured["user_input"] = kwargs["user_input"]
        return SimpleNamespace(
            payload={
                "new_tasks": [
                    {"task_id": "t_gf_1", "attack_class": "sqli",
                     "scope_hint": "db.py again", "target_files": ["db.py"],
                     "rationale": "same sqli on db.py", "priority": 2},
                    {"task_id": "t_gf_2", "attack_class": "idor",
                     "scope_hint": "admin surface in app.py",
                     "target_files": ["app.py"],
                     "rationale": "unmapped admin route", "priority": 1},
                ],
                "coverage_analysis": {},
            },
            artifact_path=tmp_path / "gapfill.jsonl",
            cost_usd=0.0, input_tokens=0, output_tokens=0,
            cache_read_tokens=0, cache_creation_tokens=0,
            num_turns=1, duration_ms=1,
        )

    monkeypatch.setattr(gapfill_stage, "run_agent", fake_agent)

    added = await gapfill_stage.run_gapfill(_context(tmp_path), db)

    ui = captured["user_input"]
    assert ui["uncovered_surfaces"][0]["surface"] == "admin"
    assert ui["entry_point_coverage"] == [
        {"kind": "http_route", "location": "app.py:2",
         "auth_required": None, "tasks_touching": 1}
    ]
    assert ui["external_input_coverage"][0]["tasks_touching"] == 0
    assert ui["refuted_patterns"] == [
        {"vuln_class": "sqli", "file": "db.py",
         "rejected_because": "param is bound"}
    ]
    # t_gf_1 re-derived the refuted (sqli, db.py) without new evidence.
    assert added == 1
    assert [t.task_id for t in db.get_all_tasks("run")
            if t.task_id.startswith("t_gf_")] == ["t_gf_2"]
