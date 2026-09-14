from __future__ import annotations

from pathlib import Path

from codesec.config import HarnessConfig, StageConfig
from codesec.runner import AgentResult
from codesec.state import StateDB
from codesec.stages import recon as recon_stage
from codesec.stages._common import StageContext


def _context(repo: Path, hunt_options: dict | None = None) -> StageContext:
    config = HarnessConfig(
        stages={
            "recon": StageConfig(
                name="recon",
                model="mapper",
                concurrency=1,
                tools=["Read"],
                max_turns=2,
                permission_mode="acceptEdits",
                repair_attempts=0,
            ),
            "hunt": StageConfig(
                name="hunt",
                model="hunter",
                concurrency=1,
                tools=["Read"],
                max_turns=2,
                permission_mode="acceptEdits",
                repair_attempts=0,
                options=hunt_options or {},
            ),
        }
    )
    return StageContext(
        run_id="run",
        repo_path=repo,
        config=config,
        run_results_root=repo / "results",
        run_work_root=repo / "work",
    )


def _task(task_id: str) -> dict:
    return {
        "task_id": task_id,
        "attack_class": "command_injection",
        "scope_hint": "app.py run() interpolates `name` into a shell command",
        "target_files": ["app.py"],
        "rationale": "untrusted `name` reaches subprocess.run with shell=True",
        "priority": 3,
    }


def test_assign_hunt_policies_round_robin() -> None:
    tasks = [_task(f"t_{i}") for i in range(5)]
    recon_stage.assign_hunt_policies(tasks)
    assert [t["policy"]["search_mode"] for t in tasks] == [
        "breadth", "depth", "recombine", "breadth", "depth",
    ]
    assert all("attempts_budget" in t["policy"] for t in tasks)
    # deterministic: same input, same output
    again = [_task(f"t_{i}") for i in range(5)]
    recon_stage.assign_hunt_policies(again)
    assert [t["policy"] for t in again] == [t["policy"] for t in tasks]


def test_assign_hunt_policies_preserves_model_emitted_fields() -> None:
    tasks = [
        {**_task("t_0"), "policy": {"search_mode": "depth"}},
        {**_task("t_1"), "policy": {"report_partial": True}},
    ]
    recon_stage.assign_hunt_policies(tasks)
    assert tasks[0]["policy"]["search_mode"] == "depth"  # model's pick wins
    assert "attempts_budget" in tasks[0]["policy"]       # defaults fill gaps
    assert tasks[1]["policy"]["search_mode"] == "depth"  # cycle slot 1
    assert tasks[1]["policy"]["report_partial"] is True


async def test_run_recon_assigns_policies_only_when_enabled(
    tmp_path: Path, monkeypatch
) -> None:
    (tmp_path / "app.py").write_text("x = 1\n")

    async def fake_run_agent(**kwargs):
        artifact = Path(kwargs["artifact_dir"]) / "recon.jsonl"
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.write_text("{}\n")
        return AgentResult(
            payload={
                "subsystems": [],
                "architecture": {},
                "initial_tasks": [_task(f"t_{i}") for i in range(4)],
            },
            cost_usd=0.0,
            input_tokens=0,
            output_tokens=0,
            cache_read_tokens=0,
            cache_creation_tokens=0,
            num_turns=1,
            duration_ms=0,
            session_id=None,
            artifact_path=artifact,
            repair_used=False,
        )

    monkeypatch.setattr(recon_stage, "run_agent", fake_run_agent)

    db = StateDB(tmp_path / "on.db")
    db.create_run(str(tmp_path), "run")
    payload = await recon_stage.run_recon(
        _context(tmp_path, {"policies": True}), db
    )
    modes = [t["policy"]["search_mode"] for t in payload["initial_tasks"]]
    assert modes == ["breadth", "depth", "recombine", "breadth"]
    stored = {t.task_id: t for t in db.get_all_tasks("run")}
    assert stored["t_2"].raw_json["policy"]["search_mode"] == "recombine"

    db2 = StateDB(tmp_path / "off.db")
    db2.create_run(str(tmp_path), "run")
    payload = await recon_stage.run_recon(_context(tmp_path), db2)
    assert all("policy" not in t for t in payload["initial_tasks"])
    assert all(
        "policy" not in t.raw_json for t in db2.get_all_tasks("run")
    )
