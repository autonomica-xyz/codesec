from __future__ import annotations

from pathlib import Path

import pytest

from codesec import orchestrator
from codesec.config import HarnessConfig, ModelProfile, StageConfig
from codesec.state import StateDB


async def test_pipeline_cannot_mark_partial_work_complete(
    tmp_path: Path, monkeypatch
) -> None:
    db = StateDB(tmp_path / "state.db")

    async def recon(ctx, state, **kwargs):
        payload = {"subsystems": [], "architecture": {}, "initial_tasks": []}
        state.save_recon_output(ctx.run_id, payload)
        state.add_task(
            ctx.run_id,
            {
                "task_id": "t_incomplete",
                "attack_class": "sqli",
                "scope_hint": "inspect the query construction",
                "target_files": ["app.py"],
                "rationale": "untrusted input reaches a database query",
                "priority": 1,
                "source": "recon",
            },
        )
        return payload

    async def no_findings(*args, **kwargs):
        return 0

    async def report(*args, **kwargs):
        return tmp_path / "report.json"

    monkeypatch.setattr(orchestrator.stages, "run_recon", recon)
    monkeypatch.setattr(orchestrator.stages, "run_hunt", no_findings)
    monkeypatch.setattr(orchestrator.stages, "run_validate", no_findings)
    monkeypatch.setattr(orchestrator.stages, "run_dedupe", no_findings)
    monkeypatch.setattr(orchestrator.stages, "run_trace", no_findings)
    monkeypatch.setattr(orchestrator.stages, "run_report", report)

    with pytest.raises(orchestrator.IncompleteRunError, match="t_incomplete"):
        await orchestrator.run_pipeline(
            repo_path=tmp_path,
            run_id="run",
            db=db,
            config=HarnessConfig(gapfill_iterations=0, feedback_iterations=0),
        )

    assert db.get_run("run")["status"] == "incomplete"


async def test_duo_pipeline_batches_hunts_before_validation(
    tmp_path: Path, monkeypatch
) -> None:
    db = StateDB(tmp_path / "state.db")
    calls: list[str] = []

    async def recon(ctx, state, **kwargs):
        calls.append("recon")
        assert kwargs == {"max_tasks": 20}
        payload = {"subsystems": [], "architecture": {}, "initial_tasks": []}
        state.save_recon_output(ctx.run_id, payload)
        return payload

    def stage(name: str, result: int = 0):
        async def run(*args, **kwargs):
            calls.append(name)
            return result

        return run

    async def report(*args, **kwargs):
        calls.append("deterministic_report")
        path = tmp_path / "report.json"
        path.write_text("{}")
        return path

    async def gapfill(*args, **kwargs):
        calls.append("gapfill")
        assert kwargs == {"max_new_tasks": 10}
        return 1

    monkeypatch.setattr(orchestrator.stages, "run_recon", recon)
    monkeypatch.setattr(orchestrator.stages, "run_hunt", stage("hunt"))
    monkeypatch.setattr(orchestrator.stages, "run_gapfill", gapfill)
    monkeypatch.setattr(orchestrator.stages, "run_validate", stage("validate"))
    monkeypatch.setattr(
        orchestrator.stages, "run_deterministic_dedupe", stage("dedupe")
    )
    monkeypatch.setattr(orchestrator.stages, "run_trace", stage("trace"))
    monkeypatch.setattr(
        orchestrator.stages, "run_deterministic_report", report, raising=False
    )

    await orchestrator.run_pipeline(
        repo_path=tmp_path,
        run_id="run",
        db=db,
        config=HarnessConfig(gapfill_iterations=1, feedback_iterations=1),
        pipeline="duo-v1",
    )

    assert calls == [
        "recon",
        "hunt",
        "gapfill",
        "hunt",
        "validate",
        "dedupe",
        "trace",
        "deterministic_report",
    ]
    assert db.get_run("run")["status"] == "completed"


async def test_duo_pipeline_switches_runtime_once_at_model_boundary(
    tmp_path: Path, monkeypatch
) -> None:
    db = StateDB(tmp_path / "state.db")
    calls: list[str] = []

    def stage_config(name: str, profile: str) -> StageConfig:
        return StageConfig(
            name=name,
            model=profile,
            concurrency=1,
            tools=["Read"],
            max_turns=5,
            permission_mode="acceptEdits",
            repair_attempts=1,
            profile=profile,
        )

    config = HarnessConfig(
        stages={
            name: stage_config(
                name,
                "titus" if name in {"recon", "hunt", "gapfill", "feedback"}
                else "openmythos",
            )
            for name in [
                "recon", "hunt", "gapfill", "feedback",
                "validate", "dedupe", "trace", "report",
            ]
        },
        model_profiles={
            "titus": ModelProfile(
                name="titus",
                engine="local",
                endpoint="http://127.0.0.1:8080",
                model="titus",
            ),
            "openmythos": ModelProfile(
                name="openmythos",
                engine="local",
                endpoint="http://127.0.0.1:8081",
                model="openmythos",
            ),
        },
        gapfill_iterations=0,
        feedback_iterations=0,
    )

    class FakeRuntime:
        async def ensure_ready(self, profile):
            calls.append(f"load:{profile.name}")

        async def close(self):
            calls.append("runtime:close")

    async def recon(ctx, state, **kwargs):
        calls.append("recon")
        payload = {"subsystems": [], "architecture": {}, "initial_tasks": []}
        state.save_recon_output(ctx.run_id, payload)
        return payload

    def stage(name: str):
        async def run(*args, **kwargs):
            calls.append(name)
            return 0

        return run

    async def report(*args, **kwargs):
        calls.append("report")
        path = tmp_path / "report.json"
        path.write_text("{}")
        return path

    monkeypatch.setattr(orchestrator.stages, "run_recon", recon)
    monkeypatch.setattr(orchestrator.stages, "run_hunt", stage("hunt"))
    monkeypatch.setattr(orchestrator.stages, "run_validate", stage("validate"))
    monkeypatch.setattr(
        orchestrator.stages, "run_deterministic_dedupe", stage("dedupe")
    )
    monkeypatch.setattr(orchestrator.stages, "run_trace", stage("trace"))
    monkeypatch.setattr(
        orchestrator.stages, "run_deterministic_report", report
    )

    await orchestrator.run_pipeline(
        repo_path=tmp_path,
        run_id="run",
        db=db,
        config=config,
        pipeline="duo-v1",
        runtime=FakeRuntime(),
    )

    assert calls == [
        "load:titus",
        "recon",
        "hunt",
        "load:openmythos",
        "validate",
        "dedupe",
        "trace",
        "report",
        "runtime:close",
    ]


async def test_duo_resume_at_validation_does_not_reload_titus_or_gapfill(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db = StateDB(tmp_path / "state.db")
    db.create_run(str(tmp_path), "run")
    db.save_recon_output(
        "run", {"subsystems": [], "architecture": {}, "initial_tasks": []}
    )
    db.add_task(
        "run",
        {
            "task_id": "t_1",
            "attack_class": "sqli",
            "scope_hint": "query sink",
            "target_files": ["app.py"],
            "rationale": "request data reaches query",
            "priority": 1,
            "source": "recon",
        },
    )
    db.update_task_status("run", "t_1", "done")
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
            "description": "Request data is interpolated into a query.",
            "evidence_snippet": "execute(query)",
            "confidence": 0.9,
        },
    )
    db.add_artifact(
        "run", "gapfill", None, "checkpoint", "completed"
    )
    calls: list[str] = []

    class Runtime:
        async def ensure_ready(self, profile):
            calls.append(f"load:{profile.name}")

        async def close(self):
            calls.append("close")

    async def recon(*args, **kwargs):
        calls.append("recon:skip")

    async def hunt(*args, **kwargs):
        calls.append("hunt:skip")
        return 0

    async def gapfill(*args, **kwargs):
        raise AssertionError("completed gapfill must not rerun")

    async def validate(ctx, state):
        calls.append("validate")
        state.set_finding_validation(
            ctx.run_id,
            "f_1",
            "rejected",
            {"finding_id": "f_1", "verdict": "rejected"},
        )
        return 0

    async def empty(name, *args, **kwargs):
        calls.append(name)
        return 0

    async def report(*args, **kwargs):
        calls.append("report")
        path = tmp_path / "report.json"
        path.write_text("{}")
        return path

    monkeypatch.setattr(orchestrator.stages, "run_recon", recon)
    monkeypatch.setattr(orchestrator.stages, "run_hunt", hunt)
    monkeypatch.setattr(orchestrator.stages, "run_gapfill", gapfill)
    monkeypatch.setattr(orchestrator.stages, "run_validate", validate)
    monkeypatch.setattr(
        orchestrator.stages,
        "run_deterministic_dedupe",
        lambda *args, **kwargs: empty("dedupe", *args, **kwargs),
    )
    monkeypatch.setattr(
        orchestrator.stages,
        "run_trace",
        lambda *args, **kwargs: empty("trace", *args, **kwargs),
    )
    monkeypatch.setattr(
        orchestrator.stages, "run_deterministic_report", report
    )

    profiles = {
        "titus": ModelProfile(
            name="titus",
            engine="local",
            endpoint="http://127.0.0.1:8080",
            model="titus",
        ),
        "openmythos": ModelProfile(
            name="openmythos",
            engine="local",
            endpoint="http://127.0.0.1:8081",
            model="openmythos",
        ),
    }
    config = HarnessConfig(
        stages={
            stage_name: StageConfig(
                name=stage_name,
                model=profile_name,
                concurrency=1,
                tools=["Read"],
                max_turns=2,
                permission_mode="acceptEdits",
                repair_attempts=0,
                profile=profile_name,
            )
            for stage_name, profile_name in {
                "recon": "titus",
                "hunt": "titus",
                "gapfill": "titus",
                "feedback": "titus",
                "validate": "openmythos",
                "dedupe": "openmythos",
                "trace": "openmythos",
                "report": "openmythos",
            }.items()
        },
        model_profiles=profiles,
        gapfill_iterations=1,
        feedback_iterations=0,
    )

    await orchestrator.run_pipeline(
        repo_path=tmp_path,
        run_id="run",
        db=db,
        config=config,
        pipeline="duo-v1",
        resume=True,
        runtime=Runtime(),
    )

    assert calls == [
        "recon:skip",
        "hunt:skip",
        "load:openmythos",
        "validate",
        "dedupe",
        "trace",
        "report",
        "close",
    ]


async def test_max_hours_closing_mode_skips_breadth_but_reports(
    tmp_path: Path, monkeypatch
) -> None:
    db = StateDB(tmp_path / "state.db")
    calls: list[str] = []

    async def recon(ctx, state, **kwargs):
        payload = {"subsystems": [], "architecture": {}, "initial_tasks": []}
        state.save_recon_output(ctx.run_id, payload)
        return payload

    async def no_findings(*args, **kwargs):
        return 0

    async def report(*args, **kwargs):
        calls.append("report")
        return tmp_path / "report.json"

    def track(name):
        async def _stage(*args, **kwargs):
            calls.append(name)
            return 0
        return _stage

    monkeypatch.setattr(orchestrator.stages, "run_recon", recon)
    monkeypatch.setattr(orchestrator.stages, "run_hunt", track("hunt"))
    monkeypatch.setattr(orchestrator.stages, "run_validate", no_findings)
    monkeypatch.setattr(orchestrator.stages, "run_gapfill", track("gapfill"))
    monkeypatch.setattr(orchestrator.stages, "run_dedupe", no_findings)
    monkeypatch.setattr(orchestrator.stages, "run_trace", no_findings)
    monkeypatch.setattr(orchestrator.stages, "run_feedback", track("feedback"))
    monkeypatch.setattr(orchestrator.stages, "run_report", report)

    # A microscopically small budget: _closing() is true immediately, so
    # gapfill and feedback must be skipped while dedupe/trace/report run.
    report_path = await orchestrator.run_pipeline(
        repo_path=tmp_path,
        run_id="run",
        db=db,
        config=HarnessConfig(gapfill_iterations=2, feedback_iterations=2),
        max_hours=1e-9,
    )

    assert report_path == tmp_path / "report.json"
    assert "gapfill" not in calls
    assert "feedback" not in calls
    assert calls.count("hunt") == 1  # first wave only, no feedback hunts
    assert "report" in calls
    assert db.get_run("run")["status"] == "completed"


async def test_no_max_hours_runs_full_loop(
    tmp_path: Path, monkeypatch
) -> None:
    db = StateDB(tmp_path / "state.db")
    calls: list[str] = []

    async def recon(ctx, state, **kwargs):
        payload = {"subsystems": [], "architecture": {}, "initial_tasks": []}
        state.save_recon_output(ctx.run_id, payload)
        return payload

    def track(name, ret=0):
        async def _stage(*args, **kwargs):
            calls.append(name)
            return ret
        return _stage

    async def report(*args, **kwargs):
        calls.append("report")
        return tmp_path / "report.json"

    monkeypatch.setattr(orchestrator.stages, "run_recon", recon)
    monkeypatch.setattr(orchestrator.stages, "run_hunt", track("hunt"))
    monkeypatch.setattr(orchestrator.stages, "run_validate", track("validate"))
    # gapfill returns 0 new tasks -> loop exits after one gapfill call
    monkeypatch.setattr(orchestrator.stages, "run_gapfill", track("gapfill"))
    monkeypatch.setattr(orchestrator.stages, "run_dedupe", track("dedupe"))
    monkeypatch.setattr(orchestrator.stages, "run_trace", track("trace"))
    monkeypatch.setattr(orchestrator.stages, "run_report", report)

    await orchestrator.run_pipeline(
        repo_path=tmp_path,
        run_id="run",
        db=db,
        config=HarnessConfig(gapfill_iterations=1, feedback_iterations=0),
    )

    assert "gapfill" in calls
    assert "report" in calls
    assert db.get_run("run")["status"] == "completed"


async def test_prior_path_requires_catalogue_db(tmp_path: Path) -> None:
    """--prior=path without --catalogue-db must error, not silently fall
    back to the default catalogue location."""
    db = StateDB(tmp_path / "state.db")
    with pytest.raises(ValueError, match="catalogue-db"):
        await orchestrator.run_pipeline(
            repo_path=tmp_path,
            run_id="r",
            db=db,
            config=HarnessConfig(gapfill_iterations=0, feedback_iterations=0),
            prior="path",
        )
