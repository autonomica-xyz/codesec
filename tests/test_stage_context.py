"""StageContext.extras() — verify optional live_target / scope_notes
flow into agent user_input."""

from __future__ import annotations

from pathlib import Path

from codesec.config import HarnessConfig, StageConfig
from codesec.stages._common import StageContext, truncated_recon_summary


def _ctx(**kwargs) -> StageContext:
    cfg = HarnessConfig(stages={"hunt": StageConfig(
        name="hunt", model="x", concurrency=1, tools=["Read"],
        max_turns=10, permission_mode="default", repair_attempts=0)})
    return StageContext(run_id="r", repo_path=Path("/tmp"), config=cfg, **kwargs)


def test_extras_static_mode_is_explicit() -> None:
    """P04: static inputs always carry evidence_mode and explicit nulls so
    a prompt template example can never be mistaken for a real target."""
    e = _ctx().extras()
    assert e == {
        "evidence_mode": "static",
        "live_target": None,
        "markers": None,
    }


def test_extras_includes_live_target() -> None:
    lt = {"url": "http://x:8080", "credentials": {"email": "a", "password": "b"}}
    e = _ctx(live_target=lt).extras()
    assert e == {"evidence_mode": "live", "live_target": lt}
    assert "markers" not in e or e.get("markers") is None


def test_extras_includes_scope_notes() -> None:
    e = _ctx(scope_notes="Mailpit is out of scope.").extras()
    assert e["scope_notes"] == "Mailpit is out of scope."
    assert e["evidence_mode"] == "static"


def test_extras_includes_both() -> None:
    lt = {"url": "http://x:8080", "credentials": {}}
    e = _ctx(live_target=lt, scope_notes="notes").extras()
    assert "live_target" in e and "scope_notes" in e
    assert e["evidence_mode"] == "live"


def test_extras_skips_falsy_values() -> None:
    # empty dict / empty string degrade to static mode without noise
    assert _ctx(live_target={}).extras() == {
        "evidence_mode": "static", "live_target": None, "markers": None,
    }
    e = _ctx(scope_notes="").extras()
    assert "scope_notes" not in e


def test_explicit_run_paths_do_not_write_to_global_results(tmp_path: Path) -> None:
    ctx = _ctx(
        run_results_root=tmp_path / "results",
        run_work_root=tmp_path / "work",
    )

    assert ctx.results_dir("trace") == tmp_path / "results" / "trace"
    assert ctx.work_dir("hunt", "t_1") == tmp_path / "work" / "hunt" / "t_1"


def test_hunt_recon_summary_keeps_only_the_relevant_subsystem() -> None:
    full = {
        "architecture": {"entry_points": ["app.py:route"]},
        "subsystems": [
            {"name": "web", "path": "app/"},
            {"name": "workers", "path": "workers/"},
            {"name": "database", "path": "db/"},
        ],
    }

    packed = truncated_recon_summary(full, "workers/jobs.py")

    assert packed["architecture"] == full["architecture"]
    assert packed["subsystems"] == [{"name": "workers", "path": "workers/"}]
    assert packed["subsystem_for_task"]["name"] == "workers"
