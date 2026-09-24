"""P05 deadline enforcement: fake-clock closing semantics, bounded retries,
hung-request/tool termination, and stage-health records."""

from __future__ import annotations

import asyncio
import json
import socket
import subprocess
import threading
import time
from pathlib import Path

import pytest

from codesec.config import HarnessConfig, StageConfig
from codesec.deadline import (
    FINAL_SNAPSHOT_RESERVE_S,
    SYNTHESIS_RESERVE_FRACTION,
    Deadline,
    TimeBudgetExceeded,
)
from codesec import local_agent, runner
from codesec.runner import AgentResult, TransientAgentError
from codesec.state import StateDB
from codesec.stages import dedupe as dedupe_stage


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def test_two_hour_budget_not_closing_at_minute_24():
    clock = FakeClock()
    deadline = Deadline(2 * 3600, clock=clock)
    clock.advance(24 * 60)
    assert not deadline.closing()
    assert not deadline.exhausted()


def test_two_hour_budget_closing_at_minute_96():
    clock = FakeClock()
    deadline = Deadline(2 * 3600, clock=clock)
    clock.advance(96 * 60)
    assert deadline.closing()
    assert not deadline.exhausted(), "80% elapsed still leaves synthesis time"


def test_three_hour_budget_closing_at_minute_144():
    clock = FakeClock()
    deadline = Deadline(3 * 3600, clock=clock)
    clock.advance(144 * 60)
    assert deadline.closing()


def test_snapshot_reserve_means_exhausted():
    clock = FakeClock()
    deadline = Deadline(600, clock=clock)
    clock.advance(600 - FINAL_SNAPSHOT_RESERVE_S)
    assert deadline.exhausted()
    with pytest.raises(TimeBudgetExceeded, match="snapshot reserve"):
        deadline.check("anything")


def test_request_timeout_bounded_by_remaining_time():
    clock = FakeClock()
    deadline = Deadline(100, clock=clock)
    clock.advance(90)  # 10 s left (+30 s snapshot allowance)
    assert deadline.request_timeout(1200.0) == 40.0
    clock.advance(20)  # past the end
    assert deadline.request_timeout(1200.0) <= 0.001


async def test_backoff_never_sleeps_past_deadline_or_restarts(monkeypatch):
    clock = FakeClock()
    deadline = Deadline(40, clock=clock)  # > 30 s snapshot reserve
    attempts = {"n": 0}

    async def failing(**kwargs):
        attempts["n"] += 1
        raise TransientAgentError("upstream 503")

    monkeypatch.setattr(runner, "_run_agent_once", failing)

    real_sleep = asyncio.sleep

    async def fast_sleep(seconds):
        # Emulate the deadline's clamp AND its exhaustion semantics without
        # waiting wall time.
        clock.advance(deadline.clamp_sleep(seconds))
        await real_sleep(0)
        if deadline.exhausted():
            raise TimeBudgetExceeded(
                "backoff sleep reached the budget; not restarting the request"
            )

    original_sleep = Deadline.sleep
    Deadline.sleep = lambda self, s: fast_sleep(s)
    try:
        with pytest.raises(TimeBudgetExceeded):
            await runner.run_agent(
                stage="hunt",
                prompt_file=Path("/nonexistent.md"),
                user_input={},
                schema_file=Path("/nonexistent.json"),
                allowed_tools=[],
                model="m",
                cwd=Path("."),
                artifact_dir=Path("/tmp"),
                artifact_name="t",
                transient_retries=5,
                transient_base_delay=30.0,
                deadline=deadline,
            )
    finally:
        Deadline.sleep = original_sleep

    # The request that failed at budget end is NOT restarted.
    assert attempts["n"] == 1


async def test_run_agent_refuses_to_start_after_exhaustion():
    deadline = Deadline(1.0)
    deadline.clock = lambda: deadline.start + 100  # long past the end

    with pytest.raises(TimeBudgetExceeded):
        await runner.run_agent(
            stage="trace",
            prompt_file=Path("/nonexistent.md"),
            user_input={},
            schema_file=Path("/nonexistent.json"),
            allowed_tools=[],
            model="m",
            cwd=Path("."),
            artifact_dir=Path("/tmp"),
            artifact_name="t",
            deadline=deadline,
        )


def test_hung_model_call_is_bounded_by_deadline():
    """A server that accepts and never responds must not outlive the
    budget: the socket timeout is bounded by the remaining time."""
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    def accept_and_hang():
        try:
            while True:
                conn, _ = server.accept()
                # never respond; hold the socket far beyond the budget
                time.sleep(600)
                conn.close()
        except OSError:
            pass

    threading.Thread(target=accept_and_hang, daemon=True).start()

    deadline_ts = time.monotonic() + 1.5
    started = time.monotonic()
    with pytest.raises(TransientAgentError):
        local_agent._chat(
            f"http://127.0.0.1:{port}/v1",
            None,
            "m",
            [{"role": "user", "content": "x"}],
            [],
            0.6,
            64,
            deadline_ts=deadline_ts,
        )
    elapsed = time.monotonic() - started
    # Bounded by remaining time + the 30 s snapshot allowance — never the
    # peer's 600 s hang.
    assert elapsed <= 35, (
        f"hung peer must be abandoned within the budget bound ({elapsed:.1f}s)"
    )
    server.close()


def test_hanging_bash_tool_is_killed_with_its_process_group(tmp_path):
    """A child shell that exceeds the remaining budget is terminated as a
    process group — no orphan survives."""
    deadline_ts = time.monotonic() + 1.0
    started = time.monotonic()
    out = local_agent._exec_tool(
        "bash",
        {"command": "sleep 60", "timeout": 60},
        tmp_path,
        deadline_ts=deadline_ts,
    )
    elapsed = time.monotonic() - started
    assert "bash timeout" in out
    assert elapsed < 15, "hanging child must be killed promptly"
    time.sleep(0.3)
    survivors = subprocess.run(
        ["pgrep", "-f", "sleep 60"], capture_output=True, text=True
    ).stdout.strip()
    assert survivors == "", f"orphan process left behind: {survivors}"


def test_bash_grandchildren_die_with_the_group(tmp_path):
    """`bash -c 'bash -c "sleep 60"'` — the whole group dies, not just the
    direct child."""
    deadline_ts = time.monotonic() + 1.0
    out = local_agent._exec_tool(
        "bash",
        {"command": "bash -c 'sleep 60 & wait'", "timeout": 60},
        tmp_path,
        deadline_ts=deadline_ts,
    )
    assert "bash timeout" in out
    time.sleep(0.3)
    survivors = subprocess.run(
        ["pgrep", "-f", "sleep 60"], capture_output=True, text=True
    ).stdout.strip()
    assert survivors == ""


async def test_dedupe_batch_failure_in_ledger_with_valid_report(tmp_path):
    """A failed dedupe batch and a task failure are visible in the stage
    ledger even when a valid report exists."""
    db = StateDB(tmp_path / "state.db")
    db.create_run(str(tmp_path), "run")
    db.add_task("run", {
        "task_id": "t_1", "attack_class": "sqli", "scope_hint": "s",
        "target_files": ["app.py"], "rationale": "r", "priority": 1,
        "source": "recon",
    })
    db.update_task_status("run", "t_1", "failed")
    db.record_stage_event("run", "dedupe", {
        "category": "degraded", "reason": "batch_failed",
        "batch_id": "dedupe-batch-0001", "error": "upstream 500: boom",
    })
    db.record_stage_event("run", "report", {
        "category": "intended", "renderer": "deterministic",
    })

    events = db.get_stage_events("run")
    degraded = [e for e in events if e["category"] == "degraded"]
    intended = [e for e in events if e["category"] == "intended"]
    assert any(e["reason"] == "batch_failed" for e in degraded)
    assert any(e.get("renderer") == "deterministic" for e in intended)
    failed_tasks = db.get_all_tasks("run")
    assert [t.status for t in failed_tasks] == ["failed"]


async def test_atomic_report_write_never_shadows_valid_snapshot(tmp_path):
    """A serializer crash mid-write leaves the previous valid document
    intact (tmp+rename semantics)."""
    from codesec.stages.report import _atomic_write_json

    path = tmp_path / "report.json"
    _atomic_write_json(path, {"findings": ["valid"]})
    good = path.read_text()

    class Unserializable:
        pass

    with pytest.raises(TypeError):
        _atomic_write_json(path, {"findings": Unserializable()})

    assert path.read_text() == good
    leftovers = [p.name for p in tmp_path.iterdir() if p.name != "report.json"]
    assert leftovers == [], f"temp files left behind: {leftovers}"


async def test_stage_health_records_budget_limited_status(tmp_path):
    """TimeBudgetExceeded inside a wrapped stage records budget_limited,
    not failed."""
    from codesec.orchestrator import _StageHealth

    db = StateDB(tmp_path / "state.db")
    db.create_run(str(tmp_path), "run")
    config = HarnessConfig(stages={
        "hunt": StageConfig(name="hunt", model="m", concurrency=4,
                            tools=["Read"], max_turns=2,
                            permission_mode="default", repair_attempts=0),
    })
    health = _StageHealth(db, "run", config)

    with pytest.raises(TimeBudgetExceeded):
        with health.wrap("hunt", intended="llm-hunt"):
            raise TimeBudgetExceeded("budget gone")

    events = [
        e for e in db.get_stage_events("run", "hunt")
        if e["category"] == "stage_health"
    ]
    assert events[0]["phase"] == "start"
    assert events[1]["phase"] == "end"
    assert events[1]["status"] == "budget_limited"
    assert events[1]["error_category"] == "time_budget"
    assert events[1]["model"] == "m"
    assert events[1]["concurrency"] == 4


def test_synthesis_reserve_fraction_is_documented():
    assert SYNTHESIS_RESERVE_FRACTION == 0.20
