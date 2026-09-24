"""Shared test helper: write the H run's stage-health evidence.

A clean H completion now requires terminal 'complete' stage health in the
run state DB (plan step E.5). Fake arms that simulate a healthy H run
write exactly the evidence a real healthy run writes.
"""

from __future__ import annotations

from pathlib import Path

REQUIRED_STAGES = ("recon", "hunt", "validate", "dedupe", "trace", "report")


def write_healthy_h_state(output_dir: Path, run_id: str = "x") -> None:
    from codesec.state import StateDB

    db = StateDB(output_dir / "run" / "state.db")
    for stage in REQUIRED_STAGES:
        db.record_stage_event(run_id, stage, {"phase": "start"})
        db.record_stage_event(
            run_id, stage, {"phase": "end", "status": "complete"}
        )
    db._conn.commit()


def write_degraded_h_state(
    output_dir: Path, run_id: str = "x", stage: str = "hunt",
    reason: str = "model_output_repaired",
) -> None:
    """Healthy everywhere except one degraded stage (e.g. a repaired model
    output or a failed hunt task)."""
    from codesec.state import StateDB

    db = StateDB(output_dir / "run" / "state.db")
    for name in REQUIRED_STAGES:
        db.record_stage_event(run_id, name, {"phase": "start"})
        if name == stage:
            end = {
                "phase": "end", "status": "degraded",
                "degraded_reasons": [reason],
            }
        else:
            end = {"phase": "end", "status": "complete"}
        db.record_stage_event(run_id, name, end)
    db._conn.commit()
