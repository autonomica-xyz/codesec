"""Stage 1: Recon — map the repo, emit initial hunt tasks."""

from __future__ import annotations

import logging

from codesec.contracts import filter_task_batch
from codesec.runner import run_agent
from codesec.state import StateDB
from codesec.stages._common import StageContext

log = logging.getLogger(__name__)

DEFAULT_MAX_TASKS = 80

# Hunt strategy policies (W11), cycled round-robin across the task list
# when hunt.policies is enabled. Deterministic post-pass — not a prompt
# instruction — so ablations can flip it in config and compare.
POLICY_CYCLE: tuple[dict, ...] = (
    {"search_mode": "breadth", "attempts_budget": 20,
     "designer_trust": 0.5, "report_partial": True},
    {"search_mode": "depth", "attempts_budget": 10,
     "designer_trust": 0.5, "report_partial": False},
    {"search_mode": "recombine", "attempts_budget": 15,
     "designer_trust": 0.3, "report_partial": True},
)


def assign_hunt_policies(tasks: list[dict]) -> None:
    """Assign a `policy` to each task, cycling breadth/depth/recombine.

    A model-emitted `policy` dict is kept and only missing subfields are
    filled from the cycle default; anything else is replaced."""
    for index, task in enumerate(tasks):
        default = POLICY_CYCLE[index % len(POLICY_CYCLE)]
        existing = task.get("policy")
        if isinstance(existing, dict):
            task["policy"] = {**default, **existing}
        else:
            task["policy"] = dict(default)


async def run_recon(ctx: StageContext, db: StateDB, max_tasks: int = DEFAULT_MAX_TASKS) -> dict:
    if db.get_recon_output(ctx.run_id) is not None:
        log.info("[%s] recon already complete, skipping", ctx.run_id)
        return db.get_recon_output(ctx.run_id)  # type: ignore[return-value]

    sc = ctx.stage("recon")
    log.info("[%s] recon: model=%s max_tasks=%d", ctx.run_id, sc.model, max_tasks)

    result = await run_agent(
        stage="recon",
        prompt_file=ctx.prompt("01-recon"),
        user_input={"repo_path": str(ctx.repo_path), "max_tasks": max_tasks,
                    **ctx.extras()},
        schema_file=ctx.schema("recon_output"),
        allowed_tools=sc.tools,
        model=sc.model,
        profile=ctx.profile("recon"),
        cwd=ctx.repo_path,
        add_dirs=[ctx.repo_path],
        max_turns=sc.max_turns,
        permission_mode=sc.permission_mode,
        artifact_dir=ctx.results_dir("recon"),
        artifact_name="recon",
        repair_attempts=sc.repair_attempts,
    )

    payload = result.payload
    db.record_agent_result(ctx.run_id, "recon", None, result)
    db.add_artifact(ctx.run_id, "recon", None, "jsonl", str(result.artifact_path))
    raw_tasks = payload.get("initial_tasks", []) or []
    kept = filter_task_batch(raw_tasks, ctx.repo_path)
    dropped = len(raw_tasks) - len(kept)
    if dropped:
        log.warning(
            "[%s] recon: dropped %d task(s) with missing/outside targets",
            ctx.run_id,
            dropped,
        )
    if (
        "hunt" in ctx.config.stages
        and ctx.stage("hunt").options.get("policies", False)
    ):
        assign_hunt_policies(kept)
    payload["initial_tasks"] = kept
    db.save_recon_output(ctx.run_id, payload)

    for task in payload.get("initial_tasks", []):
        task.setdefault("source", "recon")
        db.add_task(ctx.run_id, task)

    log.info(
        "[%s] recon done: subsystems=%d entry_points=%d initial_tasks=%d cost=$%.4f",
        ctx.run_id,
        len(payload.get("subsystems", [])),
        len(payload.get("architecture", {}).get("entry_points", [])),
        len(payload.get("initial_tasks", [])),
        result.cost_usd or 0.0,
    )
    return payload
