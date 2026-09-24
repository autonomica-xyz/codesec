"""Stage 2: Hunt — concurrent single-attack-class hunters."""

from __future__ import annotations

import asyncio
import logging
from typing import Awaitable, Callable

from codesec.contracts import StageContractError, filter_hunt_findings
from codesec.hints import hints_for, load_hints
from codesec.runner import (
    AgentRunError,
    QuotaExhaustedError,
    TransientAgentError,
    run_agent,
)
from codesec.state import StateDB, Task
from codesec.stages._common import (
    StageContext,
    record_input_size,
    truncated_recon_summary,
)

log = logging.getLogger(__name__)


async def run_hunt(
    ctx: StageContext,
    db: StateDB,
    budget_check: Callable[[str], None] | None = None,
) -> int:
    """Run all pending Hunt tasks concurrently. Returns the number of
    findings emitted. If `budget_check` is provided, it is invoked
    before each task and may raise to abort the stage early."""
    pending = db.get_pending_tasks(ctx.run_id)
    if not pending:
        log.info("[%s] hunt: no pending tasks", ctx.run_id)
        return 0

    sc = ctx.stage("hunt")
    recon_summary = db.get_recon_output(ctx.run_id) or {}
    # Cap the carry-over list — a long-lived catalogue must not blow the
    # per-task input budget.
    prior_findings = db.get_prior_exclusions(ctx.run_id)[:60]
    hints: dict = {}
    if sc.options.get("hints_in_hunt", True):
        try:
            hints = load_hints()
        except Exception as e:
            log.warning("[%s] hunt: bypass hints unavailable: %s", ctx.run_id, e)
    sem = asyncio.Semaphore(sc.concurrency)
    aborted = asyncio.Event()

    log.info(
        "[%s] hunt: dispatching %d tasks (concurrency=%d, model=%s)",
        ctx.run_id, len(pending), sc.concurrency, sc.model,
    )

    counters = {"findings": 0, "tasks_done": 0, "tasks_failed": 0, "skipped": 0}

    async def _one(task: Task) -> None:
        async with sem:
            if aborted.is_set():
                counters["skipped"] += 1
                return
            if budget_check is not None:
                try:
                    budget_check(f"hunt/{task.task_id}")
                except Exception as e:
                    log.warning("[%s] hunt aborting: %s", ctx.run_id, e)
                    aborted.set()
                    counters["skipped"] += 1
                    return
            db.update_task_status(ctx.run_id, task.task_id, "running")
            scratch = ctx.work_dir("hunt", task.task_id)
            subsystem_hint = task.target_files[0] if task.target_files else None
            user_input = {
                "task_id": task.task_id,
                "attack_class": task.attack_class,
                "scope_hint": task.scope_hint,
                "target_files": task.target_files,
                "rationale": task.rationale,
                "repo_path": str(ctx.repo_path),
                "scratch_dir": str(scratch),
                "recon_summary": truncated_recon_summary(recon_summary, subsystem_hint),
                **ctx.extras(),
            }
            bypass = hints_for(
                hints,
                cwe=task.raw_json.get("cwe"),
                vuln_class=task.attack_class,
                attack_class=task.attack_class,
            )
            if bypass:
                user_input["bypass_hints"] = bypass
            policy = task.raw_json.get("policy")
            if isinstance(policy, dict):
                user_input["policy"] = policy
            if prior_findings:
                user_input["prior_findings"] = prior_findings
            record_input_size(db, ctx.run_id, "hunt", task.task_id, user_input)
            try:
                result = await run_agent(
                    stage="hunt",
                    prompt_file=ctx.prompt("02-hunt"),
                    user_input=user_input,
                    schema_file=ctx.schema("finding"),
                    allowed_tools=sc.tools,
                    model=sc.model,
                    profile=ctx.profile("hunt"),
                    cwd=scratch,
                    add_dirs=[ctx.repo_path],
                    max_turns=sc.max_turns,
                    permission_mode=sc.permission_mode,
                    artifact_dir=ctx.results_dir("hunt"),
                    artifact_name=task.task_id,
                    repair_attempts=sc.repair_attempts,
                    deadline=ctx.deadline,
                )
            except QuotaExhaustedError:
                # Subscription quota/session limit hit mid-flight. Don't burn
                # this task to 'failed' (which resume skips) — leave it
                # 'pending' and propagate so the pipeline aborts cleanly into
                # a resumable state. See orchestrator's QuotaExhaustedError
                # handler.
                log.error(
                    "[%s] hunt task %s hit subscription quota — aborting stage",
                    ctx.run_id, task.task_id,
                )
                db.update_task_status(ctx.run_id, task.task_id, "pending")
                aborted.set()
                raise
            except (AgentRunError, TransientAgentError) as e:
                log.warning("[%s] hunt task %s failed: %s", ctx.run_id, task.task_id, e)
                db.update_task_status(ctx.run_id, task.task_id, "failed")
                counters["tasks_failed"] += 1
                return
            except Exception as e:
                log.error("[%s] hunt task %s unexpected error: %s", ctx.run_id, task.task_id, e)
                db.update_task_status(ctx.run_id, task.task_id, "failed")
                counters["tasks_failed"] += 1
                return

            payload = result.payload
            db.record_agent_result(ctx.run_id, "hunt", task.task_id, result)
            if getattr(result, "repairs", None):
                # Deterministic output interventions (envelope bracket
                # repair, advisory quarantine) are visible degradation,
                # never a clean pass (plan step E.5).
                db.record_stage_event(
                    ctx.run_id,
                    "hunt",
                    {
                        "category": "degraded",
                        "reason": "model_output_repaired",
                        "task_id": task.task_id,
                        "repairs": result.repairs,
                    },
                )
            db.add_artifact(
                ctx.run_id,
                "hunt",
                task.task_id,
                "jsonl",
                str(result.artifact_path),
            )
            try:
                findings, dropped = filter_hunt_findings(
                    task.task_id,
                    payload,
                    ctx.repo_path,
                    reserved_finding_ids={
                        finding.finding_id
                        for finding in db.get_findings(ctx.run_id)
                    },
                )
            except StageContractError as error:
                log.warning(
                    "[%s] hunt task %s violated semantic contract: %s",
                    ctx.run_id,
                    task.task_id,
                    error,
                )
                db.update_task_status(ctx.run_id, task.task_id, "failed")
                counters["tasks_failed"] += 1
                return
            if dropped:
                log.warning(
                    "[%s] hunt task %s: quarantined %d invalid findings: %s",
                    ctx.run_id, task.task_id, len(dropped), dropped,
                )
                db.record_stage_event(
                    ctx.run_id,
                    "hunt",
                    {
                        "category": "degraded",
                        "reason": "quarantined_findings",
                        "task_id": task.task_id,
                        "dropped": dropped,
                    },
                )
            if payload.get("hardening"):
                db.record_hardening_notes(
                    ctx.run_id, task.task_id, payload["hardening"]
                )
            if payload.get("uncovered"):
                db.record_uncovered_surfaces(
                    ctx.run_id, task.task_id, payload["uncovered"]
                )
            for f in findings:
                db.add_finding(ctx.run_id, task.task_id, f)
                counters["findings"] += 1
            db.update_task_status(ctx.run_id, task.task_id, "done")
            db.add_artifact(ctx.run_id, "hunt", task.task_id, "scratch_dir",
                            str(scratch))
            counters["tasks_done"] += 1
            log.info(
                "[%s] hunt %s: %d findings (cost=$%.4f)",
                ctx.run_id, task.task_id, len(findings), result.cost_usd or 0.0,
            )

    await asyncio.gather(*(_one(t) for t in pending))
    log.info(
        "[%s] hunt: done=%d failed=%d skipped=%d findings=%d",
        ctx.run_id, counters["tasks_done"], counters["tasks_failed"],
        counters["skipped"], counters["findings"],
    )
    return counters["findings"]
