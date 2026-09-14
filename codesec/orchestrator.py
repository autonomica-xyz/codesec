"""Pipeline driver: Recon → (Hunt → Validate → Gapfill)* → Dedupe → Trace
                  → Feedback → (Hunt → Validate → Dedupe → Trace)* → Report
"""

from __future__ import annotations

import logging
import time
from pathlib import Path

from codesec import stages
from codesec.config import HarnessConfig
from codesec.runner import QuotaExhaustedError
from codesec.runtime import ModelRuntime
from codesec.state import StateDB
from codesec.stages._common import StageContext

log = logging.getLogger(__name__)


class CostExceeded(RuntimeError):
    pass


class TimeBudgetExceeded(RuntimeError):
    """Wall-clock budget exhausted (raised by the breadth-stage gate
    passed into Hunt; Hunt swallows it per task, so this escaping
    run_pipeline signals a bug, not a normal abort)."""


# Closing mode (idea from round_table's Merlin): once this fraction of
# the time budget has elapsed, stop opening new breadth (gapfill,
# feedback iterations, second hunt waves) and spend what remains on
# validating and reporting what already exists.
_CLOSING_FRACTION = 0.8


class IncompleteRunError(RuntimeError):
    """The pipeline returned, but one or more stage inputs lack terminal work."""


async def run_pipeline(
    *,
    repo_path: Path,
    run_id: str,
    db: StateDB,
    config: HarnessConfig,
    max_cost_usd: float | None = None,
    max_hours: float | None = None,
    resume: bool = False,
    max_recon_tasks: int | None = None,
    live_target: dict | None = None,
    scope_notes: str | None = None,
    pipeline: str = "legacy",
    run_results_root: Path | None = None,
    run_work_root: Path | None = None,
    runtime: ModelRuntime | None = None,
    prior: str = "auto",
    catalogue_db: Path | None = None,
    upstream: str | None = None,
) -> Path:
    if pipeline not in {"legacy", "duo-v1"}:
        raise ValueError(f"unknown pipeline {pipeline!r}")
    if prior not in {"auto", "off", "path"}:
        raise ValueError(f"unknown prior mode {prior!r}")
    if prior == "path" and catalogue_db is None:
        raise ValueError("--prior=path requires --catalogue-db")

    # W8 cross-run catalogue: resolve the catalogue path once. "auto" uses
    # <repo>/.codesec-catalogue.db when it exists; "path" requires
    # catalogue_db; "off" disables prior carry entirely.
    resolved_catalogue: Path | None = None
    if prior != "off":
        candidate = catalogue_db or repo_path.resolve() / ".codesec-catalogue.db"
        if candidate.exists() or catalogue_db is not None or prior == "path":
            resolved_catalogue = candidate

    ctx = StageContext(
        run_id=run_id,
        repo_path=repo_path.resolve(),
        config=config,
        live_target=live_target,
        scope_notes=scope_notes,
        run_results_root=run_results_root,
        run_work_root=run_work_root,
        catalogue_db=resolved_catalogue,
        upstream=upstream,
    )

    if db.get_run(run_id) is None:
        db.create_run(str(repo_path.resolve()), run_id)
        log.info("[%s] starting fresh pipeline run against %s", run_id, repo_path)
    elif resume:
        # Flip status back to 'running' so subsequent /status calls don't
        # report a stale 'aborted'/'failed' while resume work is ongoing.
        db.resume_run(run_id)
        # Re-queue any task left 'running' (interrupted mid-flight by a quota
        # abort or crash) or 'failed' (transient/quota error) so resume
        # actually re-attempts the incomplete work instead of skipping it —
        # Hunt only dispatches 'pending' tasks.
        requeued = db.reset_incomplete_tasks(run_id)
        if requeued:
            log.info("[%s] resume: re-queued %d interrupted/failed tasks", run_id, requeued)
        log.info("[%s] resuming existing run", run_id)
    else:
        raise RuntimeError(
            f"run_id {run_id!r} already exists; pass --resume to continue it."
        )

    if resolved_catalogue is not None and not resume:
        # Run-start catalogue carry (W8): exclusion list for Hunt +
        # revalidation tasks for drifted priors + refuted seeds for Gapfill.
        try:
            from codesec.catalogue import prepare_priors

            priors = prepare_priors(
                db, run_id, repo_path.resolve(), resolved_catalogue
            )
            for task in priors.get("revalidate_tasks") or []:
                db.add_task(run_id, task)
            if priors.get("carried") or priors.get("revalidate_tasks"):
                log.info(
                    "[%s] catalogue: %d exclusions carried, %d revalidate "
                    "tasks, %d drifted priors",
                    run_id,
                    priors.get("carried", 0),
                    len(priors.get("revalidate_tasks") or []),
                    priors.get("drifted", 0),
                )
        except Exception as e:
            log.warning("[%s] catalogue prepare_priors failed: %s", run_id, e)

    def _budget_check(stage_name: str) -> None:
        if max_cost_usd is None:
            return
        spent = db.total_cost(run_id)
        if spent >= max_cost_usd:
            raise CostExceeded(
                f"[{run_id}] budget exhausted before {stage_name}: "
                f"${spent:.4f} >= ${max_cost_usd:.4f}"
            )

    started = time.monotonic()
    deadline = started + max_hours * 3600.0 if max_hours else None

    def _closing() -> bool:
        if deadline is None:
            return False
        return (deadline - time.monotonic()) <= _CLOSING_FRACTION * (
            deadline - started
        )

    def _breadth_check(stage_name: str) -> None:
        """Cost gate + hard wall-clock gate for breadth work (Hunt tasks).
        Hunt catches any exception from this and skips the remaining
        tasks, so the pipeline falls through to synthesis instead of
        aborting."""
        _budget_check(stage_name)
        if deadline is not None and time.monotonic() >= deadline:
            raise TimeBudgetExceeded(
                f"[{run_id}] time budget of {max_hours}h exhausted before "
                f"{stage_name}"
            )

    try:
        if pipeline == "duo-v1" and runtime is not None:
            needs_titus = (
                not resume
                or db.get_recon_output(run_id) is None
                or bool(db.get_pending_tasks(run_id))
                or (
                    config.gapfill_iterations > 0
                    and db.artifact_count(
                        run_id, "gapfill", kind="checkpoint"
                    ) == 0
                )
            )
            if needs_titus:
                titus_profile = config.profile_for_stage("recon")
                if titus_profile is None:
                    raise ValueError(
                        "duo-v1 runtime requires a model profile for recon"
                    )
                await runtime.ensure_ready(titus_profile)

        # ---- Stage 1: Recon ----
        _budget_check("recon")
        effective_recon_tasks = max_recon_tasks
        if effective_recon_tasks is None and pipeline == "duo-v1":
            # Small local models produce more reliable, cheaper recon output
            # with a bounded first wave. Gapfill can add one evidence-driven
            # second wave instead of asking Recon for an 80-task monolith.
            effective_recon_tasks = 20
        recon_kwargs = (
            {}
            if effective_recon_tasks is None
            else {"max_tasks": effective_recon_tasks}
        )
        await stages.run_recon(ctx, db, **recon_kwargs)

        if pipeline == "duo-v1":
            # Batch all Titus-role work before any OpenMythos-role work. This
            # is the minimum viable two-model path and avoids the legacy
            # Hunt → Validate → Gapfill model thrash.
            _budget_check("hunt(wave=1)")
            await stages.run_hunt(ctx, db, budget_check=_budget_check)

            if config.gapfill_iterations > 0:
                if db.artifact_count(
                    run_id, "gapfill", kind="checkpoint"
                ) > 0:
                    log.info(
                        "[%s] gapfill wave already complete, skipping",
                        run_id,
                    )
                    new_tasks = 0
                else:
                    _budget_check("gapfill(wave=1)")
                    new_tasks = await stages.run_gapfill(
                        ctx, db, max_new_tasks=10
                    )
                if new_tasks:
                    _budget_check("hunt(wave=2)")
                    await stages.run_hunt(ctx, db, budget_check=_budget_check)

            if runtime is not None:
                openmythos_profile = config.profile_for_stage("validate")
                if openmythos_profile is None:
                    raise ValueError(
                        "duo-v1 runtime requires a model profile for validate"
                    )
                await runtime.ensure_ready(openmythos_profile)

            _budget_check("validate")
            await stages.run_validate(ctx, db)
            _budget_check("dedupe")
            await stages.run_deterministic_dedupe(ctx, db)
            _budget_check("trace")
            await stages.run_trace(ctx, db)
            _budget_check("report")
            report_path = await stages.run_deterministic_report(ctx, db)
        else:
            # ---- Stages 2-3-4 loop: Hunt → Validate → Gapfill ----
            for i in range(config.gapfill_iterations + 1):
                _budget_check(f"hunt(iter={i})")
                findings_added = await stages.run_hunt(
                    ctx, db, budget_check=_breadth_check
                )
                if findings_added == 0 and i > 0:
                    log.info(
                        "[%s] no new findings — exiting Hunt/Gapfill loop",
                        run_id,
                    )
                    break

                _budget_check(f"validate(iter={i})")
                await stages.run_validate(ctx, db)

                if i >= config.gapfill_iterations:
                    break
                if _closing():
                    log.info(
                        "[%s] closing mode: time budget nearly spent — "
                        "exiting Hunt/Gapfill loop", run_id,
                    )
                    break
                _budget_check(f"gapfill(iter={i})")
                new_tasks = await stages.run_gapfill(ctx, db)
                if new_tasks == 0:
                    log.info("[%s] gapfill produced 0 tasks — exiting loop", run_id)
                    break

            _budget_check("dedupe")
            await stages.run_dedupe(ctx, db)
            _budget_check("trace")
            await stages.run_trace(ctx, db)

            if _closing():
                log.info(
                    "[%s] closing mode: time budget nearly spent — skipping "
                    "feedback iterations", run_id,
                )
            else:
                for i in range(config.feedback_iterations):
                    _budget_check(f"feedback(iter={i})")
                    new_tasks = await stages.run_feedback(ctx, db)
                    if new_tasks == 0:
                        break
                    _budget_check(f"feedback-hunt(iter={i})")
                    await stages.run_hunt(
                        ctx, db, budget_check=_breadth_check
                    )
                    _budget_check(f"feedback-validate(iter={i})")
                    await stages.run_validate(ctx, db)
                    _budget_check(f"feedback-dedupe(iter={i})")
                    await stages.run_dedupe(ctx, db)
                    _budget_check(f"feedback-trace(iter={i})")
                    await stages.run_trace(ctx, db)

                    if _closing():
                        log.info(
                            "[%s] closing mode: time budget nearly spent — "
                            "exiting feedback loop", run_id,
                        )
                        break

            _budget_check("report")
            report_path = await stages.run_report(ctx, db)

        gaps = db.completion_gaps(run_id)
        if gaps:
            db.finish_run(run_id, "incomplete")
            raise IncompleteRunError(
                f"[{run_id}] incomplete stage coverage: " + "; ".join(gaps)
            )

        if resolved_catalogue is not None:
            # Run-end catalogue upsert (W8): confirmed → confirmed,
            # rejected → refuted, needs_more_info → needs_info.
            try:
                from codesec.catalogue import record_run

                stats = record_run(
                    db, run_id, repo_path.resolve(), resolved_catalogue
                )
                log.info("[%s] catalogue updated: %s", run_id, stats)
            except Exception as e:
                log.warning("[%s] catalogue record_run failed: %s", run_id, e)

        db.finish_run(run_id, "completed")
        log.info(
            "[%s] pipeline complete: total cost $%.4f — report at %s",
            run_id, db.total_cost(run_id), report_path,
        )
        return report_path

    except CostExceeded as e:
        log.error(str(e))
        db.finish_run(run_id, "aborted")
        raise
    except QuotaExhaustedError as e:
        # Subscription quota exhausted — surface clearly; user must wait
        # for the reset window. Run is resumable via --resume once quota
        # returns.
        log.error(
            "[%s] subscription quota exhausted — aborting (resumable with --resume): %s",
            run_id, str(e)[:300],
        )
        db.finish_run(run_id, "aborted")
        raise
    except IncompleteRunError:
        raise
    except Exception:
        db.finish_run(run_id, "failed")
        raise
    finally:
        if runtime is not None:
            await runtime.close()
