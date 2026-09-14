"""Stage 4: Gapfill — coverage critic that re-queues missed units to Hunt."""

from __future__ import annotations

import logging
import re
from collections import defaultdict
from pathlib import Path

from codesec.contracts import filter_task_batch
from codesec.runner import AgentRunError, TransientAgentError, run_agent
from codesec.state import StateDB, Task
from codesec.stages._common import (
    StageContext,
    refuted_patterns_digest,
    truncated_recon_summary,
)

log = logging.getLogger(__name__)

# Gapfill defaults to a modest number — large counts amplify cost
# quadratically at low concurrency, and most projects don't need 30
# extra Hunt tasks per iteration. Override via CLI if needed.
DEFAULT_MAX_NEW_TASKS = 8

# Negative-knowledge enforcement (W9): a proposed task that re-derives a
# refuted (vuln_class, file) pair is dropped unless its rationale cites
# new evidence. Heuristic: a backtick-quoted code token or an explicit
# override word. Deliberately simple — StrikeAgent's dead-end rule minus
# the regex catalog.
_OVERRIDE_WORDS = frozenset(
    {"new", "however", "changed", "regression", "reverted", "unlike", "now"}
)


def cites_new_evidence(rationale: str) -> bool:
    """True when a task rationale claims evidence the refutation lacked."""
    if "`" in rationale:
        return True
    words = set(re.findall(r"[a-z]+", rationale.lower()))
    return bool(words & _OVERRIDE_WORDS)


def drop_refuted_tasks(
    tasks: list[dict], refuted: list[dict]
) -> tuple[list[dict], int]:
    """Drop tasks whose (attack_class, target_file) matches a refutation
    unless the rationale cites new evidence. Returns (kept, dropped)."""
    keys = {
        (str(r.get("vuln_class", "")), str(r.get("file", "")))
        for r in refuted
    }
    keys.discard(("", ""))
    kept: list[dict] = []
    dropped = 0
    for task in tasks:
        attack_class = str(task.get("attack_class", ""))
        files = [str(f) for f in (task.get("target_files") or [])]
        hit = any((attack_class, f) in keys for f in files)
        if hit and not cites_new_evidence(str(task.get("rationale") or "")):
            dropped += 1
            continue
        kept.append(task)
    return kept, dropped


def _location_file(location: str) -> str | None:
    """Extract the file part of an entry-point location.

    Locations are 'file:line' or a bare symbol reference; only treat the
    head as a file when it looks path-like."""
    head = location.split(":", 1)[0].strip()
    if "/" in head or "." in Path(head).name:
        return head
    return None


def _task_touches(task: Task, location: str, location_file: str | None) -> bool:
    """Heuristic coverage test: the task's targets hit the entry's file
    (exact, or either path is a directory prefix of the other) or the
    location string is mentioned in scope_hint/rationale."""
    hint = f"{task.scope_hint or ''} {task.rationale or ''}"
    if location and location in hint:
        return True
    if location_file is None:
        return False
    if location_file in hint:
        return True
    for target in task.target_files:
        target = str(target)
        if target == location_file:
            return True
        if location_file.startswith(target.rstrip("/") + "/"):
            return True
        parent = location_file.rsplit("/", 1)[0]
        if "/" in location_file and target.startswith(parent + "/"):
            return True
    return False


def entry_point_coverage(recon: dict, tasks: list[Task]) -> dict:
    """Per-entry-point and per-external-input coverage counts.

    Returns {"entry_points": [...], "external_inputs": [...]}, each entry
    carrying the recon fields plus `tasks_touching`. Zero means no task
    ever aimed at that surface — the critic's missing units.
    """
    architecture = recon.get("architecture") or {}
    entry_points = []
    for ep in architecture.get("entry_points") or []:
        location = str(ep.get("location", "") or "")
        location_file = _location_file(location)
        count = sum(
            1 for t in tasks if _task_touches(t, location, location_file)
        )
        entry_points.append(
            {
                "kind": ep.get("kind"),
                "location": location,
                "auth_required": ep.get("auth_required"),
                "tasks_touching": count,
            }
        )
    external_inputs = []
    for ei in architecture.get("external_inputs") or []:
        name = str(ei.get("name", "") or "")
        low = name.lower()
        count = sum(
            1
            for t in tasks
            if low
            and low
            in f"{t.scope_hint or ''} {t.rationale or ''}".lower()
        )
        external_inputs.append(
            {
                "name": name,
                "kind": ei.get("kind"),
                "controllable_by": ei.get("controllable_by"),
                "tasks_touching": count,
            }
        )
    return {"entry_points": entry_points, "external_inputs": external_inputs}


def _catalogue_refuted(ctx: StageContext) -> list[dict]:
    """Prior-run refutations from the cross-run catalogue, in the same
    {vuln_class, file, rejected_because} shape as refuted_patterns."""
    if ctx.catalogue_db is None:
        return []
    from codesec.catalogue import refuted_entries

    try:
        return refuted_entries(Path(ctx.catalogue_db))
    except Exception:
        log.warning(
            "[%s] gapfill: catalogue refuted lookup failed", ctx.run_id,
            exc_info=True,
        )
        return []


def _catalogue_needs_info(ctx: StageContext) -> list[dict]:
    """Prior-run needs_info findings with blockers — gapfill seeds."""
    if ctx.catalogue_db is None:
        return []
    from codesec.catalogue import needs_info_entries

    try:
        return needs_info_entries(Path(ctx.catalogue_db))
    except Exception:
        log.warning(
            "[%s] gapfill: catalogue needs_info lookup failed", ctx.run_id,
            exc_info=True,
        )
        return []


async def run_gapfill(ctx: StageContext, db: StateDB,
                      max_new_tasks: int = DEFAULT_MAX_NEW_TASKS) -> int:
    """Returns count of new tasks added."""
    recon_summary = db.get_recon_output(ctx.run_id) or {}
    all_tasks = db.get_all_tasks(ctx.run_id)
    completed = [t for t in all_tasks if t.status in ("done", "failed")]
    if not completed:
        log.info("[%s] gapfill: nothing to analyze", ctx.run_id)
        db.add_artifact(
            ctx.run_id,
            "gapfill",
            None,
            "checkpoint",
            "not-applicable:no-completed-tasks",
        )
        return 0

    findings_by_task: dict[str, int] = defaultdict(int)
    gaps_by_task: dict[str, list] = defaultdict(list)
    for f in db.get_findings(ctx.run_id):
        findings_by_task[f.task_id] += 1
    # Reconstruct gaps_observed by reading hunt artifacts via raw_json on task
    # No — gaps_observed lives in the hunt JSONL artifact. For simplicity
    # we pass findings_count only; the gapfill agent re-reads code itself.

    sc = ctx.stage("gapfill")
    completed_payload = [
        {
            "task_id": t.task_id,
            "attack_class": t.attack_class,
            "subsystem": _infer_subsystem(t.target_files, recon_summary),
            "scope_hint": t.scope_hint,
            "findings_count": findings_by_task.get(t.task_id, 0),
            "gaps_observed": gaps_by_task.get(t.task_id, []),
            "status": t.status,
        }
        for t in completed
    ]
    coverage = entry_point_coverage(recon_summary, all_tasks)
    # Caps keep a verbose target (or a long-lived catalogue) inside the
    # input budget — refuted_patterns_digest caps its own contribution.
    refuted = (
        refuted_patterns_digest(db, ctx.run_id) + _catalogue_refuted(ctx)
    )[:80]
    user_input = {
        "recon_summary": truncated_recon_summary(recon_summary),
        "completed_tasks": completed_payload,
        "uncovered_surfaces": db.get_uncovered_surfaces(ctx.run_id)[:60],
        "entry_point_coverage": coverage["entry_points"],
        "external_input_coverage": coverage["external_inputs"],
        "refuted_patterns": refuted,
        "prior_unresolved": _catalogue_needs_info(ctx)[:60],
        "max_new_tasks": max_new_tasks,
        **ctx.extras(),
    }
    try:
        result = await run_agent(
            stage="gapfill",
            prompt_file=ctx.prompt("04-gapfill"),
            user_input=user_input,
            schema_file=ctx.schema("gapfill_output"),
            allowed_tools=sc.tools,
            model=sc.model,
            profile=ctx.profile("gapfill"),
            cwd=ctx.repo_path,
            add_dirs=[ctx.repo_path],
            max_turns=sc.max_turns,
            permission_mode=sc.permission_mode,
            artifact_dir=ctx.results_dir("gapfill"),
            artifact_name=f"gapfill_{_iter_tag(ctx.run_id, db)}",
            repair_attempts=sc.repair_attempts,
        )
    except (AgentRunError, TransientAgentError) as e:
        log.warning("[%s] gapfill failed: %s", ctx.run_id, e)
        raise

    db.record_agent_result(ctx.run_id, "gapfill", None, result)
    db.add_artifact(
        ctx.run_id, "gapfill", None, "jsonl", str(result.artifact_path)
    )
    new_tasks = result.payload.get("new_tasks", []) or []
    kept = filter_task_batch(new_tasks, ctx.repo_path)
    dropped = len(new_tasks) - len(kept)
    if dropped:
        log.warning(
            "[%s] gapfill: dropped %d task(s) with missing/outside targets",
            ctx.run_id,
            dropped,
        )
    new_tasks = kept
    if sc.options.get("negative_knowledge", True):
        new_tasks, dropped = drop_refuted_tasks(new_tasks, refuted)
        if dropped:
            log.warning(
                "[%s] gapfill: negative-knowledge filter dropped %d "
                "task(s) matching refuted patterns without new evidence",
                ctx.run_id,
                dropped,
            )
    existing_ids = {task.task_id for task in all_tasks}
    added = 0
    for t in new_tasks:
        t.setdefault("source", "gapfill")
        db.add_task(ctx.run_id, t)
        if t["task_id"] not in existing_ids:
            added += 1
    db.add_artifact(
        ctx.run_id,
        "gapfill",
        None,
        "checkpoint",
        "completed",
    )
    log.info("[%s] gapfill: added %d new tasks", ctx.run_id, added)
    return added


def _infer_subsystem(target_files: list[str], recon: dict) -> str:
    if not target_files:
        return "unknown"
    f = target_files[0]
    for s in recon.get("subsystems", []):
        p = s.get("path", "")
        if p and f.startswith(p):
            return s.get("name", "unknown")
    return "unknown"


def _iter_tag(run_id: str, db: StateDB) -> str:
    # Simple monotonic tag based on existing gapfill artifacts.
    return f"iter_{int(_artifact_count(db, run_id, 'gapfill')) + 1}"


def _artifact_count(db: StateDB, run_id: str, stage: str) -> int:
    return db.artifact_count(run_id, stage, kind="jsonl")
