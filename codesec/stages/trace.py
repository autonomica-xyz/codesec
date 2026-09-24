"""Stage 6: Trace — reachability from entry point to sink, per canonical finding."""

from __future__ import annotations

import asyncio
import logging

from codesec.contracts import (
    StageContractError,
    trace_failure_reason_code,
    validate_trace_output,
)
from codesec.markers import markers_for
from codesec.runner import AgentRunError, TransientAgentError, run_agent
from codesec.state import Finding, StateDB
from codesec.stages._common import StageContext, record_input_size, truncated_recon_summary

log = logging.getLogger(__name__)

# P04: bounded semantic-repair budget for trace contract violations
# (counted against normal time/token budgets; every attempt preserved).
_TRACE_SEMANTIC_REPAIRS = 2


def _uncertain_payload(finding_id: str, rationale: str, *, kind: str,
                       reason_code: str, extra_blocker: str) -> dict:
    """Engine-written uncertain trace with typed uncertainty (P04):
    operational failures are never conflated with source-evidence gaps,
    and an engine failure is never evidence of unreachability."""
    return {
        "finding_id": finding_id,
        "status": "uncertain",
        "reachable": None,
        "confidence": 0.0,
        "rationale": rationale,
        "uncertainty": {"kind": kind, "reason_code": reason_code},
        "blockers": [
            {
                "kind": "other",
                "location": "tracer",
                "description": extra_blocker,
            }
        ],
    }


async def run_trace(ctx: StageContext, db: StateDB) -> int:
    canonicals = db.get_findings(ctx.run_id, validation_status="confirmed",
                                 canonical_only=True)
    if not canonicals:
        log.info("[%s] trace: no canonical findings to trace", ctx.run_id)
        return 0

    sc = ctx.stage("trace")
    sem = asyncio.Semaphore(sc.concurrency)
    # W6 canary markers: when a live target is configured, each finding gets
    # a deterministic canary the tracer must echo back through the entry
    # point before it may claim `reachable`. `canary_markers: false` in
    # stages.yaml disables minting entirely; `require_canary_marker: false`
    # keeps minting but drops the hard reachable-requires-verified rule.
    # Static mode (P04) never mints markers and never requires one.
    mint_markers = ctx.evidence_mode == "live" and bool(
        sc.options.get("canary_markers", True)
    )
    require_marker = bool(sc.options.get("require_canary_marker", True))
    recon_summary = db.get_recon_output(ctx.run_id) or {}

    log.info(
        "[%s] trace: %d canonicals (concurrency=%d, model=%s, mode=%s)",
        ctx.run_id, len(canonicals), sc.concurrency, sc.model,
        ctx.evidence_mode,
    )
    counters = {
        "reachable": 0,
        "unreachable": 0,
        "uncertain": 0,
        "failed": 0,
    }

    async def _one(f: Finding) -> None:
        async with sem:
            if db.get_trace(ctx.run_id, f.finding_id) is not None:
                return  # already traced (resume)
            markers = markers_for(f.raw_json) if mint_markers else None
            user_input = {
                "finding": f.raw_json,
                # P04: the authoritative sink location is named explicitly;
                # the final call_chain frame must sit at exactly this spot.
                "authoritative_sink": {
                    "file": f.file,
                    "line_start": f.line_start,
                    "line_end": f.line_end,
                },
                "recon_summary": truncated_recon_summary(recon_summary),
                "repo_path": str(ctx.repo_path),
                **ctx.extras(),
            }
            if markers is not None:
                user_input["markers"] = markers
            record_input_size(
                db, ctx.run_id, "trace", f.finding_id, user_input
            )

            def _validate(payload: dict) -> StageContractError | None:
                try:
                    validate_trace_output(
                        f.finding_id,
                        payload,
                        ctx.repo_path,
                        expected_sink_file=f.file,
                        expected_sink_range=(f.line_start, f.line_end),
                    )
                    # W6: in live mode a `reachable` verdict must be backed
                    # by an observed canary — exact-marker confirmation is
                    # the oracle, not a plausible-looking response.
                    marker = payload.get("marker") or {}
                    if (
                        mint_markers
                        and require_marker
                        and payload.get("status") == "reachable"
                        and marker.get("verified") is not True
                    ):
                        raise StageContractError(
                            "reachable trace lacks a verified canary marker"
                        )
                except StageContractError as error:
                    return error
                return None

            async def _call(input_for_agent: dict, artifact_name: str):
                return await run_agent(
                    stage="trace",
                    prompt_file=ctx.prompt("06-trace"),
                    user_input=input_for_agent,
                    schema_file=ctx.schema("trace"),
                    allowed_tools=sc.tools,
                    model=sc.model,
                    profile=ctx.profile("trace"),
                    cwd=ctx.repo_path,
                    add_dirs=[ctx.repo_path],
                    max_turns=sc.max_turns,
                    permission_mode=sc.permission_mode,
                    artifact_dir=ctx.results_dir("trace"),
                    artifact_name=artifact_name,
                    repair_attempts=sc.repair_attempts,
                    deadline=ctx.deadline,
                )

            try:
                result = await _call(user_input, f.finding_id)
            except (AgentRunError, TransientAgentError) as e:
                log.warning("[%s] trace %s failed: %s", ctx.run_id, f.finding_id, e)
                counters["failed"] += 1
                # An agent/output failure is an operational unknown, not
                # evidence that the vulnerable-looking path is unreachable.
                db.record_stage_event(
                    ctx.run_id,
                    "trace",
                    {
                        "category": "failed",
                        "finding_id": f.finding_id,
                        "reason_code": "engine_failure",
                        "error": f"{type(e).__name__}: {e}"[:500],
                    },
                )
                db.add_trace(
                    ctx.run_id,
                    f.finding_id,
                    _uncertain_payload(
                        f.finding_id,
                        f"tracer failed: {e}",
                        kind="operational",
                        reason_code="engine_failure",
                        extra_blocker=(
                            "agent failed to emit a valid trace payload"
                        ),
                    ),
                )
                return

            db.record_agent_result(ctx.run_id, "trace", f.finding_id, result)
            db.add_artifact(
                ctx.run_id,
                "trace",
                f.finding_id,
                "jsonl",
                str(result.artifact_path),
            )

            payload = result.payload
            error = _validate(payload)
            repairs_used = 0
            while error is not None and repairs_used < _TRACE_SEMANTIC_REPAIRS:
                repairs_used += 1
                # P04 structured repair: finding id, the exact failed
                # invariant, the authoritative sink, and the invalid payload.
                repair_input = {
                    **user_input,
                    "repair": {
                        "finding_id": f.finding_id,
                        "failed_invariant": str(error),
                        "authoritative_sink": user_input["authoritative_sink"],
                        "invalid_payload": payload,
                    },
                }
                db.record_stage_event(
                    ctx.run_id,
                    "trace",
                    {
                        "category": "semantic_repair",
                        "finding_id": f.finding_id,
                        "attempt": repairs_used,
                        "failed_invariant": str(error)[:500],
                    },
                )
                try:
                    repair_result = await _call(
                        repair_input, f"{f.finding_id}.semrepair-{repairs_used}"
                    )
                except (AgentRunError, TransientAgentError) as e:
                    log.warning(
                        "[%s] trace %s semantic repair %d failed: %s",
                        ctx.run_id, f.finding_id, repairs_used, e,
                    )
                    counters["failed"] += 1
                    db.record_stage_event(
                        ctx.run_id,
                        "trace",
                        {
                            "category": "failed",
                            "finding_id": f.finding_id,
                            "reason_code": "engine_failure",
                            "during": "semantic_repair",
                            "error": f"{type(e).__name__}: {e}"[:500],
                        },
                    )
                    db.add_trace(
                        ctx.run_id,
                        f.finding_id,
                        _uncertain_payload(
                            f.finding_id,
                            f"tracer failed during semantic repair: {e}",
                            kind="operational",
                            reason_code="engine_failure",
                            extra_blocker=(
                                "agent failed during semantic repair"
                            ),
                        ),
                    )
                    return
                db.record_agent_result(
                    ctx.run_id,
                    "trace",
                    f"{f.finding_id}.semrepair-{repairs_used}",
                    repair_result,
                )
                db.add_artifact(
                    ctx.run_id,
                    "trace",
                    f.finding_id,
                    f"semantic_repair_{repairs_used}",
                    str(repair_result.artifact_path),
                )
                payload = repair_result.payload
                error = _validate(payload)

            if error is not None:
                log.warning(
                    "[%s] trace %s violated semantic contract after %d "
                    "repairs: %s",
                    ctx.run_id, f.finding_id, repairs_used, error,
                )
                # P04: typed, machine-readable uncertainty. Invalid output
                # after exhausted repair is an operational degradation —
                # never auto-reversed, never frames moved into range, and
                # never marked unreachable because the engine failed.
                counters["uncertain"] += 1
                reason_code = trace_failure_reason_code(error)
                db.record_stage_event(
                    ctx.run_id,
                    "trace",
                    {
                        "category": "degraded",
                        "finding_id": f.finding_id,
                        "reason_code": reason_code,
                        "repairs": repairs_used,
                        "failed_invariant": str(error)[:500],
                    },
                )
                db.add_trace(
                    ctx.run_id,
                    f.finding_id,
                    _uncertain_payload(
                        f.finding_id,
                        f"Tracer output violated the semantic contract "
                        f"after {repairs_used} repairs: {error}",
                        kind="operational",
                        reason_code=reason_code,
                        extra_blocker=(
                            "Agent did not emit a trace satisfying the "
                            "contract; no frames were moved or fabricated "
                            "to force a verdict."
                        ),
                    ),
                )
                return

            # A verified canary is the strongest evidence the tracer can
            # produce — floor the confidence so downstream stages weight it.
            if (payload.get("marker") or {}).get("verified") is True:
                payload["confidence"] = max(
                    float(payload.get("confidence") or 0.0), 0.9
                )
            db.add_trace(ctx.run_id, f.finding_id, payload)
            status = payload["status"]
            counters[status] += 1

    await asyncio.gather(*(_one(f) for f in canonicals))
    log.info(
        "[%s] trace: reachable=%d unreachable=%d uncertain=%d failed=%d",
        ctx.run_id,
        counters["reachable"],
        counters["unreachable"],
        counters["uncertain"],
        counters["failed"],
    )
    return counters["reachable"]
