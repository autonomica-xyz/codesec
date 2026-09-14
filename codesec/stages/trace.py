"""Stage 6: Trace — reachability from entry point to sink, per canonical finding."""

from __future__ import annotations

import asyncio
import logging

from codesec.contracts import StageContractError, validate_trace_output
from codesec.markers import markers_for
from codesec.runner import AgentRunError, TransientAgentError, run_agent
from codesec.state import Finding, StateDB
from codesec.stages._common import StageContext, truncated_recon_summary

log = logging.getLogger(__name__)


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
    mint_markers = bool(ctx.live_target) and bool(
        sc.options.get("canary_markers", True)
    )
    require_marker = bool(sc.options.get("require_canary_marker", True))
    recon_summary = db.get_recon_output(ctx.run_id) or {}

    log.info(
        "[%s] trace: %d canonicals (concurrency=%d, model=%s)",
        ctx.run_id, len(canonicals), sc.concurrency, sc.model,
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
                "recon_summary": truncated_recon_summary(recon_summary),
                "repo_path": str(ctx.repo_path),
                **ctx.extras(),
            }
            if markers is not None:
                user_input["markers"] = markers
            try:
                result = await run_agent(
                    stage="trace",
                    prompt_file=ctx.prompt("06-trace"),
                    user_input=user_input,
                    schema_file=ctx.schema("trace"),
                    allowed_tools=sc.tools,
                    model=sc.model,
                    profile=ctx.profile("trace"),
                    cwd=ctx.repo_path,
                    add_dirs=[ctx.repo_path],
                    max_turns=sc.max_turns,
                    permission_mode=sc.permission_mode,
                    artifact_dir=ctx.results_dir("trace"),
                    artifact_name=f.finding_id,
                    repair_attempts=sc.repair_attempts,
                )
            except (AgentRunError, TransientAgentError) as e:
                log.warning("[%s] trace %s failed: %s", ctx.run_id, f.finding_id, e)
                counters["failed"] += 1
                # An agent/output failure is an operational unknown, not
                # evidence that the vulnerable-looking path is unreachable.
                db.add_trace(ctx.run_id, f.finding_id, {
                    "finding_id": f.finding_id,
                    "status": "uncertain",
                    "reachable": None,
                    "confidence": 0.0,
                    "rationale": f"tracer failed: {e}",
                    "blockers": [{"kind": "other", "location": "tracer",
                                  "description": "agent failed to emit valid trace"}],
                })
                return

            db.record_agent_result(ctx.run_id, "trace", f.finding_id, result)
            db.add_artifact(
                ctx.run_id,
                "trace",
                f.finding_id,
                "jsonl",
                str(result.artifact_path),
            )
            try:
                validate_trace_output(
                    f.finding_id,
                    result.payload,
                    ctx.repo_path,
                    expected_sink_file=f.file,
                    expected_sink_range=(f.line_start, f.line_end),
                )
                # W6: in live mode a `reachable` verdict must be backed by
                # an observed canary — exact-marker confirmation is the
                # oracle, not a plausible-looking response.
                marker = result.payload.get("marker") or {}
                if (
                    mint_markers
                    and require_marker
                    and result.payload.get("status") == "reachable"
                    and marker.get("verified") is not True
                ):
                    raise StageContractError(
                        "reachable trace lacks a verified canary marker"
                    )
            except StageContractError as error:
                log.warning(
                    "[%s] trace %s violated semantic contract: %s",
                    ctx.run_id,
                    f.finding_id,
                    error,
                )
                # Recorded outcome is "uncertain" — counting it under both
                # counters would skew the stage summary.
                counters["uncertain"] += 1
                db.add_trace(
                    ctx.run_id,
                    f.finding_id,
                    {
                        "finding_id": f.finding_id,
                        "status": "uncertain",
                        "reachable": None,
                        "confidence": 0.0,
                        "rationale": (
                            "Tracer output violated the semantic "
                            f"contract: {error}"
                        ),
                        "blockers": [
                            {
                                "kind": "other",
                                "location": "tracer",
                                "description": (
                                    "Agent did not emit a trustworthy trace."
                                ),
                            }
                        ],
                    },
                )
                return
            # A verified canary is the strongest evidence the tracer can
            # produce — floor the confidence so downstream stages weight it.
            if (result.payload.get("marker") or {}).get("verified") is True:
                result.payload["confidence"] = max(
                    float(result.payload.get("confidence") or 0.0), 0.9
                )
            db.add_trace(ctx.run_id, f.finding_id, result.payload)
            status = result.payload["status"]
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
