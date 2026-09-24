"""Stage 3: Validate — adversarial review panel, different model from Hunt.

Each finding faces a panel: `rounds` sequential adversarial reviews
(round 2+ sees the earlier verdicts condensed to verdict + crux + the
shape of the argument, and is told to attack angles the panel hasn't
covered), followed by an arbiter that rules on the evidence.

The stored verdict is the arbiter's call — or the panel majority if
the arbiter fails (ties fall back to needs_more_info). Panel rounds
see only the falsifiable claim — never the finder's confidence or the
hunt task's rationale; the arbiter gets the full finding because it
arbitrates the panel's dispute rather than re-verifying. A "confirmed"
verdict additionally requires proof material on the finding itself
(a successful PoC or a substantive evidence snippet); without it the
verdict is downgraded to needs_more_info (reason: no_proof). With
`rounds > 1`, `validator_confidence` is the fraction of panel+arbiter
votes that agree with the final call: an ensemble signal, not a
self-report. With `rounds == 1` the stage behaves exactly as the
original single-pass validator, self-reported confidence included.
"""

from __future__ import annotations

import asyncio
import logging
from collections import Counter

from codesec.contracts import StageContractError, validate_validation_output
from codesec.hints import hints_for, load_hints
from codesec.runner import AgentResult, AgentRunError, TransientAgentError, run_agent
from codesec.state import Finding, StateDB, Task
from codesec.stages._common import StageContext, record_input_size

log = logging.getLogger(__name__)

# How much of a prior round's rationale survives into the next round's
# and the arbiter's input. Verdicts are cheap; tool-laden rationales are
# not — later reviewers need the shape of the argument, not the
# transcript. Full text stays in the per-round artifacts.
_RATIONALE_CAP = 700

_VOTE_LETTER = {"confirmed": "C", "rejected": "R", "needs_more_info": "N"}


def _squash(text: object) -> str:
    return " ".join(str(text or "").split())


# Minimum evidence_snippet length (squashed) that counts as proof
# material — enough to reject placeholder junk ("", "N/A", "TODO")
# while keeping any genuine verbatim excerpt. A finding below this
# AND with no successful PoC carries no authenticity proof — the
# panel's "confirmed" cannot stand. (Idea from StrikeAgent
# graph/verify.py: no evidence ⇒ pending, never verified.)
_MIN_EVIDENCE_CHARS = 8

# Fields the review panel may see: the falsifiable claim only. The
# finder's self-assessment (confidence, hedged_language) and the hunt
# task's rationale are anchors — a verifier shown the discoverer's
# reasoning tends to agree instead of testing the claim.
_PANEL_VIEW = frozenset({
    "finding_id", "file", "line_start", "line_end", "vuln_class",
    "cwe", "severity", "description", "evidence_snippet", "poc",
})


def _project_finding(raw: dict) -> dict:
    return {k: v for k, v in (raw or {}).items() if k in _PANEL_VIEW}


def _task_context(task: Task | None, fallback_class: str,
                  *, projected: bool) -> dict:
    ctx = {
        "attack_class": task.attack_class if task else fallback_class,
        "scope_hint": task.scope_hint if task else "",
    }
    if not projected:
        # Full-shape input (arbiter, or projection disabled) keeps the
        # hunt task's reasoning as context.
        ctx["rationale"] = task.rationale if task else ""
    return ctx


def _has_proof(f: Finding) -> bool:
    raw = f.raw_json or {}
    poc = raw.get("poc") or {}
    if poc.get("succeeded"):
        return True
    if raw.get("live_evidence"):
        return True
    return len(_squash(f.evidence)) >= _MIN_EVIDENCE_CHARS


def _condense_review(round_no: int, payload: dict) -> dict:
    """Distill one review for the next round / the arbiter."""
    rationale = _squash(payload.get("rationale"))
    if len(rationale) > _RATIONALE_CAP:
        rationale = rationale[:_RATIONALE_CAP].rstrip() + " …"
    return {
        "round": round_no,
        "verdict": payload.get("verdict"),
        "crux": _squash(payload.get("crux")),
        "rationale": rationale,
        "confidence": payload.get("validator_confidence"),
    }


def _tally(round_verdicts: list[str], arbiter_verdict: str | None) -> str:
    votes = "".join(_VOTE_LETTER.get(v, "?") for v in round_verdicts)
    if arbiter_verdict:
        votes += "→" + _VOTE_LETTER.get(arbiter_verdict, "?")
    return votes


def _majority(verdicts: list[str]) -> str | None:
    """Plurality verdict, or None on a tie."""
    if not verdicts:
        return None
    counts = Counter(verdicts).most_common()
    if len(counts) > 1 and counts[0][1] == counts[1][1]:
        return None
    return counts[0][0]


def _split_fallback(finding_id: str, tally: str) -> dict:
    """Synthetic verdict for a split panel the arbiter couldn't rescue."""
    return {
        "finding_id": finding_id,
        "verdict": "needs_more_info",
        "rationale": (
            f"Review panel split ({tally}) and the arbiter produced no "
            "usable ruling, so no verdict carries the round."
        ),
        "alternative_explanation": (
            "The panel disagreed over whether a mitigating control "
            "exists; neither side's crux was verified to breaking."
        ),
        "suggested_test": (
            "Re-run validation — the tie plus the arbiter failure left "
            "this finding undecided."
        ),
        "blockers": [
            "Panel split and the arbiter produced no usable ruling."
        ],
        "validation_plan": {
            "local": "Re-run validation for this finding."
        },
        "validator_confidence": 0.0,
    }


async def run_validate(ctx: StageContext, db: StateDB) -> int:
    """Validate every finding that hasn't been validated yet. Returns
    count of confirmed findings."""
    unvalidated = db.get_unvalidated_findings(ctx.run_id)
    if not unvalidated:
        log.info("[%s] validate: nothing to validate", ctx.run_id)
        return 0

    sc = ctx.stage("validate")
    rounds = max(1, sc.rounds)
    panel_projection = bool(sc.options.get("panel_projection", True))
    hints_all_rounds = bool(sc.options.get("hints_all_rounds", False))
    bypass_hints = load_hints()
    sem = asyncio.Semaphore(sc.concurrency)

    log.info(
        "[%s] validate: %d findings (concurrency=%d, model=%s, rounds=%d)",
        ctx.run_id, len(unvalidated), sc.concurrency, sc.model, rounds,
    )

    tasks_by_id = {t.task_id: t for t in db.get_all_tasks(ctx.run_id)}
    counters = {"confirmed": 0, "rejected": 0, "needs_more_info": 0, "failed": 0}

    async def _review(prompt_name: str, artifact_name: str,
                      user_input: dict) -> AgentResult:
        record_input_size(
            db, ctx.run_id, "validate", artifact_name, user_input
        )
        return await run_agent(
            stage="validate",
            prompt_file=ctx.prompt(prompt_name),
            user_input=user_input,
            schema_file=ctx.schema("validation"),
            allowed_tools=sc.tools,
            model=sc.model,
            profile=ctx.profile("validate"),
            cwd=ctx.repo_path,
            add_dirs=[ctx.repo_path],
            max_turns=sc.max_turns,
            permission_mode=sc.permission_mode,
            artifact_dir=ctx.results_dir("validate"),
            artifact_name=artifact_name,
            repair_attempts=sc.repair_attempts,
            deadline=ctx.deadline,
        )

    def _base_input(f: Finding, *, projected: bool) -> dict:
        task = tasks_by_id.get(f.task_id)
        return {
            "finding": (
                _project_finding(f.raw_json) if projected else f.raw_json
            ),
            "task_context": _task_context(
                task, f.vuln_class, projected=projected
            ),
            "repo_path": str(ctx.repo_path),
            **ctx.extras(),
        }

    async def _one(f: Finding) -> None:
        async with sem:
            base = _base_input(f, projected=panel_projection)
            panel: list[tuple[int, dict]] = []
            errors: list[str] = []

            # Panel: `rounds` sequential reviews, each later round
            # handed the condensed earlier verdicts.
            for round_no in range(1, rounds + 1):
                user_input = dict(base)
                prior = [_condense_review(rn, p) for rn, p in panel]
                if prior:
                    user_input["prior_reviews"] = prior
                if bypass_hints and (round_no >= 2 or hints_all_rounds):
                    # Round-2+ reviewers are told to attack angles the
                    # panel missed; per-class bypass attempts make that
                    # concrete (VVAH's validator_hints design).
                    task = tasks_by_id.get(f.task_id)
                    matched = hints_for(
                        bypass_hints,
                        cwe=(f.raw_json or {}).get("cwe"),
                        vuln_class=f.vuln_class,
                        attack_class=task.attack_class if task else None,
                    )
                    if matched:
                        user_input["bypass_hints"] = matched
                name = (
                    f.finding_id if rounds == 1
                    else f"{f.finding_id}.r{round_no}"
                )
                try:
                    result = await _review("03-validate", name, user_input)
                except (AgentRunError, TransientAgentError) as e:
                    errors.append(f"round {round_no}: {e}")
                    continue
                db.record_agent_result(
                    ctx.run_id, "validate", f.finding_id, result
                )
                db.add_artifact(
                    ctx.run_id, "validate", f.finding_id,
                    "jsonl", str(result.artifact_path),
                )
                try:
                    validate_validation_output(f.finding_id, result.payload)
                except StageContractError as error:
                    errors.append(f"round {round_no}: contract: {error}")
                    continue
                panel.append((round_no, result.payload))

            if not panel:
                # No usable review at all — fail safe: undecided rather
                # than silently confirmed.
                counters["failed"] += 1
                db.set_finding_validation(
                    ctx.run_id, f.finding_id, "needs_more_info",
                    {"finding_id": f.finding_id,
                     "verdict": "needs_more_info",
                     "rationale": "validator failed to produce "
                                  f"schema-valid output: {'; '.join(errors)}",
                     "alternative_explanation":
                         "The finding could not be evaluated — the "
                         "validator produced no schema-valid output.",
                     "suggested_test": "Re-run validation for this finding.",
                     "blockers": ["validator produced no schema-valid output"],
                     "validation_plan": {
                         "local": "Re-run validation for this finding."
                     },
                     "validator_confidence": 0.0},
                )
                return

            round_verdicts = [p.get("verdict") for _, p in panel]

            # Arbiter rules on the evidence. A panel of one has nothing
            # to arbitrate.
            arbiter_payload: dict | None = None
            if rounds > 1:
                user_input = dict(_base_input(f, projected=False))
                user_input["prior_reviews"] = [
                    _condense_review(rn, p) for rn, p in panel
                ]
                user_input["tally"] = _tally(round_verdicts, None)
                try:
                    arb = await _review(
                        "03-arbiter", f"{f.finding_id}.arbiter", user_input
                    )
                    db.record_agent_result(
                        ctx.run_id, "validate", f.finding_id, arb
                    )
                    db.add_artifact(
                        ctx.run_id, "validate", f.finding_id,
                        "jsonl", str(arb.artifact_path),
                    )
                    validate_validation_output(f.finding_id, arb.payload)
                    arbiter_payload = arb.payload
                except (AgentRunError, TransientAgentError,
                        StageContractError) as e:
                    log.warning(
                        "[%s] validate %s: arbiter failed: %s",
                        ctx.run_id, f.finding_id, e,
                    )
                    errors.append(f"arbiter: {e}")

            if arbiter_payload is not None:
                final = dict(arbiter_payload)
            elif rounds > 1:
                majority = _majority(round_verdicts)
                final = (
                    next(p for _, p in panel if p.get("verdict") == majority)
                    if majority is not None
                    else _split_fallback(
                        f.finding_id, _tally(round_verdicts, None)
                    )
                )
            else:
                final = dict(panel[0][1])

            verdict = final.get("verdict", "needs_more_info")

            # Evidence gate: "confirmed" requires proof material (a
            # successful PoC or a substantive evidence snippet). Without
            # it the verdict is downgraded to needs_more_info so Trace only
            # chases findings that carry something falsifiable.
            if verdict == "confirmed" and not _has_proof(f):
                verdict = "needs_more_info"
                final = dict(final)
                final["verdict"] = verdict
                # needs_more_info forbids confirmed-only fields and
                # requires suggested_test/blockers/validation_plan —
                # keep the synthetic payload schema-valid.
                for k in ("arbiter_severity", "severity_reasoning",
                          "execution", "remediation", "production_viable"):
                    final.pop(k, None)
                final.setdefault(
                    "suggested_test",
                    "Build a proof-of-concept or collect a substantive "
                    "evidence snippet.",
                )
                final.setdefault(
                    "blockers",
                    ["no PoC and no substantive evidence snippet"],
                )
                final.setdefault(
                    "validation_plan",
                    {"local": "Construct a proof-of-concept or collect "
                              "a substantive evidence snippet."},
                )
                final["rationale"] = (
                    "[evidence_gate:no_proof] " + _squash(final.get("rationale"))
                )
                counters["no_proof"] = counters.get("no_proof", 0) + 1
                log.info(
                    "[%s] validate %s: downgraded confirmed -> needs_more_info "
                    "(no PoC and no substantive evidence snippet)",
                    ctx.run_id, f.finding_id,
                )
            arbiter_verdict = (
                arbiter_payload.get("verdict") if arbiter_payload else None
            )

            votes = round_verdicts + ([arbiter_verdict] if arbiter_verdict else [])
            vote_fraction = (
                round(votes.count(verdict) / len(votes), 2) if votes else 0.0
            )

            if rounds > 1:
                # How much of the panel actually stands behind the final
                # call — an ensemble signal beats a self-report.
                final["validator_confidence"] = vote_fraction

            final["review"] = {
                "rounds": rounds,
                "tally": _tally(round_verdicts, arbiter_verdict),
                "vote_fraction": vote_fraction,
                "agreement": (
                    "unanimous"
                    if votes and votes.count(verdict) == len(votes)
                    else "split"
                ),
                "arbiter_used": arbiter_payload is not None,
                "panel": [
                    {
                        "round": rn,
                        "verdict": p.get("verdict"),
                        "crux": _squash(p.get("crux")),
                        "self_confidence": p.get("validator_confidence"),
                    }
                    for rn, p in panel
                ],
                "errors": errors,
            }

            db.set_finding_validation(ctx.run_id, f.finding_id, verdict, final)
            counters[verdict] = counters.get(verdict, 0) + 1

    await asyncio.gather(*(_one(f) for f in unvalidated))
    log.info(
        "[%s] validate: confirmed=%d rejected=%d needs_more_info=%d failed=%d no_proof=%d",
        ctx.run_id,
        counters.get("confirmed", 0),
        counters.get("rejected", 0),
        counters.get("needs_more_info", 0),
        counters["failed"],
        counters.get("no_proof", 0),
    )
    return counters.get("confirmed", 0)
