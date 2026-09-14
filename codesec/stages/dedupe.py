"""Stage 5: Dedupe — cluster confirmed findings by root cause."""

from __future__ import annotations

import hashlib
import json
import logging
import re
from pathlib import Path

from codesec.contracts import StageContractError, validate_dedupe_partition
from codesec.runner import AgentRunError, TransientAgentError, run_agent
from codesec.state import StateDB, StateConflictError
from codesec.stages._common import StageContext

log = logging.getLogger(__name__)

# W13 deterministic pre-pass (Anthropic triage rule): findings on the same
# (file, vuln_class) whose line_starts are within this window are candidate
# duplicates — the LLM adjudicates confirm/merge, it does not discover them.
_PRECLUSTER_LINE_WINDOW = 10


def _precluster_groups(confirmed) -> list[dict]:
    """Single-linkage clustering on (file, vuln_class) + line proximity.

    Returns one entry per cluster of >= 2 confirmed findings. Deterministic:
    buckets and members are sorted before chaining so the same input always
    yields the same pre-clusters.
    """
    buckets: dict[tuple[str, str], list] = {}
    for finding in confirmed:
        key = (Path(finding.file).as_posix(), finding.vuln_class)
        buckets.setdefault(key, []).append(finding)

    clusters: list[tuple[str, str, list]] = []
    for (file, vuln_class), members in sorted(buckets.items()):
        members.sort(key=lambda f: (f.line_start, f.finding_id))
        cluster = [members[0]]
        for finding in members[1:]:
            if (
                abs(finding.line_start - cluster[-1].line_start)
                <= _PRECLUSTER_LINE_WINDOW
            ):
                cluster.append(finding)
            else:
                clusters.append((file, vuln_class, cluster))
                cluster = [finding]
        clusters.append((file, vuln_class, cluster))

    return [
        {
            "member_finding_ids": sorted(f.finding_id for f in cluster),
            "file": file,
            "vuln_class": vuln_class,
            "line_start_min": min(f.line_start for f in cluster),
            "line_start_max": max(f.line_start for f in cluster),
        }
        for file, vuln_class, cluster in clusters
        if len(cluster) > 1
    ]


def _prior_canonical(members):
    """The pre-W13 pick: successful PoC first, then lowest finding_id."""
    return min(
        members,
        key=lambda f: (not f.poc_succeeded, f.finding_id),
    )


def _best_evidence_member(members):
    """W13 canonical rule: strongest evidence story wins — successful PoC,
    then the longest evidence snippet, then lowest finding_id."""
    return min(
        members,
        key=lambda f: (
            not f.poc_succeeded,
            -len(f.evidence or ""),
            f.finding_id,
        ),
    )


async def run_deterministic_dedupe(
    ctx: StageContext,
    db: StateDB,
) -> int:
    """Compact exact duplicates without risking a false near-duplicate merge."""
    confirmed = db.get_findings(
        ctx.run_id, validation_status="confirmed"
    )
    buckets: dict[tuple, list] = {}
    for finding in confirmed:
        fingerprint = (
            re.sub(r"[^a-z0-9]", "", finding.vuln_class.lower()),
            str(finding.raw_json.get("cwe") or "").upper(),
            Path(finding.file).as_posix(),
            finding.line_start,
            finding.line_end,
            " ".join(finding.evidence.split()),
            " ".join(finding.description.split()),
        )
        buckets.setdefault(fingerprint, []).append(finding)

    for fingerprint, members in sorted(
        buckets.items(), key=lambda item: repr(item[0])
    ):
        # Duo parity with the LLM path: the group row records the prior
        # canonical; when the best-evidence member deviates from it, the
        # deviation is applied — and audited — through swap_canonical.
        prior = _prior_canonical(members)
        best = _best_evidence_member(members)
        digest = hashlib.sha256(
            json.dumps(fingerprint, separators=(",", ":")).encode()
        ).hexdigest()[:16]
        group_id = f"g_exact_{digest}"
        member_ids = sorted(finding.finding_id for finding in members)
        db.add_dedupe_group(
            ctx.run_id,
            {
                "group_id": group_id,
                "root_cause": best.description[:200],
                "canonical_finding_id": prior.finding_id,
                "member_finding_ids": member_ids,
            },
        )
        for finding_id in member_ids:
            db.assign_finding_group(
                ctx.run_id,
                finding_id,
                group_id,
                finding_id == prior.finding_id,
            )
        if best.finding_id != prior.finding_id:
            db.swap_canonical(
                ctx.run_id,
                group_id,
                best.finding_id,
                "deterministic best-evidence pick: "
                f"poc_succeeded={best.poc_succeeded}, "
                f"evidence_chars={len(best.evidence or '')}",
            )

    log.info(
        "[%s] deterministic dedupe: %d findings → %d exact groups",
        ctx.run_id,
        len(confirmed),
        len(buckets),
    )
    return len(buckets)


async def run_dedupe(ctx: StageContext, db: StateDB) -> int:
    confirmed = db.get_findings(ctx.run_id, validation_status="confirmed")
    if not confirmed:
        log.info("[%s] dedupe: no confirmed findings to cluster", ctx.run_id)
        return 0

    sc = ctx.stage("dedupe")
    payload = []
    for f in confirmed:
        payload.append({
            **f.raw_json,
            "validation": f.validation_json,
        })
    preclustered = _precluster_groups(confirmed)

    log.info(
        "[%s] dedupe: clustering %d confirmed findings "
        "(%d deterministic pre-clusters)",
        ctx.run_id,
        len(confirmed),
        len(preclustered),
    )
    try:
        result = await run_agent(
            stage="dedupe",
            prompt_file=ctx.prompt("05-dedupe"),
            user_input={
                "confirmed_findings": payload,
                "preclustered_groups": preclustered,
                **ctx.extras(),
            },
            schema_file=ctx.schema("dedupe_output"),
            allowed_tools=sc.tools,
            model=sc.model,
            profile=ctx.profile("dedupe"),
            cwd=ctx.repo_path,
            add_dirs=[ctx.repo_path],
            max_turns=sc.max_turns,
            permission_mode=sc.permission_mode,
            artifact_dir=ctx.results_dir("dedupe"),
            artifact_name="dedupe",
            repair_attempts=sc.repair_attempts,
        )
    except (AgentRunError, TransientAgentError) as e:
        log.warning("[%s] dedupe failed: %s — treating each finding as its own group",
                    ctx.run_id, e)
        return _fallback_singletons(ctx, db, confirmed)

    groups = result.payload.get("groups", [])
    db.record_agent_result(ctx.run_id, "dedupe", None, result)
    db.add_artifact(ctx.run_id, "dedupe", None, "jsonl", str(result.artifact_path))
    try:
        validate_dedupe_partition(
            {finding.finding_id for finding in confirmed}, groups
        )
    except StageContractError as error:
        log.warning(
            "[%s] dedupe violated semantic contract: %s — treating each "
            "finding as its own group",
            ctx.run_id,
            error,
        )
        return _fallback_singletons(ctx, db, confirmed)
    for g in groups:
        db.add_dedupe_group(ctx.run_id, g)
        canonical = g["canonical_finding_id"]
        for fid in g["member_finding_ids"]:
            db.assign_finding_group(
                ctx.run_id, fid, g["group_id"], fid == canonical
            )
        _apply_canonical_replacement(ctx, db, g)

    log.info("[%s] dedupe: %d findings → %d groups", ctx.run_id, len(confirmed), len(groups))
    return len(groups)


def _apply_canonical_replacement(ctx: StageContext, db: StateDB, g: dict) -> None:
    """W13 third verdict: a member with a strictly better evidence story may
    replace the canonical. Applied through swap_canonical so the override is
    audited; a non-member or missing group is logged and ignored."""
    replacement = g.get("replace_canonical_with")
    if not replacement or replacement == g["canonical_finding_id"]:
        return
    if replacement not in g["member_finding_ids"]:
        log.warning(
            "[%s] dedupe group %s: replace_canonical_with %r is not a "
            "member — ignoring",
            ctx.run_id, g["group_id"], replacement,
        )
        return
    try:
        db.swap_canonical(
            ctx.run_id,
            g["group_id"],
            replacement,
            str(g.get("replacement_reason") or "better evidence story"),
        )
    except StateConflictError as error:
        log.warning(
            "[%s] dedupe group %s: canonical swap to %r failed: %s",
            ctx.run_id, g["group_id"], replacement, error,
        )


def _fallback_singletons(ctx: StageContext, db: StateDB, confirmed) -> int:
    # Conservative fallback: never let an invalid merge hide a finding.
    for finding in confirmed:
        group_id = (
            f"g_{finding.finding_id[2:]}"
            if finding.finding_id.startswith("f_")
            else f"g_{finding.finding_id}"
        )
        db.add_dedupe_group(
            ctx.run_id,
            {
                "group_id": group_id,
                "root_cause": finding.description[:200],
                "canonical_finding_id": finding.finding_id,
                "member_finding_ids": [finding.finding_id],
            },
        )
        db.assign_finding_group(
            ctx.run_id, finding.finding_id, group_id, True
        )
    return len(confirmed)
