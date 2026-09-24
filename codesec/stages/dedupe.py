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

# P02 payload bounds: descriptors instead of full findings, batched under a
# 30,000-character serialized user-input cap (below the engine's 50,000
# guard, accounting for the serialized wrapper itself).
_DEDUPE_PAYLOAD_CAP = 30_000
_DESCRIPTOR_TEXT_CAP = 400
_VALIDATION_SUMMARY_CAP = 240


class DedupeOversizeError(AgentRunError):
    """A single bounded descriptor cannot fit in one payload-capped batch."""


class DedupeContractError(AgentRunError):
    """The assembled final partition is not exact (should be unreachable
    after per-batch validation; kept as a typed hard failure)."""


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


def _bounded_text(value, cap: int) -> tuple[str, bool]:
    text = " ".join(str(value or "").split())
    if len(text) <= cap:
        return text, False
    return text[:cap].rstrip() + " …", True


def _finding_descriptor(f) -> dict:
    """Bounded, identity-preserving summary of a confirmed finding.

    Keeps the authoritative identity/location fields (id, file, range,
    class/CWE) verbatim; free text is bounded with explicit truncation
    flags. Full evidence stays in the DB — nothing is silently truncated
    in the serialized document because every bounded field is bounded
    before serialization and flagged."""
    description, desc_trunc = _bounded_text(f.description, _DESCRIPTOR_TEXT_CAP)
    evidence, ev_trunc = _bounded_text(f.evidence, _DESCRIPTOR_TEXT_CAP)
    validation = f.validation_json or {}
    rationale, rat_trunc = _bounded_text(
        validation.get("rationale"), _VALIDATION_SUMMARY_CAP
    )
    descriptor = {
        "finding_id": f.finding_id,
        "file": Path(f.file).as_posix(),
        "line_start": f.line_start,
        "line_end": f.line_end,
        "vuln_class": f.vuln_class,
        "severity": f.severity,
        "poc_succeeded": bool(f.poc_succeeded),
        "description": description,
        "evidence": evidence,
        "validation_summary": {
            "verdict": validation.get("verdict") or f.validation_status,
            "rationale": rationale,
        },
    }
    if f.raw_json.get("cwe"):
        descriptor["cwe"] = f.raw_json["cwe"]
    truncations = {
        "description": desc_trunc,
        "evidence": ev_trunc,
        "validation_rationale": rat_trunc,
    }
    if any(truncations.values()):
        descriptor["truncated"] = truncations
    return descriptor


def _partition_key(descriptor: dict) -> tuple[str, str]:
    """Partition = (normalized file, normalized vulnerability class).
    Cross-partition findings are never merged — an algorithmic restriction
    recorded in the run's stage events."""
    return (
        descriptor["file"],
        " ".join(str(descriptor["vuln_class"]).lower().split()),
    )


def _serialized_len(value: dict) -> int:
    return len(json.dumps(value, ensure_ascii=False, sort_keys=True))


def _batch_user_input(
    batch: list[dict], preclustered: list[dict], extras: dict, batch_id: str
) -> dict:
    """Wrapper actually sent per batch. Preclusters are restricted to
    groups whose members are all inside this batch; straddling groups are
    adjudicated by the merge pass instead."""
    ids = {d["finding_id"] for d in batch}
    restricted = [
        g
        for g in preclustered
        if set(g["member_finding_ids"]) <= ids
    ]
    return {
        "batch_id": batch_id,
        "confirmed_findings": batch,
        "preclustered_groups": restricted,
        **extras,
    }


def _build_batches(
    descriptors: list[dict], preclustered: list[dict], extras: dict, cap: int = _DEDUPE_PAYLOAD_CAP
) -> list[list[dict]]:
    """Partition-first, size-bounded ordered batches.

    Partitions are ordered deterministically; an oversized partition is
    split into ordered batches of consecutive members so straddling
    duplicates reach the merge pass. Every batch's serialized wrapper
    (including preclustered_groups and extras) fits the cap.
    """
    partitions: dict[tuple[str, str], list[dict]] = {}
    for d in descriptors:
        partitions.setdefault(_partition_key(d), []).append(d)
    for members in partitions.values():
        members.sort(
            key=lambda d: (d["line_start"], d["finding_id"])
        )

    batches: list[list[dict]] = []
    current: list[dict] = []
    counter = 0

    def _seal():
        nonlocal current, counter
        if current:
            counter += 1
            user_input = _batch_user_input(
                current, preclustered, extras, f"dedupe-batch-{counter:04d}"
            )
            if _serialized_len(user_input) > cap:
                raise DedupeOversizeError(
                    "dedupe batch exceeds payload cap even though every "
                    f"descriptor fits alone ({_serialized_len(user_input)} > {cap})"
                )
            batches.append(current)
            current = []

    for key in sorted(partitions):
        for descriptor in partitions[key]:
            if _serialized_len(descriptor) > cap:
                raise DedupeOversizeError(
                    "single dedupe descriptor exceeds payload cap: "
                    f"{descriptor['finding_id']} "
                    f"({_serialized_len(descriptor)} > {cap})"
                )
            candidate = [*current, descriptor]
            counter_probe = counter + 1
            probe = _batch_user_input(
                candidate, preclustered, extras, f"dedupe-batch-{counter_probe:04d}"
            )
            if current and _serialized_len(probe) > cap:
                _seal()
                current = [descriptor]
            else:
                current = candidate
    _seal()
    return batches


def _merge_descriptor(descriptor: dict) -> dict:
    """Tighter-bounded representative for the merge pass. The merge
    adjudicator compares root causes across group representatives; it
    needs identity + short summaries, not full evidence."""
    out = {
        "finding_id": descriptor["finding_id"],
        "file": descriptor["file"],
        "line_start": descriptor["line_start"],
        "line_end": descriptor["line_end"],
        "vuln_class": descriptor["vuln_class"],
        "severity": descriptor["severity"],
    }
    if descriptor.get("cwe"):
        out["cwe"] = descriptor["cwe"]
    for key, cap in (("description", 120), ("evidence", 120)):
        text, truncated = _bounded_text(descriptor.get(key), cap)
        out[key] = text
        if truncated:
            out.setdefault("truncated", {})[key] = True
    out["validation_verdict"] = (
        (descriptor.get("validation_summary") or {}).get("verdict")
    )
    return out


def _merge_user_input(
    partition_key: tuple[str, str],
    representatives: list[dict],
    groups: list[dict],
    extras: dict,
) -> dict:
    return {
        "merge_pass": True,
        "partition": {"file": partition_key[0], "vuln_class": partition_key[1]},
        "confirmed_findings": representatives,
        "existing_groups": [
            {
                "group_id": g["group_id"],
                "root_cause": _bounded_text(g.get("root_cause", ""), 140)[0],
                "member_finding_ids": g["member_finding_ids"],
                "canonical_finding_id": g["canonical_finding_id"],
            }
            for g in groups
        ],
        **extras,
    }


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

    db.supersede_dedupe_groups(ctx.run_id)
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
    """LLM dedupe with bounded descriptors and partition-aware batches.

    Algorithm (P02):
    1. Build one bounded descriptor per confirmed finding (identity fields
       verbatim, free text capped with truncation flags).
    2. Partition by (normalized file, vuln_class); pack ordered batches so
       each serialized wrapper fits the 30k cap.
    3. One LLM adjudication call per batch over complete preclusters.
    4. One bounded representative merge call per multi-group partition —
       across partitions groups are never merged (recorded restriction).
    5. Enforce the exact-partition contract over every original finding.

    A failed batch or merge keeps deterministic singletons / pre-merge
    groups with a degraded stage event — never a silent "success".
    """
    confirmed = db.get_findings(ctx.run_id, validation_status="confirmed")
    if not confirmed:
        log.info("[%s] dedupe: no confirmed findings to cluster", ctx.run_id)
        return 0

    sc = ctx.stage("dedupe")
    extras = ctx.extras()
    preclustered = _precluster_groups(confirmed)
    descriptors = {f.finding_id: _finding_descriptor(f) for f in confirmed}
    by_id = {f.finding_id: f for f in confirmed}

    try:
        batches = _build_batches(
            list(descriptors.values()), preclustered, extras
        )
    except DedupeOversizeError as error:
        log.error("[%s] dedupe: %s", ctx.run_id, error)
        db.record_stage_event(
            ctx.run_id,
            "dedupe",
            {
                "category": "degraded",
                "reason": "oversize_descriptor",
                "error": str(error)[:500],
            },
        )
        return _fallback_singletons(ctx, db, confirmed)

    db.record_stage_event(
        ctx.run_id,
        "dedupe",
        {
            "category": "input_size",
            "findings": len(confirmed),
            "batches": len(batches),
            "max_batch_chars": max(
                _serialized_len(
                    _batch_user_input(
                        b,
                        preclustered,
                        extras,
                        f"dedupe-batch-{i + 1:04d}",
                    )
                )
                for i, b in enumerate(batches)
            ),
        },
    )
    log.info(
        "[%s] dedupe: clustering %d confirmed findings in %d payload-bounded "
        "batches (%d deterministic pre-clusters)",
        ctx.run_id,
        len(confirmed),
        len(batches),
        len(preclustered),
    )

    # ---- per-batch adjudication -------------------------------------
    batch_groups: dict[str, list[dict]] = {}   # batch_id -> groups
    degraded_batches: list[str] = []
    for index, batch in enumerate(batches, start=1):
        batch_id = f"dedupe-batch-{index:04d}"
        user_input = _batch_user_input(batch, preclustered, extras, batch_id)
        artifact_dir = ctx.work_dir("dedupe", "batches")
        (artifact_dir / f"{batch_id}.request.json").write_text(
            json.dumps(user_input, ensure_ascii=False, indent=1, sort_keys=True)
        )
        try:
            result = await run_agent(
                stage="dedupe",
                prompt_file=ctx.prompt("05-dedupe"),
                user_input=user_input,
                schema_file=ctx.schema("dedupe_output"),
                allowed_tools=sc.tools,
                model=sc.model,
                profile=ctx.profile("dedupe"),
                cwd=ctx.repo_path,
                add_dirs=[ctx.repo_path],
                max_turns=sc.max_turns,
                permission_mode=sc.permission_mode,
                artifact_dir=ctx.results_dir("dedupe"),
                artifact_name=batch_id,
                repair_attempts=sc.repair_attempts,
                deadline=ctx.deadline,
            )
        except (AgentRunError, TransientAgentError) as e:
            log.warning(
                "[%s] dedupe batch %s failed: %s — deterministic singletons",
                ctx.run_id, batch_id, e,
            )
            db.record_stage_event(
                ctx.run_id,
                "dedupe",
                {
                    "category": "degraded",
                    "reason": "batch_failed",
                    "batch_id": batch_id,
                    "error": f"{type(e).__name__}: {e}"[:500],
                },
            )
            degraded_batches.append(batch_id)
            batch_groups[batch_id] = _singleton_groups(
                by_id[fid] for fid in sorted(d["finding_id"] for d in batch)
            )
            continue
        groups = result.payload.get("groups", [])
        (artifact_dir / f"{batch_id}.response.json").write_text(
            json.dumps(result.payload, ensure_ascii=False, indent=1, sort_keys=True)
        )
        db.record_agent_result(ctx.run_id, "dedupe", batch_id, result)
        db.add_artifact(
            ctx.run_id, "dedupe", batch_id, "batch", str(result.artifact_path)
        )
        expected_ids = {d["finding_id"] for d in batch}
        try:
            validate_dedupe_partition(expected_ids, groups)
        except StageContractError as error:
            log.warning(
                "[%s] dedupe batch %s violated semantic contract: %s — "
                "deterministic singletons",
                ctx.run_id, batch_id, error,
            )
            db.record_stage_event(
                ctx.run_id,
                "dedupe",
                {
                    "category": "degraded",
                    "reason": "batch_contract_violation",
                    "batch_id": batch_id,
                    "error": str(error)[:500],
                },
            )
            degraded_batches.append(batch_id)
            batch_groups[batch_id] = _singleton_groups(
                by_id[fid] for fid in sorted(expected_ids)
            )
            continue
        batch_groups[batch_id] = groups

    # ---- representative merge pass (within partition only) ----------
    partition_of = {
        fid: _partition_key(d) for fid, d in descriptors.items()
    }
    batch_of_finding = {
        d["finding_id"]: f"dedupe-batch-{index:04d}"
        for index, batch in enumerate(batches, start=1)
        for d in batch
    }
    groups_by_partition: dict[tuple[str, str], list[dict]] = {}
    batches_of_partition: dict[tuple[str, str], set[str]] = {}
    for batch_id, groups in batch_groups.items():
        for g in groups:
            key = partition_of[g["canonical_finding_id"]]
            groups_by_partition.setdefault(key, []).append(g)
            batches_of_partition.setdefault(key, set()).add(batch_id)

    # Cross-batch duplicate candidates: findings whose deterministic
    # precluster group spans more than one batch of this partition.
    cross_batch_linked: set[str] = set()
    for pre in preclustered:
        member_batches = {
            batch_of_finding[m]
            for m in pre["member_finding_ids"]
            if m in batch_of_finding
        }
        if len(member_batches) > 1:
            cross_batch_linked.update(pre["member_finding_ids"])

    db.record_stage_event(
        ctx.run_id,
        "dedupe",
        {
            "category": "restriction",
            "reason": "merge_scope",
            "detail": (
                "cross-partition groups are never merged; cross-batch "
                "merging adjudicates all representatives when they fit the "
                "payload cap, otherwise only precluster-linked "
                "cross-batch candidates"
            ),
        },
    )

    def _merge_representatives(groups_to_merge: list[dict]) -> int:
        return _serialized_len(
            _merge_user_input(
                key,
                [_merge_descriptor(descriptors[g["canonical_finding_id"]])
                 for g in groups_to_merge],
                groups_to_merge,
                extras,
            )
        )

    merged_groups: list[dict] = []
    for key in sorted(groups_by_partition):
        partition_groups = groups_by_partition[key]
        if len(batches_of_partition[key]) <= 1:
            # Single batch already adjudicated the complete partition.
            merged_groups.extend(partition_groups)
            continue
        candidate_groups = [
            g
            for g in partition_groups
            if any(
                fid in cross_batch_linked for fid in g["member_finding_ids"]
            )
        ]
        pass_through = [
            g for g in partition_groups if g not in candidate_groups
        ]
        if not candidate_groups:
            db.record_stage_event(
                ctx.run_id,
                "dedupe",
                {
                    "category": "degraded",
                    "reason": "merge_candidates_none",
                    "partition": {"file": key[0], "vuln_class": key[1]},
                },
            )
            merged_groups.extend(partition_groups)
            continue
        if _merge_representatives(partition_groups) > _DEDUPE_PAYLOAD_CAP:
            to_merge = candidate_groups
            if _merge_representatives(to_merge) > _DEDUPE_PAYLOAD_CAP:
                db.record_stage_event(
                    ctx.run_id,
                    "dedupe",
                    {
                        "category": "degraded",
                        "reason": "merge_skipped_oversize",
                        "partition": {"file": key[0], "vuln_class": key[1]},
                    },
                )
                merged_groups.extend(partition_groups)
                continue
        else:
            to_merge = partition_groups
        merge_status, merged = await _merge_partition(
            ctx, db, key, to_merge, descriptors, extras, sc
        )
        if merged is None:
            # Degraded: keep the batch-level groups for this partition.
            db.record_stage_event(
                ctx.run_id,
                "dedupe",
                {
                    "category": "degraded",
                    "reason": f"merge_{merge_status}",
                    "partition": {"file": key[0], "vuln_class": key[1]},
                },
            )
            merged_groups.extend(partition_groups)
        else:
            merged_groups.extend(merged)
            merged_groups.extend(
                g for g in pass_through if to_merge is not partition_groups
            )

    # ---- final exact-partition contract ----------------------------
    try:
        validate_dedupe_partition(
            {f.finding_id for f in confirmed}, merged_groups
        )
    except StageContractError as error:
        db.record_stage_event(
            ctx.run_id,
            "dedupe",
            {
                "category": "failed",
                "reason": "final_partition_violation",
                "error": str(error)[:500],
            },
        )
        raise DedupeContractError(
            f"dedupe final partition invalid: {error}"
        ) from error

    # Feedback loops may run dedupe again over findings that were already
    # grouped in an earlier pass; a model-reused group_id with a different
    # payload must not raise StateConflictError mid-run. Deterministic
    # collision resolution: re-derive the id from the member set.
    existing_ids = {
        row["group_id"]
        for row in db._conn.execute(
            "SELECT group_id FROM dedupe_groups WHERE run_id = ?",
            (ctx.run_id,),
        )
    }
    seen_ids: set[str] = set()
    renumbered = 0
    for g in merged_groups:
        if g["group_id"] in existing_ids or g["group_id"] in seen_ids:
            digest = hashlib.sha256(
                "\x00".join(sorted(g["member_finding_ids"])).encode()
            ).hexdigest()[:12]
            new_id = f"g_d{digest}"
            if new_id in existing_ids or new_id in seen_ids:
                new_id = f"g_d{digest}_{len(seen_ids)}"
            if new_id != g["group_id"]:
                renumbered += 1
            g["group_id"] = new_id
        seen_ids.add(g["group_id"])
    if renumbered:
        db.record_stage_event(
            ctx.run_id,
            "dedupe",
            {
                "category": "degraded",
                "reason": "group_id_collision_renumbered",
                "count": renumbered,
            },
        )

    # The new partition replaces the previous generation: retire prior
    # group rows (kept as marked history) so no active group is left
    # without members after reassignment.
    db.supersede_dedupe_groups(ctx.run_id)
    for g in merged_groups:
        db.add_dedupe_group(ctx.run_id, g)
        canonical = g["canonical_finding_id"]
        for fid in g["member_finding_ids"]:
            db.assign_finding_group(
                ctx.run_id, fid, g["group_id"], fid == canonical
            )
        _apply_canonical_replacement(ctx, db, g)

    db.record_stage_event(
        ctx.run_id,
        "dedupe",
        {
            "category": "complete",
            "degraded_batches": degraded_batches,
            "findings": len(confirmed),
            "groups": len(merged_groups),
        },
    )
    log.info(
        "[%s] dedupe: %d findings → %d groups",
        ctx.run_id, len(confirmed), len(merged_groups),
    )
    return len(merged_groups)


async def _merge_partition(
    ctx: StageContext,
    db: StateDB,
    key: tuple[str, str],
    partition_groups: list[dict],
    descriptors: dict[str, dict],
    extras: dict,
    sc,
) -> tuple[str, list[dict] | None]:
    """One bounded merge call over the given partition groups.

    Returns (status, groups): status "merged" with expanded groups, or
    "failed" when the merge call or its contract failed (caller records
    the degraded event). Payload sizing is the caller's decision."""
    canonical_ids = [g["canonical_finding_id"] for g in partition_groups]
    representatives = [
        _merge_descriptor(descriptors[cid]) for cid in sorted(canonical_ids)
    ]
    user_input = _merge_user_input(key, representatives, partition_groups, extras)
    digest = hashlib.sha256(
        f"{key[0]}\x00{key[1]}".encode()
    ).hexdigest()[:12]
    merge_id = f"dedupe-merge-{digest}"
    artifact_dir = ctx.work_dir("dedupe", "merges")
    (artifact_dir / f"{merge_id}.request.json").write_text(
        json.dumps(user_input, ensure_ascii=False, indent=1, sort_keys=True)
    )
    try:
        result = await run_agent(
            stage="dedupe",
            prompt_file=ctx.prompt("05-dedupe"),
            user_input=user_input,
            schema_file=ctx.schema("dedupe_output"),
            allowed_tools=sc.tools,
            model=sc.model,
            profile=ctx.profile("dedupe"),
            cwd=ctx.repo_path,
            add_dirs=[ctx.repo_path],
            max_turns=sc.max_turns,
            permission_mode=sc.permission_mode,
            artifact_dir=ctx.results_dir("dedupe"),
            artifact_name=merge_id,
            repair_attempts=sc.repair_attempts,
            deadline=ctx.deadline,
        )
    except (AgentRunError, TransientAgentError) as e:
        log.warning(
            "[%s] dedupe merge for %s failed: %s — keeping batch groups",
            ctx.run_id, key, e,
        )
        return "failed", None
    groups = result.payload.get("groups", [])
    (artifact_dir / f"{merge_id}.response.json").write_text(
        json.dumps(result.payload, ensure_ascii=False, indent=1, sort_keys=True)
    )
    db.record_agent_result(ctx.run_id, "dedupe", merge_id, result)
    db.add_artifact(
        ctx.run_id, "dedupe", merge_id, "merge", str(result.artifact_path)
    )
    try:
        validate_dedupe_partition(set(canonical_ids), groups)
    except StageContractError as error:
        log.warning(
            "[%s] dedupe merge for %s violated contract: %s — keeping "
            "batch groups",
            ctx.run_id, key, error,
        )
        return "failed", None
    members_of = {
        g["canonical_finding_id"]: g["member_finding_ids"]
        for g in partition_groups
    }
    expanded: list[dict] = []
    for merged_group in groups:
        members = sorted(
            fid
            for cid in merged_group["member_finding_ids"]
            for fid in members_of[cid]
        )
        canonical = merged_group["canonical_finding_id"]
        # Keep the batch group_id of the surviving canonical.
        group_id = next(
            g["group_id"]
            for g in partition_groups
            if g["canonical_finding_id"] == canonical
        )
        out = dict(merged_group)
        out["group_id"] = group_id
        out["member_finding_ids"] = members
        expanded.append(out)
    return "merged", expanded


def _singleton_groups(findings) -> list[dict]:
    """Deterministic singleton groups (schema-valid root_cause strings)."""
    return [
        {
            "group_id": (
                f"g_{f.finding_id[2:]}"
                if f.finding_id.startswith("f_")
                else f"g_{f.finding_id}"
            ),
            "root_cause": (
                f"Deterministic singleton for {f.file}:{f.line_start} "
                f"({f.vuln_class}) — batch failure fallback"
            ),
            "canonical_finding_id": f.finding_id,
            "member_finding_ids": [f.finding_id],
        }
        for f in findings
    ]


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
    db.supersede_dedupe_groups(ctx.run_id)
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
