"""Stage 8: Report — schema-validated final document."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from codesec.contracts import StageContractError
from codesec.json_utils import validate_schema
from codesec.runner import AgentRunError, TransientAgentError, run_agent
from codesec.state import StateDB
from codesec.stages._common import StageContext

log = logging.getLogger(__name__)

_SEVERITY_ORDER = ("critical", "high", "medium", "low", "informational")


def _drop_one_severity(severity: str) -> str:
    try:
        i = _SEVERITY_ORDER.index(severity)
    except ValueError:
        return severity
    return _SEVERITY_ORDER[min(i + 1, len(_SEVERITY_ORDER) - 1)]


def _arbiter_severity(f) -> str | None:
    arbiter = (f.validation_json or {}).get("arbiter_severity")
    return arbiter if arbiter in _SEVERITY_ORDER else None


def _production_viable(f) -> dict | None:
    """Return the validation's production_viable verdict when it blocks
    production impact ('no'); other verdicts need no annotation."""
    pv = (f.validation_json or {}).get("production_viable")
    if isinstance(pv, dict) and pv.get("verdict") == "no":
        out = {"verdict": "no"}
        if pv.get("reason"):
            out["reason"] = str(pv["reason"])
        return out
    return None


def _effective_severity(f) -> str:
    """W2r+A5r: the arbiter's severity wins over the finding's own when
    present (it already accounts for preconditions); a production_viable
    'no' verdict drops one severity step on top of whichever base applies."""
    sev = _arbiter_severity(f) or f.severity
    if _production_viable(f) is not None:
        sev = _drop_one_severity(sev)
    return sev


def _recompute_summary(report: dict) -> None:
    by_sev: dict[str, int] = {}
    for entry in report.get("findings", []):
        sev = entry.get("severity")
        if sev:
            by_sev[sev] = by_sev.get(sev, 0) + 1
    report["summary"] = {
        "total": len(report.get("findings", [])),
        "by_severity": by_sev,
    }


# W12 report grader output contract. The schemas/ directory is shared
# between streams, so the grader's schema is generated into the run work
# dir instead of shipped as a file — the contract is also embedded
# verbatim in prompts/09-grade.md.
_GRADE_SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "GradeOutput",
    "type": "object",
    "required": ["evidence_score", "issues", "demote_severity", "reason"],
    "additionalProperties": False,
    "properties": {
        "evidence_score": {"type": "integer", "minimum": 0, "maximum": 10},
        "issues": {"type": "array", "items": {"type": "string"}},
        "demote_severity": {"type": "boolean"},
        "reason": {"type": "string"},
    },
}


def _grade_schema_path(ctx: StageContext) -> Path:
    path = ctx.work_dir("report") / "grade.schema.json"
    if not path.exists():
        path.write_text(json.dumps(_GRADE_SCHEMA, indent=2) + "\n")
    return path


def _needs_validation_entries(db: StateDB, run_id: str) -> list[dict]:
    """W5: findings the panel could not settle render in their own
    section — blockers + validation_plan, never a severity."""
    out: list[dict] = []
    for f in db.get_findings(run_id, validation_status="needs_more_info"):
        v = f.validation_json or {}
        blockers = v.get("blockers")
        entry = {
            "finding_id": f.finding_id,
            "file": f.file,
            "vuln_class": f.vuln_class,
            "blockers": (
                [str(b) for b in blockers] if isinstance(blockers, list) else []
            ),
        }
        plan = v.get("validation_plan")
        if isinstance(plan, dict):
            entry["validation_plan"] = {
                key: str(plan[key])
                for key in ("local", "deployment")
                if plan.get(key)
            }
        out.append(entry)
    return sorted(out, key=lambda item: item["finding_id"])


def _upstream_annotations(ctx: StageContext, reachable) -> dict:
    """W15: per confirmed finding, upstream history + fixed/unfixed/unknown.

    Resolved lazily and orchestrator-side only — the upstream clone lives
    in the run work dir, never inside an agent sandbox. Any failure
    degrades to "no annotations"."""
    if not ctx.upstream or not reachable:
        return {}
    from codesec import upstream as upstream_mod

    repo = upstream_mod.ensure_checkout(
        ctx.upstream, ctx.work_dir("report", "upstream")
    )
    if repo is None:
        return {}
    out: dict = {}
    for f, _trace in reachable:
        out[f.finding_id] = upstream_mod.status_for_finding(
            repo, f.file, f.evidence
        )
    return out


def _apply_upstream(report: dict, annotations: dict) -> None:
    """Annotate entries with upstream_status; findings already fixed
    upstream leave the main table for the fixed_upstream footnote."""
    if not annotations:
        return
    kept: list[dict] = []
    fixed: list[dict] = []
    for entry in report.get("findings", []):
        info = annotations.get(entry.get("finding_id"))
        if info is None:
            kept.append(entry)
            continue
        entry["upstream_status"] = info["status"]
        if info["status"] == "fixed":
            fixed.append(
                {
                    "finding_id": entry["finding_id"],
                    "title": entry.get("title", ""),
                    "file": entry.get("file", ""),
                    "vuln_class": entry.get("vuln_class", ""),
                }
            )
        else:
            kept.append(entry)
    report["findings"] = kept
    if fixed:
        existing = {
            e.get("finding_id") for e in report.get("fixed_upstream", [])
        }
        report.setdefault("fixed_upstream", []).extend(
            e for e in sorted(fixed, key=lambda i: i["finding_id"])
            if e["finding_id"] not in existing
        )
    _recompute_summary(report)


async def run_deterministic_report(ctx: StageContext, db: StateDB) -> Path:
    """Render authoritative final membership and a separate review queue."""
    reachable = db.get_reachable_canonical_findings(ctx.run_id)
    target = {"repo_path": str(ctx.repo_path)}
    report = _build_fallback_report(ctx, db, reachable, target)
    _apply_upstream(report, _upstream_annotations(ctx, reachable))
    await _grade_report(ctx, db, report, reachable)
    errors = validate_schema(report, ctx.schema("report"))
    if errors:
        raise StageContractError(
            f"deterministic report violates report schema: {errors[:5]}"
        )

    out_dir = ctx.results_dir("report")
    report_path = out_dir / "report.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")

    review_findings = []
    for finding in db.get_findings(ctx.run_id):
        if finding.validation_status == "needs_more_info":
            review_findings.append(
                {
                    "finding_id": finding.finding_id,
                    "reason": "validation_needs_more_info",
                    "validation": finding.validation_json,
                }
            )
        elif finding.validation_status == "confirmed" and finding.is_canonical:
            trace = db.get_trace(ctx.run_id, finding.finding_id)
            if trace and trace.get("status") == "uncertain":
                review_findings.append(
                    {
                        "finding_id": finding.finding_id,
                        "reason": "trace_uncertain",
                        "trace": trace,
                    }
                )

    review = {
        "run_id": ctx.run_id,
        "findings": sorted(
            review_findings, key=lambda item: item["finding_id"]
        ),
        "failed_tasks": sorted(
            task.task_id
            for task in db.get_all_tasks(ctx.run_id)
            if task.status == "failed"
        ),
    }
    review_path = out_dir / "review_queue.json"
    review_path.write_text(json.dumps(review, indent=2, sort_keys=True) + "\n")
    db.add_artifact(
        ctx.run_id, "report", None, "deterministic_json", str(report_path)
    )
    db.add_artifact(
        ctx.run_id, "report", None, "review_queue", str(review_path)
    )
    return report_path


async def run_report(ctx: StageContext, db: StateDB) -> Path:
    reachable = db.get_reachable_canonical_findings(ctx.run_id)
    ready = []
    for f, trace in reachable:
        ready.append({
            "finding": f.raw_json,
            "validation": f.validation_json,
            "trace": trace,
            "variants": _group_members_excluding(db, ctx.run_id, f.group_id, f.finding_id)
                       if f.group_id else [],
            "severity_guidance": {
                "recommended_severity": _effective_severity(f),
            },
        })

    upstream = _upstream_annotations(ctx, reachable)
    for item, (f, _trace) in zip(ready, reachable):
        info = upstream.get(f.finding_id)
        if info is not None:
            item["upstream_status"] = info["status"]
            item["upstream_history"] = info["history"]

    sc = ctx.stage("report")
    target = {"repo_path": str(ctx.repo_path)}
    needs_validation = _needs_validation_entries(db, ctx.run_id)
    hardening = db.get_hardening_notes(ctx.run_id)[:100]
    user_input = {"run_id": ctx.run_id, "target": target, "ready_findings": ready,
                  "needs_validation": needs_validation,
                  "hardening": hardening,
                  **ctx.extras()}

    out_path = ctx.results_dir("report") / "report.json"

    if not ready:
        # No reachable findings — emit a minimal empty report without burning an agent call.
        empty = {
            "run_id": ctx.run_id,
            "target": target,
            "summary": {"total": 0, "by_severity": {}},
            "findings": [],
        }
        if needs_validation:
            empty["needs_validation"] = needs_validation
        if hardening:
            empty["hardening"] = hardening
        out_path.write_text(json.dumps(empty, indent=2))
        log.info("[%s] report: no reachable findings — wrote empty report to %s",
                 ctx.run_id, out_path)
        return out_path

    try:
        result = await run_agent(
            stage="report",
            prompt_file=ctx.prompt("08-report"),
            user_input=user_input,
            schema_file=ctx.schema("report"),
            allowed_tools=sc.tools,
            model=sc.model,
            profile=ctx.profile("report"),
            cwd=ctx.repo_path,
            add_dirs=[ctx.repo_path],
            max_turns=sc.max_turns,
            permission_mode=sc.permission_mode,
            artifact_dir=ctx.results_dir("report"),
            artifact_name="report_agent",
            repair_attempts=max(sc.repair_attempts, 2),  # report MUST validate
        )
    except (AgentRunError, TransientAgentError) as e:
        log.error("[%s] report agent failed: %s — emitting fallback report",
                  ctx.run_id, e)
        fallback = _build_fallback_report(ctx, db, reachable, target)
        _apply_upstream(fallback, upstream)
        await _grade_report(ctx, db, fallback, reachable)
        out_path.write_text(json.dumps(fallback, indent=2))
        return out_path

    db.record_agent_result(ctx.run_id, "report", None, result)
    db.add_artifact(ctx.run_id, "report", None, "jsonl", str(result.artifact_path))
    # The section contents are mechanical — if the model omitted them while
    # inputs were non-empty, backfill the deterministic rendering so the two
    # pipeline paths stay equivalent.
    if needs_validation and not result.payload.get("needs_validation"):
        result.payload["needs_validation"] = needs_validation
    if hardening and not result.payload.get("hardening"):
        result.payload["hardening"] = hardening
    _enforce_severity_rules(ctx, result.payload, reachable)
    _apply_upstream(result.payload, upstream)
    await _grade_report(ctx, db, result.payload, reachable)
    out_path.write_text(json.dumps(result.payload, indent=2))
    log.info("[%s] report: %d findings written to %s",
             ctx.run_id, len(result.payload.get("findings", [])), out_path)
    return out_path


def _group_members_excluding(db: StateDB, run_id: str, group_id: str,
                             exclude: str) -> list[str]:
    return db.group_member_ids(run_id, group_id, exclude=exclude)


def _build_fallback_report(ctx: StageContext, db: StateDB,
                           reachable, target: dict) -> dict:
    by_sev: dict[str, int] = {}
    findings_out = []
    for f, trace in reachable:
        sev = _effective_severity(f)
        by_sev[sev] = by_sev.get(sev, 0) + 1
        findings_out.append({
            "finding_id": f.finding_id,
            "title": f"{f.vuln_class} in {f.file}",
            "severity": sev,
            "vuln_class": f.vuln_class,
            "file": f.file,
            "line_start": f.line_start,
            "line_end": f.line_end,
            "description": f.description,
            "evidence": f.evidence,
            "trace": {
                "entry_points": trace.get("entry_points", []),
                "call_chain": trace.get("call_chain", []),
            },
            "recommendation": "Review the sink and add input validation / use a safe API.",
            **({"cwe": f.raw_json["cwe"]} if f.raw_json.get("cwe") else {}),
            **({"production_viable": pv}
               if (pv := _production_viable(f)) is not None else {}),
        })
    report = {
        "run_id": ctx.run_id,
        "target": target,
        "summary": {"total": len(findings_out), "by_severity": by_sev},
        "findings": findings_out,
    }
    needs_validation = _needs_validation_entries(db, ctx.run_id)
    if needs_validation:
        report["needs_validation"] = needs_validation
    hardening = db.get_hardening_notes(ctx.run_id)[:100]
    if hardening:
        report["hardening"] = hardening
    return report


def _enforce_severity_rules(
    ctx: StageContext, report: dict, reachable
) -> None:
    """W2r+A5r post-pass on the model's report: when the validation panel's
    arbiter set a severity it is authoritative — the model may not promote
    above it (and must not stack the trace downgrade on top). A
    production_viable 'no' entry must carry the annotation."""
    by_id = {f.finding_id: f for f, _trace in reachable}
    changed = False
    for entry in report.get("findings", []):
        f = by_id.get(entry.get("finding_id"))
        if f is None:
            continue
        pv = _production_viable(f)
        if pv is not None and "production_viable" not in entry:
            entry["production_viable"] = pv
            changed = True
        if _arbiter_severity(f) is not None:
            expected = _effective_severity(f)
            if entry.get("severity") != expected:
                log.info(
                    "[%s] report: severity %s -> %s on %s per arbiter/"
                    "production-viability rules",
                    ctx.run_id, entry.get("severity"), expected, f.finding_id,
                )
                entry["severity"] = expected
                changed = True
    if changed:
        _recompute_summary(report)


async def _grade_report(ctx: StageContext, db: StateDB, report: dict,
                        reachable) -> None:
    """W12 fresh-eyes grader, behind `report.grade` (default off).

    One no-tools agent call per report entry; the grader may only demote
    (one-step severity drop + issue list) — never promote or confirm.
    Grader failures degrade gracefully: the entry ships ungraded.
    """
    sc = ctx.config.stages.get("report")
    if sc is None or not sc.options.get("grade", False):
        return
    findings = report.get("findings", [])
    if not findings:
        return
    by_id = {f.finding_id: (f, trace) for f, trace in reachable}
    schema_path = _grade_schema_path(ctx)
    for entry in findings:
        fid = entry.get("finding_id")
        pair = by_id.get(fid)
        if pair is None:
            continue
        f, trace = pair
        try:
            result = await run_agent(
                stage="report-grade",
                prompt_file=ctx.prompt("09-grade"),
                user_input={
                    "report_entry": entry,
                    "finding": f.raw_json,
                    "validation": f.validation_json,
                    "trace": trace,
                },
                schema_file=schema_path,
                allowed_tools=[],
                model=sc.model,
                profile=ctx.profile("report"),
                cwd=ctx.repo_path,
                add_dirs=[ctx.repo_path],
                max_turns=sc.max_turns,
                permission_mode=sc.permission_mode,
                artifact_dir=ctx.results_dir("report"),
                artifact_name=f"grade_{fid}",
                repair_attempts=sc.repair_attempts,
            )
        except (AgentRunError, TransientAgentError) as error:
            log.warning(
                "[%s] report grader failed for %s: %s — entry ships ungraded",
                ctx.run_id, fid, error,
            )
            continue
        db.record_agent_result(ctx.run_id, "report-grade", fid, result)
        grade = result.payload
        demoted = bool(grade.get("demote_severity"))
        entry["grading"] = {
            "evidence_score": int(grade.get("evidence_score", 0)),
            "issues": [
                str(i) for i in grade.get("issues", []) if str(i).strip()
            ],
            "demoted": demoted,
            "reason": str(grade.get("reason", "")),
        }
        if demoted:
            entry["severity"] = _drop_one_severity(entry["severity"])
    _recompute_summary(report)
