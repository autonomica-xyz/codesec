"""Semantic stage contracts that JSON Schema cannot express."""

from __future__ import annotations

from collections import Counter
from pathlib import Path


class StageContractError(RuntimeError):
    """A shape-valid stage payload violates pipeline membership invariants."""


def validate_task_batch(tasks: list[dict], repo_root: Path) -> None:
    """Require unique task IDs and concrete files inside the repository."""
    ids = [str(task.get("task_id", "")) for task in tasks]
    duplicates = sorted(
        task_id
        for task_id, count in Counter(ids).items()
        if count > 1
    )
    if duplicates:
        raise StageContractError(f"duplicate task IDs: {duplicates}")

    root = repo_root.resolve()
    for task in tasks:
        task_id = task.get("task_id")
        target_files = task.get("target_files") or []
        if not target_files:
            raise StageContractError(
                f"task {task_id!r} has no concrete target files"
            )
        for value in target_files:
            reported = Path(str(value))
            resolved = (root / reported).resolve()
            if reported.is_absolute() or not resolved.is_relative_to(root):
                raise StageContractError(
                    f"task {task_id!r} target is outside repository: {value!r}"
                )
            if not resolved.is_file():
                raise StageContractError(
                    f"task {task_id!r} target does not exist: {value!r}"
                )


def filter_task_batch(tasks: list[dict], repo_root: Path) -> list[dict]:
    """Drop tasks whose targets are missing/outside the repo.

    Models invent filenames (e.g. common/closing_fee.c when only
    closing_fee.h exists). Raising here used to abort the whole pipeline
    after a successful hunt. Keep validate_task_batch() strict for tests;
    recon/gapfill should call this filter instead.
    """
    kept: list[dict] = []
    root = repo_root.resolve()
    seen: set[str] = set()
    for task in tasks:
        task_id = str(task.get("task_id", "") or "")
        if not task_id or task_id in seen:
            continue
        target_files = task.get("target_files") or []
        if not target_files:
            continue
        ok_files = []
        bad = False
        for value in target_files:
            reported = Path(str(value))
            resolved = (root / reported).resolve()
            if reported.is_absolute() or not resolved.is_relative_to(root):
                bad = True
                break
            if not resolved.is_file():
                bad = True
                break
            ok_files.append(str(value))
        if bad or not ok_files:
            continue
        task = dict(task)
        task["target_files"] = ok_files
        seen.add(task_id)
        kept.append(task)
    return kept


def _hunt_finding_violation(
    finding: dict,
    root: Path,
    seen_ids: set[str],
    reserved_finding_ids: set[str],
) -> str | None:
    """Per-finding contract check shared by validate/filter paths."""
    finding_id = str(finding.get("finding_id", ""))
    if finding_id in seen_ids:
        return f"duplicate finding IDs: [{finding_id!r}]"
    if finding_id in reserved_finding_ids:
        return f"finding IDs already exist in this run: [{finding_id!r}]"
    if not str(finding.get("evidence_snippet", "")).strip():
        return f"finding {finding_id!r} has empty evidence"
    reported = Path(str(finding.get("file", "")))
    resolved = (root / reported).resolve()
    if reported.is_absolute() or not resolved.is_relative_to(root):
        return (
            f"finding {finding_id!r} file is outside repository: "
            f"{finding.get('file')!r}"
        )
    if not resolved.is_file():
        return (
            f"finding {finding_id!r} file does not exist: "
            f"{finding.get('file')!r}"
        )
    line_count = len(resolved.read_text(errors="replace").splitlines())
    line_start = finding.get("line_start")
    line_end = finding.get("line_end")
    if not (
        isinstance(line_start, int)
        and isinstance(line_end, int)
        and 1 <= line_start <= line_end <= line_count
    ):
        return (
            f"finding {finding_id!r} source range is invalid "
            f"for {finding.get('file')!r}: {line_start}-{line_end} "
            f"(file has {line_count} lines)"
        )
    return None


def validate_hunt_output(
    expected_task_id: str,
    payload: dict,
    repo_root: Path,
    *,
    reserved_finding_ids: set[str] | None = None,
) -> None:
    """Validate Hunt facts that depend on its authoritative request."""
    if payload.get("task_id") != expected_task_id:
        raise StageContractError(
            "hunt output task_id does not match request: "
            f"expected={expected_task_id!r}, actual={payload.get('task_id')!r}"
        )
    root = repo_root.resolve()
    seen: set[str] = set()
    reserved = reserved_finding_ids or set()
    for finding in payload.get("findings", []):
        violation = _hunt_finding_violation(
            finding, root, seen, reserved
        )
        if violation is not None:
            raise StageContractError(violation)
        seen.add(str(finding.get("finding_id", "")))

    # Optional top-level buckets (W5/W9). These are advisory payloads the
    # hunter volunteers — malformed content is sanitized, never a reason
    # to reject an otherwise valid hunt output.
    _sanitize_optional_list(payload, "hardening", ("file", "note"))
    _sanitize_optional_list(payload, "uncovered", ("surface",))


def filter_hunt_findings(
    expected_task_id: str,
    payload: dict,
    repo_root: Path,
    *,
    reserved_finding_ids: set[str] | None = None,
) -> tuple[list[dict], list[dict]]:
    """Drop findings that violate per-finding invariants.

    Models occasionally emit one bad row (invented path, off-by-a-few
    line range) inside an otherwise valid hunt payload. Failing the
    whole task — and with it the run's stage coverage — used to abort
    the pipeline, matching the old recon behavior that filter_task_batch
    replaced. Keep validate_hunt_output() strict for tests; hunt calls
    this filter instead. A payload-level task_id mismatch still raises
    (the response is not for this task at all). Returns (kept, dropped)
    where dropped entries are {"finding_id", "reason"}."""
    if payload.get("task_id") != expected_task_id:
        raise StageContractError(
            "hunt output task_id does not match request: "
            f"expected={expected_task_id!r}, actual={payload.get('task_id')!r}"
        )
    root = repo_root.resolve()
    seen: set[str] = set()
    reserved = reserved_finding_ids or set()
    kept: list[dict] = []
    dropped: list[dict] = []
    for finding in payload.get("findings", []) or []:
        violation = _hunt_finding_violation(
            finding, root, seen, reserved
        )
        if violation is None:
            kept.append(finding)
            seen.add(str(finding.get("finding_id", "")))
        else:
            dropped.append(
                {"finding_id": finding.get("finding_id"), "reason": violation}
            )
    _sanitize_optional_list(payload, "hardening", ("file", "note"))
    _sanitize_optional_list(payload, "uncovered", ("surface",))
    return kept, dropped


def _sanitize_optional_list(
    payload: dict, key: str, required: tuple[str, ...]
) -> None:
    """Normalize an optional top-level list in place.

    Non-list values become []; non-dict members and members missing every
    `required` field are dropped; required fields are coerced to str.
    Deliberately permissive: callers keep the payload either way."""
    value = payload.get(key)
    if value is None:
        return
    if not isinstance(value, list):
        payload[key] = []
        return
    cleaned: list[dict] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        entry = dict(item)
        for field in required:
            if field in entry and entry[field] is not None:
                entry[field] = str(entry[field])
        if not any(str(entry.get(field) or "").strip() for field in required):
            continue
        cleaned.append(entry)
    payload[key] = cleaned


def validate_validation_output(expected_finding_id: str, payload: dict) -> None:
    if payload.get("finding_id") != expected_finding_id:
        raise StageContractError(
            "validation output finding_id does not match request: "
            f"expected={expected_finding_id!r}, "
            f"actual={payload.get('finding_id')!r}"
        )
    if not str(payload.get("alternative_explanation", "")).strip():
        raise StageContractError(
            "validation output requires a concrete alternative_explanation"
        )
    if (
        payload.get("verdict") == "needs_more_info"
        and not str(payload.get("suggested_test", "")).strip()
    ):
        raise StageContractError(
            "needs_more_info validation requires a concrete suggested_test"
        )


def validate_trace_output(
    expected_finding_id: str,
    payload: dict,
    repo_root: Path,
    *,
    expected_sink_file: str | None = None,
    expected_sink_range: tuple[int, int] | None = None,
) -> None:
    if payload.get("finding_id") != expected_finding_id:
        raise StageContractError(
            "trace output finding_id does not match request: "
            f"expected={expected_finding_id!r}, "
            f"actual={payload.get('finding_id')!r}"
        )
    status = payload.get("status")
    expected_reachable = {
        "reachable": True,
        "unreachable": False,
        "uncertain": None,
    }
    if (
        status not in expected_reachable
        or payload.get("reachable") is not expected_reachable[status]
    ):
        raise StageContractError(
            f"trace {expected_finding_id!r} status and reachable flag disagree"
        )
    if status == "reachable" and not (
        payload.get("entry_points")
        and payload.get("external_inputs")
        and len(payload.get("call_chain", [])) >= 1
    ):
        raise StageContractError(
            f"reachable trace {expected_finding_id!r} lacks an entry point, "
            "external input, or call chain"
        )
    if status == "unreachable" and not payload.get("blockers"):
        raise StageContractError(
            f"unreachable trace {expected_finding_id!r} lacks a concrete blocker"
        )
    if status == "uncertain":
        uncertainty = payload.get("uncertainty")
        if not (
            isinstance(uncertainty, dict)
            and uncertainty.get("kind") in {"source_evidence", "operational"}
            and isinstance(uncertainty.get("reason_code"), str)
            and uncertainty["reason_code"]
        ):
            raise StageContractError(
                f"uncertain trace {expected_finding_id!r} lacks a typed "
                "uncertainty (kind: source_evidence|operational, reason_code)"
            )

    root = repo_root.resolve()
    for frame in payload.get("call_chain", []):
        reported = Path(str(frame.get("file", "")))
        resolved = (root / reported).resolve()
        line = frame.get("line")
        if (
            reported.is_absolute()
            or not resolved.is_relative_to(root)
            or not resolved.is_file()
        ):
            raise StageContractError(
                f"trace frame file is outside repository or missing: {reported} "
                "(dependency/framework boundaries belong in boundary_frames)"
            )
        line_count = len(resolved.read_text(errors="replace").splitlines())
        if not isinstance(line, int) or not 1 <= line <= line_count:
            raise StageContractError(
                f"trace frame line is invalid for {reported}: {line} "
                f"(file has {line_count} lines)"
            )
    # Boundary frames are explicit assumptions about dependency/framework
    # crossings — validated for shape only, never treated as repo files.
    for boundary in payload.get("boundary_frames", []) or []:
        if not (
            isinstance(boundary, dict)
            and isinstance(boundary.get("boundary"), str)
            and boundary.get("boundary")
            and isinstance(boundary.get("location"), str)
            and isinstance(boundary.get("assumption"), str)
            and boundary.get("assumption")
        ):
            raise StageContractError(
                "boundary frame must carry boundary, location, and a "
                "non-empty assumption"
            )
    if (
        status == "reachable"
        and expected_sink_file is not None
        and expected_sink_range is not None
    ):
        final_frame = payload["call_chain"][-1]
        expected_file = Path(expected_sink_file).as_posix()
        actual_file = Path(str(final_frame.get("file", ""))).as_posix()
        start, end = expected_sink_range
        if (
            actual_file != expected_file
            or not start <= final_frame.get("line", 0) <= end
        ):
            raise StageContractError(
                f"reachable trace {expected_finding_id!r} does not end at "
                f"the authoritative sink {expected_file}:{start}-{end} "
                "(serialize the chain entry-to-sink; the final frame must be "
                "the supplied sink)"
            )


def trace_failure_reason_code(error: StageContractError) -> str:
    """Map a failed trace contract invariant to a machine-readable
    reason code (P04): the stored uncertain row says WHY it failed."""
    text = str(error)
    if "does not end at the authoritative sink" in text:
        return "sink_mismatch"
    if "outside repository or missing" in text:
        return "missing_repo_frame"
    if "line is invalid" in text:
        return "invalid_line"
    if "lacks a typed uncertainty" in text:
        return "missing_uncertainty_type"
    return "other_contract_violation"


def validate_dedupe_partition(
    expected_finding_ids: set[str], groups: list[dict]
) -> None:
    """Require groups to be an exact, non-overlapping input partition."""
    for group in groups:
        members = group.get("member_finding_ids", [])
        if group.get("canonical_finding_id") not in members:
            raise StageContractError(
                f"dedupe group {group.get('group_id')!r} canonical must be a member"
            )

    member_ids = [
        str(member)
        for group in groups
        for member in group.get("member_finding_ids", [])
    ]
    actual = set(member_ids)
    missing = sorted(expected_finding_ids - actual)
    unknown = sorted(actual - expected_finding_ids)
    duplicates = sorted(
        finding_id
        for finding_id, count in Counter(member_ids).items()
        if count != 1
    )
    if missing or unknown or duplicates:
        raise StageContractError(
            "dedupe output is not an exact partition: "
            f"missing={missing}, unknown={unknown}, duplicates={duplicates}"
        )
