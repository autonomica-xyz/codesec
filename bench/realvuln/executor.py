#!/usr/bin/env python3
"""Cell/block execution engine for the experiment runner (P07/P11).

Per block (repo × trial): prepare the paired bundle once, then execute the
two arms consecutively — each arm attempt in its own named isolation
container with an outer wall deadline (full cap + bounded cleanup grace,
enforced by the supervisor in ``isolation.run_isolated`` — never by
abandoning the container). Every attempt is claimed, ledgered and closed
with a terminal record on EVERY outcome — success, failure, timeout, or
controller exception — and outputs are validated, adapted and committed
atomically with completion records.

Attempt accounting (frozen): the first inference-bearing attempt — judged
by trusted gateway request records — is the operational primary and is
never replaced, including when it ends ``failed_no_output``. A
pre-inference (setup) failure may be retried at most once inside the same
cell; task/recall/fallback failures are never retried into fresh cells.
Two controllers cannot run one cell: the cell flock is held for the whole
attempt and the ledger claim is refused on conflict.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from bench.realvuln import adapter, isolation
from bench.realvuln.common import write_json
from bench.realvuln.ledger import AttemptLedger, LedgerConflictError
from bench.realvuln.snapshot import (
    WorkDeadline,
    latest_valid_snapshot,
    retain_snapshot,
)

PYGOAT = "realvuln-pygoat"
CLEANUP_GRACE_S = 30.0
#: How often the supervisor re-captures agent-written output files so a
#: truncated final write cannot erase the last valid one, and so every
#: eligible byte has an operator-owned capture. Both arms are watched.
SNAPSHOT_POLL_S = 2.0

#: Operator-owned snapshot root (relative to the attempt dir): NEVER under
#: the container-mounted output/ — agent-writable "snapshot" directories
#: next to live files are forgeable evidence and are never consulted.
def snapshots_root(exp: Path, attempt_id: str) -> Path:
    return exp / "attempts" / attempt_id / "snapshots"


#: Wall ceilings per repo (seconds); early normal completion allowed.
def wall_ceiling_s(repo: str, settings: dict) -> float:
    overrides = (settings or {}).get("wall_ceiling_overrides_s") or {}
    if repo in overrides:
        return float(overrides[repo])
    return float((settings or {}).get("wall_ceiling_s", 7200))


def new_attempt_id() -> str:
    return f"att-{secrets.token_hex(6)}"


def gateway_records_path(exp: Path) -> Path:
    return exp / "operator" / "gateway" / "requests.jsonl"


def attempt_made_inference(exp: Path, attempt_id: str) -> bool | None:
    """Whether an attempt reached inference, judged ONLY by trusted gateway
    request records (admission records are written before the upstream call
    so disconnects still count). Returns None when no records exist at all
    (attribution unknown — never silently treated as inference-free)."""
    path = gateway_records_path(exp)
    if not path.exists():
        return None
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if record.get("attempt_id") == attempt_id:
            return True
    return False


def _findings_schema(payload) -> list[str]:
    """V-arm findings schema validator for snapshot retention/selection."""
    if not isinstance(payload, dict):
        return ["top-level JSON must be an object"]
    findings = payload.get("findings")
    if not isinstance(findings, list):
        return ["findings must be a list"]
    problems = []
    for i, finding in enumerate(findings):
        if not isinstance(finding, dict) or not finding.get("file"):
            problems.append(f"findings[{i}] missing file")
            break
    return problems


def _report_schema(payload) -> list[str]:
    """H report/checkpoint/confirmed shape used for capture retention."""
    if not isinstance(payload, dict):
        return ["top-level JSON must be an object"]
    if not isinstance(payload.get("findings"), list):
        return ["findings must be a list"]
    return []


class _SnapshotWatcher:
    """Operator-side capture of agent-written output files WHILE WORK IS
    ELIGIBLE (plan step B.3/B.4). Snapshots are stored under the
    operator-owned ``exp/attempts/<id>/snapshots`` tree — never inside the
    container-mounted output directory — so the agent cannot forge capture
    metadata to make late output eligible. Captures stop the moment the
    monotonic work deadline expires; a post-deadline write is never
    retained, never eligible."""

    def __init__(
        self,
        sources: dict[str, Path],
        *,
        snapshot_root: Path,
        deadline: WorkDeadline,
        schema_validators: dict[str, object] | None = None,
        poll_s: float = SNAPSHOT_POLL_S,
        tags: dict | None = None,
    ):
        self.sources = dict(sources)
        self.snapshot_root = Path(snapshot_root)
        self.deadline = deadline
        self.validators = dict(schema_validators or {})
        self.poll_s = poll_s
        self.tags = tags or {}
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self.captures = 0

    def capture_once(self) -> int:
        """Capture every watched source whose current bytes are complete
        and valid. Returns the number of new snapshots."""
        if self.deadline.expired():
            return 0  # post-deadline bytes are never eligible
        captured = 0
        for name, source in self.sources.items():
            try:
                snap = retain_snapshot(
                    source,
                    schema_validator=self.validators.get(name),
                    snapshot_dir=self.snapshot_root / name,
                    tags={**self.tags, "watch": name},
                    captured_at_wall=self.deadline.wall_ts(),
                )
            except OSError:
                snap = None
            if snap is not None:
                captured += 1
        self.captures += captured
        return captured

    def _loop(self) -> None:
        while not self._stop.wait(self.poll_s):
            if self.deadline.expired():
                return
            self.capture_once()

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        self._thread.join(timeout=self.poll_s + 2)


def prepare_or_reuse_bundles(exp: Path, manifest: dict, repo: str,
                             trial: int) -> Path:
    """One source bundle per (repo, trial), byte-identical H/V copies.
    Reused bundles are RE-VERIFIED against the recorded digest before
    serving — a drifted bundle is never silently trusted."""
    record_path = exp / "operator" / "prepared-bundles.json"
    record = (
        json.loads(record_path.read_text()) if record_path.exists() else {}
    )
    key = f"{repo}#trial{trial}"
    if key in record:
        bundles_dir = Path(record[key]["bundles_dir"])
        if (bundles_dir / "bundle.json").exists():
            check = isolation.verify_bundle_pair(bundles_dir)
            if not check["ok"]:
                raise isolation.IsolationError(
                    f"reused bundle pair failed digest re-verification: "
                    + "; ".join(check["problems"])
                )
            return bundles_dir
    bundles_dir = (
        exp / "attempts" / f"bundles-{repo}-t{trial}"
    )
    realvuln = Path(
        os.environ.get(
            "REALVULN_ROOT",
            str(Path(
                manifest.get("realvuln_root")
                or manifest["settings"].get(
                    "realvuln_root", "/home/user/g/Real-Vuln-Benchmark"
                )
            )),
        )
    )
    pair = isolation.prepare_bundle_pair(
        slug=repo, trial=trial, bundles_dir=bundles_dir, realvuln=realvuln,
    )
    record[key] = {
        "bundles_dir": str(bundles_dir),
        "digest": pair.digest,
        "dropped_paths": pair.dropped,
        "canary": pair.canary,
        "prepared_at": time.time(),
    }
    write_json(record_path, record)
    return bundles_dir


def _attempt_headers(
    *, manifest: dict, cell: dict, attempt_id: str
) -> dict[str, str]:
    """Attribution headers both arms must carry on every request: the
    gateway binds these into trusted records, which is what makes an
    attempt inference-bearing."""
    return {
        "X-Experiment-Id": manifest["experiment_id"],
        "X-Cell-Id": cell["cell_id"],
        "X-Attempt-Id": attempt_id,
        "X-Arm": cell["arm"],
    }


def run_arm_container(
    *,
    exp: Path,
    manifest: dict,
    cell: dict,
    attempt_id: str,
    target_dir: Path,
    gateway_url: str,
    deadline: WorkDeadline,
    repo: str,
) -> dict:
    """Execute one arm attempt in its isolation container.

    H: the codesec CLI with the frozen experiment config against the
    gateway. V: pinned pi, headless, isolated agent dir with the gateway
    provider definition carrying per-request attribution headers. Both
    write only under /work/output/<attempt>.

    The supervisor receives the ACTUAL REMAINING WORK BUDGET from the
    cell's single monotonic deadline — never the cap plus a cleanup
    allowance. Cleanup grace starts after work is stopped inside
    ``run_isolated`` and cannot fund further inference or tool work. H's
    in-container synthesis reserve is preserved by passing the remaining
    budget to ``--max-hours``."""
    timeout_s = deadline.remaining_s()
    output_dir = exp / "attempts" / attempt_id / "output"
    scratch_dir = exp / "attempts" / attempt_id / "scratch"
    settings = manifest["settings"]
    headers = _attempt_headers(
        manifest=manifest, cell=cell, attempt_id=attempt_id
    )
    env = {
        "ZAI_GATEWAY_KEY": "gateway-dummy",
        "PI_CODING_AGENT_DIR": "/work/output/pi-home",
    }
    if cell["arm"] == "h":
        headers["X-Stage"] = "run"
        env["CODESEC_REQUEST_HEADERS"] = json.dumps(headers)
        command = [
            "bash", "-lc",
            "codesec run --repo /work/target "
            f"--run-id {attempt_id} "
            "--run-root /work/output/run "
            "--config /usr/local/lib/python3.13/site-packages/config/stages.yaml "
            "--engine local "
            "--prior off "
            f"--max-concurrency {settings.get('h_concurrency', 4)} "
            f"--max-recon-tasks {settings.get('recon_tasks', {}).get(repo, 20)} "
            f"--max-hours {timeout_s / 3600.0:.4f} "
            "2>&1 | tee /work/output/codesec.log; exit ${PIPESTATUS[0]}",
        ]
    else:
        # V model definition: the frozen provider def with its baseUrl
        # derived from the experiment's gateway_url (never a stale alias)
        # and per-request attribution headers (Pi sends provider headers
        # verbatim on every call).
        pi_dir = output_dir / "pi-home"
        pi_dir.mkdir(parents=True, exist_ok=True)
        definition = dict(
            manifest["settings"].get("pi_model_definition")
            or json.loads((exp / "operator" / "pi-model.json").read_text())
        )
        provider = next(iter(definition.get("providers", {}).values()), {})
        if provider:
            provider["baseUrl"] = gateway_url
            provider["headers"] = {**headers, "X-Stage": "pi"}
        (pi_dir / "models.json").write_text(json.dumps(definition))
        prompt = (
            "You are auditing the web application source code in "
            "/work/target for security vulnerabilities. Read the source, "
            "then write your findings as JSON to /work/output/findings.json "
            "with schema {\"findings\": [{\"finding_id\": str, \"file\": str, "
            "\"line_start\": int, \"line_end\": int, \"cwe\": \"CWE-n\", "
            "\"severity\": str, \"description\": str, \"evidence\": str}]}. "
            "Include only real, source-backed findings."
        )
        import shlex
        command = [
            "bash", "-lc",
            "PI_CODING_AGENT_DIR=/work/output/pi-home pi "
            f"--model {settings.get('pi_model_id', 'zaihosted/glm-5.3')} "
            "--thinking low -p " + shlex.quote(prompt)
            + " 2>&1 | tee /work/output/pi.log; exit ${PIPESTATUS[0]}",
        ]
    # Scored execution runs the immutable image ID recorded at freeze —
    # never a mutable tag. The freeze gate guarantees image_id exists for
    # scored experiments; a missing pin blocks the arm (setup failure).
    image_spec = manifest.get("image") or {}
    image = (
        image_spec.get("resolved_image_id") or image_spec.get("image_id")
        if isinstance(image_spec, dict) else image_spec
    )
    return isolation.run_isolated(
        target_dir=target_dir,
        scratch_dir=scratch_dir,
        output_dir=output_dir,
        command=command,
        gateway_url=gateway_url,
        timeout_s=timeout_s,
        env=env,
        image=image,
    )


def _h_stage_health(output_dir: Path) -> dict:
    """Read the H run's terminal stage health from its state DB (plan
    step E.5): a clean completion requires every required stage to have a
    terminal 'complete' end event with no degradation reasons. Unknown or
    missing health evidence is NOT a clean pass."""
    import sqlite3

    db_path = output_dir / "run" / "state.db"
    required = ("recon", "hunt", "validate", "dedupe", "trace", "report")
    if not db_path.is_file():
        return {"clean": False, "evidence": "missing",
                "problem": "no run state DB — stage health unknown"}
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        ends = []
        for row in conn.execute(
            "SELECT stage, event FROM stage_events ORDER BY event_id"
        ):
            try:
                event = json.loads(row["event"])
            except json.JSONDecodeError:
                continue
            if event.get("phase") == "end":
                # stage lives in the row column; the event payload carries
                # it too when written by _StageHealth — accept either.
                event.setdefault("stage", row["stage"])
                ends.append(event)
        conn.close()
    except sqlite3.Error as error:
        return {"clean": False, "evidence": "unreadable",
                "problem": f"state DB unreadable: {error}"}
    if not ends:
        return {"clean": False, "evidence": "empty",
                "problem": "no terminal stage health events recorded"}
    problems: list[str] = []
    for event in ends:
        stage = event.get("stage")
        if event.get("status") != "complete":
            problems.append(
                f"stage {stage} ended {event.get('status')}"
                f"({event.get('error_category')})"
            )
        elif event.get("degraded_reasons"):
            problems.append(
                f"stage {stage} degraded: {event.get('degraded_reasons')}"
            )
    seen = {event.get("stage") for event in ends}
    for stage in required:
        if stage not in seen:
            problems.append(f"required stage {stage} has no health record")
    return {
        "clean": not problems,
        "evidence": "state_db",
        "stages": sorted(seen),
        "problems": problems,
    }


def _export_h_outputs(
    *,
    output_dir: Path,
    target_dir: Path,
    snapshot_root: Path,
    deadline: WorkDeadline,
) -> tuple[dict[str, Path], dict, dict]:
    """H export from operator-owned snapshots only (plan step B.3/B.4):
    the newest eligible capture of the final report when one exists, else
    the newest eligible checkpoint capture (the in-container synthesis
    reserve exists precisely so this artifact survives a timeout), plus
    the newest eligible confirmed.json capture. Bytes first seen after
    the cutoff have no eligible capture and are never exported."""
    files: dict[str, Path] = {}
    drops: dict[str, dict] = {}
    provenance: dict = {}
    report_dir = output_dir / "run" / "results" / "report"
    deadline_wall = deadline.deadline_wall_ts()

    def _latest(name: str) -> dict | None:
        return latest_valid_snapshot(
            report_dir / name,
            deadline_ts=deadline_wall,
            schema_validator=_report_schema,
            snapshot_dir=snapshot_root / name,
        )

    source = _latest("report.json")
    if source is not None:
        provenance["h_report_source"] = "report.json"
    else:
        source = _latest("report.checkpoint.json")
        if source is not None:
            provenance["h_report_source"] = "report.checkpoint.json"
    if source is None:
        raise FileNotFoundError(
            f"no eligible H report or checkpoint capture for "
            f"{report_dir} (work deadline already spent)"
        )
    provenance["checkpoint_only"] = (
        provenance["h_report_source"] != "report.json"
    )
    provenance["primary_capture"] = {
        "sha256": source["sha256"],
        "captured_at": source["captured_at"],
        "path": source["path"],
    }
    primary_payload = json.loads(Path(source["path"]).read_text())
    primary = adapter.adapt_findings(
        {"findings": [
            {
                "file": f.get("file"),
                "line_start": f.get("line_start"),
                "line_end": f.get("line_end"),
                "cwe": f.get("cwe"),
                "severity": f.get("severity"),
                "description": f.get("description"),
                "finding_id": f.get("finding_id"),
                "vuln_class": f.get("vuln_class"),
            }
            for f in primary_payload.get("findings", [])
        ]},
        target_dir,
    )
    secondary_capture = _latest("confirmed.json")
    if secondary_capture is not None:
        secondary_payload = json.loads(
            Path(secondary_capture["path"]).read_text()
        )
        provenance["secondary_capture"] = {
            "sha256": secondary_capture["sha256"],
            "captured_at": secondary_capture["captured_at"],
        }
    else:
        # Secondary is auxiliary: absent after a timeout means no eligible
        # capture ever happened — exported empty, and the fact recorded.
        secondary_payload = {"findings": []}
        provenance["secondary_capture"] = None
    secondary = adapter.adapt_findings(
        {"findings": [
            {
                "file": f.get("file"),
                "line_start": f.get("line_start"),
                "line_end": f.get("line_end"),
                "cwe": f.get("cwe"),
                "severity": f.get("severity"),
                "description": f.get("description"),
                "finding_id": f.get("finding_id"),
            }
            for f in secondary_payload.get("findings", [])
        ]},
        target_dir,
    )
    drops["primary"] = primary.drop_counts
    drops["secondary"] = secondary.drop_counts
    files["primary"] = output_dir / "primary.semgrep.json"
    files["primary"].write_text(
        json.dumps(adapter.semgrep_document(primary.results), indent=1)
    )
    files["secondary"] = output_dir / "secondary-confirmed.semgrep.json"
    files["secondary"].write_text(
        json.dumps(adapter.semgrep_document(secondary.results), indent=1)
    )
    provenance["h_stage_health"] = _h_stage_health(output_dir)
    return files, drops, provenance


def _export_v_outputs(
    *,
    output_dir: Path,
    target_dir: Path,
    snapshot_root: Path,
    deadline: WorkDeadline,
) -> tuple[dict[str, Path], dict, dict]:
    """V export from operator-owned snapshots only: the newest eligible
    capture of the externally-written findings file. A truncated final
    write never erases a valid earlier capture, and bytes first seen
    after the cutoff have no eligible capture and are never exported."""
    files: dict[str, Path] = {}
    drops: dict[str, dict] = {}
    provenance: dict = {}
    findings_path = output_dir / "findings.json"

    retained = latest_valid_snapshot(
        findings_path,
        deadline_ts=deadline.deadline_wall_ts(),
        schema_validator=_findings_schema,
        snapshot_dir=snapshot_root / "findings.json",
    )
    if retained is None:
        raise FileNotFoundError(
            f"missing valid V findings output: {findings_path} "
            "(no eligible pre-deadline snapshot retained)"
        )
    provenance["v_source"] = "retained_snapshot"
    provenance["snapshot_sha256"] = retained["sha256"]
    provenance["snapshot_captured_at"] = retained["captured_at"]
    provenance["primary_capture"] = {
        "sha256": retained["sha256"],
        "captured_at": retained["captured_at"],
        "path": retained["path"],
    }

    payload = adapter.parse_findings_document(
        Path(retained["path"]).read_text()
    )
    adapted = adapter.adapt_findings(payload, target_dir)
    drops["primary"] = adapted.drop_counts
    files["primary"] = output_dir / "primary.semgrep.json"
    files["primary"].write_text(
        json.dumps(adapter.semgrep_document(adapted.results), indent=1)
    )
    return files, drops, provenance


def export_arm_outputs(
    *,
    exp: Path,
    manifest: dict,
    cell: dict,
    attempt_id: str,
    output_dir: Path,
    target_dir: Path,
    deadline: WorkDeadline,
) -> dict:
    """Validate and adapt authoritative outputs to the frozen export
    formats, selecting ONLY operator-owned pre-deadline captures (hash +
    schema re-validated at selection). H: newest eligible report.json
    capture, else newest eligible report.checkpoint.json capture, plus a
    confirmed.json secondary. V: newest eligible findings.json capture.
    A file that first appears after the cutoff is not eligible."""
    snapshot_root = snapshots_root(exp, attempt_id)
    if cell["arm"] == "h":
        files, drops, provenance = _export_h_outputs(
            output_dir=output_dir, target_dir=target_dir,
            snapshot_root=snapshot_root, deadline=deadline,
        )
    else:
        files, drops, provenance = _export_v_outputs(
            output_dir=output_dir, target_dir=target_dir,
            snapshot_root=snapshot_root, deadline=deadline,
        )
    provenance["deadline"] = deadline.as_record()
    return {"files": files, "drops": drops, "provenance": provenance}


def _terminal_record(
    *,
    cell: dict,
    attempt_id: str,
    status: str,
    reason_code: str,
    exit_status,
    made_inference,
    result: dict | None = None,
    exported: dict | None = None,
    marker: Path | None = None,
    bundle_digest: str | None = None,
    error: str | None = None,
) -> dict:
    record = {
        "type": "attempt_end",
        "cell_id": cell["cell_id"],
        "attempt_id": attempt_id,
        "status": status,
        "reason_code": reason_code,
        "exit_status": exit_status,
        "made_inference_requests": made_inference,
        "bundle_digest": bundle_digest,
        "attempt_selection": "first_inference_attempt_is_primary",
    }
    if result is not None:
        record["duration_s"] = result.get("duration_s")
        record["container"] = result.get("container")
        record["timed_out"] = bool(result.get("timed_out"))
        if result.get("controller_error"):
            record["controller_error"] = result["controller_error"]
        record["stdout_tail"] = (result.get("stdout_tail") or "")[-2000:]
    if exported is not None:
        record["drops"] = exported["drops"]
        record["export_provenance"] = exported.get("provenance") or {}
        record["artifact_sha256"] = {
            role: hashlib.sha256(path.read_bytes()).hexdigest()
            for role, path in exported["files"].items()
        }
    if marker is not None:
        record["completion_marker"] = str(marker)
    if error:
        record["error"] = error[:400]
    return record


def execute_block(
    *,
    exp: Path,
    manifest: dict,
    ledger: AttemptLedger,
    cell: dict,
    block: dict,
) -> dict:
    """Run one cell (one arm of one block) under claim + ledger + atomic
    commit, with a terminal record on EVERY outcome."""
    from bench.realvuln.experiment import (
        arm_done,
        commit_cell_outputs,
    )

    repo = cell["repo"]
    settings = manifest["settings"]
    gateway_url = settings.get("gateway_url", "http://gateway:8800/v1")

    committed_cell = exp / "committed" / cell["cell_id"]
    done = arm_done(
        committed_cell, manifest=manifest, arm=cell["arm"],
        repo=repo, trial=cell["trial"],
    )
    if done["done"]:
        return {"ok": True, "already_committed": True}

    attempt_id = new_attempt_id()
    try:
        with ledger.cell_lock(cell["cell_id"]):
            # Close attempts orphaned by an interrupted controller BEFORE
            # claiming: an inference-bearing orphan is a terminal
            # operational failure (the cell is already accounted); a
            # pre-inference orphan consumes the one setup retry.
            ledger.reconcile_interrupted(
                cell["cell_id"],
                made_inference=lambda att: attempt_made_inference(exp, att),
            )
            state = ledger.terminal_state(cell["cell_id"])
            if state is not None and (
                state.get("made_inference_requests") is True
                or state.get("status") == "invalidated"
                or state.get("attribution_inconsistent")
            ):
                return {
                    "ok": False,
                    "already_accounted": True,
                    "reason": (
                        f"cell already has terminal state "
                        f"{state['status']} — never replaced"
                    ),
                }
            # A pre-inference terminal state leaves the primary slot open;
            # claim_cell enforces the single setup retry.
            ledger.claim_cell(cell["cell_id"], attempt_id)
            return _execute_attempt(
                exp=exp, manifest=manifest, ledger=ledger, cell=cell,
                block=block, attempt_id=attempt_id, repo=repo,
                settings=settings, gateway_url=gateway_url,
            )
    except LedgerConflictError as error:
        return {"ok": False, "reason": f"claim_refused: {error}"}


def _execute_attempt(
    *,
    exp: Path,
    manifest: dict,
    ledger: AttemptLedger,
    cell: dict,
    block: dict,
    attempt_id: str,
    repo: str,
    settings: dict,
    gateway_url: str,
) -> dict:
    from bench.realvuln.experiment import commit_cell_outputs

    try:
        bundles_dir = prepare_or_reuse_bundles(
            exp, manifest, repo, cell["trial"]
        )
        pair_manifest = json.loads((bundles_dir / "bundle.json").read_text())
    except Exception as error:  # setup failure — before any inference
        ledger.append({
            "type": "attempt_end",
            "cell_id": cell["cell_id"],
            "attempt_id": attempt_id,
            "status": "setup_failed",
            "reason_code": "bundle_prepare",
            "exit_status": None,
            "made_inference_requests": False,
            "error": str(error)[:400],
            "attempt_selection": "setup_retry_eligible_once",
        })
        return {"ok": False, "reason": f"bundle: {error}"}
    target_dir = bundles_dir / cell["arm"] / "target"
    bundle_digest = pair_manifest["digest"]

    ledger.append({
        "type": "attempt_start",
        "cell_id": cell["cell_id"],
        "attempt_id": attempt_id,
        "arm": cell["arm"],
        "trial": cell["trial"],
        "bundle_digest": bundle_digest,
    })

    output_dir = exp / "attempts" / attempt_id / "output"
    ceiling = wall_ceiling_s(repo, settings)
    # One work deadline per cell, defined ONCE on the monotonic clock.
    # Wall stamps in records are annotations, never the cutoff authority.
    deadline = WorkDeadline(total_seconds=ceiling)

    # Watched output files (both arms) with their capture validators;
    # snapshots are stored operator-side, never agent-writable.
    report_dir = output_dir / "run" / "results" / "report"
    if cell["arm"] == "h":
        sources = {
            "report.json": report_dir / "report.json",
            "report.checkpoint.json": report_dir / "report.checkpoint.json",
            "confirmed.json": report_dir / "confirmed.json",
        }
        validators = {name: _report_schema for name in sources}
    else:
        sources = {"findings.json": output_dir / "findings.json"}
        validators = {"findings.json": _findings_schema}
    watcher = _SnapshotWatcher(
        sources,
        snapshot_root=snapshots_root(exp, attempt_id),
        deadline=deadline,
        schema_validators=validators,
        poll_s=float(settings.get("snapshot_poll_s", SNAPSHOT_POLL_S)),
        tags={"arm": cell["arm"], "cell_id": cell["cell_id"],
              "attempt_id": attempt_id},
    )

    result: dict | None = None
    try:
        with watcher:
            result = run_arm_container(
                exp=exp, manifest=manifest, cell=cell,
                attempt_id=attempt_id, target_dir=target_dir,
                gateway_url=gateway_url, deadline=deadline, repo=repo,
            )
            # Early normal completion (plan step B.5): capture the exact
            # final bytes NOW, while still inside the work budget — the
            # periodic watcher may not have polled since the last write.
            # Only for a container that exited on its own BEFORE the cap:
            # a timed-out or controller-killed container's stop-grace
            # window can still contain writes, so no final capture there.
            if (
                not result.get("timed_out")
                and not result.get("controller_error")
                and not deadline.expired()
            ):
                watcher.capture_once()
    except isolation.IsolationError as error:
        ledger.append({
            "type": "attempt_end",
            "cell_id": cell["cell_id"],
            "attempt_id": attempt_id,
            "status": "setup_failed",
            "reason_code": "isolation",
            "exit_status": None,
            "made_inference_requests": False,
            "bundle_digest": bundle_digest,
            "error": str(error)[:400],
            "attempt_selection": "setup_retry_eligible_once",
        })
        return {"ok": False, "reason": f"isolation: {error}"}
    except Exception as error:  # noqa: BLE001 — controller failure is terminal
        made = attempt_made_inference(exp, attempt_id)
        ledger.append({
            "type": "attempt_end",
            "cell_id": cell["cell_id"],
            "attempt_id": attempt_id,
            "status": (
                "failed_no_output" if made is not False
                else "setup_failed"
            ),
            "reason_code": "controller_error",
            "exit_status": None,
            "made_inference_requests": made,
            "bundle_digest": bundle_digest,
            "error": f"{type(error).__name__}: {error}"[:400],
            "attempt_selection": "operational_failure_recorded",
        })
        return {"ok": False, "reason": f"controller: {error}"}

    # Trusted inference attribution: gateway request records decide whether
    # this attempt reached the model. No records at all → attribution
    # unknown → mark inconsistent rather than guessing.
    made_inference = attempt_made_inference(exp, attempt_id)
    timed_out = bool(result.get("timed_out"))
    controller_error = result.get("controller_error")

    if made_inference is False:
        # Provably pre-inference (dead gateway, unreachable upstream):
        # nothing this attempt wrote is an admissible outcome — a startup
        # checkpoint is debris, not a result. Commit nothing; record a
        # retry-eligible setup failure.
        ledger.append(_terminal_record(
            cell=cell, attempt_id=attempt_id,
            status="setup_failed",
            reason_code=(
                "deadline_before_inference" if timed_out
                else "no_inference"
            ),
            exit_status=result.get("exit_code"),
            made_inference=made_inference,
            result=result,
            bundle_digest=bundle_digest,
        ))
        return {
            "ok": False,
            "reason": "no_inference: attempt never reached the gateway",
        }

    try:
        exported = export_arm_outputs(
            exp=exp, manifest=manifest, cell=cell, attempt_id=attempt_id,
            output_dir=output_dir, target_dir=target_dir,
            deadline=deadline,
        )
    except Exception as error:  # noqa: BLE001 — output failure is terminal
        ledger.append(_terminal_record(
            cell=cell, attempt_id=attempt_id,
            status=(
                "failed_no_output" if made_inference is not False
                else "setup_failed"
            ),
            reason_code=(
                "deadline_no_output" if timed_out
                else "controller_error_no_output" if controller_error
                else "missing_output"
            ),
            exit_status=result.get("exit_code"),
            made_inference=made_inference,
            result=result,
            bundle_digest=bundle_digest,
            error=str(error),
        ))
        return {"ok": False, "reason": f"missing_output: {error}"}

    # Valid exportable output exists — including checkpoint-only after a
    # timeout. A timed-out run is NEVER recorded as a clean completion:
    # the status stays a failure class even though the artifacts commit.
    try:
        marker = commit_cell_outputs(
            exp=exp, manifest=manifest, cell=cell, attempt_id=attempt_id,
            export_dir=output_dir, files=exported["files"],
        )
    except Exception as error:  # noqa: BLE001
        ledger.append(_terminal_record(
            cell=cell, attempt_id=attempt_id,
            status="failed_no_output",
            reason_code="commit_failed",
            exit_status=result.get("exit_code"),
            made_inference=made_inference,
            result=result,
            exported=exported,
            bundle_digest=bundle_digest,
            error=f"commit: {error}",
        ))
        return {"ok": False, "reason": f"commit: {error}"}

    if timed_out:
        status, reason_code = "failed_output", "deadline_recovered_output"
    elif controller_error:
        status, reason_code = "failed_output", "controller_error_with_output"
    elif result["exit_code"] == 0:
        status, reason_code = "completed", "ok"
        # Exit zero alone cannot mean clean (plan step E.5): the H arm's
        # terminal stage health must be COMPLETE evidence with no
        # degradation — lost findings/coverage/advisory data downgrade the
        # cell out of the clean-completion rate while keeping the output.
        if cell["arm"] == "h":
            health = (
                exported.get("provenance", {}).get("h_stage_health")
                or {}
            )
            if not health.get("clean"):
                status = "failed_output"
                reason_code = "degraded_stage_health"
    else:
        status, reason_code = (
            "failed_output", f"arm_exit_{result['exit_code']}"
        )
    ledger.append(_terminal_record(
        cell=cell, attempt_id=attempt_id,
        status=status, reason_code=reason_code,
        exit_status=result.get("exit_code"),
        made_inference=made_inference,
        result=result,
        exported=exported,
        marker=marker,
        bundle_digest=bundle_digest,
    ))
    return {"ok": True, "status": status, "attempt_id": attempt_id}
