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
from bench.realvuln.snapshot import latest_valid_snapshot, retain_snapshot

PYGOAT = "realvuln-pygoat"
CLEANUP_GRACE_S = 30.0
#: How often the V-arm supervisor re-captures the externally-written
#: findings file so a truncated final write cannot erase the last valid one.
SNAPSHOT_POLL_S = 2.0


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


class _SnapshotWatcher:
    """Re-capture the V arm's externally-written findings file while its
    container runs, so a truncated final write (or a kill mid-write) can
    never destroy the last valid snapshot."""

    def __init__(self, source: Path, *, deadline_ts: float | None = None):
        self.source = source
        self.deadline_ts = deadline_ts
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, daemon=True)

    def _loop(self) -> None:
        while not self._stop.wait(SNAPSHOT_POLL_S):
            if (
                self.deadline_ts is not None
                and time.time() > self.deadline_ts
            ):
                return  # post-deadline captures are ineligible anyway
            try:
                retain_snapshot(
                    self.source,
                    schema_validator=_findings_schema,
                    tags={"watch": "v-arm"},
                )
            except OSError:
                pass

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        self._thread.join(timeout=SNAPSHOT_POLL_S + 2)


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
    timeout_s: float,
    repo: str,
) -> dict:
    """Execute one arm attempt in its isolation container.

    H: the codesec CLI with the frozen experiment config against the
    gateway. V: pinned pi, headless, isolated agent dir with the gateway
    provider definition carrying per-request attribution headers. Both
    write only under /work/output/<attempt>."""
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
        timeout_s=timeout_s + CLEANUP_GRACE_S,
        env=env,
        image=image,
    )


def _export_h_outputs(
    *,
    output_dir: Path,
    target_dir: Path,
) -> tuple[dict[str, Path], dict, dict]:
    """H export: the final report when present, else the newest VALID
    mid-run checkpoint (the deadline reserve exists precisely so this
    artifact is available after a timeout). Both are schema-shaped JSON
    written atomically by the harness itself."""
    files: dict[str, Path] = {}
    drops: dict[str, dict] = {}
    provenance: dict = {}
    run_root = output_dir / "run"
    report_dir = run_root / "results" / "report"
    report = report_dir / "report.json"
    checkpoint = report_dir / "report.checkpoint.json"
    confirmed = report_dir / "confirmed.json"
    source = None
    for candidate in (report, checkpoint):
        if not candidate.is_file():
            continue
        try:
            payload = json.loads(candidate.read_text())
        except (json.JSONDecodeError, OSError):
            continue  # truncated/invalid — never exported as-is
        if isinstance(payload, dict) and isinstance(
            payload.get("findings"), list
        ):
            source = candidate
            break
    if source is None:
        raise FileNotFoundError(
            f"missing valid H report or checkpoint under {report_dir}"
        )
    provenance["h_report_source"] = source.name
    provenance["checkpoint_only"] = source.name != "report.json"
    primary_payload = json.loads(source.read_text())
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
    secondary_payload = (
        json.loads(confirmed.read_text())
        if confirmed.is_file() else {"findings": []}
    )
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
    return files, drops, provenance


def _export_v_outputs(
    *,
    output_dir: Path,
    target_dir: Path,
    deadline_ts: float | None,
) -> tuple[dict[str, Path], dict, dict]:
    """V export: prefer the live findings file when it is complete and
    schema-valid; otherwise the newest retained snapshot at or before the
    deadline (re-validated: hash + JSON + schema). A truncated final write
    never erases a valid earlier capture, and post-deadline bytes are never
    eligible."""
    files: dict[str, Path] = {}
    drops: dict[str, dict] = {}
    provenance: dict = {}
    findings_path = output_dir / "findings.json"

    source: Path | None = None
    if findings_path.is_file():
        try:
            payload = json.loads(findings_path.read_bytes())
            if not _findings_schema(payload):
                retain_snapshot(
                    findings_path,
                    schema_validator=_findings_schema,
                    tags={"watch": "final"},
                )
                source = findings_path
                provenance["v_source"] = "final_file"
        except (json.JSONDecodeError, OSError):
            pass  # truncated write — fall back to the retained snapshot
    if source is None:
        retained = latest_valid_snapshot(
            findings_path,
            deadline_ts=deadline_ts,
            schema_validator=_findings_schema,
        )
        if retained is None:
            raise FileNotFoundError(
                f"missing valid V findings output: {findings_path} "
                "(no pre-deadline snapshot retained)"
            )
        source = Path(retained["path"])
        provenance["v_source"] = "retained_snapshot"
        provenance["snapshot_sha256"] = retained["sha256"]
        provenance["snapshot_captured_at"] = retained["captured_at"]

    payload = adapter.parse_findings_document(source.read_text())
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
    deadline_ts: float | None = None,
) -> dict:
    """Validate and adapt authoritative outputs to the frozen export
    formats. H: report.json (primary policy) or the newest valid
    report.checkpoint.json, + confirmed.json (secondary). V: the live
    findings file or the retained pre-deadline snapshot."""
    if cell["arm"] == "h":
        files, drops, provenance = _export_h_outputs(
            output_dir=output_dir, target_dir=target_dir,
        )
    else:
        files, drops, provenance = _export_v_outputs(
            output_dir=output_dir, target_dir=target_dir,
            deadline_ts=deadline_ts,
        )
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
    deadline_ts = time.time() + ceiling

    result: dict | None = None
    try:
        if cell["arm"] == "v":
            with _SnapshotWatcher(
                output_dir / "findings.json", deadline_ts=deadline_ts
            ):
                result = run_arm_container(
                    exp=exp, manifest=manifest, cell=cell,
                    attempt_id=attempt_id, target_dir=target_dir,
                    gateway_url=gateway_url, timeout_s=ceiling, repo=repo,
                )
        else:
            result = run_arm_container(
                exp=exp, manifest=manifest, cell=cell,
                attempt_id=attempt_id, target_dir=target_dir,
                gateway_url=gateway_url, timeout_s=ceiling, repo=repo,
            )
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
            deadline_ts=deadline_ts,
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
