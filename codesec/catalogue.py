"""Cross-run catalogue (W8): a repo-scoped DB of finding outcomes.

One catalogue per repo (default <repo>/.codesec-catalogue.db; the
orchestrator resolves and passes the path). It remembers which root
causes were confirmed, refuted, or left needing info, so a second scan
of the same repo compounds instead of re-deriving the same findings.

prepare_priors() runs at run start: confirmed entries are re-centered
against current code — unchanged ones become Hunt exclusions, drifted-
but-reattached ones become revalidation tasks, unmatchable ones count
as drifted (with a file+vuln_class-only fallback past a 15% threshold).
record_run() runs at run end: canonical findings upsert their verdicts.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from pathlib import Path

from codesec.fingerprint import finding_fp, recenter, window_hash
from codesec.state import Finding, StateDB

log = logging.getLogger(__name__)

DEFAULT_CATALOGUE_NAME = ".codesec-catalogue.db"

# When more than this fraction of confirmed priors can't be re-anchored,
# the repo churned too much for window matching to be trusted — fall
# back to file+vuln_class-only exclusions for the drifted entries.
DRIFT_FALLBACK_RATIO = 0.15

SCHEMA = """
CREATE TABLE IF NOT EXISTS catalogue (
    fp TEXT PRIMARY KEY,
    vuln_class TEXT,
    file TEXT,
    line_window TEXT,
    status TEXT,
    severity TEXT,
    first_seen_run TEXT,
    last_seen_run TEXT,
    source_ref TEXT,
    payload_json TEXT
);
"""

EXCLUSION_REASON = "already reported in prior run"
DRIFT_REASON = "prior run reported this root cause; content drifted"


def _connect(catalogue_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(catalogue_path))
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


def _parse_window(line_window: str | None) -> tuple[int, int] | None:
    try:
        start_s, end_s = str(line_window).split("-", 1)
        start, end = int(start_s), int(end_s)
        return (start, end) if 1 <= start <= end else None
    except (TypeError, ValueError):
        return None


def _row_payload(row: sqlite3.Row) -> dict:
    try:
        return json.loads(row["payload_json"] or "{}")
    except (TypeError, json.JSONDecodeError):
        return {}


def _rejected_because(payload: dict) -> str:
    for key in ("rationale", "rejected_because", "reason"):
        value = str(payload.get(key) or "").strip()
        if value:
            return value
    return "rejected in a prior run"


def refuted_entries(catalogue_path: Path) -> list[dict]:
    """Prior refutations in gapfill's refuted_patterns shape."""
    path = Path(catalogue_path)
    if not path.exists():
        return []
    conn = _connect(path)
    try:
        rows = conn.execute(
            "SELECT vuln_class, file, payload_json FROM catalogue "
            "WHERE status = 'refuted'"
        ).fetchall()
    finally:
        conn.close()
    return [
        {
            "vuln_class": row["vuln_class"],
            "file": row["file"],
            "rejected_because": _rejected_because(_row_payload(row)),
        }
        for row in rows
    ]


def needs_info_entries(catalogue_path: Path) -> list[dict]:
    """Prior needs_info findings with blockers — gapfill seeds.

    Gapfill reads these at stage time so it can schedule hunts aimed at
    the recorded blockers.
    """
    path = Path(catalogue_path)
    if not path.exists():
        return []
    conn = _connect(path)
    try:
        rows = conn.execute(
            "SELECT fp, vuln_class, file, line_window, severity, "
            "payload_json FROM catalogue WHERE status = 'needs_info'"
        ).fetchall()
    finally:
        conn.close()
    out = []
    for row in rows:
        blockers = (_row_payload(row).get("blockers") or [])
        if not blockers:
            continue
        out.append({
            "fp": row["fp"],
            "vuln_class": row["vuln_class"],
            "file": row["file"],
            "line_window": row["line_window"],
            "severity": row["severity"],
            "blockers": [str(b)[:200] for b in blockers][:8],
        })
    return out


def prepare_priors(
    db: StateDB, run_id: str, repo_root: Path, catalogue_path: Path
) -> dict:
    """Load prior-run outcomes and convert them into run inputs.

    Side effect: db.set_prior_exclusions(run_id, exclusions) so Hunt can
    read the exclusion list through state.
    """
    result: dict = {
        "exclusions": [],
        "revalidate_tasks": [],
        "refuted": [],
        "drifted": 0,
        "carried": 0,
    }
    path = Path(catalogue_path)
    if not path.exists():
        db.set_prior_exclusions(run_id, [])
        return result

    repo_root = Path(repo_root)
    conn = _connect(path)
    try:
        rows = conn.execute("SELECT * FROM catalogue").fetchall()
        unmatched: list[sqlite3.Row] = []
        confirmed = [r for r in rows if r["status"] == "confirmed"]

        for row in rows:
            status = row["status"]
            payload = _row_payload(row)
            if status == "refuted":
                result["refuted"].append(
                    {
                        "vuln_class": row["vuln_class"],
                        "file": row["file"],
                        "rejected_because": _rejected_because(payload),
                    }
                )
        for row in confirmed:
            payload = _row_payload(row)
            window = _parse_window(row["line_window"])
            expected_hash = payload.get("window_hash")
            if window is None or not expected_hash:
                # Nothing to re-anchor — carry as file+class-only.
                result["exclusions"].append(
                    {
                        "fp": None,
                        "vuln_class": row["vuln_class"],
                        "file": row["file"],
                        "reason": EXCLUSION_REASON,
                    }
                )
                continue
            line_start, line_end = window
            anchored = recenter(
                repo_root, row["file"], line_start, line_end, expected_hash
            )
            if anchored is None:
                unmatched.append(row)
            elif not anchored["drifted"]:
                result["exclusions"].append(
                    {
                        "fp": row["fp"],
                        "vuln_class": row["vuln_class"],
                        "file": row["file"],
                        "line_start": anchored["line_start"],
                        "line_end": anchored["line_end"],
                        "reason": EXCLUSION_REASON,
                    }
                )
            else:
                new_window = (
                    f"{anchored['line_start']}-{anchored['line_end']}"
                )
                conn.execute(
                    "UPDATE catalogue SET line_window = ? WHERE fp = ?",
                    (new_window, row["fp"]),
                )
                result["revalidate_tasks"].append(
                    {
                        "task_id": f"t_prior_{row['fp'][:12]}",
                        "source": "catalogue",
                        "attack_class": row["vuln_class"],
                        "scope_hint": (
                            f"Re-validate prior {row['vuln_class']} finding "
                            f"in {row['file']} (window moved to "
                            f"{new_window})"
                        ),
                        "target_files": [row["file"]],
                        "rationale": (
                            f"Prior run reported {row['vuln_class']} at "
                            f"{row['file']}:{row['line_window']} "
                            f"(fp {row['fp'][:12]}); the cited code moved "
                            "— confirm it is still present."
                        ),
                        "priority": 2,
                    }
                )

        result["drifted"] = len(unmatched)
        if confirmed and len(unmatched) / len(confirmed) > DRIFT_FALLBACK_RATIO:
            # Too much churn to trust window matching — carry the
            # unmatchable ones as coarse file+class exclusions.
            for row in unmatched:
                result["exclusions"].append(
                    {
                        "fp": None,
                        "vuln_class": row["vuln_class"],
                        "file": row["file"],
                        "reason": DRIFT_REASON,
                    }
                )
        conn.commit()
    finally:
        conn.close()

    result["carried"] = len(result["exclusions"])
    db.set_prior_exclusions(run_id, result["exclusions"])
    return result


def _finding_fp(finding: Finding, repo_root: Path) -> tuple[str, str | None]:
    """(fp, window_hash) for a finding; falls back to a static identity
    (vuln_class+file+description) when the file can't be hashed."""
    window = window_hash(
        repo_root, finding.file, finding.line_start, finding.line_end
    )
    if finding.discovery_fp:
        return finding.discovery_fp, window
    if window is not None:
        return finding_fp(finding.vuln_class, finding.file, window), window
    return (
        finding_fp(
            finding.vuln_class, finding.file, f"static:{finding.description}"
        ),
        None,
    )


def _upsert(
    conn: sqlite3.Connection,
    *,
    fp: str,
    vuln_class: str,
    file: str,
    line_window: str,
    status: str,
    severity: str | None,
    run_id: str,
    source_ref: str | None,
    payload: dict,
) -> None:
    existing = conn.execute(
        "SELECT first_seen_run FROM catalogue WHERE fp = ?", (fp,)
    ).fetchone()
    first_seen = existing["first_seen_run"] if existing else run_id
    conn.execute(
        """INSERT OR REPLACE INTO catalogue
        (fp, vuln_class, file, line_window, status, severity,
         first_seen_run, last_seen_run, source_ref, payload_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            fp,
            vuln_class,
            file,
            line_window,
            status,
            severity,
            first_seen,
            run_id,
            source_ref,
            json.dumps(payload),
        ),
    )


def record_run(
    db: StateDB, run_id: str, repo_root: Path, catalogue_path: Path
) -> dict:
    """Upsert the run's canonical findings into the catalogue."""
    counts = {"confirmed": 0, "refuted": 0, "needs_info": 0, "skipped": 0}
    repo_root = Path(repo_root)
    conn = _connect(Path(catalogue_path))
    try:
        for finding in db.get_findings(run_id, canonical_only=True):
            status = finding.validation_status
            if status not in ("confirmed", "rejected", "needs_more_info"):
                counts["skipped"] += 1
                continue
            fp, window = _finding_fp(finding, repo_root)
            validation = finding.validation_json or {}
            line_window = f"{finding.line_start}-{finding.line_end}"
            base_payload = {
                "finding_id": finding.finding_id,
                "description": finding.description,
                "window_hash": window,
                "validation": validation,
            }
            if status == "confirmed":
                severity = (
                    validation.get("arbiter_severity") or finding.severity
                )
                _upsert(
                    conn,
                    fp=fp,
                    vuln_class=finding.vuln_class,
                    file=finding.file,
                    line_window=line_window,
                    status="confirmed",
                    severity=severity,
                    run_id=run_id,
                    source_ref=finding.discovery_ref,
                    payload=base_payload,
                )
                counts["confirmed"] += 1
            elif status == "rejected":
                _upsert(
                    conn,
                    fp=fp,
                    vuln_class=finding.vuln_class,
                    file=finding.file,
                    line_window=line_window,
                    status="refuted",
                    severity=finding.severity,
                    run_id=run_id,
                    source_ref=finding.discovery_ref,
                    payload={
                        **base_payload,
                        "rationale": validation.get("rationale", ""),
                    },
                )
                counts["refuted"] += 1
            else:
                blockers = validation.get("blockers") or []
                if not blockers and validation.get("suggested_test"):
                    blockers = [validation["suggested_test"]]
                _upsert(
                    conn,
                    fp=fp,
                    vuln_class=finding.vuln_class,
                    file=finding.file,
                    line_window=line_window,
                    status="needs_info",
                    severity=finding.severity,
                    run_id=run_id,
                    source_ref=finding.discovery_ref,
                    payload={**base_payload, "blockers": blockers},
                )
                counts["needs_info"] += 1
        conn.commit()
    finally:
        conn.close()
    return counts
