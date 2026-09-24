"""SQLite-backed run state. JSONL artifacts in results/ are the source of
truth for raw agent output; this DB is the queryable index used for
orchestration, resume, and reporting."""

from __future__ import annotations

import json
import logging
import shutil
import sqlite3
import subprocess
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

from codesec.fingerprint import finding_fp, window_hash


log = logging.getLogger(__name__)


SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    repo_path TEXT NOT NULL,
    started_at REAL NOT NULL,
    finished_at REAL,
    status TEXT NOT NULL DEFAULT 'running'
);

CREATE TABLE IF NOT EXISTS recon_outputs (
    run_id TEXT PRIMARY KEY,
    raw_json TEXT NOT NULL,
    FOREIGN KEY (run_id) REFERENCES runs(run_id)
);

CREATE TABLE IF NOT EXISTS tasks (
    task_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    source TEXT NOT NULL,
    attack_class TEXT NOT NULL,
    scope_hint TEXT NOT NULL,
    target_files TEXT NOT NULL,
    rationale TEXT,
    priority INTEGER NOT NULL DEFAULT 3,
    status TEXT NOT NULL DEFAULT 'pending',
    raw_json TEXT NOT NULL,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    PRIMARY KEY (run_id, task_id),
    FOREIGN KEY (run_id) REFERENCES runs(run_id)
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    file TEXT NOT NULL,
    line_start INTEGER NOT NULL,
    line_end INTEGER NOT NULL,
    vuln_class TEXT NOT NULL,
    severity TEXT NOT NULL,
    description TEXT NOT NULL,
    evidence TEXT NOT NULL,
    poc_succeeded INTEGER DEFAULT 0,
    confidence REAL,
    raw_json TEXT NOT NULL,
    validation_status TEXT,
    validation_json TEXT,
    group_id TEXT,
    is_canonical INTEGER DEFAULT 0,
    discovery_fp TEXT,
    discovery_ref TEXT,
    PRIMARY KEY (run_id, finding_id),
    FOREIGN KEY (run_id, task_id) REFERENCES tasks(run_id, task_id)
);

CREATE TABLE IF NOT EXISTS traces (
    run_id TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    status TEXT NOT NULL,
    reachable INTEGER,
    confidence REAL,
    rationale TEXT,
    raw_json TEXT NOT NULL,
    PRIMARY KEY (run_id, finding_id),
    FOREIGN KEY (run_id, finding_id)
        REFERENCES findings(run_id, finding_id)
);

CREATE TABLE IF NOT EXISTS dedupe_groups (
    group_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    root_cause TEXT NOT NULL,
    canonical_finding_id TEXT NOT NULL,
    canonical_override TEXT,
    superseded_at REAL,
    raw_json TEXT NOT NULL,
    PRIMARY KEY (run_id, group_id),
    FOREIGN KEY (run_id) REFERENCES runs(run_id)
);

-- Hunt-reported surfaces the hunter noticed but wasn't assigned (W9).
CREATE TABLE IF NOT EXISTS uncovered_surfaces (
    run_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    surface TEXT NOT NULL,
    attack_class TEXT,
    starting_path TEXT,
    reason TEXT,
    raw_json TEXT NOT NULL,
    created_at REAL NOT NULL,
    FOREIGN KEY (run_id) REFERENCES runs(run_id)
);

-- Hunt-reported hardening observations: not findings, kept separate (W5).
CREATE TABLE IF NOT EXISTS hardening_notes (
    run_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    file TEXT NOT NULL,
    note TEXT NOT NULL,
    created_at REAL NOT NULL,
    FOREIGN KEY (run_id) REFERENCES runs(run_id)
);

-- Cross-run catalogue carry-over (W8): root causes already reported in
-- earlier runs, injected into Hunt as an exclusion list at run start.
CREATE TABLE IF NOT EXISTS prior_exclusions (
    run_id TEXT NOT NULL,
    fp TEXT,
    vuln_class TEXT,
    file TEXT,
    reason TEXT,
    raw_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS costs (
    cost_id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    stage TEXT NOT NULL,
    ref_id TEXT,
    usd REAL,
    input_tokens INTEGER,
    output_tokens INTEGER,
    cache_read_tokens INTEGER,
    cache_creation_tokens INTEGER,
    num_turns INTEGER,
    duration_ms INTEGER,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS artifacts (
    artifact_id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    stage TEXT NOT NULL,
    ref_id TEXT,
    kind TEXT NOT NULL,
    path TEXT NOT NULL,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS stage_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    stage TEXT NOT NULL,
    event TEXT NOT NULL,
    created_at REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_stage_events_run ON stage_events(run_id, stage);

CREATE INDEX IF NOT EXISTS idx_tasks_run_status ON tasks(run_id, status);
CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id);
CREATE INDEX IF NOT EXISTS idx_findings_validation ON findings(validation_status);
CREATE INDEX IF NOT EXISTS idx_findings_group ON findings(group_id);
CREATE INDEX IF NOT EXISTS idx_costs_run_stage ON costs(run_id, stage);

INSERT OR REPLACE INTO schema_meta (key, value)
VALUES ('schema_version', '3');
"""


@dataclass
class Task:
    task_id: str
    run_id: str
    source: str
    attack_class: str
    scope_hint: str
    target_files: list[str]
    rationale: str
    priority: int
    status: str
    raw_json: dict


@dataclass
class Finding:
    finding_id: str
    task_id: str
    run_id: str
    file: str
    line_start: int
    line_end: int
    vuln_class: str
    severity: str
    description: str
    evidence: str
    poc_succeeded: bool
    confidence: float | None
    raw_json: dict
    validation_status: str | None
    validation_json: dict | None
    group_id: str | None
    is_canonical: bool
    discovery_fp: str | None = None
    discovery_ref: str | None = None


class StateConflictError(RuntimeError):
    """A stable local ID was replayed with a different payload in one run."""


def _git_head(repo_root: Path) -> str | None:
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo_root), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return proc.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass
    return None


class StateDB:
    def __init__(self, db_path: Path):
        self.path = db_path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path))
        self._conn.row_factory = sqlite3.Row
        # git HEAD per repo root — one subprocess per repo, not per finding
        self._git_head_cache: dict[str, str | None] = {}
        if self._has_legacy_global_ids():
            self._migrate_global_ids_to_v2()
        self._conn.executescript(SCHEMA)
        self._migrate_v2_to_v3_columns()
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.commit()

    def _has_legacy_global_ids(self) -> bool:
        exists = self._conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'tasks'"
        ).fetchone()
        if exists is None:
            return False
        primary_key = [
            row["name"]
            for row in sorted(
                self._conn.execute("PRAGMA table_info(tasks)").fetchall(),
                key=lambda row: row["pk"],
            )
            if row["pk"]
        ]
        return primary_key == ["task_id"]

    def _migrate_global_ids_to_v2(self) -> None:
        """Migrate the original global-ID schema to run-scoped composite keys.

        The old INSERT OR IGNORE behavior may already have discarded colliding
        rows, so the backup is retained and a warning is emitted. Rows present
        in the legacy database are migrated atomically and count-checked.
        """
        backup = self.path.with_name(f"{self.path.name}.v1.bak")
        if backup.exists():
            backup = self.path.with_name(
                f"{self.path.name}.v1-{int(time.time())}.bak"
            )
        self._conn.commit()
        shutil.copy2(self.path, backup)

        legacy_counts = {
            table: int(
                self._conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            )
            for table in ("tasks", "findings", "traces", "dedupe_groups")
        }

        self._conn.execute("PRAGMA foreign_keys = OFF")
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            migration_statements = (
                """CREATE TABLE tasks_v2 (
                    task_id TEXT NOT NULL,
                    run_id TEXT NOT NULL,
                    source TEXT NOT NULL,
                    attack_class TEXT NOT NULL,
                    scope_hint TEXT NOT NULL,
                    target_files TEXT NOT NULL,
                    rationale TEXT,
                    priority INTEGER NOT NULL DEFAULT 3,
                    status TEXT NOT NULL DEFAULT 'pending',
                    raw_json TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    PRIMARY KEY (run_id, task_id),
                    FOREIGN KEY (run_id) REFERENCES runs(run_id)
                )""",
                """CREATE TABLE findings_v2 (
                    finding_id TEXT NOT NULL,
                    task_id TEXT NOT NULL,
                    run_id TEXT NOT NULL,
                    file TEXT NOT NULL,
                    line_start INTEGER NOT NULL,
                    line_end INTEGER NOT NULL,
                    vuln_class TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    description TEXT NOT NULL,
                    evidence TEXT NOT NULL,
                    poc_succeeded INTEGER DEFAULT 0,
                    confidence REAL,
                    raw_json TEXT NOT NULL,
                    validation_status TEXT,
                    validation_json TEXT,
                    group_id TEXT,
                    is_canonical INTEGER DEFAULT 0,
                    PRIMARY KEY (run_id, finding_id),
                    FOREIGN KEY (run_id, task_id)
                        REFERENCES tasks_v2(run_id, task_id)
                )""",
                """CREATE TABLE traces_v2 (
                    run_id TEXT NOT NULL,
                    finding_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    reachable INTEGER,
                    confidence REAL,
                    rationale TEXT,
                    raw_json TEXT NOT NULL,
                    PRIMARY KEY (run_id, finding_id),
                    FOREIGN KEY (run_id, finding_id)
                        REFERENCES findings_v2(run_id, finding_id)
                )""",
                """CREATE TABLE dedupe_groups_v2 (
                    group_id TEXT NOT NULL,
                    run_id TEXT NOT NULL,
                    root_cause TEXT NOT NULL,
                    canonical_finding_id TEXT NOT NULL,
                    raw_json TEXT NOT NULL,
                    PRIMARY KEY (run_id, group_id),
                    FOREIGN KEY (run_id) REFERENCES runs(run_id)
                )""",
                "INSERT INTO tasks_v2 SELECT * FROM tasks",
                "INSERT INTO findings_v2 SELECT * FROM findings",
                """INSERT INTO traces_v2
                    SELECT findings.run_id, traces.finding_id,
                           CASE WHEN traces.reachable = 1
                                THEN 'reachable' ELSE 'unreachable' END,
                           traces.reachable, traces.confidence,
                           traces.rationale, traces.raw_json
                    FROM traces
                    JOIN findings
                      ON findings.finding_id = traces.finding_id""",
                "INSERT INTO dedupe_groups_v2 SELECT * FROM dedupe_groups",
            )
            for statement in migration_statements:
                self._conn.execute(statement)

            migrated_counts = {
                table: int(
                    self._conn.execute(
                        f"SELECT COUNT(*) FROM {table}_v2"
                    ).fetchone()[0]
                )
                for table in ("tasks", "findings", "traces", "dedupe_groups")
            }
            if migrated_counts != legacy_counts:
                raise RuntimeError(
                    "state migration row-count mismatch: "
                    f"legacy={legacy_counts}, migrated={migrated_counts}"
                )

            replacement_statements = (
                "DROP TABLE traces",
                "DROP TABLE dedupe_groups",
                "DROP TABLE findings",
                "DROP TABLE tasks",
                "ALTER TABLE tasks_v2 RENAME TO tasks",
                "ALTER TABLE findings_v2 RENAME TO findings",
                "ALTER TABLE traces_v2 RENAME TO traces",
                "ALTER TABLE dedupe_groups_v2 RENAME TO dedupe_groups",
                """CREATE TABLE IF NOT EXISTS schema_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )""",
                """INSERT OR REPLACE INTO schema_meta (key, value)
                VALUES ('schema_version', '2')""",
            )
            for statement in replacement_statements:
                self._conn.execute(statement)
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise
        finally:
            self._conn.execute("PRAGMA foreign_keys = ON")

        log.warning(
            "migrated legacy state database to schema v2; backup=%s. "
            "Historical INSERT OR IGNORE collisions cannot be recovered.",
            backup,
        )

    def _migrate_v2_to_v3_columns(self) -> None:
        """Add v3 columns to databases created under schema v2.

        CREATE TABLE IF NOT EXISTS in SCHEMA only helps fresh databases;
        existing ones need ALTERs. Idempotent: driven by column presence,
        not the version counter."""
        additions = {
            "findings": [
                ("discovery_fp", "TEXT"),
                ("discovery_ref", "TEXT"),
            ],
            "dedupe_groups": [
                ("canonical_override", "TEXT"),
                ("superseded_at", "REAL"),
            ],
        }
        for table, columns in additions.items():
            existing = {
                row["name"]
                for row in self._conn.execute(
                    f"PRAGMA table_info({table})"
                ).fetchall()
            }
            for name, decl in columns:
                if name not in existing:
                    self._conn.execute(
                        f"ALTER TABLE {table} ADD COLUMN {name} {decl}"
                    )
        self._conn.commit()

    def schema_version(self) -> int:
        row = self._conn.execute(
            "SELECT value FROM schema_meta WHERE key = 'schema_version'"
        ).fetchone()
        return int(row["value"]) if row else 0

    # ---------- runs ----------

    def create_run(self, repo_path: str, run_id: str | None = None) -> str:
        run_id = run_id or f"run_{uuid.uuid4().hex[:8]}"
        self._conn.execute(
            "INSERT INTO runs (run_id, repo_path, started_at, status) VALUES (?, ?, ?, ?)",
            (run_id, repo_path, time.time(), "running"),
        )
        self._conn.commit()
        return run_id

    def finish_run(self, run_id: str, status: str = "completed") -> None:
        self._conn.execute(
            "UPDATE runs SET status = ?, finished_at = ? WHERE run_id = ?",
            (status, time.time(), run_id),
        )
        self._conn.commit()

    def resume_run(self, run_id: str) -> None:
        cursor = self._conn.execute(
            "UPDATE runs SET status = 'running', finished_at = NULL "
            "WHERE run_id = ?",
            (run_id,),
        )
        if cursor.rowcount != 1:
            raise KeyError(f"unknown run {run_id!r}")
        self._conn.commit()

    def get_run(self, run_id: str) -> sqlite3.Row | None:
        return self._conn.execute(
            "SELECT * FROM runs WHERE run_id = ?", (run_id,)
        ).fetchone()

    def list_runs(self) -> list[sqlite3.Row]:
        return list(
            self._conn.execute(
                "SELECT * FROM runs ORDER BY started_at DESC"
            ).fetchall()
        )

    def completion_gaps(self, run_id: str) -> list[str]:
        """Return deterministic reasons a run cannot be marked complete."""
        gaps: list[str] = []

        for row in self._conn.execute(
            "SELECT task_id, status FROM tasks "
            "WHERE run_id = ? AND status != 'done' ORDER BY task_id",
            (run_id,),
        ):
            gaps.append(f"task {row['task_id']} is {row['status']}")

        for row in self._conn.execute(
            "SELECT finding_id FROM findings "
            "WHERE run_id = ? AND validation_status IS NULL ORDER BY finding_id",
            (run_id,),
        ):
            gaps.append(f"finding {row['finding_id']} is not validated")

        for row in self._conn.execute(
            "SELECT finding_id FROM findings "
            "WHERE run_id = ? AND validation_status = 'confirmed' "
            "AND group_id IS NULL ORDER BY finding_id",
            (run_id,),
        ):
            gaps.append(f"confirmed finding {row['finding_id']} is not grouped")

        for row in self._conn.execute(
            """
            SELECT g.group_id
            FROM dedupe_groups AS g
            LEFT JOIN findings AS f
              ON f.run_id = g.run_id
             AND f.group_id = g.group_id
             AND f.is_canonical = 1
            WHERE g.run_id = ? AND g.superseded_at IS NULL
              AND f.finding_id IS NULL
            ORDER BY g.group_id
            """,
            (run_id,),
        ):
            gaps.append(f"group {row['group_id']} has no canonical finding")

        return gaps

    # ---------- recon ----------

    def save_recon_output(self, run_id: str, payload: dict) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO recon_outputs (run_id, raw_json) VALUES (?, ?)",
            (run_id, json.dumps(payload)),
        )
        self._conn.commit()

    def get_recon_output(self, run_id: str) -> dict | None:
        row = self._conn.execute(
            "SELECT raw_json FROM recon_outputs WHERE run_id = ?", (run_id,)
        ).fetchone()
        return json.loads(row["raw_json"]) if row else None

    # ---------- tasks ----------

    def add_task(self, run_id: str, task: dict) -> None:
        existing = self._conn.execute(
            "SELECT raw_json FROM tasks WHERE run_id = ? AND task_id = ?",
            (run_id, task["task_id"]),
        ).fetchone()
        if existing is not None:
            if json.loads(existing["raw_json"]) == task:
                return
            raise StateConflictError(
                f"task {task['task_id']!r} conflicts with its existing payload "
                f"in run {run_id!r}"
            )
        now = time.time()
        self._conn.execute(
            """INSERT INTO tasks
            (task_id, run_id, source, attack_class, scope_hint, target_files,
             rationale, priority, status, raw_json, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?)""",
            (
                task["task_id"],
                run_id,
                task.get("source", "recon"),
                task["attack_class"],
                task["scope_hint"],
                json.dumps(task["target_files"]),
                task.get("rationale", ""),
                int(task.get("priority", 3)),
                json.dumps(task),
                now,
                now,
            ),
        )
        self._conn.commit()

    def get_pending_tasks(self, run_id: str) -> list[Task]:
        rows = self._conn.execute(
            "SELECT * FROM tasks WHERE run_id = ? AND status = 'pending' ORDER BY priority, created_at",
            (run_id,),
        ).fetchall()
        return [self._row_to_task(r) for r in rows]

    def get_all_tasks(self, run_id: str) -> list[Task]:
        rows = self._conn.execute(
            "SELECT * FROM tasks WHERE run_id = ? ORDER BY created_at",
            (run_id,),
        ).fetchall()
        return [self._row_to_task(r) for r in rows]

    def update_task_status(self, run_id: str, task_id: str, status: str) -> None:
        self._conn.execute(
            "UPDATE tasks SET status = ?, updated_at = ? "
            "WHERE run_id = ? AND task_id = ?",
            (status, time.time(), run_id, task_id),
        )
        self._conn.commit()

    def reset_incomplete_tasks(self, run_id: str) -> int:
        """Flip 'running' and 'failed' tasks back to 'pending' so a resumed
        run re-attempts work that was interrupted (quota/crash, left
        'running') or that failed on a transient/quota error (marked
        'failed'). Returns the number of tasks reset."""
        cur = self._conn.execute(
            "UPDATE tasks SET status = 'pending', updated_at = ? "
            "WHERE run_id = ? AND status IN ('running', 'failed')",
            (time.time(), run_id),
        )
        self._conn.commit()
        return cur.rowcount

    @staticmethod
    def _row_to_task(r: sqlite3.Row) -> Task:
        return Task(
            task_id=r["task_id"],
            run_id=r["run_id"],
            source=r["source"],
            attack_class=r["attack_class"],
            scope_hint=r["scope_hint"],
            target_files=json.loads(r["target_files"]),
            rationale=r["rationale"] or "",
            priority=r["priority"],
            status=r["status"],
            raw_json=json.loads(r["raw_json"]),
        )

    # ---------- findings ----------

    def add_finding(self, run_id: str, task_id: str, finding: dict) -> None:
        existing = self._conn.execute(
            "SELECT task_id, raw_json FROM findings "
            "WHERE run_id = ? AND finding_id = ?",
            (run_id, finding["finding_id"]),
        ).fetchone()
        if existing is not None:
            if (
                existing["task_id"] == task_id
                and json.loads(existing["raw_json"]) == finding
            ):
                return
            raise StateConflictError(
                f"finding {finding['finding_id']!r} conflicts with its existing "
                f"payload in run {run_id!r}"
            )
        poc = finding.get("poc") or {}
        discovery_fp = finding.get("discovery_fp")
        discovery_ref = finding.get("discovery_ref")
        if discovery_fp is None or discovery_ref is None:
            auto_fp, auto_ref = self._discovery_identity(run_id, finding)
            discovery_fp = discovery_fp or auto_fp
            discovery_ref = discovery_ref or auto_ref
        self._conn.execute(
            """INSERT INTO findings
            (finding_id, task_id, run_id, file, line_start, line_end,
             vuln_class, severity, description, evidence, poc_succeeded,
             confidence, raw_json, discovery_fp, discovery_ref)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                finding["finding_id"],
                task_id,
                run_id,
                finding["file"],
                finding["line_start"],
                finding["line_end"],
                finding["vuln_class"],
                finding["severity"],
                finding["description"],
                finding["evidence_snippet"],
                1 if poc.get("succeeded") else 0,
                finding.get("confidence"),
                json.dumps(finding),
                discovery_fp,
                discovery_ref,
            ),
        )
        self._conn.commit()

    def _discovery_identity(
        self, run_id: str, finding: dict
    ) -> tuple[str | None, str | None]:
        """Best-effort (discovery_fp, discovery_ref) for a finding.

        The repo root comes from the run row; the fp is the content
        fingerprint of the cited window. Every failure mode (missing run
        row, missing file, bad line range, git absent) degrades to None —
        fingerprinting must never break add_finding."""
        try:
            run = self.get_run(run_id)
            if run is None:
                return None, None
            repo_root = Path(run["repo_path"])
            file = str(finding["file"])
            window = window_hash(
                repo_root,
                file,
                int(finding["line_start"]),
                int(finding["line_end"]),
            )
            fp = (
                finding_fp(str(finding["vuln_class"]), file, window)
                if window is not None
                else None
            )
            key = str(repo_root)
            if key not in self._git_head_cache:
                self._git_head_cache[key] = _git_head(repo_root)
            head = self._git_head_cache[key]
            if head:
                return fp, head
            try:
                return fp, str(int((repo_root / file).stat().st_mtime))
            except OSError:
                return fp, None
        except Exception:
            log.debug("discovery fingerprinting failed", exc_info=True)
            return None, None

    def get_findings(self, run_id: str, *, validation_status: str | None = None,
                     canonical_only: bool = False) -> list[Finding]:
        sql = "SELECT * FROM findings WHERE run_id = ?"
        args: list[Any] = [run_id]
        if validation_status is not None:
            sql += " AND validation_status = ?"
            args.append(validation_status)
        if canonical_only:
            sql += " AND is_canonical = 1"
        rows = self._conn.execute(sql, args).fetchall()
        return [self._row_to_finding(r) for r in rows]

    def get_unvalidated_findings(self, run_id: str) -> list[Finding]:
        rows = self._conn.execute(
            "SELECT * FROM findings WHERE run_id = ? AND validation_status IS NULL",
            (run_id,),
        ).fetchall()
        return [self._row_to_finding(r) for r in rows]

    def set_finding_validation(
        self, run_id: str, finding_id: str, status: str, payload: dict
    ) -> None:
        self._conn.execute(
            "UPDATE findings SET validation_status = ?, validation_json = ? "
            "WHERE run_id = ? AND finding_id = ?",
            (status, json.dumps(payload), run_id, finding_id),
        )
        self._conn.commit()

    def assign_finding_group(
        self,
        run_id: str,
        finding_id: str,
        group_id: str,
        is_canonical: bool,
    ) -> None:
        self._conn.execute(
            "UPDATE findings SET group_id = ?, is_canonical = ? "
            "WHERE run_id = ? AND finding_id = ?",
            (group_id, 1 if is_canonical else 0, run_id, finding_id),
        )
        self._conn.commit()

    @staticmethod
    def _row_to_finding(r: sqlite3.Row) -> Finding:
        return Finding(
            finding_id=r["finding_id"],
            task_id=r["task_id"],
            run_id=r["run_id"],
            file=r["file"],
            line_start=r["line_start"],
            line_end=r["line_end"],
            vuln_class=r["vuln_class"],
            severity=r["severity"],
            description=r["description"],
            evidence=r["evidence"],
            poc_succeeded=bool(r["poc_succeeded"]),
            confidence=r["confidence"],
            raw_json=json.loads(r["raw_json"]),
            validation_status=r["validation_status"],
            validation_json=json.loads(r["validation_json"]) if r["validation_json"] else None,
            group_id=r["group_id"],
            is_canonical=bool(r["is_canonical"]),
            discovery_fp=r["discovery_fp"],
            discovery_ref=r["discovery_ref"],
        )

    # ---------- uncovered surfaces / hardening notes (W9/W5) ----------

    def record_uncovered_surfaces(
        self, run_id: str, task_id: str, items: list[dict]
    ) -> int:
        now = time.time()
        for item in items:
            self._conn.execute(
                """INSERT INTO uncovered_surfaces
                (run_id, task_id, surface, attack_class, starting_path,
                 reason, raw_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    run_id,
                    task_id,
                    str(item.get("surface", "")),
                    item.get("attack_class"),
                    item.get("starting_path"),
                    item.get("reason"),
                    json.dumps(item),
                    now,
                ),
            )
        self._conn.commit()
        return len(items)

    def get_uncovered_surfaces(self, run_id: str) -> list[dict]:
        rows = self._conn.execute(
            "SELECT raw_json FROM uncovered_surfaces WHERE run_id = ?",
            (run_id,),
        ).fetchall()
        return [json.loads(r["raw_json"]) for r in rows]

    def record_hardening_notes(
        self, run_id: str, task_id: str, notes: list[dict]
    ) -> int:
        now = time.time()
        for note in notes:
            self._conn.execute(
                """INSERT INTO hardening_notes
                (run_id, task_id, file, note, created_at)
                VALUES (?, ?, ?, ?, ?)""",
                (
                    run_id,
                    task_id,
                    str(note.get("file", "")),
                    str(note.get("note", "")),
                    now,
                ),
            )
        self._conn.commit()
        return len(notes)

    def get_hardening_notes(self, run_id: str) -> list[dict]:
        rows = self._conn.execute(
            "SELECT task_id, file, note FROM hardening_notes WHERE run_id = ?",
            (run_id,),
        ).fetchall()
        return [
            {"task_id": r["task_id"], "file": r["file"], "note": r["note"]}
            for r in rows
        ]

    # ---------- prior exclusions (W8 cross-run catalogue) ----------

    def set_prior_exclusions(self, run_id: str, items: list[dict]) -> None:
        self._conn.execute(
            "DELETE FROM prior_exclusions WHERE run_id = ?", (run_id,)
        )
        for item in items:
            self._conn.execute(
                """INSERT INTO prior_exclusions
                (run_id, fp, vuln_class, file, reason, raw_json)
                VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    run_id,
                    item.get("fp"),
                    item.get("vuln_class"),
                    item.get("file"),
                    item.get("reason"),
                    json.dumps(item),
                ),
            )
        self._conn.commit()

    def get_prior_exclusions(self, run_id: str) -> list[dict]:
        rows = self._conn.execute(
            "SELECT raw_json FROM prior_exclusions WHERE run_id = ?",
            (run_id,),
        ).fetchall()
        return [json.loads(r["raw_json"]) for r in rows]

    # ---------- dedupe canonical override (W13) ----------

    def swap_canonical(
        self,
        run_id: str,
        group_id: str,
        new_finding_id: str,
        reason: str,
    ) -> None:
        """Replace a dedupe group's canonical finding with a member that
        has a strictly better evidence story. Auditable: the swap is
        appended to the group's canonical_override JSON list."""
        members = self._conn.execute(
            "SELECT finding_id FROM findings "
            "WHERE run_id = ? AND group_id = ?",
            (run_id, group_id),
        ).fetchall()
        member_ids = {r["finding_id"] for r in members}
        if new_finding_id not in member_ids:
            raise StateConflictError(
                f"cannot swap canonical of group {group_id!r}: "
                f"{new_finding_id!r} is not a member"
            )
        group = self._conn.execute(
            "SELECT canonical_finding_id, canonical_override "
            "FROM dedupe_groups WHERE run_id = ? AND group_id = ?",
            (run_id, group_id),
        ).fetchone()
        if group is None:
            raise StateConflictError(
                f"cannot swap canonical: group {group_id!r} not found "
                f"in run {run_id!r}"
            )
        previous = group["canonical_finding_id"]
        # Always re-assert the flags — dedupe output may be applied twice
        # (feedback re-runs, resume) and assign_finding_group resets
        # is_canonical to the payload's canonical each pass. Only the audit
        # append is gated on an actual change.
        self._conn.execute(
            "UPDATE findings SET is_canonical = 0 "
            "WHERE run_id = ? AND group_id = ?",
            (run_id, group_id),
        )
        self._conn.execute(
            "UPDATE findings SET is_canonical = 1 "
            "WHERE run_id = ? AND finding_id = ?",
            (run_id, new_finding_id),
        )
        audit = json.loads(group["canonical_override"] or "[]")
        if previous != new_finding_id:
            audit.append(
                {
                    "from": previous,
                    "to": new_finding_id,
                    "reason": reason,
                    "at": time.time(),
                }
            )
        self._conn.execute(
            "UPDATE dedupe_groups SET canonical_finding_id = ?, "
            "canonical_override = ? WHERE run_id = ? AND group_id = ?",
            (new_finding_id, json.dumps(audit), run_id, group_id),
        )
        self._conn.commit()

    # ---------- traces ----------

    def add_trace(self, run_id: str, finding_id: str, payload: dict) -> None:
        normalized = dict(payload)
        status = normalized.get("status")
        if status is None:
            status = "reachable" if normalized.get("reachable") else "unreachable"
            normalized["status"] = status
        if status not in {"reachable", "unreachable", "uncertain"}:
            raise ValueError(f"unsupported trace status: {status!r}")
        if status == "uncertain":
            normalized["reachable"] = None

        existing = self._conn.execute(
            "SELECT raw_json FROM traces "
            "WHERE run_id = ? AND finding_id = ?",
            (run_id, finding_id),
        ).fetchone()
        if existing is not None:
            if json.loads(existing["raw_json"]) == normalized:
                return
            raise StateConflictError(
                f"trace {finding_id!r} conflicts with its existing payload "
                f"in run {run_id!r}"
            )
        self._conn.execute(
            """INSERT INTO traces
            (run_id, finding_id, status, reachable, confidence, rationale, raw_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                run_id,
                finding_id,
                status,
                (
                    None
                    if normalized.get("reachable") is None
                    else 1 if normalized["reachable"] else 0
                ),
                normalized.get("confidence"),
                normalized.get("rationale", ""),
                json.dumps(normalized),
            ),
        )
        self._conn.commit()

    def get_trace(self, run_id: str, finding_id: str) -> dict | None:
        row = self._conn.execute(
            "SELECT raw_json FROM traces "
            "WHERE run_id = ? AND finding_id = ?",
            (run_id, finding_id),
        ).fetchone()
        return json.loads(row["raw_json"]) if row else None

    def get_reachable_canonical_findings(self, run_id: str) -> list[tuple[Finding, dict]]:
        out: list[tuple[Finding, dict]] = []
        for f in self.get_findings(run_id, validation_status="confirmed", canonical_only=True):
            tr = self.get_trace(run_id, f.finding_id)
            if tr and tr.get("reachable"):
                out.append((f, tr))
        return out

    def get_report_findings(
        self, run_id: str, policy: str = "confirmed_all"
    ) -> list[tuple[Finding, dict | None]]:
        """Authoritative report membership, defined once for every consumer.

        Policies (see codesec.config.REPORT_POLICIES):
        - confirmed_all: every confirmed canonical finding (historical default).
        - confirmed_reachable: confirmed canonical AND a valid reachable trace.
        - confirmed_except_unreachable: confirmed canonical except traces the
          engine marked explicitly unreachable.
        Trace may be missing (untraced) — only "confirmed_reachable" demands it.
        """
        out: list[tuple[Finding, dict | None]] = []
        for f in self.get_findings(
            run_id, validation_status="confirmed", canonical_only=True
        ):
            trace = self.get_trace(run_id, f.finding_id)
            status = self.trace_status(trace)
            if policy == "confirmed_all":
                keep = True
            elif policy == "confirmed_reachable":
                keep = status == "reachable"
            elif policy == "confirmed_except_unreachable":
                keep = status != "unreachable"
            else:
                raise ValueError(f"unknown report policy {policy!r}")
            if keep:
                out.append((f, trace))
        return out

    @staticmethod
    def trace_status(trace: dict | None) -> str:
        """Normalized trace state: reachable/unreachable/uncertain/untraced."""
        if not isinstance(trace, dict):
            return "untraced"
        status = trace.get("status")
        if status in {"reachable", "unreachable", "uncertain", "untraced"}:
            return status
        if trace.get("reachable") is True:
            return "reachable"
        if trace.get("reachable") is False:
            return "unreachable"
        return "uncertain"

    def report_membership_snapshot(self, run_id: str) -> dict:
        """Membership truth for summary counts and exports (single source).

        Emits every evidence tier separately so no tier disappears from the
        review record regardless of the selected primary policy.
        """
        by_status: dict[str, list[str]] = {
            "reachable": [],
            "uncertain": [],
            "unreachable": [],
            "untraced": [],
        }
        canonical: list[str] = []
        for f in self.get_findings(
            run_id, validation_status="confirmed", canonical_only=True
        ):
            canonical.append(f.finding_id)
            by_status[self.trace_status(self.get_trace(run_id, f.finding_id))].append(
                f.finding_id
            )
        return {
            "confirmed_canonical_ids": sorted(canonical),
            "confirmed_reachable_ids": sorted(by_status["reachable"]),
            "confirmed_except_unreachable_ids": sorted(
                fid
                for status in ("reachable", "uncertain", "untraced")
                for fid in by_status[status]
            ),
            "by_trace_status": {k: sorted(v) for k, v in by_status.items()},
        }

    # ---------- stage events ----------

    def record_stage_event(
        self, run_id: str, stage: str, event: dict
    ) -> None:
        """Append a structured stage-health/degradation/telemetry event."""
        self._conn.execute(
            "INSERT INTO stage_events (run_id, stage, event, created_at) "
            "VALUES (?, ?, ?, ?)",
            (run_id, stage, json.dumps(event, ensure_ascii=False), time.time()),
        )
        self._conn.commit()

    def get_stage_events(
        self, run_id: str, stage: str | None = None
    ) -> list[dict]:
        if stage is None:
            rows = self._conn.execute(
                "SELECT stage, event, created_at FROM stage_events "
                "WHERE run_id = ? ORDER BY event_id",
                (run_id,),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT stage, event, created_at FROM stage_events "
                "WHERE run_id = ? AND stage = ? ORDER BY event_id",
                (run_id, stage),
            ).fetchall()
        return [
            {
                "stage": row["stage"],
                "created_at": row["created_at"],
                **json.loads(row["event"]),
            }
            for row in rows
        ]

    # ---------- dedupe ----------

    def supersede_dedupe_groups(self, run_id: str) -> int:
        """Retire the current dedupe generation before a new one applies.

        Multi-pass dedupe (feedback iterations, resume) regroups the whole
        confirmed set; prior group rows stay as immutable history — marked
        superseded rather than deleted — so the coverage check never sees
        an "active" group with no canonical member."""
        cur = self._conn.execute(
            "UPDATE dedupe_groups SET superseded_at = ? "
            "WHERE run_id = ? AND superseded_at IS NULL",
            (time.time(), run_id),
        )
        self._conn.commit()
        return cur.rowcount

    def add_dedupe_group(self, run_id: str, group: dict) -> None:
        existing = self._conn.execute(
            "SELECT raw_json FROM dedupe_groups "
            "WHERE run_id = ? AND group_id = ?",
            (run_id, group["group_id"]),
        ).fetchone()
        if existing is not None:
            if json.loads(existing["raw_json"]) == group:
                # Idempotent re-apply of the same generation (resume): the
                # row may have been superseded by an aborted later pass —
                # reactivate it as current.
                self._conn.execute(
                    "UPDATE dedupe_groups SET superseded_at = NULL "
                    "WHERE run_id = ? AND group_id = ?",
                    (run_id, group["group_id"]),
                )
                self._conn.commit()
                return
            raise StateConflictError(
                f"group {group['group_id']!r} conflicts with its existing "
                f"payload in run {run_id!r}"
            )
        self._conn.execute(
            """INSERT INTO dedupe_groups
            (group_id, run_id, root_cause, canonical_finding_id, raw_json)
            VALUES (?, ?, ?, ?, ?)""",
            (
                group["group_id"],
                run_id,
                group["root_cause"],
                group["canonical_finding_id"],
                json.dumps(group),
            ),
        )
        self._conn.commit()

    def group_member_ids(
        self,
        run_id: str,
        group_id: str,
        *,
        exclude: str | None = None,
    ) -> list[str]:
        sql = (
            "SELECT finding_id FROM findings "
            "WHERE run_id = ? AND group_id = ?"
        )
        args: list[Any] = [run_id, group_id]
        if exclude is not None:
            sql += " AND finding_id != ?"
            args.append(exclude)
        sql += " ORDER BY finding_id"
        return [
            row["finding_id"]
            for row in self._conn.execute(sql, args).fetchall()
        ]

    # ---------- costs ----------

    def record_agent_result(
        self,
        run_id: str,
        stage: str,
        ref_id: str | None,
        result: Any,
    ) -> None:
        """Persist normalized AgentResult fields without backend-specific parsing."""
        self._conn.execute(
            """INSERT INTO costs
            (run_id, stage, ref_id, usd, input_tokens, output_tokens,
             cache_read_tokens, cache_creation_tokens, num_turns, duration_ms,
             created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                run_id,
                stage,
                ref_id,
                result.cost_usd,
                result.input_tokens,
                result.output_tokens,
                result.cache_read_tokens,
                result.cache_creation_tokens,
                result.num_turns,
                result.duration_ms,
                time.time(),
            ),
        )
        self._conn.commit()

    def record_cost(
        self,
        run_id: str,
        stage: str,
        ref_id: str | None,
        result_msg: dict,
    ) -> None:
        usage = result_msg.get("usage") or {}
        self._conn.execute(
            """INSERT INTO costs
            (run_id, stage, ref_id, usd, input_tokens, output_tokens,
             cache_read_tokens, cache_creation_tokens, num_turns, duration_ms, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                run_id,
                stage,
                ref_id,
                result_msg.get("total_cost_usd"),
                usage.get("input_tokens"),
                usage.get("output_tokens"),
                usage.get("cache_read_input_tokens"),
                usage.get("cache_creation_input_tokens"),
                result_msg.get("num_turns"),
                result_msg.get("duration_ms"),
                time.time(),
            ),
        )
        self._conn.commit()

    def stage_usage(self, run_id: str, stage: str) -> dict[str, int]:
        row = self._conn.execute(
            """
            SELECT
                COALESCE(SUM(input_tokens), 0) AS input_tokens,
                COALESCE(SUM(output_tokens), 0) AS output_tokens,
                COALESCE(SUM(cache_read_tokens), 0) AS cache_read_tokens,
                COALESCE(SUM(cache_creation_tokens), 0)
                    AS cache_creation_tokens,
                COALESCE(SUM(num_turns), 0) AS num_turns,
                COALESCE(SUM(duration_ms), 0) AS duration_ms
            FROM costs
            WHERE run_id = ? AND stage = ?
            """,
            (run_id, stage),
        ).fetchone()
        return {
            key: int(row[key])
            for key in (
                "input_tokens",
                "output_tokens",
                "cache_read_tokens",
                "cache_creation_tokens",
                "num_turns",
                "duration_ms",
            )
        }

    def total_cost(self, run_id: str) -> float:
        row = self._conn.execute(
            "SELECT COALESCE(SUM(usd), 0) AS total FROM costs WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        return float(row["total"]) if row else 0.0

    # ---------- artifacts ----------

    def add_artifact(
        self, run_id: str, stage: str, ref_id: str | None, kind: str, path: str
    ) -> None:
        self._conn.execute(
            """INSERT INTO artifacts
            (run_id, stage, ref_id, kind, path, created_at)
            VALUES (?, ?, ?, ?, ?, ?)""",
            (run_id, stage, ref_id, kind, path, time.time()),
        )
        self._conn.commit()

    def artifact_count(
        self,
        run_id: str,
        stage: str,
        *,
        kind: str | None = None,
    ) -> int:
        sql = (
            "SELECT COUNT(*) AS count FROM artifacts "
            "WHERE run_id = ? AND stage = ?"
        )
        args: list[Any] = [run_id, stage]
        if kind is not None:
            sql += " AND kind = ?"
            args.append(kind)
        row = self._conn.execute(sql, args).fetchone()
        return int(row["count"]) if row else 0

    # ---------- context manager ----------

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "StateDB":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


@contextmanager
def open_db(path: Path) -> Iterator[StateDB]:
    db = StateDB(path)
    try:
        yield db
    finally:
        db.close()
