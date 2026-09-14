"""Tests for schema v3 additions: uncovered surfaces, hardening notes,
prior exclusions, discovery fingerprints, and canonical swaps."""

from __future__ import annotations

import json

import pytest

from codesec.state import StateDB, StateConflictError


def _db(tmp_path):
    return StateDB(tmp_path / "state.db")


def _task(run_id: str) -> dict:
    return {
        "task_id": "t1",
        "source": "recon",
        "attack_class": "sqli",
        "scope_hint": "db.py",
        "target_files": ["db.py"],
        "rationale": "test",
        "priority": 3,
    }


def _finding(fid: str = "f1") -> dict:
    return {
        "finding_id": fid,
        "file": "db.py",
        "line_start": 1,
        "line_end": 5,
        "vuln_class": "sqli",
        "severity": "high",
        "description": "d" * 40,
        "evidence_snippet": "e" * 40,
        "confidence": 0.5,
    }


def test_schema_version_is_3(tmp_path):
    assert _db(tmp_path).schema_version() == 3


def test_uncovered_surfaces_roundtrip(tmp_path):
    db = _db(tmp_path)
    db.create_run("/repo", "r1")
    db.add_task("r1", _task("r1"))
    items = [
        {"surface": "admin panel", "attack_class": "idor",
         "starting_path": "app.py:90", "reason": "not assigned"},
        {"surface": "webhook", "attack_class": None,
         "starting_path": None, "reason": None},
    ]
    assert db.record_uncovered_surfaces("r1", "t1", items) == 2
    got = db.get_uncovered_surfaces("r1")
    assert got == items
    assert db.get_uncovered_surfaces("other") == []


def test_hardening_notes_roundtrip(tmp_path):
    db = _db(tmp_path)
    db.create_run("/repo", "r1")
    db.add_task("r1", _task("r1"))
    notes = [{"file": "app.py", "note": "missing rate limit"}]
    assert db.record_hardening_notes("r1", "t1", notes) == 1
    got = db.get_hardening_notes("r1")
    assert got == [{"task_id": "t1", "file": "app.py",
                    "note": "missing rate limit"}]


def test_prior_exclusions_replace(tmp_path):
    db = _db(tmp_path)
    db.create_run("/repo", "r1")
    db.set_prior_exclusions("r1", [{"fp": "a", "vuln_class": "sqli",
                                    "file": "db.py", "reason": "reported"}])
    assert len(db.get_prior_exclusions("r1")) == 1
    db.set_prior_exclusions("r1", [{"fp": "b"}])
    got = db.get_prior_exclusions("r1")
    assert len(got) == 1 and got[0]["fp"] == "b"


def test_finding_stores_discovery_fp(tmp_path):
    db = _db(tmp_path)
    db.create_run("/repo", "r1")
    db.add_task("r1", _task("r1"))
    f = _finding()
    f["discovery_fp"] = "fp123"
    f["discovery_ref"] = "abcHEAD"
    db.add_finding("r1", "t1", f)
    got = db.get_findings("r1")[0]
    assert got.discovery_fp == "fp123"
    assert got.discovery_ref == "abcHEAD"


def test_swap_canonical(tmp_path):
    db = _db(tmp_path)
    db.create_run("/repo", "r1")
    db.add_task("r1", _task("r1"))
    db.add_finding("r1", "t1", _finding("f1"))
    db.add_finding("r1", "t1", _finding("f2"))
    db.add_dedupe_group("r1", {
        "group_id": "g1", "root_cause": "sqli", "canonical_finding_id": "f1",
    })
    db.assign_finding_group("r1", "f1", "g1", True)
    db.assign_finding_group("r1", "f2", "g1", False)

    db.swap_canonical("r1", "g1", "f2", "better PoC")

    findings = {f.finding_id: f for f in db.get_findings("r1")}
    assert findings["f1"].is_canonical is False
    assert findings["f2"].is_canonical is True
    row = db._conn.execute(
        "SELECT canonical_finding_id, canonical_override FROM dedupe_groups "
        "WHERE run_id='r1' AND group_id='g1'"
    ).fetchone()
    assert row["canonical_finding_id"] == "f2"
    audit = json.loads(row["canonical_override"])
    assert audit[0]["from"] == "f1" and audit[0]["to"] == "f2"


def test_swap_canonical_survives_dedupe_reapplication(tmp_path):
    """Re-applying the same dedupe payload (feedback loop, resume) resets
    is_canonical via assign_finding_group — a second swap_canonical call
    must still re-assert the replacement without duplicating the audit."""
    db = _db(tmp_path)
    db.create_run("/repo", "r1")
    db.add_task("r1", _task("r1"))
    db.add_finding("r1", "t1", _finding("f1"))
    db.add_finding("r1", "t1", _finding("f2"))
    db.add_dedupe_group("r1", {
        "group_id": "g1", "root_cause": "sqli", "canonical_finding_id": "f1",
    })

    def apply_payload():
        db.assign_finding_group("r1", "f1", "g1", True)
        db.assign_finding_group("r1", "f2", "g1", False)
        db.swap_canonical("r1", "g1", "f2", "better PoC")

    apply_payload()
    apply_payload()  # second pass — the payload's canonical is still f1

    findings = {f.finding_id: f for f in db.get_findings("r1")}
    assert findings["f1"].is_canonical is False
    assert findings["f2"].is_canonical is True
    row = db._conn.execute(
        "SELECT canonical_override FROM dedupe_groups "
        "WHERE run_id='r1' AND group_id='g1'"
    ).fetchone()
    assert len(json.loads(row["canonical_override"])) == 1


def test_swap_canonical_rejects_non_member(tmp_path):
    db = _db(tmp_path)
    db.create_run("/repo", "r1")
    db.add_task("r1", _task("r1"))
    db.add_finding("r1", "t1", _finding("f1"))
    db.add_finding("r1", "t1", _finding("f2"))
    db.add_dedupe_group("r1", {
        "group_id": "g1", "root_cause": "sqli", "canonical_finding_id": "f1",
    })
    db.assign_finding_group("r1", "f1", "g1", True)
    with pytest.raises(StateConflictError):
        db.swap_canonical("r1", "g1", "f2", "not a member")


def test_v2_database_migrates_columns(tmp_path):
    """A findings table created without v3 columns gains them via ALTER."""
    import sqlite3

    path = tmp_path / "old.db"
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        INSERT INTO schema_meta VALUES ('schema_version', '2');
        CREATE TABLE runs (run_id TEXT PRIMARY KEY, repo_path TEXT NOT NULL,
            started_at REAL NOT NULL, finished_at REAL,
            status TEXT NOT NULL DEFAULT 'running');
        CREATE TABLE tasks (
            task_id TEXT NOT NULL, run_id TEXT NOT NULL,
            source TEXT NOT NULL, attack_class TEXT NOT NULL,
            scope_hint TEXT NOT NULL, target_files TEXT NOT NULL,
            rationale TEXT, priority INTEGER NOT NULL DEFAULT 3,
            status TEXT NOT NULL DEFAULT 'pending', raw_json TEXT NOT NULL,
            created_at REAL NOT NULL, updated_at REAL NOT NULL,
            PRIMARY KEY (run_id, task_id));
        CREATE TABLE findings (
            finding_id TEXT NOT NULL, task_id TEXT NOT NULL,
            run_id TEXT NOT NULL, file TEXT NOT NULL,
            line_start INTEGER NOT NULL, line_end INTEGER NOT NULL,
            vuln_class TEXT NOT NULL, severity TEXT NOT NULL,
            description TEXT NOT NULL, evidence TEXT NOT NULL,
            poc_succeeded INTEGER DEFAULT 0, confidence REAL,
            raw_json TEXT NOT NULL, validation_status TEXT,
            validation_json TEXT, group_id TEXT,
            is_canonical INTEGER DEFAULT 0,
            PRIMARY KEY (run_id, finding_id));
        CREATE TABLE dedupe_groups (
            group_id TEXT NOT NULL, run_id TEXT NOT NULL,
            root_cause TEXT NOT NULL, canonical_finding_id TEXT NOT NULL,
            raw_json TEXT NOT NULL, PRIMARY KEY (run_id, group_id));
        """
    )
    conn.commit()
    conn.close()

    db = StateDB(path)
    cols = {
        r["name"]
        for r in db._conn.execute("PRAGMA table_info(findings)").fetchall()
    }
    assert {"discovery_fp", "discovery_ref"} <= cols
    gcols = {
        r["name"]
        for r in db._conn.execute("PRAGMA table_info(dedupe_groups)").fetchall()
    }
    assert "canonical_override" in gcols
    # add_finding still works against the migrated table
    db.create_run("/repo", "r1")
    db.add_task("r1", _task("r1"))
    db.add_finding("r1", "t1", _finding())


def test_git_head_cached_per_repo(tmp_path, monkeypatch):
    """discovery_ref must not spawn a `git rev-parse` per finding — one
    subprocess per repo root for the life of the StateDB."""
    import subprocess as sp
    from codesec import state as state_mod

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "db.py").write_text("x = 'vulnerable query construction'\n")
    for args in (["init", "-q"], ["add", "db.py"],
                 ["-c", "user.email=t@t", "-c", "user.name=t",
                  "commit", "-qm", "init"]):
        sp.run(["git", "-C", str(repo)] + args, check=True,
               capture_output=True)

    rev_parse_calls = []
    real_run = sp.run

    def counting(cmd, *a, **kw):
        if "rev-parse" in cmd:
            rev_parse_calls.append(cmd)
        return real_run(cmd, *a, **kw)

    monkeypatch.setattr(state_mod.subprocess, "run", counting)

    db = _db(tmp_path)
    db.create_run(str(repo), "r1")
    db.add_task("r1", _task("r1"))
    db.add_finding("r1", "t1", _finding("f1"))
    db.add_finding("r1", "t1", _finding("f2"))

    assert len(rev_parse_calls) == 1
    f1 = {f.finding_id: f for f in db.get_findings("r1")}["f1"]
    assert f1.discovery_ref  # HEAD sha, not None
