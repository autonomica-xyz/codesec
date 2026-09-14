"""StateDB roundtrip tests."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest

from codesec.state import StateConflictError, StateDB


def _task(task_id: str = "t_1", *, attack_class: str = "sqli") -> dict:
    return {
        "task_id": task_id,
        "attack_class": attack_class,
        "scope_hint": "inspect the query construction",
        "target_files": ["a.py"],
        "rationale": "untrusted input reaches a database query",
        "priority": 1,
        "source": "recon",
    }


def _finding(finding_id: str = "f_1", *, description: str = "unsafe query") -> dict:
    return {
        "finding_id": finding_id,
        "file": "a.py",
        "line_start": 1,
        "line_end": 2,
        "vuln_class": "sqli",
        "severity": "high",
        "description": description,
        "evidence_snippet": "cursor.execute(query)",
        "confidence": 0.9,
    }


def test_task_and_finding_ids_are_scoped_to_the_run(tmp_path: Path) -> None:
    db = StateDB(tmp_path / "state.db")
    first = db.create_run("/repo/one", "run_one")
    second = db.create_run("/repo/two", "run_two")

    db.add_task(first, _task(attack_class="sqli"))
    db.add_task(second, _task(attack_class="command_injection"))
    db.add_finding(first, "t_1", _finding(description="unsafe query in run one"))
    db.add_finding(second, "t_1", _finding(description="unsafe shell in run two"))

    assert [task.attack_class for task in db.get_all_tasks(first)] == ["sqli"]
    assert [task.attack_class for task in db.get_all_tasks(second)] == [
        "command_injection"
    ]
    assert [finding.description for finding in db.get_findings(first)] == [
        "unsafe query in run one"
    ]
    assert [finding.description for finding in db.get_findings(second)] == [
        "unsafe shell in run two"
    ]


def test_conflicting_same_run_replay_is_rejected(tmp_path: Path) -> None:
    db = StateDB(tmp_path / "state.db")
    run_id = db.create_run("/repo", "run")
    db.add_task(run_id, _task(attack_class="sqli"))

    with pytest.raises(StateConflictError, match="task.*t_1"):
        db.add_task(run_id, _task(attack_class="command_injection"))

    db.add_finding(run_id, "t_1", _finding(description="first description"))
    with pytest.raises(StateConflictError, match="finding.*f_1"):
        db.add_finding(run_id, "t_1", _finding(description="different description"))

    group = {
        "group_id": "g_1",
        "root_cause": "first root cause",
        "canonical_finding_id": "f_1",
        "member_finding_ids": ["f_1"],
    }
    db.add_dedupe_group(run_id, group)
    with pytest.raises(StateConflictError, match="group.*g_1"):
        db.add_dedupe_group(run_id, {**group, "root_cause": "different root"})

    trace = {"finding_id": "f_1", "reachable": True, "rationale": "reachable"}
    db.add_trace(run_id, "f_1", trace)
    with pytest.raises(StateConflictError, match="trace.*f_1"):
        db.add_trace(run_id, "f_1", {**trace, "reachable": False})


def test_task_status_updates_are_scoped_to_the_run(tmp_path: Path) -> None:
    db = StateDB(tmp_path / "state.db")
    first = db.create_run("/repo/one", "run_one")
    second = db.create_run("/repo/two", "run_two")
    db.add_task(first, _task())
    db.add_task(second, _task())

    db.update_task_status(first, "t_1", "done")

    assert [task.status for task in db.get_all_tasks(first)] == ["done"]
    assert [task.status for task in db.get_all_tasks(second)] == ["pending"]


def test_orchestration_daos_hide_connection_details(tmp_path: Path) -> None:
    db = StateDB(tmp_path / "state.db")
    run_id = db.create_run("/repo", "run")
    db.finish_run(run_id, "aborted")
    db.resume_run(run_id)
    assert db.get_run(run_id)["status"] == "running"
    assert db.get_run(run_id)["finished_at"] is None

    db.add_artifact(run_id, "gapfill", None, "jsonl", "/tmp/one")
    db.add_artifact(run_id, "gapfill", None, "jsonl", "/tmp/two")
    assert db.artifact_count(run_id, "gapfill") == 2

    db.add_task(run_id, _task())
    db.add_finding(run_id, "t_1", _finding("f_1"))
    db.add_finding(run_id, "t_1", _finding("f_2"))
    db.add_dedupe_group(
        run_id,
        {
            "group_id": "g_1",
            "root_cause": "same unsafe query",
            "canonical_finding_id": "f_1",
            "member_finding_ids": ["f_1", "f_2"],
        },
    )
    db.assign_finding_group(run_id, "f_1", "g_1", True)
    db.assign_finding_group(run_id, "f_2", "g_1", False)
    assert db.group_member_ids(run_id, "g_1", exclude="f_1") == ["f_2"]


def test_validation_group_and_trace_state_are_scoped_to_the_run(tmp_path: Path) -> None:
    db = StateDB(tmp_path / "state.db")
    first = db.create_run("/repo/one", "run_one")
    second = db.create_run("/repo/two", "run_two")
    for run_id in (first, second):
        db.add_task(run_id, _task())
        db.add_finding(run_id, "t_1", _finding())

    db.set_finding_validation(
        first,
        "f_1",
        "confirmed",
        {"finding_id": "f_1", "verdict": "confirmed"},
    )
    db.set_finding_validation(
        second,
        "f_1",
        "rejected",
        {"finding_id": "f_1", "verdict": "rejected"},
    )
    db.add_dedupe_group(
        first,
        {
            "group_id": "g_1",
            "root_cause": "first run root cause",
            "canonical_finding_id": "f_1",
            "member_finding_ids": ["f_1"],
        },
    )
    db.add_dedupe_group(
        second,
        {
            "group_id": "g_1",
            "root_cause": "second run root cause",
            "canonical_finding_id": "f_1",
            "member_finding_ids": ["f_1"],
        },
    )
    db.assign_finding_group(first, "f_1", "g_1", True)
    db.assign_finding_group(second, "f_1", "g_1", True)
    db.add_trace(
        first,
        "f_1",
        {"finding_id": "f_1", "reachable": True, "rationale": "reachable"},
    )
    db.add_trace(
        second,
        "f_1",
        {"finding_id": "f_1", "reachable": False, "rationale": "blocked"},
    )

    assert db.get_findings(first)[0].validation_status == "confirmed"
    assert db.get_findings(second)[0].validation_status == "rejected"
    assert db.get_trace(first, "f_1")["reachable"] is True
    assert db.get_trace(second, "f_1")["reachable"] is False


def test_legacy_schema_is_migrated_without_losing_rows(tmp_path: Path) -> None:
    path = tmp_path / "state.db"
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE runs (
            run_id TEXT PRIMARY KEY,
            repo_path TEXT NOT NULL,
            started_at REAL NOT NULL,
            finished_at REAL,
            status TEXT NOT NULL DEFAULT 'running'
        );
        CREATE TABLE tasks (
            task_id TEXT PRIMARY KEY,
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
            updated_at REAL NOT NULL
        );
        CREATE TABLE findings (
            finding_id TEXT PRIMARY KEY,
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
            is_canonical INTEGER DEFAULT 0
        );
        CREATE TABLE traces (
            finding_id TEXT PRIMARY KEY,
            reachable INTEGER NOT NULL,
            confidence REAL,
            rationale TEXT,
            raw_json TEXT NOT NULL
        );
        CREATE TABLE dedupe_groups (
            group_id TEXT PRIMARY KEY,
            run_id TEXT NOT NULL,
            root_cause TEXT NOT NULL,
            canonical_finding_id TEXT NOT NULL,
            raw_json TEXT NOT NULL
        );
        """
    )
    task = _task()
    finding = _finding()
    conn.execute(
        "INSERT INTO runs VALUES (?, ?, ?, ?, ?)",
        ("legacy", "/legacy", 1.0, 2.0, "completed"),
    )
    conn.execute(
        "INSERT INTO tasks VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            "t_1",
            "legacy",
            "recon",
            "sqli",
            task["scope_hint"],
            '["a.py"]',
            task["rationale"],
            1,
            "done",
            __import__("json").dumps(task),
            1.0,
            2.0,
        ),
    )
    conn.execute(
        "INSERT INTO findings VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            "f_1",
            "t_1",
            "legacy",
            "a.py",
            1,
            2,
            "sqli",
            "high",
            finding["description"],
            finding["evidence_snippet"],
            0,
            0.9,
            __import__("json").dumps(finding),
            "confirmed",
            '{"finding_id":"f_1","verdict":"confirmed"}',
            "g_1",
            1,
        ),
    )
    conn.execute(
        "INSERT INTO traces VALUES (?, ?, ?, ?, ?)",
        ("f_1", 1, 0.9, "reachable", '{"finding_id":"f_1","reachable":true}'),
    )
    conn.execute(
        "INSERT INTO dedupe_groups VALUES (?, ?, ?, ?, ?)",
        (
            "g_1",
            "legacy",
            "legacy root cause",
            "f_1",
            '{"group_id":"g_1","member_finding_ids":["f_1"]}',
        ),
    )
    conn.commit()
    conn.close()

    db = StateDB(path)

    assert db.schema_version() == 3
    assert db.get_all_tasks("legacy")[0].task_id == "t_1"
    assert db.get_findings("legacy")[0].finding_id == "f_1"
    assert db.get_trace("legacy", "f_1")["reachable"] is True
    assert (tmp_path / "state.db.v1.bak").is_file()


def test_completion_gaps_require_terminal_work_for_every_input(tmp_path: Path) -> None:
    db = StateDB(tmp_path / "state.db")
    run_id = db.create_run("/repo", "run")
    db.add_task(run_id, _task())

    assert db.completion_gaps(run_id) == ["task t_1 is pending"]

    db.update_task_status(run_id, "t_1", "done")
    db.add_finding(run_id, "t_1", _finding())
    assert db.completion_gaps(run_id) == ["finding f_1 is not validated"]

    db.set_finding_validation(
        run_id,
        "f_1",
        "confirmed",
        {"finding_id": "f_1", "verdict": "confirmed"},
    )
    assert db.completion_gaps(run_id) == ["confirmed finding f_1 is not grouped"]

    db.add_dedupe_group(
        run_id,
        {
            "group_id": "g_1",
            "root_cause": "untrusted input reaches a database query",
            "canonical_finding_id": "f_1",
            "member_finding_ids": ["f_1"],
        },
    )
    db.assign_finding_group(run_id, "f_1", "g_1", True)
    assert db.completion_gaps(run_id) == [
        "canonical finding f_1 has no terminal trace"
    ]

    db.add_trace(
        run_id,
        "f_1",
        {
            "finding_id": "f_1",
            "status": "uncertain",
            "reachable": None,
            "rationale": "tracer output was truncated",
        },
    )
    assert db.completion_gaps(run_id) == []


def test_run_and_task_lifecycle(tmp_path: Path) -> None:
    db = StateDB(tmp_path / "state.db")
    rid = db.create_run("/some/repo", "test_run")
    assert db.get_run(rid)["status"] == "running"

    db.add_task(rid, {
        "task_id": "t_1",
        "attack_class": "sqli",
        "scope_hint": "lookup name parameter",
        "target_files": ["app.py"],
        "rationale": "raw string formatting",
        "priority": 1,
        "source": "recon",
    })
    pending = db.get_pending_tasks(rid)
    assert len(pending) == 1
    assert pending[0].task_id == "t_1"

    db.update_task_status(rid, "t_1", "done")
    assert db.get_pending_tasks(rid) == []
    assert any(t.status == "done" for t in db.get_all_tasks(rid))

    db.finish_run(rid)
    assert db.get_run(rid)["status"] == "completed"
    db.close()


def test_reset_incomplete_tasks(tmp_path: Path) -> None:
    db = StateDB(tmp_path / "state.db")
    rid = db.create_run("/some/repo", "test_run")
    for tid, status in [("t_done", "done"), ("t_run", "running"),
                        ("t_fail", "failed"), ("t_pend", "pending")]:
        db.add_task(rid, {
            "task_id": tid, "attack_class": "sqli", "scope_hint": "x",
            "target_files": ["a.py"], "rationale": "r", "priority": 1,
            "source": "recon",
        })
        db.update_task_status(rid, tid, status)

    n = db.reset_incomplete_tasks(rid)
    assert n == 2  # only running + failed are re-queued
    by_status = {t.task_id: t.status for t in db.get_all_tasks(rid)}
    assert by_status == {
        "t_done": "done", "t_run": "pending",
        "t_fail": "pending", "t_pend": "pending",
    }
    assert {t.task_id for t in db.get_pending_tasks(rid)} == {"t_run", "t_fail", "t_pend"}
    db.close()


def test_finding_validation_and_dedupe(tmp_path: Path) -> None:
    db = StateDB(tmp_path / "state.db")
    rid = db.create_run("/some/repo", "test_run")
    db.add_task(rid, {
        "task_id": "t_1", "attack_class": "sqli", "scope_hint": "x",
        "target_files": ["a.py"], "rationale": "r", "priority": 1, "source": "recon",
    })
    db.add_finding(rid, "t_1", {
        "finding_id": "f_1", "file": "a.py", "line_start": 1, "line_end": 2,
        "vuln_class": "sqli", "severity": "high",
        "description": "x", "evidence_snippet": "y", "confidence": 0.9,
    })
    assert len(db.get_unvalidated_findings(rid)) == 1

    db.set_finding_validation(rid, "f_1", "confirmed", {
        "finding_id": "f_1", "verdict": "confirmed",
        "rationale": "ok", "validator_confidence": 0.9,
    })
    assert len(db.get_findings(rid, validation_status="confirmed")) == 1

    db.add_dedupe_group(rid, {
        "group_id": "g_1", "root_cause": "rc",
        "canonical_finding_id": "f_1", "member_finding_ids": ["f_1"],
    })
    db.assign_finding_group(rid, "f_1", "g_1", True)
    assert len(db.get_findings(rid, canonical_only=True)) == 1

    db.add_trace(rid, "f_1", {
        "finding_id": "f_1", "reachable": True, "confidence": 0.9,
        "rationale": "trivial", "entry_points": [], "call_chain": [],
    })
    reachable = db.get_reachable_canonical_findings(rid)
    assert len(reachable) == 1
    db.close()


def test_cost_aggregation(tmp_path: Path) -> None:
    db = StateDB(tmp_path / "state.db")
    rid = db.create_run("/r", "test_run")
    db.record_cost(rid, "hunt", "t_1", {"total_cost_usd": 0.01, "usage": {
        "input_tokens": 100, "output_tokens": 50,
    }, "num_turns": 3, "duration_ms": 1234})
    db.record_cost(rid, "hunt", "t_2", {"total_cost_usd": 0.02, "usage": {
        "input_tokens": 200, "output_tokens": 100,
    }, "num_turns": 5, "duration_ms": 4321})
    assert abs(db.total_cost(rid) - 0.03) < 1e-9
    db.close()


def test_agent_result_usage_is_persisted_without_backend_reinterpretation(
    tmp_path: Path,
) -> None:
    db = StateDB(tmp_path / "state.db")
    rid = db.create_run("/r", "test_run")
    result = SimpleNamespace(
        cost_usd=0.0,
        input_tokens=123,
        output_tokens=45,
        cache_read_tokens=67,
        cache_creation_tokens=None,
        num_turns=3,
        duration_ms=890,
    )

    db.record_agent_result(rid, "hunt", "t_1", result)

    assert db.stage_usage(rid, "hunt") == {
        "input_tokens": 123,
        "output_tokens": 45,
        "cache_read_tokens": 67,
        "cache_creation_tokens": 0,
        "num_turns": 3,
        "duration_ms": 890,
    }


def _write_repo_file(repo: Path, name: str, lines: list[str]) -> None:
    path = repo / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n")


def test_add_finding_autopopulates_discovery_fingerprint(tmp_path: Path) -> None:
    from codesec.fingerprint import finding_fp, window_hash

    repo = tmp_path / "repo"
    repo.mkdir()
    _write_repo_file(repo, "a.py", [f"line {i}" for i in range(1, 41)])

    db = StateDB(tmp_path / "state.db")
    run_id = db.create_run(str(repo), "run")
    db.add_task(run_id, _task())
    db.add_finding(run_id, "t_1", _finding())  # cites a.py lines 1-2

    got = db.get_findings(run_id)[0]
    expected = finding_fp(
        "sqli", "a.py", window_hash(repo, "a.py", 1, 2)
    )
    assert got.discovery_fp == expected
    # Not a git repo → mtime fallback (int string), never None.
    assert got.discovery_ref is not None
    assert got.discovery_ref == str(int((repo / "a.py").stat().st_mtime))


def test_add_finding_missing_file_leaves_null_and_does_not_crash(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()  # a.py deliberately absent

    db = StateDB(tmp_path / "state.db")
    run_id = db.create_run(str(repo), "run")
    db.add_task(run_id, _task())
    db.add_finding(run_id, "t_1", _finding())

    got = db.get_findings(run_id)[0]
    assert got.finding_id == "f_1"
    assert got.discovery_fp is None
    assert got.discovery_ref is None


def test_add_finding_explicit_fingerprint_is_preserved(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_repo_file(repo, "a.py", ["x", "y"])

    db = StateDB(tmp_path / "state.db")
    run_id = db.create_run(str(repo), "run")
    db.add_task(run_id, _task())
    finding = _finding()
    finding["discovery_fp"] = "explicit-fp"
    db.add_finding(run_id, "t_1", finding)

    got = db.get_findings(run_id)[0]
    assert got.discovery_fp == "explicit-fp"
    # ref still auto-populated
    assert got.discovery_ref is not None
