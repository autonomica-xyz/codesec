"""Cross-run catalogue carry rules + upsert behavior (W8)."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from codesec.catalogue import (
    EXCLUSION_REASON,
    needs_info_entries,
    prepare_priors,
    record_run,
    refuted_entries,
)
from codesec.fingerprint import finding_fp, window_hash
from codesec.state import StateDB


def _write(repo: Path, name: str, lines: list[str]) -> None:
    path = repo / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n")


def _task(task_id: str = "t_1") -> dict:
    return {
        "task_id": task_id,
        "attack_class": "sqli",
        "scope_hint": "query construction",
        "target_files": ["app.py"],
        "rationale": "input reaches query",
        "priority": 1,
        "source": "recon",
    }


def _finding(fid: str, file: str = "app.py", ls: int = 40, le: int = 42,
             vuln: str = "sqli", desc: str = "unsafe query") -> dict:
    return {
        "finding_id": fid, "file": file, "line_start": ls, "line_end": le,
        "vuln_class": vuln, "severity": "high", "description": desc,
        "evidence_snippet": "execute(q)", "confidence": 0.9,
    }


def _confirm(db: StateDB, run_id: str, fid: str, arbiter_sev=None) -> None:
    payload = {"finding_id": fid, "verdict": "confirmed",
               "rationale": "real"}
    if arbiter_sev:
        payload["arbiter_severity"] = arbiter_sev
    db.set_finding_validation(run_id, fid, "confirmed", payload)
    db.add_dedupe_group(run_id, {
        "group_id": f"g_{fid}", "root_cause": "rc",
        "canonical_finding_id": fid, "member_finding_ids": [fid],
    })
    db.assign_finding_group(run_id, fid, f"g_{fid}", True)


def _catalogue_rows(path: Path) -> list[sqlite3.Row]:
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute("SELECT * FROM catalogue").fetchall()
    finally:
        conn.close()


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    r = tmp_path / "repo"
    r.mkdir()
    _write(r, "app.py", [f"line {i}" for i in range(1, 81)])
    _write(r, "other.py", [f"other {i}" for i in range(1, 81)])
    return r


@pytest.fixture
def db(tmp_path: Path) -> StateDB:
    return StateDB(tmp_path / "state.db")


def test_record_run_upserts_verdicts(repo: Path, db: StateDB,
                                     tmp_path: Path) -> None:
    cat = tmp_path / "cat.db"
    db.create_run(str(repo), "run1")
    db.add_task("run1", _task())
    db.add_finding("run1", "t_1", _finding("f_ok"))
    db.add_finding("run1", "t_1", _finding("f_bad", ls=50, le=52,
                                          desc="nope"))
    db.add_finding("run1", "t_1", _finding("f_nmi", ls=60, le=62,
                                          desc="unclear"))
    db.add_finding("run1", "t_1", _finding("f_skip", ls=70, le=72,
                                          desc="unvalidated"))

    _confirm(db, "run1", "f_ok", arbiter_sev="medium")
    db.set_finding_validation("run1", "f_bad", "rejected",
                              {"finding_id": "f_bad", "verdict": "rejected",
                               "rationale": "param is bound"})
    db.add_dedupe_group("run1", {"group_id": "g_f_bad", "root_cause": "x",
                                 "canonical_finding_id": "f_bad",
                                 "member_finding_ids": ["f_bad"]})
    db.assign_finding_group("run1", "f_bad", "g_f_bad", True)
    db.set_finding_validation(
        "run1", "f_nmi", "needs_more_info",
        {"finding_id": "f_nmi", "verdict": "needs_more_info",
         "blockers": ["is the route authed?"]})
    db.add_dedupe_group("run1", {"group_id": "g_f_nmi", "root_cause": "y",
                                 "canonical_finding_id": "f_nmi",
                                 "member_finding_ids": ["f_nmi"]})
    db.assign_finding_group("run1", "f_nmi", "g_f_nmi", True)
    # f_skip stays unvalidated + non-canonical → skipped

    counts = record_run(db, "run1", repo, cat)

    assert counts == {"confirmed": 1, "refuted": 1, "needs_info": 1,
                      "skipped": 0}  # f_skip not canonical → not visited
    rows = {r["fp"]: r for r in _catalogue_rows(cat)}
    assert len(rows) == 3
    f_ok = db.get_findings("run1", canonical_only=True)
    ok_row = next(r for r in rows.values() if r["status"] == "confirmed")
    assert ok_row["fp"] == f_ok[0].discovery_fp
    assert ok_row["severity"] == "medium"  # arbiter wins
    assert ok_row["line_window"] == "40-42"
    assert ok_row["first_seen_run"] == "run1"
    assert ok_row["last_seen_run"] == "run1"
    rej = next(r for r in rows.values() if r["status"] == "refuted")
    assert json.loads(rej["payload_json"])["rationale"] == "param is bound"
    nmi = next(r for r in rows.values() if r["status"] == "needs_info")
    assert json.loads(nmi["payload_json"])["blockers"] == [
        "is the route authed?"]


def test_record_run_preserves_first_seen(repo: Path, db: StateDB,
                                         tmp_path: Path) -> None:
    cat = tmp_path / "cat.db"
    for run_id in ("run1", "run2"):
        db.create_run(str(repo), run_id)
        db.add_task(run_id, _task())
        db.add_finding(run_id, "t_1", _finding("f_ok"))
        _confirm(db, run_id, "f_ok")
        record_run(db, run_id, repo, cat)

    rows = _catalogue_rows(cat)
    assert len(rows) == 1
    assert rows[0]["first_seen_run"] == "run1"
    assert rows[0]["last_seen_run"] == "run2"


def test_prepare_priors_unchanged_becomes_exclusion(
    repo: Path, db: StateDB, tmp_path: Path
) -> None:
    cat = tmp_path / "cat.db"
    db.create_run(str(repo), "run1")
    db.add_task("run1", _task())
    db.add_finding("run1", "t_1", _finding("f_ok"))
    _confirm(db, "run1", "f_ok")
    record_run(db, "run1", repo, cat)

    db.create_run(str(repo), "run2")
    out = prepare_priors(db, "run2", repo, cat)

    assert out["carried"] == 1
    assert out["drifted"] == 0
    ex = out["exclusions"][0]
    assert ex["fp"] is not None
    assert ex["file"] == "app.py"
    assert ex["reason"] == EXCLUSION_REASON
    assert db.get_prior_exclusions("run2") == out["exclusions"]


def test_prepare_priors_drift_reattaches_as_revalidate_task(
    repo: Path, db: StateDB, tmp_path: Path
) -> None:
    cat = tmp_path / "cat.db"
    db.create_run(str(repo), "run1")
    db.add_task("run1", _task())
    db.add_finding("run1", "t_1", _finding("f_ok"))
    _confirm(db, "run1", "f_ok")
    record_run(db, "run1", repo, cat)

    # Shift the whole file down by 3 lines within the recenter band.
    lines = (repo / "app.py").read_text().splitlines()
    _write(repo, "app.py", lines[:5] + ["a", "b", "c"] + lines[5:])

    db.create_run(str(repo), "run2")
    out = prepare_priors(db, "run2", repo, cat)

    assert out["revalidate_tasks"] and out["carried"] == 0
    task = out["revalidate_tasks"][0]
    assert task["source"] == "catalogue"
    assert task["attack_class"] == "sqli"
    assert task["target_files"] == ["app.py"]
    assert task["priority"] == 2
    assert task["task_id"].startswith("t_prior_")
    # catalogue line_window updated to the re-centered range
    assert _catalogue_rows(cat)[0]["line_window"] == "43-45"


def test_prepare_priors_unmatchable_counts_drifted(
    repo: Path, db: StateDB, tmp_path: Path
) -> None:
    cat = tmp_path / "cat.db"
    db.create_run(str(repo), "run1")
    db.add_task("run1", _task())
    # 10 anchored + 1 that will be unmatchable (1/11 < 15%)
    db.add_finding("run1", "t_1", _finding("f_gone"))
    for i in range(10):
        db.add_finding("run1", "t_1",
                       _finding(f"f_{i}", file="other.py",
                                ls=10 + i, le=10 + i))
        _confirm(db, "run1", f"f_{i}")
    _confirm(db, "run1", "f_gone")
    record_run(db, "run1", repo, cat)

    # Rewrite app.py so the f_gone window can't be re-anchored.
    _write(repo, "app.py", [f"rewritten {i}" for i in range(1, 81)])

    db.create_run(str(repo), "run2")
    out = prepare_priors(db, "run2", repo, cat)

    assert out["drifted"] == 1
    assert out["carried"] == 10  # only the still-anchored ones
    assert all(e["file"] == "other.py" for e in out["exclusions"])


def test_prepare_priors_drift_fallback_over_threshold(
    repo: Path, db: StateDB, tmp_path: Path
) -> None:
    cat = tmp_path / "cat.db"
    db.create_run(str(repo), "run1")
    db.add_task("run1", _task())
    db.add_finding("run1", "t_1", _finding("f_gone"))
    db.add_finding("run1", "t_1", _finding("f_kept", file="other.py",
                                           ls=10, le=11))
    _confirm(db, "run1", "f_gone")
    _confirm(db, "run1", "f_kept")
    record_run(db, "run1", repo, cat)

    _write(repo, "app.py", [f"rewritten {i}" for i in range(1, 81)])

    db.create_run(str(repo), "run2")
    out = prepare_priors(db, "run2", repo, cat)

    # 1/2 drifted > 15% → the unmatchable one falls back to
    # file+vuln_class-only carry (no fp).
    assert out["drifted"] == 1
    assert out["carried"] == 2
    fallback = next(e for e in out["exclusions"] if e["file"] == "app.py")
    assert fallback["fp"] is None
    assert fallback["vuln_class"] == "sqli"


def test_prepare_priors_refuted_and_needs_info(
    repo: Path, db: StateDB, tmp_path: Path
) -> None:
    cat = tmp_path / "cat.db"
    db.create_run(str(repo), "run1")
    db.add_task("run1", _task())
    db.add_finding("run1", "t_1", _finding("f_bad"))
    db.set_finding_validation("run1", "f_bad", "rejected",
                              {"finding_id": "f_bad", "verdict": "rejected",
                               "rationale": "param is bound"})
    db.add_dedupe_group("run1", {"group_id": "g_f_bad", "root_cause": "x",
                                 "canonical_finding_id": "f_bad",
                                 "member_finding_ids": ["f_bad"]})
    db.assign_finding_group("run1", "f_bad", "g_f_bad", True)
    db.add_finding("run1", "t_1", _finding("f_nmi", file="other.py"))
    db.set_finding_validation(
        "run1", "f_nmi", "needs_more_info",
        {"finding_id": "f_nmi", "verdict": "needs_more_info",
         "blockers": ["needs creds"]})
    db.add_dedupe_group("run1", {"group_id": "g_f_nmi", "root_cause": "y",
                                 "canonical_finding_id": "f_nmi",
                                 "member_finding_ids": ["f_nmi"]})
    db.assign_finding_group("run1", "f_nmi", "g_f_nmi", True)
    record_run(db, "run1", repo, cat)

    db.create_run(str(repo), "run2")
    out = prepare_priors(db, "run2", repo, cat)

    assert out["refuted"] == [
        {"vuln_class": "sqli", "file": "app.py",
         "rejected_because": "param is bound"}
    ]
    assert refuted_entries(cat) == out["refuted"]
    seeds = needs_info_entries(cat)
    assert seeds[0]["blockers"] == ["needs creds"]


def test_prepare_priors_missing_catalogue(db: StateDB, tmp_path: Path,
                                          repo: Path) -> None:
    db.create_run(str(repo), "run1")
    out = prepare_priors(db, "run1", repo, tmp_path / "nope.db")
    assert out == {"exclusions": [], "revalidate_tasks": [], "refuted": [],
                   "drifted": 0, "carried": 0}
    assert db.get_prior_exclusions("run1") == []


def test_record_run_missing_file_uses_static_fp(
    repo: Path, db: StateDB, tmp_path: Path
) -> None:
    cat = tmp_path / "cat.db"
    db.create_run(str(repo), "run1")
    db.add_task("run1", _task())
    (repo / "app.py").unlink()  # file gone at discovery → no stored fp
    db.add_finding("run1", "t_1", _finding("f_ok"))
    _confirm(db, "run1", "f_ok")

    counts = record_run(db, "run1", repo, cat)

    assert counts["confirmed"] == 1
    row = _catalogue_rows(cat)[0]
    expected = finding_fp("sqli", "app.py", "static:unsafe query")
    assert row["fp"] == expected
    assert json.loads(row["payload_json"])["window_hash"] is None
