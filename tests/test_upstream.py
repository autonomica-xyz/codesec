"""W15 upstream novelty check — unit tests against a real tmp git repo."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from codesec import upstream
from codesec.config import HarnessConfig
from codesec.state import StateDB
from codesec.stages import report as report_stage
from codesec.stages._common import StageContext


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        env={
            "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
            "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t",
            "PATH": "/usr/bin:/bin:/usr/local/bin",
        },
    )


def _init_repo(path: Path) -> Path:
    path.mkdir(parents=True)
    _git(path, "init", "-q")
    return path


def test_ensure_checkout_uses_local_path(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path / "up")
    assert upstream.ensure_checkout(repo, tmp_path / "cache") == repo


def test_classify_unfixed_when_pattern_present(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path / "up")
    (repo / "app.py").write_text("execute('SELECT ' + q)\n")
    _git(repo, "add", "app.py")
    _git(repo, "commit", "-qm", "add app")

    history = upstream.file_history(repo, "app.py")
    assert history and "add app" in history[0]
    status = upstream.classify(repo, "app.py", "execute('SELECT ' + q)", history)
    assert status == "unfixed"


def test_classify_fixed_when_pattern_gone_and_fix_commit(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path / "up")
    (repo / "app.py").write_text("execute('SELECT ' + q)\n")
    _git(repo, "add", "app.py")
    _git(repo, "commit", "-qm", "add app")
    (repo / "app.py").write_text("execute('SELECT ?', (q,))\n")
    _git(repo, "commit", "-qam", "fix CVE-2024-1 sql injection in app")

    history = upstream.file_history(repo, "app.py")
    status = upstream.classify(repo, "app.py", "execute('SELECT ' + q)", history)
    assert status == "fixed"


def test_classify_unknown_without_fix_commit(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path / "up")
    (repo / "app.py").write_text("execute('SELECT ' + q)\n")
    _git(repo, "add", "app.py")
    _git(repo, "commit", "-qm", "add app")
    (repo / "app.py").write_text("execute('SELECT ?', (q,))\n")
    _git(repo, "commit", "-qam", "refactor query builder")

    history = upstream.file_history(repo, "app.py")
    status = upstream.classify(repo, "app.py", "execute('SELECT ' + q)", history)
    assert status == "unknown"


def test_classify_divergent_fork_pattern_never_present_is_unknown(
    tmp_path: Path,
) -> None:
    """Pattern absent + a fix-looking commit is not enough — the pattern
    must have existed upstream at some point, else a fork that never had
    it would be reported 'fixed' and dropped to the report footnote."""
    repo = _init_repo(tmp_path / "up")
    (repo / "app.py").write_text("execute('SELECT ?', (q,))\n")
    _git(repo, "add", "app.py")
    _git(repo, "commit", "-qm", "add app")
    (repo / "app.py").write_text("execute('SELECT ?', (q,))\nx = 1\n")
    _git(repo, "commit", "-qam", "fix CVE-2024-1 harden app")

    history = upstream.file_history(repo, "app.py")
    status = upstream.classify(
        repo, "app.py", "execute('SELECT ' + q)", history
    )
    assert status == "unknown"


def test_classify_missing_file_is_unknown(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path / "up")
    (repo / "app.py").write_text("pass\n")
    _git(repo, "add", "app.py")
    _git(repo, "commit", "-qm", "init")

    assert upstream.classify(repo, "gone.py", "x" * 20, []) == "unknown"


def test_ensure_checkout_bad_url_returns_none(tmp_path: Path) -> None:
    assert (
        upstream.ensure_checkout(
            "https://nonexistent.invalid/repo.git", tmp_path / "cache"
        )
        is None
    )


async def test_deterministic_report_moves_fixed_upstream_to_footnote(
    tmp_path: Path,
) -> None:
    up = _init_repo(tmp_path / "upstream_repo")
    (up / "app.py").write_text("execute('SELECT ' + q)\n")
    _git(up, "add", "app.py")
    _git(up, "commit", "-qm", "add app")
    (up / "app.py").write_text("execute('SELECT ?', (q,))\n")
    _git(up, "commit", "-qam", "fix security: parameterize query in app")

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("execute('SELECT ' + q)\n")
    db = StateDB(tmp_path / "state.db")
    db.create_run(str(repo), "run")
    db.add_task(
        "run",
        {
            "task_id": "t_1",
            "attack_class": "sqli",
            "scope_hint": "query",
            "target_files": ["app.py"],
            "rationale": "input reaches query",
            "priority": 1,
            "source": "recon",
        },
    )
    for fid, evidence in (
        ("f_fixed", "execute('SELECT ' + q)"),
        ("f_live", "nonexistent_sink(still_there)"),
    ):
        db.add_finding(
            "run",
            "t_1",
            {
                "finding_id": fid,
                "file": "app.py",
                "line_start": 1,
                "line_end": 1,
                "vuln_class": "sql_injection",
                "severity": "high",
                "description": "Untrusted input reaches the query executor.",
                "evidence_snippet": evidence,
                "confidence": 0.9,
            },
        )
        db.set_finding_validation(
            "run", fid, "confirmed",
            {"finding_id": fid, "verdict": "confirmed"},
        )
        gid = f"g_{fid[2:]}"
        db.add_dedupe_group(
            "run",
            {
                "group_id": gid,
                "root_cause": "untrusted input reaches SQL execution",
                "canonical_finding_id": fid,
                "member_finding_ids": [fid],
            },
        )
        db.assign_finding_group("run", fid, gid, True)
        db.add_trace(
            "run",
            fid,
            {
                "finding_id": fid,
                "reachable": True,
                "confidence": 0.9,
                "rationale": "HTTP input reaches the query executor.",
                "entry_points": [{"kind": "http_route", "location": "app.py:1"}],
                "external_inputs": ["q"],
                "call_chain": [
                    {"file": "app.py", "function": "route", "line": 1},
                    {"file": "app.py", "function": "execute", "line": 1},
                ],
            },
        )
    # f_live's evidence is NOT in the upstream file and there IS a fix
    # commit -> also 'fixed'. Give it evidence that survives upstream.
    (up / "app.py").write_text(
        "execute('SELECT ?', (q,))\nnonexistent_sink(still_there)\n"
    )
    _git(up, "commit", "-qam", "add second sink")
    ctx = StageContext(
        run_id="run",
        repo_path=repo,
        config=HarnessConfig(),
        upstream=str(up),
        run_results_root=tmp_path / "results",
        run_work_root=tmp_path / "work",
    )

    report_path = await report_stage.run_deterministic_report(ctx, db)
    report = json.loads(report_path.read_text())

    main_ids = [e["finding_id"] for e in report["findings"]]
    assert main_ids == ["f_live"]
    assert report["findings"][0]["upstream_status"] == "unfixed"
    assert report["fixed_upstream"][0]["finding_id"] == "f_fixed"
    assert report["summary"]["total"] == 1
    from codesec.json_utils import validate_schema
    assert validate_schema(report, ctx.schema("report")) == []
