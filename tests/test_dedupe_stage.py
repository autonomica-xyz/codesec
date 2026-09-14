from pathlib import Path

from codesec.config import HarnessConfig, StageConfig
from codesec.runner import AgentResult
from codesec.state import StateDB
from codesec.stages import dedupe as dedupe_stage
from codesec.stages.dedupe import run_deterministic_dedupe, run_dedupe
from codesec.stages._common import StageContext


def _dedupe_context(repo: Path) -> StageContext:
    return StageContext(
        run_id="run",
        repo_path=repo,
        config=HarnessConfig(
            stages={
                "dedupe": StageConfig(
                    name="dedupe",
                    model="reviewer",
                    concurrency=1,
                    tools=["Read"],
                    max_turns=2,
                    permission_mode="acceptEdits",
                    repair_attempts=0,
                )
            }
        ),
    )


def _seed_confirmed(db: StateDB, finding: dict) -> None:
    db.add_finding("run", "t_1", finding)
    db.set_finding_validation(
        "run",
        finding["finding_id"],
        "confirmed",
        {"finding_id": finding["finding_id"], "verdict": "confirmed"},
    )


async def test_deterministic_dedupe_only_compacts_exact_candidates(
    tmp_path: Path,
) -> None:
    db = StateDB(tmp_path / "state.db")
    db.create_run(str(tmp_path), "run")
    db.add_task(
        "run",
        {
            "task_id": "t_1",
            "attack_class": "sqli",
            "scope_hint": "query sink",
            "target_files": ["app.py"],
            "rationale": "request input reaches query",
            "priority": 1,
            "source": "recon",
        },
    )
    base = {
        "file": "app.py",
        "line_start": 10,
        "line_end": 11,
        "vuln_class": "sql_injection",
        "severity": "high",
        "description": "Request input is interpolated into the SQL query.",
        "evidence_snippet": "cursor.execute('SELECT ' + value)",
        "confidence": 0.9,
    }
    for finding in (
        {"finding_id": "f_a", **base},
        {"finding_id": "f_b", **base},
        {
            "finding_id": "f_c",
            **base,
            "vuln_class": "command_injection",
        },
    ):
        db.add_finding("run", "t_1", finding)
        db.set_finding_validation(
            "run",
            finding["finding_id"],
            "confirmed",
            {
                "finding_id": finding["finding_id"],
                "verdict": "confirmed",
            },
        )
    ctx = StageContext(
        run_id="run",
        repo_path=tmp_path,
        config=HarnessConfig(),
    )

    groups = await run_deterministic_dedupe(ctx, db)

    findings = {f.finding_id: f for f in db.get_findings("run")}
    assert groups == 2
    assert findings["f_a"].group_id == findings["f_b"].group_id
    assert findings["f_c"].group_id != findings["f_a"].group_id
    assert findings["f_a"].is_canonical is True
    assert findings["f_b"].is_canonical is False
    assert findings["f_c"].is_canonical is True


async def test_llm_dedupe_preclusters_and_applies_canonical_swap(
    tmp_path: Path, monkeypatch
) -> None:
    db = StateDB(tmp_path / "state.db")
    db.create_run(str(tmp_path), "run")
    db.add_task(
        "run",
        {
            "task_id": "t_1",
            "attack_class": "sqli",
            "scope_hint": "query sink",
            "target_files": ["app.py"],
            "rationale": "request input reaches query",
            "priority": 1,
            "source": "recon",
        },
    )
    base = {
        "file": "app.py",
        "line_end": 12,
        "vuln_class": "sql_injection",
        "severity": "high",
        "description": "Request input is interpolated into the SQL query.",
        "evidence_snippet": "cursor.execute('SELECT ' + value)",
        "confidence": 0.9,
    }
    # f_a/f_b: same (file, vuln_class), |line delta| = 5 -> precluster.
    # f_c: different vuln_class -> singleton. f_d: 40 lines away -> singleton.
    for finding in (
        {"finding_id": "f_a", "line_start": 10, **base},
        {"finding_id": "f_b", "line_start": 15, **base,
         "evidence_snippet": "cursor.execute('SELECT ' + value)  -- reached via /import"},
        {"finding_id": "f_c", "line_start": 12, **base,
         "vuln_class": "command_injection"},
        {"finding_id": "f_d", "line_start": 60, **base},
    ):
        _seed_confirmed(db, finding)

    captured: dict = {}

    async def fake_agent(**kwargs):
        captured["user_input"] = kwargs["user_input"]
        return AgentResult(
            payload={
                "groups": [
                    {
                        "group_id": "g_ab",
                        "root_cause": "untrusted input concatenated into SQL query in app.py",
                        "member_finding_ids": ["f_a", "f_b"],
                        "canonical_finding_id": "f_a",
                        "replace_canonical_with": "f_b",
                        "replacement_reason": "f_b carries the fuller PoC trace",
                    },
                    {
                        "group_id": "g_c",
                        "root_cause": "untrusted input reaches os.system in app.py",
                        "member_finding_ids": ["f_c"],
                        "canonical_finding_id": "f_c",
                    },
                    {
                        "group_id": "g_d",
                        "root_cause": "second injection site lower in app.py",
                        "member_finding_ids": ["f_d"],
                        "canonical_finding_id": "f_d",
                    },
                ]
            },
            cost_usd=None,
            input_tokens=None,
            output_tokens=None,
            cache_read_tokens=None,
            cache_creation_tokens=None,
            num_turns=1,
            duration_ms=None,
            session_id=None,
            artifact_path=tmp_path / "dedupe.jsonl",
            repair_used=False,
        )

    monkeypatch.setattr(dedupe_stage, "run_agent", fake_agent)

    groups = await run_dedupe(_dedupe_context(tmp_path), db)

    assert groups == 3
    # Deterministic pre-pass grouped exactly the near-line same-class pair.
    pre = captured["user_input"]["preclustered_groups"]
    assert pre == [
        {
            "member_finding_ids": ["f_a", "f_b"],
            "file": "app.py",
            "vuln_class": "sql_injection",
            "line_start_min": 10,
            "line_start_max": 15,
        }
    ]
    # Canonical swap was applied and audited.
    findings = {f.finding_id: f for f in db.get_findings("run")}
    assert findings["f_a"].is_canonical is False
    assert findings["f_b"].is_canonical is True
    row = db._conn.execute(
        "SELECT canonical_finding_id, canonical_override FROM dedupe_groups "
        "WHERE run_id = 'run' AND group_id = 'g_ab'"
    ).fetchone()
    assert row["canonical_finding_id"] == "f_b"
    import json as _json
    audit = _json.loads(row["canonical_override"])
    assert audit[0]["from"] == "f_a"
    assert audit[0]["to"] == "f_b"
    assert audit[0]["reason"] == "f_b carries the fuller PoC trace"


async def test_llm_dedupe_ignores_nonmember_replacement(
    tmp_path: Path, monkeypatch
) -> None:
    db = StateDB(tmp_path / "state.db")
    db.create_run(str(tmp_path), "run")
    db.add_task(
        "run",
        {
            "task_id": "t_1",
            "attack_class": "sqli",
            "scope_hint": "query sink",
            "target_files": ["app.py"],
            "rationale": "request input reaches query",
            "priority": 1,
            "source": "recon",
        },
    )
    base = {
        "file": "app.py",
        "line_end": 12,
        "vuln_class": "sql_injection",
        "severity": "high",
        "description": "Request input is interpolated into the SQL query.",
        "evidence_snippet": "cursor.execute('SELECT ' + value)",
    }
    for fid, line in (("f_a", 10), ("f_b", 14)):
        _seed_confirmed(db, {"finding_id": fid, "line_start": line, **base})

    async def fake_agent(**kwargs):
        return AgentResult(
            payload={
                "groups": [
                    {
                        "group_id": "g_ab",
                        "root_cause": "untrusted input concatenated into SQL query in app.py",
                        "member_finding_ids": ["f_a", "f_b"],
                        "canonical_finding_id": "f_a",
                        "replace_canonical_with": "f_zzz",
                    }
                ]
            },
            cost_usd=None,
            input_tokens=None,
            output_tokens=None,
            cache_read_tokens=None,
            cache_creation_tokens=None,
            num_turns=1,
            duration_ms=None,
            session_id=None,
            artifact_path=tmp_path / "dedupe.jsonl",
            repair_used=False,
        )

    monkeypatch.setattr(dedupe_stage, "run_agent", fake_agent)

    groups = await run_dedupe(_dedupe_context(tmp_path), db)

    findings = {f.finding_id: f for f in db.get_findings("run")}
    assert groups == 1
    assert findings["f_a"].is_canonical is True
    assert findings["f_b"].is_canonical is False


async def test_deterministic_dedupe_prefers_poc_member_without_swap(
    tmp_path: Path,
) -> None:
    # Members of one exact-fingerprint bucket share normalized evidence and
    # description, so best-evidence can only deviate from the prior pick on
    # poc_succeeded — which the prior rule already ranks first. Assert the
    # PoC member wins canonical and no spurious audit entry is written.
    db = StateDB(tmp_path / "state.db")
    db.create_run(str(tmp_path), "run")
    db.add_task(
        "run",
        {
            "task_id": "t_1",
            "attack_class": "sqli",
            "scope_hint": "query sink",
            "target_files": ["app.py"],
            "rationale": "request input reaches query",
            "priority": 1,
            "source": "recon",
        },
    )
    base = {
        "file": "app.py",
        "line_start": 10,
        "line_end": 11,
        "vuln_class": "sql_injection",
        "severity": "high",
        "description": "Request input is interpolated into the SQL query.",
        "evidence_snippet": "cursor.execute('SELECT ' + value)",
    }
    _seed_confirmed(db, {"finding_id": "f_a", **base})
    _seed_confirmed(
        db,
        {
            "finding_id": "f_b",
            "poc": {"language": "python", "code": "print(1)", "succeeded": True},
            **base,
        },
    )
    ctx = StageContext(
        run_id="run", repo_path=tmp_path, config=HarnessConfig()
    )

    groups = await run_deterministic_dedupe(ctx, db)

    findings = {f.finding_id: f for f in db.get_findings("run")}
    assert groups == 1
    assert findings["f_b"].is_canonical is True
    row = db._conn.execute(
        "SELECT canonical_finding_id, canonical_override FROM dedupe_groups "
        "WHERE run_id = 'run'"
    ).fetchone()
    assert row["canonical_finding_id"] == "f_b"
    assert row["canonical_override"] is None
