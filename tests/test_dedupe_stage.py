from pathlib import Path

import pytest

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


# ---- P02: bounded payloads, batching, merge pass, partition contracts ----

import json as _json

from codesec.runner import AgentRunError, TransientAgentError
from codesec.stages.dedupe import (
    DedupeOversizeError,
    _DEDUPE_PAYLOAD_CAP,
    _build_batches,
    _finding_descriptor,
)


def _result(payload, tmp_path):
    return AgentResult(
        payload=payload,
        cost_usd=None, input_tokens=None, output_tokens=None,
        cache_read_tokens=None, cache_creation_tokens=None,
        num_turns=1, duration_ms=None, session_id=None,
        artifact_path=tmp_path / "x.jsonl", repair_used=False,
    )


def _seed_n_confirmed(db, n, *, evidence_chars=40_000):
    db.add_task("run", {
        "task_id": "t_1", "attack_class": "sqli", "scope_hint": "sink",
        "target_files": ["app.py"], "rationale": "input reaches sink",
        "priority": 1, "source": "recon",
    })
    for i in range(n):
        db.add_finding("run", "t_1", {
            "finding_id": f"f_{i:04d}",
            "file": f"src/mod_{i % 7}/app.py",
            "line_start": 10 + i,
            "line_end": 11 + i,
            "vuln_class": "sql_injection" if i % 2 else "xss",
            "severity": "high",
            "description": "User input reaches a dangerous sink unvalidated. " + "d" * 600,
            "evidence_snippet": "sink(input)  # " + "e" * evidence_chars,
            "confidence": 0.8,
        })
        db.set_finding_validation(
            "run", f"f_{i:04d}", "confirmed",
            {"finding_id": f"f_{i:04d}", "verdict": "confirmed",
             "rationale": "r" * 600},
        )


async def _run_dedupe_with_adjudicator(monkeypatch, tmp_path, adjudicate):
    """Run run_dedupe with a mocked adjudicator; returns (db, calls)."""
    db = StateDB(tmp_path / "state.db")
    db.create_run(str(tmp_path), "run")
    calls = []

    async def fake_agent(**kwargs):
        user_input = kwargs["user_input"]
        calls.append(user_input)
        ids = sorted(d["finding_id"] for d in user_input["confirmed_findings"])
        if user_input.get("merge_pass"):
            return _result({"groups": adjudicate.merge(ids, user_input)}, tmp_path)
        return _result({"groups": adjudicate.batch(ids, user_input)}, tmp_path)

    import codesec.stages.dedupe as ds
    monkeypatch.setattr(ds, "run_agent", fake_agent)
    await run_dedupe(_dedupe_context(tmp_path), db)
    return db, calls


class _SingletonAdjudicator:
    """Every finding stays its own group; never merges anything."""
    def batch(self, ids, user_input):
        return [
            {"group_id": f"g_{fid[2:]}", "root_cause": f"Singleton root cause for {fid} in file",
             "member_finding_ids": [fid], "canonical_finding_id": fid}
            for fid in ids
        ]

    merge = batch


async def test_dedupe_payload_bounds_1_60_200_findings(monkeypatch, tmp_path):
    """1/60/200 confirmed findings with huge evidence: no serialized
    request exceeds the 30k cap and every ID lands in exactly one group."""
    for n in (1, 60, 200):
        class _Adj(_SingletonAdjudicator):
            pass
        adj = _Adj()
        # reuse the same fake_agent machinery but seed n findings
        db = StateDB(tmp_path / f"state-{n}.db")
        db.create_run(str(tmp_path), "run")
        _seed_n_confirmed(db, n)
        calls = []

        async def fake_agent(**kwargs):
            calls.append(kwargs["user_input"])
            ids = sorted(d["finding_id"] for d in kwargs["user_input"]["confirmed_findings"])
            return _result({"groups": adj.batch(ids, kwargs["user_input"])}, tmp_path)

        import codesec.stages.dedupe as ds
        monkeypatch.setattr(ds, "run_agent", fake_agent)
        groups = await run_dedupe(_dedupe_context(tmp_path), db)

        assert groups == n
        assert calls, "adjudicator must have been called"
        for user_input in calls:
            serialized = _json.dumps(user_input, ensure_ascii=False)
            assert len(serialized) <= _DEDUPE_PAYLOAD_CAP, len(serialized)
        # every original finding in exactly one final group
        grouped = [
            fid for f in db.get_findings("run")
            for fid in [f.finding_id] if f.group_id
        ]
        assert sorted(grouped) == sorted(f.finding_id for f in db.get_findings("run"))
        members = []
        for g in db._conn.execute(
            "SELECT raw_json FROM dedupe_groups WHERE run_id='run'"
        ):
            members.extend(_json.loads(g["raw_json"])["member_finding_ids"])
        assert sorted(members) == sorted(f"f_{i:04d}" for i in range(n))
        assert len(members) == n  # no duplicates


async def test_merge_pass_adjudicates_duplicates_straddling_batches(
    monkeypatch, tmp_path
):
    """A partition split across batches: the merge pass must consider the
    straddling duplicate pair that no batch saw whole; unrelated groups
    stay distinct under the same adjudicator."""
    db = StateDB(tmp_path / "state.db")
    db.create_run(str(tmp_path), "run")
    db.add_task("run", {
        "task_id": "t_1", "attack_class": "sqli", "scope_hint": "sink",
        "target_files": ["app.py"], "rationale": "input reaches sink",
        "priority": 1, "source": "recon",
    })
    n = 45  # two payload-bounded batches; all reps fit one merge request
    for i in range(n):
        db.add_finding("run", "t_1", {
            "finding_id": f"f_{i:03d}", "file": "app.py",
            "line_start": 10 * i, "line_end": 10 * i + 1,
            "vuln_class": "sql_injection", "severity": "high",
            "description": "Root cause description " + "x" * 300,
            "evidence_snippet": "sink(input)" + "y" * 300,
        })
        db.set_finding_validation(
            "run", f"f_{i:03d}", "confirmed",
            {"finding_id": f"f_{i:03d}", "verdict": "confirmed"},
        )

    batch_membership: dict[str, int] = {}
    merge_inputs = []

    async def fake_agent(**kwargs):
        user_input = kwargs["user_input"]
        ids = sorted(d["finding_id"] for d in user_input["confirmed_findings"])
        if user_input.get("merge_pass"):
            merge_inputs.append(user_input)
            others = [fid for fid in ids if fid not in ("f_032", "f_033")]
            return _result({"groups": [
                {"group_id": "g_dup", "root_cause": "shared unsafe helper reached from route",
                 "member_finding_ids": ["f_032", "f_033"],
                 "canonical_finding_id": "f_032"},
                *[{"group_id": f"g_{fid[2:]}", "root_cause": f"Distinct root cause for {fid} in app.py",
                   "member_finding_ids": [fid], "canonical_finding_id": fid}
                  for fid in others],
            ]}, tmp_path)
        batch_id = user_input["batch_id"]
        for fid in ids:
            batch_membership[fid] = int(batch_id.split("-")[-1])
        return _result({"groups": [
            {"group_id": f"g_{fid[2:]}", "root_cause": f"Batch root cause for {fid} in app.py",
             "member_finding_ids": [fid], "canonical_finding_id": fid}
            for fid in ids
        ]}, tmp_path)

    import codesec.stages.dedupe as ds
    monkeypatch.setattr(ds, "run_agent", fake_agent)
    groups = await run_dedupe(_dedupe_context(tmp_path), db)

    assert len(set(batch_membership.values())) >= 2, "partition must span batches"
    # The merged pair straddles the batch boundary: neither batch saw both.
    assert batch_membership["f_032"] != batch_membership["f_033"]
    assert merge_inputs, "merge pass must run when a partition spans batches"
    assert len(merge_inputs) == 1
    rep_ids = sorted(d["finding_id"] for d in merge_inputs[0]["confirmed_findings"])
    assert rep_ids == [f"f_{i:03d}" for i in range(n)]
    assert groups == n - 1
    findings = {f.finding_id: f for f in db.get_findings("run")}
    assert findings["f_032"].group_id == findings["f_033"].group_id == "g_032"
    assert findings["f_032"].is_canonical and not findings["f_033"].is_canonical
    assert findings["f_000"].group_id != findings["f_001"].group_id
    assert findings["f_030"].group_id != findings["f_031"].group_id


async def test_batch_contract_violation_degrades_to_singletons(
    monkeypatch, tmp_path
):
    """Unknown/missing/duplicate membership in a batch response keeps
    deterministic singletons and records a degraded event — no silent success."""
    db = StateDB(tmp_path / "state.db")
    db.create_run(str(tmp_path), "run")
    db.add_task("run", {
        "task_id": "t_1", "attack_class": "sqli", "scope_hint": "sink",
        "target_files": ["app.py"], "rationale": "input reaches sink",
        "priority": 1, "source": "recon",
    })
    for i in range(3):
        db.add_finding("run", "t_1", {
            "finding_id": f"f_{i}", "file": "app.py", "line_start": 10 + i,
            "line_end": 11 + i, "vuln_class": "sql_injection", "severity": "high",
            "description": "Injected SQL through string concatenation into execute call",
            "evidence_snippet": "sink(input)",
        })
        db.set_finding_validation(
            "run", f"f_{i}", "confirmed",
            {"finding_id": f"f_{i}", "verdict": "confirmed"},
        )

    async def bad_agent(**kwargs):
        # f_1 dropped (missing), f_2 twice (duplicate), f_unknown invented.
        return _result({"groups": [
            {"group_id": "g_0", "root_cause": "first root cause for app.py injection",
             "member_finding_ids": ["f_0"], "canonical_finding_id": "f_0"},
            {"group_id": "g_2", "root_cause": "third root cause for app.py injection",
             "member_finding_ids": ["f_2", "f_2"], "canonical_finding_id": "f_2"},
            {"group_id": "g_9", "root_cause": "invented root cause not in the batch input",
             "member_finding_ids": ["f_unknown"], "canonical_finding_id": "f_unknown"},
        ]}, tmp_path)

    import codesec.stages.dedupe as ds
    monkeypatch.setattr(ds, "run_agent", bad_agent)
    groups = await run_dedupe(_dedupe_context(tmp_path), db)

    assert groups == 3  # deterministic singletons
    events = db.get_stage_events("run", "dedupe")
    degraded = [e for e in events if e["category"] == "degraded"]
    assert any(e["reason"] == "batch_contract_violation" for e in degraded)
    members = []
    for row in db._conn.execute(
        "SELECT raw_json FROM dedupe_groups WHERE run_id='run'"
    ):
        g = _json.loads(row["raw_json"])
        members.extend(g["member_finding_ids"])
        assert g["canonical_finding_id"] in g["member_finding_ids"]
    assert sorted(members) == ["f_0", "f_1", "f_2"]


async def test_batch_model_failure_degrades_with_event(monkeypatch, tmp_path):
    db = StateDB(tmp_path / "state.db")
    db.create_run(str(tmp_path), "run")
    _seed_n_confirmed(db, 3, evidence_chars=100)

    async def failing_agent(**kwargs):
        raise TransientAgentError("upstream 503: unavailable")

    import codesec.stages.dedupe as ds
    monkeypatch.setattr(ds, "run_agent", failing_agent)
    groups = await run_dedupe(_dedupe_context(tmp_path), db)

    assert groups == 3
    events = db.get_stage_events("run", "dedupe")
    assert any(
        e["category"] == "degraded" and e["reason"] == "batch_failed"
        for e in events
    )
    # singleton groups still assign every finding exactly once
    assert all(f.is_canonical for f in db.get_findings("run"))


async def test_malformed_merge_output_keeps_batch_groups(monkeypatch, tmp_path):
    db = StateDB(tmp_path / "state.db")
    db.create_run(str(tmp_path), "run")
    db.add_task("run", {
        "task_id": "t_1", "attack_class": "sqli", "scope_hint": "sink",
        "target_files": ["app.py"], "rationale": "input reaches sink",
        "priority": 1, "source": "recon",
    })
    n = 45
    for i in range(n):
        db.add_finding("run", "t_1", {
            "finding_id": f"f_{i:03d}", "file": "app.py",
            "line_start": 10 * i, "line_end": 10 * i + 1,
            "vuln_class": "sql_injection", "severity": "high",
            "description": "Root cause description " + "x" * 300,
            "evidence_snippet": "sink(input)" + "y" * 300,
        })
        db.set_finding_validation(
            "run", f"f_{i:03d}", "confirmed",
            {"finding_id": f"f_{i:03d}", "verdict": "confirmed"},
        )

    merge_seen = []

    async def fake_agent(**kwargs):
        user_input = kwargs["user_input"]
        ids = sorted(d["finding_id"] for d in user_input["confirmed_findings"])
        if user_input.get("merge_pass"):
            merge_seen.append(user_input)
            # malformed: representative ids missing from output
            return _result({"groups": [
                {"group_id": "g_bad", "root_cause": "merge dropped representative ids here",
                 "member_finding_ids": ids[:1], "canonical_finding_id": ids[0]},
            ]}, tmp_path)
        return _result({"groups": [
            {"group_id": f"g_{fid[2:]}", "root_cause": f"Batch root cause for {fid} in app.py",
             "member_finding_ids": [fid], "canonical_finding_id": fid}
            for fid in ids
        ]}, tmp_path)

    import codesec.stages.dedupe as ds
    monkeypatch.setattr(ds, "run_agent", fake_agent)
    groups = await run_dedupe(_dedupe_context(tmp_path), db)

    assert merge_seen, "merge pass must have been attempted"
    assert groups == n  # pre-merge batch groups kept
    events = db.get_stage_events("run", "dedupe")
    assert any(e["category"] == "degraded" and e["reason"] == "merge_failed"
               for e in events)


def test_build_batches_empty_input_and_oversize_descriptor(tmp_path):
    from codesec.state import StateDB as _SDB
    assert _build_batches([], [], {}) == []

    class FakeFinding:
        def __init__(self, fid, file):
            self.finding_id = fid
            self.task_id = "t_1"
            self.run_id = "run"
            self.file = file
            self.line_start = 1
            self.line_end = 2
            self.vuln_class = "sql_injection"
            self.severity = "high"
            self.description = "d"
            self.evidence = "e"
            self.poc_succeeded = False
            self.confidence = 0.5
            self.raw_json = {}
            self.validation_status = "confirmed"
            self.validation_json = {"verdict": "confirmed"}
            self.group_id = None
            self.is_canonical = True

    huge = FakeFinding("f_big", "app.py")
    huge.file = "x" * (_DEDUPE_PAYLOAD_CAP + 10)
    descriptor = _finding_descriptor(huge)
    with pytest.raises(DedupeOversizeError):
        _build_batches([descriptor], [], {})


async def test_cross_partition_groups_are_never_merged(monkeypatch, tmp_path):
    """Two partitions (different files); merge pass must never be asked to
    merge across them."""
    db = StateDB(tmp_path / "state.db")
    db.create_run(str(tmp_path), "run")
    db.add_task("run", {
        "task_id": "t_1", "attack_class": "sqli", "scope_hint": "sink",
        "target_files": ["app.py"], "rationale": "input reaches sink",
        "priority": 1, "source": "recon",
    })
    for i, file in enumerate(("a.py", "b.py")):
        for j in range(2):
            db.add_finding("run", "t_1", {
                "finding_id": f"f_{i}{j}", "file": file,
                "line_start": 10 * j, "line_end": 10 * j + 1,
                "vuln_class": "sql_injection", "severity": "high",
                "description": "Root cause description " + "x" * 5_000,
                "evidence_snippet": "sink(input)",
            })
            db.set_finding_validation(
                "run", f"f_{i}{j}", "confirmed",
                {"finding_id": f"f_{i}{j}", "verdict": "confirmed"},
            )

    merge_calls = []

    async def fake_agent(**kwargs):
        user_input = kwargs["user_input"]
        if user_input.get("merge_pass"):
            merge_calls.append(user_input)
            ids = sorted(d["finding_id"] for d in user_input["confirmed_findings"])
            return _result({"groups": [
                {"group_id": f"g_{fid}", "root_cause": f"Root cause for {fid} keeps files apart",
                 "member_finding_ids": [fid], "canonical_finding_id": fid}
                for fid in ids
            ]}, tmp_path)
        ids = sorted(d["finding_id"] for d in user_input["confirmed_findings"])
        return _result({"groups": [
            {"group_id": f"g_{fid}", "root_cause": f"Root cause for {fid} keeps files apart",
             "member_finding_ids": [fid], "canonical_finding_id": fid}
            for fid in ids
        ]}, tmp_path)

    import codesec.stages.dedupe as ds
    monkeypatch.setattr(ds, "run_agent", fake_agent)
    groups = await run_dedupe(_dedupe_context(tmp_path), db)

    assert groups == 4
    for merge_input in merge_calls:
        files = {d["file"] for d in merge_input["confirmed_findings"]}
        assert len(files) == 1  # merge is strictly within one partition


async def test_merge_skipped_when_representatives_exceed_cap(
    monkeypatch, tmp_path
):
    """A very large partition keeps its batch groups when even bounded
    representatives cannot fit one merge request — recorded, never an
    unbounded concatenation."""
    db = StateDB(tmp_path / "state.db")
    db.create_run(str(tmp_path), "run")
    db.add_task("run", {
        "task_id": "t_1", "attack_class": "sqli", "scope_hint": "sink",
        "target_files": ["app.py"], "rationale": "input reaches sink",
        "priority": 1, "source": "recon",
    })
    n = 200
    for i in range(n):
        db.add_finding("run", "t_1", {
            "finding_id": f"f_{i:03d}", "file": "app.py",
            "line_start": 10 * i, "line_end": 10 * i + 1,
            "vuln_class": "sql_injection", "severity": "high",
            "description": "Root cause description " + "x" * 300,
            "evidence_snippet": "sink(input)" + "y" * 300,
        })
        db.set_finding_validation(
            "run", f"f_{i:03d}", "confirmed",
            {"finding_id": f"f_{i:03d}", "verdict": "confirmed"},
        )

    merge_calls = []

    async def fake_agent(**kwargs):
        user_input = kwargs["user_input"]
        ids = sorted(d["finding_id"] for d in user_input["confirmed_findings"])
        if user_input.get("merge_pass"):
            merge_calls.append(user_input)
        return _result({"groups": [
            {"group_id": f"g_{fid[2:]}", "root_cause": f"Root cause for {fid} in app.py sink",
             "member_finding_ids": [fid], "canonical_finding_id": fid}
            for fid in ids
        ]}, tmp_path)

    import codesec.stages.dedupe as ds
    monkeypatch.setattr(ds, "run_agent", fake_agent)
    groups = await run_dedupe(_dedupe_context(tmp_path), db)

    assert groups == n  # all singleton batch groups kept
    assert not merge_calls  # oversize merge is never sent
    events = db.get_stage_events("run", "dedupe")
    assert any(
        e["category"] == "degraded" and e["reason"] == "merge_skipped_oversize"
        for e in events
    )


async def test_second_dedupe_pass_renumbers_colliding_group_ids(
    tmp_path, monkeypatch
):
    """Feedback loops run dedupe again: a model-reused group_id with a new
    payload must be deterministically renumbered, never a mid-run
    StateConflictError."""
    from codesec.state import StateConflictError

    db = StateDB(tmp_path / "state.db")
    db.create_run(str(tmp_path), "run")
    db.add_task("run", {
        "task_id": "t_1", "attack_class": "sqli", "scope_hint": "sink",
        "target_files": ["app.py"], "rationale": "r", "priority": 1,
        "source": "recon",
    })
    for fid in ("f_a", "f_b"):
        db.add_finding("run", "t_1", {
            "finding_id": fid, "file": "app.py", "line_start": 10,
            "line_end": 12, "vuln_class": "sql_injection", "severity": "high",
            "description": "Injection through string concatenation into execute",
            "evidence_snippet": "sink(input)",
        })
        db.set_finding_validation(
            "run", fid, "confirmed",
            {"finding_id": fid, "verdict": "confirmed"},
        )
    # First pass registers g_reused for f_a alone.
    db.add_dedupe_group("run", {
        "group_id": "g_reused",
        "root_cause": "first pass root cause for the injection in app.py",
        "canonical_finding_id": "f_a",
        "member_finding_ids": ["f_a"],
    })
    db.assign_finding_group("run", "f_a", "g_reused", True)

    # Second pass (feedback): the model reuses g_reused with f_a+f_b.
    async def fake_agent(**kwargs):
        ui = kwargs["user_input"]
        ids = sorted(d["finding_id"] for d in ui["confirmed_findings"])
        return _result({"groups": [
            {"group_id": "g_reused",
             "root_cause": "second pass merged root cause for both findings",
             "member_finding_ids": ids, "canonical_finding_id": "f_a"},
        ]}, tmp_path)

    import codesec.stages.dedupe as ds
    monkeypatch.setattr(ds, "run_agent", fake_agent)
    groups = await run_dedupe(_dedupe_context(tmp_path), db)

    assert groups == 1
    findings = {f.finding_id: f for f in db.get_findings("run")}
    assert findings["f_a"].group_id == findings["f_b"].group_id
    assert findings["f_a"].group_id != "g_reused", (
        "colliding id must be deterministically renumbered"
    )
    assert findings["f_a"].group_id.startswith("g_d")
    events = db.get_stage_events("run", "dedupe")
    assert any(
        e.get("reason") == "group_id_collision_renumbered" for e in events
    )
    # The original group row is untouched (append-only group history).
    row = db._conn.execute(
        "SELECT raw_json FROM dedupe_groups WHERE run_id='run' "
        "AND group_id='g_reused'"
    ).fetchone()
    assert row is not None


async def test_second_dedupe_pass_supersedes_renamed_group_rows(
    tmp_path, monkeypatch
):
    """When pass 2 returns the same members under NEW group ids, the old
    rows must be superseded — not left as active groups with no canonical
    member (which fails end-of-run coverage)."""
    db = StateDB(tmp_path / "state.db")
    db.create_run(str(tmp_path), "run")
    db.add_task("run", {
        "task_id": "t_1", "attack_class": "sqli", "scope_hint": "sink",
        "target_files": ["app.py"], "rationale": "r", "priority": 1,
        "source": "recon",
    })
    for fid in ("f_a", "f_b"):
        db.add_finding("run", "t_1", {
            "finding_id": fid, "file": "app.py", "line_start": 10,
            "line_end": 12, "vuln_class": "sql_injection", "severity": "high",
            "description": "Injection through string concatenation",
            "evidence_snippet": "sink(input)",
        })
        db.set_finding_validation(
            "run", fid, "confirmed",
            {"finding_id": fid, "verdict": "confirmed"},
        )
    # Pass 1 (already applied): model-named singleton groups.
    db.add_dedupe_group("run", {
        "group_id": "g_f_a", "root_cause": "pass-1 group for f_a",
        "canonical_finding_id": "f_a", "member_finding_ids": ["f_a"],
    })
    db.assign_finding_group("run", "f_a", "g_f_a", True)
    db.add_dedupe_group("run", {
        "group_id": "g_f_b", "root_cause": "pass-1 group for f_b",
        "canonical_finding_id": "f_b", "member_finding_ids": ["f_b"],
    })
    db.assign_finding_group("run", "f_b", "g_f_b", True)

    async def fake_agent(**kwargs):
        ids = sorted(
            d["finding_id"] for d in kwargs["user_input"]["confirmed_findings"]
        )
        return _result({"groups": [
            {"group_id": "g_merged_sql", "root_cause": "same root cause",
             "member_finding_ids": ids, "canonical_finding_id": "f_a"},
        ]}, tmp_path)

    import codesec.stages.dedupe as ds
    monkeypatch.setattr(ds, "run_agent", fake_agent)
    await run_dedupe(_dedupe_context(tmp_path), db)

    # Old rows preserved as superseded history; none still active.
    rows = db._conn.execute(
        "SELECT group_id, superseded_at FROM dedupe_groups "
        "WHERE run_id='run' ORDER BY group_id"
    ).fetchall()
    state = {r["group_id"]: r["superseded_at"] for r in rows}
    assert state["g_f_a"] is not None and state["g_f_b"] is not None
    assert state["g_merged_sql"] is None
    # Coverage sees no memberless active group.
    assert not any(
        "has no canonical finding" in gap
        for gap in db.completion_gaps("run")
    )
