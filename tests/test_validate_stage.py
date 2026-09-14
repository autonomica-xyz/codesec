"""Validate stage: panel + arbiter aggregation rules."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from codesec.config import HarnessConfig, StageConfig
from codesec.runner import AgentRunError
from codesec.state import StateDB
from codesec.stages import validate as validate_stage
from codesec.stages._common import StageContext


class _FakeResult:
    def __init__(self, payload: dict, tmp: Path):
        self.payload = payload
        self.artifact_path = tmp / f"{payload['finding_id']}.jsonl"
        self.cost_usd = None
        self.input_tokens = 0
        self.output_tokens = 0
        self.cache_read_tokens = 0
        self.cache_creation_tokens = 0
        self.num_turns = 1
        self.duration_ms = 0


def _review_payload(verdict: str, *, conf: float = 0.5, crux: str = "crux",
                    rationale: str | None = None) -> dict:
    return {
        "finding_id": "f_1",
        "verdict": verdict,
        "rationale": rationale or ("Engages with the evidence " * 3),
        "alternative_explanation": "the benign rival read",
        "validator_confidence": conf,
        "crux": crux,
    }


def _context(tmp_path: Path, rounds: int) -> StageContext:
    return StageContext(
        run_id="run",
        repo_path=tmp_path,
        config=HarnessConfig(
            stages={
                "validate": StageConfig(
                    name="validate",
                    model="opus",
                    concurrency=2,
                    tools=["Read"],
                    max_turns=2,
                    permission_mode="acceptEdits",
                    repair_attempts=0,
                    rounds=rounds,
                )
            }
        ),
        run_results_root=tmp_path / "results",
        run_work_root=tmp_path / "work",
    )


def _db_with_finding(tmp_path: Path) -> StateDB:
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
    db.add_finding(
        "run",
        "t_1",
        {
            "finding_id": "f_1",
            "file": "app.py",
            "line_start": 1,
            "line_end": 2,
            "vuln_class": "sql_injection",
            "severity": "high",
            "description": "input reaches query",
            "evidence_snippet": "execute(sql)",
            "confidence": 0.9,
        },
    )
    return db


def _install_agent(monkeypatch, tmp_path: Path, responses):
    """responses: list of payloads or exceptions, popped per call.
    Returns a recorder of (prompt_name, artifact_name, user_input)."""
    calls: list[tuple[str, str, dict]] = []

    async def fake_run_agent(*, prompt_file, artifact_name, user_input, **kw):
        prompt_name = Path(prompt_file).name
        calls.append((prompt_name, artifact_name, user_input))
        item = responses.pop(0) if responses else responses
        if isinstance(item, Exception):
            raise item
        return _FakeResult(item, tmp_path)

    monkeypatch.setattr(validate_stage, "run_agent", fake_run_agent)
    return calls


def _validation(db: StateDB) -> tuple[str, dict]:
    f = db.get_findings("run")[0]
    return f.validation_status, f.validation_json


async def test_single_round_keeps_self_reported_confidence(
    tmp_path: Path, monkeypatch
) -> None:
    db = _db_with_finding(tmp_path)
    calls = _install_agent(
        monkeypatch, tmp_path,
        [_review_payload("confirmed", conf=0.8)],
    )

    confirmed = await validate_stage.run_validate(_context(tmp_path, rounds=1), db)

    assert confirmed == 1
    assert len(calls) == 1  # no arbiter for a panel of one
    status, payload = _validation(db)
    assert status == "confirmed"
    assert payload["validator_confidence"] == 0.8  # self-report preserved
    assert payload["review"]["rounds"] == 1
    assert payload["review"]["tally"] == "C"
    assert payload["review"]["agreement"] == "unanimous"


async def test_panel_arbiter_confidence_is_vote_fraction(
    tmp_path: Path, monkeypatch
) -> None:
    db = _db_with_finding(tmp_path)
    calls = _install_agent(
        monkeypatch, tmp_path,
        [
            _review_payload("rejected"),
            _review_payload("confirmed"),
            _review_payload("confirmed", crux="arbiter crux", conf=0.95),
        ],
    )

    confirmed = await validate_stage.run_validate(_context(tmp_path, rounds=2), db)

    assert confirmed == 1
    assert len(calls) == 3
    # Round 2 saw round 1's condensed verdict; arbiter saw both + tally.
    assert "prior_reviews" not in calls[0][2]
    assert calls[1][2]["prior_reviews"][0]["verdict"] == "rejected"
    assert calls[1][2]["prior_reviews"][0]["crux"] == "crux"
    assert calls[2][0] == "03-arbiter.md"
    assert calls[2][2]["tally"] == "RC"

    status, payload = _validation(db)
    assert status == "confirmed"
    # votes: rejected, confirmed, confirmed -> 2/3 behind the arbiter's call
    assert payload["validator_confidence"] == 0.67
    assert payload["review"]["tally"] == "RC→C"
    assert payload["review"]["vote_fraction"] == 0.67
    assert payload["review"]["agreement"] == "split"
    assert payload["review"]["arbiter_used"] is True
    assert len(payload["review"]["panel"]) == 2


async def test_arbiter_failure_falls_back_to_panel_majority(
    tmp_path: Path, monkeypatch
) -> None:
    db = _db_with_finding(tmp_path)
    _install_agent(
        monkeypatch, tmp_path,
        [
            _review_payload("rejected"),
            _review_payload("rejected"),
            AgentRunError("arbiter blew up"),
        ],
    )

    confirmed = await validate_stage.run_validate(_context(tmp_path, rounds=2), db)

    assert confirmed == 0
    status, payload = _validation(db)
    assert status == "rejected"
    assert payload["review"]["arbiter_used"] is False
    # both panel votes behind the verdict, arbiter contributed none
    assert payload["validator_confidence"] == 1.0
    assert payload["review"]["tally"] == "RR"
    assert payload["review"]["agreement"] == "unanimous"


async def test_split_panel_without_arbiter_stays_undecided(
    tmp_path: Path, monkeypatch
) -> None:
    db = _db_with_finding(tmp_path)
    _install_agent(
        monkeypatch, tmp_path,
        [
            _review_payload("rejected"),
            _review_payload("confirmed"),
            AgentRunError("no arbiter"),
        ],
    )

    confirmed = await validate_stage.run_validate(_context(tmp_path, rounds=2), db)

    assert confirmed == 0
    status, payload = _validation(db)
    assert status == "needs_more_info"
    # synthetic fallback must satisfy the contract's suggested_test rule
    assert payload["suggested_test"]
    assert payload["review"]["tally"] == "RC"


async def test_all_rounds_failed_fails_safe(
    tmp_path: Path, monkeypatch
) -> None:
    db = _db_with_finding(tmp_path)
    _install_agent(
        monkeypatch, tmp_path,
        [
            AgentRunError("r1 down"),
            AgentRunError("r2 down"),
            # arbiter would run, but the panel is empty — it never gets called
        ],
    )

    confirmed = await validate_stage.run_validate(_context(tmp_path, rounds=2), db)

    assert confirmed == 0
    status, payload = _validation(db)
    assert status == "needs_more_info"
    assert payload["validator_confidence"] == 0.0
    assert "r1 down" in payload["rationale"]
    # Schema-required field on the synthetic fallback
    assert payload["alternative_explanation"]


async def test_contract_violating_round_is_dropped_not_fatal(
    tmp_path: Path, monkeypatch
) -> None:
    db = _db_with_finding(tmp_path)
    bad = _review_payload("confirmed")
    bad.pop("alternative_explanation")  # violates the semantic contract
    _install_agent(
        monkeypatch, tmp_path,
        [bad, _review_payload("rejected"), _review_payload("rejected")],
    )

    confirmed = await validate_stage.run_validate(_context(tmp_path, rounds=2), db)

    assert confirmed == 0
    status, payload = _validation(db)
    assert status == "rejected"
    assert payload["review"]["errors"]  # the dropped round is recorded


def test_condense_review_caps_and_squashes() -> None:
    payload = _review_payload(
        "confirmed",
        crux="  multi   space   crux  ",
        rationale="word " * 400,
    )

    condensed = validate_stage._condense_review(3, payload)

    assert condensed["round"] == 3
    assert condensed["crux"] == "multi space crux"
    assert len(condensed["rationale"]) <= validate_stage._RATIONALE_CAP + 2
    assert condensed["rationale"].endswith("…")


def test_majority_returns_none_on_tie() -> None:
    assert validate_stage._majority(["rejected", "rejected", "confirmed"]) == "rejected"
    assert validate_stage._majority(["rejected", "confirmed"]) is None
    assert validate_stage._majority([]) is None


async def test_confirmed_without_proof_is_downgraded(
    tmp_path: Path, monkeypatch
) -> None:
    db = _db_with_finding(tmp_path)
    # Shrink the evidence snippet below the proof threshold.
    f = db.get_findings("run")[0]
    f.raw_json["evidence_snippet"] = "N/A"
    db._conn.execute(
        "UPDATE findings SET evidence = ?, raw_json = ? "
        "WHERE run_id = ? AND finding_id = ?",
        ("N/A", __import__("json").dumps(f.raw_json), "run", "f_1"),
    )
    db._conn.commit()

    _install_agent(
        monkeypatch, tmp_path,
        [_review_payload("confirmed", conf=0.9)],
    )

    confirmed = await validate_stage.run_validate(_context(tmp_path, rounds=1), db)

    assert confirmed == 0
    status, payload = _validation(db)
    assert status == "needs_more_info"
    assert payload["verdict"] == "needs_more_info"
    assert payload["rationale"].startswith("[evidence_gate:no_proof]")


async def test_evidence_gate_downgrade_stays_schema_valid(
    tmp_path: Path, monkeypatch
) -> None:
    """A downgraded verdict must shed confirmed-only fields and gain the
    needs_more_info-required ones."""
    db = _db_with_finding(tmp_path)
    f = db.get_findings("run")[0]
    f.raw_json["evidence_snippet"] = "N/A"
    db._conn.execute(
        "UPDATE findings SET evidence = ?, raw_json = ? "
        "WHERE run_id = ? AND finding_id = ?",
        ("N/A", json.dumps(f.raw_json), "run", "f_1"),
    )
    db._conn.commit()

    review = _review_payload("confirmed", conf=0.9)
    review["arbiter_severity"] = "high"
    review["severity_reasoning"] = "preconditions met"
    review["execution"] = {"commands": ["curl x"]}
    _install_agent(monkeypatch, tmp_path, [review])

    confirmed = await validate_stage.run_validate(_context(tmp_path, rounds=1), db)

    assert confirmed == 0
    status, payload = _validation(db)
    assert status == "needs_more_info"
    for forbidden in ("arbiter_severity", "severity_reasoning", "execution"):
        assert forbidden not in payload
    assert payload["blockers"] and payload["validation_plan"]
    assert payload["suggested_test"]


async def test_confirmed_with_live_evidence_passes_gate(
    tmp_path: Path, monkeypatch
) -> None:
    db = _db_with_finding(tmp_path)
    f = db.get_findings("run")[0]
    f.raw_json["live_evidence"] = {"marker": "m-abc", "verified": True}
    f.raw_json["evidence_snippet"] = ""
    db._conn.execute(
        "UPDATE findings SET evidence = ?, raw_json = ? "
        "WHERE run_id = ? AND finding_id = ?",
        ("", json.dumps(f.raw_json), "run", "f_1"),
    )
    db._conn.commit()

    _install_agent(
        monkeypatch, tmp_path,
        [_review_payload("confirmed", conf=0.9)],
    )

    confirmed = await validate_stage.run_validate(_context(tmp_path, rounds=1), db)

    assert confirmed == 1
    status, _ = _validation(db)
    assert status == "confirmed"


async def test_confirmed_with_successful_poc_passes_gate(
    tmp_path: Path, monkeypatch
) -> None:
    db = _db_with_finding(tmp_path)
    f = db.get_findings("run")[0]
    f.raw_json["poc"] = {
        "language": "python", "code": "print(1)", "succeeded": True,
    }
    f.raw_json["evidence_snippet"] = ""  # PoC alone must carry the proof
    import json as _json
    db._conn.execute(
        "UPDATE findings SET evidence = ?, raw_json = ? "
        "WHERE run_id = ? AND finding_id = ?",
        ("", _json.dumps(f.raw_json), "run", "f_1"),
    )
    db._conn.commit()

    _install_agent(
        monkeypatch, tmp_path,
        [_review_payload("confirmed", conf=0.9)],
    )

    confirmed = await validate_stage.run_validate(_context(tmp_path, rounds=1), db)

    assert confirmed == 1
    status, _ = _validation(db)
    assert status == "confirmed"


async def test_panel_sees_claim_not_finder_assessment(
    tmp_path: Path, monkeypatch
) -> None:
    db = _db_with_finding(tmp_path)
    f = db.get_findings("run")[0]
    f.raw_json["hedged_language"] = True
    f.raw_json["finder_note"] = "definitely exploitable, trust me"
    db._conn.execute(
        "UPDATE findings SET raw_json = ? WHERE run_id = ? AND finding_id = ?",
        (json.dumps(f.raw_json), "run", "f_1"),
    )
    db._conn.commit()

    calls = _install_agent(
        monkeypatch, tmp_path,
        [_review_payload("rejected")] * 3,
    )

    await validate_stage.run_validate(_context(tmp_path, rounds=2), db)

    panel_finding = calls[0][2]["finding"]
    assert set(panel_finding) <= validate_stage._PANEL_VIEW
    assert "confidence" not in panel_finding
    assert "hedged_language" not in panel_finding
    assert "finder_note" not in panel_finding
    # task_context keeps only attack_class + scope_hint — no finder
    # rationale leaking into the panel's framing.
    assert calls[0][2]["task_context"] == {
        "attack_class": "sqli",
        "scope_hint": "query sink",
    }
    # The arbiter arbitrates rather than re-verifies: full finding,
    # hunt rationale included.
    arbiter_input = calls[2][2]
    assert arbiter_input["finding"]["confidence"] == 0.9
    assert arbiter_input["finding"]["hedged_language"] is True
    assert arbiter_input["task_context"]["rationale"] == (
        "request input reaches query"
    )


async def test_panel_projection_can_be_disabled(
    tmp_path: Path, monkeypatch
) -> None:
    db = _db_with_finding(tmp_path)
    ctx = _context(tmp_path, rounds=1)
    ctx.config.get("validate").options["panel_projection"] = False
    calls = _install_agent(
        monkeypatch, tmp_path,
        [_review_payload("confirmed")],
    )

    await validate_stage.run_validate(ctx, db)

    assert calls[0][2]["finding"]["confidence"] == 0.9
    assert calls[0][2]["task_context"]["rationale"] == (
        "request input reaches query"
    )


async def test_bypass_hints_injected_from_round_two(
    tmp_path: Path, monkeypatch
) -> None:
    db = _db_with_finding(tmp_path)
    f = db.get_findings("run")[0]
    f.raw_json["cwe"] = "CWE-89"
    db._conn.execute(
        "UPDATE findings SET raw_json = ? WHERE run_id = ? AND finding_id = ?",
        (json.dumps(f.raw_json), "run", "f_1"),
    )
    db._conn.commit()

    calls = _install_agent(
        monkeypatch, tmp_path,
        [_review_payload("rejected")] * 3,
    )

    await validate_stage.run_validate(_context(tmp_path, rounds=2), db)

    assert "bypass_hints" not in calls[0][2]           # round 1: no hints
    hints = calls[1][2]["bypass_hints"]                # round 2: matched
    assert hints and all(h.startswith("try") for h in hints)
    assert "bypass_hints" not in calls[2][2]           # arbiter: none


async def test_hints_all_rounds_knob(tmp_path: Path, monkeypatch) -> None:
    db = _db_with_finding(tmp_path)
    f = db.get_findings("run")[0]
    f.raw_json["cwe"] = "CWE-89"
    db._conn.execute(
        "UPDATE findings SET raw_json = ? WHERE run_id = ? AND finding_id = ?",
        (json.dumps(f.raw_json), "run", "f_1"),
    )
    db._conn.commit()
    ctx = _context(tmp_path, rounds=1)
    ctx.config.get("validate").options["hints_all_rounds"] = True
    calls = _install_agent(
        monkeypatch, tmp_path,
        [_review_payload("confirmed")],
    )

    await validate_stage.run_validate(ctx, db)

    assert calls[0][2]["bypass_hints"]


async def test_no_hints_when_nothing_matches(
    tmp_path: Path, monkeypatch
) -> None:
    db = _db_with_finding(tmp_path)
    calls = _install_agent(
        monkeypatch, tmp_path,
        [_review_payload("rejected")] * 3,
    )

    # finding has no cwe; vuln_class sql_injection matches no free-form key
    await validate_stage.run_validate(_context(tmp_path, rounds=2), db)

    assert "bypass_hints" not in calls[1][2]
