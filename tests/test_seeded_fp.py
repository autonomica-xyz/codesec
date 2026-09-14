"""Seeded false-positive set — the deterministic scoreboard for the
validate panel's input handling (W0b).

Each fixture under fixtures/seeded_fp/ is a finding-schema-shaped dict
plus a `_meta` block (why it is false, expected outcome). Live scoring
against a real model is out of scope; the opt-in test at the bottom only
runs when CODESEC_LIVE_BENCH is set.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from types import SimpleNamespace

import pytest

from codesec.hints import hints_for, load_hints
from codesec.json_utils import validate_schema
from codesec.state import StateDB
from codesec.stages import validate as validate_stage

from tests.test_validate_stage import (
    _context,
    _install_agent,
    _review_payload,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "seeded_fp"
SCHEMAS = FIXTURES.parents[2] / "schemas"

_REQUIRED = {
    "finding_id", "file", "line_start", "line_end", "vuln_class",
    "severity", "description", "evidence_snippet", "confidence",
}


def _load_all() -> list[tuple[Path, dict]]:
    return [
        (p, json.loads(p.read_text()))
        for p in sorted(FIXTURES.glob("*.json"))
    ]


def _finding(raw: dict) -> dict:
    return {k: v for k, v in raw.items() if k != "_meta"}


def _task(raw: dict) -> SimpleNamespace:
    t = (raw.get("_meta") or {}).get("task") or {}
    return SimpleNamespace(
        attack_class=t.get("attack_class", ""),
        scope_hint=t.get("scope_hint", ""),
        rationale=t.get("rationale", ""),
    )


def _payload_for(finding_id: str, verdict: str = "rejected") -> dict:
    p = _review_payload(verdict)
    p["finding_id"] = finding_id
    return p


def test_fixtures_load_and_match_finding_schema() -> None:
    loaded = _load_all()
    assert len(loaded) >= 8
    schema = SCHEMAS / "finding.schema.json"
    for path, raw in loaded:
        meta = raw.get("_meta") or {}
        assert meta.get("why_false"), path.name
        assert meta.get("expected_verdict") in (
            "confirmed", "rejected", "needs_more_info",
        ), path.name
        assert meta.get("task", {}).get("attack_class"), path.name
        finding = _finding(raw)
        assert _REQUIRED <= set(finding), path.name
        assert re.fullmatch(r"f_[a-z0-9_-]{1,64}", finding["finding_id"])
        payload = {
            "task_id": "t_1",
            "findings": [finding],
            "gaps_observed": [],
        }
        assert validate_schema(payload, schema) == [], path.name


def test_projection_strips_finder_assessment() -> None:
    for path, raw in _load_all():
        finding = _finding(raw)
        projected = validate_stage._project_finding(finding)
        assert set(projected) <= validate_stage._PANEL_VIEW, path.name
        for anchor in ("confidence", "hedged_language"):
            assert anchor not in projected, path.name
        task = _task(raw)
        projected_ctx = validate_stage._task_context(
            task, finding["vuln_class"], projected=True
        )
        assert "rationale" not in projected_ctx
        full_ctx = validate_stage._task_context(
            task, finding["vuln_class"], projected=False
        )
        assert "rationale" in full_ctx


async def test_hints_injected_from_round_two(
    tmp_path: Path, monkeypatch
) -> None:
    hints = load_hints()
    for i, (path, raw) in enumerate(_load_all()):
        finding = _finding(raw)
        task_meta = raw["_meta"]["task"]
        db = StateDB(tmp_path / f"fp_{i}.db")
        db.create_run(str(tmp_path), "run")
        db.add_task(
            "run",
            {
                "task_id": "t_1",
                "attack_class": task_meta["attack_class"],
                "scope_hint": task_meta.get("scope_hint", ""),
                "target_files": task_meta.get("target_files", ["app.py"]),
                "rationale": task_meta.get("rationale", ""),
                "priority": 1,
                "source": "recon",
            },
        )
        db.add_finding("run", "t_1", finding)
        calls = _install_agent(
            monkeypatch, tmp_path,
            [_payload_for(finding["finding_id"]) for _ in range(3)],
        )

        await validate_stage.run_validate(_context(tmp_path, rounds=2), db)

        expected = hints_for(
            hints,
            cwe=finding.get("cwe"),
            vuln_class=finding["vuln_class"],
            attack_class=task_meta["attack_class"],
        )
        assert "bypass_hints" not in calls[0][2], path.name   # round 1
        if expected:
            assert calls[1][2]["bypass_hints"] == expected, path.name
        else:
            assert "bypass_hints" not in calls[1][2], path.name
        assert "bypass_hints" not in calls[2][2], path.name   # arbiter


@pytest.mark.skipif(
    not os.environ.get("CODESEC_LIVE_BENCH"),
    reason="live bench only — feeds fixtures through the real agent",
)
async def test_seeded_fp_live(tmp_path: Path) -> None:
    from codesec.config import load_config
    from codesec.stages._common import StageContext

    repo = FIXTURES.parents[2] / "bench" / "corpus" / "devshop"
    ctx = StageContext(
        run_id="live-fp",
        repo_path=repo,
        config=load_config(),
        run_results_root=tmp_path / "results",
        run_work_root=tmp_path / "work",
    )
    for i, (path, raw) in enumerate(_load_all()):
        finding = _finding(raw)
        meta = raw["_meta"]
        task_meta = meta["task"]
        db = StateDB(tmp_path / f"live_{i}.db")
        db.create_run(str(repo), "live-fp")
        db.add_task(
            "live-fp",
            {
                "task_id": "t_1",
                "attack_class": task_meta["attack_class"],
                "scope_hint": task_meta.get("scope_hint", ""),
                "target_files": task_meta.get("target_files", ["app.py"]),
                "rationale": task_meta.get("rationale", ""),
                "priority": 1,
                "source": "recon",
            },
        )
        db.add_finding("live-fp", "t_1", finding)

        await validate_stage.run_validate(ctx, db)

        stored = db.get_findings("live-fp")[0]
        expected = meta["expected_verdict"]
        if expected == "confirmed":
            # Real-but-trivial bug: a confirmed verdict is only
            # acceptable when the arbiter re-derived the severity down.
            want = meta.get("expected_arbiter_severity")
            assert (
                stored.validation_status != "confirmed"
                or (stored.validation_json or {}).get("arbiter_severity")
                == want
            ), path.name
        else:
            assert stored.validation_status == expected, (
                f"{path.name}: {stored.validation_status} "
                f"!= {expected}"
            )
