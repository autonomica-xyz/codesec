from __future__ import annotations

from pathlib import Path

from codesec.config import HarnessConfig, StageConfig
from codesec.runner import AgentResult
from codesec.state import StateDB
from codesec.stages import hunt as hunt_stage
from codesec.stages._common import StageContext


def _hunt_context(repo: Path, options: dict | None = None) -> StageContext:
    config = HarnessConfig(
        stages={
            "hunt": StageConfig(
                name="hunt",
                model="hunter",
                concurrency=2,
                tools=["Read"],
                max_turns=2,
                permission_mode="acceptEdits",
                repair_attempts=0,
                options=options or {},
            )
        }
    )
    return StageContext(
        run_id="run",
        repo_path=repo,
        config=config,
        run_results_root=repo / "results",
        run_work_root=repo / "work",
    )


def _repo(tmp_path: Path) -> Path:
    (tmp_path / "app.py").write_text(
        "import subprocess\n"
        "\n"
        "def run(name):\n"
        "    subprocess.run('echo ' + name, shell=True)\n"
    )
    return tmp_path


def _add_task(db: StateDB, task_id: str = "t_1", **extra) -> None:
    db.add_task(
        "run",
        {
            "task_id": task_id,
            "attack_class": "command_injection",
            "scope_hint": "app.py run() interpolates `name` into a shell command",
            "target_files": ["app.py"],
            "rationale": "untrusted `name` reaches subprocess.run with shell=True",
            "priority": 1,
            "source": "recon",
            **extra,
        },
    )


def _agent_result(payload: dict, artifact: Path) -> AgentResult:
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text("{}\n")
    return AgentResult(
        payload=payload,
        cost_usd=0.0,
        input_tokens=0,
        output_tokens=0,
        cache_read_tokens=0,
        cache_creation_tokens=0,
        num_turns=1,
        duration_ms=0,
        session_id=None,
        artifact_path=artifact,
        repair_used=False,
    )


def _stub_agent(captured: list[dict], payload: dict):
    async def fake_run_agent(**kwargs):
        captured.append(kwargs["user_input"])
        return _agent_result(payload, Path(kwargs["artifact_dir"]) / "x.jsonl")

    return fake_run_agent


async def test_hunt_injects_bypass_hints(tmp_path: Path, monkeypatch) -> None:
    repo = _repo(tmp_path)
    db = StateDB(tmp_path / "state.db")
    db.create_run(str(repo), "run")
    _add_task(db)

    hints_map = {"command_injection": ["try `; id`", "try $(id)"]}
    seen: dict = {}
    monkeypatch.setattr(hunt_stage, "load_hints", lambda path=None: hints_map)

    def fake_hints_for(hints, *, cwe=None, vuln_class=None, attack_class=None):
        seen["hints"] = hints
        seen["cwe"] = cwe
        seen["vuln_class"] = vuln_class
        seen["attack_class"] = attack_class
        return hints.get(attack_class, [])

    monkeypatch.setattr(hunt_stage, "hints_for", fake_hints_for)

    captured: list[dict] = []
    monkeypatch.setattr(
        hunt_stage,
        "run_agent",
        _stub_agent(
            captured, {"task_id": "t_1", "findings": [], "gaps_observed": []}
        ),
    )

    emitted = await hunt_stage.run_hunt(_hunt_context(repo), db)

    assert emitted == 0
    assert len(captured) == 1
    assert captured[0]["bypass_hints"] == ["try `; id`", "try $(id)"]
    assert seen["hints"] == hints_map
    assert seen["vuln_class"] == "command_injection"
    assert seen["attack_class"] == "command_injection"


async def test_hunt_omits_bypass_hints_when_disabled(
    tmp_path: Path, monkeypatch
) -> None:
    repo = _repo(tmp_path)
    db = StateDB(tmp_path / "state.db")
    db.create_run(str(repo), "run")
    _add_task(db)

    def fail_load(path=None):  # knob off -> loader must not run at all
        raise AssertionError("load_hints called while hints_in_hunt=false")

    monkeypatch.setattr(hunt_stage, "load_hints", fail_load)

    captured: list[dict] = []
    monkeypatch.setattr(
        hunt_stage,
        "run_agent",
        _stub_agent(
            captured, {"task_id": "t_1", "findings": [], "gaps_observed": []}
        ),
    )

    await hunt_stage.run_hunt(
        _hunt_context(repo, {"hints_in_hunt": False}), db
    )

    assert "bypass_hints" not in captured[0]


async def test_hunt_omits_bypass_hints_when_none_match(
    tmp_path: Path, monkeypatch
) -> None:
    repo = _repo(tmp_path)
    db = StateDB(tmp_path / "state.db")
    db.create_run(str(repo), "run")
    _add_task(db)

    monkeypatch.setattr(
        hunt_stage, "load_hints", lambda path=None: {"xss": ["a"]}
    )
    monkeypatch.setattr(hunt_stage, "hints_for", lambda *a, **k: [])

    captured: list[dict] = []
    monkeypatch.setattr(
        hunt_stage,
        "run_agent",
        _stub_agent(
            captured, {"task_id": "t_1", "findings": [], "gaps_observed": []}
        ),
    )

    await hunt_stage.run_hunt(_hunt_context(repo), db)

    assert "bypass_hints" not in captured[0]


async def test_hunt_passes_task_policy_through(tmp_path: Path, monkeypatch) -> None:
    repo = _repo(tmp_path)
    db = StateDB(tmp_path / "state.db")
    db.create_run(str(repo), "run")
    _add_task(
        db,
        policy={"search_mode": "depth", "attempts_budget": 10,
                "designer_trust": 0.5, "report_partial": False},
    )
    _add_task(db, task_id="t_2")  # no policy -> key absent

    captured: list[dict] = []

    async def fake_run_agent(**kwargs):
        captured.append(kwargs["user_input"])
        return _agent_result(
            {"task_id": kwargs["user_input"]["task_id"],
             "findings": [], "gaps_observed": []},
            Path(kwargs["artifact_dir"]) / "x.jsonl",
        )

    monkeypatch.setattr(hunt_stage, "run_agent", fake_run_agent)

    await hunt_stage.run_hunt(_hunt_context(repo), db)

    by_task = {u["task_id"]: u for u in captured}
    assert by_task["t_1"]["policy"] == {
        "search_mode": "depth",
        "attempts_budget": 10,
        "designer_trust": 0.5,
        "report_partial": False,
    }
    assert "policy" not in by_task["t_2"]


async def test_hunt_persists_hardening_and_uncovered(
    tmp_path: Path, monkeypatch
) -> None:
    repo = _repo(tmp_path)
    db = StateDB(tmp_path / "state.db")
    db.create_run(str(repo), "run")
    _add_task(db)

    payload = {
        "task_id": "t_1",
        "findings": [
            {
                "finding_id": "f_t_1_1",
                "file": "app.py",
                "line_start": 3,
                "line_end": 4,
                "vuln_class": "command_injection",
                "severity": "high",
                "description": "untrusted `name` is concatenated into a shell command",
                "evidence_snippet": "subprocess.run('echo ' + name, shell=True)",
                "confidence": 0.8,
                "conditions": ["caller controls `name`"],
                "live_evidence": {
                    "request": "GET /run?name=;id HTTP/1.1",
                    "response_excerpt": "uid=33(www-data)",
                },
            }
        ],
        "gaps_observed": [],
        "hardening": [{"file": "app.py", "note": "no shell quoting helper"}],
        "uncovered": [
            {
                "surface": "app.py admin routes",
                "attack_class": "idor",
                "starting_path": "app.py",
                "reason": "object ids compared without ownership check",
            }
        ],
    }
    captured: list[dict] = []
    monkeypatch.setattr(
        hunt_stage, "run_agent", _stub_agent(captured, payload)
    )

    emitted = await hunt_stage.run_hunt(_hunt_context(repo), db)

    assert emitted == 1
    notes = db.get_hardening_notes("run")
    assert notes == [
        {"task_id": "t_1", "file": "app.py", "note": "no shell quoting helper"}
    ]
    surfaces = db.get_uncovered_surfaces("run")
    assert len(surfaces) == 1
    assert surfaces[0]["surface"] == "app.py admin routes"
    assert surfaces[0]["attack_class"] == "idor"
    # finding still persisted, task marked done
    findings = db.get_findings("run")
    assert [f.finding_id for f in findings] == ["f_t_1_1"]
    assert findings[0].raw_json["conditions"] == ["caller controls `name`"]
    assert findings[0].raw_json["live_evidence"]["response_excerpt"] == (
        "uid=33(www-data)"
    )
    assert db.get_all_tasks("run")[0].status == "done"


async def test_hunt_injects_prior_findings_only_when_present(
    tmp_path: Path, monkeypatch
) -> None:
    repo = _repo(tmp_path)
    db = StateDB(tmp_path / "state.db")
    db.create_run(str(repo), "run")
    _add_task(db)
    db.set_prior_exclusions(
        "run",
        [{"fp": "abc123", "vuln_class": "sql_injection",
          "file": "app.py", "reason": "reported in a prior run"}],
    )

    captured: list[dict] = []
    monkeypatch.setattr(
        hunt_stage,
        "run_agent",
        _stub_agent(
            captured, {"task_id": "t_1", "findings": [], "gaps_observed": []}
        ),
    )

    await hunt_stage.run_hunt(_hunt_context(repo), db)

    assert captured[0]["prior_findings"] == [
        {"fp": "abc123", "vuln_class": "sql_injection",
         "file": "app.py", "reason": "reported in a prior run"}
    ]

    # fresh run/db with no exclusions -> key absent
    db2 = StateDB(tmp_path / "state2.db")
    db2.create_run(str(repo), "run")
    _add_task(db2)
    captured.clear()
    await hunt_stage.run_hunt(_hunt_context(repo), db2)
    assert "prior_findings" not in captured[0]


async def test_hunt_caps_prior_findings(tmp_path: Path, monkeypatch) -> None:
    """A long-lived catalogue must not blow the per-task input budget."""
    repo = _repo(tmp_path)
    db = StateDB(tmp_path / "state.db")
    db.create_run(str(repo), "run")
    _add_task(db)
    db.set_prior_exclusions(
        "run",
        [{"fp": f"fp{i}", "vuln_class": "sqli", "file": "app.py",
          "reason": "prior"} for i in range(75)],
    )

    captured: list[dict] = []
    monkeypatch.setattr(
        hunt_stage, "run_agent",
        _stub_agent(captured, {"task_id": "t_1", "findings": [],
                               "gaps_observed": []}),
    )

    await hunt_stage.run_hunt(_hunt_context(repo), db)

    assert len(captured[0]["prior_findings"]) == 60
