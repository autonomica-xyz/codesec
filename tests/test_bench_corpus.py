from __future__ import annotations

import json
from pathlib import Path

import pytest

from bench.score_repo import evaluate, evaluate_stages, match


ROOT = Path(__file__).resolve().parents[1]


def test_repo_match_requires_source_line_overlap():
    entries = [
        {
            "id": "search_sqli",
            "vuln": True,
            "file": "db.py",
            "line_start": 31,
            "line_end": 35,
            "classes": ["sql_injection", "sqli"],
            "cwe": "CWE-89",
        }
    ]
    unrelated_claim = {
        "file": "db.py",
        "line_start": 54,
        "line_end": 60,
        "vuln_class": "sql_injection",
        "cwe": "CWE-89",
        "description": "Generic claim at a different query.",
    }

    assert match(unrelated_claim, entries) is None


def test_repo_evaluation_matches_each_truth_entry_at_most_once():
    manifest = {
        "entries": [
            {
                "id": "search_sqli",
                "tier": "T1",
                "vuln": True,
                "file": "db.py",
                "line_start": 31,
                "line_end": 35,
                "classes": ["sql_injection"],
                "cwe": "CWE-89",
            }
        ]
    }
    duplicate = {
        "file": "db.py",
        "line_start": 34,
        "line_end": 34,
        "vuln_class": "sql_injection",
        "cwe": "CWE-89",
        "description": "The same SQL injection.",
    }
    report = {
        "findings": [
            {"finding_id": "f1", **duplicate},
            {"finding_id": "f2", **duplicate},
        ]
    }

    result = evaluate(report, manifest)

    assert result["true_positive_findings"] == 1
    assert result["false_positive_findings"] == 1
    assert result["recall"] == 1
    assert result["precision"] == 0.5


def test_corpus_truth_is_external_ranged_and_labels_known_decoys_correctly():
    target = ROOT / "bench" / "corpus" / "devshop"
    manifest_path = ROOT / "bench" / "corpus" / "manifests" / "devshop.json"
    manifest = json.loads(manifest_path.read_text())
    entries = {entry["id"]: entry for entry in manifest["entries"]}

    assert not (target / "ground_truth.json").exists()
    assert all(
        isinstance(entry.get("line_start"), int)
        and isinstance(entry.get("line_end"), int)
        and entry["line_start"] <= entry["line_end"]
        for entry in entries.values()
    )
    assert entries["command_injection_export"]["vuln"] is False
    assert entries["path_traversal_serve_file"]["vuln"] is False


def test_manifest_line_ranges_are_inside_their_source_files():
    target = ROOT / "bench" / "corpus" / "devshop"
    manifest_path = ROOT / "bench" / "corpus" / "manifests" / "devshop.json"
    manifest = json.loads(manifest_path.read_text())

    for entry in manifest["entries"]:
        line_count = len((target / entry["file"]).read_text().splitlines())
        assert 1 <= entry["line_start"] <= entry["line_end"] <= line_count


def test_corpus_truth_distinguishes_candidate_from_reachable_findings():
    manifest_path = ROOT / "bench" / "corpus" / "manifests" / "devshop.json"
    manifest = json.loads(manifest_path.read_text())
    entries = {entry["id"]: entry for entry in manifest["entries"]}

    assert all(
        entry["expected_stage"] in {"final", "candidate", "decoy"}
        and entry["reachability"] in {
            "reachable", "unreachable", "not_applicable"
        }
        for entry in entries.values()
    )
    assert entries["ssti_render_preview"]["expected_stage"] == "final"
    assert entries["ssti_render_preview"]["reachability"] == "reachable"
    assert entries["redos_validate_email"]["expected_stage"] == "candidate"
    assert entries["redos_validate_email"]["reachability"] == "unreachable"
    assert entries["jwt_alg_confusion"]["expected_stage"] == "candidate"
    assert entries["yaml_unsafe_import"]["expected_stage"] == "candidate"
    assert entries["command_injection_export"]["expected_stage"] == "decoy"


def test_stage_evaluation_scores_discovery_validation_trace_and_final(
    tmp_path: Path,
):
    results = tmp_path / "results"
    for stage in ("hunt", "validate", "trace", "report"):
        (results / stage).mkdir(parents=True)

    def finding(fid: str, line: int, vuln_class: str) -> dict:
        return {
            "finding_id": fid,
            "file": "app.py",
            "line_start": line,
            "line_end": line,
            "vuln_class": vuln_class,
        }

    reachable = finding("f_reachable", 10, "sqli")
    dead = finding("f_dead", 20, "code_injection")
    decoy = finding("f_decoy", 30, "safe")
    (results / "hunt" / "task.jsonl").write_text(
        json.dumps(
            {
                "kind": "final_payload",
                "payload": {"task_id": "t1", "findings": [
                    reachable, dead, decoy,
                ]},
            }
        )
        + "\n"
    )
    for fid, verdict in (
        ("f_reachable", "confirmed"),
        ("f_dead", "confirmed"),
        ("f_decoy", "rejected"),
    ):
        (results / "validate" / f"{fid}.jsonl").write_text(
            json.dumps(
                {
                    "kind": "final_payload",
                    "payload": {"finding_id": fid, "verdict": verdict},
                }
            )
            + "\n"
        )
    for fid, status in (
        ("f_reachable", "reachable"),
        ("f_dead", "unreachable"),
    ):
        (results / "trace" / f"{fid}.jsonl").write_text(
            json.dumps(
                {
                    "kind": "final_payload",
                    "payload": {
                        "finding_id": fid,
                        "status": status,
                        "reachable": status == "reachable",
                    },
                }
            )
            + "\n"
        )
    (results / "report" / "report.json").write_text(
        json.dumps({"findings": [reachable]})
    )
    manifest = {
        "target": "synthetic",
        "entries": [
            {
                "id": "reachable",
                "tier": "T1",
                "vuln": True,
                "expected_stage": "final",
                "reachability": "reachable",
                "file": "app.py",
                "line_start": 10,
                "line_end": 10,
                "classes": ["sqli"],
            },
            {
                "id": "dead",
                "tier": "T1",
                "vuln": True,
                "expected_stage": "candidate",
                "reachability": "unreachable",
                "file": "app.py",
                "line_start": 20,
                "line_end": 20,
                "classes": ["code_injection"],
            },
            {
                "id": "decoy",
                "tier": "decoy",
                "vuln": False,
                "expected_stage": "decoy",
                "reachability": "not_applicable",
                "file": "app.py",
                "line_start": 30,
                "line_end": 30,
                "classes": ["safe"],
            },
        ],
    }

    result = evaluate_stages(results, manifest)

    assert result["candidate"]["recall"] == 1
    assert result["candidate"]["precision"] == pytest.approx(2 / 3)
    assert result["confirmed"]["recall"] == 1
    assert result["confirmed"]["precision"] == 1
    assert result["trace"]["coverage"] == 1
    assert result["trace"]["accuracy"] == 1
    assert result["final"]["recall"] == 1
    assert result["final"]["precision"] == 1
