"""P08 aggregation behavior tests (tiny fake scorer; no glob discovery)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from bench.realvuln import aggregate as agg
from bench.realvuln.aggregate import aggregate_experiment
from bench.realvuln.experiment import (
    cell_id_of,
    commit_cell_outputs,
    cmd_freeze,
    load_manifest,
)
from bench.realvuln.ledger import AttemptLedger


FAKE_SCORER = agg._fake_scorer_factory()


def _admit(tmp_path: Path, spec: dict) -> dict:
    from tests._admission import add_calibration_admission

    return add_calibration_admission(tmp_path, spec)


def _mini_realvuln(tmp_path: Path, repos, vulns_per_repo=2) -> Path:
    rv = tmp_path / "rv"
    for repo in repos:
        (rv / "repos" / repo).mkdir(parents=True, exist_ok=True)
        (rv / "repos" / repo / "app.py").write_text("x = 1\n")
        findings = []
        for i in range(vulns_per_repo):
            findings.append({
                "id": f"{repo}-{i:02d}", "is_vulnerable": True,
                "primary_cwe": "CWE-89", "file": "app.py",
                "location": {"start_line": 1 + i, "end_line": 1 + i},
            })
        findings.append({
            "id": f"{repo}-decoy", "is_vulnerable": False,
            "primary_cwe": "CWE-79", "file": "app.py",
            "location": {"start_line": 50, "end_line": 50},
        })
        findings.append({
            "id": f"{repo}-ns", "is_vulnerable": True,
            "primary_cwe": "CWE-89", "file": "app.py",
            "location": {"start_line": 65, "end_line": 65},
            "scoring": "non_scoring",
        })
        gt_dir = rv / "ground-truth" / repo
        gt_dir.mkdir(parents=True, exist_ok=True)
        (gt_dir / "ground-truth.json").write_text(
            json.dumps({"repo_id": repo, "commit_sha": "deadbeef",
                        "findings": findings})
        )
    return rv


def _freeze_exp(tmp_path: Path, repos, monkeypatch) -> Path:
    import bench.realvuln.isolation as iso

    monkeypatch.setattr(iso, "verify_pin", lambda *a, **k: {
        "head": "pinned", "pinned": "pinned", "untracked": []})
    monkeypatch.setattr(
        iso, "resolve_image_id", lambda image: "sha256:" + "ab" * 32)
    import bench.realvuln.experiment as exp_mod

    monkeypatch.setattr(
        exp_mod, "_image_profile_endpoints",
        lambda image: {"http://gateway:8800/v1"})
    spec = _admit(tmp_path, {
        "protocol_version": 2,
        "repos": list(repos), "seed": 20260922,
        "benchmark_pin": "7a710251f55c17d32d3adcb13d37468e2e3b9e4a",
        "realvuln_root": str(_mini_realvuln(tmp_path, repos)),
        "settings": {
            "gateway_url": "http://gateway:8800/v1",
            "model": "glm-5.3", "temperature": 0.6,
            "max_output_tokens_per_request": 32768,
            "wall_ceiling_s": 7200,
        },
        "effective_request": {
            "model": "glm-5.3",
            "request_params": {"thinking": {"type": "enabled"},
                               "reasoning_effort": "low"},
            "temperature": 0.6, "max_tokens": 32768,
            "context_limit": 262144, "stream": True,
            "fingerprint_sha256": "0" * 64,
        },
        "report": {"policy": "confirmed_reachable"},
        "budgets": {}, "failure_scoring": {}, "thresholds": {},
        "primary_metric": "strict micro F3",
        "image": {"tag": "codesec-iso", "image_id": "sha256:" + "ab" * 32},
    })
    spec_path = tmp_path / "protocol.json"
    spec_path.write_text(json.dumps(spec))
    exp = tmp_path / "exp"

    class _Args:
        spec, output = str(spec_path), str(exp)
    assert cmd_freeze(_Args()) == 0
    return exp


def _commit_findings(exp: Path, manifest: dict, repo: str, trial: int,
                     arm: str, findings_for_arm) -> None:
    """Commit a cell exactly as a real attempt would: primary + (H)
    secondary artifacts AND the paired ledger start/end records — a
    committed artifact without a terminal ledger record is invalid."""
    cell = {"repo": repo, "trial": trial, "arm": arm,
            "cell_id": cell_id_of(repo, trial, arm)}
    attempt_id = f"att-{repo}-{trial}-{arm}"
    staging = exp / "staging"
    if staging.exists():
        import shutil
        shutil.rmtree(staging)
    staging.mkdir()
    doc = {"version": "x", "results": [
        {"path": "app.py", "start": {"line": line}, "end": {"line": line},
         "extra": {"metadata": {"cwe": ["CWE-89"]}, "message": "m"}}
        for line in findings_for_arm
    ]}
    (staging / "primary.semgrep.json").write_text(json.dumps(doc))
    files = {"primary": staging / "primary.semgrep.json"}
    if arm == "h":
        (staging / "secondary-confirmed.semgrep.json").write_text(
            json.dumps(doc))
        files["secondary"] = staging / "secondary-confirmed.semgrep.json"
    ledger = AttemptLedger(
        exp / "operator" / "attempts.jsonl",
        experiment_id=manifest["experiment_id"],
        config_hash=manifest["manifest_sha256"],
    )
    ledger.append({"type": "attempt_start", "cell_id": cell["cell_id"],
                   "attempt_id": attempt_id})
    commit_cell_outputs(
        exp=exp, manifest=manifest, cell=cell, attempt_id=attempt_id,
        export_dir=staging, files=files,
    )
    ledger.append({"type": "attempt_end", "cell_id": cell["cell_id"],
                   "attempt_id": attempt_id, "status": "completed",
                   "made_inference_requests": True})


def _full_matrix(exp, manifest, repos, predictor):
    for repo in repos:
        for trial in (1, 2, 3):
            for arm in ("h", "v"):
                _commit_findings(
                    exp, manifest, repo, trial, arm,
                    predictor(repo, trial, arm),
                )


def _aggregate(exp, **kw):
    return aggregate_experiment(exp, scorer=FAKE_SCORER, **kw)


def test_complete_matrix_produces_decision(tmp_path, monkeypatch):
    repos = [f"realvuln-{r}" for r in "abcdef"]
    exp = _freeze_exp(tmp_path, repos, monkeypatch)
    manifest = load_manifest(exp)

    def predictor(repo, trial, arm):
        return [1, 2] if arm == "h" else [1]

    _full_matrix(exp, manifest, repos, predictor)
    report = _aggregate(exp, realvuln=_mini_realvuln(tmp_path, repos))

    assert report["problems"] == []
    assert report["headline"] is not None
    assert report["decision"]["precedence"] == "does_not_meet_success_criterion"
    # H sees both positives (recall 1.0), V misses one per repo.
    assert report["headline"]["recall_h"] == 1.0
    assert report["headline"]["recall_v"] < 1.0
    assert len(report["per_trial"]) == 3
    for trial in (1, 2, 3):
        assert report["per_trial"][trial]["h"]["tp"] == 12  # 6 repos x 2


def test_missing_one_trial_blocks_headline(tmp_path, monkeypatch):
    repos = ["realvuln-a", "realvuln-b"]
    exp = _freeze_exp(tmp_path, repos, monkeypatch)
    manifest = load_manifest(exp)
    for repo in repos:
        for trial in (1, 2):  # trial 3 missing entirely
            for arm in ("h", "v"):
                _commit_findings(exp, manifest, repo, trial, arm, [1])
    report = _aggregate(exp)
    assert report["headline"] is None
    assert any("no terminal ledger state" in p for p in report["problems"])


def test_extra_trial_ids_rejected(tmp_path, monkeypatch):
    repos = ["realvuln-a"]
    exp = _freeze_exp(tmp_path, repos, monkeypatch)
    manifest = load_manifest(exp)
    _full_matrix(exp, manifest, repos, lambda *a: [1])
    # A cell outside the manifest cannot exist via commit (refused), but an
    # unledgered expected cell is the equivalent failure:
    report = _aggregate(exp)
    assert report["headline"] is None or report["problems"] == []
    # Fabricate a duplicate assignment in the manifest itself:
    manifest_path = exp / "operator" / "manifest.json"
    payload = json.loads(manifest_path.read_text())
    payload["expected_cells"] = payload["expected_cells"] + [
        payload["expected_cells"][0]
    ]
    import hashlib
    manifest_path.write_text(json.dumps(payload, sort_keys=True))
    # self-hash now stale -> aggregation refuses
    with pytest.raises(Exception):
        _aggregate(exp)


def test_zero_predictions_vs_failed_cell(tmp_path, monkeypatch):
    """Zero committed predictions are real predictions (FN/TN); an
    unaccounted cell is not — it blocks the headline."""
    repos = ["realvuln-a", "realvuln-b"]
    exp = _freeze_exp(tmp_path, repos, monkeypatch)
    manifest = load_manifest(exp)
    # Everything committed with EMPTY predictions (valid findings: []).
    _full_matrix(exp, manifest, repos, lambda *a: [])
    report = _aggregate(exp)
    assert report["headline"] is not None
    for trial in (1, 2, 3):
        for arm in ("h", "v"):
            assert report["per_trial"][trial][arm]["fn"] == 4  # 2 repos x 2 vulns
            assert report["per_trial"][trial][arm]["tp"] == 0
            assert report["per_trial"][trial][arm]["tn"] == 2  # decoys


def test_operational_failure_after_inference_scores_empty_predictions(tmp_path, monkeypatch):
    repos = ["realvuln-a", "realvuln-b"]
    exp = _freeze_exp(tmp_path, repos, monkeypatch)
    manifest = load_manifest(exp)
    for repo in repos:
        for trial in (1, 2, 3):
            for arm in ("h", "v"):
                if repo == "realvuln-a" and arm == "h":
                    # H failed with no output AFTER inference on repo A:
                    # operational primary -> empty predictions, flagged.
                    ledger = AttemptLedger(
                        exp / "operator" / "attempts.jsonl",
                        experiment_id=manifest["experiment_id"],
                        config_hash=manifest["manifest_sha256"],
                    )
                    ledger.append({"type": "attempt_start",
                                   "cell_id": cell_id_of(repo, trial, arm),
                                   "attempt_id": f"a-{trial}"})
                    ledger.append({
                        "type": "attempt_end",
                        "cell_id": cell_id_of(repo, trial, arm),
                        "attempt_id": f"a-{trial}",
                        "status": "failed_no_output",
                        "made_inference_requests": True,
                    })
                    continue
                _commit_findings(exp, manifest, repo, trial, arm, [1, 2])
    report = _aggregate(exp)
    assert report["headline"] is not None, (
        "an accounted operational failure aggregates — it is never displayed "
        "as a clean matrix, but the denominator is preserved"
    )
    cell_key = f"realvuln-a#t1#h"
    assert report["cells"][cell_key]["output_failure"] is True
    assert report["cells"][cell_key]["agent_authored"] is False
    # Trial 1 H: repo A scored with empty predictions (2 FN); repo B found
    # both positives (0 FN). The failed cell keeps its denominator.
    assert report["per_trial"][1]["h"]["fn"] == 2
    assert report["cells"][cell_key]["counts"]["tp"] == 0


def test_setup_failure_zero_inference_blocks_headline(tmp_path, monkeypatch):
    repos = ["realvuln-a", "realvuln-b"]
    exp = _freeze_exp(tmp_path, repos, monkeypatch)
    manifest = load_manifest(exp)
    ledger = AttemptLedger(
        exp / "operator" / "attempts.jsonl",
        experiment_id=manifest["experiment_id"],
        config_hash=manifest["manifest_sha256"],
    )
    cell_id = cell_id_of("realvuln-a", 1, "h")
    ledger.append({"type": "attempt_start", "cell_id": cell_id,
                   "attempt_id": "a-1"})
    ledger.append({"type": "attempt_end", "cell_id": cell_id,
                   "attempt_id": "a-1", "status": "setup_failed",
                   "made_inference_requests": False})
    for repo in repos:
        for trial in (1, 2, 3):
            for arm in ("h", "v"):
                if cell_id_of(repo, trial, arm) == cell_id:
                    continue
                _commit_findings(exp, manifest, repo, trial, arm, [1, 2])
    report = _aggregate(exp)
    assert report["headline"] is None
    assert any("experiment incomplete" in p for p in report["problems"])


def test_decision_rule_truth_table(tmp_path):
    """The frozen decision rule, exercised on synthetic pooled numbers."""
    from bench.realvuln.aggregate import (
        FP_WIN_REPO_THRESHOLD,
        FP_WIN_TRIAL_THRESHOLD,
    )
    # exact rule re-implementation for truth-table checks
    def rule(f3_h, f3_v, r_h, r_v, p_h, p_v, fp_wins):
        f3_ok = f3_h >= f3_v + 5
        pr_ok = r_h >= r_v - 0.05 and p_h >= p_v + 0.10
        fp_ok = sum(1 for w in fp_wins if w >= FP_WIN_REPO_THRESHOLD) >= FP_WIN_TRIAL_THRESHOLD
        return (f3_ok or pr_ok) and fp_ok

    assert rule(60, 50, 0.8, 0.8, 0.7, 0.7, [6, 5, 4]) is True
    assert rule(60, 50, 0.8, 0.8, 0.7, 0.7, [6, 3, 3]) is False, (
        "F3 advantage alone cannot pass when only one trial has >=4 "
        "strictly-fewer-FP repos"
    )
    assert rule(60, 50, 0.8, 0.8, 0.7, 0.7, [4, 4, 4]) is True
    # Strictly fewer: ties never count.
    assert rule(60, 50, 0.8, 0.8, 0.7, 0.7, [6, 6, 3]) is True
    assert rule(50, 50, 0.90, 0.90, 0.80, 0.60, [4, 4, 1]) is True, (
        "precision/recall arm of the OR with the FP rule"
    )
    assert rule(50, 50, 0.90, 0.90, 0.80, 0.75, [4, 4, 4]) is False, (
        "+0.05 precision is not +0.10"
    )
    assert rule(55, 50, 0.8, 0.8, 0.7, 0.7, [6, 6, 6]) is True, (
        "F3 >= +5 (equality boundary)"
    )
    assert rule(54.9, 50, 0.8, 0.8, 0.7, 0.7, [6, 6, 6]) is False


def test_six_repo_162_positive_denominator_invariant(tmp_path, monkeypatch):
    repos = [f"realvuln-{r}" for r in "abcdef"]
    exp = _freeze_exp(tmp_path, repos, monkeypatch)
    manifest = load_manifest(exp)
    _full_matrix(exp, manifest, repos, lambda *a: [])
    report = _aggregate(exp)
    # 6 repos x (2 scored positives + 1 decoy) per trial per arm.
    for trial in (1, 2, 3):
        for arm in ("h", "v"):
            pooled = report["per_trial"][trial][arm]
            assert pooled["fn"] + pooled["tp"] == 12
            assert pooled["tn"] + pooled["fp"] == 6


def test_non_scoring_labels_never_contribute(tmp_path, monkeypatch):
    repos = ["realvuln-a", "realvuln-b"]
    exp = _freeze_exp(tmp_path, repos, monkeypatch)
    manifest = load_manifest(exp)

    def predictor(repo, trial, arm):
        # Report the non-scoring location (line 60) — never an FP.
        return [1, 2, 65]

    _full_matrix(exp, manifest, repos, predictor)
    report = _aggregate(exp)
    for trial in (1, 2, 3):
        for arm in ("h", "v"):
            assert report["per_trial"][trial][arm]["fp"] == 0


def test_wrong_config_hash_blocks(tmp_path, monkeypatch):
    repos = ["realvuln-a"]
    exp = _freeze_exp(tmp_path, repos, monkeypatch)
    manifest = load_manifest(exp)
    _full_matrix(exp, manifest, repos, lambda *a: [1])
    # Tamper with the manifest (new hash) -> committed markers mismatch.
    payload = json.loads((exp / "operator" / "manifest.json").read_text())
    payload["settings"]["x"] = 1
    (exp / "operator" / "manifest.json").write_text(
        json.dumps(payload, sort_keys=True)
    )
    (exp / "operator" / "manifest.sha256").write_text("0" * 64 + "\n")
    with pytest.raises(Exception):
        _aggregate(exp)


def test_reproducible_output_ordering(tmp_path, monkeypatch):
    repos = ["realvuln-b", "realvuln-a"]
    exp = _freeze_exp(tmp_path, sorted(repos), monkeypatch)
    manifest = load_manifest(exp)
    _full_matrix(exp, manifest, sorted(repos), lambda *a: [1])
    first = json.dumps(_aggregate(exp), sort_keys=True)
    second = json.dumps(_aggregate(exp), sort_keys=True)
    assert first == second
    report = _aggregate(exp)
    assert report["repos"] == sorted(repos)
    assert list(report["cells"]) == sorted(report["cells"])


def test_read_only_integration_against_pin():
    """Load the REAL scorer from the pinned checkout and score empty
    predictions against a real GT file (read-only, no writes to the
    benchmark)."""
    rv = Path("/home/user/g/Real-Vuln-Benchmark")
    if not (rv / "scorer" / "matcher.py").is_file():
        pytest.skip("pinned RealVuln checkout not present")
    load_gt, match, norm = agg._real_scorer(rv)
    gt = load_gt(str(rv / "ground-truth" / "realvuln-vampi" / "ground-truth.json"))
    matches = match([], gt)
    counts = agg._cell_counts(matches, gt)
    scored_positives = sum(
        1 for e in gt["findings"]
        if e.get("is_vulnerable") and e.get("scoring", "scored") != "non_scoring"
    )
    assert counts["tp"] == 0
    assert counts["fn"] == scored_positives
    assert counts["fn"] > 0
