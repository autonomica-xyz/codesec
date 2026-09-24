#!/usr/bin/env python3
"""Immutable experiment control plane (P07/P11).

New command contract:

  python -m bench.realvuln.experiment freeze --spec SPEC --output EXP
  python -m bench.realvuln.experiment run   --experiment EXP
  python -m bench.realvuln.experiment verify --experiment EXP
  python -m bench.realvuln.experiment preflight --spec SPEC --output DIR --offline

- ``freeze`` refuses an existing output directory; it hashes the canonical
  effective configuration (never a mutable YAML path alone) and writes
  operator/manifest.json + manifest.sha256.
- ``run`` executes (or resumes) the frozen cell schedule under one
  configuration hash; attempts are ledgered; outputs are committed
  atomically with completion records.
- ``verify`` checks ledger/artifact integrity and protocol consistency —
  never whether H wins.
- Cells are (experiment, corpus, repo, trial, arm); paths visible to
  agents use opaque ids only.

The layout (operator material never mounted into agents):

  EXP/
    operator/manifest.json, manifest.sha256, schedule.json,
          prepared-bundles.json, attempts.jsonl
    attempts/<opaque-attempt-id>/…
    committed/<opaque-cell-id>/completion.json + primary/secondary exports
    reports/…
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import secrets
import shutil
import subprocess
import sys
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from bench.realvuln.common import CODESEC_ROOT, write_json
from bench.realvuln.ledger import AttemptLedger

PROTOCOL_VERSION = 2
DEFAULT_SEED = 20260922
RUNS_ROOT = Path(
    os.environ.get("CODESEC_REALVULN_RUNS", str(CODESEC_ROOT / "bench" / "realvuln-runs"))
)

ARM_H = "h"
ARM_V = "v"
ARMS = (ARM_H, ARM_V)


class ExperimentError(RuntimeError):
    pass


# ---------------------------------------------------------------------------
# Run-root resolution (one resolver, honored everywhere)
# ---------------------------------------------------------------------------

def resolve_runs_root() -> Path:
    return RUNS_ROOT


def experiments_root() -> Path:
    return resolve_runs_root() / "experiments"


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sha256_tree(paths: dict[str, str]) -> str:
    """Canonical hash over name->content-hash pairs (sorted)."""
    blob = "\n".join(
        f"{sha256_file(Path(path))}  {name}" for name, path in sorted(paths.items())
    )
    return hashlib.sha256(blob.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------

def _source_hash_inputs() -> dict[str, str]:
    """Hash the implementation surface that determines behavior."""
    inputs: dict[str, str] = {}
    for pattern in ("codesec/*.py", "codesec/stages/*.py"):
        for path in sorted(CODESEC_ROOT.glob(pattern)):
            inputs[path.relative_to(CODESEC_ROOT).as_posix()] = str(path)
    for path in sorted((CODESEC_ROOT / "prompts").glob("*.md")):
        inputs["prompts/" + path.name] = str(path)
    for path in sorted((CODESEC_ROOT / "schemas").glob("*.json")):
        inputs["schemas/" + path.name] = str(path)
    for path in sorted((CODESEC_ROOT / "bench" / "realvuln").glob("*.py")):
        inputs["bench/realvuln/" + path.name] = str(path)
    for path in sorted((CODESEC_ROOT / "config").glob("*.yaml")):
        inputs["config/" + path.name] = str(path)
    return inputs


def _runtime_hash_inputs() -> dict[str, str]:
    """Everything whose bytes determine RUNTIME behavior (plan step D.3):
    the source surface plus dependency locks and the image-build inputs.
    Mutable reports/progress logs are deliberately excluded, so a
    documentation-only edit never invalidates runtime gates."""
    inputs = _source_hash_inputs()
    for name in ("pyproject.toml", "uv.lock"):
        path = CODESEC_ROOT / name
        if path.is_file():
            inputs[name] = str(path)
    return inputs


def runtime_identity(spec: dict | None = None) -> dict:
    """The runtime identity admission evidence must bind to."""
    inputs = _runtime_hash_inputs()
    identity = {
        "runtime_tree_sha256": sha256_tree(inputs),
        "inputs": sorted(inputs),
    }
    if spec:
        settings = spec.get("settings") or {}
        identity.update({
            "image_id": (spec.get("image") or {}).get("image_id"),
            "benchmark_pin": spec.get("benchmark_pin"),
            "gateway_url": settings.get("gateway_url"),
            "effective_request_fingerprint": (
                (spec.get("effective_request") or {}).get(
                    "fingerprint_sha256"
                )
            ),
        })
    return identity


def build_manifest(spec: dict, *, experiment_id: str, expected_cells: list[dict],
                   schedule: list[dict]) -> dict:
    source_inputs = _source_hash_inputs()
    dirty = subprocess.run(
        ["git", "diff", "HEAD"], cwd=str(CODESEC_ROOT),
        capture_output=True, text=True,
    ).stdout
    manifest = {
        "protocol_version": PROTOCOL_VERSION,
        "experiment_id": experiment_id,
        "created_at": time.time(),
        "source": {
            "git_head": subprocess.run(
                ["git", "rev-parse", "HEAD"], cwd=str(CODESEC_ROOT),
                capture_output=True, text=True,
            ).stdout.strip(),
            "source_tree_sha256": sha256_tree(source_inputs),
            "source_files": sorted(source_inputs),
            "dirty_diff_sha256": hashlib.sha256(dirty.encode()).hexdigest(),
            "dirty_diff_bytes": len(dirty),
        },
        "benchmark_pin": spec.get("benchmark_pin"),
        "app_shas": spec.get("app_shas", {}),
        "cohort": spec.get("cohort", "regression"),
        "corpus": spec.get("corpus"),
        "realvuln_root": spec.get("realvuln_root"),
        "frozen_repo_list": spec.get("repos"),
        "scored_label_counts": spec.get("scored_label_counts", {}),
        "non_scoring_label_counts": spec.get("non_scoring_label_counts", {}),
        "settings": spec.get("settings", {}),
        "effective_request": spec.get("effective_request"),
        "report": spec.get("report", {}),
        "budgets": spec.get("budgets", {}),
        "expected_cells": expected_cells,
        "schedule": {
            "seed": spec.get("seed", DEFAULT_SEED),
            "order": schedule,
        },
        "retry_rules": {
            "model_call_transient_retries_max": 3,
            "setup_failure_retry_max": 1,
            "no_retry_for": [
                "task_failure", "poor_recall", "fallback", "no_findings",
            ],
            "first_inference_attempt_is_operational_primary": True,
        },
        "failure_scoring": spec.get("failure_scoring", {}),
        "primary_metric": spec.get("primary_metric"),
        "thresholds": spec.get("thresholds", {}),
        "secondary_analyses": spec.get("secondary_analyses", []),
        "image": spec.get("image"),
        "isolation_evidence_sha256": spec.get("isolation_evidence_sha256"),
        "admission": {
            "purpose": admission_purpose(spec),
            "evidence": {
                name: {
                    "path": (ref or {}).get("path"),
                    "sha256": (ref or {}).get("sha256"),
                }
                for name, ref in (
                    spec.get("admission") or {}
                ).items()
                if isinstance(ref, dict)
            },
        },
        "runtime": runtime_identity(spec),
        "no_secrets": True,
    }
    canonical = json.dumps(manifest, sort_keys=True, ensure_ascii=False)
    manifest["manifest_sha256"] = hashlib.sha256(canonical.encode()).hexdigest()
    return manifest


def load_manifest(exp: Path) -> dict:
    manifest = json.loads((exp / "operator" / "manifest.json").read_text())
    recorded = (exp / "operator" / "manifest.sha256").read_text().strip()
    recorded_in_doc = manifest.pop("manifest_sha256", None)
    canonical = json.dumps(manifest, sort_keys=True, ensure_ascii=False)
    actual = hashlib.sha256(canonical.encode()).hexdigest()
    if actual != recorded or recorded != recorded_in_doc:
        raise ExperimentError(
            f"manifest hash mismatch: recorded {recorded} != actual {actual}"
        )
    manifest["manifest_sha256"] = recorded
    return manifest


# ---------------------------------------------------------------------------
# Schedule (P11 algorithm)
# ---------------------------------------------------------------------------

def build_schedule(repos: list[str], trials: tuple[int, ...] = (1, 2, 3),
                   seed: int = DEFAULT_SEED) -> list[dict]:
    """Sort slugs; per repo three paired blocks; H-first for 2 of every 3
    seeded-selected repos (counterbalanced 9 H-first / 9 V-first overall);
    random order assignment to trials; shuffle the 18 blocks with the
    recorded seed. No temporal order chosen from outcomes."""
    rng = random.Random(seed)
    ordered = sorted(repos)
    # Seeded selection of which repos get 2 H-first blocks (the others 1).
    h_first_counts = {repo: 1 for repo in ordered}
    for repo in rng.sample(ordered, len(ordered) // 2):
        h_first_counts[repo] = 2
    blocks: list[dict] = []
    orders: dict[str, list[str]] = {}
    for repo in ordered:
        repo_orders: list[str] = []
        h_blocks = h_first_counts[repo]
        v_blocks = len(trials) - h_blocks
        repo_orders = [ARM_H] * h_blocks + [ARM_V] * v_blocks
        rng.shuffle(repo_orders)
        orders[repo] = repo_orders
    for trial in trials:
        for repo in ordered:
            first_arm = orders[repo].pop(0)  # consume the repo's assignment
            blocks.append({
                "repo": repo, "trial": trial,
                "first_arm": first_arm,
                "arm_sequence": (
                    [ARM_H, ARM_V] if first_arm == ARM_H
                    else [ARM_V, ARM_H]
                ),
            })
    rng.shuffle(blocks)
    return blocks


def expected_cells_from_schedule(schedule: list[dict]) -> list[dict]:
    cells = []
    for block in schedule:
        for arm in ARMS:
            cells.append({
                "repo": block["repo"], "trial": block["trial"], "arm": arm,
                "cell_id": cell_id_of(block["repo"], block["trial"], arm),
            })
    return sorted(cells, key=lambda c: (c["repo"], c["trial"], c["arm"]))


def cell_id_of(repo: str, trial: int, arm: str) -> str:
    """Opaque cell id — agents never see repo names."""
    return hashlib.sha256(
        f"{repo}\x00{trial}\x00{arm}".encode()
    ).hexdigest()[:16]


# ---------------------------------------------------------------------------
# freeze
# ---------------------------------------------------------------------------

def validate_spec(spec: dict) -> list[str]:
    """Freeze gate: the spec must be COMPLETE before a manifest exists —
    a freeze that skips validation admits a scored run on a partial
    contract. Returns a list of problems (empty = admissible)."""
    problems: list[str] = []
    for key in (
        "protocol_version", "benchmark_pin", "repos", "seed", "settings",
        "effective_request", "report", "budgets", "failure_scoring",
        "primary_metric", "thresholds",
    ):
        if key not in spec:
            problems.append(f"missing required spec key: {key}")
    effective = spec.get("effective_request") or {}
    for key in (
        "model", "request_params", "temperature", "max_tokens",
        "context_limit", "stream", "fingerprint_sha256",
    ):
        if key not in effective:
            problems.append(f"effective_request missing: {key}")
    params = effective.get("request_params") or {}
    if "top_p" in params or "top_p" in effective:
        problems.append("effective_request must not carry top_p")
    settings = spec.get("settings") or {}
    for key in ("gateway_url", "model", "temperature",
                "max_output_tokens_per_request", "wall_ceiling_s"):
        if key not in settings:
            problems.append(f"settings missing: {key}")
    # Cross-check frozen request settings vs the effective-request record —
    # a spec whose two halves disagree is a config mismatch by definition.
    if settings.get("model") and effective.get("model") and (
        settings["model"] != effective["model"]
    ):
        problems.append(
            f"settings.model {settings['model']!r} != "
            f"effective_request.model {effective['model']!r}"
        )
    if (
        "temperature" in settings and "temperature" in effective
        and settings["temperature"] != effective["temperature"]
    ):
        problems.append("settings.temperature != effective_request.temperature")
    if (
        settings.get("max_output_tokens_per_request")
        and effective.get("max_tokens")
        and settings["max_output_tokens_per_request"]
        != effective["max_tokens"]
    ):
        problems.append(
            "settings.max_output_tokens_per_request != "
            "effective_request.max_tokens"
        )
    scored = admission_purpose(spec) == "scored"
    if spec.get("repos"):
        image = spec.get("image")
        if not isinstance(image, dict) or not image.get("image_id"):
            problems.append(
                ("scored" if scored else "calibration")
                + " freeze with repos requires an immutable image_id "
                "(a mutable tag alone is not admissible)"
            )
        # Isolation/calibration/preflight evidence is enforced by
        # validate_admission (real file references, contents verified) —
        # the legacy isolation_evidence_sha256 string is no longer
        # sufficient NOR required.
        if not spec.get("realvuln_root") and not settings.get(
            "realvuln_root"
        ):
            problems.append(
                "freeze with repos requires realvuln_root"
            )
    return problems


def _image_profile_endpoints(image_id: str) -> set[str]:
    """The gateway endpoints the pinned image's baked stage config will
    actually use for the H arm. ``runner`` prefers the model-profile
    endpoint over CODESEC_BASE_URL, so THIS — not spec.gateway_url alone —
    is what H really dials. A spec that names a different gateway is a
    config mismatch and must not freeze."""
    result = subprocess.run(
        [
            "docker", "run", "--rm", "--network", "none",
            "--read-only", image_id,
            "cat",
            "/usr/local/lib/python3.13/site-packages/config/stages.yaml",
        ],
        capture_output=True, text=True, check=False,
    )
    if result.returncode != 0:
        raise SystemExit(
            f"cannot read baked stage config from pinned image "
            f"{image_id}: {result.stderr.strip()[:300]}"
        )
    import yaml

    cfg = yaml.safe_load(result.stdout) or {}
    return {
        str(profile.get("endpoint", "")).rstrip("/")
        for profile in (cfg.get("model_profiles") or {}).values()
        if profile.get("endpoint")
    }


def cmd_freeze(args: argparse.Namespace) -> int:
    spec_path = Path(args.spec).resolve()
    exp = Path(args.output).resolve()
    if exp.exists():
        raise SystemExit(
            f"freeze refuses an existing output: {exp} (resume starts at "
            "`run`, or choose the next unused numeric suffix and document why)"
        )
    spec = json.loads(spec_path.read_text())
    problems = validate_spec(spec)
    # Admission gate (plan step D): evidence references must resolve to
    # REAL, verified artifacts bound to this runtime — never a bare hash.
    problems.extend(validate_admission(spec))
    if problems:
        raise SystemExit(
            "spec failed freeze validation:\n  - " + "\n  - ".join(problems)
        )
    # A scored freeze must be able to verify the benchmark pin and resolve
    # the pinned image NOW — deferring these to first cell execution would
    # let an invalid protocol produce partial cells.
    if spec.get("repos"):
        from bench.realvuln.isolation import resolve_image_id, verify_pin
        realvuln = Path(
            spec.get("realvuln_root")
            or spec.get("settings", {}).get("realvuln_root")
        )
        verify_pin(realvuln, expected_sha=spec["benchmark_pin"])
        resolved = resolve_image_id(spec["image"]["image_id"])
        if resolved != spec["image"]["image_id"]:
            raise SystemExit(
                f"pinned image_id {spec['image']['image_id']} resolves to "
                f"{resolved} locally — refusing to freeze"
            )
        spec = dict(spec)
        spec["image"] = {**spec["image"], "resolved_image_id": resolved}
        # The H arm dials the model-profile endpoint baked into the pinned
        # image, not settings.gateway_url — refuse to freeze a spec whose
        # declared gateway disagrees with what H will actually use.
        endpoints = _image_profile_endpoints(resolved)
        declared = spec["settings"].get("gateway_url", "").rstrip("/")
        if endpoints != {declared}:
            raise SystemExit(
                f"settings.gateway_url {declared!r} does not match the "
                f"pinned image's baked profile endpoints {sorted(endpoints)}"
                f" — H would not dial the declared gateway"
            )
    trials = tuple(spec.get("trials", (1, 2, 3)))
    schedule = build_schedule(spec["repos"], trials=trials,
                              seed=int(spec.get("seed", DEFAULT_SEED)))
    expected_cells = expected_cells_from_schedule(schedule)
    manifest = build_manifest(spec, experiment_id=exp.name,
                              expected_cells=expected_cells, schedule=schedule)
    (exp / "operator").mkdir(parents=True)
    write_json(exp / "operator" / "manifest.json", manifest)
    (exp / "operator" / "manifest.sha256").write_text(
        manifest["manifest_sha256"] + "\n"
    )
    # Immutable operator-owned copies of every verified admission evidence
    # document (plan step D.4): later edits to the originals can never
    # rewrite what this experiment was admitted on.
    admission_dir = exp / "operator" / "admission"
    admission_dir.mkdir()
    for name, ref in (spec.get("admission") or {}).items():
        if isinstance(ref, dict) and ref.get("path"):
            src = Path(ref["path"])
            if src.is_file():
                shutil.copyfile(src, admission_dir / f"{name}.json")
    # Per-input digests so a later drift error can NAME what changed.
    write_json(
        exp / "operator" / "runtime-inputs.json",
        {
            name: sha256_file(Path(path))
            for name, path in _runtime_hash_inputs().items()
        },
    )
    write_json(
        exp / "operator" / "schedule.json",
        {"seed": manifest["schedule"]["seed"], "blocks": schedule},
    )
    (exp / "attempts").mkdir()
    (exp / "committed").mkdir()
    (exp / "reports").mkdir()
    print(f"frozen: {exp}")
    print(f"manifest sha256: {manifest['manifest_sha256']}")
    print(f"expected cells: {len(expected_cells)}")
    return 0


# ---------------------------------------------------------------------------
# Admission evidence (plan step D): reference REAL artifacts, verify their
# contents, and bind them to the runtime identity being frozen.
# ---------------------------------------------------------------------------

def admission_purpose(spec: dict) -> str:
    """Explicit purpose wins; otherwise a spec carrying repos is a scored
    matrix and is held to scored admission — never silently relaxed."""
    purpose = spec.get("purpose")
    if purpose in ("calibration", "scored"):
        return purpose
    return "scored" if spec.get("repos") else "calibration"


def _verify_evidence_reference(
    ref: object, name: str
) -> tuple[list[str], dict | None, Path | None]:
    """Resolve one evidence reference: the file must exist, the recorded
    digest must match the actual bytes, and the document must parse. A
    nonempty or all-zero hash string alone is not evidence."""
    if not isinstance(ref, dict):
        return ([f"admission evidence {name}: missing reference object"],
                None, None)
    path_s = ref.get("path")
    digest = ref.get("sha256")
    if not path_s or not isinstance(path_s, str):
        return ([f"admission evidence {name}: missing path"], None, None)
    path = Path(path_s)
    if not isinstance(digest, str) or len(digest) != 64 or (
        set(digest) - set("0123456789abcdef")
    ):
        return ([
            f"admission evidence {name}: sha256 must be a 64-hex digest "
            f"(got {digest!r})",
        ], None, None)
    if not path.is_file():
        return ([
            f"admission evidence {name}: file not found: {path}",
        ], None, None)
    actual = sha256_file(path)
    if actual != digest:
        return ([
            f"admission evidence {name}: digest mismatch (recorded "
            f"{digest[:16]}… != actual {actual[:16]}…)",
        ], None, None)
    try:
        document = json.loads(path.read_text())
    except json.JSONDecodeError as error:
        return ([
            f"admission evidence {name}: corrupt JSON: {error}",
        ], None, None)
    if not isinstance(document, dict):
        return ([
            f"admission evidence {name}: document is not a JSON object",
        ], None, None)
    return ([], document, path)


def _check_gates(document: dict, name: str) -> list[str]:
    """Every gate in an evidence document must be passed — skipped,
    missing, failed, or not_run gates do not pass."""
    problems: list[str] = []
    passed_flag = document.get("passed")
    status = document.get("status")
    if passed_flag is not True and status not in ("passed", "completed"):
        problems.append(
            f"admission evidence {name}: overall status is neither passed "
            f"nor completed (passed={passed_flag!r}, status={status!r})"
        )
    gates = document.get("gates") or document.get("checks")
    if isinstance(gates, list):
        for gate in gates:
            if not isinstance(gate, dict):
                continue
            gate_status = gate.get("status", gate.get("passed"))
            if gate_status is not True and gate_status != "passed":
                problems.append(
                    f"admission evidence {name}: gate "
                    f"{gate.get('name', '?')} is {gate_status!r}"
                )
    return problems


def _check_image_binding(document: dict, name: str, spec: dict) -> list[str]:
    image_id = (spec.get("image") or {}).get("image_id")
    recorded = document.get("image_id")
    if recorded is not None and image_id and recorded != image_id:
        return [
            f"admission evidence {name}: produced against image "
            f"{recorded} but the spec freezes {image_id} — stale evidence"
        ]
    return []


def _check_runtime_binding(document: dict, name: str, spec: dict) -> list[str]:
    recorded = document.get("runtime_tree_sha256")
    current = runtime_identity(spec)["runtime_tree_sha256"]
    if not recorded:
        return [
            f"admission evidence {name}: does not record the runtime "
            "tree hash it was produced under — cannot bind to the frozen "
            "runtime"
        ]
    if recorded != current:
        return [
            f"admission evidence {name}: produced under runtime tree "
            f"{recorded[:16]}… but freezing {current[:16]}… — stale "
            "evidence"
        ]
    return []


def validate_admission(spec: dict) -> list[str]:
    """Freeze admission gate (plan step D.1/D.2). Calibration admission
    needs valid settings, real isolation evidence, and prerequisites; it
    cannot require its own future completion. Scored admission
    additionally requires a completed calibration record and a fully
    passed preflight, each bound to the runtime identity being frozen."""
    purpose = admission_purpose(spec)
    problems: list[str] = []
    admission = spec.get("admission")
    if not isinstance(admission, dict):
        return [
            f"{purpose} admission requires an 'admission' block with "
            "evidence file references (a bare hash string is not evidence)"
        ]

    refs = [("isolation_evidence", admission.get("isolation_evidence"))]
    if purpose == "scored":
        refs.append((
            "calibration_evidence", admission.get("calibration_evidence")
        ))
        refs.append((
            "preflight_record", admission.get("preflight_record")
        ))
    for name, ref in refs:
        ref_problems, document, _path = _verify_evidence_reference(ref, name)
        problems.extend(ref_problems)
        if document is None:
            continue
        problems.extend(_check_gates(document, name))
        problems.extend(_check_image_binding(document, name, spec))
        if name != "isolation_evidence":
            # Isolation evidence binds via image_id; the other records must
            # bind the full runtime tree they were produced under.
            problems.extend(_check_runtime_binding(document, name, spec))
    if purpose == "scored":
        calib = admission.get("calibration_evidence")
        if isinstance(calib, dict) and Path(str(calib.get("path", ""))).is_file():
            try:
                document = json.loads(Path(calib["path"]).read_text())
                if not document.get("experiment_ids"):
                    problems.append(
                        "admission evidence calibration_evidence: no "
                        "experiment ids recorded"
                    )
            except (json.JSONDecodeError, OSError):
                pass
    return problems


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------

def _config_hash(manifest: dict) -> str:
    return manifest["manifest_sha256"]


def _completion_marker(committed_cell: Path) -> Path:
    return committed_cell / "completion.json"


def arm_done(committed_cell: Path, *, manifest: dict,
             arm: str, repo: str, trial: int,
             cell_id: str | None = None,
             experiment_id: str | None = None) -> dict:
    """Verify completion: marker + artifact hashes + schema shape +
    matching experiment/config/cell identity. A leftover file or truncated
    JSON is NOT completion and must not block an eligible retry.

    When ``cell_id``/``experiment_id`` are supplied (the shared validity
    path always supplies them) the marker's OWN identity fields are
    compared — a marker naming another repo/cell/experiment is a wrong-
    identity completion even when every artifact hash matches (review
    finding 3)."""
    marker_path = _completion_marker(committed_cell)
    if not marker_path.is_file():
        return {"done": False, "reason": "missing completion marker"}
    try:
        marker = json.loads(marker_path.read_text())
    except json.JSONDecodeError:
        return {"done": False, "reason": "corrupt completion marker"}
    if marker.get("manifest_sha256") != manifest["manifest_sha256"]:
        return {"done": False, "reason": "config hash mismatch"}
    if marker.get("arm") != arm or marker.get("trial") != trial:
        return {"done": False, "reason": "cell identity mismatch"}
    if marker.get("repo") != repo:
        return {"done": False, "reason": "marker repo identity mismatch"}
    if cell_id is not None and marker.get("cell_id") != cell_id:
        return {"done": False, "reason": "marker cell_id identity mismatch"}
    if (
        experiment_id is not None
        and marker.get("experiment_id") != experiment_id
    ):
        return {
            "done": False,
            "reason": "marker experiment identity mismatch",
        }
    # The primary artifact must be DECLARED (absence of the key is not
    # skippable); the H arm must also declare its secondary export.
    required = ("primary",) if arm == ARM_V else ("primary", "secondary")
    for key in ("primary", "secondary"):
        name = marker.get(f"{key}_path")
        if not name:
            if key in required:
                return {"done": False, "reason": f"undeclared {key} artifact"}
            continue
        artifact = committed_cell / name
        if not artifact.is_file():
            return {"done": False, "reason": f"missing {key} artifact"}
        try:
            json.loads(artifact.read_text())
        except json.JSONDecodeError:
            return {"done": False, "reason": f"truncated {key} artifact"}
        if sha256_file(artifact) != marker.get(f"{key}_sha256"):
            return {"done": False, "reason": f"{key} hash mismatch"}
    return {"done": True, "marker": marker}


def commit_cell_outputs(
    *,
    exp: Path,
    manifest: dict,
    cell: dict,
    attempt_id: str,
    export_dir: Path,
    files: dict[str, Path],
) -> Path:
    """Validate → hash → atomic rename into committed/<cell>/ + completion
    record. The completion record is the final commit marker.

    A committed dir that already exists WITH a valid marker is a double
    commit — refused. A committed dir WITHOUT a valid marker is a crashed
    partial commit (the staging rename is atomic, the marker write is not):
    it is stale, removed, and re-committed — never allowed to permanently
    wedge a cell."""
    committed_cell = exp / "committed" / cell["cell_id"]
    if committed_cell.exists():
        stale_marker = _completion_marker(committed_cell)
        valid_marker = False
        if stale_marker.is_file():
            try:
                valid_marker = (
                    json.loads(stale_marker.read_text()).get(
                        "manifest_sha256"
                    ) == manifest["manifest_sha256"]
                )
            except json.JSONDecodeError:
                valid_marker = False
        if valid_marker:
            raise ExperimentError(
                f"committed cell already exists: {committed_cell} "
                "(two controllers cannot commit one cell twice)"
            )
        shutil.rmtree(committed_cell)  # crashed partial commit — stale
    (exp / "committed").mkdir(parents=True, exist_ok=True)
    (exp / "attempts").mkdir(parents=True, exist_ok=True)
    staging = exp / "attempts" / attempt_id / "export-staging"
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True)
    marker_files: dict[str, str] = {}
    for role, src in files.items():
        payload = json.loads(src.read_text())  # schema-shape check: valid JSON
        dest = staging / src.name
        shutil.copyfile(src, dest)
        marker_files[role] = {
            "name": src.name,
            "sha256": sha256_file(dest),
        }
    os.rename(staging, committed_cell)
    marker = {
        "experiment_id": manifest["experiment_id"],
        "manifest_sha256": manifest["manifest_sha256"],
        "cell_id": cell["cell_id"],
        "repo": repo_only(exp, manifest, cell),  # operator-side only
        "trial": cell["trial"],
        "arm": cell["arm"],
        "attempt_id": attempt_id,
        "committed_at": time.time(),
        **{f"{role}_path": meta["name"] for role, meta in marker_files.items()},
        **{f"{role}_sha256": meta["sha256"] for role, meta in marker_files.items()},
    }
    # completion.json written AFTER the artifacts are in place — the marker
    # is the commit point.
    marker_path = _completion_marker(committed_cell)
    tmp = committed_cell / ".completion.tmp"
    tmp.write_text(json.dumps(marker, indent=2, sort_keys=True) + "\n")
    os.rename(tmp, marker_path)
    return marker_path


def repo_only(exp: Path, manifest: dict, cell: dict) -> str:
    """Resolve the repo name from the manifest's expected cells (operator
    side; never passed into the agent container)."""
    for expected in manifest["expected_cells"]:
        if expected["cell_id"] == cell["cell_id"]:
            return expected["repo"]
    raise ExperimentError(f"cell {cell['cell_id']} not in manifest")


# ---------------------------------------------------------------------------
# Shared cell validity (plan step C): one check used by BOTH verify and
# aggregation. Attempt selection (the immutable operational primary) is
# kept separate from cell/experiment validity: a later protocol
# invalidation blocks scoring without replacing the primary or rewriting
# history.
# ---------------------------------------------------------------------------

#: problem classes: 'integrity' and 'invalid' block verify AND headline;
#: 'incomplete' withholds the headline (experiment not finished) without
#: claiming corrupt evidence.
INTEGRITY = "integrity"
INVALID = "invalid"
INCOMPLETE = "incomplete"


def cell_validity(
    exp: Path,
    manifest: dict,
    cell: dict,
    *,
    ledger: AttemptLedger | None = None,
) -> dict:
    """Structured validity of one expected cell.

    Returns {mode, valid, problems, incomplete, marker, state,
    primary_path} where ``mode`` is one of:

    - ``committed``: valid marker + artifacts + ledger backing. The
      document is scored and the cell keeps its actual health status.
    - ``no_output``: inference-bearing terminal failure with NO committed
      evidence — genuinely empty predictions (operational failure).
    - ``setup_failed``: retries did not reach inference — the experiment
      is incomplete; no headline.
    - ``invalidated`` / ``unaccounted`` / ``wrong_state`` / ``integrity``:
      see the returned problems.
    """
    exp = Path(exp)
    if ledger is None:
        ledger = AttemptLedger(
            exp / "operator" / "attempts.jsonl",
            experiment_id=manifest["experiment_id"],
            config_hash=_config_hash(manifest),
        )
    committed_cell = exp / "committed" / cell["cell_id"]
    problems: list[tuple[str, str]] = []
    incomplete = False

    marker_exists = _completion_marker(committed_cell).is_file()
    done = arm_done(
        committed_cell,
        manifest=manifest,
        arm=cell["arm"],
        repo=cell["repo"],
        trial=cell["trial"],
        cell_id=cell["cell_id"],
        experiment_id=manifest["experiment_id"],
    )

    # Any protocol invalidation anywhere in the cell's history blocks
    # scoring — regardless of which attempt is the operational primary.
    records = ledger.records(cell["cell_id"])
    ends = [r for r in records if r.get("type") == "attempt_end"]
    invalidated = [
        r for r in ends if r.get("status") == "invalidated"
    ]
    state = ledger.terminal_state(cell["cell_id"])

    if invalidated:
        problems.append((
            INVALID,
            f"cell {cell['cell_id']}: protocol invalidation recorded "
            f"({invalidated[0].get('reason_code', 'unknown')}) — comparison "
            "invalidated",
        ))

    if done["done"]:
        marker = done["marker"]
        if state is None:
            problems.append((
                INTEGRITY,
                f"cell {cell['cell_id']}: committed artifact has no "
                "terminal ledger state",
            ))
        else:
            if state.get("attribution_inconsistent"):
                problems.append((
                    INVALID,
                    f"cell {cell['cell_id']}: inconsistent inference "
                    "attribution",
                ))
            marker_attempt = marker.get("attempt_id")
            if marker_attempt and state.get("attempt_id") != marker_attempt:
                problems.append((
                    INTEGRITY,
                    f"cell {cell['cell_id']}: committed attempt "
                    f"{marker_attempt} is not the operational primary "
                    f"({state.get('attempt_id')})",
                ))
            if state.get("status") == "failed_no_output":
                problems.append((
                    INTEGRITY,
                    f"cell {cell['cell_id']}: terminal state records no "
                    "output, yet committed artifacts exist — inconsistent",
                ))
        mode = "committed"
        valid = not problems
        return {
            "mode": mode,
            "valid": valid,
            "problems": problems,
            "incomplete": False,
            "marker": marker,
            "state": state,
            "primary_path": committed_cell / marker["primary_path"],
        }

    # No valid completion marker.
    if marker_exists or (
        committed_cell.exists()
        and any(committed_cell.iterdir())
    ):
        # A completion.json that fails validation, or committed debris
        # without a commit point, is CORRUPT/INCONSISTENT committed
        # evidence — never "absence of output".
        problems.append((
            INTEGRITY,
            f"cell {cell['cell_id']}: committed evidence present but "
            f"invalid ({done['reason']}) — integrity failure",
        ))
        return {
            "mode": "integrity",
            "valid": False,
            "problems": problems,
            "incomplete": False,
            "marker": None,
            "state": state,
            "primary_path": None,
        }

    if state is None:
        problems.append((
            INTEGRITY,
            f"cell {cell['cell_id']} ({cell['repo']} t{cell['trial']} "
            f"{cell['arm']}) has no terminal ledger state",
        ))
        return {
            "mode": "unaccounted", "valid": False, "problems": problems,
            "incomplete": True, "marker": None, "state": None,
            "primary_path": None,
        }

    if state.get("attribution_inconsistent") or (
        state.get("made_inference_requests") is None
    ):
        problems.append((
            INVALID,
            f"cell {cell['cell_id']}: inference attribution unknown or "
            "inconsistent — invalid",
        ))
        return {
            "mode": "invalid", "valid": False, "problems": problems,
            "incomplete": False, "marker": None, "state": state,
            "primary_path": None,
        }

    status = state.get("status")
    if status == "setup_failed":
        incomplete = True
        problems.append((
            INCOMPLETE,
            f"cell {cell['cell_id']}: setup failure with zero inference "
            "— experiment incomplete",
        ))
        return {
            "mode": "setup_failed", "valid": False, "problems": problems,
            "incomplete": True, "marker": None, "state": state,
            "primary_path": None,
        }
    if status == "failed_no_output":
        # Honest accounted absence: inference happened, no eligible output
        # was ever committed. NOT a problem — empty predictions.
        return {
            "mode": "no_output", "valid": not problems, "problems": problems,
            "incomplete": False, "marker": None, "state": state,
            "primary_path": None,
        }
    # completed / failed_output terminal state WITHOUT valid committed
    # artifacts: the ledger says output existed, so missing evidence is an
    # integrity failure, not an empty prediction.
    problems.append((
        INTEGRITY,
        f"cell {cell['cell_id']}: terminal state {status} without valid "
        "committed output — integrity failure",
    ))
    return {
        "mode": "wrong_state", "valid": False, "problems": problems,
        "incomplete": False, "marker": None, "state": state,
        "primary_path": None,
    }


def _drift_check(exp: Path, manifest: dict, *, pending_cells: list[dict]) -> None:
    """Runtime identity recheck before admitting NEW cells (plan step
    D.5), including on resume. Drift (or an unresolvable pinned image)
    stops new admissions with a specific error — never a silent refreeze
    and never a continuation under changed code. Complete experiments
    have no pending cells, so historical verification/reanalysis is
    unaffected."""
    if not pending_cells:
        return
    runtime = manifest.get("runtime") or {}
    recorded = runtime.get("runtime_tree_sha256")
    if not recorded:
        raise SystemExit(
            "runtime drift check: frozen manifest predates runtime "
            "identity binding; cannot admit new cells — refreeze with a "
            "new experiment id instead of editing this one"
        )
    current_inputs = _runtime_hash_inputs()
    current = sha256_tree(current_inputs)
    if current != recorded:
        recorded_inputs = set(runtime.get("inputs") or [])
        current_names = set(current_inputs)
        changed = sorted(
            name for name in recorded_inputs & current_names
            if sha256_file(Path(current_inputs[name])) != _recorded_input_digest(
                exp, name
            )
        )
        added = sorted(current_names - recorded_inputs)
        removed = sorted(recorded_inputs - current_names)
        detail = ""
        if changed or added or removed:
            detail = (
                f" (changed: {changed[:5]}, added: {added[:5]}, "
                f"removed: {removed[:5]})"
            )
        raise SystemExit(
            f"runtime drift: current runtime tree {current[:16]}… != frozen "
            f"{recorded[:16]}…{detail} — refusing to admit new cells under "
            "changed code; freeze a new experiment instead"
        )
    image_id = (manifest.get("image") or {}).get(
        "resolved_image_id"
    ) or (manifest.get("image") or {}).get("image_id")
    if image_id:
        from bench.realvuln.isolation import resolve_image_id

        try:
            resolved = resolve_image_id(image_id)
        except Exception as error:  # noqa: BLE001
            raise SystemExit(
                f"runtime drift check: pinned image {image_id} no longer "
                f"resolves locally ({error}) — cannot admit new cells"
            ) from error
        if resolved != image_id:
            raise SystemExit(
                f"runtime drift check: pinned image {image_id} now resolves "
                f"to {resolved} — refusing to admit new cells"
            )


def _recorded_input_digest(exp: Path, name: str) -> str:
    """Digest of a runtime input recorded at freeze time (from the
    operator-owned evidence copy in operator/runtime-inputs.json)."""
    path = exp / "operator" / "runtime-inputs.json"
    if path.is_file():
        try:
            return (json.loads(path.read_text()) or {}).get(name, "?")
        except json.JSONDecodeError:
            return "?"
    return "?"


def cmd_run(args: argparse.Namespace) -> int:
    exp = Path(args.experiment).resolve()
    if not exp.is_dir():
        raise SystemExit(f"no such experiment: {exp}")
    manifest = load_manifest(exp)
    ledger = AttemptLedger(
        exp / "operator" / "attempts.jsonl",
        experiment_id=manifest["experiment_id"],
        config_hash=_config_hash(manifest),
    )
    schedule = json.loads((exp / "operator" / "schedule.json").read_text())
    # Frozen schedule: run must execute exactly the order recorded at
    # freeze — an edited schedule.json is a protocol breach, not a resume.
    if schedule.get("blocks") != manifest["schedule"]["order"] or (
        schedule.get("seed") != manifest["schedule"]["seed"]
    ):
        raise SystemExit(
            "schedule.json does not match the frozen manifest schedule — "
            "the frozen order is not editable between freeze and run"
        )
    from bench.realvuln.executor import execute_block

    # Which cells still need work? The runtime identity gate applies to
    # THOSE admissions (D.5) — completed cells keep their history.
    pending: list[dict] = []
    for block in schedule["blocks"]:
        for arm in block["arm_sequence"]:
            cell = {
                "repo": block["repo"], "trial": block["trial"], "arm": arm,
                "cell_id": cell_id_of(block["repo"], block["trial"], arm),
            }
            committed_cell = exp / "committed" / cell["cell_id"]
            done = arm_done(
                committed_cell, manifest=manifest, arm=arm,
                repo=cell["repo"], trial=cell["trial"],
                cell_id=cell["cell_id"],
                experiment_id=manifest["experiment_id"],
            )
            if done["done"]:
                continue
            if ledger.terminal_state(cell["cell_id"]):
                continue  # accounted terminal failure — no new admission
            pending.append(cell)
    _drift_check(exp, manifest, pending_cells=pending)

    failures: list[str] = []
    for block in schedule["blocks"]:
        for arm in block["arm_sequence"]:
            cell = {
                "repo": block["repo"], "trial": block["trial"], "arm": arm,
                "cell_id": cell_id_of(block["repo"], block["trial"], arm),
            }
            committed_cell = exp / "committed" / cell["cell_id"]
            done = arm_done(
                committed_cell, manifest=manifest, arm=arm,
                repo=cell["repo"], trial=cell["trial"],
                cell_id=cell["cell_id"],
                experiment_id=manifest["experiment_id"],
            )
            if done["done"]:
                continue  # idempotent resume
            outcome = execute_block(
                exp=exp, manifest=manifest, ledger=ledger, cell=cell,
                block=block,
            )
            if not outcome.get("ok"):
                failures.append(f"{cell['cell_id']}: {outcome.get('reason')}")
    if failures:
        print(f"run finished with failures ({len(failures)}):", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1
    print("all cells accounted")
    return 0


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------

def manifest_assignment_problems(manifest: dict) -> list[str]:
    """Structural problems with the frozen repo/trial/arm product:
    duplicate or missing assignments (plan step C.2)."""
    problems: list[str] = []
    ids = [c["cell_id"] for c in manifest["expected_cells"]]
    if len(ids) != len(set(ids)):
        problems.append("duplicate cell assignments in manifest")
    keys = [
        (c["repo"], c["trial"], c["arm"]) for c in manifest["expected_cells"]
    ]
    if len(keys) != len(set(keys)):
        problems.append(
            "duplicate (repo, trial, arm) assignments in manifest"
        )
    for cell in manifest["expected_cells"]:
        if cell.get("cell_id") != cell_id_of(
            cell["repo"], cell["trial"], cell["arm"]
        ):
            problems.append(
                f"cell_id does not match (repo, trial, arm) for "
                f"{cell['repo']} t{cell['trial']} {cell['arm']}"
            )
    return problems


def cmd_verify(args: argparse.Namespace) -> int:
    exp = Path(args.experiment).resolve()
    manifest = load_manifest(exp)
    problems: list[str] = list(manifest_assignment_problems(manifest))
    expected = {c["cell_id"]: c for c in manifest["expected_cells"]}
    committed_dir = exp / "committed"
    seen: set[str] = set()
    for cell_dir in sorted(committed_dir.iterdir()):
        if not cell_dir.is_dir():
            continue
        if cell_dir.name not in expected:
            problems.append(f"unexpected committed cell: {cell_dir.name}")
            continue
        if cell_dir.name in seen:
            problems.append(f"duplicate committed cell: {cell_dir.name}")
        seen.add(cell_dir.name)
    ledger = AttemptLedger(
        exp / "operator" / "attempts.jsonl",
        experiment_id=manifest["experiment_id"],
        config_hash=_config_hash(manifest),
    )
    # One shared validity check per expected cell (plan step C): verify
    # fails on integrity/invalidity. Incompleteness (a cell still pending
    # or setup-failed before inference) is an accounted outcome, not
    # corrupt evidence — it does not fail this command.
    for cell_id, cell in expected.items():
        validity = cell_validity(exp, manifest, cell, ledger=ledger)
        for cls, message in validity["problems"]:
            if cls != INCOMPLETE:
                problems.append(message)
    if problems:
        print(f"verify FAILED ({len(problems)} problems):", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 1
    print(f"verify OK: {len(expected)} cells complete and accounted")
    return 0


# ---------------------------------------------------------------------------
# preflight (P09 extends; basic offline form here)
# ---------------------------------------------------------------------------

def cmd_preflight(args: argparse.Namespace) -> int:
    from bench.realvuln.preflight import run_preflight
    spec = json.loads(Path(args.spec).read_text())
    report = run_preflight(spec, offline=bool(args.offline))
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    write_json(out / "preflight.json", report)
    failed = [g for g in report["gates"] if g["status"] == "failed"]
    not_run = [g for g in report["gates"] if g["status"] == "not_run"]
    print(f"preflight: {len(report['gates']) - len(failed) - len(not_run)} passed, "
          f"{len(failed)} failed, {len(not_run)} not_run")
    for gate in failed:
        print(f"  FAILED: {gate['name']}: {gate.get('detail', '')[:160]}")
    for gate in not_run:
        print(f"  NOT RUN: {gate['name']}")
    return 0 if not failed and not not_run else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    freeze = sub.add_parser(
        "freeze", help="freeze an experiment from a protocol spec"
    )
    freeze.add_argument("--spec", required=True)
    freeze.add_argument("--output", required=True)
    freeze.set_defaults(func=cmd_freeze)

    run = sub.add_parser("run", help="execute/resume the frozen schedule")
    run.add_argument("--experiment", required=True)
    run.set_defaults(func=cmd_run)

    verify = sub.add_parser("verify", help="verify ledger/artifact integrity")
    verify.add_argument("--experiment", required=True)
    verify.set_defaults(func=cmd_verify)

    preflight = sub.add_parser("preflight", help="offline/live gate checks")
    preflight.add_argument("--spec", required=True)
    preflight.add_argument("--output", required=True)
    preflight.add_argument("--offline", action="store_true", default=True)
    preflight.add_argument("--live", dest="offline", action="store_false")
    preflight.set_defaults(func=cmd_preflight)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
