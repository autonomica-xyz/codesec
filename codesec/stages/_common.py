"""Shared helpers for stage modules."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from codesec.config import HarnessConfig, ModelProfile, StageConfig
from codesec.state import StateDB


REPO_ROOT = Path(__file__).resolve().parent.parent.parent
PROMPTS = REPO_ROOT / "prompts"
SCHEMAS = REPO_ROOT / "schemas"
RESULTS = REPO_ROOT / "results"
WORK = REPO_ROOT / "work"


@dataclass
class StageContext:
    run_id: str
    repo_path: Path
    config: HarnessConfig
    # Optional operator context — when set, downstream prompts use them.
    live_target: dict | None = None    # {"url": "...", "credentials": {...}}
    scope_notes: str | None = None     # verbatim text appended to user_input
    run_results_root: Path | None = None
    run_work_root: Path | None = None
    # Cross-run catalogue (W8): path to the repo-scoped catalogue DB when
    # prior-carry is active, else None. Stages read it directly; the
    # orchestrator owns run-start/run-end catalogue maintenance.
    catalogue_db: Path | None = None
    # Upstream novelty check (W15): git URL/path of the upstream repo when
    # --upstream was passed, else None. Consumed by the report stage only —
    # orchestrator-side, never inside agent sandboxes.
    upstream: str | None = None

    def stage(self, name: str) -> StageConfig:
        return self.config.get(name)

    def profile(self, name: str) -> ModelProfile | None:
        return self.config.profile_for_stage(name)

    def extras(self) -> dict:
        """Optional fields merged into every agent's user_input."""
        out: dict = {}
        if self.live_target:
            out["live_target"] = self.live_target
        if self.scope_notes:
            out["scope_notes"] = self.scope_notes
        return out

    def prompt(self, name: str) -> Path:
        path = PROMPTS / f"{name}.md"
        if not path.exists():
            raise FileNotFoundError(f"Missing prompt: {path}")
        return path

    def schema(self, name: str) -> Path:
        path = SCHEMAS / f"{name}.schema.json"
        if not path.exists():
            raise FileNotFoundError(f"Missing schema: {path}")
        return path

    def results_dir(self, stage: str) -> Path:
        base = self.run_results_root or RESULTS / self.run_id
        d = base / stage
        d.mkdir(parents=True, exist_ok=True)
        return d

    def work_dir(self, stage: str, ref: str | None = None) -> Path:
        base = self.run_work_root or WORK / self.run_id
        d = base / stage / (ref or "default")
        d.mkdir(parents=True, exist_ok=True)
        return d


def truncated_recon_summary(full: dict, subsystem_filter: str | None = None) -> dict:
    """Pass only the architecture facts downstream agents need."""
    subsystems = full.get("subsystems", [])
    out: dict = {"architecture": full.get("architecture", {})}
    if subsystem_filter is not None:
        match = next(
            (s for s in subsystems if s.get("name") == subsystem_filter
             or subsystem_filter.startswith(s.get("path", "##nope##"))),
            None,
        )
        out["subsystems"] = [match] if match is not None else []
        out["subsystem_for_task"] = match
    else:
        out["subsystems"] = subsystems
    return out


# Dead-end digest: rejected findings stay visible to the task-generating
# stages so Hunt never re-derives an already-refuted pattern. Bodies are
# capped to a one-line rejection reason — titles always, details never.
# (Idea from round_table digest.py: dead-ends must always be on the table.)
_REFUTED_RATIONALE_CAP = 200
_REFUTED_LIMIT = 60


def refuted_patterns_digest(db: StateDB, run_id: str) -> list[dict]:
    out: list[dict] = []
    for f in db.get_findings(run_id, validation_status="rejected"):
        rationale = " ".join(
            str((f.validation_json or {}).get("rationale") or "").split()
        )
        if len(rationale) > _REFUTED_RATIONALE_CAP:
            rationale = rationale[:_REFUTED_RATIONALE_CAP].rstrip() + " …"
        out.append({
            "vuln_class": f.vuln_class,
            "file": f.file,
            "rejected_because": rationale,
        })
        if len(out) >= _REFUTED_LIMIT:
            break
    return out
