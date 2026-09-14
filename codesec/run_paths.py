"""Isolated filesystem layout and immutable identity for one pipeline run."""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from pathlib import Path


_IDENTITY_FIELDS = (
    "run_id",
    "repo_path",
    "pipeline",
    "config_path",
    "config_sha256",
)


@dataclass(frozen=True)
class RunPaths:
    root: Path

    @property
    def database(self) -> Path:
        return self.root / "state.db"

    @property
    def results(self) -> Path:
        return self.root / "results"

    @property
    def work(self) -> Path:
        return self.root / "work"

    @property
    def logs(self) -> Path:
        return self.root / "logs"

    @property
    def manifest(self) -> Path:
        return self.root / "run-manifest.json"

    def prepare(
        self,
        *,
        run_id: str,
        repo_path: Path,
        pipeline: str,
        config_path: Path,
        resume: bool,
    ) -> dict:
        """Create a new run root or validate an exact resumable identity."""
        root = self.root.resolve()
        config = config_path.resolve()
        candidate = {
            "schema_version": 1,
            "run_id": run_id,
            "repo_path": str(repo_path.resolve()),
            "pipeline": pipeline,
            "config_path": str(config),
            "config_sha256": hashlib.sha256(config.read_bytes()).hexdigest(),
        }
        manifest_path = root / self.manifest.name

        if manifest_path.exists():
            existing = json.loads(manifest_path.read_text())
            if not resume:
                raise FileExistsError(
                    f"run root {root} already exists; pass --resume to reuse it"
                )
            mismatches = [
                field
                for field in _IDENTITY_FIELDS
                if existing.get(field) != candidate[field]
            ]
            if mismatches:
                raise ValueError(
                    "resume manifest mismatch: " + ", ".join(mismatches)
                )
            self._ensure_directories(root)
            return existing

        if resume:
            raise FileNotFoundError(
                f"cannot resume {root}: run-manifest.json is missing"
            )
        if root.exists() and any(root.iterdir()):
            raise FileExistsError(
                f"run root {root} is non-empty and has no run manifest"
            )

        self._ensure_directories(root)
        manifest = {**candidate, "created_at": time.time()}
        temporary = manifest_path.with_suffix(".json.tmp")
        temporary.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n"
        )
        temporary.replace(manifest_path)
        return manifest

    @staticmethod
    def _ensure_directories(root: Path) -> None:
        root.mkdir(parents=True, exist_ok=True)
        for name in ("results", "work", "logs"):
            (root / name).mkdir(parents=True, exist_ok=True)
