from __future__ import annotations

import json
from pathlib import Path

import pytest

from codesec.run_paths import RunPaths


def test_run_paths_create_isolated_layout_and_manifest(tmp_path: Path) -> None:
    repo = tmp_path / "target"
    repo.mkdir()
    config = tmp_path / "duo.yaml"
    config.write_text("stages: {}\n")
    paths = RunPaths(tmp_path / "runs" / "run_1")

    manifest = paths.prepare(
        run_id="run_1",
        repo_path=repo,
        pipeline="duo-v1",
        config_path=config,
        resume=False,
    )

    assert paths.database == paths.root / "state.db"
    assert paths.results.is_dir()
    assert paths.work.is_dir()
    assert paths.logs.is_dir()
    assert json.loads(paths.manifest.read_text()) == manifest
    assert manifest["run_id"] == "run_1"
    assert manifest["pipeline"] == "duo-v1"
    assert len(manifest["config_sha256"]) == 64


def test_run_paths_refuse_reuse_without_exact_resume(tmp_path: Path) -> None:
    repo = tmp_path / "target"
    repo.mkdir()
    config = tmp_path / "duo.yaml"
    config.write_text("stages: {}\n")
    paths = RunPaths(tmp_path / "run")
    paths.prepare(
        run_id="run_1",
        repo_path=repo,
        pipeline="duo-v1",
        config_path=config,
        resume=False,
    )

    with pytest.raises(FileExistsError, match="--resume"):
        paths.prepare(
            run_id="run_1",
            repo_path=repo,
            pipeline="duo-v1",
            config_path=config,
            resume=False,
        )

    config.write_text("stages: {changed: true}\n")
    with pytest.raises(ValueError, match="config_sha256"):
        paths.prepare(
            run_id="run_1",
            repo_path=repo,
            pipeline="duo-v1",
            config_path=config,
            resume=True,
        )


def test_run_paths_resume_exact_manifest(tmp_path: Path) -> None:
    repo = tmp_path / "target"
    repo.mkdir()
    config = tmp_path / "duo.yaml"
    config.write_text("stages: {}\n")
    paths = RunPaths(tmp_path / "run")
    original = paths.prepare(
        run_id="run_1",
        repo_path=repo,
        pipeline="duo-v1",
        config_path=config,
        resume=False,
    )

    resumed = paths.prepare(
        run_id="run_1",
        repo_path=repo,
        pipeline="duo-v1",
        config_path=config,
        resume=True,
    )

    assert resumed == original
