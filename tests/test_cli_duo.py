import json
from pathlib import Path

from click.testing import CliRunner

from codesec import cli
from codesec.cli import main
from codesec.runtime import ExternalRuntime


def test_run_help_exposes_duo_runtime_and_run_root() -> None:
    result = CliRunner().invoke(main, ["run", "--help"])

    assert result.exit_code == 0
    assert "--pipeline" in result.output
    assert "duo-v1" in result.output
    assert "--run-root" in result.output
    assert "--runtime" in result.output
    assert "--llama-server" in result.output


def test_status_and_report_accept_isolated_run_root() -> None:
    runner = CliRunner()

    status = runner.invoke(main, ["status", "--help"])
    report = runner.invoke(main, ["report", "--help"])

    assert status.exit_code == 0
    assert "--run-root" in status.output
    assert report.exit_code == 0
    assert "--run-root" in report.output


def test_duo_cli_uses_profile_config_and_isolated_paths_by_default(
    tmp_path: Path,
    monkeypatch,
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    run_root = tmp_path / "run"
    captured = {}

    async def fake_pipeline(**kwargs):
        captured.update(kwargs)
        return kwargs["run_results_root"] / "report" / "report.json"

    monkeypatch.setattr(cli, "run_pipeline", fake_pipeline)

    result = CliRunner().invoke(
        main,
        [
            "run",
            "--repo",
            str(target),
            "--pipeline",
            "duo-v1",
            "--run-id",
            "duo-test",
            "--run-root",
            str(run_root),
        ],
    )

    assert result.exit_code == 0, result.output
    manifest = json.loads((run_root / "run-manifest.json").read_text())
    assert manifest["pipeline"] == "duo-v1"
    assert manifest["config_path"].endswith("config/duo-v1.yaml")
    assert captured["pipeline"] == "duo-v1"
    assert captured["run_results_root"] == run_root / "results"
    assert captured["run_work_root"] == run_root / "work"
    assert isinstance(captured["runtime"], ExternalRuntime)
