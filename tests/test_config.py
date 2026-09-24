"""Config loading test — make sure stages.yaml is valid."""

from __future__ import annotations

from pathlib import Path

import pytest

from codesec.config import HarnessConfig, load_config


def test_default_config_loads() -> None:
    cfg = load_config()
    for name in ["recon", "hunt", "validate", "gapfill", "dedupe", "trace",
                 "feedback", "report"]:
        sc = cfg.get(name)
        assert sc.model, f"{name}: missing model"
        assert sc.concurrency >= 1, f"{name}: invalid concurrency"
        assert sc.tools, f"{name}: missing tools"


def test_hunt_validate_model_diversity() -> None:
    """Hunt and Validate MUST use different models — the blog's
    'deliberate disagreement' rule."""
    cfg = load_config()
    assert cfg.get("hunt").model != cfg.get("validate").model


def test_validate_panel_rounds_parse_from_yaml(tmp_path: Path) -> None:
    """validate.rounds configures the review-panel size; default is a
    single pass (no arbiter)."""
    path = tmp_path / "rounds.yaml"
    path.write_text(
        """
stages:
  hunt:
    model: sonnet
    concurrency: 2
    tools: [Read]
  validate:
    model: opus
    concurrency: 1
    tools: [Read]
    rounds: 3
"""
    )

    assert load_config(path).get("validate").rounds == 3
    assert load_config().get("validate").rounds >= 1  # shipped default


def test_stage_profiles_resolve_distinct_local_endpoints(tmp_path: Path) -> None:
    path = tmp_path / "duo.yaml"
    path.write_text(
        """
defaults:
  max_turns: 10
  permission_mode: acceptEdits
  repair_attempts: 1
model_profiles:
  titus:
    engine: local
    endpoint: http://127.0.0.1:8080
    model: titus
    source: owner/titus@revision:titus.gguf
    temperature: 0
    max_output_tokens: 4096
  openmythos:
    engine: local
    endpoint: http://127.0.0.1:8081
    model: openmythos
    temperature: 0
    max_output_tokens: 3072
stages:
  hunt:
    profile: titus
    concurrency: 2
    tools: [Read, Grep]
  validate:
    profile: openmythos
    concurrency: 1
    tools: [Read]
loops:
  gapfill_iterations: 1
  feedback_iterations: 0
"""
    )

    config = load_config(path)

    assert config.get("hunt").model == "titus"
    assert config.profile_for_stage("hunt").endpoint.endswith(":8080")
    assert config.get("validate").model == "openmythos"
    assert config.profile_for_stage("validate").endpoint.endswith(":8081")


def test_model_profile_loads_managed_runtime_settings(tmp_path: Path) -> None:
    path = tmp_path / "managed.yaml"
    path.write_text(
        """
model_profiles:
  titus:
    engine: local
    endpoint: http://127.0.0.1:8080
    model: titus
    source: owner/titus@revision:titus.gguf
    model_path_env: CODESEC_TITUS_GGUF
    expected_sha256: abc123
    context_limit: 32768
    server_args: [--parallel, "4"]
stages:
  recon:
    profile: titus
    concurrency: 1
    tools: [Read]
"""
    )

    profile = load_config(path).profile_for_stage("recon")

    assert profile.model_path_env == "CODESEC_TITUS_GGUF"
    assert profile.source == "owner/titus@revision:titus.gguf"
    assert profile.expected_sha256 == "abc123"
    assert profile.context_limit == 32768
    assert profile.server_args == ("--parallel", "4")


def test_duo_config_pins_both_gguf_hashes() -> None:
    config = load_config(
        Path(__file__).resolve().parents[1] / "config" / "duo-v1.yaml"
    )

    for name in ("titus", "openmythos"):
        profile = config.model_profiles[name]
        assert profile.source and "@" in profile.source
        assert profile.expected_sha256
        assert len(profile.expected_sha256) == 64
        int(profile.expected_sha256, 16)


# ---- P02: explicit report policy / renderer settings ----

def test_report_policy_and_renderer_defaults_preserved(tmp_path):
    cfg = load_config(None)
    assert cfg.report_policy == "confirmed_all"
    assert cfg.report_renderer == "agent"


def test_report_policy_and_renderer_loaded_from_yaml(tmp_path):
    path = tmp_path / "stages.yaml"
    path.write_text(
        "defaults: {}\n"
        "stages:\n"
        "  recon:\n    model: m\n    concurrency: 1\n    tools: []\n"
        "report_policy: confirmed_reachable\n"
        "report_renderer: deterministic\n"
    )
    cfg = load_config(path)
    assert cfg.report_policy == "confirmed_reachable"
    assert cfg.report_renderer == "deterministic"


def test_unknown_report_policy_rejected(tmp_path):
    with pytest.raises(ValueError, match="unknown report_policy"):
        HarnessConfig(report_policy="whatever_scores_best")
    with pytest.raises(ValueError, match="unknown report_renderer"):
        HarnessConfig(report_renderer="silent")
