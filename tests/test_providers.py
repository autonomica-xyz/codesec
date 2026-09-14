"""Tests for the provider-preset feature (z.ai / unsloth / anthropic)."""

from __future__ import annotations

import os

import pytest

from codesec import auth as auth_mod
from codesec.auth import AuthError, configure_auth
from codesec.config import load_config
from codesec.providers import (
    PROVIDERS,
    ProviderError,
    apply_provider_env,
    get_provider,
    role_model,
)


def _empty_env(tmp_path):
    p = tmp_path / ".env"
    p.write_text("")
    return p


def _monkeypatch_claude_cli(monkeypatch):
    # configure_auth requires a `claude` binary on PATH; stub it so the
    # provider path can be exercised without Claude Code installed.
    import shutil

    class _R:
        returncode = 0
        stdout = "stub 1.0"

    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/claude")
    monkeypatch.setattr(
        "codesec.auth.subprocess.run", lambda *a, **k: _R(), raising=False
    )


def test_provider_registry_has_expected_names():
    assert set(PROVIDERS) == {"anthropic", "zai", "unsloth"}


def test_zai_preset_speaks_anthropic_api():
    p = get_provider("zai")
    assert p.base_url == "https://api.z.ai/api/anthropic"
    assert p.opus_role_model == "glm-5.2"
    assert p.sonnet_role_model == "glm-4.7"
    assert "ZAI_API_KEY" in p.key_env_vars


def test_unsloth_preset_defaults_to_local_port():
    p = get_provider("unsloth")
    assert p.base_url.startswith("http://localhost")
    assert p.opus_role_model is None  # model is dynamic (loaded GGUF)


def test_role_model_classifies_by_family():
    zai = get_provider("zai")
    assert role_model(zai, "claude-opus-4-7") == "glm-5.2"
    assert role_model(zai, "claude-sonnet-4-6") == "glm-4.7"
    assert role_model(zai, "claude-haiku-4-5") == "glm-4.5-air"


def test_apply_provider_env_zai_sets_gateway_vars(monkeypatch):
    for v in ("ANTHROPIC_BASE_URL", "ANTHROPIC_AUTH_TOKEN",
              "ANTHROPIC_API_KEY", "ZAI_API_KEY", "CODESEC_API_KEY"):
        monkeypatch.delenv(v, raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "should-be-scrubbed")
    info = apply_provider_env(get_provider("zai"), api_key="zai-secret")
    assert info == {"provider": "zai", "applied": True,
                    "base_url": "https://api.z.ai/api/anthropic"}
    assert os.environ["ANTHROPIC_BASE_URL"] == "https://api.z.ai/api/anthropic"
    assert os.environ["ANTHROPIC_AUTH_TOKEN"] == "zai-secret"
    assert "ANTHROPIC_API_KEY" not in os.environ  # scrubbed (would outrank)


def test_apply_provider_env_resolves_key_from_env(monkeypatch):
    for v in ("ZAI_API_KEY", "CODESEC_API_KEY", "ANTHROPIC_AUTH_TOKEN",
              "ANTHROPIC_API_KEY"):
        monkeypatch.delenv(v, raising=False)
    monkeypatch.setenv("ZAI_API_KEY", "from-env")
    apply_provider_env(get_provider("zai"))
    assert os.environ["ANTHROPIC_AUTH_TOKEN"] == "from-env"


def test_apply_provider_env_unsloth_base_url_override(monkeypatch):
    for v in ("CODESEC_BASE_URL", "ANTHROPIC_BASE_URL"):
        monkeypatch.delenv(v, raising=False)
    apply_provider_env(get_provider("unsloth"), api_key="sk-unsloth-x",
                       base_url="http://localhost:9000")
    assert os.environ["ANTHROPIC_BASE_URL"] == "http://localhost:9000"


def test_apply_provider_env_anthropic_is_noop(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "keep-me")
    info = apply_provider_env(get_provider("anthropic"))
    assert info == {"provider": "anthropic", "applied": False}
    assert os.environ["ANTHROPIC_API_KEY"] == "keep-me"


def test_apply_provider_env_missing_key_raises(monkeypatch):
    for v in ("ZAI_API_KEY", "CODESEC_API_KEY", "ANTHROPIC_AUTH_TOKEN"):
        monkeypatch.delenv(v, raising=False)
    with pytest.raises(ProviderError):
        apply_provider_env(get_provider("zai"))


def test_unknown_provider_raises():
    with pytest.raises(ProviderError):
        get_provider("nope")


def test_config_apply_provider_models_zai_preserves_disagreement():
    cfg = load_config()
    cfg.apply_provider_models(get_provider("zai"))
    # Opus-role stages -> glm-5.2, sonnet-role -> glm-4.7.
    assert cfg.get("recon").model == "glm-5.2"
    assert cfg.get("validate").model == "glm-5.2"
    assert cfg.get("trace").model == "glm-5.2"
    assert cfg.get("hunt").model == "glm-4.7"
    assert cfg.get("report").model == "glm-4.7"
    # Deliberate disagreement survives: validate != hunt.
    assert cfg.get("validate").model != cfg.get("hunt").model


def test_config_apply_provider_models_explicit_overrides_all():
    cfg = load_config()
    cfg.apply_provider_models(get_provider("unsloth"),
                              explicit_model="unsloth/gemma-4-26B-A4B-it-GGUF")
    models = {s.model for s in cfg.stages.values()}
    assert models == {"unsloth/gemma-4-26B-A4B-it-GGUF"}


def test_config_apply_provider_models_unsloth_without_model_is_noop():
    # Unsloth has no role models and no explicit model -> stages stay claude-*,
    # which the CLI flags as a usage error.
    cfg = load_config()
    before = {n: s.model for n, s in cfg.stages.items()}
    cfg.apply_provider_models(get_provider("unsloth"))
    after = {n: s.model for n, s in cfg.stages.items()}
    assert before == after


def test_configure_auth_provider_zai_flow(monkeypatch, tmp_path):
    _monkeypatch_claude_cli(monkeypatch)
    for v in ("ANTHROPIC_API_KEY", "ANTHROPIC_BASE_URL", "ANTHROPIC_AUTH_TOKEN",
              "ZAI_API_KEY", "CODESEC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN"):
        monkeypatch.delenv(v, raising=False)
    status = configure_auth(
        _empty_env(tmp_path), provider="zai", provider_api_key="zai-secret",
    )
    assert status.auth_mode == "gateway"
    assert status.provider == "zai"
    assert status.gateway_base_url == "https://api.z.ai/api/anthropic"
    assert os.environ["ANTHROPIC_AUTH_TOKEN"] == "zai-secret"


def test_configure_auth_provider_missing_key_raises(monkeypatch, tmp_path):
    _monkeypatch_claude_cli(monkeypatch)
    for v in ("ZAI_API_KEY", "CODESEC_API_KEY", "ANTHROPIC_AUTH_TOKEN",
              "ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN"):
        monkeypatch.delenv(v, raising=False)
    with pytest.raises(AuthError):
        configure_auth(_empty_env(tmp_path), provider="zai")
