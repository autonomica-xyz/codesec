"""Tests for the API-error classification in runner.py."""

from __future__ import annotations

from pathlib import Path

import pytest

from codesec import local_agent, runner
from codesec.config import ModelProfile
from codesec.runner import (
    AgentResult,
    QuotaExhaustedError,
    TransientAgentError,
    _classify_api_error,
)


@pytest.mark.parametrize("text", [
    "You're out of extra usage · resets 2am (Europe/Rome)",
    "Usage limit reached for the day.",
    "Your plan has no remaining quota.",
    "YOU'RE OUT OF EXTRA USAGE.",
    "You've hit your session limit · resets 5:10am (UTC)",
    "You've hit your session limit · resets 11pm",
])
def test_quota_classified(text: str) -> None:
    label, exc = _classify_api_error(text)
    assert label == "quota_exhausted"
    assert exc is QuotaExhaustedError


@pytest.mark.parametrize("text", [
    "API Error: 529 Overloaded. This is a server-side issue, usually temporary",
    "Server overloaded — please try again",
    "API Error: 503",
    "API Error: 502 Bad Gateway",
    "API Error: 500 Internal Server Error",
    "rate_limit hit",
    "Service temporarily unavailable",
])
def test_transient_classified(text: str) -> None:
    label, exc = _classify_api_error(text)
    assert label == "transient"
    assert exc is TransientAgentError


def test_unknown_defaults_to_transient() -> None:
    label, exc = _classify_api_error("some weird new error string")
    assert label == "unknown_api_error"
    assert exc is TransientAgentError


def test_empty_defaults_to_transient() -> None:
    label, exc = _classify_api_error("")
    assert label == "unknown_api_error"
    assert exc is TransientAgentError


async def test_retry_uses_a_new_artifact_name(tmp_path: Path, monkeypatch) -> None:
    artifact_names: list[str] = []

    def fake_local_agent(**kwargs):
        artifact_names.append(kwargs["artifact_name"])
        if len(artifact_names) == 1:
            raise TransientAgentError("temporary")
        return AgentResult(
            payload={},
            cost_usd=0,
            input_tokens=1,
            output_tokens=1,
            cache_read_tokens=0,
            cache_creation_tokens=0,
            num_turns=1,
            duration_ms=1,
            session_id=None,
            artifact_path=tmp_path / f"{kwargs['artifact_name']}.jsonl",
            repair_used=False,
        )

    monkeypatch.setattr(local_agent, "run_local_agent", fake_local_agent)
    runner.set_engine("local", "http://localhost:8080")
    try:
        await runner.run_agent(
            stage="hunt",
            prompt_file=tmp_path / "prompt.md",
            user_input={},
            schema_file=tmp_path / "schema.json",
            allowed_tools=[],
            model="model",
            cwd=tmp_path,
            artifact_dir=tmp_path,
            artifact_name="t_1",
            transient_retries=1,
            transient_base_delay=0,
        )
    finally:
        runner.set_engine("sdk")

    assert artifact_names == ["t_1", "t_1.retry-2"]


async def test_request_profile_overrides_process_global_local_routing(
    tmp_path: Path, monkeypatch
) -> None:
    captured = {}

    def fake_local_agent(**kwargs):
        captured.update(kwargs)
        return AgentResult(
            payload={},
            cost_usd=0,
            input_tokens=1,
            output_tokens=1,
            cache_read_tokens=0,
            cache_creation_tokens=0,
            num_turns=1,
            duration_ms=1,
            session_id=None,
            artifact_path=tmp_path / "result.jsonl",
            repair_used=False,
        )

    monkeypatch.setattr(local_agent, "run_local_agent", fake_local_agent)
    monkeypatch.setenv("DUO_API_KEY", "secret")
    runner.set_engine("sdk")
    profile = ModelProfile(
        name="titus",
        engine="local",
        endpoint="http://127.0.0.1:9090",
        model="titus-model",
        api_key_env="DUO_API_KEY",
        temperature=0.1,
        max_output_tokens=2048,
        thinking=False,
        max_input_chars=40_000,
    )

    await runner.run_agent(
        stage="hunt",
        prompt_file=tmp_path / "prompt.md",
        user_input={},
        schema_file=tmp_path / "schema.json",
        allowed_tools=[],
        model="legacy-model",
        profile=profile,
        cwd=tmp_path,
        artifact_dir=tmp_path,
        artifact_name="t_1",
    )

    assert captured["base_url"] == "http://127.0.0.1:9090"
    assert captured["model"] == "titus-model"
    assert captured["api_key"] == "secret"
    assert captured["temperature"] == 0.1
    assert captured["max_tokens"] == 2048
    assert captured["max_input_chars"] == 40_000
