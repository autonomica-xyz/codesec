"""Provider presets for non-Anthropic LLM backends that speak the Anthropic
Messages API.

codesec is built on the Claude Code Agent SDK, which speaks the Anthropic
Messages API natively. Any gateway that also speaks that API (an
Anthropic-compatible ``POST /v1/messages``) already works through the
existing gateway auth path — set ``ANTHROPIC_BASE_URL`` + ``ANTHROPIC_AUTH_TOKEN``
and you're done. ``auth-check`` will report "using LLM gateway at ...".

These presets remove the need to memorize each provider's base URL, give a
sane per-stage model mapping (preserving the deliberate-disagreement
opus/sonnet role split from ``config/stages.yaml``), and accept a
provider-specific API key without touching the raw ``ANTHROPIC_*`` vars.

Supported providers:

  - ``zai`` (Z.AI GLM Coding Plan)
      Anthropic endpoint: https://api.z.ai/api/anthropic
      Key: a Z.AI API key (from https://z.ai/manage-apikey/apikey-list).
      Spend a GLM Coding Plan subscription instead of Anthropic credits.
      Docs: https://docs.z.ai/devpack/overview

  - ``unsloth`` (Unsloth Studio local server)
      Anthropic endpoint: http://localhost:<port>  (POST /v1/messages)
      Key: ``sk-unsloth-...`` printed by Unsloth Studio / ``unsloth run``.
      Model: whatever GGUF is loaded — pass ``--model`` (exact id from
      ``GET /v1/models``). Local inference; deliberate-disagreement
      collapses to a single model.
      Docs: https://unsloth.ai/docs/basics/api

  - ``anthropic`` (default)
      No env mutation — uses Claude subscription / API key / an existing
      gateway exactly as the upstream auth module does.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


class ProviderError(RuntimeError):
    pass


@dataclass(frozen=True)
class Provider:
    name: str
    base_url: str
    docs_url: str
    notes: str
    # Role models map config/stages.yaml's claude-opus-* / claude-sonnet-*
    # / claude-haiku-* tags to this provider's equivalents. None means
    # "caller must supply --model / CODESEC_MODEL" (e.g. Unsloth's loaded GGUF).
    opus_role_model: str | None
    sonnet_role_model: str | None
    haiku_role_model: str | None
    # Env vars consulted, in order, when no explicit key is passed. The last
    # entry is always the bare gateway token so a pre-set ANTHROPIC_AUTH_TOKEN
    # still works.
    key_env_vars: tuple[str, ...]
    # OpenAI-compatible chat-completions root used by `--engine local`.
    # Empty means "same as base_url" (Unsloth) or unused (Anthropic SDK).
    openai_base_url: str = ""


PROVIDERS: dict[str, Provider] = {
    "anthropic": Provider(
        name="anthropic",
        base_url="",
        docs_url="https://code.claude.com/docs/en/authentication",
        notes="Default. Claude subscription / API key / existing gateway env.",
        opus_role_model="claude-opus-4-7",
        sonnet_role_model="claude-sonnet-4-6",
        haiku_role_model="claude-haiku-4-5",
        key_env_vars=("CODESEC_API_KEY", "ANTHROPIC_AUTH_TOKEN"),
    ),
    "zai": Provider(
        name="zai",
        base_url="https://api.z.ai/api/anthropic",
        docs_url="https://docs.z.ai/devpack/overview",
        notes="Z.AI GLM Coding Plan. Spend a GLM subscription, not Anthropic credits.",
        # glm-5.2 is Z.AI's Opus-tier flagship (used for the critical
        # recon / validate / trace stages); glm-4.7 is the fast coding model
        # for the high-fanout hunt stage. Different models for validate vs
        # hunt preserves the deliberate-disagreement rule.
        opus_role_model="glm-5.2",
        sonnet_role_model="glm-4.7",
        haiku_role_model="glm-4.5-air",
        key_env_vars=("ZAI_API_KEY", "CODESEC_API_KEY", "ANTHROPIC_AUTH_TOKEN"),
        # Pi / OpenAI-compat tools use the Coding Plan paas endpoint, not
        # the Anthropic Messages URL. `--engine local` talks to this.
        openai_base_url="https://api.z.ai/api/coding/paas/v4",
    ),
    "unsloth": Provider(
        name="unsloth",
        base_url="http://localhost:8888",
        docs_url="https://unsloth.ai/docs/basics/api",
        notes="Unsloth Studio local server. One loaded model — pass --model.",
        opus_role_model=None,
        sonnet_role_model=None,
        haiku_role_model=None,
        key_env_vars=("UNSLOTH_API_KEY", "CODESEC_API_KEY", "ANTHROPIC_AUTH_TOKEN"),
        openai_base_url="http://localhost:8888/v1",
    ),
}


def provider_names() -> list[str]:
    return list(PROVIDERS)


def get_provider(name: str) -> Provider:
    try:
        return PROVIDERS[name]
    except KeyError:
        raise ProviderError(
            f"Unknown provider {name!r}. Known: {provider_names()}"
        ) from None


def resolve_key(provider: Provider, explicit: str | None = None) -> str | None:
    return _resolve_key(provider, explicit)


def local_base_url(provider: Provider, explicit: str | None = None) -> str:
    """Base URL for `--engine local` (OpenAI chat completions)."""
    if explicit:
        return explicit.rstrip("/")
    override = os.environ.get("CODESEC_BASE_URL", "").strip()
    if override:
        return override.rstrip("/")
    if provider.openai_base_url:
        return provider.openai_base_url.rstrip("/")
    return (provider.base_url or "http://localhost:8080").rstrip("/")


def _resolve_key(provider: Provider, explicit: str | None) -> str | None:
    if explicit:
        return explicit
    for var in provider.key_env_vars:
        val = os.environ.get(var, "").strip()
        if val:
            return val
    return None


def apply_provider_env(
    provider: Provider,
    *,
    api_key: str | None = None,
    base_url: str | None = None,
) -> dict:
    """Mutate os.environ so the existing gateway auth path picks up this
    provider. Sets ANTHROPIC_BASE_URL + ANTHROPIC_AUTH_TOKEN and scrubs
    ANTHROPIC_API_KEY (it would outrank the gateway token at precedence
    rung 3). No-op for the ``anthropic`` provider.

    Returns a small dict describing what was applied, for display.
    Raises ProviderError if a required key / model can't be resolved.
    """
    if provider.name == "anthropic":
        return {"provider": "anthropic", "applied": False}

    url = (base_url
           or os.environ.get("CODESEC_BASE_URL", "")
           or os.environ.get("ANTHROPIC_BASE_URL", "")).strip()
    if not url:
        url = provider.base_url

    key = _resolve_key(provider, api_key)
    if not key:
        raise ProviderError(
            f"No API key for provider {provider.name!r}. Set one of "
            f"{list(provider.key_env_vars)} or pass --api-key. "
            f"Docs: {provider.docs_url}"
        )

    os.environ["ANTHROPIC_BASE_URL"] = url
    os.environ["ANTHROPIC_AUTH_TOKEN"] = key
    # ANTHROPIC_API_KEY would outrank the gateway token — scrub it.
    os.environ.pop("ANTHROPIC_API_KEY", None)

    return {"provider": provider.name, "applied": True, "base_url": url}


def role_model(provider: Provider, stage_model: str) -> str | None:
    """Pick the provider's model for a stage based on the role tag in its
    current model name (opus/sonnet/haiku). Returns None if the provider
    has no mapping for that role (caller should require --model)."""
    m = (stage_model or "").lower()
    if "opus" in m:
        return provider.opus_role_model
    if "sonnet" in m:
        return provider.sonnet_role_model
    if "haiku" in m:
        return provider.haiku_role_model
    return None
