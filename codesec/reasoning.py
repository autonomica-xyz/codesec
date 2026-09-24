"""Provider-aware reasoning + sampling request settings (P03).

One generic ``thinking: bool`` cannot encode incompatible provider protocols:

- Z.AI GLM (hosted, OpenAI-compatible chat completions): ``thinking.type``
  must be ``"enabled"`` (disabling is unsupported for glm-5.3 and rejected)
  plus ``reasoning_effort`` in {low, high, max}. Reasoning streams back as
  ``delta.reasoning_content`` and is serialized back on assistant messages
  in later requests (Pi-compatible history transport).
- llama.cpp / llama-server (local): ``chat_template_kwargs.enable_thinking``
  chat-template kwarg. Never send this as the hosted reasoning control.

The frozen hosted experiment protocol is:
``thinking.type=enabled`` + ``reasoning_effort=low`` + history=preserve.

References (archived 2026-09-22):
- https://docs.z.ai/guides/llm/glm-5.3  (thinking.type enabled-only;
  reasoning_effort low/high/max, default max; disabled requests fail)
- https://docs.z.ai/guides/llm/glm-5.2  (streaming delta.reasoning_content)
- Pi 0.85.1 request builder (openai-completions): zai thinkingFormat sends
  ``thinking`` + ``reasoning_effort`` and echoes ``reasoning_content`` on
  assistant history messages with that signature.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass

REASONING_PROTOCOLS = ("none", "llama_chat_template", "zai_thinking")
ZAI_EFFORTS = ("low", "high", "max")
HISTORY_POLICIES = ("preserve", "drop")

# Fields providers use to stream reasoning deltas (order matters: first
# non-empty wins — mirrors Pi's OpenAI-completions reader).
REASONING_DELTA_FIELDS = ("reasoning_content", "reasoning", "reasoning_text")


class ReasoningConfigError(ValueError):
    """Invalid or protocol-incompatible reasoning settings."""


@dataclass(frozen=True)
class ReasoningSpec:
    protocol: str = "none"
    enabled: bool = False
    effort: str | None = None
    history: str = "preserve"

    def __post_init__(self) -> None:
        if self.protocol not in REASONING_PROTOCOLS:
            raise ReasoningConfigError(
                f"unknown reasoning protocol {self.protocol!r}; "
                f"expected one of {REASONING_PROTOCOLS}"
            )
        if self.history not in HISTORY_POLICIES:
            raise ReasoningConfigError(
                f"unknown reasoning history policy {self.history!r}; "
                f"expected one of {HISTORY_POLICIES}"
            )
        if self.protocol == "zai_thinking":
            if not self.enabled:
                raise ReasoningConfigError(
                    "zai_thinking protocol requires enabled reasoning — "
                    "glm-5.3 rejects thinking.type=disabled"
                )
            if self.effort not in ZAI_EFFORTS:
                raise ReasoningConfigError(
                    f"zai reasoning_effort must be one of {ZAI_EFFORTS}, "
                    f"got {self.effort!r}"
                )

    def request_params(self) -> dict:
        """Wire parameters for the chosen protocol (empty for none)."""
        if self.protocol == "zai_thinking":
            # Documented shape only: {"type": "enabled"} + reasoning_effort.
            return {
                "thinking": {"type": "enabled"},
                "reasoning_effort": self.effort,
            }
        if self.protocol == "llama_chat_template":
            return {"chat_template_kwargs": {"enable_thinking": self.enabled}}
        return {}

    def serialize_history(self, assistant_message: dict, reasoning_text: str) -> dict:
        """Attach streamed reasoning to an assistant history message.

        Pi-compatible: the reasoning is echoed back on later requests under
        the ``reasoning_content`` field, including tool-call turns, when the
        policy is ``preserve``.
        """
        if self.protocol == "zai_thinking" and self.history == "preserve" and reasoning_text:
            assistant_message = dict(assistant_message)
            assistant_message["reasoning_content"] = reasoning_text
        return assistant_message


def effective_request_settings(
    *,
    model: str,
    reasoning: ReasoningSpec | None = None,
    temperature: float | None = None,
    max_tokens: int | None = None,
    context_limit: int | None = None,
    stream: bool = True,
) -> dict:
    """Canonical effective request settings shared by codesec, the gateway
    validation, and the run manifest. Hash THIS, not a config file path."""
    spec = reasoning or ReasoningSpec()
    settings = {
        "model": model,
        "reasoning": {
            "protocol": spec.protocol,
            "enabled": spec.enabled,
            "effort": spec.effort,
            "history": spec.history,
        },
        "request_params": spec.request_params(),
        "temperature": temperature,
        "max_tokens": max_tokens,
        "context_limit": context_limit,
        "stream": stream,
    }
    settings["fingerprint_sha256"] = hashlib.sha256(
        json.dumps(settings, sort_keys=True).encode()
    ).hexdigest()
    return settings


def reasoning_from_dict(raw: dict | None) -> ReasoningSpec:
    if not raw:
        return ReasoningSpec()
    return ReasoningSpec(
        protocol=str(raw.get("protocol", "none")),
        enabled=bool(raw.get("enabled", False)),
        effort=raw.get("effort"),
        history=str(raw.get("history", "preserve")),
    )


def spec_to_dict(spec: ReasoningSpec) -> dict:
    return asdict(spec)
