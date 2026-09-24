"""Run one agent: open a ClaudeSDKClient session, send a JSON input,
parse + schema-validate the final JSON output, and persist a JSONL
artifact of every message exchanged.

Always uses ClaudeSDKClient (not query()) so that a schema-validation
failure can be followed up with a repair turn inside the same session.

API-error handling: the Claude CLI surfaces 529 Overloaded and
subscription-quota-exhausted errors as `ResultMessage(is_error=True)` with
the error text in place of a real assistant response. We detect this
BEFORE schema validation, classify the error, and either retry with
exponential backoff (transient) or raise QuotaExhaustedError (terminal).
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import logging
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from typing import TYPE_CHECKING

from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    ClaudeSDKClient,
    ResultMessage,
    TextBlock,
    ThinkingBlock,
    ToolResultBlock,
    ToolUseBlock,
)

from codesec.json_utils import extract_json, validate_schema

if TYPE_CHECKING:
    from codesec.config import ModelProfile

from codesec.reasoning import reasoning_from_dict, spec_to_dict

log = logging.getLogger(__name__)


# ---- engine switch: SDK (default) vs direct local-LLM client -----------------
# Set once by the CLI (``codesec run --engine local``). When ``local``, run_agent
# delegates to codesec.local_agent — no Claude Code SDK / subprocess, talking
# straight to a llama-server /v1/chat/completions endpoint for KV-cache-friendly
# multi-turn agent loops.
_ENGINE = "sdk"
_LOCAL_BASE_URL: str | None = None
_LOCAL_API_KEY: str | None = None


def set_engine(engine: str, base_url: str | None = None, api_key: str | None = None) -> None:
    global _ENGINE, _LOCAL_BASE_URL, _LOCAL_API_KEY
    _ENGINE = engine
    _LOCAL_BASE_URL = base_url
    _LOCAL_API_KEY = api_key


@dataclass
class AgentResult:
    payload: dict
    cost_usd: float | None
    input_tokens: int | None
    output_tokens: int | None
    cache_read_tokens: int | None
    cache_creation_tokens: int | None
    num_turns: int | None
    duration_ms: int | None
    session_id: str | None
    artifact_path: Path
    repair_used: bool
    raw_result_message: dict = field(default_factory=dict)


class AgentRunError(RuntimeError):
    """Schema validation failed after repair attempts (model produced
    parseable output that didn't match the schema)."""


class TransientAgentError(RuntimeError):
    """API returned a transient error (529 Overloaded, generic 5xx).
    The agent call should be retried with backoff."""


class QuotaExhaustedError(RuntimeError):
    """The Claude subscription has run out of quota. Don't retry — abort
    the pipeline and let the user wait for the reset window."""


_QUOTA_MARKERS = (
    "out of extra usage",
    "usage limit reached",
    # Subscription session/usage caps that reset on a timer, e.g.
    # "You've hit your session limit · resets 5:10am (UTC)". The reset is
    # often hours out, so backoff-retrying is futile — treat it as terminal
    # and let the caller abort into a resumable state.
    "session limit",
    "your plan has no remaining",
)

_LIVE_PROBE_TOOL_NAME = "mcp__live_probe__http_request"

# Stages that may hold a live probe — the plan scopes request capability to
# Hunt/Validate/Trace. recon/gapfill/dedupe/feedback/report never get it,
# even though live_target flows into their inputs for context.
_LIVE_PROBE_STAGES = frozenset({"hunt", "validate", "trace"})


def _redacted_user_input(user_input: dict) -> dict:
    """Copy of user_input safe to persist: live-target credentials are
    never written to artifacts (the local engine redacts the same way)."""
    live = (user_input or {}).get("live_target")
    if not isinstance(live, dict) or not live.get("credentials"):
        return user_input
    red = dict(user_input)
    live = dict(live)
    live["credentials"] = {k: "***" for k in live["credentials"]}
    red["live_target"] = live
    return red


def live_probe_mcp_config(user_input: dict) -> dict | None:
    """Return the MCP stdio-server config for the live_probe tool, or None.

    The gate is ``user_input.live_target.url`` — no config change needed.
    The target is handed to the server via env so the host pin is enforced
    inside the spawned process, not by the prompt.
    """
    live = (user_input or {}).get("live_target")
    if not isinstance(live, dict) or not live.get("url"):
        return None
    script = Path(__file__).resolve().parent / "live_probe_mcp.py"
    return {
        "type": "stdio",
        "command": sys.executable,
        "args": [str(script)],
        "env": {"CODESEC_LIVE_TARGET_URL": str(live["url"])},
    }


_TRANSIENT_MARKERS = (
    "api error: 529",
    "overloaded",
    "api error: 503",
    "api error: 502",
    "api error: 504",
    "api error: 500",
    "rate_limit",
    "temporarily unavailable",
    "service unavailable",
)


def _classify_api_error(text: str) -> tuple[str, type[RuntimeError]]:
    """Return (label, exception_class) for an is_error response."""
    t = (text or "").lower()
    if any(m in t for m in _QUOTA_MARKERS):
        return "quota_exhausted", QuotaExhaustedError
    if any(m in t for m in _TRANSIENT_MARKERS):
        return "transient", TransientAgentError
    # Default to transient — better to retry once than abort on classification miss.
    return "unknown_api_error", TransientAgentError


async def run_agent(
    *,
    stage: str,
    prompt_file: Path,
    user_input: dict,
    schema_file: Path,
    allowed_tools: list[str],
    model: str,
    profile: ModelProfile | None = None,
    cwd: Path,
    add_dirs: list[Path] | None = None,
    max_turns: int = 25,
    permission_mode: str = "acceptEdits",
    artifact_dir: Path,
    artifact_name: str,
    repair_attempts: int = 1,
    transient_retries: int = 3,
    transient_base_delay: float = 30.0,
    deadline: "object | None" = None,
) -> AgentResult:
    """Run one agent, retrying transient API errors with exponential backoff.

    ``deadline`` (codesec.deadline.Deadline, P05) bounds every request,
    tool call and backoff sleep; retries never restart after budget
    exhaustion (TimeBudgetExceeded propagates instead).

    Raises `QuotaExhaustedError` if the subscription is out of quota
    (caller should abort the run). Raises `TransientAgentError` if all
    backoff retries are exhausted. Raises `AgentRunError` if the model
    produced parseable output that doesn't match the schema even after
    repair turns.
    """
    from codesec.deadline import TimeBudgetExceeded

    if deadline is not None:
        deadline.check(f"{stage}/{artifact_name}")
    async def _once(attempt: int) -> AgentResult:
        attempt_artifact_name = (
            artifact_name if attempt == 0 else f"{artifact_name}.retry-{attempt + 1}"
        )
        effective_engine = profile.engine if profile is not None else _ENGINE
        effective_model = profile.model if profile is not None else model
        if (
            profile is not None
            and model
            and profile.model != model
        ):
            # P03: a stage label says one model while the attached profile
            # silently overrides the actual request with another. Fail loudly
            # instead of logging the wrong model name.
            raise ValueError(
                f"model conflict for stage {stage!r}: stage config says "
                f"{model!r} but attached profile {profile.name!r} would "
                f"send {profile.model!r}. Fix the stage config/profile "
                f"routing before running."
            )
        if effective_engine in {"local", "local_openai"}:
            # Direct local-LLM path: no SDK, no subprocess. The tool loop,
            # schema validation and artifact writing all live in
            # codesec.local_agent. Offload to a worker thread: run_local_agent
            # does blocking urllib + subprocess, so without this the asyncio
            # event loop is held for the whole agent run and the per-stage
            # asyncio.Semaphore(concurrency) serializes every task -- i.e.
            # --max-concurrency was a no-op. Routed through the same transient
            # retry loop as the SDK path so a flaky local upstream (socket
            # timeout, conn reset) is retried, not fatal to the whole gather.
            from codesec.local_agent import run_local_agent
            return await asyncio.to_thread(
                run_local_agent,
                stage=stage, prompt_file=prompt_file, user_input=user_input,
                schema_file=schema_file, allowed_tools=allowed_tools,
                model=effective_model,
                cwd=cwd,
                base_url=(
                    profile.endpoint
                    if profile is not None
                    else _LOCAL_BASE_URL or "http://localhost:8080"
                ),
                api_key=(
                    os.environ.get(profile.api_key_env)
                    if profile is not None and profile.api_key_env
                    else _LOCAL_API_KEY
                ),
                add_dirs=add_dirs, max_turns=max_turns,
                artifact_dir=artifact_dir, artifact_name=attempt_artifact_name,
                repair_attempts=repair_attempts,
                temperature=profile.temperature if profile is not None else 0.6,
                max_tokens=(
                    profile.max_output_tokens
                    if profile is not None
                    else int(os.environ.get("CODESEC_MAX_TOKENS", "32768"))
                ),
                reasoning=(
                    spec_to_dict(profile.reasoning_spec())
                    if profile is not None
                    else None
                ),
                max_input_chars=(
                    profile.max_input_chars if profile is not None else 50_000
                ),
                context_limit=(
                    profile.context_limit if profile is not None else 262_144
                ),
                deadline_ts=(
                    # The model-work cutoff (not the run's absolute end):
                    # the final snapshot reserve is never spent streaming.
                    deadline.snapshot_deadline()
                    if deadline is not None else None
                ),
            )
        if profile is not None:
            raise ValueError(
                f"request-scoped profile engine {profile.engine!r} is not supported"
            )
        return await _run_agent_once(
            stage=stage,
            prompt_file=prompt_file,
            user_input=user_input,
            schema_file=schema_file,
            allowed_tools=allowed_tools,
            model=effective_model,
            cwd=cwd,
            add_dirs=add_dirs,
            max_turns=max_turns,
            permission_mode=permission_mode,
            artifact_dir=artifact_dir,
            artifact_name=attempt_artifact_name,
            repair_attempts=repair_attempts,
        )

    last_exc: RuntimeError | None = None
    for attempt in range(transient_retries + 1):
        try:
            return await _once(attempt)
        except QuotaExhaustedError:
            raise
        except TimeBudgetExceeded:
            raise
        except TransientAgentError as e:
            last_exc = e
            if attempt >= transient_retries:
                break
            delay = min(transient_base_delay * (2 ** attempt), 240.0)
            log.warning(
                "[%s/%s] transient API error (attempt %d/%d): %s — retrying in %.0fs",
                stage, artifact_name, attempt + 1, transient_retries + 1,
                str(e)[:160], delay,
            )
            if deadline is not None:
                # Never sleep past the deadline, and never restart a
                # request after budget exhaustion.
                await deadline.sleep(delay)
            else:
                await asyncio.sleep(delay)
    assert last_exc is not None
    raise last_exc


async def _run_agent_once(
    *,
    stage: str,
    prompt_file: Path,
    user_input: dict,
    schema_file: Path,
    allowed_tools: list[str],
    model: str,
    cwd: Path,
    add_dirs: list[Path] | None,
    max_turns: int,
    permission_mode: str,
    artifact_dir: Path,
    artifact_name: str,
    repair_attempts: int,
) -> AgentResult:
    """Single attempt. Raises TransientAgentError / QuotaExhaustedError
    before schema validation if the API returned is_error=True."""
    artifact_dir.mkdir(parents=True, exist_ok=True)
    artifact_path = artifact_dir / f"{artifact_name}.jsonl"
    cwd.mkdir(parents=True, exist_ok=True)

    system_prompt = prompt_file.read_text()
    # Append the literal schema body so the model never has to guess
    # field names — this drastically reduces schema-validation failures
    # on the first attempt and frees up the repair budget for real
    # ambiguities.
    schema_text = schema_file.read_text()
    system_prompt += (
        "\n\n# Output schema\n\n"
        "Your output MUST validate against this JSON Schema. "
        "Pay attention to nested objects, required fields, and "
        "`additionalProperties: false`.\n\n"
        f"```json\n{schema_text}\n```\n"
    )
    # W7: when the run has a live target, expose the host-pinned
    # live_probe MCP tool. The pin lives in the spawned server (env-passed
    # URL), not the prompt — the model cannot aim it elsewhere.
    live_probe_cfg = (
        live_probe_mcp_config(user_input)
        if stage in _LIVE_PROBE_STAGES
        else None
    )
    effective_tools = list(allowed_tools)
    mcp_servers = None
    if live_probe_cfg is not None:
        mcp_servers = {"live_probe": live_probe_cfg}
        if _LIVE_PROBE_TOOL_NAME not in effective_tools:
            effective_tools = [*effective_tools, _LIVE_PROBE_TOOL_NAME]

    options = ClaudeAgentOptions(
        system_prompt=system_prompt,
        # `tools` is the set of tools ADVERTISED to the model; `allowed_tools`
        # only controls auto-permission. Setting `tools` explicitly is
        # load-bearing for non-Anthropic gateways (z.ai / Unsloth / OpenRouter):
        # with tools=None the SDK advertises every built-in tool the install
        # registers, and llama-server's tool-calling grammar compiler fails on
        # large toolsets for some models (e.g. hybrid/SSM Qwen), 400ing every
        # turn. Restricting to the stage's tool list keeps the grammar small.
        tools=effective_tools,
        allowed_tools=effective_tools,
        mcp_servers=mcp_servers,
        model=model,
        max_turns=max_turns,
        cwd=str(cwd),
        add_dirs=[str(p) for p in (add_dirs or [])],
        permission_mode=permission_mode,
        setting_sources=[],
    )

    initial_prompt = json.dumps(user_input, ensure_ascii=False)
    artifact_prompt = json.dumps(
        _redacted_user_input(user_input), ensure_ascii=False
    )

    last_text = ""
    last_result_msg: dict[str, Any] = {}
    repair_used = False

    with artifact_path.open("w") as art:
        _write_artifact(art, {"kind": "meta", "stage": stage, "model": model, "started_at": time.time()})
        _write_artifact(art, {"kind": "user", "text": artifact_prompt[:50000]})

        try:
            sdk_ctx = ClaudeSDKClient(options=options)
            client = await sdk_ctx.__aenter__()
        except Exception as e:
            if "timeout" in str(e).lower() or "initialize" in str(e).lower():
                raise TransientAgentError(
                    f"[{stage}/{artifact_name}] SDK initialize timeout: {e}"
                ) from e
            raise

        try:
            await client.query(initial_prompt)
            last_text, last_result_msg = await _drain(client, art)

            # Before schema validation: was this a real model response, or
            # did the CLI surface an API error as the assistant text?
            if last_result_msg.get("is_error"):
                label, exc_cls = _classify_api_error(last_text)
                _write_artifact(art, {"kind": "api_error", "classification": label,
                                      "text": last_text[:1000]})
                raise exc_cls(
                    f"[{stage}/{artifact_name}] {label}: "
                    f"{(last_text or '').strip()[:300]}"
                )

            attempts = 0
            errors = _validate(last_text, schema_file)
            while errors and attempts < repair_attempts:
                attempts += 1
                repair_used = True
                repair_prompt = _build_repair_prompt(last_text, errors, schema_file)
                _write_artifact(art, {"kind": "repair_request", "text": repair_prompt[:50000]})
                await client.query(repair_prompt)
                last_text, last_result_msg = await _drain(client, art)
                # An API error on the repair turn is also retry-worthy.
                if last_result_msg.get("is_error"):
                    label, exc_cls = _classify_api_error(last_text)
                    _write_artifact(art, {"kind": "api_error_on_repair",
                                          "classification": label,
                                          "text": last_text[:1000]})
                    raise exc_cls(
                        f"[{stage}/{artifact_name}] {label} on repair turn: "
                        f"{(last_text or '').strip()[:300]}"
                    )
                errors = _validate(last_text, schema_file)

            if errors:
                _write_artifact(art, {"kind": "schema_errors", "errors": errors})
                raise AgentRunError(
                    f"[{stage}/{artifact_name}] schema validation failed after "
                    f"{repair_attempts} repair attempts: {errors[:5]}"
                )

            payload = extract_json(last_text)
            _write_artifact(art, {"kind": "final_payload", "payload": payload})
        finally:
            await sdk_ctx.__aexit__(None, None, None)

    usage = last_result_msg.get("usage") or {}
    return AgentResult(
        payload=payload,
        cost_usd=last_result_msg.get("total_cost_usd"),
        input_tokens=usage.get("input_tokens"),
        output_tokens=usage.get("output_tokens"),
        cache_read_tokens=usage.get("cache_read_input_tokens"),
        cache_creation_tokens=usage.get("cache_creation_input_tokens"),
        num_turns=last_result_msg.get("num_turns"),
        duration_ms=last_result_msg.get("duration_ms"),
        session_id=last_result_msg.get("session_id"),
        artifact_path=artifact_path,
        repair_used=repair_used,
        raw_result_message=last_result_msg,
    )


async def _drain(client: ClaudeSDKClient, art) -> tuple[str, dict[str, Any]]:
    """Consume the response stream, write each message to the JSONL
    artifact, and return (concatenated assistant text from last
    assistant message, result_message_dict)."""
    text_chunks: list[str] = []
    result_msg: dict[str, Any] = {}
    last_assistant_text: list[str] = []

    async for msg in client.receive_response():
        _write_artifact(art, _serialize_message(msg))
        if isinstance(msg, AssistantMessage):
            last_assistant_text = []
            for block in msg.content:
                if isinstance(block, TextBlock):
                    last_assistant_text.append(block.text)
            text_chunks.append("".join(last_assistant_text))
        elif isinstance(msg, ResultMessage):
            result_msg = _result_to_dict(msg)

    final_text = "".join(last_assistant_text) if last_assistant_text else (
        text_chunks[-1] if text_chunks else ""
    )
    return final_text, result_msg


def _validate(text: str, schema_file: Path) -> list[str]:
    try:
        payload = extract_json(text)
    except ValueError as e:
        return [f"json_extract: {e}"]
    return validate_schema(payload, schema_file)


def _build_repair_prompt(prev_output: str, errors: list[str], schema_file: Path) -> str:
    err_block = "\n".join(f"- {e}" for e in errors[:20])
    return (
        "Your previous output failed schema validation against "
        f"`{schema_file.name}`. Errors:\n"
        f"{err_block}\n\n"
        "Re-emit the same response, fixing ONLY these errors. Output a "
        "single JSON object — no prose, no markdown fence."
    )


def _write_artifact(fp, obj: Any) -> None:
    fp.write(json.dumps(obj, default=_json_fallback, ensure_ascii=False) + "\n")
    fp.flush()


def _json_fallback(o: Any) -> Any:
    if dataclasses.is_dataclass(o):
        return dataclasses.asdict(o)
    if isinstance(o, Path):
        return str(o)
    return repr(o)


def _serialize_message(msg: Any) -> dict[str, Any]:
    if isinstance(msg, AssistantMessage):
        return {
            "kind": "assistant",
            "model": msg.model,
            "usage": msg.usage,
            "content": [_serialize_block(b) for b in msg.content],
        }
    if isinstance(msg, ResultMessage):
        return {"kind": "result", **_result_to_dict(msg)}
    if dataclasses.is_dataclass(msg):
        return {"kind": type(msg).__name__, **dataclasses.asdict(msg)}
    return {"kind": type(msg).__name__, "repr": repr(msg)}


def _serialize_block(b: Any) -> dict[str, Any]:
    if isinstance(b, TextBlock):
        return {"type": "text", "text": b.text}
    if isinstance(b, ThinkingBlock):
        return {"type": "thinking", "thinking": b.thinking}
    if isinstance(b, ToolUseBlock):
        return {"type": "tool_use", "id": b.id, "name": b.name, "input": b.input}
    if isinstance(b, ToolResultBlock):
        return {
            "type": "tool_result",
            "tool_use_id": b.tool_use_id,
            "content": b.content,
            "is_error": b.is_error,
        }
    if dataclasses.is_dataclass(b):
        return dataclasses.asdict(b)
    return {"type": type(b).__name__, "repr": repr(b)}


def _result_to_dict(msg: ResultMessage) -> dict[str, Any]:
    return {
        "subtype": msg.subtype,
        "is_error": msg.is_error,
        "duration_ms": msg.duration_ms,
        "duration_api_ms": msg.duration_api_ms,
        "num_turns": msg.num_turns,
        "session_id": msg.session_id,
        "stop_reason": msg.stop_reason,
        "total_cost_usd": msg.total_cost_usd,
        "usage": msg.usage,
        "result": msg.result,
        "model_usage": msg.model_usage,
    }
