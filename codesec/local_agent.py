"""Direct local-LLM agent engine — no Claude Code SDK, no subprocess.

Talks straight to a llama-server / Unsloth `/v1/chat/completions` (OpenAI)
endpoint with a hand-rolled Read/Grep/Glob/Bash tool loop. This is the
optimized path for local models:

  - No `claude` CLI subprocess per turn.
  - No Claude-Code attribution header thrashing the KV cache (Unsloth docs
    call this a ~90% slowdown for local models).
  - Append-only message history -> llama-server's prefix KV cache hits on
    every turn after the first (the big multi-turn win).
  - Only the 4 tools codesec stages use are advertised, so llama-server's
    tool-call grammar compiles cleanly (no proxy needed).
  - Full control over sampling / max_tokens.

Same `run_agent` contract as codesec.runner so stages don't change.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import logging
import os
import re
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path, PurePath
from typing import Any

from codesec.json_utils import extract_json, validate_schema
from codesec.live_probe_mcp import (
    TOOL_INPUT_SCHEMA as _LIVE_PROBE_SCHEMA,
    http_request as _live_probe_request,
)
from codesec.reasoning import (
    REASONING_DELTA_FIELDS,
    effective_request_settings,
    reasoning_from_dict,
    spec_to_dict,
)
from codesec.runner import AgentResult, AgentRunError, TransientAgentError

log = logging.getLogger(__name__)


# ---- the 4 tools codesec stages need, in OpenAI function-call format --------

def _t(name, desc, params):
    return {"type": "function", "function": {"name": name, "description": desc,
                                             "parameters": params}}

ALL_TOOLS = {
    "read": _t("read", "Read a UTF-8 text file under the repo. Returns the file "
                       "contents (optionally a line range). Use offset/limit (1-based) "
                       "for large files.",
               {"type": "object",
                "properties": {"path": {"type": "string"},
                               "offset": {"type": "number"},
                               "limit": {"type": "number"}},
                "required": ["path"]}),
    "grep": _t("grep", "Search file contents with a Python regular expression. "
                       "output_mode: 'content' (default, with file:line), 'files' "
                       "(just filenames), 'count'. Optional path/glob to scope.",
               {"type": "object",
                "properties": {"pattern": {"type": "string"},
                               "path": {"type": "string"},
                               "glob": {"type": "string"},
                               "output_mode": {"type": "string",
                                               "enum": ["content", "files", "count"]}},
                "required": ["pattern"]}),
    "glob": _t("glob", "Find files by glob pattern (e.g. '**/*.py'). Returns "
                       "matching paths under the repo.",
               {"type": "object",
                "properties": {"pattern": {"type": "string"},
                               "path": {"type": "string"}},
                "required": ["pattern"]}),
    "bash": _t("bash", "Run a shell command in the writable scratch directory. "
                       "The repository is available only through its explicit "
                       "path. Use for PoCs or read-only inspection. Avoid "
                       "long-running / network commands.",
               {"type": "object",
                "properties": {"command": {"type": "string"},
                               "timeout": {"type": "number"}},
                "required": ["command"]}),
}

# W7: advertised only when user_input.live_target is present. The host is
# pinned to live_target.url inside the probe — the model cannot aim it
# elsewhere.
# Stages allowed to hold a live probe — mirrors runner._LIVE_PROBE_STAGES.
_LIVE_PROBE_STAGES = frozenset({"hunt", "validate", "trace"})

LIVE_PROBE_TOOL = _t(
    "live_probe",
    "Send one HTTP request to the pinned live target under test "
    "(live_target.url). `path` is a path on that host (absolute URLs are "
    "accepted only for the same host). Redirects are not followed; the "
    "3xx response is returned for inspection. Bodies are capped at 64KB, "
    "responses at 64KB, timeout 10s.",
    _LIVE_PROBE_SCHEMA,
)

# map codesec's PascalCase config names -> our tool defs
_NAME_MAP = {"Read": "read", "Grep": "grep", "Glob": "glob", "Bash": "bash"}


# ---- tool execution ---------------------------------------------------------

_READ_CAP = 24_000
_READ_LINE_PAGE = 400
_GREP_MATCH_CAP = 200
_GLOB_MATCH_CAP = 500
# Never load files above this size into memory in tools. A ~600MB Rust
# build artifact under target/ OOM-killed the scanner on an 8GB host
# (read_text on the binary -> multi-GB Python str).
_TOOL_FILE_SIZE_CAP = 8 * 1024 * 1024
_IGNORED_PARTS = {
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    "node_modules",
    "vendor",
    "dist",
    "build",
    "target",
}


class ContextBudgetError(AgentRunError):
    """Authoritative structured input cannot fit without losing fields."""


def pack_user_input(user_input: dict, *, max_chars: int = 50_000) -> str:
    """Serialize a whole valid JSON document or fail before inference."""
    serialized = json.dumps(user_input, ensure_ascii=False)
    if len(serialized) > max_chars:
        digest = hashlib.sha256(serialized.encode()).hexdigest()
        raise ContextBudgetError(
            "structured user input exceeds context budget: "
            f"{len(serialized)} chars > {max_chars}; sha256={digest}"
        )
    return serialized


def _redact_artifact_input(value: Any, *, redact_values: bool = False) -> Any:
    """Return a structure safe to persist in transcripts."""
    if redact_values:
        if isinstance(value, dict):
            return {
                key: _redact_artifact_input(item, redact_values=True)
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [
                _redact_artifact_input(item, redact_values=True)
                for item in value
            ]
        return "[REDACTED]"
    if isinstance(value, dict):
        redacted = {}
        for key, item in value.items():
            normalized = key.lower().replace("-", "_")
            sensitive = (
                normalized == "credentials"
                or any(
                    marker in normalized
                    for marker in (
                        "password",
                        "token",
                        "secret",
                        "api_key",
                        "authorization",
                        "cookie",
                    )
                )
            )
            redacted[key] = _redact_artifact_input(
                item, redact_values=sensitive
            )
        return redacted
    if isinstance(value, list):
        return [_redact_artifact_input(item) for item in value]
    return value


def _continuable_json_body(text: str) -> str | None:
    """Return a JSON-looking body only for accepted output envelopes."""
    body = (text or "").strip()
    if body.startswith("<think>"):
        close = body.find("</think>")
        if close == -1:
            return None
        body = body[close + len("</think>"):].strip()
    if body.startswith("```"):
        first_newline = body.find("\n")
        if first_newline == -1:
            return None
        opening = body[:first_newline].strip().lower()
        if opening not in {"```", "```json"}:
            return None
        body = body[first_newline + 1:].strip()
        if body.endswith("```"):
            body = body[:-3].rstrip()
    return body if body.startswith(("{", "[")) else None


class ToolArgumentError(ValueError):
    """A model emitted malformed or non-object function arguments."""


def _sanitize_tool_args(raw: str) -> str:
    """Return raw if it is valid JSON, else "{}"."""
    try:
        json.loads(raw or "{}")
        return raw or "{}"
    except (json.JSONDecodeError, TypeError):
        return "{}"


def _decode_tool_arguments(raw: str) -> dict:
    try:
        value = json.loads(raw or "{}")
    except json.JSONDecodeError as error:
        raise ToolArgumentError(f"tool arguments are invalid JSON: {error}") from error
    if not isinstance(value, dict):
        raise ToolArgumentError("tool arguments must be a JSON object")
    return value


# ---- context window management --------------------------------------------

# Conservative character-to-token ratio for Qwen BPE and similar tokenizers.
# We use this to estimate prompt size before sending; if the estimate is over
# the model's context window we drop the oldest non-essential turns.
_CHARS_PER_TOKEN = 3.5
_MESSAGE_OVERHEAD_TOKENS = 10


def _message_token_estimate(msg: dict) -> float:
    chars = 0
    content = msg.get("content")
    if isinstance(content, str):
        chars += len(content)
    tool_calls = msg.get("tool_calls")
    if tool_calls:
        chars += len(json.dumps(tool_calls))
    return chars / _CHARS_PER_TOKEN + _MESSAGE_OVERHEAD_TOKENS


def _estimate_prompt_tokens(messages: list, tools: list, max_tokens: int) -> int:
    total = sum(_message_token_estimate(m) for m in messages)
    if tools:
        total += len(json.dumps(tools)) / _CHARS_PER_TOKEN
    return int(total) + max_tokens


def _prune_messages(messages: list, tools: list, max_tokens: int,
                    context_limit: int) -> None:
    """Drop oldest non-system, non-initial-user messages until the estimated
    prompt fits inside the model's context window with the requested output.

    We always keep the system prompt and the initial user task, then retain as
    much of the recent conversation as possible. This is a safety valve for
    long multi-turn runs on large repos that would otherwise hit the provider's
    context-length limit.
    """
    buffer = 1024
    target = context_limit - max_tokens - buffer
    if target <= 0:
        return
    while _estimate_prompt_tokens(messages, tools, max_tokens) > target and len(messages) > 4:
        # Remove the oldest message after the initial system/user prompt.
        # Index 0 is system, index 1 is the initial user task.
        messages.pop(2)


def _run_bash(args: dict, cwd: Path, *, deadline_ts: float | None = None) -> str:
    """Deadline-aware, process-group-controlled Bash tool (P05).

    ``asyncio.to_thread`` cancellation cannot stop a blocking ``urllib``
    call or a child shell, so instead: every child runs in its own process
    group (setsid), the timeout is bounded by the remaining budget, and on
    expiry (or budget exhaustion) the whole process GROUP is terminated —
    grandchildren included — rather than waiting on an orphan."""
    command = args["command"]
    requested = float(args.get("timeout", 120) or 120)
    if deadline_ts is not None:
        remaining = deadline_ts - time.monotonic()
        timeout = max(0.001, min(requested, remaining + 1.0))
    else:
        timeout = requested
    proc = subprocess.Popen(
        command,
        shell=True,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,  # own process group: killable as a unit
    )
    import signal
    try:
        out, err = proc.communicate(timeout=timeout)
        return (out + err)[:_READ_CAP] or "(no output)"
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            proc.kill()
        out, err = proc.communicate()
        return (
            f"[bash timeout after {timeout:.1f}s — process group terminated]"
            + (out + err)
        )[:_READ_CAP]


def _exec_tool(
    name: str,
    args: dict,
    cwd: Path,
    *,
    repo_root: Path | None = None,
    live_target: dict | None = None,
    deadline_ts: float | None = None,
) -> str:
    repo = (repo_root or cwd).resolve()

    def _resolve_in_repo(raw: Any) -> Path:
        candidate = Path(str(raw))
        resolved = (candidate if candidate.is_absolute() else repo / candidate).resolve()
        if not resolved.is_relative_to(repo):
            raise ValueError(f"path is outside repository: {raw!r}")
        return resolved

    def repository_path(raw: Any) -> Path:
        return _resolve_in_repo(raw)

    def repository_scope(raw: Any, *, must_be_dir: bool = False) -> Path:
        """Resolve a search scope (empty -> repo root) with an explicit
        error for missing paths, never a silent "(no matches)"."""
        if raw in (None, ""):
            return repo
        resolved = _resolve_in_repo(raw)
        if not resolved.exists():
            raise FileNotFoundError(f"no such file or directory under repo: {raw!r}")
        if must_be_dir and not resolved.is_dir():
            raise NotADirectoryError(f"path must be a directory, not a file: {raw!r}")
        return resolved

    def iter_repo_files(root: Path, pattern: str = "*") -> tuple[list[Path], int]:
        """Centralized enumeration shared by Grep and Glob.

        - Ignore rules apply to path parts RELATIVE TO the repo root, so a
          repo root that is itself named e.g. `target` stays fully
          searchable while a nested `target/` build directory is excluded.
        - Deterministic: results are sorted by path.
        - Symlinked directories are not traversed during recursion
          (pathlib rglob does not follow them); symlinked files are accepted
          only when they resolve back inside the repo. Escaping symlinks are
          skipped and counted, never read.
        """
        files: list[Path] = []
        escaped = 0
        for path in sorted(root.rglob(pattern)):
            if not path.is_file():
                continue
            try:
                rel = path.relative_to(repo)
            except ValueError:
                continue
            if any(part in _IGNORED_PARTS for part in rel.parts):
                continue
            if not path.resolve().is_relative_to(repo):
                escaped += 1
                continue
            files.append(path)
        return files, escaped

    try:
        if name == "read":
            p = repository_path(args.get("path", ""))
            file_size = p.stat().st_size
            if file_size > _TOOL_FILE_SIZE_CAP:
                return (
                    f"[refused: {p.relative_to(repo)} is {file_size} bytes "
                    f"(> {_TOOL_FILE_SIZE_CAP}); use grep with a scoped pattern]"
                )
            with p.open("rb") as _fh:
                if b"\0" in _fh.read(8192):
                    return (
                        f"[refused: {p.relative_to(repo)} looks binary; "
                        "use grep with a scoped pattern]"
                    )
            txt = p.read_text(errors="replace")
            lines = txt.splitlines()
            off = max(1, int(args.get("offset", 1) or 1))
            if not lines:
                return "(empty file)"
            if off > len(lines):
                return (
                    f"(no lines at offset {off}; total_lines={len(lines)})"
                )
            lim = args.get("limit")
            limit = (
                max(1, int(lim))
                if lim is not None
                else _READ_LINE_PAGE
            )
            page = lines[off - 1: off - 1 + limit]
            rendered: list[str] = []
            size = 0
            for line_number, line in enumerate(page, off):
                numbered = f"{line_number}:{line}"
                if rendered and size + len(numbered) + 1 > _READ_CAP:
                    break
                if not rendered and len(numbered) > _READ_CAP:
                    numbered = numbered[:_READ_CAP]
                rendered.append(numbered)
                size += len(numbered) + 1
            next_offset = off + len(rendered)
            if next_offset <= len(lines):
                rendered.append(
                    f"[truncated: next_offset={next_offset}; "
                    f"total_lines={len(lines)}]"
                )
            return "\n".join(rendered) or "(empty file)"
        if name == "grep":
            pat = re.compile(args["pattern"])
            mode = args.get("output_mode", "content")
            root = repository_scope(args.get("path"))
            if root.is_file():
                # File-scoped search: search exactly that file (an explicit
                # rglob on a file yields nothing — that bug hid results).
                files = [root]
                escaped = 0
            else:
                files, escaped = iter_repo_files(
                    root, pattern=args.get("glob") or "*"
                )
            res: list[str] = []
            total = 0
            skipped_large = 0
            for f in files:
                try:
                    if f.stat().st_size > _TOOL_FILE_SIZE_CAP:
                        skipped_large += 1
                        continue
                    match_count = 0
                    for i, line in enumerate(f.read_text(errors="replace").splitlines(), 1):
                        if pat.search(line):
                            if mode == "files":
                                total += 1
                                if len(res) < _GREP_MATCH_CAP:
                                    res.append(str(f.relative_to(repo)))
                                break
                            elif mode == "count":
                                match_count += 1
                            else:
                                total += 1
                                if len(res) < _GREP_MATCH_CAP:
                                    res.append(
                                        f"{f.relative_to(repo)}:{i}:{line}"
                                    )
                    if mode == "count" and match_count:
                        total += 1
                        if len(res) < _GREP_MATCH_CAP:
                            res.append(f"{f.relative_to(repo)}:{match_count}")
                except (OSError, UnicodeDecodeError):
                    continue
            if total > len(res):
                res.append(
                    f"[truncated: omitted_matches={total - len(res)}]"
                )
            if skipped_large:
                res.append(
                    f"[skipped {skipped_large} files larger than "
                    f"{_TOOL_FILE_SIZE_CAP} bytes]"
                )
            if escaped:
                res.append(
                    f"[skipped {escaped} symlink(s) escaping the repository]"
                )
            output = "\n".join(res)
            if len(output) > _READ_CAP:
                output = (
                    output[:_READ_CAP]
                    + "\n[truncated: output exceeded byte budget]"
                )
            return output or "(no matches)"
        if name == "glob":
            pat = args["pattern"]
            root = repository_scope(args.get("path"), must_be_dir=True)
            files, escaped = iter_repo_files(root)
            matched = sorted(
                {str(rel) for rel in (f.relative_to(root) for f in files)
                 if PurePath(rel).full_match(pat)}
            )
            rel = matched[:_GLOB_MATCH_CAP]
            if len(matched) > len(rel):
                rel.append(
                    f"[truncated: omitted_matches={len(matched) - len(rel)}]"
                )
            if escaped:
                rel.append(
                    f"[skipped {escaped} symlink(s) escaping the repository]"
                )
            return "\n".join(rel) or "(no matches)"
        if name == "bash":
            return _run_bash(args, cwd, deadline_ts=deadline_ts)
        if name == "live_probe":
            url = (live_target or {}).get("url")
            if not url:
                return "[refused: live_probe is unavailable — no live_target configured]"
            return json.dumps(
                _live_probe_request(
                    url,
                    method=args.get("method", "GET"),
                    path=args.get("path", "/"),
                    headers=args.get("headers"),
                    body=args.get("body"),
                ),
                ensure_ascii=False,
            )
    except subprocess.TimeoutExpired:
        return f"[bash timeout after {args.get('timeout',120)}s]"
    except Exception as e:
        return f"[tool error: {type(e).__name__}: {e}]"
    return f"[unknown tool: {name}]"


# ---- the agent loop ---------------------------------------------------------

def _consume_sse(r: Any, *, deadline_ts: float | None = None) -> dict:
    """Rebuild a non-stream chat completion from an OpenAI SSE stream.

    Hosted gateways (Hetzner, Cloudflare-fronted vLLM) kill idle non-streaming
    requests: the connection sits byte-silent while the model generates, hits
    the gateway's upstream timeout, and returns 504/hangs. Streaming keeps
    bytes flowing, so every chunk resets the idle timer.

    P03: preserves streamed reasoning (``reasoning_content`` / ``reasoning`` /
    ``reasoning_text`` deltas — same field set Pi reads) on the rebuilt
    assistant message, and keeps the provider's usage payload verbatim
    (including reasoning/cache details when supplied — never fabricated).

    ``deadline_ts`` is a monotonic wall cutoff for model work (P05): a
    continuously streaming response cannot extend it — the socket idle
    timeout alone never bounds a stream that keeps producing bytes.
    """
    content_parts: list[str] = []
    reasoning_parts: list[str] = []
    reasoning_field: str | None = None
    tool_calls: dict[int, dict] = {}
    finish: str | None = None
    usage: dict = {}
    done = False
    stream: Any = r
    if (r.headers.get("Content-Encoding") or "").strip().lower() == "gzip":
        import gzip
        stream = gzip.GzipFile(fileobj=r)
    try:
        for raw in stream:
            if deadline_ts is not None and time.monotonic() > deadline_ts:
                from codesec.deadline import TimeBudgetExceeded
                raise TimeBudgetExceeded(
                    "model-work deadline reached mid-stream"
                )
            line = raw.decode("utf-8", "replace").strip()
            if not line.startswith("data:"):
                continue
            data = line[len("data:"):].strip()
            if data == "[DONE]":
                done = True
                break
            try:
                chunk = json.loads(data)
            except json.JSONDecodeError:
                continue
            if chunk.get("usage"):
                usage = chunk["usage"]
            for choice in chunk.get("choices") or []:
                finish = choice.get("finish_reason") or finish
                delta = choice.get("delta") or {}
                if delta.get("content"):
                    content_parts.append(delta["content"])
                for field in REASONING_DELTA_FIELDS:
                    value = delta.get(field)
                    if isinstance(value, str) and value:
                        if reasoning_field is None:
                            reasoning_field = field
                        reasoning_parts.append(value)
                        break
                for tc in delta.get("tool_calls") or []:
                    slot = tool_calls.setdefault(
                        tc.get("index", 0),
                        {"id": "", "name": "", "arguments": ""},
                    )
                    if tc.get("id"):
                        slot["id"] = tc["id"]
                    fn = tc.get("function") or {}
                    if fn.get("name"):
                        slot["name"] = fn["name"]
                    if fn.get("arguments"):
                        slot["arguments"] += fn["arguments"]
    except http.client.IncompleteRead as e:
        raise TransientAgentError(
            f"stream truncated mid-response: {e!r}") from None
    if not done and finish is None:
        # Stream ended without [DONE] or a finish reason: treat as a
        # transient network failure, not an empty model turn.
        raise TransientAgentError("stream ended before completion")
    message: dict = {
        "role": "assistant",
        "content": "".join(content_parts) or None,
    }
    if reasoning_parts:
        message["reasoning_content"] = "".join(reasoning_parts)
        message["reasoning_field"] = reasoning_field or REASONING_DELTA_FIELDS[0]
    if tool_calls:
        message["tool_calls"] = [
            {"id": slot["id"], "type": "function",
             "function": {"name": slot["name"],
                          "arguments": slot["arguments"]}}
            for _, slot in sorted(tool_calls.items())
        ]
    return {"choices": [{"message": message, "finish_reason": finish}],
            "usage": usage}


def chat_completions_url(base_url: str) -> str:
    """Join a provider root onto POST .../chat/completions.

    Z.AI Coding Plan is ``.../api/coding/paas/v4`` (not ``/v1``). llama-server
    and Unsloth are typically ``http://host:port`` or ``.../v1``.
    """
    endpoint = base_url.rstrip("/")
    if endpoint.endswith("/chat/completions"):
        return endpoint
    if endpoint.endswith("/v1") or endpoint.endswith("/paas/v4"):
        return endpoint + "/chat/completions"
    return endpoint + "/v1/chat/completions"


def _chat(base_url: str, api_key: str | None, model: str, messages: list,
          tools: list, temperature: float, max_tokens: int,
          tool_choice: str | dict | None = None,
          reasoning: dict | None = None,
          context_limit: int = 262_144,
          extra_headers: dict | None = None,
          deadline_ts: float | None = None) -> dict:
    """One chat-completions request.

    ``reasoning`` is a serialized ReasoningSpec (P03): the zai_thinking
    protocol sends ``thinking.type=enabled`` + ``reasoning_effort`` — never
    local llama.cpp chat-template kwargs as the hosted control.
    """
    spec = reasoning_from_dict(reasoning)
    _prune_messages(messages, tools, max_tokens, context_limit)
    body = {"model": model, "messages": messages, "temperature": temperature,
            "max_tokens": max_tokens, "stream": True,
            "stream_options": {"include_usage": True}}
    body.update(spec.request_params())
    if tools:
        body["tools"] = tools
    if tool_choice is not None:
        body["tool_choice"] = tool_choice
    chat_url = chat_completions_url(base_url)
    headers = {"Content-Type": "application/json",
               # Hetzner's Envoy ext_proc chokes on urllib's implicit
               # 'Accept-Encoding: identity' over SSE (streams stall -> 504).
               # Advertise gzip and decompress if the server honors it.
               "Accept-Encoding": "gzip",
               # Zen front Cloudflare bans the default Python-urllib UA (error 1010)
               "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36",
               **({"Authorization": f"Bearer {api_key}"} if api_key else {}),
               **(extra_headers or {})}
    req = urllib.request.Request(chat_url, data=json.dumps(body).encode(), headers=headers)
    # P05: socket timeout bounded by the remaining budget so a hung peer
    # cannot outlive the run (deadline is monotonic; wall clock fallback
    # keeps a sane bound when no deadline is set).
    if deadline_ts is not None:
        remaining = deadline_ts - time.monotonic()
        timeout = max(0.001, min(1200.0, remaining + 30.0))
    else:
        timeout = 1200.0
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return _consume_sse(r, deadline_ts=deadline_ts)
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")[:300]
        message = f"upstream {e.code}: {detail}"
        if e.code == 429 or 500 <= e.code < 600:
            raise TransientAgentError(message) from None
        raise RuntimeError(message) from None
    except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as e:
        # Network blip / socket timeout / conn reset on a local server. Raise
        # as transient so run_agent's retry loop backs off and retries instead
        # of one hung call killing the whole asyncio.gather.
        raise TransientAgentError(
            f"local upstream unreachable: {type(e).__name__}: {e}") from None


def run_local_agent(
    *,
    stage: str,
    prompt_file: Path,
    user_input: dict,
    schema_file: Path,
    allowed_tools: list[str],
    model: str,
    cwd: Path,
    base_url: str,
    api_key: str | None = None,
    add_dirs: list[Path] | None = None,
    max_turns: int = 25,
    artifact_dir: Path,
    artifact_name: str,
    temperature: float = 0.6,
    max_tokens: int = 8192,
    reasoning: dict | None = None,
    max_input_chars: int = 50_000,
    repair_attempts: int = 1,
    context_limit: int = 262_144,
    deadline_ts: float | None = None,
) -> AgentResult:
    """Drop-in local replacement for codesec.runner.run_agent."""
    artifact_dir.mkdir(parents=True, exist_ok=True)
    artifact_path = artifact_dir / f"{artifact_name}.jsonl"
    cwd.mkdir(parents=True, exist_ok=True)

    system_prompt = prompt_file.read_text()
    schema_text = schema_file.read_text()
    system_prompt += (
        "\n\n# Output schema\n\nYour final message MUST be a single JSON object "
        "validating against this schema (no prose, no markdown fence):\n\n"
        f"```json\n{schema_text}\n```\n")

    repo_root = (add_dirs[0] if add_dirs else cwd).resolve()
    tools = [ALL_TOOLS[_NAME_MAP[n]] for n in allowed_tools if n in _NAME_MAP]
    # W7: presence of user_input.live_target is the gate — no config change
    # required. If a stage explicitly lists `live_probe` in its tools we
    # still only advertise it when a live target exists. The stage gate
    # mirrors runner._LIVE_PROBE_STAGES — recon/gapfill/dedupe/feedback/
    # report never hold a probe even though live_target is in their input.
    live_target = user_input.get("live_target")
    if not isinstance(live_target, dict) or not live_target.get("url"):
        live_target = None
    if live_target is None or stage not in _LIVE_PROBE_STAGES:
        live_target = None
    if live_target is not None and LIVE_PROBE_TOOL not in tools:
        tools = [*tools, LIVE_PROBE_TOOL]
    serialized_input = pack_user_input(
        user_input, max_chars=max_input_chars
    )
    spec = reasoning_from_dict(reasoning)
    # Operator tags (experiment/cell/attempt/stage) forwarded as headers so
    # the P03 inference gateway can attribute requests without reading
    # message content. JSON object of header-name -> value.
    try:
        _extra_headers = dict(
            json.loads(os.environ.get("CODESEC_REQUEST_HEADERS", "{}"))
        )
    except json.JSONDecodeError:
        _extra_headers = {}
    messages: list[dict] = [
        {"role": "system", "content": system_prompt},
        {
            "role": "user",
            "content": serialized_input,
        },
    ]

    usage_tot = {
        "prompt_tokens": 0,
        "completion_tokens": 0,
        "cached": 0,
        "reasoning_tokens": 0,
        "reasoning_reported": False,
    }
    final_text = ""
    turns = 0
    repair_used = False
    started = time.time()

    with artifact_path.open("w") as art:
        def _w(o):
            art.write(json.dumps(o, default=str, ensure_ascii=False) + "\n"); art.flush()

        def _accumulate_usage(response: dict) -> None:
            usage = response.get("usage") or {}
            usage_tot["prompt_tokens"] += usage.get("prompt_tokens", 0)
            usage_tot["completion_tokens"] += usage.get(
                "completion_tokens", 0
            )
            cached = (
                (usage.get("prompt_tokens_details") or {}).get(
                    "cached_tokens"
                )
                or usage.get("cached_tokens")
                or 0
            )
            usage_tot["cached"] += cached
            # P03: reasoning-token usage only where the provider supplies it
            # (completion_tokens_details.reasoning_tokens / reasoning_tokens)
            # — never a fabricated zero.
            reasoning = (
                (usage.get("completion_tokens_details") or {}).get(
                    "reasoning_tokens"
                )
                or usage.get("reasoning_tokens")
            )
            if isinstance(reasoning, int):
                usage_tot["reasoning_tokens"] += reasoning
                usage_tot["reasoning_reported"] = True

        def _continue_json(text: str) -> str:
            nonlocal turns
            for _ in range(6):
                json_body = _continuable_json_body(text)
                if json_body is None:
                    break
                try:
                    json.loads(json_body)
                    break
                except json.JSONDecodeError:
                    pass
                messages.append(
                    {
                        "role": "user",
                        "content": (
                            "Continue your JSON output exactly from where it "
                            "was cut off. Do not repeat earlier output; add no "
                            "prose or code fence."
                        ),
                    }
                )
                turns += 1
                response = _chat(
                    base_url,
                    api_key,
                    model,
                    messages,
                    tools,
                    temperature,
                    max_tokens,
                    tool_choice="none",
                    reasoning=reasoning,
                    context_limit=context_limit,
                    extra_headers=_extra_headers,
                    deadline_ts=deadline_ts,
                )
                _w({"kind": "continue_response", "response": response})
                _accumulate_usage(response)
                chunk = (
                    ((response.get("choices") or [{}])[0].get(
                        "message", {}
                    ) or {}).get("content")
                    or ""
                )
                if not chunk.strip():
                    break
                text += chunk
                messages.append(
                    {"role": "assistant", "content": chunk}
                )
            return text

        _w({"kind": "meta", "engine": "local", "stage": stage, "model": model,
            "base_url": base_url, "started_at": started,
            "effective_request": effective_request_settings(
                model=model,
                reasoning=spec,
                temperature=temperature,
                max_tokens=max_tokens,
                context_limit=context_limit,
                stream=True,
            )})
        artifact_input = json.dumps(
            _redact_artifact_input(user_input),
            ensure_ascii=False,
        )
        _w(
            {
                "kind": "user",
                "text": artifact_input[:5000],
                "redacted": True,
                "full_input_sha256": hashlib.sha256(
                    serialized_input.encode()
                ).hexdigest(),
                "full_input_chars": len(serialized_input),
                "preview_truncated": len(artifact_input) > 5000,
            }
        )

        for turn in range(max_turns):
            turns += 1
            try:
                resp = _chat(
                    base_url,
                    api_key,
                    model,
                    messages,
                    tools,
                    temperature,
                    max_tokens,
                    reasoning=reasoning,
                    context_limit=context_limit,
                    extra_headers=_extra_headers,
                    deadline_ts=deadline_ts,
                )
            except RuntimeError as e:
                _w({"kind": "api_error", "error": str(e)})
                raise
            _w({"kind": "response", "turn": turn, "response": resp})

            msg = (resp.get("choices") or [{}])[0].get("message", {})
            _accumulate_usage(resp)

            content = msg.get("content") or ""
            tool_calls = msg.get("tool_calls") or []

            # append the assistant turn (preserve tool_calls for the API contract)
            asst = {"role": "assistant", "content": content}
            if tool_calls:
                # Echoing malformed arguments back verbatim makes strict
                # upstreams 400 the whole next request (seen: Qwen3.6 MoE
                # emitting an unterminated string). Sanitize to "{}"; the
                # ToolArgumentError result below tells the model to retry.
                asst["tool_calls"] = [
                    {"id": tc["id"], "type": "function",
                     "function": {"name": tc["function"]["name"],
                                  "arguments": _sanitize_tool_args(
                                      tc["function"]["arguments"])}}
                    for tc in tool_calls]
            # P03: serialize streamed reasoning back onto the assistant
            # history message (including tool-call turns) per the protocol's
            # history policy — Pi-compatible reasoning_content transport.
            asst = spec.serialize_history(
                asst, msg.get("reasoning_content") or ""
            )
            messages.append(asst)

            if not tool_calls:
                final_text = content
                break
            # execute each tool call, feed results back
            for tc in tool_calls:
                fn = tc["function"]["name"]
                try:
                    args = _decode_tool_arguments(tc["function"]["arguments"])
                    result = _exec_tool(fn, args, cwd, repo_root=repo_root,
                                    live_target=live_target,
                                    deadline_ts=deadline_ts)
                except ToolArgumentError as error:
                    args = {}
                    result = json.dumps(
                        {
                            "ok": False,
                            "error": "invalid_tool_arguments",
                            "message": str(error),
                        }
                    )
                _w({"kind": "tool_result", "tool": fn, "args": args,
                    "result": result[:2000]})
                messages.append({"role": "tool", "tool_call_id": tc["id"],
                                 "content": result})
        else:
            final_text = final_text or (content if 'content' in locals() else "")

        # Keep asking for an exact suffix when bare, fenced, or bounded-think
        # JSON was cut off. The tool schema stays byte-stable for KV reuse.
        final_text = _continue_json(final_text)

        # schema validation + one repair turn
        errors = _validate(final_text, schema_file)
        while errors and repair_attempts > 0:
            repair_attempts -= 1
            repair_used = True
            repair = _build_repair_prompt(schema_file, errors)
            messages.append({"role": "user", "content": repair})
            _w({"kind": "repair_request", "text": repair})
            # As above, retain tools for prefix-cache reuse while explicitly
            # preventing a repair response from invoking one.
            turns += 1
            resp = _chat(base_url, api_key, model, messages, tools, temperature,
                         max_tokens, tool_choice="none", reasoning=reasoning,
                         context_limit=context_limit,
                         extra_headers=_extra_headers,
                         deadline_ts=deadline_ts)
            _w({"kind": "repair_response", "response": resp})
            _accumulate_usage(resp)
            msg = (resp.get("choices") or [{}])[0].get("message", {})
            final_text = msg.get("content") or ""
            messages.append(
                {"role": "assistant", "content": final_text}
            )
            final_text = _continue_json(final_text)
            errors = _validate(final_text, schema_file)

        if errors:
            # If repair turned into tool-markup, retry validation against the
            # last non-markup candidate text before giving up.
            if _looks_like_tool_markup(final_text):
                for prev in reversed(messages):
                    if prev.get("role") == "assistant" and isinstance(prev.get("content"), str):
                        cand = prev.get("content") or ""
                        if cand.strip() and not _looks_like_tool_markup(cand):
                            alt_err = _validate(cand, schema_file)
                            if not alt_err:
                                final_text = cand
                                errors = []
                                _w({"kind": "recovered_from_markup", "from_repair": True})
                                break
            if errors:
                _w({"kind": "schema_errors", "errors": errors, "final_text_head": (final_text or "")[:500]})
                raise AgentRunError(f"[{stage}/{artifact_name}] schema validation failed: {errors[:5]}")

        payload = _normalize_stage_payload(extract_json(final_text), schema_file)
        # final hard check after normalize
        post_errs = validate_schema(payload, schema_file)
        if post_errs:
            _w({"kind": "schema_errors", "errors": post_errs, "phase": "post_normalize"})
            raise AgentRunError(f"[{stage}/{artifact_name}] schema validation failed: {post_errs[:5]}")
        _w({"kind": "final_payload", "payload": payload})

    cache_hit = usage_tot["cached"] > 0 and usage_tot["prompt_tokens"] > 0
    if turns > 1:
        log.info("[%s/%s] local engine: %d turns, %d in / %d out tokens "
                 "(%.0f%% prompt cached)%s",
                 stage, artifact_name, turns, usage_tot["prompt_tokens"],
                 usage_tot["completion_tokens"],
                 100 * usage_tot["cached"] / max(1, usage_tot["prompt_tokens"]),
                 "" if cache_hit else " [warm prefix missing]")

    return AgentResult(
        payload=payload,
        cost_usd=0.0,  # local inference — no metered cost
        input_tokens=usage_tot["prompt_tokens"],
        output_tokens=usage_tot["completion_tokens"],
        cache_read_tokens=usage_tot["cached"],
        cache_creation_tokens=None,
        num_turns=turns,
        duration_ms=int((time.time() - started) * 1000),
        session_id=None,
        artifact_path=artifact_path,
        repair_used=repair_used,
        raw_result_message={"engine": "local", "model": model,
                            "usage": usage_tot, "base_url": base_url},
    )



def _build_repair_prompt(schema_file: Path, errors: list[str]) -> str:
    """Schema-aware repair instruction.

    IMPORTANT: do not hardcode recon/hunt-task field names here. Hunt uses
    finding.schema.json (task_id/findings/gaps_observed); recon uses
    recon_output.schema.json with nested hunt_task objects. A wrong hint
    steers the model into emitting TASK-shaped JSON for hunt outputs.
    """
    schema_name = schema_file.name
    try:
        schema = json.loads(schema_file.read_text())
    except Exception:
        schema = {}
    required = schema.get("required") or []
    props = list((schema.get("properties") or {}).keys())
    hints: list[str] = []
    if schema_name.startswith("finding") or (
        "findings" in props and "gaps_observed" in props
    ):
        hints.append(
            "This is HUNT OUTPUT (not a hunt task). Required top-level fields: "
            "task_id, findings, gaps_observed. Do NOT include attack_class, "
            "priority, rationale, scope_hint, or target_files at the top level "
            "(those belong only in the input task). findings/gaps_observed may "
            "be empty arrays."
        )
    elif schema_name.startswith("recon") or "initial_tasks" in props:
        hints.append(
            "This is RECON OUTPUT. Top-level requires subsystems/architecture/"
            "initial_tasks. Each initial_tasks[] item is a hunt task with "
            "task_id, attack_class, scope_hint, target_files, rationale, priority. "
            "Do not include a subsystem field; put that context in rationale."
        )
    elif required or props:
        shape = ", ".join(required or props[:12])
        hints.append(f"Schema `{schema_name}` top-level fields focus on: {shape}.")
    hint_block = (" " + " ".join(hints)) if hints else ""
    return (
        "Your previous message failed JSON-schema validation. Errors:\n"
        + "\n".join(f"- {e}" for e in errors[:15])
        + "\n\nRe-emit the COMPLETE JSON object as plain text only. "
        "Emit a JSON INSTANCE matching the schema — not the schema "
        "definition itself (no \"type\"/\"properties\"/\"$schema\" keys). "
        "Do NOT call tools. Do NOT use markup. Do NOT wrap in markdown. "
        f"Fix ONLY the listed errors. Schema file: `{schema_name}`."
        + hint_block
    )


def _normalize_stage_payload(payload: Any, schema_file: Path) -> Any:
    """Best-effort coercion of near-valid stage JSON into schema shape.

    Models often emit hunt tasks with `subsystem` instead of `rationale`, or
    put recon JSON inside proprietary tool-call markup. This keeps the pipeline
    moving when the semantic content is present.

    Hunt (finding.schema.json) commonly re-echoes the input task fields
    (attack_class/priority/...) alongside findings; strip those extras and
    default missing arrays so additionalProperties:false accepts the payload.
    """
    name = schema_file.name
    if isinstance(payload, list) and name.startswith("recon"):
        payload = {
            "subsystems": [item for item in payload if isinstance(item, dict)]
        }
    if not isinstance(payload, dict):
        return payload
    out = dict(payload)

    # Hunt output / finding.schema.json
    if name.startswith("finding") or (
        ("findings" in out or "gaps_observed" in out)
        and "initial_tasks" not in out
        and "subsystems" not in out
    ):
        # Accept common aliases
        if "findings" not in out:
            for alt in ("results", "vulnerabilities", "issues", "candidates"):
                if isinstance(out.get(alt), list):
                    out["findings"] = out.pop(alt)
                    break
        if "gaps_observed" not in out:
            for alt in ("gaps", "coverage_gaps", "unexamined"):
                if isinstance(out.get(alt), list):
                    out["gaps_observed"] = out.pop(alt)
                    break
        out.setdefault("findings", [])
        out.setdefault("gaps_observed", [])
        if not isinstance(out.get("findings"), list):
            out["findings"] = []
        if not isinstance(out.get("gaps_observed"), list):
            out["gaps_observed"] = []

        # Normalize findings items lightly
        norm_findings = []
        for i, finding in enumerate(out["findings"]):
            if not isinstance(finding, dict):
                continue
            f = dict(finding)
            # common alias fixes
            if "file" not in f and "path" in f:
                f["file"] = f.pop("path")
            if "vuln_class" not in f:
                for alt in ("attack_class", "class", "vulnerability_class", "type"):
                    if f.get(alt):
                        f["vuln_class"] = f.get(alt)
                        break
            if "finding_id" not in f or not f.get("finding_id"):
                tid = re.sub(r"[^a-z0-9_-]+", "-", str(out.get("task_id") or "task").lower())
                f["finding_id"] = f"f_{tid[:40]}_{i+1}"
            # finding_id pattern
            fid = re.sub(r"[^a-z0-9_-]+", "-", str(f.get("finding_id")).lower()).strip("-")
            if not fid.startswith("f_"):
                fid = "f_" + fid
            f["finding_id"] = fid[:66]
            # line numbers
            for lk in ("line_start", "line_end"):
                if lk in f:
                    try:
                        f[lk] = max(1, int(f[lk]))
                    except Exception:
                        pass
            if "line_end" in f and "line_start" in f:
                try:
                    if int(f["line_end"]) < int(f["line_start"]):
                        f["line_end"] = f["line_start"]
                except Exception:
                    pass
            # severity enum coerce
            sev = str(f.get("severity") or "").lower().strip()
            sev_map = {
                "crit": "critical", "critical": "critical",
                "hi": "high", "high": "high",
                "med": "medium", "medium": "medium", "moderate": "medium",
                "lo": "low", "low": "low",
                "info": "informational", "informational": "informational",
                "none": "informational",
            }
            if sev in sev_map:
                f["severity"] = sev_map[sev]
            # confidence
            if "confidence" in f:
                try:
                    c = float(f["confidence"])
                    if c > 1.0 and c <= 100.0:
                        c = c / 100.0
                    f["confidence"] = max(0.0, min(1.0, c))
                except Exception:
                    f["confidence"] = 0.5
            # cwe normalize
            if "cwe" in f and f["cwe"] is not None:
                cwe = str(f["cwe"]).strip().upper()
                m = re.search(r"(\d+)", cwe)
                if m:
                    f["cwe"] = f"CWE-{int(m.group(1))}"
                elif not cwe:
                    f.pop("cwe", None)
            # poc cleanup if partial
            poc = f.get("poc")
            if isinstance(poc, dict):
                if not all(k in poc for k in ("language", "code", "succeeded")):
                    # drop incomplete poc rather than fail whole payload
                    f.pop("poc", None)
                else:
                    p = {
                        "language": str(poc.get("language") or "unknown"),
                        "code": str(poc.get("code") or ""),
                        "succeeded": bool(poc.get("succeeded")),
                    }
                    for opt in ("compile_output", "run_output", "notes"):
                        if opt in poc and poc[opt] is not None:
                            p[opt] = str(poc[opt])
                    f["poc"] = p
            elif poc is not None:
                f.pop("poc", None)
            # conditions: list of attacker-precondition strings
            if "conditions" in f:
                conds = f["conditions"]
                if isinstance(conds, list):
                    f["conditions"] = [
                        str(c) for c in conds if str(c).strip()
                    ]
                    if not f["conditions"]:
                        f.pop("conditions")
                elif not isinstance(conds, (list, type(None))):
                    f.pop("conditions", None)
            # live_evidence: drop when malformed rather than fail the payload
            if "live_evidence" in f:
                le = f["live_evidence"]
                if isinstance(le, dict) and le.get("request") and le.get("response_excerpt"):
                    f["live_evidence"] = {
                        "request": str(le["request"])[:4000],
                        "response_excerpt": str(le["response_excerpt"])[:4000],
                    }
                else:
                    f.pop("live_evidence", None)
            # allowlist finding fields
            allowed_f = {
                "finding_id", "file", "line_start", "line_end", "vuln_class",
                "severity", "cwe", "description", "evidence_snippet", "poc",
                "confidence", "hedged_language", "conditions", "live_evidence",
            }
            f = {k: f[k] for k in allowed_f if k in f}
            norm_findings.append(f)
        out["findings"] = norm_findings

        # hardening notes: [{file, note}] — missing best practices, not findings
        if "hardening" in out:
            if not isinstance(out["hardening"], list):
                out.pop("hardening")
            else:
                notes = []
                for h in out["hardening"]:
                    if not isinstance(h, dict):
                        continue
                    file_v = str(h.get("file") or "").strip()
                    note_v = str(h.get("note") or h.get("notes") or "").strip()
                    if file_v and note_v:
                        notes.append({"file": file_v, "note": note_v})
                if notes:
                    out["hardening"] = notes
                else:
                    out.pop("hardening")

        # uncovered surfaces: [{surface, attack_class?, starting_path?, reason?}]
        if "uncovered" in out:
            if not isinstance(out["uncovered"], list):
                out.pop("uncovered")
            else:
                unc = []
                for u in out["uncovered"]:
                    if isinstance(u, str) and u.strip():
                        u = {"surface": u.strip()}
                    if not isinstance(u, dict):
                        continue
                    surface = str(u.get("surface") or u.get("area") or "").strip()
                    if not surface:
                        continue
                    item = {"surface": surface}
                    for opt in ("attack_class", "starting_path", "reason"):
                        if u.get(opt):
                            item[opt] = str(u[opt])
                    unc.append(item)
                if unc:
                    out["uncovered"] = unc
                else:
                    out.pop("uncovered")

        norm_gaps = []
        for g in out["gaps_observed"]:
            if isinstance(g, str):
                g = {"file_or_subsystem": g, "reason": "not fully examined"}
            if not isinstance(g, dict):
                continue
            gg = dict(g)
            if "file_or_subsystem" not in gg:
                gg["file_or_subsystem"] = str(
                    gg.get("file") or gg.get("subsystem") or gg.get("area") or "unknown"
                )
            if "reason" not in gg or not str(gg.get("reason") or "").strip():
                gg["reason"] = str(gg.get("notes") or gg.get("detail") or "not fully examined")
            allowed_g = {"file_or_subsystem", "reason", "suggested_attack_class"}
            gg = {k: gg[k] for k in allowed_g if k in gg}
            if "suggested_attack_class" in gg:
                gg["suggested_attack_class"] = str(gg["suggested_attack_class"])
            norm_gaps.append(gg)
        out["gaps_observed"] = norm_gaps

        if not out.get("task_id"):
            # leave missing; validator will catch — but try common alias
            if out.get("id"):
                out["task_id"] = str(out["id"])
        if "task_id" in out:
            out["task_id"] = str(out["task_id"])

        # Strip hunt-TASK fields that models echo into hunt OUTPUT
        allowed_top = {
            "task_id", "findings", "gaps_observed", "hardening", "uncovered",
        }
        out = {k: out[k] for k in allowed_top if k in out}
        return out

    # Recon / anything with initial_tasks
    tasks = out.get("initial_tasks")
    if isinstance(tasks, list):
        norm_tasks = []
        for i, task in enumerate(tasks):
            if not isinstance(task, dict):
                continue
            t = dict(task)
            # drop unknown fields that break additionalProperties:false
            # keep only hunt_task fields + temporary aliases we map
            subsystem = t.pop("subsystem", None)
            if "rationale" not in t or not str(t.get("rationale") or "").strip():
                # prefer scope_hint, then subsystem note, then attack_class
                base = (
                    str(t.get("scope_hint") or "").strip()
                    or (f"Target subsystem {subsystem}" if subsystem else "")
                    or str(t.get("attack_class") or "recon-derived task")
                )
                if len(base) < 10:
                    base = (base + " — recon-derived hunt task").strip()
                t["rationale"] = base[:2000]
            if "task_id" not in t or not t.get("task_id"):
                ac = re.sub(r"[^a-z0-9_-]+", "-", str(t.get("attack_class") or "task").lower())
                t["task_id"] = f"{ac[:40] or 'task'}-{i+1}"
            # task_id pattern
            tid = re.sub(r"[^a-z0-9_-]+", "-", str(t.get("task_id")).lower()).strip("-")
            t["task_id"] = (tid or f"task-{i+1}")[:64]
            if "priority" not in t:
                t["priority"] = 3
            try:
                t["priority"] = int(t["priority"])
            except Exception:
                t["priority"] = 3
            t["priority"] = max(1, min(5, t["priority"]))
            if "source" in t and t["source"] not in ("recon", "gapfill", "feedback"):
                t["source"] = "recon"
            if not t.get("source"):
                t["source"] = "recon"
            # target_files must be list of strings
            tf = t.get("target_files") or t.get("files") or t.get("paths") or []
            if isinstance(tf, str):
                tf = [tf]
            t["target_files"] = [str(x) for x in tf if str(x).strip()]
            if not t["target_files"]:
                # skip empty targets — contracts will reject otherwise; better fewer
                continue
            if "attack_class" not in t or not str(t.get("attack_class") or "").strip():
                t["attack_class"] = "logic_bug"
            if "scope_hint" not in t or len(str(t.get("scope_hint") or "")) < 10:
                t["scope_hint"] = str(t.get("rationale") or t.get("attack_class"))[:500]
                if len(t["scope_hint"]) < 10:
                    t["scope_hint"] = f"Investigate {t['attack_class']} in listed target files"
            # policy: keep only a dict of known knobs (recon post-pass may
            # overwrite/extend; schema owns the enum constraints)
            if "policy" in t:
                pol = t["policy"]
                if isinstance(pol, dict):
                    allowed_pol = {
                        "search_mode", "attempts_budget", "designer_trust",
                        "report_partial",
                    }
                    pol = {k: pol[k] for k in allowed_pol if k in pol}
                    if pol:
                        t["policy"] = pol
                    else:
                        t.pop("policy")
                else:
                    t.pop("policy", None)
            # final allowlist for hunt_task
            allowed = {"task_id", "attack_class", "scope_hint", "target_files", "rationale", "priority", "source", "policy"}
            t = {k: t[k] for k in allowed if k in t}
            norm_tasks.append(t)
        out["initial_tasks"] = norm_tasks

    # architecture defaults — only when the model actually provided one.
    # Do NOT fabricate a missing architecture: let the validator flag the
    # error so the model is asked to repair (rather than persisting an empty
    # architecture that starves downstream hunt/gapfill of context).
    if name.startswith("recon") or "initial_tasks" in out or "subsystems" in out:
        arch = out.get("architecture")
        if isinstance(arch, dict):
            arch = dict(arch)
            arch.setdefault("build_commands", [])
            arch.setdefault("entry_points", [])
            arch.setdefault("trust_boundaries", [])
            # coerce entry_points items
            eps = []
            for ep in arch.get("entry_points") or []:
                if not isinstance(ep, dict):
                    continue
                e = dict(ep)
                e.setdefault("kind", "library_api")
                e.setdefault("location", e.get("path") or e.get("name") or "unknown")
                # strip extras
                eps.append({k: e[k] for k in ("kind", "location", "auth_required", "notes") if k in e or k in ("kind", "location")})
                if "auth_required" not in eps[-1] and "auth_required" in e:
                    eps[-1]["auth_required"] = e["auth_required"]
                if "notes" in e:
                    eps[-1]["notes"] = e["notes"]
            if eps:
                arch["entry_points"] = eps
            tbs = []
            for tb in arch.get("trust_boundaries") or []:
                if not isinstance(tb, dict):
                    continue
                b = dict(tb)
                b.setdefault("name", "boundary")
                b.setdefault("description", b.get("notes") or b.get("name") or "trust boundary")
                tbs.append({k: b[k] for k in ("name", "description", "source_zone", "sink_zone") if k in b or k in ("name", "description")})
            if tbs:
                arch["trust_boundaries"] = tbs
            out["architecture"] = arch
        # GLM-5.3 often emits a bare subsystem list and never repairs into
        # architecture/initial_tasks. Seed the minimum valid object so one
        # bad recon shape does not abort the whole trial.
        if name.startswith("recon"):
            subs = [s for s in (out.get("subsystems") or []) if isinstance(s, dict)]
            tasks = out.get("initial_tasks")
            bare_list = not isinstance(tasks, list) or not tasks
            # Only seed when recon emitted subsystems with no hunt tasks
            # (typical GLM-5.3 bare array). If tasks exist but architecture
            # does not, leave it for a repair turn.
            if subs and bare_list and not isinstance(out.get("architecture"), dict):
                loc = str(subs[0].get("path") or "app.py")
                out["architecture"] = {
                    "build_commands": [],
                    "entry_points": [{"kind": "http_route", "location": loc}],
                    "trust_boundaries": [
                        {
                            "name": "http_to_app",
                            "description": "Recon omitted architecture; default HTTP-to-app boundary.",
                        }
                    ],
                }
            if subs and bare_list:
                seeded = []
                for i, sub in enumerate(subs[:20]):
                    path = str(sub.get("path") or ".")
                    purpose = str(sub.get("purpose") or sub.get("name") or "component")
                    hint = f"Review {path} for injection and auth issues. {purpose}"
                    if len(hint) < 10:
                        hint = f"Review {path} for security issues in this subsystem"
                    seeded.append(
                        {
                            "task_id": f"t-recon-seed-{i+1}",
                            "attack_class": "injection",
                            "scope_hint": hint[:500],
                            "target_files": [path],
                            "rationale": (
                                f"Seeded because recon listed subsystem "
                                f"{sub.get('name') or path} without hunt tasks."
                            ),
                            "priority": 3,
                            "source": "recon",
                        }
                    )
                if seeded:
                    out["initial_tasks"] = seeded
    return out


def _looks_like_tool_markup(text: str) -> bool:
    t = text or ""
    return (
        "<|message_model|>" in t
        or "<|content_invoke_tool_json|>" in t
        or "invoke_tool_json" in t
        or (t.strip().startswith("<|") and "args" in t)
    )



def _validate(text: str, schema_file: Path) -> list[str]:
    try:
        payload = extract_json(text)
    except ValueError as e:
        return [f"json_extract: {e}"]
    try:
        payload = _normalize_stage_payload(payload, schema_file)
    except Exception as e:
        return [f"normalize: {e}"]
    return validate_schema(payload, schema_file)
