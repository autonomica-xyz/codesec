"""Tests for the hand-rolled tools in codesec.local_agent (no server needed)."""

from __future__ import annotations

import http.client
import io
import json
import urllib.error
from pathlib import Path

import pytest

from codesec import local_agent
from codesec.local_agent import (
    ALL_TOOLS,
    _NAME_MAP,
    ContextBudgetError,
    ToolArgumentError,
    _chat,
    _decode_tool_arguments,
    _exec_tool,
    _continuable_json_body,
    _redact_artifact_input,
    pack_user_input,
)
from codesec.runner import TransientAgentError


def test_name_map_and_tool_set():
    assert set(_NAME_MAP) == {"Read", "Grep", "Glob", "Bash"}
    assert set(ALL_TOOLS) == {"read", "grep", "glob", "bash"}
    for d in ALL_TOOLS.values():
        assert d["type"] == "function"
        assert "name" in d["function"]


def _make_repo(tmp_path: Path) -> Path:
    (tmp_path / "a.py").write_text("import os\npassword = 'hunter2'\nprint(1)\n")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b.py").write_text("x = 1\n")
    return tmp_path


def test_read(tmp_path):
    cwd = _make_repo(tmp_path)
    out = _exec_tool("read", {"path": "a.py"}, cwd)
    assert "hunter2" in out and "import os" in out
    out2 = _exec_tool("read", {"path": "a.py", "offset": 2, "limit": 1}, cwd)
    assert out2.splitlines()[0] == "2:password = 'hunter2'"
    assert "next_offset=3" in out2


def test_read_is_line_numbered_and_returns_continuation_offset(tmp_path):
    path = tmp_path / "large.py"
    path.write_text("".join(f"value_{line} = {line}\n" for line in range(1, 502)))

    out = _exec_tool("read", {"path": "large.py"}, tmp_path)

    assert out.startswith("1:value_1 = 1")
    assert "[truncated: next_offset=401" in out
    assert "value_501" not in out


def test_grep_content_files_count(tmp_path):
    cwd = _make_repo(tmp_path)
    assert "a.py:2" in _exec_tool("grep", {"pattern": "hunter2"}, cwd)
    assert "a.py" in _exec_tool("grep", {"pattern": "hunter2", "output_mode": "files"}, cwd)
    assert _exec_tool(
        "grep", {"pattern": "import|print", "output_mode": "count"}, cwd
    ) == "a.py:2"
    assert _exec_tool("grep", {"pattern": "zzzznotfound"}, cwd) == "(no matches)"


def test_grep_caps_matches_and_reports_omitted_count(tmp_path):
    (tmp_path / "many.txt").write_text("needle\n" * 250)

    out = _exec_tool("grep", {"pattern": "needle"}, tmp_path)

    assert "many.txt:1:needle" in out
    assert "[truncated: omitted_matches=50]" in out


def test_glob(tmp_path):
    cwd = _make_repo(tmp_path)
    out = _exec_tool("glob", {"pattern": "**/*.py"}, cwd)
    assert "a.py" in out and "sub/b.py" in out
    assert _exec_tool("glob", {"pattern": "**/*.nope"}, cwd) == "(no matches)"


def test_bash(tmp_path):
    cwd = _make_repo(tmp_path)
    out = _exec_tool("bash", {"command": "ls a.py && echo done"}, cwd)
    assert "a.py" in out and "done" in out


def test_repository_tools_and_bash_use_separate_roots(tmp_path):
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    repo = _make_repo(repo_dir)
    scratch = tmp_path / "scratch"
    scratch.mkdir()

    read_result = _exec_tool(
        "read", {"path": "a.py"}, scratch, repo_root=repo
    )
    bash_result = _exec_tool("bash", {"command": "pwd"}, scratch, repo_root=repo)

    assert "hunter2" in read_result
    assert bash_result.strip() == str(scratch)


def test_repository_tools_reject_path_traversal(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    secret = tmp_path / "secret.txt"
    secret.write_text("do not expose")

    result = _exec_tool(
        "read", {"path": "../secret.txt"}, repo, repo_root=repo
    )

    assert "outside repository" in result
    assert "do not expose" not in result


def test_unknown_tool(tmp_path):
    assert "unknown tool" in _exec_tool("frobnicate", {}, tmp_path)


def test_read_missing_file_is_handled(tmp_path):
    assert "tool error" in _exec_tool("read", {"path": "nope.py"}, tmp_path)


def test_chat_keeps_tools_when_tool_choice_is_none(monkeypatch):
    captured = {}

    class Response:
        headers = {}

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def __iter__(self):
            yield b'data: {"choices":[{"index":0,"delta":{"content":"ok"},"finish_reason":"stop"}]}\n\n'
            yield b'data: [DONE]\n\n'

        def read(self):
            return b'{"choices":[]}'

    def fake_urlopen(request, timeout):
        captured.update(json.loads(request.data))
        return Response()

    monkeypatch.setattr(local_agent.urllib.request, "urlopen", fake_urlopen)
    _chat(
        "http://localhost:8888",
        None,
        "model",
        [{"role": "user", "content": "repair"}],
        [ALL_TOOLS["read"]],
        0.6,
        128,
        tool_choice="none",
    )

    assert captured["tools"] == [ALL_TOOLS["read"]]
    assert captured["tool_choice"] == "none"
    # P03: no generic thinking flag on the wire. Default protocol "none"
    # sends no reasoning control at all; the llama chat-template kwarg is a
    # separate explicit protocol, never the hosted default.
    assert "chat_template_kwargs" not in captured
    assert "thinking" not in captured
    assert "reasoning_effort" not in captured


def test_chat_sends_zai_thinking_protocol(monkeypatch):
    captured = {}

    class Response:
        headers = {}

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def __iter__(self):
            yield b'data: {"choices":[{"index":0,"delta":{"content":"ok"},"finish_reason":"stop"}]}\n\n'
            yield b"data: [DONE]\n\n"

        def read(self):
            return b'{"choices":[]}'

    def fake_urlopen(request, timeout):
        captured.update(json.loads(request.data))
        return Response()

    monkeypatch.setattr(local_agent.urllib.request, "urlopen", fake_urlopen)
    _chat(
        "https://api.z.ai/api/coding/paas/v4",
        None,
        "glm-5.3",
        [{"role": "user", "content": "test"}],
        [],
        0.6,
        32768,
        reasoning={
            "protocol": "zai_thinking",
            "enabled": True,
            "effort": "low",
            "history": "preserve",
        },
    )

    assert captured["thinking"] == {"type": "enabled"}
    assert captured["reasoning_effort"] == "low"
    assert "chat_template_kwargs" not in captured
    assert captured["temperature"] == 0.6
    assert captured["max_tokens"] == 32768
    assert captured["stream"] is True


def test_chat_sends_llama_chat_template_protocol(monkeypatch):
    captured = {}

    class Response:
        headers = {}

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def __iter__(self):
            yield b'data: {"choices":[{"index":0,"delta":{"content":"ok"},"finish_reason":"stop"}]}\n\n'
            yield b"data: [DONE]\n\n"

        def read(self):
            return b'{"choices":[]}'

    def fake_urlopen(request, timeout):
        captured.update(json.loads(request.data))
        return Response()

    monkeypatch.setattr(local_agent.urllib.request, "urlopen", fake_urlopen)
    _chat(
        "http://localhost:8888/v1",
        None,
        "qwen-local",
        [{"role": "user", "content": "test"}],
        [],
        0.6,
        8192,
        reasoning={
            "protocol": "llama_chat_template",
            "enabled": True,
        },
    )

    assert captured["chat_template_kwargs"] == {"enable_thinking": True}
    assert "thinking" not in captured
    assert "reasoning_effort" not in captured


def test_chat_accepts_endpoint_with_v1_suffix(monkeypatch):
    captured = {}

    class Response:
        headers = {}

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def __iter__(self):
            yield b'data: {"choices":[{"index":0,"delta":{"content":"ok"},"finish_reason":"stop"}]}\n\n'
            yield b'data: [DONE]\n\n'

        def read(self):
            return b'{"choices":[]}'

    def fake_urlopen(request, timeout):
        captured["url"] = request.full_url
        return Response()

    monkeypatch.setattr(local_agent.urllib.request, "urlopen", fake_urlopen)

    _chat(
        "http://localhost:8888/v1",
        None,
        "model",
        [{"role": "user", "content": "test"}],
        [],
        0,
        128,
    )

    assert captured["url"] == "http://localhost:8888/v1/chat/completions"


def test_chat_completions_url_for_zai_coding_paas():
    from codesec.local_agent import chat_completions_url
    assert chat_completions_url("https://api.z.ai/api/coding/paas/v4") == (
        "https://api.z.ai/api/coding/paas/v4/chat/completions"
    )
    assert chat_completions_url("http://127.0.0.1:8080") == (
        "http://127.0.0.1:8080/v1/chat/completions"
    )


def test_chat_classifies_http_500_as_transient(monkeypatch):
    def fail(request, timeout):
        raise urllib.error.HTTPError(
            request.full_url,
            500,
            "server error",
            {},
            io.BytesIO(b'{"error":"temporary"}'),
        )

    monkeypatch.setattr(local_agent.urllib.request, "urlopen", fail)

    with pytest.raises(TransientAgentError, match="upstream 500"):
        _chat(
            "http://localhost:8888",
            None,
            "model",
            [{"role": "user", "content": "test"}],
            [],
            0,
            128,
        )


def test_large_user_input_is_rejected_before_json_can_be_truncated():
    payload = {"required_ids": ["f_1"], "body": "x" * 60_000}

    with pytest.raises(ContextBudgetError, match="600"):
        pack_user_input(payload, max_chars=50_000)


def test_malformed_tool_arguments_are_not_coerced_to_an_empty_object():
    with pytest.raises(ToolArgumentError, match="invalid JSON"):
        _decode_tool_arguments('{"path":')


def test_artifact_input_redacts_credentials_recursively():
    payload = {
        "live_target": {
            "url": "http://localhost",
            "credentials": {
                "email": "admin@example.test",
                "password": "super-secret",
                "token": "bearer-secret",
            },
        },
        "api_key": "key-secret",
        "ordinary": "visible",
    }

    redacted = _redact_artifact_input(payload)

    assert redacted["live_target"]["credentials"] == {
        "email": "[REDACTED]",
        "password": "[REDACTED]",
        "token": "[REDACTED]",
    }
    assert redacted["api_key"] == "[REDACTED]"
    assert redacted["ordinary"] == "visible"


def test_continuation_detects_bare_fenced_and_bounded_think_json():
    assert _continuable_json_body('{"finding_id":') == '{"finding_id":'
    assert _continuable_json_body("```json\n{\"finding_id\":") == (
        '{"finding_id":'
    )
    assert _continuable_json_body(
        "<think>bounded reasoning</think>\n{\"finding_id\":"
    ) == '{"finding_id":'
    assert _continuable_json_body("prose before {\"finding_id\":") is None


def test_repair_output_can_continue_and_usage_counts_every_request(
    tmp_path,
    monkeypatch,
):
    prompt = tmp_path / "prompt.md"
    prompt.write_text("Return JSON.")
    schema = tmp_path / "schema.json"
    schema.write_text(
        json.dumps(
            {
                "type": "object",
                "required": ["value"],
                "additionalProperties": False,
                "properties": {"value": {"type": "string"}},
            }
        )
    )
    responses = iter(
        [
            {"choices": [{"message": {"content": '{"value": 1}'}}],
             "usage": {"prompt_tokens": 10, "completion_tokens": 2}},
            {"choices": [{"message": {"content": '{"value":"'}}],
             "usage": {"prompt_tokens": 20, "completion_tokens": 3}},
            {"choices": [{"message": {"content": 'ok"}'}}],
             "usage": {"prompt_tokens": 30, "completion_tokens": 4}},
        ]
    )
    monkeypatch.setattr(local_agent, "_chat", lambda *args, **kwargs: next(responses))

    result = local_agent.run_local_agent(
        stage="test",
        prompt_file=prompt,
        user_input={"input": "small"},
        schema_file=schema,
        allowed_tools=[],
        model="model",
        cwd=tmp_path / "scratch",
        base_url="http://localhost:8080",
        artifact_dir=tmp_path / "artifacts",
        artifact_name="attempt",
        max_turns=1,
        repair_attempts=1,
    )

    assert result.payload == {"value": "ok"}
    assert result.input_tokens == 60
    assert result.output_tokens == 9
    assert result.num_turns == 3


def test_live_probe_tool_is_separate_from_config_gated_tools():
    """W7: live_probe is advertised only when user_input.live_target is
    present — it is not part of ALL_TOOLS/_NAME_MAP (no config knob)."""
    from codesec.local_agent import LIVE_PROBE_TOOL

    assert "live_probe" not in ALL_TOOLS
    assert "live_probe" not in _NAME_MAP.values()
    assert LIVE_PROBE_TOOL["function"]["name"] == "live_probe"
    params = LIVE_PROBE_TOOL["function"]["parameters"]
    assert params["required"] == ["path"]
    assert "method" in params["properties"]


def test_exec_tool_live_probe_refuses_without_live_target(tmp_path):
    out = _exec_tool("live_probe", {"path": "/"}, tmp_path)
    assert "refused" in out


# ---- P01: blinded-tree tool behavior (audit finding 1) ----------------------

def _blinded_repo(root: Path) -> Path:
    """Mimic the blinded layout: /tmp/<opaque>/target with app code at top."""
    root.mkdir(parents=True, exist_ok=True)
    (root / "app.py").write_text(
        "from flask import request\n\n\ndef run():\n    payload = request.args.get('p')\n    eval(payload)\n"
    )
    (root / "sub").mkdir()
    (root / "sub" / "helper.py").write_text("def helper():\n    return 1\n")
    return root


def test_repo_root_named_target_is_fully_searchable(tmp_path):
    """Regression: `target` in _IGNORED_PARTS used to blind every blinded
    repo because exclusions were checked against absolute path parts."""
    repo = _blinded_repo(tmp_path / "opaque1" / "target")

    read_out = _exec_tool("read", {"path": "app.py"}, repo)
    grep_out = _exec_tool("grep", {"pattern": "eval"}, repo)
    glob_out = _exec_tool("glob", {"pattern": "**/*.py"}, repo)

    assert "eval(payload)" in read_out
    assert "app.py:6:    eval(payload)" in grep_out
    assert "app.py" in glob_out and "sub/helper.py" in glob_out


def test_target_named_ancestor_of_repo_root_is_searchable(tmp_path):
    """A `target` directory above a differently named repo root must not
    exclude anything either (relative-to-root semantics)."""
    repo = _blinded_repo(tmp_path / "target" / "opaque2" / "proj")

    assert "app.py:6:    eval(payload)" in _exec_tool("grep", {"pattern": "eval"}, repo)
    assert "app.py" in _exec_tool("glob", {"pattern": "**/*.py"}, repo)


def test_nested_target_directory_is_still_ignored(tmp_path):
    """A nested build directory named `target` inside the repo stays
    excluded under the existing policy."""
    repo = _blinded_repo(tmp_path / "opaque3")
    (repo / "target").mkdir()
    (repo / "target" / "generated.py").write_text("eval(payload)\n")

    grep_out = _exec_tool("grep", {"pattern": "eval"}, repo)
    glob_out = _exec_tool("glob", {"pattern": "**/*.py"}, repo)

    assert "app.py:6:    eval(payload)" in grep_out
    assert "generated" not in grep_out
    assert "app.py" in glob_out and "sub/helper.py" in glob_out
    assert "generated.py" not in glob_out


def test_git_venv_and_build_folders_excluded_consistently(tmp_path):
    repo = _blinded_repo(tmp_path / "opaque4")
    for ignored in (".git", ".venv", "node_modules", "__pycache__", "dist"):
        d = repo / ignored
        d.mkdir()
        (d / "noise.py").write_text("eval(payload)\n")

    for tool, args in (
        ("grep", {"pattern": "eval"}),
        ("glob", {"pattern": "**/*.py"}),
    ):
        out = _exec_tool(tool, args, repo)
        assert "noise.py" not in out, (tool, args, out)
        assert "app.py" in out, (tool, args, out)
    # Even explicit ignore-scoped patterns cannot enumerate ignored files.
    assert _exec_tool("glob", {"pattern": "**/noise.py"}, repo) == "(no matches)"
    assert "noise.py" not in _exec_tool(
        "grep", {"pattern": "eval", "glob": "*.py"}, repo
    )


def test_file_scoped_grep_searches_exactly_that_file(tmp_path):
    """Regression: rglob() on a regular file yields nothing, so a supported
    file-scoped Grep used to return '(no matches)' independently of the
    directory-name bug."""
    repo = _blinded_repo(tmp_path / "opaque5" / "target")

    out = _exec_tool("grep", {"pattern": "eval", "path": "app.py"}, repo)

    assert "app.py:6:    eval(payload)" in out
    # Directory-scoped search agrees for the same file and recurses more.
    dir_out = _exec_tool("grep", {"pattern": "eval|helper", "path": "."}, repo)
    assert "app.py:6:    eval(payload)" in dir_out
    assert "helper.py" in dir_out
    # A scoped search that matches nothing in that file is distinguishable
    # from a missing path.
    assert _exec_tool("grep", {"pattern": "helper", "path": "app.py"}, repo) == (
        "(no matches)"
    )


def test_grep_missing_path_is_explicit_error_not_no_matches(tmp_path):
    repo = _blinded_repo(tmp_path)

    out = _exec_tool("grep", {"pattern": "x", "path": "nope.py"}, repo)

    assert out.startswith("[tool error: FileNotFoundError:")
    assert "(no matches)" not in out
    # Read keeps its explicit error too.
    assert "tool error" in _exec_tool("read", {"path": "nope.py"}, repo)
    # Glob path semantics: directory scope or explicit error.
    glob_missing = _exec_tool("glob", {"pattern": "*.py", "path": "nope"}, repo)
    assert glob_missing.startswith("[tool error: FileNotFoundError:")
    glob_file = _exec_tool("glob", {"pattern": "*.py", "path": "app.py"}, repo)
    assert glob_file.startswith("[tool error: NotADirectoryError:")


def test_external_symlink_and_traversal_cannot_expose_host_files(tmp_path):
    repo = _blinded_repo(tmp_path / "opaque6")
    secret = tmp_path / "host-secret.txt"
    secret.write_text("do-not-leak")
    (repo / "host-link.py").symlink_to(secret)
    (repo / "in-link.py").symlink_to(repo / "app.py")

    read_via_link = _exec_tool("read", {"path": "host-link.py"}, repo)
    assert "outside repository" in read_via_link
    assert "do-not-leak" not in read_via_link

    traversal = _exec_tool("read", {"path": "../host-secret.txt"}, repo)
    assert "outside repository" in traversal
    assert "do-not-leak" not in traversal

    grep_all = _exec_tool("grep", {"pattern": "do-not-leak"}, repo)
    assert "do-not-leak" not in grep_all
    assert "[skipped 1 symlink(s) escaping the repository]" in grep_all
    glob_all = _exec_tool("glob", {"pattern": "**/*"}, repo)
    assert "host-link.py" not in glob_all

    # Internal symlinks are deterministic: resolved-in-repo files are
    # searchable; symlinked directories are not traversed during recursion.
    grep_eval = _exec_tool("grep", {"pattern": "eval"}, repo)
    assert "in-link.py:6:    eval(payload)" in grep_eval
    assert "in-link.py" in glob_all
    linkdir = repo / "linkdir"
    linkdir.symlink_to(repo / "sub")
    glob2 = _exec_tool("glob", {"pattern": "**/*.py"}, repo)
    assert "linkdir/helper.py" not in glob2
    assert "sub/helper.py" in glob2


def test_grep_content_count_files_modes_under_target_root(tmp_path):
    repo = _blinded_repo(tmp_path / "opaque7" / "target")
    (repo / "app.py").write_text("eval(payload)\neval(x)\n")

    assert _exec_tool(
        "grep", {"pattern": "eval", "output_mode": "count"}, repo
    ) == "app.py:2"
    files_out = _exec_tool(
        "grep", {"pattern": "eval", "output_mode": "files"}, repo
    )
    assert files_out == "app.py"
    content_out = _exec_tool("grep", {"pattern": "eval"}, repo)
    assert "app.py:1:eval(payload)" in content_out
    assert "app.py:2:eval(x)" in content_out


def test_long_read_paging_neither_skips_nor_repeats_lines(tmp_path):
    repo = tmp_path / "opaque8"
    repo.mkdir()
    total = 1500
    (repo / "big.py").write_text(
        "".join(f"line_{i}\n" for i in range(1, total + 1))
    )

    seen: list[str] = []
    offset = 1
    for _ in range(20):
        out = _exec_tool(
            "read", {"path": "big.py", "offset": offset, "limit": 100}, repo
        )
        body = [l for l in out.splitlines() if not l.startswith("[")]
        seen.extend(body)
        if "[truncated:" not in out:
            break
        offset = int(out.split("next_offset=")[1].split(";")[0])

    assert seen == [f"{i}:line_{i}" for i in range(1, total + 1)]

    # Offset beyond EOF is explicit, not a false 'empty file'.
    tail = _exec_tool("read", {"path": "big.py", "offset": total + 10}, repo)
    assert tail.startswith(f"(no lines at offset {total + 10}; total_lines={total})")
    (repo / "empty.py").write_text("")
    assert _exec_tool("read", {"path": "empty.py"}, repo) == "(empty file)"


def test_empty_vs_missing_vs_error_results_are_distinguishable(tmp_path):
    repo = _blinded_repo(tmp_path)

    assert _exec_tool("grep", {"pattern": "nothing-matches-this"}, repo) == "(no matches)"
    assert _exec_tool("glob", {"pattern": "*.zzz"}, repo) == "(no matches)"
    missing = _exec_tool("grep", {"pattern": "x", "path": "gone"}, repo)
    assert missing.startswith("[tool error: FileNotFoundError:")
    bad_pattern = _exec_tool("grep", {"pattern": "([unclosed"}, repo)
    assert bad_pattern.startswith("[tool error:")
    assert bad_pattern != "(no matches)"


# ---- P03: SSE reasoning preservation, usage fidelity, history transport ----

from codesec.local_agent import _consume_sse


class _FakeSSE:
    def __init__(self, chunks, headers=None, raise_mid=None):
        self._chunks = chunks
        self.headers = headers or {}
        self._raise_mid = raise_mid

    def __iter__(self):
        for i, chunk in enumerate(self._chunks):
            if self._raise_mid is not None and i == self._raise_mid:
                raise http.client.IncompleteRead(b"partial")
            yield chunk


def test_sse_preserves_chunked_reasoning_content_and_tool_calls():
    stream = _FakeSSE([
        b'data: {"choices":[{"index":0,"delta":{"reasoning_content":"think "}}]}\n\n',
        b'data: {"choices":[{"index":0,"delta":{"reasoning_content":"hard"}}]}\n\n',
        b'data: {"choices":[{"index":0,"delta":{"content":"answer"}}]}\n\n',
        b'data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"c1","function":{"name":"read","arguments":"{\\"pa"}}]},"finish_reason":null}]}\n\n',
        b'data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"th\\": \\"a.py\\"}"}}]},"finish_reason":"tool_calls"}]}\n\n',
        b'data: {"usage":{"prompt_tokens":11,"completion_tokens":7,"completion_tokens_details":{"reasoning_tokens":4},"prompt_tokens_details":{"cached_tokens":3}},"choices":[]}\n\n',
        b"data: [DONE]\n\n",
    ])

    out = _consume_sse(stream)

    msg = out["choices"][0]["message"]
    assert msg["content"] == "answer"
    assert msg["reasoning_content"] == "think hard"
    assert msg["tool_calls"][0]["function"] == {
        "name": "read", "arguments": '{"path": "a.py"}'
    }
    assert out["choices"][0]["finish_reason"] == "tool_calls"
    # Usage payload kept verbatim, reasoning + cache details intact.
    assert out["usage"]["completion_tokens_details"]["reasoning_tokens"] == 4
    assert out["usage"]["prompt_tokens_details"]["cached_tokens"] == 3


def test_sse_missing_usage_stays_missing_not_fabricated():
    stream = _FakeSSE([
        b'data: {"choices":[{"index":0,"delta":{"content":"x"},"finish_reason":"stop"}]}\n\n',
        b"data: [DONE]\n\n",
    ])
    out = _consume_sse(stream)
    assert out["usage"] == {}


def test_sse_malformed_events_are_skipped():
    stream = _FakeSSE([
        b"event: ping\n",
        b"data: not-json\n\n",
        b": keepalive comment\n",
        b'data: {"choices":[{"index":0,"delta":{"content":"ok"},"finish_reason":"stop"}]}\n\n',
        b"data: [DONE]\n\n",
    ])
    out = _consume_sse(stream)
    assert out["choices"][0]["message"]["content"] == "ok"


def test_sse_truncation_is_transient():
    import http.client
    stream = _FakeSSE(
        [b'data: {"choices":[{"index":0,"delta":{"content":"par"}}]}\n\n'],
        raise_mid=0,
    )
    with pytest.raises(TransientAgentError, match="truncated"):
        _consume_sse(stream)


def test_sse_terminal_error_maps_to_runtime_error(monkeypatch):
    def fail(request, timeout):
        raise urllib.error.HTTPError(
            request.full_url, 400, "bad request", {}, io.BytesIO(b"{}")
        )

    monkeypatch.setattr(local_agent.urllib.request, "urlopen", fail)
    with pytest.raises(RuntimeError, match="upstream 400"):
        _chat("http://localhost:1", None, "m", [{"role": "user", "content": "x"}], [], 0.6, 64)




def _sse_response_bytes(events):
    return b"".join(b"data: " + e + b"\n\n" for e in events) + b"data: [DONE]\n\n"


def test_real_codesec_client_wire_request_via_mock_server():
    """Drive the REAL codesec client (urllib + SSE reader, no mocks inside
    local_agent) against a local HTTP server: assert the effective zai
    reasoning controls, sampling, history transport, and artifact
    effective-request fingerprint."""
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    requests_seen = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length))
            requests_seen.append(body)
            if len(requests_seen) == 1:
                # Turn 1: reasoning + tool call, with reasoning usage.
                events = [
                    {"choices": [{"index": 0, "delta": {
                        "reasoning_content": "plan: read a.py"}}]},
                    {"choices": [{"index": 0, "delta": {"tool_calls": [{
                        "index": 0, "id": "c1",
                        "function": {"name": "read",
                                     "arguments": '{"path": "a.py"}'}}]},
                        "finish_reason": "tool_calls"}]},
                    {"usage": {"prompt_tokens": 10, "completion_tokens": 5,
                               "completion_tokens_details": {
                                   "reasoning_tokens": 3}}, "choices": []},
                ]
            else:
                events = [
                    {"choices": [{"index": 0, "delta": {
                        "content": '{"value": "done"}'},
                        "finish_reason": "stop"}]},
                    {"usage": {"prompt_tokens": 20, "completion_tokens": 2,
                               "completion_tokens_details": {
                                   "reasoning_tokens": 1}}, "choices": []},
                ]
            payload = _sse_response_bytes(
                [json.dumps(e).encode() for e in events]
            )
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            (td / "repo").mkdir()
            (td / "repo" / "a.py").write_text("x = 1\n")
            (td / "scratch").mkdir()
            prompt = td / "prompt.md"
            prompt.write_text("Return JSON.")
            schema = td / "schema.json"
            schema.write_text(json.dumps({
                "type": "object", "required": ["value"],
                "additionalProperties": False,
                "properties": {"value": {"type": "string"}},
            }))
            result = local_agent.run_local_agent(
                stage="test",
                prompt_file=prompt,
                user_input={"input": "small"},
                schema_file=schema,
                allowed_tools=["Read"],
                model="glm-5.3",
                cwd=td / "scratch",
                add_dirs=[td / "repo"],
                base_url=f"http://127.0.0.1:{server.server_port}/v1",
                artifact_dir=td / "art",
                artifact_name="wire",
                max_turns=4,
                temperature=0.6,
                max_tokens=32768,
                reasoning={
                    "protocol": "zai_thinking",
                    "enabled": True,
                    "effort": "low",
                    "history": "preserve",
                },
            )
            assert result.payload == {"value": "done"}
            assert result.input_tokens == 30
            assert result.output_tokens == 7

            first, second = requests_seen
            for body in (first, second):
                assert body["model"] == "glm-5.3"
                assert body["thinking"] == {"type": "enabled"}
                assert body["reasoning_effort"] == "low"
                assert "chat_template_kwargs" not in body
                assert body["temperature"] == 0.6
                assert body["max_tokens"] == 32768
                assert body["stream"] is True
            # History transport: the tool-call turn's reasoning_content is
            # serialized back on the follow-up request (Pi-compatible).
            tool_turn = second["messages"][2]
            assert tool_turn["role"] == "assistant"
            assert tool_turn["reasoning_content"] == "plan: read a.py"
            assert tool_turn["tool_calls"][0]["function"]["name"] == "read"
            assert second["messages"][3]["role"] == "tool"
            # Reasoning usage counted only where supplied.
            assert result.raw_result_message["usage"]["reasoning_tokens"] == 4
            assert result.raw_result_message["usage"]["reasoning_reported"] is True
    finally:
        server.shutdown()


def test_reasoning_history_drop_policy_omits_reasoning():
    from codesec.reasoning import ReasoningSpec

    spec = ReasoningSpec(protocol="none")
    msg = {"role": "assistant", "content": "x"}
    assert spec.serialize_history(msg, "secret thoughts") == msg
    zai_drop = ReasoningSpec(
        protocol="zai_thinking", enabled=True, effort="low", history="drop"
    )
    assert zai_drop.serialize_history(msg, "secret thoughts") == msg
    zai_keep = ReasoningSpec(
        protocol="zai_thinking", enabled=True, effort="low", history="preserve"
    )
    out = zai_keep.serialize_history(msg, "thoughts")
    assert out["reasoning_content"] == "thoughts"
    assert msg == {"role": "assistant", "content": "x"}  # original untouched


def test_zai_spec_rejects_disabled_and_bad_effort():
    from codesec.reasoning import ReasoningSpec, ReasoningConfigError

    with pytest.raises(ReasoningConfigError, match="rejects"):
        ReasoningSpec(protocol="zai_thinking", enabled=False)
    with pytest.raises(ReasoningConfigError, match="reasoning_effort"):
        ReasoningSpec(protocol="zai_thinking", enabled=True, effort="medium")


def test_effective_request_settings_fingerprint_is_canonical():
    from codesec.reasoning import (
        ReasoningSpec,
        effective_request_settings,
    )

    a = effective_request_settings(
        model="glm-5.3",
        reasoning=ReasoningSpec(protocol="zai_thinking", enabled=True, effort="low"),
        temperature=0.6,
        max_tokens=32768,
        context_limit=262144,
    )
    b = effective_request_settings(
        context_limit=262144,
        max_tokens=32768,
        temperature=0.6,
        reasoning=ReasoningSpec(protocol="zai_thinking", enabled=True, effort="low"),
        model="glm-5.3",
    )
    assert a["fingerprint_sha256"] == b["fingerprint_sha256"]
    different = effective_request_settings(
        model="glm-5.3",
        reasoning=ReasoningSpec(protocol="zai_thinking", enabled=True, effort="high"),
        temperature=0.6,
        max_tokens=32768,
    )
    assert different["fingerprint_sha256"] != a["fingerprint_sha256"]
    assert a["request_params"] == {
        "thinking": {"type": "enabled"}, "reasoning_effort": "low"
    }


def test_sse_active_stream_cannot_extend_model_deadline(monkeypatch):
    """P05: a continuously streaming response may not extend the model-work
    cap — the wall cutoff fires mid-stream even while bytes keep arriving."""
    import time as _time

    from codesec.deadline import TimeBudgetExceeded

    clock = {"t": _time.monotonic()}
    monkeypatch.setattr(
        local_agent.time, "monotonic", lambda: clock["t"])

    class _Streaming:
        headers = {}

        def __iter__(self):
            for i in range(10):
                clock["t"] += 5.0  # each chunk advances the wall 5 s
                yield (
                    b'data: {"choices":[{"index":0,"delta":{"content":"x"'
                    b'}}]}\n\n'
                )

    with pytest.raises(TimeBudgetExceeded):
        _consume_sse(_Streaming(), deadline_ts=clock["t"] + 8.0)


def test_sse_before_deadline_consumes_normally():
    stream = _FakeSSE([
        b'data: {"choices":[{"index":0,"delta":{"content":"ok"},'
        b'"finish_reason":"stop"}]}\n\n',
        b"data: [DONE]\n\n",
    ])
    out = _consume_sse(stream, deadline_ts=None)
    assert out["choices"][0]["message"]["content"] == "ok"
