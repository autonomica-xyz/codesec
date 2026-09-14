"""Tests for the hand-rolled tools in codesec.local_agent (no server needed)."""

from __future__ import annotations

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
    assert captured["chat_template_kwargs"] == {"enable_thinking": False}


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
