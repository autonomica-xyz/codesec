"""Tests for the W7 live_probe tool — host pinning is the whole contract."""

from __future__ import annotations

import http.server
import json
import threading
from pathlib import Path

import pytest

from codesec import local_agent, runner
from codesec.local_agent import _exec_tool, run_local_agent
from codesec.live_probe_mcp import http_request
from codesec.runner import TransientAgentError, live_probe_mcp_config


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/redir":
            self.send_response(302)
            self.send_header("Location", "http://203.0.113.9/away")
            self.end_headers()
            return
        body = b"hello-marker"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n)
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture()
def live_server():
    srv = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


# ---- the pinned probe core ---------------------------------------------------

def test_probe_hits_pinned_host(live_server):
    r = http_request(live_server, "GET", "/hello?x=1")
    assert r["ok"] and r["status"] == 200 and r["body"] == "hello-marker"


@pytest.mark.parametrize("path", [
    "http://evil.example/x",        # absolute URL, foreign host
    "//evil.example/x",             # scheme-relative foreign host
    "http://127.0.0.1:1/x",         # same host, wrong port
    "https://127.0.0.1/x",          # same host, wrong scheme->port
])
def test_probe_refuses_foreign_targets(live_server, path):
    r = http_request(live_server, "GET", path)
    assert r["ok"] is False and "refused" in r["error"]


def test_probe_accepts_absolute_url_to_same_host(live_server):
    r = http_request(live_server, "GET", f"{live_server}/hello")
    assert r["ok"] and r["status"] == 200


def test_probe_rejects_non_http_targets():
    for url in ("file:///etc/passwd", "gopher://x/", "ftp://x/"):
        r = http_request(url, "GET", "/")
        assert r["ok"] is False and "refused" in r["error"]


def test_probe_does_not_follow_redirects(live_server):
    r = http_request(live_server, "GET", "/redir")
    assert r["ok"] and r["status"] == 302
    assert r["headers"].get("Location") == "http://203.0.113.9/away"


def test_probe_caps_and_methods(live_server):
    assert "not allowed" in http_request(live_server, "TRACE", "/")["error"]
    big = "x" * (64 * 1024 + 1)
    assert "exceeds" in http_request(live_server, "POST", "/", body=big)["error"]
    assert "managed by the probe" in http_request(
        live_server, "GET", "/", headers={"Host": "evil.example"}
    )["error"]
    # a sane POST round-trips
    r = http_request(live_server, "POST", "/", headers={"Content-Type": "text/plain"},
                     body="ping")
    assert r["ok"] and r["body"] == "ping"


# ---- local engine wiring -----------------------------------------------------

def test_exec_tool_live_probe_refused_without_target(tmp_path):
    out = _exec_tool("live_probe", {"path": "/"}, tmp_path)
    assert "refused" in out


def test_exec_tool_live_probe_uses_pinned_url(tmp_path, live_server):
    out = _exec_tool(
        "live_probe", {"path": "/x"}, tmp_path,
        live_target={"url": live_server},
    )
    payload = json.loads(out)
    assert payload["ok"] and payload["status"] == 200


def _prompt_and_schema(tmp_path):
    prompt = tmp_path / "prompt.md"
    prompt.write_text("Return JSON.")
    schema = tmp_path / "schema.json"
    schema.write_text(json.dumps({
        "type": "object",
        "required": ["value"],
        "additionalProperties": False,
        "properties": {"value": {"type": "string"}},
    }))
    return prompt, schema


def _run_kwargs(tmp_path, user_input):
    prompt, schema = _prompt_and_schema(tmp_path)
    return dict(
        stage="hunt", prompt_file=prompt, user_input=user_input,
        schema_file=schema, allowed_tools=["Read"], model="m",
        cwd=tmp_path / "scratch", base_url="http://localhost:9",
        artifact_dir=tmp_path / "artifacts", artifact_name="t",
        max_turns=3, repair_attempts=0,
    )


def test_local_agent_advertises_live_probe_only_with_live_target(
    tmp_path, monkeypatch
):
    seen: list[list[str]] = []

    def fake_chat(base_url, api_key, model, messages, tools, *a, **kw):
        seen.append([t["function"]["name"] for t in tools])
        return {"choices": [{"message": {"content": '{"value":"ok"}'}}],
                "usage": {}}

    monkeypatch.setattr(local_agent, "_chat", fake_chat)

    run_local_agent(**_run_kwargs(tmp_path, {"input": 1}))
    assert "live_probe" not in seen[-1]

    run_local_agent(**_run_kwargs(
        tmp_path, {"live_target": {"url": "http://127.0.0.1:5199"}}))
    assert "live_probe" in seen[-1]


def test_local_agent_live_probe_tool_call_round_trip(tmp_path, monkeypatch, live_server):
    calls = []

    def tracking_chat(*a, **kw):
        calls.append(1)
        if len(calls) == 1:
            return {"choices": [{"message": {"content": None, "tool_calls": [
                {"id": "c1", "type": "function", "function": {
                    "name": "live_probe",
                    "arguments": '{"method":"GET","path":"/probe"}'}}]}}],
                "usage": {}}
        return {"choices": [{"message": {"content": '{"value":"ok"}'}}],
                "usage": {}}

    monkeypatch.setattr(local_agent, "_chat", tracking_chat)
    res = run_local_agent(**_run_kwargs(
        tmp_path, {"live_target": {"url": live_server}}))
    assert res.payload == {"value": "ok"}
    assert len(calls) == 2  # one tool turn, one final


# ---- SDK path wiring ----------------------------------------------------------

def test_live_probe_mcp_config_gate():
    assert live_probe_mcp_config({}) is None
    assert live_probe_mcp_config({"live_target": {}}) is None
    cfg = live_probe_mcp_config(
        {"live_target": {"url": "http://127.0.0.1:5199"}})
    assert cfg["type"] == "stdio"
    assert cfg["env"]["CODESEC_LIVE_TARGET_URL"] == "http://127.0.0.1:5199"
    assert cfg["args"][0].endswith("live_probe_mcp.py")


async def test_run_agent_sdk_registers_live_probe_mcp(tmp_path, monkeypatch):
    captured = {}

    class FakeOptions:
        def __init__(self, **kw):
            captured.update(kw)

    class FakeClient:
        def __init__(self, options):
            pass

        async def __aenter__(self):
            raise TransientAgentError("stop after options construction")

        async def __aexit__(self, *a):
            return None

    monkeypatch.setattr(runner, "ClaudeAgentOptions", FakeOptions)
    monkeypatch.setattr(runner, "ClaudeSDKClient", FakeClient)
    runner.set_engine("sdk")
    prompt, schema = _prompt_and_schema(tmp_path)

    with pytest.raises(TransientAgentError):
        await runner.run_agent(
            stage="hunt", prompt_file=prompt,
            user_input={"live_target": {"url": "http://127.0.0.1:5199"}},
            schema_file=schema, allowed_tools=["Read"], model="m",
            cwd=tmp_path, artifact_dir=tmp_path, artifact_name="t",
            transient_retries=0,
        )
    assert captured["mcp_servers"]["live_probe"]["type"] == "stdio"
    assert "mcp__live_probe__http_request" in captured["tools"]
    assert "mcp__live_probe__http_request" in captured["allowed_tools"]

    captured.clear()
    with pytest.raises(TransientAgentError):
        await runner.run_agent(
            stage="hunt", prompt_file=prompt, user_input={},
            schema_file=schema, allowed_tools=["Read"], model="m",
            cwd=tmp_path, artifact_dir=tmp_path, artifact_name="t2",
            transient_retries=0,
        )
    assert captured["mcp_servers"] is None
    assert captured["tools"] == ["Read"]


# ---- review-pass regressions --------------------------------------------------

def test_request_url_port_is_scheme_aware():
    """Port may only be elided when it matches the SCHEME default —
    http://host:443 and https://host:443 are different targets."""
    from codesec.live_probe_mcp import _request_url

    assert _request_url(("http", "ex.com", 443), "/") == "http://ex.com:443/"
    assert _request_url(("https", "ex.com", 443), "/") == "https://ex.com/"
    assert _request_url(("http", "ex.com", 80), "/") == "http://ex.com/"
    assert _request_url(("https", "ex.com", 8443), "/") == "https://ex.com:8443/"


def test_request_url_ipv6_host_gets_brackets():
    from codesec.live_probe_mcp import _request_url

    assert _request_url(("http", "::1", 8080), "/x") == "http://[::1]:8080/x"


def test_probe_refuses_control_characters(live_server):
    r = http_request(live_server, "GET", "/x\r\nX-Injected: y")
    assert r["ok"] is False and "refused" in r["error"]
    r = http_request(live_server, "GET", "/", headers={"X-T": "a\r\nb"})
    assert r["ok"] is False and "refused" in r["error"]


def test_live_probe_stage_allowlist_is_shared():
    assert runner._LIVE_PROBE_STAGES == local_agent._LIVE_PROBE_STAGES
    assert "report" not in runner._LIVE_PROBE_STAGES
    assert "recon" not in runner._LIVE_PROBE_STAGES


def test_local_agent_no_live_probe_for_non_probe_stage(tmp_path, monkeypatch):
    """A live_target in input must not arm the probe for stages outside
    the allowlist — report/gapfill get context, not capability."""
    seen: list[list[str]] = []

    def fake_chat(base_url, api_key, model, messages, tools, *a, **kw):
        seen.append([t["function"]["name"] for t in tools])
        return {"choices": [{"message": {"content": '{"value":"ok"}'}}],
                "usage": {}}

    monkeypatch.setattr(local_agent, "_chat", fake_chat)
    kw = _run_kwargs(
        tmp_path, {"live_target": {"url": "http://127.0.0.1:5199"}})
    kw["stage"] = "report"
    run_local_agent(**kw)
    assert "live_probe" not in seen[-1]

    kw["stage"] = "trace"
    kw["artifact_name"] = "t2"
    run_local_agent(**kw)
    assert "live_probe" in seen[-1]


async def test_run_agent_sdk_no_live_probe_for_report_stage(
    tmp_path, monkeypatch
):
    captured = {}

    class FakeOptions:
        def __init__(self, **kw):
            captured.update(kw)

    class FakeClient:
        def __init__(self, options):
            pass

        async def __aenter__(self):
            raise TransientAgentError("stop after options construction")

        async def __aexit__(self, *a):
            return None

    monkeypatch.setattr(runner, "ClaudeAgentOptions", FakeOptions)
    monkeypatch.setattr(runner, "ClaudeSDKClient", FakeClient)
    runner.set_engine("sdk")
    prompt, schema = _prompt_and_schema(tmp_path)

    with pytest.raises(TransientAgentError):
        await runner.run_agent(
            stage="report", prompt_file=prompt,
            user_input={"live_target": {"url": "http://127.0.0.1:5199"}},
            schema_file=schema, allowed_tools=["Read"], model="m",
            cwd=tmp_path, artifact_dir=tmp_path, artifact_name="t",
            transient_retries=0,
        )
    assert captured["mcp_servers"] is None
    assert "mcp__live_probe__http_request" not in captured["tools"]


async def test_sdk_artifact_redacts_live_credentials(tmp_path, monkeypatch):
    """The artifact user-payload must never contain live credentials —
    the model prompt keeps them, the on-disk record does not."""

    class FakeOptions:
        def __init__(self, **kw):
            pass

    class FakeClient:
        def __init__(self, options):
            pass

        async def __aenter__(self):
            raise TransientAgentError("stop after artifact write")

        async def __aexit__(self, *a):
            return None

    monkeypatch.setattr(runner, "ClaudeAgentOptions", FakeOptions)
    monkeypatch.setattr(runner, "ClaudeSDKClient", FakeClient)
    runner.set_engine("sdk")
    prompt, schema = _prompt_and_schema(tmp_path)

    with pytest.raises(TransientAgentError):
        await runner.run_agent(
            stage="hunt", prompt_file=prompt,
            user_input={"live_target": {
                "url": "http://127.0.0.1:5199",
                "credentials": {"authorization": "Bearer sekret-token"}},
            },
            schema_file=schema, allowed_tools=["Read"], model="m",
            cwd=tmp_path, artifact_dir=tmp_path, artifact_name="t",
            transient_retries=0,
        )
    artifact = (tmp_path / "t.jsonl").read_text()
    assert "sekret-token" not in artifact
    assert "***" in artifact
