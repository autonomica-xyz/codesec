"""P03 gateway behavior tests: frozen-setting enforcement, credential
isolation, sanitized records, SSE passthrough."""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from bench.realvuln.gateway import GatewayConfig, serve

EXPECT = {
    "thinking": {"type": "enabled"},
    "reasoning_effort": "low",
    "temperature": 0.6,
    "max_tokens": 32768,
    "stream": True,
}

GOOD_BODY = {
    "model": "glm-5.3",
    "messages": [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "hi"},
    ],
    **EXPECT,
}


class Upstream(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_POST(self):
        self.server.requests.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
        self.server.auth = self.headers.get("Authorization")
        if self.server.fail_with:
            status, body = self.server.fail_with
            payload = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        events = [
            {"choices": [{"index": 0, "delta": {"content": "{\"ok\": true}"},
                          "finish_reason": "stop"}]},
            {"usage": {"prompt_tokens": 5, "completion_tokens": 2,
                       "completion_tokens_details": {"reasoning_tokens": 1}},
             "choices": []},
        ]
        payload = b"".join(
            b"data: " + json.dumps(e).encode() + b"\n\n" for e in events
        ) + b"data: [DONE]\n\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def _upstream(tmp_path):
    server = HTTPServer(("127.0.0.1", 0), Upstream)
    server.requests = []
    server.auth = None
    server.fail_with = None
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def _gateway(tmp_path, upstream_server, expect=None):
    cfg = GatewayConfig(
        upstream=f"http://127.0.0.1:{upstream_server.server_port}/v1",
        model="glm-5.3",
        expect=dict(expect if expect is not None else EXPECT),
        records_dir=tmp_path / "records",
        api_key="operator-secret",
    )
    gateway = serve(cfg, "127.0.0.1:0")
    threading.Thread(target=gateway.serve_forever, daemon=True).start()
    return gateway, cfg


def _terminals(cfg):
    return [r for r in _records(cfg, min_lines=2)
            if r.get("kind") == "terminal"]


def _admissions(cfg):
    return [r for r in _records(cfg, min_lines=2)
            if r.get("kind") == "admission"]


import time


def _records(cfg, *, rejected=False, wait=True, min_lines=1):
    """Read gateway records; the handler writes the admission record before
    forwarding and the terminal record after — wait until enough lines
    have landed."""
    path = cfg.rejected_path if rejected else cfg.records_path
    deadline = time.time() + 3.0
    while True:
        if path.exists():
            lines = [
                json.loads(line)
                for line in path.read_text().splitlines()
                if line.strip()
            ]
            if len(lines) >= min_lines or not wait:
                return lines
        if time.time() >= deadline:
            return []
        time.sleep(0.02)


def _post(gateway, body, headers=None, path="/v1/chat/completions"):
    req = urllib.request.Request(
        f"http://127.0.0.1:{gateway.server_port}{path}",
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json",
                 "Authorization": "Bearer agent-dummy",
                 **(headers or {})},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode()


def test_gateway_forwards_and_records_sanitized(tmp_path):
    upstream = _upstream(tmp_path)
    gateway, cfg = _gateway(tmp_path, upstream)

    status, body = _post(
        gateway,
        {**GOOD_BODY, "clear_thinking": False},
        headers={
            "X-Experiment-Id": "exp-1", "X-Cell-Id": "cell-9",
            "X-Attempt-Id": "att-3", "X-Arm": "h", "X-Stage": "hunt",
        },
    )

    assert status == 200
    assert "[DONE]" in body
    assert upstream.requests, "request must reach the allowlisted upstream"
    assert upstream.auth == "Bearer operator-secret"
    records = _records(cfg, min_lines=2)
    assert [r["kind"] for r in records] == ["admission", "terminal"]
    adm, rec = records
    assert rec["request_id"] == adm["request_id"]
    assert rec["status"] == "forwarded"
    assert rec["stream_complete"] is True
    assert rec["stop_reason"] == "stop"
    assert rec["usage"]["completion_tokens_details"]["reasoning_tokens"] == 1
    for record in (adm, rec):
        assert record["experiment_id"] == "exp-1"
        assert record["cell_id"] == "cell-9"
        assert record["attempt_id"] == "att-3"
        assert record["stage"] == "hunt"
        assert record["observed_settings"]["reasoning_effort"] == "low"
    assert adm["observed_extra"] == {"clear_thinking": False}
    # History transport proof without content: counts + hash only.
    assert adm["messages"]["message_count"] == 2
    assert adm["messages"]["roles"] == {"system": 1, "user": 1}
    assert len(adm["messages"]["sha256"]) == 64
    # Credential isolation: neither the operator key nor caller auth appears.
    blob = cfg.records_path.read_text()
    if cfg.rejected_path.exists():
        blob += cfg.rejected_path.read_text()
    assert "operator-secret" not in blob
    assert "agent-dummy" not in blob
    upstream.shutdown()
    gateway.shutdown()


@pytest.mark.parametrize("mutation,problem", [
    ({"model": "glm-4.7"}, "frozen setting mismatch: model"),
    ({"reasoning_effort": "high"}, "reasoning_effort"),
    ({"thinking": {"type": "disabled"}}, "thinking"),
    ({"temperature": 0.2}, "temperature"),
    ({"max_tokens": 4096}, "max_tokens"),
    ({"stream": False}, "stream"),
])
def test_gateway_rejects_setting_mismatches_before_forwarding(
    tmp_path, mutation, problem
):
    upstream = _upstream(tmp_path)
    gateway, cfg = _gateway(tmp_path, upstream)

    status, body = _post(gateway, {**GOOD_BODY, **mutation})

    assert status == 400
    assert "gateway_rejected" in body
    assert problem in body
    assert upstream.requests == [], "mismatched request must not be forwarded"
    rejected = _records(cfg, rejected=True)
    assert rejected and rejected[0]["problems"]
    upstream.shutdown()
    gateway.shutdown()


def test_gateway_rejects_missing_frozen_setting(tmp_path):
    upstream = _upstream(tmp_path)
    gateway, cfg = _gateway(tmp_path, upstream)

    body = {k: v for k, v in GOOD_BODY.items() if k != "thinking"}
    status, body = _post(gateway, body)

    assert status == 400
    assert "missing frozen setting: thinking" in body
    assert upstream.requests == []
    upstream.shutdown()
    gateway.shutdown()


def test_gateway_serves_only_the_chat_route(tmp_path):
    upstream = _upstream(tmp_path)
    gateway, cfg = _gateway(tmp_path, upstream)

    status, body = _post(gateway, GOOD_BODY, path="/v1/messages")

    assert status == 404
    assert "only /v1/chat/completions" in body
    assert upstream.requests == []
    upstream.shutdown()
    gateway.shutdown()


def test_gateway_records_upstream_http_error(tmp_path):
    upstream = _upstream(tmp_path)
    upstream.fail_with = (429, {"error": "rate limited"})
    gateway, cfg = _gateway(tmp_path, upstream)

    status, body = _post(gateway, GOOD_BODY)

    assert status == 429
    terminals = _terminals(cfg)
    assert len(terminals) == 1
    assert terminals[0]["status"] == "upstream_error"
    assert terminals[0]["http_status"] == 429
    assert "rate limited" in terminals[0]["upstream_error"]
    assert len(_admissions(cfg)) == 1  # admission precedes the failure
    upstream.shutdown()
    gateway.shutdown()


def test_gateway_reasoning_history_seen_in_later_request(tmp_path):
    """A tool-loop follow-up carrying reasoning_content on an assistant
    message is forwarded and reflected in the message digest counts."""
    upstream = _upstream(tmp_path)
    gateway, cfg = _gateway(tmp_path, upstream)

    follow_up = {
        **GOOD_BODY,
        "messages": [
            {"role": "system", "content": "sys"},
            {"role": "user", "content": "hi"},
            {"role": "assistant", "content": None,
             "reasoning_content": "thinking…",
             "tool_calls": [{"id": "c1", "type": "function",
                             "function": {"name": "read", "arguments": "{}"}}]},
            {"role": "tool", "tool_call_id": "c1", "content": "1:x"},
        ],
    }
    status, _ = _post(gateway, follow_up)

    assert status == 200
    adm = _admissions(cfg)[0]
    assert adm["messages"]["roles"] == {
        "system": 1, "user": 1, "assistant": 1, "tool": 1,
    }
    assert adm["messages"]["assistant_messages_with_reasoning"] == 1
    upstream.shutdown()
    gateway.shutdown()


def test_gateway_pinned_dict_keys_allow_undocumented_extensions(tmp_path):
    """Pi sends thinking:{type:enabled, clear_thinking:false}; the frozen
    pin is thinking.type=enabled. The extension is admitted only when
    allowlisted with its pinned value, recorded, never normalized — and a
    wrong TYPE still rejects."""
    upstream = _upstream(tmp_path)
    expect = dict(EXPECT)
    expect["allowed_nested"] = {"thinking": {"clear_thinking": False}}
    gateway, cfg = _gateway(tmp_path, upstream, expect=expect)

    status, _ = _post(gateway, {
        **GOOD_BODY,
        "thinking": {"type": "enabled", "clear_thinking": False},
    })
    assert status == 200
    adm = _admissions(cfg)[0]
    assert adm["observed_settings"]["thinking"] == {
        "type": "enabled", "clear_thinking": False,
    }

    # An extra member outside the allowlist is a rejection, not a pass.
    status, body = _post(gateway, {
        **GOOD_BODY,
        "thinking": {"type": "enabled", "clear_thinking": False, "type2": "x"},
    })
    assert status == 400
    assert "unexpected member" in body

    # The allowlisted member with the WRONG value rejects too — only the
    # history-policy value is admissible.
    status, body = _post(gateway, {
        **GOOD_BODY,
        "thinking": {"type": "enabled", "clear_thinking": True},
    })
    assert status == 400

    status, body = _post(gateway, {
        **GOOD_BODY, "thinking": {"type": "disabled", "clear_thinking": False},
    })
    assert status == 400
    assert "frozen setting mismatch: thinking" in body
    upstream.shutdown()
    gateway.shutdown()


def test_gateway_rejects_forbidden_and_unlisted_extra_members(tmp_path):
    """Required absences are enforced: top_p/chat_template_kwargs never
    appear in the frozen protocol, and without an allowed_nested entry even
    Pi's clear_thinking is a rejection (no silent normalization)."""
    upstream = _upstream(tmp_path)
    gateway, cfg = _gateway(tmp_path, upstream)  # plain EXPECT: no allowlist

    status, body = _post(gateway, {**GOOD_BODY, "top_p": 0.9})
    assert status == 400
    assert "forbidden setting present: top_p" in body
    assert upstream.requests == []

    status, body = _post(gateway, {
        **GOOD_BODY, "thinking": {"type": "enabled", "clear_thinking": False},
    })
    assert status == 400
    assert "unexpected member" in body
    upstream.shutdown()
    gateway.shutdown()
