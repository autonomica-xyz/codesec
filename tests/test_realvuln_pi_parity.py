"""P03 wire-parity test: the REAL installed Pi client, driven headless
against a mock inference server, must send the frozen experiment controls.

Skipped when the pi binary or its node runtime is unavailable, or when
PI_PARITY_TEST_EXE is unset and pi cannot be found on PATH.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

PI_EXE = os.environ.get("PI_PARITY_TEST_EXE") or shutil.which("pi")


class _Upstream(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        self.server.requests.append(body)
        if len(self.server.requests) == 1:
            events = [
                {"choices": [{"index": 0, "delta": {
                    "reasoning_content": "read the file first"}}]},
                {"choices": [{"index": 0, "delta": {"tool_calls": [{
                    "index": 0, "id": "call_1", "type": "function",
                    "function": {"name": "read",
                                 "arguments": json.dumps({"path": "note.txt"})}}]},
                    "finish_reason": "tool_calls"}]},
                {"usage": {"prompt_tokens": 10, "completion_tokens": 4,
                           "completion_tokens_details": {"reasoning_tokens": 2}},
                 "choices": []},
            ]
        else:
            events = [
                {"choices": [{"index": 0, "delta": {
                    "content": "the note says parity"},
                    "finish_reason": "stop"}]},
                {"usage": {"prompt_tokens": 30, "completion_tokens": 3,
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


@pytest.mark.skipif(PI_EXE is None, reason="pi binary not available")
def test_real_pi_client_sends_frozen_controls(tmp_path):
    server = HTTPServer(("127.0.0.1", 0), _Upstream)
    server.requests = []
    threading.Thread(target=server.serve_forever, daemon=True).start()

    # Isolated Pi agent dir: models.json only; no user sessions/settings.
    agent_dir = tmp_path / "pi-agent-dir"
    agent_dir.mkdir()
    model_def = json.loads(
        (Path(__file__).resolve().parent.parent
         / "bench" / "realvuln" / "pi-hosted-model.json").read_text()
    )
    model_def["providers"]["zaihosted"]["baseUrl"] = (
        f"http://127.0.0.1:{server.server_port}/v1"
    )
    (agent_dir / "models.json").write_text(json.dumps(model_def))

    workdir = tmp_path / "work"
    workdir.mkdir()
    (workdir / "note.txt").write_text("parity\n")

    env = {
        **os.environ,
        "PI_CODING_AGENT_DIR": str(agent_dir),
        "HOME": str(tmp_path / "home"),  # isolate host home
        "PATH": os.environ.get("PATH", ""),
    }
    (tmp_path / "home").mkdir()

    proc = subprocess.run(
        [
            PI_EXE,
            "--model", "zaihosted/glm-5.3",
            "--thinking", "low",
            "-p", "Read note.txt and reply with its content.",
        ],
        cwd=workdir,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    server.shutdown()

    assert proc.returncode == 0, (
        f"pi failed:\nstdout: {proc.stdout[-2000:]}\nstderr: {proc.stderr[-2000:]}"
    )
    requests = server.requests
    assert requests, "pi must have issued at least one inference request"

    for i, body in enumerate(requests):
        assert body["model"] == "glm-5.3", (i, body.get("model"))
        thinking = body.get("thinking")
        assert isinstance(thinking, dict) and thinking.get("type") == "enabled", (i, body.get("thinking"))
        assert body.get("reasoning_effort") == "low", (i, body.get("reasoning_effort"))
        assert body.get("temperature") == 0.6, (i, body.get("temperature"))
        assert "top_p" not in body, (i, body.get("top_p"))
        assert body.get("max_tokens") == 32768, (i, body.get("max_tokens"))
        assert body.get("stream") is True, (i, body.get("stream"))
        assert "chat_template_kwargs" not in body, i

    # The tool round-trip: the second request carries the tool result, and
    # Pi preserved the streamed reasoning on the assistant history message
    # (clear_thinking:false / reasoning_content transport).
    assert len(requests) >= 2, (
        f"expected a tool round-trip; got {len(requests)} request(s)"
    )
    roles = [m.get("role") for m in requests[1]["messages"]]
    assert "tool" in roles, roles
    assistant_with_reasoning = [
        m for m in requests[1]["messages"]
        if m.get("role") == "assistant"
        and (m.get("reasoning_content") is not None)
    ]
    assert assistant_with_reasoning, (
        "reasoning must be transported back on assistant history"
    )
