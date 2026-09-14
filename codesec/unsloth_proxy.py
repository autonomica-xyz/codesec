"""Sidecar proxy that lets the Claude Code Agent SDK talk to local llama-server
backends (Unsloth Studio + hybrid/SSM models like Qwopus3.6-27B, OpenRouter
with non-Anthropic models, etc.).

The problem
-----------
llama-server builds a tool-calling grammar from the tool schemas in each
request. The Claude Code Agent SDK advertises the FULL set of tools the
install has registered (built-ins + every extension/MCP/GSD tool: Agent,
Bash, Cron*, Workflow, Task*, DesignSync, ...), not just what codesec asked
for. For some model/quant combos (notably hybrid/SSM Qwen) llama-server can't
compile a grammar over that many tools and 400s every turn::

    The model couldn't compile a tool-calling grammar for this request.
    This is a llama-server limitation with some model/quant and tool-schema
    combinations.

`ClaudeAgentOptions.tools` only restricts BUILT-IN tools, so it can't remove
environment-injected ones.

The fix
-------
This proxy strips the `tools` array in /v1/messages (and /v1/chat/completions)
down to an allowlist — by default exactly what codesec's stages use:
``Read, Grep, Glob, Bash``. The model only sees those, calls only those, and
the SDK (which still has them all registered) executes them. A small toolset
compiles cleanly. Other requests pass through untouched.

Run it, then point codesec at it::

    codesec unsloth-proxy --upstream http://localhost:8888 &
    codesec run --provider unsloth --base-url http://localhost:9999 --model <gguf>

This is a workaround for Unsloth's bundled llama.cpp; revisit once llama.cpp
handles large toolsets in the grammar compiler.
"""

from __future__ import annotations

import http.server
import json
import socketserver
import urllib.error
import urllib.request

DEFAULT_ALLOW = ("Read", "Grep", "Glob", "Bash")


def _strip_tools(body: bytes, allow: tuple[str, ...]) -> bytes:
    """Filter the `tools` array in a JSON request body to `allow`; fix
    tool_choice if it points at a stripped tool. Returns body (bytes)."""
    if not body:
        return body
    try:
        d = json.loads(body)
    except json.JSONDecodeError:
        return body
    tools = d.get("tools")
    if isinstance(tools, list) and tools:
        kept = [t for t in tools if t.get("name") in allow]
        if len(kept) != len(tools):
            d["tools"] = kept
            # A forced tool_choice to a now-stripped tool would 400; relax it.
            tc = d.get("tool_choice")
            if isinstance(tc, dict) and tc.get("name") not in allow:
                d["tool_choice"] = {"type": "any"}
    return json.dumps(d).encode()


class _Proxy(http.server.BaseHTTPRequestHandler):
    upstream = "http://localhost:8888"
    allow = DEFAULT_ALLOW

    def _handle(self) -> None:
        n = self.headers.get("Content-Length")
        body = self.rfile.read(int(n)) if n else b""

        if self.command == "POST" and self.path.rstrip("/").endswith(
                ("/v1/messages", "/v1/chat/completions")):
            body = _strip_tools(body, self.allow)

        headers = {k: v for k, v in self.headers.items()
                   if k.lower() not in ("host", "content-length")}
        req = urllib.request.Request(self.upstream + self.path,
                                     data=body or None, method=self.command,
                                     headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=600) as r:
                data = r.read()
                self.send_response(r.status)
                for k, v in r.headers.items():
                    if k.lower() not in ("transfer-encoding", "content-encoding",
                                         "content-length", "connection"):
                        self.send_header(k, v)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
        except urllib.error.HTTPError as e:
            data = e.read()
            self.send_response(e.code)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    do_POST = do_GET = do_PUT = do_DELETE = _handle

    def log_message(self, *a) -> None:
        pass


class _ThreadingServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


def run_proxy(upstream: str, host: str = "127.0.0.1", port: int = 9999,
              allow: tuple[str, ...] = DEFAULT_ALLOW) -> None:
    _Proxy.upstream = upstream.rstrip("/")
    _Proxy.allow = allow
    srv = _ThreadingServer((host, port), _Proxy)
    print(f"codesec unsloth-proxy: {host}:{port} -> {_Proxy.upstream} "
          f"(tools stripped to {list(allow)})", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--upstream", default="http://localhost:8888")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9999)
    ap.add_argument("--allow", default=",".join(DEFAULT_ALLOW),
                    help="Comma-separated tool names to keep (default: Read,Grep,Glob,Bash).")
    a = ap.parse_args()
    run_proxy(a.upstream, a.host, a.port, tuple(x.strip() for x in a.allow.split(",")))
