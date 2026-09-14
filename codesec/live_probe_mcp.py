"""live_probe — a host-pinned HTTP probe for the live-target path (W7).

One shared core, two front-ends:

- Local engine: ``codesec.local_agent`` calls :func:`http_request` directly
  when ``user_input.live_target`` is present.
- SDK engine: this module is launched as a stdio MCP server
  (``python -m codesec.live_probe_mcp`` or the file path) by the Claude Code
  CLI; ``codesec.runner`` registers it under ``mcp_servers["live_probe"]``
  and passes the pinned target via ``CODESEC_LIVE_TARGET_URL``.

The host pin is enforced HERE — in the tool implementation, not the prompt:
only the exact (scheme, host, port) of the live target may be contacted,
redirects are never followed, absolute URLs to other hosts are refused, and
request/response bodies are capped.

``mcp`` is imported lazily inside :func:`build_server` so importing this
module from the local engine never requires the MCP SDK.
"""

from __future__ import annotations

import json
import os
import socket
import sys
import urllib.error
import urllib.parse
import urllib.request

MAX_REQUEST_BYTES = 64 * 1024
MAX_RESPONSE_BYTES = 64 * 1024
TIMEOUT_S = 10.0
ALLOWED_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
# Callers may not override these — urllib owns framing; Host is the pin.
_RESERVED_HEADERS = {"host", "content-length", "connection", "transfer-encoding"}

TOOL_NAME = "http_request"
TOOL_DESCRIPTION = (
    "Send one HTTP request to the pinned live target. The host is fixed by "
    "the scan configuration — `path` must be a path on that host (or an "
    "absolute URL to the same host). Redirects are NOT followed; the 3xx "
    "response is returned so you can inspect Location yourself."
)
TOOL_INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "method": {
            "type": "string",
            "enum": sorted(ALLOWED_METHODS),
            "description": "HTTP method (default GET)",
        },
        "path": {
            "type": "string",
            "description": "Path + optional query on the pinned host, "
                           "e.g. '/search?q=test'. Absolute URLs are only "
                           "accepted if they point at the pinned host.",
        },
        "headers": {
            "type": "object",
            "description": "Optional request headers (Host/Content-Length/"
                           "Connection are managed by the probe).",
            "additionalProperties": {"type": "string"},
        },
        "body": {
            "type": "string",
            "description": "Optional request body (capped at 64KB).",
        },
    },
    "required": ["path"],
    "additionalProperties": False,
}


class ProbeRefused(ValueError):
    """The requested target escapes the pinned live host."""


def _pin(target_url: str) -> tuple[str, str, int]:
    """Parse + validate the live target. Returns (scheme, host, port)."""
    parts = urllib.parse.urlsplit(str(target_url))
    if parts.scheme not in ("http", "https"):
        raise ProbeRefused(
            f"live target scheme {parts.scheme!r} is not http/https"
        )
    if not parts.hostname:
        raise ProbeRefused(f"live target has no host: {target_url!r}")
    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError as e:
        raise ProbeRefused(f"live target port is invalid: {e}") from e
    return parts.scheme, parts.hostname.lower(), port


def _resolve_once(host: str, port: int) -> None:
    """Resolve the pinned host once — fail fast if it doesn't resolve."""
    socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)


def _request_url(pin: tuple[str, str, int], path: str) -> str:
    """Build the request URL on the pinned host, or refuse."""
    scheme, host, port = pin
    path = str(path)
    if "://" in path or path.startswith("//"):
        # Absolute (or scheme-relative) URL: allowed only if it resolves to
        # exactly the pinned (scheme, host, port).
        try:
            p = urllib.parse.urlsplit(
                path if "://" in path else f"{scheme}:{path}"
            )
            p_port = p.port or (443 if p.scheme == "https" else 80)
        except ValueError as e:
            raise ProbeRefused(f"unparsable URL: {e}") from e
        if (p.scheme, (p.hostname or "").lower(), p_port) != pin:
            raise ProbeRefused(
                f"URL host {p.hostname}:{p_port} is not the pinned live "
                f"target {host}:{port}"
            )
        rel = p.path or "/"
        if p.query:
            rel += "?" + p.query
        path = rel
    if not path.startswith("/"):
        path = "/" + path
    # Reject control characters (incl. space): urllib's behaviour on them
    # differs by version (silent strip vs InvalidURL) — deterministic
    # refusal keeps the "refused is a normal result" contract.
    if any(ord(c) <= 0x20 or ord(c) == 0x7F for c in path):
        raise ProbeRefused("path contains control characters")
    default_port = 443 if scheme == "https" else 80
    netloc = f"[{host}]" if ":" in host and not host.startswith("[") else host
    if port != default_port:
        netloc = f"{netloc}:{port}"
    return urllib.parse.urlunsplit((scheme, netloc, path, "", ""))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow redirects — they could leave the pinned host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


# ProxyHandler({}) disables *_proxy env vars — an environment proxy must
# never see the pinned target's Authorization credentials.
_opener = urllib.request.build_opener(
    _NoRedirect(), urllib.request.ProxyHandler({})
)


def http_request(
    target_url: str,
    method: str = "GET",
    path: str = "/",
    headers: dict | None = None,
    body: str | bytes | None = None,
) -> dict:
    """One capped HTTP request to the pinned live target.

    Returns ``{"ok": bool, "status": int, "headers": {...}, "body": str}``
    or ``{"ok": False, "error": "..."}``. Never raises for refusal — a
    refused request is a normal tool result so the model can correct it.
    """
    try:
        pin = _pin(target_url)
        url = _request_url(pin, path)
    except ProbeRefused as e:
        return {"ok": False, "error": f"refused: {e}"}

    method = str(method or "GET").upper()
    if method not in ALLOWED_METHODS:
        return {"ok": False, "error": f"refused: method {method!r} not allowed"}

    req_headers = {}
    for k, v in (headers or {}).items():
        k, v = str(k), str(v)
        if k.lower() in _RESERVED_HEADERS:
            return {"ok": False,
                    "error": f"refused: header {k!r} is managed by the probe"}
        if (any(ord(c) < 0x20 or ord(c) == 0x7F for c in k)
                or any(ord(c) < 0x20 or ord(c) == 0x7F for c in v)):
            return {"ok": False,
                    "error": f"refused: header {k!r} contains control characters"}
        req_headers[k] = v

    data: bytes | None = None
    if body is not None:
        data = body.encode("utf-8") if isinstance(body, str) else bytes(body)
        if len(data) > MAX_REQUEST_BYTES:
            return {"ok": False,
                    "error": f"refused: body exceeds {MAX_REQUEST_BYTES} bytes"}

    req = urllib.request.Request(url, data=data, method=method)
    for k, v in req_headers.items():
        req.add_header(k, v)

    try:
        resp = _opener.open(req, timeout=TIMEOUT_S)
    except urllib.error.HTTPError as e:
        resp = e  # 3xx/4xx/5xx are still observations, not failures
    except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as e:
        return {"ok": False,
                "error": f"{type(e).__name__}: {e}"}

    with resp:
        raw = resp.read(MAX_RESPONSE_BYTES + 1)
    truncated = len(raw) > MAX_RESPONSE_BYTES
    text = raw[:MAX_RESPONSE_BYTES].decode("utf-8", "replace")
    if truncated:
        text += f"\n[truncated: response exceeded {MAX_RESPONSE_BYTES} bytes]"
    return {
        "ok": True,
        "status": resp.status,
        "headers": {k: v for k, v in list(resp.headers.items())[:50]},
        "body": text,
    }


# ---- stdio MCP server front-end (SDK engine path) -----------------------------

def build_server(target_url: str):
    """Build an MCP server exposing http_request pinned to target_url.

    Supports mcp>=2 (mcp.server.mcpserver.MCPServer) and mcp<2
    (mcp.server.fastmcp.FastMCP) — both are stdio MCP servers with a
    ``tool`` decorator and a ``run('stdio')`` entry point.
    """
    pin = _pin(target_url)  # fail fast on a malformed/foreign target
    _resolve_once(pin[1], pin[2])

    try:
        from mcp.server.mcpserver import MCPServer as _Server  # mcp>=2
    except ModuleNotFoundError:
        from mcp.server.fastmcp import FastMCP as _Server  # mcp<2

    server = _Server("live_probe")

    @server.tool(name=TOOL_NAME, description=TOOL_DESCRIPTION)
    def _http_request(
        method: str = "GET",
        path: str = "/",
        headers: dict | None = None,
        body: str | None = None,
    ) -> str:
        return json.dumps(
            http_request(target_url, method, path, headers=headers, body=body),
            ensure_ascii=False,
        )

    return server


def main() -> None:
    target = os.environ.get("CODESEC_LIVE_TARGET_URL")
    if not target:
        print("CODESEC_LIVE_TARGET_URL is required", file=sys.stderr)
        sys.exit(2)
    build_server(target).run("stdio")


if __name__ == "__main__":
    main()
