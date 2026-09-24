"""Operator-side inference gateway / request recorder (P03).

Both arms of the experiment point at this local gateway instead of the
provider. It:

- forwards to exactly ONE allowlisted upstream endpoint + model;
- validates the frozen effective settings on every request and REJECTS a
  mismatch before forwarding (never rewrites differing settings into
  apparent equality);
- holds the provider credential operator-side (agents get a dummy key;
  Authorization headers are never written to records);
- records sanitized metadata per request: IDs/tags (via X-* headers), stage
  when known, model/endpoint/protocol, observed settings, message counts +
  sha256 (history-transport proof without publishing content), stop reason,
  usage (verbatim, incl. cache/reasoning details when supplied), HTTP
  errors, and duration. Message bodies are NOT persisted.

Run:
  .venv/bin/python -m bench.realvuln.gateway \
      --listen 127.0.0.1:8800 \
      --upstream https://api.z.ai/api/coding/paas/v4 \
      --model glm-5.3 \
      --expect '{"thinking":{"type":"enabled"},"reasoning_effort":"low",
                 "temperature":0.6,"max_tokens":32768}' \
      --records bench/realvuln-runs/experiments/<id>/operator/gateway

The API key comes from --api-key-env (default ZAI_API_KEY) on the operator
host; it is never accepted from, or echoed to, callers.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import threading
import time
import urllib.error
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

# The only route the gateway serves. Not arbitrary upstream proxying.
CHAT_ROUTE = "/v1/chat/completions"

# Frozen settings compared exactly (present + equal). Everything else the
# caller sends is recorded as "observed_extra" but not rewritten.
ENFORCED_KEYS = (
    "model",
    "thinking",
    "reasoning_effort",
    "temperature",
    "max_tokens",
    "stream",
)

TAG_HEADERS = {
    "X-Experiment-Id": "experiment_id",
    "X-Cell-Id": "cell_id",
    "X-Attempt-Id": "attempt_id",
    "X-Arm": "arm",
    "X-Stage": "stage",
    "X-Codesec-Stage": "stage",
    "X-Request-Role": "request_role",
}


#: Top-level request keys that must NEVER appear (the frozen protocol has
#: no top-p and no local chat-template kwargs). Configured via
#: ``expect["forbidden"]``; these defaults apply when unspecified.
DEFAULT_FORBIDDEN_KEYS = ("top_p", "chat_template_kwargs")


class GatewayConfig:
    def __init__(self, *, upstream: str, model: str, expect: dict,
                 records_dir: Path, api_key: str | None):
        self.upstream = upstream.rstrip("/")
        self.model = model
        # The gateway itself pins the model: a request naming anything else
        # is rejected regardless of the expect block.
        expect = dict(expect)
        # ``forbidden``: top-level keys whose mere presence rejects the
        # request (required absences are enforced, not just values).
        self.forbidden = tuple(
            expect.pop("forbidden", DEFAULT_FORBIDDEN_KEYS)
        )
        # ``allowed_nested``: {enforced_dict_key: {extra_key: pinned_value}} —
        # a dict-valued frozen setting may carry ONLY these extra members,
        # and only with exactly these values (e.g. Pi's documented
        # clear_thinking:false under the preserved-reasoning history
        # policy). Any other nested member or value is a rejection.
        self.allowed_nested = {
            key: dict(extra)
            for key, extra in (expect.pop("allowed_nested", {}) or {}).items()
        }
        expect["model"] = model
        self.expect = expect
        self.records_dir = records_dir
        self.api_key = api_key
        self.records_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self.records_path = self.records_dir / "requests.jsonl"
        self.rejected_path = self.records_dir / "rejected.jsonl"
        # An existing-but-empty record store means "gateway deployed, zero
        # requests" — consultable attribution evidence. A missing file is
        # only possible when the gateway was never bound to the dir.
        self.records_path.touch(exist_ok=True)

    def validate(self, body: dict) -> tuple[dict, list[str]]:
        """Return (observed_settings, problems). problems non-empty -> reject.

        Frozen settings compare exactly. A dict-valued frozen setting pins
        every key it names AND allows only ``allowed_nested`` extras with
        pinned values — Pi's ``clear_thinking`` is admitted only when it
        carries the history policy's required value; any other member is a
        mismatch, never rewritten into apparent equality. ``forbidden``
        top-level keys are required absences.
        """
        observed = {}
        problems = []

        for key in self.forbidden:
            if key in body:
                problems.append(f"forbidden setting present: {key}")

        def _matches(expected, actual, path) -> bool:
            if isinstance(expected, dict):
                if not isinstance(actual, dict):
                    return False
                allowed = self.allowed_nested.get(path, {})
                for key in actual:
                    if key in expected:
                        continue
                    if key in allowed and allowed[key] == actual[key]:
                        continue
                    problems.append(
                        f"unexpected member {path}.{key}={actual[key]!r} "
                        "in a pinned setting"
                    )
                return all(
                    key in actual and _matches(value, actual[key], key)
                    for key, value in expected.items()
                )
            return expected == actual

        for key in ENFORCED_KEYS:
            if key not in body:
                problems.append(f"missing frozen setting: {key}")
                continue
            observed[key] = body[key]
            expected = self.expect.get(key)
            if expected is None:
                continue  # not pinned for this experiment
            if not _matches(expected, body[key], key):
                problems.append(
                    f"frozen setting mismatch: {key}={body[key]!r} "
                    f"!= expected {expected!r}"
                )
        return observed, problems

    def record(self, entry: dict, *, rejected: bool = False) -> None:
        path = self.rejected_path if rejected else self.records_path
        with self._lock:
            with path.open("a") as fh:
                fh.write(json.dumps(entry, ensure_ascii=False) + "\n")


def _messages_digest(messages) -> dict:
    """Counts + hashes prove history transport without publishing content."""
    if not isinstance(messages, list):
        messages = messages or []
    roles = {}
    for msg in messages:
        role = msg.get("role") if isinstance(msg, dict) else "?"
        roles[role] = roles.get(role, 0) + 1
    with_reasoning = sum(
        1 for m in messages
        if isinstance(m, dict) and m.get("reasoning_content")
    )
    try:
        serialized = json.dumps(messages, ensure_ascii=False, sort_keys=True)
    except (TypeError, ValueError):
        return {"message_count": -1, "sha256": None}
    return {
        "message_count": len(messages) if isinstance(messages, list) else -1,
        "roles": roles,
        "assistant_messages_with_reasoning": with_reasoning,
        "sha256": hashlib.sha256(serialized.encode()).hexdigest(),
        "chars": len(serialized),
    }


class GatewayHandler(BaseHTTPRequestHandler):
    server_version = "codesec-gateway/1"
    protocol_version = "HTTP/1.1"

    @property
    def cfg(self) -> GatewayConfig:
        return self.server.cfg  # type: ignore[attr-defined]

    def log_message(self, *args):  # keep the console quiet
        pass

    def _tags(self) -> dict:
        tags = {}
        for header, field in TAG_HEADERS.items():
            value = self.headers.get(header)
            if value:
                tags[field] = value
        return tags

    def _reject(self, status: int, entry: dict, problems: list) -> None:
        entry["problems"] = problems
        self.cfg.record(entry, rejected=True)
        payload = json.dumps(
            {"error": "gateway_rejected", "problems": problems}
        ).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self) -> None:
        started = time.time()
        request_id = uuid.uuid4().hex
        base_entry = {
            "request_id": request_id,
            "received_at": started,
            "route": self.path,
            "upstream": self.cfg.upstream,
            **self._tags(),
        }
        if self.path.rstrip("/") != CHAT_ROUTE.rstrip("/"):
            self._reject(
                404,
                base_entry,
                [f"only {CHAT_ROUTE} is served by this gateway"],
            )
            return
        try:
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length)
            body = json.loads(raw)
        except (ValueError, json.JSONDecodeError) as error:
            self._reject(400, base_entry, [f"unparseable body: {error}"])
            return

        observed, problems = self.cfg.validate(body)
        entry = {
            **base_entry,
            "observed_settings": observed,
            "observed_extra": {
                k: body[k] for k in sorted(body)
                if k not in ENFORCED_KEYS and k != "messages"
            },
            "messages": _messages_digest(body.get("messages")),
        }
        if problems:
            self._reject(400, entry, problems)
            return

        # Admission record: written BEFORE the upstream call. Every request
        # that passes validation is an inference admission — paired with a
        # terminal record below, this is the trusted record the ledger uses
        # to mark an attempt inference-bearing (including when the client
        # disconnects mid-stream or the gateway dies mid-relay).
        self.cfg.record({**entry, "kind": "admission"})

        terminal: dict = {"kind": "terminal"}

        # Forward with the operator-side credential; never echo caller auth.
        req = urllib.request.Request(
            f"{self.cfg.upstream}/chat/completions",
            data=raw,
            headers={
                "Content-Type": "application/json",
                "Accept-Encoding": "identity",
                **({"Authorization": f"Bearer {self.cfg.api_key}"}
                   if self.cfg.api_key else {}),
            },
        )
        try:
            upstream_resp = urllib.request.urlopen(req, timeout=1800)
        except urllib.error.HTTPError as error:
            detail = error.read(2048).decode(errors="replace")
            terminal.update(
                status="upstream_error",
                http_status=error.code,
                upstream_error=detail[:1000],
            )
            self._terminal(entry, terminal, started)
            try:
                self.send_response(error.code)
                self.send_header("Content-Type", "application/json")
                encoded = detail.encode(errors="replace")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass
            return
        except (urllib.error.URLError, OSError, TimeoutError) as error:
            terminal.update(
                status="upstream_unreachable",
                upstream_error=f"{type(error).__name__}: {error}"[:500],
            )
            self._terminal(entry, terminal, started)
            try:
                payload = json.dumps(
                    {"error": "gateway_upstream_unreachable"}
                ).encode()
                self.send_response(502)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass
            return

        # Relay the SSE stream, parsing usage/finish without persisting text.
        try:
            self.send_response(upstream_resp.status)
            content_type = upstream_resp.headers.get(
                "Content-Type", "text/event-stream")
            self.send_header("Content-Type", content_type)
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
        except (BrokenPipeError, ConnectionResetError, OSError):
            upstream_resp.close()
            terminal.update(status="client_disconnect",
                            stream_complete=False)
            self._terminal(entry, terminal, started)
            return

        usage: dict = {}
        finish_reason = None
        done_marker = False
        buffer = b""
        client_disconnect = False
        upstream_truncated = False
        try:
            while True:
                try:
                    chunk = upstream_resp.read(8192)
                except (OSError, TimeoutError, http.client.HTTPException) \
                        as error:
                    upstream_truncated = True
                    terminal["upstream_error"] = (
                        f"{type(error).__name__}: {error}"[:500])
                    break
                if not chunk:
                    break
                try:
                    self.wfile.write(
                        b"%x\r\n" % len(chunk) + chunk + b"\r\n")
                    self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError, OSError):
                    client_disconnect = True
                    break
                buffer += chunk
                while b"\n" in buffer:
                    line, buffer = buffer.split(b"\n", 1)
                    text = line.decode("utf-8", "replace").strip()
                    if not text.startswith("data:"):
                        continue
                    data = text[len("data:"):].strip()
                    if data == "[DONE]":
                        done_marker = True
                        continue
                    try:
                        parsed = json.loads(data)
                    except json.JSONDecodeError:
                        continue
                    if parsed.get("usage"):
                        usage = parsed["usage"]
                    for choice in parsed.get("choices") or []:
                        finish_reason = (
                            choice.get("finish_reason") or finish_reason)
        finally:
            if not client_disconnect:
                try:
                    self.wfile.write(b"0\r\n\r\n")
                    self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError, OSError):
                    pass
            upstream_resp.close()
        terminal.update(
            status=(
                "client_disconnect" if client_disconnect
                else "upstream_error" if upstream_truncated
                else "forwarded"
            ),
            http_status=upstream_resp.status,
            stop_reason=finish_reason,
            done_marker=done_marker,
            stream_complete=bool(
                done_marker and not client_disconnect
                and not upstream_truncated),
            usage=usage,
        )
        self._terminal(entry, terminal, started)

    def _terminal(self, entry: dict, terminal: dict, started: float) -> None:
        """Write the terminal record for an admitted request. The record is
        written BEFORE/at-least-independent-of client delivery, so a client
        that disconnects mid-stream still leaves a complete trusted record."""
        terminal["duration_ms"] = int((time.time() - started) * 1000)
        self.cfg.record({**entry, **terminal})


def serve(cfg: GatewayConfig, listen: str) -> ThreadingHTTPServer:
    host, port = listen.rsplit(":", 1)
    server = ThreadingHTTPServer((host, int(port)), GatewayHandler)
    server.cfg = cfg  # type: ignore[attr-defined]
    return server


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--listen", default="127.0.0.1:8800")
    parser.add_argument("--upstream", required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--expect", required=True,
                        help="JSON object of frozen settings (model pinned automatically)")
    parser.add_argument("--records", type=Path, required=True)
    parser.add_argument("--api-key-env", default="ZAI_API_KEY")
    args = parser.parse_args()

    expect = json.loads(args.expect)
    api_key = os.environ.get(args.api_key_env, "").strip() or None
    if api_key is None:
        raise SystemExit(
            f"operator credential missing: set {args.api_key_env} "
            "(never passed through agents)"
        )
    cfg = GatewayConfig(
        upstream=args.upstream,
        model=args.model,
        expect=expect,
        records_dir=args.records,
        api_key=api_key,
    )
    server = serve(cfg, args.listen)
    print(
        f"gateway listening on {args.listen} -> {cfg.upstream} "
        f"(model={cfg.model}, records={cfg.records_dir})",
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
