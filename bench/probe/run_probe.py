#!/usr/bin/env python3
"""Run the detection probe against any model endpoint.

Repeated classification calls per snippet; writes auditable JSONL. Supports:
  --proto anthropic : Anthropic Messages API (z.ai GLM-5.2: base https://api.z.ai/api/anthropic)
  --proto openai    : OpenAI /v1/chat/completions (Unsloth/llama-server/vLLM)

Usage:
  python3 run_probe.py --model glm-5.2 --proto anthropic \\
      --base-url https://api.z.ai/api/anthropic --api-key $ZAI_API_KEY --out glm52.jsonl
  python3 run_probe.py --model unsloth/Qwen3-Coder-30B-A3B-Instruct-GGUF --proto openai \\
      --base-url http://localhost:8888 --api-key sk-... --out qwen-coder.jsonl
"""
from __future__ import annotations
import argparse
import concurrent.futures as cf
import json
import os
import platform
import re
import socket
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
try:
    from .cases import CASES, dataset_sha256
except ImportError:  # direct script execution
    sys.path.insert(0, os.path.dirname(__file__))
    from cases import CASES, dataset_sha256

SYS = (
    "You are an expert application security reviewer. Treat function parameters "
    "and request values as attacker-controlled unless the code constrains them. "
    "Classify only the code shown; do not invent omitted conversions, sanitizers, "
    "deployment conditions, or vulnerable dependency versions. Mark vulnerable only when "
    "the shown code contains a concrete exploitable security bug. Reply with "
    "exactly one JSON object and no prose or code fence:\n"
    '{"vulnerable": <true|false>, "cwe": "CWE-XX" when vulnerable, otherwise null, '
    '"confidence": 0.0-1.0, "reason": "<brief reason>"}'
)


class PredictionError(ValueError):
    """The model response does not satisfy the probe prediction contract."""


_JSON_FENCE = re.compile(
    r"\A```(?:json)?[ \t]*\r?\n(?P<body>.*)\r?\n```[ \t]*\Z",
    re.IGNORECASE | re.DOTALL,
)
_THINK_PREFIX = re.compile(
    r"\A<think>(?P<thought>.*?)</think>[ \t]*\r?\n*(?P<body>.+)\Z",
    re.IGNORECASE | re.DOTALL,
)


def _prediction_payload(text: str) -> tuple[str, bool]:
    stripped = text.strip()
    exact = True
    think = _THINK_PREFIX.fullmatch(stripped)
    if think:
        stripped = think.group("body").strip()
        exact = False
    fence = _JSON_FENCE.fullmatch(stripped)
    if fence:
        return fence.group("body").strip(), False
    return stripped, exact


def _parse_response_object(text: str) -> dict:
    payload, _ = _prediction_payload(text)
    try:
        value = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise PredictionError(f"response is not a JSON object: {exc.msg}") from exc
    if not isinstance(value, dict):
        raise PredictionError("response must be a JSON object")
    return value


def parse_detection_verdict(text: str) -> dict:
    """Parse the semantic verdict without requiring auxiliary schema fields."""
    value = _parse_response_object(text)
    if type(value.get("vulnerable")) is not bool:
        raise PredictionError("vulnerable must be a JSON boolean")
    cwe = value.get("cwe")
    normalized_cwe = (
        cwe.upper()
        if isinstance(cwe, str)
        and re.fullmatch(r"CWE-[0-9]+", cwe.upper()) is not None
        else None
    )
    confidence = value.get("confidence")
    normalized_confidence = (
        float(confidence)
        if not isinstance(confidence, bool)
        and isinstance(confidence, (int, float))
        and 0 <= confidence <= 1
        else None
    )
    reason = value.get("reason")
    normalized_reason = (
        reason.strip()
        if isinstance(reason, str) and reason.strip()
        else None
    )
    return {
        "vulnerable": value["vulnerable"],
        "cwe": normalized_cwe,
        "confidence": normalized_confidence,
        "reason": normalized_reason,
    }


def parse_prediction(text: str) -> dict:
    value = _parse_response_object(text)
    required = {"vulnerable", "cwe", "confidence", "reason"}
    if set(value) != required:
        raise PredictionError(
            f"response keys must be exactly {sorted(required)}"
        )
    if type(value["vulnerable"]) is not bool:
        raise PredictionError("vulnerable must be a JSON boolean")
    cwe = value["cwe"]
    if cwe is not None and (
        not isinstance(cwe, str) or re.fullmatch(r"CWE-[0-9]+", cwe.upper()) is None
    ):
        raise PredictionError("cwe must be null or CWE-<number>")
    if value["vulnerable"] and cwe is None:
        raise PredictionError("cwe must be present when vulnerable is true")
    if not value["vulnerable"] and cwe is not None:
        raise PredictionError("cwe must be null when vulnerable is false")
    confidence = value["confidence"]
    if (
        isinstance(confidence, bool)
        or not isinstance(confidence, (int, float))
        or not 0 <= confidence <= 1
    ):
        raise PredictionError("confidence must be a number between 0 and 1")
    reason = value["reason"]
    if not isinstance(reason, str) or not reason.strip():
        raise PredictionError("reason must be a non-empty string")
    return {
        "vulnerable": value["vulnerable"],
        "cwe": cwe.upper() if cwe else None,
        "confidence": float(confidence),
        "reason": reason.strip(),
    }


def _call_anthropic(
    base, key, model, code, max_tokens, temperature, thinking, seed
):
    body = json.dumps({
        "model": model,
        "max_tokens": max_tokens,
        "temperature": temperature,
        "thinking": {"type": thinking},
        "system": SYS,
        "messages": [
            {"role": "user", "content": "```python\n" + code.strip() + "\n```"}
        ],
    }).encode()
    req = urllib.request.Request(base.rstrip("/") + "/v1/messages", data=body, headers={
        "content-type": "application/json", "x-api-key": key, "anthropic-version": "2023-06-01"})
    with urllib.request.urlopen(req, timeout=180) as r:
        d = json.loads(r.read())
    return "".join(b.get("text","") for b in d.get("content",[]) if b.get("type")=="text")


def _call_openai(
    base, key, model, code, max_tokens, temperature, thinking, seed
):
    body = json.dumps({
        "model": model,
        "max_tokens": max_tokens,
        "temperature": temperature,
        "seed": seed,
        "chat_template_kwargs": {"enable_thinking": thinking == "enabled"},
        "messages": [{"role":"system","content":SYS},
                     {"role":"user","content":"```python\n"+code.strip()+"\n```"}],
        "tool_choice":"none",
    }).encode()
    req = urllib.request.Request(base.rstrip("/") + "/v1/chat/completions", data=body, headers={
        "content-type":"application/json", **({"Authorization":f"Bearer {key}"} if key else {})})
    with urllib.request.urlopen(req, timeout=300) as r:
        d = json.loads(r.read())
    msg = ((d.get("choices") or [{}])[0].get("message",{}) or {})
    # thinking models: the answer may land in reasoning_content if content is empty
    return msg.get("content") or msg.get("reasoning_content") or ""


def classify_case(case: dict, *, repeat: int, call, attempts: int = 1) -> dict:
    """Classify one case through a caller-supplied model function."""
    started = time.time()
    base = {
        "kind": "case_result",
        "id": case["id"],
        "repeat": repeat,
        "tier": case["tier"],
        "vuln": case["vuln"],
        "cwe": case["cwe"],
    }
    failures = []
    raw_responses = []
    prediction = None
    contract_ok = False
    contract_error = None
    format_exact = False
    for attempt in range(1, attempts + 1):
        try:
            raw = call(case["code"])
            raw_responses.append(raw)
            _, format_exact = _prediction_payload(raw)
            prediction = parse_detection_verdict(raw)
            try:
                prediction = parse_prediction(raw)
                contract_ok = True
            except PredictionError as exc:
                contract_error = f"{type(exc).__name__}: {exc}"
            break
        except Exception as exc:
            failures.append(f"{type(exc).__name__}: {exc}")
            if attempt < attempts:
                time.sleep(min(attempt, 2))
    if prediction is None:
        return {
            **base,
            "ok": False,
            "attempts": len(failures),
            "raw_response": raw_responses[-1] if raw_responses else None,
            "raw_responses": raw_responses,
            "error": failures[-1],
            "errors": failures,
            "dt": round(time.time() - started, 3),
        }
    return {
        **base,
        "ok": True,
        "contract_ok": contract_ok,
        "contract_error": contract_error,
        "attempts": len(failures) + 1,
        "first_pass_ok": not failures,
        "format_exact": format_exact,
        "pred_vuln": prediction["vulnerable"],
        "pred_cwe": prediction["cwe"],
        "conf": prediction["confidence"],
        "reason": prediction["reason"],
        "raw_response": raw,
        "raw_responses": raw_responses,
        "dt": round(time.time() - started, 3),
    }


def _dataset_hash() -> str:
    return dataset_sha256(CASES)


def _load_extra_metadata(path: str | None) -> dict:
    if not path:
        return {}
    value = json.loads(Path(path).read_text())
    if not isinstance(value, dict):
        raise ValueError("--metadata-json must contain a JSON object")
    return value


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--proto", choices=["anthropic","openai"], required=True)
    ap.add_argument("--base-url", required=True)
    ap.add_argument("--api-key", default=os.environ.get("ZAI_API_KEY",""))
    ap.add_argument("--out", required=True)
    ap.add_argument("--concurrency", type=int, default=4)
    ap.add_argument("--max-tokens", type=int, default=512)
    ap.add_argument("--repeats", type=int, default=3)
    ap.add_argument("--attempts", type=int, default=2,
                    help="Total attempts for requests without a semantic verdict.")
    ap.add_argument("--temperature", type=float, default=0.0)
    ap.add_argument("--seed", type=int, default=20260724)
    ap.add_argument("--thinking", choices=["disabled", "enabled"],
                    default="disabled")
    ap.add_argument("--metadata-json")
    ap.add_argument("--allow-errors", action="store_true",
                    help="Deprecated: unresolved responses are scored as missing coverage.")
    ap.add_argument("--require-complete-output", action="store_true",
                    help="Exit nonzero if any response is not machine-readable.")
    a = ap.parse_args()
    if a.repeats < 1 or a.attempts < 1 or a.concurrency < 1:
        ap.error("--repeats, --attempts and --concurrency must be positive")
    call = _call_anthropic if a.proto == "anthropic" else _call_openai
    extra_metadata = _load_extra_metadata(a.metadata_json)
    metadata = {
        "kind": "run_meta",
        "schema_version": 3,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "hostname": socket.gethostname(),
        "python": platform.python_version(),
        "model": a.model,
        "protocol": a.proto,
        "base_url": a.base_url,
        "dataset_sha256": _dataset_hash(),
        "case_count": len(CASES),
        "repeats": a.repeats,
        "settings": {
            "temperature": a.temperature,
            "seed": a.seed,
            "thinking": a.thinking,
            "max_tokens": a.max_tokens,
            "concurrency": a.concurrency,
            "attempts": a.attempts,
        },
        "runtime": extra_metadata,
    }

    def one(item):
        c, repeat = item

        def invoke(code):
            return call(
                a.base_url, a.api_key, a.model, code, a.max_tokens,
                a.temperature, a.thinking, a.seed + repeat,
            )

        return classify_case(
            c, repeat=repeat, call=invoke, attempts=a.attempts
        )

    n_ok = 0
    work = [(case, repeat) for repeat in range(a.repeats) for case in CASES]
    with open(a.out, "w") as f, cf.ThreadPoolExecutor(a.concurrency) as ex:
        f.write(json.dumps(metadata, ensure_ascii=False) + "\n")
        for r in ex.map(one, work):
            f.write(json.dumps(r, ensure_ascii=False) + "\n"); f.flush()
            n_ok += r.get("ok", False)
            mark = (
                "ERR"
                if not r.get("ok")
                else ("VULN" if r["pred_vuln"] else "safe")
            )
            print(f"  r{r['repeat']+1} {r['id']:24s} "
                  f"truth={'V' if r['vuln'] else 'S'} pred={mark} "
                  f"cwe={r.get('pred_cwe')} {'OK' if r.get('ok') else 'ERR:'+r.get('error','')[:60]}")
    print(f"\n{n_ok}/{len(work)} semantically decidable -> {a.out}")
    if n_ok != len(work) and a.require_complete_output and not a.allow_errors:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
