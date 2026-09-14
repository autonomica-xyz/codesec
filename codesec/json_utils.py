"""Robust JSON extraction + schema validation for agent outputs."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from jsonschema import Draft7Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT7


_FENCE_RE = re.compile(r"```(?:json)?\s*(\{.*?\}|\[.*?\])\s*```", re.DOTALL)


def _strip_tool_markup(text: str) -> str:
    """Remove proprietary tool-call wrappers some models emit instead of JSON."""
    # e.g. <|message_model|>Bash<|content_invoke_tool_json|>{...}<|end_message|>
    text = re.sub(r"<\|[^|>]+\|>", " ", text)
    # bare function-call prose wrappers
    text = re.sub(r"invoke_tool_json", " ", text, flags=re.I)
    return text


def _json_rank(obj: Any) -> int:
    """Higher is better. Prefer recon/report shaped objects over tool-call shapes."""
    if isinstance(obj, list):
        # Bare arrays are almost never a stage payload (often a nested
        # target_files / findings fragment). Rank below any object.
        if not obj:
            return -50
        if all(isinstance(x, dict) for x in obj):
            # list of objects — weak candidate (sometimes models emit a bare
            # findings array); score by best element, capped.
            return max(_json_rank(x) for x in obj) - 20
        return -50
    if not isinstance(obj, dict):
        return -100
    keys = set(obj.keys())
    # tool-call shaped — almost never a stage payload
    if keys <= {"name", "args", "arguments", "id", "type"} or (
        "name" in keys and ("args" in keys or "arguments" in keys) and "subsystems" not in keys
        and "findings" not in keys and "tasks" not in keys and "gaps_observed" not in keys
    ):
        return -100
    score = 0
    for k in ("subsystems", "architecture", "initial_tasks", "findings",
              "gaps_observed", "task_id",
              "clusters", "traces", "report", "reachable", "verdict"):
        if k in obj:
            score += 10
    score += min(len(keys), 20)
    # Prefer hunt OUTPUT over hunt TASK when both appear as candidates.
    if {"findings", "gaps_observed"} & keys:
        score += 30
    if "findings" in keys and "task_id" in keys:
        score += 15
    # Pure task-shaped objects are weaker than hunt/recon outputs, but still
    # vastly preferable to nested fragments (target_files arrays, etc.).
    task_keys = {"attack_class", "scope_hint", "target_files", "rationale", "priority"}
    if task_keys.issubset(keys) and "findings" not in keys and "initial_tasks" not in keys:
        score -= 25  # keep above bare lists/fragments; below real outputs
    return score


def extract_json(text: str) -> Any:
    """Pull a JSON object out of an assistant message.

    Order of attempts:
      1. The full text is valid JSON (returned as-is — never stripped, so
         markup-like substrings inside string values are preserved).
      2. The text after stripping proprietary tool-call wrappers is valid JSON.
      3. The text contains a ```json ... ``` fenced block.
      4. All balanced {...}/{...} candidates, ranked by stage-payload likelihood
         (avoids preferring nested tool-call {"name","args"} blobs).

    Raises ValueError if no JSON can be extracted.
    """
    text = (text or "").strip()
    if not text:
        raise ValueError("Empty assistant output.")

    # 1. Full text is valid JSON — return immediately (full-text-first).
    #    This preserves valid top-level arrays and avoids corrupting string
    #    values that legitimately contain markup-like substrings.
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # 2. Strip tool-call markup wrappers and retry (only reached when the
    #    raw text did NOT parse, so valid JSON is never corrupted).
    stripped = _strip_tool_markup(text).strip()
    if stripped != text:
        try:
            return json.loads(stripped)
        except json.JSONDecodeError:
            pass

    candidates: list[Any] = []
    search_text = stripped if stripped != text else text

    for m in _FENCE_RE.finditer(search_text):
        try:
            candidates.append(json.loads(m.group(1)))
        except json.JSONDecodeError:
            pass

    # collect multiple balanced objects, not only the largest
    for open_c, close_c in (("{", "}"), ("[", "]")):
        i = 0
        while i < len(search_text):
            if search_text[i] != open_c:
                i += 1
                continue
            depth = 0
            in_str = False
            esc = False
            for j in range(i, len(search_text)):
                c = search_text[j]
                if esc:
                    esc = False
                    continue
                if c == "\\":
                    esc = True
                    continue
                if c == '"' and not esc:
                    in_str = not in_str
                if in_str:
                    continue
                if c == open_c:
                    depth += 1
                elif c == close_c:
                    depth -= 1
                    if depth == 0:
                        chunk = search_text[i : j + 1]
                        try:
                            candidates.append(json.loads(chunk))
                        except json.JSONDecodeError:
                            pass
                        i = j + 1
                        break
            else:
                i += 1
                continue
            continue

    if not candidates:
        raise ValueError(
            f"Could not extract JSON from assistant output (len={len(text)}). "
            f"Head: {text[:200]!r}"
        )

    # unique by json dump
    uniq = []
    seen = set()
    for c in candidates:
        try:
            sig = json.dumps(c, sort_keys=True)[:2000]
        except Exception:
            sig = str(type(c))
        if sig in seen:
            continue
        seen.add(sig)
        uniq.append(c)
    uniq.sort(key=_json_rank, reverse=True)
    best = uniq[0]
    # Only reject hard-negative ranks (tool-call shapes / bare fragments).
    # Mildly negative ranks (e.g. pure hunt-TASK objects at -9) are still
    # usable — hunt normalize can coerce them into empty findings output.
    TOOLISH = -80
    if _json_rank(best) <= TOOLISH and len(uniq) > 1:
        for c in uniq[1:]:
            if _json_rank(c) > TOOLISH:
                best = c
                break
    if _json_rank(best) <= TOOLISH:
        raise ValueError(
            f"Only tool-call shaped JSON found in assistant output (len={len(text)}). "
            f"Head: {text[:200]!r}"
        )
    return best


def _largest_balanced(text: str) -> str | None:
    """Return the largest balanced {...} or [...] substring, or None."""
    best: str | None = None
    for open_c, close_c in (("{", "}"), ("[", "]")):
        for i, ch in enumerate(text):
            if ch != open_c:
                continue
            depth = 0
            in_str = False
            esc = False
            for j in range(i, len(text)):
                c = text[j]
                if esc:
                    esc = False
                    continue
                if c == "\\":
                    esc = True
                    continue
                if c == '"' and not esc:
                    in_str = not in_str
                if in_str:
                    continue
                if c == open_c:
                    depth += 1
                elif c == close_c:
                    depth -= 1
                    if depth == 0:
                        candidate = text[i : j + 1]
                        if best is None or len(candidate) > len(best):
                            best = candidate
                        break
    return best


def validate_schema(payload: Any, schema_path: Path) -> list[str]:
    """Validate `payload` against the schema at `schema_path`.

    Sibling schemas in the same directory are loaded into a referencing
    Registry so `$ref` entries like `"hunt_task.schema.json"` resolve.

    Returns a list of human-readable error strings; empty means valid.
    """
    schema = json.loads(schema_path.read_text())
    schemas_dir = schema_path.parent.resolve()

    registry: Registry = Registry()
    for sf in schemas_dir.glob("*.schema.json"):
        raw = json.loads(sf.read_text())
        registry = registry.with_resource(
            sf.name, Resource.from_contents(raw, default_specification=DRAFT7)
        )

    validator = Draft7Validator(schema, registry=registry)
    return [
        f"{'/'.join(str(p) for p in err.absolute_path) or '<root>'}: {err.message}"
        for err in sorted(validator.iter_errors(payload), key=lambda e: e.path)
    ]
