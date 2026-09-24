#!/usr/bin/env python3
"""Allocate an opaque trial id and materialize a blinded read-only target."""

from __future__ import annotations

import argparse
import os
import re
import secrets
import shutil
import subprocess
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from bench.realvuln.common import (
    CODESEC_ROOT,
    DEFAULT_REALVULN,
    DROP_DIR_NAMES,
    DROP_NAME_RE,
    OPERATOR_DIR,
    RSYNC_EXCLUDES,
    digest_tree,
    load_json,
    slug_aliases,
    write_json,
)

CANARY_FN_PREFIX = "session_cookie_materialize_"
LINE_GAP = 12  # RealVuln matcher is ±10


def _gt_paths(gt: dict) -> dict[str, int]:
    """file -> max end_line among labeled entries."""
    maxima: dict[str, int] = {}
    for entry in gt.get("findings") or []:
        rel = str(entry.get("file") or "").replace("\\", "/").lstrip("./")
        loc = entry.get("location") or {}
        end = loc.get("end_line") or loc.get("start_line") or 0
        try:
            end_i = int(end)
        except (TypeError, ValueError):
            continue
        if rel:
            maxima[rel] = max(maxima.get(rel, 0), end_i)
    return maxima


def _drop_identity(target: Path, aliases: tuple[str, ...]) -> list[str]:
    dropped: list[str] = []
    alias_re = re.compile("|".join(re.escape(a) for a in aliases), re.I)
    for path in sorted(target.rglob("*"), reverse=True):
        rel = path.relative_to(target).as_posix()
        if path.is_dir():
            if path.name.lower() in DROP_DIR_NAMES:
                shutil.rmtree(path)
                dropped.append(rel + "/")
            continue
        if DROP_NAME_RE.match(path.name):
            path.unlink()
            dropped.append(rel)
            continue
        if path.name.upper() == "LICENSE":
            try:
                text = path.read_text(errors="ignore")
            except OSError:
                text = ""
            if alias_re.search(text):
                path.unlink()
                dropped.append(rel)
    return dropped


def _assert_gt_present(target: Path, gt: dict, dropped: list[str]) -> None:
    dropped_set = set(dropped)
    missing: list[str] = []
    for rel, _end in _gt_paths(gt).items():
        if any(
            rel == d.rstrip("/") or rel.startswith(d)
            for d in dropped_set
            if d.endswith("/")
        ):
            missing.append(rel)
            continue
        if rel in dropped_set or not (target / rel).is_file():
            missing.append(rel)
    if missing:
        raise SystemExit(
            "blind_prepare: ground-truth files missing after identity drop: "
            + ", ".join(sorted(set(missing)))
        )


def _pick_canary_file(target: Path, maxima: dict[str, int]) -> Path:
    py_files = [
        target / rel
        for rel in maxima
        if rel.endswith(".py") and (target / rel).is_file()
    ]
    if not py_files:
        py_files = sorted(p for p in target.rglob("*.py") if p.is_file())
    if not py_files:
        raise SystemExit("blind_prepare: no .py file to host the canary")
    py_files.sort(key=lambda p: (len(p.read_bytes()), str(p)))
    return py_files[0]


def _inject_canary(target: Path, gt: dict, nonce: str) -> dict:
    maxima = _gt_paths(gt)
    host = _pick_canary_file(target, maxima)
    rel = host.relative_to(target).as_posix()
    text = host.read_text()
    if not text.endswith("\n"):
        text += "\n"
    current_lines = text.count("\n")
    min_start = maxima.get(rel, 0) + LINE_GAP
    pad = max(0, min_start - current_lines - 1)
    fn = f"{CANARY_FN_PREFIX}{nonce}"
    block = (
        "\n" * pad
        + f"def {fn}(payload):\n"
        + "    return eval(payload)\n"
    )
    new_text = text + block
    compile(new_text, str(host), "exec")
    host.write_text(new_text)
    start = new_text[: new_text.rfind(f"def {fn}")].count("\n") + 1
    return {
        "file": rel,
        "line": start,
        "line_end": start + 1,
        "cwe": "CWE-95",
        "nonce": nonce,
        "function": fn,
    }


def _make_readonly(target: Path) -> bool:
    """Lock the tree against writes. If sudo works, chown root then chmod
    via sudo (a user chmod after chown root is EPERM). Keep world-readable
    so digest_tree and the agents can still read."""
    try:
        subprocess.check_call(
            ["sudo", "-n", "true"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        subprocess.check_call(["chmod", "-R", "a-w", str(target)])
        return False
    subprocess.check_call(["sudo", "-n", "chown", "-R", "root:root", str(target)])
    subprocess.check_call(["sudo", "-n", "chmod", "-R", "a=rX", str(target)])
    return True


def cmd_allocate(args: argparse.Namespace) -> int:
    opaque = args.opaque or secrets.token_hex(4)
    OPERATOR_DIR.mkdir(parents=True, exist_ok=True)
    map_path = Path(args.map) if args.map else OPERATOR_DIR / f"{opaque}.json"
    if map_path.exists() and not args.force:
        raise SystemExit(f"refusing to overwrite operator map: {map_path}")
    payload = {
        "opaque_id": opaque,
        "slug": args.slug,
        "trial": args.trial,
        "arm": args.arm,
        "commit_sha": args.commit_sha or "",
        "realvuln_root": str(Path(args.realvuln).resolve()),
        "target": None,
        "dropped_paths": [],
        "canary": None,
    }
    write_json(map_path, payload, mode=0o600)
    print(opaque)
    print(map_path, file=sys.stderr)
    return 0


def cmd_prepare(args: argparse.Namespace) -> int:
    map_path = Path(args.map)
    payload = load_json(map_path)
    slug = payload["slug"]
    opaque = payload["opaque_id"]
    realvuln = Path(payload.get("realvuln_root") or args.realvuln)
    source = Path(args.source) if args.source else realvuln / "repos" / slug
    gt_path = (
        Path(args.gt) if args.gt else realvuln / "ground-truth" / slug / "ground-truth.json"
    )
    if not source.is_dir():
        raise SystemExit(f"missing source tree: {source}")
    if not gt_path.is_file():
        raise SystemExit(f"missing ground truth: {gt_path}")
    gt = load_json(gt_path)
    payload["commit_sha"] = gt.get("commit_sha") or payload.get("commit_sha") or ""

    parent = Path(args.work_parent) if args.work_parent else Path(
        f"/tmp/{opaque}"
    )
    if parent.exists():
        raise SystemExit(f"work parent already exists: {parent}")
    parent.mkdir(parents=True)
    target = parent / "target"
    cmd = ["rsync", "-a"]
    for exclude in RSYNC_EXCLUDES:
        cmd.extend(["--exclude", exclude])
    cmd.extend([str(source) + "/", str(target) + "/"])
    subprocess.check_call(cmd)

    aliases = slug_aliases(slug)
    dropped = _drop_identity(target, aliases)
    _assert_gt_present(target, gt, dropped)
    nonce = secrets.token_hex(8)
    canary = _inject_canary(target, gt, nonce)
    if canary["line"] <= _gt_paths(gt).get(canary["file"], 0) + 10:
        raise SystemExit("canary landed inside RealVuln ±10 of a GT line")

    residual: list[str] = []
    alias_re = re.compile("|".join(re.escape(a) for a in aliases), re.I)
    for path in target.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() in {".py", ".js", ".html", ".jinja2", ".txt", ".cfg", ".ini"}:
            continue
        # leftover identity docs only
        try:
            text = path.read_text(errors="ignore")
        except OSError:
            continue
        if alias_re.search(text) and DROP_NAME_RE.match(path.name):
            residual.append(path.relative_to(target).as_posix())

    root_owned = False if args.skip_root else _make_readonly(target)
    digest = digest_tree(target)
    payload.update(
        {
            "target": str(target.resolve()),
            "work_parent": str(parent.resolve()),
            "source": str(source.resolve()),
            "gt_path": str(gt_path.resolve()),
            "dropped_paths": dropped,
            "canary": canary,
            "digest": digest,
            "root_owned": root_owned,
            "residual_identity_docs": residual,
            "codesec_root": str(CODESEC_ROOT),
        }
    )
    write_json(map_path, payload, mode=0o600)
    print(opaque)
    print(str(target))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    alloc = sub.add_parser("allocate", help="write operator map, print opaque id")
    alloc.add_argument("--slug", required=True)
    alloc.add_argument("--trial", type=int, required=True)
    alloc.add_argument("--arm", choices=["h", "v"], required=True)
    alloc.add_argument("--opaque")
    alloc.add_argument("--map")
    alloc.add_argument("--commit-sha", default="")
    alloc.add_argument("--realvuln", default=str(DEFAULT_REALVULN))
    alloc.add_argument("--force", action="store_true")
    alloc.set_defaults(func=cmd_allocate)

    prep = sub.add_parser("prepare", help="copy, strip, canary, lock target")
    prep.add_argument("--map", required=True)
    prep.add_argument("--source")
    prep.add_argument("--gt")
    prep.add_argument("--realvuln", default=str(DEFAULT_REALVULN))
    prep.add_argument("--work-parent")
    prep.add_argument("--skip-root", action="store_true")
    prep.set_defaults(func=cmd_prepare)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
