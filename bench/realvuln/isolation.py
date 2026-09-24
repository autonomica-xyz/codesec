#!/usr/bin/env python3
"""Operator/agent isolation + paired corpus integrity (P06).

Two layers:

1. **Bundle preparation** (host, operator-side): verify the benchmark pin,
   materialize one source bundle per (repo, trial) with consistent identity
   stripping, byte-identical copies for the H and V arms, no canaries in
   scored bundles, and integrity checks (GT locations present with
   unchanged bytes; symlink policy; tree digests including symlink
   targets).

2. **Container isolation** (docker): one container per arm attempt —
   nonprivileged user, read-only rootfs and /work/target mount, writable
   scratch + opaque output, no host home/.git/bench/labels/prior runs,
   no container socket, private PID namespace, dropped capabilities, no
   sudo; general egress blocked with only the inference gateway reachable
   on a private network. The negative/positive access suites run through
   the SAME bash boundary agents use.

If docker is unavailable, `require_isolation()` raises — scored execution
is blocked rather than falling back to cwd "isolation".
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from bench.realvuln.common import (
    CODESEC_ROOT,
    DEFAULT_REALVULN,
    DROP_DIR_NAMES,
    DROP_NAME_RE,
    RSYNC_EXCLUDES,
    load_json,
    slug_aliases,
    write_json,
)

PIN_SHA = "7a710251f55c17d32d3adcb13d37468e2e3b9e4a"
#: Minimum separation between a canary fixture's inserted interval and any
#: GT acceptance window when the ±10 matcher filter is retained (plan: >20).
CANARY_GT_SEPARATION_LINES = 20

_IMAGE_TAG = "codesec-iso"
_ISOLATION_NET = "codesec-iso-net"


class IsolationError(RuntimeError):
    """Isolation prerequisites failed — scored execution must be blocked."""


# --------------------------------------------------------------------------
# Pin + integrity
# --------------------------------------------------------------------------

def verify_pin(realvuln_root: Path, expected_sha: str = PIN_SHA) -> dict:
    """Verify the benchmark checkout HEAD matches the pin and the tracked
    tree is clean (untracked scan outputs of our own runs are tolerated but
    reported)."""
    def git(*args: str) -> str:
        return subprocess.check_output(
            ["git", "-C", str(realvuln_root), *args], text=True
        ).strip()

    head = git("rev-parse", "HEAD")
    if head != expected_sha:
        raise IsolationError(
            f"benchmark HEAD {head} != pinned SHA {expected_sha}"
        )
    dirty = [
        line
        for line in git("status", "--porcelain").splitlines()
        if not line.startswith("??")
    ]
    if dirty:
        raise IsolationError(
            f"benchmark tracked tree is dirty: {dirty[:5]}"
        )
    untracked = [
        line[3:]
        for line in git("status", "--porcelain").splitlines()
        if line.startswith("??")
    ]
    return {"head": head, "pinned": expected_sha, "untracked": untracked}


def digest_tree_v2(root: Path) -> str:
    """Tree hash over relative paths, file content hashes AND symlink
    targets (a symlink-only swap changes the digest)."""
    items: list[str] = []
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root).as_posix()
        if path.is_symlink():
            items.append(f"L {rel} -> {os.readlink(path)}")
        elif path.is_file():
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            items.append(f"F {rel} {digest}")
        elif path.is_dir():
            items.append(f"D {rel}")
    return hashlib.sha256("\n".join(items).encode()).hexdigest()


def verify_symlink_policy(root: Path) -> list[str]:
    """Only links resolving inside the prepared tree are allowed; dangling
    or escaping links are reported (and must block the run)."""
    problems: list[str] = []
    resolved_root = root.resolve()
    for path in root.rglob("*"):
        if not path.is_symlink():
            continue
        rel = path.relative_to(root).as_posix()
        target = os.readlink(path)
        try:
            resolved = path.resolve()
        except OSError:
            problems.append(f"{rel}: dangling symlink -> {target}")
            continue
        if not resolved.exists():
            problems.append(f"{rel}: dangling symlink -> {target}")
            continue
        if not resolved.is_relative_to(resolved_root):
            problems.append(f"{rel}: symlink escapes tree -> {target}")
    return problems


def _gt_entries(gt: dict) -> list[dict]:
    return [
        entry
        for entry in gt.get("findings") or []
        if entry.get("is_vulnerable")
    ]


def _gt_label_locations(entry: dict) -> list[tuple[str, dict]]:
    """Every file/line location a GT entry labels: the primary ``file`` +
    ``location`` and every ``acceptable_locations`` alternative."""
    locations = [(entry.get("file"), entry.get("location") or {})]
    for alt in entry.get("acceptable_locations") or []:
        if isinstance(alt, dict):
            locations.append((alt.get("file"), alt))
    return locations


def verify_gt_locations(bundle: Path, gt: dict, *, source_root: Path,
                        allow_changed: set[str] = frozenset()) -> dict:
    """Every GT label location — vulnerable AND non-vulnerable (decoy)
    entries, primary files and acceptable-location alternatives — must be
    present in the bundle with bytes unchanged from the original source
    checkout, and labeled ranges must sit inside the file."""
    checked, problems = 0, []
    for entry in gt.get("findings") or []:
        for raw_file, loc in _gt_label_locations(entry):
            rel = str(raw_file or "").replace("\\", "/").lstrip("./")
            if not rel:
                problems.append(
                    f"GT entry {entry.get('id')}: empty file label"
                )
                continue
            start = int(loc.get("start_line") or 0)
            end = int(loc.get("end_line") or start or 0)
            checked += 1
            prepared = bundle / rel
            original = source_root / rel
            if not prepared.is_file():
                problems.append(f"missing GT file in bundle: {rel}")
                continue
            if rel in allow_changed:
                continue
            if not original.is_file():
                problems.append(
                    f"GT file absent from source checkout: {rel}")
                continue
            if prepared.read_bytes() != original.read_bytes():
                problems.append(
                    f"GT file bytes changed by preparation: {rel}")
                continue
            line_count = len(
                prepared.read_text(errors="replace").splitlines())
            if start and (start > line_count or end > line_count):
                problems.append(
                    f"GT range {start}-{end} outside file {rel} "
                    f"({line_count} lines)"
                )
    return {"checked": checked, "problems": problems}


# --------------------------------------------------------------------------
# Bundle preparation (paired, canary-free by default)
# --------------------------------------------------------------------------

@dataclass
class BundlePair:
    slug: str
    trial: int
    bundles_dir: Path
    source_root: Path
    dropped: list[str] = field(default_factory=list)
    digest: str = ""
    canary: dict | None = None

    @property
    def h(self) -> Path:
        return self.bundles_dir / "h" / "target"

    @property
    def v(self) -> Path:
        return self.bundles_dir / "v" / "target"


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


def _gt_file_line_maxima(gt: dict) -> dict[str, int]:
    """file -> max line touched by ANY GT entry (acceptance windows are
    ±10 around each labeled line, so canary separation counts from the
    farthest labeled line)."""
    maxima: dict[str, int] = {}
    for entry in _gt_entries(gt):
        rel = str(entry.get("file") or "").replace("\\", "/").lstrip("./")
        loc = entry.get("location") or {}
        end = int(loc.get("end_line") or loc.get("start_line") or 0)
        if rel and end:
            maxima[rel] = max(maxima.get(rel, 0), end)
    return maxima


def verify_app_checkout(source_root: Path, expected_sha: str | None) -> dict:
    """Verify the app clone's actual revision and working-tree state BEFORE
    bundling — recording the GT's commit string is not verifying it.

    A git checkout must sit at ``expected_sha`` with a clean tracked tree
    (untracked files are reported: rsync would otherwise carry operator-side
    mutations into the scored bundle). A non-git source tree cannot prove
    its revision: ``verified`` stays False so scored admission can refuse.
    """
    result: dict = {"source_root": str(source_root), "expected": expected_sha}
    if not (source_root / ".git").exists():
        result.update(
            git=False, head=None, verified=False,
            problems=["source tree is not a git checkout — revision "
                      "cannot be verified"],
        )
        return result
    def git(*args: str) -> str:
        return subprocess.check_output(
            ["git", "-C", str(source_root), *args], text=True,
        ).strip()

    head = git("rev-parse", "HEAD")
    status = git("status", "--porcelain")
    dirty = [l for l in status.splitlines() if not l.startswith("??")]
    untracked = [l[3:] for l in status.splitlines() if l.startswith("??")]
    problems: list[str] = []
    if expected_sha and head != expected_sha:
        problems.append(
            f"app HEAD {head} != GT commit_sha {expected_sha}")
    if dirty:
        problems.append(f"app tracked tree is dirty: {dirty[:5]}")
    result.update(
        git=True, head=head, dirty=dirty, untracked=untracked,
        verified=not problems, problems=problems,
    )
    return result


def verify_bundle_pair(bundles_dir: Path) -> dict:
    """Re-verify a prepared bundle pair: both arm digests must still equal
    the digest recorded at preparation time. Used when reusing a bundle and
    again after each arm run (read-only mounts make in-run mutation
    impossible — this is the positive check, not the enforcement)."""
    problems: list[str] = []
    manifest_path = bundles_dir / "bundle.json"
    if not manifest_path.is_file():
        return {"ok": False, "problems": ["missing bundle.json"]}
    manifest = load_json(manifest_path)
    recorded = manifest.get("digest")
    digest_h = digest_tree_v2(bundles_dir / "h" / "target")
    digest_v = digest_tree_v2(bundles_dir / "v" / "target")
    if digest_h != recorded:
        problems.append(f"H bundle digest drifted: {digest_h} != {recorded}")
    if digest_v != recorded:
        problems.append(f"V bundle digest drifted: {digest_v} != {recorded}")
    return {
        "ok": not problems,
        "digest": digest_h,
        "recorded": recorded,
        "problems": problems,
    }


def prepare_bundle_pair(
    *,
    slug: str,
    trial: int,
    bundles_dir: Path,
    realvuln: Path = DEFAULT_REALVULN,
    inject_canary: bool = False,
) -> BundlePair:
    """One source bundle per (repo, trial) with byte-identical H/V copies.

    Scored bundles contain NO canary. When ``inject_canary`` is set (only
    for unscored canary fixtures) the exact inserted interval is recorded
    and must sit more than CANARY_GT_SEPARATION_LINES from every GT
    acceptance window in the host file."""
    source_root = realvuln / "repos" / slug
    gt_path = realvuln / "ground-truth" / slug / "ground-truth.json"
    if not source_root.is_dir():
        raise IsolationError(f"missing source repo {source_root}")
    if not gt_path.is_file():
        raise IsolationError(f"missing ground truth {gt_path}")
    gt = load_json(gt_path)

    # Verify the actual app revision/tree before copying: a bundle prepared
    # from the wrong checkout is silently the wrong corpus.
    app_check = verify_app_checkout(source_root, gt.get("commit_sha"))
    if app_check["git"] and not app_check["verified"]:
        raise IsolationError(
            f"app checkout {source_root} failed verification: "
            + "; ".join(app_check["problems"])
        )

    if bundles_dir.exists():
        raise IsolationError(f"bundles dir already exists: {bundles_dir}")
    bundles_dir.mkdir(parents=True)

    pair = BundlePair(
        slug=slug, trial=trial, bundles_dir=bundles_dir,
        source_root=source_root,
    )
    for arm in ("h", "v"):
        target = bundles_dir / arm / "target"
        target.mkdir(parents=True)
        cmd = ["rsync", "-a"]
        for exclude in RSYNC_EXCLUDES:
            cmd.extend(["--exclude", exclude])
        cmd.extend([f"{source_root}/", f"{target}/"])
        subprocess.check_call(cmd)

    # Identity stripping on the H copy, then mirror the exact result to V
    # (single policy; digests must be equal anyway).
    dropped = _drop_identity(pair.h, slug_aliases(slug))
    # Mirror: wipe V target and copy the prepared H tree byte-identically.
    shutil.rmtree(pair.v)
    subprocess.check_call(["rsync", "-a", f"{pair.h}/", f"{pair.v}/"])
    pair.dropped = dropped

    allow_changed: set[str] = set()
    if inject_canary:
        canary = _inject_canary_fixture(pair, gt)
        pair.canary = canary
        allow_changed.add(canary["file"])
        # V gets a byte-identical copy INCLUDING the canary (paired inputs).
        shutil.rmtree(pair.v)
        subprocess.check_call(["rsync", "-a", f"{pair.h}/", f"{pair.v}/"])

    gt_check = verify_gt_locations(
        pair.h, gt, source_root=source_root, allow_changed=allow_changed
    )
    if gt_check["problems"]:
        raise IsolationError(
            "GT integrity violated by preparation: "
            + "; ".join(gt_check["problems"])
        )
    for arm_target in (pair.h, pair.v):
        link_problems = verify_symlink_policy(arm_target)
        if link_problems:
            raise IsolationError(
                f"symlink policy violated: {link_problems}"
            )

    digest_h = digest_tree_v2(pair.h)
    digest_v = digest_tree_v2(pair.v)
    if digest_h != digest_v:
        raise IsolationError(
            f"paired digests differ: h={digest_h} v={digest_v}"
        )
    pair.digest = digest_h
    write_json(
        bundles_dir / "bundle.json",
        {
            "slug": slug,
            "trial": trial,
            "commit_sha": gt.get("commit_sha"),
            "app_head": app_check.get("head"),
            "app_pin_verified": bool(app_check["verified"]),
            "digest": digest_h,
            "dropped_paths": dropped,
            "canary": pair.canary,
            "scored": not inject_canary,
            "gt_locations_checked": gt_check["checked"],
            "gt_label_entries": len(gt.get("findings") or []),
            "prepared_at": time.time(),
        },
    )
    return pair


def _inject_canary_fixture(pair: BundlePair, gt: dict) -> dict:
    """Unscored fixture only: append an eval() canary with the exact
    inserted interval recorded and > CANARY_GT_SEPARATION_LINES separation
    from every GT acceptance window in the host file."""
    maxima = _gt_file_line_maxima(gt)
    candidates = sorted(
        (p for p in pair.h.rglob("*.py") if p.is_file()),
        key=lambda p: (len(p.read_bytes()), str(p)),
    )
    if not candidates:
        raise IsolationError("no python file to host the canary fixture")
    host = candidates[0]
    rel = host.relative_to(pair.h).as_posix()
    text = host.read_text()
    if not text.endswith("\n"):
        text += "\n"
    # Windows are ±10 around labeled lines; require >20 lines of daylight
    # from the furthest labeled line (also covers acceptable locations,
    # which share the same file/line records).
    min_start = maxima.get(rel, 0) + CANARY_GT_SEPARATION_LINES + 1
    pad = max(0, min_start - text.count("\n") - 1)
    import secrets as _secrets

    nonce = _secrets.token_hex(8)
    fn = f"session_cookie_materialize_{nonce}"
    new_text = text + "\n" * pad + f"def {fn}(payload):\n    return eval(payload)\n"
    compile(new_text, str(host), "exec")
    host.write_text(new_text)
    start = new_text[: new_text.rfind(f"def {fn}")].count("\n") + 1
    return {
        "file": rel,
        "line_start": start,
        "line_end": start + 1,
        "cwe": "CWE-95",
        "nonce": nonce,
        "function": fn,
        "min_separation_from_gt_lines": CANARY_GT_SEPARATION_LINES,
        "furthest_gt_line_in_file": maxima.get(rel, 0),
    }


# --------------------------------------------------------------------------
# Container isolation
# --------------------------------------------------------------------------

def _docker(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", *args], capture_output=True, text=True, check=check
    )


def require_docker() -> None:
    try:
        result = _docker("version", "--format", "{{.Server.Version}}", check=False)
    except FileNotFoundError as error:
        raise IsolationError(
            "docker unavailable — scored execution is BLOCKED rather than "
            "falling back to cwd isolation"
        ) from error
    if result.returncode != 0:
        raise IsolationError(
            f"docker server unreachable: {result.stderr.strip()[:200]}"
        )


def build_agent_image(*, tag: str = _IMAGE_TAG, pi_version: str = "0.85.1") -> str:
    """Build the pinned isolation image from a source ALLOWLIST (never
    `COPY .` of the workspace): the codesec package, prompts, schemas and
    experiment config; plus a pinned pi install for the V arm."""
    require_docker()
    staging = CODESEC_ROOT / "bench" / "realvuln-runs" / ".image-staging"
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True)
    for item in ("codesec", "prompts", "schemas", "pyproject.toml"):
        src = CODESEC_ROOT / item
        dst = staging / item
        if src.is_dir():
            shutil.copytree(src, dst, ignore=shutil.ignore_patterns("__pycache__"))
        else:
            shutil.copy2(src, dst)
    # Experiment config only — not the whole config dir with other profiles.
    (staging / "config").mkdir()
    shutil.copy2(
        CODESEC_ROOT / "config" / "zai-glm53-experiment.yaml",
        staging / "config" / "stages.yaml",
    )
    dockerfile = f"""FROM python:3.13-slim

# V arm: pinned pi install (operator-side build; no agent credentials).
# Node 22+ required (pi uses node:fs globSync).
RUN apt-get update \\
 && apt-get install -y --no-install-recommends curl ca-certificates gnupg \\
 && curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \\
 && apt-get install -y --no-install-recommends nodejs \\
 && npm install -g @earendil-works/pi-coding-agent@{pi_version} \\
 && apt-get purge -y gnupg && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

# Harness from the source allowlist — never the workspace checkout.
COPY codesec /opt/codesec-src/codesec
COPY prompts /opt/codesec-src/prompts
COPY schemas /opt/codesec-src/schemas
COPY config /opt/codesec-src/config
COPY pyproject.toml /opt/codesec-src/pyproject.toml
# codesec resolves prompts/schemas/config relative to the installed
# package's grandparent (the python prefix) — place them there.
RUN pip install --no-cache-dir /opt/codesec-src \
 && cp -r /opt/codesec-src/prompts /opt/codesec-src/schemas /opt/codesec-src/config \
      /usr/local/lib/python3.13/site-packages/ \
 && rm -rf /opt/codesec-src

# Nonprivileged fixed user; no sudo installed.
RUN useradd --create-home --uid 10001 --shell /bin/bash agent
USER agent
WORKDIR /work
ENV HOME=/home/agent PIP_NO_CACHE_DIR=1
"""
    (staging / "Dockerfile").write_text(dockerfile)
    result = _docker("build", "-t", tag, str(staging), check=False)
    if result.returncode != 0:
        raise IsolationError(
            f"image build failed: {result.stdout[-500:]} {result.stderr[-500:]}"
        )
    inspect = _docker("inspect", tag, "--format", "{{.Id}}")
    image_id = inspect.stdout.strip()
    write_json(
        staging.parent / "image-build.json",
        {"tag": tag, "image_id": image_id, "pi_version": pi_version,
         "built_at": time.time()},
    )
    return image_id


def ensure_isolated_network(gateway_container: str | None = None) -> str:
    """Private network for arm containers + gateway; nothing else."""
    require_docker()
    result = _docker("network", "ls", "--format", "{{.Name}}", check=False)
    if _ISOLATION_NET not in result.stdout.split():
        created = _docker("network", "create", "--internal", _ISOLATION_NET,
                          check=False)
        if created.returncode != 0:
            raise IsolationError(f"network create failed: {created.stderr}")
    if gateway_container:
        attached = _docker(
            "network", "inspect", _ISOLATION_NET, "--format",
            "{{range .Containers}}{{.Name}} {{end}}", check=False,
        ).stdout
        if gateway_container not in attached:
            _docker("network", "connect", "--alias", "gateway",
                    _ISOLATION_NET, gateway_container, check=False)
    return _ISOLATION_NET


#: Environment allowlist passed INTO arm containers. No host proxy/cloud
#: credentials, no provider keys (the gateway holds those operator-side).
CONTAINER_ENV_ALLOWLIST = (
    "PATH",
    "HOME",
    "LANG",
    "LC_ALL",
    "PYTHONUNBUFFERED",
    "CODESEC_REQUEST_HEADERS",   # operator tags (experiment/cell/attempt ids)
    "ZAI_GATEWAY_KEY",           # dummy value set by the runner, never a secret
    "PI_CODING_AGENT_DIR",
)


def _path_writable_by(path: Path, uid: int) -> bool:
    """True when the mount root is owned by ``uid`` (no host passwd entry
    needed for container uids)."""
    try:
        return path.stat().st_uid == uid
    except OSError:
        return False


def _chown_fallback(path: Path) -> None:
    """When passwordless sudo is unavailable, prepare the mount with
    world-writable 0777 + sticky so uid 10001 can write (recorded as a
    weaker fallback: sandbox separation still comes from the container)."""
    path.chmod(0o777)
    for child in path.rglob("*"):
        child.chmod(0o777 if child.is_dir() else 0o666)


def resolve_image_id(image: str) -> str:
    """Resolve an image reference (tag or id) to its immutable local ID.
    Raises IsolationError when the reference does not resolve — scored
    execution must run the recorded image ID, never a mutable tag alone."""
    require_docker()
    result = _docker(
        "inspect", "--format", "{{.Id}}", image, check=False,
    )
    resolved = result.stdout.strip()
    if result.returncode != 0 or not resolved:
        raise IsolationError(
            f"image {image!r} does not resolve locally: "
            f"{result.stderr.strip()[:200]}"
        )
    return resolved


def run_isolated(
    *,
    target_dir: Path,
    scratch_dir: Path,
    output_dir: Path,
    command: list[str],
    gateway_url: str | None,
    timeout_s: float,
    env: dict | None = None,
    workdir: str = "/work/scratch",
    image: str | None = None,
    tag: str | None = None,
    network: str = _ISOLATION_NET,
    cleanup_grace_s: float = 30.0,
) -> dict:
    """One arm attempt in its own container: read-only target mount,
    writable scratch/output, no host paths, dropped capabilities, private
    PID namespace, stopped at the wall cap (outer deadline).

    The container gets a unique known identity. On success, failure,
    timeout, or controller exception the container is stopped and removed
    inside a bounded cleanup window — the docker CLI dying never leaves
    model/tool work running. Only this attempt's container is ever
    signalled; unrelated services are never touched.

    ``image`` is the image reference to run; pass the immutable image ID/
    digest recorded in the manifest (``tag`` remains as a deprecated
    alias). ``timeout_s`` is the model-work wall cap; the result carries
    ``timed_out`` when the cap was hit.
    """
    require_docker()
    ensure_isolated_network()
    scratch_dir.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)
    # Bind mounts must be writable by the container's fixed uid 10001
    # (operator-side chown; the agent user owns only its scratch/output).
    for writable in (scratch_dir, output_dir):
        subprocess.run(
            ["sudo", "-n", "chown", "-R", "10001:10001", str(writable)],
            check=False,
        )
        if not _path_writable_by(writable, 10001):
            _chown_fallback(writable)
    image_ref = image or tag or _IMAGE_TAG
    name = f"codesec-iso-{secrets.token_hex(6)}"
    env_flags: list[str] = []
    merged = {**(env or {})}
    for key in CONTAINER_ENV_ALLOWLIST:
        if key in os.environ and key not in merged:
            merged[key] = os.environ[key]
    for key, value in merged.items():
        env_flags.extend(["-e", f"{key}={value}"])
    if gateway_url:
        env_flags.extend(["-e", f"CODESEC_BASE_URL={gateway_url}"])
    started = time.time()
    cmd = [
        "docker", "run", "--rm", "--init", "--name", name,
        "--network", network,
        "--read-only",
        "--user", "10001:10001",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--pids-limit", "512",
        "--tmpfs", "/tmp:rw,size=64m,exec",
        "-v", f"{target_dir.resolve()}:/work/target:ro",
        "-v", f"{scratch_dir.resolve()}:/work/scratch:rw",
        "-v", f"{output_dir.resolve()}:/work/output:rw",
        "-w", workdir,
        *env_flags,
        image_ref,
        *command,
    ]
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    timed_out = False
    controller_error: str | None = None
    stdout, stderr = "", ""
    try:
        stdout, stderr = proc.communicate(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        timed_out = True
    except Exception as error:  # controller-side failure — still clean up
        controller_error = f"{type(error).__name__}: {error}"
    finally:
        cleanup_deadline = time.time() + max(1.0, cleanup_grace_s)

        def _bounded(args: list[str]) -> None:
            remaining = cleanup_deadline - time.time()
            if remaining <= 0:
                return
            try:
                subprocess.run(
                    args, capture_output=True, timeout=remaining,
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired):
                pass

        if timed_out or controller_error or proc.poll() is None:
            _bounded(["docker", "stop", "-t", "5", name])
        try:
            rest_out, rest_err = proc.communicate(
                timeout=max(0.5, cleanup_deadline - time.time())
            )
            stdout = (stdout or "") + (rest_out or "")
            stderr = (stderr or "") + (rest_err or "")
        except (subprocess.TimeoutExpired, OSError, ValueError):
            proc.kill()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass
        # The container is --rm, but an explicit remove covers any path
        # where the CLI died before the daemon honoured the stop. Only OUR
        # named container is ever removed.
        _bounded(["docker", "rm", "-f", name])
        # Container outputs are owned by uid 10001; hand them back to the
        # operator user so exports/ledger/commit can read and write them.
        subprocess.run(
            ["sudo", "-n", "chown", "-R", f"{os.getuid()}:{os.getgid()}",
             str(scratch_dir), str(output_dir)],
            check=False,
        )
    result = {
        "exit_code": proc.returncode,
        "timed_out": timed_out,
        "container": name,
        "image": image_ref,
        "stdout_tail": (stdout or "")[-8000:],
        "stderr_tail": (stderr or "")[-8000:],
        "duration_s": round(time.time() - started, 2),
        "cmd": command,
    }
    if controller_error:
        result["controller_error"] = controller_error
    if result["exit_code"] not in (0, None) and (
        "Permission denied" in (stdout + stderr)
    ):
        # A permission failure on scratch/output means the mount ownership
        # is wrong for the agent uid — surface as infra detail.
        result["mount_ownership_warning"] = True
    return result


# --------------------------------------------------------------------------
# Access suites (through the same bash boundary agents use)
# --------------------------------------------------------------------------

# Every probe prints PROBE_RAN first: a check that never executed cannot
# pass merely because its output is empty or its exit code is nonzero —
# infrastructure failure is not proof of isolation.
_PROBE_SENTINEL = "echo PROBE_RAN; "

_NEGATIVE_CHECKS = (
    # (name, command, safe_marker_required_in_output)
    ("host_home_absent",
     _PROBE_SENTINEL + "cat /home/user/.bashrc || cat /root/.bashrc",
     None),
    ("operator_map_absent",
     _PROBE_SENTINEL + "cat /work/operator/map.json", None),
    ("gt_labels_absent",
     _PROBE_SENTINEL + "cat /work/ground-truth.json", None),
    ("prior_runs_absent",
     _PROBE_SENTINEL + "ls /work/realvuln-runs", None),
    ("codesec_checkout_absent",
     _PROBE_SENTINEL + "ls /home/user/g/codesec/bench", None),
    ("docker_socket_absent",
     _PROBE_SENTINEL + "ls -l /var/run/docker.sock", None),
    ("sudo_absent", _PROBE_SENTINEL + "command -v sudo", None),
    (
        "host_pid_hidden",
        _PROBE_SENTINEL +
        "cat /proc/1/cmdline | tr '\\0' ' ' | grep -qv 'docker-init\\|init' "
        "&& echo HOST_PID_VISIBLE || echo container_pid_namespace",
        "container_pid_namespace",
    ),
    (
        "host_root_via_proc_absent",
        _PROBE_SENTINEL +
        "test -e /proc/1/root/home/user/.bashrc && echo HOST_ROOT_VISIBLE "
        "|| echo container_root_only",
        "container_root_only",
    ),
    (
        "egress_blocked",
        _PROBE_SENTINEL +
        "curl -s -m 5 -o /dev/null -w '%{http_code}' "
        "http://example.com/ 2>&1 || echo EGRESS_BLOCKED",
        "EGRESS_BLOCKED|000",  # a live HTTP answer is a breach
    ),
    (
        "target_readonly",
        _PROBE_SENTINEL +
        "echo x > /work/target/.write-probe && echo WRITE_SUCCEEDED "
        "|| echo WRITE_BLOCKED",
        "WRITE_BLOCKED",
    ),
    (
        "rootfs_readonly",
        _PROBE_SENTINEL +
        "echo x > /usr/.write-probe 2>/dev/null && echo WRITE_SUCCEEDED "
        "|| echo WRITE_BLOCKED",
        "WRITE_BLOCKED",
    ),
)

_POSITIVE_CHECKS = (
    ("read_target",
     _PROBE_SENTINEL +
     "head -c 32 /work/target/* 2>/dev/null | head -1", None),
    ("write_scratch",
     _PROBE_SENTINEL +
     "echo ok > /work/scratch/probe && cat /work/scratch/probe", None),
    ("write_output",
     _PROBE_SENTINEL +
     "echo ok > /work/output/probe && cat /work/output/probe", None),
)


def _evaluate_check(name: str, result: dict) -> dict:
    out = (result["stdout_tail"] or "") + (result["stderr_tail"] or "")
    # Docker-level infrastructure failures are NEVER a pass: the check did
    # not actually run (e.g. network missing, image absent, mount refused).
    # A timed-out probe is likewise inconclusive, not a pass.
    if (
        result["exit_code"] == 125
        or "docker: Error response" in out
        or result.get("timed_out")
        or result.get("controller_error")
    ):
        return {
            "name": name, "passed": False,
            "infra_error": True,
            "exit_code": result["exit_code"],
            "observed": out.strip()[:200],
        }
    # Positive control: the probe must prove it actually executed.
    if "PROBE_RAN" not in out:
        return {
            "name": name, "passed": False,
            "infra_error": True,
            "exit_code": result["exit_code"],
            "observed": f"probe sentinel absent — probe did not run: "
                        f"{out.strip()[:160]}",
        }
    expected_fail = name in {
        "host_home_absent", "operator_map_absent", "gt_labels_absent",
        "prior_runs_absent", "codesec_checkout_absent", "docker_socket_absent",
        "sudo_absent",
    }
    safe_marker = dict(
        (n, p) for n, _, p in _NEGATIVE_CHECKS if p
    ).get(name)
    if expected_fail:
        ok = (
            result["exit_code"] != 0
            or "No such file" in out
            or "not found" in out
        )
        return {"name": name, "passed": ok, "exit_code": result["exit_code"],
                "observed": out.strip()[:200]}
    if name == "egress_blocked":
        # The curl must demonstrably have run (sentinel) AND produced a
        # blocked/failed outcome — a live HTTP answer is a breach.
        ok = "EGRESS_BLOCKED" in out or "000" in out
        return {"name": name, "passed": ok, "observed": out.strip()[:200]}
    if safe_marker is not None:
        # Require the explicit safe marker — absence of the bad string is
        # not evidence the probe ran or the boundary held.
        ok = safe_marker in out
        return {"name": name, "passed": ok, "observed": out.strip()[:200]}
    return {"name": name, "passed": result["exit_code"] == 0,
            "observed": out.strip()[:200]}


def run_isolation_suite(
    *,
    target_dir: Path,
    gateway_url: str | None,
    output_dir: Path,
    timeout_s: float = 30.0,
    image: str | None = None,
) -> dict:
    """Negative + positive access tests executed through the same container
    bash boundary agents use. Returns the sign-off document."""
    require_docker()
    scratch = output_dir / "iso-scratch"
    results: list[dict] = []
    for name, command, _pat in _NEGATIVE_CHECKS + _POSITIVE_CHECKS:
        result = run_isolated(
            target_dir=target_dir,
            scratch_dir=scratch,
            output_dir=output_dir / "iso-out",
            command=["bash", "-lc", command],
            gateway_url=gateway_url,
            timeout_s=timeout_s,
            image=image,
        )
        results.append(_evaluate_check(name, result))
    if gateway_url:
        # Positive: the inference gateway IS reachable.
        base = gateway_url.rstrip("/")
        endpoint = (
            f"{base}/chat/completions" if base.endswith("/v1")
            else f"{base}/v1/chat/completions"
        )
        probe = run_isolated(
            target_dir=target_dir,
            scratch_dir=scratch,
            output_dir=output_dir / "iso-out",
            command=[
                "bash", "-lc",
                _PROBE_SENTINEL +
                "curl -s -m 5 -o /dev/null -w '%{http_code}' "
                "-X POST -H 'Content-Type: application/json' -d '{}' "
                f"{endpoint} "
                "|| echo EGRESS_BLOCKED",
            ],
            gateway_url=gateway_url,
            timeout_s=timeout_s,
            image=image,
        )
        out = probe["stdout_tail"].strip()
        # Any HTTP response (even 400/405) proves gateway reachability;
        # a total block is a failure for the scored setup. The sentinel
        # proves the probe actually ran.
        results.append({
            "name": "gateway_reachable",
            "passed": (
                "PROBE_RAN" in out
                and not probe.get("timed_out")
                and any(
                    code in out
                    for code in ("200", "400", "401", "404", "405", "415")
                )
            ),
            "observed": out[:200],
        })
    signoff = {
        "ran_at": time.time(),
        "checks": results,
        "passed": all(c["passed"] for c in results),
    }
    write_json(output_dir / "isolation-test.json", signoff)
    return signoff


def require_isolation(target_dir: Path, gateway_url: str | None,
                      output_dir: Path, image: str | None = None) -> dict:
    """Run the suite and BLOCK scored execution on any failure."""
    signoff = run_isolation_suite(
        target_dir=target_dir, gateway_url=gateway_url,
        output_dir=output_dir, image=image,
    )
    if not signoff["passed"]:
        failed = [c["name"] for c in signoff["checks"] if not c["passed"]]
        raise IsolationError(
            "isolation sign-off failed; scored execution BLOCKED: "
            + ", ".join(failed)
        )
    return signoff


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    build = sub.add_parser("build", help="build the pinned isolation image")
    build.add_argument("--pi-version", default="0.85.1")
    build.set_defaults(
        func=lambda a: (
            print(build_agent_image(pi_version=a.pi_version)), 0
        )[1]
    )

    verify = sub.add_parser("verify-pin", help="verify benchmark pin")
    verify.add_argument("--realvuln", default=str(DEFAULT_REALVULN))
    verify.set_defaults(
        func=lambda a: (verify_pin(Path(a.realvuln)), print("pin OK"), 0)[2]
    )

    suite = sub.add_parser("suite", help="run the isolation access suite")
    suite.add_argument("--target", type=Path, required=True)
    suite.add_argument("--gateway-url", default=None)
    suite.add_argument("--output-dir", type=Path, required=True)

    def _suite(args: argparse.Namespace) -> int:
        signoff = run_isolation_suite(
            target_dir=args.target,
            gateway_url=args.gateway_url,
            output_dir=args.output_dir,
        )
        return 0 if signoff["passed"] else 1

    suite.set_defaults(func=_suite)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
