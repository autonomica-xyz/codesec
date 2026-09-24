"""P06 isolation + paired corpus integrity tests."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from bench.realvuln import isolation as iso


# ---- pin verification --------------------------------------------------------

def _git_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "rv"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    (repo / "repos").mkdir()
    (repo / "repos" / ".keep").write_text("")
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "-c", "user.email=t@t", "-c", "user.name=t",
         "commit", "-qm", "init"],
        check=True,
    )
    return repo


def test_verify_pin_matches_and_detects_dirty(tmp_path):
    repo = _git_repo(tmp_path)
    sha = subprocess.check_output(
        ["git", "-C", str(repo), "rev-parse", "HEAD"], text=True
    ).strip()

    result = iso.verify_pin(repo, expected_sha=sha)
    assert result["head"] == sha

    # Tracked modification blocks the pin.
    (repo / "repos" / ".keep").write_text("dirty")
    with pytest.raises(iso.IsolationError, match="dirty"):
        iso.verify_pin(repo, expected_sha=sha)

    # Untracked files are reported, not fatal.
    subprocess.run(["git", "-C", str(repo), "checkout", "-q", "--", "repos"],
                   check=True)
    (repo / "scan-results").mkdir()
    (repo / "scan-results" / "run-1.json").write_text("{}")
    result = iso.verify_pin(repo, expected_sha=sha)
    assert any(u.startswith("scan-results") for u in result["untracked"])

    # Wrong pin blocks.
    with pytest.raises(iso.IsolationError, match="pinned SHA"):
        iso.verify_pin(repo, expected_sha="0" * 40)


# ---- digests + symlink policy ------------------------------------------------

def test_digest_tree_v2_sees_symlink_targets(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    digest_before = iso.digest_tree_v2(tmp_path)
    (tmp_path / "link.py").symlink_to(tmp_path / "a.py")
    assert iso.digest_tree_v2(tmp_path) != digest_before
    # Swapping the target changes the digest even with identical content.
    (tmp_path / "b.py").write_text("x = 1\n")
    (tmp_path / "link.py").unlink()
    (tmp_path / "link.py").symlink_to(tmp_path / "b.py")
    swapped = iso.digest_tree_v2(tmp_path)
    (tmp_path / "link.py").unlink()
    (tmp_path / "link.py").symlink_to(tmp_path / "a.py")
    assert iso.digest_tree_v2(tmp_path) != swapped


def test_symlink_policy_rejects_escapes_and_dangling(tmp_path):
    inside = tmp_path / "real.txt"
    inside.write_text("ok")
    (tmp_path / "ok.txt").symlink_to(inside)
    assert iso.verify_symlink_policy(tmp_path) == []

    secret = tmp_path.parent / "secret.txt"
    secret.write_text("host")
    (tmp_path / "escape.txt").symlink_to(secret)
    problems = iso.verify_symlink_policy(tmp_path)
    assert any("escapes" in p for p in problems)

    (tmp_path / "escape.txt").unlink()
    (tmp_path / "dangling.txt").symlink_to(tmp_path / "gone.txt")
    problems = iso.verify_symlink_policy(tmp_path)
    assert any("dangling" in p for p in problems)


# ---- bundle preparation ------------------------------------------------------

def _mini_corpus(tmp_path: Path) -> Path:
    """A tiny realvuln-shaped corpus: one repo + ground truth."""
    rv = tmp_path / "rv"
    (rv / "repos" / "slug-a").mkdir(parents=True)
    (rv / "ground-truth" / "slug-a").mkdir(parents=True)
    repo = rv / "repos" / "slug-a"
    (repo / "app.py").write_text("def handler(q):\n    return eval(q)\n")
    (repo / "util.py").write_text("def helper():\n    return 1\n")
    (repo / "README.md").write_text("slug-a OWASP walkthrough\n")
    (rv / "ground-truth" / "slug-a" / "ground-truth.json").write_text(json.dumps({
        "repo_id": "slug-a",
        "commit_sha": "deadbeef",
        "findings": [
            {
                "id": "a-001", "is_vulnerable": True,
                "vulnerability_class": "rce",
                "primary_cwe": "CWE-95",
                "acceptable_cwes": ["CWE-95"],
                "file": "app.py",
                "location": {"start_line": 2, "end_line": 2},
            },
            {
                "id": "a-002", "is_vulnerable": False,
                "file": "util.py",
                "location": {"start_line": 1, "end_line": 1},
            },
        ],
    }))
    return rv


def test_scored_bundle_pair_is_identical_and_canary_free(tmp_path):
    rv = _mini_corpus(tmp_path)
    bundles = tmp_path / "bundles" / "slug-a-trial1"
    pair = iso.prepare_bundle_pair(
        slug="slug-a", trial=1, bundles_dir=bundles, realvuln=rv,
    )

    assert pair.h.is_dir() and pair.v.is_dir()
    assert pair.canary is None, "scored bundles must contain no canary"
    assert pair.digest
    assert iso.digest_tree_v2(pair.h) == iso.digest_tree_v2(pair.v) == pair.digest
    manifest = json.loads((bundles / "bundle.json").read_text())
    assert manifest["scored"] is True
    assert manifest["digest"] == pair.digest
    # identity docs dropped consistently in both arms
    assert not (pair.h / "README.md").exists()
    assert not (pair.v / "README.md").exists()
    assert "README.md" in pair.dropped
    # GT file bytes unchanged from source
    assert (pair.h / "app.py").read_bytes() == (
        rv / "repos" / "slug-a" / "app.py"
    ).read_bytes()


def test_gt_integrity_blocks_dropped_or_modified_gt_file(tmp_path):
    rv = _mini_corpus(tmp_path)
    bundles = tmp_path / "bundles" / "b1"
    pair = iso.prepare_bundle_pair(
        slug="slug-a", trial=1, bundles_dir=bundles, realvuln=rv,
    )
    # Tamper after the fact: verification of the SAME bundle must flag it.
    result = iso.verify_gt_locations(
        pair.h,
        json.loads(
            (rv / "ground-truth" / "slug-a" / "ground-truth.json").read_text()
        ),
        source_root=rv / "repos" / "slug-a",
    )
    assert result["problems"] == []

    (pair.h / "app.py").write_text("tampered\n")
    result = iso.verify_gt_locations(
        pair.h,
        json.loads(
            (rv / "ground-truth" / "slug-a" / "ground-truth.json").read_text()
        ),
        source_root=rv / "repos" / "slug-a",
    )
    assert any("bytes changed" in p for p in result["problems"])


def test_canary_fixture_records_interval_and_separation(tmp_path):
    rv = _mini_corpus(tmp_path)
    # Force a GT label late in util.py so separation matters.
    gt_path = rv / "ground-truth" / "slug-a" / "ground-truth.json"
    gt = json.loads(gt_path.read_text())
    gt["findings"][0]["file"] = "util.py"
    gt["findings"][0]["location"] = {"start_line": 2, "end_line": 2}
    gt_path.write_text(json.dumps(gt))

    bundles = tmp_path / "bundles" / "canary-fixture"
    pair = iso.prepare_bundle_pair(
        slug="slug-a", trial=1, bundles_dir=bundles, realvuln=rv,
        inject_canary=True,
    )
    canary = pair.canary
    assert canary["file"] == "util.py"
    assert canary["line_start"] >= canary["furthest_gt_line_in_file"] + \
        iso.CANARY_GT_SEPARATION_LINES + 1
    assert "eval(payload)" in (pair.h / "util.py").read_text()
    # Paired copies still byte-identical INCLUDING the fixture.
    assert iso.digest_tree_v2(pair.h) == iso.digest_tree_v2(pair.v)
    manifest = json.loads((bundles / "bundle.json").read_text())
    assert manifest["scored"] is False


def test_bundle_rejects_existing_directory(tmp_path):
    rv = _mini_corpus(tmp_path)
    bundles = tmp_path / "bundles" / "x"
    bundles.mkdir(parents=True)
    with pytest.raises(iso.IsolationError, match="already exists"):
        iso.prepare_bundle_pair(
            slug="slug-a", trial=1, bundles_dir=bundles, realvuln=rv,
        )


# ---- docker gating -----------------------------------------------------------

def test_missing_docker_blocks_rather_than_falling_back(monkeypatch, tmp_path):
    def no_docker(*args, **kwargs):
        raise FileNotFoundError("docker")

    monkeypatch.setattr(iso.subprocess, "run", no_docker)
    with pytest.raises(iso.IsolationError, match="BLOCKED"):
        iso.require_docker()


def test_env_allowlist_excludes_host_credentials():
    assert "ZAI_API_KEY" not in iso.CONTAINER_ENV_ALLOWLIST
    assert "HTTP_PROXY" not in iso.CONTAINER_ENV_ALLOWLIST
    assert "AWS_" not in "".join(iso.CONTAINER_ENV_ALLOWLIST)
    assert "ZAI_GATEWAY_KEY" in iso.CONTAINER_ENV_ALLOWLIST


# ---- docker integration (skipped when docker is unavailable) -----------------

def _docker_available() -> bool:
    try:
        return subprocess.run(
            ["docker", "version", "--format", "x"],
            capture_output=True, timeout=20,
        ).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


@pytest.mark.skipif(not _docker_available(), reason="docker unavailable")
def test_isolation_suite_blocks_and_permits(tmp_path):
    """The real access suite through the container bash boundary."""
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("def f(q):\n    return eval(q)\n")
    out = tmp_path / "iso"
    out.mkdir()
    try:
        signoff = iso.run_isolation_suite(
            target_dir=target,
            gateway_url=None,   # no gateway in this offline check
            output_dir=out,
        )
    finally:
        # mounts are chowned to the container uid; clean with sudo
        subprocess.run(
            ["sudo", "-n", "rm", "-rf", str(out)], check=False
        )
    assert signoff["passed"], json.dumps(signoff, indent=1)
    names = {c["name"] for c in signoff["checks"]}
    assert {
        "host_home_absent", "operator_map_absent", "gt_labels_absent",
        "prior_runs_absent", "codesec_checkout_absent",
        "docker_socket_absent", "sudo_absent", "host_pid_hidden",
        "egress_blocked", "target_readonly", "rootfs_readonly",
        "read_target", "write_scratch", "write_output",
    } <= names


@pytest.mark.skipif(not _docker_available(), reason="docker unavailable")
def test_agent_image_contains_allowlist_only(tmp_path):
    image_id = iso.build_agent_image()
    result = subprocess.run(
        ["docker", "run", "--rm", image_id, "bash", "-lc",
         "ls /opt/codesec-src 2>/dev/null; "
         "python -c 'import codesec, codesec.local_agent; print(\"harness-ok\")'; "
         "ls /home/agent/g/codesec 2>/dev/null; "
         "command -v pi; sudo -n true 2>&1 | head -1"],
        capture_output=True, text=True, timeout=300,
    )
    out = result.stdout
    assert result.returncode == 0, result.stderr[-500:]
    assert "harness-ok" in out
    assert "pi" in out
    # No source staging, no bench/, no sudo.
    assert "/opt/codesec-src" not in out.replace("ls /opt/codesec-src", "")
    assert "g/codesec" not in out
    assert "not found" in out or "sudo" not in out


def test_identity_mentions_measured_on_equivalent_fields():
    from bench.realvuln.common import measure_identity_mentions, slug_aliases

    result = measure_identity_mentions(
        {
            "description": [
                "User input reaches eval in the route handler.",
                "VAmPI-style SQL injection in the user lookup endpoint.",
                None,
            ],
            "evidence": ["eval(name)", "owasp pygoat reference in comment"],
        },
        aliases=slug_aliases("realvuln-pygoat") + ("vampi",),
    )
    # 1 description + 1 evidence mention; alias-free texts are not mentions.
    assert result["per_field"] == {"description": 1, "evidence": 1}
    assert result["total_mentions"] == 2
    assert result["texts_measured"] == 5


def test_hanging_container_is_stopped_and_removed(tmp_path):
    """R1 acceptance: a container that ignores its workload deadline is
    stopped and removed by name within the bounded cleanup window — no
    owned container survives."""
    import subprocess
    import time

    import pytest

    from bench.realvuln import isolation

    try:
        isolation.require_docker()
    except isolation.IsolationError:
        pytest.skip("docker unavailable")
    image = None
    try:
        image = isolation.resolve_image_id("codesec-iso")
    except isolation.IsolationError:
        pytest.skip("codesec-iso image not built")
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("x = 1\n")
    started = time.time()
    result = isolation.run_isolated(
        target_dir=target,
        scratch_dir=tmp_path / "scratch",
        output_dir=tmp_path / "out",
        command=["bash", "-lc", "sleep 3600"],
        gateway_url=None,
        timeout_s=3,
        image=image,
        network="codesec-iso-net",
        cleanup_grace_s=20,
    )
    elapsed = time.time() - started
    assert result["timed_out"] is True
    assert result["container"].startswith("codesec-iso-")
    assert elapsed < 3 + 25, f"cleanup exceeded grace: {elapsed:.1f}s"
    # The owned container must be gone (not merely stopped).
    ps = subprocess.run(
        ["docker", "ps", "-aq", "--filter", f"name={result['container']}"],
        capture_output=True, text=True,
    )
    assert not ps.stdout.strip(), "attempt container survived cleanup"


def test_run_isolated_normal_completion(tmp_path):
    """Sanity: a fast command completes normally, is not flagged timed_out,
    and its container is removed."""
    import subprocess

    import pytest

    from bench.realvuln import isolation

    try:
        isolation.require_docker()
        image = isolation.resolve_image_id("codesec-iso")
    except isolation.IsolationError:
        pytest.skip("docker/image unavailable")
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("x = 1\n")
    out = tmp_path / "out"
    result = isolation.run_isolated(
        target_dir=target,
        scratch_dir=tmp_path / "scratch",
        output_dir=out,
        command=["bash", "-lc", "echo hello > /work/output/done.txt"],
        gateway_url=None,
        timeout_s=60,
        image=image,
    )
    assert result["timed_out"] is False
    assert result["exit_code"] == 0
    assert (out / "done.txt").read_text().strip() == "hello"
    ps = subprocess.run(
        ["docker", "ps", "-aq", "--filter", f"name={result['container']}"],
        capture_output=True, text=True,
    )
    assert not ps.stdout.strip()
