from __future__ import annotations

import signal
import json
from pathlib import Path

import pytest

from codesec.config import ModelProfile
from codesec.runtime import (
    ExternalRuntime,
    ManagedLlamaCppRuntime,
    RuntimeUnavailableError,
)


async def test_external_runtime_rejects_wrong_served_model() -> None:
    profile = ModelProfile(
        name="titus",
        engine="local",
        endpoint="http://127.0.0.1:8080",
        model="titus",
    )

    async def probe(_profile):
        return {"data": [{"id": "some-other-model"}]}

    runtime = ExternalRuntime(probe=probe)

    with pytest.raises(RuntimeUnavailableError, match="titus"):
        await runtime.ensure_ready(profile)


async def test_managed_runtime_stops_owned_server_before_model_switch(
    tmp_path: Path,
) -> None:
    titus_path = tmp_path / "titus.gguf"
    open_path = tmp_path / "openmythos.gguf"
    titus_path.write_bytes(b"titus")
    open_path.write_bytes(b"openmythos")
    profiles = [
        ModelProfile(
            name="titus",
            engine="local",
            endpoint="http://127.0.0.1:8080",
            model="titus",
            model_path=str(titus_path),
            context_limit=32768,
            server_args=("--parallel", "4"),
        ),
        ModelProfile(
            name="openmythos",
            engine="local",
            endpoint="http://127.0.0.1:8081",
            model="openmythos",
            model_path=str(open_path),
            context_limit=24576,
        ),
    ]
    commands: list[list[str]] = []
    signals: list[tuple[int, int]] = []

    class Process:
        def __init__(self, pid: int):
            self.pid = pid
            self.returncode = None

        def poll(self):
            return self.returncode

        def wait(self, timeout=None):
            self.returncode = 0
            return 0

    def spawn(command, **kwargs):
        commands.append(command)
        return Process(1000 + len(commands))

    async def probe(profile):
        return {"data": [{"id": profile.model}]}

    async def gpu_verifier(pid, model_path):
        assert pid in {1001, 1002}
        assert model_path in {titus_path, open_path}
        return 22000

    runtime = ManagedLlamaCppRuntime(
        binary="/opt/llama-server",
        logs_dir=tmp_path / "logs",
        manifest_path=tmp_path / "run-manifest.json",
        binary_version="llama.cpp test-build",
        process_factory=spawn,
        group_signaler=lambda pid, sig: signals.append((pid, sig)),
        probe=probe,
        gpu_verifier=gpu_verifier,
        startup_timeout=0.1,
        poll_interval=0,
    )
    (tmp_path / "run-manifest.json").write_text(
        json.dumps({"run_id": "run"})
    )

    await runtime.ensure_ready(profiles[0])
    await runtime.ensure_ready(profiles[0])
    await runtime.ensure_ready(profiles[1])
    await runtime.close()

    assert len(commands) == 2
    assert commands[0][:3] == [
        "/opt/llama-server", "-m", str(titus_path),
    ]
    assert "--alias" in commands[0]
    assert commands[0][commands[0].index("--ctx-size") + 1] == "32768"
    assert commands[0][-2:] == ["--parallel", "4"]
    assert commands[1][2] == str(open_path)
    assert signals == [
        (1001, signal.SIGTERM),
        (1002, signal.SIGTERM),
    ]
    manifest = json.loads((tmp_path / "run-manifest.json").read_text())
    assert manifest["runtime"]["binary"] == "/opt/llama-server"
    assert manifest["runtime"]["binary_version"] == "llama.cpp test-build"
    assert [load["profile"] for load in manifest["runtime"]["loads"]] == [
        "titus", "openmythos",
    ]
    assert all(len(load["model_sha256"]) == 64 for load in manifest["runtime"]["loads"])
    assert all(
        load["loaded_vram_mib"] == 22000
        for load in manifest["runtime"]["loads"]
    )


async def test_managed_runtime_requires_local_endpoint_and_model_file(
    tmp_path: Path,
) -> None:
    runtime = ManagedLlamaCppRuntime(
        binary="llama-server",
        logs_dir=tmp_path / "logs",
    )
    remote = ModelProfile(
        name="remote",
        engine="local",
        endpoint="https://models.example/v1",
        model="model",
        model_path=str(tmp_path / "missing.gguf"),
    )

    with pytest.raises(ValueError, match="local HTTP endpoint"):
        await runtime.ensure_ready(remote)
