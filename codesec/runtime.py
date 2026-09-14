"""Model lifecycle implementations for phase-batched local pipelines."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import signal
import subprocess
import time
import urllib.request
from pathlib import Path
from typing import Any, Awaitable, Callable, Protocol
from urllib.parse import urlparse

from codesec.config import ModelProfile


class RuntimeUnavailableError(RuntimeError):
    """A configured endpoint did not make the expected model available."""


class ModelRuntime(Protocol):
    """Make a model profile ready before a phase and release owned resources."""

    async def ensure_ready(self, profile: ModelProfile) -> None:
        ...

    async def close(self) -> None:
        ...


Probe = Callable[[ModelProfile], Awaitable[dict[str, Any]]]
GpuVerifier = Callable[[int, Path], Awaitable[int]]


def _models_url(endpoint: str) -> str:
    base = endpoint.rstrip("/")
    return f"{base}/models" if base.endswith("/v1") else f"{base}/v1/models"


async def probe_openai_endpoint(
    profile: ModelProfile,
    *,
    timeout: float = 5.0,
) -> dict[str, Any]:
    """Return the OpenAI-compatible model-list response for a profile."""
    if not profile.endpoint:
        raise ValueError(f"profile {profile.name!r} has no endpoint")

    def request() -> dict[str, Any]:
        api_key = (
            os.environ.get(profile.api_key_env)
            if profile.api_key_env
            else None
        )
        request = urllib.request.Request(
            _models_url(profile.endpoint),
            headers={
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36",
                **(
                    {"Authorization": f"Bearer {api_key}"}
                    if api_key
                    else {}
                ),
            },
        )
        with urllib.request.urlopen(
            request, timeout=timeout
        ) as response:
            return json.loads(response.read())

    return await asyncio.to_thread(request)


async def verify_nvidia_gpu_allocation(pid: int, model_path: Path) -> int:
    """Fail closed if the owned server did not allocate substantial VRAM."""

    def query() -> int:
        try:
            result = subprocess.run(
                [
                    "nvidia-smi",
                    "--query-compute-apps=pid,used_memory",
                    "--format=csv,noheader,nounits",
                ],
                capture_output=True,
                text=True,
                timeout=10,
                check=True,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise RuntimeUnavailableError(
                f"cannot verify NVIDIA GPU allocation: {error}"
            ) from error
        for line in result.stdout.splitlines():
            fields = [field.strip() for field in line.split(",")]
            if len(fields) != 2:
                continue
            try:
                listed_pid, used_mib = int(fields[0]), int(fields[1])
            except ValueError:
                continue
            if listed_pid == pid:
                minimum_mib = max(
                    1024, int(model_path.stat().st_size / (1024 * 1024) * 0.5)
                )
                if used_mib < minimum_mib:
                    raise RuntimeUnavailableError(
                        f"llama-server PID {pid} allocated only {used_mib} MiB "
                        f"VRAM; expected at least {minimum_mib} MiB"
                    )
                return used_mib
        raise RuntimeUnavailableError(
            f"llama-server PID {pid} is absent from nvidia-smi compute apps"
        )

    return await asyncio.to_thread(query)


def _assert_served_model(
    profile: ModelProfile,
    response: dict[str, Any],
) -> None:
    served = {
        item.get("id")
        for item in response.get("data", [])
        if isinstance(item, dict)
    }
    if profile.model not in served:
        raise RuntimeUnavailableError(
            f"profile {profile.name!r} expected served model "
            f"{profile.model!r}; endpoint reported {sorted(x for x in served if x)}"
        )


class ExternalRuntime:
    """Health-check operator-managed endpoints without owning their processes."""

    def __init__(self, *, probe: Probe = probe_openai_endpoint):
        self._probe = probe

    async def ensure_ready(self, profile: ModelProfile) -> None:
        _assert_served_model(profile, await self._probe(profile))

    async def close(self) -> None:
        return None


class ManagedLlamaCppRuntime:
    """Own one llama.cpp server process and replace it at model boundaries."""

    def __init__(
        self,
        *,
        binary: str,
        logs_dir: Path,
        manifest_path: Path | None = None,
        binary_version: str | None = None,
        startup_timeout: float = 120.0,
        poll_interval: float = 1.0,
        process_factory: Callable[..., Any] = subprocess.Popen,
        group_signaler: Callable[[int, int], None] = os.killpg,
        probe: Probe = probe_openai_endpoint,
        gpu_verifier: GpuVerifier = verify_nvidia_gpu_allocation,
    ):
        self.binary = binary
        self.logs_dir = logs_dir
        self.manifest_path = manifest_path
        self.binary_version = binary_version
        self.startup_timeout = startup_timeout
        self.poll_interval = poll_interval
        self._spawn = process_factory
        self._signal_group = group_signaler
        self._probe = probe
        self._gpu_verifier = gpu_verifier
        self._process: Any | None = None
        self._profile_name: str | None = None
        self._log_file: Any | None = None

    async def ensure_ready(self, profile: ModelProfile) -> None:
        if self._profile_name == profile.name and self._process is not None:
            if self._process.poll() is None:
                return
        endpoint = self._local_endpoint(profile)
        model_path = self._model_path(profile)
        model_sha256 = await self._verify_checksum(profile, model_path)
        await self._stop()

        self.logs_dir.mkdir(parents=True, exist_ok=True)
        log_path = self.logs_dir / f"llama-{profile.name}.log"
        self._log_file = log_path.open("ab")
        command = [
            self.binary,
            "-m",
            str(model_path),
            "--alias",
            profile.model,
            "--host",
            endpoint.hostname or "127.0.0.1",
            "--port",
            str(endpoint.port or 80),
            "-ngl",
            "999",
            "--ctx-size",
            str(profile.context_limit),
            *profile.server_args,
        ]
        try:
            self._process = self._spawn(
                command,
                stdout=self._log_file,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            self._profile_name = profile.name
            await self._wait_until_ready(profile)
            loaded_vram_mib = await self._gpu_verifier(
                self._process.pid, model_path
            )
            await self._record_load(
                profile,
                model_path,
                model_sha256,
                command,
                loaded_vram_mib,
            )
        except Exception:
            await self._stop()
            raise

    async def close(self) -> None:
        await self._stop()

    @staticmethod
    def _local_endpoint(profile: ModelProfile):
        if not profile.endpoint:
            raise ValueError(f"profile {profile.name!r} has no endpoint")
        parsed = urlparse(profile.endpoint)
        if (
            parsed.scheme != "http"
            or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
        ):
            raise ValueError(
                "managed llama.cpp requires a local HTTP endpoint"
            )
        return parsed

    @staticmethod
    def _model_path(profile: ModelProfile) -> Path:
        configured = profile.model_path
        if configured is None and profile.model_path_env:
            configured = os.environ.get(profile.model_path_env)
        if not configured:
            hint = (
                f"environment variable {profile.model_path_env}"
                if profile.model_path_env
                else "model_path"
            )
            raise ValueError(
                f"profile {profile.name!r} requires {hint} for managed runtime"
            )
        path = Path(configured).expanduser().resolve()
        if not path.is_file():
            raise FileNotFoundError(f"model file not found: {path}")
        return path

    @staticmethod
    async def _verify_checksum(
        profile: ModelProfile,
        model_path: Path,
    ) -> str:

        def digest() -> str:
            checksum = hashlib.sha256()
            with model_path.open("rb") as source:
                for chunk in iter(lambda: source.read(1024 * 1024), b""):
                    checksum.update(chunk)
            return checksum.hexdigest()

        actual = await asyncio.to_thread(digest)
        if (
            profile.expected_sha256
            and actual.lower() != profile.expected_sha256.lower()
        ):
            raise RuntimeUnavailableError(
                f"checksum mismatch for profile {profile.name!r}: "
                f"expected {profile.expected_sha256}, got {actual}"
            )
        return actual

    async def _record_load(
        self,
        profile: ModelProfile,
        model_path: Path,
        model_sha256: str,
        command: list[str],
        loaded_vram_mib: int,
    ) -> None:
        if self.manifest_path is None:
            return
        if self.binary_version is None:
            self.binary_version = await asyncio.to_thread(
                self._detect_binary_version
            )
        manifest = json.loads(self.manifest_path.read_text())
        runtime = manifest.setdefault(
            "runtime",
            {
                "kind": "managed_llama_cpp",
                "binary": self.binary,
                "binary_version": self.binary_version,
                "loads": [],
            },
        )
        runtime["loads"].append(
            {
                "profile": profile.name,
                "source": profile.source,
                "served_model": profile.model,
                "endpoint": profile.endpoint,
                "model_path": str(model_path),
                "model_sha256": model_sha256,
                "command": command,
                "loaded_vram_mib": loaded_vram_mib,
                "ready_at": time.time(),
            }
        )
        temporary = self.manifest_path.with_suffix(".json.tmp")
        temporary.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n"
        )
        temporary.replace(self.manifest_path)

    def _detect_binary_version(self) -> str:
        try:
            result = subprocess.run(
                [self.binary, "--version"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except OSError as error:
            return f"unavailable: {error}"
        output = (result.stdout or result.stderr).strip()
        return output or f"exit {result.returncode}"

    async def _wait_until_ready(self, profile: ModelProfile) -> None:
        deadline = time.monotonic() + self.startup_timeout
        last_error: Exception | None = None
        while time.monotonic() <= deadline:
            if self._process is None or self._process.poll() is not None:
                code = None if self._process is None else self._process.poll()
                raise RuntimeUnavailableError(
                    f"llama-server for {profile.name!r} exited with code {code}"
                )
            try:
                response = await self._probe(profile)
                _assert_served_model(profile, response)
                return
            except Exception as error:
                last_error = error
                await asyncio.sleep(self.poll_interval)
        raise RuntimeUnavailableError(
            f"timed out waiting for profile {profile.name!r}: {last_error}"
        )

    async def _stop(self) -> None:
        process, self._process = self._process, None
        self._profile_name = None
        if process is not None and process.poll() is None:
            try:
                self._signal_group(process.pid, signal.SIGTERM)
                await asyncio.to_thread(process.wait, timeout=10)
            except subprocess.TimeoutExpired:
                self._signal_group(process.pid, signal.SIGKILL)
                await asyncio.to_thread(process.wait, timeout=5)
            except ProcessLookupError:
                pass
        if self._log_file is not None:
            self._log_file.close()
            self._log_file = None
