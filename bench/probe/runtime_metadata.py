#!/usr/bin/env python3
"""Capture the exact local inference runtime without recording credentials."""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import shutil
import subprocess
from pathlib import Path


SECRET_OPTIONS = {"--api-key", "--api-key-file", "--token", "--password"}


def process_command(pid: int) -> list[str]:
    raw = Path(f"/proc/{pid}/cmdline").read_bytes()
    return [part.decode(errors="replace") for part in raw.split(b"\0") if part]


def redact_command(command: list[str]) -> list[str]:
    redacted = list(command)
    for index, value in enumerate(redacted[:-1]):
        if value in SECRET_OPTIONS:
            redacted[index + 1] = "<redacted>"
    return redacted


def selected_option(command: list[str], options: tuple[str, ...]) -> str | None:
    for option in options:
        if option in command:
            index = command.index(option)
            if index + 1 < len(command):
                return command[index + 1]
    return None


def command_output(command: list[str]) -> str | None:
    try:
        result = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return (result.stdout or result.stderr).strip() or None


def package_version(name: str) -> str | None:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return None


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    parser.add_argument("--requested-model", required=True)
    parser.add_argument("--served-model", required=True)
    parser.add_argument("--server-pid", required=True, type=int)
    parser.add_argument("--dataset-sha256")
    parser.add_argument("--run-id")
    parser.add_argument("--target-path")
    parser.add_argument("--launcher-path", default=shutil.which("unsloth"))
    args = parser.parse_args()

    command = process_command(args.server_pid)
    gpu = command_output(
        [
            "nvidia-smi",
            "--query-gpu=name,memory.total,memory.used,driver_version",
            "--format=csv,noheader,nounits",
        ]
    )
    llama_binary = command[0] if command else None
    runtime = {
        "requested_model": args.requested_model,
        "served_model": args.served_model,
        "selected_model_file": selected_option(command, ("-m", "--model")),
        "server_port": selected_option(command, ("--port", "-p")),
        "server_pid": args.server_pid,
        "server_command": redact_command(command),
        "gpu": gpu.splitlines() if gpu else None,
        "unsloth_cli_version": (
            command_output([args.launcher_path, "--version"])
            if args.launcher_path
            else None
        ),
        "llama_server_version": (
            command_output([llama_binary, "--version"])
            if llama_binary
            else None
        ),
        "dataset_sha256": args.dataset_sha256,
        "run_id": args.run_id,
        "target_path": args.target_path,
        "packages": {
            name: package_version(name)
            for name in ("unsloth", "torch", "transformers", "huggingface-hub")
        },
    }
    Path(args.out).write_text(json.dumps(runtime, indent=2) + "\n")


if __name__ == "__main__":
    main()
