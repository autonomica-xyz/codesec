#!/usr/bin/env python3
"""One-command calibration run: freeze → test gateway → run → teardown.

Replaces the six-step manual dance used for the relfix evidence runs:

  python -m bench.realvuln.calib_run \
      --spec bench/realvuln-runs/spec.json \
      --output bench/realvuln-runs/experiments/<id> \
      --gateway-name codesec-gateway-<name> --alias gateway-<name>

The gateway binds its records to <exp>/operator/gateway (so inference
attribution works), is attached to the isolation network under --alias and
to the default bridge for upstream egress, and is ALWAYS removed at the
end (including on failure). Use --gateway-image/--upstream/--expect to
override the defaults; --no-gateway for dead-endpoint images that must not
reach any gateway. The shared codesec-gateway is never touched.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from bench.realvuln.experiment import cmd_freeze, cmd_run  # noqa: E402

GATEWAY_IMAGE = "python:3.13-slim"
UPSTREAM = "https://api.z.ai/api/coding/paas/v4"
MODEL = "glm-5.3"
EXPECT = str(_ROOT / "bench/realvuln-runs/gateway-probe/probe_spec.json")


def _docker(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", *args], capture_output=True, text=True, check=check)


def start_gateway(name: str, alias: str, records: Path) -> None:
    _docker("rm", "-f", name, check=False)
    _docker(
        "run", "-d", "--name", name,
        "--network", "codesec-iso-net", "--network-alias", alias,
        "-v", f"{_ROOT}:/codesec:ro",
        "-v", f"{records}:/records",
        "-e", "ZAI_API_KEY",
        GATEWAY_IMAGE,
        "bash", "-lc",
        'pip -q install pyyaml >/dev/null 2>&1; cd /codesec && '
        "python -m bench.realvuln.gateway --listen 0.0.0.0:8800 "
        f"--upstream {UPSTREAM} --model {MODEL} "
        f'--expect "$(cat {EXPECT})" --records /records',
    )
    # Upstream egress lives on the default bridge (the isolation network is
    # internal) — same layout as the shared gateway.
    _docker("network", "connect", "bridge", name, check=False)
    for _ in range(10):
        if "Up " in _docker("ps", "--filter", f"name={name}",
                            "--format", "{{.Status}}").stdout:
            return
        time.sleep(0.5)
    raise SystemExit(f"test gateway {name} did not come up")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--gateway-name", default="codesec-gateway-calib")
    parser.add_argument("--alias", default="gateway-calib")
    parser.add_argument("--no-gateway", action="store_true",
                        help="dead-endpoint run: start no test gateway")
    parser.add_argument("--keep-gateway", action="store_true",
                        help="leave the gateway running after the run")
    parser.add_argument("--gateway-image", default=GATEWAY_IMAGE)
    parser.add_argument("--upstream", default=UPSTREAM)
    parser.add_argument("--model", default=MODEL)
    parser.add_argument("--expect", default=EXPECT)
    args = parser.parse_args(argv)

    exp = Path(args.output).resolve()
    started_gateway = False
    try:
        class _FreezeArgs:
            spec, output = args.spec, str(exp)

        freeze_rc = cmd_freeze(_FreezeArgs())
        if freeze_rc != 0:
            return freeze_rc
        if not args.no_gateway:
            records = exp / "operator" / "gateway"
            records.mkdir(parents=True, exist_ok=True)
            start_gateway(args.gateway_name, args.alias, records)
            started_gateway = True
        class _RunArgs:
            experiment = str(exp)

        return cmd_run(_RunArgs())
    finally:
        if started_gateway and not args.keep_gateway:
            _docker("rm", "-f", args.gateway_name, check=False)
            print(f"[calib_run] test gateway {args.gateway_name} removed",
                  file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
