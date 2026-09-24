"""Click-based CLI: auth-check, run, status, report."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import uuid
from pathlib import Path

import click
from dotenv import load_dotenv
from rich.console import Console
from rich.logging import RichHandler
from rich.table import Table

from codesec.auth import AuthError, configure_auth
from codesec.config import load_config
from codesec.orchestrator import CostExceeded, run_pipeline
from codesec.providers import ProviderError, get_provider, provider_names
from codesec.run_paths import RunPaths
from codesec.runtime import ExternalRuntime, ManagedLlamaCppRuntime
from codesec.state import StateDB


def _allow_api_key_from_env_or_flag(flag: bool) -> bool:
    """Opt into api_key mode via --allow-api-key OR via
    CODESEC_ALLOW_API_KEY=1 in the env (AUDIT_ALLOW_API_KEY also accepted
    for users porting config from upstream evilsocket/audit)."""
    if flag:
        return True
    for var in ("CODESEC_ALLOW_API_KEY", "AUDIT_ALLOW_API_KEY"):
        if os.environ.get(var, "").strip() not in ("", "0", "false", "False"):
            return True
    return False


def _provider_options(fn):
    """Shared --provider / --api-key / --base-url / --model flags for the
    auth-check and run commands. Keeps the four options in sync."""
    opts = [
        click.option("--provider", type=click.Choice(provider_names()),
                     default="anthropic", show_default=True,
                     envvar="CODESEC_PROVIDER",
                     help="LLM backend preset. 'anthropic' (default) uses Claude subscription/API/gateway as-is. 'zai' = Z.AI GLM Coding Plan, 'unsloth' = local Unsloth Studio server."),
        click.option("--api-key", "provider_api_key", default=None,
                     help="API key for the provider (also via ZAI_API_KEY / UNSLOTH_API_KEY / CODESEC_API_KEY). For non-anthropic providers this is mapped onto ANTHROPIC_AUTH_TOKEN."),
        click.option("--base-url", "provider_base_url", default=None,
                     envvar="CODESEC_BASE_URL",
                     help="Override the provider's default base URL (also via CODESEC_BASE_URL). Useful for Unsloth's port."),
        click.option("--model", "model", default=None, envvar="CODESEC_MODEL",
                     help="Force one model for every stage. For Unsloth pass the loaded GGUF id (from GET /v1/models). Collapses deliberate-disagreement to a single model."),
    ]
    for opt in reversed(opts):
        fn = opt(fn)
    return fn


def _apply_provider_models(config, provider: str, model: str | None) -> None:
    """Remap per-stage models for the chosen provider. Errors loudly if a
    non-anthropic provider still ends up pointing at claude-* models."""
    if provider == "anthropic" and not model:
        return
    prov = get_provider(provider)
    config.apply_provider_models(prov, model)
    leftover = [s.name for s in config.stages.values()
                if s.model.lower().startswith("claude")]
    if leftover:
        raise click.UsageError(
            f"provider {provider!r} has no default model for stages still set "
            f"to a claude-* model ({leftover}). Pass --model <id> "
            f"(for Unsloth: the GGUF id from GET /v1/models)."
        )

REPO_ROOT = Path(__file__).resolve().parent.parent
DB_PATH = REPO_ROOT / "state.db"
RESULTS_ROOT = REPO_ROOT / "results"
RUNS_ROOT = REPO_ROOT / "runs"
DEFAULT_CONFIG_PATH = REPO_ROOT / "config" / "stages.yaml"
DUO_CONFIG_PATH = REPO_ROOT / "config" / "duo-v1.yaml"

console = Console()


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=console, rich_tracebacks=True,
                              show_path=False, markup=False)],
    )


@click.group()
@click.option("-v", "--verbose", is_flag=True, help="DEBUG logging.")
@click.pass_context
def main(ctx: click.Context, verbose: bool) -> None:
    """codesec — Cloudflare-style 8-stage vulnerability discovery agent."""
    ctx.ensure_object(dict)
    _setup_logging(verbose)
    load_dotenv()


@main.command("auth-check")
@_provider_options
@click.option("--allow-api-key", is_flag=True, default=False,
              help="Honor ANTHROPIC_API_KEY for metered Anthropic billing "
                   "(also via CODESEC_ALLOW_API_KEY=1).")
def auth_check(provider: str, provider_api_key: str | None,
               provider_base_url: str | None, model: str | None,
               allow_api_key: bool) -> None:
    """Verify Claude Code auth is configured correctly."""
    allow = _allow_api_key_from_env_or_flag(allow_api_key)
    try:
        status = configure_auth(
            allow_api_key=allow,
            provider=provider,
            provider_api_key=provider_api_key,
            provider_base_url=provider_base_url,
        )
    except (AuthError, ProviderError) as e:
        console.print(f"[red]auth error:[/red] {e}")
        sys.exit(2)
    label = {
        "oauth_token": "using CLAUDE_CODE_OAUTH_TOKEN",
        "api_key": "using ANTHROPIC_API_KEY (metered Anthropic API billing)",
        "keychain_login": f"using stored login from {status.credentials_file}",
        "macos_keychain_login": "using macOS Keychain-backed Claude Code login",
        "gateway": f"using LLM gateway at {status.gateway_base_url} (ANTHROPIC_AUTH_TOKEN)",
    }.get(status.auth_mode)
    if label:
        console.print(f"[green]OK[/green] {label}")
    if status.provider != "anthropic":
        console.print(f"          provider={status.provider}")
        from codesec.providers import get_provider, local_base_url
        console.print(f"          openai_base={local_base_url(get_provider(status.provider))}")
        console.print("          engine=local (no Claude CLI)")
    if status.gateway_model:
        console.print(f"          ANTHROPIC_MODEL={status.gateway_model}")
    if status.api_key_scrubbed:
        console.print("[yellow]scrubbed[/yellow] ANTHROPIC_API_KEY removed from env "
                      "(it would have outranked the active auth mode)")
    if status.auth_token_scrubbed:
        console.print("[yellow]scrubbed[/yellow] ANTHROPIC_AUTH_TOKEN removed from env "
                      "(no gateway base URL set — leaving it would outrank subscription)")
    if status.claude_cli_path:
        console.print(f"claude CLI: {status.claude_cli_path} ({status.claude_cli_version})")


@main.command("unsloth-proxy")
@click.option("--upstream", default="http://localhost:8888", show_default=True,
              help="Unsloth Studio base URL to forward to.")
@click.option("--host", default="127.0.0.1", show_default=True)
@click.option("--port", default=9999, show_default=True, type=int)
@click.option("--allow", default="Read,Grep,Glob,Bash", show_default=True,
              help="Comma-separated tool names to keep (strips the rest so "
                   "llama-server can compile the tool-call grammar).")
def unsloth_proxy(upstream: str, host: str, port: int, allow: str) -> None:
    """Sidecar that lets the SDK talk to local llama-server backends.

    llama-server can't compile a tool-calling grammar over the full Claude
    Code toolset (every extension/MCP tool your install registers) for some
    models, 400ing every turn. This proxy strips the advertised `tools` down
    to the allowlist (default: exactly what codesec stages use), which
    compiles cleanly. Run it, then: codesec run --provider unsloth
    --base-url http://HOST:PORT --model <gguf>.
    """
    from codesec.unsloth_proxy import run_proxy
    run_proxy(upstream, host, port, tuple(x.strip() for x in allow.split(",")))


@main.command("providers")
def providers() -> None:
    """List the built-in LLM provider presets."""
    t = Table(title="providers", show_lines=False)
    t.add_column("name")
    t.add_column("base URL")
    t.add_column("opus-role")
    t.add_column("sonnet-role")
    t.add_column("docs")
    for name in provider_names():
        p = get_provider(name)
        t.add_row(name, p.base_url or "(anthropic.com / gateway)",
                  p.opus_role_model or "—", p.sonnet_role_model or "—",
                  p.docs_url)
    console.print(t)
    console.print("Pass --provider <name> to `run` or `auth-check`. "
                  "Set the key via ZAI_API_KEY / UNSLOTH_API_KEY / CODESEC_API_KEY "
                  "or --api-key.")


@main.command("run")
@click.option("--repo", "repo", required=True, type=click.Path(exists=True, file_okay=False),
              help="Path to the target source-code repo.")
@click.option("--run-id", default=None, help="Run identifier (default: random).")
@click.option("--resume", is_flag=True, help="Resume an existing run-id.")
@click.option("--max-cost-usd", default=None, type=float,
              help="Abort if cumulative cost crosses this threshold.")
@click.option("--max-hours", default=None, type=float,
              help="Wall-clock budget in hours. The last 20% is closing "
                   "mode: no new Hunt/Gapfill/Feedback breadth — spend it "
                   "validating and reporting what exists.")
@click.option("--max-concurrency", default=None, type=int,
              help="Cap every stage's concurrency to this (cost containment).")
@click.option("--max-recon-tasks", default=None, type=int,
              help="Cap the number of initial Hunt tasks Recon may emit.")
@click.option("--target-url", default=None,
              help="Optional: URL of a live deployment the agents can hit "
                   "to confirm findings (e.g. http://server.local:8888).")
@click.option("--target-creds", "target_creds", multiple=True,
              metavar="KEY=VALUE",
              help="Credentials for the live target. Repeat the flag for "
                   "each KEY=VALUE pair (e.g. --target-creds email=admin@x "
                   "--target-creds password=...).")
@click.option("--scope-notes", "scope_notes_path", default=None,
              type=click.Path(exists=True, dir_okay=False),
              help="Optional: path to a text file with target-specific scope "
                   "rules / exclusions; passed verbatim to every stage.")
@click.option("--prior", type=click.Choice(["auto", "off", "path"]),
              default="auto", show_default=True,
              help="Cross-run catalogue carry (W8). 'auto' uses the repo's "
                   ".codesec-catalogue.db when present; 'path' uses "
                   "--catalogue-db; 'off' disables prior carry.")
@click.option("--catalogue-db", "catalogue_db", default=None,
              type=click.Path(path_type=Path),
              help="Path to the cross-run catalogue DB (default: "
                   "<repo>/.codesec-catalogue.db).")
@click.option("--upstream", default=None,
              help="Upstream git URL or path (W15): confirmed findings are "
                   "checked against recent upstream history for novelty.")
@click.option("--config", "config_path", default=None, type=click.Path(),
              help="Override config/stages.yaml.")
@click.option("--pipeline", type=click.Choice(["legacy", "duo-v1"]),
              default="legacy", show_default=True,
              help="Pipeline schedule. duo-v1 batches Titus before OpenMythos.")
@click.option("--run-root", default=None,
              type=click.Path(file_okay=False, path_type=Path),
              help="Isolated state/results/work root. duo-v1 defaults to runs/RUN_ID.")
@click.option("--runtime", "runtime_mode",
              type=click.Choice(["external", "managed"]), default=None,
              help="duo-v1 model lifecycle (default: external endpoint checks).")
@click.option("--llama-server", default="llama-server",
              envvar="CODESEC_LLAMA_SERVER", show_default=True,
              help="llama.cpp server binary used by --runtime managed.")
@_provider_options
@click.option("--engine", type=click.Choice(["sdk", "local"]), default=None,
              help="Agent engine. Default: local (OpenAI chat completions, no "
                   "Claude CLI) for --provider zai/unsloth; sdk (Claude Code) "
                   "for anthropic. Pass --engine sdk to force Claude Code.")
@click.option("--allow-api-key", is_flag=True, default=False,
              help="Honor ANTHROPIC_API_KEY for metered Anthropic billing "
                   "(also via CODESEC_ALLOW_API_KEY=1).")
def run(repo: str, run_id: str | None, resume: bool, max_cost_usd: float | None,
        max_hours: float | None, max_concurrency: int | None, max_recon_tasks: int | None,
        target_url: str | None, target_creds: tuple[str, ...],
        scope_notes_path: str | None,
        prior: str, catalogue_db: Path | None, upstream: str | None,
        config_path: str | None, pipeline: str, run_root: Path | None,
        runtime_mode: str | None, llama_server: str,
        provider: str, provider_api_key: str | None,
        provider_base_url: str | None, model: str | None,
        engine: str | None, allow_api_key: bool) -> None:
    """Run the full 8-stage pipeline against a target repo."""
    from codesec import runner

    selected_config_path = (
        Path(config_path).resolve()
        if config_path
        else (DUO_CONFIG_PATH if pipeline == "duo-v1" else DEFAULT_CONFIG_PATH)
    )
    config = load_config(selected_config_path)
    profile_routed = bool(config.model_profiles) and all(
        stage.profile is not None for stage in config.stages.values()
    )

    if engine is None:
        engine = "local" if provider in {"zai", "unsloth"} else "sdk"

    if profile_routed:
        if model:
            raise click.UsageError(
                "--model cannot override a profile-routed configuration"
            )
        console.print(
            "[cyan]engine:[/cyan] request-scoped local model profiles"
        )
    elif engine == "local":
        # Direct OpenAI-compat path: skip Claude Code entirely.
        from codesec.providers import get_provider, local_base_url, resolve_key
        prov = get_provider(provider)
        base = local_base_url(prov, provider_base_url)
        key = resolve_key(prov, provider_api_key)
        if provider != "anthropic" and not key:
            console.print(
                f"[red]auth error:[/red] No API key for provider {provider!r}. "
                f"Set one of {list(prov.key_env_vars)} or pass --api-key."
            )
            sys.exit(2)
        if not model:
            console.print("[red]--engine local requires --model[/red] "
                          "(the model id / GGUF alias the server reports)")
            sys.exit(2)
        runner.set_engine("local", base, key or None)
        console.print(f"[cyan]engine:[/cyan] local  base={base}  model={model}")
    else:
        allow = _allow_api_key_from_env_or_flag(allow_api_key)
        try:
            status = configure_auth(
                allow_api_key=allow,
                provider=provider,
                provider_api_key=provider_api_key,
                provider_base_url=provider_base_url,
            )
        except (AuthError, ProviderError) as e:
            console.print(f"[red]auth error:[/red] {e}")
            sys.exit(2)

    if max_concurrency is not None:
        config.cap_concurrency(max_concurrency)
        console.print(f"[cyan]capped concurrency to {max_concurrency} across all stages[/cyan]")
    if not profile_routed:
        _apply_provider_models(config, provider, model)
    if profile_routed:
        console.print(
            f"[cyan]models:[/cyan] recon/hunt={config.get('hunt').model}, "
            f"validate/trace={config.get('validate').model}"
        )
    elif engine == "local":
        console.print(f"[cyan]models:[/cyan] recon/trace={config.get('recon').model}, "
                      f"hunt={config.get('hunt').model}")
    elif provider != "anthropic":
        console.print(f"[cyan]provider:[/cyan] {provider} "
                      f"(recon/trace={config.get('recon').model}, "
                      f"hunt={config.get('hunt').model})")

    # Live-target plumbing — agents will receive {"url": ..., "credentials": {...}}
    # in their user_input when set.
    live_target: dict | None = None
    if target_url:
        creds: dict[str, str] = {}
        for kv in target_creds:
            if "=" not in kv:
                console.print(f"[red]invalid --target-creds {kv!r} — expected KEY=VALUE[/red]")
                sys.exit(2)
            k, _, v = kv.partition("=")
            creds[k.strip()] = v.strip()
        live_target = {"url": target_url, "credentials": creds}
        console.print(f"[cyan]live target:[/cyan] {target_url} (creds: {sorted(creds)})")
    elif target_creds:
        console.print("[yellow]--target-creds without --target-url is ignored[/yellow]")

    scope_notes: str | None = None
    if scope_notes_path:
        scope_notes = Path(scope_notes_path).read_text()
        console.print(f"[cyan]scope notes loaded:[/cyan] {scope_notes_path} ({len(scope_notes)} chars)")

    run_id = run_id or f"run_{uuid.uuid4().hex[:8]}"
    repo_path = Path(repo).resolve()

    if runtime_mode is not None and pipeline != "duo-v1":
        raise click.UsageError("--runtime is only valid with --pipeline duo-v1")

    run_paths: RunPaths | None = None
    if pipeline == "duo-v1" or run_root is not None:
        run_paths = RunPaths(
            (run_root if run_root is not None else RUNS_ROOT / run_id).resolve()
        )
        run_paths.prepare(
            run_id=run_id,
            repo_path=repo_path,
            pipeline=pipeline,
            config_path=selected_config_path,
            resume=resume,
        )
        database_path = run_paths.database
        results_root = run_paths.results
        work_root = run_paths.work
        console.print(f"[cyan]run root:[/cyan] {run_paths.root}")
    else:
        database_path = DB_PATH
        results_root = None
        work_root = None

    model_runtime = None
    if pipeline == "duo-v1":
        effective_runtime = runtime_mode or "external"
        if effective_runtime == "managed":
            assert run_paths is not None
            model_runtime = ManagedLlamaCppRuntime(
                binary=llama_server,
                logs_dir=run_paths.logs,
                manifest_path=run_paths.manifest,
            )
        else:
            model_runtime = ExternalRuntime()

    db = StateDB(database_path)
    try:
        report = asyncio.run(run_pipeline(
            repo_path=repo_path,
            run_id=run_id,
            db=db,
            config=config,
            max_cost_usd=max_cost_usd,
            max_hours=max_hours,
            resume=resume,
            max_recon_tasks=max_recon_tasks,
            live_target=live_target,
            scope_notes=scope_notes,
            pipeline=pipeline,
            run_results_root=results_root,
            run_work_root=work_root,
            runtime=model_runtime,
            prior=prior,
            catalogue_db=catalogue_db,
            upstream=upstream,
        ))
        console.print(f"[green]done[/green] run_id={run_id} report={report}")
    except CostExceeded as e:
        console.print(f"[yellow]aborted[/yellow] {e}")
        sys.exit(3)
    except Exception as e:
        console.print(f"[red]failed[/red] {type(e).__name__}: {e}")
        raise
    finally:
        db.close()


@main.command("status")
@click.option("--run-id", default=None)
@click.option("--run-root", default=None,
              type=click.Path(file_okay=False, path_type=Path),
              help="Read state from an isolated run root.")
def status(run_id: str | None, run_root: Path | None) -> None:
    """Show pipeline status: tasks, findings, traces, cost."""
    database_path = (
        run_root.resolve() / "state.db" if run_root is not None else DB_PATH
    )
    if run_root is not None and not database_path.is_file():
        raise click.UsageError(f"no state database at {database_path}")
    db = StateDB(database_path)
    try:
        if run_id is None:
            _show_runs_table(db)
            return
        run = db.get_run(run_id)
        if run is None:
            console.print(f"[red]unknown run_id {run_id!r}[/red]")
            sys.exit(1)
        _show_run_detail(db, run_id)
    finally:
        db.close()


@main.command("report")
@click.option("--run-id", required=True)
@click.option("--format", "fmt", type=click.Choice(["json", "md"]), default="json")
@click.option("--run-root", default=None,
              type=click.Path(file_okay=False, path_type=Path),
              help="Read the report from an isolated run root.")
def report(run_id: str, fmt: str, run_root: Path | None) -> None:
    """Print (or generate) the final report."""
    report_path = (
        run_root.resolve() / "results" / "report" / "report.json"
        if run_root is not None
        else RESULTS_ROOT / run_id / "report" / "report.json"
    )
    if not report_path.exists():
        console.print(f"[red]no report at {report_path}[/red]")
        sys.exit(1)
    payload = json.loads(report_path.read_text())
    if fmt == "json":
        click.echo(json.dumps(payload, indent=2))
    else:
        click.echo(_render_markdown_report(payload))


def _show_runs_table(db: StateDB) -> None:
    runs = db.list_runs()
    t = Table(title="runs", show_lines=False)
    t.add_column("run_id")
    t.add_column("repo")
    t.add_column("status")
    t.add_column("cost ($)")
    for r in runs:
        t.add_row(r["run_id"], r["repo_path"], r["status"],
                  f"{db.total_cost(r['run_id']):.4f}")
    console.print(t)


def _show_run_detail(db: StateDB, run_id: str) -> None:
    tasks = db.get_all_tasks(run_id)
    findings = db.get_findings(run_id)
    confirmed = [f for f in findings if f.validation_status == "confirmed"]
    canonical = [f for f in confirmed if f.is_canonical]
    reachable = db.get_reachable_canonical_findings(run_id)
    reportable = db.get_report_findings(run_id)
    untraced = sum(1 for _f, tr in reportable if tr is None)

    t = Table(title=f"run {run_id}", show_lines=False)
    t.add_column("metric"); t.add_column("count")
    t.add_row("tasks (total)", str(len(tasks)))
    t.add_row("tasks (pending)", str(sum(1 for x in tasks if x.status == "pending")))
    t.add_row("tasks (done)", str(sum(1 for x in tasks if x.status == "done")))
    t.add_row("tasks (failed)", str(sum(1 for x in tasks if x.status == "failed")))
    t.add_row("findings (raw)", str(len(findings)))
    t.add_row("findings (confirmed)", str(len(confirmed)))
    t.add_row("findings (canonical)", str(len(canonical)))
    t.add_row("findings (reachable)", str(len(reachable)))
    t.add_row("findings (report)", str(len(reportable)))
    t.add_row("findings (untraced)", str(untraced))
    t.add_row("total cost ($)", f"{db.total_cost(run_id):.4f}")
    console.print(t)


def _render_markdown_report(report: dict) -> str:
    lines: list[str] = []
    lines.append(f"# Vulnerability report — `{report['run_id']}`")
    lines.append(f"Target: `{report['target']['repo_path']}`  ")
    s = report["summary"]
    by = s.get("by_severity", {})
    lines.append(f"**Total findings: {s['total']}** — "
                 + ", ".join(f"{k}: {v}" for k, v in by.items()) if by
                 else f"**Total findings: {s['total']}**")
    lines.append("")
    for f in report["findings"]:
        lines.append(f"## {f['title']}")
        lines.append(f"- **Severity**: {f['severity']}  ")
        lines.append(f"- **Class**: {f['vuln_class']}"
                     + (f" ({f['cwe']})" if f.get("cwe") else ""))
        lines.append(f"- **Location**: `{f['file']}:{f['line_start']}-{f['line_end']}`  ")
        lines.append("")
        lines.append(f["description"])
        lines.append("")
        lines.append("```")
        lines.append(f["evidence"])
        lines.append("```")
        lines.append("")
        ep = f["trace"].get("entry_points", [])
        if ep:
            lines.append("**Entry points**:")
            for e in ep:
                lines.append(f"- `{e['kind']}` at `{e['location']}`")
            lines.append("")
        cc = f["trace"].get("call_chain", [])
        if cc:
            lines.append("**Call chain**:")
            for frame in cc:
                lines.append(f"1. `{frame['file']}:{frame['line']}` — `{frame['function']}()`")
            lines.append("")
        lines.append(f"**Recommendation**: {f['recommendation']}")
        lines.append("")
        if f.get("variants"):
            lines.append(f"_Variants_: {', '.join(f['variants'])}")
            lines.append("")
        lines.append("---")
        lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    main()
