# codesec

A multi-agent vulnerability-discovery harness for real codebases. Instead of
asking one big model "find bugs here", codesec fans out **many narrow agents**
on tightly-scoped questions, has a **second, adversarial panel on a different
model try to disprove every finding**, and gates the final report on a
**reachability trace** — proof that attacker-controlled input can actually
reach the sink. Findings are fingerprinted and remembered **across runs**, so
the tool gets cheaper and more precise the more you point it at the same repo.

It runs against a **Claude subscription**, the **Z.AI GLM Coding Plan**, or
**your own GPU** (GGUF models via llama-server / Unsloth / vLLM), including a
fully-local two-model pipeline that manages its own llama.cpp processes.


## How it works

The architecture is a from-scratch reimplementation of the pipeline Cloudflare
described in [Project Glasswing](https://blog.cloudflare.com/cyber-frontier-models/)
which argues that real-world vulnerability discovery comes from:

1. **Many narrow agents** working in parallel on tightly-scoped questions
   ("Look for command injection in this specific function, with this trust
   boundary above it") rather than one exhaustive agent.
2. **Deliberate disagreement** — a second agent, on a different model, that
   tries to *disprove* the first agent's findings.
3. **A reachability trace** as the gating step — most "is this code buggy?"
   findings are noise unless an attacker-controlled input can actually reach
   the sink from outside the system.
4. **A feedback loop** so reachable bugs in one place automatically seed
   hunts for the same pattern elsewhere.

codesec implements this as an 8-stage pipeline and then goes further:
hardening the disagreement step into an adversarial panel, turning
reachability into an *executable* check against live targets, and giving the
harness cross-run memory.

## The 8 stages

| # | Stage    | Role (model family) | Purpose |
|---|----------|---------------------|---------|
| 1 | Recon    | opus  | Map the repo, emit narrowly-scoped Hunt tasks |
| 2 | Hunt     | sonnet | One attack class per agent; compile/run PoCs |
| 3 | Validate | opus  | Adversarial review panel + arbiter; tries to **disprove** (different model from Hunt) |
| 4 | Gapfill  | sonnet | Re-queue under-covered areas |
| 5 | Dedupe   | sonnet | Cluster findings by root cause |
| 6 | Trace    | opus  | Prove attacker-controlled input reaches the sink |
| 7 | Feedback | sonnet | Turn reachable traces into new Hunt tasks |
| 8 | Report   | sonnet | Schema-validated structured report |

Each stage is one markdown prompt in `prompts/` + one JSON Schema in
`schemas/`. The orchestrator passes the schema into the system prompt so
every output is shape-stable on the first try, with semantic postconditions
(`codesec/contracts.py`) covering what JSON Schema can't express, and a
repair turn when validation fails anyway. Stages are tagged by **role**
(opus / sonnet); swapping the whole model family (see backends below) keeps
the validate≠hunt disagreement intact. An optional post-report grader
(`grade: true`) can only demote, never promote.

## Verification machinery

What separates codesec from "prompt an LLM to review my code":

- **Adversarial validation panel.** `validate.rounds` independent adversarial
  reviews per finding — later rounds see the earlier verdicts' cruxes and are
  told to attack the angles the panel hasn't covered — then an arbiter rules
  on the evidence. The panel only sees falsifiable fields, never the finder's
  own confidence. With `rounds > 1` the stored `validator_confidence` is the
  fraction of panel+arbiter votes agreeing with the final call — an ensemble
  signal, not a self-report.
- **Executable reachability.** Trace must prove the path from an
  attacker-controlled input to the sink. If you point codesec at a **live
  deployment**, Hunt *reproduces* findings against the real service, Validate
  *rejects* findings that don't reproduce, and Trace confirms reachability
  with real HTTP round-trips.
- **Canary markers.** With a live target, each finding gets a deterministic
  per-finding canary; "reachable" requires the canary to actually come back
  in a response — an oracle, not a vibe.
- **Host-pinned probing.** The live-probe tool (`live_probe_mcp.py`) is
  pinned to the exact scheme/host/port of the declared target. Redirects are
  never followed; other hosts are refused; bodies are capped. Agents literally
  cannot use it to hit anything else.
- **Per-CWE bypass hints.** Known filter-evasion hints per CWE
  (`config/bypass_hints.yaml`) are injected into Hunt tasks and later
  validation rounds.
- **Negative knowledge.** Gapfill won't re-queue (class, file) pairs that
  were already tried and refuted; bounded loop counts stop runaway cycles.

## Finding identity & cross-run memory

- **Content fingerprints.** A finding's identity is the code window it
  cites, not its line numbers — tolerant of drift, and "same bug, moved"
  between runs is recognized.
- **Deterministic dedupe.** Findings on the same file + class are clustered
  by code, not prose; the canonical member is picked by evidence story
  (successful PoC first), not by which agent ran first.
- **Cross-run catalogue.** One repo-scoped DB per repo (default
  `<repo>/.codesec-catalogue.db`). Root causes already confirmed in earlier
  runs skip straight to reporting; refuted ones become exclusion lists so
  Hunt stops re-finding them. `--prior auto|off|path` controls it.
- **Upstream novelty.** `--upstream <git-url-or-path>` annotates each
  confirmed finding with whether it exists in the upstream version — useful
  when auditing a fork that carries private patches.

## Model backends

One `--provider` flag picks the backend; every stage's model is re-mapped by
role while preserving the deliberate-disagreement split.

| `--provider` | Base URL | Models | Billing |
|---|---|---|---|
| `anthropic` (default) | anthropic.com / gateway env | Claude family | Claude subscription / metered |
| `zai` | `https://api.z.ai/api/anthropic` | GLM-5.2 / GLM-4.7 | Z.AI GLM Coding Plan |
| `unsloth` | `http://localhost:8888` (configurable) | any loaded GGUF | your own hardware |

- **Anthropic (default)**: subscription OAuth (interactive or headless for
  CI), metered API key (opt-in via `--allow-api-key`), or any
  Anthropic-compatible gateway via env vars. Run `codesec auth-check` to
  verify.
- **Z.AI GLM Coding Plan**: opus-role stages → `glm-5.2`, sonnet-role stages
  → `glm-4.7`, so Validate still disagrees with Hunt.
- **Unsloth Studio**: any loaded GGUF through the Anthropic-compatible local
  endpoint. One model at a time collapses disagreement to a single model —
  accept lower recall on adversarial validation, or use the local engine
  below.

### Local models — direct engine (`--engine local`)

For local models the Claude Code Agent SDK is the wrong tool: it spawns a
subprocess per turn and prepends a per-request attribution header that
thrashes llama-server's KV cache (~90% slowdown per Unsloth's docs), and it
advertises the full Claude Code toolset, which trips llama-server's
tool-grammar compiler on hybrid/SSM models.

`--engine local` drops all of that. codesec talks **directly** to any
OpenAI-compatible `/v1/chat/completions` endpoint (llama-server, Unsloth,
vLLM, Ollama compat layer, hosted APIs) with a hand-rolled
Read/Grep/Glob/Bash loop:

- no `claude` subprocess, no login, no proxy,
- append-only message history → **prefix KV cache hits on turn 2+**
  (verified: 22-27 tok/s decode, 84-97% prompt cache reuse — ~3× the
  SDK path),
- only 4 tools advertised → grammar compiles cleanly on hybrid/SSM models,
- full control over sampling / max_tokens / thinking.

```bash
# 1. serve the model (raw llama.cpp = fastest; Unsloth works too)
llama-server -m /path/to/model.gguf --port 8080 --alias my-model &

# 2. codesec, direct
codesec run --repo /path/to/target --engine local \
  --base-url http://localhost:8080 --model my-model \
  --max-concurrency 1 --max-recon-tasks 15
```

Hosted OpenAI-compatible APIs work the same way, e.g. Hetzner
(`https://inference.hetzner.com`, key via `HETZNER_API_KEY` or
`CODESEC_API_KEY`):

```bash
codesec run --repo /path/to/target --engine local \
  --base-url https://inference.hetzner.com/api/v1 \
  --model Qwen3.8-27B --max-concurrency 4
```

If you keep `--engine sdk` with a local llama-server backend,
`codesec unsloth-proxy` strips the advertised toolset down to the four
tools the stages use, so hybrid/SSM models (e.g. Qwopus3.6) pass the
grammar compiler.

### duo-v1 — fully local two-model pipeline

`duo-v1` pairs a recall-first discovery model (Titus) with a
validation/tracing model (OpenMythos): it batches all Titus work before
OpenMythos, uses conservative deterministic exact dedupe, and assembles the
final report and review queue in code. Every run's database, results,
scratch files, logs, and runtime manifest live under one isolated run root.

```bash
export CODESEC_TITUS_GGUF=/models/Titus-CybersecurityLLM-v1.0.Q4_K_M.gguf
export CODESEC_OPENMYTHOS_GGUF=/models/OpenMythos-27B-Q6_K.gguf
export CODESEC_LLAMA_SERVER=/path/to/llama-server

codesec run --repo /path/to/target \
  --pipeline duo-v1 --runtime managed \
  --run-id duo-001 --run-root ./runs/duo-001
```

The managed runtime requests full GPU offload, verifies VRAM allocation via
`nvidia-smi`, records both model hashes and exact server commands, then
stops Titus before loading OpenMythos (one GPU). For two GPUs or
operator-managed servers, expose the aliases and endpoints in
`config/duo-v1.yaml` and use `--runtime external`.

## Quickstart

```bash
# 1. Install
python -m venv .venv && source .venv/bin/activate
pip install -e .

# 2. Pick a provider and verify auth
codesec providers                       # list presets
codesec auth-check                      # default: Claude subscription / API / gateway
codesec auth-check --provider zai       # Z.AI GLM Coding Plan
codesec auth-check --provider unsloth   # local Unsloth Studio

# 3. Run
codesec run --repo /path/to/target --run-id my-run
codesec status --run-id my-run
codesec report --run-id my-run --format md > report.md
```

## Cost containment

A real production codebase can produce 15–50 Hunt tasks and 25+ findings to
validate. Flags to keep it sane:

```bash
codesec run --repo /path/to/target \
  --max-concurrency 1 \           # one agent subprocess at a time
  --max-recon-tasks 15 \          # cap initial Hunt fanout
  --max-cost-usd 30 \             # abort cleanly if exceeded (Anthropic only)
  --max-hours 6                   # wall-clock budget
```

The budget guard fires between *and* within stages — a per-task check in
Hunt cooperatively aborts rather than running 30 more tasks past the cap.
Once ~80% of the time budget has elapsed, the orchestrator stops opening
new breadth (gapfill, feedback, second hunt waves) and spends what remains
validating and reporting what already exists.

## Live-target reproduction (optional)

If the target has a running deployment, point the agents at it (see
*Verification machinery* above):

```bash
codesec run --repo /path/to/target --run-id live \
  --max-concurrency 1 \
  --target-url http://server.local:8888 \
  --target-creds email=admin@system.com --target-creds password=changechangeme
```

## Scope notes (optional)

Drop intentionally-loose-by-design surfaces (plaintext API keys that are a
feature, test-only endpoints, etc.) in a text file:

```bash
codesec run --repo /path/to/target --scope-notes target_scope.md
```

## Benchmark

`bench/` measures both models and the harness itself:

- **Snippet probe** (`bench/probe/`): 44 CWE-tagged Python cases with a
  difficulty gradient and genuinely-safe decoys — a development/diagnostic
  set for model selection.
- **Repo corpus** (`bench/corpus/`): `devshop`, a realistic Flask app with
  planted T1–T3 bugs plus safe decoys, a ground-truth manifest
  (`bench/corpus/manifests/devshop.json`), and a live `serve.sh` so runs can
  exercise the full live-target path.
- **Per-stage scoring**: `python -m bench.score_repo <run-root> <manifest>
  --stages` scores discovery, validation, dedup, tracing, and final
  reporting against the manifest.

The corrected evaluation protocol is documented in
[`bench/METHODOLOGY.md`](bench/METHODOLOGY.md); historical results live in
`bench/REPORT.md` (superseded) and `bench/RESULTS-2026-07-24.md`.

This path is currently benchmark/experimental hardening, not a fully
sandboxed production scanner (see Safety).

## Layout

```
prompts/        8 stage prompts (markdown, loaded as system prompts)
schemas/        9 JSON schemas — every agent output is validated
config/         stages.yaml (per-stage model role + concurrency + tools),
                bypass_hints.yaml, provider/duo/hetzner presets
codesec/        Python package
  cli.py        Click CLI — run / status / report / providers / auth-check / unsloth-proxy
  providers.py  provider presets (--provider)
  auth.py       OAuth/gateway/API-key check (provider-aware)
  config.py     per-stage config + provider model-mapping
  runner.py     claude-agent-sdk wrapper with schema validation + repair turn
  local_agent.py direct OpenAI-compatible client for local LLMs (--engine local)
  orchestrator.py pipeline driver
  contracts.py  semantic stage postconditions JSON Schema can't express
  fingerprint.py content fingerprints for findings
  catalogue.py  cross-run repo-scoped finding catalogue
  hints.py      per-CWE bypass hints
  markers.py    deterministic canary markers for live-target verification
  live_probe_mcp.py host-pinned HTTP probe (MCP for the SDK engine)
  upstream.py   upstream novelty check (--upstream)
  run_paths.py  isolated run-root layout (--run-root / duo-v1)
  runtime.py    managed/external llama.cpp lifecycle (--runtime / duo-v1)
  unsloth_proxy.py tool-stripping sidecar for local llama-server backends
  json_utils.py robust JSON extraction + schema validation
  state.py      SQLite DAO (runs, tasks, findings, traces, dedupe, costs)
  stages/       one module per stage
work/           per-Hunt-task scratch dirs (sandbox for PoC compile/run)
results/        JSONL artifacts per stage + final report.json (legacy pipeline)
runs/           isolated run roots for duo-v1 (--run-root; one state.db per run)
state.db        legacy shared SQLite (gitignored)
```

## Safety

Hunt agents have Bash and run inside per-task scratch dirs. They are **not**
sandboxed at the OS level. Run the audit inside a disposable VM or container
when you don't trust the target source — a target with malicious build
scripts could otherwise execute on your host during PoC compilation.

The agent reads everything you point it at, including any `.env` or
`secrets/` directories in the target. Outputs land in `results/<run-id>/`
which is `.gitignore`d but **not** scrubbed of those reads.

## Origin & credits

- **Pipeline design**: Cloudflare's
  [Project Glasswing](https://blog.cloudflare.com/cyber-frontier-models/) —
  many narrow agents, deliberate disagreement, reachability gating.
- **Original implementation**: codesec is a fork of
  [evilsocket/audit](https://github.com/evilsocket/audit) 

## License
[MIT](LICENSE). Reuse freely. No warranty.
