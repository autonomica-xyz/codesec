# Titus + OpenMythos Optimization Implementation Plan

- **Status:** Lean benchmark milestone implemented; later production phases deferred
- **Date:** 2026-07-27
- **Audience:** CodeSec maintainers and contributors
- **Post-read action:** Implement, evaluate, and safely roll out a two-model
  local pipeline in which Titus performs recall-first discovery and
  OpenMythos performs independent validation and reachability analysis.

## 1. Executive decision

### Implementation checkpoint (2026-07-28)

The first benchmarkable slice is implemented:

- run-scoped schema-v2 state with migration and collision detection;
- semantic Hunt, validation, dedupe, trace, and completion contracts;
- valid-JSON context bounds, corrected local tool roots, retries, and
  normalized usage;
- immutable per-stage Titus/OpenMythos profiles;
- `duo-v1` phase batching with managed single-GPU and external runtimes;
- isolated run roots and resume-manifest checks;
- bounded Titus waves, recall-first Hunt instructions, adversarial
  OpenMythos validation, and explicit trace uncertainty;
- conservative deterministic exact dedupe, final report, and review queue;
- stage-level DevShop truth and scoring plus a reproducible one-GPU launcher.

The deterministic repository inventory/task compiler, rule catalog,
coverage-ledger replacement for Gapfill, host-assigned IDs, general static
analysis, production Bash sandbox, holdout expansion, and measured tuning
sweeps remain deliberately deferred. Those items should be promoted only when
the corrected repository baseline shows that their expected recall, latency,
or safety gain justifies their complexity.

Build a new `duo-v1` pipeline around these roles:

| Responsibility | Implementation |
|---|---|
| Repository inventory and initial task generation | Deterministic code |
| Vulnerability discovery | Titus-Cybersecurity-35B |
| Coverage analysis and second-wave task generation | Deterministic code |
| Adversarial finding validation | OpenMythos-27B |
| Root-cause deduplication | Deterministic code |
| Reachability tracing | OpenMythos-27B |
| Final report and review queue | Deterministic code |

The recommended single-A6000 schedule is:

```text
CPU inventory
  → load Titus
  → Hunt wave 1
  → CPU coverage analysis
  → Hunt wave 2
  → unload Titus
  → load OpenMythos
  → validate all candidates
  → CPU exact-duplicate compaction
  → trace every remaining confirmed unit
  → CPU root-cause dedupe and report
```

This schedule deliberately groups work by model. It needs one model transition
in the default path, compared with repeated transitions if the existing
Hunt → Validate → Gapfill loop is retained unchanged.

The existing eight-stage pipeline remains available as `legacy` until the new
path passes the release gates in this document. Do not silently change the
legacy provider behavior while building the local-model path.

## 2. Why this pair

The [corrected 44-case development probe](../bench/RESULTS-2026-07-24.md)
provides the current selection evidence:

| Model/system | MCC | Recall | Precision | Specificity | CWE exact | Decidable |
|---|---:|---:|---:|---:|---:|---:|
| Titus 35B Q4_K_M | 0.752 | 97.5% | 90.2% | 71.7% | 72.4% | 220/220 |
| OpenMythos 27B Q6_K | 0.709 | 90.6% | 92.9% | 81.7% | 82.8% | 220/220 |
| Titus ∩ OpenMythos, exploratory | 0.787 | 90.6% | 96.7% | 91.7% | — | 220/220 |

Titus has the best observed recall and is therefore the stronger discovery
candidate. OpenMythos is more precise, more specific, has better CWE
exactness, and produced exact JSON on every probe response. Those properties
fit an adversarial validator and tracer.

The exploratory intersection is evidence for a high-confidence tier, not for
discarding every Titus-only result. The product must retain three outcomes:

- **Confirmed:** Titus found it, OpenMythos confirmed it, and the trace is
  reachable.
- **Review:** validation or reachability is inconclusive, or required
  preconditions cannot be established automatically.
- **Rejected:** OpenMythos supplied a concrete falsification, or the trace
  established that the code is unreachable under the declared threat model.

Titus self-reported confidence must remain diagnostic only. Thresholding it
reduced MCC in the development probe and is not an acceptable product gate.

### What the evidence does not establish

- The top local models were not statistically separable on only 44 cases.
- The probe is a development set that has already influenced model selection.
- The probe is Python-only and does not test repository navigation, tool use,
  deduplication, or tracing.
- There is no valid completed end-to-end Titus or OpenMythos repository run
  yet.
- The ensemble point estimate was discovered on the same development set and
  requires a frozen holdout.

The implementation must therefore treat Titus + OpenMythos as the leading
hypothesis to test, not as a finished model-selection result.

## 3. Goals and non-goals

### Goals

1. Preserve Titus's recall while using OpenMythos to raise final precision and
   specificity.
2. Spend model tokens only on security reasoning that deterministic code
   cannot reliably perform.
3. Make every run isolated, resumable, complete, and auditable.
4. Eliminate invalid JSON truncation and silent cross-stage omissions.
5. Support stage-specific endpoints, models, generation settings, and tool
   policies.
6. Run efficiently on one RTX A6000 through phase batching and sequential model
   loading.
7. Support two always-on endpoints without changing pipeline semantics when
   two GPUs are available.
8. Produce a high-confidence final report plus a separate review queue, with
   no invented, lost, or duplicated findings.
9. Establish a repeatable evaluation protocol that separates discovery,
   validation, reachability, reporting, and operational quality.

### Non-goals for `duo-v1`

- Training or fine-tuning either model.
- Treating the current 44-case probe as a final leaderboard.
- Loading both current quantizations on one A6000 by default.
- Replacing the hosted SDK pipeline for Anthropic or Z.AI users.
- Building a general static-analysis engine before validating the Python-first
  task compiler.
- Automatically suppressing a candidate solely because one model reports low
  confidence.
- Allowing an LLM to rewrite authoritative IDs, counts, file locations, or
  report membership.

## 4. Release-level success criteria

The new pipeline is ready to become the recommended local path only when all
release blockers pass.

### Integrity blockers

- A repeated task or finding ID in another run cannot hide, overwrite, or
  reassign work.
- Every stage proves exact coverage of its input IDs before committing output.
- No prompt is produced by slicing serialized JSON.
- Every model-reported file resolves inside the scan root and every source
  range exists.
- Every reachable trace has a non-empty entry point, external input, and
  ordered call chain ending at the reported sink.
- The final report contains exactly the reachable canonical finding set.
- Summary counts exactly equal report contents.
- A benchmark target has the same content hash before and after a run.
- A failed retry cannot overwrite an earlier attempt transcript.
- Three consecutive end-to-end repetitions complete without unexplained
  missing tasks, findings, validations, traces, or reports.

### Quality gates

Quality gates are evaluated on frozen data that was not used to tune prompts
or parameters:

- Titus candidate recall is no more than 2 percentage points below its clean
  single-model baseline, with paired uncertainty reported.
- The confirmed-and-reachable tier has at least 95% finding precision, or
  improves materially over both clean single-model baselines if the holdout is
  too small to resolve 95%.
- The pair does not lose more than 5 percentage points of final recall versus
  the better clean single-model final-report baseline.
- Decoy specificity improves over Titus-only operation.
- Reachability decisions are scored separately and do not receive credit from
  merely locating the vulnerable sink.
- All point estimates are accompanied by coverage and uncertainty; unresolved
  differences are reported as unresolved.

### Efficiency targets

These are optimization targets, not excuses to waive an integrity or quality
gate:

- Zero LLM calls for inventory, coverage calculation, dedupe, feedback task
  expansion, and report assembly in the default path.
- At most two model loads in a default one-GPU run.
- At least 40% fewer cumulative prompt tokens than the legacy eight-stage local
  pipeline on the same repository.
- At least 30% lower median wall time than a corrected legacy two-model
  equivalent, excluding initial model download.
- No out-of-memory event at the documented A6000 settings.
- At least 80% prefix-cache reuse after the first turn of a multi-turn task,
  when the server exposes cache telemetry.

## 5. Target architecture

### 5.1 Pipeline shape

```text
Repository
   │
   ▼
Deterministic inventory ──► deterministic Hunt task queue
   │
   ▼
Titus Hunt wave 1 ──► candidate ledger
   │
   ▼
Deterministic coverage matrix ──► Titus Hunt wave 2
   │
   ▼
OpenMythos adversarial validation
   │
   ├── rejected ───────────────► rejection ledger
   ├── needs more information ─► review queue
   ▼
confirmed
   │
   ▼
Deterministic exact-duplicate compaction
   │
   ▼
OpenMythos reachability trace
   │
   ├── unreachable ────────────► rejection ledger
   ├── uncertain ──────────────► review queue
   ▼
reachable
   │
   ▼
Deterministic root-cause grouping and final report
```

### 5.2 New model-profile abstraction

The current local engine uses process-global engine, base URL, API key, and a
single model forced across every stage. Replace that with immutable model
profiles resolved per agent request.

A model profile should contain:

- stable profile name;
- engine type;
- endpoint or managed-runtime reference;
- served model alias;
- expected model/GGUF identity and checksum;
- context limit;
- temperature;
- maximum output tokens;
- thinking mode;
- seed policy;
- request timeout;
- transient retry policy;
- tool protocol;
- JSON-constrained-output capability;
- default concurrency;
- optional GPU/runtime metadata expectations.

Stage configuration should reference a profile instead of duplicating endpoint
details. Secrets are resolved from environment-variable names and are never
stored in configuration or artifacts.

Proposed configuration shape:

```yaml
model_profiles:
  titus_hunt:
    engine: local_openai
    endpoint: http://127.0.0.1:8080
    model: titus-cybersecurity-35b
    temperature: 0
    thinking: false
    max_output_tokens: 4096

  openmythos_review:
    engine: local_openai
    endpoint: http://127.0.0.1:8081
    model: openmythos-27b
    temperature: 0
    thinking: false
    max_output_tokens: 3072

pipelines:
  duo-v1:
    hunt_profile: titus_hunt
    validate_profile: openmythos_review
    trace_profile: openmythos_review
```

The concrete defaults above are starting baselines. The tuning phase can
change them only through measured experiments.

### 5.3 Backend and runtime separation

Separate two concerns:

- **Agent backend:** sends messages, tools, and generation parameters to a
  ready endpoint.
- **Model runtime:** makes the correct model available at that endpoint.

Define an `AgentBackend` interface with one request/result contract for SDK and
local OpenAI-compatible engines. Define a `ModelRuntime` interface with
`ensure_ready(profile)` and `release(profile)` lifecycle operations.

Initial runtime implementations:

1. **External runtime:** health-checks an already running endpoint. This is the
   path for two GPUs, remote servers, or operator-managed Unsloth.
2. **Managed llama.cpp runtime:** starts a pinned server using an argument
   array, waits for the expected served model, verifies GPU allocation, owns
   only its process group, and shuts that process down at phase boundaries.

Do not launch managed servers through `shell=True`. Persist the exact binary,
arguments, model checksum, server build, GPU, and measured VRAM in the run
manifest.

### 5.4 Authoritative data ownership

Models may propose security judgments, but deterministic code owns:

- run, task, finding, group, and trace IDs;
- input-to-output membership;
- repository-relative file normalization;
- source line validation;
- coverage accounting;
- dedupe membership;
- canonical selection tie-breakers;
- report membership and counts;
- confidence-tier assignment;
- runtime metadata and usage totals.

This boundary removes work that small models perform unreliably and makes
omissions detectable.

### 5.5 Current-component implementation map

| Current component | Planned responsibility |
|---|---|
| `codesec.config` | Parse model profiles, pipeline definitions, generation settings, and runtime policy |
| `codesec.runner` | Retain the public run-one-agent contract and route legacy SDK requests through a compatibility adapter |
| `codesec.local_agent` | Split into the local backend, response adapter, context packer, and tool workspace; remove process-global routing |
| `codesec.state.StateDB` | Own schema migration, run-scoped identity, checkpoints, coverage ledgers, transactions, and normalized usage |
| `codesec.orchestrator` | Dispatch either the unchanged legacy flow or the phase-batched `duo-v1` flow |
| `codesec.stages` | Keep legacy stage entry points while sharing semantic validators and authoritative state models with `duo-v1` |
| Hunt, validation, and trace prompts/schemas | Carry only model judgments that deterministic code cannot own |
| Benchmark package | Enforce isolated trials, runtime manifests, stage-level scoring, final-report scoring, and paired comparisons |

## 6. Delivery phases

Phases are ordered by dependency. Do not run expensive Titus/OpenMythos
repository trials until Phase 1 is complete; otherwise harness defects can be
mistaken for model behavior.

### Phase 0 — Freeze the baseline and characterize failures

**Objective:** Preserve reproducible evidence before changing execution
semantics.

#### P0.1 Record the selection decision

- Mark Titus Q4_K_M as the recall-first discovery baseline.
- Mark OpenMythos Q6_K as the independent review baseline.
- Keep Gemma-4-12B as the efficiency control.
- Record exact model repositories, revisions, filenames, checksums, chat
  templates, and llama.cpp build.
- Record that the current ensemble result is exploratory and holdout-gated.

#### P0.2 Preserve clean benchmark inputs

- Freeze the corrected probe dataset hash and current result artifacts.
- Mark the historical report as superseded in every benchmark entry point.
- Give every repository trial a unique state database, results root, work root,
  and read-only scan copy.
- Add an immutable run manifest before inference begins.

#### P0.3 Add characterization tests

Write failing tests that reproduce:

- cross-run task ID collision;
- cross-run finding and group ID collision;
- invalid JSON caused by the current character slice;
- dedupe accepting a partial input partition;
- report accepting an incomplete ready-finding set;
- local usage fields being persisted as null;
- an HTTP 500 bypassing transient retry;
- a malformed tool argument becoming an empty argument object;
- Hunt tools failing to read the repository from a scratch working directory;
- `grep` count mode returning no counts;
- retry transcript overwrite.

**Exit criteria:** Every known harness defect has a deterministic regression
test or a written reason why it requires an integration test in a later phase.

### Phase 1 — Make execution and measurement trustworthy

**Objective:** Remove silent data loss, invalid inputs, and unverifiable stage
outputs.

#### P1.1 Introduce schema-versioned, run-scoped state

Change state keys to:

- tasks: `(run_id, task_id)`;
- findings: `(run_id, finding_id)`;
- traces: `(run_id, finding_id)`;
- dedupe groups: `(run_id, group_id)`.

All foreign keys include `run_id`. Enable SQLite foreign-key enforcement.
Update every mutating and lookup method to require a run ID. Remove direct
access to the database connection from orchestration and stage code.

Replace silent `INSERT OR IGNORE` behavior:

- an exact same-run replay may be explicitly idempotent;
- a differing same-run payload raises `StateConflictError`;
- an identical local ID in another run is valid because the composite key
  differs.

Add a schema version table and an atomic migration:

1. back up the existing database;
2. create versioned replacement tables;
3. copy rows;
4. validate row counts and foreign keys;
5. swap tables in one transaction;
6. report legacy runs affected by historical ignored collisions.

Rows that were never inserted because of old collisions cannot be recovered.
The migration must warn rather than imply those runs are complete.

Add explicit DAO operations for run status, artifact counts, group members,
stage checkpoints, and transactions.

#### P1.2 Add run-root isolation

Introduce a `RunPaths` value object that owns:

- database;
- results;
- work/scratch;
- run manifest;
- logs;
- target snapshot metadata.

Add a CLI option for an explicit run root. Repository benchmarks always create
a new isolated root and refuse reuse unless resuming the exact same run
manifest.

#### P1.3 Replace blind input truncation with context packing

Create a `ContextPack` builder that:

- always serializes valid JSON;
- measures tokens with the server tokenizer when available;
- otherwise uses a conservative model-specific estimate;
- records the full authoritative input hash;
- selects whole fields or whole list members, never raw character prefixes;
- emits pagination/chunk metadata;
- fails before inference if required fields cannot fit.

Use tools and narrow task scopes instead of embedding repository contents.
Large fan-in lists must be chunked with an exact coverage ledger. The new
deterministic dedupe and report stages remove the two largest fan-in prompts
entirely.

Artifact logging stores a redacted structured input plus its full hash, byte
count, token estimate, and included IDs. It must not leak target credentials.

#### P1.4 Add semantic postcondition validators

JSON Schema remains the shape gate. Add a second, code-level semantic gate
before state mutation.

Hunt validation:

- output task ID equals the requested task;
- every finding receives a host-assigned stable ID;
- all files are normalized, repository-relative, and exist;
- line ranges are ordered and within the file;
- evidence is non-empty and can be located near the claimed source range;
- duplicate candidate fingerprints are reported, not silently inserted;
- every tool-created artifact stays in scratch.

Adversarial-validation checks:

- output finding ID equals the requested finding;
- verdict is exactly one of the supported states;
- a rejection identifies the guard, safe API, dead path, or unmet
  precondition that falsifies the claim;
- `needs_more_info` states what evidence is missing and proposes a test;
- a confirmation cannot change the authoritative file, range, or class.

Dedupe checks, while legacy LLM dedupe remains available:

- group IDs are unique;
- every input finding appears exactly once;
- no unknown finding appears;
- the canonical is a member;
- no finding is canonical in two groups.

Trace checks:

- output finding ID equals the request;
- reachable traces have at least one entry point, external input, and two-frame
  call chain;
- call-chain files and lines exist;
- the final frame agrees with the authoritative sink;
- unreachable traces have at least one concrete blocker;
- uncertainty is represented as review, not coerced to unreachable.

Report checks, while legacy LLM reporting remains available:

- run ID and target equal authoritative state;
- finding IDs exactly equal the reachable canonical set;
- immutable fields equal state;
- summary counts equal report contents and severity buckets.

Semantic failures get one targeted repair only when a model can correct them.
The harness never guesses a missing ID or fabricates evidence.

#### P1.5 Correct the local tool workspace

Replace the single working-directory assumption with a `ToolWorkspace`:

- repository root: readable, immutable;
- scratch root: readable and writable;
- process working directory: scratch;
- path resolver: rejects traversal and paths outside both roots;
- tool output: structured result with truncation and pagination metadata.

Tool changes:

- `Read` returns line-numbered output and conservative page sizes;
- `Read` exposes continuation offsets instead of returning 200,000 characters;
- `Grep` implements content, file, and count modes;
- `Grep` caps matches and bytes and reports omitted counts;
- `Glob` respects repository ignore rules and skips binary/generated trees by
  default;
- absolute repository paths and repo-relative paths resolve consistently;
- invalid JSON tool arguments return a structured argument error;
- Bash runs in scratch with the repository path passed explicitly;
- tool errors are visible to the model and telemetry.

For benchmarks, mount or copy the target read-only. For production hardening,
run Bash in an OS sandbox with scratch as the only writable mount and network
denied unless a live-target allowlist is explicitly configured.

#### P1.6 Normalize retries, artifacts, and usage

- Classify HTTP 429 and retryable 5xx responses as transient.
- Treat authentication, unsupported request shapes, and deterministic 4xx
  failures as terminal.
- Give every attempt a unique artifact record and append to one attempt-aware
  transcript.
- Preserve the last successful tool state only within its attempt.
- Persist `AgentResult` fields directly instead of asking the database to
  reinterpret backend-specific raw usage.
- Record input, output, cached, and total prompt tokens consistently.
- Record first-token latency, request duration, turns, repairs,
  continuations, tool calls, and finish reason.

**Phase 1 exit criteria:**

- All P0 characterization tests pass.
- A two-run collision integration test preserves both complete runs.
- Deliberately incomplete dedupe, trace, and report payloads are rejected.
- A 100,000-character structured input is either validly packed or rejected
  before inference; it is never sliced into invalid JSON.
- Benchmark target hashes remain unchanged.

### Phase 2 — Add stage-specific routing and model lifecycle

**Objective:** Allow Titus and OpenMythos to serve different stages without
global mutable engine state.

#### P2.1 Define backend-neutral request and result types

Create:

- `AgentRequest`;
- `AgentResult`;
- `GenerationConfig`;
- `ToolPolicy`;
- `ModelProfile`;
- `AgentBackend`;
- `ModelRuntime`.

`AgentRequest` carries the profile and stage explicitly. Remove process-global
engine, endpoint, and key variables after a compatibility adapter is in place.

#### P2.2 Implement local OpenAI-compatible backend

Move HTTP transport and the tool loop behind `LocalOpenAIBackend`. It must:

- send every profile setting explicitly;
- preserve an append-only prefix for KV reuse;
- keep the tool schema byte-stable across turns;
- use `tool_choice: none` for final repair/continuation turns without removing
  tools from the prefix;
- parse normal content, supported reasoning fields, and native tool calls;
- inspect finish reasons;
- continue truncated bare JSON, fenced JSON, and bounded think-envelope JSON;
- allow continuation after a repair response;
- stop with an explicit exhausted-output status rather than validating a
  partial object.

#### P2.3 Implement constrained final output

Test each selected model/server combination in this order:

1. native JSON Schema response format;
2. grammar-constrained JSON;
3. prompt-only JSON plus semantic repair.

Use constrained output only for final and repair turns. Tool-bearing reasoning
turns keep the model's native tool grammar. Store the chosen capability in the
model profile so unsupported request fields are never sent speculatively.

Titus's bounded `<think></think>` envelope is accepted by a model-specific
response adapter, while the underlying JSON must still pass the same shared
contract. OpenMythos should remain on exact bare JSON if live conformance tests
confirm the probe behavior.

#### P2.4 Implement phase-aware runtime scheduling

The orchestrator declares the required profile at each phase boundary.
`ModelRuntime` ensures it is available before tasks dispatch.

Single-GPU invariant:

- all pending Titus tasks finish before Titus is released;
- OpenMythos is loaded once for validation and tracing;
- the default pipeline does not switch back to Titus.

Two-GPU invariant:

- both external endpoints may remain ready;
- task semantics and artifacts are identical to single-GPU operation.

#### P2.5 Add proposed CLI surface

Support an explicit pipeline and model configuration, for example:

```text
codesec run \
  --pipeline duo-v1 \
  --model-config <config> \
  --runtime managed-llama-cpp \
  --run-root <new-run-root> \
  --repo <target>
```

Keep the current `--engine`, `--base-url`, and `--model` flags as a deprecated
legacy shorthand during migration.

**Phase 2 exit criteria:**

- A fake-server integration test proves Hunt requests use the Titus profile
  and Validate/Trace requests use the OpenMythos profile.
- A managed-runtime test proves the expected load/release order.
- No request obtains endpoint or model identity from mutable process globals.
- Legacy SDK/provider tests still pass.

### Phase 3 — Replace low-value LLM stages with deterministic code

**Objective:** Reduce prompt volume, output failures, model switches, and
non-security reasoning.

#### P3.1 Repository inventory

Build a deterministic inventory that records:

- language and framework evidence;
- source files after ignore filtering;
- dependency and lock files;
- build and test commands from trusted metadata;
- candidate entry points;
- external-input sources;
- security-sensitive sinks;
- authentication and authorization boundaries;
- generated/vendor/test classification;
- file and symbol hashes used by later stages.

Start with a high-quality Python adapter because the existing probe and
repository corpus are Python. Define a language-adapter interface before
adding JavaScript/TypeScript, Go, Rust, Java, or other ecosystems.

Inventory output is deterministic, versioned, and cached by repository commit
and configuration hash. Unknown frameworks remain visible as unsupported
coverage rather than being silently treated as covered.

#### P3.2 Security rule catalog and task compiler

Create a versioned rule catalog mapping source/sink evidence to attack classes.
Examples include:

- HTTP input → SQL execution;
- user input → shell or process execution;
- URL input → outbound network call;
- untrusted bytes → deserializer;
- user-controlled template → template rendering;
- identifier input → object access without an ownership check;
- path input → filesystem access;
- token input → authentication/algorithm decisions;
- shared mutable state → race-sensitive update.

The task compiler emits narrow tasks with:

- host-generated stable task ID;
- one attack class;
- a bounded set of files and symbols;
- source and sink hints;
- explicit trust boundary;
- priority derived from evidence strength and reachability;
- rule-catalog version;
- reason the task exists.

Avoid the full subsystem × attack-class Cartesian product. Emit a task only
when inventory evidence makes the pair plausible, plus a small configured set
of framework-level control tasks.

#### P3.3 Deterministic coverage and gap wave

Persist every Hunt task's:

- inspected files/symbols;
- tool-read ranges;
- sources and sinks considered;
- findings;
- explicit gaps;
- completion/failure reason.

Build a coverage matrix over relevant rule evidence, not finding counts.
Generate wave-two tasks for:

- plausible source/sink pairs with no completed task;
- failed or truncated tasks;
- model-reported gaps with valid repository locations;
- high-risk entry points that were only partially read;
- variants of strong candidate fingerprints in other call sites.

Cap tasks per rule and subsystem. Stop after wave two by default. A third wave
requires evidence that its incremental recall justifies cost.

#### P3.4 Deterministic conservative dedupe

Extend candidate and validation contracts with:

- normalized vulnerability class and CWE;
- sink location and symbol;
- root-cause location and symbol when distinct;
- source location;
- data-flow fingerprint;
- explicit preconditions.

Use two passes so grouping cannot hide a reachable variant:

1. Before Trace, compact only exact duplicates with the same normalized class,
   root-cause fingerprint, sink, and evidence range. Preserve every original
   finding ID as a member of the trace unit.
2. Trace every remaining confirmed unit. A unit containing exact duplicates
   supplies every recorded entry-point/source variant to the tracer.
3. After Trace, group conservative near-duplicates only when they share the
   same root-cause symbol and equivalent validated data flow.

When uncertain, keep findings separate. False merges lose security
information; extra variants only cost report space. Final canonical selection
happens after tracing and is deterministic:

1. confirmed and reachable evidence;
2. successful reproducible PoC;
3. clearer source-to-sink trace;
4. higher severity;
5. stable finding-ID tie-break.

#### P3.5 Deterministic feedback

Replace prose feedback generation with rule-based variant expansion from a
validated root-cause fingerprint. Search for sibling sinks, call sites, and
equivalent source flows.

The default single-GPU pipeline performs candidate-based variant expansion
during the Titus phase so it does not require another model swap. An optional
post-validation feedback round may switch back to Titus only if experiments
show a material recall gain after accounting for the two extra model loads.

#### P3.6 Deterministic report and review queue

Build the final report directly from authoritative state:

- include only confirmed, canonical, reachable findings;
- copy immutable source fields and trace frames;
- calculate all counts in code;
- include model/profile provenance;
- include validation rationale and preconditions;
- generate stable JSON and Markdown renderings.

Generate a separate review queue containing:

- Titus candidates marked `needs_more_info`;
- trace-uncertain candidates;
- failed agent tasks;
- unsupported inventory areas;
- rejected candidates only when configured for audit provenance.

OpenMythos may propose a recommendation during validation or tracing, but the
report renderer owns membership and structure.

**Phase 3 exit criteria:**

- Inventory, task generation, coverage, dedupe, feedback expansion, and report
  need no model endpoint.
- Identical inputs produce byte-stable task IDs, groups, and reports.
- Coverage tests prove every relevant inventory rule is completed, queued, or
  explicitly unsupported.
- Dedupe property tests prove no member is lost or duplicated.
- Report property tests prove exact equality with authoritative state.

### Phase 4 — Optimize Titus for discovery

**Objective:** Give Titus small, evidence-rich tasks and a reliable tool
protocol that maximize candidate recall per token.

#### P4.1 Rewrite the Hunt contract

The Titus Hunt prompt should:

- state one attack class and one trust boundary;
- provide target symbols and why they were selected;
- require source → transformations/guards → sink reasoning;
- require exact line-numbered evidence;
- require the model to inspect defenses before reporting;
- separate exploitability from hardening advice;
- state attacker capabilities and configuration/version preconditions;
- allow zero findings without penalty;
- return coverage and gaps in a compact fixed structure;
- forbid changing the task ID or inventing files.

Do not embed the full repository map or full JSON Schema repeatedly when the
server can enforce the response grammar.

#### P4.2 Host-assign finding IDs

Titus emits candidate bodies with a task-local ordinal. The harness derives a
stable finding ID from the run, task, normalized sink, class, and content
fingerprint. This prevents collisions and makes retries idempotent.

#### P4.3 Reduce tool and context cost

- Start with inventory-provided files and symbols.
- Return small line-numbered pages.
- Encourage Grep before broad Read.
- Include truncation metadata in every tool result.
- Stop a task when required evidence is complete.
- Give an explicit remaining-turn/output budget.
- Summarize earlier tool output only through deterministic references, not
  model-written free-form summaries.

#### P4.4 Tune in a fixed order

Use the current Q4_K_M, temperature 0, and thinking disabled as the baseline.
Change one dimension at a time:

1. prompt/contract conformance;
2. context size: 16K, 32K, then 64K only if needed;
3. maximum turns and output tokens;
4. concurrency: 1, 2, 4;
5. thinking disabled versus enabled;
6. temperature 0 versus a small exploratory value;
7. Q4_K_M versus larger quantization if it fits and improves holdout quality.

Reject a faster setting if it lowers candidate recall beyond the quality gate.
Do not select settings on self-reported confidence.

#### P4.5 Failure behavior

- A failed task remains explicitly incomplete and enters the retry/review
  ledger.
- Retry only transport, server, and clearly repairable contract failures.
- Do not repeatedly rerun a semantically valid zero-finding result.
- Resume from the task boundary, not from a partially trusted state mutation.

**Phase 4 exit criteria:**

- Titus completes the tool-use conformance suite.
- Candidate output is schema- and semantic-valid on at least 99% of first
  attempts; the remainder succeeds within one repair or is explicit failure.
- The clean Titus-only repository baseline completes three repetitions.
- Candidate recall and token/turn distributions are recorded per attack class.

### Phase 5 — Optimize OpenMythos for validation and tracing

**Objective:** Use OpenMythos as a strict independent critic, not as a
rubber-stamp or a second general scanner.

#### P5.1 Adversarial validation prompt

For each candidate, OpenMythos receives:

- the authoritative candidate;
- the original task and threat model;
- a narrow inventory slice;
- repository read tools;
- optional live-target test capability under an enforced allowlist.

It must check:

1. whether the source is attacker-controlled;
2. whether type coercion, parsing, sanitization, escaping, allowlists, or safe
   APIs break the claim;
3. whether the sink is actually invoked;
4. whether version, configuration, authentication, timing, or local-access
   preconditions are realistic;
5. whether the reported class and CWE match the root cause;
6. what concrete evidence would falsify or confirm the remaining uncertainty.

It cannot introduce a new finding. Newly noticed issues become suggestions for
the next deterministic task compiler run, never mutations of the candidate
being validated.

#### P5.2 Validation policy

- `confirmed` requires the evidence to survive an explicit falsification
  attempt.
- `rejected` requires a concrete benign explanation or blocking control.
- `needs_more_info` is preferred over guessing when runtime, version, or
  deployment facts are absent.
- Validation confidence is diagnostic and does not override the verdict
  contract.
- Candidate location, class, and evidence remain immutable; corrections are
  stored as proposed amendments for operator review.

#### P5.3 Reachability prompt

Run tracing after exact-duplicate compaction and before final root-cause
grouping. Every confirmed candidate must therefore be represented in exactly
one trace unit. The tracer must establish:

- a declared external entry point;
- attacker-controllable input;
- ordered cross-file call/data-flow frames;
- relevant guards and transformations;
- the exact reported sink;
- authentication, role, deployment, race, or filesystem preconditions;
- a concrete blocker when unreachable.

Trace output supports `reachable`, `unreachable`, and `uncertain` at the
application level even if the wire schema retains a verdict plus rationale
during migration. Agent failure is `uncertain`, never silently unreachable.

#### P5.4 Model-specific conformance

Test OpenMythos for:

- exact JSON under the production prompt size;
- native function-call behavior;
- response-format/grammar support;
- long call-chain output;
- repair behavior;
- context-limit finish reasons;
- cache reuse across multi-turn reads.

Tune validation and trace separately. Validation should be short and
deterministic; trace may need a larger context and output budget.

**Phase 5 exit criteria:**

- Every Titus candidate receives exactly one terminal validation or explicit
  failed/review state.
- Every confirmed trace unit receives exactly one trace or explicit
  failed/review state.
- Validation improves decoy rejection without violating the recall gate.
- Reachability fixtures distinguish dead vulnerable-looking code from
  externally reachable flaws.

### Phase 6 — Optimize serving on the A6000

**Objective:** Find the fastest stable settings after semantics are correct.

#### P6.1 Default to sequential loading

Measured standalone loaded VRAM is approximately:

- Titus Q4_K_M: 20,940 MiB;
- OpenMythos Q6_K: 22,326 MiB;
- naïve combined weights: 43,266 MiB;
- A6000 total: 49,140 MiB.

The remaining nominal headroom is about 5,874 MiB before large KV caches,
parallel slots, runtime buffers, and fragmentation. Therefore:

- do not make co-residency the default;
- batch by model and load sequentially;
- gate every load on measured process VRAM and full GPU offload;
- fail closed on silent CPU fallback.

#### P6.2 Benchmark runtime dimensions

For each model and stage role, measure:

- context: 16K, 32K, 64K where justified;
- parallel slots/concurrency: 1, 2, 4;
- KV cache type and size;
- prompt prefill and decode throughput;
- cache-hit percentage;
- peak and steady VRAM;
- first-token and full-request latency;
- tool turns and output tokens;
- OOM/recovery behavior;
- model load/unload time.

Use representative full stage transcripts, not the 512-token snippet probe,
for performance tuning.

#### P6.3 Quantization experiments

The current quantizations are the quality baseline. Test alternatives only
after the end-to-end pair is stable:

- Titus Q5/Q6 if sequential loading permits it;
- OpenMythos Q5 or Q4 as a speed/VRAM experiment;
- lower-KV-memory settings;
- possible co-resident lower quantizations as an explicitly separate system.

Every quantization is a new serving system and must repeat the quality gates.
Do not infer quality equivalence from parameter count or file size.

#### P6.4 Two-GPU mode

When two GPUs are available:

- pin one endpoint/profile per GPU;
- retain identical stage batching and data contracts;
- remove load latency but do not introduce cross-stage races;
- compare cost and wall time to single-GPU sequential mode.

**Phase 6 exit criteria:**

- A documented recommended A6000 profile completes three runs without OOM or
  CPU fallback.
- Concurrency selection is based on end-to-end throughput, not request
  concurrency alone.
- Exact runtime metadata is attached to every benchmark result.

### Phase 7 — Build valid evaluation and optimization loops

**Objective:** Determine whether the pair improves the product rather than
merely fitting the development probe.

#### P7.1 Repair repository ground truth

Extend each truth entry with:

- expected pipeline stage: candidate, confirmed, or final reachable;
- reachability;
- attacker capabilities;
- authentication and role requirements;
- version and configuration prerequisites;
- runtime/timing/filesystem assumptions;
- label status: accepted, ambiguous, excluded;
- executable exploit and fixed regression test where practical.

Re-adjudicate dead or condition-dependent examples, including imported but
uncalled functions, configuration-only weaknesses, race conditions, and
filesystem preconditions. Score candidate discovery separately from final
reachable reporting.

Update matching so file-and-line overlap remains mandatory but is not
sufficient for semantic credit. A match should also require a compatible
normalized class or accepted CWE alias, unless a truth entry is explicitly
marked location-only. Keep one-to-one assignment.

#### P7.2 Create a frozen external holdout

Build a positive-and-negative holdout that:

- is sourced independently of the current hand-written snippets;
- includes vulnerable and patched/safe pairs;
- includes reachable and dead-code examples;
- includes multiple repositories and eventually multiple languages;
- freezes exact source, labels, prompts, runtime settings, and hashes;
- is not inspected during prompt or parameter tuning;
- is expert-adjudicated before use.

Use the current probe as a fast development regression only.

#### P7.3 Evaluation arms

Run, at minimum:

| Arm | Hunt | Validate/Trace | Other stages |
|---|---|---|---|
| A | Titus | Titus | deterministic |
| B | OpenMythos | OpenMythos | deterministic |
| C | Titus | OpenMythos | deterministic |
| D, diagnostic | OpenMythos | Titus | deterministic |
| E, efficiency control | Gemma-4-12B | same-model or fixed reviewer | deterministic |
| F, legacy control | Existing pipeline | existing routing | LLM stages |

Arm C is the product candidate. Arms A and B isolate the value of model
disagreement. Arm D tests whether the role assignment, rather than merely
using two models, creates the benefit.

#### P7.4 Stage-level metrics

Inventory/tasking:

- supported versus unsupported repository area;
- relevant source/sink rule coverage;
- task count and duplicate rate.

Hunt:

- candidate recall and precision;
- source-range accuracy;
- attack-class/CWE accuracy;
- task success and zero-finding validity;
- first-pass contract rate;
- tokens, turns, tool errors, and duration.

Validate:

- true-finding retention;
- decoy rejection;
- false rejection;
- `needs_more_info` calibration;
- correction and unsupported-precondition rates.

Trace:

- reachable recall;
- unreachable specificity;
- uncertain rate;
- entry-point and call-chain correctness.

Final:

- finding precision;
- positive-entry recall;
- decoy specificity;
- per-tier and per-class recall;
- review-queue yield;
- exact report membership;
- wall time, tokens, cache reuse, model loads, and VRAM.

#### P7.5 Statistical discipline

- Use clustered resampling by case or repository, not by repeated request.
- Use paired comparisons on shared examples.
- Report semantic coverage beside every quality metric.
- Keep operational failures separate from guessed binary predictions.
- Publish confidence intervals and explicitly state unresolved comparisons.
- Pre-register the primary metric and release thresholds before opening the
  holdout results.

**Phase 7 exit criteria:**

- The holdout is frozen and was not used for tuning.
- All evaluation arms have complete, integrity-valid artifacts.
- The release decision is based on final-report and stage-level evidence.
- A point-estimate win without resolved or practically meaningful improvement
  is not presented as certainty.

### Phase 8 — Rollout, compatibility, and hardening

**Objective:** Introduce the optimized path without breaking existing users or
weakening safety.

#### P8.1 Compatibility

- Keep `legacy` as the default while `duo-v1` is experimental.
- Preserve report schema compatibility where possible.
- Add explicit schema versions to new state and artifacts.
- Provide read-only access to completed legacy runs.
- Make resume reject a changed pipeline, model profile, prompt, schema, target
  hash, or rule-catalog version unless the operator starts a new run.

#### P8.2 Observability

Add a run manifest and structured stage events containing:

- pipeline and schema versions;
- target commit/hash and scope settings;
- profile, served model, GGUF checksum, quantization, and server build;
- prompt, schema, task-catalog, and semantic-validator hashes;
- generation settings;
- per-attempt input membership and hashes;
- token and cache usage;
- repairs, continuations, retries, tool errors, and truncation;
- stage checkpoints and incomplete reasons;
- model load count/time and GPU/VRAM observations.

Status output should make incomplete coverage visible. A run with 14 of 27
dedupe members or 1 of 12 Hunt tasks is failed/incomplete, never “completed.”

#### P8.3 Security hardening

Before calling the path production-ready:

- enforce repository read-only and scratch writable boundaries;
- sandbox Bash at the OS level;
- deny network by default;
- enforce live-target host allowlists outside the prompt;
- pass credential references rather than plaintext credentials where possible;
- redact credentials and secrets from artifacts and console output;
- cap process time, output, filesystem, and child-process resources;
- document residual risk.

#### P8.4 Rollout stages

1. `experimental`: explicit flag, benchmark use only.
2. `preview`: user opt-in, compatibility promised, telemetry reviewed.
3. `recommended-local`: all release blockers and quality gates pass.
4. `default-local`: only after multiple real repositories show stable gains.

**Phase 8 exit criteria:** The recommended local command is documented,
reproducible, safe enough for its stated threat model, and backed by frozen
evaluation artifacts.

## 7. Test plan

### Unit tests

- state migration and composite-key behavior;
- same-run idempotent replay versus conflicting replay;
- context packing and token-budget failure;
- semantic validators for every stage;
- stable host-assigned IDs;
- repository/scratch path resolution;
- line-numbered Read pagination;
- all Grep modes and caps;
- HTTP error classification;
- usage normalization;
- response extraction for bare, fenced, think-envelope, reasoning-field, and
  truncated JSON;
- deterministic inventory, task generation, coverage, dedupe, and report.

### Property tests

- dedupe is a total, non-overlapping partition;
- report membership equals reachable canonicals;
- severity totals equal finding totals;
- stable inputs produce stable IDs and output;
- path normalization never escapes allowed roots;
- context packing always emits valid JSON;
- retries never delete earlier attempt records.

### Integration tests with scripted endpoints

- multi-turn Read/Grep/tool-call loop;
- malformed tool arguments;
- 429/500 retry then success;
- terminal 400 without retry;
- output-length continuation;
- continuation after repair;
- first attempt preserved after retry;
- concurrent local requests actually overlap;
- profile routing by stage;
- single-GPU model lifecycle order;
- resume after task, validation, and trace interruption.

### Orchestrator tests

Use fake deterministic backends to run the whole pipeline and assert:

- exact stage order;
- two Titus Hunt waves;
- one Titus → OpenMythos transition;
- exact candidate-to-validation coverage;
- exact confirmed-to-trace coverage;
- review queue behavior;
- deterministic final report;
- clean no-finding completion;
- partial failure cannot be marked complete.

### Benchmark tests

- fresh read-only target per trial;
- external answer key;
- pre/post target hash;
- unique run state and output;
- exact runtime manifest;
- candidate and final-report scorers;
- class-aware, location-aware one-to-one matching;
- launcher shell syntax plus an executable smoke run;
- GPU-offload gate and occupied-port refusal.

## 8. Experiment sequence

Run experiments in this order to avoid optimizing on a broken or moving
harness:

1. Corrected deterministic smoke tests with fake models.
2. Clean Titus-only end-to-end baseline.
3. Clean OpenMythos-only end-to-end baseline.
4. Titus Hunt + OpenMythos Validate/Trace with legacy non-reasoning stages.
5. `duo-v1` with deterministic stages.
6. Titus prompt and tool-budget tuning.
7. OpenMythos validation prompt tuning.
8. OpenMythos trace tuning.
9. Concurrency/context/KV performance sweep.
10. Quantization sweep.
11. Frozen holdout, opened once after settings are locked.

Every experiment has:

- one hypothesis;
- one primary metric;
- unchanged comparison inputs;
- exact runtime metadata;
- a unique run root;
- a stop/accept rule written before execution.

## 9. Proposed merge sequence

Keep changes reviewable and preserve a working legacy path:

1. Characterization tests and benchmark integrity checks.
2. State schema v2, migration, and run-root isolation.
3. Context packing, semantic contracts, and normalized usage.
4. Tool workspace and local-engine reliability.
5. Backend/profile interfaces and legacy adapters.
6. Local OpenAI backend plus fake-server integration suite.
7. Runtime scheduler and managed llama.cpp lifecycle.
8. Deterministic inventory and task compiler.
9. Deterministic coverage/gap wave.
10. Deterministic dedupe, feedback expansion, and reporting.
11. Titus Hunt prompt/contract.
12. OpenMythos Validate and Trace prompts/contracts.
13. End-to-end duo orchestrator and CLI.
14. Ground-truth repair, holdout tooling, and evaluation matrix.
15. Performance tuning, recommended profiles, and rollout documentation.

Each merge must include tests and migration notes. Do not combine the database
migration, backend rewrite, and pipeline rewrite into one unreviewable change.

## 10. Risk register

| Risk | Consequence | Mitigation |
|---|---|---|
| Development-set overfitting | Apparent ensemble gain does not generalize | Lock tuning data; use a frozen external holdout |
| Titus over-reports decoys | Review cost and low precision | OpenMythos falsification gate; retain review tier |
| OpenMythos false rejection | Titus recall is lost | Measure validator retention; use `needs_more_info`; preserve candidate ledger |
| Deterministic task compiler misses unknown patterns | Lower discovery recall | Unsupported-coverage ledger; optional bounded LLM recon fallback; language adapters |
| Deterministic dedupe under-merges | Noisy report | Conservative variants; improve fingerprints after evidence |
| Deterministic dedupe over-merges | Lost vulnerabilities | Prefer separate groups; property tests; operator-visible variants |
| Context packing omits required facts | Wrong model decisions | Required-field contracts; exact included-ID ledger; fail before request |
| Single-GPU model switching dominates time | Slow runs | One default transition; measure load time; two-GPU external mode |
| Co-residency causes OOM or KV starvation | Crashes or tiny context | Sequential default; empirical gate for any co-resident profile |
| Model update/template change | Silent behavior drift | Pin revisions/checksums/builds; live conformance test |
| Tool sandbox is only logical | Target code can affect host | OS sandbox, read-only mount, network deny, resource caps |
| Legacy migration loses historical truth | Misleading resumes | Back up, validate migration, mark collision-affected runs incomplete |
| Incomplete stage appears successful | False assurance | Semantic coverage gates and explicit incomplete run status |

## 11. Definition of done

The optimization effort is complete when:

- `duo-v1` implements the target architecture;
- Titus and OpenMythos use independently configured, pinned profiles;
- the recommended A6000 run uses no more than one model transition;
- all non-security-reasoning stages are deterministic;
- state, input, output, and report integrity blockers pass;
- local tools operate correctly across repository and scratch roots;
- output repair and continuation cannot silently lose data;
- tokens, cache, turns, failures, model identity, and VRAM are observable;
- clean Titus-only, OpenMythos-only, paired, and efficiency-control runs exist;
- repository truth distinguishes candidate discovery from final reachability;
- a frozen holdout confirms or rejects the pair hypothesis;
- the final report and review queue are complete and reproducible;
- safety boundaries match the documentation;
- legacy users retain a supported migration path.

Until those conditions hold, Titus + OpenMythos should be described as the
primary optimization track, not as a proven production winner.

## 12. Evidence and reference documents

- [Benchmark methodology](../bench/METHODOLOGY.md) defines the corrected probe
  and repository protocols.
- [Corrected local-model results](../bench/RESULTS-2026-07-24.md) contain the
  Titus, OpenMythos, ensemble, quantization, and VRAM evidence used here.
- [Corrected GLM-5.2 results](../bench/RESULTS-GLM-5.2-2026-07-24.md) provide a
  hosted-model control with the documented cross-protocol caveat.
- [Historical benchmark report](../bench/REPORT.md) is retained for provenance
  but is superseded and must not drive implementation decisions.
- [Repository README](../README.md) documents the current legacy pipeline,
  provider behavior, direct local engine, and operator safety caveats.
