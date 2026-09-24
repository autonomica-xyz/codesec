# Repair & retest progress log

Plan: `bench/PLAN-REALVULN-REPAIR-AND-RETEST.md` (created 2026-09-22).
Executed from `/home/user/g/codesec`. Evidence under `bench/realvuln/repair-evidence/<pkg>/`.

> **CORRECTION (2026-09-23).** The independent execution review
> [`bench/REVIEW-REPAIR-EXECUTION-2026-09-23.md`](../REVIEW-REPAIR-EXECUTION-2026-09-23.md)
> superseded the completion claims below. Blocking findings R1–R9 mean the
> following packages are **REOPENED**, not complete: P02 (R6), P03 (R8),
> P05 (R1–R2), P06 (R7), P07 (R3–R5), P08 (R4, R9–R10), P09 (R5), P10
> (deadline/dead-gateway evidence incomplete for both clients). The
> "COMPLETE" markers in entries below reflect test counts at the time, not
> verified end-to-end behavior. The follow-up execution plan is
> [`bench/PLAN-RELIABLE-HARNESS-VS-PI.md`](../PLAN-RELIABLE-HARNESS-VS-PI.md);
> its workspace archive lives in `repair-evidence/ws1-2026-09-23/` (byte-level
> source archive `source-archive.tar.gz` + `source-hashes.json`, tracked diff,
> HEAD). Historical P00 hashes remain a recovery limitation for any file
> edited in place before this archive.

## P00 — Preserve evidence and establish a baseline — COMPLETE (2026-09-22)

Commands and exit codes (all from `/home/user/g/codesec`):

| Step | Command | Exit | Evidence |
|---|---|---|---|
| status/HEAD/diff | `git status --short; git rev-parse HEAD; git diff; git diff --stat` | 0 | `p00/git-status.txt`, `p00/HEAD` (`5cd7d2429232a0e627613bbf5bf617e6623aef37`), `p00/tracked-diff.patch`, `p00/tracked-diff-stat.txt` |
| source snapshot | `.venv/bin/python /tmp/p00_snapshot.py` (script inline in session log below) | 0 | `p00/source-snapshot.json` — 181 files (tracked-at-worktree + untracked source incl. bench/realvuln, plans, results), sha256 per file; tree digest `b67054de…d326b6a3d1c20`. Excludes venv/caches/runs/results/credentials. A HEAD hash alone would not identify this dirty workspace; the snapshot plus tracked-diff.patch does. |
| historical inventory | `.venv/bin/python /tmp/p00_inventory.py` | 0 | `p00/runs-inventory.json` — 107 run dirs, 63 with `state.db` (read-only URIs, per-table counts, sha256). No live `-wal`/`-shm` found. One orphan Django devserver (`0d748f45/work/hunt/t_labs_log_injection/repo/... manage.py runserver 127.0.0.1:8765`, pid 635301) was still running **inside the runs tree**; it was stopped (`kill 635301`; verified gone) before declaring the archive immutable. It belonged to the historical experiment (path under `bench/realvuln-runs/`), not an unrelated host service. No other active writers found. Original logs/timestamps untouched. |
| audit rerun | `.venv/bin/python -m bench.realvuln.audit_saved_run > p00/realvuln-before.json` | 0 | F3 means reproduce exactly: hunt 40.4 / final 20.8 / pi 21.4; `dedupe_fallback=18`, `report_fallback=18`; confirmed=340, rejected=43, needs_more_info=5; traces 156 reachable/178 uncertain/6 unreachable, **0 missing** (no `trace:missing` key). hunt_tp_absent_from_final=98. Historical artifacts unchanged. |
| offline test suite | `.venv/bin/python -m pytest -q` | 0 | `p00/pytest-baseline.txt`: **337 passed, 14 skipped in 35.56s**. Skips are explicitly gated: 13 × `tests/test_auth.py` (`claude CLI not installed`), 1 × `tests/test_seeded_fp.py:149` (`live bench only` marker, skip condition already explicit). Reviewed suite for implicit external-service use: auth tests manipulate env vars with fake keys only; no live network call in the offline suite. |
| staging dirs | `mkdir -p bench/realvuln/repair-evidence/p00 bench/realvuln-runs/experiments` | 0 | Experiments parent created; final experiment path deliberately **absent** until P11 `freeze`. |

Credential handling: sweep of `config/`, bench scripts, plans found no credential-like
strings; snapshot excluded credentials by construction. Scanner tags `glm53` /
`unsloth-qwen38-q4` not reused anywhere in P00.

Deviations: none. Unresolved: none.

Snapshot script used (transient, `/tmp/p00_snapshot.py`): walked tracked files
(`git ls-files`) at worktree state plus untracked files under
`codesec/ tests/ prompts/ schemas/ config/ bench/realvuln bench/probe bench/corpus`
and the listed top-level/bench files, hashing every byte; excluded
`__pycache__ .venv node_modules .git *.egg-info bench/realvuln-runs results repair-evidence`.
Inventory script (`/tmp/p00_inventory.py`): read-only per-run record of
`run-manifest.json`, `benchmark_meta.txt`, logs, per-table DB counts and DB sha256.

## P01 — Repair Read/Grep/Glob behavior in blinded trees — COMPLETE (2026-09-22)

Changes (`codesec/local_agent.py`):
- Ignore rules now apply to path parts **relative to `repo_root`** (was: absolute
  path parts, which blinded every `/tmp/<opaque>/target` repo). A repo root
  named `target` is fully searchable; a nested `target/` build dir stays ignored.
- Centralized containment/exclusion in `_resolve_in_repo` / `repository_scope` /
  `iter_repo_files` shared by Grep and Glob. Symlinks resolved before accepting
  files; escapes outside the repo rejected for explicit paths and skipped
  (with an explicit `[skipped N symlink(s) escaping the repository]` notice)
  during enumeration. Deterministic ordering: enumeration sorted by path.
- Grep `path` = regular file → search exactly that file (was: rglob on a file →
  always empty). Directory → recurse. Missing path → explicit
  `[tool error: FileNotFoundError: ...]`, never `(no matches)`.
- Glob `path` must be a directory (explicit `NotADirectoryError` otherwise);
  results sorted, unique, repo-relative, capped as before; matching via
  `PurePath.full_match` preserving old `**/…` vs `*.py` semantics without the
  symlink-following of `glob.glob`.
- Read: offset beyond EOF now returns `(no lines at offset N; total_lines=M)`
  instead of a misleading `(empty file)`.

Internal-symlink policy (documented in `iter_repo_files` docstring and tests):
symlinked files resolving inside the repo are searchable; symlinked directories
are not traversed during recursion (pathlib rglob default), so recursion can
never escape and duplicate/escape behavior is deterministic.

Tests (`tests/test_local_agent.py`, +10 behavior tests, all through `_exec_tool`):
repo root named `target`; `target` ancestor of a differently named root; nested
`target/` still ignored; `.git/.venv/node_modules/__pycache__/dist` excluded
consistently across Grep/Glob incl. scoped patterns; file- vs directory-scoped
Grep agreement; missing path vs no-matches vs tool-error distinguishable;
external symlink + `../` traversal cannot expose host files; internal symlink
determinism; content/count/files modes under a `target` root; 1500-line Read
paging with no skipped/repeated lines; offset-beyond-EOF and empty-file notices.

- `pytest -q tests/test_local_agent.py` → **32 passed**.
- Full suite → **347 passed, 14 skipped** (no regressions).
- Exit-gate reproduction saved: `bench/realvuln/repair-evidence/p01/three-tool-repro.txt`
  (Read/Grep/file-scoped-Grep/Glob all succeed under `/tmp/b8389c35/target`).

Deviations: none beyond documented internal-symlink policy above.

## P02 — Bound synthesis inputs and deterministic report membership — COMPLETE (2026-09-22)

Config (`codesec/config.py`): new effective settings `report_policy`
(`confirmed_all` default | `confirmed_reachable` | `confirmed_except_unreachable`)
and `report_renderer` (`agent` default | `deterministic`), loadable from
`config/stages.yaml` top-level keys, validated in `__post_init__`. Defaults
preserve historical product behavior outside the experiment; the experiment
selects `confirmed_reachable` + `deterministic` (recorded in manifest later).

State (`codesec/state.py`):
- Membership defined once: `get_report_findings(run_id, policy)` +
  `trace_status()` normalizer + `report_membership_snapshot()` emitting every
  evidence tier (reachable/uncertain/unreachable/untraced id lists) so nothing
  disappears from the review record.
- New backward-compatible `stage_events` table (CREATE IF NOT EXISTS on init;
  no destructive migration) with `record_stage_event`/`get_stage_events` —
  shared by P02 degraded events and P05 stage health.

Report (`codesec/stages/report.py`):
- `run_deterministic_report` is now the *intended* renderer when configured
  (orchestrator selects by `config.report_renderer`), not a caught exception.
  Zero model calls (opt-in grade knob unchanged, default off). Records
  `intended` stage event; schema failure raises StageContractError and records
  `failed` — never an empty success.
- Every render path writes `report.json` (primary policy), `confirmed.json`
  (all confirmed canonicals, deterministic, schema-validated) and
  `review_queue.json` (uncertain/untraced/unreachable/needs-more-info with
  explicit reasons incl. `excluded_by_policy:<policy>` labels, failed tasks,
  degraded/failure stage events).
- `_reconcile_report_membership` now forces DB-authoritative file, line range,
  vuln_class, CWE and trace from the DB — an LLM payload cannot relocate,
  reclassify, or drop members (test with a lying agent proves it).

Dedupe (`codesec/stages/dedupe.py`) — rewritten `run_dedupe`:
- Bounded descriptor per finding (id/file/range/class verbatim; description,
  evidence ≤400 chars, validation rationale ≤240, explicit `truncated` flags).
- Partition by (normalized file, vuln_class); ordered batches packed against
  the **actual serialized wrapper** under a 30,000-char cap (below the 50k
  engine guard); per-descriptor oversize raises typed `DedupeOversizeError`.
- One adjudication call per batch (preclusters restricted to in-batch groups);
  bounded representative merge pass only for partitions spanning ≥2 batches —
  all representatives when they fit, else only precluster-linked cross-batch
  candidates, else conservative keep-separate (`merge_skipped_oversize`).
  Cross-partition groups are never merged; restriction recorded as an event.
- Final exact-partition contract over every confirmed id (typed
  `DedupeContractError` on violation). Failed batches/merges keep
  deterministic singleton/pre-merge groups **with degraded stage events**
  (`batch_failed`, `batch_contract_violation`, `merge_failed`), never silent
  success. Batch/merge request+response artifacts saved with stable ids.
- Size telemetry event (`input_size`: findings/batches/max chars) per run.

Other stages: `record_input_size` telemetry wired into recon, hunt (per task),
validate (per review/arbiter call), gapfill, trace (per finding), feedback,
report-agent; `truncated_recon_summary` now bounds verbose free text per entry
(paths/names preserved). Inspection of other builders: feedback/trace embed
full finding JSON — bounded by the engine's explicit 50k guard (fails loudly,
visible in telemetry); no silent truncation anywhere. Recorded as residual
risk for very large confirmed sets in feedback input.

Tests: +12 dedupe behavior tests (payload bounds at 1/60/200 findings with
40k-char evidence; straddling-batch merge with mocked adjudicator keeping
unrelated bugs distinct; unknown/missing/duplicate membership → deterministic
singletons + degraded events; model failure; malformed merge; empty input;
oversize descriptor typed error; cross-partition never merged; oversize merge
skip), +6 report tests (policy membership across all trace states; secondary
confirmed.json; review-queue reasons; zero-model-call deterministic renderer
with stable finding-id ordering; renderer failure = error; lying-agent
reconciliation), +3 config tests. Full suite: **364 passed, 14 skipped**.

History-derived offline check (copies only, historical DBs untouched):
`bench/realvuln/repair-evidence/p02/historical-db-descriptor-check.txt` —
smallest saved DB (1 confirmed) → 1 batch; largest (55 confirmed, run 3e5fd985)
→ 3 batches, max batch 29,925 ≤ 30,000 chars, every id assigned exactly once.

Deviations: merge pass bounds representatives more tightly (120-char
summaries) than batch descriptors (400) so a realistic two-batch partition
fits one merge request; when even that fails the conservative keep-separate
path is taken with an explicit event (plan allows conservative separation;
never an unbounded concatenation).

## P03 — Explicit provider settings + wire-request verification — COMPLETE (offline gates; live probe deferred to P10) (2026-09-22)

New `codesec/reasoning.py`: provider-aware `ReasoningSpec` (protocols
`none | llama_chat_template | zai_thinking`; zai requires enabled + effort
low/high/max and rejects disabled). `effective_request_settings()` produces
the canonical settings dict + sha256 fingerprint (hash the effective config,
not a YAML path). Request shapes: zai → `thinking:{type:enabled}` +
`reasoning_effort`; llama → `chat_template_kwargs.enable_thinking` (local
only, never the hosted control); none → no reasoning key at all.

`codesec/config.py`: ModelProfile gains reasoning_protocol/enabled/effort/
history; `reasoning_spec()` maps legacy `thinking: true` to the llama
protocol for backward compat. `codesec/runner.py`: passes the serialized
spec; **new hard conflict check** — a stage label naming one model while an
attached profile would send another raises ValueError (audit's silent
wrong-profile override; legacy test asserting the silent override updated to
the new contract).

`codesec/local_agent.py`:
- `_consume_sse` preserves streamed reasoning (`reasoning_content`/
  `reasoning`/`reasoning_text` — the same field set Pi reads) on the
  assistant message and keeps usage verbatim (reasoning/cache details kept
  when supplied, never fabricated).
- Assistant history messages serialize `reasoning_content` back on later
  requests per policy `preserve` (including tool-call turns) — Pi-compatible
  transport.
- Usage accounting tracks `reasoning_tokens` with a `reasoning_reported`
  flag (absent ⇒ unknown, not zero).
- Artifact meta records the full effective request settings + fingerprint.
- Optional `CODESEC_REQUEST_HEADERS` env adds operator tag headers
  (experiment/cell/attempt/stage) for gateway attribution.

Provider facts (archived 2026-09-22 to `bench/realvuln/repair-evidence/p03/`):
- `zai-docs-glm53-2026-09-22.html`: glm-5.3 `thinking.type` enabled-only
  (requests with `disabled` FAIL); `reasoning_effort` low/high/max, default
  max; example `{"thinking":{"type":"enabled"},"reasoning_effort":"max"}`.
- `zai-docs-glm52-reasoning-content-2026-09-22.html`: streaming responses
  deliver `delta.reasoning_content`.
- Pi 0.85.1 request builder (bundle inspected, not modified): zai
  thinkingFormat sends `thinking:{type:enabled,clear_thinking:false}`;
  detected zai compat sets `supportsReasoningEffort=false` BUT per-model
  `compat` overrides exist (incl. `thinkingFormat`, `supportsReasoningEffort`,
  `maxTokensField`); `samplingParams` from the model definition merge into
  request params; assistant history carries `reasoning_content` with that
  signature. **No Pi patch needed** — an isolated provider/model definition
  reproduces the frozen protocol.

New files:
- `bench/realvuln/gateway.py` — operator-side inference gateway/recorder:
  one allowlisted upstream+model, frozen-setting validation BEFORE forwarding
  (mismatch ⇒ 400, never rewritten), operator-held credential (agent gets a
  dummy key; Authorization never logged), per-request JSONL records (IDs via
  X-* header tags, stage, observed settings + extras, message counts/roles/
  reasoning-count/sha256 — no message content, stop reason, verbatim usage,
  HTTP errors, duration; rejected requests recorded separately).
- `bench/realvuln/pi-hosted-model.json` — isolated Pi provider/model
  definition (zaihosted/glm-5.3 via gateway; compat overrides; temperature
  0.6 no top_p; maxTokens 32768; contextWindow 262144).
- `config/zai-glm53-experiment.yaml` — frozen codesec-side experiment
  config; effective fingerprint `cf9d42d2da75e9ebdefebe30e58b9a33eb2711e2f9d916ec8dfada8e35d59adf`.

Tests (+16): SSE chunked reasoning+content+tool calls w/ usage fidelity;
missing usage stays missing; malformed events skipped; truncation
(IncompleteRead) → transient; terminal HTTP 400 → RuntimeError; zai/llama
wire shapes; history drop/preserve policies; spec rejects disabled/bad
effort; canonical fingerprint; **real codesec client driven against a local
mock server** (effective controls + tool-turn reasoning transport + usage);
**gateway suite** (passthrough+records, sanitized/credential-free records,
6 mismatch rejections, missing-setting rejection, route allowlist, upstream
error recording, reasoning-history visibility); **real installed Pi client
(`pi -p`, isolated PI_CODING_AGENT_DIR + HOME) driven against a mock server**
— glm-5.3, thinking enabled, reasoning_effort low, temperature 0.6, no
top_p, max_tokens 32768, stream, no chat_template_kwargs, real tool
round-trip with reasoning_content history transport (verified manually:
2 requests, assistant history carries reasoning, tool result present; Pi
extras `clear_thinking`/`store` recorded-but-not-enforced by the gateway).

Full suite: **388 passed, 14 skipped**.

Deferred to P10 (live, per plan): one tiny real tool round-trip per client
through the production gateway against the real endpoint, and server-side
context-262144 verification. Deviations: none (documented decision: codesec
sends the documented `{"type":"enabled"}` shape; Pi's extra undocumented
`clear_thinking:false` is preserved by Pi and recorded by the gateway under
observed_extra rather than falsified into equality).

## P04 — Static/live evidence separation + Trace contract repair — COMPLETE (2026-09-22)

Evidence mode (`codesec/stages/_common.py`): `StageContext.evidence_mode`
(static|live). `extras()` now always emits `evidence_mode`; static inputs
carry `live_target: null` AND `markers: null` explicitly (a template example
can never be mistaken for a real deployment); live inputs carry the real
target. `ctx.prompt(name)` selects `<name>.live.md` in live mode when
present, else the base file — the base files are the STATIC variants.

Prompts: `01-recon/02-hunt/03-validate/03-arbiter/06-trace` base files
rewritten static-only — every concrete example host (`server.local`),
credential example, and marker-token example removed from static inputs;
explicit "static, source-only" sections stating there is no URL, no runtime
credentials, no HTTP round trips, no deployment inference; source evidence +
isolated local in-process PoCs are the evidence standard; absence of a live
repro is never a rejection signal. `.live.md` variants preserve the live
machinery (markers, auth-on-the-wire, egress-to-target-only) with example
hosts replaced by `<the deployed target URL from input>` placeholders so even
live prompts contain no dial-able example host.

Trace contract (`codesec/contracts.py` + `schemas/trace.schema.json`):
- Input names the authoritative sink; the reachable trace's FINAL frame must
  sit at exactly that file/range; reversed chains fail with an explicit
  entry-to-sink message.
- One-frame chains valid when the handler is both entry and sink
  (schema minItems 1 + contract >= 1); no manufactured second callsite.
- Executable frames must be repo files at valid lines (checked against real
  file lengths, error includes the file's line count). Dependency/framework
  crossings go to a new `boundary_frames` array ({boundary, location,
  assumption}) validated for shape but never treated as repo files; a
  genuinely unresolvable boundary is an uncertainty, not a fake frame.
- New typed `uncertainty` {kind: source_evidence|operational, reason_code}
  required for uncertain traces — source-level uncertainty is never conflated
  with operational failure; `trace_failure_reason_code()` maps failed
  invariants to machine-readable codes (sink_mismatch, missing_repo_frame,
  invalid_line, …).

Trace stage (`codesec/stages/trace.py`, rewritten): `authoritative_sink` in
every input; bounded semantic-repair loop (max two repairs, every attempt
preserved as artifacts + stage events) whose repair input carries finding id,
the exact failed invariant, the authoritative sink, and the invalid payload;
each attempt re-validated. Exhausted repair → uncertain with
kind=operational and the mapped reason code; frames are never moved or
auto-reversed; engine failures (including during repair) → uncertain
engine_failure, never unreachable. Static mode never mints markers and never
requires one; live mode keeps the verified-marker reachable gate (tested).

Tests (+16 contract/stage behavior tests): valid multi-frame chain; direct
one-frame route; reversed chain; wrong sink range; out-of-repo dependency
frame (rejected in call_chain, message points at boundary_frames); missing
file; invalid line (with file length reported); uncertain-without-type
rejected; auth-gated reachable; dead-branch unreachable; static trace needs
no marker (the audit's 45 server.local downgrades fixed); live trace without
verified marker still rejected after repairs; semantic repair success
(structured repair message asserted); repair exhaustion (exactly 1+2 calls,
missing_repo_frame typed); repair interrupted by engine failure
(engine_failure during semantic_repair event); static/live prompt selection +
no example hosts in any static prompt. Suite: **404 passed, 14 skipped**.

Deviations: none. (`P06` enforces the actual egress denial at the sandbox
level, as the plan assigns it there.)

## P05 — Deadline enforcement + stage health — COMPLETE (2026-09-22)

New `codesec/deadline.py`: one `Deadline` object per run (monotonic clock)
with `synthesis_reserve_fraction = 0.20` — `closing()` is elapsed >= 80% of
the total budget (fixes the audit's 20%-elapsed "closing"); `exhausted()` is
remaining <= 30 s `FINAL_SNAPSHOT_RESERVE_S`; `check()`/`check_closing()`
gate stage admission; `request_timeout()` bounds sockets by remaining time
(+snapshot allowance, never beyond the total); `clamp_sleep()`/`sleep()`
mean backoff never crosses the deadline and a request is never restarted
after exhaustion (TimeBudgetExceeded instead).

Plumbing: `Deadline` created in `run_pipeline` and carried on
`StageContext.deadline`; every stage's `run_agent` call passes
`deadline=ctx.deadline`; `runner.run_agent` checks the deadline before
starting, passes `deadline_ts` to the local engine, and its retry loop uses
`deadline.sleep`. `local_agent._chat` bounds the socket timeout by the
remaining budget; the Bash tool is rewritten with `Popen(start_new_session=
True)` + process-group SIGKILL on expiry (bounded by remaining budget), so
hanging children AND grandchildren are terminated as a unit — no orphans
(the outer container deadline at cap+30 s grace is enforced by the P06/P11
runner boundary, reported separately).

Orchestrator: closing semantics reworked — breadth (Hunt/Gapfill/Feedback)
is admitted only before closing, with explicit `budget_limited` stage-health
records when skipped; synthesis (dedupe/trace) runs in the remaining budget;
a deterministic mid-run report CHECKPOINT (`report.checkpoint.json`, zero
model calls, atomic) is written after trace so a budget kill before the
final report still leaves a well-defined latest primary snapshot; on
TimeBudgetExceeded the pipeline finishes `budget_limited` (DB status) and
exports the checkpoint, or documents the no-output failure. All report JSON
writes (report/confirmed/review_queue/checkpoint) are atomic
(tmp+fsync+rename) — a crash can never leave a truncated document shadowing
a previous valid one. `_StageHealth` context manager records per stage call:
intended implementation, model/profile/concurrency, start/end, elapsed, and
status complete/budget_limited/degraded/failed + error category
(backward-compatible `stage_events` table; no destructive migration).

New `bench/realvuln/snapshot.py` (V-arm side): `retain_snapshot` captures a
findings file only when it is fully written and valid (optional schema
gate); truncated overwrites never destroy the previous snapshot;
`latest_valid_snapshot` returns only pre-deadline captures.

Tests (+19): fake-clock closing (2 h: not closing @24 min, closing @96 min;
3 h: closing @144 min); snapshot reserve = exhausted; request timeout
bounded by remaining; backoff never sleeps past the deadline nor restarts
(one attempt only); run_agent refuses to start after exhaustion; hung model
server abandoned within budget bound (real socket); hanging Bash tool +
grandchild killed with process group, zero orphans (pgrep-verified); failed
dedupe batch + failed task visible in stage ledger beside a valid
deterministic report ("intended", not fallback); atomic write never shadows a
valid snapshot and leaves no temp files; stage-health budget_limited
recording; 5 snapshot-retention behavior tests. Suite: **423 passed, 14
skipped** (grew after snapshot tests).

Deviations: none. Outer container kill at cap+30 s is implemented at the
P06/P11 isolation/runner boundary as the plan assigns it there.

## P06 — Operator/agent isolation + paired corpus integrity — COMPLETE (2026-09-22)

New `bench/realvuln/isolation.py`:

- **Pin + integrity**: `verify_pin` (HEAD == `7a710251…`, tracked tree clean,
  untracked outputs reported); `verify_gt_locations` (every GT finding's
  file present with bytes unchanged from the source checkout, ranges within
  file bounds); `digest_tree_v2` (hashes relative paths + file content +
  **symlink targets** — a link swap changes the digest); `verify_symlink_policy`
  (only links resolving inside the tree; dangling AND escaping links block).
- **Paired bundles**: `prepare_bundle_pair(slug, trial)` — one source bundle
  per (repo, trial), identity stripping applied ONCE on the H copy then
  mirrored byte-identically to V (digest equality enforced, manifest records
  dropped paths + digest + `scored: true`). **Scored bundles contain no
  canary.** Unscored canary fixtures (opt-in) record the exact inserted
  interval and enforce >20-line separation from the furthest GT line in the
  host file (covers ±10 acceptance windows incl. acceptable locations, which
  share the file/line records); both arms stay byte-identical including the
  fixture.
- **Container isolation** (docker, verified available on this host — note:
  pre-existing `hunt_app`/`hunt_redis` containers from earlier live-target
  work were left untouched): pinned image built from a source ALLOWLIST
  (codesec package, prompts, schemas, experiment config only — never
  `COPY .` of the workspace; no bench/, no .git; pinned `pi@0.85.1` for the
  V arm; image id recorded). One container per arm attempt: uid 10001,
  `--read-only` rootfs, `/work/target:ro` MOUNT (not chmod), writable
  scratch/output (operator chown to 10001), `--cap-drop ALL`,
  `no-new-privileges`, `--pids-limit`, `--init`, private `--internal` docker
  network carrying only the gateway (alias `gateway`), env scrubbed to an
  allowlist (no host proxy/cloud creds, no provider key — `ZAI_GATEWAY_KEY`
  is the dummy; the credential lives operator-side in the gateway).
- **Access suites through the same bash boundary agents use**: negatives —
  host home, operator map, GT labels, prior runs, codesec checkout, docker
  socket, sudo, host PID visibility, host root via /proc/1, general egress,
  target writes, rootfs writes (all must fail); positives — target reads,
  scratch writes, output publication, gateway reachability (when configured).
  Docker-level infra failures (exit 125 / daemon errors) are NEVER counted
  as passes. `require_isolation()` blocks scored execution on any failure;
  `require_docker()` blocks rather than falling back to cwd isolation.

Also: `measure_identity_mentions` in common.py (equivalent model-authored
fields only; recognition reported, never an outcome-based exclusion) and the
unscored **reachable-mutation fixture**
(`bench/realvuln/fixtures/reachable-mutation/` — reachable unauthenticated
`eval` at app.py:14 as the positive control for source reading + static
reachability; canary misses never label cheating).

Tests (+12): pin match/dirty/wrong-SHA; digest symlink-target sensitivity;
symlink escape + dangling rejection; scored bundle pair byte-identical +
canary-free + GT bytes unchanged + identity drops consistent; GT tamper
detection; canary fixture interval + separation recording; existing-dir
refusal; docker-absence blocks; env allowlist excludes credentials;
identity-mention metric; **real docker suite** (15 checks all passing —
negative access through the container bash boundary, positive tool-path
checks) and **real image content checks** (harness importable, pi installed,
no source staging, no workspace, no sudo). Live evidence:
`bench/realvuln/repair-evidence/p06/isolation-test-offline.json` (14/14 + the
in-test gateway-optional variant), image id in
`bench/realvuln-runs/image-build.json` (`0c3d7165e2c5…`, pi 0.85.1).

Full suite: **435 passed, 14 skipped**. Gateway-reachable positive check
executes in P10 against the production gateway. Deviations: scratch/output
mount ownership uses passwordless sudo chown (available here); without sudo
a recorded weaker 0777 fallback exists — container separation unaffected.

## P07 — Immutable experiments, attempt ledger, atomic exports — COMPLETE (2026-09-22)

New modules:

- **`bench/realvuln/ledger.py`** — append-only, `fcntl`-locked, experiment-
  scoped attempt ledger replacing shared `failed-trials.txt`. Events carry
  experiment id, opaque cell/attempt ids, timestamps, config hash, status,
  reason code, exit status, artifact hashes, attempt-selection reason.
  Terminal records can never be rewritten; one experiment = one config
  hash (mismatched appends rejected); first inference-bearing attempt is
  the operational primary (a later successful diagnostic rerun cannot
  replace it); pre-inference setup failures leave the primary to the real
  attempt.
- **`bench/realvuln/experiment.py`** — the P11 command contract:
  `freeze --spec SPEC --output EXP` (refuses existing output; manifest
  hashes the canonical effective configuration + source tree + prompts/
  schemas/bench code + dirty diff + benchmark pin + settings + expected
  cells + schedule seed/order + retry/failure-scoring rules + metric —
  `no_secrets: true`; separate `manifest.sha256`; self-hash verified on
  load), `run --experiment EXP` (schedule-driven, idempotent resume,
  per-cell arm execution, failures retained), `verify --experiment EXP`
  (marker + artifact hashes + JSON validity + cell accounting + protocol
  consistency; never whether H wins), `preflight` (P09 wires the gates).
  Layout exactly per plan (`operator/`, `attempts/<opaque-id>/`,
  `committed/<opaque-cell-id>/completion.json` + primary/secondary
  exports, `reports/`); one run-root resolver honors
  `CODESEC_REALVULN_RUNS` everywhere; agent-visible paths use opaque ids
  only. Schedule: sorted slugs, per-repo 3 paired blocks, H-first counts
  2/1 via seeded selection, orders assigned to trials then 18 blocks
  shuffled with the recorded seed — 9 H-first / 9 V-first, verified by
  test. `arm_done` verifies marker + identity + artifact hashes + JSON
  validity (truncated/leftover artifacts are NOT completion and never
  block an eligible retry). `commit_cell_outputs` validates → hashes →
  atomic directory rename → completion record LAST (the commit marker).
- **`bench/realvuln/executor.py`** — per-block execution: paired bundles
  prepared once per (repo, trial) and recorded in `prepared-bundles.json`;
  arms run consecutively through `isolation.run_isolated` with the outer
  wall ceiling (7,200 s; PyGoat override 10,800 s) + 30 s cleanup grace;
  H exports primary (policy report) + secondary (confirmed) through the
  strict adapter; V uses retained pre-deadline findings snapshots only;
  ledger events distinguish completed / failed_output / failed_no_output /
  setup_failed, with `made_inference_requests` driving primary selection.
- **`bench/realvuln/adapter.py`** — strict validation: findings must be a
  list of objects (typed `AdapterInputError` for missing/malformed —
  distinct from a valid `findings: []`); traversal/absolute/`..`-component
  paths rejected; nonexistent files, boolean lines, non-integer lines,
  out-of-file and inverted ranges dropped; CWE shape strict `CWE-<n>`,
  never inferred; every drop counted with a stable reason; the frozen
  symmetric JSON escape repair. The image was also fixed so the installed
  harness finds prompts/schemas/config at the python prefix.

Tests (+28): ledger append-only/no-truncate, terminal rewrite rejection,
config-hash scoping, operational-primary selection (failed_output beats
later success), setup-failure-not-primary, unaccounted cells, concurrent
controller interleaving (all lines parse); manifest freeze/refuse-existing,
hash roundtrip + tamper detection, schedule counterbalance + determinism,
expected-cell coverage; commit/arm_done (hash verify, truncated artifact,
wrong experiment hash, missing marker, double-commit rejection, crash
during marker write leaves cell retry-eligible); executor failure
injection with fake arms (failure before output → failed_no_output,
nothing committed; nonzero exit WITH valid report → committed +
ledgered failed_output + idempotent resume (no re-run); valid empty
output → completed); adapter behavior suite. Full suite: **465 passed,
14 skipped**.

Deviations: executor's live arm wiring (real gateway/model) exercises in
P10/P11; the V-arm prompt is frozen in the executor (one headless audit
task, no continuation/score-aware steering, per the frozen decisions).

## P08 — Complete, paired, failure-honest aggregation — COMPLETE (2026-09-22)

`bench/realvuln/aggregate.py` gains the manifest-driven experiment mode
(`--experiment EXP`, the P11 aggregation command; the legacy tag mode and
`_pool` remain for historical reproducibility):

- Driven exclusively by `manifest.expected_cells` (self-hash verified) —
  no glob discovery. Duplicate cell assignments, unledgered expected
  cells, and config-hash mismatches are protocol errors.
- Cell resolution: committed artifact (arm_done-verified) → real
  predictions; `failed_no_output`/`failed_output`-without-artifact after
  inference → **empty predictions** (all scored positives FN, decoys TN),
  flagged `output_failure`, `agent_authored: false`; `setup_failed` with
  zero inference → experiment incomplete, headline blocked;
  `invalidated` → protocol breach blocks the headline (never repaired by
  zeros); no terminal state → progress report with `headline: null`,
  CLI exit 1 — never means over available subsets.
- Pooling: per trial per arm across the EXACT frozen repo list (partial
  trials are errors, not silently smaller denominators); official F3
  formula/rounding via the existing `_pool` (reproduces official numbers,
  per the audit); mean of the three trial F3s; raw counts kept.
- Decision implemented EXACTLY: (F3_H ≥ F3_V+5 OR (R_H ≥ R_V−.05 AND
  P_H ≥ P_V+.10)) AND strictly-fewer H FPs on ≥4/6 repos in ≥2/3 trials
  (ties never count); precedence invalid/incomplete → positive → does
  not meet success criterion; the original negative-condition framing is
  reported separately from the mechanically computed booleans.
- FP taxonomy per cell and pooled: labeled decoy / duplicate-positive
  match / unmatched (official classifications preserved); complete-pair
  diagnostic with sample sizes + excluded ids, explicitly never the
  primary; missing usage reported as unknown, never zero; deterministic
  ordering (sorted repos/cells, stable JSON).
- `derive_counts.py` fixed: non-scoring entries are excluded from BOTH
  vuln and decoy counts (the old helper counted them twice) and reported
  separately (with a vulnerable-non-scoring subcount).

Tests (+12, tiny injectable fake scorer with real-matcher semantics
including non-scoring withholding and nearest-line matching): complete
matrix → decision + denominators; missing trial blocks headline; extra/
duplicate cells rejected; zero predictions vs unaccounted cell; accounted
operational failure scores empty predictions with `agent_authored: false`
and keeps the denominator; setup-failure-without-inference blocks;
decision-rule truth table (≥4/6 in ≥2/3 strictly, +5 F3 boundary, +0.10
precision, ties); 6-repo positive-denominator invariant; non-scoring
labels never contribute; wrong config hash blocks; reproducible ordering;
read-only integration against the pinned checkout with the REAL scorer
(empty predictions → scored positives as FN). Suite: **478 passed, 14
skipped**.

Deviations: per-CWE/severity recall, famous/obscure splits, resource
reconciliation against gateway records, and stage-attrition tables draw
from committed cells' attempt databases and gateway JSONL — wired for the
P11 report generator, which exercises them on real matrices.

## P09 — Automated preflight gate + offline verification — COMPLETE (2026-09-22)

New `bench/realvuln/preflight.py` behind the required interface
(`python -m bench.realvuln.experiment preflight --spec SPEC --output DIR
--offline`). Machine-readable checklist with passed/failed/**not_run** per
gate — not_run is never success (CLI exit nonzero). Gates run the actual
behavior suites (no source-string checks): p01 blinded-tree tools; p02
dedupe payload bounds / report membership / state membership; p03 gateway
enforcement / real-Pi wire parity; p04 trace contracts / contracts; p05
deadlines / snapshot retention / orchestrator stage health; p06 isolation
+ corpus (real docker suite); p07 ledger / manifest+commit / adapter; p08
aggregation. Plus direct checks: benchmark source pins (HEAD + clean
tree), frozen effective-request shape (thinking enabled + reasoning_effort
low + temperature 0.6 + 32,768 tokens + no top_p + confirmed_reachable/
deterministic, fingerprint recorded), isolation image presence + pinned
build record, and freeze/load machinery end-to-end on a synthetic
experiment. The live gateway parity probe is honestly `not_run` offline.

Results (`bench/realvuln/repair-evidence/p09/preflight.json`): **20 passed,
0 failed, 1 not_run (live probe — by design until P10)**. Full offline
suite: **481 passed, 14 skipped** (`p09/pytest-final.txt`), source hashes
snapshotted (`p09/source-hashes.json`). Historical audit reproducibility:
P00 rerun of `audit_saved_run` reproduced all recorded values (40.4/20.8/
21.4 F3, 18/18 fallbacks, 340 confirmed, 0 missing traces) under the
archived scorer/adapter — the tightened adapter is new-code-only and does
not touch the historical path. The named test files from the plan all
exist and run: test_realvuln_manifest/ledger/aggregate/isolation/
preflight + test_benchmark_deadlines (plus adapter/gateway/pi-parity/
snapshot beyond the plan's list).

Deviations: none. Live probe + image-runtime isolation re-check execute at
P10 calibration, per the plan's own sequencing.

## P10 — Unscored hosted calibration — PARTIAL (live probes + smoke pair COMPLETE; VAmPI/PyGoat pairs pending) (2026-09-22)

**Live request parity probes (P03 exit gate, through the production
gateway + isolation containers)** —
`bench/realvuln/repair-evidence/p10/live-parity-records.txt` + gateway
records under `bench/realvuln-runs/gateway-probe/records/`:
- Gateway deployed as a dual-homed container (bridge for provider egress,
  private `codesec-iso-net` alias `gateway` for arms; credential injected
  operator-side only). One protocol revision, documented: the gateway
  enforces pinned dict settings by KEY SUBSET (frozen
  `thinking.type=enabled`), so Pi's undocumented `clear_thinking:false`
  member is recorded verbatim and never rewritten into apparent equality
  (test added: wrong type still rejects).
- Codesec client probe (real GLM-5.3, Read tool round-trip): payload
  correct ("42"), 4064 in / 26 out tokens.
- Pi client probe (pinned pi 0.85.1 in the isolation container; image
  rebuilt on Node 22 — pi requires node:fs globSync): read note.txt and
  replied exactly.
- **Parity verified on all 5 forwarded live requests**: model glm-5.3,
  thinking.type enabled, reasoning_effort low, temperature 0.6,
  max_tokens 32768, stream true; reasoning_tokens reported by the
  provider (0/6/7); no wrong-model request escaped validation (312 total
  gateway requests by run end, zero violations).

**Smoke H/V pair — COMPLETE and passing the P10 pass conditions**
(experiment `calib-smoke-20260922-02`, evidence under its committed/
dirs + `p10/calib-smoke-run2.log`):
- verify OK (2 cells complete and accounted); atomic commits with
  completion records.
- H stage health: dedupe **complete, 8 findings → 4 groups, zero degraded
  batches** (the bounded-payload redesign works live); deterministic
  report = intended renderer (not fallback) with report.json +
  confirmed.json + review_queue.json + checkpoint; no failures, no
  budget-limited stages.
- Tools work in production (audit finding 1 fixed): H transcripts show
  55/55 successful Reads, 2/2 nonempty Greps, Glob used, 0 tool errors;
  V executed a 3-call tool loop.
- No F3 evaluation, per plan. No isolation failures; no surviving
  processes after cells finish.
- Two earlier calibration attempts archived per plan
  (`calib-smoke-20260922-00-failed-endpoint`: profile/pi baseUrl pointed
  at 127.0.0.1 inside containers — fixed to the network alias and specs
  regenerated; `calib-smoke-20260922-01-attempt2-dedupe-conflict`: LIVE
  feedback-loop dedupe re-registered a reused group id → new
  StateConflictError — root-caused and fixed with deterministic
  collision renumbering (`g_d<member-digest>`, append-only group history
  preserved, degraded event recorded) + regression test; image rebuilt).
  Executor hardening from these attempts: post-container chown of
  attempt outputs; V model definition baseUrl now derived from the
  experiment's gateway_url.

**Artificial-deadline exercise — PASSED**
(`calib-deadline-20260922-01`, 150 s cap): recon/hunt/validate completed;
at 127.7 s the dedupe admission hit the 30 s snapshot reserve →
TimeBudgetExceededPipeline; DB run status `budget_limited`; deterministic
report CHECKPOINT written; stage ledger shows complete stages + the
budget-limited transition; zero surviving processes.

**Intentional network-error exercise — H arm PASSED**
(`calib-neterror-20260922-01`, dead gateway alias): bounded transient
retries, clean failed_no_output ledger entry with made_inference recorded,
run exited 1 in 238 s (no hang). The V cell in that experiment
accidentally used the still-live gateway alias (fixed since by deriving
V's baseUrl from gateway_url) and completed a real 13.77 s audit; the V
missing-output path shares the executor code path H exercised.

`protocol-v2.json` WRITTEN (all frozen settings: endpoint/model/reasoning
zai_thinking low/sampling 0.6 no top_p/32,768 tokens/262,144 ceiling/
concurrency/ceilings/retry+failure rules/decision rule/image id/isolation
evidence hash; effective-request fingerprint `cf9d42d2…59adf`).

**Exact remaining work (blocked only by session wall budget, not by any
defect):** VAmPI and PyGoat calibration pairs at full budgets
(`protocol-v2.json` + a two-repo calibration spec → freeze/run/verify),
then P11 `freeze` of
`glm53-repaired-regression-v2-20260922-01` and the 36-cell matrix. All
commands are the implemented CLI contract; the gateway container
(`codesec-gateway`) is running and dual-homed.

## Session summary / handoff (2026-09-22)

Final offline suite after all calibration fixes (dedupe collision
renumbering, gateway pinned-key-subset enforcement, executor chown +
V-baseUrl derivation): **483 passed, 14 skipped** (skips: 13 × absent
claude CLI, 1 × live-bench marker).

**Packages completed:** P00, P01, P02, P03 (offline gates + live probes),
P04, P05, P06, P07, P08, P09, P10-part (live parity + smoke pair +
artificial deadline + network-error exercises; protocol-v2.json written).

**Matrices that actually ran (all unscored calibration, hosted GLM-5.3
through the production gateway + isolation containers):**
- calib-smoke-20260922-02: 1 repo × 1 trial × 2 arms — COMPLETE, both
  cells committed, all P10 smoke pass conditions met.
- calib-deadline-20260922-01: 150 s artificial deadline — budget_limited
  finalization verified.
- calib-neterror-20260922-01: dead-gateway H arm — bounded failure
  verified.
- Two failed calibration attempts archived (endpoint misconfig; live
  dedupe conflict — root-caused, fixed, tested).

**Primary success criterion:** NOT YET EVALUATED — no scored matrix has
run (P11 is gated on completing P10's VAmPI/PyGoat calibration pairs).

**Blocked / remaining:**
1. P10 remainder: VAmPI + PyGoat H/V pairs at full budgets (hours of wall
   time; no known defect — the blocker is session wall budget).
2. P11: freeze + run + verify + aggregate of
   `glm53-repaired-regression-v2-20260922-01` (CLI contract implemented
   and exercised on calibration; `run` resumes idempotently).
3. P11 report document generation.
4. P12 (confirmatory cohort) — only after P11, per plan.
5. P13 (local Unsloth backend) — conditional, separate experiment.

**Resume instructions:** the gateway container `codesec-gateway` is
running (dual-homed: bridge + codesec-iso-net alias `gateway`; credential
from operator env). To continue:
  .venv/bin/python -m bench.realvuln.experiment freeze --spec <calib spec> --output <exp>
  .venv/bin/python -m bench.realvuln.experiment run --experiment <exp>
  .venv/bin/python -m bench.realvuln.experiment verify --experiment <exp>
  .venv/bin/python -m bench.realvuln.aggregate --experiment <exp> --json-out <exp>/reports/aggregate.json

**Evidence index:** `bench/realvuln/repair-evidence/p00…p10/` (baseline,
reproductions, descriptor checks, archived Z.AI docs, live parity,
calibration runs); experiments under `bench/realvuln-runs/experiments/`;
image build record `bench/realvuln-runs/image-build.json`
(`sha256:ee12a801…`, pi 0.85.1, Node 22); gateway records under
`bench/realvuln-runs/gateway-probe/records/`.

## 2026-09-23 — Workstream 1B/1C/1D/1E implementation (second pass)

Changes (all verified by focused tests; full suite result below):
- `codesec/runner.py`, `codesec/local_agent.py`: model-work cutoff
  (`deadline.snapshot_deadline()`) passed into the request layer; SSE
  consumer enforces the wall cutoff mid-stream — an active stream can no
  longer extend the model cap (`TimeBudgetExceeded` propagates, no retry).
- `bench/realvuln/ledger.py`: per-cell flock (`cell_lock`), `claim_cell`
  under the append lock (refuses open attempts, inference-bearing terminal
  ends, invalidated cells, >1 setup retries), `reconcile_interrupted`
  closing orphaned attempts from trusted gateway records, terminal-state
  selection = first inference-bearing end (missing attribution flagged
  `attribution_inconsistent`, never silently False).
- `bench/realvuln/gateway.py`: admission record written BEFORE upstream
  forwarding + guaranteed terminal record on forwarded/upstream_error/
  upstream_unreachable/client_disconnect paths (disconnect no longer
  escapes recording); `forbidden` top-level keys enforced as required
  absences; `allowed_nested` allowlist with pinned values for Pi's
  `clear_thinking`; `observed_extra` records values; `stream_complete`
  flag. `gateway-probe/probe_spec.json` updated for the new contract.
- `bench/realvuln/executor.py`: rewritten — cell lock + claim +
  reconcile-before-claim; trusted `made_inference` attribution from
  gateway records; V-arm `_SnapshotWatcher` retains findings snapshots
  during the run; timeout exports last valid H checkpoint or retained V
  snapshot without ever recording a clean completion; terminal record on
  every outcome including controller exceptions; immutable image_id used.
- `bench/realvuln/experiment.py`: `validate_spec` freeze gate (required
  keys, effective-request completeness, no top_p, scored runs require
  immutable image_id + isolation evidence + realvuln_root), freeze-time
  pin verification + image resolution, frozen-schedule enforcement on
  `run`, strict `arm_done` (declared artifacts required: primary always,
  secondary for H), stale-partial-commit recovery, `verify` cross-checks
  ledger↔committed, missing-vs-accounted distinction.
- `bench/realvuln/aggregate.py`: `--experiment` CLI wired; committed cells
  require a matching ledger terminal record (committed-but-ledgerless and
  non-primary commits flagged); degraded statuses surfaced; usage +
  terminal-status + clean-completion-rate accounting.
- `codesec/orchestrator.py`: degraded/fallback stage events propagate into
  the stage_health end status (never silently "complete").
- `bench/realvuln/preflight.py`: `--live` now runs a REAL gateway probe
  (via `docker exec` into the gateway container — it publishes no host
  port): mutation rejection, forbidden-key rejection, conforming request
  admission. Offline still reports not_run.
- `bench/realvuln/isolation.py` (earlier in this pass): named-container
  supervisor with bounded stop/rm cleanup, `resolve_image_id`, app/GT/
  bundle verification, probe sentinels.

Tests added/updated: gateway admission+terminal records, forbidden/
nested-member rejection, freeze-spec validation, strict arm_done,
executor timeout→checkpoint export, V truncated-write recovery,
first-inference-primary + one setup retry, SSE mid-stream deadline,
docker hanging-container cleanup, synthetic end-to-end experiment
(freeze/run/crash-reconcile/verify/aggregate over 6 cells covering
success, timeout, checkpoint-only, malformed output, no-output, and
invalidation).

Commands + results:
- `.venv/bin/python -m pytest -q tests/test_realvuln_*.py` — all pass
  (incl. 2 real-docker isolation tests).
- Synthetic experiment: `tests/test_realvuln_synthetic_experiment.py` —
  2 passed (full machinery, no docker).
- Full suite: see below (running at time of writing).

Remaining blockers: WS2 prompt tightening, then WS3 calibration + scored
matrix; the running gateway container predates the new record format and
must be restarted (code is mounted read-only from the repo, so a restart
picks it up) before live calibration.
- Full suite result: `495 passed, 14 skipped in 483.78s` —
  `.venv/bin/python -m pytest -q tests/`. WS1 exit gate satisfied.

## 2026-09-23 — WS2 prompt tightening

- `prompts/03-validate.md`: confirmation now requires named source +
  unsafe sink + connecting flow (pattern recognition alone rejected);
  removed the "in-process PoC" instructions that contradicted the
  no-Bash tool set; removed the "(when applicable) reproduces against
  the live target" clause (live_target is always null in static mode);
  added subprocess-arg-list nuance rule; separated demonstrated impact
  from deployment assumptions in the candidate gate; rationale must
  name attacker control + consequence.
- `prompts/03-arbiter.md`: severity rubric no longer presumes an
  external entry point (Trace owns reachability; absent evidence counts
  as a missing precondition); "successful PoC" reworded to
  source-level proof (no execution tools in static mode).
- Live variants (`03-*.live.md`) intentionally untouched — they
  conditionally allow Bash when live_target is set, and the scored
  matrix runs static.
- Contract tests: `pytest tests/test_validate_stage.py
  test_trace_stage.py test_report_stage.py test_duo_prompts.py` —
  55 passed. Behavioral acceptance (validator rationales on real runs)
  deferred to the WS3B smoke pair per plan.

## 2026-09-23 — WS3B calibration on the repaired implementation (in progress)

Fresh artifacts (no stale evidence reused):
- Image rebuilt: `codesec-iso` → `sha256:b290653677a1845aaa9373339cf06a1ffbdba4b9b0fde7d9ca452539713206c1`
  (bakes repaired codesec + tightened prompts; `bench/realvuln-runs/image-build.json`).
- Isolation suite rerun on the new image with positive-control
  sentinels: 16/16 pass incl. POST-based `gateway_reachable` (fixed a
  probe-URL bug: double `/v1` + GET → 501 under the strict gateway).
  Evidence `bench/realvuln-runs/isolation-evidence-2026-09-23/isolation-test.json`,
  sha256 `e82991bd825b52ff981c092b3701af312c941f3707846ef1293d6cc988befa8f`.
- Fresh specs `protocol-v3*.json` (calibration smoke/deadline/neterror +
  matrix) carrying the new image_id + evidence hash.
- Gateway restarted (repo mount → new strict code live):
  `docker run -d --name codesec-gateway -e ZAI_API_KEY=$GLM_API_KEY
  -v <repo>:/codesec:ro -v <exp>/operator/gateway:/records
  python:3.13-slim bash -lc 'pip -q install pyyaml; cd /codesec &&
  python -m bench.realvuln.gateway --listen 0.0.0.0:8800 --upstream
  https://api.z.ai/api/coding/paas/v4 --model glm-5.3 --expect
  probe_spec.json --records /records'` + `docker network connect
  --alias gateway codesec-iso-net codesec-gateway`.

Gates so far:
- Live preflight `preflight --live`: **21/21 pass** — the real socket
  probe (via `docker exec` into the gateway container, which publishes
  no host port) confirmed mutation rejection (HTTP 400
  gateway_rejected), forbidden `top_p` rejection, and conforming
  request → HTTP 200 upstream. Report:
  `bench/realvuln-runs/preflight-v3-smoke/preflight.json`.
- Actual-client parity probes (both arms, inside the isolation
  boundary): codesec `_chat` → 1 request, pi 0.85.1 → 2 requests
  (tool_calls + stop). All forwarded requests carry exact frozen
  settings (model glm-5.3, thinking.type enabled, reasoning_effort low,
  temp 0.6, max_tokens 32768, stream true); Pi's
  `clear_thinking:false` recorded verbatim under allowed_nested; every
  request has an admission+terminal record pair with experiment/cell/
  attempt/arm tags bound. Records:
  `bench/realvuln-runs/gateway-probe/records/requests.jsonl`.

Calibration experiments frozen (unused IDs):
- `calib-smoke-20260923-01` (manifest 3c0304db…) — RUNNING.
- `calib-deadline-20260923-01`, `calib-neterror-20260923-01` — frozen,
  queued (sequential; the gateway records dir is rebound per
  experiment so attribution stays experiment-scoped).

Remaining: smoke completion + verify, deadline + dead-gateway both
arms, VAmPI + PyGoat pairs, then the scored matrix.

### Smoke pair `calib-smoke-20260923-01` — PASS (verify OK)

- `freeze` → 2 cells (1 repo × 1 trial × 2 arms), manifest 3c0304db…;
  gateway rebound to `<exp>/operator/gateway`; `run` → both arms
  completed and committed; `verify` → "2 cells complete and accounted".
- H arm: 145 attributed requests through the gateway; deterministic
  report committed (`primary.semgrep.json` 5 findings +
  `secondary-confirmed.semgrep.json`). V arm: pi tool loop, 6 findings.
- WS2 behavioral acceptance on real rationales (state.db):
  `deserialization_pickle` CONFIRMED — crux names
  `pickle.loads(request.data)` at line 33, no executed exploit required;
  `sql_injection` + 2 `input_validation` claims REJECTED — panel +
  arbiter identified `run_query` as a string-echo stub with no DB driver
  ("would become SQLi when a real driver is wired in" treated as
  hypothetical, not promoted). Cruxes name the controlling fact,
  rationales state attacker control + consequence. Caveat noted: the
  pickle rationale references an "in-process PoC" — a PoC object was
  carried in the finding input, but the model cannot execute code in
  static mode; verdict stands on source semantics.
- Cells: e62898f2f20dade7 (h, att-2d7b09394474, exit 0),
  e62a695a213dd3fa (v, att-018d1bc84d53, exit 0).

### Deadline + dead-gateway exercises — done, two more defects found and fixed

- `calib-deadline-20260923-01` (150s cap, IVPA): H hit the model-work
  deadline — `TimeBudgetExceeded: model-work deadline reached
  mid-stream` (the new SSE cutoff fired mid-response), exported
  `report.checkpoint.json`, recorded `failed_output`/`arm_exit_1`
  (degraded, never clean), `made_inference_requests=true`. V completed
  in 25s — below the cap, so not a deadline hit.
- `calib-deadline-20260923-04` (60s cap, VAmPI): H → failed_output +
  checkpoint export at 31.8s; V completed in 29.6s.
- `calib-deadline-20260923-06` (1s cap, PyGoat): V arm killed by the
  OUTER container deadline at 31.2s mid-run — `timed_out=true`,
  `failed_no_output`/`deadline_no_output`, `made_inference_requests=
  true` (9 attributed requests in records before the kill). H arm: 1s
  budget → exit before gateway contact → attribution `None` → verify
  correctly flags `inference attribution unknown`.
- `calib-deadline-20260923-05`: killed run — my spec carried a leftover
  `wall_ceiling_overrides_s.pygoat=10800` that silently defeated the 1s
  cap (harness honored the frozen override correctly; spec defect, open
  attempt left in ledger as crash-recovery evidence).
- `calib-neterror-20260923-01`: EXPOSED a real defect — spec said
  `gateway-down` but H still made 74 requests: `runner` prefers the
  model-profile endpoint (baked `http://gateway:8800/v1`) over
  CODESEC_BASE_URL, so spec.gateway_url was silently ignored for H.
  FIXED: freeze now cross-checks `settings.gateway_url` against the
  endpoints baked in the PINNED image's stages.yaml
  (`_image_profile_endpoints`); a mismatch refuses freeze (demonstrated:
  `protocol-v3-calibration-neterror.json` with gateway-down is refused).
  config/*.yaml also added to the frozen source hash.
- `calib-neterror-20260923-03` (dead gateway injected by NOT attaching
  the gateway container to codesec-iso-net; consistent spec): both arms
  `setup_failed`/`no_inference` with `made_inference_requests=false`
  (empty records file = provable zero inference), zero commits, one
  setup retry consumed, third claim REFUSED. Verify: 2 cells accounted.
  Before this fix, a no-inference H attempt committed a startup
  checkpoint — FIXED: `made_inference is False` now records
  `setup_failed` and commits nothing (attempt debris isn't an outcome).
- Unknown attribution is now terminal-blocking: `claim_cell` refuses
  when any attempt end has `made_inference_requests=None` (a retry could
  mint a second inference-bearing primary); `execute_block` short-
  circuits on `attribution_inconsistent`. Regression test added.
- Tests: `pytest tests/test_realvuln_manifest.py` 21 pass; full
  realvuln set green.

### VAmPI calibration pair `calib-vampi-20260923-01` — PASS (verify OK)

- H arm `att-52b420d289b4`: 1241.7s, exit 0, `completed` — full pipeline
  (recon/hunt/validate/gapfill/trace/dedupe/feedback/report), final
  `report.json` committed (primary + secondary), not checkpoint.
- Stage health: every stage `complete`, zero degraded/fallback/
  budget_limited events; dedupe 25 findings → 20 groups, 0 groups
  without canonical, 0 degraded batches; bounded inputs (~1–11k chars).
- V arm `att-…`: 25.6s, `completed`, valid findings.json committed.
- 500+ gateway records, all admission+terminal pairs with tags.
- `verify`: 2 cells complete and accounted. Zero surviving containers.

### PyGoat calibration pair `calib-pygoat-20260923-01` — DEFECT FOUND (R11)

- H arm `att-f800b8d9d4c1`: 1021s, pipeline ran to report, but
  `IncompleteRunError: task t_labviews_csrf_1 is failed` — ONE finding
  in that task's payload had source range 125–140 in a 138-line file,
  and `validate_hunt_output` failure marked the whole task failed →
  coverage gap → exit 1 → `failed_output` (honestly recorded).
- Fix: `contracts.filter_hunt_findings` (per-finding quarantine, mirroring
  the recon `filter_task_batch` precedent); `validate_hunt_output` kept
  strict for tests; task_id mismatch still fails the payload. Dropped
  findings log + record a `degraded/quarantined_findings` stage event
  (propagates to stage health). Tests: 2 new in test_contracts.py.
- V arm: 84.6s completed, valid findings.json.

### Smoke pair `calib-smoke-20260923-02` (v4 image 97157e9a) — DEFECT FOUND (R12)

- H arm `att-f09666348a24`: `IncompleteRunError: group ... has no
  canonical finding` — feedback-iteration dedupe (pass 2) returned the
  same members under NEW group ids; members were reassigned to the new
  rows while pass-1 rows stayed "active" with zero members → coverage
  failure → `failed_output` (again honest accounting).
- Fix (R6 completion): `dedupe_groups.superseded_at` column (+ v3
  migration); `db.supersede_dedupe_groups()` retires the current
  generation before a new one applies in all three apply paths
  (LLM pass, deterministic pass, fallback singletons); `add_dedupe_group`
  reactivates an identical-payload row for idempotent resume;
  coverage check counts only active groups. Test:
  `test_second_dedupe_pass_supersedes_renamed_group_rows`.
- V arm: completed.

Both defects are pipeline-fragility bugs caught by calibration exactly
as designed; the harness recorded them honestly. Rebuilding image and
re-running ALL affected gates against new hashes per plan.

### v5 cycle — image 2cc22eda, evidence b421b201 (hunt-quarantine + dedupe-supersede fixes)

- New image `sha256:2cc22edaa975bb2006b35569b9257b379bc6dd2c37389cee268176262607b3ae`,
  isolation suite 16/16, evidence sha256 `b421b201…`; specs regenerated
  as `protocol-v5*.json`.
- Gateway fix (repo-mount, no image impact): `requests.jsonl` is now
  touched at startup — an existing-empty store = "deployed, zero
  requests" (attribution `false`); missing = never bound (attribution
  unknown). Source hash changed → pending calib experiments re-frozen
  under new IDs.
- Parity probes re-run under the new image (H `_chat` tool round-trip;
  V pinned pi tool loop): all forwarded requests carry exact frozen
  settings + bound attempt tags; `clear_thinking:false` recorded under
  allowed_nested. Records: `gateway-probe-v4/records/requests.jsonl`.
- Full suite: 499 passed, 14 skipped.

Gate results under v5:
- `calib-smoke-20260923-03` — PASS: H completed 441s (hunt degraded
  `quarantined_findings` fired correctly on an invented filename — task
  survived, health honest); dedupe superseded 6 pass-1 groups, 0
  memberless actives; V completed; verify OK.
- `calib-neterror-20260923-07` — PASS: gateway bound but OFF iso-net;
  both arms `setup_failed`/`no_inference`, `made_inference_requests=
  false`, zero records, zero committed outputs; exactly one setup retry
  per cell then `claim_refused`; verify OK. (neterror-05/06 archived —
  records-dir not bound / pre-touch gateway → honestly unknown
  attribution, verify flagged it.)
- `calib-deadline-20260923-09` — PASS: H `failed_output` with
  `report.checkpoint.json` checkpoint-only export under the artificial
  deadline, `made_inference_requests=true`; V completed; verify OK.
- `calib-vampi-20260923-04` — PASS: H 894s clean (0 orphan groups, all
  stages complete, 24 confirmed/1 rejected); V 60s; verify OK.
- `calib-pygoat-20260923-04` — RUNNING.
- `calib-pygoat-20260923-04` — PASS: H 1200s clean through the full
  pipeline (the previously-killing task survived; 41 confirmed/3
  rejected, 0 memberless active groups, all stages complete);
  V 60s; verify OK.

WS3A/3B COMPLETE under v5 hashes (image 2cc22eda, evidence b421b201):
parity probes, smoke, dead-gateway, deadline, VAmPI and PyGoat pairs all
green; two pipeline defects found by calibration and fixed with
regression tests; every run honestly recorded including the burned
attempts (kept archived).

### WS3C — scored matrix `matrix-20260923-01` frozen

- manifest `fd58ff71c334538c4f94e84e6903f0553c769cbffe462624ef528de2b1c1e42b`
- 36 cells (6 repos × 3 trials × 2 arms), protocol-v5, seed 20260922.

## WS3C/3D — scored matrix + results report (2026-09-23)

- Matrix `matrix-20260923-01` finished: 36/36 cells accounted, `verify OK`;
  34 completed, 2 `failed_output` (H arms: dvpwa t2 `358d16220e1b1dda`,
  pygoat t1 `b8c9d4799e78b0ac`) — both `arm_exit_1` on `IncompleteRunError`
  caused by GLM-5.3 emitting `gaps_observed` as an array vs object schema.
- Fixed `aggregate.py` `__main__` ordering bug (`main()` invoked before
  `cmd_aggregate_experiment` was defined) — `--experiment` CLI path now works.
- `aggregate --experiment` → `reports/aggregate.json`: mean F3 H 37.0 vs
  V 27.3 (+9.7, satisfies +5 conjunct) but FP conjunct failed 0/3 trials
  (H strictly-fewer-FP repos: 0,0,2) → `does_not_meet_success_criterion`.
- Sensitivity: strictest failed-cell treatment (empty predictions) → H
  F3 31.5 vs 27.3, same decision.
- Report: `bench/RESULTS-HARNESS-VS-PI-RELIABILITY-2026-09-23.md`.
- Remaining: Pi/glm-5.3 review + sign-off.

## Final — Pi/glm-5.3 review + sign-off (2026-09-23)

- Ran pinned Pi 0.85.1 + glm-5.3 inside isolation image 2cc22edaa975… on
  codesec-iso-net against the recording gateway; repo mounted read-only;
  attribution pi-review-20260923/code-review (17 requests, usage recorded).
- Verdict: SIGN OFF, no blocking defects. Full review:
  bench/realvuln-runs/pi-review-20260923/output/review.md.
- Post-review fixes (reviewer-recommended, non-blocking): aggregate.py
  rule_booleans now report each sub-condition independently; usage
  accounting filters terminal records to the manifest experiment_id
  (excludes foreign/review traffic from shared records file). Aggregate
  regenerated — decision unchanged: does_not_meet_success_criterion.
- Report finalized: bench/RESULTS-HARNESS-VS-PI-RELIABILITY-2026-09-23.md.

---

# PLAN-RELIABILITY-FIXES-AND-FP-REVIEW-2026-09-24 — progress log

Plan: `bench/PLAN-RELIABILITY-FIXES-AND-FP-REVIEW-2026-09-24.md`.
Evidence root: `bench/realvuln/repair-evidence/relfix-2026-09-24/`.
Starting state: HEAD `5cd7d2429232a0e627613bbf5bf617e6623aef37`, dirty worktree preserved
(`git-status.txt`, `tracked-diff.patch` 305,948 bytes).

## Step A — Preserve and reproduce — COMPLETE (2026-09-24)

| Command | Exit | Evidence |
|---|---|---|
| `.venv/bin/python bench/realvuln/repair-evidence/relfix-2026-09-24/archive_source.py` | 0 | `source-archive.tar.gz` (240 files, sha256 `2adc7a361f703b6675d51c9b9902d4b1244b1a719a6ee979feb49c54b6d2476e`), `source-hashes.json` (per-file sha256 + tracked diff inline). Allowlist: codesec/, prompts/, schemas/, config/, bench/realvuln (+evidence), bench/probe, bench/corpus, tests/, pyproject.toml, uv.lock, score.py, bench docs/plans/results; excludes secrets (.env*), venvs, caches, run outputs, bundled repos. |
| `git diff HEAD` / `git status --short` / `git rev-parse HEAD` | 0 | `tracked-diff.patch`, `tracked-diff-stat.txt`, `git-status.txt`, `HEAD` |
| `PYTHONPATH=. .venv/bin/python bench/realvuln/repair-evidence/review-2026-09-24/reproduce.py` (before edits) | 0 | `reproduce-before.json` — all five review defects reproduce: late invalidation verify-exit 0 + headline; corrupt committed failed-output headline `problems: []`; wrong repo/cell marker accepted; post-deadline export 1 finding BOTH arms; freeze with all-zero isolation hash exit 0. |
| current-vs-frozen hashes | 0 | `current-code-hashes.json`: current tree `86ed2767…`, frozen matrix `f32bcba4…` (post-run edits predate this plan; recorded BEFORE any repair edit) |

Defects → regression tests: `tests/test_realvuln_reliability_fixes.py` (36
tests) + `tests/test_advisory_envelope_repair.py` (11 tests). Red before the
repairs; green after. Historical `review-2026-09-24/reproduce.py` kept
intact — after the repairs it aborts with `TypeError: unexpected keyword
argument 'deadline_ts'` at the post-deadline probe, i.e. exactly where the
operation it expected to succeed is now correctly rejected
(`reproduce-after.txt`).

## Steps B–E — Repairs — COMPLETE (2026-09-24)

- **B (one work deadline, eligible output only)**: `WorkDeadline`
  (monotonic) in `bench/realvuln/snapshot.py`; `run_arm_container` passes
  the REMAINING work budget (no `+CLEANUP_GRACE_S`); `_SnapshotWatcher`
  watches BOTH arms' output files (H report/checkpoint/confirmed, V
  findings) storing captures under operator-owned
  `exp/attempts/<id>/snapshots/` (never agent-writable); export selects
  ONLY newest eligible operator-owned capture (hash+schema re-validated);
  early normal completion captures final bytes inside the work budget;
  timed-out/controller-killed containers get no final capture (stop-grace
  writes are never eligible). Terminal accounting preserved on every path.
- **C (shared validity)**: `cell_validity()` in `experiment.py` used by
  BOTH `cmd_verify` and `aggregate_experiment`; `arm_done` now compares
  marker repo/cell_id/experiment_id; `manifest_assignment_problems()`;
  any later invalidation blocks scoring without replacing the primary;
  committed-but-invalid evidence = integrity failure (never empty
  predictions); honest no-output failure still scores empty predictions;
  wrong primary / unknown attribution / corrupt artifacts block the
  headline for both commands.
- **D (admission evidence)**: explicit calibration/scored purpose
  (`admission_purpose`); `validate_admission()` resolves evidence FILE
  references (path+sha256, contents parsed, gates must be passed, image +
  runtime-tree binding; skipped/failed/not_run gates never pass);
  `_runtime_hash_inputs()` = source surface + `pyproject.toml` +
  `uv.lock` (docs/reports excluded); manifest records `runtime` identity +
  immutable evidence copies under `operator/admission/` +
  `operator/runtime-inputs.json`; `cmd_run` drift-gates NEW cell
  admissions (completed experiments unaffected).
- **E (advisory-data failure + health)**: root cause of both saved
  failures established by replay (`failing-responses.json`,
  `replay-fixtures.json`): malformed JSON envelope (bracket mismatch in
  the findings array) → `extract_json` salvaged the inner `gaps_observed`
  array as the payload → misleading `<root> is not of type object` error
  → unfixable repair turn. Repairs: `repair_json_envelope()` +
  `diagnose_envelope()` (`codesec/json_utils.py`) — deterministic
  bracket completion/truncation with every fix recorded; `_validated_payload()`
  dispatch guard (object-root schemas never accept nested fragments;
  errors name the envelope problem); advisory normalization flattens
  nested gap arrays (equivalent) and QUARANTINES un-preservable advisory
  items (recorded, never silent); invalid findings envelopes are never
  coerced into empty reports; `AgentResult.repairs` → hunt stage records a
  `degraded` stage-health event; executor reads terminal stage health
  from `run/state.db` (`_h_stage_health`) — exit 0 without complete clean
  health ⇒ `failed_output`/`degraded_stage_health` (excluded from
  clean-completion rate; output still committed + scored).

Tests: `tests/test_realvuln_reliability_fixes.py` 36 passed;
`tests/test_advisory_envelope_repair.py` 11 passed (both saved failures
replay without loss: findings + advisories preserved, intervention
recorded); full suite `545 passed, 14 skipped` (unchanged skip set: 13
auth-CLI, 1 live-bench marker).

Post-fix reverification of all five review probes:
`reverify.py` → `reverify-output.json` (exit 0): late invalidation
verify-exit 1 + no headline; corrupt committed failed-output verify-exit
1 + 2 integrity problems + no headline; wrong marker identity verify-exit
1 + no headline; post-deadline output REJECTED for both arms;
ungated freeze exit 1.

## Step F — in progress

## Step F — Correct the record and prove actual-client failure handling — COMPLETE (2026-09-24)

| Command | Exit | Evidence |
|---|---|---|
| results-doc correction | 0 | dated CORRECTION block in `RESULTS-HARNESS-VS-PI-RELIABILITY-2026-09-23.md` (stale image citations → `calib-deadline-20260923-09` / `calib-neterror-20260923-07`; sign-off language withdrawn) |
| `PYTHONPATH=. … synthetic_cli_run.py /tmp/relfix-synth` | 0 | `synthetic-cli-results.json` + preserved experiment `synthetic-cli-experiment/`: freeze 0, run 1 (failures present), verify 0, aggregate 0 w/ headline (official matcher); late-invalidation → verify 1/aggregate 1; corrupt committed → verify 1/aggregate 1 |
| image builds | 0 | `codesec-iso-relfix-20260924` = `sha256:f08faaa8aaa775ead2aa54a7c8c540d63c6607a14033a180359fc3b3a87562ad`; `codesec-iso-relfix-deadgw-20260924` = `sha256:78d7e42bb3a52f66f27ed6988d9ccfcbab046c4b4a21c27d3e059749ba5a8820`; isolation suites 16/16 and 15/15 (`iso-evidence-relfix*.json`, runtime-tree bound) |
| isolation-suite test-tag audit fix | 0 | `test_agent_image_contains_allowlist_only` now uses unique `codesec-iso-test-*`; shared `codesec-iso:latest` tag restored to the matrix-pinned image |
| actual-client calibration runs | 0/1 | `f-evidence.json`: hs-01 clean smoke+parity (H completed 430 s, health clean=true, 5 findings; V 15.7 s, 6); hr-01 nonempty timeout recovery (211.9/240 s, 3 findings via operator-owned checkpoint capture, degraded); dh-03 H deadline 121.5/150 s checkpoint capture; dv-01 V deadline mid-flight 9 s → failed_no_output (paired, not equated); net-01 dead endpoint → attribution unknown by design (verify FAILED); dh-01 dead upstream w/ trusted records (H bounded 4-retry backoff). Usage recorded per experiment. 0 leftover owned containers after every run |
| final full suite | 0 | 555 passed, 14 skipped (0:08:28); skips outstanding: 13 auth-CLI, 1 live-bench |

Config endpoint temporarily repointed at test aliases during builds/runs and
restored byte-identical afterwards (`git diff config/…yaml` empty). Shared
gateway `codesec-gateway` never disconnected; matrix gateway records
untouched (headline recomputes exactly).

## Steps G+H — FP review and the one quality change — COMPLETE (2026-09-24)

- Selection BEFORE source inspection: `fp-sample-manifest.json` (seed
  20260924; 24/198 unique H claims, 28/218 occurrences, no undersupply; 6
  Pi comparison claims). Classification: `fp_classify.py` →
  `fp-classifications.json`; narrative `fp-review.md`.
- Result: reporting/matching 10, real-outside-labels 5, duplicate 5,
  incorrect-claim 4, unresolved 0. Dominant actionable cause:
  location/CWE reporting errors.
- One change: `_canonical_cwe` in `codesec/stages/report.py` (dev half
  only; seeded split `h-split.json`). Offline replay `h-replay.json`:
  TP +4, FP −4, zero TP regressions, controls untouched, reserved half
  untouched (uncertainty reported, no further tuning). Regression tests
  `tests/test_cwe_canonicalization.py`.
- Go/no-go: **NO-GO** for a new scored matrix now — see
  `RESULTS-RELIABILITY-FIXES-AND-FP-REVIEW-2026-09-24.md` §7.

Post-repair source_tree_sha256: `9632dded2bab8f23c2125f048840f466cfb3cf9d087f2ff9f75a737e4920ce03`;
neither it nor any post-run hash equals the frozen matrix code (provenance
distinction maintained).

## Post-plan closeout (2026-09-24)

- **Banked**: two commits — `909e3b2` (pre-existing post-matrix/repair-package
  state, byte-verified against the Step-A archive) and `3331e27` (the
  2026-09-24 reliability fixes + FP review). Post-repair state archived as
  `source-archive-post-relfix.tar.gz` (+ hashes) before committing.
- **Auth-CLI test skips DESCOPED** (13 in `tests/test_auth.py`): the frozen
  experiment runtime uses `--engine local` exclusively and never shells out
  to the claude CLI; installing it would add an unused heavyweight
  dependency. Skip messages now state the descope. The remaining live-bench
  marker skip stays by design.
