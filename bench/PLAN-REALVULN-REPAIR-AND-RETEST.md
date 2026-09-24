# Executable plan: repair and retest the RealVuln harness experiment

Status: **plan only; implementation and new inference runs have not started**.
Created 2026-09-22. Execute from `/home/user/g/codesec`.

Read [the audit](AUDIT-HARNESS-GLM53-REALVULN-2026-09-22.md) first. This plan
supersedes the old plan's execution, failure-handling, and rerun instructions for
the next experiment. It does not change historical scores or redefine historical
success. New interfaces named below are **implementation requirements**, not
commands that already exist.

The objective is a reproducible comparison of a repaired codesec configuration
with a vanilla Pi session on the same hosted model. Implement and test the
controls before spending a full matrix's inference budget. A negative result is
a successful experiment if the protocol was followed.

## 0. Instructions to the executing agent

1. Execute work packages P00–P12 in order. P13 is conditional local-backend work;
   it must not delay or contaminate the hosted comparison. Do not start parallel
   agents unless the user or applicable repository instructions authorize them.
2. Mark a package complete only when its listed tests and exit gate pass. Record
   commands, exit codes, evidence paths, deviations, and unresolved issues in
   `bench/realvuln/repair-progress.md` (create it). Never mark a gate passed from
   the presence of a file or an optimistic log message.
3. Preserve existing dirty/untracked work. There are pre-existing changes to
   providers, the engine, report membership, tests, and benchmark scripts. Do not
   reset, stash, clean, or replace them wholesale. Read their diffs before edits.
4. Do not inspect held-out source, labels, or scanner findings to tune prompts.
   An operator-only manifest builder may mechanically read label metadata.
5. Add regression tests for the failures specified here. A test that only checks
   whether a source file contains a flag or string is not adequate.
6. Never patch the frozen scorer to improve the headline. Never choose retries,
   report policy, thresholds, or a corpus after looking at their scores.
7. Save partial work and an exact blocker if a prerequisite is unavailable. Do
   not disable isolation, skip a failed gate, invent historical evidence, or
   silently substitute another model to keep going.
8. Before paid execution, inspect the user's current authorization and available
   quota. This document is not a request to incur API charges while merely writing
   or reviewing the plan. Once execution is authorized, do not repeatedly seek
   confirmation for the prescribed steps.

## 1. Freeze these decisions before implementation

These defaults remove choices that otherwise invite result-dependent changes.
An incompatible provider capability may require a documented revision during
calibration. Once scored execution begins, any such change requires a new
experiment ID and a new matrix.

| Item | Required decision |
|---|---|
| First experiment | Hosted GLM-5.3, repaired codesec vs vanilla Pi; source-only |
| Provider endpoint | `https://api.z.ai/api/coding/paas/v4`, same protocol in both arms |
| Model | `glm-5.3` on every request, including repairs and synthesis |
| Reasoning | Explicit enabled + `reasoning_effort=low` in both arms; never label this “off” |
| Sampling | Temperature 0.6; omit top-p in both; explicit 32,768 maximum output tokens/request |
| Client context ceiling | 262,144 tokens in both; verify server support; record different compaction behavior as a harness feature |
| Memory | Off; fresh process, HOME, Pi agent/session dirs, codesec run root per attempt |
| H concurrency | Cap four for all stages; naturally single-request stages stay at one |
| V concurrency | One native Pi session; no continuation messages or score-aware steering |
| H task caps | 20 initial Recon tasks; PyGoat 40; retain 2 Gapfill / 1 Feedback loop limits |
| Wall ceilings | Both arms: 7,200 s per repo; PyGoat 10,800 s; early normal completion allowed |
| H synthesis reserve | Last 20% of wall budget; stop new breadth work at 80% elapsed |
| Primary comparison | Configured-product quality and operational reliability, **not equal-compute architecture quality** |
| Primary H report policy | `confirmed_reachable`: confirmed canonical + valid reachable Trace |
| Secondary H policies | All confirmed canonicals; confirmed except unreachable; Hunt discovery |
| Report rendering | Deterministic from authoritative DB; optional LLM prose disabled for this experiment |
| Runtime target | None; no target deployment, no live probing, no upstream novelty filtering |
| Canary in scored corpus | None; retain old canary-bearing results unchanged; move canaries to unscored fixtures |
| First corpus | Existing frozen six apps, three trials, 36 arm cells; explicitly a regression matrix |
| Benchmark pin | `7a710251f55c17d32d3adcb13d37468e2e3b9e4a`; verify actual app SHAs and source bytes |
| Ordering | Seed 20260922; counterbalanced H/V order; no overlapping provider load |
| Primary score | Official matcher; strict micro F3 within each trial, mean over three trials |

The primary report-policy choice intentionally tests the original claim about
externally reachable shipped findings. Implement it as an **explicit experiment
option**, not a silent reversal of the existing ship-confirmed product default.
Emit all evidence tiers separately so nothing disappears from the review record.
Do not later promote whichever tier scores best to primary.

The primary experiment has equal wall ceilings, not equal actual token use. If a
claim about equal-compute advantage is wanted, create a separate protocol after
this work: a shared total-token/cost admission budget, native early stopping, and
any Pi continuation policy must be frozen before that separate matrix. Do not
force vanilla Pi to use time after it has completed its session.

Current provider behavior must be verified during P03 against official Z.AI docs
and captured requests. These are chosen experimental settings, not an assertion
that every existing client already supports them.

## P00 — Preserve evidence and establish a baseline

**Files:** historical artifacts, `bench/realvuln/audit_saved_run.py`, progress log.

Tasks:

1. Record `git status --short`, HEAD, binary diff against HEAD, and an inventory
   of untracked source files. Snapshot tracked plus relevant untracked source,
   prompts, schemas, config, tests, and scripts with file hashes. A HEAD hash alone
   does not identify this dirty workspace. Exclude credentials, auth files,
   caches, virtualenvs, and generated run directories from the source snapshot.
2. Inventory historical benchmark outputs and scored H databases without changing
   them. Capture SQLite consistently with its backup API if a DB has a live WAL;
   do not copy only `state.db` from an active writer. Stop or isolate active writers
   before declaring an immutable archive. Preserve original logs and timestamps.
3. Run the existing audit to a new path. Check the original F3 values 40.4/20.8/21.4,
   18 Dedupe fallbacks, 18 Report fallbacks, 340 confirmed, and zero missing traces.
   If artifacts differ, record why; never edit them to satisfy these expectations.
4. Run the current full offline test suite once and save failures as baseline.
   Diagnose any test that unexpectedly attempts external services; use an explicit
   marker for live tests rather than running them implicitly.
5. Create a staging directory and the experiments parent directory; leave the
   final experiment path absent until P11 `freeze` creates it. Do not reuse scanner
   tags `glm53` or `unsloth-qwen38-q4`. Restrict any archives containing credentials; preferably
   exclude credentials and retain only sanitized runtime records.

Existing commands:

```bash
git status --short
git diff --stat
.venv/bin/python -m bench.realvuln.audit_saved_run > /tmp/realvuln-before.json
.venv/bin/pytest -q
```

**Exit gate:** historical evidence and workspace state are recoverable; baseline
results are recorded; no historical scan output or DB has been modified.

## P01 — Repair Read/Grep/Glob behavior in blinded trees

**Files:** `codesec/local_agent.py`, `tests/test_local_agent.py`.

Tasks:

1. Apply ignored-directory rules to paths **relative to `repo_root`**, not to
   absolute parents. `/tmp/target/project/target/app.py` must remain searchable
   when the final `target` is the repo root. A nested ignored build directory
   `repo/target/generated.py` may still be excluded under the existing policy.
2. Centralize containment/exclusion logic so Grep and Glob agree. Resolve symlinks
   before accepting files; reject escapes outside the repo. Preserve deterministic
   ordering and current output caps.
3. When Grep's `path` is a regular file, search that file. When it is a directory,
   recurse. A nonexistent path returns an explicit error, not “no matches”.
4. Preserve line numbers, paging, binary-file behavior, and truncated-result
   notices. Make Glob's root/path semantics unambiguous.

Required behavior tests (invoke `_exec_tool`, not just helper functions):

- Root named `target`: Read, Grep, Glob all find known `eval(payload)` in `app.py`.
- Ancestor named `target`: same result with a differently named repo root.
- File-scoped Grep and directory-scoped Grep agree for the same file.
- Nested `.git`, `.venv`, and ignored build folders are excluded consistently.
- External symlink and `../` path cannot expose a host file; internal symlink
  behavior is deterministic and documented.
- Grep content/count/files modes work; long Read paging does not skip/repeat lines.
- Empty results, missing paths, and tool errors remain distinguishable.

Run `pytest -q tests/test_local_agent.py`. **Exit gate:** all tests pass; save the
three-tool reproduction showing successful results under an actual `target/` root.

## P02 — Bound synthesis inputs and make report membership deterministic

**Files:** `codesec/stages/dedupe.py`, `report.py`, `_common.py`, `codesec/state.py`,
`codesec/config.py`, report schema/prompts, Dedupe/Report/State tests.

Tasks:

1. Add explicit effective settings `report_policy` and `report_renderer` to config.
   Preserve existing defaults outside the experiment. The experiment selects
   `confirmed_reachable` + `deterministic`; record both in the run manifest.
2. Define membership once in State/Report, and reuse it for summary counts and
   export. Produce primary `report.json`, secondary `confirmed.json`, and
   `review_queue.json`. The review queue includes uncertain, untraced,
   unreachable, needs-more-info, and task/stage failures with explicit reasons.
3. A schema-valid LLM response must not remove DB-authorized members. Canonical
   file, line, CWE, validation state, and trace state come from DB, not prose.
   Empty findings are legitimate only if the selected membership set is empty.
4. Use deterministic report rendering directly, not as a caught exception. Do
   not invoke a Report LLM in the experiment. Label the revised pipeline honestly
   as one with deterministic report rendering.
5. Replace all-findings Dedupe payloads with a bounded descriptor per finding:
   stable ID, file/range, class/CWE, bounded description, bounded evidence,
   bounded validation summary, and truncation flags. Keep full evidence in DB.
   Never silently truncate a serialized JSON document.
6. Start with a 30,000-character complete Dedupe user-payload cap, below the
   engine's 50,000 guard. Size batches using the actual serialized wrapper too.
   Each descriptor must fit alone; otherwise emit a typed oversize error.
7. Partition first by normalized file and vulnerability class. Split oversized
   partitions into ordered batches; perform a bounded representative merge pass
   over within-partition groups. Assign every original finding exactly once.
   Do not concatenate all representatives into another unbounded request.
8. Across different partitions, conservatively retain separate groups. Record
   this algorithmic restriction; do not merge merely because line numbers or
   CWEs match. Any exact-duplicate prepass must use an explicitly tested
   fingerprint, not proximity alone.
9. Enforce the final partition contract: no unknown, duplicated, or lost IDs;
   every nonempty group has one member canonical. A failed batch may retain
   deterministic singleton groups **with a degraded-stage event**, not silent
   “success”. Keep all batch and merge artifacts with stable IDs.
10. Inspect other stage input builders for the same unbounded data pattern. Add
    size telemetry for every stage and bound verbose Recon context without
    deleting authoritative finding identity/location fields.

Required tests:

- 1, 60, and 200 synthetic confirmed findings with large evidence fields:
  no request exceeds the payload cap; every ID reaches one final group.
- Duplicates straddling two batches are considered by the merge pass; unrelated
  nearby bugs stay distinct under a mocked adjudicator.
- Unknown IDs, missing IDs, duplicate membership, empty partitions, model failure,
  and malformed merge output produce explicit, tested outcomes.
- Every evidence state yields the correct primary and secondary memberships.
- Primary excludes explicitly unreachable and uncertain findings, secondary keeps
  them with labels; existing default ship-confirmed tests still pass.
- Deterministic renderer makes zero model calls, validates schema, and has stable
  ordering by finding ID. Renderer failure is an error, never an empty success.

Use copies of saved small/large DBs for offline descriptor-size checks; do not run
new inference against or mutate historical DBs. **Exit gate:** no oversized request
in synthetic/history-derived fixtures; complete partition and membership tests pass.

## P03 — Make provider settings explicit and verify actual wire requests

**Files:** `codesec/config.py`, `providers.py`, `runner.py`, `local_agent.py`,
benchmark Pi configuration/runner, provider and local-engine tests.

Tasks:

1. Introduce provider-aware settings: reasoning enabled, reasoning effort,
   reasoning-history policy, context ceiling, temperature, output cap. Do not use
   one generic `thinking: bool` to encode incompatible provider protocols.
2. For this Z.AI experiment send `thinking.type=enabled`, `reasoning_effort=low`,
   and an explicit supported history-preservation setting. Do not send local
   llama.cpp chat-template kwargs as the hosted reasoning control.
3. Preserve streamed `reasoning_content` when required by the chosen protocol,
   including tool-call turns; serialize it on later requests consistently with
   Pi. Keep non-reasoning providers and content/tool-only SSE working. Record
   reasoning-token usage where supplied, not fabricated zero values.
4. Configure Pi using an isolated provider/model definition and supported client
   options. Verify the installed version's actual request builder. Do not edit
   global `node_modules` in place. If a pinned client patch is unavoidable, vendor
   the patch and label the client build; do not change its review strategy.
5. Build an operator-side inference gateway/request recorder used by both arms.
   It forwards to exactly one allowlisted provider/model, logs sanitized effective
   parameters and usage, and does not rewrite differing settings into apparent
   equality. Reject a mismatch before forwarding it. Keep credentials out of
   agent-visible artifacts, source snapshots, and normal logs.
6. Request records need experiment/cell/attempt/request IDs, stage when known,
   model/endpoint/protocol, relevant request settings, timestamps, stop reason,
   usage including cache/reasoning if available, retries, and HTTP errors.
   Session role/message counts or hashes can prove history transport without
   publishing private reasoning text. Retain tool transcripts separately.
7. Hash the canonical effective configuration, not the path to a mutable YAML
   file. Catch conflicts where `--model` changes stage labels but an attached
   `ModelProfile` still overrides the actual request with another model.

Tests and gate:

- Mock-SSE tests: chunked reasoning plus content plus tool calls, missing usage,
  malformed events, truncation, terminal error, and next-turn history transport.
- Mock HTTP server captures requests from **the real codesec and real Pi clients**
  for a tiny file-read/tool-response task. Assert the selected controls match.
- A deliberate wrong model, effort, or endpoint is blocked by the gateway.
- Credential-like strings are absent from normal logs and artifacts.
- Before live calibration, run one tiny real tool round-trip per client through
  the gateway. Check current official Z.AI documentation; archive URL/date and
  the relevant parameter facts. Actual records, not CLI flags, determine parity.
- If a required parameter is unsupported, stop calibration, revise the protocol
  once with a reason, and repeat both client probes. No silent fallback to defaults.

**Exit gate:** both clients have verified requests under the same chosen settings;
no scored call can escape request validation.

## P04 — Separate static and live evidence, then repair Trace contracts

**Files:** `prompts/01-recon.md`, `02-hunt.md`, `03-validate.md`, `03-arbiter.md`,
`06-trace.md`; `codesec/stages/_common.py`, `trace.py`; `codesec/contracts.py`;
Trace schema, context/contract/Trace tests.

Tasks:

1. Add explicit `evidence_mode=static|live`; static inputs contain
   `live_target: null` and `markers: null`. Select static prompt variants for all
   relevant stages. Remove concrete example hosts/credentials/marker tokens from
   static prompts. This problem is not limited to `06-trace.md`.
2. Static prompts allow source evidence and isolated local PoCs where stage tools
   permit them. They must not demand an HTTP round trip, infer a deployment from
   an example, or call an external host. Runtime egress is denied by P06.
3. Live mode retains its separate marker/auth-on-the-wire requirements. Test
   this path even though it is outside the initial matrix; do not weaken live
   evidence controls while repairing static mode.
4. Trace input explicitly names the authoritative sink file and range. Instruct:
   investigate backward if useful, but serialize `call_chain` from external entry
   to sink, with the final frame at that supplied sink location.
5. Permit a one-frame chain when the handler itself is both entry and sink, with
   consistent entry-point/input evidence. Update schema and semantic validator
   together. Do not manufacture a second callsite to satisfy the old minimum.
6. Keep executable frames repository-local and validate file existence/ranges.
   Put dependency/framework boundary assumptions in a separate annotation field;
   do not pretend installed dependency paths are repo files. A genuinely
   unresolvable boundary remains uncertain.
7. On semantic failure, provide a structured repair message with finding ID,
   exact failed invariant, authoritative sink, and the invalid payload. Allow
   at most two repairs, counted against normal time/token budgets. Revalidate
   schema and semantics each time; preserve all attempts.
8. After exhausted repair, store `uncertain` with a machine-readable reason such
   as `sink_mismatch`, `missing_repo_frame`, or `repair_exhausted`. Do not mark
   unreachable because of an engine failure. Never auto-reverse or move frames
   into the required range without validated model/source evidence.
9. Preserve a separate field for source-level uncertainty versus operational
   failure. Review all missing/uncertain states in final diagnostics.

Required fixtures: valid multi-frame trace; direct one-frame route; reversed
chain; wrong sink range; out-of-repo dependency; missing file; invalid line;
auth-gated but reachable route; dead branch with concrete blocker; static trace
without markers; live trace lacking its required verified marker; semantic repair
success; repair exhaustion; repair interrupted by deadline.

**Exit gate:** static paths never require a marker, bad traces are not promoted,
valid simple traces pass, and live-mode requirements remain enforced.

## P05 — Enforce deadlines and record stage health

**Files:** `codesec/orchestrator.py`, `runner.py`, `local_agent.py`, `state.py`,
stage scheduling code; orchestrator/runner/runtime tests.

Tasks:

1. Replace the ambiguous closing fraction with `synthesis_reserve_fraction=0.20`.
   Enter closing at elapsed >= 80% of the total budget. Use a monotonic clock.
2. Pass a common absolute deadline to all stages, calls, repairs, retries, and
   tools. Bound request/socket/tool timeouts by remaining time. Backoff must not
   sleep past the deadline or restart a request after budget exhaustion.
3. Stop admitting new Hunt/Gapfill/Feedback breadth work at closing. Deduplicate,
   trace existing canonicals, and render within the remaining budget. Incomplete
   work gets an explicit status. Never silently relabel skipped tasks as done.
4. Reserve the final 30 seconds for deterministic snapshot/export. Stop model
   work by that point. Enforce an outer process/container deadline at the full
   cap, with at most 30 seconds of cleanup grace reported separately.
5. Cancellation must actually stop work. `asyncio.to_thread` cancellation does
   **not** stop its urllib call or child shell. Use deadline-aware I/O and a
   controllable process boundary where required; terminate the trial's process
   group/container, never broad `pkill -f` or unrelated GPU services.
6. Preserve atomically written report checkpoints during the run. A deadline
   must leave a well-defined latest primary snapshot or a documented no-output
   failure. Do not generate a new Pi answer by querying it after its cap.
   Have the supervisor retain each schema-valid Pi findings file after a completed
   write; a later truncated overwrite must not destroy the previous valid snapshot.
   Do not accept a file while it is still being written. Record each snapshot's
   capture time/hash and use only snapshots made before the deadline.
7. Add stage-health records: intended implementation, start/end, success,
   deliberate skip, fallback, input size, repair counts, error category, and
   effective model/profile/concurrency. Distinguish `complete`, `budget_limited`,
   `degraded`, and `failed`. Any final DB migration must be backward compatible.

Required tests use fake clocks and a fake hanging server/process:

- Two-hour budget: not closing at minute 24; closing at minute 96.
- Three-hour budget: closing at minute 144.
- Queued jobs, running model calls, retries, tools, and semantic repairs honor
  the same deadline; no orphan request/tool process remains after cleanup.
- A failed Dedupe batch and task failure appear in the stage ledger even if a
  valid report exists. Deterministic Report is “intended”, not “fallback”.
- Timeout export is valid/atomic; renderer failure cannot produce empty success.

**Exit gate:** fake hangs terminate within cap + 30 s grace and produce accurate
status; full stage health is visible without interpreting free-text logs.

## P06 — Enforce operator/agent isolation and paired corpus integrity

**Files:** `bench/realvuln/blind_prepare.py`, `common.py`, setup/runner scripts;
new `isolation.py` and a pinned container build; isolation/corpus tests.

Tasks:

1. Use a separate sandbox/container per arm attempt with a nonprivileged user,
   read-only prepared `/work/target`, empty writable scratch, and an opaque output
   path. No host home, `.git`, benchmark checkout, operator maps, prior runs,
   container socket, host PID namespace, sudo, or privileged capabilities.
2. The agent process may see the installed harness and its own stage artifacts;
   it must not see the whole codesec working checkout, its bench directory, or
   labels. Build/install from a source allowlist, not `COPY .` of this workspace.
3. Block general network egress. Allow only the P03 inference gateway on a private
   network; it supplies the provider credential outside the agent container.
   The gateway accepts only the intended inference routes/model, not arbitrary
   upstream URLs. Remove inherited proxy/cloud credentials and host settings.
4. Prepare one source bundle per `(repo, trial)` and use byte-identical copies
   for H and V. Keep identity stripping consistent; preserve source paths and
   line numbers. Do not insert canaries into the new scored bundles.
5. Verify actual app checkout HEAD against the pinned GT SHA and verify a clean
   source tree before copying. Verify every primary and acceptable GT location
   remains present with unchanged original source bytes/lines after preparation.
   Record file inventory, permissions, symlinks, removed files, and tree digest.
6. Follow a single policy for symlinks: allow only links resolving inside the
   prepared tree; reject dangling or escaping links before running. Tree hashes
   must include relative paths and symlink targets, not only regular files.
7. Make source read-only via mount, not merely chmod. Verify digests before/after.
   Pair digests must be equal. Operator maps remain outside all agent mounts.
8. For unscored canary fixtures, record the exact inserted interval and ensure no
   overlap with any GT acceptance window, including acceptable locations. If
   retaining ±10 canary filtering for compatibility, require >20-line separation
   of the relevant ranges. An uncalled canary is an attention diagnostic only.
9. Use a separate synthetic reachable mutation fixture to test source reading and
   static reachability. Do not use canary misses to label an arm as cheating.
10. Measure identity mentions in equivalent model-authored final descriptions
    for both arms; separately measure assistant narrative if available for both.
    Exclude tool output, paths, framework logs, and operator metadata from that
    metric. Save source residual-identity inventory separately. Do not impose an
    outcome-based trial exclusion for model recognition.

Negative tests must execute **through the same Bash/tool boundary used by agents**:
read a secret sentinel in host home, operator map, GT, previous-run directory,
`/proc` outside namespace, and network endpoints other than gateway. They must
fail. Source writes and symlink escapes must fail. Normal tool reads, scratch
writes, output publication, and inference-gateway calls must succeed.

**Exit gate:** signed-off isolation test JSON, equal pair digests, verified pins,
and no GT/operator material in the installed image or agent mounts. If the host
cannot provide this isolation, block scored execution instead of relying on cwd.

## P07 — Implement immutable experiments, an attempt ledger, and atomic exports

**Files:** all `bench/realvuln/run_*.sh`, `common.py`, adapter;
new `experiment.py`, `ledger.py`, manifest schemas and tests.

Use this layout; operator files must not be mounted into agents:

```text
bench/realvuln-runs/experiments/<experiment-id>/
  operator/manifest.json
  operator/manifest.sha256
  operator/schedule.json
  operator/prepared-bundles.json
  operator/attempts.jsonl
  attempts/<opaque-attempt-id>/...
  committed/<opaque-cell-id>/completion.json
  committed/<opaque-cell-id>/primary.semgrep.json
  committed/<opaque-cell-id>/secondary-*.semgrep.json
  reports/...
```

A cell is `(experiment_id, corpus_id, repo_id, trial, arm)`. An attempt is a unique
execution of that cell; it has its own source/runtime/output roots. Paths visible
to the agent use opaque IDs only.

Manifest fields required:

- Protocol version, experiment ID, source snapshot hash, dirty diff hash, all
  prompt/schema/config hashes, dependency lock/image digests, Python/Pi versions.
- Benchmark/scorer/adapter hashes, exact app SHAs, scored/non-scoring label counts,
  frozen repo list, cohort (calibration/regression/heldout), and pair tree digests.
- All settings from section 1; resolved per-stage profiles; effective endpoint
  and reasoning settings; report policy; budget/deadline semantics.
- Expected cells, schedule seed/order, retry rules, failure-scoring rules,
  primary metric, thresholds, and secondary analyses.
- Preparation/isolation/preflight evidence hashes; creation timestamp; no secrets.

Tasks:

1. Use one run-root resolver in shell and Python; honor `CODESEC_REALVULN_RUNS`
   consistently. Pass explicit paths rather than depending on import-time globals.
2. Replace shared `failed-trials.txt` with an append-only, locked ledger. Events
   contain IDs, timestamps, configuration hash, status, reason code, exit status,
   artifact hashes, and attempt-selection reason. Never truncate failed history.
3. Model-call transient retries are bounded inside a cell (max three retries,
   deadline-aware). Schema/semantic repairs are distinct events. No automatic
   fresh-cell retry for task failure, poor recall, fallback, or no findings.
4. Once a cell has made its first inference request, its first execution is the
   operational primary. Process/server/provider failures remain visible. A later
   diagnostic rerun gets a new attempt but cannot replace it in the primary score.
5. Pre-inference setup failures may be retried once after fixing an operational
   issue; no model output has then been observed. If source/config/protocol changes,
   create a new experiment manifest. Audit all retries regardless of eligibility.
6. Write all result files to a temporary attempt-export directory. Validate them,
   hash them, then atomically rename the directory on the same filesystem and
   write its completion record. A completion record is the final commit marker.
7. `arm_done` must verify the marker, artifact hashes, schema, attempt selection,
   and matching experiment/config hashes. A leftover Hunt file or truncated JSON
   is not completion and must not prevent an eligible retry.
8. Export primary and secondary H outputs from authoritative DB/finalized reports,
   not all historical `final_payload` records. A rejected/retried artifact must
   not silently overwrite the accepted finding. Log source provenance per finding.
9. Tighten adapter validation: findings must be a list of objects; normalized
   paths must stay inside target; reject internal traversal, nonexistent files,
   booleans as line integers, inverted/out-of-file ranges, and invalid CWE shape.
   Count every dropped item with a stable reason. Freeze any syntax-only JSON
   escape repair and apply it symmetrically; never infer missing locations/CWEs
   from GT. Valid `findings: []` is different from missing/malformed output.
10. Smoke must fail if either arm, export, or required health gate fails. Matrix
    execution may finish other eligible cells, but its exit/report must retain
    failures. Do not print `wave ok` merely because the loop terminated.

Required failure-injection tests:

- Failure before output; failure after Hunt export but before Final; crash during
  completion write; malformed output; valid empty output; wrong experiment hash.
- Different tag/root/model cannot reuse another run's artifacts or retry ledger.
- All nonzero exits remain visible even when a report exists.
- Resume is idempotent; two controllers cannot run/commit the same cell twice.
- Missing metadata invalidates completion; cross-arm source digests must agree.
- Two retries with same finding ID use only the explicitly accepted payload.
- Adapter traversal, invalid types, canary legacy boundary, and metrics-sidecar
  cases cannot change the scored set silently.

**Exit gate:** the failure-injection matrix passes and no shell helper can bypass
the manifest/ledger/commit-marker checks.

## P08 — Make aggregation complete, paired, and honest about failures

**Files:** `aggregate.py`, `derive_counts.py`, new aggregation tests.

Tasks:

1. Drive aggregation from `manifest.expected_cells`. Do not discover the matrix
   by globbing `run-*.json`. Reject extra trial IDs, wrong scanner/config hashes,
   duplicate cell assignments, missing completion metadata, and corrupt artifacts.
2. Count GT positives/decoys only when `scoring != non_scoring`; report the excluded
   counts separately. The present count helper counts non-scoring entries twice
   conceptually; fix it before extending beyond this six-app corpus.
3. Distinguish an unaccounted cell from a recorded failure. If any expected cell
   lacks a terminal ledger state, write a progress report with `headline: null`
   and exit nonzero. Do not report means over available subsets.
4. For the operational primary, include every scheduled cell after its first
   inference request: score its last valid primary snapshot; if no valid snapshot
   exists, use empty predictions (all scored positives FN, decoys TN), and mark
   `output_failure`. Do not label this synthesized empty set as agent-authored.
5. For unrecoverable setup failure with zero inference, report the experiment
   incomplete and block the primary headline. Do not silently reduce the corpus.
6. A protocol breach (wrong model, mutable input, leaked GT, incompatible config)
   invalidates the comparison and blocks its headline; it is not repaired by
   assigning zero. Preserve the record and rerun under a new valid experiment.
7. Separately report complete-pair-only diagnostic scores with sample sizes and
   excluded IDs. Never use this survivorship-prone subset as the primary.
8. Pool TP/FP/FN/TN across the exact repo list within each trial; use the official
   metric formula/rounding, then mean the three trial F3 values. Keep raw counts.
9. Implement the original positive decision exactly:
   `(F3_H >= F3_V + 5 OR (R_H >= R_V - .05 AND P_H >= P_V + .10))`
   **AND** fewer H FPs on >=4/6 repos in >=2/3 trials. Strictly fewer; ties do not
   count. A secondary report policy cannot satisfy the primary gate on its behalf.
10. Decision precedence: protocol invalid/incomplete first; then positive rule;
    then “does not meet success criterion”. Report the original negative-condition
    boolean and trial ranges separately; overlapping ranges are not a significance
    test and must not override a mechanically computed rule.
11. Export per-repo/trial counts, macro sensitivity, famous/obscure splits,
    per-CWE/severity recall, actual resource use, completion/fallback rates, and
    stage attrition. Missing usage is `unknown`, not zero cost. Reconcile gateway
    usage with engine/session totals including failures, repairs, and retries.
12. Classify benchmark FPs as labeled decoy, duplicate-positive match, or unmatched.
    Preserve official classifications. Optional human adjudication is blind to
    arm/model and secondary; no LLM judge or edited GT in the headline.
13. Preserve deterministic finding order. Optionally reverse/shuffle with a fixed
    seed to measure greedy-matcher sensitivity, labeled secondary only.

Required tests: missing one of three trials; only metrics sidecars; extra trial;
unequal repo coverage; zero predictions; failed H versus successful V; six-repo
162-positive denominator invariant; non-scoring labels; FP ties; full decision
truth table; wrong config; reproducible output ordering. Use a tiny fake scorer
fixture for failure logic plus a read-only integration check against the pin.

**Exit gate:** no partial matrix can be presented as a complete comparison;
every primary denominator and failure policy is checked by behavior tests.

## P09 — Build the automated preflight gate and run offline verification

**New interface:** `python -m bench.realvuln.experiment preflight --spec SPEC
--output DIR --offline`. Implement it; do not assume it exists.

It must run/validate P01–P08 evidence and produce a machine-readable checklist
with `passed`, `failed`, or `not_run` per gate. `not_run` is not success.
Checks include tools, stage contracts, payload sizes, deterministic report,
deadline kills, adapter/export failures, complete-cell aggregation, source pins,
isolation, and mock wire parity.

Create focused tests where absent:

```text
tests/test_realvuln_manifest.py
tests/test_realvuln_ledger.py
tests/test_realvuln_aggregate.py
tests/test_realvuln_isolation.py
tests/test_realvuln_preflight.py
tests/test_benchmark_deadlines.py
```

Run all affected unit tests, then the full offline suite once. Run the isolation
integration tests in the exact pinned image/runtime intended for the matrix.
Do not substitute mocked permissions for the negative access tests. Save test
reports and source hashes. Re-run only affected checks after subsequent fixes,
then repeat the final gate if the frozen source snapshot changes.

**Exit gate:** offline preflight passes with no required check skipped. Historical
audit still reproduces from archived inputs under its archived scorer/adapter;
do not require old adapter compatibility from newly tightened code.

## P10 — Unscored hosted calibration, then freeze the experiment

Calibration corpus: the existing smoke app, VAmPI, and PyGoat. These are already
development-visible; no held-out source/labels are used. Run one H/V pair on each.
Keep calibration in its own experiment namespace and out of all scored globs.

Steps:

1. Run P03 live request parity probes through the production isolation/gateway.
2. Run the smoke pair; require proper completion, no unexpected stage fallback,
   valid exports, and tool/read evidence. Do not evaluate success using F3.
3. Run VAmPI and PyGoat pairs with the final intended concurrency and budgets.
   Check actual workload size, bounded Dedupe payloads, Trace reason codes,
   deadline finalization, and memory/usage records.
4. Preflight must additionally exercise a short artificial deadline and intentional
   network error. A normal run alone cannot prove timeout/retry behavior.
5. Required calibration pass conditions: no broken/disabled search; zero context
   overflow; zero unintended Dedupe/Report fallback; valid global partitions;
   no invented live-target accesses; zero wrong-profile requests; no isolation
   failure; all exports and metadata valid; no surviving process after deadline.
6. Static semantic uncertainty may remain. Review its reason taxonomy. Invalid
   output after repair is operationally degraded, not evidence uncertainty; it
   fails the clean calibration gate. Do not loosen checks to improve a score.
7. Fix a failing gate and repeat the affected calibration plus dependency gates.
   Archive every calibration attempt. After two failed calibration cycles for
   the same unresolved defect, report the exact blocker rather than launch a
   full matrix or indefinitely retry the model.
8. Save all settings explicitly in `protocol-v2.json`. Freeze source/image/config,
   schedule, manifests, and test evidence. No mid-matrix concurrency/model/prompt
   changes. Any new fix starts a new experiment ID.

Budget accounting: the hosted regression matrix contains 36 cells with a combined
wall ceiling of **78 hours**, plus at most 18 minutes cleanup grace if every cell
needs it. Calibration adds at most **14 hours** at the selected caps. These are
upper bounds, not forecasts. Before launch, estimate tokens/plan-quota use from
calibration and record remaining capacity; the gateway should stop new cells if
the authorized experiment-level expenditure/quota limit would be exceeded.
No currency limit should be invented when the subscription's billing basis is
unknown. Paused-for-quota cells remain unaccounted until completed or the run is
reported incomplete.

**Exit gate:** the spec is ready to freeze, with all required live/offline gates
passed against its exact source/configuration. P11 performs `freeze` once; that
command must independently validate the gate evidence before creating the output.

## P11 — Execute the six-repo regression matrix and publish its result

Implement the following **new command contract** in `experiment.py` and cover it
with CLI tests. Use explicit experiment paths; do not wrap the old unchecked
matrix and assume its outputs satisfy the new contract.

```bash
# P10 must have created this file. The EXP path must not already exist.
SPEC=/home/user/g/codesec/bench/realvuln/protocol-v2.json
EXP=/home/user/g/codesec/bench/realvuln-runs/experiments/glm53-repaired-regression-v2-20260922-01
.venv/bin/python -m bench.realvuln.experiment freeze --spec "$SPEC" --output "$EXP"
.venv/bin/python -m bench.realvuln.experiment run --experiment "$EXP"
.venv/bin/python -m bench.realvuln.experiment verify --experiment "$EXP"
.venv/bin/python -m bench.realvuln.aggregate --experiment "$EXP" --json-out "$EXP/reports/aggregate.json"
```

`freeze` must refuse existing output. `run` may resume only eligible pending cells
under the same hash. `verify` checks ledger/artifact integrity and protocol, not
whether H wins. Commands must print useful failure paths and return nonzero on
invalid/incomplete execution. A fully accounted operational failure may be
aggregated, but must never be displayed as a clean matrix.
If the proposed experiment path already exists, inspect it: resume only if its
frozen hash matches; otherwise choose the next unused numeric suffix and document
why a new experiment is needed. Never delete the existing directory to make the
example command succeed. A resume starts at `run`, not at `freeze`.

Schedule algorithm: sort the six slugs; generate each repo's three paired blocks;
choose H-first counts of 2 for three seeded-selected repos and 1 for the other
three; randomly assign those orders to trials, then shuffle the 18 blocks with
the same recorded seed. Execute the two arms of each block consecutively. This
gives 9 H-first and 9 V-first blocks, with no temporal order chosen from outcomes.

During execution:

- Check manifest/image/source/gateway hashes before each cell.
- Preserve first-attempt output and stage health; use the retry rules in P07.
- Pause new admissions on persistent provider outage, quota exhaustion, or detected
  protocol breach. Do not terminate unrelated host services or change concurrency.
- Investigate operational status without scoring intermediate cells for tuning.
- After all terminal outcomes, verify digests, cell count, model settings, process
  cleanup, and resource usage. Generate the complete report from structured data.

Write `bench/RESULTS-HARNESS-GLM53-REALVULN-REPAIRED-<date>.md` containing:

1. Experiment ID/hashes, source changes, intended report policy, and cohort label.
2. All 18 pair outcomes, failures/degradation, missing-usage notices, and retry log.
3. Primary micro F3/P/R plus per-trial counts and the exact decision-rule booleans.
4. Per-repo deltas; macro sensitivity; famous/obscure and CWE/severity breakdowns.
5. Hunt → validated → canonical → Trace states → primary membership → adapter →
   scorer attrition, distinguishing rejected candidates from operational losses.
6. FP taxonomy and optional blinded secondary adjudication; canary claims omitted.
7. Total and per-cell tokens, reasoning/cache usage when known, latency, retries,
   completion rate, and fallback rate. No claim of equal actual compute.
8. Secondary report-policy ablations, clearly separated from the decision.
9. Original versus repaired results labeled as an engineering regression; changes
   to prompts, settings, rendering, canaries, and budgets prohibit attribution of
   the entire gain to any one fix. A causal fix ablation would require its own run.

**Exit gate:** complete, reviewable result even if H loses. Do not change anything
and rerun until the original success criterion happens to pass.

## P12 — Confirm on an untouched cohort, if a confirmatory claim is required

Do this after the implementation is frozen, regardless of whether the six-repo
regression looks favorable. Do not select a held-out set based on observed wins.

1. Build an exposure inventory of apps whose source, GT details, or results were
   inspected during development/calibration. Exclude those from confirmation.
   “Obscure” is not the same as unexposed.
2. From the remaining Python community apps at the same benchmark pin, select six
   deterministically with seed 20260922 using metadata only. Stratify by framework
   and source-size bucket if feasible; freeze selection and counts before scanning.
   If fewer than six unexposed apps remain, report that confirmation is unavailable
   under this design; do not quietly reuse inspected apps.
3. Keep the same source/image/prompt/config/report policy and six-repo success rule.
   Apply the general 2-hour cap and 20-task cap to every new app. The original
   PyGoat exception does not extend to new apps. Do not invent larger budgets
   after a difficult run; a different size-based budget policy would need a
   separate preregistered experiment.
4. Run 3 trials per app and both arms with new manifests/opaque targets, same
   counterbalancing, same failure rules, and the full verification/report workflow.
5. If a defect requires a result-informed repair, the cohort becomes development
   data for that revision. Do not describe a subsequent rerun as untouched.
6. Report six apps as six corpus units, not 18 or 36 independent applications.
   Three trial ranges measure stochastic variation; they are not a confidence
   interval. No broad security/product superiority claim from a small educational
   corpus and no public leaderboard claim under a modified protocol.

**Exit gate:** confirmatory report with a documented exposure boundary, or an
explicit statement that no valid untouched confirmation was performed.

## P13 — Local Unsloth backend: separate conditional experiment

Only execute if local retesting is in scope after hosted controls are working.
Reuse P01–P09 and the artifact protocol, but freeze a separate manifest/tag and
do not combine local and hosted trials into one headline.

1. Inventory GPU/unified memory owners. Obtain exclusive capacity without killing
   unrelated jobs automatically. Record available RAM/VRAM before server load.
2. Record GGUF repository/revision, local file hash, quantization, tokenizer/chat
   template, server binary/version/build, full effective arguments, and client
   config. No moving model alias as the only provenance.
3. Run the server under a supervisor independent of the agent/task wrapper.
   Use a dedicated service/process group with health/restart logs. `setsid` alone
   does not prove survival across every parent/container lifetime.
4. Start with one decode slot and H concurrency one. Use the same local model and
   request controls for both arms. This is a separate configuration, not an excuse
   to alter the hosted matrix. Verify actual thinking disabled at the local chat
   template and request level if that is the frozen local policy.
5. Verify effective context and output reservation via logs plus a real near-limit
   request. Test the largest prepared stage input, tool loop, compaction, and
   two-hour deadline handling under the intended slot/concurrency settings.
6. Run at least a 30-minute load/health check and a separate launcher-exit survival
   check. A server restart during a scored cell remains an operational failure;
   do not silently join outputs from different server configurations.
7. Calibrate small and large apps. If latency prevents useful completion, revise
   local budgets before freeze and apply them symmetrically. Do not report a
   partial surviving-repo mean as H quality.
8. Run the complete local matrix only after gates pass. Aggregate using its manifest
   and tag; reject attempts to overwrite hosted aggregate files.

**Exit gate:** complete local comparison under its own protocol, or documented
incomplete experiment with no selective H headline.

## 2. Completion checklist and audit coverage

The executing agent must link actual evidence in the progress log for each row.

| Finding / risk | Mitigation | Required evidence |
|---|---|---|
| `target/` disables search; file Grep broken | P01 | Actual tool behavior tests |
| 50k synthesis cap; singleton fallback | P02 | Large-input batching and partition tests |
| Report omissions / changed evidence standard | P02, section 1 | Explicit policy and deterministic membership tests |
| Wrong sink / dependency / direct-call Trace contract | P04 | Positive, negative, repair fixtures |
| Imaginary live host / marker in static review | P04, P06 | Static prompt inputs + blocked egress tests |
| Reasoning/model/profile mismatch | P03 | Actual client request captures and gateway enforcement |
| Lost reasoning transport / unknown usage | P03, P08 | SSE round-trip tests and usage reconciliation |
| Closing at 20%; deadline overrun | P05 | Fake-clock and real hanging-process tests |
| Mid-run concurrency drift | P07, P10 | Immutable per-stage config hashes |
| Budget/one-shot mischaracterization | Section 1, P11 | Explicit estimand and actual usage table |
| Partial aggregation / denominators | P08 | Missing-cell and failure-scoring tests |
| Smoke false success / swallowed failures | P07, P09 | CLI failure-injection tests |
| Partial export / stale reuse / retry contamination | P07 | Atomic commit and scoped-ledger tests |
| Root override mismatch | P07 | Custom root end-to-end CLI fixture |
| Unverified pins / lines / acceptable locations | P06, P08 | Source and scoring manifest verification |
| Retry-transcript Hunt contamination / adapter loss | P07 | Authoritative export and drop-provenance tests |
| GT/maps accessible to Bash | P06 | Negative access tests through real runtime |
| Unequal paired canaries / overlapping filters | P06 | Equal digests; separate canary fixtures |
| Asymmetric identity metric | P06 | Equivalent model-output fields tested |
| FP labels, duplicate/order sensitivity | P08 | Unchanged headline plus secondary taxonomy |
| Post-hoc overclaim / tiny rerun / held-out leakage | P11–P12 | Full regression + exposure-controlled confirmation |
| Server lifetime / effective KV / shared GPU | P13 | Independent supervision and load checks |
| Missing manifests / reproducibility | P00, P07, P10 | Snapshot, hashes, ledger, repeatable report |

Final handoff must say exactly which packages were completed, which matrices
actually ran, whether either primary success criterion passed, what remains
blocked, and where all evidence lives. A plan, a passing unit suite, an offline
membership ablation, or a two-repo pilot alone is not a completed retest.
