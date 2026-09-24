# Review of the repair execution — 2026-09-23

**Verdict: substantial implementation progress, but not ready for the full
calibration or scored matrix. “P00–P09 fully complete; no known defect” is not
supported by the implementation and saved evidence.**

The original search failure is repaired, bounded Dedupe/report policy work is
present, and static/live Trace separation has meaningful tests. The smoke artifacts
contain four primary findings, four confirmed findings, and a checkpoint. None of
this establishes that failure handling, provenance, or scoring admission is sound.

I ran 154 focused existing tests: all passed. I also reproduced the failures below
outside those tests. No live inference requests were made. Historical results,
application source, and the running gateway were not changed. The timeout probe
created one temporary sleep-only container and explicitly removed it afterward.

Evidence directory:
[`realvuln/repair-evidence/review-2026-09-23/`](realvuln/repair-evidence/review-2026-09-23/).
The `reproduce.py` script uses temporary fixtures and mocks for gate-control tests:

```bash
PYTHONPATH=. .venv/bin/python bench/realvuln/repair-evidence/review-2026-09-23/reproduce.py
```

These reproductions document **undesired current behavior**, not passing
acceptance tests. Convert each into a regression test whose expected behavior is
the corrected one. The separate real-container result is in
`container-timeout.json`; artifact/CLI checks are in `saved-artifact-checks.json`.

## Blocking findings

### R1 — P05/P07: the outer timeout does not stop the container

**Priority P1.** `isolation.py:584` applies `subprocess.run(timeout=...)` to the
Docker CLI. There is no container name/CID handle and no `finally` block that stops
or removes the running container. Killing the client does not terminate the
container. `execute_block` does not catch `TimeoutExpired`, so it also fails to
record a terminal attempt and export the last valid output.

**Reproduction:** `run_isolated` on a sleep-only container with a two-second cap
raised `TimeoutExpired`; the matching container was still running afterward.
I removed only that review-owned container. This can leave model/tool work running
beyond budget and overlapping subsequent trials.

The internal deadline also passes `deadline.absolute()` rather than the snapshot
cutoff to the local engine; `_chat` adds 30 seconds to remaining time and applies
an idle socket timeout, not a streaming wall deadline. A continuously streaming
response is not guaranteed to stop for the final snapshot reserve.

**Required correction:** supervise the actual container with a known identity;
stop it at the model-work cutoff/cell cap as appropriate, force removal after a
bounded grace period, recover ownership in `finally`, and always record a terminal
ledger state. Enforce the deadline during SSE consumption and retries as well.
Test a hanging container and a slow continuously streaming mock provider through
the full executor, not only Bash subprocess cancellation.

### R2 — P05/P07/P10: checkpoint retention is not connected to export

**Priority P1.** `executor.py:181` requires `report.json` and ignores
`report.checkpoint.json`. The saved `calib-deadline-20260922-01` H attempt is actually
ledgered `failed_no_output` with “missing H report”, even though a schema-valid
checkpoint exists. The reported deadline exercise did not pass end-to-end snapshot
recovery. Its checkpoint has zero findings in this particular run, but the same
path would discard a nonempty checkpoint.

For V, `executor.py:233` calls `retain_snapshot` only after the container returns.
There is no in-run watcher, no deadline passed, and no use of
`latest_valid_snapshot`. A previous valid snapshot followed by a truncated final
write raises `AdapterInputError` instead of using the saved valid output. This
exception is not caught by `execute_block` either.

`snapshot.py:59` validates/hashes one read but then copies the source file again,
so a concurrent rewrite can make the stored bytes differ from their recorded
hash. Its latest-snapshot selector trusts metadata without checking the referenced
file, hash, or schema.

**Required correction:** export the newest valid, pre-deadline H checkpoint or
final; capture V snapshots during execution and recover the newest valid snapshot
after exit/timeout. Atomically store the exact bytes that were validated and
revalidate on selection. Add full-executor tests for nonempty H checkpoint-only
output, V valid-then-truncated output, missing final files, and post-cap writes.
Repeat deadline and dead-gateway exercises for **both** real clients afterward.

### R3 — P07: first-attempt scoring and retry limits are not enforced

**Priority P1.** `ledger.py:35` limits `PRIMARY_STATUSES` to `completed` and
`failed_output`. `failed_no_output` after inference is excluded. Reproduction:
append a first inference-bearing `failed_no_output`, then a successful attempt;
`terminal_state` chooses the second attempt.

`cmd_run` and `execute_block` skip only valid committed outputs. A terminal
no-output failure is run again on resume, with no check of the setup retry count.
`made_inference_requests` is inferred from output-directory/file existence at
`executor.py:299`: an H run directory does not prove a request, and a Pi session
can make requests without writing findings. A failed setup and a failed audit
cannot be reliably distinguished this way.

The ledger lock protects individual appends, not acquisition of a cell for its
whole execution. Two controllers can start the same cell concurrently. Likewise,
rename-before-marker crashes leave a directory that `arm_done` considers incomplete
but `commit_cell_outputs` refuses to replace, preventing recovery.

**Required correction:** claim each cell under a lock/lease; persist request-start
events from the trusted gateway; select the first inference-bearing attempt
regardless of output success; enforce one setup retry and no automatic operational
retry. Preserve diagnostics separately. Add crash recovery for interrupted commits
and tests that call the real resume path twice, not only ledger helpers.

### R4 — P07/P08: committed files bypass ledger validity

**Priority P1.** `aggregate.py:396` scores a valid-looking committed directory
without checking its ledger outcome. Missing terminal records, a recorded
invalidation, a different selected attempt, and output from a non-primary attempt
are therefore not necessarily rejected.

**Reproduction:** a two-cell temporary experiment with one committed-but-invalidated
cell and one committed cell without any terminal record produces a non-null
headline and `problems: []`.

`arm_done` at `experiment.py:290` checks arm/trial/hash but ignores its `repo`
argument and does not require a primary artifact. A marker with wrong repo/cell/
attempt IDs and no artifact paths returns `done: true`. Commit validation accepts
arbitrary parseable JSON rather than an output schema. With failed outputs, the
aggregator can also replace a corrupt committed artifact with synthetic zeros
instead of surfacing integrity failure.

**Required correction:** resolve protocol validity and selected attempt from the
ledger first; then require an exact matching completion record and validated
artifacts. Invalidation and integrity failures must block the headline. Validate
the full expected Cartesian product against frozen repos/trials/arms, not just
whatever `expected_cells` currently contains. Test post-commit invalidation,
missing terminal state, wrong attempt/repo, absent primary, and corrupt output.

### R5 — P03/P06/P07/P09: the freeze gate and runtime pins are bypassable

**Priority P1.** `cmd_freeze` (`experiment.py:245`) writes a manifest from a minimal
spec without preflight/calibration evidence, image, app SHAs, or settings. This
reproduces with exit code 0. Hashing a document is not checking its completeness
or proving it matches executed code.

`preflight.py:192` includes a `not_run` live gate only in offline mode. In live
mode it omits that gate entirely; with its offline dependencies passing, live
preflight reports `passed: true` without performing any live probe. The image
gate checks only that `docker inspect` succeeded, not that the returned ID matches
the recorded ID or the spec.

Actual drift already exists: `protocol-v2.json` pins image `98f6b85e…`, while the
current `codesec-iso` tag resolves to `ee12a801…`. The executor never passes the
manifest image ID; `run_isolated` uses the mutable tag by default. H also reads the
configuration baked into that image rather than validating it against the manifest.
The source hash omits configuration files, dependency locks, and several runtime
inputs, and is not checked before each cell. `cmd_run` reads a separate writable
`schedule.json` without comparing it to the schedule inside the hashed manifest.

The preflight isolation test also calls `build_agent_image()`, retagging the shared
runtime image. A verification gate must not rebuild the artifact it claims to
verify. I stopped an initial broader test invocation when I found this recursive
preflight side effect and reran the focused suites without that test; the image
ID remained unchanged during this review.

**Required correction:** schema-validate specs; distinguish calibration admission
from scored admission; bind every required gate to exact source/config/image/gateway
hashes. Execute by image digest and verify installed config/prompts. Test-only image
builds need unique tags. Store and validate the schedule once. Missing, stale,
skipped, or failed evidence must prevent scored `freeze` and `run`.

### R6 — P02/P05: the Dedupe collision repair leaves invalid active DB state

**Priority P1.** `dedupe.py:658–698` renumbers a reused group, moves its findings
into the new group, and preserves the old group row. `state.py:532` then regards
that old row as an active group without a canonical finding.

**Reproduction:** the newly added
`test_second_dedupe_pass_renumbers_colliding_group_ids` passes, but calling
`completion_gaps('run')` afterward returns:

```text
group g_reused has no canonical finding
```

Thus the feedback-loop fix removes the immediate conflict exception but can
still fail the final pipeline completeness check. The case must be exercised
through run completion, not just checked for a changed ID.

Also, `_StageHealth.wrap` always records `complete` unless an exception escapes;
internal Dedupe degraded events do not make the stage terminal health degraded.
The executor labels an exit-zero run `completed` without checking stage health.

**Required correction:** distinguish active group generations from immutable
history, or atomically replace the active partition while keeping history in a
separate table. Validate current groups only, and propagate degraded events into
stage/run/cell status. Add multi-pass merge/split/idempotence tests and a full
feedback-loop completion test with no group-related completeness gaps.

### R7 — P06: corpus pin and location verification is incomplete

**Priority P1.** `prepare_bundle_pair` (`isolation.py:245`) copies the current app
checkout but never checks its actual HEAD/dirty state against GT's `commit_sha`.
It merely records that GT string. `verify_pin` checks the benchmark repository,
not the app clones, and is not called on the actual execution path here.

`_gt_entries` filters to vulnerable entries. `verify_gt_locations` ignores decoys
and `acceptable_locations`, despite its docstring claiming complete coverage.
Reproduction with missing decoy and acceptable-location files reports
`checked: 1, problems: []`. Reused bundles are accepted based on `bundle.json`
existence; there is no pre/post-run digest comparison on the execution path.
The supplied protocol and saved smoke manifest have empty app-SHA/count maps.

**Required correction:** verify benchmark/scorer hashes and each app SHA plus
working-tree content before preparation. Check all label files and alternative
locations. Record actual pins/counts/digests in the frozen manifest and validate
reused bundles before and after each arm. Read-only mounting is useful but does
not detect an operator-side mutation between the two executions.

### R8 — P03/P07/P08: request attribution and full parity are not implemented

**Priority P1.** The gateway supports optional tag headers, but the executor does
not supply experiment/cell/attempt/arm identifiers to either client. At review
time all **448** saved gateway request records have **none** of those identifiers
(nor stage). This prevents reliable per-attempt usage reconciliation and proof
of which attempt made its first inference request.

`GatewayConfig.validate` checks a limited positive key list. It accepts forbidden
extra controls such as `top_p=0.01`, and the nested subset rule accepts a changed
`thinking.clear_thinking` value. Reproduction sends both and receives no problems.
The reported live probes establish parity of selected fields, not complete parity
of the chosen history/sampling policy. `observed_extra` stores extra key names,
not their values, which further limits retrospective inspection.

The gateway logs a successful request only after relay finishes. A client
disconnect/BrokenPipe can escape the relay/finally block before the final record,
losing precisely the failed-request evidence needed for accounting.

**Required correction:** bind trusted attempt identity at the gateway; record
request admission before forwarding and terminal outcome in exception-safe
cleanup. Enforce required absences as well as values and settle the history-policy
contract explicitly. Reconcile usage/errors/request counts to each ledger attempt,
including interrupted calls. Repeat actual-client parity/dead-gateway checks.

### R9 — P08/P11: the advertised aggregation CLI is not wired

**Priority P1.** `aggregate.py:87` is still the legacy parser; it has no
`--experiment` argument. Its `__main__` invocation at line 182 occurs before the
new experiment functions are defined. `cmd_aggregate_experiment` exists but is
unreachable from the supplied command.

The exact handoff command exits 2 with:

```text
aggregate.py: error: unrecognized arguments: --experiment ...
```

**Required correction:** add the parser/dispatch and move the module entry point
after all definitions. Add subprocess tests for the documented CLI, including
complete, incomplete, invalid, and accounted-operational-failure experiments.
Importing `aggregate_experiment` in a unit test does not test this interface.

### R10 — P08: several advertised diagnostics are missing or incorrect

**Priority P2.** `usage_records`/`usage_missing` are initialized to zero and never
populated. The complete-pair diagnostic counts any pair with score counts,
including synthetic all-FN operational failures, rather than genuinely complete
executions. The official matcher represents unmatched duplicates with no GT
entry, so `_fp_taxonomy` cannot identify them by testing
`ground_truth_entry.is_vulnerable` as it currently does; the fake test scorer has
different duplicate/CWE/assignment semantics and masks that gap.

The `negative_condition_original` output is explanatory text rather than the
requested independently computed original-negative-condition boolean. Per-CWE/
severity recall, famous/obscure splits, macro sensitivity, and stage attrition are
not supplied by this aggregator. They should be marked pending rather than
“wired” without an executable report path.

**Required correction:** use official-matcher integration fixtures for duplicate
and unmatched findings; compute actual selected-attempt completion diagnostics;
implement and test usage reconciliation and the promised secondary report fields.
Keep these separate from the unchanged primary score.

## Other evidence qualifications

- P00's source snapshot is a list of hashes; the saved diff covers tracked files.
  The provided evidence does not contain the original bytes of untracked source
  files. Hashes cannot restore files later edited in place. Preserve a real
  allowlisted source archive now and record any historical recovery limitation.
- The dead-gateway exercise did not test V's intended failure path; its V cell
  made a successful audit. Sharing some executor code is not equivalent evidence
  for client-specific timeout, retry, and snapshot handling.
- The new Pi prompt in `executor.py` asks for source-backed findings rather than
  explicitly externally exploitable ones, while H's primary policy requires
  reachability. Resolve and freeze the intended common scope before calibration;
  do not alter it in response to comparative scores.
- Isolation is a substantial improvement, but some negative checks treat arbitrary
  command failure/absence of a marker as a pass. Use positive control sentinels and
  explicit exit/status validation; Docker error 125 is not the only way a probe
  can fail to execute. Tests skipped for unavailable Docker/Pi must not count as
  a passed required preflight gate just because pytest exits zero.

## Revised package status and next action

| Package | Review disposition |
|---|---|
| P00 | Baseline scores reproduced; qualify source-byte preservation claim |
| P01 | Focused behavior tests support the repair |
| P02 | Reopen active Dedupe partition / feedback completion (R6) |
| P03 | Selected-field parity demonstrated; reopen attribution and enforcement (R8) |
| P04 | Focused contract/Trace tests pass; no new blocker found in this review |
| P05 | Reopen real outer timeout and checkpoint recovery (R1–R2) |
| P06 | Container separation exists; reopen app pins/location/digest verification (R7) |
| P07 | Reopen cell ownership, attempt selection, commits, provenance (R3–R5) |
| P08 | Reopen ledger admission, CLI, and diagnostics (R4, R9–R10) |
| P09 | Reopen actual live/scored admission gate and evidence binding (R5) |
| P10 | Smoke is useful; timeout/network gates are not complete end-to-end |
| P11–P13 | Correctly not executed; keep the scored matrix blocked |

Fix R1–R9 and their full-path regression tests first. Then run a miniature
synthetic experiment through the **actual** freeze/run/resume/verify/aggregate
commands, exercising success, no-output failure, checkpoint-only output, malformed
output, timeout, late invalidation, and crash recovery. Prove no second primary
attempt is admitted and no container/request survives its deadline. Generate a
fresh image/protocol/preflight record and repeat live smoke/deadline/dead-gateway
calibration for both arms. Only then proceed to VAmPI and PyGoat calibration.

Existing tests passing is not the remaining milestone: the failure paths and
experimental admission controls must be shown to work together.
