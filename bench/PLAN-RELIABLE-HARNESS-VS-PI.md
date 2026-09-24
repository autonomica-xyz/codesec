# Reliable harness, then a fair Pi comparison

Date: 2026-09-23
Status: planned; implementation and new experiments have not started.

## Objective and scope

Make the existing harness run reliably, improve its existing verification, and
determine whether its final reports outperform vanilla Pi. Finish with an honest
result even if the harness loses.

This is the execution plan for the next iteration. It narrows the earlier
[repair plan](PLAN-REALVULN-REPAIR-AND-RETEST.md); the settings, primary scoring
rule, and failure-accounting rules below remain unchanged. The
[execution review](REVIEW-REPAIR-EXECUTION-2026-09-23.md) is the defect inventory.
Its findings supersede the optimistic completion claims in
`realvuln/repair-progress.md`.

Keep the current stages, agent counts, validation rounds, schemas, and report
policy. Do not add a challenge agent, orchestration service, general dynamic
validation system, new benchmark, or new severity framework. Use existing
modules and small regression tests. Defer local-model experiments, held-out
confirmation, optional report-policy ablations, and elaborate diagnostics.

Execute workstreams 1 and 2 before live calibration. Complete workstream 3 only
after their acceptance checks pass. This document authorizes no execution by
itself: it records the work requested for planning, not a claim that it was run.

## 1. Fix execution and experiment reliability

### 1A. Preserve the starting point

- Inspect the dirty workspace; preserve an allowlisted archive of source,
  prompts, configuration, and dependency locks, plus the tracked diff and hashes.
  Exclude secrets. Do not discard existing changes or overwrite historical runs.
- Add a correction to `realvuln/repair-progress.md` linking the execution review
  and this plan. Mark the affected packages reopened.
- Use `realvuln/repair-evidence/review-2026-09-23/` reproductions as starting
  fixtures. Their current outputs demonstrate bugs, not acceptance criteria.

### 1B. Make stopping and partial-output recovery work end to end

Files: `bench/realvuln/isolation.py`, `executor.py`, `snapshot.py`,
`codesec/deadline.py`, and the existing client deadline code. Review: R1–R2.

- Give each attempt's container a known identity. On success, failure, timeout,
  or controller exception, stop and clean up that container in bounded cleanup.
  Never touch unrelated services. Record a terminal attempt outcome.
- Enforce the model-work cutoff during request retries and streaming responses,
  leaving the existing snapshot reserve. An active stream cannot extend the cap.
- Export the latest valid pre-deadline H final report or checkpoint. Retain V's
  valid snapshots while it runs, so a truncated final write cannot erase them.
- Store exactly the bytes validated and hashed. Check hash, schema, and deadline
  eligibility again when selecting a snapshot. Retained output does not turn a
  timed-out run into a clean completion.

Acceptance checks through the actual executor:

1. A hanging container and a continuously streaming mock provider stop within
   the configured deadline plus bounded cleanup grace; no owned container survives.
2. Nonempty H checkpoint-only output is exported after a timeout.
3. A valid V snapshot followed by a truncated write is recovered.
4. Missing output becomes an accounted failure; post-deadline output is excluded.

### 1C. Make one attempt mean one scored attempt

Files: `ledger.py`, `executor.py`, `experiment.py`, `gateway.py`, and
`aggregate.py` under `bench/realvuln/`. Review: R3–R4, R8–R9.

- Reuse the ledger and a local cell lock; do not introduce a job service. Claim
  a cell before starting it so two controllers cannot execute it concurrently.
- Bind experiment/cell/attempt/arm identity to gateway requests from trusted
  executor context. Log admission before forwarding and terminal outcome even
  on disconnect. Derive request occurrence from these records, not output files.
- The first inference-bearing attempt is primary, including no-output failure.
  Resume must not replace it. Permit only the existing single setup retry before
  inference; missing or inconsistent attribution blocks validity, not a free retry.
- Recover interrupted commits without overwriting valid committed results.
- Aggregate from ledger-selected attempts. Require matching repo, trial, arm,
  attempt, completion marker, artifact schema, and hashes. Check all expected
  cells. Invalidation or corrupt provenance blocks the headline.
- Account valid operational failures using retained eligible predictions, or
  empty predictions when none exist. A setup failure or integrity violation is
  not an ordinary empty-prediction result.
- Wire the documented `aggregate --experiment` command and test it as a subprocess.

Acceptance: exercise success, inference-with-no-output followed by resume,
concurrent acquisition, setup retry exhaustion, crash during commit, wrong-repo
marker, post-commit invalidation, and corrupt output. No case may silently select
a better later attempt or publish an invalid headline. A second resume starts no
already-accounted cell. Include the official matcher in scoring integration tests.

### 1D. Execute exactly the configuration and corpus that were frozen

Files: `experiment.py`, `preflight.py`, `isolation.py`, `gateway.py`.
Review: R5, R7–R8 and the review's isolation qualifications.

- Validate required manifest fields and bind gate evidence to the exact runtime
  source, prompts, config, dependency locks, image, and gateway settings.
- Execute the immutable image ID/digest, not a mutable tag. Verify its effective
  configuration. Read one frozen schedule and reject drift before each cell.
- Verify actual application revisions and source bytes, all GT locations
  including decoys/alternatives, and paired bundle digests. Recheck reused bundles
  and pre/post-run digests. Preserve byte-identical H/V input.
- Enforce complete shared request settings, including forbidden extras and the
  chosen reasoning-history policy. Attribute usage and errors to attempts.
- Required live gates must actually run; missing, skipped, stale, or failed gates
  cannot pass scored admission. Keep calibration admission distinct from scored
  admission so there is no circular prerequisite.
- Verification must not rebuild or retag the image being verified. Isolation
  probes need positive controls; infrastructure failure is not proof of isolation.

Acceptance: deliberately alter the image, prompt/config, app bytes, schedule,
request settings, or gate evidence. Each affected scored admission must fail with
a specific reason. Required skipped tests remain unmet gates.

### 1E. Finish the existing Dedupe repair

Files: `codesec/stages/dedupe.py`, `codesec/state.py`, stage-health handling.
Review: R6.

Fix active group replacement so a second Dedupe pass cannot leave empty active
groups. Keep historical evidence separate from active membership using the
smallest change consistent with the existing DB. Propagate handled degradation
into stage/run status rather than calling every exit-zero run complete.

Acceptance: run merge, split, reused-group-ID, and repeated-pass cases through
pipeline completion. Require an exact active partition, one canonical per active
group, and no group-related `completion_gaps`. A degraded stage is reported as such.

### Workstream 1 exit gate

Run focused tests for changed behavior, then the full existing suite once. Inspect
skips individually. Run a miniature synthetic experiment through the real
freeze/run/resume/verify/aggregate commands, covering the failure paths above.
Save commands, exit codes, and artifacts under a new repair-evidence directory.
Passing helper tests alone is insufficient. All R1–R9 blockers must be resolved;
optional R10 breakdowns may stay deferred, but usage and completion reporting
must be accurate and unavailable fields explicitly marked unavailable.

## 2. Tighten the existing verifier without adding a stage

Primary file: `prompts/03-validate.md`. Inspect `prompts/03-arbiter.md` for
contradictory instructions. Keep Trace responsible for external reachability.

The validator already challenges findings and checks downstream behavior. Do not
append another long checklist. Revise the existing rules to make their evidence
threshold consistent and concise:

1. Confirmation requires an actual unsafe operation under the stated input
   control, not just a familiar bug pattern or a source comment. Read a local
   sink's implementation and the relevant caller before deciding.
2. In the existing `crux` and `rationale`, identify the controlling code fact,
   what the attacker controls, and why the claimed consequence follows. Do not
   add schema fields or a second report format.
3. A subprocess argument list prevents ordinary shell interpretation but can
   still allow dangerous option semantics. Check the specific argument position,
   executable behavior, and consequence; do not blanket-accept or blanket-reject.
4. Separate observed impact from deployment assumptions. Do not inflate a
   cosmetic login response into privilege gain or enabled debugging into proven
   remote execution. Use existing severity and missing-precondition fields.
5. Reject a disproven operation, such as a supposed SQL sink that only formats a
   string. Use `needs_more_info` when a decisive fact is genuinely unavailable.
   Do not require a live exploit for a source-proven bug such as unsafe pickle
   loading. Remove conflicting instructions suggesting live proof in static mode
   or local execution with tools the validator does not have.

Preserve the Validate/Trace boundary: validation establishes unsafe semantics;
Trace establishes external reachability. Do not invent new Trace statuses or
mislabel a reachable but harmless operation as unreachable.

Acceptance:

- Run the existing validation, Trace, and report contract tests.
- During the unscored smoke pair in workstream 3, inspect actual validator and
  arbiter source reads and rationales. Confirm unsafe pickle loading is retained;
  SQL-stub and unsupported library-version claims are not promoted; ping/debug/
  credential claims state only supported consequences and conditions.
- Record candidates that were never emitted as “not exercised,” not a successful
  rejection. If an important case was absent, use a small calibration-only replay
  through the existing validator with the source and candidate. Save raw output.
- Do not pretend a prompt text assertion or mocked model proves model behavior.
  Do not tune against matrix scores or embed repository-specific answers in prompts.

## 3. Complete calibration and compare against Pi

### 3A. Preserve the comparison contract

Use the earlier plan's section 1 settings: hosted GLM-5.3 in both arms, explicit
low reasoning, temperature 0.6, no top-p, 32,768 maximum output tokens/request,
262,144 context ceiling, H concurrency four, native Pi concurrency one, fresh
sessions, static analysis, deterministic H reports, and `confirmed_reachable`
as H's primary policy. Preserve existing task and loop caps.

Both arms receive 7,200 seconds per repository, with 10,800 seconds for PyGoat.
This is equal wall-time ceilings, **not equal tokens, cost, or compute**. Record
actual resource use and describe the conclusion accordingly. Give both arms the
same security scope: externally reachable vulnerabilities supported by source,
with authentication and deployment conditions stated. Freeze prompts before scoring.

### 3B. Repeat affected calibration on the final implementation

1. Create fresh image/config/protocol artifacts and unused calibration IDs;
   preserve all previous attempts. Do not reuse stale `protocol-v2.json` evidence.
2. Run actual-client gateway parity probes for both arms.
3. Run the smoke H/V pair and the workstream 2 source review.
4. Run artificial-deadline and dead-gateway exercises for **both** clients. Verify
   exported output, terminal ledger records, attributed requests, and cleanup.
   The earlier H checkpoint and successful V network run do not satisfy this gate.
5. Run one VAmPI pair and one PyGoat pair at intended budgets. Require working
   search, bounded inputs, valid Dedupe partitions, no unexpected stage fallback,
   valid exports, accurate health, and no isolation/settings violations.
6. Archive every attempt. If a defect appears, fix it and repeat affected gates
   against the new hashes. After two cycles of the same unresolved defect, record
   the blocker instead of launching the matrix. Do not use calibration F3 to tune.

Use measured calibration usage to record expected quota/cost needs before the
matrix. Respect the actual available/authorized limit; do not invent a monetary
limit or treat a subscription as unlimited. Pending cells remain pending on outage
or quota exhaustion. The existing matrix's maximum combined cell time is 78 hours.

### 3C. Freeze and run one scored matrix

Use the existing six repositories, three trials, and two arms: 36 cells, 18 pairs.
Retain the seeded counterbalanced schedule and run paired arms consecutively with
no overlapping provider load. Use the official matcher and existing label rules.

After CLI integration tests pass, execute these commands with concrete new paths
recorded in the progress log:

```bash
.venv/bin/python -m bench.realvuln.experiment freeze --spec "$SPEC" --output "$EXP"
.venv/bin/python -m bench.realvuln.experiment run --experiment "$EXP"
.venv/bin/python -m bench.realvuln.experiment verify --experiment "$EXP"
.venv/bin/python -m bench.realvuln.aggregate --experiment "$EXP" --json-out "$EXP/reports/aggregate.json"
```

`SPEC` must reference the new complete protocol; `EXP` must be an unused path.
Resume an existing matching experiment from `run`, never from `freeze`. Preserve
all inference-bearing failures. No changes to code, prompts, budgets, primary
membership, scorer, or settings during the matrix; a required fix invalidates
the affected protocol and requires a new experiment, not selective replacement.

### 3D. Publish the result, including a loss

Compute primary metrics by pooling counts within each trial, then averaging the
three trial metrics as prescribed in the original plan. Preserve the exact rule:

```text
(F3_H >= F3_Pi + 5 percentage points
 OR (Recall_H >= Recall_Pi - 0.05 AND Precision_H >= Precision_Pi + 0.10))
AND strictly fewer H false positives on at least 4/6 repos in at least 2/3 trials.
```

Recall/precision use fractions in this expression; F3 uses the 0–100 scale.
Protocol validity and accounting completeness come first. Report aggregate FP
counts too: the per-repository gate alone does not establish fewer total FPs.

Write `bench/RESULTS-HARNESS-VS-PI-RELIABILITY-<date>.md` with:

- Frozen experiment identity and the exact settings/scope.
- All 18 pair outcomes, failures, degradation, and retry history.
- TP/FP/FN, precision, recall, F3 per trial; per-repository comparisons; the
  mechanically computed success-rule result.
- Clean completion rate, deadline recovery, elapsed time, and attributed token/
  cost data where available; explicitly identify missing usage.
- A short source-backed review of representative wins and false positives from
  both arms. Do not alter official scoring through post-hoc adjudication.
- One conclusion: invalid/incomplete, meets the predeclared criterion, or does
  not meet it. A pass on this development-visible corpus is regression evidence,
  not proof of general superiority or attribution to the prompt change alone.

Do not rerun merely because H loses. Use observed failures to propose at most one
next targeted change, or simplify the weak stage. Any broader confirmation is a
separate follow-up, not part of this iteration.

## Completion checklist

- [ ] R1–R9 corrected with full-path evidence; no known integrity blocker remains.
- [ ] Existing verifier tightened without new stages, rounds, or schemas.
- [ ] Both clients pass fresh parity, deadline, and dead-gateway exercises.
- [ ] Smoke, VAmPI, and PyGoat calibration pairs pass on the frozen implementation.
- [ ] All 36 scored cells are accounted for under the unchanged selection rules.
- [ ] A reproducible report states the actual outcome and resource costs.

Maintain a short progress entry after each completed step: changes, exact command,
result, artifact path, and remaining blocker. Do not mark a workstream complete
from test count alone.
