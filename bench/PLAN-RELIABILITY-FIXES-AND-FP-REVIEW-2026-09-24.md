# Reliability fixes and false-positive review

Date: 2026-09-24
Status: plan only; no fixes or new experiments executed by creating this file.

## Objective

Close the defects reproduced in [the September 24 review](REVIEW-RELIABILITY-2026-09-24.md),
verify both clients' failure handling, and determine what causes the harness's
extra scored false positives before paying for another full comparison.

Keep the current architecture. No additional agents, pipeline stages, validation
rounds, orchestration service, general dynamic-testing system, or benchmark
expansion. Implement checks in existing modules. Preserve strict validation of
security findings; tolerate malformed advisory metadata only with explicit evidence
of what was discarded or normalized.

The saved matrix remains `matrix-20260923-01`: F3 H/Pi 37.0/27.3, precision
53.36%/68.47%, recall 35.80%/25.72%, and scored FPs 152/66. It did not meet the
predeclared criterion. Its reported token usage was about 58.8 times greater for
H; that is not a dollar-cost ratio. Do not edit its artifacts, replace failed
attempts, change its labels, or tune a new result into a win.

## Order and deliverables

| Step | Work | Exit evidence |
|---|---|---|
| A | Preserve baseline and reproduce failures | Source archive and reproduction outputs |
| B | Correct deadlines and eligible output | Both-arm late-write and recovery tests |
| C | Unify validity checks | Verify/aggregate reject every invalid fixture |
| D | Enforce freeze/runtime evidence | Missing, stale, and changed inputs rejected |
| E | Repair advisory-data handling and health reporting | Exact failing responses replay successfully and honestly |
| F | Correct records and repeat affected calibration | Real-client timeout and gateway-failure evidence |
| G | Review a fixed sample of extra FPs | Source-backed classification and one proposed change, if justified |
| H | Decide whether to retest quality | Written go/no-go; no automatic matrix rerun |

Implement B–E before fresh calibration. G can use saved source and findings while
reliability work is underway. Do not change verification prompts until G identifies
a concrete cause. Maintain one progress log, with exact commands, exit codes,
artifact paths, and unresolved issues after each step.

## A. Preserve and reproduce

1. Read applicable repository instructions and inspect `git status --short`.
   Preserve existing changes. Archive allowlisted source, prompts, schemas,
   configuration, lockfiles, image-build inputs, and tracked diff; exclude secrets
   and large run outputs. Record hashes and the archive path.
2. Create a new evidence directory under `bench/realvuln/repair-evidence/` with an
   unused name. Use fresh experiment IDs for any subsequent execution.
3. Run the existing review reproduction before editing:

   ```bash
   PYTHONPATH=. .venv/bin/python bench/realvuln/repair-evidence/review-2026-09-24/reproduce.py
   ```

   Save stdout and exit status. This script mutates disposable copies only.
4. Turn its demonstrated defects into regression tests expecting correct behavior.
   Keep the historical reproduction intact; once repaired it may abort earlier
   because an operation it expects to succeed is correctly rejected.
5. Record current code hashes separately from the frozen matrix hashes. Existing
   post-run analysis changes must not be represented as code used during the run.

Done when the reproduced failures are independently observable and the starting
source can be restored from actual bytes, not just a hash list.

## B. One work deadline, separate cleanup, eligible output only

Files: `bench/realvuln/executor.py`, `isolation.py`, `snapshot.py`, existing
`codesec/deadline.py` and client cutoff handling where necessary.

Implementation:

1. Define the cell's work deadline once using a monotonic clock. Preserve wall
   timestamps for readable audit records, not as the live cutoff authority.
2. Remove the extra workload allowance at `run_arm_container`'s
   `timeout_s + CLEANUP_GRACE_S`. Pass the actual remaining work budget to the
   supervisor. Cleanup grace starts after work is stopped and must not permit
   additional inference or useful tool work. Retain H's existing synthesis reserve.
3. Use the existing snapshot mechanism for both H final/checkpoint files and V
   findings. Capture and validate exact bytes while work is eligible. Store
   operator-owned metadata outside locations writable by the agent.
4. At cutoff, stop the owned container and select the latest eligible valid
   snapshot. A final file discovered only after cutoff is not automatically
   eligible. Do not rely on agent-controlled file mtime or metadata as proof.
5. Handle early normal completion explicitly: capture final bytes while still
   inside the work budget. Do not lose a valid fast completion because the
   periodic watcher has not polled yet. For cutoff races, conservatively use the
   last demonstrably eligible snapshot and report that choice.
6. Revalidate selected bytes, schema, hash, and capture provenance at export.
   Preserve earlier valid output after a truncated overwrite. If no eligible
   output exists after inference, record a no-output operational failure.
7. Make cleanup bounded and ownership-specific. Preserve terminal accounting on
   exceptions; a recovered timeout is not a clean completion.

Required tests through the executor, parameterized for H and V:

- Early normal completion exports a nonempty final result.
- Nonempty pre-cutoff output followed by a late replacement exports only the
  pre-cutoff result; late-only output exports no finding.
- Valid output followed by a truncated write recovers the earlier bytes.
- A hanging container stops and is removed within cap plus bounded cleanup.
- An active stream cannot consume the reserve or run beyond the work cutoff.
- A wall-clock adjustment does not change the monotonic work budget.
- An agent cannot forge capture metadata to make late output eligible.

Keep tests short using local fixtures/mock streams. F supplies the separate
actual-client acceptance evidence.

## C. Share validity checks between verification and aggregation

Files: `bench/realvuln/ledger.py`, `experiment.py`, `aggregate.py`, and existing
artifact/schema helpers. Add one shared validation helper in an existing module;
do not build a new framework.

Implementation:

1. Separate two questions: which attempt is the immutable operational primary,
   and whether the cell/experiment is valid. A later protocol invalidation must
   block scoring without replacing the original primary or rewriting history.
2. Validate expected cells against the frozen repository/trial/arm product.
   Reject missing/duplicate assignments and unexpected committed cells.
3. Require exact experiment, repo, trial, arm, cell ID, selected attempt, and
   manifest identity. Validate all required artifacts and their schemas/hashes.
   Artifact paths must remain inside the committed cell directory.
4. Return structured validity problems to both `verify` and `aggregate`.
   Aggregation must perform its own check; it cannot assume verify ran first.
5. Distinguish corrupt committed evidence from genuine absence of output:

   | State | Treatment |
   |---|---|
   | Valid selected attempt, valid eligible output | Score output; retain actual health status |
   | Inference occurred, no eligible output ever committed | Empty predictions; operational failure |
   | Committed artifact missing/corrupt/mismatched | Integrity failure; no headline |
   | Setup retries exhausted before inference | Incomplete experiment; no headline |
   | Invalidation, unknown attribution, or wrong primary | Invalid experiment; no headline |

6. Make this policy explicit in the next protocol. The saved v5 text and its
   report disagree on failed-output treatment; document that historical
   discrepancy and retain its sensitivity analysis, rather than rewriting v5.

Required tests:

- Late invalidation after a valid completed attempt blocks both commands.
- Wrong repo/cell/experiment/attempt identity blocks both commands even when
  file hashes match; test each field independently.
- Truncated, missing, wrong-schema, and hash-mismatched committed files block
  aggregation even when the ledger says `failed_output`.
- A real no-output operational failure still receives empty predictions.
- Retained eligible output remains scored and explicitly degraded.
- Resume cannot replace the first inference-bearing failure with a later success.
- A complete valid synthetic experiment passes CLI subprocess checks and an
  official-matcher integration case. Mock-scorer tests alone are insufficient.

Done when every September 24 integrity reproduction is rejected for the intended
reason, while legitimate recovery and accounting still work.

## D. Make admission evidence real and tied to execution

Files: `bench/realvuln/experiment.py`, `preflight.py`, `executor.py`, image-build
input hashing in `isolation.py`, and the next protocol file.

Implementation:

1. Add an explicit calibration/scored purpose to admission. Calibration needs
   valid settings, isolation, and prerequisites; it cannot require its own future
   completion. Scored admission additionally requires completed calibration.
2. Reference actual evidence artifacts with paths and hashes. Read them, verify
   their contents and status, and compare source/config/image/request-setting
   identities. A nonempty or all-zero hash is not evidence. Skipped, missing,
   failed, or mismatched required gates do not pass.
3. Bind evidence to the runtime inputs that matter: source/prompts/schemas,
   effective config, `pyproject.toml`, `uv.lock`, relevant image build inputs,
   immutable image ID, gateway policy, benchmark/scorer pin, and paired corpus
   bytes. Exclude mutable reports/progress logs from the runtime hash.
4. Preserve immutable evidence copies or content-addressed references in the
   experiment's operator directory. Verification itself must not rebuild or
   retag the image it is checking.
5. Recheck runtime identities before starting pending cells, including on resume.
   Drift stops new admissions with a specific error; do not silently refreeze or
   continue under changed code. Keep schedule and first-attempt selection fixed.
6. Distinguish historical reanalysis from execution: reanalysis records its own
   analyzer hash and does not pretend the current host equals the frozen source.

Required tests: missing evidence file, bad digest, failed/skipped gate, stale
prompt/config/image, changed lockfile, changed schedule, changed source after
freeze, and a valid evidence set. Use a passing set of mocked gate artifacts for
offline control-flow tests, then actual artifacts for F. Do not mock the evidence
validation under test. A documentation-only edit must not invalidate runtime gates.

## E. Repair the exact advisory-data failure and propagate health

Files to inspect: `codesec/local_agent.py`, `codesec/runner.py`,
`codesec/contracts.py`, `codesec/stages/hunt.py`,
`schemas/finding.schema.json`, `codesec/orchestrator.py`, and executor health export.

Do not implement a blanket array-to-object conversion. The current
`finding.schema.json` already declares `gaps_observed` as an array of objects.
The saved summary's description is insufficient to locate the failing boundary.

1. Extract the exact model responses, validation errors, and schema paths from
   attempts `att-a852333aab94` and `att-a8af740ab089` under the saved matrix.
   Identify the schema and normalization path actually used by the frozen image.
2. Replay the saved responses through that path, without inference. Establish
   whether the mismatch is a nested item, envelope, incorrect schema dispatch,
   or a genuinely malformed advisory field. Save a minimal regression fixture.
3. Prefer repairing schema selection/dispatch if it is wrong. Otherwise normalize
   only an unambiguous equivalent advisory representation. If advisory content
   cannot be preserved faithfully, quarantine that content and record the loss.
   Keep raw output and valid findings; never manufacture a finding or pretend an
   invalid finding envelope was an intentional empty report.
4. Keep normalization idempotent and narrowly scoped. Do not weaken finding
   location/CWE/type contracts or add model calls/review rounds as the default fix.
5. Propagate stage health into the exported run/cell outcome. Exit zero alone
   cannot mean clean if findings or coverage metadata were lost. Reuse existing
   health/failure statuses and reason fields; avoid inventing another status system.
   Unknown/missing required health evidence is not a clean pass.

Acceptance:

- Both saved failures exercise the repaired path without losing valid findings.
- Valid payloads are unchanged; repeated normalization has no further effect.
- Malformed security findings remain rejected/quarantined under existing rules.
- Discarded advisory data is visible as degradation and excluded from the clean
  completion rate. Normalized equivalent data is recorded without inventing loss.
- Deterministic report generation and downstream Gapfill still accept the result.

## F. Correct the record and prove actual-client failure handling

1. Add dated corrections to the results/progress documents; preserve previous
   claims as history where useful. Correct the v5 calibration references to
   `calib-deadline-20260923-09` and `calib-neterror-20260923-07`, noting that the
   older cited runs used another image. Withdraw unconditional sign-off language.
2. Run focused tests for B–E, then the full existing suite once. Audit test side
   effects first: image-building tests must use unique test tags, not overwrite
   the shared experiment image. Required skipped checks remain outstanding.
3. Run a miniature synthetic experiment through the real freeze/run/resume/
   verify/aggregate CLI, including late output, corruption, invalidation, clean
   success, eligible recovery, and no-output failure. Save exit codes and outputs.
4. Build a new immutable image with an unused tag and fresh protocol/evidence.
   Do not start a scored matrix. Run actual H/Pi parity and smoke checks.
5. Exercise a real deadline for **each** client. Use an unscored fixture or a
   controlled gateway delay so work is still in flight when the cutoff arrives.
   The client must not merely finish early. Save request admission/termination,
   capture provenance, terminal ledger state, and container cleanup evidence.
   Prove nonempty recovery where possible; pair no-output timeout evidence with
   a separate nonempty snapshot-recovery case rather than claiming they are equal.
6. Repeat dead-gateway handling for both clients using an isolated test gateway
   or dedicated test network. Do not disconnect a shared gateway serving other
   work. Verify request attribution, bounded retries, setup classification, and
   absence of leftover owned containers.
7. If a scored comparison is later proposed, rerun VAmPI/PyGoat calibration
   against the exact final runtime, including any G/H prompt change. New runtime
   hashes cannot inherit old calibration passes without checking applicability.

Use small explicit caps for failure tests and record actual usage. After two
cycles of the same unresolved defect, document the blocker instead of repeatedly
spending model calls. This is a diagnostic stop, not permission to score anyway.

## G. Review a fixed sample of the extra scored false positives

Use saved artifacts and the exact bundled source. No new full audit is needed.
Unmatched benchmark predictions are not automatically disproven vulnerabilities.

1. Before inspecting source, save a deterministic selection manifest. From H's
   official scored FPs, sort by repo/trial/finding ID, deduplicate identical
   file/location/CWE claims for review, retain occurrence counts, and use seed
   `20260924` to choose up to four claims per repo (maximum 24). Record undersupply;
   do not replace difficult cases with easier ones. Select up to one Pi FP per
   repo similarly as a small comparison sample.
2. For each selected claim, read the exact source lines, callers, sink
   implementation, necessary conditions, GT entries, and official match reason.
   Inspect H's validation/Trace evidence to identify where an unsupported claim
   survived. Consult primary dependency documentation only if source leaves a
   decisive semantic question unresolved.
3. Assign one principal category with evidence:

   | Category | Required evidence |
   |---|---|
   | Incorrect security claim | Source contradicts the claimed operation/control/impact |
   | Real issue outside labels | Source-backed unsafe flow, plausible entry conditions, no matching label |
   | Reporting/matching error | Same labeled issue with wrong location/CWE or documented matcher mismatch |
   | Duplicate | Same underlying issue already reported; no distinct affected path/principal |
   | Unresolved | Exact missing fact and why available evidence cannot decide |

4. Record finding IDs, trial occurrences, source citations, claimed vs supported
   impact, classification, rationale, and implicated stage in JSON plus a short
   Markdown summary. Do not require a deployed exploit for source-proven behavior.
5. Report both unique-claim and sampled-occurrence counts, clearly limited to this
   stratified development sample. Do not extrapolate a new full-matrix precision
   or alter the official score through adjudication.

Done when another reader can check each classification from the cited evidence.
If there is no dominant actionable cause, stop with that finding; do not invent
a generic verification overhaul.

## H. One evidence-driven quality change, then a retest decision

Choose at most one change supported by G:

- Incorrect claims: tighten the relevant existing Validate/arbiter instruction.
- Location/CWE errors: correct the existing evidence-to-report mapping; never
  select coordinates/CWEs using GT during execution.
- Duplicates: fix the existing Dedupe rule for the demonstrated duplicate class.
- Real unlabeled issues: disclose the benchmark limitation separately; do not
  teach the harness to hide real findings to improve its score.

Before applying a quality change, reserve half the sampled H cases (seeded within
repo where possible) for a diagnostic check. Develop on the other half. Include
fixed known true-positive controls from saved output, especially unsafe pickle
loading, so rejecting everything cannot appear successful. This is a development
check, not independent held-out confirmation.

For deterministic fixes, replay artifacts offline. For prompt changes, compare old
and new prompts on the fixed cases using the same model/settings/context and a
small predeclared number of repeats (two per version per case). Record every
outcome and usage; do not rerun individual failures until they pass. Check that
unsupported claims decrease without new rejection of the true-positive controls.
If results are mixed, report uncertainty and stop tuning this sample.

Write a go/no-go note with reliability gate results, quality evidence, expected
matrix usage, quota availability, and the concrete reason a new matrix would be
informative. No automatic full-matrix launch is part of this plan.

If a subsequent matrix is undertaken, use a new frozen experiment, preserve the
existing six-repo/three-trial paired protocol and success rule, keep first-attempt
failures, and report per-arm usage. Equal wall limits must not be described as
equal compute. Do not change budgets, report policy, or thresholds after seeing
scores, and do not claim the combined changes isolate a prompt's causal effect.

## Final handoff

Produce `bench/RESULTS-RELIABILITY-FIXES-AND-FP-REVIEW-<date>.md` with:

- Implemented changes and evidence closing each September 24 finding.
- Test commands/results, required skips, and actual-client calibration IDs.
- Corrected failure-scoring policy and honest clean/degraded completion reporting.
- The fixed FP sample, classifications, source evidence, and sample limitations.
- Any one quality change and its before/after diagnostic outcomes and usage.
- A go/no-go decision for further scoring, with unresolved blockers explicit.

Completion means these defects are closed and the next experiment decision is
supported. It does not mean the harness has beaten Pi; only a valid comparison
meeting the predeclared criterion could support that narrower measured claim.
