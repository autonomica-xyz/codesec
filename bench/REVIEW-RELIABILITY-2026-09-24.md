# Reverification of the repaired harness — 2026-09-24

Verdict: meaningful improvement, but not fully reliable and not demonstrated to
be better than Pi under the predeclared criterion. The supplied execution summary
is stale: `matrix-20260923-01` now contains all 36 scored cells. Its arithmetic
reproduces, but several previously identified integrity requirements remain unmet.

## What was verified

- Recomputed the saved matrix using `aggregate_experiment` with the official
  matcher, not the fake test scorer. F3, precision, recall, and the negative
  success decision reproduce exactly.
- Ran the current `experiment verify` command: it returns success for all 36
  cells. The adversarial checks below show why this is not a comprehensive
  integrity sign-off.
- Ran 124 focused tests covering ledger, manifest, snapshot, aggregation,
  gateway, synthetic execution, Dedupe, deadlines, Validate, and Trace: all
  passed in 92.96 seconds.
- Ran the two actual-container timeout/normal-completion tests: both passed in
  3.70 seconds, including removal of the hanging container. No image rebuild,
  live inference, or change to existing experiment outputs was performed.
- Inspected the tightened validation prompt: it now requires actual unsafe sink
  semantics and separates disproven claims from unavailable evidence. This is
  an improvement in instructions, not independent proof of a precision gain.

Commands:

```bash
.venv/bin/python -m pytest -q tests/test_realvuln_ledger.py tests/test_realvuln_manifest.py tests/test_realvuln_snapshot.py tests/test_realvuln_aggregate.py tests/test_realvuln_gateway.py tests/test_realvuln_synthetic_experiment.py tests/test_dedupe_stage.py tests/test_benchmark_deadlines.py tests/test_validate_stage.py tests/test_trace_stage.py
.venv/bin/python -m pytest -q tests/test_realvuln_isolation.py::test_hanging_container_is_stopped_and_removed tests/test_realvuln_isolation.py::test_run_isolated_normal_completion
.venv/bin/python -m bench.realvuln.experiment verify --experiment bench/realvuln-runs/experiments/matrix-20260923-01
PYTHONPATH=. .venv/bin/python bench/realvuln/repair-evidence/review-2026-09-24/reproduce.py
```

The last script uses temporary copies for all mutation probes. Its output is
saved in `realvuln/repair-evidence/review-2026-09-24/reproductions.json`.
These probes demonstrate current defects; they are not passing acceptance tests.

## Remaining findings

### 1. P1: post-deadline findings remain eligible

`bench/realvuln/executor.py:290` adds `CLEANUP_GRACE_S` to the workload timeout
passed to `run_isolated`, which then has its own cleanup grace. Pi can therefore
continue useful work beyond the nominal cell cap. H's export function at line
296 receives no deadline. V's final-file path at line 398 accepts a valid final
file without testing deadline eligibility; only fallback snapshot selection uses
the cutoff.

Reproduction: create a valid finding after a cutoff 60 seconds in the past, then
call `export_arm_outputs` with that cutoff. Both H and V export one finding.

Correction: stop model/tool work at the cap, with cleanup separately budgeted;
export only verifiably eligible final/checkpoint/snapshot bytes for both arms.
Exercise the real Pi timeout path, not just Pi completing early in a paired test.
The current matrix's cells finished well below their full caps; this probe does
not establish that their scores benefited from extra time.

### 2. P1: invalidation and artifact integrity can still bypass scoring admission

`ledger.py:154` returns the first inference-bearing terminal event before looking
for a later invalidation. `aggregate.py:429` checks ledger presence/selected
attempt but does not block a committed artifact based on every invalidation.
`aggregate.py:471` converts a failed-output cell with a corrupt committed artifact
to empty predictions rather than flagging an integrity failure.

Reproductions on disposable copies of the matrix:

- Append a terminal invalidation for a completed cell: `verify` still returns 0;
  aggregation publishes a headline with `problems: []`.
- Truncate the primary artifact of the existing failed-output DVPWA cell:
  `verify` catches the truncation, but aggregation independently publishes a
  headline with `problems: []`.

Correction: distinguish attempt selection from experiment/cell validity, and
block aggregation on invalidation or corrupted committed evidence. Only genuine
accounted absence of eligible output should receive empty predictions. Use the
same validity checks in verify and aggregate.

### 3. P1: completion-marker identity is still only partially checked

`experiment.py:428` accepts `repo` but never compares it with the marker. It
checks arm/trial and manifest hash, but not marker cell identity. Schema checking
is only JSON parsing.

Reproduction: change a marker's repo and cell ID while preserving its artifact
bytes/hashes. Both verify and aggregate accept the copied experiment.

Correction: validate experiment, repo, trial, arm, cell, selected attempt, and
required artifact schema together. Add the wrong-identity reproduction to the
existing manifest tests.

### 4. P1: freeze does not enforce the claimed calibration/preflight gates

`experiment.py:248–316` requires certain fields, but a nonempty
`isolation_evidence_sha256` is sufficient; the evidence is not resolved and
verified. `cmd_freeze` checks benchmark/image availability and baked endpoints,
but neither validates calibration/preflight records nor binds their success to
the frozen implementation. There is no distinct calibration/scored admission.

Reproduction: use the real v5 spec with an all-zero isolation-evidence hash and
no supplied gate evidence, mocking only the Docker/benchmark availability
checks. Freeze succeeds. This demonstrates the missing gate logic, not a failure
of the actual saved isolation suite.

Host source hashes are recorded but not rechecked on `run`/per-cell execution.
The current source hash differs from the frozen matrix hash. The report discloses
post-run aggregator edits, so that mismatch alone does not establish mid-run
drift; it does mean provenance must distinguish executed code from current
reanalysis code. Dependency locks are still absent from `_source_hash_inputs`.

Correction: verify existing evidence files and their source/config/image binding
at scored admission; reject missing/stale evidence and runtime drift. This needs
checks in the existing CLI, not a new orchestration layer.

### 5. P2: calibration sign-off overstates coverage and cites stale runs

The results report labels all calibration evidence as using v5 image
`2cc22eda…`, but its deadline `calib-deadline-20260923-01` and network-error
`calib-neterror-20260923-02` rows actually use older image `b2906536…`.
The progress log has newer runs `calib-deadline-20260923-09` and
`calib-neterror-20260923-07` using the correct image.

Even in the newer deadline pair, V completes normally in 12.36 seconds while H
hits its cutoff. This does not test the actual Pi deadline recovery path. The
newer smoke H run is recorded `completed` despite the documented degraded Hunt
stage. `executor.py:749–755` derives clean completion from timeout/controller
error/exit code, without consulting stage health.

Correction: cite the correct calibration IDs, force Pi through a real deadline,
and propagate stage degradation into clean-completion reporting. Synthetic
snapshot recovery and the real container test are useful but different evidence.

## What the measured comparison says

| Metric | Harness | Pi |
|---|---:|---:|
| Mean F3 | 37.0 | 27.3 |
| Mean precision | 53.36% | 68.47% |
| Mean recall | 35.80% | 25.72% |
| Total scored false positives | 152 | 66 |
| Recorded completed cells | 16/18 | 18/18 |
| Gateway requests | 8,118 | 124 |
| Reported prompt + completion tokens | 51,078,255 | 868,500 |

The harness spends about 58.8 times as many reported tokens for this recall gain.
This is not a dollar-cost ratio: cached-token pricing is not established here,
and prompt totals include repeated context. The experiment allows equal wall
ceilings, not equal compute. All 8,242 matrix terminal records have usage; records
from the later review were excluded by experiment ID.

The two failed H cells are documented schema-robustness failures involving
`gaps_observed`. A nondeterministic model output does not make this reliability
problem disappear: users still receive an incomplete run. Fix that advisory-field
handling narrowly, preserving the original scored artifacts.

The success criterion fails because H has fewer scored FPs on only 0, 0, and 2
repos across the three trials, below the required 4/6 in at least two trials.
Unmatched predictions are benchmark FPs, not necessarily disproven vulnerabilities;
determining which are real bugs would require separate source adjudication.

The frozen protocol's failure-scoring text says post-inference output failure
receives empty predictions, while the report scores both failed-output artifacts.
The newer focused plan explicitly permits retained eligible output, so the
documents need reconciliation rather than an undisclosed policy assumption.
The published empty-output sensitivity still fails the overall criterion.

## Recommended next step

Keep the current matrix as a disclosed regression result; do not describe it as
an unconditional integrity sign-off or a win over Pi. Correct the narrow
deadline/admission/identity defects above and the advisory-schema failure, with
regression tests for these exact cases. Correct calibration references and prove
Pi timeout recovery. Do not launch another expensive matrix just because this
one lost. Inspect a small source-backed sample of the harness's extra scored FPs
before deciding whether the existing verifier needs one further targeted change.
