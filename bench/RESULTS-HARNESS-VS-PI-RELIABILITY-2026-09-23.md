# RESULTS — Harness vs Pi Reliability Experiment (2026-09-23)

## Conclusion

**Does not meet the predeclared success criterion.**

The protocol executed to completion: all 36 cells are accounted for under the
unchanged selection rules, no integrity problems were detected, and the
mechanical rule was computed by `bench/realvuln/aggregate.py` against the
official RealVuln matcher. H (codesec multi-stage harness) beat vanilla Pi on
F3 in every trial (35.2 / 36.4 / 39.5 vs 19.4 / 32.8 / 29.8; mean 37.0 vs
27.3, satisfying the +5 conjunct) but failed the required second conjunct —
strictly fewer H false positives on at least 4/6 repos in at least 2/3 trials
was achieved in **0 of 3 trials** (H had strictly fewer FPs on 0, 0, and 2
repos respectively). The result is a genuine harness *recall* win paired with
a decisive *precision/FP* loss, not a harness malfunction.

A pass on this development-visible corpus would only have been regression
evidence anyway; the loss is reported as measured.

## Frozen experiment identity

| Field | Value |
|---|---|
| Experiment | `matrix-20260923-01` |
| Manifest SHA-256 | `fd58ff71c334538c4f94e84e6903f0553c769cbffe462624ef528de2b1c1e42b` |
| Protocol | `bench/realvuln/protocol-v5.json` (protocol_version 2) |
| Isolation image | `sha256:2cc22edaa975bb2006b35569b9257b379bc6dd2c37389cee268176262607b3ae` (declared == resolved) |
| Isolation evidence | `b421b20179e7e906b0c1739480498c4f38bde7503834ea6e3839e8bcef4a6063` (16/16 checks, `isolation-evidence-2026-09-23-v3`) |
| Source tree SHA-256 | `f32bcba43e11eef0681ebf1eb347934dde21d76847c4b3aeb4a0db54fc4a5525` |
| Git HEAD at freeze | `5cd7d2429232a0e627613bbf5bf617e6623aef37` (dirty diff archived, `dirty_diff_sha256 508cb2a0…`) |
| RealVuln benchmark pin | `7a710251f55c17d32d3adcb13d37468e2e3b9e4a` |
| Request fingerprint | `cf9d42d2da75e9ebdefebe30e58b9a33eb2711e2f9d916ec8dfada8e35d59adf` |

Exact settings/scope: 6 Python repos (`realvuln-vampi`,
`-damn-vulnerable-flask-application`, `-python-insecure-app`, `-dvpwa`,
`-lets-be-bad-guys`, `-pygoat`) × 3 trials × {h, v} = 36 cells, seeded
counterbalanced schedule, arms run consecutively with no overlapping provider
load. Model `glm-5.3`, `zai_thinking` enabled, effort `low`, temperature 0.6,
`top_p` omitted, `max_tokens` 32768, context ceiling 262144, streaming on,
enforced by the gateway as a frozen request subset. H concurrency 4, V
concurrency 1.

## All 18 pair outcomes

Durations are arm wall-clock seconds. H = codesec harness, V = pinned Pi
0.85.1.

| Repo | Trial | H status | H s | V status | V s |
|---|---|---|---|---|---|
| damn-vulnerable-flask-application | 1 | completed | 742 | completed | 22 |
| damn-vulnerable-flask-application | 2 | completed | 731 | completed | 24 |
| damn-vulnerable-flask-application | 3 | completed | 998 | completed | 29 |
| dvpwa | 1 | completed | 975 | completed | 28 |
| dvpwa | 2 | **failed_output** | 796 | completed | 27 |
| dvpwa | 3 | completed | 1034 | completed | 32 |
| lets-be-bad-guys | 1 | completed | 670 | completed | 31 |
| lets-be-bad-guys | 2 | completed | 727 | completed | 31 |
| lets-be-bad-guys | 3 | completed | 824 | completed | 39 |
| pygoat | 1 | **failed_output** | 1341 | completed | 59 |
| pygoat | 2 | completed | 1069 | completed | 57 |
| pygoat | 3 | completed | 1473 | completed | 72 |
| python-insecure-app | 1 | completed | 737 | completed | 24 |
| python-insecure-app | 2 | completed | 973 | completed | 28 |
| python-insecure-app | 3 | completed | 919 | completed | 18 |
| vampi | 1 | completed | 809 | completed | 25 |
| vampi | 2 | completed | 1061 | completed | 35 |
| vampi | 3 | completed | 853 | completed | 27 |

### Failures, degradation, retries

Two cells ended `failed_output` (`arm_exit_1`), both H arms, both after real
inference, both with a committed `report.json` that was scored and flagged
`degraded` — never silently upgraded to clean:

- `dvpwa` t2 (cell `358d16220e1b1dda`, attempt `att-a852333aab94`, 796 s):
  hunt task `t_gf_views_reflected_xss_1` failed JSON-schema validation — the
  model emitted `gaps_observed` as an array of objects instead of an object —
  and the post-run coverage check raised `IncompleteRunError`.
- `pygoat` t1 (cell `b8c9d4799e78b0ac`, attempt `att-a8af740ab089`, 1341 s):
  same defect class on task `t_gf_dockerized_labs_pickle_deserialization`
  (`gaps_observed` array-vs-object schema mismatch).

Both are model/schema-robustness failures, not infrastructure failures: the
gateway records show normal admission/terminal traffic, no timeouts, no
setup faults, and `made_inference_requests: true`. The same pygoat cell ID
completed cleanly (1201 s) in the calibration pair, confirming the failure
is non-deterministic model output, not a deterministic harness defect. No
retries were consumed (retry is only for zero-inference setup failures);
no cells were checkpoint-only, timed out, or unaccounted.

Scoring treatment disclosure: the aggregator scored the two committed
`report.json` artifacts and flagged them `degraded` (per the committed-
artifact policy; empty predictions apply only to `failed_no_output`). As a
sensitivity check, re-scoring both cells as empty predictions gives H trial
F3 of 23.0 / 32.1 / 39.5 (mean 31.5 vs V 27.3) — the +5 conjunct fails and
the FP conjunct is unaffected, so the conclusion is identical under either
treatment.

## Scored results (official matcher, pooled per trial)

| Trial | Arm | TP | FP | FN | TN | Precision | Recall | F3 (0–100) |
|---|---|---|---|---|---|---|---|---|
| 1 | H | 55 | 51 | 107 | 29 | 0.5189 | 0.3395 | **35.2** |
| 1 | V | 29 | 8 | 133 | 29 | 0.7838 | 0.1790 | 19.4 |
| 2 | H | 57 | 53 | 105 | 29 | 0.5182 | 0.3519 | **36.4** |
| 2 | V | 50 | 18 | 112 | 27 | 0.7353 | 0.3086 | 32.8 |
| 3 | H | 62 | 48 | 100 | 29 | 0.5636 | 0.3827 | **39.5** |
| 3 | V | 46 | 40 | 116 | 27 | 0.5349 | 0.2840 | 29.8 |
| **mean** | H | — | — | — | — | 0.5336 | 0.3580 | **37.0** |
| **mean** | V | — | — | — | — | 0.6847 | 0.2572 | 27.3 |

Aggregate FP totals: H 152 vs V 66. FP taxonomy (both arms): 4 labeled
decoys, 0 duplicate-positive matches, 214 unmatched.

Per-repo FP comparison (H vs V), the failing conjunct:

| Repo | t1 H/V | t2 H/V | t3 H/V | trials H strictly fewer |
|---|---|---|---|---|
| damn-vulnerable-flask-application | 3/0 | 5/2 | 9/5 | 0 |
| dvpwa | 6/1 | 5/0 | 6/2 | 0 |
| lets-be-bad-guys | 6/3 | 7/2 | 3/12 | 1 |
| pygoat | 24/0 | 16/14 | 16/18 | 1 |
| python-insecure-app | 3/1 | 9/0 | 5/2 | 0 |
| vampi | 9/3 | 11/0 | 9/1 | 0 |

Repos where H had strictly fewer FPs per trial: 0, 0, 2 (needs ≥4 of 6 in
≥2 of 3 trials).

Mechanical rule evaluation (from `reports/aggregate.json`):

- `F3_H >= F3_V + 5`: **true** (37.0 ≥ 32.3)
- `Recall_H >= Recall_V − 0.05 AND Precision_H >= Precision_V + 0.10`: false
  (recall condition true; precision 0.5336 < 0.6847 + 0.10)
- FP conjunct: **false** (0/3 trials)
- Decision: `does_not_meet_success_criterion`

## Reliability accounting

- Clean completion rate: 34/36 = 94.4%; 2/36 honest `failed_output`.
- `verify`: "36 cells complete and accounted"; aggregator `problems: []`;
  all committed artifacts have matching terminal ledger records and
  first-inference-primary attempt selection.
- Deadline recovery (calibration): under a 120 s artificial cap, H hit the
  deadline, exported `report.checkpoint.json` (`checkpoint_only: true`), and
  recorded `failed_output` with inference attribution — the pre-deadline
  checkpoint export path works end-to-end.
- Dead-gateway exercise: with the gateway off the isolation network, both
  arms terminated with `made_inference_requests: false` and zero leftover
  containers — attribution is not fabricated on dead runs.
- Elapsed wall time for the matrix: ~4.8 h (first ledger record to last).
- Token usage (gateway terminal records): 8,242 requests, **0 missing
  usage**; 49,547,980 prompt tokens, 2,398,775 completion tokens
  (383,145 of them reasoning). Dollar cost is not recorded by the provider
  usage payloads (`$0.0000` reported) — token counts are the attributable
  cost data.
- V cells with empty output (0 findings): 3 of 18 (pygoat t1, vampi t2,
  dvfa t1 — scored as zero-prediction completed cells, which is a model
  outcome, not a harness failure; V produced no artifact-level degradation).

## Source-backed examples

Wins (H TPs on `pygoat` t1 where V emitted zero findings; GT ids from
`ground-truth/realvuln-pygoat/ground-truth.json`):

- `pygoat-008` CWE-78 command injection, `introduction/views.py:424`
- `pygoat-006` CWE-502 insecure deserialization, `introduction/views.py:214`
- `pygoat-007` CWE-611 XXE, `introduction/views.py:258`
- `pygoat-027` CWE-78, `introduction/mitre.py:241`
- `pygoat-026` CWE-94 code injection, `introduction/mitre.py:218`

Representative H unmatched FPs (same cell; plausible near-miss claims that
landed outside the official matcher's file/CWE/±10-line window — the
precision cost behind the failed conjunct):

- `introduction/views.py:95` CWE-79 — claimed `GET /xss_lab` reflects `q`
- `introduction/views.py:342` CWE-565 — claimed `ba_lab` cookie-gated
  broken-access
- `introduction/views.py:583` CWE-1336 — claimed SSTI in `a9_lab2`
- `introduction/utility.py:9` CWE-94 — claimed ssrf write-then-execute chain

These are reported as scored; no post-hoc adjudication was applied. V's
FP profile is the opposite: very few claims (e.g. 0–16 findings/cell vs
H's ~30–45), high precision, low recall.

## Calibration evidence (all under v5 hashes, same image)

| Exercise | Result |
|---|---|
| `calib-smoke-20260923-03` | H completed 441 s + V completed 21 s, both inference-bearing; 1 invalid hunt finding quarantined as degraded stage health; 6 superseded dedupe generations retained for audit |
| `calib-deadline-20260923-01` | H `failed_output` at 121 s with checkpoint-only export + inference; V completed 25 s |
| `calib-neterror-20260923-02` | gateway disconnected: H `failed_output`/`arm_exit_1` 211 s, V `setup_failed` ×2; both `made_inference_requests: false`, 0 leftover containers |
| `calib-vampi-20260923-04` | H completed 894 s `report.json`, V completed 60 s `final_file` |
| `calib-pygoat-20260923-04` | H completed 1201 s `report.json`, V completed 60 s `final_file` |
| Isolation suite | 16/16 checks passed under image `2cc22edaa975…` |
| Live parity probes | H (`codesec.local_agent._chat`) and V (Pi 0.85.1 in-container) both reached the gateway through isolation with correct frozen request shape and full attempt attribution headers |
| Live preflight | provider reachability verified from inside the gateway container (`docker exec`) — the gateway has no host-published provider port |

Calibration deviations found and fixed *before* the matrix (protocol
invalidated and re-frozen each time): the neterror spec originally lied
about the gateway URL while an image-baked endpoint override kept the
client connected (now the fault is injected by disconnecting the gateway
and freeze cross-checks spec-vs-baked endpoints); the deadline spec
inherited a 10800 s `wall_ceiling_overrides_s` for pygoat (removed); a
single out-of-range hunt line number killed an otherwise clean arm (fixed
by per-finding quarantine, `filter_hunt_findings`); re-dedupe generations
left orphan active groups (fixed by `superseded_at` generation
supersession).

## Independent review (Pi 0.85.1 + glm-5.3)

An independent review agent — pinned Pi 0.85.1 with `glm-5.3` inside the
same isolation image against the recording gateway (attribution
`pi-review-20260923`/`code-review`) — read the plan, this report, the
aggregate JSON, the ledger, committed markers, and the implementation files
listed in `bench/realvuln-runs/pi-review-20260923/output/review.md`.

Verdict: **SIGN OFF** — no blocking defects. It verified the integrity
requirements in code and evidence (image pinning, ledger-driven accounting,
attribution, honest failure statuses, timeout/cleanup, stale-artifact
rejection, dedupe supersession, hunt quarantine, stage-health propagation)
and independently reproduced the pooled counts and the mechanical decision.

Two non-blocking review findings were fixed post-review and the aggregate
regenerated (decision unchanged):

- `decision.rule_booleans` ANDed the conjunction into each sub-boolean,
  mislabeling the recall condition `false`; each sub-boolean now reports
  its own condition (`recall` is correctly `true` in the regenerated JSON).
- Usage accounting counted every terminal record in the gateway log
  unfiltered; it now filters to `experiment_id == matrix-20260923-01`,
  so the review's own 17 requests (which land in the same shared log file)
  are excluded. `records_found` remains 8242 with 0 missing usage.

Review artifacts: `bench/realvuln-runs/pi-review-20260923/output/review.md`,
`pi.log`, and the gateway records carrying `experiment_id:
pi-review-20260923` in the matrix `requests.jsonl` (the gateway binds one
records file; foreign records are identifiable by `experiment_id` and are
excluded from usage accounting).

## Known limitation / proposed next change

The two matrix `failed_output` cells share one root cause: the hunt schema
rejects `gaps_observed` as an array while GLM-5.3 sometimes emits a list.
One targeted next change (per the plan's "at most one"): either normalize
`gaps_observed`/`uncovered` array→object before schema validation in the
hunt task runner, or loosen the schema for that advisory bucket. This is
model-robustness hardening, not a scoring change; it does not alter the
published result.

## Artifact paths

- Experiment: `bench/realvuln-runs/experiments/matrix-20260923-01/`
- Aggregate: `bench/realvuln-runs/experiments/matrix-20260923-01/reports/aggregate.json`
- Ledger: `bench/realvuln-runs/experiments/matrix-20260923-01/operator/attempts.jsonl`
- Gateway records: `bench/realvuln-runs/experiments/matrix-20260923-01/operator/gateway/requests.jsonl`
- Committed artifacts: `bench/realvuln-runs/experiments/matrix-20260923-01/committed/<cell_id>/`
- Attempt logs: `bench/realvuln-runs/experiments/matrix-20260923-01/attempts/<attempt_id>/`
