# Reliability fixes and FP review — results (2026-09-24)

Plan: `bench/PLAN-RELIABILITY-FIXES-AND-FP-REVIEW-2026-09-24.md` (all steps
A–H executed). Evidence root: `bench/realvuln/repair-evidence/relfix-2026-09-24/`.
Progress log: `bench/realvuln/repair-progress.md` (relfix section).
The saved matrix `matrix-20260923-01` was never modified: its numbers
stand exactly as frozen (F3 H/Pi 37.0/27.3, precision 53.36%/68.47%,
recall 35.80%/25.72%, scored FPs 152/66, decision
`does_not_meet_success_criterion`).

## 1. September 24 findings closed

All five reproduced defects from `REVIEW-RELIABILITY-2026-09-24.md` are
closed and verified by `reverify.py` → `reverify-output.json` on disposable
copies of the saved matrix:

| Review finding | Fix | Post-fix probe |
|---|---|---|
| P1 post-deadline output eligible (both arms) | One monotonic `WorkDeadline` per cell; work supervisor gets the remaining budget (no `+CLEANUP_GRACE_S`); both arms' outputs captured by an operator-side watcher into `exp/attempts/<id>/snapshots/` (never agent-writable); export selects only newest eligible capture (hash+schema re-validated); early normal completion captures final bytes inside the budget; timed-out stop-grace writes are never captured | Both arms REJECT the post-cutoff file |
| P1 invalidation/corruption bypass scoring | `cell_validity()` shared by `cmd_verify` and `aggregate_experiment`; any later invalidation blocks scoring without replacing the primary; corrupt/missing committed evidence is an integrity failure (no headline), never empty predictions | verify exit 1 + no headline; corrupt failed-output cell blocked |
| P1 marker identity unchecked | `arm_done` compares marker repo/cell_id/experiment_id (+ existing arm/trial/manifest hash); wrong-primary and unknown-attribution checks | verify exit 1 + no headline for wrong repo/cell/experiment/trial/arm/hash (each field tested) |
| P1 freeze gates not verified | `validate_admission()`: purpose-aware (calibration/scored) file-reference evidence — contents parsed, gates must be passed, image+runtime-tree binding; `_runtime_hash_inputs()` includes `pyproject.toml`/`uv.lock`; immutable evidence copies under `operator/admission/`; `cmd_run` drift-gates new cell admissions | Ungated freeze (all-zero hash, no evidence) exit 1 |
| P2 advisory-data failure + health | See §3 | Both saved failures replay to full findings+advisories |

## 2. Test evidence

- New regression suites: `tests/test_realvuln_reliability_fixes.py` (36),
  `tests/test_advisory_envelope_repair.py` (11),
  `tests/test_cwe_canonicalization.py` (9), plus shared test helpers
  (`tests/_admission.py`, `tests/_h_health.py`).
- Full suite: **555 passed, 14 skipped** (`0:08:28`). Skips unchanged and
  outstanding by design: 13 × `tests/test_auth.py` (claude CLI not
  installed), 1 × `tests/test_seeded_fp.py` (live-bench marker).
- F.2 audit fix: `test_agent_image_contains_allowlist_only` now builds a
  unique `codesec-iso-test-*` tag; it had silently overwritten the shared
  `codesec-iso:latest` tag during suite runs (the matrix's immutable image
  ID was never affected; the tag was restored to the pinned image
  `sha256:2cc22eda…`).
- Miniature synthetic experiment through the real freeze/run/verify/
  aggregate CLI (`synthetic_cli_run.py`, exit 0): clean success, early
  output + late replacement (pre-cutoff bytes exported), checkpoint
  recovery, no-output failure, late invalidation (verify 1 / aggregate 1),
  corrupt committed artifact (verify 1 / aggregate 1); headline published
  with the official matcher.

## 3. The exact advisory-data failure (step E)

Root cause established by replaying the saved artifact JSONL
(`failing-responses.json`, `replay-fixtures.json`): both scored failures
(`att-a852333aab94`, `att-a8af740ab089`) emitted a **malformed JSON
envelope** (a `{` inside the findings array closed by `]`); the extractor
salvaged the inner `gaps_observed` ARRAY as the "payload"; the schema then
reported `<root> … is not of type 'object'` — a wrong dispatch the repair
turn could not act on.

Repairs (no blanket array-to-object conversion; `finding.schema.json`
unchanged):

- `repair_json_envelope()` / `diagnose_envelope()`
  (`codesec/json_utils.py`): deterministic bracket-level completion
  (insert missing closer at a mismatch, append dangling closers, drop
  unmatched trailing closers, truncate extra-data tails with the dropped
  bytes recorded). Content bytes are never edited.
- `_validated_payload()` (`codesec/local_agent.py`): dispatch guard — an
  object-root schema never accepts a nested fragment; errors name the
  envelope problem with a structural diagnosis.
- Advisory normalization is loss-visible: nested gap arrays flattened
  (equivalent), single gap object/string wrapped, un-preservable items
  quarantined into `AgentResult.repairs` → hunt records a `degraded`
  stage-health event. Invalid findings envelopes are never coerced into
  empty reports.
- **Replay acceptance:** both saved failures now parse to their original
  findings + advisories with the intervention recorded; idempotent; valid
  payloads untouched; malformed security findings still rejected.

## 4. Corrected records and actual-client evidence (step F)

- Dated correction added to
  `RESULTS-HARNESS-VS-PI-RELIABILITY-2026-09-23.md`: the cited
  `calib-deadline-20260923-01`/`calib-neterror-20260923-02` ran under the
  older image `b2906536…`; correct v5-image citations are
  **`calib-deadline-20260923-09`** and **`calib-neterror-20260923-07`**;
  unconditional sign-off language withdrawn (the v5 deadline run also
  stopped H only via the then-current `timeout_s + CLEANUP_GRACE_S`
  allowance, and its V completed in 12.36 s — the V deadline path was not
  exercised).
- New immutable images (unused tags, repaired source):
  `codesec-iso-relfix-20260924` = `sha256:f08faaa8…` (16/16 isolation
  checks) and `codesec-iso-relfix-deadgw-20260924` = `sha256:78d7e42b…`
  (15/15, no-gateway mode). Isolation evidence:
  `iso-evidence-relfix.json` / `iso-evidence-relfix-deadgw.json`
  (runtime-tree bound). Shared gateway never disconnected; test gateway
  `codesec-gateway-relfix` on its own alias, removed afterwards;
  `config/zai-glm53-experiment.yaml` restored byte-identical.
- Actual-client calibration (all evidence in `f-evidence.json`):
  - **`calib-relfix-hs-20260924-01`** — clean smoke + real parity: H
    `completed` 430 s, exit 0, `report.json`, **stage health clean=true**,
    5 findings; V `completed` 15.7 s, 6 findings. Usage: H 140 requests /
    661,593 prompt / 43,176 completion tokens; V 4 / 7,496 / 1,049.
  - **`calib-relfix-hr-20260924-01`** — nonempty timeout recovery: H
    stopped at 211.9 s of a 240 s cap (internal budget + reserve), the
    operator-owned checkpoint capture exported **3 findings**;
    `failed_output` with health clean=false. V completed (6 findings).
  - **`calib-relfix-dh-20260924-03`** — H deadline at a 150 s cap:
    checkpoint capture (0 findings at that point), `failed_output`
    (arm_exit_1), degraded. V completed (5 findings).
  - **`calib-relfix-dv-20260924-01`** — **V deadline**: Pi cut mid-flight
    at a 9 s cap (3 admission/terminal pairs prove in-flight work),
    `failed_no_output`/`deadline_no_output` — paired with hr-01's nonempty
    recovery, not claimed equal. H below its 30 s reserve correctly
    refused to start model work (`setup_failed`/`no_inference`).
  - **`calib-relfix-net-20260924-01`** — dead-endpoint image: both clients
    fail fast with bounded retries, 0 leftover containers, no committed
    output; with no gateway records the attribution is UNKNOWN and
    verify/aggregate flag the cells — by design (never guess). Trusted
    dead-**upstream** handling (502 `gateway_upstream_unreachable` with
    admission records intact) is evidenced by `calib-relfix-dh-20260924-01`:
    H's bounded 4-attempt backoff then deadline, V fast failure.
- `protocol-v6.json` records the corrected failure-scoring policy
  explicitly (scored+degraded retained output; empty predictions only for
  genuine accounted no-output; integrity failures block the headline) and
  documents the v5 text/report discrepancy as history; the v5
  empty-output sensitivity analysis is retained.

## 5. FP review (step G) — summary

24 unique H FP claims (28 occurrences) + 6 Pi claims, seed 20260924,
manifest saved before source inspection (`fp-sample-manifest.json`;
classifications `fp-classifications.json`; narrative `fp-review.md`):

| Category | Unique claims | Occurrences |
|---|---:|---:|
| Reporting/matching error | 10 | 13 |
| Real issue outside labels | 5 | 5 |
| Duplicate | 5 | 5 |
| Incorrect security claim | 4 | 5 |

Dominant actionable cause: **location/CWE reporting errors** — 6 claims
used a CWE outside the GT entry's `acceptable_cwes`, 3 were just outside
the ±10-line window with an accepted CWE, 1 named the wrong file (an
OpenAPI spec instead of the handler). Sample limitations as stated in
`fp-review.md`; no scores altered.

## 6. The one quality change (step H) and its diagnostic

Change: narrow evidence-to-report CWE canonicalization in the
deterministic report stage (`codesec/stages/report.py::_canonical_cwe`),
keyed on the finding's own evidence, developed from the seeded dev half
only: (a) SSTI via an expression-evaluating engine (e.g. `ImageMath.eval`)
→ CWE-94; (b) brute-forceable low-entropy authentication factor (OTP/PIN
leaked to the response) → CWE-287; (c) a shipped debug-config statement as
the evidence → CWE-16. No coordinates or CWEs are selected from GT at
execution time.

Offline deterministic replay of the saved matrix H arm (`h-replay.json`,
zero model usage): **TP +4 (174→178), FP −4 (152→148)** — all four
targeted classes converted; **zero TP regressions**; true-positive
controls untouched (0 pickle/deserialization renumberings); the reserved
diagnostic half (3 claims: 837→94, 565→639, 287→639 classes) was **not
touched** — the change does not generalize there, and per the plan that
uncertainty is reported with no further tuning of this sample. Unit
regression: `tests/test_cwe_canonicalization.py`.

## 7. Go/no-go for another scored matrix

**Decision: NO-GO now.** Reasons and the conditions that would change it:

- **Reliability gates: CLOSED** for all five review findings, with
  regression tests and actual-client evidence for deadlines (both arms),
  recovery (nonempty checkpoint capture), clean-smoke health propagation,
  and dead-gateway/upstream handling (trusted-record and no-record cases).
- **Quality evidence: partial and honest.** The single quality change
  converts 4 sampled-class FPs on replay with zero TP harm, but the
  reserved diagnostic half shows the broader location/CWE class is not
  covered (3 untouched claims; 3 further location misses and 1 wrong-file
  case in the sample would need localization changes not attempted).
  Expected matrix effect is small: a −4 FP replay delta on 152 scored FPs
  does not approach the predeclared success rule (which failed on
  fewer-H-FP repos: 0/0/2 of 6).
- **Cost/quota reality:** the matrix's H arm consumed ~8.1 k gateway
  requests / ~51 M reported prompt tokens; this repair's entire actual-
  client evidence cost 190 requests / ~892 k prompt tokens. A new full
  matrix (~36 cells) would spend matrix-scale usage again for a decision
  whose dominant remaining lever (label-gap + localization FPs) the
  harness cannot honestly move much further.
- **A new matrix WOULD be informative when:** (1) a protocol change aims
  at a hypothesis the FP review actually supports (e.g. a localization
  improvement with its own dev/reserved evidence), or (2) the benchmark's
  label gaps are adjudicated separately and the comparison question is
  re-scoped; and VAmPI/PyGoAt calibration is rerun against the exact
  final runtime (new runtime hashes cannot inherit the relfix
  calibration passes — `calib-relfix-*` bound the repaired runtime and
  the f08faaa8… image; any further prompt/config edit invalidates them).

No automatic full-matrix launch is part of this plan; none was run.

## 8. Residual limitations (explicit)

- The 14 outstanding test skips (auth CLI, live-bench marker) remain.
- Attribution for a fully-dead gateway is unknowable by design (no
  trusted records) — such cells are invalid rather than setup-failed; the
  dead-upstream variant (gateway alive) is the testable path and is
  evidenced.
- The FP review is a 24-claim stratified sample; its category counts are
  not a full-matrix precision estimate, and the 5 real-issues-outside-
  labels claims are disclosed benchmark label gaps, not harness wins.
- The canonicalization improves the three classes it targets; claims that
  rest on nearby-but-out-of-window locations, wrong files, or unlabeled
  real issues are unaffected (by design of "at most one change").
- Historical P00-era in-place edits before the ws1 archive remain a
  recovery limitation for those files (unchanged by this plan).
