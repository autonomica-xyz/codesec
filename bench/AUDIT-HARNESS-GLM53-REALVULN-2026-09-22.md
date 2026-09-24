# Audit of the GLM-5.3 RealVuln experiment

Execution follow-up: [repair and retest plan](PLAN-REALVULN-REPAIR-AND-RETEST.md)
with ordered implementation tasks, regression tests, and mandatory run gates.

The published F3 arithmetic reproduces, but the explanation of the failure does
not. This is evidence about a defective, partially degraded implementation of
codesec, not a controlled measurement of the intended eight-stage pipeline.
The observed final output did not meet the original success rule. That conclusion
survives this audit; a general conclusion about the value of the architecture does
not follow.

This audit covers the **18 scored GLM pairs**, excluding smoke. It reads saved
Semgrep files, operator maps, SQLite databases, logs, and Pi sessions. No model
requests were made and no historical outputs were overwritten. The current
benchmark checkout matches the recorded SHA:
`7a710251f55c17d32d3adcb13d37468e2e3b9e4a`.

Reproduce the numeric audit from the codesec root:

```bash
.venv/bin/python -m bench.realvuln.audit_saved_run > /tmp/realvuln-audit.json
```

Saved evidence: [audit JSON](realvuln/audit-glm53-2026-09-22.json) and
[audit program](realvuln/audit_saved_run.py). The JSON includes per-cell counts,
opaque run IDs, and hashes of scoring inputs/databases/logs. Historical request
bodies and source snapshots are not complete, so this is not a reconstruction of
every inference parameter used at run time.

**1. Critical: the blinding directory broke codesec's search tools.**

[`local_agent.py`](../codesec/local_agent.py) includes `target` in
`_IGNORED_PARTS`; Grep and Glob check every component of the **absolute** path.
Every blinded repo is `/tmp/<opaque>/target`. Consequently, every file is filtered
out. Checking exclusions relative to the repo root would avoid this collision.
Grep also iterates `root.rglob(...)` when `path` is a file, so that supported-looking
usage returns no results independently of the directory-name bug.

Direct reproduction: create `target/app.py` containing `eval(payload)`, then call
`_exec_tool` with that repo. Read returns `1:eval(payload)`; Grep for `eval` and Glob
for `**/*.py` both return `(no matches)`.

Across saved H stage transcripts, including repair/retry transcripts:

| Tool | Calls | No matches | Tool errors | Successful nonempty results |
|---|---:|---:|---:|---:|
| Grep | 8,276 | 8,089 | 187 | 0 |
| Glob | 6,084 | 5,677 | 407 | 0 |

Agents sometimes recovered with Bash searches. This still wasted turns and made
negative search results untrustworthy. A smoke test that merely writes a report
cannot catch this. Before rerunning, exercise every actual agent tool against the
blinded directory layout, including file-scoped searches and pagination.

**2. Critical: Dedupe and Report failed in every scored H run.**

All **18/18 Dedupe calls** and **18/18 Report calls** hit the local engine's
`pack_user_input` limit of **50,000 characters**. For example, VAmPI trial 1
(`b8389c35`) logs a Report input of **116,739 characters**.

Dedupe's fallback treats each confirmed finding as a singleton. The intended
deduplication was therefore absent. Report used its fallback renderer. This was
not an isolated local Unsloth context-capacity problem; it affected the completed
hosted GLM matrix too.

Fix the payload design with bounded summaries and evidence references, and batch
deduplication with an explicit final partition check. Alternatively, make
deterministic reporting the intended, tested design and declare that in the
protocol. Do not silently call a fallback a successful execution of the planned
stage. Simply increasing the character limit leaves token/output growth and
large-repo failures unresolved.

**3. Critical: the claimed Trace failure mechanism is wrong.**

The report says closing mode skipped remaining Trace work and left confirmed
findings untraced. The databases instead contain:

| Scored H finding state | Count |
|---|---:|
| Confirmed and canonical | 340 |
| Trace reachable | 156 |
| Trace uncertain | 178 |
| Trace unreachable | 6 |
| Confirmed canonical without a trace | **0** |

Of the 178 uncertain traces, **133 were downgraded by semantic validation**:
95 did not end inside the authoritative finding's sink range; 38 violated other
contract checks, including references to dependency files outside the repo.
These errors need examination and repair, not automatic conversion to reachable.
The Trace prompt describes backward traversal while the contract requires an
entry-to-sink output order, an exact final sink range, repository-local frames,
and at least two frames. State that contract explicitly, support direct
entry-to-sink cases deliberately, and feed semantic errors into bounded repair.

The other **45 uncertain traces all mention canary/marker requirements**;
**44 mention `server.local`**, the illustrative host in
[`06-trace.md`](../prompts/06-trace.md). These were source-only runs. At least one
saved Recon tool call also attempts `http://server.local:8888/`. The template's
live-target example and conditional marker instructions are being interpreted as
real inputs. Separate static and live prompts, omit fabricated concrete hosts,
and explicitly state `live_target: null`, `markers: null`, and the applicable
evidence policy. Missing dynamic evidence must not invalidate an otherwise
sufficient static trace in the static arm.

The reported **98 Hunt TPs absent from Final** reproduces. Looking up the matched
Hunt finding IDs gives 83 confirmed/uncertain, 11 rejected, 3
confirmed/unreachable, and 1 confirmed/reachable. That final case also illustrates
why matching and reporting transformations need inspection rather than treating
every score loss as a missing report member.

The report's `350 confirmed / 44 rejected` includes more than the scored matrix:
the 18 scored databases contain **340 confirmed / 43 rejected / 5 needs-more-info**.

**4. Critical control failure: “thinking off” was not established.**

All **18 scored Pi sessions record `thinkingLevel: low`**, despite the shell
metadata/prompt invocation saying `off`. Codesec sends
`chat_template_kwargs.enable_thinking`, omits Z.AI's `reasoning_effort`, and records
`thinking=unset-sdk` even though the local engine was used. Its SSE reader also
does not preserve `reasoning_content` between tool calls.

Current official [Z.AI GLM-5.3 documentation](https://docs.z.ai/guides/llm/glm-5.3)
states that reasoning is always enabled, with `low`, `high`, and `max` effort;
the default is `max`. Thus the two arms plausibly ran different effort levels.
The exact historical server behavior is not recoverable from flags alone.

Before rerunning, capture sanitized outbound requests for both clients and check
the actual endpoint, model, `thinking`, `reasoning_effort`, sampling parameters,
output limit, context handling, and reasoning-history policy. Choose a supported
common effort explicitly. A check of model names or CLI flags is insufficient.

**5. The time-budget explanation is also misleading.**

[`orchestrator.py`](../codesec/orchestrator.py) sets `_CLOSING_FRACTION = 0.8` and
enters closing mode when remaining time is at most 80% of the initial budget.
That is **20% elapsed**: 24 minutes into a two-hour allocation, or 36 minutes into
three hours. “Time budget nearly spent” therefore does not mean near exhaustion.
Closing skips later Gapfill/Feedback work; the initial Trace call still runs.

The deadline checks gate new Hunt breadth work, not every stage or in-flight
request. PyGoat trial 3 lasted **17,851 seconds (4 h 57 m)** under a nominal
three-hour allocation. The initial VAmPI trial used concurrency **10**; later
trials used **4**, so the whole matrix was not run at concurrency four.

Define a real deadline and an explicit synthesis reserve. Drain or cancel work
consistently, record timeouts, and serialize the effective configuration. Keep
concurrency fixed after calibration.

**6. The comparison needs a precise resource question, not forced busywork.**

The original plan explicitly allowed different token use and wall time, so the
budget asymmetry is not by itself a violation of that plan. It measures the two
configured products, however, not architecture quality at equal resources.
Pi did execute a tool loop: **4–14 tool calls per scored session**. Calling it a
“one-shot dump” is inaccurate. Available scored Pi metadata spans **13–133
seconds**, not just 15–40 seconds; VAmPI trial 1 has no `benchmark_meta.txt`.

Use two separately named comparisons if both questions matter:

- The default-session product comparison, retaining early termination and
  reporting actual quality, tokens, latency, and completion rate.
- A resource-controlled comparison with a preregistered common token/cost budget
  and wall-clock ceiling. If Pi gets continuations, freeze a generic continuation
  policy in advance and call it a different arm. Do not prompt until its score
  looks competitive or force it to consume time after it declares completion.

**7. Aggregation and runner success are not reliable experiment gates.**

[`aggregate.py`](realvuln/aggregate.py) discovers whatever `run-*.json` happens to
exist. It checks missing directories, not the expected slug × arm × trial cells.
It can return success with missing trial files or only metrics sidecars, pool
different repo sets, include extra trial numbers, and compute headline means on
incomplete data. The local H “3.7” uses 23 positive labels in trial 1 and 15 in
trial 3, versus 162 in every Pi trial. It is not an experiment-level H estimate.
The report correctly declines to compare those local H numbers.

Other runner defects:

- `run_trial` swallows failures. Smoke can print `smoke ok` after failed arms
  because smoke has no completeness gate. A final success message is not proof
  of stage success.
- `arm_done` checks only file existence. It neither validates JSON nor matches
  model/configuration/protocol hashes. An interrupted two-file export can leave
  a Hunt file that prevents retry from publishing a new pair of outputs.
- Six scored GLM H processes exited nonzero; the wrapper accepted their existing
  reports. Keep them in the operational comparison, but report degraded status
  and failures explicitly. Do not silently retry poor-quality valid outputs.
- One shared `failed-trials.txt` is copied and truncated for retries. It is not
  scoped to tag, model, wave, or experiment, so historical cells can be replayed
  under a different current configuration.
- Shell `CODESEC_REALVULN_RUNS` overrides are not honored by Python's fixed
  `RUNS_ROOT`/`OPERATOR_DIR`. Custom isolated run roots can fail allocation lookup.
- The setup records the benchmark HEAD but does not enforce that pin on future
  runs; prepare copies the GT commit string without checking the source checkout
  or verifying unchanged source lines.

Replace discovery-by-glob with an immutable expected-cell manifest and an
append-only attempt ledger. Publish validated outputs atomically with a completion
record. Scope retries to the experiment and record the first attempt, retry
reason, configuration, and selected artifact. For confirmatory quality, block a
headline until all expected cells are accounted for. For operational reliability,
retain failures in the denominator using a frozen scoring rule. Reconcile the
current plan's conflicting “all-FN” versus “invalid/re-run” instructions first.

**8. Blinding and contamination claims are stronger than the controls.**

Keeping the key outside `target/` is useful, but the agent's Bash runs as the host
user and is not filesystem-confined. A mode-0600 operator map owned by that same
user is readable by the agent. GT, prior outputs, host configuration, and network
access are not made inaccessible by setting cwd. This demonstrates exposure,
not evidence that a particular agent read the answer key.

Use a separate user/container/VM with only the blinded source, scratch space, and
output location mounted, plus controlled provider access. Verify negative access
tests for GT, maps, prior runs, host home, and unrelated network destinations.
Pair H and V on byte-identical prepared trees; the current per-arm random canary
means the paired input digests differ.

The appended canary is an uncalled `eval(payload)` function. A reviewer asked for
externally exploitable bugs may correctly omit it. Missing it is not evidence of
memorization. Treat it only as a weak source-attention diagnostic, or use a
separate reachable mutation suite. Its 12-line padding also does not prevent
overlap between **two ±10 matching windows**; strip the inserted interval
precisely or ensure disjoint windows, including acceptable GT locations.

Identity diagnostics are asymmetric: H scans its entire run directory, including
operator/framework logs, while V scans only `findings.json`. Paths containing
`realvuln-runs` can trigger H flags without model recognition. Measure identity
mentions in equivalent model-authored output fields, record residual identities
in source separately, and report that public educational apps remain recognizable.

**What the offline report-policy check actually shows.**

Using the saved confirmed canonical findings, the existing canary filter, and the
same RealVuln matcher, without any new inference:

| Output policy | Mean micro F3 | Trial F3 values |
|---|---:|---|
| Historical Hunt | 40.4 | 38.5, 37.7, 45.0 |
| Historical Final | 20.8 | 20.7, 21.1, 20.5 |
| Historical Pi | 21.4 | 18.1, 21.4, 24.7 |
| All confirmed canonicals | **38.4** | 36.1, 37.4, 41.7 |
| Confirmed except explicitly unreachable | 37.8 | 35.5, 36.8, 41.1 |

This is a **post-hoc membership ablation**, not a fresh run of the patched
pipeline. It does not repair search, Dedupe, Trace, or inference settings.
Shipping everything confirmed also includes six explicitly unreachable findings;
that changes the product's evidentiary standard, not just report completeness.

Historical Final has fewer FPs than Pi on **2, 0, and 1** of six slugs in trials
1–3. The all-confirmed ablation does so on **0, 0, and 0**. Neither meets the
preregistered requirement of at least four slugs in at least two trials. A larger
F3 alone does not pass the original success rule.

Also distinguish benchmark-unmatched reports from proven false alarms. The saved
Final has 61 benchmark FPs: six match already-covered positive locations and 55
are unmatched; none match a labeled decoy. Keep the official score unchanged,
but blind-adjudicate unmatched findings as a secondary analysis. The current
greedy matcher can also be order-sensitive for overlapping labels; preserve its
version and original order for the headline, and label any sensitivity analysis.

**Required sequence before a confirmatory rerun.**

1. Preserve this matrix as exploratory; freeze its source/configuration evidence
   as far as recoverable. Do not overwrite it with the ablation or new outputs.
2. Repair search, payload sizing, static Trace instructions/contracts, provider
   settings, and deadline accounting. Decide which evidence tier the primary
   report represents before seeing new scores. Keep explicit unreachable,
   uncertain, and confirmed/reachable counts visible.
3. Add failure-injection checks for missing/invalid cells, partial export, timeouts,
   retries, tag separation, and smoke failure. The current focused suite passes
   **43 tests**, yet it misses the failures above; passing it is insufficient.
4. Run unscored calibration on a small app and a representative large app.
   Require functional tools, explicit resolved wire settings, bounded payloads,
   a deliberately exercised finalization path, and correct completion accounting.
   Any fallback must be declared as intended behavior or make the calibration
   gate fail. Do not use two favorable scored repos as confirmation.
5. Freeze an experiment manifest: source snapshot including dirty changes,
   prompt/schema/config hashes, benchmark and app SHAs, prepared-tree hashes,
   adapter/scorer versions, client versions, endpoint/effort/sampling settings,
   budgets, environment limits, randomization seed, and failure/retry rules.
6. Run the full paired matrix with randomized/counterbalanced arm order and no
   overlapping provider load. Preserve every attempt and actual resource usage.
   For local serving, independently supervise the server and verify effective
   context capacity and worst-case requests under the intended concurrency before
   admitting it to the matrix. A `/v1/models` response alone is insufficient.
7. Report the frozen primary metric and full decision rule, completion rates,
   per-repo and per-trial deltas, FP taxonomy, evidence-state attrition, tokens,
   wall time, and famous/obscure diagnostics. Six repos are the independent corpus
   units; repeated trials are not additional independent applications. PyGoat
   contributes 78/162 positives, so include equal-repo sensitivity without changing
   the primary micro metric.
8. Use the already-inspected six repos for regression. Reserve an untouched set
   for a confirmatory claim after these result-informed repairs. A repeat on the
   same six is useful engineering evidence, but not a pristine held-out test.

No experiment can promise perfection. These gates make failures visible and the
comparison reproducible, which the current “18/18 scored” condition does not.
