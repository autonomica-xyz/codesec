# Plan — ship confirmed findings (do not throw them away)

Status: **planned**. Fixes the RealVuln glm-5.3 result: hunt F3 40.4 vs
final 20.8 because `report.py` only ships TRACE-reachable canonicals, and
almost every H trial hit closing mode before Trace finished.

Evidence: 98 hunt TPs absent from final; Validate confirmed 350 vs
rejected 44; `overnight.log` `closing mode: time budget nearly spent —
skipping` on essentially every codesec trial.

---

## 1. Goal

**Confirmed, canonical findings must appear in `report.json` even if Trace
did not run or returned `uncertain`.** Trace is an annotation, not a
survival filter.

Hunt, Validate, and Dedupe stay as they are. This is a report-membership
and completeness-contract change, plus a small orchestrator change so
closing mode cannot convert “budget gone” into “delete confirmed TPs.”

Success on the already-scored glm-5.3 matrix (offline rebuild, no new
API): final-report recall moves toward hunt recall (~0.40) without
requiring a 20-hour rerun. Precision will likely sit between hunt (0.52)
and current final (0.62). That is acceptable: the failure mode we are
fixing is silent TP deletion, not hunt noise.

---

## 2. Current kill path (do not re-litigate)

1. Hunt writes candidates → Semgrep `codesec-glm53-hunt`.
2. Validate confirms most of them (350 vs 44).
3. Dedupe sets `is_canonical`.
4. Trace is supposed to mark `reachable`.
5. Closing mode skips leftover Trace/feedback (`orchestrator.py` ~278–305).
6. `get_reachable_canonical_findings` (`state.py` ~1018–1024) keeps only
   confirmed + canonical + `trace.reachable == true`.
7. `run_report` / `_build_fallback_report` iterate that list only
   (`report.py` ~180, 239, 341).
8. `completion_gaps` still flags canonical confirmed with **no** trace
   row (`state.py` ~514–530), so a budget-truncated run is
   `IncompleteRunError` *and* missing TPs in the report.

---

## 3. Design

### 3.1 Report membership (the actual fix)

Replace “reachable canonicals” as the report input with **confirmed
canonicals**:

```python
def get_report_findings(self, run_id) -> list[tuple[Finding, dict | None]]:
    """Confirmed + canonical. Trace may be missing."""
    out = []
    for f in self.get_findings(run_id, validation_status="confirmed",
                               canonical_only=True):
        out.append((f, self.get_trace(run_id, f.finding_id)))
    return out
```

Keep `get_reachable_canonical_findings` for **Feedback** only (still
wants exploits that have a path). Do not use it for report membership.

### 3.2 Trace as annotation

Each report finding’s `trace` object:

| Situation | `trace.status` | `entry_points` / `call_chain` |
|---|---|---|
| Trace `reachable: true` | `"reachable"` | as today |
| Trace `reachable: false` | `"unreachable"` | as today (may be empty) |
| Trace `uncertain` | `"uncertain"` | as today |
| No trace row | `"untraced"` | `[]` / `[]` |

Schema (`schemas/report.schema.json`):

- Description: drop “only reachable, deduped findings.”
- Add `trace.status` with
  `enum: ["reachable", "unreachable", "uncertain", "untraced"]`.
  **Compatibility:** bump is in-repo only (no external report consumers).
  New writers always emit `status`. Readers: if `status` absent, derive
  from non-empty `call_chain` → `reachable`, else `untraced`. Tests for
  both shapes. Do not make old on-disk `report.json` files a runtime
  dependency.
- Empty `call_chain` / `entry_points` already valid (arrays, minItems
  unset). `_build_fallback_report` must emit empty arrays for untraced,
  not omit `trace`.

Agent-written reports (`run_report` ready_findings): pass every confirmed
canonical, including `trace: null`. **Do not trust the agent list as
membership.** After the agent returns (or on fallback), **reconcile
deterministically**: union of confirmed canonical IDs, authoritative
`trace.status` from the DB, recompute `summary`. A schema-valid empty
`findings: []` must not ship if confirmed canonicals exist
(`report.py` ~311 currently would accept it). `fixed_upstream` stripping
stays the only allowed membership shrink.

Update `prompts/08-report.md`: it currently forbids shipping unreachable
findings and allows deleting everything when nothing is “high
severity.” Both instructions contradict this plan. PR 1 must rewrite
them (emit `trace.status`, never drop confirmed canonicals for
reachability or severity).

### 3.3 Completeness contract

`completion_gaps`: **remove** the “canonical finding has no terminal
trace” gap. Missing traces are expected under budget. Keep:

- unfinished tasks
- unvalidated findings
- confirmed findings with no `group_id`
- **group has no canonical finding** (`state.py` ~532 — still required)

A run that confirmed and grouped everything but skipped Trace is
**complete** with `trace.status=untraced` on those findings. Do not
raise `IncompleteRunError` for missing traces.

Optional run-status field later (`trace_coverage`); not required for this
fix.

### 3.4 Closing mode (orchestrator)

Today: after first Trace, if `_closing()`, skip **feedback** (good) then
still `run_report` on the truncated reachable set (bad).

Change:

1. After Dedupe, always `run_trace` once (already).
2. If `_closing()` after that Trace, **skip feedback** (unchanged) and
   go to report — report now includes untraced confirmeds.
3. Do **not** skip Trace itself to save budget. If we must skip
   something, skip feedback (already) not Trace. If Trace is mid-flight
   when the cap hits, remaining findings stay `untraced` and still ship.

No new stage. No Hunt/Validate change.

### 3.5 Review queue

Extend `review_queue.json` (already lists `needs_more_info` and
`trace_uncertain`):

- `trace_untraced` — confirmed canonical, no trace row
- `trace_unreachable` — confirmed but Trace said not reachable
  (shipped in the report, flagged for human review)

Unreachable confirmed still **ship**. Product choice: a confirmed sink
without a demonstrated entry point is still a finding; reachability is
evidence quality, not existence.

### 3.6 CLI status

`codesec/cli.py` ~499–500 prints reachable counts. Add untraced /
confirmed-canonical totals so operators see “12 confirmed, 5 traced
reachable, 7 untraced” instead of a silent drop.

---

## 4. Out of scope

- Hunt/Validate prompts or voting.
- Raising `--max-hours` as the primary fix (we still must not drop TPs
  when the cap hits).
- Changing RealVuln scoring.
- Re-running the 18-trial API matrix (optional later). First prove the
  fix by **rebuilding reports from existing `state.db`**.

---

## 5. Offline replay (prove it on the glm-5.3 matrix)

Add `python3 -m bench.realvuln.rebuild_final_from_state`:

- For each Wave 1 H `state.db`, emit Semgrep JSON from confirmed
  canonical findings (same adapter rules: CWE + path + lines; strip
  canary).
- Write `scan-results/{slug}/codesec-glm53-final-untraced/run-{t}.json`
  (new scanner slug — do not overwrite the original finals).
- `aggregate.py` that extra slug vs hunt vs Pi.

Pass criterion: mean micro recall of the rebuilt finals ≥ hunt recall −
5 pts (we should recover almost all 98 killed TPs that were confirmed
canonical). If rebuilt recall stays near 0.19, membership is not the
bug (adapter/CWE/canonical flags) — stop and inspect `is_canonical` /
CWE before merging.

---

## 6. Tests (mandatory)

- `get_report_findings` includes confirmed canonical with no trace.
- `_build_fallback_report` emits `trace.status=untraced` and empty
  chains; schema validates.
- **Both** `run_report` and `run_deterministic_report` preserve
  reachable, unreachable, uncertain, and untraced canonicals; exclude
  rejected / unvalidated / noncanonical.
- Schema-valid agent payload that **omits** IDs is reconciled back to
  the full confirmed-canonical set.
- Feedback fixture: mixed traces; only `reachable: true` reach
  `run_feedback`.
- `completion_gaps` does not list missing traces.
- Orchestrator: closing after first Trace still calls `run_report`;
  report contains untraced confirmeds (mock Trace skipping leftover
  ids).
- Existing reachable-only tests for **feedback** still use
  `get_reachable_canonical_findings`.
- Review queue lists `trace_untraced` (and unreachable) on **both**
  report paths, not only deterministic.

No `pkill -f`.

---

## 7. PR plan

**PR 1 — membership + schema + gaps** (no orchestrator behavior yet)

- `state.py`: `get_report_findings`; stop using reachable for report.
- `report.py`: membership from `get_report_findings`; **deterministic
  reconcile** after the agent; untraced traces; `08-report.md` rewrite.
- `schemas/report.schema.json`: `trace.status` always written by new
  code.
- `completion_gaps`: drop missing-trace gap; keep no-canonical-in-group.
- Unit tests above.
- `cli.py` status counts.

**PR 2 — review queue + CLI copy**

- `review_queue.json` reasons.
- Docs: report description; README one paragraph.

**PR 3 — offline replay**

- `bench/realvuln/rebuild_final_from_state.py`
- Document numbers in `bench/RESULTS-HARNESS-GLM53-REALVULN-*.md`
  addendum (rebuilt vs original final).

Orchestrator closing-mode comment-only in PR 1 if behavior is already
“always trace once then report.” Confirm `run_trace` is not skipped
today (it is not; only feedback is). **No orchestrator logic change
required** if PR 1 ships untraced confirmeds. Add a test that closing
after Trace still reports untraced ids so a future skip-Trace patch
cannot regress.

---

## 8. Risks

| Risk | Handling |
|---|---|
| Shipping untraced FPs lowers precision | Expected; recall is the broken metric. Replay will quantify. |
| `is_canonical=0` duplicates | Still only canonicals; duplicates stay grouped. |
| Agent report path omits untraced | Fallback report is authoritative on schema failure (already). Deterministic report path (`run_deterministic_report`) is the source of truth when used; default `run_report` must pass untraced in `ready_findings`. |
| Schema consumers require non-empty call_chain | None in-repo; empty arrays are valid. |
| IncompleteRunError was hiding other gaps | Tests list remaining gap types; replay will fail loudly if tasks/validation still incomplete. |

---

## 9. Key decisions

1. **Ship confirmed canonicals; Trace is optional evidence.** Matches
   the measured failure (98 killed TPs, Validate not rejecting).
2. **Unreachable confirmed still ships**, flagged in the review queue.
   Reachability is not existence.
3. **Do not require traces for run completeness.** Budget-truncated
   traces are a quality field, not a hard fail.
4. **Prove on existing `state.db`s** before another live matrix.
   Replay is necessary but not sufficient: unit tests must prove the
   **writer** preserves IDs (agent omit + fallback), because replay
   bypasses `run_report`.

Reviewed by Codex **gpt-6-astra** (not glm-5.3). Blockers from that
review are folded into §§3.2–3.3, 6, 7.
