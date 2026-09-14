# Implementation plan: detection + quality ideas from the harness survey

Scope: every idea from `docs/harness-ideas-for-codesec.md` and
`docs/tsecbench-team-repos-analysis.md` that improves **detection** (more true
findings) or **detection quality** (correct verdicts, honest severity,
trustworthy report). Ops/safety items (sandbox, nonce boundary, failover,
budget reservation) are out of scope here; they are prerequisites only where
marked.

Evidence base for rankings: Cloudflare skill + blog (multi-run additivity,
candidate-gate rules), Anthropic defending-code blog + triage skill (verifier
isolation, precondition severity, streaming, novelty), VVAH source (bypass
hints, canary markers, auth-on-the-wire), codex-security (stopAfterNoNew,
cross-scan catalogue), mantis (production-viability critic, snapshot drift),
Strix (coverage ledger provenance), round_table (KnightPolicy, negative
knowledge), StrikeAgent (evidence-gated statuses).

---

## 1. Confidence ranking

Confidence = strength of external evidence × cheap to verify on our bench ×
low regression risk. Not effort — effort is in §3.

| # | Item | Axis | Confidence | Why |
|---|------|------|-----------|-----|
| W1 | Validator input projection | quality | **High** | Anthropic reported it directly ("verifier may simply agree"); one-function diff; instantly A/B-able on panel reject-rate |
| W2 | Severity from preconditions, evidence-first | quality | **High** | Anthropic's rubric, shipped in their triage skill + VVAH judge has `_preconditions`; anti-anchoring is measurable (severity MAE vs ground truth) |
| W3 | Escalation discipline in candidate gate | quality | **High** | Cloudflare + Anthropic state the identical rule; zero-risk prompt addition |
| W4 | Per-CWE bypass hints | both | **High** | VVAH ships it as their *only* hints source in production; trivially reversible |
| W10 | Recall-preserving Hunt discipline | detection | **High** | Anthropic "learned this the hard way"; hunt prompt currently under-specifies this |
| W13 | Cleaner-replaces-canonical dedupe | quality | Med-High | Anthropic judge `DUP_BETTER`; deterministic pre-filter already proven in duo-v1 |
| W9 | Coverage-critic Gapfill + `uncovered` + negative knowledge | detection | Med-High | Cloudflare critic waves + round_table/CyberPenda dead-end rule; codesec's gapfill already has the inputs (`refuted_patterns`), just under-uses them |
| W16 | Drift re-check at synthesis | quality | Med-High | mantis; trivial once fingerprints exist; prevents stale reports |
| W6 | Canary markers + auth-on-the-wire | both | Medium | VVAH production oracle; needs a served bench target to measure |
| W5 | needs_validation contract + hardening bucket | quality | Medium | Cloudflare three-verdict contract; improves artifact, weak bench signal |
| W14 | Production-viability gate | quality | Medium | mantis critic; class-dependent value (Python/C targets) |
| W12 | Report grader (fresh eyes) | quality | Medium | Anthropic report grader + Cloudflare Phase 5; adds cost per run |
| W11 | Hunt strategy knobs | detection | Medium | round_table KnightPolicy; **ablation risk** — "Baselines Before Architecture" warns scaffold gains evaporate; must ship behind a flag |
| W8 | Cross-run catalogue | detection | Medium (high ceiling) | Cloudflare's compounding numbers are the strongest in the field, but biggest surface; value only appears on the *second* scan of a repo |
| W7 | Live-probe Hunt | detection | Medium (highest single-datapoint) | Anthropic quotes ~100% TP with live request tools; blocked on a served bench target + minimal host guard |
| W15 | Upstream novelty check | quality | Medium-Low | Anthropic `--novelty`; hygiene, small measurable win (already-fixed bugs not reported) |

---

## 2. Workstreams and file ownership (parallelism)

Five streams with disjoint file ownership. Within a stream, items serialize
(same files); across streams, everything runs in parallel.

| Stream | Owns | Items (order) |
|--------|------|---------------|
| **A — Validate panel** | `stages/validate.py`, `prompts/03-*.md`, `schemas/validation.schema.json` | W1 → W2 → W3(A) → W4(A) → W14 |
| **B — Hunt** | `stages/hunt.py`, `prompts/02-hunt.md`, `prompts/01-recon.md`, `schemas/hunt_task.schema.json`, `schemas/finding.schema.json` | W10 → W3(B) → W4(B) → W11 → W9(B) |
| **C — Synthesis** | `stages/dedupe.py`, `stages/report.py`, `prompts/05-dedupe.md`, `prompts/08-report.md`, `schemas/dedupe_output.schema.json`, `schemas/report.schema.json` | W13 → W5(C) → W12 → W15 |
| **D — Cross-run state** | `state.py`, `contracts.py`, `stages/gapfill.py`, `prompts/04-gapfill.md`, new `fingerprint.py` | W16-util → W9(A/C) → W8 |
| **E — Live path** | `stages/trace.py`, `prompts/06-trace.md`, `schemas/trace.schema.json`, `runner.py`/new MCP helper | W6 → W7 |

Shared-file conflicts to respect:
- `schemas/finding.schema.json`: B adds `hardening` + `conditions` (W5/W10), C
  reads them. B lands first; C consumes.
- `schemas/validation.schema.json`: only A touches it.
- `stages/gapfill.py` + `04-gapfill.md`: D rewrites inputs; A/B don't touch.
- `cli.py`: every stream adds at most one flag; merge in release order, no
  interleave conflicts expected.

---

## 3. Waves

### Wave 0 — Measurement baseline (blocking, ~0.5 day, everyone)

Before any change:

1. Pin bench config: devshop manifest, fixed model pair (SDK provider default
   + one local config), fixed seeds, `gapfill_iterations`/`feedback_iterations`
   frozen. Record 3 baseline runs with `python -m bench.score_repo <run>
   bench/corpus/manifests/devshop.json --stages`.
2. Record per-stage token/cost from `state.stage_usage` for each run
   (prompts change prompt sizes; every later claim must net out token cost).
3. Build the **severity ground-truth table** for devshop (expected severity
   per known bug) — needed to score W2/W3/W14. If the manifest lacks
   severities, add them once, by hand, into the manifest.
4. Craft a **seeded-FP set**: ~10 plausible-but-false findings (sanitized
   upstream, unreachable sink, assert-guarded path, inflated severity) fed
   through `stages.validate` directly via a small pytest harness. This is the
   W1/W4/W14 scoreboard.

Gate for every later wave: ship only if TP count ≥ baseline − noise AND the
targeted metric improves; otherwise revert the item (all items are flagged or
prompt-only precisely to make this cheap).

### Wave 1 — High-confidence, small diffs (streams A, B, C in parallel; ~1 week)

**A1. W1 — Validator input projection** (S, ~0.5d)
- `validate.py::_base_input`: project finding to falsifiable fields:
  ```python
  _PANEL_VIEW = {"finding_id","file","line_start","line_end","vuln_class",
                 "cwe","severity","description","evidence_snippet","poc"}
  ```
  Drop `confidence`, `hedged_language`. `task_context` keeps only
  `attack_class` + `scope_hint` — drop the hunt task `rationale` (finder
  reasoning). Arbiter input unchanged (it arbitrates, doesn't re-verify).
- Prompt note in `03-validate.md`: "You receive the claim, not the finder's
  assessment."
- Test: seeded-FP set — expect reject-rate on inflated/hedged FPs to rise;
  bench TP must not drop.
- Rollback: config flag `validate.panel_projection: true|false`.

**A2. W2 — Precondition severity** (S, ~0.5d)
- `03-arbiter.md`: add rubric section — first enumerate
  `missing_preconditions` from the panel (field already exists in the schema),
  *then* assign `arbiter_severity`. Mapping: 0 preconditions + unauth external
  entry = high (critical only with PoC or trace backing); 1–2 preconditions or
  authenticated = medium; ≥3 or local-only/config-file = low. "Overall
  severity may not exceed demonstrated impact."
- `validation.schema.json`: optional `arbiter_severity` (enum same as
  severity) + `severity_reasoning` (required when `arbiter_severity` present).
- `08-report.md`: prefer `validation.arbiter_severity` over finding severity;
  keep the existing one-step drop only when arbiter absent (duo-v1).
- Test: severity MAE vs Wave-0 ground truth; expect strict improvement.
  Anthropic's ordering (evidence list before score) is load-bearing — do not
  let the schema put severity before the precondition array in the output.

**A3/B1. W3 — Escalation discipline** (S, ~0.25d)
- Add the four-line candidate gate to `02-hunt.md` and `03-validate.md`
  verbatim-adapted: never strengthen crash→RCE, ordinary work→availability,
  same-principal→privilege gain; missing best practice with no affected
  principal is hardening, not a finding.

**A4. W4 — Bypass hints** (S, ~1d)
- New `config/bypass_hints.yaml`: keyed by CWE-89/78/79/22/94/918 + free-form
  attack-class keys (substring match, lowercase). ≤6 one-line hints each,
  phrased as *attempts* ("try stacked queries via `;`"), lifted from VVAH's
  file as the starting set.
- Loader (new `codesec/hints.py`, ~40 lines): match on finding `cwe` then
  `vuln_class`/task `attack_class`; malformed file ⇒ log warning, run without
  hints (VVAH behavior).
- Inject as `bypass_hints` into: validate round ≥2 user_input (default) and
  hunt task input (`hints_all_rounds: false`, `hints_in_hunt: true` knobs in
  `config/stages.yaml`).
- Tests: loader unit test; seeded-FP set (hinted rounds should catch
  "sanitizer actually bypassable" cases); bench TP/FP delta.

**B2. W10 — Recall-preserving Hunt discipline** (S, ~0.5d)
- `02-hunt.md` additions: (a) "Discovery optimizes for recall — precision is
  a later stage's job. Report any candidate that survives a few minutes of
  your own scrutiny; do not self-censor borderline ones." (b) Empty findings
  + gaps is a valid, expected outcome. (c) PoC-first: when the class allows,
  build and run the PoC; failed PoCs are still findings
  (`poc.succeeded: false`) — never drop a finding because the PoC failed.
- Gate: bench TP must not drop (this is the risk direction: FP may rise;
  the evidence gate downstream absorbs it — watch panel volume, not hunt
  volume).

### Wave 2 — Medium-confidence, medium diffs (~1–2 weeks, A/B/C/D parallel)

**C1. W13 — Dedupe upgrades** (M, ~2d)
- `dedupe.py`: deterministic pre-pass before the LLM stage: group by exact
  `(file, vuln_class)` with `abs(line_start − line_start) ≤ 10` (Anthropic
  triage's rule). Pre-groups are passed to the LLM prompt as
  `preclustered_groups` (adjudicate only confirm/merge, not discovery), and
  singletons go through as today.
- `dedupe_output.schema.json`: group gains optional
  `replace_canonical_with: <finding_id>` + `replacement_reason`.
- `02-dedupe`… `05-dedupe.md`: add the third verdict — "if a member has a
  strictly better evidence story (successful PoC, tighter trace, clearer
  description), propose it as the new canonical."
- `state.assign_finding_group`: accept canonical override; store swap in the
  group row (auditable).
- Tests: unit test on synthetic groups; bench dedupe stage unchanged-or-better
  group purity.

**A5. W14 — Production-viability gate** (S, ~0.5d)
- `03-validate.md` (round ≥2): "If the vulnerable path is guarded by an
  assertion, debug flag, dev-mode env var, or verbose-errors setting, state
  whether it still fires in a release configuration (asserts compiled out,
  production flags)."
- `validation.schema.json`: optional `production_viable:
  {verdict: yes|no|unknown, reason}`.
- `08-report.md`: `no` ⇒ annotate + drop one severity step.
- Scoreboard: the seeded-FP set includes one assert-guarded finding.

**C2. W5 — needs_validation contract + hardening bucket** (M, ~2d)
- `validation.schema.json` `needs_more_info` branch: require `blockers:
  string[]` (exact unresolved facts, ≥1) + `validation_plan:
  {local?: string, deployment?: string}` (≥1); forbid severity/execution/
  remediation fields on that branch (`not` clause).
- `finding.schema.json` (hunt output): optional top-level `hardening:
  [{file, note}]`; `contracts.validate_hunt_output` passes it through;
  `hunt.py` stores as artifacts (new `hardening_notes` table or artifact kind).
- `08-report.md` + `report.schema.json`: `needs_validation` entries carry no
  severity and render in their own section with blockers + plan; hardening
  renders as a separate list.
- Note: duo-v1's deterministic report consumes the same fields — extend
  `run_deterministic_report` accordingly (same stream C file).

**D1. W16-util — Fingerprint utility** (S, ~0.5d)
- New `codesec/fingerprint.py`: `window_hash(repo_root, file, line_start,
  line_end, ctx=20)` → sha256 of the referenced lines ±context, trimmed;
  `finding_fp = sha256(vuln_class + file + window_hash)`.
- `state.add_finding`: store `discovery_fp` + `discovery_ref` (git HEAD if
  repo, else mtime) on the findings table (migration v3).
- Tests: stable under whitespace-only changes; changes when a cited line
  changes; tolerant of ±small line drift via context re-centering (match the
  exact window content in a ±15-line search band; if found re-centered, use
  new coordinates, else mark drifted).

**D2/A+C. W9 — Coverage-critic Gapfill** (M, ~3d)
- `finding.schema.json` → actually `hunt_task.schema.json` *output* side
  (`schemas/hunt_task.schema.json` is the task; hunt output schema is
  `finding.schema.json`): add optional `uncovered:
  [{surface, attack_class, starting_path, reason}]` — surfaces the hunter
  noticed but wasn't assigned.
- `hunt.py`: persist into new `uncovered_surfaces` table.
- `04-gapfill.md` reframe from "coverage analyst" to **coverage critic**:
  inputs gain (a) `uncovered_surfaces`, (b) recon's `entry_points` +
  `external_inputs` lists with per-entry coverage counts (which entry points
  have zero tasks touching them), (c) the existing `refuted_patterns`.
  Instruction: propose *missing units* — unmapped entry points, unchecked
  parallel paths to known sinks — not just untried matrix cells.
- Negative-knowledge enforcement (deterministic, in `gapfill.py` post-filter):
  drop any proposed task whose `(attack_class, target_file)` matches a
  refutation's `(vuln_class, file)` unless its rationale cites new evidence;
  log dropped count. This is StrikeAgent's negative-conclusion rule, minus
  the regexes.
- Tests: unit test the post-filter; bench: gapfill wave-2 tasks should show
  more novel (attack_class, subsystem) cells and fewer re-refutations.

**B3. W11 — Hunt strategy knobs** (M, ~2d, behind a flag, ablate before default)
- `hunt_task.schema.json`: optional `policy: {search_mode:
  breadth|depth|recombine, attempts_budget: int, designer_trust: number,
  report_partial: bool}`.
- `01-recon.md`: assign policies round-robin across tasks when
  `hunt.policies: true` (default **false**).
- `02-hunt.md`: one paragraph per knob (breadth = enumerate many candidate
  sinks shallowly; depth = pick ≤2 candidates and trace to ground;
  recombine = start from existing findings' patterns elsewhere;
  designer_trust low = hunt unintended behaviors, not the designed flow).
- Gate: run the bench with `policies: true` vs false; ship default-on only if
  TP improves (this is exactly the "harness gain vs plain agent" ablation the
  2026 papers demand).

### Wave 3 — Big/strategic (~2–4 weeks; D, C, E parallel)

**D3. W8 — Cross-run catalogue** (L, ~1.5 wk)
- New repo-scoped catalogue DB (default `<repo>/.codesec-catalogue.db`,
  overridable `--catalogue-db`): table `catalogue(fp PRIMARY KEY, vuln_class,
  file, line_window, status, severity, first_seen_run, last_seen_run,
  source_ref, payload_json)`.
- **Run start** (`orchestrator.run_pipeline`, new `--prior {auto|off|path}`,
  default `auto` = use catalogue if present):
  1. Load confirmed+reachable entries; for each, recompute `window_hash`:
     unchanged ⇒ inject `prior_findings` into hunt input as an exclusion list
     ("these root causes are already reported — do not re-emit them; hunt
     *other* classes in these files"), changed ⇒ queue a *revalidation task*
     (new task kind `revalidate`, target_files=[file], attack_class from
     entry, rationale names the prior finding).
  2. Prior rejections matching (fp or file+vuln_class) ⇒ append to Gapfill's
     `refuted_patterns` (cross-run dead ends).
  3. `needs_more_info` priors with blockers ⇒ candidate gapfill seeds.
- **Run end** (`report` stage): upsert catalogue from final report (confirmed
  → status confirmed; rejected → status refuted with reason; severity from
  arbiter).
- Tests: carry-rule unit tests (unchanged/changed/refuted); integration — two
  consecutive bench runs, assert run 2 dispatches fewer duplicate-finding
  tasks and ≥ same novel findings.
- Metrics: second-scan novelty (new TPs) vs first scan; expected direction
  per Cloudflare: repeated additive runs ≈ 2× single-run findings.
- Risk: fingerprint drift noise on churny files → the W16 re-centering search
  band is the mitigation; if drift >15% of priors, fall back to
  file+vuln_class-only carry for those.

**C3. W12 — Report grader** (M, ~2d)
- New optional pass after report generation (`report.grade: true`, default
  false in wave 3, flip after one bench cycle): per confirmed finding, one
  no-tools agent gets the report entry + finding payload, returns
  `{evidence_score: 0–10, issues: [], demote_severity: bool, reason}`.
  Cloudflare asymmetry: the grader may **demote** (flag or −1 severity) but
  never promote or confirm. Scores render in the report; low scores append
  the issue list.
- Duo-v1 deterministic path: same pass, model-graded rows.
- Scoreboard: grader should catch the seeded-FP inflated entries that
  survived the panel.

**C4. W15 — Upstream novelty check** (S–M, ~1d)
- CLI `--upstream <git-url>`; `report.py` (orchestrator side, never the
  agent): `git clone --depth 100` to a temp dir, per confirmed finding
  `git log --oneline -- <file>` (last 50) injected as `upstream_history`;
  report schema gains `upstream_status: fixed|unfixed|unknown` per finding;
  `fixed` findings render in a footnote section, not the main table.
- Orchestrator-only network egress; agent sandboxes unaffected.

### Wave 4 — Live-target path (stream E; needs served bench target)

Prerequisite (E0, ~0.5d): a runnable target in the corpus. Add
`bench/corpus/devshop/serve.sh` (or a new tiny 3-endpoint flask app with 2
known bugs + 1 hardened route) + a `live` block in the manifest
(`{url, credentials}`). Without this, W6/W7 cannot be measured — do not ship
them on vibes.

**E1. W6 — Canary markers** (M, ~2d)
- New `codesec/markers.py` (VVAH's design, ~40 lines): deterministic from
  finding identity — `tok = sha1(file:line_start:title)[:8]`;
  `xss = f"<evx{tok}>"`, `ssti = (a, b, a*b)`, `redirect_host =
  f"evredir-{tok}.invalid"`.
- `stages/trace.py` when `live_target` set: mint markers, pass into the trace
  prompt — "embed the marker via the matching entry point, then verify the
  *exact* marker (not a substring, not a similar string) in the response."
- `06-trace.md` + `trace.schema.json`: optional `marker:
  {kind, token, verified: bool, where}`; `verified: true` upgrades trace
  confidence; `reachable` requires exact-marker confirmation when a marker
  was applicable.
- Auth-on-the-wire rule in the same prompt: if credentials are configured,
  the trace must confirm a credential was actually attached (response differs
  from unauthenticated baseline; or log line) — an authenticated 200 with
  nothing attached proves nothing.
- Tests: marker determinism unit test; live bench target — expect the
  hardened route (false reflection) to stop being marked reachable.

**E2. W7 — Live-probe Hunt** (L, ~1 wk, gated on a minimal host guard)
- When `live_target` is set, Hunt gets request capability against that host
  only:
  - Local engine: add a `live_probe` tool to `local_agent.py`
    (`http_request(method, path, headers, body)` with host pinned to
    `live_target.url`, size/time caps).
  - SDK path: tiny stdio MCP server (`codesec/live_probe_mcp.py`) exposing
    the same tool; `runner.py` registers it in `ClaudeAgentOptions` only when
    `live_target` exists. Host allowlist enforced in the server, not the
    prompt.
- `02-hunt.md`: "when live_probe is available, test candidate inputs against
  the running app as you hunt; a request/response observation beats a guessed
  reachability claim" + canary-marker instructions (reuse W6).
- `hunt.py`: findings may carry `live_evidence: {request, response_excerpt}`
  (schema addition), which counts as proof material for the evidence gate.
- Safety prerequisite (minimal, in-scope): the host pin *is* the guard for
  this tool; the general Bash sandbox stays out of scope (tracked separately
  as harness-ideas #2).
- Measurement: devshop-live bench, live findings TP/FP vs static-only run of
  the same repo. This is the item with the single strongest external claim
  (~100% TP with live tools) — worth the corpus work.

---

## 4. Cross-cutting rules

1. **Every item ships behind a flag or a prompt-only diff** so a failed gate
   reverts in one line. Prompt changes are versioned per item (git history is
   the version; note the item ID in the commit message) so bench regressions
   bisect to one idea.
2. **Gate = bench, not opinion.** TP count must not regress; the item's
   targeted metric must improve; token cost per stage reported alongside.
   Items that add cost (W4 hints, W12 grader) must show metric-per-token net
   positive.
3. **Schema additions are optional-first** (`additionalProperties: false` is
   kept by adding explicit optional fields, never by loosening) — old runs
   must resume against new code.
4. **Duo-v1 parity:** every schema/prompt change lands once; the
   deterministic stages (`run_deterministic_dedupe`, `run_deterministic_report`)
   are extended in the same PR as their LLM-stage counterpart or explicitly
   marked duo-N/A (W12 rows, W5 sections).
5. **No new dependencies.** Everything above is stdlib + existing deps.

## 5. Timeline sketch (one implementer; halve wall-clock per parallel stream)

| Week | Work |
|------|------|
| 0 | Wave 0 baseline + severity GT + seeded-FP set |
| 1 | Wave 1 (A1–A4, B1–B2, C-none) — all high-confidence |
| 2 | Gate Wave 1 on bench; start Wave 2 A5/C1/D1 in parallel |
| 3 | Wave 2 C2/D2/B3; gate Wave 2 |
| 4–5 | Wave 3 D3 (catalogue) — biggest item, starts after D1/D2 land |
| 5 | Wave 3 C3/C4 in parallel with D3 (different files) |
| 6 | E0 corpus + E1 canaries; gate |
| 7 | E2 live-probe hunt; final gate + defaults flip for anything still flagged |

Total: ~7 weeks single-threaded, ~4 weeks with streams A/B/C/D/E split across
two people (A+D and B+C+E are natural pairings given file ownership).
