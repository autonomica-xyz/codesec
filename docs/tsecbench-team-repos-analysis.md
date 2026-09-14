# What the Tsecbench team-submission repos can teach codesec

Source: the four official-leaderboard team submissions, cloned and read in full
(backend/agent cores; frontends skipped).

> **Update note:** This is a patched version. Items 1–10 are the original ranking.
> Addendum A adds missed findings, Addendum B corrects inaccuracies, and the build
> order at the end is updated.

| Repo | Rank context | What it is |
|---|---|---|
| [Autumn-27/ARTEX](https://github.com/Autumn-27/ARTEX) | Tsecbench v1 + Baidu, official | Autonomous pentest system (Go). Asset-graph driven, planner/worker, LLM pool |
| [Yean-Sec/StrikeAgent_AtkBrain-Flash](https://github.com/Yean-Sec/StrikeAgent_AtkBrain-Flash) | Cybench board | Attack-graph self-loop on Claude Code SDK, supervisor-at-round-boundaries, cross-run memory |
| [n1majne3/CyberPenda](https://github.com/n1majne3/CyberPenda) | Tsecbench v1, official | Local-first pentest control plane (Go). Blackboard v2, runtimes, receipts |
| [ignite0522/round_table](https://github.com/ignite0522/round_table) | Tsecbench v1 ("RoundTable-V3"), official | Multi-agent round table: knights + Merlin scheduler + Arthur arbiter, FunSearch islands |

## Ranked: ideas worth stealing

### 1. Cross-run memory of transferable tactics (StrikeAgent) — HIGH VALUE

`backend/atkbrain/memory/evolve.py`, `methodology.py`, `store.py`

codesec's Feedback stage seeds new Hunt tasks **within one run only**; every run
starts from zero. StrikeAgent distills lessons that survive across engagements:

- **Only wins get distilled** — high/critical findings or flags ("不蒸失败局",
  don't distill losing runs). Gate: `verification_status` must be
  verified/flaky AND (red-team rating high/critical OR secondary-verified).
- **Lesson shape is `when / do / avoid / chain`** keyed by a content hash
  (`lesson_key`), deduped across runs. Confidence is a formula, not a
  self-report: `0.4 + 0.12*wins − 0.14*fails`, floored/capped, with a penalty
  when used ≥4 times with zero wins. Confidence **decays with use-without-win**.
- **Scrubbing is regex-enforced**: hostnames, IPs, ports, paths, `flag{...}`,
  challenge IDs are stripped before a lesson is stored (`_HOSTISH_RE`,
  `scrub_lesson`). Cross-target memory carries *methods*, never *targets*.
- **Retrieval is gated by stack/cue tokens**: a lesson only re-enters a new run
  if its `when` tokens (php, nginx, wordpress, … or cues like
  `upload_surface`, `deserialize_surface`) match the current target's stack.
  "做过的题" never gets replayed as a fixed template.

**codesec application**: a `lessons` table beside `state.db`. After Report,
distill every validated+traced (i.e., reachable) finding into
`when/avoid/chain` with stack tokens extracted from recon. Before Recon/Hunt,
inject only the matching lessons into the stage prompt. The Feedback loop then
becomes *cumulative across runs* — the same "reachable bug seeds a hunt for the
same pattern elsewhere" idea, but at portfolio scale. The scrub-regexes and the
win/fail confidence formula are directly liftable.

### 2. Digest-style context: titles always, bodies on demand (round_table + CyberPenda) — HIGH VALUE

`roundtable/core/digest.py`, CyberPenda ADR-0004

Both teams independently solved the same problem — token explosion when N
agents share a board — the same way:

- round_table: each knight gets a per-agent **digest**: titles + confidence +
  endorse/challenge counts + status; **all dead-ends are always included in
  full** ("必须全给,避免重复劳动"); full bodies are pulled via `read_entry(id)`
  only when wanted.
- CyberPenda formalizes it as **deterministic semantic snapshots**: per-type
  field allowlists (finding proof/CVSS read by key, not at startup),
  byte-identical canonical JSON with an internal hash for cheap change
  detection, and one rule: *before invalidated knowledge leaves the snapshot, a
  reusable invalidation reason must survive as a Fact.*

**codesec application**: Validate panel rounds already pass earlier verdicts'
cruxes around; Dedupe passes whole findings around; Feedback reads every
finding. A digest layer (id, title, attack_class, confidence, status +
`read_entry` tool for bodies) would cut the prompt cost of stages 3/5/7 roughly
by findings-count×body-size, and the "dead ends always fully visible" rule maps
to: **every rejected finding's rejection reason must reach Gapfill/Feedback**,
so Hunt never re-derives an already-refuted pattern. Cheap, structural, and
directly on the bench metric (token usage).

### 3. Strategy-prior knobs instead of personality prompts (round_table `KnightPolicy`) — MEDIUM-HIGH

`roundtable/knights/policy.py`

"Personality = a set of executable config knobs, not roleplay lines" — the
difference between 5 diverse agents and "5 换皮 LLM" (5 reskinned LLMs).
Knobs: `search_mode` (breadth/depth/recombine), `max_attempts_before_giveup`,
`designer_trust` (0–1: hunt the intended bug vs hunt unintended ones),
`post_confidence_threshold`, `post_partial_findings` (recall vs precision),
`tool_budget_per_cycle`.

**codesec application**: Hunt agents vary only by attack class today. A small
policy object per Hunt task (attempts budget, partial-findings toggle,
"assume the maintainer intended this pattern vs not") would diversify the
panel the same way `validate.rounds` does for Validate — ensemble recall from
*strategy* diversity, not just model disagreement. The validate≠hunt model
split stays; this adds a second, cheaper axis.

### 4. Evidence-gated verification statuses (StrikeAgent `graph/verify.py`) — MEDIUM

A finding is `verified` **only if it carries authenticity proof** (evidence,
PoC curl/python, canary, proof URL); otherwise it's `pending` with a reason
code. Non-exploit categories (DoS/crash/misconfig) can never count as "verified
exploitable". Red-team re-rating and secondary verification are recorded as
**separate fields**, never folded into one score.

**codesec application**: `set_finding_validation` should require the same
proof-tuple before storing `accepted`; the arbiter's confidence and the
*presence of a runnable PoC* should be distinct columns. This makes the Report
stage's precision measurable and the Trace stage's input cleaner (trace only
what has proof). Cheap schema + guard change.

### 5. LLM failover pool with a process-wide circuit breaker (ARTEX `llmpool`) — MEDIUM

`llmpool/pool.go`, `llmpool/health.go`

Ordered chain of LLM profiles; equal-priority members round-robin; a member
whose context window can't hold the request is *skipped, not failed*.
Circuit-breaker: 3 transient failures (429/5xx/net) trip it, deterministic
failures (no credit, bad key) trip on the first; backoff ladder
1min → 5min → 30min; state is process-wide and DB-persisted so a cooling-off
window survives restart. One task's discovery marks the profile dead for all.

**codesec application**: `providers.py` + the local engine already classify
429/5xx as transient for retry; a failover *chain* (anthropic → zai → local)
with one shared breaker registry would let long unattended runs survive a dead
provider instead of aborting mid-Hunt. Directly matters for the Tsecbench
5-hour runs.

### 6. Supervisor only at round boundaries + stall/starvation detection (StrikeAgent `engine/`) — MEDIUM

`supervise.py`, `advisor_bind.py`, `hunt_clock.py`

- The strong model ("御主"/supervisor) is consulted **only between worker
  rounds**, never mid-turn: workers execute, the supervisor re-plans from the
  attack graph at boundaries. Within a wall-clock budget it keeps asking until
  it produces a *usable* plan (there are `plan_is_usable` /
  `plan_is_fake_key_loop` checks — it rejects hallucinated supervisor output).
- The advisor binding system detects **starvation** (`starves_chain_close`,
  `in_flight_blocks_new_direction`) — a worker that keeps opening new
  directions instead of closing chains gets tightened.
- `hunt_clock.py`: turns/elapsed persist across backend restarts; a hunt only
  resets on policy closure reasons, not on process death. "entry_dead with a
  live foothold ≠ new hunt" is encoded, not vibes.

**codesec application**: codesec's stages are already boundary-structured, so
half of this is native. What's worth taking: (a) **usable-plan validation** on
Recon's task list (reject tasks that cite assets that don't exist in the repo
map — the same shape as `plan_cites_peer_entry`), and (b) a persistent
per-run turn/elapsed clock so a crashed `codesec run` resumes with honest
budget accounting instead of starting the clock over.

### 7. Hypothesis derivation from a graph with negative-knowledge regexes (StrikeAgent `graph/hypothesize.py`) — MEDIUM

When observations land, derive *orthogonal follow-up intents* mechanically:
found a secret → derive "mount it" intents; found a login form → derive
cred-reuse; and — the clever part — **negative-conclusion regexes**
(`_NEGATIVE_CONCLUSION_RE`, `_UNIFORM_OBS_RE`): when the agent writes "面穷尽 /
all-404 / uniform status / no set-cookie", the derivation engine stops
emitting intents that assume that surface exists. Uniform observation ⇒ don't
close the input surface, switch channels. It's a rule engine that reads the
agent's *own conclusions* and cancels hypotheses the agent already falsified.

**codesec application**: Gapfill is codesec's equivalent (re-queue
under-covered areas) but it only sees coverage counts, not conclusions. A
`negative_knowledge` table — "pattern X was hunted in function F and refuted
because R" — fed from Validate rejections, would let Gapfill skip refuted
combinations and Feedback avoid re-seeding them. Same spirit as idea 2's
"dead-ends always visible," but at task-generation time.

### 8. Append-mostly blackboard with endorse/challenge/claim (round_table) — CONTEXT-DEPENDENT

`core/board.py`: entries are append-mostly; interaction is only
endorse/challenge/claim; every mutation is one JSONL line (replayable,
crash-recoverable); inverted tag index feeds the digests. Merlin's tick adds:
dedup two agents doing the same thing, dead-end broadcast when
challenge ≥ endorse and no progress, **anti-herding** (claims too concentrated
→ forced divergence), and **closing mode** (time nearly up → everyone converges
on the strongest lead).

**codesec application**: codesec's sqlite state is already append-mostly per
stage; the missing pieces are the *social* primitives. If Hunt ever runs as a
parallel swarm over shared findings, endorse/challenge/claim + a Merlin-style
tick (pure rules, no LLM) is the cheapest coordination layer available. For the
current 8-stage pipeline, the directly useful piece is **closing mode**: a
deadline signal that collapses remaining Hunt breadth into "finish validating
what you have" — Report precision is what's scored.

### 9. FunSearch islands over candidates (round_table `funsearch/`) — LOW (for now)

Multi-island deterministic population with UCB selection and a Codex-based
reranker, scoring blackboard candidates by a fixed objective
(`candidate_objective`: type bonus, confidence, endorse/challenge delta, refs).
Interesting if codesec ever evolves *prompts or hunt heuristics* against the
bench corpus — islands avoid premature convergence, the deterministic state
file makes runs reproducible. Not worth building until the bench harness can
score variants cheaply.

### 10. Misc that maps 1:1

- **ARTEX task clock** (`agent/taskclock.go`): absolute per-task deadline
  carried in ctx; runs clamp their own budget to remaining time and switch to
  "FINAL round" wording. codesec has `--max-cost-usd` but no wall-clock
  deadline per run → trivial addition, big UX win for unattended bench runs.
- **ARTEX utf8Clean** (`db/exploration.go`): strip NUL + repair invalid UTF-8
  from tool stdout before it hits sqlite — one function, prevents silent
  activity-record loss on binary-heavy targets.
- **CyberPenda ADR-0009**: resume from *semantic state* (goal, snapshot, open
  attempts, unconsumed steering), never from task summaries — task summaries
  duplicate what the state already knows and drift from it.
- **round_table Arthur**: `flag_candidate` and `resolved` are separate states,
  so a hallucinated flag can't terminate the session — the verifier callback
  gates the transition. Same shape as codesec's Trace gate; worth keeping the
  separation explicit if Hunt ever gets to claim "done".

## What all four teams did that codesec already does

Narrow scoped agents, explicit state machines with append-only logs, schema-
validated outputs, adversarial second opinions (Validate panel ≈ endorse/
challenge ≈ red-team re-rating), and resume-after-crash were table stakes at
the top of this leaderboard. codesec's deliberate *model-family* disagreement
(Validate on a different model than Hunt) is actually ahead of what these four
do — none of them split models across their adversarial step.

## Addendum A: Additional ideas worth stealing (post-audit)

The original audit missed several patterns that make the ranked ideas reliable at scale.

### 11. Cross-engagement worker memory (ARTEX) — HIGH VALUE

`ARTEX/agent/worker.go:50`, `ARTEX/agent/worker.go:141-143`, `ARTEX/agent/worker.go:438-440`

The original report attributes cross-run transferable tactics only to StrikeAgent (#1). ARTEX also has a cross-engagement `memory.Store` with `RecallMemory` / `RecordMemory` tools and auto-injection of up to three relevant memories per worker run.

**codesec application**: wire a persistent lessons store into the Worker/Hunt stage with auto-injection and a small cap. This is the same pattern as the `lessons` table idea, with a built-in prompt-budget guard.

### 12. Pre-injected, token-budgeted graph digest (ARTEX) — HIGH VALUE

`ARTEX/agent/tools.go:348-458`, `ARTEX/agent/planner.go:255-282`

ARTEX already implements the digest idea in #2. `graph_overview` distills goals, hints, open/running/recently done intents, frontier count, recent facts, findings, and related tasks into a compact snapshot. The planner prompt pre-injects it, so the model does not spend a turn calling the tool. `overviewTextBudget` enforces per-source rune budgets.

**codesec application**: build a `graph_overview`-style digest for Recon/Hunt/Validate and pass a `node_detail(id)` tool instead of full finding bodies.

### 13. DB-backed tool catalog and skill usage ledger (ARTEX) — HIGH VALUE

`ARTEX/agent/toolcatalog.go:19-49`, `ARTEX/db/skill_usage.go:17-27`, `ARTEX/db/skill_usage.go:103-107`

ARTEX seeds a `ToolSeed` catalog per agent (mainagent, planner, worker, auto, pentest) with DB-overridable descriptions, parameter schemas, and default bindings. A `skill_usage` ledger tracks which skills are called and which skills agents asked for but do not exist (`MissingSkillStats`).

**codesec application**: treat skills and tools as versioned catalog entries. Use the ledger to see which playbooks agents reach for and which gaps they report.

### 14. Skill-based Kali tool catalog and execution guard (StrikeAgent) — HIGH VALUE

`StrikeAgent_AtkBrain-Flash/backend/atkbrain/agents/project_skills.py:14-18`, `StrikeAgent_AtkBrain-Flash/backend/atkbrain/agents/kali_kit.py:11-28`, `StrikeAgent_AtkBrain-Flash/backend/atkbrain/exec/guard.py`

StrikeAgent ships `.claude/skills/kali-kit/SKILL.md` into the project workspace. It lists allowed Kali binaries by absolute path, exact one-liner templates, timeouts, and permitted wordlist sizes. `exec/guard.py` parses shell tokens (not raw substrings) to block loopback, destructive commands, SQL `DROP/DELETE/INSERT`, and >100k wordlists.

**codesec application**: replace ad-hoc tool prompts with a versioned tool catalog and a shell-token guard. This stops the agent from hallucinating tool availability and running destructive commands.

### 15. AdvisorBinding hard constraints (StrikeAgent) — HIGH VALUE

`StrikeAgent_AtkBrain-Flash/backend/atkbrain/engine/advisor_bind.py:169-191`, `StrikeAgent_AtkBrain-Flash/backend/atkbrain/engine/advisor_bind.py:204-257`

Supervisor output is compiled into an `AdvisorBinding` (`must_intents`, `prefer_tactics`, `deny_tactics`, `ban_repeats`, `stall`). The engine fills an orthogonal bundle of up to three tactics, enforces tactic diversity, and sanitizes premature "done" plans with regex filters (`_ORACLE_FALSE_CLOSE_RE`, `_FALSE_CLOSE_RE`, `_LEAVE_BRIDGE_RE`).

**codesec application**: convert Recon/Hunt supervisor prompts into a structured `must/prefer/deny/ban_repeats` contract and enforce it at the engine level.

### 16. Typed blackboard grammar and evidence-gated validation (CyberPenda) — HIGH VALUE

`CyberPenda/internal/blackboardv2grammar/grammar.go:58-83`, `CyberPenda/docs/adr/0012-use-eleven-blackboard-relationship-types.md`, `CyberPenda/internal/blackboardv2/finding.go:170-211`

CyberPenda enforces typed blackboard relationships (`produced`, `evidences`, `supports`, `contradicts`, `depends_on`, `satisfies`, `supersedes`, etc.) with source/target record type and acyclicity rules. A `confirmed` finding is rejected unless it has `target`, `proof`, `impact`, `recommendation`, and a valid CVSS vector.

**codesec application**: add a typed relationship grammar to findings. `set_finding_validation` should require the full proof tuple and a CVSS vector.

### 17. Durable evidence retention and idempotency receipts (CyberPenda) — HIGH VALUE

`CyberPenda/internal/blackboardv2/evidence.go:26-55`, `CyberPenda/internal/blackboardv2/evidence.go:196-452`, `CyberPenda/internal/blackboardv2/service.go:859-905`

CyberPenda copies evidence from the confined runtime, SHA-256 checks it, and commits it with the blackboard in one transaction. Every `ChangeBatch`, `FinishContinuation`, and `RetainEvidence` call is hashed and receipted. Exact replay returns the stored result without re-executing.

**codesec application**: make `Trace`/`Report` retain PoC artifacts by hash and wrap expensive provider calls in idempotent receipts. This is the reliability layer the original report only hinted at.

### 18. Scope guardrails and prompt-level attack-surface constraints (round_table) — HIGH VALUE

`round_table/roundtable/roles/merlin.py:28-43`, `round_table/roundtable/roles/merlin.py:298-376`, `round_table/roundtable/roles/merlin_scope_judge.py:33-127`, `round_table/roundtable/knights/codex_knight.py:137-148`

Merlin auto-refutes entries that look like attacks on `localhost` / `127.0.0.1` / `host.docker.internal` and uses an LLM judge for ambiguous cases. The knight system prompt forbids `localhost`/`Host` tricks and requires dry-run tool checks.

**codesec application**: add scope guardrails at the prompt and orchestrator layer, not just the sandbox, to prevent the agent from pivoting to the bench harness or internal proxy.

### 19. FunSearch is the default scheduling pipeline (round_table) — HIGH VALUE

`round_table/examples/run_ctf.py:164`, `round_table/roundtable/roles/merlin.py:56-70`, `round_table/roundtable/funsearch/merlin_control.py:16-74`, `round_table/roundtable/funsearch/population.py`

`--merlin-search-mode` defaults to `funsearch` in the CTF harness. The implementation includes UCB island selection, elite pools, periodic reset/migration, and an LLM reranker with a deterministic fallback.

**codesec application**: do not treat FunSearch as "for later". If codesec evolves attack chains, the UCB-island mechanism is directly applicable to maintaining diverse exploit variants and avoiding premature convergence.

### 20. Append-only JSONL resume and per-knight debug bundles (round_table) — MEDIUM-HIGH

`round_table/roundtable/core/board.py:191-225`, `round_table/examples/run_ctf.py:156-159`, `round_table/examples/run_ctf.py:315-358`, `round_table/roundtable/knights/codex_knight.py:731-753`

The board is an append-only JSONL log that can be replayed. The submitted-flags cache is also replayable. When `codex exec` fails, the full prompt and outputs are dumped to `.roundtable_failures/`.

**codesec application**: use append-only JSONL for shared state and write per-failure debug bundles. This makes long runs recoverable and failures auditable.

## Addendum B: Corrections to the original report

1. **round_table dead-ends in the digest.** The original report says "all dead-ends are always included in full." The code shows dead-ends appear as `DigestLine` titles and metadata only; `body` is not part of `DigestLine`. Full bodies are fetched with `read_entry(id)`. See `round_table/roundtable/core/digest.py:21-35`, `:59`, `:127`.

2. **round_table FunSearch default.** The original report rates FunSearch "LOW (for now)." The CTF harness defaults `--merlin-search-mode` to `funsearch`; it is the active scheduling pipeline. See `round_table/examples/run_ctf.py:164`.

3. **StrikeAgent supervisor cadence.** The original report says the supervisor is consulted "only between worker rounds." The code shows the supervisor is consulted at the start of every worker turn; the meaningful invariant is "never mid-turn." See `StrikeAgent_AtkBrain-Flash/backend/atkbrain/engine/advisor_schedule.py:80-103`.

4. **StrikeAgent memory learns from failures too.** The original report says "only wins get distilled." The episode store records `failed_techniques` from disproved intents, and `evolve.py` uses those as `avoid` content. The win gate applies to the final `playbook`/`lesson` distillation, not the whole cross-run memory pipeline. See `StrikeAgent_AtkBrain-Flash/backend/atkbrain/memory/store.py:59-70` and `StrikeAgent_AtkBrain-Flash/backend/atkbrain/memory/evolve.py:110-149`.

5. **CyberPenda canonical JSON and SHA-256.** The original report says "byte-identical canonical JSON with an internal hash for cheap change detection." The canonicalization comes from ordered `map[string]X` fields and SQL `ORDER BY`. The SHA-256 is for idempotency receipts and continuation integrity, not a cheap change-detection hash. See `CyberPenda/internal/blackboardv2/service.go:859-905`.

6. **CyberPenda receipts are a multi-part system.** The original report mentions "receipts" briefly. The full system spans `ChangeBatch` receipts, `FinishContinuation` receipts, `FinishIntent` settlement, and `RetainEvidence` integrity receipts. See `CyberPenda/internal/blackboardv2/evidence.go:34-55`.

## Updated build order for codesec

1. **Lessons table + distillation into prompts** (#1, #11) — biggest compounding win.
2. **Digest layer + dead-end visibility** (#2, #7, #12) — token cost ↓, precision ↑.
3. **Evidence-gated validation statuses** (#4, #16) — small diff, measurable precision.
4. **Provider failover chain** (#5) + **task clock/deadline** (#10) — unattended runs.
5. **Hunt policy knobs** (#3) — recall from strategy diversity.
6. **Scope guardrails and prompt-level attack-surface constraints** (#18) — prevent harness/proxy pivoting.
7. **DB-backed tool catalog + skill usage ledger** (#13, #14) — reproducible tooling and gap detection.
8. **Typed relationship grammar + durable evidence/receipts** (#16, #17) — proof quality and run reliability.
9. **Fresh session per turn + execution guard** (#14, #15) — context hygiene and safety.
10. **Append-only state log + failure debug bundles** (#20) — crash recovery and observability.
11. **FunSearch-style UCB scheduling** (#19) — when attack-chain evolution becomes a priority.
