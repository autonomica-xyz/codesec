# What happened — codesec vs vanilla Pi on RealVuln (Sep 2026)

> **Audit correction (2026-09-22):** The score table reproduces, but the Trace
> explanation below is incorrect: all 340 confirmed scored findings had traces.
> Search tools were broken by the `target/` directory name, and Dedupe/Report
> fell back in all 18 scored H runs. Pi sessions record reasoning `low`, not
> `off`. Read the [artifact-backed audit and rerun gates](AUDIT-HARNESS-GLM53-REALVULN-2026-09-22.md)
> before using this notebook's causal conclusions or rerun advice.

This is a lab notebook, not a leaderboard. One host (NVIDIA GB10, 128 GB
unified), one corpus (RealVuln v3 Python community, 6 apps, 162 vulns /
29 decoys), two harnesses (codesec 8-stage vs Pi CLI), two backends
(Z.AI hosted `glm-5.3`, then Unsloth local Qwen3.8-27B Q4).

Plans: `bench/PLAN-LOCAL-VS-ZAI.md`, `bench/PLAN-SHIP-CONFIRMED.md`.
Scorer: RealVuln file + CWE + line ±10, F3 (recall-weighted, 0–100).

---

## 1. Question

On the **same model**, does the codesec pipeline detect more — and more
precisely — than a vanilla Pi session?

Pre-registered rule (plan §8): codesec **final** “earns its keep” if
F3_H ≥ F3_V + 5 **or** (recall within 5 pts and precision +10 pts), and
fewer FPs on ≥4/6 slugs in ≥2/3 trials.

---

## 2. What actually ran

### Arm H — codesec

`codesec run --provider zai --model glm-5.3 --engine local --prior off`

- OpenAI-compat `https://api.z.ai/api/coding/paas/v4` (not Claude Code).
- `--model glm-5.3` on every stage (Hunt/Validate disagreement collapsed).
- Concurrency 10 in the plan, **4 in the run** (Z.AI 429s).
- `--max-hours 2` (pygoat 3). Almost every trial hit
  `closing mode: time budget nearly spent — skipping`.
- Blinded read-only `target/` copies; canaries stripped from Semgrep.

### Arm V — vanilla Pi

`pi -p --provider zai --model glm-5.3 --thinking off`

- Isolated `PI_CODING_AGENT_DIR`, cwd always `…/target`.
- Frozen prompt → `findings.json` → Semgrep adapter.
- Wall clock **~15–40 seconds** per repo (not a full audit budget).

### Corpus / matrix

6 slugs × 3 trials × {H,V} = 18 pairs, plus smoke.
Interleaved H then V. `--prior off`. Answer key never in the scan root.

Z.AI matrix: **18/18 scored**. Log:
`bench/realvuln-runs/overnight/overnight.log` (`wave1 ok` 2026-09-20 09:53).

---

## 3. Result that counts (Z.AI glm-5.3)

Strict micro F3, mean of 3 trials (`aggregate-glm53.json`):

| Arm | F3 | Precision | Recall |
|---|---:|---:|---:|
| codesec **hunt** (discovery) | **40.4** (37.7–45.0) | 0.52 | **0.40** |
| codesec **final** (shipped report) | 20.8 (20.5–21.1) | 0.62 | 0.19 |
| vanilla Pi | **21.4** (18.1–24.7) | **0.83** | 0.20 |

**Decision:** codesec **final does not earn its keep** on this corpus.
Pi matches F3 and is more precise. Hunt *would* have won on recall; the
pipeline threw that away.

Trial 1 final slightly beat Pi (F3 20.7 vs 18.1, P 0.78). Trials 2–3
final precision collapsed to ~0.54 while Pi stayed ~0.86.

Per-slug pattern: Pi cleaner on VAmPI / lets-be-bad-guys / pygoat; codesec
final only competitive on smaller apps.

Pi wall clock minutes vs codesec **45 min–3 h**.

---

## 4. Why codesec looked poor (glm-5.3)

Not “GLM cannot hunt.” Hunt F3 40 vs Pi 21. Pi only found **13** TPs
hunt missed (3 trials pooled). Pi is a high-precision **subset**.

Validate was not a mass-reject: **350 confirmed / 44 rejected** across H
runs.

**The kill is report membership.** `report.py` only shipped
`get_reachable_canonical_findings`: confirmed **and** canonical **and
TRACE reachable**. Closing mode skipped leftover Trace. Untraced
confirmed findings never became Semgrep `*-final`.

That matches **98 hunt TPs absent from final** (pygoat 32, lets-be-bad-guys
21, dvpwa 17, …), including real bugs (VAmPI debug endpoint, PyGoat SQLi,
`exec()`). Recall 0.40 → 0.19.

Offline rebuild from VAmPI t1 `state.db` (confirmed canonicals, no
reachable filter): hunt TP **9**, old final **5**, rebuilt **9**.

Adapter drops were **canaries**, not missing CWEs. Blinding (no `.git` /
README, opaque ids) held; residual package names (`pygoat`) can still
identify famous apps.

**Fix landed in-tree** (`PLAN-SHIP-CONFIRMED.md`): report ships confirmed
canonicals; `trace.status` is annotation (`reachable` / `unreachable` /
`uncertain` / `untraced`); missing traces are not a completeness fail;
agent `findings: []` is reconciled from the DB. Tests in
`tests/test_report_stage.py` / `test_state.py`. **Not re-run on the 18
Z.AI trials** (would need a new matrix or a full `state.db` replay).

---

## 5. Local Unsloth attempt (Qwen3.8-27B Q4) — incomplete H

Same runners, `SCANNER_TAG=unsloth-qwen38-q4` so glm-5.3 files were not
overwritten. Serving: Unsloth Studio → llama.cpp, model
`unsloth/Qwen3.8-27B-GGUF` UD-Q4_K_XL.

### What worked

- Smoke H+V completed.
- **Pi on Unsloth completed 18/18 V cells.**
- Pi+Unsloth F3 **31.2** (P 0.81, R 0.29) vs Pi+glm-5.3 F3 21.4 — local
  Pi had **higher recall** on this corpus (educational apps; take with
  salt).
- After Gemma was stopped: 262k context, thinking off, 1 decode slot.

### What did not work

1. **KV / context.** First Unsloth load **auto-reduced 262144 → 32768**
   because vLLM Gemma-4-31B still held ~72 GB. Codesec recon died:
   `request (32807 tokens) exceeds … (32768 tokens)`.
2. **Thinking on** filled the window (thousands of hidden tokens, one
   slot busy). Fixed later with
   `--chat-template-kwargs enable_thinking:false`.
3. **Grok 10h wrapper killed Unsloth** (not the matrix). Recon then
   `Connection refused`. Unsloth was restarted **setsid-detached**.
4. **Codesec H almost all FAIL.** Final Semgrep missing on most cells.
   Unsloth codesec F3 ~3.7 on the 2 partial trials — **not a valid H
   comparison**. Failed-trial log was truncated on retry; see
   `unsloth/overnight.log` `[matrix] FAIL h …`.
5. **Overnight `aggregate.py` defaulted to glm-5.3 slugs** and rewrote
   `aggregate.json` at the end of the Unsloth loop. Restored. Unsloth
   scores: `aggregate-unsloth-qwen38-q4.json` (`--tag` flag added).
6. Decode ~11–20 tok/s. Shared GPU with Gemma until it was killed.
   Local H was always going to be slower than Z.AI.

**Do not use Unsloth codesec numbers for the harness decision.** Use Pi
Unsloth only as a qualitative “vanilla local agent can score.”

---

## 6. Ops / infra timeline (compressed)

| When | What |
|---|---|
| Z.AI auth | First `auth-check` required `claude` on PATH. Fixed: zai → `--engine local`, no Claude CLI. |
| Blind prepare | `chmod` after `chown root` EPERM. Fixed: sudo chmod `a=rX`. |
| `run_h.sh` | `tee` into run-root before `codesec` → non-empty dir abort. Fixed. |
| Pi JSON | Illegal `\w` escape aborted adapter. Parser now repairs. |
| Recon | Bare subsystem **array** failed schema. Local engine wraps + seeds tasks. |
| Matrix `set -e` | One trial killed the night. Now continue-on-fail + one retry. |
| Grok 10h cap | Killed wrapped Unsloth / watchers. Matrix/Unsloth must be `setsid`. |
| Unsloth auto KV | 32k while Gemma occupied VRAM. Need `--max-seq-length 262144` + `--gpu-memory-mode manual` + thinking off **after** GPU is free. |

---

## 7. What we did **not** do

- No live-target (Phase 3) runs.
- No Titus/OpenMythos local duo (Appendix A). Intentionally blocked until
  the harness question had an answer; the answer is “final report does
  not beat Pi.”
- No Juice Shop / JS RealVuln.
- No glm-5.3 thinking-on arm.
- No re-matrix after the ship-confirmed code change.
- Unsloth codesec H not completed.

---

## 8. Artifact index

| Thing | Path |
|---|---|
| Z.AI scores | `bench/realvuln-runs/aggregate-glm53.json` (copy: `aggregate.json`) |
| Unsloth scores | `bench/realvuln-runs/aggregate-unsloth-qwen38-q4.json` |
| Z.AI run log | `bench/realvuln-runs/overnight/overnight.log` |
| Unsloth run log | `bench/realvuln-runs/unsloth/overnight.log` |
| Semgrep JSON | `Real-Vuln-Benchmark/scan-results/{slug}/{scanner}/run-{t}.json` |
| Blind maps | `bench/realvuln-runs/operator/*.json` |
| Runners | `bench/realvuln/run_{h,v,matrix,overnight}.sh` |
| Report-membership fix | `codesec/stages/report.py`, `codesec/state.py`, `prompts/08-report.md` |

Scanner slugs: `codesec-glm53-{hunt,final}`, `pi-glm53`;
`codesec-unsloth-qwen38-q4-{hunt,final}`, `pi-unsloth-qwen38-q4`.

---

## 9. If we run again

1. Keep Z.AI glm-5.3 as the only **completed** harness comparison until
   codesec H finishes on the local model.
2. Serve Unsloth **setsid**, 262k, thinking off, Gemma (or any other 70 GB
   tenant) **off** before load. Confirm `context_length` on `/v1/models`
   **before** recon.
3. Aggregate with `--tag` so glm-5.3 files are never overwritten.
4. After ship-confirmed: either rebuild all H `state.db` → new finals, or
   a short 2-repo re-matrix, before claiming the harness beats Pi.
5. Pi’s 15–40 s sessions are a **different budget** than codesec’s 2 h.
   A fair V arm needs a wall-clock / tool-call cap that actually gets
   used (or admit V is “one-shot dump”).
