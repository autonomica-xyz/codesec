# codesec vuln-toolbox — detection benchmark report

> **⚠ PROVISIONAL / SUPERSEDED (2026-07-24).** A methodology review found the
> corpus runs contaminated (answer-key inside scan root + cross-task mutation) and
> the probe scoring/labels non-rigorous (parse-failures scored as valid, `bool("false")==True`,
> several wrong labels, non-uniform thinking regime, no statistics, test-set
> optimization). **Do not cite the ranking or the "gemma ≈ GLM-5.2" recommendation.**
> The corrected, executable protocol is now documented in
> [`METHODOLOGY.md`](METHODOLOGY.md), with corrected results in
> [`RESULTS-2026-07-24.md`](RESULTS-2026-07-24.md). The numbers below are kept
> only as a record of what was measured, not as validated conclusions.

**Status:** detection-probe phase complete; agent-loop validation in progress.
**Date:** 2026-07-23 · **Hardware (remote):** NVIDIA RTX A6000 48 GB (ThunderCompute) · **Local:** RTX A5000 16 GB

---

## 1. Mission

Build a **local static-analysis / vulnerability-discovery toolbox** that runs on
our GPU cluster, to optimize development and code-security review. Two questions:

1. **Quality:** how good is each locally-runnable model at *detecting* vulnerabilities?
2. **Sizing:** what is the **smallest model whose detection quality matches GLM-5.2**
   (the reference / target quality bar)?

## 2. Toolbox components

| Component | Path | Role |
|---|---|---|
| codesec agent | `codesec/` (8-stage pipeline: recon→hunt→validate→gapfill→dedupe→trace→feedback→report) | repo-level agentic vuln discovery (the product) |
| Detection probe | `bench/probe/` | standardized CWE-tagged snippet benchmark (model-quality) |
| Repo corpus | `bench/corpus/` *(in progress)* | realistic repo with planted bugs for agent-loop eval |
| Scorer | `bench/probe/score_probe.py`, `bench/probe/compare.py` | recall / precision / F1, per-tier, per-CWE |
| Model launcher | `bench/probe/probe_model.sh`, `bench/probe/run_sweep.sh` | load model on A6000 (Unsloth, parallel 4) → probe → score |

Serving backend: **Unsloth Studio** (`unsloth run`) fronting llama.cpp, OpenAI-compatible
`/v1/chat/completions`. GLM-5.2 via the **z.ai GLM Coding Plan** Anthropic-compatible API.

## 3. Methodology — detection probe

### 3.1 Dataset (`bench/probe/cases.py`)

Hand-curated, **CWE-tagged Python snippets (n=44)** with a deliberate difficulty
gradient so models separate (no ceiling effect). Every vulnerable snippet is
genuinely exploitable; every "safe" decoy is genuinely safe (so flagging it is a
real false positive).

| Tier | n | Description |
|---|---|---|
| **T1 blatant** | 10 | obvious sinks: `eval`, `pickle.loads`, `shell=True` concat, `render_template_string`, string-formatted SQL, `yaml.load`, SSRF, MD5 |
| **T2 medium** | 12 | bypassable sanitization / framework nuance: SSRF allowlist bypass (`127.0.0.1` vs `localhost`), ORDER BY SQLi, `basename` traversal, JWT `verify_signature=False`, ReDoS, sandboxed-eval escape, `Markup()` XSS, `random` tokens, mass-assignment |
| **T3 subtle** | 10 | logic/timing/state: TOCTOU, non-constant-time compare, authz boolean flaw, second-order SQLi, JWT alg-confusion, `json` object_hook→eval, int overflow, low bcrypt cost |
| **decoy (safe)** | 12 | looks risky, is safe: parameterized SQL, `shell=False` argv, hardcoded-arg `eval`, `render_template` (autoescape), strict allowlist redirect, `bcrypt`, `secrets.token`, `realpath`+prefix guard, `safe_load`, `compare_digest` |

**Correction:** CyberSecEval is available in Meta's PurpleLlama repository. The
earlier contrary conclusion came from a misspelled sparse-checkout path.
CyberSecEval's secure-code-generation arm measures a different construct; this
custom set is retained only as a development/diagnostic classification probe,
not an external holdout.

### 3.2 Probe protocol (`bench/probe/run_probe.py`)

One classification call per snippet. System prompt instructs the model that many
snippets are **safe** (only flag concrete exploitable bugs) and to reply **only**
with JSON: `{"vulnerable": bool, "cwe": "CWE-XX"|null, "confidence": 0-1, "reason": "≤15 words"}`.

- **Thinking disabled uniformly** (`chat_template_kwargs.enable_thinking=false`,
  `max_tokens=400`). **Why:** reasoning models otherwise burn the token budget on
  chain-of-thought and return empty `content` → mis-scored as "safe" (this caused
  the initial false 0% recall for Qwen3-8B / gemma-12B / Qwen3.6-27B). Disabling
  thinking gives a fair, fast, deterministic comparison of raw classification
  ability. Caveat: this undersells reasoning-tuned models (Qwen3.x), whose
  strength is CoT — see §6.
- **Two protocols:** Anthropic Messages API (z.ai → GLM-5.2), OpenAI chat
  completions (Unsloth → local models).
- Concurrency 6 per model.

### 3.3 Scoring (`bench/probe/score_probe.py`, `compare.py`)

Per model, per case: predicted `vulnerable` + `cwe` vs ground truth.

- **recall** = TP/(TP+FN) — fraction of real bugs caught.
- **precision** = TP/(TP+FP) — fraction of "vulnerable" calls that are real.
- **F1**, **accuracy**.
- **per-tier recall** (T1/T2/T3) — the difficulty curve.
- **decoy specificity** = TN/(TN+FP) — fraction of safe code correctly *not* flagged.
- **CWE-exact** = among TP, fraction with the correct CWE.

### 3.4 Model sweep

Ladder (Unsloth GGUF, recommended quant per model), all loaded `--parallel 4` on
the A6000: Qwen3.5-2B · Qwen3.5-4B · Qwen3-8B · gemma-4-12b-it · Qwen3.6-27B-MTP ·
Qwen3-Coder-30B-A3B · Qwen3.6-35B-A3B. GLM-5.2 via z.ai API as the ceiling.

## 4. Results — detection-quality frontier

Same regime (thinking-off, n=44), sorted by F1:

| rank | model | size | acc | recall | prec | **F1** | T1 | T2 | T3(subtle) | decoy-spec |
|---|---|---|---|---|---|---|---|---|---|---|
| — | **GLM-5.2** | API | 89% | 91% | 94% | **0.92** | 100% | 100% | 70% | 83% | ← target |
| 1 | **gemma-4-12b** | **12B** | 86% | 84% | 96% | **0.90** | 100% | 100% | 50% | 92% |
| 2 | Qwen3.6-35B-A3B | 35B | 84% | 84% | 93% | 0.89 | 100% | 92% | 60% | 83% |
| 3 | Qwen3.5-4B | **4B** | 82% | 84% | 90% | 0.87 | 90% | 83% | **80%** | 75% |
| 4 | Qwen3.6-27B-MTP | 27B | 82% | 78% | 96% | 0.86 | 90% | 92% | 50% | 92% |
| 5 | Qwen3-Coder-30B-A3B | 30B | 82% | 75% | 100% | 0.86 | 100% | 83% | 40% | 100% |
| 6 | Qwen3.5-2B | 2B | 75% | 81% | 84% | 0.83 | 90% | 75% | 80% | 58% |
| 7 | Qwen3-8B | 8B | 77% | 72% | 96% | 0.82 | 100% | 67% | 50% | 92% |

GLM-5.2 CWE-exact = 66%. Per-CWE recall (GLM-5.2): full marks on CWE-89/94/502/918/78/
601/611/79/863/347/367/1333/190/327/330/915/614; missed CWE-284 (cache-key DoS),
CWE-916 (low bcrypt cost), and the borderline CWE-78 glob case.

## 5. Findings & recommendation

1. **No local model matches GLM-5.2's 0.92** — it leads by 2–10 F1 points. The gap
   is smallest on blatant/medium bugs and largest on *subtle* (T3) and CWE-exactness.
2. **Best local pick — `gemma-4-12b` (F1 0.90)**: within 0.02 of GLM-5.2, highest
   precision (96%), perfect on T1/T2, small/cheap. Sole weakness: subtle bugs (T3 50%
   vs GLM 70%). **Recommended default for the toolbox.**
3. **Smallest viable — `Qwen3.5-4B` (F1 0.87)**: only 4B, and best-in-class on subtle
   bugs (T3 80%, *ahead of GLM-5.2*). Good when VRAM is tight.
4. **Bigger ≠ better (in this regime).** Qwen3.x reasoning models (8B/27B/30B/35B)
   *underperform* gemma-12b and Qwen3.5-4B with thinking off. Their CoT strength is
   disabled here; re-evaluating with thinking-on is future work (§6).
5. **Precision is uniformly high (84–100%)** — the safe decoys worked; models don't
   cry wolf. The discriminator is **recall on subtle bugs**.

## 6. Caveats / threats to validity

- **Thinking-off regime** undersells reasoning models. A thinking-on sweep (longer,
  higher-variance) is the natural follow-up; expect Qwen3.x to rise.
- **n=44** is a focused set; per-CWE cells are small. The tier breakdown is the
  robust signal.
- **Probe = model-quality, not agent-quality.** A model that classifies snippets well
  must still be validated through the full codesec agent (recon→hunt→trace) on a real
  repo — see §7.
- **Snippet bias:** snippets telegraph the sink (no surrounding code to hide it). The
  repo eval (§7) tests discovery *in context*.

## 7. Agent-loop validation (in progress)

Run the codesec 8-stage agent on a **harder, realistic repo** (`bench/corpus/`)
through:
- **gemma-4-12b** (probe winner) on the A6000,
- **GLM-5.2** via z.ai (reference),
scored against a ground-truth manifest with `score.py`.

Earlier agent result on the *easy* devnotes target (281 lines, blatant bugs):
Qwen3.6-27B full pipeline → **16/16 recall, 27/27 precision** — a ceiling effect that
motivated building a harder corpus. The gapfill stage was the recall multiplier
(recon's first pass found 3/16 bugs; gapfill recovered the other 13).

## 8. Engineering fixes made to codesec (this project)

Both are real correctness bugs that blocked local-GPU use; both shipped to the
remote and are in `codesec/`:

1. **Concurrency was a no-op for the local engine** (`codesec/runner.py`).
   `run_local_agent` does blocking `urllib`/`subprocess`, but the local branch did a
   plain synchronous `return` inside an `async def` — never offloaded to a thread. So
   `asyncio.Semaphore(concurrency)` + `asyncio.gather` serialized every task; `--max-concurrency`
   did nothing. **Fix:** route through `await asyncio.to_thread(...)` via a shared
   `_once()` closure. Result: `--parallel 4` on the A6000 → **~2.2× aggregate decode
   throughput** (measured), full pipeline completes.
2. **One network timeout killed the whole pipeline** (`codesec/runner.py`,
   `codesec/local_agent.py`). `_chat` only caught `HTTPError`, not socket timeouts; and
   the local path bypassed the transient-retry loop. **Fix:** classify
   `URLError`/`TimeoutError`/`ConnectionError` as `TransientAgentError`, and route the
   local engine through the same retry-with-backoff loop as the SDK path. Verified in
   production (a `TimeoutError: timed out` was retried and recovered mid-run).

## 9. Reproducibility

```bash
# detection probe on a local model (A6000, Unsloth)
cd bench/probe && ./probe_model.sh unsloth/gemma-4-12b-it-GGUF gemma4-12b
python3 score_probe.py results/gemma4-12b.jsonl

# GLM-5.2 ceiling (z.ai API)
ZAI_API_KEY=... python3 run_probe.py --model glm-5.2 --proto anthropic \
  --base-url https://api.z.ai/api/anthropic --out glm52.jsonl

# full ranked table
python3 compare.py --dir results
```

## 10. End-game checklist (after agent validation)

1. Pull all artifacts (results, runlogs, `bench/`) off the remote.
2. **Snapshot** the ThunderCompute instance (preserve data).
3. `source ~/.bashrc && tnr <destroy>` to stop spend.
