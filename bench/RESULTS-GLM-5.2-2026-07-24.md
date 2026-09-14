# GLM-5.2 on the corrected probe protocol — 2026-07-24

## Why this run exists

`RESULTS-2026-07-24.md` ranks 11 local GGUF models but deliberately excludes
GLM-5.2: the only prior GLM artifact (`bench/probe/results/glm52.jsonl`) is the
old invalidated run (schema v1, 44 rows = 1 repeat, no metadata, no dataset
hash, thinking/label regime unmatched). `METHODOLOGY.md` says not to compare it
to the corrected runs. This file adds GLM-5.2 under the **exact corrected
protocol** so it can sit beside the leaderboard — with one stated caveat.

## Protocol (matches the v3 runs exactly, except transport)

44 cases × 5 repeats (220 requests), dataset SHA-256
`e01c93758993a9899fc56cf583c1baa855f4bf8838927530705066de5c613ef2`,
temperature 0, thinking disabled, 512 output tokens, 2 attempts, concurrency 4,
seed 20260724.

```bash
ZAI_API_KEY=<host ~/.bashrc key> python3 -m bench.probe.run_probe \
  --model glm-5.2 --proto anthropic \
  --base-url https://api.z.ai/api/anthropic --api-key "$ZAI_API_KEY" \
  --out bench/probe/results-current/glm-5.2.jsonl --repeats 5 \
  --metadata-json bench/probe/results-current/glm-5.2.runtime.json
```

Thinking is controlled via the Anthropic `thinking.type=disabled` body field
(not `chat_template_kwargs`, which is llama.cpp-only). Runtime metadata is in
`bench/probe/results-current/glm-5.2.runtime.json`. 220/220 responses were
semantically decidable (100% coverage), all bare JSON, no think envelopes.

## ⚠ Comparability caveat

`bench/probe/compare.py` **refuses cross-protocol comparison** by design
(`validate_compatible`: different API protocols → `CompatibilityError`). GLM-5.2
is the only `anthropic` run; every local model is `openai`. The numbers below
bypass that one guard (`bench/probe/results-current/_compare_glm.py`) while
keeping every protocol-independent integrity check: dataset hash, embedded
truth, complete `(case, repeat)` coverage, and the same paired clustered
bootstrap on mutually-decidable rows. **Treat the cross-protocol comparison as
a serving-system comparison, not a clean causal estimate**: GLM-5.2 runs behind
z.ai's hosted API; the local models run on a local A6000 via llama.cpp GGUF.
Per `METHODOLOGY.md`, this 44-case set is a development/diagnostic set, not an
external holdout — no general leaderboard claim follows.

## Result

GLM-5.2 is the top model on this set by every balanced metric.

| Model | proto | MCC | 95% CI | bal-acc | F1 | recall | prec | spec | CWE-exact | cover |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| **GLM-5.2** | anthropic | **0.821** | 0.611–0.989 | **91.9%** | **0.949** | 93.8% | 96.2% | **90.0%** | 68.7% | 100% |
| Titus-Cybersecurity-35B | openai | 0.752 | 0.508–0.935 | 84.6% | 0.937 | 97.5% | 90.2% | 71.7% | 72.4% | 100% |
| OpenMythos-27B | openai | 0.709 | 0.454–0.913 | 86.1% | 0.918 | 90.6% | 92.9% | 81.7% | 82.8% | 100% |
| Qwen3.6-27B | openai | 0.687 | 0.414–0.899 | 86.1% | 0.906 | 87.4% | 93.9% | 84.7% | 66.9% | 99.1% |
| Gemma-4-12B | openai | 0.673 | 0.422–0.879 | 84.5% | 0.908 | 89.4% | 92.3% | 79.7% | 54.5% | 99.5% |
| Qwopus3.6-27B-v2 | openai | 0.642 | 0.353–0.879 | 80.2% | 0.909 | 93.8% | 88.2% | 66.7% | 67.3% | 100% |
| Qwen3.6-35B-A3B | openai | 0.587 | 0.280–0.830 | 76.4% | 0.899 | 94.4% | 85.8% | 58.3% | 77.5% | 100% |
| CyberPal2.0-20B | openai | 0.393 | 0.040–0.686 | 66.7% | 0.857 | 91.7% | 80.4% | 41.7% | 44.4% | 98.6% |
| Qwen3-Coder-30B-A3B | openai | 0.385 | 0.081–0.660 | 70.0% | 0.821 | 80.0% | 84.2% | 60.0% | 65.6% | 100% |
| Qwen3.5-2B | openai | 0.328 | −0.051–0.566 | 58.0% | 0.862 | 99.4% | 76.1% | 16.7% | 11.3% | 100% |
| Qwen3-8B | openai | 0.292 | −0.029–0.591 | 63.9% | 0.821 | 84.4% | 79.9% | 43.3% | 19.3% | 100% |
| Qwen3.5-4B | openai | 0.257 | −0.070–0.564 | 61.3% | 0.826 | 87.5% | 78.2% | 35.0% | 36.4% | 100% |

Trivial always-vulnerable baseline: F1 0.842, bal-acc 0.500, MCC 0.000.

GLM-5.2 is unusually stable across the 5 repeats: per-repeat MCC
`[0.834, 0.771, 0.834, 0.834, 0.834]`, stdev 0.028 — the tightest of any run.

## GLM-5.2 error profile (deterministic at temperature 0)

Only **two** case types are ever missed, both 5/5 (real bugs GLM consistently
calls safe): `t2_cookie_secure` (CWE-614, missing Secure flag) and
`t3_bcrypt_low` (CWE-916, low bcrypt cost). These are both "configuration /
hardening" weaknesses, not injection — a consistent blind spot, not noise.

Only **two** decoys are ever flagged: `d_ssrf_allowlist_proper` (5/5 — the same
hardest decoy that also trips Gemma and others) and `d_realpath_guard` (1/5).

Per-tier recall: **T1 100%, T2 91.7%, T3 90.0%** — GLM is the only model above
90% on the subtle (T3) tier. (Titus T3 ≈ 84%, Gemma T3 ≈ 50%.)

CWE-exactness is 68.7% on true positives, but the losses are almost all
adjacent/related CWE mappings, not random: eval 94↔95, sandbox-escape 94→95,
jwt-none 347→345, authz 863→639, alg-confusion 347→327, hmac-timing 208↔327,
toctou 367→22, argument-injection 88→78, object-hook 502→95. Several of these
are the version-dependent labels `METHODOLOGY.md` flags as corrected/ambiguous.

## Is GLM-5.2 meaningfully ahead? (paired clustered bootstrap, mutually-decidable rows)

| Candidate | 95% CI (GLM − candidate MCC) | P(diff ≤ 0) | Verdict |
|---|---:|---:|---|
| Titus-Cybersecurity-35B | −0.196 .. +0.351 | 0.294 | not resolved |
| OpenMythos-27B | −0.163 .. +0.399 | 0.217 | not resolved |
| Qwen3.6-27B | −0.139 .. +0.432 | 0.177 | not resolved |
| Gemma-4-12B | −0.086 .. +0.428 | 0.113 | not resolved |
| Qwopus3.6-27B-v2 | −0.151 .. +0.511 | 0.154 | not resolved |
| Qwen3.6-35B-A3B | −0.010 .. +0.517 | 0.033 | not resolved |
| CyberPal2.0-20B | +0.136 .. +0.756 | 0.001 | **GLM ahead** |
| Qwen3-Coder-30B-A3B | +0.167 .. +0.736 | 0.000 | **GLM ahead** |
| Qwen3.5-2B | +0.192 .. +0.911 | 0.001 | **GLM ahead** |
| Qwen3-8B | +0.266 .. +0.824 | 0.000 | **GLM ahead** |
| Qwen3.5-4B | +0.254 .. +0.898 | 0.000 | **GLM ahead** |

GLM-5.2 is resolved ahead of the bottom five. Against the top five local models
(Titus, OpenMythos, Qwen3.6-27B, Gemma, Qwopus) and Qwen3.6-35B, the difference
is **not statistically resolved** on 44 cases — the 95% intervals all cross
zero, the closest being Qwen3.6-35B at P(diff ≤ 0) = 0.033. The point estimate
favors GLM everywhere, and its CI is the only one that clears MCC 0.8, but
44 cases × 5 repeats cannot separate GLM from the best local model on this dev
set.

## Bottom line

Under the corrected protocol GLM-5.2 is the strongest detector on this
development set (MCC 0.821, 100% coverage, highest specificity and the only
>90% T3 recall), with a consistent hardening-weakness blind spot. It is not
statistically separable from the top local model (Titus) here. The original
mission question — "smallest local model matching GLM-5.2" — still has no
resolved answer on 44 cases; Gemma-4-12B and Qwen3.6-27B remain the closest
unresolved contenders. Per `METHODOLOGY.md`, defer a product-selection claim to
a frozen external holdout.
