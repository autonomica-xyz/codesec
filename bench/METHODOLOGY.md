# Benchmark methodology

This file defines the corrected protocol. `REPORT.md` is an invalidated
historical record and its old rankings must not be used.

## Evaluation arms

The benchmark has two distinct arms and does not combine their scores:

1. The 44-case snippet probe measures narrow vulnerability-classification
   behavior. Because these cases were previously inspected and used for model
   selection, this is a **development/diagnostic set**, not an unbiased
   holdout.
2. The `devshop` repository measures end-to-end codesec behavior: discovery,
   validation, deduplication, reachability tracing, and final reporting.

CyberSecEval is available in Meta's PurpleLlama repository. The earlier claim
that its data was unavailable came from a misspelled sparse-checkout path.
Its secure-code-generation datasets measure a different construct from
vulnerability classification, so their scores must not be presented as a
drop-in validation of this probe. A future confirmatory classification result
needs a separately sourced, frozen positive-and-negative holdout.

## Snippet probe protocol

- Dataset: `bench/probe/cases.py`, frozen per run by a SHA-256 over the IDs,
  labels, CWE, tier, language, and exact code.
- Result schema: version 3 separates a semantic boolean verdict (`ok`) from
  full auxiliary response-contract compliance (`contract_ok`).
- Prompt: generic review instructions. It does not enumerate the decoy
  defenses or expose case notes.
- Sampling: five repeats per case by default, temperature 0, repeat-derived
  seeds, thinking explicitly disabled, 512 output tokens, concurrency four.
- Endpoint: legacy Unsloth-hosted runs use Unsloth to select and launch the
  GGUF, then send evaluation requests to its localhost llama.cpp port directly.
  Community GGUF runs pin the Hugging Face repository revision, stage one model
  at a time in tmpfs, and launch llama.cpp directly. The Unsloth proxy is not
  used because it drops per-request `chat_template_kwargs`; direct requests
  demonstrably enforce `enable_thinking=false`.
- Response contract: one JSON object, either bare or as the sole content of one
  JSON markdown fence. A single leading `<think>...</think>` block emitted by a
  chat template is treated as a transparent reasoning-channel envelope only
  when the remainder is exactly that JSON payload. Bare-JSON compliance is
  recorded separately, so fences and think envelopes are non-exact formatting.
  Arbitrary surrounding prose is not accepted. `vulnerable` must be a JSON
  boolean; a vulnerable call must contain a `CWE-<number>` and a safe call must
  contain `null`; confidence must be in `[0, 1]`.
- Detection extraction: a sole JSON object with a boolean `vulnerable` field
  is a decidable semantic verdict even if an auxiliary `cwe`, `confidence`, or
  `reason` field violates the full response contract. Auxiliary violations
  are recorded as contract failures; a missing/invalid CWE still fails CWE
  exactness. Responses containing multiple answers or surrounding prose remain
  undecidable because selecting one verdict would require post-hoc judgment.
- Failure policy: requests and responses without an unambiguous semantic
  verdict receive at most two attempts. An unresolved response error is
  retained as an **undecidable row**: it is neither coerced into a prediction
  nor allowed to erase the model's other semantic classifications. Missing
  rows, duplicates, unexpected rows, truth mismatches, and dataset-hash
  mismatches still invalidate the artifact because they compromise evaluation
  integrity.
- Comparability: the comparator rejects runs with different result schemas,
  dataset hashes, API protocols, repeat counts, thinking settings,
  temperatures, token budgets, seeds, retry counts, or concurrency.
- Runtime record: every run stores the requested model, served alias, selected
  GGUF path/quantization, server command, package versions, GPU, host, Python
  version, and inference settings.
- GPU gate: direct GGUF runs export the dynamic CUDA backend/runtime paths,
  request all layers on GPU, and abort unless the server process allocates VRAM
  proportional to the GGUF size. Endpoint readiness alone is insufficient
  because llama.cpp can otherwise load successfully on CPU.
- Derived artifacts: `reparse_run.py` can replay preserved raw responses through
  the current parser without another model request. It never overwrites the
  source, records the source SHA-256/schema in `derivation`, stops at the first
  semantically decidable attempt, and validates the derived artifact before it
  can enter the standard comparator.

The north star is semantic detection quality. Primary metrics are Matthews
correlation coefficient (MCC) and balanced accuracy on decidable rows because
the set has 32 vulnerable and 12 safe cases. Semantic coverage
(`decidable / requested`) is always displayed beside those metrics so missing
answers cannot be hidden. Recall, precision, specificity, F1, CWE exactness,
and per-tier recall are secondary detection diagnostics. Exact format,
first-pass validity, retries, and request failures are operational diagnostics;
they do not change a semantic verdict into a classification error or discard
an otherwise informative run.

Uncertainty is a 95% clustered bootstrap interval resampled by case. Model
differences use only mutually decidable `(case, repeat)` pairs in a paired
clustered bootstrap, and coverage is reported for both models. When a run has
undecidable rows, the scorer also reports the full-coverage MCC range across
every possible binary verdict for those rows; this exposes the maximum impact
of missing answers without pretending to know what the model meant. The
always-vulnerable baseline is printed with every score. Repeats characterize
serving/output stability and are not treated as 220 independent cases.

## Repository protocol

- The answer key is outside the scan root at
  `bench/corpus/manifests/devshop.json`.
- Each trial receives a fresh temporary corpus copy, owned by root and made
  recursively read-only. The runner verifies a deterministic content hash
  before and after the run. Target mutation invalidates the trial.
- The runner refuses to overwrite an existing result or take over an occupied
  inference port. It stops only the process group it started.
- Agents share result state through codesec's run directories, not through the
  target. Generated PoCs, databases, and finding files cannot become input to
  another task or model.
- Candidate, validation, reachability, and final-report outputs are scored
  separately with `python -m bench.score_repo <run-root> <manifest> --stages`.
  A strong final score cannot hide weak discovery recall or missing traces.
- A match requires exact source basename and line overlap. Each truth entry can
  match at most one finding. Class and CWE agreement strengthen assignment but
  cannot substitute for location.
- The manifest contains source ranges for every positive and decoy. The
  allowlisted export command and basename-guarded file read are decoys, not
  positives.
- Every entry declares `expected_stage`, `reachability`, and attacker
  preconditions. Unsafe YAML loading, the vulnerable email regex, and JWT
  algorithm confusion are valid discovery candidates but have no application
  entry path in this fixture; they must not receive final-report recall credit.

Repository results report candidate and confirmed precision/recall, trace
decision coverage and accuracy, final finding precision/recall/specificity,
per-tier recall, missed IDs, and flagged decoys. One repository and one trial
cannot support a population-level uncertainty claim; it is an end-to-end
regression/acceptance test.

The reproducible one-GPU pair command is:

```bash
bench/corpus/run_duo.sh \
  /models/Titus-CybersecurityLLM-v1.0.Q4_K_M.gguf \
  /models/OpenMythos-27B-Q6_K.gguf \
  repetition-1
```

Use `bench/corpus/run_agent.sh <unsloth-model-spec> <tag>` for clean
Titus-only and OpenMythos-only legacy baselines. Run each arm in a fresh run
root and repeat the three arms before comparing quality or timing.

## Interpretation limits

- Do not claim that a probe winner is generally best at security review.
- Do not compare the old GLM run with corrected local runs: the datasets and
  protocols differ.
- Do not infer model-size effects from seven hand-picked models.
- Do not call a difference meaningful solely because point estimates differ;
  report the paired interval.
- Freeze this protocol and use a new external holdout before making a final
  product-selection claim.
