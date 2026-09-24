# Evaluation plan — codesec vs vanilla Pi on RealVuln (GLM-5.3)

Status: **planned, not yet executed**. This is the executable contract for
the first scored run.

**Question:** on the same model (`glm-5.3` via the Z.AI GLM Coding Plan),
does the codesec 8-stage pipeline detect more — and more precisely — than a
clean vanilla Pi coding-agent session, on a public labeled corpus?

Corpus is **[RealVuln](https://github.com/kolega-ai/Real-Vuln-Benchmark)
v3.0.0**, not `bench/corpus/devshop`. Scoring is RealVuln's matcher
(file + CWE + line ±10) and **F3** (recall weighted 9×). `devshop` and
`score_repo` are diagnostics only; they are not the headline.

Local-vs-Z.AI (Titus/OpenMythos, GGUFs) stays in Appendix A and does not
start until this harness question has a scored answer.

---

## 0. Arms

Two arms. Same provider, same model id, different harness.

| Arm | Harness | Model | Invocation |
|---|---|---|---|
| **H — codesec** | codesec 8-stage pipeline | `glm-5.3` on **every** stage | `codesec run --provider zai --model glm-5.3 --prior off …` |
| **V — vanilla pi** | Pi CLI, one non-interactive session, default four tools, one frozen audit prompt | `glm-5.3` | `pi -p --provider zai --model glm-5.3 …` |

`--model glm-5.3` on codesec is load-bearing: bare `--provider zai` maps
opus → `glm-5.2` and sonnet → `glm-4.7`. Collapsing Hunt and Validate onto
the same id is **intentional**. The validate panel stays adversarial in the
prompt.

Do **not** use `glm-5.3-flash`, `glm-5.3-highspeed`, or this host's local
`glm-5.3-flash` on `:8000`.

Scanner slugs written into RealVuln `scan-results/`:

| Slug | Source |
|---|---|
| `codesec-glm53-hunt` | Hunt candidates (discovery) |
| `codesec-glm53-final` | Report-stage findings (shipped) |
| `pi-glm53` | Vanilla Pi findings |

Headline comparison is **`codesec-glm53-final` vs `pi-glm53`**. Hunt vs Pi
is the discovery diagnostic. Hunt vs final is the “does Validate+Trace
help inside codesec” diagnostic. Do not invent a confirmed-validator slug
from a second model.

---

## 1. Corpus (frozen)

Pin RealVuln by **commit SHA**, not a guessed tag. There is **no `v3.0.0`
tag** on `kolega-ai/Real-Vuln-Benchmark` (only `v1.0`). `main` currently
advertises `benchmark_version` **3.1.0**. Phase 0 records
`git rev-parse HEAD` and re-derives every Wave 1 vuln/trap count from
that SHA’s `ground-truth/{slug}/ground-truth.json`. The table below is a
planning snapshot and is **invalid until re-derived**.

Clone the benchmark repo **next to** codesec, not inside the scan root:

```
/home/user/g/codesec/                  # harness under test
/home/user/g/Real-Vuln-Benchmark/      # GT, scorer, pinned app clones
  ground-truth/{slug}/ground-truth.json
  repos/{slug}/                        # git clones at pinned SHAs
  scan-results/{slug}/{scanner}/run-N.json
  reports/
```

**In scope: Python community (human-authored) apps only.** 26 repos, 703
vulns, 121 FP traps. Skip:

- Python LLM-generated seeded apps (authorship confound)
- All TypeScript/JavaScript (no FP traps in v3; Juice Shop is memorized)
- `realvuln-juice-shop` and `realvuln-juice-shop-goof` even if someone
  later adds Python — contamination

### Wave 0 — smoke (unscored)

`realvuln-intentionally-vulnerable-python-application` (7 vulns, 2 traps,
Flask). Confirms runners, adapter, scorer, glm-5.3 on every codesec stage.

### Wave 1 — the experiment (scored)

Frozen six-repo set. Do not add or drop a slug after the first scored
trial.

| Slug | Framework | Vulns | FP traps | Why |
|---|---|---|---:|---|
| `realvuln-vampi` | Flask | 15 | 4 | small API |
| `realvuln-damn-vulnerable-flask-application` | Flask | 15 | 4 | classic DV Flask |
| `realvuln-python-insecure-app` | FastAPI | 8 | 2 | second framework |
| `realvuln-dvpwa` | aiohttp | 23 | 4 | third framework |
| `realvuln-lets-be-bad-guys` | Django | 24 | 4 | Django, mid size |
| `realvuln-pygoat` | Django | 78 | 10 | large; where fan-out should matter |

**Do not use these counts as the denominator.** A GLM-5.3 Pi review of
`main` already disagrees with this table
(`realvuln-damn-vulnerable-flask-application` 14/5, not 15/4; Wave 1
arithmetic 15+15+8+23+24+78 = 163, not 155). Phase 0 prints a frozen
`subset-counts.json` from the pinned SHA and the rest of this document
defers to that file.

6 repos × 2 arms × 3 trials = **36 scored runs**.

### Wave 2 — optional remainder

The other 20 Python community slugs, same protocol, only if Wave 1 is
inconclusive (T3-equivalent: per-CWE-family recall ties and decoy counts
overlap) or if H clearly wins and we want a headline on the full 26.

Headline aggregation is RealVuln **strict micro**: pool TP/FP/FN/TN across
the Wave 1 slugs. An unfinished repo counts as all false-negatives for that
arm/trial.

---

## 2. What is held constant vs what is the harness

Held constant:

- Provider `zai`, model id `glm-5.3`. **Wire protocol is not the same by
  default:** codesec uses Anthropic Messages at
  `https://api.z.ai/api/anthropic`; Pi 0.85.1’s built-in `zai` catalog
  serves `glm-5.3` as `openai-completions` at
  `https://api.z.ai/api/coding/paas/v4`. Phase 0 either (a) drops a
  trial-local `models.json` in `$PI_CODING_AGENT_DIR` that points Pi at
  the Anthropic endpoint, or (b) records the protocol split as part of
  the harness and stamps resolved `{provider, model, baseUrl, api}` per
  arm. Silence is not allowed.
- RealVuln slug and pinned commit SHA (operator-side only)
- Blinded read-only work copy named `target/` (§3.1) — no slug, no `.git`,
  no README/walkthrough
- Ground truth **outside** the scan root (the RealVuln checkout, never copied
  into `repos/` or the work copy)
- Cross-run memory off
- No human steering
- Same adapter → Semgrep JSON → `python3 score.py`
- Same thinking setting on both arms (Phase 0 lock)

Allowed to differ (the harness):

- Fan-out, stage prompts, schemas, repair, adversarial panel, trace
- codesec tools vs Pi tools
- Concurrency (H: 10, V: 1) — recorded, not a quality knob
- Token mix and wall clock

---

## 3. Fairness rules

1. **Budget (H).** `--max-recon-tasks 20` on every Wave 1 slug except
   `realvuln-pygoat`, which uses **40**. Same number on all three H
   trials of that slug. Also set **`--max-hours 2`** (pygoat **3**).
   Exhausted budget with parseable `report.json` is **scored** (not
   all-FN, not silently invalid). Missing report → invalid, re-run at
   end. Default loop budget from `config/stages.yaml`. `--prior off`.
2. **Budget (V).** One `pi -p` session, one frozen prompt, no
   `--continue`. Wall-clock cap **45 minutes** except pygoat **90
   minutes**. Hitting the cap still scores whatever `findings.json`
   exists; missing/unparseable file → trial invalid, not zero-recall.
3. **Thinking.** codesec’s SDK path currently builds `ClaudeAgentOptions`
   **without** a thinking field; Pi has `--thinking`. Expect Phase 0 to
   lock **both off** unless a codesec change can enable thinking and a
   captured H request proves it. Do not leave a one-sided CoT advantage.
   Record the resolved thinking level from each session, not only the flag.
4. **Memory.** H: `--prior off`, fresh `--run-root`. V: fresh
   `PI_CODING_AGENT_DIR` + `--session-dir "$RUN_ROOT/pi-session"`. Never
   use host `~/.pi` (it has `pi-local-models` and local glm-5.3-flash).
5. **Fresh blinded read-only copy.** Every trial goes through
   `blind_prepare.py` (§3.1), not a raw copy of `repos/$SLUG`. Digest
   before and after. Mutation invalidates. GT, scan-results, the RealVuln
   git checkout, and the slug→opaque map are **never** in the scan tree.
6. **No overwrite.** Refuse an existing
   `scan-results/{slug}/{scanner}/run-{N}.json`.
7. **No overlapping Z.AI load.** Never run H and V at the same time.
8. **No LLM-as-judge.** Adapter is strict JSON (bare object or one fence)
   → Semgrep JSON. Findings missing repo-relative `path` + positive line +
   `CWE-\d+` are dropped and counted. No second model, no GT lookup.
9. **Path + CWE are required for a TP.** RealVuln matching is stricter
   than codesec `score_repo` (which only needs basename + line). The
   prompt and adapter must emit repo-relative paths (`app/views.py`, not
   `views.py`) and a CWE. Basename-only output will miss.
10. **Runtime record** per trial: slug (operator-side only), opaque id,
    commit SHA, arm, trial index, glm-5.3, thinking, Pi version, codesec
    git rev, prompt SHA-256, adapter kept/dropped, tokens, wall clock,
    recon-task cap / Pi timeout, RealVuln git SHA, identity-leak flags,
    canary hit.

---

## 3.1 Blind protocol (anti-cheat)

The agents must not be told which RealVuln app they are on, and the work
tree must not hand them the answer. This is a **two-layer** problem:

| Layer | What leaks | Can we stop it? |
|---|---|---|
| **Trial identity** | directory name `realvuln-pygoat`, `.git` remote, README “this is PyGoat”, run-id in the prompt, `git log` | **Yes — mandatory.** If any of these is visible, the trial is invalid. |
| **Training-data recall** | GLM-5.3 has seen VAmPI/PyGoat source on the public web and can recognize `SECRET_KEY = 'random'` or `/users/v1/_debug` even in a folder named `target` | **Not fully.** Do not pretend renaming the folder is enough. Measure it (§3.1.4). |

Do **not** rewrite Python identifiers or move source files in Wave 1.
That would break imports, Hunt PoCs, and GT line numbers. Residual leak:
`INSTALLED_APPS = ['pygoat']` can still name the app. Record it; do not
“fix” it by rewriting the program.

### 3.1.1 Operator vs agent view

| Visible to the operator (run root, logs on the host) | Visible to the agent (cwd + prompt + env) |
|---|---|
| RealVuln slug, trial index, GT path | **Never** |
| Opaque id `t9f3c2a1` | Generic cwd only |
| `scan-results/realvuln-pygoat/...` | Not mounted |

codesec `--repo` and Pi cwd **must** be the blinded tree. codesec
`--run-id` must be the opaque id, not `h_pygoat_t1` (recon does not
put run-id in the user payload, but `ps`, shell history, and artifact
paths can). `repo_path` in the recon JSON is `/…/target`, never a slug.

The frozen Pi prompt is **identical** for every slug. No
`scope_notes`. No “intentionally vulnerable”, “CTF”, “OWASP”,
“RealVuln”, “PyGoat”, “VAmPI”.

### 3.1.2 `blind_prepare.py` (mandatory, every trial)

Input: `$REALVULN/repos/$SLUG` at the pinned SHA.
Output: `$WORK/target` (read-only) plus `$RUN_ROOT/blind.json` (operator
only).

1. `rsync -a --delete` excluding:
   `.git/`, `.github/`, `.gitignore`, `.gitattributes`, `.gitmodules`,
   `__pycache__/`, `*.pyc`, `.venv/`, `node_modules/`, `.idea/`, `.vscode/`.
2. Destination directory is always named `target`, under a random
   `mktemp -d` parent with **no** `rv`/`realvuln`/`pygoat` prefix
   (`/tmp/XXXXXXXX/target` or `$WORK_BASE/$OPAQUE/target`). The parent
   name is the opaque id, not the slug.
3. **Delete identity/spoiler docs** (do not copy): root and nested
   `README*`, `CHANGELOG*`, `CONTRIBUTING*`, `SECURITY.md`, `AUTHORS*`,
   `NOTICE*`, files matching `*walkthrough*`, `*solution*`, `*writeup*`,
   `docs/`, `documentation/`, `challenges/`, `lessons/`, `.env.example`.
   Keep `LICENSE` only if it does not contain the project name; otherwise
   drop it. These files are how recon starts (`01-recon.md` step 1 is
   `ls` + root README).
4. **Do not** strip `.py` comments or `if vuln == 1` branches. Those are
   program semantics GT is labeled against. Blanking them shifts meaning
   or lines.
5. **Canary (every scored trial).** Append one unique, not-on-the-public-
   internet sink at the **end** of one existing `.py` file so earlier GT
   line numbers do not move. The inserted range must start **more than
   10 lines after** that file’s max GT `end_line` (RealVuln ±10). Use a
   neutral function name, not `audit_probe_*`. Record
   `{file, line, cwe, nonce}` in the **operator-only** map (not under
   any path the agent can read). The agent is not told.
   `adapt_to_semgrep.py` **must strip** a canary-matched finding from the
   Semgrep JSON written to `scan-results/` and set `canary_hit` only in
   metrics. If it is left in, RealVuln scores it as an unmatched FP and
   the arm that notices the canary is punished. Do not add the canary to
   RealVuln GT.
6. `chown root:root` and `chmod -R a-w` on `target`. Digest the blinded
   tree (this digest is what before/after compares).
7. Write the operator map **outside** `$RUN_ROOT` if that directory is
   agent-writable (Pi is told to write `$RUN_ROOT/findings.json`).
   Preferred: `$CODESEC/bench/realvuln-runs/operator/$OPAQUE.json`
   mode 0600, never copied into the VM/guest. Contents:

   ```json
   {
     "opaque_id": "t9f3c2a1",
     "slug": "realvuln-pygoat",
     "commit_sha": "…",
     "target": "/tmp/XXXXXXXX/target",
     "dropped_paths": ["README.md", ".git"],
     "canary": {"file": "app.py", "line": 214, "cwe": "CWE-95", "nonce": "…"}
   }
   ```

   Host-only. Never inside `target`. Never next to `findings.json`.

8. **Dropped-path ∩ GT = ∅.** After deletions, every GT `file` for the
   slug must still exist in `target/` with the same start/end lines.
   Fail Phase 0 / the trial if a labeled file was deleted.

Phase 0 gate: after a dry `blind_prepare` of pygoat and vampi,
`rg -i 'pygoat|vampi|realvuln|owasp|intentionally vulnerable' $TARGET`
returns **no matches in deleted-class files** (README etc. are gone).
Hits inside `.py` source (package names) are logged as
`residual_identity` and are **not** a Phase 0 failure.

### 3.1.3 What the runners pass

```bash
OPAQUE="$(python3 blind_prepare.py --slug "$SLUG" --out "$RUN_ROOT")"
TARGET="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["target"])' \
  "$RUN_ROOT/blind.json")"
# H:
codesec run --repo "$TARGET" --run-id "$OPAQUE" --provider zai --model glm-5.3 …
# V: cwd=$TARGET, findings path is $RUN_ROOT/findings.json (outside target)
```

Adapter maps agent paths relative to `$TARGET` onto GT paths (same
relative layout; we did not rename source files). Canary matching uses
`blind.json`, not GT.

### 3.1.4 Measuring remaining cheat (not a reason to skip blinding)

Blinding stops **label leakage**. It does not stop a model that already
memorized VAmPI. After scoring, compute three diagnostics — they do not
change F3, they qualify it:

1. **Identity leak in output.** Grep Hunt/Pi/report text for slug
   aliases (`pygoat`, `vampi`, `dvpwa`, `lets-be-bad-guys`, `realvuln`,
   `juice shop`, `owasp goat`, `intentionally vulnerable app`). Flag the
   trial `identity_leak=true`. Still score it; do not silently drop.
   A high leak rate means the residual package-name channel is live.
2. **Canary miss + famous-hit.** On a slug, if the arm hits ≥ 70% of
   labeled vulns and **misses the canary**, footnote as
   `possible_recall`. One trial does not prove cheating; a pattern
   across famous slugs does.
3. **Famous vs obscure split.** Wave 1 buckets:
   - Famous (high public walkthrough density): `vampi`,
     `damn-vulnerable-flask-application`, `pygoat`
   - Obscure: `python-insecure-app`, `dvpwa`, `lets-be-bad-guys`
   Report micro F3 on each bucket. If H and V tie on famous and
   separate only on obscure, the harness result is the obscure bucket.

If identity leaks fire on a majority of trials, stop and add a **level-2
blind** (identifier rewrite + GT path map) before Wave 2. That is a
protocol change, not a silent mid-matrix tweak.

---

## 4. Layout and artifacts

```
$CODESEC/bench/realvuln/
  pi_audit_prompt.md              # frozen; placeholders __FINDINGS_PATH__
  blind_prepare.py                # identity strip + canary + opaque cwd
  adapt_to_semgrep.py             # findings.json | report.json → Semgrep JSON
  run_h.sh                        # one H trial
  run_v.sh                        # one V trial
  run_matrix.sh                   # Wave 1 interleave + score
  subset.txt                      # the six slugs, one per line
  famous.txt                      # vampi, damn-vulnerable-flask, pygoat
  obscure.txt                     # python-insecure-app, dvpwa, lets-be-bad-guys

$CODESEC/bench/realvuln-runs/
  {opaque_id}/                    # NOT the RealVuln slug
    blind.json                    # operator map: opaque → slug (never in target)
    findings.json                 # V only
    adapter_dropped.json
    benchmark_meta.json
    identity_leak.txt             # grep hits in agent output, if any

$REALVULN/scan-results/{slug}/
  codesec-glm53-hunt/run-{1,2,3}.json
  codesec-glm53-final/run-{1,2,3}.json
  pi-glm53/run-{1,2,3}.json
  *.metrics.json                  # tokens, wall clock, prompt hash
```

Ground truth is only read by `score.py`. The adapter **never** opens it.
`blind.json` is operator-only. The agent's cwd is always `…/target`.

---

## 5. Phase 0 — prep (est. 0.5 day)

Exit criteria in brackets.

1. **codesec**
   ```bash
   cd /home/user/g/codesec
   python3 -m venv .venv && . .venv/bin/activate && pip install -e .
   codesec providers   # anthropic, zai, unsloth
   ```
2. **RealVuln**
   ```bash
   git clone https://github.com/kolega-ai/Real-Vuln-Benchmark \
     /home/user/g/Real-Vuln-Benchmark
   cd /home/user/g/Real-Vuln-Benchmark
   git checkout v3.0.0   # or the SHA recorded here if the tag moves
   python3 -m venv .venv && . .venv/bin/activate && pip install -e ".[dev]"
   python3 validate_gt.py
   python3 clone_repos.py --repo \
     realvuln-intentionally-vulnerable-python-application \
     realvuln-vampi \
     realvuln-damn-vulnerable-flask-application \
     realvuln-python-insecure-app \
     realvuln-dvpwa \
     realvuln-lets-be-bad-guys \
     realvuln-pygoat
   python3 clone_repos.py --status
   python3 smoke_test.py
   ```
   Record `git rev-parse HEAD` and each slug's `commit_sha` from
   `ground-truth/{slug}/ground-truth.json`. [All seven clones exist at the
   pinned SHA.]
3. **Z.AI auth**
   ```bash
   export ZAI_API_KEY=…
   codesec auth-check --provider zai --model glm-5.3
   pi auth check --provider zai --model glm-5.3
   ```
   Record each arm’s resolved `{baseUrl, api}`. Pi’s built-in zai catalog
   is **not** the Anthropic URL (see §2). Neither may show `:8000`.
4. **Pin Pi** at the recorded version (currently 0.85.1). Do not `pi update`
   mid-comparison. Confirm `pi -p` runs the tool loop to completion.
5. **Confirm codesec uses glm-5.3 everywhere.** Wave 0 H with
   `--max-recon-tasks 2`; grep stage logs so recon, hunt, validate, trace,
   report all say `glm-5.3`. A 5.2/4.7 leftover invalidates the trial.
6. **Lock thinking** from one captured H request and one V session
   (§3 rule 3). Expect both **off** unless codesec grows an SDK thinking
   knob.
7. **Land** `pi_audit_prompt.md`, `blind_prepare.py`, `adapt_to_semgrep.py`,
   `run_h.sh`, `run_v.sh`, `run_matrix.sh` under `bench/realvuln/`.
8. **Blindness smoke.** `blind_prepare.py` on pygoat and vampi. Confirm:
   cwd is named `target`; no `.git`; no README; `rg` for slug aliases in
   dropped-class files is empty; operator map is **not** next to
   `findings.json`; canary starts **>10 lines after** that file’s max GT
   `end_line`; **no GT `file` was deleted**. [Gate.]
9. **Decide execution venue** before Wave 1: (A) this host with
   transcript greps for `curl|wget|git clone|/proc/`; or (B) one
   disposable VM per trial with egress allowlisted to Z.AI only (exe.dev
   is a candidate for isolation + key proxy, **not** for egress lock
   unless they add it). Default if unspecified: **B if egress lock
   exists, else A plus greps**. Do not silently mix venues mid-matrix.

---

## 6. Phase 1 — Wave 0 smoke (unscored)

One H trial and one V trial on
`realvuln-intentionally-vulnerable-python-application`, **through
`blind_prepare.py`**. Roots named `smoke-*`. [Adapter emits valid Semgrep
JSON; `score.py` returns a scorecard for both slugs; H stages all
`glm-5.3`; blinded digest unchanged; agent cwd is `target`; `ps`-visible
argv has no RealVuln slug.]

Do not put smoke files in the Wave 1 `run-N` slots.

---

## 7. Phase 2 — Wave 1 matrix (the experiment)

**Order (interleaved, sequential, one Z.AI key):**

```
# Control host only. Guest/agent never sees $slug in argv.
# run_*.sh takes an opaque job id; slug is read from operator/$OPAQUE.json
for slug in $(cat subset.txt); do
  for t in 1 2 3; do
    run_h.sh "$(issue_opaque "$slug" "$t")"    # wait
    run_v.sh "$(issue_opaque "$slug" "$t")"    # wait
  done
done
```

That is H1, V1, H2, V2, H3, V3 per slug, then the next slug. Completes
paired diffs early. Never overlap H and V.

After each trial, write Semgrep JSON into `scan-results/` and refuse
overwrite. After all 36, score:

```bash
cd /home/user/g/Real-Vuln-Benchmark
for slug in $(cat $CODESEC/bench/realvuln/subset.txt); do
  python3 score.py --repo "$slug" --runs \
    --scanner codesec-glm53-hunt \
    --scanner codesec-glm53-final \
    --scanner pi-glm53
done
```

`--runs` scores each `run-N.json` independently and prints mean ± stddev.

### 7.1 `run_h.sh` sketch

```bash
OPAQUE="$1"
MAP="$CODESEC/bench/realvuln-runs/operator/${OPAQUE}.json"   # not agent-readable
python3 blind_prepare.py --map "$MAP" --out "$RUN_ROOT"
TARGET="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["target"])' "$MAP")"
SLUG="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["slug"])' "$MAP")"
RECON=20; HOURS=2
[[ "$SLUG" == realvuln-pygoat ]] && { RECON=40; HOURS=3; }
codesec run --repo "$TARGET" --run-id "$OPAQUE" \
  --provider zai --model glm-5.3 --prior off \
  --max-concurrency 10 --max-recon-tasks "$RECON" \
  --max-hours "$HOURS" \
  --run-root "$RUN_ROOT"
# digest check on $TARGET
python3 adapt_to_semgrep.py --from-codesec "$RUN_ROOT" --map "$MAP" \
  --hunt-out  "$REALVULN/scan-results/$SLUG/codesec-glm53-hunt/run-${T}.json" \
  --final-out "$REALVULN/scan-results/$SLUG/codesec-glm53-final/run-${T}.json"
```

### 7.2 `run_v.sh` sketch

```bash
OPAQUE="$1"
MAP="$CODESEC/bench/realvuln-runs/operator/${OPAQUE}.json"
python3 blind_prepare.py --map "$MAP" --out "$RUN_ROOT"
TARGET="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["target"])' "$MAP")"
SLUG="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["slug"])' "$MAP")"
export PI_CODING_AGENT_DIR="$RUN_ROOT/pi-home"
mkdir -p "$PI_CODING_AGENT_DIR"
: "${ZAI_API_KEY:?}"
: "${THINKING:?}"   # Phase 0 lock, expected off
PROMPT="$(sed "s|__FINDINGS_PATH__|$RUN_ROOT/findings.json|g" \
  "$CODESEC/bench/realvuln/pi_audit_prompt.md")"
CAP=2700
[[ "$SLUG" == realvuln-pygoat ]] && CAP=5400
cd "$TARGET"
test "$(basename "$PWD")" = target
timeout --signal=TERM --kill-after=30s "$CAP" \
  pi -p \
    --provider zai --model glm-5.3 \
    --thinking "$THINKING" \
    --no-skills --no-extensions \
    --no-context-files --no-prompt-templates \
    --no-approve \
    --session-dir "$RUN_ROOT/pi-session" \
    -- \
    "$PROMPT"
# cwd was $TARGET — generic name, no slug, no .git, no README
python3 adapt_to_semgrep.py --from-pi "$RUN_ROOT/findings.json" \
  --map "$MAP" \
  --out "$REALVULN/scan-results/$SLUG/pi-glm53/run-${T}.json"
```

### 7.3 Frozen Pi prompt

`bench/realvuln/pi_audit_prompt.md` must:

- Ask for a security review of the working directory.
- Write **only** `__FINDINGS_PATH__`. Do not modify application source.
- Never name the product, benchmark, or a known vulnerable-app list.
- Require repo-relative paths, line ranges, and a CWE:

  ```json
  {
    "findings": [
      {
        "title": "…",
        "file": "app/views.py",
        "line_start": 42,
        "line_end": 48,
        "vuln_class": "sql_injection",
        "cwe": "CWE-89",
        "severity": "high",
        "description": "…"
      }
    ]
  }
  ```

- Omit anything that cannot be pinned to file + line + CWE.
- **Not** enumerate planted bugs, decoys, RealVuln, CWEs of interest, or
  codesec stages. Generic review instructions only.

Keep write/edit/bash enabled. The read-only copy is the mutation control.
Only denylist write/edit if Wave 0 shows Pi burning the budget patching
the app — document that before Wave 1.

### 7.4 Adapter (`adapt_to_semgrep.py`)

Emit Semgrep-compatible JSON (`version` + `results[]` with `path`,
`start.line`, `extra.metadata.cwe`). Normalize paths to repo-relative
POSIX (strip `$TARGET` prefix; no leading `./`). Drop and count rows
missing path, line, or `CWE-\d+`. **Strip canary hits** (file + line
within ±10 of the operator map) from this JSON; write `canary_hit` only
in `*.metrics.json`. Never read ground truth.

Invalidation: corpus digest change; any codesec stage not on `glm-5.3`;
Pi using global `~/.pi` or `:8000`; Pi writing into the scan copy;
missing/unparseable findings; zai rate-limit abort mid-stage; **slug or
`.git` visible in `$TARGET` or in the Pi/codesec command line**.
`identity_leak` in *output* (the model naming PyGoat) does **not**
invalidate — it is a cheat diagnostic. Re-run invalid trials at the
**end** of the sequence; never delete silently.

---

## 8. Metrics and decision (fixed before results)

Per slug, per arm, per trial, from `score.py`: F3 (primary), F2, precision,
recall, TP/FP/FN/TN, FPR, per-CWE-family recall, per-severity recall.

Headline estimand (one, frozen): **strict micro F3 on the 0–100
`f3_score` scale**, pooling TP/FP/FN/TN across the six Wave 1 slugs
**within each trial**, then mean ± range of those three trial F3s.
`score.py` is per-repo and has no `--json`; land
`bench/realvuln/aggregate.py` that imports RealVuln `scorer/` (do not
parse the human table). Equal-repo-mean F3 is a sensitivity table only.

Let `F3_H`, `F3_V` be those trial-mean micro F3s (0–100); `P_H`, `P_V`
micro precision (0–1); `R_H`, `R_V` micro recall (0–1).

- **Harness helps** if `F3_H ≥ F3_V + 5` (points on 0–100) **or**
  (`R_H ≥ R_V − 0.05` and `P_H ≥ P_V + 0.10`), **and** H has fewer FP
  than V on at least 4 of 6 slugs in at least 2 of 3 trials. Expected
  mechanism: Validate+Trace cuts FP at comparable recall.
- **Harness does not earn its keep on this corpus** if V matches or beats
  H on both F3 (within 5 points) and precision (within 0.05), or V is
  ahead on both. Stop; do not start Appendix A until the pipeline is
  changed or the claim is narrowed.
- **Inconclusive** if F3 ranges overlap across the three trials and FP
  counts do not separate. Report that; do not pick a winner.
- Do not declare Pi a product replacement. Do not claim a RealVuln
  leaderboard slot unless Wave 2 (all 26 Python community) is run under
  their published protocol. This comparison supports an engineering
  decision on this host and this model.

Secondary tables (not decision): hunt vs Pi (discovery), hunt vs final
(internal filter), per-slug F3, per-CWE-family, wall clock, tokens, adapter
drops, **famous vs obscure F3**, **canary hit rate**, **identity_leak
count**. If canary-miss + high famous recall is the dominant pattern,
do not treat a T1-style sweep as evidence the harness (or Pi) “understands”
the repo.

---

## 9. Cost

Both arms bill one GLM Coding Plan. Record input+output tokens per trial
(per stage for H). Report tokens, $-at-list-price if published, and
amortized $ per repo assuming N audits/month. Keep a running total so V
does not starve later H trials. State rate-limit hits.

Rough size: 36 API runs. V is one 45–90 min session; H is many short
stage calls and will dominate tokens. Do not overlap.

---

## 10. Risks

| Risk | Mitigation |
|---|---|
| `--provider zai` silently uses 5.2/4.7 | `--model glm-5.3`; Phase 0 grep; invalidate on mismatch |
| Local `:8000` flash hijacks Pi | isolated `PI_CODING_AGENT_DIR`; pin `--provider zai --model glm-5.3` |
| Thinking mismatch | Phase 0 dump; match or both off |
| Basename-only paths fail RealVuln file match | prompt requires repo-relative path; adapter strips `$TARGET` |
| Missing CWE → no TP | prompt + adapter drop-count; do not infer CWE from vuln_class via GT |
| GT leakage | GT stays in RealVuln checkout; work copy is blinded `target/` only |
| Trial identity leak (slug, README, `.git`) | `blind_prepare.py`; invalidate if `$TARGET` or argv still contains the slug |
| Training-data recall of famous DV apps | cannot fully stop; canary + famous/obscure split + identity_leak grep |
| Residual `pygoat` in Python package names | accepted in Wave 1; escalate to identifier rewrite only if leaks dominate |
| Canary shifts GT lines | append-only at end of file; Phase 0 checks line > max GT `end_line` |
| Pi patches the tree | read-only copy; Wave 0 watch |
| zai rate limits | sequential H/V; concurrency 10; re-run at end |
| pygoat 78 vulns / 20 recon cap | pygoat H uses 40 recon tasks; V 90 min |
| Unfinished slug counted as all-FN | strict micro; finish or invalidate |
| Memorized educational apps | Python community only; still Type 1; do not use Juice Shop |
| One host, three trials overinterpreted | ranges, no significance tests |

---

## 11. Run matrix

| # | What | Trials | Scored |
|---|---|---|---|
| 0 | Prep: clone RealVuln + 7 apps, auth, thinking lock | — | no |
| 1 | Wave 0 smoke, both arms | 1 each | no |
| 2 | Wave 1: 6 slugs × {H,V} × 3 | 36 | yes, `score.py --runs` |
| 3 | Analysis → `bench/RESULTS-HARNESS-GLM53-REALVULN-<date>.md` | — | — |
| 4 | Wave 2 remainder of 26 | only if §8 says so | yes |

Estimated wall-clock after Phase 0: **2–4 days** (API-bound; pygoat H is
the long pole).

---

## 12. Deliverables

1. `bench/RESULTS-HARNESS-GLM53-REALVULN-<date>.md` — tables per §8,
   decision per §8, RealVuln git SHA, subset list, thinking lock.
2. 36 scored Semgrep result files + metrics under
   `$REALVULN/scan-results/`, plus smoke roots kept separate.
3. Runners, `blind_prepare.py`, adapter, and `aggregate.py` in
   `bench/realvuln/`.
4. `subset.txt`, `subset-counts.json` (from pinned SHA), `famous.txt`,
   `obscure.txt`, and the Phase 0 pin record (RealVuln SHA, app SHAs, Pi
   version, codesec rev, resolved `{baseUrl, api}` per arm).
5. Per-trial `blind.json` (operator-only) and identity-leak/canary
   diagnostics in the results doc.

---

## Appendix A — deferred: local models vs Z.AI on the codesec pipeline

Not scheduled until §8 of this run is answered. Original mission: can a
fully-local duo (Titus discovery / OpenMythos validate) match codesec+Z.AI.

If this run concludes the harness does not earn its keep, **do not start
Appendix A** — fix or narrow the pipeline first.
