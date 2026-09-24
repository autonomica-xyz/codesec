# False-positive review — fixed stratified sample (2026-09-24)

Plan step G of `PLAN-RELIABILITY-FIXES-AND-FP-REVIEW-2026-09-24.md`.
Selection manifest (`fp-sample-manifest.json`) was written and hashed
BEFORE any source inspection. Data: `fp-classifications.json`.

## Sample

From the saved matrix `matrix-20260923-01` H arm's official scored FPs:
218 FP occurrences → 198 unique (repo, arm, file, line, CWE) claims.
Deduplicated, sorted by repo/trial/finding ID, seed `20260924`, up to four
claims per repo: **24 unique H claims (28 sampled occurrences, 0
undersupply)** plus one Pi FP per repo (6 comparison claims).

**Limitations:** this is a stratified development sample — 24 of 198
unique claims. It does not estimate a new full-matrix precision, does not
alter the official score, and unmatched benchmark predictions are not
automatically disproven vulnerabilities.

## H classifications (24 unique claims / 28 occurrences)

| Category | Unique claims | Sampled occurrences |
|---|---:|---:|
| Reporting/matching error | 10 | 13 |
| Real issue outside labels | 5 | 5 |
| Duplicate | 5 | 5 |
| Incorrect security claim | 4 | 5 |
| Unresolved | 0 | 0 |

### Reporting/matching error (dominant) — 10 claims

Decomposed against the official matcher (file + line ± 10 + `acceptable_cwes`):

- **CWE not in the GT entry's `acceptable_cwes` (6):** CWE-209 vs
  {16,489} (DVPWA debug config, `sqli/app.py:23`, GT dvpwa-015 at :24);
  CWE-837 vs {94,470,306} (LBBG `globals().get(fwd)` dispatch,
  `views.py:181`, GT lbbg-009 at :183); CWE-307 vs {287,304,798} (PyGoat
  OTP lab, `views.py:493`, GT pygoat-010 at :496); CWE-1336 vs {94,95}
  (PyGoat ImageMath.eval SSTI, `views.py:583`, GT pygoat-019 at :588);
  CWE-565 vs {639,284,285,862} (PyGoat User-Agent trust, `views.py:789`,
  GT pygoat-013 at :797); CWE-287 vs {639,284,565} (PyGoat cookie trust,
  `views.py:1055`, GT pygoat-031 at :1060).
- **Location just outside the ±10 window with an accepted CWE (3):**
  DVFA `/dashboard` no-auth (CWE-862 accepted; `app.py:79` vs GT
  CWE-306 blocks at 111/132/152/185); LBBG session-cookie flags (CWE-614
  accepted; `settings.py:99` vs GT lbbg-024 at :174); PIA debug traceback
  (CWE-209 accepted; `main.py:29` vs GT pia-006 at :14, 15 lines).
- **Wrong file (1):** VAmPI unauth `/createdb` reported in
  `openapi_specs/openapi3.yml:16` (CWE-306 accepted) instead of the
  handler `api_views/main.py:6` (GT vampi-011).

Implicated stage: the evidence-to-report mapping (CWE selection and
localization) — not Validate, which confirmed plausible claims, and not a
verifier prompt problem.

### Real issues outside labels — 5 claims

DVFA missing session-cookie hardening (CWE-614, `app.py:14`); DVPWA
login timing oracle (CWE-204, `views.py:40`); LBBG jQuery 1.9.1/Zepto
served unauthenticated (CWE-1104); PIA blocking `requests.get` without
timeout in an async handler (CWE-1088, `main.py:31`); PIA unbounded
Jinja2 compile DoS (CWE-400, `main.py:38`, distinct from the labeled XSS
at the same line). These are benchmark label gaps, disclosed as such —
not harness defects.

### Duplicates — 5 claims

DVFA `rp`-undefined NameError (impact = the labeled debug disclosure
-011); DVFA shipped `test.db` cleartext (artifact of labeled -010);
DVPWA `/students` KeyError (same route as labeled -012; impact via
labeled debug -015); LBBG `user_pic` TypeError (same function as labeled
-001, impact via labeled DEBUG -012); PIA `SecRuleEngine Off` restated as
CWE-288 while H itself scored the same issue as a TP (CWE-693,
`Caddyfile:17`) in the same run — the one claim implicating the **Dedupe**
rule (cross-CWE restatement not merged).

### Incorrect security claims — 4 claims

DVPWA `/courses` "validation bypass" (COURSE_SCHEMA is not wired into any
route, DAO parameterized — no control bypassed); VAmPI cross-user
IntegrityError (standalone impact is a 500 page); VAmPI pre-validation
`AttributeError` (validation IS applied at :59); VAmPI registration TOCTOU
(worst case an unhandled 500). Validate let impact-unsupported claims
through in these marginal classes.

## Pi comparison sample (6 claims)

Same failure mode dominates: import-line localization (DVFA pickle at
`app.py:2` vs sink ~:111), CWE-family mismatch on exact-line DEBUG=True
(CWE-489 vs labeled {215}), function-start localization (PyGoat
`apis.py:104` vs labeled :131), plus 2 real issues outside labels
(DVPWA dev.yaml postgres creds; VAmPI register enumeration message) and
1 near-labeled enumeration (VAmPI `users.py:40` vs labeled :101). Pi's
unmatched FPs are qualitatively similar — the benchmark scores
unmatched-but-real claims as FPs for both arms.

## Outcome feeding step H

Dominant actionable cause: **location/CWE reporting errors** (10/24). Per
the plan's H options this maps to "correct the existing evidence-to-report
mapping; never select coordinates/CWEs using GT during execution". See
`h-split.json` (seeded dev/diagnostic halves) and `h-replay.json`
(offline deterministic replay: TP +4, FP −4, zero TP regressions,
reserved half untouched — uncertainty reported, no further tuning).
