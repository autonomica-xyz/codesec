# Benchmark label gaps and matcher artifacts — disclosure (2026-09-24)

Source: the fixed FP review sample of plan step G
(`bench/realvuln/repair-evidence/relfix-2026-09-24/fp-review.md`,
classifications in `fp-classifications.json`). This note is about the
**benchmark's ground truth and matching semantics**, not the harness: the
harness was not taught to hide or suppress any of these findings, and no
scored result was altered. Every item below was verified against the exact
bundled source before being listed.

## A. Real issues with no matching label (scored as FP for the scanner)

| # | Repo | Location | Claim | Source evidence |
|---|---|---|---|---|
| 1 | DVFA | `app.py:14` | CWE-614 session-cookie hardening absent | No `SESSION_COOKIE_SECURE`/`SAMESITE`/`LIFETIME` anywhere in the app; plain-HTTP bind; the nearby hardcoded `secret_key` is labeled separately (`damn-vulnerable-flask-app-009`, CWE-798), so the cookie-flags gap is distinct |
| 2 | DVPWA | `sqli/views.py:40` | CWE-204 login timing oracle | `user.check_password` (md5, `sqli/dao/user.py:40-41`) runs only when the username exists — measurable user-enumeration oracle; distinct from the labeled brute-force (`dvpwa-017`) and weak-hash (`dvpwa-008`) entries |
| 3 | LBBG | `badguys/static/js/vendor/jquery.js:1` | CWE-1104 known-vulnerable components | jQuery 1.9.1 (selector-XSS CVE class) plus a 2010–2012 Zepto snapshot served on exercise pages; DVPWA's GT labels this class (`dvpwa-022`, CWE-1395), LBBG's does not |
| 4 | PIA | `app/main.py:31` | CWE-1088 blocking call in async handler | `requests.get(config.PUBLIC_IP_SERVICE_URL)` with no `timeout=` inside `async def` — event-loop starvation; distinct from the labeled SSRF at the same line (`python-insecure-app-004`) |
| 5 | PIA | `app/main.py:38` | CWE-400 unbounded template compile | Anonymous `name` parameter of unbounded size compiled by Jinja2 `Template()` per request — CPU-bound parsing; distinct from the labeled XSS at the same line (`…-002/-003`) |

Pi comparison sample (same class of gap):

| # | Repo | Location | Claim | Source evidence |
|---|---|---|---|---|
| 6 | DVPWA | `config/dev.yaml:1` | CWE-798 hardcoded DB credentials | `postgres/postgres` in the default committed config; the labeled config issue is the SECRET at `sqli/schema/config.py:12` (`dvpwa-016`) |
| 7 | VAmPI | `api_views/users.py:40` | CWE-204 registration enumeration | "User already exists. Please Log in." message; the labeled enumeration entry (`vampi-006`) covers a different function (`users.py:101`) |

Suggested dispositions (for benchmark maintainers, not for the harness):
either add labels for these seven, or add `non_scoring` entries so a
scanner reporting them is withheld (NS) rather than penalized (FP). The GT
machinery (`acceptable_cwes`, `acceptable_locations`, `scoring`) already
supports both.

## B. Matching-semantics artifacts observed in the same sample

For benchmark maintainers; full detail in `fp-review.md`:

- **CWE vocabulary vs `acceptable_cwes` (6 sampled claims):** scanners
  using a semantically adjacent CWE (862 vs 306; 209 vs 16; 837/306 vs 94;
  307 vs 287/304; 1336 vs 94/95; 565/287 vs 639/284) score as FP even when
  file/line match. Widening `acceptable_cwes` for these families (or
  family-level matching) would reduce this noise for any scanner.
- **±10-line window (3 sampled claims):** accepted CWE but the anchor is
  15–75 lines from the labeled line (DVFA `app.py:79` vs route blocks at
  111–185; LBBG `settings.py:99` vs 174; PIA `main.py:29` vs 14).
  `acceptable_locations` ranges already exist and could absorb these.
- **Wrong file (1 sampled claim):** VAmPI `/createdb` reported in the
  OpenAPI spec (`openapi3.yml:16`) rather than the handler
  (`api_views/main.py:6`, labeled `vampi-011`).

## What the harness did and did not do about this

The only harness change arising from the FP review is the narrow
evidence-keyed CWE canonicalization (three classes, replay: TP +4 / FP −4,
zero TP regressions; `RESULTS-RELIABILITY-FIXES-AND-FP-REVIEW-2026-09-24.md`
§6). No finding is suppressed, relocated, or re-CWE'd toward a label
beyond those three semantically-defensible classes. Per plan step H, real
unlabeled issues are disclosed here rather than hidden to improve the
score.
