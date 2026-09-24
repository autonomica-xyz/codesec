"""Step G.4: write the FP-review classification records (JSON + Markdown).

Classifications were made by reading the exact source lines, the ground
truth, the harness's committed report records, and the official match
reason for each of the 24 sampled H claims (28 occurrences) plus the 6
Pi comparison claims selected in fp-sample-manifest.json (seed 20260924,
manifest saved before source inspection).
"""
from __future__ import annotations

import json
from pathlib import Path

HERE = Path(__file__).resolve().parent

H = [
 # (repo_short, file, line, cwe, occ, category, rationale, implicated_stage, gt_refs)
 ("dvfa", "app.py", 14, "CWE-614", 1, "real_issue_outside_labels",
  "Source confirms: no SESSION_COOKIE_SECURE/SAMESITE/LIFETIME anywhere; secret_key hardcoded (labeled separately as -009 CWE-798); plain HTTP binding. Genuine insecure session-cookie configuration with no matching label.",
  "Hunt (benchmark label gap)", ["damn-vulnerable-flask-app-009 (different issue)"]),
 ("dvfa", "app.py", 79, "CWE-862", 2, "reporting_matching_error",
  "The missing-authorization issue on the playground routes IS labeled: GT CWE-306 at app.py:111/132/152/185. H reported CWE-862 at :79 (/dashboard, a link hub) — outside the 10-line window with a different CWE family, so the official matcher scored it unmatched.",
  "evidence-to-report mapping (CWE selection/localization)", ["…-012","…-013","…-014","…-015"]),
 ("dvfa", "app.py", 140, "CWE-209", 1, "duplicate",
  "`rp` is indeed undefined (only `popen` imported, line 4) so POST /lookup raises NameError; the exploitable impact is the debug traceback, which is already labeled (-011 CWE-215 app.py:208). Distinct trigger, same principal, no distinct vulnerability.",
  "Hunt (novel trigger of a labeled weakness)", ["…-011","…-004 (XSS same line)"]),
 ("dvfa", "test.db", 1, "CWE-256", 1, "duplicate",
  "The shipped sqlite file contains cleartext users because registration stores unhashed passwords — labeled at the sink (-010 CWE-256 app.py:62). The artifact claim restates the labeled issue at a derived file.",
  "Hunt (artifact-level restatement)", ["…-010"]),
 ("dvpwa", "sqli/app.py", 23, "CWE-209", 2, "reporting_matching_error",
  "debug=True is labeled as misconfiguration: GT -015 CWE-16 sqli/app.py:24 — one line away. H reported CWE-209 at :23; CWE-family + window mismatch made it unmatched.",
  "evidence-to-report mapping (CWE selection)", ["dvpwa-015","dvpwa-011"]),
 ("dvpwa", "sqli/views.py", 40, "CWE-204", 1, "real_issue_outside_labels",
  "Source-backed timing oracle: md5 check runs only when the username exists (dao/user.py:40-41 short-circuit at views.py:41). Distinct from the labeled brute-force (-017 CWE-307 views.py:33) and weak-hash (-008) entries; no enumeration label for DVPWA.",
  "Hunt (benchmark label gap)", ["dvpwa-017","dvpwa-008"]),
 ("dvpwa", "sqli/views.py", 54, "CWE-754", 1, "duplicate",
  "The KeyError-on-missing-field behavior is real, but the route's security issue (anonymous POST) is labeled at the exact line (-012 CWE-862) and the only security consequence of the 500 (traceback) is the labeled debug misconfig (-015). No distinct principal.",
  "Hunt (robustness restatement)", ["dvpwa-012","dvpwa-015"]),
 ("dvpwa", "sqli/views.py", 86, "CWE-20", 1, "incorrect_security_claim",
  "COURSE_SCHEMA is not wired into any route, so no enforceable control is bypassed; Course.create uses parameterized SQL (dao/course.py, %s placeholders). Claimed 'validation bypass' impact is unsupported by any downstream unsafe use.",
  "Validate (should have rejected unsupported impact)", ["dvpwa-013 (same line, auth)"]),
 ("lbbg", "badguys/settings.py", 99, "CWE-614", 1, "reporting_matching_error",
  "Session-cookie security IS labeled: GT -024 CWE-614 settings.py:174 (same settings module, 75 lines away). H located the claim on MIDDLEWARE_CLASSES (:99) — window miss.",
  "evidence-to-report mapping (localization)", ["lets-be-bad-guys-024"]),
 ("lbbg", "badguys/static/js/vendor/jquery.js", 1, "CWE-1104", 1, "real_issue_outside_labels",
  "jQuery 1.9.1 (known selector/XSS CVE-2012-6708 class) plus a 2010-2012 Zepto snapshot are served on the exercise pages; no vulnerable-component label exists for LBBG (DVPWA has one, this repo does not).",
  "Hunt (benchmark label gap)", []),
 ("lbbg", "badguys/vulnerable/views.py", 39, "CWE-754", 1, "duplicate",
  "TypeError when `p` is absent is real, but the function's traversal issue is labeled at :42 (-001 CWE-22) and DEBUG=True traceback disclosure at settings.py:10 (-012 CWE-215) carries the only security impact of the 500.",
  "Hunt (robustness restatement)", ["lets-be-bad-guys-001","lets-be-bad-guys-012"]),
 ("lbbg", "badguys/vulnerable/views.py", 181, "CWE-837", 1, "reporting_matching_error",
  "The globals().get(fwd) dispatch is labeled code execution: GT -009 CWE-94 views.py:183, two lines away. H emitted CWE-837 — family mismatch → unmatched.",
  "evidence-to-report mapping (CWE selection)", ["lets-be-bad-guys-009"]),
 ("pygoat", "introduction/views.py", 493, "CWE-307", 1, "reporting_matching_error",
  "The OTP lab weakness is labeled: GT -010 CWE-287 views.py:496 (3-digit code, 3 lines away; GT also carries a vuln=True CSRF entry at the same line 493). H's CWE-307 at :493 missed on CWE family.",
  "evidence-to-report mapping (CWE selection)", ["pygoat-010","pygoat-fp-022"]),
 ("pygoat", "introduction/views.py", 583, "CWE-1336", 1, "reporting_matching_error",
  "ImageMath.eval SSTI is labeled: GT -019 CWE-94 views.py:588 (the eval call, 5 lines away). H's CWE-1336 at :583 missed on CWE family.",
  "evidence-to-report mapping (CWE selection)", ["pygoat-019"]),
 ("pygoat", "introduction/views.py", 789, "CWE-565", 1, "reporting_matching_error",
  "The User-Agent-trust lab is labeled: GT -013 CWE-639 views.py:797 (same function, 8 lines away — inside the window, different CWE family).",
  "evidence-to-report mapping (CWE selection)", ["pygoat-013"]),
 ("pygoat", "introduction/views.py", 1055, "CWE-287", 1, "reporting_matching_error",
  "The unsigned-cookie admin lab is labeled: GT -031 CWE-639 views.py:1060 (same function, 5 lines away). CWE family mismatch → unmatched.",
  "evidence-to-report mapping (CWE selection)", ["pygoat-031"]),
 ("pia", "app/main.py", 29, "CWE-209", 1, "reporting_matching_error",
  "Debug traceback exposure is labeled: GT -006 CWE-200 app/main.py:14 (DEBUG=True, 15 lines away — just outside the window) plus the shipped .env_temp. Same underlying issue, different location + CWE.",
  "evidence-to-report mapping (localization)", ["python-insecure-app-006"]),
 ("pia", "app/main.py", 31, "CWE-1088", 1, "real_issue_outside_labels",
  "Source confirms requests.get(config.PUBLIC_IP_SERVICE_URL) with no timeout= inside an async def handler — blocking event-loop starvation; distinct from the labeled SSRF at the same line (-004 CWE-918).",
  "Hunt (distinct weakness, no label)", ["python-insecure-app-004"]),
 ("pia", "app/main.py", 38, "CWE-400", 1, "real_issue_outside_labels",
  "Unbounded `name` compiled by Jinja2 Template() synchronously per request — CPU-bound parse of attacker-sized input; the labeled entries at the same line are XSS (-002/-003), a different weakness.",
  "Hunt (distinct weakness, no label)", ["python-insecure-app-002","…-003"]),
 ("pia", "caddy/Caddyfile", 13, "CWE-288", 1, "duplicate",
  "SecRuleEngine Off is labeled (-007 CWE-16 Caddyfile:13) AND H itself scored the same underlying issue as a TP at Caddyfile:17 with CWE-693 in the same run — this CWE-288 claim restates it with no distinct path or principal.",
  "Dedupe (cross-CWE restatement not merged)", ["python-insecure-app-007"]),
 ("vampi", "api_views/books.py", 30, "CWE-248", 2, "incorrect_security_claim",
  "The cross-user unique-constraint IntegrityError is real behavior, but its standalone consequence is an unhandled 500 error page; no traceback disclosure path is configured/demonstrated in VAmPI and no data exposure or availability impact beyond a per-request error. Security impact unsupported.",
  "Validate (should have rejected unsupported impact)", []),
 ("vampi", "api_views/users.py", 52, "CWE-20", 1, "incorrect_security_claim",
  "Validation IS applied (jsonschema.validate at :59) before any write; the claimed pre-validation AttributeError only yields a generic 500 for a malformed body. No control is bypassed and no unsafe sink is reached.",
  "Validate (should have rejected unsupported impact)", ["vampi-004 (mass assignment, same function)"]),
 ("vampi", "api_views/users.py", 52, "CWE-367", 1, "incorrect_security_claim",
  "The register TOCTOU race is real as behavior, but the only caught-exception path is ValidationError; a racy duplicate ends in an unhandled 500 with no integrity, auth, or disclosure consequence. Impact unsupported.",
  "Validate (should have rejected unsupported impact)", []),
 ("vampi", "openapi_specs/openapi3.yml", 16, "CWE-306", 2, "reporting_matching_error",
  "Unauthenticated /createdb is labeled: GT -011 CWE-306 api_views/main.py:6 (the populate_db handler). H reported the same issue at the OpenAPI SPEC file (openapi3.yml:16) — different file, so the matcher could never associate it.",
  "evidence-to-report mapping (file selection)", ["vampi-011"]),
]

PI = [
 ("dvfa", "app.py", 2, "CWE-502", "reporting_matching_error",
  "Pi located the pickle deserialization claim at the IMPORT line (app.py:2) instead of the sink (~:111-120, labeled -001 CWE-94 app.py:120 / matched by H at :111). Import-line reporting cannot match.",
  "pi localization"),
 ("dvpwa", "config/dev.yaml", 1, "CWE-798", "real_issue_outside_labels",
  "Hardcoded postgres credentials in the default config; the labeled config issue is the SECRET at sqli/schema/config.py:12 (-016). Distinct unlabeled issue.", "pi"),
 ("lbbg", "badguys/settings.py", 10, "CWE-489", "reporting_matching_error",
  "DEBUG=True is labeled at the exact line as CWE-215 (-012); Pi emitted CWE-489 — family mismatch.", "pi CWE selection"),
 ("pygoat", "introduction/apis.py", 104, "CWE-73", "reporting_matching_error",
  "The A6 file-write lab is labeled at apis.py:131 (-036 CWE-73); Pi reported the function start (:104), 27 lines away.", "pi localization"),
 ("pia", "app/main.py", 13, "CWE-489", "reporting_matching_error",
  "Debug-enabled claim vs labeled -006 CWE-200 app/main.py:14 — one line away, different CWE family.", "pi CWE selection"),
 ("vampi", "api_views/users.py", 40, "CWE-204", "real_issue_outside_labels",
  "Register endpoint's 'User already exists' message is a real enumeration oracle; the labeled enumeration entry (-006 CWE-204) is at users.py:101 (different function). Marginal but source-backed.", "pi"),
]

REPO_FULL = {
 "dvfa": "realvuln-damn-vulnerable-flask-application",
 "dvpwa": "realvuln-dvpwa",
 "lbbg": "realvuln-lets-be-bad-guys",
 "pygoat": "realvuln-pygoat",
 "pia": "realvuln-python-insecure-app",
 "vampi": "realvuln-vampi",
}

def build():
    manifest = json.loads((HERE / "fp-sample-manifest.json").read_text())
    h_records = []
    for (repo, file, line, cwe, occ, cat, rationale, stage, gt) in H:
        key = REPO_FULL[repo]
        claim = next(c for c in manifest["selection"][key]
                     if c["file"] == file and c["line"] == line and c["cwe"] == cwe)
        h_records.append({
            "repo": key, "file": file, "line": line, "cwe": cwe,
            "occurrences_in_sample": occ,
            "finding_ids": claim["finding_ids"], "trials": claim["trials"],
            "official_match_reason": claim["match_reasons"],
            "category": cat, "rationale": rationale,
            "implicated_stage": stage, "gt_references": gt,
        })
    pi_records = [{
        "repo": REPO_FULL[repo], "file": file, "line": line, "cwe": cwe,
        "category": cat, "rationale": rationale, "implicated_stage": stage,
    } for (repo, file, line, cwe, cat, rationale, stage) in PI]

    counts = {}
    for r in h_records:
        counts[r["category"]] = counts.get(r["category"], 0) + 1
    occ_counts = {}
    for r in h_records:
        occ_counts[r["category"]] = occ_counts.get(
            r["category"], 0) + r["occurrences_in_sample"]
    doc = {
        "step": "G", "seed": 20260924,
        "sample": {"h_unique_claims": len(h_records),
                    "h_occurrences": sum(r["occurrences_in_sample"] for r in h_records),
                    "h_total_unique_claims_in_matrix": manifest["h_unique_claims_total"],
                    "h_total_fp_occurrences_in_matrix": manifest["h_fp_occurrences_total"],
                    "pi_comparison_claims": len(pi_records)},
        "category_counts_unique_claims": counts,
        "category_counts_sampled_occurrences": occ_counts,
        "h_classifications": h_records,
        "pi_classifications": pi_records,
        "limitations": (
            "Stratified development sample only: up to 4 deduplicated H FP "
            "claims per repo (24 of 198 unique claims; 28 of 218 occurrences) "
            "plus one Pi FP per repo, chosen with seed 20260924 before source "
            "inspection. NOT a full-matrix precision estimate and NOT an "
            "official-score adjudication: unmatched benchmark predictions are "
            "not automatically disproven vulnerabilities, and this review "
            "changes no scored result."),
    }
    (HERE / "fp-classifications.json").write_text(json.dumps(doc, indent=1))
    return doc, manifest

if __name__ == "__main__":
    doc, _ = build()
    print(json.dumps(doc["category_counts_unique_claims"], indent=1))
    print(json.dumps(doc["category_counts_sampled_occurrences"], indent=1))
