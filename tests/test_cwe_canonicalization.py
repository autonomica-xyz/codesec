"""Step H: evidence-to-report CWE canonicalization tests (narrow, keyed on
the finding's own evidence; developed from the FP-review dev half)."""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from codesec.stages.report import _canonical_cwe


def mk(cwe, vuln_class, description="", evidence=""):
    return SimpleNamespace(
        vuln_class=vuln_class, description=description, evidence=evidence,
        raw_json={"cwe": cwe} if cwe else {},
    )


def test_ssti_via_eval_engine_maps_to_code_injection():
    f = mk("CWE-1336", "ssti",
           "PIL.ImageMath.eval() with attacker function field",
           "output = ImageMath.eval(function_str, ...)")
    assert _canonical_cwe(f) == "CWE-94"


def test_otp_low_entropy_auth_factor_maps_to_improper_authentication():
    f = mk("CWE-307", "logic_chain",
           "3-digit OTP rendered in the response enables brute force",
           "otpN=randint(100,999)")
    assert _canonical_cwe(f) == "CWE-287"


def test_debug_config_statement_maps_to_misconfiguration():
    f = mk("CWE-209", "insecure_configuration",
           "app constructed with debug=True returns tracebacks",
           "app = Application(debug=True, ...)")
    assert _canonical_cwe(f) == "CWE-16"


def test_rate_limit_stays_307():
    f = mk("CWE-307", "auth_bypass", "no rate limiting on login", "")
    assert _canonical_cwe(f) is None


def test_error_template_disclosure_stays_209():
    f = mk("CWE-209", "information_disclosure",
           "error template renders the traceback", "{{ traceback|safe }}")
    assert _canonical_cwe(f) is None


def test_pickle_deserialization_control_untouched():
    f = mk("CWE-502", "deserialization",
           "unsafe pickle.loads of uploaded file", "pickle.loads(data)")
    assert _canonical_cwe(f) is None


def test_xss_and_others_untouched():
    for cwe, vc in (("CWE-79", "xss"), ("CWE-89", "sqli"),
                    ("CWE-862", "auth_bypass"), ("CWE-287", "auth_bypass")):
        assert _canonical_cwe(mk(cwe, vc, "anything", "")) is None


def test_missing_evidence_or_cwe_is_none():
    assert _canonical_cwe(mk("", "ssti")) is None
    assert _canonical_cwe(mk(None, "ssti")) is None


def test_ssti_without_eval_evidence_stays_1336():
    f = mk("CWE-1336", "ssti", "template reflection without code eval", "")
    assert _canonical_cwe(f) is None
