"""Deterministic canary markers for live-target verification (VVAH design).

When a run has a ``live_target``, the trace stage mints a per-finding canary
so the tracer can prove reachability with a real oracle instead of "a
response came back": embed the marker through the matching entry point,
then look for the *exact* marker (not a substring, not a similar string) in
the response.

Markers are deterministic functions of finding identity so they are stable
across retries and resumable runs:

    tok = sha1(f"{file}:{line_start}:{title}")[:8]

Kinds:

    generic        ``ev<tok>``              — any reflective input
    xss            ``<evx<tok>>``           — HTML/JS reflection
    ssti           ``a * b`` -> ``a*b``     — server-side evaluation
    redirect_host  ``evredir-<tok>.invalid``— open-redirect Location target

``markers_for(finding)`` returns only the kinds applicable to the finding's
vuln_class/cwe, plus ``generic`` which always applies.
"""

from __future__ import annotations

import hashlib

_TOKEN_LEN = 8

# vuln_class substrings (lowercased) -> marker kinds. Kept deliberately
# narrow: a marker only helps when the class can plausibly echo it.
_XSS_CLASSES = ("xss", "cross_site", "cross-site", "html_injection", "html-injection")
_XSS_CWES = {"CWE-79", "CWE-80"}
_SSTI_CLASSES = (
    "ssti",
    "template",
    "code_injection",
    "code-injection",
    "eval",
    "expression_injection",
    "expression-injection",
)
_SSTI_CWES = {"CWE-94", "CWE-1336"}
_REDIRECT_CLASSES = ("redirect",)
_REDIRECT_CWES = {"CWE-601"}


def marker_token(finding: dict) -> str:
    """Stable 8-char token derived from finding identity."""
    file = str(finding.get("file") or "")
    line = finding.get("line_start") or 0
    title = str(finding.get("title") or finding.get("description") or "")
    digest = hashlib.sha1(f"{file}:{line}:{title}".encode("utf-8")).hexdigest()
    return digest[:_TOKEN_LEN]


def _ssti_pair(tok: str) -> tuple[int, int]:
    """Two small factors derived from the token; product is the canary."""
    a = int(tok[:4], 16) % 90 + 10
    b = int(tok[4:], 16) % 90 + 10
    return a, b


def markers_for(finding: dict) -> dict:
    """Return the canary markers applicable to this finding.

    Shape::

        {
          "finding_id": "f_...",
          "token": "<tok>",
          "markers": {
            "generic": {"kind": "generic", "send": "ev<tok>",
                        "expect": "ev<tok>", "where": "response body"},
            "xss": {...},            # only for xss-ish classes
            "ssti": {...},           # only for template/eval-ish classes
            "redirect_host": {...},  # only for open-redirect classes
          }
        }
    """
    tok = marker_token(finding)
    vuln_class = str(finding.get("vuln_class") or "").lower()
    cwe = str(finding.get("cwe") or "").upper()

    markers: dict[str, dict] = {
        "generic": {
            "kind": "generic",
            "send": f"ev{tok}",
            "expect": f"ev{tok}",
            "where": "response body",
        }
    }
    if any(k in vuln_class for k in _XSS_CLASSES) or cwe in _XSS_CWES:
        markers["xss"] = {
            "kind": "xss",
            "send": f"<evx{tok}>",
            "expect": f"<evx{tok}>",
            "where": "response body",
        }
    if any(k in vuln_class for k in _SSTI_CLASSES) or cwe in _SSTI_CWES:
        a, b = _ssti_pair(tok)
        markers["ssti"] = {
            "kind": "ssti",
            "a": a,
            "b": b,
            "send": f"{a}*{b}",
            "expect": str(a * b),
            "where": "response body",
        }
    if any(k in vuln_class for k in _REDIRECT_CLASSES) or cwe in _REDIRECT_CWES:
        host = f"evredir-{tok}.invalid"
        markers["redirect_host"] = {
            "kind": "redirect_host",
            "send": f"http://{host}/",
            "expect": host,
            "where": "Location response header",
        }
    return {
        "finding_id": finding.get("finding_id"),
        "token": tok,
        "markers": markers,
    }
