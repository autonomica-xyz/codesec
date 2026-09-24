from __future__ import annotations

import json
from pathlib import Path

from bench.realvuln.adapt_to_semgrep import from_pi, _filter, _semgrep_result
from bench.realvuln.blind_prepare import cmd_allocate, cmd_prepare
from bench.realvuln.common import extract_json_object, f3_score, normalize_relpath


ROOT = Path(__file__).resolve().parents[1]


def test_f3_score_scale_is_zero_to_one_hundred():
    assert f3_score(1.0, 1.0) == 100.0
    assert f3_score(0.5, 1.0) == round((10 * 0.5 * 1.0 / (9 * 0.5 + 1.0)) * 100, 1)


def test_extract_json_object_accepts_fence_or_bare():
    bare = extract_json_object('{"findings": []}')
    fenced = extract_json_object('```json\n{"findings": [{"file": "a.py"}]}\n```')
    assert bare == {"findings": []}
    assert fenced["findings"][0]["file"] == "a.py"


def test_extract_json_object_repairs_illegal_backslash_w():
    raw = '{"findings":[{"description":"regex ([0-9a-zA-Z]([-\\.\\w]*[0-9a-zA-Z])*)+"}]}'
    payload = extract_json_object(raw)
    assert r"\w" in payload["findings"][0]["description"]


def test_normalize_relpath_strips_target_prefix(tmp_path: Path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("x\n")
    assert normalize_relpath(str(target / "app.py"), target) == "app.py"
    assert normalize_relpath("../etc/passwd", target) is None


def test_semgrep_result_requires_path_line_and_cwe():
    ok = _semgrep_result(
        {
            "file": "app.py",
            "line_start": 3,
            "line_end": 4,
            "cwe": "CWE-89",
            "description": "sql",
        },
        None,
    )
    assert ok["path"] == "app.py"
    assert ok["start"]["line"] == 3
    assert ok["extra"]["metadata"]["cwe"] == ["CWE-89"]
    assert _semgrep_result({"file": "app.py", "line_start": 1}, None) is None


def test_canary_is_stripped_not_scored():
    results = [
        {
            "path": "app.py",
            "start": {"line": 40},
            "extra": {"metadata": {"cwe": ["CWE-95"]}},
        }
    ]
    kept, dropped, hit = _filter(results, {"file": "app.py", "line": 40, "line_end": 41})
    assert hit is True
    assert kept == []
    assert dropped[0]["reason"] == "canary"


def test_from_pi_drops_incomplete_rows(tmp_path: Path):
    findings = tmp_path / "findings.json"
    findings.write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "file": "app.py",
                        "line_start": 2,
                        "line_end": 2,
                        "cwe": "CWE-78",
                        "description": "command injection here",
                    },
                    {"file": "app.py", "description": "no line or cwe"},
                ]
            }
        )
    )
    kept, dropped = from_pi(findings, None)
    assert len(kept) == 1
    assert len(dropped) == 1


def test_blind_prepare_strips_readme_keeps_gt_file_and_appends_canary(tmp_path: Path):
    source = tmp_path / "src"
    source.mkdir()
    (source / "README.md").write_text("# PyGoat\nintentionally vulnerable\n")
    (source / "app.py").write_text("def ping():\n    return 1\n")
    gt = {
        "commit_sha": "abc",
        "findings": [
            {
                "file": "app.py",
                "is_vulnerable": True,
                "location": {"start_line": 1, "end_line": 2},
            }
        ],
    }
    gt_path = tmp_path / "gt.json"
    gt_path.write_text(json.dumps(gt))
    map_path = tmp_path / "op.json"
    ns = type("NS", (), {})()
    ns.slug = "realvuln-pygoat"
    ns.trial = 1
    ns.arm = "h"
    ns.opaque = "abcd1234"
    ns.map = str(map_path)
    ns.commit_sha = "abc"
    ns.realvuln = str(tmp_path)
    ns.force = True
    cmd_allocate(ns)

    work = tmp_path / "workparent"
    prep = type("NS", (), {})()
    prep.map = str(map_path)
    prep.source = str(source)
    prep.gt = str(gt_path)
    prep.realvuln = str(tmp_path)
    prep.work_parent = str(work)
    prep.skip_root = True
    cmd_prepare(prep)

    target = work / "target"
    assert not (target / "README.md").exists()
    assert (target / "app.py").is_file()
    text = (target / "app.py").read_text()
    assert "session_cookie_materialize_" in text
    payload = json.loads(map_path.read_text())
    assert payload["canary"]["line"] > 12
    assert payload["digest"]


def test_run_scripts_do_not_pkill_dash_f():
    for relative in (
        "bench/realvuln/run_h.sh",
        "bench/realvuln/run_v.sh",
        "bench/realvuln/run_matrix.sh",
    ):
        text = (ROOT / relative).read_text()
        assert "pkill -f" not in text
        assert "set -euo pipefail" in text
    v = (ROOT / "bench/realvuln/run_v.sh").read_text()
    assert 'cd "$TARGET"' in v
    matrix = (ROOT / "bench/realvuln/run_matrix.sh").read_text()
    assert "[matrix] FAIL" in matrix
    assert "retrying failed trials once" in matrix
    h = (ROOT / "bench/realvuln/run_h.sh").read_text()
    assert "--prior off" in h
    assert "--model" in h
    assert "--engine local" in h
    assert 'tee "$RUN_ROOT/codesec.log"' not in h
    common = (ROOT / "bench/realvuln/run_common.sh").read_text()
    assert "SCANNER_TAG" in common
