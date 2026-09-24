"""Post-repair reverification of the 2026-09-24 review defects.

Same probes as review-2026-09-24/reproduce.py, updated for the repaired
APIs (WorkDeadline instead of deadline_ts). Disposable copies only; the
saved matrix is never modified.
"""
from __future__ import annotations

import contextlib
import io
import json
import shutil
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from bench.realvuln import experiment as ex, executor
from bench.realvuln.aggregate import aggregate_experiment
from bench.realvuln.ledger import AttemptLedger
from bench.realvuln.snapshot import WorkDeadline

root = Path(__file__).resolve().parents[4]
exp = root / 'bench/realvuln-runs/experiments/matrix-20260923-01'
manifest = ex.load_manifest(exp)
results = {}

with tempfile.TemporaryDirectory(prefix='codesec-relfix-') as temp:
    tmp = Path(temp)

    def copied(name):
        dest = tmp / name
        (dest / 'operator').mkdir(parents=True)
        for filename in ('manifest.json', 'manifest.sha256', 'attempts.jsonl',
                         'schedule.json'):
            shutil.copy2(exp / 'operator' / filename, dest / 'operator' / filename)
        shutil.copytree(exp / 'committed', dest / 'committed')
        return dest

    def summarize(dest):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stdout):
            code = ex.cmd_verify(SimpleNamespace(experiment=str(dest)))
        agg = aggregate_experiment(dest)
        return {'verify_exit': code, 'verify_message': stdout.getvalue().strip(),
                'headline_present': agg['headline'] is not None,
                'problems': agg['problems']}

    # 1: late invalidation after a completed cell
    dest = copied('late-invalidation')
    cell = manifest['expected_cells'][0]
    ledger = AttemptLedger(dest / 'operator/attempts.jsonl',
                           experiment_id=manifest['experiment_id'],
                           config_hash=manifest['manifest_sha256'])
    ledger.append({'type': 'attempt_end', 'cell_id': cell['cell_id'],
                   'attempt_id': 'review-invalidation', 'status': 'invalidated',
                   'made_inference_requests': False,
                   'reason_code': 'review_simulated_protocol_breach'})
    results['late_invalidation'] = summarize(dest)

    # 2: corrupt committed artifact of the failed-output DVPWA cell
    dest = copied('corrupt-failed-output')
    failed_cell = dest / 'committed/358d16220e1b1dda'
    marker = json.loads((failed_cell / 'completion.json').read_text())
    (failed_cell / marker['primary_path']).write_text('{')
    results['corrupt_committed_failed_output'] = summarize(dest)

    # 3: wrong marker repo/cell identity
    dest = copied('wrong-repo')
    marker_path = dest / 'committed' / cell['cell_id'] / 'completion.json'
    marker = json.loads(marker_path.read_text())
    marker['repo'] = 'WRONG-REPO'
    marker['cell_id'] = 'WRONG-CELL'
    marker_path.write_text(json.dumps(marker))
    results['wrong_marker_identity'] = summarize(dest)

    # 4: post-deadline findings are not eligible for either arm
    target = tmp / 'target'
    target.mkdir()
    (target / 'app.py').write_text('x = 1\n')
    finding = {'file': 'app.py', 'line_start': 1, 'line_end': 1,
               'cwe': 'CWE-89', 'severity': 'high', 'description': 'test'}
    results['post_deadline_output'] = {}
    for arm in ('h', 'v'):
        output = tmp / f'late-{arm}'
        output.mkdir()
        path = (output / 'run/results/report/report.json'
                if arm == 'h' else output / 'findings.json')
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({'findings': [finding]}))
        deadline = WorkDeadline(total_seconds=60.0)
        deadline._expire_for_test()  # cutoff 60s in the past, monotonic
        try:
            result = executor.export_arm_outputs(
                exp=exp, manifest=manifest, cell={'arm': arm}, attempt_id='review',
                output_dir=output, target_dir=target, deadline=deadline)
            exported = json.loads(result['files']['primary'].read_text())
            results['post_deadline_output'][arm] = {
                'rejected': False, 'exported_count': len(exported['results'])}
        except Exception as error:  # noqa: BLE001 — rejection is the fix
            results['post_deadline_output'][arm] = {
                'rejected': True, 'error': type(error).__name__}

    # 5: freeze without real gate evidence
    spec = json.loads((root / 'bench/realvuln/protocol-v5.json').read_text())
    spec['isolation_evidence_sha256'] = '0' * 64
    spec_path = tmp / 'spec.json'
    spec_path.write_text(json.dumps(spec))
    freeze_result = {'exit_code': None}
    with patch('bench.realvuln.isolation.verify_pin', return_value={}), \
         patch('bench.realvuln.isolation.resolve_image_id',
               return_value=spec['image']['image_id']), \
         patch.object(ex, '_image_profile_endpoints',
                      return_value={spec['settings']['gateway_url']}), \
         contextlib.redirect_stdout(io.StringIO()):
        try:
            freeze_result['exit_code'] = ex.cmd_freeze(
                SimpleNamespace(spec=str(spec_path),
                                output=str(tmp / 'ungated')))
        except SystemExit as error:
            freeze_result['exit_code'] = 1
            freeze_result['message'] = str(error)[:300]
    results['freeze_without_real_gate_evidence'] = freeze_result

print(json.dumps(results, indent=2))
