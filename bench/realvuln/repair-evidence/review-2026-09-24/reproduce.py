"""Read saved results; probe failure paths on disposable copies only."""
import contextlib
import io
import json
import shutil
import tempfile
import time
from collections import Counter, defaultdict
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from bench.realvuln import experiment as ex, executor
from bench.realvuln.aggregate import aggregate_experiment
from bench.realvuln.ledger import AttemptLedger

root = Path(__file__).resolve().parents[4]
exp = root / 'bench/realvuln-runs/experiments/matrix-20260923-01'
manifest = ex.load_manifest(exp)
results = {}
aggregate = aggregate_experiment(exp)
results['recomputed_matrix'] = {
    k: aggregate[k] for k in ('headline', 'decision', 'problems',
                              'terminal_status_counts', 'usage')
}
results['source_hash'] = {
    'frozen': manifest['source']['source_tree_sha256'],
    'current': ex.sha256_tree(ex._source_hash_inputs()),
}
usage = defaultdict(Counter)
for line in (exp / 'operator/gateway/requests.jsonl').read_text().splitlines():
    r = json.loads(line)
    if r.get('experiment_id') != manifest['experiment_id']:
        continue
    arm = r.get('arm', 'unknown')
    usage[arm][r.get('kind', 'unknown')] += 1
    if r.get('kind') == 'terminal':
        for key, value in (r.get('usage') or {}).items():
            if isinstance(value, (int, float)):
                usage[arm][key] += value
results['usage_by_arm'] = dict(usage)

with tempfile.TemporaryDirectory(prefix='codesec-reverify-') as temp:
    tmp = Path(temp)

    def copied(name):
        dest = tmp / name
        (dest / 'operator').mkdir(parents=True)
        for filename in ('manifest.json', 'manifest.sha256', 'attempts.jsonl', 'schedule.json'):
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

    dest = copied('corrupt-failed-output')
    failed_cell = dest / 'committed/358d16220e1b1dda'
    marker = json.loads((failed_cell / 'completion.json').read_text())
    (failed_cell / marker['primary_path']).write_text('{')
    results['corrupt_committed_failed_output'] = summarize(dest)

    dest = copied('wrong-repo')
    marker_path = dest / 'committed' / cell['cell_id'] / 'completion.json'
    marker = json.loads(marker_path.read_text())
    marker['repo'] = 'WRONG-REPO'
    marker['cell_id'] = 'WRONG-CELL'
    marker_path.write_text(json.dumps(marker))
    results['wrong_marker_identity'] = summarize(dest)

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
        result = executor.export_arm_outputs(
            exp=exp, manifest=manifest, cell={'arm': arm}, attempt_id='review',
            output_dir=output, target_dir=target, deadline_ts=time.time() - 60)
        primary = json.loads(result['files']['primary'].read_text())
        results['post_deadline_output'][arm] = {'exported_count': len(primary['results'])}

    # Check gate admission, mocking only Docker/benchmark availability.
    spec = json.loads((root / 'bench/realvuln/protocol-v5.json').read_text())
    spec['isolation_evidence_sha256'] = '0' * 64
    spec_path = tmp / 'spec.json'
    spec_path.write_text(json.dumps(spec))
    with patch('bench.realvuln.isolation.verify_pin', return_value={}), \
         patch('bench.realvuln.isolation.resolve_image_id', return_value=spec['image']['image_id']), \
         patch.object(ex, '_image_profile_endpoints', return_value={spec['settings']['gateway_url']}), \
         contextlib.redirect_stdout(io.StringIO()):
        code = ex.cmd_freeze(SimpleNamespace(spec=str(spec_path), output=str(tmp / 'ungated')))
    results['freeze_without_real_gate_evidence'] = {'exit_code': code}

print(json.dumps(results, indent=2))
