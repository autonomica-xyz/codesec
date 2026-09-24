"""Read-only audit of the scored GLM53 matrix; no inference or artifact replay writes.

Run from the codesec root:
  .venv/bin/python -m bench.realvuln.audit_saved_run > /tmp/realvuln-audit.json

Membership ablations below rescore saved DB findings, not new pipeline runs.
They deliberately preserve the frozen scorer and adapter semantics.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import sys

from bench.realvuln.adapt_to_semgrep import _filter, _semgrep_result
from bench.realvuln.aggregate import _pool
from bench.realvuln.common import DEFAULT_REALVULN, HERE, RUNS_ROOT


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--realvuln', type=Path, default=DEFAULT_REALVULN)
    parser.add_argument('--runs', type=Path, default=RUNS_ROOT)
    args = parser.parse_args()
    sys.path.insert(0, str(args.realvuln.resolve()))
    from parsers import get_parser
    from parsers.base import NormalisedFinding
    from scorer.matcher import load_ground_truth, match_findings

    totals = Counter()
    trials = defaultdict(lambda: defaultdict(list))
    cells = []
    hashes = {}

    def read(path):
        data = path.read_bytes()
        hashes[str(path)] = hashlib.sha256(data).hexdigest()
        return json.loads(data)

    def score(findings, gt, slug):
        matches = match_findings(findings, gt)
        counts = Counter(m.classification.lower() for m in matches)
        return dict(slug=slug, **{k: counts[k] for k in ('tp', 'fp', 'fn', 'tn')}), matches

    def convert(rows, target, canary):
        kept, _, _ = _filter([_semgrep_result(f, target) for f in rows], canary)
        return [NormalisedFinding(
            file=f['path'], cwe=f['extra']['metadata']['cwe'][0],
            line=f['start']['line'], function=None, severity=None,
            rule_id=f['check_id'], message=f['extra']['message'],
            scanner='offline-membership-ablation',
            finding_id=f['extra']['metadata']['finding_id'],
        ) for f in kept]

    for slug in (HERE / 'subset.txt').read_text().split():
        gt_path = args.realvuln / 'ground-truth' / slug / 'ground-truth.json'
        read(gt_path)
        gt = load_ground_truth(str(gt_path))
        for trial in (1, 2, 3):
            cell = {'slug': slug, 'trial': trial}
            matched = {}
            for arm in ('hunt', 'final', 'pi'):
                scanner = 'pi-glm53' if arm == 'pi' else f'codesec-glm53-{arm}'
                path = args.realvuln / 'scan-results' / slug / scanner / f'run-{trial}.json'
                read(path)
                row, matches = score(get_parser(scanner).parse(str(path)), gt, slug)
                trials[trial][arm].append(row)
                matched[arm] = {m.ground_truth_id for m in matches if m.classification == 'TP'}
            metrics = read(args.realvuln / 'scan-results' / slug / 'codesec-glm53-final' / f'run-{trial}.metrics.json')
            root = args.runs / metrics['opaque_id']
            mapping = read(args.runs / 'operator' / f"{metrics['opaque_id']}.json")
            target = Path(mapping['target'])
            cell['opaque_id'] = metrics['opaque_id']
            meta = dict(line.split('=', 1) for line in (root / 'benchmark_meta.txt').read_text().splitlines() if '=' in line)
            cell['h_wall_s'] = int(meta['wall_s'])
            cell['h_exit_status'] = int(meta['status'])
            log = (root / 'codesec.log').read_text()
            hashes[str(root / 'codesec.log')] = hashlib.sha256(log.encode()).hexdigest()
            for key, needle in [('dedupe_fallback', 'dedupe failed:'), ('report_fallback', 'report agent failed:')]:
                cell[key] = needle in log
                totals[key] += cell[key]
            cell['concurrency_values'] = sorted(set(re.findall(r'concurrency=(\d+)', log)))
            for transcript in (root / 'results').rglob('*.jsonl'):
                for line in transcript.read_text().splitlines():
                    record = json.loads(line)
                    if record.get('kind') == 'tool_result' and record.get('tool') in ('grep', 'glob'):
                        tool = record['tool']
                        totals[tool + ':calls'] += 1
                        totals[tool + ':no_matches'] += record.get('result') == '(no matches)'
                        totals[tool + ':errors'] += str(record.get('result', '')).startswith('[tool error:')
            db_path = root / 'state.db'
            hashes[str(db_path)] = hashlib.sha256(db_path.read_bytes()).hexdigest()
            with sqlite3.connect(f'{db_path.resolve().as_uri()}?mode=ro', uri=True) as db:
                db.row_factory = sqlite3.Row
                findings = [dict(row) for row in db.execute('SELECT * FROM findings ORDER BY finding_id')]
                traces = {row['finding_id']: dict(row) for row in db.execute('SELECT * FROM traces')}
            validation = Counter(f['validation_status'] for f in findings)
            totals.update({'validation:' + str(k): v for k, v in validation.items()})
            confirmed = [f for f in findings if f['validation_status'] == 'confirmed' and f['is_canonical']]
            statuses = Counter(traces[f['finding_id']]['status'] if f['finding_id'] in traces else 'missing' for f in confirmed)
            cell['canonical_trace_statuses'] = dict(statuses)
            totals.update({'trace:' + k: v for k, v in statuses.items()})
            for tr in traces.values():
                if tr['status'] != 'uncertain':
                    continue
                reason = json.loads(tr['raw_json']).get('rationale', '')
                kind = ('sink_mismatch' if 'authoritative sink' in reason else
                        'other_contract' if 'semantic contract' in reason else 'model_uncertainty')
                totals['uncertain:' + kind] += 1
                if kind == 'model_uncertainty':
                    totals['uncertain:example_host'] += 'server.local' in reason
                    totals['uncertain:marker_or_canary'] += any(x in reason.lower() for x in ('marker', 'canary'))
            for name, selected in (
                ('confirmed_all', confirmed),
                ('confirmed_except_unreachable', [f for f in confirmed if traces.get(f['finding_id'], {}).get('status') != 'unreachable']),
            ):
                normalized = convert([json.loads(f['raw_json']) for f in selected], target, mapping['canary'])
                row, _ = score(normalized, gt, slug)
                trials[trial][name].append(row)
            cell['lost_hunt_tp_ids'] = sorted(matched['hunt'] - matched['final'])
            totals['hunt_tp_absent_from_final'] += len(cell['lost_hunt_tp_ids'])
            totals['pi_tp_absent_from_hunt'] += len(matched['pi'] - matched['hunt'])
            vm = read(args.realvuln / 'scan-results' / slug / 'pi-glm53' / f'run-{trial}.metrics.json')
            vr = args.runs / vm['opaque_id']
            vmeta_path = vr / 'benchmark_meta.txt'
            vmeta = dict(line.split('=', 1) for line in vmeta_path.read_text().splitlines() if '=' in line) if vmeta_path.exists() else {}
            cell['v_wall_s'] = int(vmeta['wall_s']) if 'wall_s' in vmeta else None
            cell['v_metadata_missing'] = not vmeta_path.exists()
            levels = []
            calls = Counter()
            for session in sorted((vr / 'pi-session').glob('*.jsonl')):
                for line in session.read_text().splitlines():
                    record = json.loads(line)
                    if record['type'] == 'thinking_level_change':
                        levels.append(record['thinkingLevel'])
                    msg = record.get('message', {})
                    if msg.get('role') == 'assistant':
                        for block in msg.get('content', []):
                            if block.get('type') == 'toolCall':
                                calls[block['name']] += 1
            cell['pi_recorded_thinking_levels'] = levels
            cell['pi_tool_calls'] = dict(calls)
            cells.append(cell)

    pooled = {t: {name: _pool(rows) for name, rows in arms.items()} for t, arms in trials.items()}
    means = {name: round(sum(pooled[t][name]['f3_score'] for t in pooled) / 3, 1) for name in pooled[1]}
    fp_wins = {t: sum(h['fp'] < v['fp'] for h, v in zip(trials[t]['final'], trials[t]['pi'])) for t in trials}
    ablation_fp_wins = {t: sum(h['fp'] < v['fp'] for h, v in zip(trials[t]['confirmed_all'], trials[t]['pi'])) for t in trials}
    print(json.dumps({
        'scope': '18 scored GLM53 pairs only; smoke excluded',
        'ablation_warning': 'Offline membership rescore of existing findings, sorted by finding_id; not a fresh run or proof of correctness.',
        'totals': dict(totals), 'trial_micro': pooled, 'mean_f3': means,
        'final_fewer_fp_slugs_per_trial': fp_wins, 'cells': cells,
        'confirmed_all_fewer_fp_slugs_per_trial': ablation_fp_wins,
        'input_sha256': hashes,
    }, indent=2))


if __name__ == '__main__':
    main()
