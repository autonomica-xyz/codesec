import contextlib
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
from unittest.mock import patch
import asyncio
import sqlite3
import pytest

from bench.realvuln import experiment as ex, executor, isolation, preflight, snapshot
from bench.realvuln.aggregate import aggregate_experiment, _fake_scorer_factory
from bench.realvuln.ledger import AttemptLedger

results = {}
with tempfile.TemporaryDirectory(prefix='codesec-review-') as td:
    root = Path(td)
    spec = root / 'spec.json'
    spec.write_text(json.dumps({'repos': ['review-app'], 'trials': [1]}))
    exp = root / 'experiment'
    with contextlib.redirect_stdout(io.StringIO()):
        code = ex.cmd_freeze(SimpleNamespace(spec=spec, output=exp))
    results['freeze_without_any_preflight_or_model_or_image'] = code
    manifest = ex.load_manifest(exp)
    cells = manifest['expected_cells']

    ledger = AttemptLedger(exp/'operator/attempts.jsonl', experiment_id=exp.name,
                           config_hash=manifest['manifest_sha256'])
    cell = cells[0]
    for aid, status in [('first','failed_no_output'),('second','completed')]:
        ledger.append({'type':'attempt_end','cell_id':'ledger-selection-probe',
                       'attempt_id':aid,'status':status,'made_inference_requests':True})
    results['primary_after_failed_no_output_then_success'] = ledger.terminal_state('ledger-selection-probe')['attempt_id']

    missing = root/'missing-primary'; missing.mkdir()
    (missing/'completion.json').write_text(json.dumps({
        'manifest_sha256':manifest['manifest_sha256'], 'arm':cell['arm'],
        'trial':1,'repo':'WRONG','cell_id':'WRONG','attempt_id':'WRONG'}))
    results['arm_done_accepts_no_artifact_and_wrong_repo'] = ex.arm_done(
        missing,manifest=manifest,arm=cell['arm'],repo=cell['repo'],trial=1)['done']

    target = root/'target'; target.mkdir(); (target/'app.py').write_text('pass\n')
    out = root/'output'; out.mkdir()
    findings = out/'findings.json'; findings.write_text('{"findings": []}')
    snapshot.retain_snapshot(findings)
    findings.write_text('{')
    try:
        executor.export_arm_outputs(exp=exp,manifest=manifest,cell={'arm':'v'},
                                    attempt_id='v',output_dir=out,target_dir=target)
        results['previous_valid_pi_snapshot_after_truncated_overwrite'] = 'used'
    except Exception as error:
        results['previous_valid_pi_snapshot_after_truncated_overwrite'] = type(error).__name__

    run_report=out/'run/results/report';run_report.mkdir(parents=True)
    (run_report/'report.checkpoint.json').write_text('{"findings": []}')
    try:
        executor.export_arm_outputs(exp=exp,manifest=manifest,cell={'arm':'h'},
                                    attempt_id='h',output_dir=out,target_dir=target)
        results['valid_h_checkpoint_without_final_report'] = 'used'
    except Exception as error:
        results['valid_h_checkpoint_without_final_report'] = type(error).__name__

    source=root/'source';source.mkdir();(source/'app.py').write_text('pass\n')
    gt={'findings':[
        {'is_vulnerable':True,'file':'app.py','location':{'start_line':1},
         'acceptable_locations':[{'file':'missing-alternative.py','start_line':1}]},
        {'is_vulnerable':False,'file':'missing-decoy.py','location':{'start_line':1}},
    ]}
    results['missing_decoy_and_alternative_locations'] = isolation.verify_gt_locations(target,gt,source_root=source)

    # Emulate a late invalidation on H and a committed V without any ledger.
    rv=root/'rv';gt_dir=rv/'ground-truth/review-app';gt_dir.mkdir(parents=True)
    (gt_dir/'ground-truth.json').write_text(json.dumps({'repo_id':'review-app','findings':[
        {'id':'bug','file':'app.py','is_vulnerable':True,'location':{'start_line':1},
         'acceptable_cwes':['CWE-95'],'primary_cwe':'CWE-95'}]}))
    for c in cells:
        payload=root/f"{c['arm']}.json";payload.write_text('{"results": []}')
        ex.commit_cell_outputs(exp=exp,manifest=manifest,cell=c,attempt_id=f"export-{c['arm']}",
                               export_dir=root,files={'primary':payload})
    ledger.append({'type':'attempt_end','cell_id':cell['cell_id'],'attempt_id':'invalid',
                   'status':'invalidated','made_inference_requests':True})
    agg=aggregate_experiment(exp,realvuln=rv,scorer=_fake_scorer_factory())
    results['aggregate_committed_but_invalidated_or_no_ledger']={
        'headline_present':agg['headline'] is not None,'problems':agg['problems']}

    with (
        patch.object(preflight,'_pytest_gate',side_effect=lambda name,path:preflight._gate(name,'passed')),
        patch.object(isolation,'require_docker'),
        patch.object(isolation,'verify_pin',return_value={'head':'fake','untracked':[]}),
        patch.object(preflight,'_run',return_value={'exit_code':0,'stdout_tail':'WRONG_IMAGE','stderr_tail':''}),
        contextlib.redirect_stdout(io.StringIO()),
    ):
        report=preflight.run_preflight({},offline=False)
    results['live_preflight_with_mocked_offline_dependencies']={
        'passed':report['passed'],
        'live_gates':[g['name'] for g in report['gates'] if 'live' in g['name']],
        'image_gate':[g['status'] for g in report['gates'] if g['name']=='isolation_image'],
    }

    from tests import test_dedupe_stage as dt
    from codesec.state import StateDB
    droot=root/'dedupe-repro';droot.mkdir()
    old_context=dt._dedupe_context
    def isolated_context(path):
        ctx=old_context(path);ctx.run_results_root=droot/'results';ctx.run_work_root=droot/'work'
        return ctx
    with pytest.MonkeyPatch.context() as mp, patch.object(dt,'_dedupe_context',isolated_context):
        asyncio.run(dt.test_second_dedupe_pass_renumbers_colliding_group_ids(droot,mp))
    db=StateDB(droot/'state.db')
    results['second_dedupe_existing_test_passes_but_group_gaps']=[
        g for g in db.completion_gaps('run') if g.startswith('group ')]

    from bench.realvuln.gateway import GatewayConfig
    cfg=GatewayConfig(upstream='https://example.invalid',model='glm-5.3',
        expect={'thinking':{'type':'enabled'},'reasoning_effort':'low',
                'temperature':0.6,'max_tokens':32768,'stream':True},records_dir=root/'gateway',api_key=None)
    request={**cfg.expect,'top_p':0.01,'thinking':{'type':'enabled','clear_thinking':True}}
    results['gateway_accepts_top_p_and_changed_history'] = cfg.validate(request)[1]==[]

print(json.dumps(results,indent=2))
