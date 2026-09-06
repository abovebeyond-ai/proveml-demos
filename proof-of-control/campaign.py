"""Many live runs, several models, both conditions, one after the other, then
the summary. Each run is agent_run.py with its own name under runs/campaign-*;
a run that crashes is recorded as such and the campaign goes on.

usage: python3 campaign.py --models claude-sonnet-5,claude-haiku-4-5 --runs 5 --reference 3
"""
import subprocess, sys, os, json, time
HERE = os.path.dirname(os.path.abspath(__file__))
args = sys.argv[1:]
opt = lambda k, d: args[args.index(k) + 1] if k in args else d
MODELS = opt('--models', 'claude-sonnet-5').split(','); RUNS = int(opt('--runs', '5')); REF = int(opt('--reference', '0'))
log = []
for model in MODELS:
    short = model.replace('claude-', '')
    plan = [(f'campaign-{short}-{i + 1}', []) for i in range(RUNS)] + [(f'campaign-{short}-ref-{i + 1}', ['--reference']) for i in range(REF)]
    for name, extra in plan:
        if os.path.exists(os.path.join(HERE, 'runs', name, 'run.json')): print('skip', name, '(exists)'); continue
        t0 = time.time()
        r = subprocess.run([sys.executable, os.path.join(HERE, 'agent_run.py'), '--model', model, '--name', name, '--max', '8', *extra], capture_output=True, text=True, cwd=HERE)
        ok = r.returncode == 0 and os.path.exists(os.path.join(HERE, 'runs', name, 'run.json'))
        log.append({'name': name, 'ok': ok, 'seconds': round(time.time() - t0), 'tail': (r.stdout or r.stderr)[-300:]})
        print(('ok  ' if ok else 'FAIL'), name, f'{round(time.time() - t0)}s', (r.stdout.strip().splitlines() or [''])[-1][:100], flush=True)
json.dump(log, open(os.path.join(HERE, 'results', 'live-campaign-log.json'), 'w'), indent=1)
subprocess.run([sys.executable, os.path.join(HERE, 'summarize.py')], cwd=HERE)
