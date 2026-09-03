"""A stranger's replay of a run, with no model and no gateway: only the
published material. For every token: the standard's own validator (schema,
canonical form, signature); the reference verifier over the chain and the
anchor; and, for the extension claims, a recomputation of the certificate,
store and registry digests from the recorded snapshots plus a re-run of the
certificate verifier, whose result must equal what the token claims.

usage: python3 verify.py runs/<name>
"""
import json, os, sys, subprocess, tempfile, glob, hashlib
import gateway
from poc.core import Verifier, TransparencyLog, canonical, sha256, untag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

HERE = os.path.dirname(os.path.abspath(__file__))
run_dir = sys.argv[1]
run = json.load(open(os.path.join(run_dir, 'run.json')))
tokens = json.load(open(os.path.join(run_dir, 'tokens.json')))
POC = gateway.POC
report = {'run': run['name'], 'tokens': len(tokens), 'checks': []}

# 1. the standard's validator
ok = 0
for i, t in enumerate(tokens):
    with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False) as f: json.dump(t, f); p = f.name
    r = subprocess.run(['python3', POC + '/schema/validate.py', p, '--key', run['public_key']], capture_output=True, text=True)
    ok += r.returncode == 0
report['checks'].append({'check': 'standard validator (schema, canonical form, signature)', 'passed': ok, 'of': len(tokens)})

# 2. the reference verifier: signatures, measurement, sequence, chain, anchor
log = TransparencyLog('replay')
if run.get('anchor'): log.entries.append(run['anchor'])
pk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(run['public_key']))
chain_ok, msg = Verifier(pk, run['measurement']).verify_chain(tokens, log)
report['checks'].append({'check': 'reference verifier: chain and anchor', 'passed': chain_ok, 'detail': msg})

# 3. the extension claims: recompute and re-verify
recomputed = 0; agreed = 0; steps_dir = os.path.join(run_dir, 'steps')
step_files = sorted(glob.glob(os.path.join(steps_dir, '*.store.json')))
for i, t in enumerate(tokens):
    c = t['poc_claims']
    if 'proveml_certificate_hash' not in c: continue
    base = step_files[i][:-len('.store.json')] if i < len(step_files) else None
    if not base: continue
    store = json.load(open(base + '.store.json')); cert = open(base + '.cert.md').read(); registry = json.load(open(base + '.registry.json'))
    same = (untag(c['proveml_certificate_hash']) == sha256(cert.encode()) and untag(c['proveml_store_hash']) == sha256(canonical(store)) and untag(c['proveml_registry_hash']) == sha256(canonical(registry)))
    r = subprocess.run(['node', os.path.join(HERE, 'verify-cert.mjs'), base + '.store.json', base + '.registry.json', base + '.cert.md', ','.join(c.get('proveml_required_controls', []))], capture_output=True, text=True, cwd=HERE)
    try: v = json.loads(r.stdout.strip().splitlines()[-1])
    except Exception: v = {'verified': False}
    recomputed += 1
    if same and bool(v['verified']) == bool(c['proveml_verified']) and (c['verdict'] == 'DENY' or v['verified']): agreed += 1
report['checks'].append({'check': 'extension claims: digests recomputed and certificates re-verified', 'passed': agreed, 'of': recomputed})
report['verified'] = all((x.get('passed') is True) or (isinstance(x.get('passed'), int) and x['passed'] == x.get('of')) for x in report['checks'])
print(json.dumps(report, indent=1))
sys.exit(0 if report['verified'] else 1)
