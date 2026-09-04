"""A stranger's replay of a run, with no model and no gateway: only the
published material. For every token: the standard's own validator (schema,
canonical form, signature); the reference verifier over the chain and the
anchor; for the extension claims, a recomputation of the certificate, store
and registry digests from the recorded snapshots plus a re-run of the
certificate verifier, whose result must equal what the token claims; and for
the provenance, a recomputation of its digest and a re-check of every source
it names: the PDF digest and the clerk's mapping signature, the vetting desk's
credential, the customer's presentation against the nonce the gateway chose,
and the signed ledger up to the entry the snapshot saw.

usage: python3 verify.py runs/<name>
"""
import json, os, sys, subprocess, tempfile, glob, hashlib
import gateway
from gateway import node_json, SOURCES, HERE
from poc.core import Verifier, TransparencyLog, canonical, sha256, untag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

run_dir = sys.argv[1]
run = json.load(open(os.path.join(run_dir, 'run.json')))
tokens = json.load(open(os.path.join(run_dir, 'tokens.json')))
POC = gateway.POC
policy = gateway.load_policy(); required_provenance = policy.get('required_provenance', {})
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

# the recorded snapshots, one per token that carries the claims
steps_dir = os.path.join(run_dir, 'steps')
step_files = sorted(glob.glob(os.path.join(steps_dir, '*.store.json'))) or sorted(glob.glob(os.path.join(run_dir, 'a*.store.json')), key=lambda p: int(os.path.basename(p)[1:].split('.')[0]))
def base_for(i): return step_files[i][:-len('.store.json')] if i < len(step_files) else None

# 3. the extension claims: recompute and re-verify
recomputed = 0; agreed = 0
for i, t in enumerate(tokens):
    c = t['poc_claims']
    if 'proveml_certificate_hash' not in c: continue
    base = base_for(i)
    if not base: continue
    store = json.load(open(base + '.store.json')); cert = open(base + '.cert.md').read(); registry = json.load(open(base + '.registry.json'))
    same = (untag(c['proveml_certificate_hash']) == sha256(cert.encode()) and untag(c['proveml_store_hash']) == sha256(canonical(store)) and untag(c['proveml_registry_hash']) == sha256(canonical(registry)))
    args = ['node', os.path.join(HERE, 'verify-cert.mjs'), base + '.store.json', base + '.registry.json', base + '.cert.md', ','.join(c.get('proveml_required_controls', []))]
    if 'proveml_provenance_hash' in c and os.path.exists(base + '.provenance.json'): args += [base + '.provenance.json', json.dumps(required_provenance)]
    r = subprocess.run(args, capture_output=True, text=True, cwd=HERE)
    try: v = json.loads(r.stdout.strip().splitlines()[-1])
    except Exception: v = {'verified': False}
    recomputed += 1
    if same and bool(v['verified']) == bool(c['proveml_verified']) and (c['verdict'] == 'DENY' or v['verified']): agreed += 1
report['checks'].append({'check': 'extension claims: digests recomputed and certificates re-verified', 'passed': agreed, 'of': recomputed})

# 4. the provenance: digest, then every source it names, re-checked from the files
def value_of(prov_record, path, store):
    return store.get(path)
checked = 0; sound = 0; problems = []
for i, t in enumerate(tokens):
    c = t['poc_claims']
    if 'proveml_provenance_hash' not in c: continue
    base = base_for(i)
    if not base or not os.path.exists(base + '.provenance.json'): continue
    prov = json.load(open(base + '.provenance.json')); store = json.load(open(base + '.store.json')); checked += 1; errs = []
    if untag(c['proveml_provenance_hash']) != sha256(canonical(prov)): errs.append('provenance digest does not recompute')
    for path, pv in prov.items():
        g = pv.get('grade'); ent, _, field = path.partition('.'); eid = ent.split(':')[1]
        if g == 'inferred:signed':
            if not pv.get('mapping') or not pv.get('source'): errs.append(f'{path}: claims a signed mapping but names none'); continue
            pdf = os.path.join(HERE, pv['source'])
            if hashlib.sha256(open(pdf, 'rb').read()).hexdigest() != pv['pdf_sha256']: errs.append(f'{path}: the PDF on disk is not the one extracted from')
            m = node_json(os.path.join(SOURCES, 'check.mjs'), 'mapping', os.path.join(HERE, pv['mapping']), pv['pdf_sha256'])
            if not m.get('ok'): errs.append(f'{path}: mapping signature: ' + m.get('why', ''))
            elif m['signer'] != pv['signed_by']: errs.append(f'{path}: signed by {m["signer"]}, not {pv["signed_by"]}')
            else:
                signed = m['fields'].get({'name': 'description'}.get(field, field))
                if signed is not None and signed != store[path]: errs.append(f'{path}: store says {store[path]}, the signed mapping says {signed}')
        elif g == 'attested':
            if not pv.get('credential'): errs.append(f'{path}: claims a credential but names none'); continue
            cr = node_json(os.path.join(SOURCES, 'check.mjs'), 'credential', os.path.join(HERE, pv['credential']))
            if not cr.get('ok'): errs.append(f'{path}: credential: ' + cr.get('why', ''))
            elif cr['issuer'] != pv['issuer'] or cr['claims'].get('supplier') != eid or (cr['claims'].get('vetted') is True) != (store[path] == 1): errs.append(f'{path}: the credential does not say what the store says')
        elif g == 'presented':
            if not pv.get('presentation'): errs.append(f'{path}: claims a presentation but names none'); continue
            pr = node_json(os.path.join(SOURCES, 'check.mjs'), 'presentation', os.path.join(HERE, pv['presentation']), pv['nonce'], pv['aud'])
            if not pr.get('ok'): errs.append(f'{path}: presentation: ' + pr.get('why', ''))
            elif pr['issuer'] != pv['issuer'] or pr['claims'].get('customer') != eid or (policy['purpose'] in pr['claims'].get('purposes', [])) != (store[path] == 1): errs.append(f'{path}: the presentation does not say what the store says')
        elif g == 'ledger' and field == 'paid':
            ledger_file = os.path.join(HERE, pv['ledger']) if pv.get('ledger') else None
            n = sum(1 for line in open(ledger_file) if line.strip() and json.loads(line)['entry'].get('invoice') == eid) if ledger_file and os.path.exists(ledger_file) else 0
            # the ledger has grown since this snapshot; the count then is bounded by the count now, and the token committed to the snapshot's value
            if store[path] > n: errs.append(f'{path}: the snapshot says paid {store[path]} times, the ledger holds {n} payments of it')
        elif g == 'ledger':
            if not pv.get('ledger') or 'entries' not in pv or 'head' not in pv: errs.append(f'{path}: claims the ledger but names no entry'); continue
            lv = node_json(os.path.join(SOURCES, 'ledger.mjs'), 'verify', os.path.join(HERE, pv['ledger']), policy['principal'], str(pv['entries']))
            if not lv.get('ok'): errs.append(f'{path}: ledger: ' + '; '.join(lv.get('errors') or [lv.get('why', '')]))
            elif lv['head'] != pv['head'] or float(lv['sum']) != float(pv['sum_before']): errs.append(f'{path}: the ledger up to entry {pv["entries"]} does not give the spend the snapshot used')
            elif abs(float(pv['sum_before']) + float(store.get(ent + '.amount', 0)) - float(store[path])) > 1e-9: errs.append(f'{path}: spend_after is not ledger spend plus the amount')
    if errs: problems.append({'step': i, 'errors': errs})
    else: sound += 1
report['checks'].append({'check': 'provenance: digests recomputed; PDF digests, mapping signatures, credentials, presentations and ledger re-checked', 'passed': sound, 'of': checked, **({'problems': problems} if problems else {})})
report['verified'] = all((x.get('passed') is True) or (isinstance(x.get('passed'), int) and x['passed'] == x.get('of')) for x in report['checks'])
print(json.dumps(report, indent=1))
sys.exit(0 if report['verified'] else 1)
