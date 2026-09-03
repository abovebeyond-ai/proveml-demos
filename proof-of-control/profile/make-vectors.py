"""Builds the profile's test vectors from real runs, so a vector is never a
token typed by hand. Positive: a verified ALLOW from runs/injected-with, with
its certificate, snapshot, registry and provenance. Negatives are that token
or another real one with one thing wrong, each expected to fail on a named
check.

usage: python3 make-vectors.py   (from anywhere; writes profile/vectors/)
"""
import json, os, shutil, copy
HERE = os.path.dirname(os.path.abspath(__file__)); UP = os.path.dirname(HERE); VD = os.path.join(HERE, 'vectors')
os.makedirs(VD, exist_ok=True)
def run(name): return json.load(open(os.path.join(UP, 'runs', name, 'tokens.json')))
def step(name, i, ext): return os.path.join(UP, 'runs', name, 'steps', f'{i:02d}{ext}')
dump = lambda o, f: json.dump(o, open(os.path.join(VD, f), 'w'), indent=1)

# positive: injected-with step 2, the payment of inv-77 (ALLOW, certificate verified, every grade met)
tokens = run('injected-with'); i = next(k for k, t in enumerate(tokens) if t['poc_claims']['verdict'] == 'ALLOW' and t['poc_claims'].get('proveml_verified') and t['poc_claims']['target_resource'] == 'payments.api')
pos = tokens[i]; dump(pos, 'positive-allow-verified.json')
for ext, out in (('.cert.md', 'positive.cert.md'), ('.store.json', 'positive.store.json'), ('.registry.json', 'positive.registry.json'), ('.provenance.json', 'positive.provenance.json')):
    shutil.copy(step('injected-with', i, ext), os.path.join(VD, out))
shutil.copy(step('injected-with', i + 1, '.cert.md'), os.path.join(VD, 'negative-other.cert.md'))   # the next step's certificate, a real one for a different action

# negative 1: an ALLOW whose certificate did not verify
n1 = copy.deepcopy(pos); n1['poc_claims']['proveml_verified'] = False; dump(n1, 'negative-allow-unverified.json')
# negative 2: the certificate published beside the token is another one
dump(pos, 'negative-certificate-substituted.json')
# negative 3: the token claims a control was required that the certificate never argued
n3 = copy.deepcopy(pos); n3['poc_claims']['proveml_required_controls'] = n3['poc_claims']['proveml_required_controls'] + ['CONSENTED']; dump(n3, 'negative-required-control-missing.json')
# negative 4: the provenance map published beside the token has been edited (a grade raised)
prov = json.load(open(step('injected-with', i, '.provenance.json'))); edited = copy.deepcopy(prov)
k = next(p for p, r in edited.items() if r.get('grade') == 'inferred:signed'); edited[k]['grade'] = 'attested'
dump(edited, 'negative-edited.provenance.json'); dump(pos, 'negative-provenance-substituted.json')
# negative 5: a real token from the unchecked run, the payment on an unsigned mapping, with proveml_verified flipped to true and the verdict to ALLOW;
# the digests are intact, so only re-verification with the policy's required grades catches it
un = run('unchecked-with'); j = next(k for k, t in enumerate(un) if t['poc_claims']['target_resource'] == 'payments.api')
n5 = copy.deepcopy(un[j]); n5['poc_claims']['proveml_verified'] = True; n5['poc_claims']['verdict'] = 'ALLOW'; dump(n5, 'negative-provenance-insufficient.json')
for ext, out in (('.cert.md', 'unchecked.cert.md'), ('.store.json', 'unchecked.store.json'), ('.registry.json', 'unchecked.registry.json'), ('.provenance.json', 'unchecked.provenance.json')):
    shutil.copy(step('unchecked-with', j, ext), os.path.join(VD, out))

P = {'cert': 'positive.cert.md', 'store': 'positive.store.json', 'registry': 'positive.registry.json', 'provenance': 'positive.provenance.json'}
U = {'cert': 'unchecked.cert.md', 'store': 'unchecked.store.json', 'registry': 'unchecked.registry.json', 'provenance': 'unchecked.provenance.json'}
dump({'profile': 'poc-reason v0.1', 'source_runs': ['runs/injected-with', 'runs/unchecked-with'], 'vectors': [
    {'file': 'positive-allow-verified.json', **P, 'expect': 'ok', 'why': 'a real token from the run: ALLOW, certificate verified, digests recompute, every bound fact at the grade the policy requires'},
    {'file': 'negative-allow-unverified.json', 'expect': 'verdict', 'why': 'an ALLOW whose certificate did not verify is not evidence of a warranted action'},
    {'file': 'negative-certificate-substituted.json', **{**P, 'cert': 'negative-other.cert.md'}, 'expect': 'certificate-hash', 'why': 'the certificate published beside the token is not the one it commits to'},
    {'file': 'negative-required-control-missing.json', **P, 'expect': 'reverify', 'why': 'the token claims a control was required that the certificate never argued; re-verification disagrees'},
    {'file': 'negative-provenance-substituted.json', **{**P, 'provenance': 'negative-edited.provenance.json'}, 'expect': 'provenance-hash', 'why': 'the provenance map published beside the token has a grade raised; it is not the map the token commits to'},
    {'file': 'negative-provenance-insufficient.json', **U, 'expect': 'reverify', 'why': 'a payment on an unsigned extraction, with the verdict and the verified flag forged; the digests hold, re-verification with the required grades does not'},
]}, 'manifest.json')
print('vectors written from injected-with step', i, 'and unchecked-with step', j)
