"""The extension checks of the reason-as-evidence profile, run after the
standard's own validator. Structure via the profile's JSON Schema fragment
(jsonschema), then the semantics: a false proveml_verified forces DENY; the
digests must recompute from the published certificate, store snapshot,
registry and provenance map when those are given; re-running the certificate
verifier on that material, with the policy's required grades, must reproduce
proveml_verified.

usage: python3 validate.py token.json [--cert c.md --store s.json --registry r.json --provenance p.json]
       python3 validate.py --vectors
"""
import json, os, sys, subprocess, hashlib, glob, tempfile
HERE = os.path.dirname(os.path.abspath(__file__)); UP = os.path.dirname(HERE)
sys.path.insert(0, UP); import gateway
from poc.core import canonical, sha256, untag
import jsonschema
SCHEMA = json.load(open(os.path.join(HERE, 'poc-reason.schema.json')))
REQUIRED_PROVENANCE = gateway.load_policy().get('required_provenance', {})

def check(token, cert=None, store=None, registry=None, provenance=None):
    c = token['poc_claims']
    if 'proveml_verified' not in c: return {'ok': False, 'code': 'absent', 'why': 'no reason-as-evidence claims'}
    if c['proveml_verified'] is False and c['verdict'] != 'DENY': return {'ok': False, 'code': 'verdict', 'why': 'certificate did not verify but the verdict is not DENY'}
    try: jsonschema.validate(c, SCHEMA)
    except jsonschema.ValidationError as e: return {'ok': False, 'code': 'schema', 'why': e.message[:160]}
    if cert is not None and untag(c['proveml_certificate_hash']) != sha256(cert.encode()): return {'ok': False, 'code': 'certificate-hash', 'why': 'the published certificate is not the one the token commits to'}
    if store is not None and untag(c['proveml_store_hash']) != sha256(canonical(store)): return {'ok': False, 'code': 'store-hash', 'why': 'the published snapshot is not the one the token commits to'}
    if registry is not None and untag(c['proveml_registry_hash']) != sha256(canonical(registry)): return {'ok': False, 'code': 'registry-hash', 'why': 'the published registry is not the one the token commits to'}
    if provenance is not None:
        if 'proveml_provenance_hash' not in c: return {'ok': False, 'code': 'provenance-hash', 'why': 'a provenance map was published but the token commits to none'}
        if untag(c['proveml_provenance_hash']) != sha256(canonical(provenance)): return {'ok': False, 'code': 'provenance-hash', 'why': 'the published provenance map is not the one the token commits to'}
        for path, grade in c.get('proveml_provenance', {}).items():
            if provenance.get(path, {}).get('grade', 'absent') != grade: return {'ok': False, 'code': 'provenance-grade', 'why': f'the token says {path} is {grade}, the map says {provenance.get(path, {}).get("grade", "absent")}'}
    if cert is not None and store is not None and registry is not None:
        d = tempfile.mkdtemp(); json.dump(store, open(d + '/s.json', 'w')); json.dump(registry, open(d + '/r.json', 'w')); open(d + '/c.md', 'w').write(cert)
        args = ['node', os.path.join(UP, 'verify-cert.mjs'), d + '/s.json', d + '/r.json', d + '/c.md', ','.join(c['proveml_required_controls'])]
        if provenance is not None: json.dump(provenance, open(d + '/p.json', 'w')); args += [d + '/p.json', json.dumps(REQUIRED_PROVENANCE)]
        r = subprocess.run(args, capture_output=True, text=True, cwd=UP)
        v = json.loads(r.stdout.strip().splitlines()[-1])
        if bool(v['verified']) != bool(c['proveml_verified']): return {'ok': False, 'code': 'reverify', 'why': f"re-verification gives {v['verified']}, the token claims {c['proveml_verified']}"}
    return {'ok': True, 'code': 'ok'}

def load_material(d, v):
    m = {}
    for k in ('cert', 'store', 'registry', 'provenance'):
        if k in v: m[k] = open(os.path.join(d, v[k])).read() if k == 'cert' else json.load(open(os.path.join(d, v[k])))
    return m

if __name__ == '__main__':
    a = sys.argv[1:]
    if a and a[0] == '--vectors':
        vd = os.path.join(HERE, 'vectors'); man = json.load(open(os.path.join(vd, 'manifest.json'))); passed = 0
        for v in man['vectors']:
            t = json.load(open(os.path.join(vd, v['file']))); m = load_material(vd, v)
            r = check(t, m.get('cert'), m.get('store'), m.get('registry'), m.get('provenance'))
            good = r['code'] == v['expect']; passed += good
            print(('ok  ' if good else 'FAIL'), v['file'], '->', r['code'], '' if good else f"(expected {v['expect']}: {r.get('why', '')})")
        print(f"{passed} passed, {len(man['vectors']) - passed} failed"); sys.exit(0 if passed == len(man['vectors']) else 1)
    opt = lambda k: a[a.index(k) + 1] if k in a else None
    t = json.load(open(a[0]))
    r = check(t, open(opt('--cert')).read() if opt('--cert') else None, json.load(open(opt('--store'))) if opt('--store') else None,
              json.load(open(opt('--registry'))) if opt('--registry') else None, json.load(open(opt('--provenance'))) if opt('--provenance') else None)
    print(json.dumps(r)); sys.exit(0 if r['ok'] else 1)
