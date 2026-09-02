#!/usr/bin/env python3
"""Independent re-verification of a proveml review folder, sharing not one
line with the JavaScript implementation. Standard library only. It recomputes
every inclusion proof (leaf text -> leaf hash -> path -> root), checks each
quoted value sits in its leaf, and refolds the review root from review.json
plus the output root. If this agrees with the page, two implementations in
two languages independently confirm the same receipts: interop is an
afternoon, not a port.

Usage: python3 verify.py <review-folder>   (expects review-page-proofs.json,
manifests/<id>.json, review.json, roots.json)
"""
import hashlib, json, os, re, sys

sha = lambda s: hashlib.sha256(s.encode()).hexdigest()
leaf = lambda t: sha('leaf\0' + t)
node = lambda l, r: sha('node\0' + l + r)
squash = lambda s: re.sub(r'\s+', ' ', s).strip()

def verify_inclusion(root, text, proof):
    h = leaf(text)
    if h != proof['leafHash']:
        return False
    for step in proof['path']:
        h = node(h, step['hash']) if step['side'] == 'R' else node(step['hash'], h)
    return h == root

def tree_root(lines):
    level = [leaf(t) for t in lines]
    while len(level) > 1:
        level = [node(level[i], level[i + 1]) if i + 1 < len(level) else level[i]
                 for i in range(0, len(level), 2)]
    return level[0]

d = sys.argv[1] if len(sys.argv) > 1 else '.'
proofs = json.load(open(os.path.join(d, 'review-page-proofs.json')))['proofs']
manifests = {f[:-5]: json.load(open(os.path.join(d, 'manifests', f)))
             for f in os.listdir(os.path.join(d, 'manifests')) if f.endswith('.json')}
review = json.load(open(os.path.join(d, 'review.json')))
roots = json.load(open(os.path.join(d, 'roots.json')))

ok = bad = 0
for p in proofs:
    text = manifests[p['subject']]['leaves'][p['leafIndex']]['text']
    good = verify_inclusion(p['root'], text, p['proof']) and squash(p['quote']) in squash(text) \
        and p['root'] == manifests[p['subject']]['root']
    ok += good
    bad += not good
    print(f"  {'ok' if good else 'FAIL'} {p['subject']}.{p['field']}: quote in leaf {p['leafIndex'] + 1}, proof to root {p['root'][:10]}…")

lines = ['output ' + roots['output']] + [
    f"{k} {v['src']}.{v['field']} {v['verdict']} {v['at']}"
    for k, v in sorted(review['judgements'].items())
]
rr = tree_root(lines)
match = rr == roots['review']
print(f"  {'ok' if match else 'FAIL'} review root refolds from review.json: {rr[:16]}…")
print(f"\npython re-verification: {ok}/{len(proofs)} proofs hold, review root {'matches' if match else 'DIFFERS'}")
sys.exit(0 if match and bad == 0 else 1)
