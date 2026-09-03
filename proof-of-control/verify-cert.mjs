// The certificate check, as a stranger runs it: a store snapshot, the
// registry, the certificate text, the controls the policy requires for this
// action, and (optionally) the provenance of the snapshot with the grades the
// policy requires per field. Prints JSON: verified, which required controls
// were argued, which store paths the certificate bound, their provenance
// grades, and every error the verifier found. Exit 0 only when everything
// holds.
//
// usage: node verify-cert.mjs store.json registry.json cert.md [REQ1,REQ2,...] [provenance.json] ['{"type.field":"grade"}']
import { readFileSync } from 'node:fs';
import { verifyProveml } from 'proveml/verify';
const [storeF, regF, certF, req, provF, reqProvJson] = process.argv.slice(2);
const store = JSON.parse(readFileSync(storeF, 'utf8'));
const registry = JSON.parse(readFileSync(regF, 'utf8'));
const cert = readFileSync(certF, 'utf8');
const required = req ? req.split(',').filter(Boolean) : [];
const v = verifyProveml(cert, store, { thresholds: registry, strict: true });
const argued = [...cert.matchAll(/\?\[[^\]:]+:\s*([A-Z][A-Z0-9_]*)/g)].map((m) => m[1]);
const missing = required.filter((r) => !argued.includes(r));
const errors = [...v.errors, ...missing.map((m) => `required control ${m} not argued`)];

// what the certificate bound: every fact's path, and for every judgement the
// entity in scope (an explicit THRESHOLD(path) or the last entity named
// before it) joined with the registry field the threshold reads
const entities = v.details.filter((d) => d.type === 'entity' && d.path);
const bound = new Set(v.details.filter((d) => d.type === 'fact' && d.path && d.status === 'verified').map((d) => d.path));
for (const m of cert.matchAll(/\?\[[^\]:]+:\s*([A-Z][A-Z0-9_]*)(?:\(([^)]*)\))?\]/g)) {
    const th = registry[m[1]]; if (!th) continue;
    const explicit = m[2] ? m[2].split('.')[0] : null;
    const scope = explicit || entities.filter((e) => e.pos < m.index).map((e) => e.path).pop();
    if (scope && (scope + '.' + th.field) in store) bound.add(scope + '.' + th.field);
}
const RANK = { absent: 0, inferred: 1, gateway: 2, 'inferred:signed': 2, attested: 3, presented: 4, ledger: 4, policy: 4 };
const provenance = {};
if (provF) {
    const prov = JSON.parse(readFileSync(provF, 'utf8')); const need = reqProvJson ? JSON.parse(reqProvJson) : {};
    for (const p of bound) {
        const rec = prov[p] || {}; const grade = rec.grade || 'absent'; provenance[p] = grade;
        const want = need[p.split(':')[0] + '.' + p.split('.').pop()]; if (!want) continue;
        if ((RANK[grade] ?? 0) < (RANK[want] ?? 0)) errors.push(`${p} is ${grade}${rec.why ? ' (' + rec.why + ')' : rec.mapping_error ? ' (' + rec.mapping_error + ')' : ''}; policy requires ${want}`);
    }
}
const out = { verified: errors.length === 0 && v.total > 0, total: v.total, checked: v.verified, argued, missing, bound: [...bound].sort(), provenance, errors };
console.log(JSON.stringify(out));
process.exit(out.verified ? 0 : 1);
