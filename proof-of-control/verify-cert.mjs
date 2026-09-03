// The certificate check, as a stranger runs it: a store snapshot, the
// registry, the certificate text, the controls the policy requires for this
// action. Prints JSON: verified, which required controls were argued, and
// every error the verifier found. Exit 0 only when everything holds.
//
// usage: node verify-cert.mjs store.json registry.json cert.md [REQ1,REQ2,...]
import { readFileSync } from 'node:fs';
import { verifyProveml } from 'proveml/verify';
const [storeF, regF, certF, req] = process.argv.slice(2);
const store = JSON.parse(readFileSync(storeF, 'utf8'));
const registry = JSON.parse(readFileSync(regF, 'utf8'));
const cert = readFileSync(certF, 'utf8');
const required = req ? req.split(',').filter(Boolean) : [];
const v = verifyProveml(cert, store, { thresholds: registry, strict: true });
const argued = [...cert.matchAll(/\?\[[^\]:]+:\s*([A-Z][A-Z0-9_]*)/g)].map((m) => m[1]);
const missing = required.filter((r) => !argued.includes(r));
const errors = [...v.errors, ...missing.map((m) => `required control ${m} not argued`)];
const out = { verified: errors.length === 0 && v.total > 0, total: v.total, checked: v.verified, argued, missing, errors };
console.log(JSON.stringify(out));
process.exit(out.verified ? 0 : 1);
