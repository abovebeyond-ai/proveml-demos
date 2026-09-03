// Anchor a run's chain head in Sigstore Rekor, so the demo's own transparency
// log (in-process, as in the reference implementation) is pinned to a public
// one nobody here operates. Same key and same recipe as Vera's anchor: a
// signed hash of the payload, read back from the log, kept only as the log
// returned it.
// usage: node anchor-run.mjs runs/<name>
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
const runDir = process.argv[2];
const run = JSON.parse(readFileSync(join(runDir, 'run.json'), 'utf8'));
const KEY = join(homedir(), '.config', 'proveml', 'rekor-key.pem'); const PUB = join(homedir(), '.config', 'proveml', 'rekor-key.pub.pem');
if (!existsSync(KEY)) { execFileSync('openssl', ['ecparam', '-genkey', '-name', 'prime256v1', '-noout', '-out', KEY]); execFileSync('chmod', ['600', KEY]); }
if (!existsSync(PUB)) execFileSync('openssl', ['ec', '-in', KEY, '-pubout', '-out', PUB], { stdio: 'ignore' });
const sha = (b) => createHash('sha256').update(b).digest('hex');
const payload = { v: 1, kind: 'poc-reason-run-anchor', run: run.name, chain_head: run.chain_head, tree_root: run.tree_root, measurement: run.measurement, policy_bundle_hash: run.policy_bundle_hash, tokens: run.steps.length, at: new Date().toISOString() };
const message = Buffer.from(JSON.stringify(payload));
writeFileSync(join(runDir, 'anchor-message.json'), message);
const sig = execFileSync('openssl', ['dgst', '-sha256', '-sign', KEY, join(runDir, 'anchor-message.json')]);
const pub = readFileSync(PUB);
const entry = { apiVersion: '0.0.1', kind: 'hashedrekord', spec: { data: { hash: { algorithm: 'sha256', value: sha(message) } }, signature: { content: sig.toString('base64'), publicKey: { content: pub.toString('base64') } } } };
const res = await fetch('https://rekor.sigstore.dev/api/v1/log/entries', { method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json' }, body: JSON.stringify(entry) });
if (res.status !== 201 && res.status !== 409) throw new Error(`rekor ${res.status}: ${await res.text()}`);
const created = await res.json(); const uuid = Object.keys(created)[0];
const back = (await (await fetch(`https://rekor.sigstore.dev/api/v1/log/entries/${uuid}`)).json())[uuid];
const record = { log: 'https://rekor.sigstore.dev', uuid, logIndex: back.logIndex, integratedAt: new Date(back.integratedTime * 1000).toISOString(), inclusionProofHashes: (back.verification && back.verification.inclusionProof && back.verification.inclusionProof.hashes || []).length, treeSize: back.verification && back.verification.inclusionProof && back.verification.inclusionProof.treeSize, payload, search: `https://search.sigstore.dev/?logIndex=${back.logIndex}` };
writeFileSync(join(runDir, 'anchor-rekor.json'), JSON.stringify(record, null, 1) + '\n');
console.log(`rekor index ${record.logIndex}, integrated ${record.integratedAt}, ${record.inclusionProofHashes} hashes of inclusion proof -> ${join(runDir, 'anchor-rekor.json')}`);
