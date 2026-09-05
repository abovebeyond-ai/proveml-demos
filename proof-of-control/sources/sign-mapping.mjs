// A person signs that the extraction mapped a PDF correctly. The credential
// binds the PDF digest and the fields as extracted; change either and the
// signature no longer covers it. Signer: did:web:abovebeyond.ai key-1, which
// in this demo stands in for the accounts-payable clerk. Nothing is signed
// that was not extracted: the fields are copied from extraction.json, never
// typed here.
// usage: node sign-mapping.mjs inv-77 [inv-78 ...]
//   PROVEML_CLERK_KEY=<path to {privateJwk, publicJwk}> signs with that key instead, as did:jwk
//   (a runner without the clerk's did:web key, such as CI, still needs a clerk)
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { HERE, loadKey, issuer, didJwk } from './lib.mjs';

const keyPath = process.env.PROVEML_CLERK_KEY || join(homedir(), '.config', 'proveml', 'abovebeyond-signing.jwk');
const key = loadKey(keyPath);
const SIGNER = process.env.PROVEML_CLERK_KEY ? didJwk(key.publicJwk) : 'did:web:abovebeyond.ai';
const ex = JSON.parse(readFileSync(join(HERE, 'extraction.json'), 'utf8'));
for (const id of process.argv.slice(2)) {
    const e = ex.invoices[id]; if (!e) throw new Error('not extracted: ' + id);
    const { note, ...fields } = e.fields;   // the note is content, not a field the clerk vouches for
    const vc = await issuer(key.privateJwk).issue({ vct: 'urn:proveml:extraction-mapping:1', iss: SIGNER, iat: Math.floor(Date.now() / 1000), invoice: id, pdf_sha256: e.pdf_sha256, text_sha256: e.text_sha256, method: ex.method, as_of: ex.as_of, fields, checked_by: 'accounts-payable clerk' }, { _sd: [] });
    writeFileSync(join(HERE, 'invoices', id + '.mapping.sdjwt'), vc);
    console.log('mapping signed:', id, 'by', SIGNER);
}
