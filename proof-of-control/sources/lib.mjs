// Shared pieces of the source layer: Ed25519 keys as JWKs, did:jwk for the
// demo issuers, did:web for the person, SD-JWT VC instances for issuing,
// presenting and verifying, a minimal PDF writer, and digests.
import { createHash, createPrivateKey, createPublicKey, sign, verify, generateKeyPairSync } from 'node:crypto';
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { SDJwtVcInstance } from '@sd-jwt/sd-jwt-vc';
import { digest, generateSalt } from '@owf/crypto';
import { base64url } from 'jose';

export const HERE = dirname(fileURLToPath(import.meta.url));
export const ROOT = dirname(HERE);
export const sha256 = (b) => createHash('sha256').update(b).digest('hex');
// sorted keys, no whitespace: the same form the reference implementation's canonical() gives
export const canonical = (o) => JSON.stringify(sortKeys(o));
function sortKeys(o) { return Array.isArray(o) ? o.map(sortKeys) : (o && typeof o === 'object' ? Object.fromEntries(Object.keys(o).sort().map((k) => [k, sortKeys(o[k])])) : o); }

// keys
export function newKey() {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    return { privateJwk: privateKey.export({ format: 'jwk' }), publicJwk: publicKey.export({ format: 'jwk' }) };
}
export function loadKey(path) { return JSON.parse(readFileSync(path, 'utf8')); }
export function ensureKey(path) {
    if (existsSync(path)) return loadKey(path);
    mkdirSync(dirname(path), { recursive: true });
    const k = newKey(); writeFileSync(path, JSON.stringify(k, null, 1)); return k;
}
export const didJwk = (publicJwk) => 'did:jwk:' + base64url.encode(Buffer.from(JSON.stringify({ kty: publicJwk.kty, crv: publicJwk.crv, x: publicJwk.x })));
export function resolveDidJwk(did) {
    if (!did.startsWith('did:jwk:')) throw new Error('not a did:jwk: ' + did);
    return JSON.parse(Buffer.from(base64url.decode(did.slice(8))).toString());
}
const DID_WEB_CACHE = join(HERE, 'keys', 'did-web-cache.json');
export async function resolveDid(did) {
    if (did.startsWith('did:jwk:')) return { jwk: resolveDidJwk(did), via: 'did:jwk' };
    if (did.startsWith('did:web:')) {
        const host = did.slice(8).split(':')[0]; const url = `https://${host}/.well-known/did.json`;
        let doc = null, via = 'fetched';
        try { const r = await fetch(url); if (r.ok) doc = await r.json(); } catch { /* offline */ }
        const cache = existsSync(DID_WEB_CACHE) ? JSON.parse(readFileSync(DID_WEB_CACHE, 'utf8')) : {};
        if (doc) { cache[did] = doc; mkdirSync(dirname(DID_WEB_CACHE), { recursive: true }); writeFileSync(DID_WEB_CACHE, JSON.stringify(cache, null, 1)); }
        else if (cache[did]) { doc = cache[did]; via = 'cached DID document'; }
        if (!doc) throw new Error('cannot resolve ' + did);
        const vm = (doc.verificationMethod || []).find((m) => m.id === did + '#key-1') || (doc.verificationMethod || [])[0];
        return { jwk: vm.publicKeyJwk, via };
    }
    throw new Error('unsupported DID method: ' + did);
}

// signing callbacks in the shape @sd-jwt expects
export const signerFor = (privateJwk) => { const key = createPrivateKey({ key: privateJwk, format: 'jwk' }); return async (data) => base64url.encode(sign(null, Buffer.from(data), key)); };
export const verifierFor = (publicJwk) => { const key = createPublicKey({ key: publicJwk, format: 'jwk' }); return async (data, sig) => verify(null, Buffer.from(data), key, base64url.decode(sig)); };
export const issuer = (privateJwk) => new SDJwtVcInstance({ signer: signerFor(privateJwk), signAlg: 'EdDSA', hasher: digest, hashAlg: 'sha-256', saltGenerator: generateSalt });
export const holder = (privateJwk) => new SDJwtVcInstance({ hasher: digest, saltGenerator: generateSalt, kbSigner: signerFor(privateJwk), kbSignAlg: 'EdDSA' });
export const verifierOf = (publicJwk, withKb = false) => new SDJwtVcInstance({
    verifier: verifierFor(publicJwk), hasher: digest,
    ...(withKb ? { kbVerifier: (data, sig, payload) => verify(null, Buffer.from(data), createPublicKey({ key: payload.cnf.jwk, format: 'jwk' }), base64url.decode(sig)) } : {}),
});
export function issuerOf(sdjwt) { return JSON.parse(Buffer.from(base64url.decode(sdjwt.split('~')[0].split('.')[1])).toString()).iss; }

// a minimal PDF: one page, Helvetica, one line per entry. pdftotext reads it.
export function makePdf(lines) {
    const esc = (s) => s.replace(/\\/g, '\\\\').replace(/\(/g, '\\(').replace(/\)/g, '\\)');
    const content = ['BT', '/F1 11 Tf', '14 TL', '72 740 Td', ...lines.map((l, i) => `${i ? 'T* ' : ''}(${esc(l)}) Tj`), 'ET'].join('\n');
    const objs = [
        '<< /Type /Catalog /Pages 2 0 R >>',
        '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
        '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>',
        `<< /Length ${Buffer.byteLength(content)} >>\nstream\n${content}\nendstream`,
        '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',
    ];
    let out = '%PDF-1.4\n'; const offsets = [];
    objs.forEach((o, i) => { offsets.push(Buffer.byteLength(out)); out += `${i + 1} 0 obj\n${o}\nendobj\n`; });
    const xref = Buffer.byteLength(out);
    out += `xref\n0 ${objs.length + 1}\n0000000000 65535 f \n` + offsets.map((o) => String(o).padStart(10, '0') + ' 00000 n \n').join('');
    out += `trailer\n<< /Size ${objs.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
    return Buffer.from(out, 'latin1');
}
