/**
 * A Person Identification Data credential as a ProveML fact source.
 *
 * Format and names are the EU Digital Identity Wallet's: SD-JWT VC with
 * vct urn:eudi:pid:1 and the claim names of the PID Rulebook (v1.7, July
 * 2026). The credential itself is issued here by a demo "PID Provider" key,
 * because the EU reference issuer needs a browser step; everything after
 * issuance is the real protocol: the holder discloses a subset with a
 * key-binding JWT over the verifier's nonce, and the verifier checks the
 * issuer signature, the key binding, and the digests of the disclosed claims
 * with the OpenWallet Foundation's sd-jwt library.
 *
 * Two rules of the PID shape carry through to the fact store. The PID has no
 * age attribute (removed in Rulebook v1.1); age is derived by the verifier,
 * which for ProveML means in this adapter, as a fact with its own proof line,
 * never inside the verifier. And an undisclosed claim is simply not in the
 * store: a sentence about it is unverifiable, not wrong.
 */
import { createHash, createPublicKey, sign, verify, generateKeyPairSync, randomUUID } from 'crypto';
import { SDJwtVcInstance } from '@sd-jwt/sd-jwt-vc';
import { digest, generateSalt } from '@owf/crypto';
import * as jose from 'jose';

const EU = new Set(['AT','BE','BG','HR','CY','CZ','DK','EE','FI','FR','DE','GR','HU','IE','IT','LV','LT','LU','MT','NL','PL','PT','RO','SK','SI','ES','SE']);

const signer = (key) => (data) => jose.base64url.encode(sign('sha256', Buffer.from(data), { key, dsaEncoding: 'ieee-p1363' }));
const verifierFor = (key) => (data, sig) => verify('sha256', Buffer.from(data), { key, dsaEncoding: 'ieee-p1363' }, jose.base64url.decode(sig));

/** The demo PID Provider and the holder's wallet key, created at startup. */
export async function setupIdentity() {
    const issuer = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const holder = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const holderJwk = await jose.exportJWK(holder.publicKey);
    const issuerJwk = await jose.exportJWK(issuer.publicKey);
    const now = Math.floor(Date.now() / 1000);

    // A fictional person; the shape is the Rulebook's.
    const claims = {
        family_name: 'Vandenberghe',
        given_name: 'Elke',
        birthdate: '1991-06-03',
        place_of_birth: { locality: 'Gent', country: 'BE' },
        nationalities: ['BE'],
        address: { street_address: 'Korenmarkt 12', locality: 'Gent', postal_code: '9000', country: 'BE' },
        issuing_authority: 'Demo PID Provider',
        issuing_country: 'BE',
        date_of_expiry: '2031-06-03',
        document_number: 'PID-DEMO-0001',
    };
    const disclosable = ['family_name', 'given_name', 'birthdate', 'place_of_birth', 'nationalities', 'address', 'date_of_expiry', 'document_number'];

    const issuing = new SDJwtVcInstance({ signer: signer(issuer.privateKey), signAlg: 'ES256', hasher: digest, hashAlg: 'sha-256', saltGenerator: generateSalt });
    const credential = await issuing.issue(
        { vct: 'urn:eudi:pid:1', iss: 'https://pid-provider.demo.abovebeyond.ai', iat: now, nbf: now, exp: now + 365 * 86400, cnf: { jwk: holderJwk }, ...claims },
        { _sd: disclosable },
    );

    return { issuer, issuerJwk, holder, holderJwk, credential, claims, disclosable, sub: randomUUID().slice(0, 8) };
}

/**
 * Present a subset of the claims (the wallet's side) and verify the
 * presentation (the relying party's side). Returns the verification, the
 * disclosed claims, and a ProveML adapter over them.
 */
export async function presentAndVerify(id, disclose, nonce) {
    const now = Math.floor(Date.now() / 1000);
    const wallet = new SDJwtVcInstance({ hasher: digest, saltGenerator: generateSalt, kbSigner: signer(id.holder.privateKey), kbSignAlg: 'ES256' });
    const frame = Object.fromEntries(disclose.map(c => [c, true]));
    const presentation = await wallet.present(id.credential, frame, { kb: { payload: { aud: 'https://bank.demo.abovebeyond.ai', nonce, iat: now } } });

    const rp = new SDJwtVcInstance({
        verifier: verifierFor(id.issuer.publicKey), hasher: digest,
        kbVerifier: (data, sig, payload) => verify('sha256', Buffer.from(data), { key: createPublicKey({ key: payload.cnf.jwk, format: 'jwk' }), dsaEncoding: 'ieee-p1363' }, jose.base64url.decode(sig)),
    });
    let status = 'verified', error = null, payload = null;
    try {
        ({ payload } = await rp.verify(presentation, { keyBindingNonce: nonce }));
    } catch (e) { status = 'error'; error = e.message; }
    if (payload && payload.exp && payload.exp < now) status = 'expired';

    const digestHex = createHash('sha256').update(presentation).digest('hex');
    const P = `person:${id.sub}`;
    const facts = {}, proofs = {};
    const put = (k, v, proof) => { facts[`${P}.${k}`] = v; proofs[`${P}.${k}`] = proof; };
    const fromCred = `disclosed claim in the presentation, issuer signature ${status}, presentation sha256 ${digestHex.slice(0, 16)}…`;
    if (payload) {
        if (payload.given_name !== undefined && payload.family_name !== undefined) put('name', `${payload.given_name} ${payload.family_name}`, fromCred);
        for (const k of ['family_name', 'given_name', 'birthdate', 'date_of_expiry', 'document_number']) if (payload[k] !== undefined) put(k, payload[k], fromCred);
        if (payload.nationalities) {
            put('nationalities', payload.nationalities.join(','), fromCred);
            put('euNational', payload.nationalities.some(n => EU.has(n)) ? 'yes' : 'no', 'derived by the relying party from nationalities against the EU member-state list');
        }
        if (payload.place_of_birth) for (const [k, v] of Object.entries(payload.place_of_birth)) put(`place_of_birth.${k}`, v, fromCred);
        if (payload.address) for (const [k, v] of Object.entries(payload.address)) put(`address.${k}`, v, fromCred);
        if (payload.birthdate) {
            const b = new Date(payload.birthdate), t = new Date();
            let age = t.getUTCFullYear() - b.getUTCFullYear();
            if (t.getUTCMonth() < b.getUTCMonth() || (t.getUTCMonth() === b.getUTCMonth() && t.getUTCDate() < b.getUTCDate())) age--;
            put('ageYears', age, `derived by the relying party from birthdate on ${t.toISOString().slice(0, 10)}; the PID carries no age attribute`);
        }
        put('issuing_authority', payload.issuing_authority, 'always-disclosed metadata claim');
        put('issuing_country', payload.issuing_country, 'always-disclosed metadata claim');
    }

    const adapter = {
        subjects() { return Object.entries(facts).filter(([k]) => k.endsWith('.name')).map(([k, v]) => ({ path: k.slice(0, -5), name: String(v) })); },
        resolve(path) {
            if (!(path in facts)) return { found: false };
            return { found: true, value: facts[path], trust: { status, backend: 'sd-jwt-vc', issuer: 'https://pid-provider.demo.abovebeyond.ai', proofRef: `sha256:${digestHex}`, checkedAt: new Date().toISOString() } };
        },
    };
    return { presentation, status, error, disclosed: Object.keys(payload || {}).filter(k => disclose.includes(k)), facts, proofs, adapter, digestHex, entity: P };
}

/** The verification result, issued as a credential of its own. */
export async function attestVerdict(id, { markup, verification, digestHex, thresholds }) {
    const now = Math.floor(Date.now() / 1000);
    const rpKey = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const attesting = new SDJwtVcInstance({ signer: signer(rpKey.privateKey), signAlg: 'ES256', hasher: digest, hashAlg: 'sha-256', saltGenerator: generateSalt });
    const payload = {
        vct: 'urn:proveml:verification:1', iss: 'https://bank.demo.abovebeyond.ai', iat: now,
        presentation_sha256: digestHex,
        report_sha256: createHash('sha256').update(markup).digest('hex'),
        registry_sha256: createHash('sha256').update(JSON.stringify(thresholds)).digest('hex'),
        claims_total: verification.total, claims_verified: verification.verified,
        coverage: verification.coverage.rate,
        verifier: 'proveml@0.3.0',
    };
    const vc = await attesting.issue(payload, { _sd: [] });
    return { vc, payload, verifierJwk: await jose.exportJWK(rpKey.publicKey) };
}
