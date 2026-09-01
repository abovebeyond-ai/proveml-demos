/**
 * Source credentials: a publisher vouches for its own content.
 *
 * The snapshot mode proves "this is what we saw"; this adapter upgrades a
 * cooperative source to "this is what we SAID". The publisher computes the
 * proveml manifest of a page and issues a credential over its ROOT — an
 * SD-JWT VC (with zero disclosures it is a plain JWS, which keeps verifiers
 * trivial), Ed25519, issuer a did:web whose keys live at the publisher's own
 * /.well-known/did.json. The consumer fetches the page, rebuilds the manifest
 * under the same versioned contract, verifies the signature against the
 * publisher's published key, and accepts the source as publisher-signed only
 * when the recomputed root equals the signed root.
 *
 * From there the whole chain is checkable by anyone: publisher key -> signed
 * root -> inclusion proof -> leaf -> quote -> store value -> claim on screen.
 *
 * Discovery convention: the page links its credential as
 *   <link rel="proveml-credential" href=".../<slug>.vc.jwt">
 *
 * vct: urn:proveml:source-manifest:1
 */

import { SignJWT, jwtVerify, importJWK, generateKeyPair, exportJWK } from 'jose';
import { buildManifest, CANONICALIZATION, SEGMENTATION } from 'proveml/manifest';

export const VCT = 'urn:proveml:source-manifest:1';

/** One-time publisher setup: an Ed25519 pair as JWKs. Keep the private half out of the repo. */
export async function generateSiteKey() {
    const { publicKey, privateKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519', extractable: true });
    return { publicJwk: await exportJWK(publicKey), privateJwk: await exportJWK(privateKey) };
}

/** The did:web document to serve at /.well-known/did.json. */
export function didDocument(did, publicJwk) {
    return {
        '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/suites/jws-2020/v1'],
        id: did,
        verificationMethod: [{
            id: `${did}#key-1`,
            type: 'JsonWebKey2020',
            controller: did,
            publicKeyJwk: publicJwk,
        }],
        assertionMethod: [`${did}#key-1`],
    };
}

/** did:web:example.com[:path:segments] -> the URL of its did.json. */
export function didWebUrl(did) {
    const m = /^did:web:(.+)$/.exec(did);
    if (!m) throw new Error(`not a did:web: ${did}`);
    const parts = m[1].split(':').map(decodeURIComponent);
    const host = parts.shift();
    return parts.length === 0
        ? `https://${host}/.well-known/did.json`
        : `https://${host}/${parts.join('/')}/did.json`;
}

export async function resolveDidWeb(did, { fetchImpl = fetch } = {}) {
    const res = await fetchImpl(didWebUrl(did));
    if (!res.ok) throw new Error(`did:web resolution failed: ${res.status} for ${didWebUrl(did)}`);
    return await res.json();
}

/**
 * Publisher side: manifest the content, sign its root.
 * Returns { jwt, manifest, root } — serve the jwt next to the page.
 */
export async function issueSourceCredential({ raw, html = true, url, issuerDid, privateJwk }) {
    const manifest = buildManifest(raw, { html, source: url });
    const key = await importJWK(privateJwk, 'EdDSA');
    const jwt = await new SignJWT({
        vct: VCT,
        url,
        root: manifest.root,
        canonicalization: manifest.canonicalization,
        segmentation: manifest.segmentation,
        leafCount: manifest.leaves.length,
    })
        .setProtectedHeader({ alg: 'EdDSA', typ: 'vc+sd-jwt', kid: `${issuerDid}#key-1` })
        .setIssuer(issuerDid)
        .setIssuedAt()
        .sign(key);
    return { jwt, manifest, root: manifest.root };
}

/** Find the credential link in a page. */
export function discoverCredentialUrl(rawHtml, baseUrl) {
    const m = /<link\s[^>]*rel=["']proveml-credential["'][^>]*href=["']([^"']+)["']/i.exec(rawHtml)
        || /<link\s[^>]*href=["']([^"']+)["'][^>]*rel=["']proveml-credential["']/i.exec(rawHtml);
    if (!m) return null;
    return new URL(m[1], baseUrl).toString();
}

/**
 * Consumer side: verify the signature against the publisher's did:web key,
 * rebuild the manifest from the fetched content, and demand the roots match.
 * `verified` is true only when signature, contract, root and (if given) url
 * all hold; the parts are reported so a failure names itself.
 */
export async function verifySourceCredential({ jwt, raw, html = true, expectedUrl, resolveDid = resolveDidWeb }) {
    const [, payloadB64] = jwt.split('.');
    const unverified = JSON.parse(Buffer.from(payloadB64, 'base64url').toString());
    const issuer = unverified.iss;
    if (!issuer) throw new Error('credential has no issuer');

    const doc = await resolveDid(issuer);
    const method = (doc.verificationMethod || []).find((m) => m.id === `${issuer}#key-1`) || (doc.verificationMethod || [])[0];
    if (!method?.publicKeyJwk) throw new Error(`no usable key in DID document for ${issuer}`);
    const key = await importJWK(method.publicKeyJwk, 'EdDSA');

    let payload = null, signature = false;
    try {
        ({ payload } = await jwtVerify(jwt, key, { issuer }));
        signature = true;
    } catch {
        payload = unverified; // report against the claimed payload, verified stays false
    }

    const contract = payload.vct === VCT
        && payload.canonicalization === CANONICALIZATION
        && payload.segmentation === SEGMENTATION;

    const manifest = buildManifest(raw, { html, source: payload.url });
    const rootMatches = signature && contract && manifest.root === payload.root;
    const urlMatches = expectedUrl === undefined || payload.url === expectedUrl;

    return {
        verified: signature && contract && rootMatches && urlMatches,
        checks: { signature, contract, rootMatches, urlMatches },
        issuer,
        url: payload.url,
        root: payload.root,
        issuedAt: payload.iat ? new Date(payload.iat * 1000).toISOString() : undefined,
        manifest,
    };
}
