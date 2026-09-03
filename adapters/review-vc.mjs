/**
 * Review credentials: the reviewer vouches for what they verified.
 *
 * The mirror of source-vc. Inbound, a publisher signs a source's manifest
 * root; outbound, the reviewer signs the REVIEW root: the judgements they
 * handed back, with the output's own root folded in as the first leaf, and
 * the source roots the readings stood on carried in the payload. Change a
 * judgement, a word of the output, or a source, and the recomputed root
 * walks away from the signature.
 *
 * The verifier recomputes the review root from the review JSON and the
 * output root under the same recipe the page uses (proveml's reviewRootOf;
 * the recipe is restated here for older packages and must match it), then
 * checks the signature against the reviewer's did:web key.
 *
 * vct: urn:proveml:review:1
 */

import { SignJWT, jwtVerify, importJWK } from 'jose';
import { buildManifest } from 'proveml/manifest';
import { resolveDidWeb } from './source-vc.mjs';

export const REVIEW_VCT = 'urn:proveml:review:1';

/** The one recipe: output root is leaf one, then judgements sorted by id. */
export function reviewRoot(judgements, outputRoot) {
    const entries = Object.entries(judgements).sort(([a], [b]) => (a < b ? -1 : 1));
    const lines = [`output ${outputRoot}`, ...entries.map(([id, v]) => `${id} ${v.src}.${v.field} ${v.verdict} ${v.at}`)];
    return buildManifest(lines.join('\n'), { html: false }).root;
}

/**
 * Reviewer side: sign the review root.
 * `sources` is { id: { root, signedBy? } } — carried, not hashed again: the
 * readings inside the review are already keyed to those blocks.
 */
export async function issueReviewCredential({ review, outputRoot, sources = {}, issuerDid, privateJwk }) {
    if (!review || !review.judgements) throw new Error('issueReviewCredential: expected a review with judgements.');
    const root = reviewRoot(review.judgements, outputRoot);
    const verdicts = Object.values(review.judgements);
    const key = await importJWK(privateJwk, 'EdDSA');
    const jwt = await new SignJWT({
        vct: REVIEW_VCT,
        reviewRoot: root,
        outputRoot,
        sources,
        judgements: { total: verdicts.length, no: verdicts.filter((v) => v.verdict !== 'fair').length },
        exported: review.exported,
    })
        .setProtectedHeader({ alg: 'EdDSA', typ: 'vc+sd-jwt', kid: `${issuerDid}#key-1` })
        .setIssuer(issuerDid)
        .setIssuedAt()
        .sign(key);
    return { jwt, root };
}

/**
 * Anyone's side: resolve the reviewer's key, verify the signature, recompute
 * the review root from the review JSON and the output root, and demand they
 * match. Every check is reported, so a failure names itself.
 */
export async function verifyReviewCredential({ jwt, review, outputRoot, resolveDid = resolveDidWeb }) {
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
        payload = unverified;
    }

    const contract = payload.vct === REVIEW_VCT;
    const recomputed = reviewRoot(review.judgements, outputRoot);
    const rootMatches = signature && contract && recomputed === payload.reviewRoot && outputRoot === payload.outputRoot;

    return {
        verified: signature && contract && rootMatches,
        checks: { signature, contract, rootMatches },
        issuer,
        reviewRoot: payload.reviewRoot,
        outputRoot: payload.outputRoot,
        sources: payload.sources || {},
        issuedAt: payload.iat ? new Date(payload.iat * 1000).toISOString() : undefined,
    };
}
