import { generateSiteKey, didDocument } from './source-vc.mjs';
import { issueReviewCredential, verifyReviewCredential, reviewRoot, REVIEW_VCT } from './review-vc.mjs';

let passed = 0, failed = 0;
const assert = (name, c, d = '') => c ? (passed++, console.log(`  ok ${name}`)) : (failed++, console.error(`  FAIL ${name} ${d}`));

const DID = 'did:web:reviewer.example';
const review = {
    exported: '2026-09-01T21:03:30.319Z',
    judgements: {
        aaaa1111: { verdict: 'fair', src: 'order', field: 'number', at: '2026-09-01T21:02:57Z' },
        bbbb2222: { verdict: 'flag', src: 'carrier', field: 'shippedOn', at: '2026-09-01T21:03:13Z' },
    },
};
const outputRoot = 'c'.repeat(64);

console.log('\n=== review-vc: the reviewer signs what they verified ===');
{
    const { publicJwk, privateJwk } = await generateSiteKey();
    const doc = didDocument(DID, publicJwk);
    const resolveDid = async (did) => { if (did !== DID) throw new Error('unknown did'); return doc; };

    const { jwt, root } = await issueReviewCredential({ review, outputRoot, sources: { order: { root: 'd'.repeat(64), signedBy: 'did:web:shop.example' } }, issuerDid: DID, privateJwk });
    assert('root follows the shared recipe', root === reviewRoot(review.judgements, outputRoot));

    const ok = await verifyReviewCredential({ jwt, review, outputRoot, resolveDid });
    assert('the honest path verifies end to end', ok.verified === true && ok.issuer === DID && ok.reviewRoot === root, JSON.stringify(ok.checks));
    assert('source roots ride the credential', ok.sources.order.signedBy === 'did:web:shop.example');

    const flipped = JSON.parse(JSON.stringify(review));
    flipped.judgements.bbbb2222.verdict = 'fair';
    const tampered = await verifyReviewCredential({ jwt, review: flipped, outputRoot, resolveDid });
    assert('a flipped judgement fails on rootMatches', tampered.verified === false && tampered.checks.signature === true && tampered.checks.rootMatches === false);

    const movedOutput = await verifyReviewCredential({ jwt, review, outputRoot: 'e'.repeat(64), resolveDid });
    assert('a changed output fails on rootMatches', movedOutput.verified === false && movedOutput.checks.rootMatches === false);

    const { privateJwk: wrongKey } = await generateSiteKey();
    const forged = await issueReviewCredential({ review, outputRoot, issuerDid: DID, privateJwk: wrongKey });
    const bad = await verifyReviewCredential({ jwt: forged.jwt, review, outputRoot, resolveDid });
    assert('a forged signature fails on signature', bad.verified === false && bad.checks.signature === false);

    assert('vct is the versioned contract', REVIEW_VCT === 'urn:proveml:review:1');
}

console.log(`\n${passed} passed, ${failed} failed\n`);
process.exit(failed > 0 ? 1 : 0);
