import {
    generateSiteKey, didDocument, didWebUrl, issueSourceCredential,
    verifySourceCredential, discoverCredentialUrl, VCT,
} from './source-vc.mjs';
import { verifyInclusion, quoteEvidence } from 'proveml/manifest';

let passed = 0, failed = 0;
const assert = (name, c, d = '') => c ? (passed++, console.log(`  ok ${name}`)) : (failed++, console.error(`  FAIL ${name} ${d}`));

const PAGE = `
<html><head>
<link rel="proveml-credential" href="/blog/why-we-sign.vc.jwt">
<title>Why we sign our posts</title></head><body>
<h1>Why we sign our posts</h1>
<p>Trust is a track record, not a promise.</p>
<p>Every post on this site carries a credential over its manifest root.</p>
</body></html>`;

const DID = 'did:web:abovebeyond.ai';
const URL_ = 'https://abovebeyond.ai/blog/why-we-sign/';

console.log('\n=== source-vc: publisher signs, anyone verifies ===');
{
    const { publicJwk, privateJwk } = await generateSiteKey();
    const doc = didDocument(DID, publicJwk);
    assert('did:web document serves the public key', doc.id === DID && doc.verificationMethod[0].publicKeyJwk.crv === 'Ed25519');
    assert('did:web url convention', didWebUrl(DID) === 'https://abovebeyond.ai/.well-known/did.json'
        && didWebUrl('did:web:example.com:blog:keys') === 'https://example.com/blog/keys/did.json');

    const { jwt, root } = await issueSourceCredential({ raw: PAGE, url: URL_, issuerDid: DID, privateJwk });
    assert('credential discovery from the page link', discoverCredentialUrl(PAGE, URL_) === 'https://abovebeyond.ai/blog/why-we-sign.vc.jwt');

    const resolveDid = async (did) => { if (did !== DID) throw new Error('unknown did'); return doc; };

    const ok = await verifySourceCredential({ jwt, raw: PAGE, expectedUrl: URL_, resolveDid });
    assert('the honest path verifies end to end', ok.verified === true && ok.issuer === DID && ok.root === root, JSON.stringify(ok.checks));

    // The whole chain: publisher signature -> signed root -> inclusion proof -> quote.
    const ev = quoteEvidence(ok.manifest, 'Trust is a track record, not a promise.');
    assert('a quote proves into the SIGNED root', ev.root === ok.root && verifyInclusion(ok.root, ok.manifest.leaves[ev.leafIndex].text, ev.proof));

    const tampered = await verifySourceCredential({ jwt, raw: PAGE.replace('track record', 'vibe'), expectedUrl: URL_, resolveDid });
    assert('tampered content fails on rootMatches, and the failure names itself', tampered.verified === false && tampered.checks.signature === true && tampered.checks.rootMatches === false);

    const { privateJwk: wrongKey } = await generateSiteKey();
    const forged = await issueSourceCredential({ raw: PAGE, url: URL_, issuerDid: DID, privateJwk: wrongKey });
    const bad = await verifySourceCredential({ jwt: forged.jwt, raw: PAGE, resolveDid });
    assert('a forged signature fails on signature', bad.verified === false && bad.checks.signature === false);

    const wrongUrl = await verifySourceCredential({ jwt, raw: PAGE, expectedUrl: 'https://evil.example/', resolveDid });
    assert('a replayed credential fails on urlMatches', wrongUrl.verified === false && wrongUrl.checks.urlMatches === false);

    assert('vct is the versioned contract', VCT === 'urn:proveml:source-manifest:1');
}

console.log(`\n${passed} passed, ${failed} failed\n`);
process.exit(failed > 0 ? 1 : 0);
