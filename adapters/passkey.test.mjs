import { reviewCanonical, reviewChallenge, passkeySigner, passkeyPageScript, isEnrolled } from './passkey.mjs';
import { writeFileSync, mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

let passed = 0, failed = 0;
const assert = (name, c, d = '') => c ? (passed++, console.log(`  ok ${name}`)) : (failed++, console.error(`  FAIL ${name} ${d}`));
const throwsAsync = async (fn, re) => { try { await fn(); return false; } catch (e) { return re.test(String(e.message)); } };

console.log('\n=== passkey: the challenge is the review ===');
{
    const j = { b: { verdict: 'fair', at: '2026-09-01T10:00:00Z' }, a: { verdict: 'flag', at: '2026-09-01T09:00:00Z' } };
    assert('canonical sorts by id', reviewCanonical(j).startsWith('[["a"'));
    assert('challenge is deterministic', reviewChallenge(j) === reviewChallenge({ ...j }));
    assert('any verdict change changes the challenge', reviewChallenge(j) !== reviewChallenge({ ...j, a: { ...j.a, verdict: 'fair' } }));
}

console.log('\n=== passkey: fail closed without a valid assertion ===');
{
    const dir = mkdtempSync(join(tmpdir(), 'pk-'));
    const store = join(dir, 'passkey.json');
    assert('not enrolled reads as not enrolled', isEnrolled(store) === false);
    writeFileSync(store, JSON.stringify({
        rpId: 'localhost', origin: 'http://localhost:3960', user: { name: 'Test' },
        credential: { id: 'AAAA', publicKey: Buffer.from([1, 2, 3]).toString('base64url'), counter: 0 },
    }));
    const signer = passkeySigner({ storePath: store });
    assert('a review without an assertion is refused', await throwsAsync(() => signer({ judgements: {} }), /no assertion/));
    assert('a garbage assertion is refused, not accepted', await throwsAsync(() => signer({
        judgements: {},
        passkey: { id: 'AAAA', rawId: 'AAAA', type: 'public-key', response: { clientDataJSON: 'AAAA', authenticatorData: 'AAAA', signature: 'AAAA', userHandle: null } },
    }), /./));
    const script = passkeyPageScript(store);
    assert('the browser half listens on the signing event and demands user verification',
        script.includes('proveml:signing') && script.includes("userVerification: 'required'") && script.includes('AAAA'));
}

console.log(`\n${passed} passed, ${failed} failed\n`);
process.exit(failed > 0 ? 1 : 0);
