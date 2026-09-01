/**
 * Passkey signing for the review gate: the person's half of the trust chain.
 *
 * A site key says "this organization published this"; a passkey says "this
 * person was physically present and verified" — the credential lives in the
 * platform authenticator, never leaves it, and every signature demands user
 * verification (Touch ID, Face ID). For the sign-off, whose entire meaning
 * is that a human stood here, that is the semantically right key.
 *
 * WebAuthn signs authenticatorData || sha256(clientDataJSON), with the
 * challenge embedded in clientDataJSON. We set the challenge to the sha256
 * of the exact judgements being signed (same canonical recipe as the HCS
 * anchor), so the assertion is cryptographically bound to this review's
 * content, and the userVerification flag inside authenticatorData is the
 * proof of presence.
 *
 * Two halves, because the assertion can only be born in a browser:
 *   - passkeyPageScript(store): browser side; hooks the gate's
 *     'proveml:signing' event, computes the challenge, calls
 *     navigator.credentials.get, and rides the assertion along in the POST.
 *   - passkeySigner(opts): server side; verifies the assertion against the
 *     enrolled credential and the recomputed challenge, refuses without it.
 *
 * Enrollment is one-time and separate (bin/passkey-enroll.mjs); the store is
 * ~/.config/proveml/passkey.json. rpId must be a domain — WebAuthn refuses
 * IP origins — so the gate is addressed as localhost.
 */

import { createHash } from 'crypto';
import { readFileSync, existsSync } from 'fs';
import { homedir } from 'os';
import { join } from 'path';
import { verifyAuthenticationResponse } from '@simplewebauthn/server';

export const PASSKEY_STORE = join(homedir(), '.config', 'proveml', 'passkey.json');

/** The canonical string a review's challenge is computed over (same recipe as the HCS anchor). */
export function reviewCanonical(judgements) {
    const ids = Object.keys(judgements || {}).sort();
    return JSON.stringify(ids.map((id) => [id, judgements[id].verdict, judgements[id].at]));
}

/** The WebAuthn challenge for a review: base64url(sha256(canonical)). */
export function reviewChallenge(judgements) {
    return createHash('sha256').update(reviewCanonical(judgements)).digest('base64url');
}

export function isEnrolled(storePath = PASSKEY_STORE) {
    return existsSync(storePath);
}

export function loadEnrollment(storePath = PASSKEY_STORE) {
    if (!isEnrolled(storePath)) throw new Error(`no passkey enrolled: run bin/passkey-enroll.mjs first (${storePath})`);
    return JSON.parse(readFileSync(storePath, 'utf8'));
}

/**
 * Browser half: a script for review-flow's pageScript option. Computes the
 * same challenge the server will recompute, asks the authenticator for an
 * assertion over it, and attaches it to the POST via the signing event.
 */
export function passkeyPageScript(storePath = PASSKEY_STORE) {
    const { credential } = loadEnrollment(storePath);
    return `
(() => {
    const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');
    const fromB64u = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));
    document.addEventListener('proveml:signing', (e) => {
        e.detail.wait = (async () => {
            const j = e.detail.review.judgements;
            const ids = Object.keys(j).sort();
            const canonical = JSON.stringify(ids.map((id) => [id, j[id].verdict, j[id].at]));
            const challenge = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonical));
            const cred = await navigator.credentials.get({ publicKey: {
                challenge,
                rpId: ${JSON.stringify(loadEnrollment(storePath).rpId)},
                allowCredentials: [{ type: 'public-key', id: fromB64u(${JSON.stringify(credential.id)}) }],
                userVerification: 'required',
            } });
            e.detail.extra.passkey = {
                id: cred.id,
                rawId: b64u(cred.rawId),
                type: cred.type,
                response: {
                    clientDataJSON: b64u(cred.response.clientDataJSON),
                    authenticatorData: b64u(cred.response.authenticatorData),
                    signature: b64u(cred.response.signature),
                    userHandle: cred.response.userHandle ? b64u(cred.response.userHandle) : null,
                },
            };
        })();
    });
})();`;
}

/**
 * Server half: the signer adapter. Refuses a review without a valid
 * assertion; on success the raw assertion is replaced by an attestation the
 * review carries durably. A signer attests, it never judges.
 */
export function passkeySigner({ storePath = PASSKEY_STORE, expectedOrigin } = {}) {
    const enrollment = loadEnrollment(storePath);
    return async (review) => {
        const assertion = review.passkey;
        if (!assertion) throw new Error('passkey signer: no assertion travelled with the review.');
        const expectedChallenge = reviewChallenge(review.judgements);
        const verification = await verifyAuthenticationResponse({
            response: assertion,
            expectedChallenge,
            expectedOrigin: expectedOrigin || enrollment.origin,
            expectedRPID: enrollment.rpId,
            credential: {
                id: enrollment.credential.id,
                publicKey: Buffer.from(enrollment.credential.publicKey, 'base64url'),
                counter: enrollment.credential.counter ?? 0,
            },
            requireUserVerification: true,
        });
        if (!verification.verified) throw new Error('passkey signer: assertion did not verify.');
        const { passkey, ...rest } = review;
        return {
            ...rest,
            attestation: {
                kind: 'passkey',
                credentialId: enrollment.credential.id,
                rpId: enrollment.rpId,
                userVerified: true,
                challenge: expectedChallenge,
                signedBy: enrollment.user?.name,
                at: new Date().toISOString(),
            },
        };
    };
}
