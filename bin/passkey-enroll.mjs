#!/usr/bin/env node
/**
 * One-time passkey enrollment for the review gate.
 *
 * Serves a single page on http://localhost:3970/ that creates a platform
 * passkey (rpId localhost, user verification required), verifies the
 * registration server-side, and stores the credential's public half in
 * ~/.config/proveml/passkey.json. The private half never leaves your
 * authenticator; deleting the store only forgets which passkey to expect.
 *
 * Usage: node bin/passkey-enroll.mjs [--name "Your Name"]
 */
import { createServer } from 'http';
import { randomBytes } from 'crypto';
import { writeFileSync, mkdirSync } from 'fs';
import { dirname } from 'path';
import { exec } from 'child_process';
import { verifyRegistrationResponse } from '@simplewebauthn/server';
import { PASSKEY_STORE } from '../adapters/passkey.mjs';

const args = process.argv.slice(2);
const name = args.find((_, i) => args[i - 1] === '--name') || 'Reviewer';
const RP_ID = 'localhost';
const PORT = 3970;
const ORIGIN = `http://localhost:${PORT}`;
const challenge = randomBytes(32).toString('base64url');

const PAGE = `<!doctype html><meta charset="utf-8"><title>Enroll passkey</title>
<body style="font-family:system-ui;max-width:34rem;margin:4rem auto;line-height:1.6">
<h1 style="font-size:1.3rem">Enroll your passkey for the review gate</h1>
<p>One touch creates a passkey bound to <code>localhost</code>. The private key stays in your authenticator; only the public half is stored, at <code>~/.config/proveml/passkey.json</code>.</p>
<button id="go" style="font-size:1rem;padding:.5rem 1.2rem">Create passkey</button>
<p id="out"></p>
<script>
const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');
const fromB64u = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));
document.getElementById('go').onclick = async () => {
    const out = document.getElementById('out');
    try {
        const cred = await navigator.credentials.create({ publicKey: {
            challenge: fromB64u(${JSON.stringify(challenge)}),
            rp: { id: ${JSON.stringify(RP_ID)}, name: 'proveml review gate' },
            user: { id: crypto.getRandomValues(new Uint8Array(16)), name: ${JSON.stringify(name)}, displayName: ${JSON.stringify(name)} },
            pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -8 }, { type: 'public-key', alg: -257 }],
            authenticatorSelection: { userVerification: 'required', residentKey: 'preferred' },
        } });
        const body = {
            id: cred.id, rawId: b64u(cred.rawId), type: cred.type,
            response: {
                clientDataJSON: b64u(cred.response.clientDataJSON),
                attestationObject: b64u(cred.response.attestationObject),
                transports: cred.response.getTransports ? cred.response.getTransports() : [],
            },
        };
        const r = await fetch('/register', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
        out.textContent = r.ok ? 'Enrolled. You can close this tab.' : 'Enrollment failed: ' + await r.text();
    } catch (e) { out.textContent = 'Failed: ' + e; }
};
</script>`;

const server = createServer((req, res) => {
    if (req.method === 'GET') { res.setHeader('content-type', 'text/html; charset=utf-8'); res.end(PAGE); return; }
    if (req.method === 'POST' && req.url === '/register') {
        let body = '';
        req.on('data', (c) => { body += c; });
        req.on('end', async () => {
            try {
                const response = JSON.parse(body);
                const verification = await verifyRegistrationResponse({
                    response,
                    expectedChallenge: challenge,
                    expectedOrigin: ORIGIN,
                    expectedRPID: RP_ID,
                    requireUserVerification: true,
                });
                if (!verification.verified) throw new Error('registration did not verify');
                const { credential } = verification.registrationInfo;
                mkdirSync(dirname(PASSKEY_STORE), { recursive: true });
                writeFileSync(PASSKEY_STORE, JSON.stringify({
                    rpId: RP_ID,
                    origin: ORIGIN,
                    user: { name },
                    enrolledAt: new Date().toISOString(),
                    credential: {
                        id: credential.id,
                        publicKey: Buffer.from(credential.publicKey).toString('base64url'),
                        counter: credential.counter,
                        transports: credential.transports || [],
                    },
                }, null, 2) + '\n');
                res.end('ok');
                console.log(`enrolled "${name}" (${credential.id.slice(0, 12)}…) -> ${PASSKEY_STORE}`);
                server.close();
            } catch (error) {
                res.statusCode = 400; res.end(String(error?.message || error));
                console.error('enrollment failed:', error?.message || error);
            }
        });
        return;
    }
    res.statusCode = 404; res.end();
});

server.listen(PORT, '127.0.0.1', () => {
    console.log(`enroll at ${ORIGIN}/`);
    exec(`open ${ORIGIN}/`, () => {});
});
