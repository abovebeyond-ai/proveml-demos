// The source checks, as the gateway runs them before it trusts a fact, and as
// a stranger reruns them afterwards. One JSON object per call, ok true or
// false with the reason. Nothing here needs the gateway.
//   mapping <file.sdjwt> <pdf_sha256>          the clerk's signature over the extraction, for this PDF
//   credential <file.sdjwt>                    an issuer's credential (vetting)
//   presentation <file.sdjwt> <nonce> <aud>    a holder's presentation, key-bound to this nonce
import { readFileSync } from 'node:fs';
import { resolveDid, verifierOf, issuerOf } from './lib.mjs';

const [kind, file, a, b] = process.argv.slice(2);
const out = (o) => { console.log(JSON.stringify(o)); process.exit(o.ok ? 0 : 1); };
try {
    const sdjwt = readFileSync(file, 'utf8').trim();
    const iss = issuerOf(sdjwt);
    const { jwk, via } = await resolveDid(iss);
    if (kind === 'mapping') {
        const { payload } = await verifierOf(jwk).verify(sdjwt);
        if (payload.vct !== 'urn:proveml:extraction-mapping:1') out({ ok: false, why: 'not a mapping credential' });
        if (payload.pdf_sha256 !== a) out({ ok: false, why: 'signed for a different PDF', signer: iss });
        out({ ok: true, signer: iss, resolved: via, fields: payload.fields, checked_by: payload.checked_by, iat: payload.iat });
    } else if (kind === 'credential') {
        const { payload } = await verifierOf(jwk).verify(sdjwt);
        out({ ok: true, issuer: iss, resolved: via, vct: payload.vct, claims: Object.fromEntries(Object.entries(payload).filter(([k]) => !['iss', 'iat', 'vct', '_sd_alg', 'cnf'].includes(k))) });
    } else if (kind === 'presentation') {
        const { payload, kb } = await verifierOf(jwk, true).verify(sdjwt, { keyBindingNonce: a });
        if (!kb) out({ ok: false, why: 'no key binding' });
        if (kb.payload.aud !== b) out({ ok: false, why: 'presented to a different audience', aud: kb.payload.aud });
        out({ ok: true, issuer: iss, resolved: via, vct: payload.vct, holder: payload.cnf?.jwk?.x || null, nonce: kb.payload.nonce, aud: kb.payload.aud, presented_at: kb.payload.iat, claims: Object.fromEntries(Object.entries(payload).filter(([k]) => !['iss', 'iat', 'vct', '_sd_alg', 'cnf'].includes(k))) });
    } else out({ ok: false, why: 'usage: check.mjs mapping|credential|presentation <file> [args]' });
} catch (e) { out({ ok: false, why: String(e.message || e).slice(0, 200) }); }
