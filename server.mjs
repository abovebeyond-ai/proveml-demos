/**
 * The demo server: static page plus a few JSON routes. No framework.
 *
 *   GET  /api/models                  which models the button can call
 *   GET  /api/ledger/snapshot         the live fact store, with proof URLs
 *   POST /api/ledger/report {model}   snapshot -> model -> verify -> render
 *   POST /api/ledger/anchor {reportId} put the verdict on Hedera (HCS)
 *
 * A report is kept in memory for the anchor step; the page shows the same
 * verification a reader can reproduce with `npx proveml verify`.
 */
import { createServer } from 'http';
import { readFileSync, existsSync } from 'fs';
import { dirname, extname, join } from 'path';
import { fileURLToPath } from 'url';
import { randomUUID } from 'crypto';
import { verifyProveml, stripProveml } from 'proveml/verify';
import { renderProveml, PROVEML_CSS } from 'proveml/render';
import { promptFor } from 'proveml/prompt';
import { tokenSnapshot, mirrorAdapter } from './adapters/hedera-mirror.mjs';
import { anchor, anchorPayload, hasOperator } from './adapters/hedera-hcs.mjs';
import { ledgerThresholds } from './registry/ledger.mjs';
import { identityThresholds } from './registry/identity.mjs';
import { setupIdentity, presentAndVerify, attestVerdict } from './adapters/pid-sdjwt.mjs';
import { availableModels, generate } from './llm.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT || 3939);
const reports = new Map();
const identity = await setupIdentity();

const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.json': 'application/json' };

function ledgerPrompt(snap) {
    // The rules come from the package (proveml/prompt): what a model has to be
    // told is measured there, not improvised here. Only the role, the example
    // and the data are this demo's.
    const system = promptFor({
        store: snap.facts,
        thresholds: ledgerThresholds,
        role: 'You write short daily ledger reports for the holders of a token. Treasury figures (treasuryBalance, treasuryShare, treasuryTxCount24h, treasuryVolume24h) are fields of the token; the treasury account also exists as a holder with balance, share, txCount24h and volume24h. Say "the last day" rather than "24 hours". Four to six sentences.',
        example: `@[token:0.0.456858]{USD Coin} has a total supply of %[totalSupply]{450010110 USDC} on Hedera, of which %[circulating]{450009947.703719 USDC} is outside the treasury; ?[large: LARGE_ISSUANCE]{this is a large issuance for the network}.`,
    });
    const facts = Object.entries(snap.facts).filter(([k]) => !k.endsWith('._unit') && !k.endsWith('._display'))
        .map(([k, v]) => `${k} = ${v}${snap.facts[`${k}._unit`] ? ' ' + snap.facts[`${k}._unit`] : ''}`).join('\n');
    const user = `DATA (snapshot ${snap.snapshot.id}):\n${facts}\n\nWrite today's report on USDC on Hedera: issuance, treasury activity over the last day, and the largest holders.`;
    return { system, user };
}

export async function ledgerReport(model) {
    const snap = await tokenSnapshot();
    const { system, user } = ledgerPrompt(snap);
    const gen = await generate({ model, system, user });
    const adapter = mirrorAdapter(snap);
    const options = { thresholds: ledgerThresholds, snapshot: snap.snapshot.id, strict: true };
    const verification = verifyProveml(gen.text, adapter, options);
    // Every fact here comes from one source with one trust status, so the
    // per-claim trust tag the audit render adds is stated once in the verdict
    // line instead; the path link per claim stays.
    const html = renderProveml(gen.text, adapter, { ...options, showProofPaths: true }).html
        .replace(/<span class="proveml-proof">\[trust: [^<]*<\/span>/g, '');
    const id = randomUUID();
    const report = { id, model: gen.model, ms: gen.ms, markup: gen.text, plain: stripProveml(gen.text), html, verification, snapshot: snap.snapshot, proofs: snap.proofs, canAnchor: hasOperator(), trust: 'every fact read from the Hedera mirror node at the snapshot timestamp' };
    reports.set(id, report);
    return report;
}

function identityPrompt(facts, entity, disclosed) {
    const system = promptFor({
        store: facts,
        thresholds: identityThresholds,
        role: `You draft short account-opening summaries for a bank from a verified identity credential. Start with the person as the subject: @[${entity}]{Name Surname}, using ${entity}.name exactly; if there is no name in the data, write @[${entity}]{the applicant}, which will show as unverifiable, and that is correct. Nested fields keep their dotted name (%[address.locality]{Gent}). Never state an attribute that is not in the data; say it was not disclosed. Three to five sentences, formal register.`,
        example: `@[${entity}]{Elke Vandenberghe} presented a PID issued by %[issuing_authority]{Demo PID Provider}. She was born on %[birthdate]{1991-06-03} and ?[adult: IS_ADULT]{is of age}; her nationality is %[nationalities]{BE}, so she ?[eu: EU_NATIONAL]{is a national of an EU member state}.`,
    });
    const lines = Object.entries(facts).map(([k, v]) => `${k} = ${v}`).join('\n');
    const user = `DATA (disclosed: ${disclosed.join(', ') || 'nothing'}):\n${lines}\n\nDraft the account-opening summary for this applicant.`;
    return { system, user };
}

export async function identitySummary(model, disclose) {
    const nonce = randomUUID();
    const pres = await presentAndVerify(identity, disclose, nonce);
    const { system, user } = identityPrompt(pres.facts, pres.entity, pres.disclosed);
    const gen = await generate({ model, system, user });
    const options = { thresholds: identityThresholds, snapshot: `presentation:sha256:${pres.digestHex}`, strict: true };
    const verification = verifyProveml(gen.text, pres.adapter, options);
    const { html } = renderProveml(gen.text, pres.adapter, { ...options, showProofPaths: false });
    const id = randomUUID();
    const report = { id, kind: 'identity', model: gen.model, ms: gen.ms, markup: gen.text, plain: stripProveml(gen.text), html, verification, credentialStatus: pres.status, credentialError: pres.error, disclosed: pres.disclosed, facts: pres.facts, proofs: pres.proofs, presentation: pres.presentation, digestHex: pres.digestHex };
    reports.set(id, report);
    return report;
}

function json(res, status, body) {
    res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
    res.end(JSON.stringify(body));
}

async function readBody(req) {
    let data = '';
    for await (const chunk of req) data += chunk;
    return data ? JSON.parse(data) : {};
}

const EXAMPLES = join(here, 'web', 'examples');
function examples(kind) {
    const file = join(EXAMPLES, `${kind}.json`);
    return existsSync(file) ? JSON.parse(readFileSync(file, 'utf8')) : [];
}

if (process.env.PROVEML_NO_SERVER) {
    // imported by build-examples.mjs; do not listen
} else createServer(async (req, res) => {
    const url = new URL(req.url, `http://${req.headers.host}`);
    try {
        if (url.pathname === '/api/models') return json(res, 200, { models: availableModels() });
        if (url.pathname === '/api/examples/ledger') return json(res, 200, { examples: examples('ledger') });
        if (url.pathname === '/api/examples/identity') return json(res, 200, { examples: examples('identity') });
        if (url.pathname === '/api/ledger/snapshot') {
            const snap = await tokenSnapshot();
            return json(res, 200, { ...snap, thresholds: ledgerThresholds });
        }
        if (url.pathname === '/api/ledger/report' && req.method === 'POST') {
            const { model } = await readBody(req);
            if (!availableModels().some(m => m.id === model)) return json(res, 400, { error: `model not available: ${model}` });
            return json(res, 200, await ledgerReport(model));
        }
        if (url.pathname === '/api/ledger/anchor' && req.method === 'POST') {
            const { reportId } = await readBody(req);
            const report = reports.get(reportId);
            if (!report) return json(res, 404, { error: 'unknown report' });
            if (!hasOperator()) return json(res, 503, { error: 'no Hedera operator configured on this server' });
            const payload = anchorPayload({ markup: report.markup, verification: report.verification, snapshot: report.snapshot.id, thresholds: ledgerThresholds });
            const where = await anchor(payload);
            report.anchor = { payload, where };
            return json(res, 200, report.anchor);
        }
        if (url.pathname === '/api/identity/credential') {
            return json(res, 200, { vct: 'urn:eudi:pid:1', issuer: 'https://pid-provider.demo.abovebeyond.ai', issuerJwk: identity.issuerJwk, claims: identity.claims, disclosable: identity.disclosable, thresholds: identityThresholds });
        }
        if (url.pathname === '/api/identity/summary' && req.method === 'POST') {
            const { model, disclose = [] } = await readBody(req);
            if (!availableModels().some(m => m.id === model)) return json(res, 400, { error: `model not available: ${model}` });
            return json(res, 200, await identitySummary(model, disclose.filter(c => identity.disclosable.includes(c))));
        }
        if (url.pathname === '/api/identity/attest' && req.method === 'POST') {
            const { reportId } = await readBody(req);
            const report = reports.get(reportId);
            if (!report || report.kind !== 'identity') return json(res, 404, { error: 'unknown report' });
            return json(res, 200, await attestVerdict(identity, { markup: report.markup, verification: report.verification, digestHex: report.digestHex, thresholds: identityThresholds }));
        }
        if (url.pathname === '/proveml.css') { res.writeHead(200, { 'content-type': MIME['.css'] }); return res.end(PROVEML_CSS); }
        // static
        const file = join(here, 'web', url.pathname === '/' ? 'index.html' : url.pathname);
        if (!file.startsWith(join(here, 'web')) || !existsSync(file)) { res.writeHead(404); return res.end('not found'); }
        res.writeHead(200, { 'content-type': MIME[extname(file)] || 'application/octet-stream' });
        res.end(readFileSync(file));
    } catch (e) {
        console.error(e);
        json(res, 500, { error: e.message });
    }
}).listen(PORT, () => console.log(`proveml demos on http://localhost:${PORT}`));
