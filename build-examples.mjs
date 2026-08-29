#!/usr/bin/env node
/**
 * Pre-generate example reports for the site: every available model writes
 * one ledger report and two identity summaries (full disclosure, and the
 * name withheld), each verified and rendered exactly as the live button
 * would. Saved to web/examples/{ledger,identity}.json so a visitor can see a
 * finished example instantly, and so the hosted site shows Claude's writing
 * even where only the laptop login can reach Claude.
 *
 * Usage: node build-examples.mjs [--only ledger|identity]
 */
process.env.PROVEML_NO_SERVER = '1';
import { mkdirSync, writeFileSync } from 'fs';
import { availableModels } from './llm.mjs';
const { ledgerReport, identitySummary } = await import('./server.mjs');

const only = process.argv.includes('--only') ? process.argv[process.argv.indexOf('--only') + 1] : null;
mkdirSync('web/examples', { recursive: true });
const models = availableModels();
const strip = (r) => { const { id, canAnchor, ...rest } = r; return { ...rest, writtenAt: new Date().toISOString() }; };

if (!only || only === 'ledger') {
    const out = [];
    for (const m of models) {
        process.stdout.write(`ledger ${m.id} … `);
        try { const r = await ledgerReport(m.id); out.push({ ...strip(r), modelLabel: m.label }); console.log(`${r.verification.verified}/${r.verification.total} in ${(r.ms / 1000).toFixed(1)}s`); }
        catch (e) { console.log(`failed: ${e.message}`); }
    }
    writeFileSync('web/examples/ledger.json', JSON.stringify(out, null, 1));
}
if (!only || only === 'identity') {
    const out = [];
    const sets = [['given_name', 'family_name', 'birthdate', 'nationalities', 'address'], ['birthdate', 'address']];
    for (const m of models) for (const disclose of sets) {
        process.stdout.write(`identity ${m.id} [${disclose.length} claims] … `);
        try { const r = await identitySummary(m.id, disclose); out.push({ ...strip(r), modelLabel: m.label }); console.log(`${r.verification.verified}/${r.verification.total} in ${(r.ms / 1000).toFixed(1)}s`); }
        catch (e) { console.log(`failed: ${e.message}`); }
    }
    writeFileSync('web/examples/identity.json', JSON.stringify(out, null, 1));
}
