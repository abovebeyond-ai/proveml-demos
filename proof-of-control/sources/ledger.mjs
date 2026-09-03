// The payments ledger: an append-only, hash-chained log of executed payments,
// each entry signed by the ledger key. The gateway's spend path is read from
// it, not from the gateway's memory, so a stranger can recompute the spend
// before any action from the same file the gateway used.
// usage: node ledger.mjs append <file> '<entry json>'    (prints the entry as written)
//        node ledger.mjs verify <file> [principal] [upto]  (prints {ok, entries, sum, head}; upto = first n entries)
import { readFileSync, writeFileSync, existsSync, appendFileSync } from 'node:fs';
import { join } from 'node:path';
import { HERE, loadKey, sha256, canonical, signerFor, verifierFor, didJwk, resolveDidJwk } from './lib.mjs';

const [cmd, file, arg, upto] = process.argv.slice(2);
const read = () => (existsSync(file) ? readFileSync(file, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l)) : []);
if (cmd === 'append') {
    const key = loadKey(join(HERE, 'keys', 'ledger.jwk')); const did = didJwk(key.publicJwk);
    const rows = read(); const prev = rows.length ? sha256(canonical(rows[rows.length - 1])) : 'genesis';
    const entry = { seq: rows.length, prev, ...JSON.parse(arg) };
    const row = { entry, kid: did + '#0', sig: await signerFor(key.privateJwk)(canonical(entry)) };
    appendFileSync(file, JSON.stringify(row) + '\n');
    console.log(JSON.stringify({ ok: true, seq: entry.seq, head: sha256(canonical(row)) }));
} else if (cmd === 'verify') {
    const rows = read().slice(0, upto !== undefined ? Number(upto) : undefined); const errors = []; let prev = 'genesis', sum = 0;
    for (const [i, row] of rows.entries()) {
        const jwk = resolveDidJwk(row.kid.split('#')[0]);
        if (!(await verifierFor(jwk)(canonical(row.entry), row.sig))) errors.push(`entry ${i}: bad signature`);
        if (row.entry.seq !== i) errors.push(`entry ${i}: seq ${row.entry.seq}`);
        if (row.entry.prev !== prev) errors.push(`entry ${i}: prev does not chain`);
        prev = sha256(canonical(row));
        if (!arg || row.entry.principal === arg) sum += Number(row.entry.amount || 0);
    }
    console.log(JSON.stringify({ ok: errors.length === 0, entries: rows.length, sum, head: rows.length ? prev : 'genesis', signer: rows[0]?.kid?.split('#')[0] || null, errors }));
} else { console.error('usage: ledger.mjs append|verify <file> [arg]'); process.exit(2); }
