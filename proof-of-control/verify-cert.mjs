// The certificate check, as a stranger runs it: a store snapshot, the
// registry, the certificate text, the controls the policy requires for this
// action, and (optionally) the provenance of the snapshot with the grades the
// policy requires per field. Prints JSON: verified, which required controls
// were argued, which store paths the certificate bound, their provenance
// grades, and every error found. Exit 0 only when everything holds.
//
// Everything here is read from the parser's own output (verifyProveml details
// and renderProveml's marked spans), never from a regex over the raw text:
// the red team of 2026-09-04 walked 32 wrong certificates past a regex
// version of this file through code spans, OR/NOT conditions and scope
// tricks the parser handles differently. Rules beyond proveml's own:
//   - a judgement must name exactly one registered threshold, bare or with an
//     explicit path; OR, NOT and label references are refused (composition
//     belongs to the registry, not to the certificate)
//   - a required control counts as argued only through such a judgement that
//     verified
//   - a fact with an explicit path may only name a record the certificate
//     also mentions as an entity
//   - every numeral the reader sees outside a verified fact or entity name is
//     an error, whatever script it is written in (proveml 0.8.0's certificate
//     coverage, plus a second scan here over the rendered text)
//   - grading binds a judgement to the entity the parser had in force when it
//     evaluated it (proveml 0.8.0 reports it), or to the explicit path
//
// usage: node verify-cert.mjs store.json registry.json cert.md [REQ1,REQ2,...] [provenance.json] ['{"type.field":"grade"}']
import { readFileSync } from 'node:fs';
import { verifyProveml } from 'proveml/verify';
import { renderProveml } from 'proveml/render-html';
const [storeF, regF, certF, req, provF, reqProvJson] = process.argv.slice(2);
const store = JSON.parse(readFileSync(storeF, 'utf8'));
const registry = JSON.parse(readFileSync(regF, 'utf8'));
const cert = readFileSync(certF, 'utf8');
const required = req ? req.split(',').filter(Boolean) : [];
const errors = [];
const v = verifyProveml(cert, store, { thresholds: registry, strict: true, coverage: 'certificate' });
errors.push(...v.errors);

// the marks as the renderer saw them, in document order, with their attributes
const html = renderProveml(cert, store, { thresholds: registry }).html;
const spans = [...html.matchAll(/<span class="(proveml-(?:entity|fact|inference)[^"]*)"([^>]*)>/g)].map((m) => {
  const attrs = Object.fromEntries([...m[2].matchAll(/([a-z-]+)="([^"]*)"/g)].map((a) => [a[1], a[2].replace(/&quot;/g, '"').replace(/&amp;/g, '&')]));
  return { kind: m[1].split(' ')[0].replace('proveml-', ''), verified: m[1].includes('proveml-verified'), ...attrs };
});
const marks = v.details.filter((d) => d.type === 'entity' || d.type === 'fact' || d.type === 'inference');
if (spans.length !== marks.length) errors.push(`the renderer saw ${spans.length} marks and the verifier ${marks.length}`);

// judgements: one registered threshold each; argued = named through a verified bare judgement
const BARE = /^([A-Z][A-Z0-9_]*)(?:\(([a-z_]+:[A-Za-z0-9_.~-]+)(?:\.([a-z_]+))?\))?$/;
const judgements = [];
spans.forEach((s, i) => {
  if (s.kind !== 'inference') return;
  const d = marks[i] || {}; const m = BARE.exec((s['data-condition'] || '').trim());
  if (!m) { errors.push(`?[${d.label || '?'}: ${s['data-condition']}]: a judgement names one registered threshold; OR, NOT and label references are not accepted in a certificate`); return; }
  if (!registry[m[1]]) { errors.push(`?[${d.label || '?'}: ${m[1]}]: unknown threshold`); return; }
  judgements.push({ name: m[1], explicit: m[2] || null, entity: d.entity || null, verified: d.status === 'verified' && s.verified });
});
const argued = judgements.filter((j) => j.verified).map((j) => j.name);
const missing = required.filter((r) => !argued.includes(r));
errors.push(...missing.map((m) => `required control ${m} not argued`));

// entities the certificate names, and facts with explicit paths that name a record it does not
const named = new Set(spans.filter((s) => s.kind === 'entity' && s['data-entity']).map((s) => s['data-entity']));
spans.forEach((s, i) => {
  if (s.kind !== 'fact' || !s['data-path']) return;
  const d = marks[i] || {}; const src = cert.slice(d.pos, d.end);
  const explicit = /^%\[[a-z_]+:/.test(src);
  const ent = s['data-path'].split('.')[0];
  if (explicit && !named.has(ent)) errors.push(`%[${s['data-path']}]: names a record the certificate never mentions as an entity`);
});

// what the certificate bound: verified facts, named entities (their name), and every path a verified judgement's field could read
const bound = new Set();
spans.forEach((s) => { if (s.kind === 'fact' && s.verified && s['data-path']) bound.add(s['data-path']); if (s.kind === 'entity' && s.verified && s['data-entity'] && (s['data-entity'] + '.name') in store) bound.add(s['data-entity'] + '.name'); });
for (const j of judgements) {
  if (!j.verified) continue; const field = registry[j.name].field;
  if (j.explicit) { const p = j.explicit + '.' + field; if (p in store) bound.add(p); continue; }
  if (j.entity && (j.entity + '.' + field) in store) { bound.add(j.entity + '.' + field); continue; }
  for (const p of Object.keys(store)) if (p.endsWith('.' + field) && p.split('.').length === 2) bound.add(p);   // no entity reported: bind every candidate
}

// numerals the reader sees outside a verified fact or entity name
const visible = html.replace(/<span class="proveml-(?:fact|entity)[^"]*"[^>]*>[\s\S]*?<\/span>/g, ' ').replace(/<[^>]+>/g, ' ').replace(/&[a-z]+;|&#\d+;/g, ' ');
const stray = [...visible.matchAll(/\p{N}+(?:[.,]\p{N}+)*/gu)].map((m) => m[0]);
if (stray.length) errors.push(`numerals in prose are not claims: ${[...new Set(stray)].join(', ')}`);

// provenance grades of what was bound, against the policy's requirement per type.field
const RANK = { absent: 0, inferred: 1, gateway: 2, 'inferred:signed': 2, attested: 3, presented: 4, ledger: 4, policy: 4 };
const provenance = {};
if (provF) {
  const prov = JSON.parse(readFileSync(provF, 'utf8')); const need = reqProvJson ? JSON.parse(reqProvJson) : {};
  for (const p of bound) {
    const rec = prov[p] || {}; const grade = rec.grade || 'absent'; provenance[p] = grade;
    const want = need[p.split(':')[0] + '.' + p.split('.').pop()]; if (!want) continue;
    if ((RANK[grade] ?? 0) < (RANK[want] ?? 0)) errors.push(`${p} is ${grade}${rec.why ? ' (' + rec.why + ')' : rec.mapping_error ? ' (' + rec.mapping_error + ')' : ''}; policy requires ${want}`);
  }
}
const out = { verified: errors.length === 0 && v.total > 0, total: v.total, checked: v.verified, argued: [...new Set(argued)], missing, bound: [...bound].sort(), provenance, errors };
console.log(JSON.stringify(out));
process.exit(out.verified ? 0 : 1);
