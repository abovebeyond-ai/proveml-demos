// The run as a person reads it: each intercepted action with the certificate
// the agent wrote, rendered by proveml so a true claim and a false one look
// different, the gateway's verdict and reason, and the digests that let a
// stranger replay it. One HTML file, no dependencies beyond proveml.
// usage: node report.mjs runs/<name> [runs/<baseline>] > runs/<name>/report.html
// The baseline is the same scenario under the reference gateway alone, as Proof-of-Control works today;
// each step then shows what the token says today next to what it says with reason as evidence.
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { renderProveml, PROVEML_CSS } from 'proveml/render-html';
const dir = process.argv[2]; const baseDir = process.argv[3];
const run = JSON.parse(readFileSync(join(dir, 'run.json'), 'utf8'));
const tokens = JSON.parse(readFileSync(join(dir, 'tokens.json'), 'utf8'));
const policy = JSON.parse(readFileSync(new URL('./policy.json', import.meta.url), 'utf8'));
const baseline = baseDir && existsSync(join(baseDir, 'run.json')) ? { run: JSON.parse(readFileSync(join(baseDir, 'run.json'), 'utf8')), tokens: JSON.parse(readFileSync(join(baseDir, 'tokens.json'), 'utf8')) } : null;
const attacks = existsSync(new URL('./results/attacks.json', import.meta.url)) ? JSON.parse(readFileSync(new URL('./results/attacks.json', import.meta.url), 'utf8')) : [];
const baseRow = baseline ? attacks.find((x) => `${x.scenario}-${x.requirement}` === baseline.run.name) : null;
const todayFor = (stepId) => { if (!baseline) return null; const j = baseline.run.steps.findIndex((s) => s.step === stepId); return j < 0 ? null : { step: baseline.run.steps[j], claims: (baseline.tokens[j] || {}).poc_claims || {} }; };
const anchor = existsSync(join(dir, 'anchor-rekor.json')) ? JSON.parse(readFileSync(join(dir, 'anchor-rekor.json'), 'utf8')) : null;
const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const stepFile = (i, ext) => { const p = join(dir, 'steps', String(i).padStart(2, '0') + ext); const q = join(dir, (run.steps[i] || {}).step + ext); return existsSync(p) ? p : (existsSync(q) ? q : null); };
const issuers = existsSync(new URL('./sources/issuers.json', import.meta.url)) ? JSON.parse(readFileSync(new URL('./sources/issuers.json', import.meta.url), 'utf8')) : {};
const who = (did) => { const k = Object.keys(issuers).find((k) => issuers[k] === did); return k ? `the ${k}` : (did || '').replace(/^did:jwk:.*/, 'a did:jwk key'); };
// the provenance of what the certificate bound, as a sentence per source
function provLine(prov, bound) {
  const parts = []; const seen = new Set();
  for (const p of bound) {
    const r = prov[p]; if (!r) continue; const ent = p.split('.')[0]; const [type, id] = ent.split(':');
    const key = r.grade + ':' + (r.source || r.credential || r.presentation || r.ledger || ent); if (seen.has(key)) continue; seen.add(key);
    if (r.grade === 'inferred:signed') parts.push(`${type} ${id} inferred from ${r.source.split('/').pop()}, mapping signed by ${r.signed_by}`);
    else if (r.grade === 'inferred') parts.push(`${type} ${id} inferred from ${r.source.split('/').pop()}, mapping unsigned`);
    else if (r.grade === 'attested') parts.push(`${type} ${id} vetting attested by ${who(r.issuer)}`);
    else if (r.grade === 'presented') parts.push(`consent of ${type} ${id} presented by the customer's wallet for nonce ${r.nonce.slice(0, 8)}, issued by ${who(r.issuer)}`);
    else if (r.grade === 'ledger') parts.push(`spend from the signed ledger, ${r.entries} ${r.entries === 1 ? 'entry' : 'entries'} before this action`);
    else if (r.grade === 'absent') parts.push(`${type} ${id} ${p.split('.').pop()}: ${r.why}`);
  }
  return parts.length ? parts.join('; ') + '.' : 'everything bound was computed by the gateway or declared in policy.';
}
const rows = tokens.map((t, i) => {
  const c = t.poc_claims; const st = run.steps[i] || {};
  const certPath = stepFile(i, '.cert.md'); const storePath = stepFile(i, '.store.json');
  const cert = certPath ? readFileSync(certPath, 'utf8') : (st.certificate || '');
  const store = storePath ? JSON.parse(readFileSync(storePath, 'utf8')) : {};
  const provPath = stepFile(i, '.provenance.json'); const prov = provPath ? JSON.parse(readFileSync(provPath, 'utf8')) : null;
  const rendered = cert ? renderProveml(cert, store, { thresholds: policy.registry }).html : '<p class="muted">no certificate</p>';
  return `<section class="step ${c.verdict === 'ALLOW' ? 'allow' : 'deny'}">
<h2><span class="nr">${String(c.step_index + 1).padStart(2, '0')}</span> ${esc(st.name || c.target_resource)} <span class="verdict">${esc(c.verdict)}</span></h2>
<p class="meta">${esc(c.target_resource)}${c.proveml_required_controls && c.proveml_required_controls.length ? `, must argue ${esc(c.proveml_required_controls.join(', '))}` : ''}. ${esc(c.reason)}</p>
${(() => { const t = todayFor(st.step); if (!t) return ''; const loss = baseRow && baseRow.unwarranted_executed && baseRow.unwarranted_executed[st.step]; return `<p class="today"><span class="lbl">today, reference gateway alone</span> ${esc(t.step.verdict)}, reason <q>${esc(t.claims.reason || t.step.reason || '')}</q>${t.step.executed ? ', executed' : ''}.${loss ? ` <b>${esc(loss)}.</b>` : ''} The token names the resource, the verdict, the path and the policy bundle; nothing in it names the invoice, the supplier, the amount or the consent.</p>`; })()}
<div class="cert proveml-root">${rendered}</div>
${prov && c.proveml_provenance ? `<p class="prov">${esc(provLine(prov, Object.keys(c.proveml_provenance)))}</p>` : ''}
<p class="digests">certificate ${esc((c.proveml_certificate_hash || '').slice(8, 20))}, store ${esc((c.proveml_store_hash || '').slice(8, 20))}, chain head ${esc(c.chain_head.slice(8, 20))}, tree ${esc(String(c.tree_size))} leaves</p>
</section>`;
}).join('\n');
const executed = run.steps.filter((s) => s.executed).length;
process.stdout.write(`<!doctype html><html lang="en"><head><meta charset="utf-8"><title>${esc(run.name)}: reason as evidence</title><style>
${PROVEML_CSS}
:root{--ink:#0e2433;--muted:#47616f;--sky:#f2f6f7;--card:#fafcfd;--line:rgba(14,36,51,.18);--ok:#126b3a;--bad:#a8352a;--proveml-entity-color:#126b3a;--proveml-danger-color:#a8352a;--proveml-warning-color:#a35a06;--proveml-inference-color:#0e5730}
body{margin:0;background:var(--sky);color:var(--ink);font-family:Lato,system-ui,sans-serif;line-height:1.55}
main{max-width:52rem;margin:0 auto;padding:2.5rem 1.5rem 4rem}
h1{font-size:1.5rem;margin:0 0 .3rem}.lede{color:var(--muted);margin:0 0 1.6rem;max-width:60ch}
.step{background:var(--card);border:1px solid var(--line);padding:1rem 1.2rem 1.1rem;margin:0 0 .9rem;border-left-width:3px}
.step.allow{border-left-color:var(--ok)}.step.deny{border-left-color:var(--bad)}
h2{font-size:1.02rem;margin:0 0 .2rem;display:flex;gap:.6rem;align-items:baseline}.nr{font-family:"Spline Sans Mono",ui-monospace,monospace;font-size:.8rem;color:var(--muted);font-weight:500}
.verdict{margin-left:auto;font-family:"Spline Sans Mono",ui-monospace,monospace;font-size:.78rem;color:var(--muted)}.deny .verdict{color:var(--bad)}.allow .verdict{color:var(--ok)}
.meta{margin:0 0 .6rem;font-size:.9rem;color:var(--muted)}.cert{font-size:1rem}.cert p{margin:0 0 .5rem}
.prov{font-size:.86rem;color:var(--muted);margin:.4rem 0 0}
.today{font-size:.86rem;color:var(--muted);margin:0 0 .7rem;padding:.45rem .6rem;border:1px dashed var(--line)}.today .lbl{font-family:"Spline Sans Mono",ui-monospace,monospace;font-size:.72rem;color:var(--ink);margin-right:.4rem}.today b{color:var(--bad);font-weight:600}.today q{quotes:"\u201C" "\u201D"}
.digests{font-family:"Spline Sans Mono",ui-monospace,monospace;font-size:.72rem;color:var(--muted);margin:.5rem 0 0}
.foot{font-family:"Spline Sans Mono",ui-monospace,monospace;font-size:.78rem;color:var(--muted);margin-top:1.4rem;line-height:1.7}.foot a{color:var(--ink)}
.muted{color:var(--muted)}
</style></head><body><main>
<h1>${esc(run.name)}: an agent under a grant, every action with its reason</h1>
<p class="lede">${tokens.length} intercepted actions, ${executed} executed. What the gateway verified before each one is printed as the agent wrote it: a green mark is a claim that held against the store, a struck one is a claim that did not. Under each certificate: where the facts it bound came from, and what guarantee each carries. The verdict on the right is the reference gateway's.${baseline ? ' The dashed line above each certificate is the same step as Proof-of-Control records it today, without one.' : ''}${run.model ? ` The agent was ${esc(run.model)}.` : ''}</p>
${rows}
${baseline ? `<p class="lede">Same scenario, reference gateway alone (${esc(baseline.run.name)}): ${baseline.tokens.length} intercepted, ${baseline.run.steps.filter((s) => s.executed).length} executed${baseRow && Object.keys(baseRow.unwarranted_executed || {}).length ? `, of which unwarranted: ${esc(Object.values(baseRow.unwarranted_executed).join('; '))}` : ''}. Its tokens pass the standard's validator just the same.</p>` : ''}
<p class="foot">grant: ${esc(policy.principal)}, ${esc(policy.grant.allowed_kinds.join(' '))} on ${esc(policy.grant.allowed_resources.join(', '))}, spend ${esc(String(policy.grant.max_spend))} EUR, egress up to ${esc(policy.grant.max_sensitivity_egress)}.<br>
policy bundle ${esc(run.policy_bundle_hash.slice(0, 12))}, measurement ${esc(run.measurement.slice(0, 12))}, chain head ${esc(run.chain_head.slice(0, 12))}, tree root ${esc(run.tree_root.slice(0, 12))}.${anchor ? ` Chain head <a href="${esc(anchor.search)}">anchored in Sigstore Rekor</a>, index ${esc(String(anchor.logIndex))}, ${esc(anchor.integratedAt)}.` : ''}<br>
Replay without a model or a gateway: <code>python3 verify.py ${esc(dir)}</code>. What this does not prove: that the registry is the right policy.</p>
</main></body></html>`);
