// The run as a person reads it: each intercepted action with the certificate
// the agent wrote, rendered by proveml so a true claim and a false one look
// different, the gateway's verdict and reason, and the digests that let a
// stranger replay it. One HTML file, no dependencies beyond proveml.
// usage: node report.mjs runs/<name> > runs/<name>/report.html
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { renderProveml, PROVEML_CSS } from 'proveml/render-html';
const dir = process.argv[2];
const run = JSON.parse(readFileSync(join(dir, 'run.json'), 'utf8'));
const tokens = JSON.parse(readFileSync(join(dir, 'tokens.json'), 'utf8'));
const policy = JSON.parse(readFileSync(new URL('./policy.json', import.meta.url), 'utf8'));
const anchor = existsSync(join(dir, 'anchor-rekor.json')) ? JSON.parse(readFileSync(join(dir, 'anchor-rekor.json'), 'utf8')) : null;
const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const stepFile = (i, ext) => { const p = join(dir, 'steps', String(i).padStart(2, '0') + ext); const q = join(dir, (run.steps[i] || {}).step + ext); return existsSync(p) ? p : (existsSync(q) ? q : null); };
const rows = tokens.map((t, i) => {
  const c = t.poc_claims; const st = run.steps[i] || {};
  const certPath = stepFile(i, '.cert.md'); const storePath = stepFile(i, '.store.json');
  const cert = certPath ? readFileSync(certPath, 'utf8') : (st.certificate || '');
  const store = storePath ? JSON.parse(readFileSync(storePath, 'utf8')) : {};
  const rendered = cert ? renderProveml(cert, store, { thresholds: policy.registry }).html : '<p class="muted">no certificate</p>';
  return `<section class="step ${c.verdict === 'ALLOW' ? 'allow' : 'deny'}">
<h2><span class="nr">${String(c.step_index + 1).padStart(2, '0')}</span> ${esc(st.name || c.target_resource)} <span class="verdict">${esc(c.verdict)}</span></h2>
<p class="meta">${esc(c.target_resource)}${c.proveml_required_controls && c.proveml_required_controls.length ? `, must argue ${esc(c.proveml_required_controls.join(', '))}` : ''}. ${esc(c.reason)}</p>
<div class="cert proveml-root">${rendered}</div>
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
.digests{font-family:"Spline Sans Mono",ui-monospace,monospace;font-size:.72rem;color:var(--muted);margin:.5rem 0 0}
.foot{font-family:"Spline Sans Mono",ui-monospace,monospace;font-size:.78rem;color:var(--muted);margin-top:1.4rem;line-height:1.7}.foot a{color:var(--ink)}
.muted{color:var(--muted)}
</style></head><body><main>
<h1>${esc(run.name)}: an agent under a grant, every action with its reason</h1>
<p class="lede">${tokens.length} intercepted actions, ${executed} executed. What the gateway verified before each one is printed as the agent wrote it: a green mark is a claim that held against the store, a struck one is a claim that did not. The verdict on the right is the reference gateway's.${run.model ? ` The agent was ${esc(run.model)}.` : ''}</p>
${rows}
<p class="foot">grant: ${esc(policy.principal)}, ${esc(policy.grant.allowed_kinds.join(' '))} on ${esc(policy.grant.allowed_resources.join(', '))}, spend ${esc(String(policy.grant.max_spend))} EUR, egress up to ${esc(policy.grant.max_sensitivity_egress)}.<br>
policy bundle ${esc(run.policy_bundle_hash.slice(0, 12))}, measurement ${esc(run.measurement.slice(0, 12))}, chain head ${esc(run.chain_head.slice(0, 12))}, tree root ${esc(run.tree_root.slice(0, 12))}.${anchor ? ` Chain head <a href="${esc(anchor.search)}">anchored in Sigstore Rekor</a>, index ${esc(String(anchor.logIndex))}, ${esc(anchor.integratedAt)}.` : ''}<br>
Replay without a model or a gateway: <code>python3 verify.py ${esc(dir)}</code>. What this does not prove: that the registry is the right policy.</p>
</main></body></html>`);
