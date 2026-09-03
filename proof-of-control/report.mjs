// The run as a person watches it: every intercepted action is a gate. The
// certificate the agent wrote is checked claim by claim in front of you, the
// controls the policy requires flip to held or failed, the meter fills, and
// the gate opens with an ALLOW or stays shut with a DENY; then the signed
// evidence token appears, chained to the step before. Above each gate, the
// same step as the reference gateway alone records it today. One HTML file,
// no dependencies beyond proveml.
// usage: node report.mjs runs/<name> [runs/<baseline>] > runs/<name>/report.html
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { renderProveml, PROVEML_CSS } from 'proveml/render-html';
import { verifyProveml } from 'proveml/verify';
const dir = process.argv[2]; const baseDir = process.argv[3];
const run = JSON.parse(readFileSync(join(dir, 'run.json'), 'utf8'));
const tokens = JSON.parse(readFileSync(join(dir, 'tokens.json'), 'utf8'));
const policy = JSON.parse(readFileSync(new URL('./policy.json', import.meta.url), 'utf8'));
const baseline = baseDir && existsSync(join(baseDir, 'run.json')) ? { run: JSON.parse(readFileSync(join(baseDir, 'run.json'), 'utf8')), tokens: JSON.parse(readFileSync(join(baseDir, 'tokens.json'), 'utf8')) } : null;
const attacks = existsSync(new URL('./results/attacks.json', import.meta.url)) ? JSON.parse(readFileSync(new URL('./results/attacks.json', import.meta.url), 'utf8')) : [];
const baseRow = baseline ? attacks.find((x) => `${x.scenario}-${x.requirement}` === baseline.run.name) : null;
const todayFor = (stepId) => { if (!baseline) return null; const j = baseline.run.steps.findIndex((s) => s.step === stepId); return j < 0 ? null : { step: baseline.run.steps[j], claims: (baseline.tokens[j] || {}).poc_claims || {} }; };
const anchor = existsSync(join(dir, 'anchor-rekor.json')) ? JSON.parse(readFileSync(join(dir, 'anchor-rekor.json'), 'utf8')) : null;
const issuers = existsSync(new URL('./sources/issuers.json', import.meta.url)) ? JSON.parse(readFileSync(new URL('./sources/issuers.json', import.meta.url), 'utf8')) : {};
const who = (did) => { const k = Object.keys(issuers).find((k) => issuers[k] === did); return k ? `the ${k}` : (did || '').replace(/^did:jwk:.*/, 'a did:jwk key'); };
const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const short = (h) => esc((h || '').replace(/^sha-256:/, '').slice(0, 12));
const stepFile = (i, ext) => { const p = join(dir, 'steps', String(i).padStart(2, '0') + ext); const q = join(dir, (run.steps[i] || {}).step + ext); return existsSync(p) ? p : (existsSync(q) ? q : null); };
const GRADES = ['inferred', 'inferred:signed', 'attested', 'presented', 'ledger'];
const gradeWord = { inferred: 'inferred', 'inferred:signed': 'signed', attested: 'attested', presented: 'presented', ledger: 'ledger', gateway: 'gateway', policy: 'policy', absent: 'absent' };

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
  const certPath = stepFile(i, '.cert.md'); const storePath = stepFile(i, '.store.json'); const provPath = stepFile(i, '.provenance.json');
  const cert = certPath ? readFileSync(certPath, 'utf8') : (st.certificate || '');
  const store = storePath ? JSON.parse(readFileSync(storePath, 'utf8')) : {};
  const prov = provPath ? JSON.parse(readFileSync(provPath, 'utf8')) : null;
  const rendered = cert ? renderProveml(cert, store, { thresholds: policy.registry }).html : '';
  const v = cert ? verifyProveml(cert, store, { thresholds: policy.registry, strict: true }) : { details: [], errors: [] };
  // the controls, in the order the certificate argues them, each tied to the k-th judgement the verifier saw
  const inferences = v.details.filter((d) => d.type === 'inference');
  const argued = [...cert.matchAll(/\?\[[^\]:]+:\s*([A-Z][A-Z0-9_]*)/g)].map((m, k) => ({ name: m[1], k, held: (inferences[k] || {}).status === 'verified' }));
  const required = c.proveml_required_controls || [];
  const controls = [...required.map((name) => { const a = argued.find((x) => x.name === name); return { name, required: true, argued: !!a, held: !!(a && a.held), k: a ? a.k : -1 }; }),
                    ...argued.filter((a) => !required.includes(a.name)).map((a) => ({ name: a.name, required: false, argued: true, held: a.held, k: a.k }))];
  // the grades of what was bound, and whether each met the policy
  const gradeRows = Object.entries(c.proveml_provenance || {}).filter(([p]) => !p.startsWith('action:') && !p.startsWith('grant:')).map(([p, g]) => {
    const need = policy.required_provenance[p.split(':')[0] + '.' + p.split('.').pop()]; return { path: p, grade: g, need: need || null };
  });
  const gate = { verified: !!c.proveml_verified, verdict: c.verdict, controls };
  const today = todayFor(st.step); const loss = today && baseRow && baseRow.unwarranted_executed && baseRow.unwarranted_executed[st.step];
  const tokenView = [['verdict', c.verdict], ['target_resource', c.target_resource], ['step_index', c.step_index], ['chain_head', short(c.chain_head)], ['merkle_root', short(c.merkle_root)], ['policy_bundle_hash', short(c.policy_bundle_hash)], ['path_summary_hash', short(c.path_summary_hash)],
    ...(c.proveml_verified !== undefined ? [['proveml_verified', String(c.proveml_verified)], ['proveml_certificate_hash', short(c.proveml_certificate_hash)], ['proveml_store_hash', short(c.proveml_store_hash)], ['proveml_registry_hash', short(c.proveml_registry_hash)], ['proveml_required_controls', (c.proveml_required_controls || []).join(' ') || '(none)'], ...(c.proveml_provenance_hash ? [['proveml_provenance_hash', short(c.proveml_provenance_hash)]] : [])] : []),
    ['signature', esc(String(t.signature).slice(0, 12))]];
  return `<section class="step ${c.verdict === 'ALLOW' ? 'allow' : 'deny'}" data-gate='${esc(JSON.stringify(gate))}'>
<div class="chain"><span class="dot"></span></div>
<h2><span class="nr">${String(c.step_index + 1).padStart(2, '0')}</span> ${esc(st.name || c.target_resource)} <span class="res">${esc(c.target_resource)}</span></h2>
${today ? `<p class="today"><span class="lbl">today, reference gateway alone</span> ${esc(today.step.verdict)}, reason <q>${esc(today.claims.reason || today.step.reason || '')}</q>${today.step.executed ? ', executed' : ''}.${loss ? ` <b>${esc(loss)}.</b>` : ''}</p>` : ''}
${cert ? `<div class="cert proveml-root">${rendered}</div>` : '<p class="muted">no certificate: the reference gateway alone does not ask for one.</p>'}
${prov && c.proveml_provenance ? `<p class="prov">${esc(provLine(prov, Object.keys(c.proveml_provenance)))}</p>` : ''}
<div class="gate">
  <div class="controls">${controls.length ? controls.map((k) => `<span class="ctl${k.required ? ' req' : ''}" data-k="${k.k}" data-name="${esc(k.name)}" title="${k.required ? 'required by the policy for this action' : 'argued, not required'}">${esc(k.name)}</span>`).join('') : '<span class="none">no controls required for this action</span>'}</div>
  ${gradeRows.length ? `<div class="grades">${gradeRows.map((g) => `<span class="grade ${g.need && GRADES.indexOf(g.grade) < GRADES.indexOf(g.need) ? 'low' : 'met'}" title="${esc(g.path)}: ${esc(g.grade)}${g.need ? ', policy requires ' + esc(g.need) : ''}">${esc(g.path.split(':')[0])} ${esc(g.path.split('.').pop())} <i>${esc(gradeWord[g.grade] || g.grade)}</i></span>`).join('')}</div>` : ''}
  <div class="bar"><div class="meter"><span class="fill"></span></div><span class="verdict">${esc(c.verdict)}</span></div>
  <p class="why">${c.proveml_verified === undefined ? esc(c.reason) : (c.proveml_verified ? (c.verdict === 'ALLOW' ? 'certificate verified, then the grant: ' + esc(c.reason) : 'certificate verified; the grant refused: ' + esc(c.reason)) : esc(c.reason.replace(/^certificate does not verify: /, '')))}</p>
</div>
<div class="token"><span class="lbl">evidence token, signed by the attesting environment</span><dl>${tokenView.map(([k, val]) => `<dt${k.startsWith('proveml_') ? ' class="ext"' : ''}>${esc(k)}</dt><dd>${val}</dd>`).join('')}</dl></div>
</section>`;
}).join('\n');
const executed = run.steps.filter((s) => s.executed).length;
process.stdout.write(`<!doctype html><html lang="en"><head><meta charset="utf-8"><title>${esc(run.name)}: reason as evidence</title><style>
${PROVEML_CSS}
:root{--ink:#0e2433;--muted:#47616f;--sky:#f2f6f7;--card:#fafcfd;--line:rgba(14,36,51,.18);--groove:rgba(14,36,51,.09);--ok:#126b3a;--bad:#a8352a;--amber:#a35a06;--proveml-entity-color:#126b3a;--proveml-danger-color:#a8352a;--proveml-warning-color:#a35a06;--proveml-inference-color:#0e5730;--mono:"Spline Sans Mono",ui-monospace,monospace}
body{margin:0;background:var(--sky);color:var(--ink);font-family:Lato,system-ui,sans-serif;line-height:1.55}
main{max-width:54rem;margin:0 auto;padding:2.5rem 1.5rem 4rem}
h1{font-size:1.5rem;margin:0 0 .3rem}.lede{color:var(--muted);margin:0 0 1.6rem;max-width:62ch}
.step{position:relative;background:var(--card);border:1px solid var(--line);padding:1rem 1.2rem 1.1rem 1.6rem;margin:0 0 1.1rem 1.4rem}
.chain{position:absolute;left:-1.4rem;top:0;bottom:-1.1rem;width:1.4rem}.chain::before{content:"";position:absolute;left:.55rem;top:0;bottom:0;border-left:2px solid var(--groove)}
.chain .dot{position:absolute;left:.2rem;top:1.15rem;width:.8rem;height:.8rem;border-radius:50%;background:var(--sky);border:2px solid var(--line);box-sizing:border-box;transition:background .3s,border-color .3s}
.step.done.allow .chain .dot{background:var(--ok);border-color:var(--ok)}.step.done.deny .chain .dot{background:var(--bad);border-color:var(--bad)}
.step:last-of-type .chain{bottom:0}
h2{font-size:1.02rem;margin:0 0 .35rem;display:flex;gap:.6rem;align-items:baseline}.nr{font-family:var(--mono);font-size:.8rem;color:var(--muted);font-weight:500}.res{margin-left:auto;font-family:var(--mono);font-size:.74rem;color:var(--muted);font-weight:400}
.today{font-size:.86rem;color:var(--muted);margin:0 0 .8rem;padding:.45rem .6rem;border:1px dashed var(--line)}.today .lbl,.token .lbl{font-family:var(--mono);font-size:.72rem;color:var(--ink);margin-right:.4rem}.today b{color:var(--bad);font-weight:600}.today q{quotes:"\\201C" "\\201D"}
.cert{font-size:1rem}.cert p{margin:0 0 .5rem}
.cert .proveml-entity,.cert .proveml-fact,.cert .proveml-inference{transition:background-color .25s,box-shadow .25s}
.cert .lit{background-color:rgba(18,107,58,.14);box-shadow:0 0 0 3px rgba(18,107,58,.14)}
.cert .lit.bad{background-color:rgba(168,53,42,.14);box-shadow:0 0 0 3px rgba(168,53,42,.14)}
.cert .pin{background-color:rgba(14,36,51,.1);box-shadow:0 0 0 3px rgba(14,36,51,.1)}
.prov{font-size:.86rem;color:var(--muted);margin:.4rem 0 0}
.gate{margin:.9rem 0 0;padding:.8rem 0 0;border-top:1px solid var(--line)}
.controls{display:flex;flex-wrap:wrap;gap:.4rem .5rem;margin:0 0 .5rem}
.ctl{font-family:var(--mono);font-size:.74rem;padding:.2rem .5rem;border:1px solid var(--line);color:var(--muted);background:transparent;transition:color .3s,border-color .3s,background .3s;cursor:default}
.ctl.req{border-style:solid}.ctl:not(.req){border-style:dotted}
.ctl.ok{color:var(--ok);border-color:var(--ok);background:rgba(18,107,58,.08)}.ctl.no{color:var(--bad);border-color:var(--bad);background:rgba(168,53,42,.08);text-decoration:line-through}.ctl.missing{color:var(--amber);border-color:var(--amber);background:rgba(163,90,6,.08)}
.ctl.ok::before{content:"held "}.ctl.no::before{content:"false "}.ctl.missing::before{content:"not argued "}.ctl::before{font-family:Lato,system-ui,sans-serif;font-size:.72rem;color:inherit}
.none{font-family:var(--mono);font-size:.74rem;color:var(--muted)}
.grades{display:flex;flex-wrap:wrap;gap:.35rem .6rem;margin:0 0 .6rem;font-size:.78rem;color:var(--muted)}.grade i{font-style:normal;font-family:var(--mono);font-size:.7rem;padding:.05rem .3rem;border:1px solid var(--line)}.grade.met i{color:var(--ok);border-color:rgba(18,107,58,.5)}.grade.low i{color:var(--bad);border-color:var(--bad);text-decoration:line-through}
.bar{display:flex;align-items:center;gap:.8rem}
.meter{flex:1;height:.55rem;background:var(--groove);position:relative;overflow:hidden}.meter .fill{position:absolute;left:0;top:0;bottom:0;width:0;background:var(--ok);transition:width .35s ease-out}
.deny .meter .fill{background:var(--bad)}
.verdict{font-family:var(--mono);font-size:.82rem;font-weight:600;min-width:4.2em;text-align:right;opacity:0;transform:translateX(.3rem);transition:opacity .35s,transform .35s}
.allow .verdict{color:var(--ok)}.deny .verdict{color:var(--bad)}.step.done .verdict{opacity:1;transform:none}
.why{font-size:.86rem;color:var(--muted);margin:.5rem 0 0;opacity:0;transition:opacity .4s}.step.done .why{opacity:1}
.token{margin:.8rem 0 0;padding:0 .7rem;border:0 solid var(--line);background:var(--sky);max-height:0;overflow:hidden;opacity:0;transition:max-height .5s ease-out,opacity .4s,padding .3s;box-sizing:border-box}
.step.done .token{max-height:26rem;opacity:1;padding:.6rem .7rem;border-width:1px}
.token dl{display:grid;grid-template-columns:max-content 1fr;gap:.1rem .9rem;margin:.35rem 0 0;font-family:var(--mono);font-size:.72rem}.token dt{color:var(--muted)}.token dd{margin:0;color:var(--ink)}.token dt.ext{color:var(--ok)}
.foot{font-family:var(--mono);font-size:.78rem;color:var(--muted);margin-top:1.4rem;line-height:1.7}.foot a{color:var(--ink)}
.muted{color:var(--muted)}
.again{font-family:var(--mono);font-size:.74rem;color:var(--muted);background:none;border:0;padding:0;cursor:pointer;text-decoration:underline}
@media (prefers-reduced-motion:reduce){.cert .lit,.verdict,.why,.token,.meter .fill{transition:none}}
.instant .cert .lit,.instant .verdict,.instant .why,.instant .token,.instant .meter .fill,.instant .ctl,.instant .chain .dot{transition:none}
</style></head><body><main>
<h1>${esc(run.name)}: an agent under a grant, every action through the gate</h1>
<p class="lede">${tokens.length} intercepted actions, ${executed} executed. Each one is a gate. Scroll to a step and watch: the certificate the agent wrote is checked claim by claim, the controls the policy requires turn to held or false, the meter fills, and the gate opens with ALLOW or stays shut with DENY. Then the signed evidence token appears, chained to the step before; the green keys are the claims this profile adds.${baseline ? ' The dashed line above each certificate is the same step as Proof-of-Control records it today, without one.' : ''}${run.model ? ` The agent was ${esc(run.model)}.` : ''} <button class="again" type="button">run it again</button></p>
${rows}
${baseline ? `<p class="lede">Same scenario, reference gateway alone (${esc(baseline.run.name)}): ${baseline.tokens.length} intercepted, ${baseline.run.steps.filter((s) => s.executed).length} executed${baseRow && Object.keys(baseRow.unwarranted_executed || {}).length ? `, of which unwarranted: ${esc(Object.values(baseRow.unwarranted_executed).join('; '))}` : ''}. Its tokens pass the standard's validator just the same.</p>` : ''}
<p class="foot">grant: ${esc(policy.principal)}, ${esc(policy.grant.allowed_kinds.join(' '))} on ${esc(policy.grant.allowed_resources.join(', '))}, spend ${esc(String(policy.grant.max_spend))} EUR, egress up to ${esc(policy.grant.max_sensitivity_egress)}.<br>
policy bundle ${esc(run.policy_bundle_hash.slice(0, 12))}, measurement ${esc(run.measurement.slice(0, 12))}, chain head ${esc(run.chain_head.slice(0, 12))}, tree root ${esc(run.tree_root.slice(0, 12))}.${anchor ? ` Chain head <a href="${esc(anchor.search)}">anchored in Sigstore Rekor</a>, index ${esc(String(anchor.logIndex))}, ${esc(anchor.integratedAt)}.` : ''}<br>
Replay without a model or a gateway: <code>python3 verify.py ${esc(dir)}</code>. What this does not prove: that the registry is the right policy.</p>
</main>
<script>
(() => {
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const reduced = matchMedia('(prefers-reduced-motion: reduce)').matches || location.search.includes('instant');
  if (location.search.includes('instant')) document.documentElement.classList.add('instant');
  const steps = [...document.querySelectorAll('.step')];
  const marks = (s) => [...s.querySelectorAll('.cert .proveml-entity, .cert .proveml-fact, .cert .proveml-inference')];
  const isBad = (el) => el.classList.contains('proveml-failed');
  async function play(s) {
    if (s.dataset.playing) return; s.dataset.playing = '1';
    const g = JSON.parse(s.dataset.gate); const ms = reduced ? 0 : 110;
    s.classList.remove('done'); const fill = s.querySelector('.fill'); fill.style.width = '0';
    for (const el of marks(s)) el.classList.remove('lit', 'bad');
    for (const c of s.querySelectorAll('.ctl')) c.classList.remove('ok', 'no', 'missing');
    const inferences = [...s.querySelectorAll('.cert .proveml-inference')];
    const req = g.controls.filter((c) => c.required); let passed = 0; const total = Math.max(req.length, 1);
    await sleep(ms * 2);
    for (const el of marks(s)) {
      el.classList.add('lit'); if (isBad(el)) el.classList.add('bad');
      const k = inferences.indexOf(el);
      if (k >= 0) for (const c of s.querySelectorAll('.ctl[data-k="' + k + '"]')) {
        const ctl = g.controls.find((x) => x.k === k); c.classList.add(ctl && ctl.held ? 'ok' : 'no');
        if (ctl && ctl.required && ctl.held) { passed++; fill.style.width = (100 * passed / total) + '%'; }
      }
      await sleep(isBad(el) ? ms * 3 : ms); el.classList.remove('lit');
    }
    for (const c of s.querySelectorAll('.ctl.req:not(.ok):not(.no)')) c.classList.add('missing');
    if (g.verified && g.verdict === 'ALLOW') fill.style.width = '100%';
    await sleep(ms * 2); s.classList.add('done'); delete s.dataset.playing;
  }
  const io = new IntersectionObserver((es) => es.forEach((e) => { if (e.isIntersecting && !e.target.classList.contains('done') && !e.target.dataset.playing) play(e.target); }), { threshold: 0.3 });
  steps.forEach((s) => io.observe(s));
  document.querySelector('.again').addEventListener('click', async () => { for (const s of steps) s.classList.remove('done'); for (const s of steps) if (s.getBoundingClientRect().top < innerHeight && s.getBoundingClientRect().bottom > 0) await play(s); });
  // hover a control: pin the judgement that argues it
  document.querySelectorAll('.ctl').forEach((c) => {
    const s = c.closest('.step'); const el = [...s.querySelectorAll('.cert .proveml-inference')][Number(c.dataset.k)];
    if (!el) return;
    c.addEventListener('mouseenter', () => el.classList.add('pin')); c.addEventListener('mouseleave', () => el.classList.remove('pin'));
  });
})();
</script>
</body></html>`);
