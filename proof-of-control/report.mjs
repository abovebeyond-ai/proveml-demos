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
  // the lane: every claim of the certificate is a station, then every required control, then the gate, then the dock
  const nMarks = v.details.filter((d) => d.type === 'entity' || d.type === 'fact' || d.type === 'inference').length;
  const reqControls = controls.filter((k) => k.required);
  const at = (i, n, a, b) => (n <= 1 ? (a + b) / 2 : a + (b - a) * i / (n - 1));
  const claimNodes = Array.from({ length: nMarks }, (_, i) => `<span class="node claim" style="left:${at(i, nMarks, 2, 34).toFixed(2)}%" data-m="${i}"></span>`).join('');
  const ctlNodes = reqControls.map((k, i) => `<span class="node ctl${i % 2 ? ' below' : ''}" style="left:${at(i, reqControls.length, 41, 78).toFixed(2)}%" data-k="${k.k}" data-held="${k.held ? 1 : 0}" data-argued="${k.argued ? 1 : 0}" title="${esc(k.name)}: ${k.argued ? (k.held ? 'held' : 'false') : 'not argued'}"><i>${esc(k.name.toLowerCase().replace(/_/g, ' '))}</i></span>`).join('');
  const lane = `<div class="lane" data-marks="${nMarks}" data-open="${gate.verified && c.verdict === 'ALLOW' ? 1 : 0}">
    <div class="track"><span class="fill"></span></div>
    ${claimNodes}${ctlNodes || (nMarks ? '' : '')}
    ${reqControls.length ? '' : `<span class="nonode" style="left:60%">no controls required</span>`}
    <div class="gatebar" style="left:85%"><span class="top"></span><span class="bot"></span></div>
    <div class="dock"><span class="verdict">${esc(c.verdict)}</span></div>
    <span class="trav"></span>
  </div>`;
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
  ${gradeRows.length ? `<div class="grades">${gradeRows.map((g) => `<span class="grade ${g.need && GRADES.indexOf(g.grade) < GRADES.indexOf(g.need) ? 'low' : 'met'}" title="${esc(g.path)}: ${esc(g.grade)}${g.need ? ', policy requires ' + esc(g.need) : ''}">${esc(g.path.split(':')[0])} ${esc(g.path.split('.').pop())} <i>${esc(gradeWord[g.grade] || g.grade)}</i></span>`).join('')}</div>` : ''}
  ${lane}
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
.grades{display:flex;flex-wrap:wrap;gap:.35rem .6rem;margin:0 0 .2rem;font-size:.78rem;color:var(--muted)}.grade i{font-style:normal;font-family:var(--mono);font-size:.7rem;padding:.05rem .3rem;border:1px solid var(--line)}.grade.met i{color:var(--ok);border-color:rgba(18,107,58,.5)}.grade.low i{color:var(--bad);border-color:var(--bad);text-decoration:line-through}
.lane{position:relative;height:4.6rem;margin:.2rem 0 0;cursor:pointer}
.track{position:absolute;left:0;right:9%;top:50%;height:.5rem;margin-top:-.25rem;background:var(--groove)}
.track .fill{position:absolute;left:0;top:0;bottom:0;width:0;background:var(--ok)}.lane.failed .track .fill{background:var(--bad)}
.node{position:absolute;top:50%;width:.55rem;height:.55rem;margin:-.275rem 0 0 -.275rem;border-radius:50%;background:var(--card);border:1.5px solid var(--line);box-sizing:border-box;transition:background .2s,border-color .2s,transform .2s}
.node.ctl{width:.8rem;height:.8rem;margin:-.4rem 0 0 -.4rem;border-radius:2px}
.node.ok{background:var(--ok);border-color:var(--ok)}.node.no{background:var(--bad);border-color:var(--bad)}.node.missing{background:var(--card);border-color:var(--amber);border-style:dashed}
.node.fired{transform:scale(1.35)}.node.fired.settled{transform:none}
.node.ctl i{position:absolute;left:50%;transform:translateX(-50%);top:1.1rem;font-style:normal;font-family:var(--mono);font-size:.62rem;white-space:nowrap;color:var(--muted);transition:color .2s}
.node.ctl.below i{top:auto;bottom:1.1rem}
.node.ctl.ok i{color:var(--ok)}.node.ctl.no i{color:var(--bad);text-decoration:line-through}.node.ctl.missing i{color:var(--amber)}
.nonode{position:absolute;top:50%;transform:translate(-50%,-50%);font-family:var(--mono);font-size:.62rem;color:var(--muted);background:var(--card);padding:0 .4rem}
.gatebar{position:absolute;top:50%;width:3px;height:2.2rem;margin:-1.1rem 0 0 -1.5px}
.gatebar span{position:absolute;left:0;width:3px;height:50%;background:var(--ink);transition:transform .45s cubic-bezier(.2,.8,.2,1)}
.gatebar .top{top:0}.gatebar .bot{bottom:0}
.lane.open .gatebar .top{transform:translateY(-.9rem)}.lane.open .gatebar .bot{transform:translateY(.9rem)}
.lane.shut .gatebar span{background:var(--bad)}
.dock{position:absolute;top:50%;right:0;transform:translateY(-50%)}
.trav{position:absolute;top:50%;left:0;width:.95rem;height:.95rem;margin:-.475rem 0 0 -.475rem;border-radius:50%;background:var(--ink);box-shadow:0 0 0 3px var(--card);transform:translateX(0);will-change:transform;opacity:0}
.lane.playing .trav,.lane.done .trav{opacity:1}.lane.done .trav{background:var(--ok)}.lane.done.failed .trav,.lane.shut .trav{background:var(--bad)}
.verdict{font-family:var(--mono);font-size:.78rem;font-weight:600;opacity:0;transition:opacity .35s}
.allow .verdict{color:var(--ok)}.deny .verdict{color:var(--bad)}.step.done .verdict{opacity:1}
.why{font-size:.86rem;color:var(--muted);margin:.5rem 0 0;opacity:0;transition:opacity .4s}.step.done .why{opacity:1}
.token{margin:.8rem 0 0;padding:0 .7rem;border:0 solid var(--line);background:var(--sky);max-height:0;overflow:hidden;opacity:0;transition:max-height .5s ease-out,opacity .4s,padding .3s;box-sizing:border-box}
.step.done .token{max-height:26rem;opacity:1;padding:.6rem .7rem;border-width:1px}
.token dl{display:grid;grid-template-columns:max-content 1fr;gap:.1rem .9rem;margin:.35rem 0 0;font-family:var(--mono);font-size:.72rem}.token dt{color:var(--muted)}.token dd{margin:0;color:var(--ink)}.token dt.ext{color:var(--ok)}
.foot{font-family:var(--mono);font-size:.78rem;color:var(--muted);margin-top:1.4rem;line-height:1.7}.foot a{color:var(--ink)}
.muted{color:var(--muted)}
.again{font-family:var(--mono);font-size:.74rem;color:var(--muted);background:none;border:0;padding:0;cursor:pointer;text-decoration:underline}
@media (prefers-reduced-motion:reduce){.cert .lit,.verdict,.why,.token,.node,.gatebar span{transition:none}}
.instant .cert .lit,.instant .verdict,.instant .why,.instant .token,.instant .node,.instant .gatebar span,.instant .chain .dot{transition:none}
</style></head><body><main>
<h1>${esc(run.name)}: an agent under a grant, every action through the gate</h1>
<p class="lede">${tokens.length} intercepted actions, ${executed} executed. Each one is a gate. Scroll to a step and watch the action travel the lane, left to right: past every claim of the certificate as the verifier reads it, past every control the policy requires, to the gate, which parts for an ALLOW or stays shut for a DENY. Click a lane to run it again. Then the signed evidence token appears, chained to the step before; the green keys are the claims this profile adds.${baseline ? ' The dashed line above each certificate is the same step as Proof-of-Control records it today, without one.' : ''}${run.model ? ` The agent was ${esc(run.model)}.` : ''} <button class="again" type="button">run it again</button></p>
${rows}
${baseline ? `<p class="lede">Same scenario, reference gateway alone (${esc(baseline.run.name)}): ${baseline.tokens.length} intercepted, ${baseline.run.steps.filter((s) => s.executed).length} executed${baseRow && Object.keys(baseRow.unwarranted_executed || {}).length ? `, of which unwarranted: ${esc(Object.values(baseRow.unwarranted_executed).join('; '))}` : ''}. Its tokens pass the standard's validator just the same.</p>` : ''}
<p class="foot">grant: ${esc(policy.principal)}, ${esc(policy.grant.allowed_kinds.join(' '))} on ${esc(policy.grant.allowed_resources.join(', '))}, spend ${esc(String(policy.grant.max_spend))} EUR, egress up to ${esc(policy.grant.max_sensitivity_egress)}.<br>
policy bundle ${esc(run.policy_bundle_hash.slice(0, 12))}, measurement ${esc(run.measurement.slice(0, 12))}, chain head ${esc(run.chain_head.slice(0, 12))}, tree root ${esc(run.tree_root.slice(0, 12))}.${anchor ? ` Chain head <a href="${esc(anchor.search)}">anchored in Sigstore Rekor</a>, index ${esc(String(anchor.logIndex))}, ${esc(anchor.integratedAt)}.` : ''}<br>
Replay without a model or a gateway: <code>python3 verify.py ${esc(dir)}</code>. What this does not prove: that the registry is the right policy.</p>
</main>
<script>
(() => {
  const reduced = matchMedia('(prefers-reduced-motion: reduce)').matches || location.search.includes('instant');
  if (location.search.includes('instant')) document.documentElement.classList.add('instant');
  const steps = [...document.querySelectorAll('.step')];
  const marksOf = (s) => [...s.querySelectorAll('.cert .proveml-entity, .cert .proveml-fact, .cert .proveml-inference')];
  const isBad = (el) => el.classList.contains('proveml-failed');
  const raf = () => new Promise((r) => requestAnimationFrame(r));
  function reset(s) {
    const lane = s.querySelector('.lane'); s.classList.remove('done'); lane.classList.remove('playing', 'done', 'open', 'shut', 'failed');
    lane.querySelector('.fill').style.width = '0'; lane.querySelector('.trav').style.transform = 'translateX(0)';
    for (const n of lane.querySelectorAll('.node')) n.classList.remove('ok', 'no', 'missing', 'fired', 'settled');
    for (const el of marksOf(s)) el.classList.remove('lit', 'bad');
  }
  async function play(s) {
    if (s.dataset.playing) return; s.dataset.playing = '1'; reset(s);
    const lane = s.querySelector('.lane'); const g = JSON.parse(s.dataset.gate); const marks = marksOf(s);
    const inferences = [...s.querySelectorAll('.cert .proveml-inference')];
    const W = lane.clientWidth; const trav = lane.querySelector('.trav'); const fill = lane.querySelector('.fill');
    const stations = [...lane.querySelectorAll('.node')].map((n) => ({ el: n, x: parseFloat(n.style.left) / 100 * W, fired: false }));
    const gateX = 0.85 * W, dockX = 0.91 * W; const open = lane.dataset.open === '1';
    const endX = open ? dockX : gateX - 14;
    const speed = W / 3200;   // px per ms: a lane crosses in about three seconds
    let failed = false; lane.classList.add('playing');
    const fire = (st) => {
      st.fired = true; st.el.classList.add('fired'); setTimeout(() => st.el.classList.add('settled'), 260);
      if (st.el.classList.contains('claim')) {
        const el = marks[Number(st.el.dataset.m)]; if (!el) return;
        const bad = isBad(el); el.classList.add('lit'); if (bad) el.classList.add('bad');
        st.el.classList.add(bad ? 'no' : 'ok'); if (bad) { failed = true; lane.classList.add('failed'); }
        setTimeout(() => el.classList.remove('lit'), bad ? 1400 : 700);
      } else {
        const held = st.el.dataset.held === '1', argued = st.el.dataset.argued === '1';
        st.el.classList.add(!argued ? 'missing' : held ? 'ok' : 'no'); if (!held) { failed = true; lane.classList.add('failed'); }
        const el = inferences[Number(st.el.dataset.k)]; if (el && argued) { el.classList.add('pin'); setTimeout(() => el.classList.remove('pin'), 700); }
      }
    };
    if (reduced) {
      for (const st of stations) fire(st);
      trav.style.transform = 'translateX(' + endX + 'px)'; fill.style.width = endX + 'px';
      lane.classList.add(open ? 'open' : 'shut', 'done'); s.classList.add('done'); delete s.dataset.playing; return;
    }
    let x = 0, last = performance.now(); await raf();
    while (x < endX) {
      const now = performance.now(); const dt = Math.min(now - last, 50); last = now;
      const near = stations.some((st) => !st.fired && Math.abs(st.x - x) < 6);
      x = Math.min(endX, x + speed * dt * (near ? 0.35 : 1));   // ease past each station
      trav.style.transform = 'translateX(' + x + 'px)'; fill.style.width = x + 'px';
      for (const st of stations) if (!st.fired && st.x <= x) fire(st);
      if (open && x > gateX - 40 && !lane.classList.contains('open')) lane.classList.add('open');
      await raf();
    }
    if (!open) lane.classList.add('shut');
    lane.classList.add('done'); lane.classList.remove('playing'); s.classList.add('done'); delete s.dataset.playing;
  }
  const io = new IntersectionObserver((es) => es.forEach((e) => { if (e.isIntersecting && !e.target.classList.contains('done') && !e.target.dataset.playing) play(e.target); }), { threshold: 0.4 });
  steps.forEach((s) => { io.observe(s); s.querySelector('.lane').addEventListener('click', () => { if (!s.dataset.playing) play(s); }); });
  document.querySelector('.again').addEventListener('click', async () => { for (const s of steps) if (!s.dataset.playing) reset(s); for (const s of steps) { const r = s.getBoundingClientRect(); if (r.top < innerHeight && r.bottom > 0) await play(s); } });
  // hover a control station: pin the judgement that argues it
  document.querySelectorAll('.node.ctl').forEach((n) => {
    const s = n.closest('.step'); const el = [...s.querySelectorAll('.cert .proveml-inference')][Number(n.dataset.k)]; if (!el) return;
    n.addEventListener('mouseenter', () => el.classList.add('pin')); n.addEventListener('mouseleave', () => el.classList.remove('pin'));
  });
})();
</script>
</body></html>`);
