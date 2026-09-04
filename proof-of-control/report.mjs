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
  // the lane, in the four stages the gateway really goes through, left to right:
  //   extraction      the sources the bound facts came from, each with the grade it has and whether the policy accepts it
  //   interpretation  the records the prose names, resolved against the snapshot
  //   verification    every fact and judgement checked against the snapshot
  //   policy gate     the controls the policy requires, then the gate
  const marks = v.details.filter((d) => d.type === 'entity' || d.type === 'fact' || d.type === 'inference');   // reading order, same as the rendered marks
  const bound = Object.keys(c.proveml_provenance || {});
  const sources = []; const seenSrc = new Set();
  for (const p of bound) {
    const r = prov && prov[p]; if (!r || ['gateway', 'policy'].includes(r.grade)) continue;
    const key = r.source || r.credential || r.presentation || r.ledger || p; if (seenSrc.has(key)) continue; seenSrc.add(key);
    const need = policy.required_provenance[p.split(':')[0] + '.' + p.split('.').pop()];
    const met = !need || GRADES.indexOf(r.grade) >= GRADES.indexOf(need);
    const label = r.grade === 'ledger' ? 'ledger, ' + r.entries + (r.entries === 1 ? ' entry' : ' entries') : r.grade === 'presented' ? 'consent, presented' : r.grade === 'attested' ? 'vetting credential' : r.grade === 'absent' ? p.split('.').pop() + ': absent' : (r.source || '').split('/').pop() + (r.grade === 'inferred:signed' ? ', mapping signed' : ', unsigned');
    sources.push({ label, ok: met && r.grade !== 'absent', why: r.why || (need && !met ? 'policy requires ' + need : r.grade) });
  }
  const readable = (d) => d.type === 'entity' ? d.status === 'verified' : !/unverifiable|no-context|not-found|unknown/.test(d.status || '');
  const entities = marks.map((d, m) => ({ m, label: d.type === 'entity' ? d.path.replace(':', ' ') : d.type === 'fact' ? (d.path || '').split('.').pop() + ' = ' + d.value : (d.label || 'judgement'), ok: readable(d), kind: d.type }));
  const checks = marks.map((d, m) => ({ d, m })).filter(({ d }) => d.type !== 'entity').map(({ d, m }) => ({ m, ok: d.status === 'verified', label: d.type === 'fact' ? (d.path || '').split('.').pop() : (d.label || 'judgement') }));
  const reqControls = controls.filter((k) => k.required);
  const at = (i, n, a, b) => (n <= 1 ? (a + b) / 2 : a + (b - a) * i / (n - 1));
  const SEG = { extraction: [2, 14], interpretation: [19, 44], verification: [49, 64], policy: [69, 82] };
  const STAGE = { src: 'extraction', ent: 'reading', chk: 'checking', ctl: 'policy gate' };
  const node = (cls, x, attrs, label, alt) => `<span class="node ${cls}${alt ? ' below' : ''}" style="left:${x.toFixed(2)}%" data-stage="${STAGE[cls]}" data-label="${esc(label || '')}" ${attrs}>${label ? `<i>${esc(label)}</i>` : ''}</span>`;
  const srcNodes = sources.length ? sources.map((sr, i) => node('src', at(i, sources.length, ...SEG.extraction), `data-ok="${sr.ok ? 1 : 0}" title="${esc(sr.why || '')}"`, sr.label, i % 2)).join('') : `<span class="nonode" style="left:8%">gateway state only</span>`;
  const entNodes = entities.length ? entities.map((e, i) => node('ent', at(i, entities.length, ...SEG.interpretation), `data-m="${e.m}" data-ok="${e.ok ? 1 : 0}" data-kind="${e.kind}" title="${esc(e.label)}${e.ok ? '' : ': cannot be bound'}"`, e.label, i % 2)).join('') : `<span class="nonode" style="left:31.5%">no certificate</span>`;
  const chkNodes = checks.map((k, i) => node('chk', at(i, checks.length, ...SEG.verification), `data-m="${k.m}" data-ok="${k.ok ? 1 : 0}" title="${esc(k.label)}: ${k.ok ? 'verified' : 'failed'}"`, k.label, 0)).join('');
  const ctlNodes = reqControls.length ? reqControls.map((k, i) => node('ctl', at(i, reqControls.length, ...SEG.policy), `data-k="${k.k}" data-held="${k.held ? 1 : 0}" data-argued="${k.argued ? 1 : 0}" title="${esc(k.name)}: ${k.argued ? (k.held ? 'held' : 'false') : 'not argued'}"`, k.name.toLowerCase().replace(/_/g, ' '), i % 2)).join('') : `<span class="nonode" style="left:75.5%">no controls required</span>`;
  const lane = `<div class="stages"><span style="left:${SEG.extraction[0]}%">extraction</span><span style="left:${SEG.interpretation[0]}%">reading</span><span style="left:${SEG.verification[0]}%">checking</span><span style="left:${SEG.policy[0]}%">policy gate</span></div>
  <div class="lane" data-open="${gate.verified && c.verdict === 'ALLOW' ? 1 : 0}">
    <div class="track"><span class="fill"></span></div>
    ${srcNodes}${entNodes}${chkNodes}${ctlNodes}
    <div class="gatebar" style="left:87%"><span class="top"></span><span class="bot"></span></div>
    <div class="dock"><span class="verdict">${esc(c.verdict)}</span></div>
    <span class="trav"></span>
  </div>
  <p class="now"></p>`;
  const today = todayFor(st.step); const loss = today && baseRow && baseRow.unwarranted_executed && baseRow.unwarranted_executed[st.step];
  // what the agent intends, what the grant lets it do, what the policy demands it show: all read from the snapshot and the policy
  const aid = Object.keys(store).find((k) => k.startsWith('action:'))?.split('.')[0] || '';
  const sv = (f) => store[aid + '.' + f];
  const invId = Object.keys(store).find((k) => k.startsWith('invoice:'))?.split('.')[0]?.split(':')[1];
  const custId = Object.keys(store).find((k) => k.startsWith('customer:'))?.split('.')[0]?.split(':')[1];
  const intent = sv('kind') === 'http.post' && c.target_resource === 'payments.api' ? `pay ${sv('amount')} EUR against ${invId ? 'invoice ' + invId + ' (' + store['invoice:' + invId + '.name'] + ')' : 'an invoice'} to ${store['supplier:' + store['invoice:' + invId + '.supplier'] + '.name'] || 'its supplier'}`
    : c.target_resource === 'mail.api' ? `send mail to ${sv('recipient')}` : c.target_resource === 'customers' ? `read the record of customer ${custId} (${store['customer:' + custId + '.name']})` : `read ${c.target_resource}`;
  const g = policy.grant; const kindOk = g.allowed_kinds.includes(sv('kind') || c.target_resource.includes('.api') ? 'http.post' : 'db.read'); const resOk = g.allowed_resources.includes(c.target_resource);
  const may = `${sv('kind') || ''} on ${c.target_resource}${resOk && kindOk ? ' is within the grant' : ' is outside the grant'}; ${c.target_resource === 'payments.api' ? `single and cumulative spend up to ${g.max_spend} EUR` : c.target_resource === 'mail.api' ? `nothing above ${g.max_sensitivity_egress} may leave` : 'reads leave the path more sensitive, never less'}`;
  const controlWords = required.map((n) => (policy.registry[n] || {}).label || n.toLowerCase());
  const provWords = []; const rp = policy.required_provenance;
  if (invId) provWords.push(`invoice facts at ${rp['invoice.amount']}`); if (Object.keys(store).some((k) => k.startsWith('supplier:'))) provWords.push(`vetting ${rp['supplier.vetted']}`);
  if (custId) provWords.push(`consent ${rp['customer.consented']}`); if (sv('spend_after') !== undefined) provWords.push(`spend from the ${rp['action.spend_after']}`);
  const must = required.length ? `argue ${controlWords.join(', ')}` + (provWords.length ? `; facts: ${provWords.join(', ')}` : '') : 'nothing beyond the grant: a read inside it needs no argument' + (provWords.length ? `; facts: ${provWords.join(', ')}` : '');
  const tokenView = [['verdict', c.verdict], ['target_resource', c.target_resource], ['step_index', c.step_index], ['chain_head', short(c.chain_head)], ['merkle_root', short(c.merkle_root)], ['policy_bundle_hash', short(c.policy_bundle_hash)], ['path_summary_hash', short(c.path_summary_hash)],
    ...(c.proveml_verified !== undefined ? [['proveml_verified', String(c.proveml_verified)], ['proveml_certificate_hash', short(c.proveml_certificate_hash)], ['proveml_store_hash', short(c.proveml_store_hash)], ['proveml_registry_hash', short(c.proveml_registry_hash)], ['proveml_required_controls', (c.proveml_required_controls || []).join(' ') || '(none)'], ...(c.proveml_provenance_hash ? [['proveml_provenance_hash', short(c.proveml_provenance_hash)]] : [])] : []),
    ['signature', esc(String(t.signature).slice(0, 12))]];
  return `<section class="step ${c.verdict === 'ALLOW' ? 'allow' : 'deny'}" data-gate='${esc(JSON.stringify(gate))}'>
<h2><span class="nr">${String(c.step_index + 1).padStart(2, '0')}</span> ${esc(st.name || c.target_resource)} <span class="res">${esc(c.target_resource)}</span></h2>
<dl class="frame"><dt>intends</dt><dd>${esc(intent)}</dd><dt>may</dt><dd>${esc(may)}</dd><dt>must show</dt><dd>${esc(must)}</dd></dl>
${today ? `<p class="today"><span class="lbl">today, reference gateway alone</span> ${esc(today.step.verdict)}, reason <q>${esc(today.claims.reason || today.step.reason || '')}</q>${today.step.executed ? ', executed' : ''}.${loss ? ` <b>${esc(loss)}.</b>` : ''}</p>` : ''}
${cert ? `<div class="cert proveml-root">${rendered}</div>` : '<p class="muted">no certificate: the reference gateway alone does not ask for one.</p>'}
${prov && c.proveml_provenance ? `<p class="prov">${esc(provLine(prov, Object.keys(c.proveml_provenance)))}</p>` : ''}
<div class="gate">
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
h1{font-size:1.6rem;margin:0 0 .6rem;letter-spacing:-.01em}.thesis{font-size:1.18rem;line-height:1.5;color:var(--ink);max-width:58ch;margin:0 0 1.4rem}
.lede{color:var(--muted);margin:.6rem 0 0;max-width:66ch;font-size:.92rem}
.grant{display:grid;grid-template-columns:1fr 1.1fr 2.3fr;gap:1.6rem;padding:1rem 0 1.1rem;border-top:1px solid var(--line);border-bottom:1px solid var(--line);margin:0 0 1.2rem}
.grant h3{font-family:var(--mono);font-size:.7rem;font-weight:500;color:var(--muted);margin:0 0 .4rem}.grant p{margin:0;font-size:.92rem;line-height:1.5}
.req{display:grid;grid-template-columns:max-content 1fr;gap:.3rem .8rem;margin:0}.req dt{font-size:.86rem;color:var(--muted);padding-top:.15rem}.req dd{margin:0;display:flex;flex-wrap:wrap;gap:.3rem}
.chip{font-family:var(--mono);font-size:.68rem;padding:.12rem .45rem;border:1px solid var(--line);color:var(--ink);background:var(--card)}
.legend{margin:0 0 2rem}.legend .lane{cursor:default;height:4.2rem}.legend .node i{display:block !important}.legend .node.no i{text-decoration:none}
.step{position:relative;padding:1.6rem 0 1.4rem;border-top:1px solid var(--line)}
h2{font-size:1.15rem;margin:0 0 .5rem;display:flex;gap:.6rem;align-items:baseline}.nr{font-family:var(--mono);font-size:.8rem;color:var(--muted);font-weight:500}.res{margin-left:auto;font-family:var(--mono);font-size:.74rem;color:var(--muted);font-weight:400}
.frame{display:grid;grid-template-columns:max-content 1fr;gap:.15rem 1rem;margin:0 0 .9rem;font-size:.9rem}.frame dt{font-family:var(--mono);font-size:.7rem;color:var(--muted);padding-top:.2rem}.frame dd{margin:0;color:var(--muted)}.frame dd:first-of-type{color:var(--ink);font-size:1rem}
.today{font-size:.86rem;color:var(--muted);margin:0 0 .8rem;padding:.45rem .6rem;border:1px dashed var(--line)}.today .lbl,.token .lbl{font-family:var(--mono);font-size:.72rem;color:var(--ink);margin-right:.4rem}.today b{color:var(--bad);font-weight:600}.today q{quotes:"\\201C" "\\201D"}
.cert{font-size:1.22rem;line-height:1.55;max-width:60ch;color:var(--ink)}.cert p{margin:0 0 .6rem}
.cert .w{opacity:1}.cert.typing .w{opacity:0}.cert.typing .w.on{opacity:1}
.cert .proveml-entity,.cert .proveml-fact,.cert .proveml-inference{position:relative}
.cert .proveml-entity:not(.seen),.cert .proveml-fact:not(.seen),.cert .proveml-inference:not(.seen){border-bottom-color:transparent !important;color:inherit !important;text-decoration:none !important;font-weight:inherit !important;background:none !important}
.cert .seen:not(.judged){border-bottom-color:var(--muted) !important;color:inherit !important;text-decoration:none !important;background:none !important}
.bind{position:absolute;left:0;bottom:1.35em;font-family:var(--mono);font-size:.68rem;font-weight:500;color:var(--ink);background:var(--card);border:1px solid var(--line);padding:.1rem .4rem;white-space:nowrap;pointer-events:none;z-index:2;animation:rise 1.4s ease-out forwards}
.bind.bad{color:var(--bad);border-color:var(--bad)}.bind.stay{animation:none}
@keyframes rise{0%{opacity:0;transform:translateY(.3rem)}15%{opacity:1;transform:none}75%{opacity:1}100%{opacity:0;transform:translateY(-.2rem)}}
.cert .proveml-entity,.cert .proveml-fact,.cert .proveml-inference{transition:background-color .25s,box-shadow .25s}
.cert .lit{background-color:rgba(18,107,58,.14);box-shadow:0 0 0 3px rgba(18,107,58,.14)}
.cert .lit.bad{background-color:rgba(168,53,42,.14);box-shadow:0 0 0 3px rgba(168,53,42,.14)}
.cert .pin{background-color:rgba(14,36,51,.1);box-shadow:0 0 0 3px rgba(14,36,51,.1)}
.prov{font-size:.86rem;color:var(--muted);margin:.4rem 0 0}
.gate{margin:.9rem 0 0;padding:.8rem 0 0;border-top:1px solid var(--line)}
.stages{position:relative;height:1.1rem;margin:.3rem 0 0}.stages span{position:absolute;top:0;font-family:var(--mono);font-size:.66rem;color:var(--muted)}
.lane{position:relative;height:5rem;margin:0;cursor:pointer}
.track{position:absolute;left:0;right:9%;top:50%;height:.5rem;margin-top:-.25rem;background:var(--groove)}
.track .fill{position:absolute;left:0;top:0;bottom:0;width:0;background:var(--ok)}.lane.failed .track .fill{background:var(--bad)}
.node{position:absolute;top:50%;width:.55rem;height:.55rem;margin:-.275rem 0 0 -.275rem;border-radius:50%;background:var(--sky);border:1.5px solid var(--line);box-sizing:border-box;transition:background .2s,border-color .2s,transform .2s}
.node.ctl,.node.src,.node.ent{width:.8rem;height:.8rem;margin:-.4rem 0 0 -.4rem;border-radius:2px}
.node.ent{border-radius:50%}.node.ent[data-kind=fact]{border-radius:1px;width:.6rem;height:.6rem;margin:-.3rem 0 0 -.3rem}
.node.src,.node.ent[data-kind=inference]{border:0;background:none;border-radius:0}
.node.src::before,.node.ent[data-kind=inference]::before{content:"";position:absolute;inset:.06rem;border:1.5px solid var(--line);background:var(--sky);box-sizing:border-box;transform:rotate(45deg);transition:background .2s,border-color .2s,transform .2s}
.node.src.ok::before,.node.ent[data-kind=inference].ok::before{background:var(--ok);border-color:var(--ok)}.node.src.no::before,.node.ent[data-kind=inference].no::before{background:var(--bad);border-color:var(--bad)}
.node.src.fired::before,.node.ent[data-kind=inference].fired::before{transform:rotate(45deg) scale(1.3)}.node.src.fired.settled::before,.node.ent[data-kind=inference].fired.settled::before{transform:rotate(45deg)}
.node.ok{background:var(--ok);border-color:var(--ok)}.node.no{background:var(--bad);border-color:var(--bad)}.node.missing{background:var(--card);border-color:var(--amber);border-style:dashed}
.node.fired:not(.src):not([data-kind=inference]){transform:scale(1.35)}.node.fired.settled:not(.src):not([data-kind=inference]){transform:none}
.node i{display:none;position:absolute;left:50%;transform:translateX(-50%);top:1.1rem;font-style:normal;font-family:var(--mono);font-size:.62rem;white-space:nowrap;color:var(--muted)}
.node.no i,.node.missing i{display:block}.node.chk i{display:none !important}
.node.below i{top:auto;bottom:1.1rem}
.node.ok i{color:var(--ok)}.node.no i{color:var(--bad);text-decoration:line-through}.node.missing i{color:var(--amber)}
.nonode{position:absolute;top:50%;transform:translate(-50%,-50%);font-family:var(--mono);font-size:.62rem;color:var(--muted);background:var(--sky);padding:0 .4rem}
.gatebar{position:absolute;top:50%;width:3px;height:2.2rem;margin:-1.1rem 0 0 -1.5px}
.gatebar span{position:absolute;left:0;width:3px;height:50%;background:var(--ink);transition:transform .45s cubic-bezier(.2,.8,.2,1)}
.gatebar .top{top:0}.gatebar .bot{bottom:0}
.lane.open .gatebar .top{transform:translateY(-.9rem)}.lane.open .gatebar .bot{transform:translateY(.9rem)}
.lane.shut .gatebar span{background:var(--bad)}
.dock{position:absolute;top:50%;right:0;transform:translateY(-50%)}
.trav{position:absolute;top:50%;left:0;width:.95rem;height:.95rem;margin:-.475rem 0 0 -.475rem;border-radius:50%;background:var(--ink);box-shadow:0 0 0 3px var(--sky);transform:translateX(0);will-change:transform;opacity:0}
.lane.playing .trav,.lane.done .trav{opacity:1}.lane.done .trav{background:var(--ok)}.lane.done.failed .trav,.lane.shut .trav{background:var(--bad)}
.verdict{font-family:var(--mono);font-size:.78rem;font-weight:600;visibility:hidden}
.allow .verdict{color:var(--ok)}.deny .verdict{color:var(--bad)}.step.done .verdict{visibility:visible}
.now{font-family:var(--mono);font-size:.72rem;color:var(--muted);margin:0;min-height:1.2rem}.now b{font-weight:500;color:var(--ink)}.now.bad b{color:var(--bad)}.step.done .now{display:none}
.why{font-size:.86rem;color:var(--muted);margin:.2rem 0 0;display:none}.step.done .why{display:block}
.token{margin:.8rem 0 0;padding:0 .7rem;border:0 solid var(--line);background:var(--card);max-height:0;overflow:hidden;opacity:0;transition:max-height .5s ease-out,opacity .4s,padding .3s;box-sizing:border-box}
.step.done .token{max-height:26rem;opacity:1;padding:.6rem .7rem;border-width:1px}
.token dl{display:grid;grid-template-columns:max-content 1fr;gap:.1rem .9rem;margin:.35rem 0 0;font-family:var(--mono);font-size:.72rem}.token dt{color:var(--muted)}.token dd{margin:0;color:var(--ink)}.token dt.ext{color:var(--ok)}
.foot{font-family:var(--mono);font-size:.78rem;color:var(--muted);margin-top:1.4rem;line-height:1.7}.foot a{color:var(--ink)}
.muted{color:var(--muted)}
.again{font-family:var(--mono);font-size:.74rem;color:var(--muted);background:none;border:0;padding:0;cursor:pointer;text-decoration:underline}
@media (prefers-reduced-motion:reduce){.cert .lit,.verdict,.why,.token,.node,.gatebar span{transition:none}}
.instant .node,.instant .gatebar span,.instant .verdict,.instant .token{transition:none}
</style></head><body><main>
<script>window.REGISTRY = ${JSON.stringify(policy.registry)};</script>
<h1>${esc(run.name)}: an agent under a grant, every action through the gate</h1>
<p class="thesis">The agent forms its own intents, so the trust runs the other way round: a person is trusted until shown otherwise; an agent's intent is refused until it shows why it is warranted, in prose the gateway can check.</p>
<div class="grant">
  <div><h3>the agent</h3><p>${esc(tokens[0]?.poc_claims?.agent_id || 'the agent')}<br>${run.model ? esc(run.model) : 'scripted'}<br>acting for ${esc(policy.principal)}</p></div>
  <div><h3>may</h3><p>${esc(policy.grant.allowed_kinds.join(', '))}<br>on ${esc(policy.grant.allowed_resources.join(', '))}<br>spend up to ${esc(String(policy.grant.max_spend))} EUR, single and cumulative<br>nothing above ${esc(policy.grant.max_sensitivity_egress)} may leave<br>purpose ${esc(policy.purpose.split('/').pop())}</p></div>
  <div><h3>must show</h3>
    <dl class="req">${[['a payment', 'http.post:payments.api'], ['a mail', 'http.post:mail.api'], ['a customer record', 'db.read:customers']].map(([w, k]) => `<dt>${w}</dt><dd>${policy.required_controls[k].map((n) => `<span class="chip">${esc(policy.registry[n].label)}</span>`).join('')}</dd>`).join('')}
    <dt>the facts</dt><dd><span class="chip">invoice fields ${esc(policy.required_provenance['invoice.amount'])}</span><span class="chip">vetting ${esc(policy.required_provenance['supplier.vetted'])}</span><span class="chip">consent ${esc(policy.required_provenance['customer.consented'])}</span><span class="chip">spend from the ${esc(policy.required_provenance['action.spend_after'])}</span></dd></dl>
  </div>
</div>
<div class="legend">
  <div class="stages"><span style="left:2%">extraction</span><span style="left:26%">reading</span><span style="left:56%">checking</span><span style="left:74%">policy gate</span></div>
  <div class="lane static">
    <div class="track"><span class="fill" style="width:91%"></span></div>
    <span class="node src ok" style="left:6%"><i>a source, at its grade</i></span>
    <span class="node ent ok" style="left:28%"><i>a record</i></span><span class="node ent ok below" data-kind="fact" style="left:36%"><i>a number</i></span><span class="node ent ok" data-kind="inference" style="left:44%"><i>a judgement</i></span>
    <span class="node chk ok" style="left:58%"><i>checked</i></span><span class="node chk no below" style="left:64%"><i>failed</i></span>
    <span class="node ctl ok" style="left:76%"><i>a control</i></span><span class="node ctl no below" style="left:82%"><i>false</i></span>
    <div class="gatebar" style="left:87%"><span class="top"></span><span class="bot"></span></div>
    <div class="dock"><span class="verdict" style="visibility:visible;color:var(--muted)">verdict</span></div>
    <span class="trav" style="opacity:1;left:91%"></span>
  </div>
  <p class="lede">${tokens.length} intercepted actions, ${executed} executed. Each intent runs this lane, left to right, after the certificate appears as the agent wrote it: what its facts stand on, what its prose binds to, what holds, what the policy requires. The gate parts for an ALLOW and stays shut for a DENY; the signed token follows.${baseline ? ' The dashed line above each certificate is the same step as Proof-of-Control records it today.' : ''} <button class="again" type="button">run it again</button></p>
</div>
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
  // the prose as the agent wrote it: word by word, marks hidden until the reading pass
  function words(cert) {
    if (cert.dataset.words) return; cert.dataset.words = '1';
    const walker = document.createTreeWalker(cert, NodeFilter.SHOW_TEXT); const nodes = []; while (walker.nextNode()) nodes.push(walker.currentNode);
    for (const t of nodes) { if (!t.nodeValue.trim()) continue; const frag = document.createDocumentFragment(); for (const part of t.nodeValue.split(/(\\s+)/)) { if (!part) continue; if (/^\\s+$/.test(part)) frag.append(part); else { const w = document.createElement('span'); w.className = 'w'; w.textContent = part; frag.append(w); } } t.replaceWith(frag); }
  }
  const rule = (name) => { const r = (window.REGISTRY || {})[name]; return r ? name + ': ' + r.field + ' ' + r.op + ' ' + r.value : name; };
  const bindingOf = (el) => el.classList.contains('proveml-entity') ? (el.dataset.entity || '') : el.classList.contains('proveml-fact') ? (el.dataset.path || '') + ' = ' + (el.dataset.value || '') : rule(el.dataset.condition || '');
  function bubble(el, text, bad, stay) { for (const old of el.querySelectorAll('.bind')) old.remove(); const b = document.createElement('b'); b.className = 'bind' + (bad ? ' bad' : '') + (stay ? ' stay' : ''); b.textContent = text; el.append(b); if (!stay) setTimeout(() => b.remove(), 1450); return b; }
  async function type(s) {
    const cert = s.querySelector('.cert'); if (!cert) return; words(cert);
    const ws = [...cert.querySelectorAll('.w')]; cert.classList.add('typing'); for (const w of ws) w.classList.remove('on');
    const now = s.querySelector('.now'); now.classList.remove('bad'); now.textContent = 'the agent writes its certificate';
    const per = Math.max(14, Math.min(34, 2200 / Math.max(ws.length, 1))); let i = 0, t0 = performance.now();
    while (i < ws.length) { await raf(); const due = Math.floor((performance.now() - t0) / per); while (i < ws.length && i <= due) ws[i++].classList.add('on'); }
    cert.classList.remove('typing');
  }
  function reset(s) {
    const lane = s.querySelector('.lane'); s.classList.remove('done'); lane.classList.remove('playing', 'done', 'open', 'shut', 'failed');
    for (const el of marksOf(s)) { el.classList.remove('seen', 'judged'); for (const b of el.querySelectorAll('.bind')) b.remove(); }
    lane.querySelector('.fill').style.width = '0'; lane.querySelector('.trav').style.transform = 'translateX(0)';
    for (const n of lane.querySelectorAll('.node')) n.classList.remove('ok', 'no', 'missing', 'fired', 'settled');
    for (const el of marksOf(s)) el.classList.remove('lit', 'bad');
  }
  async function play(s) {
    if (s.dataset.playing) return; s.dataset.playing = '1'; reset(s);
    const lane = s.querySelector('.lane'); const g = JSON.parse(s.dataset.gate); const marks = marksOf(s);
    if (!reduced) await type(s); else { const cert = s.querySelector('.cert'); if (cert) { words(cert); cert.classList.remove('typing'); } }
    const inferences = [...s.querySelectorAll('.cert .proveml-inference')];
    const W = lane.clientWidth; const trav = lane.querySelector('.trav'); const fill = lane.querySelector('.fill');
    const stations = [...lane.querySelectorAll('.node')].map((n) => ({ el: n, x: parseFloat(n.style.left) / 100 * W, fired: false }));
    const gateX = 0.87 * W, dockX = 0.91 * W; const open = lane.dataset.open === '1';
    const endX = open ? dockX : gateX - 14;
    const speed = W / 3800;   // px per ms: a lane crosses in about three seconds
    let failed = false; lane.classList.add('playing');
    const now = s.querySelector('.now');
    const fire = (st) => {
      st.fired = true; st.el.classList.add('fired'); setTimeout(() => st.el.classList.add('settled'), 260);
      const okNow = st.el.classList.contains('ctl') ? st.el.dataset.held === '1' : st.el.dataset.ok === '1';
      const el = st.el.dataset.m !== undefined ? marks[Number(st.el.dataset.m)] : null;
      const text = st.el.classList.contains('ent') && el ? bindingOf(el) : st.el.dataset.label;
      now.textContent = ''; const b = document.createElement('b'); b.textContent = text; now.append(st.el.dataset.stage + ': ', b, okNow ? (st.el.classList.contains('chk') ? ', held' : '') : (st.el.classList.contains('ctl') && st.el.dataset.argued !== '1' ? ', not argued' : st.el.classList.contains('ent') ? ', cannot be bound' : ', failed'));
      now.classList.toggle('bad', !okNow);
      if (st.el.classList.contains('src')) {
        const ok = st.el.dataset.ok === '1'; st.el.classList.add(ok ? 'ok' : 'no'); if (!ok) { failed = true; lane.classList.add('failed'); }
      } else if (st.el.classList.contains('ent')) {
        const el = marks[Number(st.el.dataset.m)]; const ok = st.el.dataset.ok === '1';
        if (el) { el.classList.add('seen'); if (!reduced) bubble(el, bindingOf(el), !ok); }
        st.el.classList.add(ok ? 'ok' : 'no'); if (!ok) { failed = true; lane.classList.add('failed'); }
      } else if (st.el.classList.contains('chk')) {
        const el = marks[Number(st.el.dataset.m)]; const ok = st.el.dataset.ok === '1';
        if (el) { el.classList.add('seen', 'judged', 'lit'); if (!ok) el.classList.add('bad'); setTimeout(() => el.classList.remove('lit'), ok ? 600 : 1400); }
        st.el.classList.add(ok ? 'ok' : 'no'); if (!ok) { failed = true; lane.classList.add('failed'); }
      } else {
        const held = st.el.dataset.held === '1', argued = st.el.dataset.argued === '1';
        st.el.classList.add(!argued ? 'missing' : held ? 'ok' : 'no'); if (!held) { failed = true; lane.classList.add('failed'); }
        const el = inferences[Number(st.el.dataset.k)]; if (el && argued) { el.classList.add('pin'); setTimeout(() => el.classList.remove('pin'), 700); }
      }
    };
    if (reduced) {
      for (const st of stations) fire(st); for (const el of marks) el.classList.add('seen', 'judged');
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
  // hover a mark once judged: its binding
  document.querySelectorAll('.cert .proveml-entity, .cert .proveml-fact, .cert .proveml-inference').forEach((el) => {
    el.addEventListener('mouseenter', () => { if (el.classList.contains('judged')) bubble(el, bindingOf(el), el.classList.contains('proveml-failed') || el.classList.contains('proveml-mismatch'), true); });
    el.addEventListener('mouseleave', () => { for (const b of el.querySelectorAll('.bind')) b.remove(); });
  });
  // hover a control station: pin the judgement that argues it
  document.querySelectorAll('.node.ctl').forEach((n) => {
    const s = n.closest('.step'); const el = [...s.querySelectorAll('.cert .proveml-inference')][Number(n.dataset.k)]; if (!el) return;
    n.addEventListener('mouseenter', () => el.classList.add('pin')); n.addEventListener('mouseleave', () => el.classList.remove('pin'));
  });
})();
</script>
</body></html>`);
