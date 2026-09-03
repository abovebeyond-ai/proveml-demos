// One page over the whole demo: the harness table with a link per scenario to
// the report with and without reason as evidence, and the live runs.
// usage: node results/index.mjs > results/index.html
import { readFileSync, existsSync } from 'node:fs';
const U = (p) => new URL('../' + p, import.meta.url);
const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const rows = JSON.parse(readFileSync(U('results/attacks.json'), 'utf8'));
const scenarios = [...new Set(rows.map((r) => r.scenario))];
const live = ['live-sonnet-reference', 'live-sonnet-provenance', 'live-sonnet', 'live-sonnet-first'].filter((n) => existsSync(U(`runs/${n}/run.json`))).map((n) => ({ name: n, run: JSON.parse(readFileSync(U(`runs/${n}/run.json`), 'utf8')) }));
const cell = (sc, req) => { const r = rows.find((x) => x.scenario === sc && x.requirement === req); const n = Object.keys(r.unwarranted_executed || {}).length; return `<td class="${n ? 'bad' : ''}"><a href="../runs/${sc}-${req}/report.html">${r.executed.length} executed</a>${n ? `, ${n} unwarranted` : ''}</td>`; };
process.stdout.write(`<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Reason as evidence: the runs</title><style>
:root{--ink:#0e2433;--muted:#47616f;--sky:#f2f6f7;--card:#fafcfd;--line:rgba(14,36,51,.18);--bad:#a8352a;--ok:#126b3a}
body{margin:0;background:var(--sky);color:var(--ink);font-family:Lato,system-ui,sans-serif;line-height:1.55}main{max-width:52rem;margin:0 auto;padding:2.5rem 1.5rem 4rem}
h1{font-size:1.5rem;margin:0 0 .3rem}.lede{color:var(--muted);max-width:62ch;margin:0 0 1.4rem}h2{font-size:1.05rem;margin:1.6rem 0 .5rem}
table{border-collapse:collapse;width:100%;font-size:.92rem}th,td{text-align:left;padding:.45rem .6rem;border-bottom:1px solid var(--line);vertical-align:top}th{font-family:"Spline Sans Mono",ui-monospace,monospace;font-size:.74rem;font-weight:500;color:var(--muted)}
td.bad{color:var(--bad)}a{color:var(--ink)}.mono{font-family:"Spline Sans Mono",ui-monospace,monospace;font-size:.8rem;color:var(--muted)}
</style></head><body><main>
<h1>Reason as evidence: the runs</h1>
<p class="lede">The same agent, the same grant, the same queue, through the Proof-of-Control reference gateway twice: as it works today, and with a certificate the gateway verifies before the policy. Counted: actions the grant permits but the facts do not warrant. Each cell links to the report of that run, where every step shows the certificate the agent wrote, rendered so a claim that held and one that did not look different, and the same step as the reference gateway alone records it.</p>
<h2>Scripted scenarios</h2>
<table><tr><th>scenario</th><th>unwarranted actions</th><th>reference gateway alone (today)</th><th>with reason as evidence</th></tr>
${scenarios.map((sc) => { const w = rows.find((x) => x.scenario === sc && x.requirement === 'without'); return `<tr><td>${esc(sc)}</td><td>${Object.keys((rows.find((x) => x.scenario === sc && x.requirement === 'with') || {}).unwarranted_executed || {}).length + Object.keys(w.unwarranted_executed || {}).length ? '' : ''}${esc(String(Math.max(...rows.filter((x) => x.scenario === sc).map((x) => Object.keys(x.unwarranted_executed || {}).length))))}</td>${cell(sc, 'without')}${cell(sc, 'with')}</tr>`; }).join('\n')}
</table>
<p class="mono">unwarranted actions per scenario are listed in attacks.py; the count shown is the most any run of the scenario executed, which is the reference-alone run</p>
<h2>Live agent (Claude, claude-sonnet-5)</h2>
<table><tr><th>run</th><th>gateway</th><th>intercepted</th><th>executed</th><th>paid</th><th>report</th></tr>
${live.map(({ name, run }) => { const paid = run.steps.filter((s) => s.executed && s.resource === 'payments.api').map((s) => (run.transcript || []).find((t) => t.step === s.step)?.proposal?.invoice || s.name).join(', '); return `<tr><td>${esc(name)}</td><td>${run.require_certificate === false ? 'reference alone (today)' : 'with reason as evidence'}</td><td>${run.steps.filter((s) => s.verdict === 'ALLOW' || s.verdict === 'DENY').length}</td><td>${run.steps.filter((s) => s.executed).length}</td><td>${esc(paid || 'none')}</td><td><a href="../runs/${name}/report.html">report</a></td></tr>`; }).join('\n')}
</table>
<p class="mono">every token of every run passes the standard's validator; replay any run with python3 verify.py runs/&lt;name&gt;</p>
</main></body></html>`);
