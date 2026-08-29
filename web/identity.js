const $ = (s) => document.querySelector(s);
const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
let current = null;

async function api(path, body) {
    const res = await fetch(path, body ? { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) } : undefined);
    const json = await res.json();
    if (!res.ok) throw new Error(json.error || res.statusText);
    return json;
}

async function loadModels() {
    const { models } = await api('/api/models');
    $('#model').innerHTML = models.map(m => `<option value="${esc(m.id)}">${esc(m.label)}</option>`).join('');
    if (!models.length) { $('#go').disabled = true; $('#go-meta').textContent = 'no model configured on this server; the examples below were written earlier'; }
}

function showSummary(r) {
    current = r;
    const v = r.verification;
    const cov = v.coverage.rate === null ? 'n/a' : `${Math.round(v.coverage.rate * 100)}%`;
    const when = r.writtenAt ? `<span>written ${esc(r.writtenAt.slice(0, 10))}</span>` : '';
    $('#verdict').innerHTML = `<span>credential <b class="${r.credentialStatus === 'verified' ? 'good' : 'poor'}">${esc(r.credentialStatus)}</b></span><span><b class="${v.verified === v.total ? 'good' : 'poor'}">${v.verified}/${v.total}</b> claims verified</span><span>coverage <b>${cov}</b></span><span>${esc(r.model)} · ${(r.ms / 1000).toFixed(1)} s</span>${when}`;
    $('#rendered').innerHTML = r.html;
    $('#markup').textContent = r.markup;
    $('#presentation').textContent = `disclosed: ${r.disclosed.join(', ') || '(nothing)'}\n\nfacts available to the verifier:\n${Object.entries(r.facts).map(([k, val]) => `  ${k} = ${val}\n      ${r.proofs[k]}`).join('\n')}\n\npresentation (SD-JWT ~ disclosures ~ KB-JWT):\n${r.presentation}`;
    $('#report').hidden = false;
    $('#attest-section').hidden = r.example === true;
    $('#attest').disabled = false;
}

async function loadExamples() {
    const { examples } = await api('/api/examples/identity');
    if (!examples.length) return;
    const box = $('#examples');
    box.innerHTML = `<span class="meta">or see one written earlier:</span> ` + examples.map((e, i) => `<button class="link" data-i="${i}">${esc(e.modelLabel || e.model)}${e.disclosed.length < 5 ? ' (name withheld)' : ''}</button>`).join(' ');
    box.hidden = false;
    box.addEventListener('click', (ev) => {
        const b = ev.target.closest('button[data-i]'); if (!b) return;
        showSummary({ ...examples[b.dataset.i], example: true });
        $('#report').scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
}

async function loadCredential() {
    const c = await api('/api/identity/credential');
    $('#cred-meta').innerHTML = `vct <b>${esc(c.vct)}</b> · issuer <b>${esc(c.issuer)}</b> · alg ES256 · ${c.disclosable.length} selectively disclosable claims`;
    $('#claims tbody').innerHTML = c.disclosable.map(k => `<tr><td><input type="checkbox" name="disclose" value="${esc(k)}" ${['given_name','family_name','birthdate','nationalities','address'].includes(k) ? 'checked' : ''}></td><td class="path">${esc(k)}</td><td class="val">${esc(typeof c.claims[k] === 'object' ? JSON.stringify(c.claims[k]) : c.claims[k])}</td></tr>`).join('');
    $('#registry tbody').innerHTML = Object.entries(c.thresholds).map(([n, t]) =>
        `<tr><td class="path">${esc(n)}</td><td class="val">${esc(t.field)} ${esc(t.op)} ${esc(t.value)}</td><td>“${esc(t.label)}” <span class="meta">source: ${esc(t.source)}</span></td></tr>`).join('');
}

async function draft() {
    const btn = $('#go'); btn.disabled = true; $('#go-meta').textContent = 'presenting, verifying the credential, then asking the model…';
    $('#report').hidden = true; $('#attest-section').hidden = true; $('#attested').hidden = true;
    const disclose = [...document.querySelectorAll('input[name=disclose]:checked')].map(i => i.value);
    try {
        const r = await api('/api/identity/summary', { model: $('#model').value, disclose });
        showSummary(r); $('#go-meta').textContent = '';
    } catch (e) {
        $('#go-meta').innerHTML = `<span class="error">${esc(e.message)}</span>`;
    } finally { btn.disabled = false; }
}

async function attest() {
    const btn = $('#attest'); btn.disabled = true; $('#attest-meta').textContent = 'signing…';
    try {
        const a = await api('/api/identity/attest', { reportId: current.id });
        $('#attested').innerHTML = `<pre>${esc(JSON.stringify(a.payload, null, 2))}</pre><details><summary>The credential (SD-JWT VC, compact)</summary><pre>${esc(a.vc)}</pre></details><details><summary>Verifier public key (JWK)</summary><pre>${esc(JSON.stringify(a.verifierJwk, null, 2))}</pre></details>`;
        $('#attested').hidden = false; $('#attest-meta').textContent = '';
    } catch (e) { $('#attest-meta').innerHTML = `<span class="error">${esc(e.message)}</span>`; btn.disabled = false; }
}

$('#go').addEventListener('click', draft);
$('#attest').addEventListener('click', attest);
loadModels().catch(e => { $('#go-meta').innerHTML = `<span class="error">${esc(e.message)}</span>`; });
loadExamples().catch(() => {});
loadCredential().catch(e => { $('#cred-meta').innerHTML = `<span class="error">${esc(e.message)}</span>`; });
