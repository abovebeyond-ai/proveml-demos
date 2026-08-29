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
    const sel = $('#model');
    sel.innerHTML = models.map(m => `<option value="${esc(m.id)}">${esc(m.label)}</option>`).join('');
    if (!models.length) { $('#go').disabled = true; $('#go-meta').textContent = 'no model configured on this server'; }
}

async function loadSnapshot() {
    const snap = await api('/api/ledger/snapshot');
    $('#snapshot-meta').innerHTML = `snapshot <b>${esc(snap.snapshot.id)}</b> · <a href="${esc(snap.snapshot.hashscan)}" target="_blank" rel="noopener">token on HashScan</a>`;
    const rows = Object.entries(snap.facts).filter(([k]) => !k.endsWith('._unit')).map(([k, v]) => {
        const unit = snap.facts[`${k}._unit`] ? ` ${snap.facts[`${k}._unit`]}` : '';
        return `<tr><td class="path">${esc(k)}</td><td class="val">${esc(v)}${esc(unit)}</td><td><a href="${esc(snap.proofs[k])}" target="_blank" rel="noopener">mirror node ↗</a></td></tr>`;
    });
    $('#facts tbody').innerHTML = rows.join('');
    $('#registry tbody').innerHTML = Object.entries(snap.thresholds).map(([n, t]) =>
        `<tr><td class="path">${esc(n)}</td><td class="val">${esc(t.field)} ${esc(t.op)} ${esc(t.value)}${t.unit ? ' ' + esc(t.unit) : ''}</td><td>“${esc(t.label)}” <span class="meta">source: ${esc(t.source)}</span></td></tr>`).join('');
}

async function writeReport() {
    const btn = $('#go'); btn.disabled = true; $('#go-meta').textContent = 'reading the ledger, then asking the model…';
    $('#report').hidden = true; $('#anchor-section').hidden = true; $('#anchored').hidden = true;
    try {
        const r = await api('/api/ledger/report', { model: $('#model').value });
        current = r;
        const v = r.verification;
        const cov = v.coverage.rate === null ? 'n/a' : `${Math.round(v.coverage.rate * 100)}%`;
        const outside = v.details.filter(d => d.type === 'unmarked').length;
        $('#verdict').innerHTML = `<span><b class="${v.verified === v.total ? 'good' : 'poor'}">${v.verified}/${v.total}</b> claims verified</span><span>coverage <b>${cov}</b>${outside ? ` (${outside} number${outside === 1 ? '' : 's'} outside any claim)` : ''}</span><span>${esc(r.model)} · ${(r.ms / 1000).toFixed(1)} s</span><span>snapshot ${esc(r.snapshot.id)}</span>`;
        $('#rendered').innerHTML = r.html;
        // proof paths -> links to the mirror node
        for (const el of $('#rendered').querySelectorAll('.proveml-proof')) {
            const path = el.textContent.replace(/^\[|\]$/g, '');
            if (r.proofs[path]) el.innerHTML = `<a href="${esc(r.proofs[path])}" target="_blank" rel="noopener" title="open the mirror-node query">[${esc(path)}]</a>`;
        }
        $('#markup').textContent = r.markup;
        $('#selfcheck').textContent = `# save the markup as report.md and the snapshot as facts.json, then:\nnpx proveml verify --input report.md --facts facts.json --strict\n\n# ${v.verified}/${v.total} claims verified, ${v.errors.length} finding${v.errors.length === 1 ? '' : 's'}${v.errors.length ? ':\n# - ' + v.errors.join('\n# - ') : ''}`;
        $('#report').hidden = false;
        $('#anchor-section').hidden = false;
        $('#anchor').disabled = !r.canAnchor;
        $('#anchor-meta').textContent = r.canAnchor ? '' : 'no Hedera operator configured on this server';
        $('#go-meta').textContent = '';
    } catch (e) {
        $('#go-meta').innerHTML = `<span class="error">${esc(e.message)}</span>`;
    } finally { btn.disabled = false; }
}

async function anchorVerdict() {
    const btn = $('#anchor'); btn.disabled = true; $('#anchor-meta').textContent = 'submitting to the consensus service…';
    try {
        const a = await api('/api/ledger/anchor', { reportId: current.id });
        $('#anchored').innerHTML = `<p>Sequence <b>${esc(a.where.sequenceNumber)}</b> on topic <a href="${esc(a.where.hashscanTopic)}" target="_blank" rel="noopener">${esc(a.where.topicId)}</a> (${esc(a.where.network)}) · <a href="${esc(a.where.hashscanTx)}" target="_blank" rel="noopener">transaction on HashScan</a> · <a href="${esc(a.where.mirror)}" target="_blank" rel="noopener">read it back from the mirror node</a></p><pre>${esc(JSON.stringify(a.payload, null, 2))}</pre>`;
        $('#anchored').hidden = false; $('#anchor-meta').textContent = '';
    } catch (e) {
        $('#anchor-meta').innerHTML = `<span class="error">${esc(e.message)}</span>`; btn.disabled = false;
    }
}

$('#go').addEventListener('click', writeReport);
$('#anchor').addEventListener('click', anchorVerdict);
loadModels().catch(e => { $('#go-meta').innerHTML = `<span class="error">${esc(e.message)}</span>`; });
loadSnapshot().catch(e => { $('#snapshot-meta').innerHTML = `<span class="error">${esc(e.message)}</span>`; });
