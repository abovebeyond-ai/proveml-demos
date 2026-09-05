"""Reason as evidence, on top of the Proof-of-Control reference implementation.

The reference gateway is used as it is: interception, path-aware policy,
hash-chained signed evidence, capability-bound dispatch, anchoring. One class
is wrapped and one is subclassed:

  ReasonedPolicyEngine   every action must carry a ProveML certificate that
                         justifies it against the policy's registry; the
                         certificate is verified deterministically against a
                         store snapshot the agent cannot edit, BEFORE the
                         reference policy runs; a certificate that does not
                         verify is a DENY with the verifier's reason
  ReasonedEnvironment    the reference evidence token, with the extension
                         claims added before signing (the claim set has an
                         open extension point): the certificate digest, the
                         store snapshot digest, the registry digest, the
                         controls the policy required, the verifier's result,
                         and the provenance of the facts the certificate bound

Every fact in the snapshot carries its provenance, the kind of guarantee it
really has, and the policy says which grade each field needs:

  inferred          extracted from a document by a machine (a PDF, pdftotext)
  inferred:signed   the same, and a person signed that the mapping is correct
  attested          stated in a credential whose issuer signed it
  presented         a credential presented by its holder for THIS action,
                    key-bound to a nonce the gateway chose
  ledger            recomputed from a signed, hash-chained ledger
  gateway           computed by the gateway from its own state
  policy            declared in the policy or the directory the gateway holds
  absent            no source; the value is the default and cannot be argued

Nothing else changes. Set POC_STANDARD to the ov-poc-standard checkout.
"""
import json, os, subprocess, sys, time, hashlib, tempfile, datetime, dataclasses
POC = os.environ.get('POC_STANDARD') or os.path.expanduser('~/Projects/ov-poc-standard')
if not os.path.isdir(POC): POC = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'ov-poc-standard')   # a sibling checkout, as CI lays it out
if not os.path.isdir(POC): POC = '/private/tmp/claude-501/-Volumes-shanedeconinck-be-Projects-proveml-all/aaffe3ee-a529-4c8f-bc96-24f5cec9bb0e/scratchpad/ov-poc-standard'
sys.path.insert(0, POC + '/impl')
from poc.core import (Action, Grant, PolicyEngine, AttestingEnvironment, EvidenceStore, Gateway,
                      TransparencyLog, Verifier, PathSummary, canonical, sha256, tag, untag)
HERE = os.path.dirname(os.path.abspath(__file__))
SOURCES = os.path.join(HERE, 'sources')
ORDER = PathSummary.ORDER
GRADE_RANK = {'absent': 0, 'inferred': 1, 'gateway': 2, 'inferred:signed': 2, 'attested': 3, 'presented': 4, 'ledger': 4, 'policy': 4}
rel = lambda p: os.path.relpath(p, HERE)

def node_json(*args):
    r = subprocess.run(['node', *args], capture_output=True, text=True, cwd=HERE)
    try: return json.loads(r.stdout.strip().splitlines()[-1])
    except Exception: return {'ok': False, 'why': 'node failed: ' + (r.stderr or r.stdout)[-200:]}

def load_policy(path=None):
    return json.load(open(path or os.path.join(HERE, 'policy.json')))

def load_data(path=None):
    """The directory the gateway holds (supplier and customer names, the
    allowlist) joined with the sources: invoices from the extraction, with the
    clerk's mapping signature checked; supplier vetting from the vetting desk's
    credentials, checked; each with its provenance under _prov."""
    d = json.load(open(path or os.path.join(HERE, 'data.json')))
    ex = json.load(open(os.path.join(SOURCES, 'extraction.json')))
    d['invoices'] = {}
    for iid, e in ex['invoices'].items():
        f = e['fields']; signed_fields = {k: v for k, v in f.items() if k != 'note'}
        prov = {'grade': 'inferred', 'source': 'sources/' + e['pdf'], 'pdf_sha256': e['pdf_sha256'], 'method': ex['method']}
        mp = os.path.join(SOURCES, 'invoices', iid + '.mapping.sdjwt')
        if os.path.exists(mp):
            m = node_json(os.path.join(SOURCES, 'check.mjs'), 'mapping', mp, e['pdf_sha256'])
            if m.get('ok') and m.get('fields') == signed_fields: prov.update({'grade': 'inferred:signed', 'mapping': rel(mp), 'signed_by': m['signer'], 'resolved': m['resolved'], 'checked_by': m.get('checked_by')})
            else: prov['mapping_error'] = m.get('why', 'the signed fields differ from the extraction')
        else: prov['why'] = 'no one has signed the mapping'
        d['invoices'][iid] = {'supplier': f['supplier'], 'amount': f['amount'], 'currency': f['currency'], 'due_in_days': f['due_in_days'], 'description': f['description'], **({'note': f['note']} if 'note' in f else {}), '_prov': prov}
    for sid, s in d['suppliers'].items():
        cp = os.path.join(SOURCES, 'credentials', sid + '.vetting.sdjwt')
        if os.path.exists(cp):
            c = node_json(os.path.join(SOURCES, 'check.mjs'), 'credential', cp)
            if c.get('ok') and c['claims'].get('supplier') == sid and c['claims'].get('vetted') is True:
                s['vetted'] = 1; s['_prov'] = {'grade': 'attested', 'credential': rel(cp), 'issuer': c['issuer'], 'vct': c['vct'], 'checked_at': c['claims'].get('checked_at')}
            else: s['vetted'] = 0; s['_prov'] = {'grade': 'absent', 'why': c.get('why', 'the credential does not attest this supplier')}
        else: s['vetted'] = 0; s['_prov'] = {'grade': 'absent', 'why': 'no vetting credential on file'}
    return d

def present_consent(policy, cid, action, phi, base):
    """Ask the customer's wallet to present the consent credential for this
    action: the nonce is derived from the action and the path, so a copy
    taken for another action cannot answer it."""
    nonce = sha256(canonical({'action': action.params.get('id'), 'path': phi.digest()}))[:32]
    aud = policy['principal'].split('#')[0] + '#gateway'
    r = subprocess.run(['node', os.path.join(SOURCES, 'wallet.mjs'), cid, nonce, aud], capture_output=True, text=True, cwd=HERE)
    if r.returncode != 0: return 0, {'grade': 'absent', 'why': 'the wallet did not answer: ' + r.stderr[-120:]}
    pf = (base or tempfile.mktemp()) + '.presentation.sdjwt'; open(pf, 'w').write(r.stdout)
    c = node_json(os.path.join(SOURCES, 'check.mjs'), 'presentation', pf, nonce, aud)
    if not c.get('ok'): return 0, {'grade': 'absent', 'why': 'presentation rejected: ' + c.get('why', '')}
    ok = c['claims'].get('customer') == cid and policy['purpose'] in c['claims'].get('purposes', [])
    return (1 if ok else 0), {'grade': 'presented', 'presentation': rel(pf) if base else None, 'issuer': c['issuer'], 'holder': c['holder'], 'nonce': nonce, 'aud': aud, 'presented_at': c['presented_at'], 'vct': c['vct']}

def ledger_spend(ledger, principal):
    """The spend so far, recomputed from the signed ledger (None when there is no ledger)."""
    if not ledger: return None, None
    v = node_json(os.path.join(SOURCES, 'ledger.mjs'), 'verify', ledger, principal)
    if not v.get('ok'): raise RuntimeError('ledger does not verify: ' + '; '.join(v.get('errors') or [v.get('why', '')]))
    return float(v['sum']), {'grade': 'ledger', 'ledger': rel(ledger), 'entries': v['entries'], 'head': v['head'], 'signer': v['signer'], 'sum_before': float(v['sum'])}

def ledger_paid(ledger, invoice):
    """How many times this invoice was paid, from the signed ledger the gateway keeps (the red team of
    2026-09-04 paid one invoice twice under the cap: nothing in the snapshot said it was already paid)."""
    if not ledger or not os.path.exists(ledger): return 0
    n = 0
    for line in open(ledger):
        if line.strip() and json.loads(line)['entry'].get('invoice') == invoice: n += 1
    return n

def action_name(p, kind, resource):
    """The action's name as the snapshot carries it: composed by the gateway from the action, never the
    agent's own words (which entered the store at a trusted grade and carried numbers past strict mode)."""
    if resource == 'payments.api': return 'pay invoice ' + str(p.get('invoice', '?'))
    if resource == 'mail.api': return 'mail ' + str(p.get('recipient', '?'))
    if resource == 'customers': return 'read customer ' + str(p.get('customer', '?'))
    return ('read ' if kind == 'db.read' else kind + ' ') + resource

def effective_classification(data, action):
    """What the action touches decides its classification, not the label the agent put on it."""
    if action.resource == 'customers':
        c = data['customers'].get(action.params.get('customer', ''))
        return (c or {}).get('classification', 'confidential')
    return 'internal'

def store_for(policy, data, action, phi, base=None, ledger=None):
    """The facts a certificate may bind: the action, what it touches, the grant,
    and the path so far. Computed by the gateway, never by the agent. Returns
    the store and, per field, its provenance."""
    p = action.params; aid = p.get('id', 'a')
    s = {}; prov = {}
    def put(path, value, pv): s[path] = value; prov[path] = pv
    G = {'grade': 'gateway'}; P = {'grade': 'policy'}
    inv = data['invoices'].get(p.get('invoice', ''))
    # a payment's supplier is the invoice's supplier, never a parameter: otherwise an agent
    # paying an unvetted supplier could name a vetted one and argue SUPPLIER_VETTED on it
    sup_id = inv['supplier'] if inv else p.get('supplier', '')
    sup = data['suppliers'].get(sup_id)
    amount = float(p.get('amount', 0) or 0)
    put(f'action:{aid}.name', action_name(p, action.kind, action.resource), G)
    put(f'action:{aid}.kind', action.kind, G)
    put(f'action:{aid}.resource', action.resource, G)
    if amount:
        put(f'action:{aid}.amount', amount, G)
        spent, lprov = ledger_spend(ledger, policy['principal'])
        if spent is not None and abs(spent - phi.spend) > 1e-9: raise RuntimeError(f'the ledger says {spent} spent, the path says {phi.spend}')
        put(f'action:{aid}.spend_after', (spent if spent is not None else phi.spend) + amount, lprov or G)
        if inv: put(f'action:{aid}.amount_delta', amount - float(inv['amount']), {**inv['_prov'], 'from': f'invoice:{p["invoice"]}.amount'})   # a derived value is no better than its weakest input
    put(f'action:{aid}.path_sensitivity_rank', ORDER[phi.sensitivity], G)
    if 'recipient' in p:
        put(f'action:{aid}.recipient', p['recipient'], G)
        put(f'action:{aid}.recipient_allowlisted', 1 if p['recipient'] in data['recipients']['allowlist'] else 0, {'grade': 'policy', 'from': 'data.json#recipients'})
    put(f'action:{aid}.purpose_matches', 1 if p.get('purpose') == policy['purpose'] else 0, G)
    if inv:
        iid = p['invoice']; ip = inv['_prov']
        put(f'invoice:{iid}.name', inv['description'], ip); put(f'invoice:{iid}.amount', float(inv['amount']), ip)
        put(f'invoice:{iid}.due_in_days', inv['due_in_days'], ip); put(f'invoice:{iid}.supplier', inv['supplier'], ip); put(f'invoice:{iid}.currency', inv['currency'], ip)
        put(f'invoice:{iid}.paid', ledger_paid(ledger, iid), {'grade': 'ledger', 'ledger': rel(ledger) if ledger else None, 'entries': ledger_paid(ledger, iid)})
    if sup:
        put(f'supplier:{sup_id}.name', sup['name'], {'grade': 'policy', 'from': 'data.json#suppliers'})
        put(f'supplier:{sup_id}.vetted', sup['vetted'], sup['_prov'])
    cust = data['customers'].get(p.get('customer', ''))
    if cust:
        cid = p['customer']; consented, cprov = present_consent(policy, cid, action, phi, base)
        put(f'customer:{cid}.name', cust['name'], {'grade': 'policy', 'from': 'data.json#customers'})
        put(f'customer:{cid}.consented', consented, cprov)
    put('grant:g.name', 'the grant', P); put('grant:g.max_spend', policy['grant']['max_spend'], P); put('grant:g.purpose', policy['purpose'], P)
    return s, prov

def record_execution(run_dir, action, res, policy):
    """Capability-bound dispatch happened: an executed payment goes to the
    signed ledger, which the next snapshot reads its spend from."""
    if not res.get('executed') or action.resource != 'payments.api': return None
    p = action.params
    return node_json(os.path.join(SOURCES, 'ledger.mjs'), 'append', os.path.join(run_dir, 'ledger.jsonl'),
                     json.dumps({'principal': policy['principal'], 'action': p.get('id'), 'invoice': p.get('invoice'), 'amount': float(p.get('amount', 0) or 0), 'at': datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')}))

class ReasonedPolicyEngine(PolicyEngine):
    def __init__(self, policy, data, run_dir, path_aware=True, require_certificate=True):
        g = policy['grant']
        super().__init__(Grant(policy['principal'], frozenset(g['allowed_kinds']), frozenset(g['allowed_resources']), float(g['max_spend']), g['max_sensitivity_egress']), path_aware)
        self.policy, self.data, self.run_dir, self.require = policy, data, run_dir, require_certificate
        self.registry_hash = sha256(canonical(policy['registry']))
        self.required_hash = sha256(canonical(policy['required_controls']))
        self.provenance_hash = sha256(canonical(policy.get('required_provenance', {})))
        # the policy bundle now commits to the reason policy as well as the grant
        self.bundle_hash = sha256(canonical({'reference_bundle': self.bundle_hash, 'registry': self.registry_hash, 'required_controls': self.required_hash, 'required_provenance': self.provenance_hash, 'version': 'poc-reason-2'}))
        self.last = None; self.step = 0

    def evaluate(self, action, phi):
        self.last = None
        if self.require is True:
            cert = action.params.get('certificate', '')
            os.makedirs(os.path.join(self.run_dir, 'steps'), exist_ok=True)
            base = os.path.join(self.run_dir, 'steps', f'{self.step:02d}')
            ledger = os.path.join(self.run_dir, 'ledger.jsonl')
            store, prov = store_for(self.policy, self.data, action, phi, base=base, ledger=ledger)
            required = self.policy['required_controls'].get(f'{action.kind}:{action.resource}')
            if required is None:
                self.step += 1; self.last = {'proveml_verified': False, 'proveml_required_controls': [], 'proveml_certificate_hash': tag(sha256(cert.encode())), 'proveml_store_hash': tag(sha256(canonical(store))), 'proveml_registry_hash': tag(self.registry_hash)}
                return 'DENY', f'no policy for {action.kind} on {action.resource}: an action kind the policy did not foresee is refused, not waved through'
            json.dump(store, open(base + '.store.json', 'w'), indent=1); open(base + '.cert.md', 'w').write(cert)
            json.dump(self.policy['registry'], open(base + '.registry.json', 'w')); json.dump(prov, open(base + '.provenance.json', 'w'), indent=1)
            try:
                r = subprocess.run(['node', os.path.join(HERE, 'verify-cert.mjs'), base + '.store.json', base + '.registry.json', base + '.cert.md', ','.join(required), base + '.provenance.json', json.dumps(self.policy.get('required_provenance', {}))], capture_output=True, text=True, cwd=HERE, timeout=20)
                result = json.loads(r.stdout.strip().splitlines()[-1])
            except subprocess.TimeoutExpired: result = {'verified': False, 'errors': ['certificate verifier did not answer within 20 seconds'], 'bound': []}
            except Exception: result = {'verified': False, 'errors': ['certificate verifier failed: ' + (r.stderr or r.stdout)[-300:]], 'bound': []}
            json.dump(result, open(base + '.verify.json', 'w'), indent=1)
            self.last = {'proveml_certificate_hash': tag(sha256(cert.encode())), 'proveml_store_hash': tag(sha256(canonical(store))), 'proveml_registry_hash': tag(self.registry_hash),
                         'proveml_required_controls': required, 'proveml_verified': bool(result['verified']),
                         'proveml_provenance_hash': tag(sha256(canonical(prov))), 'proveml_provenance': {p: prov.get(p, {}).get('grade', 'absent') for p in result.get('bound', [])}}
            self.step += 1
            if not result['verified']:
                return 'DENY', 'certificate does not verify: ' + '; '.join(result['errors'])[:240]
        elif self.require == 'predicate':
            # the baseline the red team asked for: the gateway evaluates the same registry, controls and grades
            # itself, from the same snapshot, with no certificate; a judgement reads every store path carrying its field
            os.makedirs(os.path.join(self.run_dir, 'steps'), exist_ok=True)
            base = os.path.join(self.run_dir, 'steps', f'{self.step:02d}'); ledger = os.path.join(self.run_dir, 'ledger.jsonl')
            store, prov = store_for(self.policy, self.data, action, phi, base=base, ledger=ledger)
            json.dump(store, open(base + '.store.json', 'w'), indent=1); json.dump(prov, open(base + '.provenance.json', 'w'), indent=1)
            required = self.policy['required_controls'].get(f'{action.kind}:{action.resource}'); self.step += 1
            if required is None: return 'DENY', f'no policy for {action.kind} on {action.resource}'
            failed = []
            for name in required:
                th = self.policy['registry'][name]; paths = [p for p in store if p.endswith('.' + th['field'])]
                if not paths: failed.append(f'{name}: no {th["field"]} in the snapshot'); continue
                for p in paths:
                    val = store[p]; ok = {'<=': val <= th['value'], '<': val < th['value'], '>=': val >= th['value'], '>': val > th['value'], '==': val == th['value'], '!=': val != th['value']}[th['op']]
                    if not ok: failed.append(f'{name}: {p} is {val}')
                    need = self.policy.get('required_provenance', {}).get(p.split(':')[0] + '.' + th['field']); g = prov.get(p, {}).get('grade', 'absent')
                    if need and GRADE_RANK.get(g, 0) < GRADE_RANK[need]: failed.append(f'{p} is {g}; policy requires {need}')
            self.last = {'poc_predicate': True, 'poc_predicate_controls': required, 'poc_predicate_failed': failed[:8]}
            if failed: return 'DENY', 'predicate: ' + '; '.join(failed)[:240]
        else:
            self.step += 1
        return super().evaluate(action, phi)

class ReasonedEnvironment(AttestingEnvironment):
    """The reference evaluate_and_evidence, with the extension claims added to
    poc_claims before the token is signed. Kept line for line with the
    reference otherwise; a diff shows one insertion."""
    def evaluate_and_evidence(self, action, nonce, agent_id):
        snap = {'agent_id': agent_id, 'action': json.loads(action.canonical_form()), 'path_summary': self.phi.digest(), 'step_index': self.step_index}
        snap_bytes = canonical(snap); snap_digest = sha256(snap_bytes)
        verdict, reason = self.policy.evaluate(action, self.phi)
        leaf = sha256((self.chain_head + snap_digest + verdict).encode()); self.chain_head = leaf
        self.tree.append(canonical({'snapshot': snap_digest, 'verdict': verdict}))
        self.phi = self.phi.fold(action, verdict)
        claims = {'agent_id': agent_id, 'initiating_user': self.policy.grant.principal, 'agbom_digest': tag(self.agbom_digest), 'interception_point': 'PRE_CALL_TOOL_INVOCATION', 'step_index': self.step_index, 'chain_head': tag(leaf), 'merkle_root': tag(self.tree.root().hex()), 'tree_size': self.tree.size, 'policy_bundle_hash': tag(self.policy.bundle_hash), 'target_resource': action.resource, 'canonical_snapshot_hash': tag(snap_digest), 'path_summary_hash': tag(snap['path_summary']), 'verdict': verdict, 'reason': reason, 'alg': 'EdDSA'}
        if getattr(self.policy, 'last', None): claims.update(self.policy.last)   # <-- the one insertion
        token = {'iss': 'https://verifier.example/poc', 'iat': int(time.time()), 'nonce': nonce, 'eat_profile': 'https://advancedaisociety.org/poc/v0.1', 'poc_claims': claims, 'submods': {'attestation': {'platform': 'SOFTWARE', 'measurement': tag(self.measurement)}}}
        token['signature'] = self._sign(canonical(token)).hex()
        token_bytes_signed = canonical(token)
        capability = None
        if verdict == 'ALLOW':
            cap_body = {'evidence_digest': tag(sha256(token_bytes_signed)), 'step_index': self.step_index, 'snapshot_hash': tag(snap_digest), 'action_digest': tag(sha256(action.canonical_form())), 'resource': action.resource, 'nonce': nonce, 'measurement': tag(self.measurement), 'alg': 'EdDSA'}
            capability = dict(cap_body); capability['signature'] = self._sign(canonical(cap_body)).hex(); self._nonces_issued.add(nonce)
        self.step_index += 1
        if self.anchor is not None:
            now = time.time()
            if now - self._last_anchor >= self.anchor_interval_s:
                self.anchor.publish(self.chain_head, self.step_index, self._sign, tree_root=self.tree.root().hex()); self._last_anchor = now
        return {'token': token, 'capability': capability, 'verdict': verdict, 'snapshot': snap}

def make_gateway(run_dir, policy=None, data=None, path_aware=True, require_certificate=True, agent_id='did:web:abovebeyond.ai#agent-ap'):
    policy = policy or load_policy(); data = data or load_data()
    os.makedirs(run_dir, exist_ok=True)
    ledger = os.path.join(run_dir, 'ledger.jsonl')
    open(ledger, 'w').close()   # a run starts with an empty ledger: no entries, spend 0, still a ledger
    engine = ReasonedPolicyEngine(policy, data, run_dir, path_aware, require_certificate)
    log = TransparencyLog('demo-log')
    env = ReasonedEnvironment(engine, anchor=log, anchor_interval_s=0.0)
    store = EvidenceStore()
    gw = Gateway(env, store, agent_id=agent_id)
    submit = gw.submit
    def reclassified_submit(action):
        # never the agent's label: a confidential read under "public" defeated egress in the red team of 2026-09-04
        return submit(dataclasses.replace(action, classification=effective_classification(data, action)))
    gw.submit = reclassified_submit
    return gw, env, store, log, engine

def run_steps(name, steps, path_aware=True, require_certificate=True):
    """steps: list of dicts {kind, resource, params, classification}. require_certificate: True (reason as
    evidence), False (the reference gateway alone), or 'predicate' (the gateway evaluates the registry itself).
    Returns the run record."""
    run_dir = os.path.join(HERE, 'runs', name)
    gw, env, store, log, engine = make_gateway(run_dir, path_aware=path_aware, require_certificate=require_certificate)
    out = []
    for st in steps:
        a = Action(st['kind'], st['resource'], dict(st.get('params', {})), st.get('classification', 'public'))
        res = gw.submit(a)
        record_execution(run_dir, a, res, engine.policy)
        out.append({'step': st['params'].get('id'), 'name': st['params'].get('name'), 'verdict': res['verdict'], 'reason': res.get('reason', res.get('token', {}).get('poc_claims', {}).get('reason')), 'executed': res['executed']})
    env.force_anchor()
    record = {'name': name, 'path_aware': path_aware, 'require_certificate': require_certificate, 'public_key': env.pk.public_bytes_raw().hex(), 'measurement': env.measurement, 'policy_bundle_hash': engine.bundle_hash, 'chain_head': env.chain_head, 'tree_root': env.tree.root().hex(), 'anchor': log.latest(), 'steps': out}
    json.dump(store.records, open(os.path.join(run_dir, 'tokens.json'), 'w'), indent=1)
    json.dump(record, open(os.path.join(run_dir, 'run.json'), 'w'), indent=1)
    v = Verifier(env.pk, env.measurement); ok, msg = v.verify_chain(store.records, log)
    record['chain_check'] = msg
    return record
