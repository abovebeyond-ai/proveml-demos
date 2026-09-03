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
  ReasonedEnvironment    the reference evidence token, with five extension
                         claims added before signing (the claim set has an
                         open extension point): the certificate digest, the
                         store snapshot digest, the registry digest, the
                         controls the policy required, and the verifier's
                         result

Nothing else changes. Set POC_STANDARD to the ov-poc-standard checkout.
"""
import json, os, subprocess, sys, time, hashlib, tempfile
POC = os.environ.get('POC_STANDARD') or os.path.expanduser('~/Projects/ov-poc-standard')
if not os.path.isdir(POC): POC = '/private/tmp/claude-501/-Volumes-shanedeconinck-be-Projects-proveml-all/aaffe3ee-a529-4c8f-bc96-24f5cec9bb0e/scratchpad/ov-poc-standard'
sys.path.insert(0, POC + '/impl')
from poc.core import (Action, Grant, PolicyEngine, AttestingEnvironment, EvidenceStore, Gateway,
                      TransparencyLog, Verifier, PathSummary, canonical, sha256, tag, untag)
HERE = os.path.dirname(os.path.abspath(__file__))
ORDER = PathSummary.ORDER

def load_policy(path=None):
    return json.load(open(path or os.path.join(HERE, 'policy.json')))

def load_data(path=None):
    return json.load(open(path or os.path.join(HERE, 'data.json')))

def store_for(policy, data, action, phi):
    """The facts a certificate may bind: the action, what it touches, the grant,
    and the path so far. Computed by the gateway, never by the agent."""
    p = action.params; aid = p.get('id', 'a')
    s = {}
    inv = data['invoices'].get(p.get('invoice', ''))
    # a payment's supplier is the invoice's supplier, never a parameter: otherwise an agent
    # paying an unvetted supplier could name a vetted one and argue SUPPLIER_VETTED on it
    sup_id = inv['supplier'] if inv else p.get('supplier', '')
    sup = data['suppliers'].get(sup_id)
    cust = data['customers'].get(p.get('customer', ''))
    amount = float(p.get('amount', 0) or 0)
    s[f'action:{aid}.name'] = p.get('name', f'action {aid}')
    s[f'action:{aid}.kind'] = action.kind
    s[f'action:{aid}.resource'] = action.resource
    if amount:
        s[f'action:{aid}.amount'] = amount
        s[f'action:{aid}.spend_after'] = phi.spend + amount
        if inv: s[f'action:{aid}.amount_delta'] = amount - float(inv['amount'])
    s[f'action:{aid}.path_sensitivity_rank'] = ORDER[phi.sensitivity]
    if 'recipient' in p: s[f'action:{aid}.recipient'] = p['recipient']; s[f'action:{aid}.recipient_allowlisted'] = 1 if p['recipient'] in data['recipients']['allowlist'] else 0
    s[f'action:{aid}.purpose_matches'] = 1 if p.get('purpose') == policy['purpose'] else 0
    if inv:
        iid = p['invoice']; s[f'invoice:{iid}.name'] = inv['description']; s[f'invoice:{iid}.amount'] = float(inv['amount']); s[f'invoice:{iid}.due_in_days'] = inv['due_in_days']; s[f'invoice:{iid}.supplier'] = inv['supplier']
    if sup:
        sid = sup_id; s[f'supplier:{sid}.name'] = sup['name']; s[f'supplier:{sid}.vetted'] = sup['vetted']
    if cust:
        cid = p['customer']; s[f'customer:{cid}.name'] = cust['name']; s[f'customer:{cid}.consented'] = 1 if policy['purpose'] in cust['consented_purposes'] else 0
    s['grant:g.name'] = 'the grant'; s['grant:g.max_spend'] = policy['grant']['max_spend']; s['grant:g.purpose'] = policy['purpose']
    return s

class ReasonedPolicyEngine(PolicyEngine):
    def __init__(self, policy, data, run_dir, path_aware=True, require_certificate=True):
        g = policy['grant']
        super().__init__(Grant(policy['principal'], frozenset(g['allowed_kinds']), frozenset(g['allowed_resources']), float(g['max_spend']), g['max_sensitivity_egress']), path_aware)
        self.policy, self.data, self.run_dir, self.require = policy, data, run_dir, require_certificate
        self.registry_hash = sha256(canonical(policy['registry']))
        self.required_hash = sha256(canonical(policy['required_controls']))
        # the policy bundle now commits to the reason policy as well as the grant
        self.bundle_hash = sha256(canonical({'reference_bundle': self.bundle_hash, 'registry': self.registry_hash, 'required_controls': self.required_hash, 'version': 'poc-reason-1'}))
        self.last = None; self.step = 0

    def evaluate(self, action, phi):
        self.last = None
        if self.require:
            cert = action.params.get('certificate', '')
            store = store_for(self.policy, self.data, action, phi)
            required = self.policy['required_controls'].get(f'{action.kind}:{action.resource}', [])
            os.makedirs(os.path.join(self.run_dir, 'steps'), exist_ok=True)
            base = os.path.join(self.run_dir, 'steps', f'{self.step:02d}')
            json.dump(store, open(base + '.store.json', 'w'), indent=1); open(base + '.cert.md', 'w').write(cert)
            json.dump(self.policy['registry'], open(base + '.registry.json', 'w'))
            r = subprocess.run(['node', os.path.join(HERE, 'verify-cert.mjs'), base + '.store.json', base + '.registry.json', base + '.cert.md', ','.join(required)], capture_output=True, text=True, cwd=HERE)
            try: result = json.loads(r.stdout.strip().splitlines()[-1])
            except Exception: result = {'verified': False, 'errors': ['certificate verifier failed: ' + (r.stderr or r.stdout)[-300:]]}
            json.dump(result, open(base + '.verify.json', 'w'), indent=1)
            self.last = {'proveml_certificate_hash': tag(sha256(cert.encode())), 'proveml_store_hash': tag(sha256(canonical(store))), 'proveml_registry_hash': tag(self.registry_hash), 'proveml_required_controls': required, 'proveml_verified': bool(result['verified'])}
            self.step += 1
            if not result['verified']:
                return 'DENY', 'certificate does not verify: ' + '; '.join(result['errors'])[:240]
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
    engine = ReasonedPolicyEngine(policy, data, run_dir, path_aware, require_certificate)
    log = TransparencyLog('demo-log')
    env = ReasonedEnvironment(engine, anchor=log, anchor_interval_s=0.0)
    store = EvidenceStore()
    gw = Gateway(env, store, agent_id=agent_id)
    return gw, env, store, log, engine

def run_steps(name, steps, path_aware=True, require_certificate=True):
    """steps: list of dicts {kind, resource, params, classification}. Returns the run record."""
    run_dir = os.path.join(HERE, 'runs', name); os.makedirs(run_dir, exist_ok=True)
    gw, env, store, log, engine = make_gateway(run_dir, path_aware=path_aware, require_certificate=require_certificate)
    out = []
    for st in steps:
        a = Action(st['kind'], st['resource'], dict(st.get('params', {})), st.get('classification', 'public'))
        res = gw.submit(a)
        out.append({'step': st['params'].get('id'), 'name': st['params'].get('name'), 'verdict': res['verdict'], 'reason': res.get('reason', res.get('token', {}).get('poc_claims', {}).get('reason')), 'executed': res['executed']})
    env.force_anchor()
    record = {'name': name, 'path_aware': path_aware, 'require_certificate': require_certificate, 'public_key': env.pk.public_bytes_raw().hex(), 'measurement': env.measurement, 'policy_bundle_hash': engine.bundle_hash, 'chain_head': env.chain_head, 'tree_root': env.tree.root().hex(), 'anchor': log.latest(), 'steps': out}
    json.dump(store.records, open(os.path.join(run_dir, 'tokens.json'), 'w'), indent=1)
    json.dump(record, open(os.path.join(run_dir, 'run.json'), 'w'), indent=1)
    v = Verifier(env.pk, env.measurement); ok, msg = v.verify_chain(store.records, log)
    record['chain_check'] = msg
    return record
