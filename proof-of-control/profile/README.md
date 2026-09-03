# Reason as evidence: an extension profile for Proof-of-Control evidence tokens

Status: proposal, drafted against Proof-of-Control Working Draft v0.1 (schema
`https://advancedaisociety.org/poc/v0.1/poc-evidence.schema.json`). Intended as a
lab project beside KYA-OS, the Legal Context Protocol and OpenVTC, not as a change
to the core.

## The gap it fills

A Proof-of-Control token proves that a control held: the action was within the
grant, the path did not exceed the spend or egress bounds. Its `reason` claim is
free text, declared not security-relevant. Nothing in the token says whether the
action was warranted: that the invoice was due, the supplier vetted, the
recipient on the allowlist, the purpose the one the data's owner consented to.
An agent that pays a fraudulent invoice within its spend limit passes every
check. That is the loss an insurer prices and the question a regulator asks.

This profile makes the reason evidence of the same grade as the rest: before
the reference policy runs, the agent hands the gateway a certificate in ProveML,
plain prose in which every number is a claim on a named record, every entity a
named record, and every judgement a threshold from a registry the policy owner
declared in advance. The gateway verifies the certificate deterministically
against a store snapshot it computed itself, and only then evaluates the grant.
A certificate that does not verify is a `DENY`, recorded as the standard already
requires. Verification is binary and needs no privileged access, which is Tier 3.

The snapshot is the residual trust of that design, so the profile also says
where each fact in it came from. Every store path carries a provenance grade,
the policy says which grade each field needs, and a certificate that binds a
fact below its grade does not verify, however true the fact is.

## The claims

Seven claims are added to `poc_claims`, under the claim set's open extension
point (`* tstr => any`; verifiers that do not understand them ignore them).

| claim | type | meaning |
| --- | --- | --- |
| `proveml_certificate_hash` | digest (`sha-256:<hex>`, the token's own tagged form) | sha256 of the certificate text the agent supplied for this action |
| `proveml_store_hash` | digest | sha256 of the canonical store snapshot the gateway verified against |
| `proveml_registry_hash` | digest | sha256 of the canonical threshold registry in force |
| `proveml_required_controls` | array of text | the thresholds the policy required the certificate to argue for this action kind and resource |
| `proveml_verified` | bool | whether the certificate verified: every fact in the store, every judgement true, every required control argued, every bound fact at the grade the policy requires |
| `proveml_provenance_hash` | digest, optional | sha256 of the canonical provenance map of the snapshot |
| `proveml_provenance` | map of store path to grade, optional | the grade of each store path the certificate bound |

The grades, from weakest to strongest guarantee:

| grade | the fact is |
| --- | --- |
| `inferred` | extracted from a document by a machine |
| `inferred:signed` | the same, and a person signed that the mapping is correct (a credential over the document digest and the fields) |
| `attested` | stated in a credential its issuer signed |
| `presented` | a credential presented by its holder for this action, key-bound to a nonce the gateway chose |
| `ledger` | recomputed from a signed, hash-chained ledger |
| `gateway` | computed by the gateway from its own state |
| `policy` | declared in the policy or the directory the gateway holds |
| `absent` | without a source; the default value, which cannot satisfy a control |

Semantics a verifier enforces: if `proveml_verified` is false, `verdict` MUST be
`DENY`; the digests MUST recompute from the published certificate, snapshot,
registry and provenance map; every grade in `proveml_provenance` MUST equal the
map's grade for that path; re-running the certificate verifier on that material,
with the policy's required grades, MUST reproduce `proveml_verified`; and each
source the map names MUST re-check from the published files: the document
digest and the mapping signature, the credential signature, the presentation's
key binding against the recorded nonce and audience, the ledger chain up to the
recorded entry. The `policy_bundle_hash` of a conforming gateway commits to the
registry, the required-controls map and the required-provenance map as well as
the grant.

## Files

- `poc-reason.cddl`: the claims in CDDL, as a fragment to be merged into the
  `poc-claims` map.
- `poc-reason.schema.json`: the same, as JSON Schema properties for the JWT
  rendering.
- `vectors/`: one positive vector (a real token from a run, with its certificate,
  snapshot, registry and provenance map) and five negatives: a `DENY` verdict
  with `proveml_verified` true; a certificate that does not match its hash; a
  required control the certificate does not argue; a provenance map with a grade
  raised; and a real token for a payment on an unsigned extraction with the
  verdict and the verified flag forged, whose digests all hold and whose
  re-verification does not. `make-vectors.py` rebuilds them from the runs.
- `validate.py`: the extension checks, run after the standard's own validator.

## What it does not claim

The certificate proves that the premises of an action were true in the store,
that its judgements are registered thresholds that held, and that each premise
came from a source of the grade the policy asked for. It does not prove the
registry is the right policy, it does not prove the issuers of the credentials
are the right issuers, and it does not make the agent's reasoning sound beyond
what the registry can express. Whether the controls were adequate remains a
person's judgement, the same line the standard draws.
