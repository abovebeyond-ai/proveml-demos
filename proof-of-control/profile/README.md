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

## The claims

Five claims are added to `poc_claims`, under the claim set's open extension
point (`* tstr => any`; verifiers that do not understand them ignore them).

| claim | type | meaning |
| --- | --- | --- |
| `proveml_certificate_hash` | digest (`sha-256:<hex>`, the token's own tagged form) | sha256 of the certificate text the agent supplied for this action |
| `proveml_store_hash` | digest | sha256 of the canonical store snapshot the gateway verified against |
| `proveml_registry_hash` | digest | sha256 of the canonical threshold registry in force |
| `proveml_required_controls` | array of text | the thresholds the policy required the certificate to argue for this action kind and resource |
| `proveml_verified` | bool | whether the certificate verified: every fact in the store, every judgement true, every required control argued |

Semantics a verifier enforces: if `proveml_verified` is false, `verdict` MUST be
`DENY`; the three digests MUST recompute from the published certificate, snapshot
and registry; re-running the certificate verifier on that material MUST
reproduce `proveml_verified`. The `policy_bundle_hash` of a conforming gateway
commits to the registry and the required-controls map as well as the grant.

## Files

- `poc-reason.cddl`: the claims in CDDL, as a fragment to be merged into the
  `poc-claims` map.
- `poc-reason.schema.json`: the same, as JSON Schema properties for the JWT
  rendering.
- `vectors/`: one positive vector (a real token from a run) and three negatives:
  a `DENY` verdict with `proveml_verified` true; a certificate hash that does not
  match the published certificate; a required control the certificate does not
  argue.
- `validate.py`: the extension checks, run after the standard's own validator.

## What it does not claim

The certificate proves that the premises of an action were true in the store
and that its judgements are registered thresholds that held. It does not prove
the registry is the right policy, and it does not make the agent's reasoning
sound beyond what the registry can express. Whether the controls were adequate
remains a person's judgement, the same line the standard draws.
