# ProveML demos

Two live demos of [ProveML](https://github.com/abovebeyond-ai/proveml) on sources
nobody invented: the Hedera ledger and an EU Digital Identity Wallet credential.
Press a button, a frontier model writes the text, a program with no model in it
checks every claim, and the verdict can be anchored or issued as a credential.

```bash
npm install
npm start            # http://localhost:3939
```

## What runs behind the buttons

**Ledger** (`/`): the fact store is USDC on Hedera mainnet (`0.0.456858`), read from
the public mirror node at one consensus timestamp (`adapters/hedera-mirror.mjs`).
Every fact carries the mirror-node query that produced it as its proof reference.
The model writes the daily report in ProveML; `verifyProveml` checks each entity,
number and judgement against that snapshot; the page renders the audit view with a
link per claim. A second button posts the verdict (snapshot id, counts, hash of the
report, verifier version) to a Hedera Consensus Service topic (`adapters/hedera-hcs.mjs`).

**Identity** (`/identity.html`): the fact store is a Person Identification Data
credential in the EUDI format, SD-JWT VC with `vct: urn:eudi:pid:1` and the claim
names of the PID Rulebook v1.7 (`adapters/pid-sdjwt.mjs`). The holder discloses a
chosen subset with a key-binding JWT over the verifier's nonce; the relying party
verifies issuer signature, key binding and digests with the OpenWallet Foundation
sd-jwt library. The model drafts an account-opening summary; the verifier checks it
against the disclosed attributes only. A third button issues the verdict as an
SD-JWT VC (`urn:proveml:verification:1`).

The registries (`registry/`) are demo policy and say so in their `source`; in a
deployment they are the issuer's covenants or the bank's onboarding rules.

## Configuration (all optional, all outside the repo)

| file | purpose |
|---|---|
| `~/.config/proveml/together-key` | DeepSeek V4 Pro through Together AI |
| `~/.config/proveml/anthropic-key` or `ANTHROPIC_API_KEY` | Claude Opus 5 / Sonnet 5 through the Anthropic SDK |
| `~/.config/proveml/hedera-operator.json` | `{ "network": "testnet", "accountId": "0.0.x", "privateKey": "302e…" }`; a topic is created on first use and written back |

Without a Hedera operator the anchor button is disabled; without a model key the
report button is. Nothing else needs credentials: the mirror node is public.

## Boundaries, stated

- The verifier checks that text matches the store, not that the store is true. The
  ledger adds an audit trail for the verdict, not truth about the data.
- The PID has no age attribute; age is derived by the relying party in the adapter,
  as a fact with its own proof line, never inside the verifier.
- The credential is issued by a demo provider key. The EU reference issuer needs a
  browser step; the protocol after issuance is the real one.
