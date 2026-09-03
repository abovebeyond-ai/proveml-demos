// The customer's wallet, answering a presentation request: the consent
// credential with a key-binding JWT over the verifier's nonce and audience.
// The fact the gateway gets is therefore PRESENTED for this action, now, by
// the holder the credential was bound to; a copy of the credential taken
// earlier cannot answer a fresh nonce. In production this is an OpenID4VP
// request to the customer's wallet; here it is a local script with the same
// cryptography.
// usage: node wallet.mjs <customer-id> <nonce> <aud>   (prints the presentation)
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { HERE, loadKey, holder } from './lib.mjs';

const [customer, nonce, aud] = process.argv.slice(2);
const key = loadKey(join(HERE, 'keys', 'customer-wallet.jwk'));
const credential = readFileSync(join(HERE, 'credentials', customer + '.consent.sdjwt'), 'utf8');
const presentation = await holder(key.privateJwk).present(credential, {}, { kb: { payload: { aud, nonce, iat: Math.floor(Date.now() / 1000) } } });
process.stdout.write(presentation);
