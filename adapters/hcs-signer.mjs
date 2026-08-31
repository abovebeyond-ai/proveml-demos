/**
 * Sign a ProveML review by anchoring it on Hedera Consensus Service.
 *
 * This is a signer adapter for proveml/review-flow: `async (review) => review`.
 * It attests, it never judges --- the verdicts pass through untouched, and what
 * lands on the ledger is not the review but its fingerprint: a hash of the
 * judgements, the counts, and who signed. Anyone holding the review JSON can
 * recompute the hash and check it against a consensus timestamp and sequence
 * number that nobody, including the signer, can change afterwards.
 *
 * Use it as the gate of an agent pipeline:
 *
 *   npx proveml review --facts store.json --evidence subjects.json \
 *     --await --out review.json --signer adapters/hcs-signer.mjs
 *
 * The review that comes back carries `attestation` with the topic, sequence
 * number and HashScan links. Operator credentials are the same file the other
 * Hedera adapters read (~/.config/proveml/hedera-operator.json).
 */
import { createHash } from 'crypto';
import { anchor } from './hedera-hcs.mjs';

/** The fingerprint that goes on the ledger; small on purpose (1024-byte limit). */
export function signoffPayload(review) {
    const judgements = review.judgements || {};
    const ids = Object.keys(judgements).sort();
    const canonical = JSON.stringify(ids.map((id) => [id, judgements[id].verdict, judgements[id].at]));
    return {
        v: 1,
        kind: 'proveml-review-signoff',
        reviewSha256: createHash('sha256').update(canonical).digest('hex'),
        judged: ids.length,
        flagged: ids.filter((id) => judgements[id].verdict === 'flag').length,
        ...(review.signedBy ? { signedBy: review.signedBy } : {}),
        at: review.signedAt || new Date().toISOString(),
    };
}

export default async function signReview(review) {
    const payload = signoffPayload(review);
    const anchored = await anchor(payload);
    return {
        ...review,
        attestation: {
            kind: 'hcs',
            reviewSha256: payload.reviewSha256,
            network: anchored.network,
            topicId: anchored.topicId,
            sequenceNumber: anchored.sequenceNumber,
            transactionId: anchored.transactionId,
            hashscanTx: anchored.hashscanTx,
            mirror: anchored.mirror,
        },
    };
}
