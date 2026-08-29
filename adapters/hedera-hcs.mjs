/**
 * Anchor a verification result on Hedera Consensus Service.
 *
 * What gets anchored is the verdict, not the text: the snapshot id the report
 * was checked against, the counts, the hash of the report, and the verifier
 * version. Anyone with the topic id can read it back from a mirror node with a
 * consensus timestamp and a sequence number that nobody, including us, can
 * change afterwards. That is what a ledger adds: an audit trail for the
 * verdict, not truth about the data.
 *
 * Operator credentials (a testnet account from portal.hedera.com) live in
 * ~/.config/proveml/hedera-operator.json:
 *   { "network": "testnet", "accountId": "0.0.x", "privateKey": "302e..." , "topicId": "0.0.y" }
 * topicId is optional: without it a topic is created once and written back.
 */
import { createHash } from 'crypto';
import { existsSync, readFileSync, writeFileSync } from 'fs';
import { homedir } from 'os';
import { join } from 'path';

const CONFIG = join(homedir(), '.config', 'proveml', 'hedera-operator.json');

export function hasOperator() {
    return existsSync(CONFIG);
}

function loadOperator() {
    if (!hasOperator()) throw new Error(`No Hedera operator: write ${CONFIG} (see adapters/hedera-hcs.mjs)`);
    return JSON.parse(readFileSync(CONFIG, 'utf8'));
}

let sdk;
async function loadSdk() {
    sdk ||= await import('@hiero-ledger/sdk');
    return sdk;
}

function privateKeyFrom(s, str) {
    // DER keys from the portal start with 302e (ED25519) or 3030 (ECDSA).
    return str.startsWith('3030') ? s.PrivateKey.fromStringECDSA(str) : s.PrivateKey.fromStringED25519(str);
}

async function client() {
    const op = loadOperator();
    const s = await loadSdk();
    const c = op.network === 'mainnet' ? s.Client.forMainnet() : s.Client.forTestnet();
    c.setOperator(op.accountId, privateKeyFrom(s, op.privateKey));
    return { c, op, s };
}

/** The message that goes on the ledger; small on purpose (1024-byte limit). */
export function anchorPayload({ markup, verification, snapshot, thresholds }) {
    return {
        v: 1,
        kind: 'proveml-verification',
        snapshot,
        reportSha256: createHash('sha256').update(markup).digest('hex'),
        registrySha256: createHash('sha256').update(JSON.stringify(thresholds)).digest('hex'),
        claims: { total: verification.total, verified: verification.verified },
        coverage: verification.coverage,
        verifier: 'proveml@0.3.0',
        at: new Date().toISOString(),
    };
}

/** Submit the payload; returns where it landed. */
export async function anchor(payload) {
    const { c, op, s } = await client();
    let topicId = op.topicId;
    if (!topicId) {
        const rx = await new s.TopicCreateTransaction().setTopicMemo('proveml verification anchors').execute(c);
        topicId = (await rx.getReceipt(c)).topicId.toString();
        writeFileSync(CONFIG, JSON.stringify({ ...op, topicId }, null, 2));
    }
    const message = JSON.stringify(payload);
    const tx = await new s.TopicMessageSubmitTransaction().setTopicId(topicId).setMessage(message).execute(c);
    const receipt = await tx.getReceipt(c);
    const txId = tx.transactionId.toString();
    const net = op.network || 'testnet';
    c.close();
    return {
        network: net,
        topicId,
        sequenceNumber: receipt.topicSequenceNumber?.toString(),
        transactionId: txId,
        hashscanTopic: `https://hashscan.io/${net}/topic/${topicId}`,
        hashscanTx: `https://hashscan.io/${net}/transaction/${txId}`,
        mirror: `https://${net}.mirrornode.hedera.com/api/v1/topics/${topicId}/messages/${receipt.topicSequenceNumber}`,
    };
}
