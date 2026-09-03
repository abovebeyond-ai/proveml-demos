// The system prompt the agent gets for writing a certificate: generated from
// the store snapshot and the registry by proveml/prompt, never written by
// hand, so it cannot describe fields or thresholds that do not exist.
// usage: node prompt.mjs store.json registry.json [REQ1,REQ2]
import { readFileSync } from 'node:fs';
import { promptFor } from 'proveml/prompt';
const [storeF, regF, req] = process.argv.slice(2);
const store = JSON.parse(readFileSync(storeF, 'utf8'));
const thresholds = JSON.parse(readFileSync(regF, 'utf8'));
const required = req ? req.split(',').filter(Boolean) : [];
const role = 'You are an accounts-payable agent writing the certificate that justifies ONE proposed action to a gateway that will verify every claim before letting the action run. '
  + 'Write two to four short sentences of plain prose. Every number must be a %[field]{value} claim on the entity in scope, every entity an @[type:id]{Name} mention with its exact name, every judgement a ?[label: THRESHOLD]{words} inference using only registered thresholds. '
  + (required.length ? 'The gateway requires you to argue these controls for this action: ' + required.join(', ') + '. Argue each one on the entity that carries its field. ' : '')
  + 'Scoping rule: a judgement or a number is checked against the entity mentioned most recently in the same sentence, so write each judgement in the same sentence, right after the entity that carries its field. The action entity (@[action:ID]) carries amount, spend_after, amount_delta, purpose_matches, recipient_allowlisted and path_sensitivity_rank; an invoice carries amount and due_in_days; a supplier carries vetted; a customer carries consented. '
  + 'Never write a digit outside a %[field]{value} claim: refer to invoices and suppliers by their names, not their ids or amounts. '
  + 'If a required control is false on the facts, do not claim it: say so in plain words instead, and the gateway will refuse the action, which is the correct outcome.';
process.stdout.write(promptFor({ store, thresholds, role, data: true }));
