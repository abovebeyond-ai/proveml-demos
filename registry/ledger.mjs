/**
 * The vocabulary a ledger report may use for qualitative wording.
 *
 * These three are demo policies, and say so in their source: in a deployment
 * they would be the issuer's covenants or the regulator's limits, and the
 * point of the registry is that the model can use a name from it and nothing
 * else. It cannot invent the bound, the direction, or the field.
 */
export const ledgerThresholds = {
    LARGE_ISSUANCE: { field: 'totalSupply', op: 'gte', value: 100000000, unit: 'USDC', label: 'more than 100 million in issue on this network', source: 'demo-policy' },
    CONCENTRATED_HOLDER: { field: 'share', op: 'gte', value: 10, unit: '%', label: 'this holder holds more than 10% of supply', source: 'demo-policy' },
    ACTIVE_TREASURY: { field: 'treasuryTxCount24h', op: 'gte', value: 1, label: 'the treasury moved the token in the last 24 hours', source: 'demo-policy' },
};
