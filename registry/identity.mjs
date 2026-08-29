/**
 * What an account-opening summary may say about a person, qualitatively.
 * Demo policy; in a bank these are the onboarding rules, with their source.
 */
export const identityThresholds = {
    IS_ADULT: { field: 'ageYears', op: 'gte', value: 18, label: 'of age', source: 'demo-policy (age derived by the relying party; the PID has no age attribute)' },
    EU_NATIONAL: { field: 'euNational', op: 'eq', value: 'yes', label: 'a national of an EU member state', source: 'demo-policy' },
    RESIDENT_BE: { field: 'address.country', op: 'eq', value: 'BE', label: 'resident in Belgium', source: 'demo-policy' },
};
