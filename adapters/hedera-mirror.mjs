/**
 * Hedera mirror node as a ProveML fact source.
 *
 * The ledger is the store. Every fact is read from the public mirror node at
 * one consensus timestamp, and every resolution carries the exact query that
 * produced it as its proof reference, so a reader can open the URL and see
 * the same number. Nothing here is computed by a model; the only arithmetic is
 * unit conversion and two materialised derived values (circulating supply and
 * shares of supply), which are facts in the store like any other, so a report
 * can claim them and the verifier can check them.
 */

const NETWORKS = {
    mainnet: { mirror: 'https://mainnet-public.mirrornode.hedera.com', hashscan: 'https://hashscan.io/mainnet' },
    testnet: { mirror: 'https://testnet.mirrornode.hedera.com', hashscan: 'https://hashscan.io/testnet' },
};

export const USDC = { mainnet: '0.0.456858', testnet: '0.0.429274' };

async function get(url) {
    const res = await fetch(url, { headers: { accept: 'application/json' } });
    if (!res.ok) throw new Error(`mirror node ${res.status} for ${url}`);
    return res.json();
}

/** "450010110000000" with 6 decimals -> "450010110"; trailing zeros dropped. */
function units(raw, decimals) {
    const s = BigInt(raw).toString().padStart(decimals + 1, '0');
    const whole = s.slice(0, s.length - decimals);
    const frac = s.slice(s.length - decimals).replace(/0+$/, '');
    return frac ? `${whole}.${frac}` : whole;
}

/** share of `part` in `whole`, one decimal, as a string: "62.4" */
function share(part, whole) {
    if (whole === 0n) return '0';
    return (Number((part * 10000n) / whole) / 100).toFixed(1);
}

/**
 * Read a token's state at one consensus timestamp.
 * @param {object} opts
 * @param {'mainnet'|'testnet'} [opts.network]
 * @param {string} [opts.tokenId]
 * @param {string} [opts.at]  consensus timestamp "seconds.nanos"; default now
 * @param {number} [opts.topHolders]
 * @returns {{ snapshot, facts, proofs, network }}
 */
export async function tokenSnapshot({ network = 'mainnet', tokenId = USDC[network], at, topHolders = 5 } = {}) {
    const { mirror, hashscan } = NETWORKS[network];
    const ts = at || `${Math.floor(Date.now() / 1000)}.000000000`;
    const dayAgo = `${Math.floor(Number(ts.split('.')[0]) - 86400)}.000000000`;
    const q = (path) => `${mirror}/api/v1${path}`;

    const facts = {};
    const proofs = {};
    const put = (key, value, unit, url) => {
        facts[key] = value;
        if (unit) facts[`${key}._unit`] = unit;
        proofs[key] = url;
    };

    // Token
    const tokenUrl = q(`/tokens/${tokenId}?timestamp=lte:${ts}`);
    const t = await get(tokenUrl);
    const decimals = Number(t.decimals);
    const supply = BigInt(t.total_supply);
    const T = `token:${tokenId}`;
    put(`${T}.name`, t.name, null, tokenUrl);
    put(`${T}.symbol`, t.symbol, null, tokenUrl);
    put(`${T}.decimals`, decimals, null, tokenUrl);
    put(`${T}.totalSupply`, units(supply, decimals), t.symbol, tokenUrl);
    put(`${T}.treasury`, t.treasury_account_id, null, tokenUrl);

    // Treasury balance
    const treasuryUrl = q(`/tokens/${tokenId}/balances?account.id=${t.treasury_account_id}&timestamp=lte:${ts}`);
    const tb = await get(treasuryUrl);
    const treasuryBal = BigInt(tb.balances[0]?.balance ?? 0);
    put(`${T}.treasuryBalance`, units(treasuryBal, decimals), t.symbol, treasuryUrl);
    put(`${T}.circulating`, units(supply - treasuryBal, decimals), t.symbol, treasuryUrl);
    put(`${T}.treasuryShare`, share(treasuryBal, supply), '%', treasuryUrl);

    // Largest holders. The balances endpoint orders by account id, not by
    // amount, so "top holders" has to be read as a bounded scan: every account
    // above a floor (1,000,000 units), sorted here. The floor is part of the
    // fact's meaning and is recorded with it.
    const floor = 1_000_000n * 10n ** BigInt(decimals);
    let holdersUrl = q(`/tokens/${tokenId}/balances?account.balance=gte:${floor}&limit=100&timestamp=lte:${ts}`);
    const firstHoldersUrl = holdersUrl;
    const holders = [];
    let hp = 0;
    while (holdersUrl && hp < 10) {
        const page = await get(holdersUrl);
        for (const b of page.balances) holders.push({ account: b.account, balance: BigInt(b.balance) });
        holdersUrl = page.links?.next ? `${mirror}${page.links.next}` : null;
        hp++;
    }
    holders.sort((a, b) => (a.balance < b.balance ? 1 : a.balance > b.balance ? -1 : 0));
    const top = holders.slice(0, topHolders);
    put(`${T}.holdersAboveOneMillion`, holders.length, null, firstHoldersUrl);
    top.forEach((h, i) => {
        const H = `holder:${h.account}`;
        put(`${H}.name`, h.account, null, firstHoldersUrl);
        put(`${H}.rank`, i + 1, null, firstHoldersUrl);
        put(`${H}.balance`, units(h.balance, decimals), t.symbol, firstHoldersUrl);
        put(`${H}.share`, share(h.balance, supply), '%', firstHoldersUrl);
    });
    const largest = top.find(h => h.account !== t.treasury_account_id) || top[0];
    if (largest) {
        put(`${T}.largestHolder`, largest.account, null, firstHoldersUrl);
        put(`${T}.largestHolderBalance`, units(largest.balance, decimals), t.symbol, firstHoldersUrl);
        put(`${T}.largestHolderShare`, share(largest.balance, supply), '%', firstHoldersUrl);
    }

    // Treasury activity in the last 24 hours: transactions on the treasury
    // account that moved this token. Bounded to 10 pages of 100.
    let txUrl = q(`/transactions?account.id=${t.treasury_account_id}&transactiontype=CRYPTOTRANSFER&timestamp=gte:${dayAgo}&timestamp=lte:${ts}&order=desc&limit=100`);
    const firstTxUrl = txUrl;
    let txCount = 0, moved = 0n, pages = 0;
    while (txUrl && pages < 10) {
        const page = await get(txUrl);
        for (const tx of page.transactions) {
            const mine = (tx.token_transfers || []).filter(x => x.token_id === tokenId);
            if (mine.length === 0) continue;
            txCount++;
            for (const x of mine) if (x.amount > 0) moved += BigInt(x.amount);
        }
        txUrl = page.links?.next ? `${mirror}${page.links.next}` : null;
        pages++;
    }
    put(`${T}.treasuryTxCount24h`, txCount, null, firstTxUrl);
    put(`${T}.treasuryVolume24h`, units(moved, decimals), t.symbol, firstTxUrl);

    return {
        network,
        snapshot: { id: `hedera:${network}:${ts}`, consensusTimestamp: ts, tokenId, hashscan: `${hashscan}/token/${tokenId}` },
        facts,
        proofs,
    };
}

/**
 * A ProveML trust adapter over a snapshot: every found value is "verified" by
 * the mirror node, with the query URL as proof reference.
 */
export function mirrorAdapter(snap) {
    return {
        resolve(path) {
            if (!(path in snap.facts)) return { found: false };
            return {
                found: true,
                value: snap.facts[path],
                unit: snap.facts[`${path}._unit`],
                trust: { status: 'verified', backend: 'hedera-mirror', proofRef: snap.proofs[path], checkedAt: snap.snapshot.consensusTimestamp },
            };
        },
    };
}
