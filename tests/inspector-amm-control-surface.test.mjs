// Regression guard for AMM Control Surface / Concentration of AMM
// Influence (spec §28-29) — combines four dimensions already computed
// elsewhere (LP ownership, fee-vote weight, auction-win share, trading-
// volume share) into one view per account, with zero new data fetching.
// Deliberately never called "control of the AMM" (per spec's own explicit
// instruction) — only "concentration of influence."
//
// A real correctness issue was caught and fixed before shipping:
// holderCohorts/lpTraderOverlap are ALWAYS scoped to the inspected
// account's own issued currency (its issuerAmmPool specifically) — the
// first draft attached them to EVERY pool in ammGovernanceByPool
// (including a completely unrelated pool the account merely holds an LP
// position in), which would have borrowed one pool's LP-holder/volume
// data and mislabeled it as another pool's. Fixed by only attaching real
// holderCohorts/lpTraderOverlap to the entry matching issuerAmmPool.
import { withPage, makeSuite, assert } from './helpers.mjs';

const suite = makeSuite('AMM Control Surface (Concentration of Influence)');

const WALLET_A = 'rWalletA00000000000000000000000000000000';
const WALLET_B = 'rWalletB00000000000000000000000000000000';
const WALLET_C = 'rWalletC00000000000000000000000000000000';

function gov(voters) {
  return { applicable: true, voting: { voters, voterCount: voters.length, top1WeightPct: 0, top3WeightPct: 0, ownVote: null }, auctionSlot: { applicable: false } };
}

suite.register('An account with signal in 3+ dimensions (LP + vote + auction) ranks first and produces a finding framed as "concentration," never "control"', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugAmmControlSurface, { timeout: 8000 });
    const g = gov([{ account: WALLET_A, feeVotedPct: 0.5, weightPct: 60 }, { account: WALLET_B, feeVotedPct: 0.3, weightPct: 40 }]);
    const holderCohorts = { lpHolders: [{ addr: WALLET_A, sharePct: 45 }, { addr: WALLET_C, sharePct: 10 }] };
    const auctionDominance = { applicable: true, totalWins: 4, winsByAccount: [{ account: WALLET_A, winCount: 3 }, { account: WALLET_B, winCount: 1 }] };
    const lpTraderOverlap = { applicable: true, volumeByHolder: { [WALLET_A]: 900, [WALLET_B]: 100 } };

    const result = await page.evaluate(([g, hc, ad, lto]) => window._debugAmmControlSurface(g, hc, ad, lto), [g, holderCohorts, auctionDominance, lpTraderOverlap]);

    assert(result.applicable === true, 'expected applicable:true');
    assert(result.profiles[0].account === WALLET_A, `expected Wallet A (LP+vote+auction+volume) ranked first, got ${result.profiles[0].account}`);
    assert(result.profiles[0].dimensionsPresent === 4, `expected Wallet A to have all 4 dimensions present, got ${result.profiles[0].dimensionsPresent}`);
    const finding = result.findings.find(f => f.module === 'AMM Control Surface');
    assert(finding, 'expected a finding when the top account has 3+ dimensions');
    // The classification MAY reference "control of the AMM" only to
    // explicitly disclaim it (spec's own pattern) — what must never
    // happen is ASSERTING control as a positive claim, which the
    // headline (the most prominent, consequential text) is checked for.
    assert(!/control of the amm/i.test(finding.headline), 'the headline must never assert "control of the AMM" as a positive claim');
    assert(/not.{0,5}"?control of the amm/i.test(finding.classification), 'classification must explicitly disclaim "control of the AMM" (not merely omit the phrase)');
    assert(/concentration/i.test(finding.classification), 'classification must use "concentration" framing instead');
  });
});

suite.register('An account with signal in only 1 dimension is excluded entirely — this is not a "control surface" finding on its own', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugAmmControlSurface, { timeout: 8000 });
    const g = gov([]);
    const holderCohorts = { lpHolders: [{ addr: WALLET_C, sharePct: 5 }] }; // only 1 dimension for Wallet C
    const result = await page.evaluate(([g, hc]) => window._debugAmmControlSurface(g, hc, { applicable: false }, { applicable: false }), [g, holderCohorts]);
    assert(!result.profiles.some(p => p.account === WALLET_C), 'a single-dimension account must not appear in the profile list at all');
  });
});

suite.register('No gov data at all produces applicable:false with a safe findings array', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugAmmControlSurface, { timeout: 8000 });
    const result = await page.evaluate(() => window._debugAmmControlSurface({ applicable: false }, null, null, null));
    assert(result.applicable === false, 'expected applicable:false');
    assert(Array.isArray(result.findings) && result.findings.length === 0, 'findings must be a real empty array, not undefined');
  });
});

suite.register('Only 2 dimensions present (below the 3-dimension finding threshold) still populates the profile list but produces no finding', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugAmmControlSurface, { timeout: 8000 });
    const g = gov([{ account: WALLET_A, feeVotedPct: 0.5, weightPct: 100 }]);
    const holderCohorts = { lpHolders: [{ addr: WALLET_A, sharePct: 20 }] };
    const result = await page.evaluate(([g, hc]) => window._debugAmmControlSurface(g, hc, { applicable: false }, { applicable: false }), [g, holderCohorts]);
    assert(result.profiles.length === 1, `expected Wallet A to appear (2 dimensions: LP + vote), got ${result.profiles.length}`);
    assert(result.profiles[0].dimensionsPresent === 2, `expected exactly 2 dimensions, got ${result.profiles[0].dimensionsPresent}`);
    assert(result.findings.length === 0, 'must not produce a finding below the 3-dimension threshold');
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
