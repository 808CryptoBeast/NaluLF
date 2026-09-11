// Regression guard for Auction Economics (spec §22-24) — the discounted
// fee is not free; the slot owner paid real LP tokens to win it. This
// compares that real, already-known cost (from amm_info's own
// auction_slot.price — no new fetch) against fee savings ESTIMATED from
// the account's own observed trading volume during the current window
// (Auction-Window Market Analysis). Deliberately never a profit figure:
// LP tokens and the pool's non-XRP asset have no price feed to convert
// into a common unit, so only real, already-known quantities are combined.
import { withPage, makeSuite, assert } from './helpers.mjs';

const suite = makeSuite('AMM Auction Economics');

function gov({ isOwner = true, normalFeePct = 0.5, discountedFeePct = 0.05, lpTokensPaid = 10 } = {}) {
  return { auctionSlot: { applicable: true, isOwner, isAuthorized: false, normalFeePct, discountedFeePct, lpTokensPaid, slotOwner: 'rOwner', authAccounts: [] } };
}
function auctionWindow({ totalXrpVolume = 1000, ownerPct = 40, count = 5 } = {}) {
  return { applicable: true, during: { count, totalXrpVolume, ownerPct, authorizedPct: 0, externalPct: 100 - ownerPct } };
}

suite.register('Real bid cost and observed volume produce a real, correctly-computed fee-savings estimate', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugAuctionEconomics, { timeout: 8000 });
    const result = await page.evaluate(([g, aw]) => window._debugAuctionEconomics(g, aw), [gov(), auctionWindow()]);

    assert(result.applicable === true, 'expected applicable:true when the account owns the slot');
    assert(result.bidCostLp === 10, `expected bid cost 10 LP tokens, got ${result.bidCostLp}`);
    // ownerVolumeDuring = 1000 XRP * 40% = 400 XRP
    assert(Math.abs(result.ownerVolumeDuring - 400) < 0.01, `expected owner volume 400 XRP, got ${result.ownerVolumeDuring}`);
    // savings = 400 * (0.5% - 0.05%) = 400 * 0.0045 = 1.8 XRP
    assert(Math.abs(result.estimatedFeeSavingsXrp - 1.8) < 0.01, `expected estimated savings 1.8 XRP, got ${result.estimatedFeeSavingsXrp}`);

    const finding = result.findings.find(f => f.module === 'AMM Auction Economics');
    assert(finding, 'expected a finding when real savings are computable');
    assert(finding.sev === 'info', `must stay info severity, got ${finding.sev}`);
    assert(/not a profit calculation/i.test(finding.classification), 'must explicitly disclaim this as a profit calculation');
    assert(/opportunity cost/i.test(finding.alternativeExplanations.join(' ')), 'must frame LP token cost as opportunity cost, not a cash expense');
  });
});

suite.register('An account that is NOT the slot owner gets applicable:false — economics only applies to the account paying the bid cost', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugAuctionEconomics, { timeout: 8000 });
    const result = await page.evaluate(([g, aw]) => window._debugAuctionEconomics(g, aw), [gov({ isOwner: false }), auctionWindow()]);
    assert(result.applicable === false, 'expected applicable:false for a non-owner (e.g. an authorized account or an unrelated inspection)');
  });
});

suite.register('Owner with no observed trading volume in the window yet gets applicable:true but no fabricated savings figure', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugAuctionEconomics, { timeout: 8000 });
    const result = await page.evaluate(([g, aw]) => window._debugAuctionEconomics(g, aw), [gov(), { applicable: true, during: { count: 0, totalXrpVolume: 0, ownerPct: 0 } }]);
    assert(result.applicable === true, 'expected applicable:true (the account does own the slot)');
    assert(result.estimatedFeeSavingsXrp === null, 'must not fabricate a savings figure with zero observed volume');
    assert(result.findings.length === 0, 'must not produce a finding with nothing real to compare');
  });
});

suite.register('No auction slot at all produces applicable:false, not an error', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugAuctionEconomics, { timeout: 8000 });
    const result = await page.evaluate(() => window._debugAuctionEconomics({ auctionSlot: { applicable: false } }, null));
    assert(result.applicable === false, 'expected applicable:false with no active auction slot');
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
