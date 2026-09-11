// Regression guard for a real, severe bug found while verifying Auction
// Economics: analyseAuctionWindowMarket / analyseAuctionDominance /
// analyseAuctionEconomics each had an early-return path shaped
// `{ applicable: false }` with NO `findings` field, while their call
// sites in renderAll do `ammAnalysis.signals.push(...result.findings)`
// unconditionally. Spreading `undefined` throws a TypeError ("is not
// iterable"), which aborted the entire runInspect pipeline BEFORE
// renderAll ever ran — breaking not just the AMM panel but every section
// of the page for any inspection where the early-return path was hit
// (e.g. any account that isn't the auction slot owner, which is the
// common case). This is exactly the kind of bug that's invisible in
// isolated unit-style checks of a single function's return shape, but
// fatal in the full render pipeline — so this suite specifically checks
// every applicable:false path always carries a real, spreadable array.
import { withPage, makeSuite, assert } from './helpers.mjs';

const suite = makeSuite('Auction Analysis — findings Array Safety');

suite.register('analyseAuctionWindowMarket: every applicable:false path returns a real (spreadable) findings array', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugAuctionWindowMarket, { timeout: 8000 });
    const results = await page.evaluate(() => ([
      window._debugAuctionWindowMarket(null, 'rPool', { applicable: true, expiration: '2026-01-01T00:00:00Z', authAccounts: [] }),
      window._debugAuctionWindowMarket({ txList: [], truncated: false }, 'rPool', { applicable: false }),
      window._debugAuctionWindowMarket({ txList: [{ tx: {}, meta: {} }], truncated: false }, 'rPool', { applicable: true, expiration: 'not-a-real-date', authAccounts: [] }),
    ]));
    for (const r of results) {
      assert(r.applicable === false, `expected applicable:false for this edge case, got ${JSON.stringify(r)}`);
      assert(Array.isArray(r.findings), `findings must always be a real array, even on early return — got ${JSON.stringify(r.findings)}`);
      const spread = [];
      spread.push(...r.findings); // must not throw "is not iterable"
    }
  });
});

suite.register('analyseAuctionDominance: applicable:false always carries a real findings array', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugAuctionDominance, { timeout: 8000 });
    const results = await page.evaluate(() => ([
      window._debugAuctionDominance(null),
      window._debugAuctionDominance({ txList: [], truncated: false }),
    ]));
    for (const r of results) {
      assert(r.applicable === false, `expected applicable:false, got ${JSON.stringify(r)}`);
      assert(Array.isArray(r.findings), `findings must always be a real array — got ${JSON.stringify(r.findings)}`);
      const spread = [];
      spread.push(...r.findings); // must not throw "is not iterable"
    }
  });
});

suite.register('analyseAuctionEconomics: the common case (account is NOT the slot owner) always carries a real findings array — this was the exact bug that crashed the whole render pipeline', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugAuctionEconomics, { timeout: 8000 });
    const results = await page.evaluate(() => ([
      window._debugAuctionEconomics({ auctionSlot: { applicable: true, isOwner: false, isAuthorized: false, normalFeePct: 0.5, discountedFeePct: 0.05 } }, null),
      window._debugAuctionEconomics({ auctionSlot: { applicable: false } }, null),
    ]));
    for (const r of results) {
      assert(r.applicable === false, `expected applicable:false, got ${JSON.stringify(r)}`);
      assert(Array.isArray(r.findings), `findings must always be a real array — got ${JSON.stringify(r.findings)}. This exact gap crashed runInspect for the real CULT/XRP issuer account (not the slot owner) with "TypeError: ... findings is not iterable", aborting the page before renderAll ran at all.`);
      const spread = [];
      spread.push(...r.findings);
    }
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
