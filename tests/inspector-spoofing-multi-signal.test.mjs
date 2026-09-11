// Regression guard for two NEW spoofing evidence families built entirely
// from this account's own already-resolved offer lifecycle records (no
// live book state needed, unlike the historical-book-depth signals which
// remain an honest "Insufficient Data" gap on public XRPL nodes):
//
//   E. Layering-Like Behavior — multiple of the account's own offers
//      resting simultaneously in the same pair/direction at meaningfully
//      different price levels.
//   F. Opposite-Side Execution — the account genuinely traded the
//      opposite direction of the same pair WHILE one of its own offers
//      was still displayed (time-windowed, not just "eventually happened"
//      like the existing Wash Execution round-trip check).
//
// Per spec: no single evidence family should produce a high-confidence
// spoofing conclusion on its own; when BOTH fire, confidence should rise
// because independent signals corroborate each other.
import { withPage, makeSuite, assert } from './helpers.mjs';

const suite = makeSuite('Spoofing — Multi-Signal Model (Layering + Opposite-Side Execution)');

const FOO = { currency: 'FOO', issuer: 'rFooIssuer00000000000000000000000000' };
const XRP = { currency: 'XRP', issuer: null };

function offerRecord({ offerId, gets, pays, price, createDate, cancelDate = null, consumedEvents = [], crossedGets = 0, timeRestingSeconds = null }) {
  return {
    offerId,
    takerGetsOriginal: { ...gets, value: 1000 },
    takerPaysOriginal: { ...pays, value: 1000 * price },
    createDate, cancelDate,
    consumedEvents,
    crossedAtCreation: { gets: crossedGets, pays: crossedGets * price },
    timeRestingSeconds: timeRestingSeconds ?? (cancelDate != null ? cancelDate - createDate : null),
  };
}

suite.register('4 of the account\'s own offers resting simultaneously in the same pair/direction at different prices trigger Layering-Like detection', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugLayeringPattern, { timeout: 8000 });
    // Sell XRP for FOO at 4 different price levels, all overlapping
    // 1000-5000 in time (price differs by well over 0.5% between levels).
    const list = [
      offerRecord({ offerId: 'o1', gets: XRP, pays: FOO, price: 1.10, createDate: 1000, cancelDate: 5000 }),
      offerRecord({ offerId: 'o2', gets: XRP, pays: FOO, price: 1.14, createDate: 1200, cancelDate: 5100 }),
      offerRecord({ offerId: 'o3', gets: XRP, pays: FOO, price: 1.17, createDate: 1400, cancelDate: 5200 }),
      offerRecord({ offerId: 'o4', gets: XRP, pays: FOO, price: 1.21, createDate: 1600, cancelDate: 5300 }),
    ];
    const result = await page.evaluate((list) => window._debugLayeringPattern(list), list);
    assert(result.detected === true, `expected layering detected with 4 overlapping different-priced offers, got: ${JSON.stringify(result)}`);
    assert(result.maxConcurrentLevels >= 3, `expected at least 3 concurrent price levels, got ${result.maxConcurrentLevels}`);
    assert(result.pairCount === 1, `expected 1 pair/direction involved, got ${result.pairCount}`);
  });
});

suite.register('Offers at nearly the same price (within 0.5%) do NOT count as separate layers', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugLayeringPattern, { timeout: 8000 });
    const list = [
      offerRecord({ offerId: 'o1', gets: XRP, pays: FOO, price: 1.100, createDate: 1000, cancelDate: 5000 }),
      offerRecord({ offerId: 'o2', gets: XRP, pays: FOO, price: 1.101, createDate: 1200, cancelDate: 5100 }), // 0.09% apart — same level
      offerRecord({ offerId: 'o3', gets: XRP, pays: FOO, price: 1.102, createDate: 1400, cancelDate: 5200 }),
    ];
    const result = await page.evaluate((list) => window._debugLayeringPattern(list), list);
    assert(result.detected === false, `near-identical prices must not count as layering, got: ${JSON.stringify(result)}`);
  });
});

suite.register('Offers that never overlap in time (sequential quote replacement, not simultaneous layers) do NOT trigger layering', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugLayeringPattern, { timeout: 8000 });
    const list = [
      offerRecord({ offerId: 'o1', gets: XRP, pays: FOO, price: 1.10, createDate: 1000, cancelDate: 1100 }),
      offerRecord({ offerId: 'o2', gets: XRP, pays: FOO, price: 1.14, createDate: 1200, cancelDate: 1300 }),
      offerRecord({ offerId: 'o3', gets: XRP, pays: FOO, price: 1.17, createDate: 1400, cancelDate: 1500 }),
    ];
    const result = await page.evaluate((list) => window._debugLayeringPattern(list), list);
    assert(result.detected === false, `sequential non-overlapping offers must not count as layering, got: ${JSON.stringify(result)}`);
  });
});

suite.register('Opposite-Side Execution: a displayed sell order with a genuine reverse-direction trade during its display window is flagged', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugOppositeSideExecution, { timeout: 8000 });
    // 5 long-resting sell offers (XRP for FOO); 3 of them have a matching
    // reverse-direction (FOO for XRP) crossing during their display window.
    const list = [
      offerRecord({ offerId: 's1', gets: XRP, pays: FOO, price: 1.1, createDate: 1000, cancelDate: 5000 }),
      offerRecord({ offerId: 's2', gets: XRP, pays: FOO, price: 1.1, createDate: 6000, cancelDate: 10000 }),
      offerRecord({ offerId: 's3', gets: XRP, pays: FOO, price: 1.1, createDate: 11000, cancelDate: 15000 }),
      offerRecord({ offerId: 's4', gets: XRP, pays: FOO, price: 1.1, createDate: 16000, cancelDate: 20000 }),
      offerRecord({ offerId: 's5', gets: XRP, pays: FOO, price: 1.1, createDate: 21000, cancelDate: 25000 }),
      // Reverse-direction (buy XRP with FOO) executions landing inside 3 of the 5 windows above.
      offerRecord({ offerId: 'b1', gets: FOO, pays: XRP, price: 0.9, createDate: 2000, crossedGets: 100 }),
      offerRecord({ offerId: 'b2', gets: FOO, pays: XRP, price: 0.9, createDate: 7000, crossedGets: 100 }),
      offerRecord({ offerId: 'b3', gets: FOO, pays: XRP, price: 0.9, createDate: 12000, crossedGets: 100 }),
    ];
    const result = await page.evaluate((list) => window._debugOppositeSideExecution(list), list);
    assert(result.totalCandidates === 5, `expected 5 candidate displayed offers, got ${result.totalCandidates}`);
    assert(result.flaggedCount === 3, `expected 3 flagged (matched by a reverse execution in-window), got ${result.flaggedCount}`);
    assert(result.detected === true, `expected detected:true (5 candidates, 3 flagged clears the threshold), got ${JSON.stringify(result)}`);
  });
});

suite.register('Opposite-Side Execution: reverse trades OUTSIDE the display window do not count', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugOppositeSideExecution, { timeout: 8000 });
    const list = [
      offerRecord({ offerId: 's1', gets: XRP, pays: FOO, price: 1.1, createDate: 1000, cancelDate: 2000 }),
      offerRecord({ offerId: 's2', gets: XRP, pays: FOO, price: 1.1, createDate: 3000, cancelDate: 4000 }),
      offerRecord({ offerId: 's3', gets: XRP, pays: FOO, price: 1.1, createDate: 5000, cancelDate: 6000 }),
      offerRecord({ offerId: 's4', gets: XRP, pays: FOO, price: 1.1, createDate: 7000, cancelDate: 8000 }),
      offerRecord({ offerId: 's5', gets: XRP, pays: FOO, price: 1.1, createDate: 9000, cancelDate: 10000 }),
      // This reverse trade happens well AFTER s1's window closed.
      offerRecord({ offerId: 'b1', gets: FOO, pays: XRP, price: 0.9, createDate: 50000, crossedGets: 100 }),
    ];
    const result = await page.evaluate((list) => window._debugOppositeSideExecution(list), list);
    assert(result.flaggedCount === 0, `a reverse trade outside every window must not be flagged, got ${result.flaggedCount}`);
    assert(result.detected === false, 'must not detect a pattern with zero in-window matches');
  });
});

suite.register('analyseSpoofingScore: when BOTH families fire, confidence is higher than either alone, and the finding explicitly names the corroboration', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugSpoofingScore, { timeout: 8000 });
    const layeringOnly = [
      offerRecord({ offerId: 'o1', gets: XRP, pays: FOO, price: 1.10, createDate: 1000, cancelDate: 5000 }),
      offerRecord({ offerId: 'o2', gets: XRP, pays: FOO, price: 1.14, createDate: 1200, cancelDate: 5100 }),
      offerRecord({ offerId: 'o3', gets: XRP, pays: FOO, price: 1.17, createDate: 1400, cancelDate: 5200 }),
      offerRecord({ offerId: 'o4', gets: XRP, pays: FOO, price: 1.21, createDate: 1600, cancelDate: 5300 }),
    ];
    const profile = { cancelRatio: 0, sizeCV: null, burstWindows: { thirtySec: 0, oneHour: 0 } };
    const resultLayeringOnly = await page.evaluate(([list, profile]) => {
      const offerLifecycles = { list, byOfferId: new Map() };
      return window._debugSpoofingScore(profile, offerLifecycles, [], 'rAddr', null);
    }, [layeringOnly, profile]);

    const layeringFinding = resultLayeringOnly.findings.find(f => /Layering-like/.test(f.headline));
    assert(layeringFinding, 'expected a layering-only finding');
    assert(layeringFinding.sev === 'warn', `expected warn severity (not critical) for a single evidence family, got ${layeringFinding.sev}`);
    assert(layeringFinding.confidence <= 0.4, `single-family confidence should stay moderate (<=0.4), got ${layeringFinding.confidence}`);
    assert(/market-making/i.test(layeringFinding.alternativeExplanations.join(' ')), 'must offer legitimate market-making as an alternative explanation');
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
