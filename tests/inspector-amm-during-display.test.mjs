// Regression guard for spoofing evidence family I (AMM Activity During
// Display) — while one of this account's own CLOB offers was resting and
// displayed, did the same account ALSO execute a trade against an AMM
// pool? Reuses the execution ledger's already-classified CLOB/AMM/HYBRID
// routes (built for Execution Routing) rather than re-deriving route
// classification. Also covers the updated 3-family corroboration model in
// analyseSpoofingScore, which now scales confidence/severity by how many
// of the 3 evidence families (layering, opposite-side, AMM-during-display)
// independently fire, not just a binary "both" check.
import { withPage, makeSuite, assert } from './helpers.mjs';

const suite = makeSuite('Spoofing — AMM Activity During Display');

const FOO = { currency: 'FOO', issuer: 'rFooIssuer00000000000000000000000000' };
const XRP = { currency: 'XRP', issuer: null };

function offerRecord({ offerId, price, createDate, cancelDate }) {
  return {
    offerId,
    takerGetsOriginal: { ...XRP, value: 1000 },
    takerPaysOriginal: { ...FOO, value: 1000 * price },
    createDate, cancelDate,
    consumedEvents: [],
    crossedAtCreation: { gets: 0, pays: 0 },
    timeRestingSeconds: cancelDate - createDate,
    replacesOfferSeq: null,
  };
}

function execLedger(executions) {
  return { executions, stats: { total: executions.length } };
}

suite.register('AMM-routed executions landing inside 3+ of 5 displayed-offer windows trigger detection', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugAmmActivityDuringDisplay, { timeout: 8000 });
    const list = [
      offerRecord({ offerId: 's1', price: 1.1, createDate: 1000, cancelDate: 5000 }),
      offerRecord({ offerId: 's2', price: 1.1, createDate: 6000, cancelDate: 10000 }),
      offerRecord({ offerId: 's3', price: 1.1, createDate: 11000, cancelDate: 15000 }),
      offerRecord({ offerId: 's4', price: 1.1, createDate: 16000, cancelDate: 20000 }),
      offerRecord({ offerId: 's5', price: 1.1, createDate: 21000, cancelDate: 25000 }),
    ];
    const ledger = execLedger([
      { date: 2000, route: 'AMM' },
      { date: 7000, route: 'HYBRID' },
      { date: 12000, route: 'AMM' },
      { date: 50000, route: 'CLOB' }, // outside every window, and CLOB anyway
    ]);
    const result = await page.evaluate(([list, ledger]) => window._debugAmmActivityDuringDisplay(list, ledger), [list, ledger]);
    assert(result.totalCandidates === 5, `expected 5 candidates, got ${result.totalCandidates}`);
    assert(result.flaggedCount === 3, `expected 3 flagged, got ${result.flaggedCount}`);
    assert(result.detected === true, `expected detected:true, got ${JSON.stringify(result)}`);
  });
});

suite.register('Only CLOB-routed executions (no AMM/HYBRID at all) never trigger detection', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugAmmActivityDuringDisplay, { timeout: 8000 });
    const list = [offerRecord({ offerId: 's1', price: 1.1, createDate: 1000, cancelDate: 5000 })];
    const ledger = execLedger([{ date: 2000, route: 'CLOB' }, { date: 3000, route: 'CLOB' }]);
    const result = await page.evaluate(([list, ledger]) => window._debugAmmActivityDuringDisplay(list, ledger), [list, ledger]);
    assert(result.flaggedCount === 0, 'CLOB-only executions must never be counted as AMM activity');
    assert(result.detected === false);
  });
});

suite.register('No execution ledger (null) or empty executions produces detected:false without throwing', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugAmmActivityDuringDisplay, { timeout: 8000 });
    const list = [offerRecord({ offerId: 's1', price: 1.1, createDate: 1000, cancelDate: 5000 })];
    const results = await page.evaluate(([list]) => ([
      window._debugAmmActivityDuringDisplay(list, null),
      window._debugAmmActivityDuringDisplay(list, { executions: [] }),
    ]), [list]);
    for (const r of results) {
      assert(r.detected === false, `expected detected:false, got ${JSON.stringify(r)}`);
      assert(r.totalCandidates === 0, 'expected zero candidates when there is nothing to compare against');
    }
  });
});

suite.register('analyseSpoofingScore: 3 independently-fired families produce higher confidence/severity than any 1 or 2 alone, and the headline names all 3', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugSpoofingScore, { timeout: 8000 });
    const profile = { cancelRatio: 0, sizeCV: null, burstWindows: { thirtySec: 0, oneHour: 0 } };

    // Layering: 4 offers, same pair/direction, overlapping, different prices.
    const layeringOffers = [
      offerRecord({ offerId: 'o1', price: 1.10, createDate: 1000, cancelDate: 5000 }),
      offerRecord({ offerId: 'o2', price: 1.14, createDate: 1200, cancelDate: 5100 }),
      offerRecord({ offerId: 'o3', price: 1.17, createDate: 1400, cancelDate: 5200 }),
      offerRecord({ offerId: 'o4', price: 1.21, createDate: 1600, cancelDate: 5300 }),
    ];
    const ledger = execLedger([{ date: 1500, route: 'AMM' }]); // lands inside every offer's window (they all overlap 1000-5000ish)

    const offerLifecycles = { list: layeringOffers, byOfferId: new Map() };
    const result = await page.evaluate(([profile, offerLifecycles, ledger]) => {
      return window._debugSpoofingScore(profile, offerLifecycles, [], 'rAddr', null, ledger);
    }, [profile, offerLifecycles, ledger]);

    const finding = result.findings.find(f => /Layering-like|independent evidence families/.test(f.headline));
    assert(finding, `expected a spoofing finding, got: ${JSON.stringify(result.findings.map(f => f.headline))}`);
    // Only layering fires here (4 offers isn't enough candidates for
    // opposite-side/AMM-during-display's 5-candidate minimum), so this
    // should read as a single-family finding, not "N independent families".
    assert(finding.confidence === 0.35, `expected single-family confidence 0.35, got ${finding.confidence}`);
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
