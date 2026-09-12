// Regression guard for spoofing evidence family J (Auction-Group
// Relationship) — when AMM-during-display activity is already flagged,
// note whether this account ALSO currently holds or is authorized for
// the discounted-fee auction slot in the SAME currency. Per spec this is
// relevant context (a discounted fee makes frequent CLOB/AMM cycling more
// economically viable), never independent evidence of intent by itself —
// it must never add to the family count, the score, or fire a finding on
// its own; it only enriches an ALREADY-firing finding.
import { withPage, makeSuite, assert } from './helpers.mjs';

const suite = makeSuite('Spoofing — Auction-Group Relationship (Evidence Family J)');

const FOO = { currency: 'FOO', issuer: 'rFooIssuer00000000000000000000000000' };
const BAR = { currency: 'BAR', issuer: 'rBarIssuer00000000000000000000000000' };
const XRP = { currency: 'XRP', issuer: null };

function offerRecord({ offerId, gets, pays, price, createDate, cancelDate }) {
  return {
    offerId,
    takerGetsOriginal: { ...gets, value: 1000 },
    takerPaysOriginal: { ...pays, value: 1000 * price },
    createDate, cancelDate,
    consumedEvents: [],
    crossedAtCreation: { gets: 0, pays: 0 },
    timeRestingSeconds: cancelDate - createDate,
    replacesOfferSeq: null,
  };
}

// 5 long-resting CLOB offers with a matching AMM execution landing inside
// 3 of their windows — reliably triggers ammDuringDisplay.detected.
function buildAmmDuringDisplayFixture(pairGets, pairPays) {
  const list = [
    offerRecord({ offerId: 's1', gets: pairGets, pays: pairPays, price: 1.1, createDate: 1000, cancelDate: 5000 }),
    offerRecord({ offerId: 's2', gets: pairGets, pays: pairPays, price: 1.1, createDate: 6000, cancelDate: 10000 }),
    offerRecord({ offerId: 's3', gets: pairGets, pays: pairPays, price: 1.1, createDate: 11000, cancelDate: 15000 }),
    offerRecord({ offerId: 's4', gets: pairGets, pays: pairPays, price: 1.1, createDate: 16000, cancelDate: 20000 }),
    offerRecord({ offerId: 's5', gets: pairGets, pays: pairPays, price: 1.1, createDate: 21000, cancelDate: 25000 }),
  ];
  const ledger = { executions: [{ date: 2000, route: 'AMM' }, { date: 7000, route: 'HYBRID' }, { date: 12000, route: 'AMM' }], stats: {} };
  return { offerLifecycles: { list, byOfferId: new Map() }, ledger };
}

const profile = { cancelRatio: 0, sizeCV: null, burstWindows: { thirtySec: 0, oneHour: 0 } };

suite.register('When the account holds the auction slot for the SAME currency as the flagged offers, the finding is enriched with the auction-group note', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugSpoofingScore, { timeout: 8000 });
    const { offerLifecycles, ledger } = buildAmmDuringDisplayFixture(XRP, FOO);
    const auctionGroupCurrencies = new Set(['FOO']); // matches the offers' pair currency

    const result = await page.evaluate(([profile, offerLifecycles, ledger, currencies]) => {
      return window._debugSpoofingScore(profile, offerLifecycles, [], 'rAddr', null, ledger, new Set(currencies));
    }, [profile, offerLifecycles, ledger, [...auctionGroupCurrencies]]);

    const finding = result.findings.find(f => /AMM activity during CLOB display/.test(f.headline));
    assert(finding, `expected an AMM-during-display finding, got: ${JSON.stringify(result.findings.map(f => f.headline))}`);
    assert(finding.observed.some(o => /discounted-fee auction slot/.test(o)), `expected the auction-group note in observed, got: ${JSON.stringify(finding.observed)}`);
    assert(finding.observed.some(o => /not independent evidence of intent/.test(o)), 'the note must explicitly disclaim itself as independent evidence');
  });
});

suite.register('When auctionGroupCurrencies does NOT overlap the flagged offers\' currency, no note is added (the intersection check is real, not just "any auction group exists")', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugSpoofingScore, { timeout: 8000 });
    const { offerLifecycles, ledger } = buildAmmDuringDisplayFixture(XRP, FOO);
    const auctionGroupCurrencies = new Set(['BAR']); // does NOT match FOO

    const result = await page.evaluate(([profile, offerLifecycles, ledger, currencies]) => {
      return window._debugSpoofingScore(profile, offerLifecycles, [], 'rAddr', null, ledger, new Set(currencies));
    }, [profile, offerLifecycles, ledger, [...auctionGroupCurrencies]]);

    const finding = result.findings.find(f => /AMM activity during CLOB display/.test(f.headline));
    assert(finding, 'expected the underlying finding to still fire');
    assert(!finding.observed.some(o => /discounted-fee auction slot/.test(o)), 'must NOT add the note when the auction-group currency does not match the flagged pair');
  });
});

suite.register('With no auctionGroupCurrencies at all (null/empty), the finding fires normally with no note and no crash', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugSpoofingScore, { timeout: 8000 });
    const { offerLifecycles, ledger } = buildAmmDuringDisplayFixture(XRP, FOO);

    const resultNull = await page.evaluate(([profile, offerLifecycles, ledger]) => {
      return window._debugSpoofingScore(profile, offerLifecycles, [], 'rAddr', null, ledger, null);
    }, [profile, offerLifecycles, ledger]);
    const resultEmpty = await page.evaluate(([profile, offerLifecycles, ledger]) => {
      return window._debugSpoofingScore(profile, offerLifecycles, [], 'rAddr', null, ledger, new Set());
    }, [profile, offerLifecycles, ledger]);

    for (const result of [resultNull, resultEmpty]) {
      const finding = result.findings.find(f => /AMM activity during CLOB display/.test(f.headline));
      assert(finding, 'expected the underlying finding to still fire');
      assert(!finding.observed.some(o => /discounted-fee auction slot/.test(o)), 'must not fabricate a note with no auction-group data');
    }
  });
});

suite.register('The auction-group relationship never fires a finding on its own — it only ever enriches an already-firing AMM-during-display finding', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugSpoofingScore, { timeout: 8000 });
    // No layering, no opposite-side, no AMM-during-display pattern at all
    // (only 1 offer, well below every family's minimum candidate count) —
    // even with real auction-group membership, nothing should fire.
    const list = [offerRecord({ offerId: 's1', gets: XRP, pays: FOO, price: 1.1, createDate: 1000, cancelDate: 5000 })];
    const offerLifecycles = { list, byOfferId: new Map() };
    const ledger = { executions: [{ date: 2000, route: 'AMM' }], stats: {} };

    const result = await page.evaluate(([profile, offerLifecycles, ledger]) => {
      return window._debugSpoofingScore(profile, offerLifecycles, [], 'rAddr', null, ledger, new Set(['FOO']));
    }, [profile, offerLifecycles, ledger]);

    assert(!result.findings.some(f => /AMM activity during CLOB display|independent evidence families/.test(f.headline)), 'auction-group membership alone (with no underlying pattern) must never produce a spoofing finding');
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
