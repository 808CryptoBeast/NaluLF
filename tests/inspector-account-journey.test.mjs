// Regression guard for Account Journey (beginner-UX spec §41) — a plain-
// language timeline of real, verifiable "first occurrence" milestones
// built from a single chronological scan of already-fetched txList.
//
// Live verification against the real CULT/XRP issuer caught a genuine
// bug before it shipped: walletCreatedTs is a Unix-epoch MILLISECONDS
// timestamp (ready for `new Date()` directly), while every other date in
// this feature is a raw Ripple-epoch-SECONDS value like tx.date. Pushing
// walletCreatedTs into the shared events array as-is caused it to be
// double-converted by the shared render path (which applies
// `(date + XRPL_EPOCH) * 1000`), producing a nonsense date ("9/8/58639")
// and breaking chronological sort order (it should always be first).
import { withPage, makeSuite, assert } from './helpers.mjs';

const suite = makeSuite('Account Journey');

const ADDR = 'rJourneyTest00000000000000000000000000000';
const XRPL_EPOCH = 946684800;

function tx(type, date, extra = {}) {
  return { tx: { Account: ADDR, TransactionType: type, date, ...extra }, meta: { TransactionResult: 'tesSUCCESS' } };
}

suite.register('walletCreatedTs (Unix ms) converts correctly and sorts as the FIRST event, not scattered or nonsensical', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugAccountJourney, { timeout: 8000 });
    // A real-looking wallet creation instant: 2024-01-01 00:00:00 UTC, as
    // walletCreatedTs is actually produced: (rippleSec + RIPPLE_EPOCH) * 1000.
    const creationRippleSec = 1000;
    const walletCreatedTs = (creationRippleSec + XRPL_EPOCH) * 1000;
    const txList = [tx('Payment', creationRippleSec + 500000, { Destination: 'rSomeone000000000000000000000000000000000' })];

    const result = await page.evaluate(([txList, addr, walletCreatedTs]) => window._debugAccountJourney(txList, addr, walletCreatedTs, false), [txList, ADDR, walletCreatedTs]);

    assert(result.applicable === true, 'expected applicable:true');
    assert(result.events[0].label === 'Account activated', `expected "Account activated" to sort first, got "${result.events[0].label}"`);
    // The stored event date must be back in Ripple-epoch-seconds (matching
    // every other event's units), i.e. close to creationRippleSec, NOT a
    // huge Unix-ms-scale number and NOT double-shifted.
    assert(Math.abs(result.events[0].date - creationRippleSec) < 5, `expected the activation event's date to be ~${creationRippleSec} (Ripple-epoch seconds), got ${result.events[0].date} — a units bug would produce a wildly different number`);
    assert(result.events[1].label === 'First outbound payment', `expected the payment to sort second, got "${result.events[1].label}"`);
  });
});

suite.register('Real "first occurrence" milestones are detected across transaction types, each only once (the FIRST, not every occurrence)', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugAccountJourney, { timeout: 8000 });
    const txList = [
      tx('Payment', 1000, { Destination: 'rB00000000000000000000000000000000000000' }), // first outbound
      tx('Payment', 2000, { Destination: 'rC00000000000000000000000000000000000000' }), // second outbound — must not create a duplicate milestone
      tx('TrustSet', 1500),
      tx('OfferCreate', 3000),
      tx('OfferCreate', 4000), // second offer — must not duplicate
      tx('AMMDeposit', 5000),
      tx('NFTokenMint', 6000),
      tx('SetRegularKey', 7000),
    ];
    const result = await page.evaluate(([txList, addr]) => window._debugAccountJourney(txList, addr, null, false), [txList, ADDR]);

    const labels = result.events.map(e => e.label);
    assert(labels.filter(l => l === 'First outbound payment').length === 1, 'expected exactly one "First outbound payment" milestone despite 2 outbound payments');
    assert(labels.includes('First token trust line established'), 'expected a TrustSet milestone');
    assert(labels.filter(l => l === 'First DEX offer placed').length === 1, 'expected exactly one DEX offer milestone despite 2 OfferCreates');
    assert(labels.includes('First AMM liquidity deposit'), 'expected an AMM deposit milestone');
    assert(labels.includes('First NFT minted'), 'expected an NFT mint milestone');
    assert(labels.includes('First account security configuration change'), 'expected a security-change milestone');
    // Chronological order must be preserved.
    const dates = result.events.map(e => e.date);
    assert(dates.every((d, i) => i === 0 || d >= dates[i - 1]), `expected events in chronological order, got dates: ${JSON.stringify(dates)}`);
  });
});

suite.register('The largest-ever outbound transfer is recorded as a genuine milestone (unlike "Is This Normal?", this is a plain fact, not a percentile judgment)', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugAccountJourney, { timeout: 8000 });
    const txList = [
      tx('Payment', 1000, { Destination: 'rB00000000000000000000000000000000000000', Amount: '50000000' }), // 50 XRP
      tx('Payment', 2000, { Destination: 'rC00000000000000000000000000000000000000', Amount: '900000000' }), // 900 XRP — the largest
      tx('Payment', 3000, { Destination: 'rD00000000000000000000000000000000000000', Amount: '30000000' }), // 30 XRP
    ];
    const result = await page.evaluate(([txList, addr]) => window._debugAccountJourney(txList, addr, null, false), [txList, ADDR]);
    const milestone = result.events.find(e => e.label === 'Largest recorded outbound transfer');
    assert(milestone, 'expected a "Largest recorded outbound transfer" milestone');
    assert(/900/.test(milestone.detail), `expected the milestone to cite the real largest amount (900 XRP), got: "${milestone.detail}"`);
    assert(milestone.date === 2000, `expected the milestone's date to match the actual largest transfer's date (2000), got ${milestone.date}`);
  });
});

suite.register('No transactions and no wallet-creation timestamp produces applicable:false, not an empty fabricated timeline', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugAccountJourney, { timeout: 8000 });
    const result = await page.evaluate(([addr]) => window._debugAccountJourney([], addr, null, false), [ADDR]);
    assert(result.applicable === false, 'expected applicable:false with no data at all');
    assert(result.events.length === 0, 'expected zero events');
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
