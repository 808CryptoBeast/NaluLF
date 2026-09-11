// Regression guard for a real bug found while auditing the Offer Lifecycle
// Engine against XRPL's IOC/FOK semantics: a tfImmediateOrCancel order
// NEVER leaves a resting Offer object on the ledger, regardless of how
// much (if anything) actually crossed. The old code used "no resting
// node found" as a proxy for "fully filled," which is correct for an
// ordinary order that crosses 100% but WRONG for an IOC order that only
// partially (or never) filled before the remainder was killed — every
// such order was silently recorded as a 100%-filled success, inflating
// realizedFillPct and mislabeling status as 'filled-immediately'.
//
// Fixed by deriving crossedAtCreation from the CREATE transaction's own
// real balance delta (extractBalanceDeltas) instead of assuming full
// fill whenever nothing rests, and adding explicit 'killed-partial' /
// 'killed-unfilled' statuses for IOC/FOK orders that didn't fully cross.
import { withPage, makeSuite, assert } from './helpers.mjs';

const suite = makeSuite('Offer Lifecycle — IOC/FOK Fill Accuracy');

const FOO_ISSUER = 'rFooIssuer000000000000000000000000000';
const RIPPLE_NEUTRAL = 'rrrrrrrrrrrrrrrrrrrrrrrrrrrrrqLQg';
const tfImmediateOrCancel = 0x00020000;

function iocOfferTx(addr, { xrpCrossed, fooCrossed, hash, seq = 1 }) {
  const xrpBefore = 1300000000; // 1300 XRP starting balance, in drops
  const xrpAfter = xrpBefore - xrpCrossed * 1e6;
  const nodes = [];
  if (xrpCrossed > 0) {
    nodes.push({ ModifiedNode: { LedgerEntryType: 'AccountRoot', FinalFields: { Account: addr, Balance: String(xrpAfter) }, PreviousFields: { Balance: String(xrpBefore) } } });
  }
  if (fooCrossed > 0) {
    nodes.push({ ModifiedNode: { LedgerEntryType: 'RippleState',
      FinalFields: { Balance: { currency: 'FOO', issuer: RIPPLE_NEUTRAL, value: String(fooCrossed) }, LowLimit: { issuer: addr, currency: 'FOO', value: '0' }, HighLimit: { issuer: FOO_ISSUER, currency: 'FOO', value: '1000000' } },
      PreviousFields: { Balance: { currency: 'FOO', issuer: RIPPLE_NEUTRAL, value: '0' } } } });
  }
  return {
    tx: {
      Account: addr, TransactionType: 'OfferCreate', Sequence: seq, Flags: tfImmediateOrCancel,
      TakerGets: String(1000 * 1e6), // wants to sell 1000 XRP
      TakerPays: { currency: 'FOO', issuer: FOO_ISSUER, value: '100' }, // for up to 100 FOO
      date: 800000000, hash,
    },
    meta: { TransactionResult: 'tesSUCCESS', AffectedNodes: nodes },
  };
}

suite.register('An IOC order with a real 30% partial fill is NOT mislabeled as 100% filled', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugOfferLifecycles, { timeout: 8000 });
    const addr = 'rIocPartial000000000000000000000000000';
    const txList = [iocOfferTx(addr, { xrpCrossed: 300, fooCrossed: 30, hash: 'h1' })];
    const result = await page.evaluate(([txList, addr]) => {
      const r = window._debugOfferLifecycles(txList, addr, {});
      return r.list[0];
    }, [txList, addr]);

    assert(result.status === 'killed-partial', `expected status 'killed-partial' for a 30%-filled IOC order, got '${result.status}'`);
    assert(Math.abs(result.crossedAtCreation.gets - 300) < 0.01, `expected 300 XRP actually crossed, got ${result.crossedAtCreation.gets}`);
    assert(Math.abs(result.realizedFillPct - 30) < 0.5, `expected realizedFillPct ~30%, got ${result.realizedFillPct} (the bug would report 100%)`);
  });
});

suite.register('An IOC order with zero fill is distinguished from a partial fill and from a full fill', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugOfferLifecycles, { timeout: 8000 });
    const addr = 'rIocZero0000000000000000000000000000000';
    const txList = [iocOfferTx(addr, { xrpCrossed: 0, fooCrossed: 0, hash: 'h1' })];
    const result = await page.evaluate(([txList, addr]) => {
      const r = window._debugOfferLifecycles(txList, addr, {});
      return r.list[0];
    }, [txList, addr]);

    assert(result.status === 'killed-unfilled', `expected status 'killed-unfilled' for a zero-fill IOC order, got '${result.status}'`);
    assert(result.crossedAtCreation.gets === 0, `expected 0 XRP crossed, got ${result.crossedAtCreation.gets}`);
    assert(result.realizedFillPct === 0, `expected realizedFillPct 0%, got ${result.realizedFillPct}`);
    assert(result.status !== 'cancelled', 'a killed IOC must never be counted as an intentional OfferCancel');
  });
});

suite.register('An IOC order that genuinely fills 100% still reports filled-immediately, not killed-partial', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugOfferLifecycles, { timeout: 8000 });
    const addr = 'rIocFull0000000000000000000000000000000';
    const txList = [iocOfferTx(addr, { xrpCrossed: 1000, fooCrossed: 100, hash: 'h1' })];
    const result = await page.evaluate(([txList, addr]) => {
      const r = window._debugOfferLifecycles(txList, addr, {});
      return r.list[0];
    }, [txList, addr]);

    assert(result.status === 'filled-immediately', `expected 'filled-immediately' for a genuinely fully-filled IOC order, got '${result.status}'`);
    assert(Math.abs(result.realizedFillPct - 100) < 0.5, `expected realizedFillPct ~100%, got ${result.realizedFillPct}`);
  });
});

suite.register('killed-partial/killed-unfilled are excluded from cancelledCount and reported as their own stat in analyseOfferFillRate', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugOfferLifecycles, { timeout: 8000 });
    const addr = 'rIocStats000000000000000000000000000000';
    const txList = [
      iocOfferTx(addr, { xrpCrossed: 300, fooCrossed: 30, hash: 'h1', seq: 1 }),
      iocOfferTx(addr, { xrpCrossed: 0, fooCrossed: 0, hash: 'h2', seq: 2 }),
    ];
    const stats = await page.evaluate(([txList, addr]) => window._debugOfferLifecycles(txList, addr, {}).stats, [txList, addr]);
    assert(stats.killedPartial === 1, `expected 1 killed-partial, got ${stats.killedPartial}`);
    assert(stats.killedUnfilled === 1, `expected 1 killed-unfilled, got ${stats.killedUnfilled}`);
    assert(stats.cancelled === 0, `killed IOC orders must never inflate the cancelled count, got ${stats.cancelled}`);
    assert(stats.filledImmediately === 0, `killed IOC orders (even partial) must not count as filled-immediately, got ${stats.filledImmediately}`);
  });
});

suite.register('A second, separate bug found in the same audit: an ordinary (non-IOC) order that fully crosses at creation now gets a real realizedFillPct instead of null', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugOfferLifecycles, { timeout: 8000 });
    const addr = 'rOrdinaryFullFill00000000000000000000000';
    // No IOC/FOK flag at all — an ordinary order that happens to fully
    // cross in its own CREATE transaction, leaving nothing resting.
    // realizedFillPct's computation used to live inside a loop gated on
    // `if (!record.createLedgerIndex) continue` — which is exactly the
    // condition every filled-immediately order (IOC or not) meets, so it
    // silently never ran and realizedFillPct stayed null for ALL of them,
    // not just the IOC/FOK cases above.
    const txList = [{
      tx: { Account: addr, TransactionType: 'OfferCreate', Sequence: 1, Flags: 0,
        TakerGets: String(500 * 1e6), TakerPays: { currency: 'FOO', issuer: FOO_ISSUER, value: '50' },
        date: 800000000, hash: 'h1' },
      meta: { TransactionResult: 'tesSUCCESS', AffectedNodes: [
        { ModifiedNode: { LedgerEntryType: 'AccountRoot', FinalFields: { Account: addr, Balance: '800000000' }, PreviousFields: { Balance: '1300000000' } } },
        { ModifiedNode: { LedgerEntryType: 'RippleState',
          FinalFields: { Balance: { currency: 'FOO', issuer: RIPPLE_NEUTRAL, value: '50' }, LowLimit: { issuer: addr, currency: 'FOO', value: '0' }, HighLimit: { issuer: FOO_ISSUER, currency: 'FOO', value: '1000000' } },
          PreviousFields: { Balance: { currency: 'FOO', issuer: RIPPLE_NEUTRAL, value: '0' } } } },
      ] },
    }];
    const result = await page.evaluate(([txList, addr]) => window._debugOfferLifecycles(txList, addr, {}).list[0], [txList, addr]);
    assert(result.status === 'filled-immediately', `expected 'filled-immediately', got '${result.status}'`);
    assert(result.realizedFillPct !== null, `realizedFillPct must not be null for a filled-immediately order (this was the second bug — it was never computed at all before the fix)`);
    assert(Math.abs(result.realizedFillPct - 100) < 0.5, `expected realizedFillPct ~100%, got ${result.realizedFillPct}`);
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
