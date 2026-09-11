// Regression guard for AMM Auction Bid History — the inspected account's
// OWN AMMBid transaction history (who they authorized, how much LP value
// they actually spent), distinct from the CURRENT auction-slot snapshot
// (AMM Governance). Reconstructed entirely from already-fetched txList
// data; the real LP cost is read from the bid transaction's own balance
// delta rather than assumed from a transaction field, matching the same
// "trust the ledger delta" principle used for the IOC/FOK fill fix.
import { withPage, makeSuite, assert } from './helpers.mjs';

const suite = makeSuite('AMM Auction Bid History');

const LP_CURRENCY = '03E8C1A1B4D2F5AAAAAAAAAAAAAAAAAAAAAAAAAA'; // starts with '03', 40 hex chars -> a real LP token shape
const RIPPLE_NEUTRAL = 'rrrrrrrrrrrrrrrrrrrrrrrrrrrrrqLQg';
const POOL_ACCOUNT = 'rPoolAccount000000000000000000000000000';

function bidTx(addr, { lpSpent, authAccounts = [], hash, seq = 1, bidMin = null, bidMax = null }) {
  const before = 100;
  const after = before - lpSpent;
  return {
    tx: {
      Account: addr, TransactionType: 'AMMBid', Sequence: seq,
      Asset: { currency: 'FOO', issuer: 'rFooIssuer00000000000000000000000000' },
      Asset2: { currency: 'XRP' },
      AuthAccounts: authAccounts.map(a => ({ AuthAccount: { Account: a } })),
      BidMin: bidMin, BidMax: bidMax,
      date: 800000000, hash,
    },
    meta: {
      TransactionResult: 'tesSUCCESS',
      AffectedNodes: [{ ModifiedNode: { LedgerEntryType: 'RippleState',
        FinalFields: { Balance: { currency: LP_CURRENCY, issuer: RIPPLE_NEUTRAL, value: String(after) }, LowLimit: { issuer: addr, currency: LP_CURRENCY, value: '0' }, HighLimit: { issuer: POOL_ACCOUNT, currency: LP_CURRENCY, value: '1000000' } },
        PreviousFields: { Balance: { currency: LP_CURRENCY, issuer: RIPPLE_NEUTRAL, value: String(before) } } } }],
    },
  };
}

suite.register('A real AMMBid transaction is parsed with its true LP cost read from the balance delta, plus authorized accounts', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugAmmBidHistory, { timeout: 8000 });
    const addr = 'rBidder0000000000000000000000000000000000';
    const txList = [bidTx(addr, { lpSpent: 5.25, authAccounts: ['rAuthA00000000000000000000000000000', 'rAuthB00000000000000000000000000000'], hash: 'h1' })];
    const result = await page.evaluate(([txList, addr]) => window._debugAmmBidHistory(txList, addr), [txList, addr]);

    assert(result.applicable === true, 'expected applicable:true with a real bid present');
    assert(result.bidCount === 1, `expected 1 bid, got ${result.bidCount}`);
    const bid = result.bids[0];
    assert(Math.abs(bid.lpTokensBid - 5.25) < 0.001, `expected 5.25 LP tokens spent (real delta), got ${bid.lpTokensBid}`);
    assert(bid.authAccounts.length === 2, `expected 2 authorized accounts, got ${bid.authAccounts.length}`);
    assert(bid.assetCurrency === 'FOO' && bid.asset2Currency === 'XRP', `expected the correct asset pair, got ${bid.assetCurrency}/${bid.asset2Currency}`);
    const finding = result.findings.find(f => f.module === 'AMM Auction Slot');
    assert(finding, 'expected a bid-history finding');
    assert(/5\.25 LP token/.test(finding.observed.join(' ')), `expected the real LP cost to appear in observed text: ${JSON.stringify(finding.observed)}`);
  });
});

suite.register('An account with no AMMBid transactions gets applicable:false and zero findings — no fabricated "0 bids" card', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugAmmBidHistory, { timeout: 8000 });
    const result = await page.evaluate(() => window._debugAmmBidHistory([], 'rNoBidder00000000000000000000000000000000'));
    assert(result.applicable === false, 'expected applicable:false with no bids');
    assert(result.findings.length === 0, 'expected zero findings with no bids');
  });
});

suite.register('Multiple bids are aggregated correctly (total LP spent, distinct authorized accounts, sorted newest-first)', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugAmmBidHistory, { timeout: 8000 });
    const addr = 'rRepeatBidder000000000000000000000000000';
    const first = bidTx(addr, { lpSpent: 2, authAccounts: ['rAuthA00000000000000000000000000000'], hash: 'h1', seq: 1 });
    const second = bidTx(addr, { lpSpent: 3, authAccounts: ['rAuthA00000000000000000000000000000', 'rAuthC00000000000000000000000000000'], hash: 'h2', seq: 2 });
    second.tx.date = 800000500; // later than the first bid
    const txList = [first, second];
    const result = await page.evaluate(([txList, addr]) => window._debugAmmBidHistory(txList, addr), [txList, addr]);
    assert(result.bidCount === 2, `expected 2 bids, got ${result.bidCount}`);
    assert(result.bids[0].date >= result.bids[1].date, 'expected bids sorted newest-first');
    const finding = result.findings[0];
    assert(/2 distinct account/.test(finding.observed.join(' ')) || /3 distinct account/.test(finding.observed.join(' ')), `expected a distinct-authorized-accounts count in observed: ${JSON.stringify(finding.observed)}`);
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
