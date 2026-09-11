// Regression guard for Auction Dominance (Outbid Events, spec §25-27) —
// reconstructs who has actually WON a pool's auction slot over time (not
// just the current owner) from every successful AMMBid transaction found
// in the pool's own fetched tx history. A successful AMMBid immediately
// displaces whoever held the slot before, so consecutive bids in the
// pool's own history directly reconstruct the real outbid sequence.
//
// Live-verified manually against the real CULT/XRP pool: its fetched
// ~1200-tx window (capped/truncated) contained zero AMMBid transactions
// at all — the actual winning bid happened further back than the bounded
// fetch reaches — and the feature correctly stayed silent (applicable:
// true, totalWins: 0, no finding, no rendered block) rather than
// fabricating a "0 wins" result. This suite covers the populated case
// with synthetic data, since live data won't reliably land an AMMBid
// inside the fetch window on demand.
import { withPage, makeSuite, assert } from './helpers.mjs';

const suite = makeSuite('AMM Auction Dominance (Outbid Events)');

const POOL_ACCOUNT = 'rPoolAccount000000000000000000000000000';
const WALLET_A = 'rWalletA00000000000000000000000000000000';
const WALLET_B = 'rWalletB00000000000000000000000000000000';
const WALLET_C = 'rWalletC00000000000000000000000000000000';

const LP_CURRENCY = '03E8C1A1B4D2F5AAAAAAAAAAAAAAAAAAAAAAAAAA';
const RIPPLE_NEUTRAL = 'rrrrrrrrrrrrrrrrrrrrrrrrrrrrrqLQg';

function ammBidTx({ account, lpSpent, date, hash }) {
  const before = 100;
  const after = before - lpSpent;
  return {
    tx: { Account: account, TransactionType: 'AMMBid', date, hash },
    meta: {
      TransactionResult: 'tesSUCCESS',
      AffectedNodes: [{ ModifiedNode: { LedgerEntryType: 'RippleState',
        FinalFields: { Balance: { currency: LP_CURRENCY, issuer: RIPPLE_NEUTRAL, value: String(after) }, LowLimit: { issuer: account, currency: LP_CURRENCY, value: '0' }, HighLimit: { issuer: POOL_ACCOUNT, currency: LP_CURRENCY, value: '1000000' } },
        PreviousFields: { Balance: { currency: LP_CURRENCY, issuer: RIPPLE_NEUTRAL, value: String(before) } } } }],
    },
  };
}

suite.register('A real sequence of AMMBid transactions reconstructs the actual outbid history, ranked by win count', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugAuctionDominance, { timeout: 8000 });
    const txList = [
      ammBidTx({ account: WALLET_A, lpSpent: 2, date: 1000, hash: 'b1' }),
      ammBidTx({ account: WALLET_B, lpSpent: 3, date: 2000, hash: 'b2' }),
      ammBidTx({ account: WALLET_A, lpSpent: 2.5, date: 3000, hash: 'b3' }),
      ammBidTx({ account: WALLET_A, lpSpent: 2.2, date: 4000, hash: 'b4' }),
      ammBidTx({ account: WALLET_C, lpSpent: 4, date: 5000, hash: 'b5' }),
    ];
    const result = await page.evaluate((poolTxData) => window._debugAuctionDominance(poolTxData), { txList, truncated: false });

    assert(result.applicable === true, 'expected applicable:true with real bids');
    assert(result.totalWins === 5, `expected 5 total wins, got ${result.totalWins}`);
    assert(result.winsByAccount.length === 3, `expected 3 distinct winners, got ${result.winsByAccount.length}`);
    assert(result.winsByAccount[0].account === WALLET_A, `expected Wallet A ranked first (3 wins), got ${result.winsByAccount[0].account}`);
    assert(result.winsByAccount[0].winCount === 3, `expected Wallet A to have 3 wins, got ${result.winsByAccount[0].winCount}`);
    assert(Math.abs(result.topWinnerSharePct - 60) < 0.5, `expected top winner share 60% (3 of 5), got ${result.topWinnerSharePct}`);
    // periods should be chronologically ordered and each bid's period ends when the next bid wins
    assert(result.bids[0].periodEnd === 2000, `expected the first bid's period to end when the second bid won, got ${result.bids[0].periodEnd}`);
    assert(result.bids[result.bids.length - 1].periodEnd === null, 'the most recent bid has no known period end yet');

    const finding = result.findings.find(f => f.module === 'AMM Auction Dominance');
    assert(finding, 'expected a dominance finding with >=3 total wins');
    assert(finding.sev === 'info', `must stay info severity, got ${finding.sev}`);
    assert(/market structural influence.*not manipulation/i.test(finding.classification), 'classification must explicitly disclaim manipulation');
  });
});

suite.register('Fewer than 3 total bids produces no finding (avoids over-interpreting a tiny sample), but data is still returned', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugAuctionDominance, { timeout: 8000 });
    const txList = [
      ammBidTx({ account: WALLET_A, lpSpent: 2, date: 1000, hash: 'b1' }),
      ammBidTx({ account: WALLET_B, lpSpent: 3, date: 2000, hash: 'b2' }),
    ];
    const result = await page.evaluate((poolTxData) => window._debugAuctionDominance(poolTxData), { txList, truncated: false });
    assert(result.applicable === true, 'expected applicable:true');
    assert(result.totalWins === 2, `expected 2 total wins, got ${result.totalWins}`);
    assert(result.findings.length === 0, 'must not produce a finding from only 2 observed bids');
  });
});

suite.register('Zero AMMBid transactions in the fetched window produces applicable:true with totalWins:0 and no fabricated finding (the real CULT/XRP live case)', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugAuctionDominance, { timeout: 8000 });
    const txList = [
      { tx: { Account: WALLET_A, TransactionType: 'Payment', date: 1000, hash: 'p1' }, meta: { TransactionResult: 'tesSUCCESS', AffectedNodes: [] } },
    ];
    const result = await page.evaluate((poolTxData) => window._debugAuctionDominance(poolTxData), { txList, truncated: true });
    assert(result.applicable === true, 'expected applicable:true even with zero bids found');
    assert(result.totalWins === 0, `expected 0 total wins, got ${result.totalWins}`);
    assert(result.findings.length === 0, 'must not fabricate a finding with zero real bids observed');
    assert(result.dataCompleteness === 'possibly-truncated', 'must propagate the truncated flag honestly');
  });
});

suite.register('No pool tx data at all produces applicable:false, not an error', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugAuctionDominance, { timeout: 8000 });
    const result = await page.evaluate(() => window._debugAuctionDominance(null));
    assert(result.applicable === false, 'expected applicable:false with no pool tx data');
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
