// Regression guard for Auction-Window Market Analysis (spec §11-14/§46) —
// splits a pool's REAL trading volume during the current auction slot
// into slot-owner / authorized-accounts / external-participant shares,
// classified by CLOB/AMM/HYBRID route. Built from a bounded, targeted
// fetch of the POOL's own account_tx (every AMM execution necessarily
// touches the pool's own reserves, so its tx history contains every
// execution against it — the same trick already used for a confirmed
// issuer's own token). This suite covers the pure analysis function
// directly; the live fetch pipeline was verified manually against a real
// pool with an active auction slot (correctly rendered an honest empty
// state when no trades fell in the exact current window, rather than a
// fabricated 0/0/0 bar).
import { withPage, makeSuite, assert } from './helpers.mjs';

const suite = makeSuite('Auction-Window Market Analysis');

const POOL_ACCOUNT = 'rPoolAccount000000000000000000000000000';
const SLOT_OWNER = 'rSlotOwner00000000000000000000000000000';
const AUTH_A = 'rAuthA00000000000000000000000000000000000';
const EXTERNAL_1 = 'rExternal100000000000000000000000000000';
const AMMID = '419A61974BDCB91E0408865D554605F466084BA9A88F75391502502F0578DF89';

// Expiration fixed to a known instant so slotStart (expiration - 24h) is
// easy to reason about in test fixtures.
const EXPIRATION_ISO = '2026-01-02T00:00:00.000Z';
const XRPL_EPOCH = 946684800;
const expirationRippleSec = Math.floor(Date.parse(EXPIRATION_ISO) / 1000) - XRPL_EPOCH;
const slotStartRippleSec = expirationRippleSec - 24 * 3600;

function poolTradeTx({ account, xrpDelta, date, hash, withOfferNode = false }) {
  const before = 1000000000;
  const after = before + xrpDelta * 1e6;
  const nodes = [
    { ModifiedNode: { LedgerEntryType: 'AccountRoot', FinalFields: { Account: POOL_ACCOUNT, Balance: String(after), AMMID }, PreviousFields: { Balance: String(before) } } },
  ];
  if (withOfferNode) {
    nodes.push({ ModifiedNode: { LedgerEntryType: 'Offer', FinalFields: { Account: 'rSomeOfferOwner00000000000000000000000', TakerGets: '1000000', TakerPays: '1000000' }, PreviousFields: { TakerGets: '2000000' } } });
  }
  return { tx: { Account: account, TransactionType: 'OfferCreate', date, hash }, meta: { TransactionResult: 'tesSUCCESS', AffectedNodes: nodes } };
}

const auctionSlot = { applicable: true, slotOwner: SLOT_OWNER, authAccounts: [AUTH_A], expiration: EXPIRATION_ISO };

suite.register('Trades outside the slot window are correctly bucketed before/after, and during-window trades are classified by group (owner/authorized/external)', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugAuctionWindowMarket, { timeout: 8000 });
    const txList = [
      poolTradeTx({ account: EXTERNAL_1, xrpDelta: 500, date: slotStartRippleSec - 3600, hash: 'before1' }), // 1h before slot
      poolTradeTx({ account: SLOT_OWNER, xrpDelta: 1000, date: slotStartRippleSec + 3600, hash: 'during-owner' }), // 1h into slot
      poolTradeTx({ account: AUTH_A, xrpDelta: 500, date: slotStartRippleSec + 7200, hash: 'during-auth' }),
      poolTradeTx({ account: EXTERNAL_1, xrpDelta: 500, date: slotStartRippleSec + 10800, hash: 'during-ext' }),
      poolTradeTx({ account: EXTERNAL_1, xrpDelta: 200, date: expirationRippleSec + 3600, hash: 'after1' }), // 1h after expiration
    ];
    const result = await page.evaluate(([txList, poolAccount, auctionSlot]) => {
      return window._debugAuctionWindowMarket({ txList, truncated: false }, poolAccount, auctionSlot);
    }, [txList, POOL_ACCOUNT, auctionSlot]);

    assert(result.applicable === true, 'expected applicable:true with real trades and an active slot');
    assert(result.before.count === 1, `expected 1 before-slot trade, got ${result.before.count}`);
    assert(result.during.count === 3, `expected 3 during-slot trades, got ${result.during.count}`);
    assert(result.after.count === 1, `expected 1 after-slot trade, got ${result.after.count}`);

    const d = result.during;
    assert(Math.abs(d.ownerPct - 50) < 0.5, `expected owner=50% of during-window volume (1000 of 2000), got ${d.ownerPct}`);
    assert(Math.abs(d.authorizedPct - 25) < 0.5, `expected authorized=25%, got ${d.authorizedPct}`);
    assert(Math.abs(d.externalPct - 25) < 0.5, `expected external=25%, got ${d.externalPct}`);
    assert(Math.abs(d.ownerPct + d.authorizedPct + d.externalPct - 100) < 0.5, 'group percentages must sum to ~100%');
  });
});

suite.register('Every trade sourced from the pool\'s own tx history necessarily touches the AMM (route is never plain CLOB) — HYBRID only when an Offer node is also present', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugAuctionWindowMarket, { timeout: 8000 });
    const txList = [
      poolTradeTx({ account: SLOT_OWNER, xrpDelta: 100, date: slotStartRippleSec + 100, hash: 'pure-amm' }),
      poolTradeTx({ account: SLOT_OWNER, xrpDelta: 100, date: slotStartRippleSec + 200, hash: 'hybrid', withOfferNode: true }),
    ];
    const result = await page.evaluate(([txList, poolAccount, auctionSlot]) => {
      return window._debugAuctionWindowMarket({ txList, truncated: false }, poolAccount, auctionSlot);
    }, [txList, POOL_ACCOUNT, auctionSlot]);

    assert(result.during.clobCount === 0, `a transaction indexed to the pool's own account_tx always touches the pool -> never plain CLOB, got clobCount=${result.during.clobCount}`);
    assert(result.during.ammCount === 1, `expected 1 pure-AMM trade, got ${result.during.ammCount}`);
    assert(result.during.hybridCount === 1, `expected 1 hybrid (AMM + Offer node) trade, got ${result.during.hybridCount}`);
  });
});

suite.register('No trades in the fetched window during the slot produces applicable:true with during.count 0, not a fabricated result', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugAuctionWindowMarket, { timeout: 8000 });
    const txList = [poolTradeTx({ account: EXTERNAL_1, xrpDelta: 500, date: slotStartRippleSec - 3600, hash: 'before-only' })];
    const result = await page.evaluate(([txList, poolAccount, auctionSlot]) => {
      return window._debugAuctionWindowMarket({ txList, truncated: false }, poolAccount, auctionSlot);
    }, [txList, POOL_ACCOUNT, auctionSlot]);
    assert(result.applicable === true, 'expected applicable:true even with zero during-window trades (a real slot exists)');
    assert(result.during.count === 0, 'expected zero during-window trades');
    assert(result.findings.length === 0, 'must not fabricate a finding when there is nothing to report during the window');
  });
});

suite.register('No active auction slot (or no pool tx data) produces applicable:false, not an error', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugAuctionWindowMarket, { timeout: 8000 });
    const result = await page.evaluate(([poolAccount]) => ({
      noSlot: window._debugAuctionWindowMarket({ txList: [{ tx: {}, meta: {} }], truncated: false }, poolAccount, { applicable: false }),
      noPoolData: window._debugAuctionWindowMarket(null, poolAccount, { applicable: true, slotOwner: 'rX', authAccounts: [], expiration: '2026-01-01T00:00:00Z' }),
    }), [POOL_ACCOUNT]);
    assert(result.noSlot.applicable === false, 'expected applicable:false with no active auction slot');
    assert(result.noPoolData.applicable === false, 'expected applicable:false with no pool tx data fetched');
  });
});

suite.register('A high auction-group share during the window produces a descriptive finding that explicitly offers arbitrage/market-making as alternative explanations', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugAuctionWindowMarket, { timeout: 8000 });
    const txList = [
      poolTradeTx({ account: SLOT_OWNER, xrpDelta: 900, date: slotStartRippleSec + 100, hash: 'owner-big' }),
      poolTradeTx({ account: EXTERNAL_1, xrpDelta: 100, date: slotStartRippleSec + 200, hash: 'ext-small' }),
    ];
    const result = await page.evaluate(([txList, poolAccount, auctionSlot]) => {
      return window._debugAuctionWindowMarket({ txList, truncated: false }, poolAccount, auctionSlot);
    }, [txList, POOL_ACCOUNT, auctionSlot]);
    const finding = result.findings.find(f => f.module === 'AMM Auction Window');
    assert(finding, 'expected a finding when during-window trades exist');
    assert(finding.sev === 'info', `must stay info severity (descriptive, not accusatory), got ${finding.sev}`);
    assert(/arbitrage/i.test(finding.alternativeExplanations.join(' ')), 'must explicitly offer arbitrage as an alternative explanation');
    assert(/WHO traded.*not WHY/.test(finding.classification), 'classification must explicitly distinguish who-traded from why, deferring intent to Wash Execution/Execution Routing');
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
