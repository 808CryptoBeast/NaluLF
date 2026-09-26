// Regression guard for Holder Cohort Intelligence: Top Holders (reused from
// analyseIssuerConnections, not recomputed), Early Holders (new, from
// TrustSet history), and LP Holders (new, from a single targeted
// account_lines call on the token's AMM pool account) — plus how much of
// the token's aggregate trading volume (from Issuer Market Activity) each
// cohort actually generated. Cohorts overlap by design and must never be
// summed together as if they partitioned the market.
//
// Also covers the "Distribution Cohort & Overlap Matrix" phase (phase 2 of
// the 4-phase Issuer Distribution-to-Market Intelligence build): a real
// Seller cohort (issuerMarketActivity's per-holder holderGrossSold, zero
// extra RPC calls — reuses the same extractBalanceDeltas pass already run
// for trade volume/routing) and an Overlap Matrix over all 4 cohorts
// (Early/Top/LP/Seller). Two things this specifically guards:
// 1. The RippleState delta SIGN convention — verified by hand against real
//    XRPL semantics (RippleState.Balance is stored from the LOW account's
//    side; a NEGATIVE balance means the low account owes the high account).
//    With the issuer as the low account and a holder as high: the issuer
//    DISTRIBUTING tokens to the holder makes the balance MORE negative
//    (delta NEGATIVE), while the holder REDEEMING/selling tokens back moves
//    the balance toward zero (delta POSITIVE) — so positive delta = seller,
//    negative = buyer, from the issuer's own perspective.
// 2. holderGrossSold sums only the DECREASING legs (a running NET total
//    would hide a holder who received a big distribution and later sold
//    only part of it — they'd still show net-positive/buyer overall despite
//    genuinely selling some of it).
import { withPage, connectAndShowDashboard, inspectAddress, makeSuite, assert } from './helpers.mjs';

// Real, active token issuer (CULT) confirmed live to have real top/early/LP
// holder cohorts and real settled trade volume to attribute to them.
const REAL_ISSUER_ACCOUNT = 'rCULtAKrKbQjk1Tpmg5hkw4dpcf9S9KCs';

const suite = makeSuite('Holder Cohort Intelligence');

suite.register('A real token issuer gets a Holder Cohorts finding with top/early/LP holders and a volume-share breakdown', async () => {
  await withPage(async (page) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, REAL_ISSUER_ACCOUNT, { timeout: 90000 });
    await page.waitForTimeout(2500); // let the fuller tx-history fetch settle for this high-volume account

    const finding = await page.evaluate(() => (window._lastAllFindings || []).find((f) => f.module === 'Holder Cohorts'));
    assert(finding, 'expected a Holder Cohorts finding — live data may have drifted; re-verify against current mainnet state if this fails');
    assert(/top.*early/i.test(finding.headline), `headline should report top and early holder counts: ${finding.headline}`);
    assert(finding.sev === 'info', `this is descriptive, not accusatory, expected info severity, got ${finding.sev}`);
    assert(finding.detail?.includes('should not be added together'), 'must explicitly warn against summing overlapping cohort percentages');
    assert(finding.observed?.some((o) => /supply/.test(o)), 'expected an observed line reporting top-holder supply share');
  });
});

suite.register('A non-issuer account produces applicable:false and zero findings, without running the cohort scan', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugHolderCohorts, { timeout: 8000 });
    const result = await page.evaluate(() => {
      const notApplicableMarketActivity = { applicable: false, findings: [] };
      return window._debugHolderCohorts([], 'rOrdinary', {}, { topHolders: [], totalIssued: 0 }, notApplicableMarketActivity, null);
    });
    assert(result.applicable === false, 'a non-issuer (or issuer with zero market activity) must not produce cohort data');
    assert(result.findings.length === 0, 'expected zero findings when Issuer Market Activity itself is not applicable');
  });
});

suite.register('Synthetic issuer: early holders, top holders (reused), and LP holders are all correctly identified and volume-attributed, with the incomplete-history caveat set', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugHolderCohorts, { timeout: 8000 });
    const result = await page.evaluate(() => {
      const issuer = 'rIssuerAddr';
      const early1 = 'rEarly1'; // first-ever trustline holder in the fetched window — NOT a top holder
      const early2 = 'rEarly2'; // second-earliest — NOT a top holder, no trade
      const lateHolder = 'rLateHolder'; // a top holder whose trustline predates the fetched window (realistic incomplete-history case)
      const topOnly = 'rTopOnly'; // a top holder, not early, no recorded trade
      const lpOnly = 'rLpOnlyHolder'; // provides liquidity but never trades directly

      const txList = [
        { tx: { TransactionType: 'TrustSet', Account: early1, date: 100, LimitAmount: { currency: 'FOO', issuer, value: '1000000' } } },
        { tx: { TransactionType: 'TrustSet', Account: early2, date: 200, LimitAmount: { currency: 'FOO', issuer, value: '1000000' } } },
        // Irrelevant trustline (different currency) must be excluded.
        { tx: { TransactionType: 'TrustSet', Account: 'rIrrelevant', date: 150, LimitAmount: { currency: 'BAR', issuer, value: '500' } } },
      ];

      const issuerConnAnalysis = {
        topHolders: [{ addr: lateHolder, balance: 900, currency: 'FOO' }, { addr: topOnly, balance: 100, currency: 'FOO' }],
        totalIssued: 1000,
        isSampleOnly: false,
      };

      const issuerMarketActivity = {
        applicable: true,
        issuedCurrencies: ['FOO'],
        trades: [
          { hash: 't1', route: 'CLOB', holders: [lateHolder], amount: 900 }, // top-holder cohort only
          { hash: 't2', route: 'AMM', holders: [early1], amount: 50 },      // early-holder cohort only
          { hash: 't3', route: 'CLOB', holders: ['rUnrelated'], amount: 50 }, // outside every cohort
        ],
      };

      const issuerAmmPool = {
        currency: 'FOO',
        lpHolderLines: [
          { account: lpOnly, currency: '03464F4F00000000000000000000000000000000', balance: '-80' },
          { account: lateHolder, currency: '03464F4F00000000000000000000000000000000', balance: '-20' },
        ],
      };

      // historyCoverage deliberately omits oldestToNewestFetched -> incomplete-history caveat expected.
      return window._debugHolderCohorts(txList, issuer, {}, issuerConnAnalysis, issuerMarketActivity, issuerAmmPool);
    });

    assert(result.applicable === true, 'expected applicable:true');
    assert(result.earlyHolders.length === 2, `expected 2 early holders (excluding the different-currency trustline; lateHolder's trustline predates the fetched window), got ${result.earlyHolders.length}`);
    assert(result.earlyHolders[0].addr === 'rEarly1', `earliest holder should be rEarly1 (date 100), got ${result.earlyHolders[0].addr}`);
    assert(result.earlyHolders[1].addr === 'rEarly2', `second-earliest should be rEarly2 (date 200), got ${result.earlyHolders[1].addr}`);
    assert(result.topHolders.length === 2, 'top holders should be passed through unchanged from analyseIssuerConnections');
    assert(result.lpHolders.length === 2, `expected 2 LP holders, got ${result.lpHolders.length}`);
    const lpOnlyEntry = result.lpHolders.find((h) => h.addr === 'rLpOnlyHolder');
    assert(lpOnlyEntry && Math.abs(lpOnlyEntry.sharePct - 80) < 0.01, `expected rLpOnlyHolder to hold 80% of LP supply, got ${lpOnlyEntry?.sharePct}`);
    assert(result.earlyHolderCoverageComplete === false, 'expected earlyHolderCoverageComplete:false when historyCoverage.oldestToNewestFetched is not set');

    // Cohorts are non-overlapping in this fixture by design: top-holder
    // cohort = {lateHolder, topOnly}, early-holder cohort = {early1, early2}.
    assert(Math.abs(result.cohortVolume.top.volumePct - 90) < 0.01, `expected top-holder cohort volume share 90% (lateHolder's 900/1000), got ${result.cohortVolume.top.volumePct}`);
    assert(Math.abs(result.cohortVolume.early.volumePct - 5) < 0.01, `expected early-holder cohort volume share 5% (early1's 50/1000), got ${result.cohortVolume.early.volumePct}`);

    const finding = result.findings[0];
    assert(finding, 'expected a Holder Cohorts finding to be produced');
    assert(finding.applicability?.applicable === true && /genesis/.test(finding.applicability.reason), 'expected an explicit incomplete-history caveat when oldestToNewestFetched coverage is not confirmed');
  });
});

suite.register('RippleState delta sign: distributing tokens to a holder is NEGATIVE, the holder redeeming them back is POSITIVE (from the issuer\'s own perspective)', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugExtractBalanceDeltas, { timeout: 8000 });
    const result = await page.evaluate(() => {
      const ISSUER = 'rIssuerLow00000000000000000000000000';
      const HOLDER = 'rHolderHigh0000000000000000000000000';
      // Issuer is the LOW account, holder is HIGH — RippleState.Balance is
      // always stored from the LOW side; negative = low owes high.
      const distributeTx = { TransactionType: 'Payment', Account: ISSUER, Destination: HOLDER };
      const distributeMeta = {
        TransactionResult: 'tesSUCCESS',
        AffectedNodes: [{
          ModifiedNode: {
            LedgerEntryType: 'RippleState',
            FinalFields: { LowLimit: { issuer: ISSUER }, HighLimit: { issuer: HOLDER }, Balance: { currency: 'FOO', value: '-500' } },
            PreviousFields: { Balance: { currency: 'FOO', value: '0' } },
          },
        }],
      };
      const redeemTx = { TransactionType: 'Payment', Account: HOLDER, Destination: ISSUER };
      const redeemMeta = {
        TransactionResult: 'tesSUCCESS',
        AffectedNodes: [{
          ModifiedNode: {
            LedgerEntryType: 'RippleState',
            FinalFields: { LowLimit: { issuer: ISSUER }, HighLimit: { issuer: HOLDER }, Balance: { currency: 'FOO', value: '0' } },
            PreviousFields: { Balance: { currency: 'FOO', value: '-500' } },
          },
        }],
      };
      const distributeDelta = window._debugExtractBalanceDeltas(distributeTx, distributeMeta, ISSUER);
      const redeemDelta = window._debugExtractBalanceDeltas(redeemTx, redeemMeta, ISSUER);
      return {
        distribute: distributeDelta.tokenDeltas.find(d => d.issuer === HOLDER)?.delta,
        redeem: redeemDelta.tokenDeltas.find(d => d.issuer === HOLDER)?.delta,
      };
    });
    assert(result.distribute === -500, `expected distributing 500 tokens to the holder to show delta -500 from the issuer's perspective, got ${result.distribute}`);
    assert(result.redeem === 500, `expected the holder redeeming 500 tokens back to show delta +500, got ${result.redeem}`);
  });
});

suite.register('holderGrossSold sums ONLY the decreasing legs — a holder who received a big distribution then sold part of it shows the real gross-sold amount, not a misleadingly-buyer-looking net total', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugIssuerMarketActivity, { timeout: 8000 });
    const result = await page.evaluate(() => {
      const ISSUER = 'rIssuerLow00000000000000000000000000';
      const HOLDER = 'rHolderHigh0000000000000000000000000';
      const mkRippleStateTx = (account, dest, fromVal, toVal, date) => ({
        tx: { TransactionType: 'Payment', Account: account, Destination: dest, date },
        meta: {
          TransactionResult: 'tesSUCCESS',
          AffectedNodes: [{
            ModifiedNode: {
              LedgerEntryType: 'RippleState',
              FinalFields: { LowLimit: { issuer: ISSUER }, HighLimit: { issuer: HOLDER }, Balance: { currency: 'FOO', value: String(toVal) } },
              PreviousFields: { Balance: { currency: 'FOO', value: String(fromVal) } },
            },
          }],
        },
      });
      const txList = [
        // Issuer distributes 1000 to the holder (balance 0 -> -1000).
        mkRippleStateTx(ISSUER, HOLDER, 0, -1000, 100),
        // Holder later sells/redeems 300 of it back (balance -1000 -> -700).
        mkRippleStateTx(HOLDER, ISSUER, -1000, -700, 200),
      ];
      const lines = [{ currency: 'FOO', balance: '-700', account: HOLDER }];
      const result = window._debugIssuerMarketActivity(txList, ISSUER, lines, {});
      return { grossSoldEntries: [...(result.holderGrossSold || new Map()).entries()] };
    });
    const holderEntry = result.grossSoldEntries.find(([addr]) => addr === 'rHolderHigh0000000000000000000000000');
    assert(holderEntry, 'expected the holder to appear in holderGrossSold despite ending net-positive (still holding 700 of the 1000 received)');
    assert(holderEntry[1] === 300, `expected gross sold to be exactly the 300 they redeemed (not the net -700), got ${holderEntry[1]}`);
  });
});

suite.register('Seller cohort: derived correctly from holderGrossSold, ranked by amount sold', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugHolderCohorts, { timeout: 8000 });
    const result = await page.evaluate(() => {
      const issuer = 'rIssuerAddr';
      const bigSeller = 'rBigSeller';
      const smallSeller = 'rSmallSeller';
      const issuerConnAnalysis = { topHolders: [], totalIssued: 1000, isSampleOnly: false };
      const issuerMarketActivity = {
        applicable: true, issuedCurrencies: ['FOO'], trades: [],
        holderGrossSold: new Map([[bigSeller, 800], [smallSeller, 50]]),
      };
      return window._debugHolderCohorts([], issuer, {}, issuerConnAnalysis, issuerMarketActivity, null);
    });
    assert(result.sellerHolders.length === 2, `expected 2 sellers, got ${result.sellerHolders.length}`);
    assert(result.sellerHolders[0].addr === 'rBigSeller' && result.sellerHolders[0].grossSold === 800, `expected the biggest seller ranked first, got ${JSON.stringify(result.sellerHolders[0])}`);
    assert(result.sellerHolders[1].addr === 'rSmallSeller' && result.sellerHolders[1].grossSold === 50, `expected the smaller seller ranked second, got ${JSON.stringify(result.sellerHolders[1])}`);
  });
});

suite.register('Overlap matrix: only wallets in 2+ cohorts appear, sorted by how many cohorts they belong to', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugHolderCohorts, { timeout: 8000 });
    const result = await page.evaluate(() => {
      const issuer = 'rIssuerAddr';
      const tripleOverlap = 'rTripleOverlap'; // early + top + seller
      const doubleOverlap = 'rDoubleOverlap'; // top + LP
      const soloEarly = 'rSoloEarly'; // early only — must NOT appear
      const soloTop = 'rSoloTop'; // top only — must NOT appear

      const txList = [
        { tx: { TransactionType: 'TrustSet', Account: tripleOverlap, date: 100, LimitAmount: { currency: 'FOO', issuer, value: '1000000' } } },
        { tx: { TransactionType: 'TrustSet', Account: soloEarly, date: 200, LimitAmount: { currency: 'FOO', issuer, value: '1000000' } } },
      ];
      const issuerConnAnalysis = {
        topHolders: [{ addr: tripleOverlap, balance: 500 }, { addr: doubleOverlap, balance: 300 }, { addr: soloTop, balance: 100 }],
        totalIssued: 1000, isSampleOnly: false,
      };
      const issuerMarketActivity = {
        applicable: true, issuedCurrencies: ['FOO'], trades: [],
        holderGrossSold: new Map([[tripleOverlap, 200]]),
      };
      const issuerAmmPool = {
        currency: 'FOO',
        lpHolderLines: [{ account: doubleOverlap, currency: '03464F4F00000000000000000000000000000000', balance: '-50' }],
      };
      return window._debugHolderCohorts(txList, issuer, {}, issuerConnAnalysis, issuerMarketActivity, issuerAmmPool);
    });
    const addrs = result.overlapMatrix.map(r => r.addr);
    assert(addrs.includes('rTripleOverlap'), 'expected the triple-overlap wallet in the matrix');
    assert(addrs.includes('rDoubleOverlap'), 'expected the double-overlap wallet in the matrix');
    assert(!addrs.includes('rSoloEarly'), 'expected a single-cohort wallet (early only) to be excluded from the overlap matrix');
    assert(!addrs.includes('rSoloTop'), 'expected a single-cohort wallet (top only) to be excluded from the overlap matrix');
    const triple = result.overlapMatrix.find(r => r.addr === 'rTripleOverlap');
    assert(triple.cohortCount === 3 && triple.early && triple.top && triple.seller && !triple.lp, `expected the triple-overlap row to show early+top+seller (not lp), got ${JSON.stringify(triple)}`);
    assert(result.overlapMatrix[0].addr === 'rTripleOverlap', 'expected the triple-overlap wallet sorted first (most cohorts)');
  });
});

suite.register('Live: a real token issuer with real Holder Cohorts data renders the Seller table and/or Overlap Matrix without crashing', async () => {
  await withPage(async (page, { pageErrors }) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, REAL_ISSUER_ACCOUNT, { timeout: 90000 });
    await page.waitForTimeout(1500);

    const state = await page.evaluate(() => {
      const el = document.getElementById('inspect-issuer-body');
      return {
        hasSellerTable: !!el?.querySelector('.lp-participant-table--sellers'),
        hasOverlapMatrix: !!el?.querySelector('.overlap-matrix'),
        bodyExists: !!el,
      };
    });
    assert(state.bodyExists, 'expected the issuer panel body to exist');
    // Either is fine (a real, live token may or may not currently have
    // sellers or multi-cohort overlap) — what matters is no crash occurred
    // rendering whichever tables DO apply, checked via pageErrors below.
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
