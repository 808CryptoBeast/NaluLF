// Regression guard for Holder Cohort Intelligence: Top Holders (reused from
// analyseIssuerConnections, not recomputed), Early Holders (new, from
// TrustSet history), and LP Holders (new, from a single targeted
// account_lines call on the token's AMM pool account) — plus how much of
// the token's aggregate trading volume (from Issuer Market Activity) each
// cohort actually generated. Cohorts overlap by design and must never be
// summed together as if they partitioned the market.
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

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
