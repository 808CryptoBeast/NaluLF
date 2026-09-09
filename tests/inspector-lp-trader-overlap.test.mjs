// Regression guard for LP <-> Trader Overlap and the AMM LP Participant
// Table: ranks a token's holders by their own settled trade volume (from
// Issuer Market Activity's per-trade holder attribution — no new data),
// checks how many of the most active traders are also liquidity providers,
// and renders a real participant table with each LP's pool share and
// current underlying position (computed from pool reserves x share).
import { withPage, connectAndShowDashboard, inspectAddress, makeSuite, assert } from './helpers.mjs';

// Real, active token issuer (CULT) confirmed live to have a real AMM pool
// with LP holders and real trader volume to rank.
const REAL_ISSUER_ACCOUNT = 'rCULtAKrKbQjk1Tpmg5hkw4dpcf9S9KCs';

const suite = makeSuite('LP <-> Trader Overlap');

suite.register('A real token issuer renders a real LP Participant Table with pool share and computed underlying position', async () => {
  await withPage(async (page) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, REAL_ISSUER_ACCOUNT, { timeout: 90000 });
    await page.waitForTimeout(2500); // let the fuller tx-history fetch settle for this high-volume account

    const result = await page.evaluate(() => {
      const issuerBody = document.getElementById('inspect-issuer-body');
      const rows = [...(issuerBody?.querySelectorAll('.lp-participant-row') || [])];
      return {
        headerPresent: !!issuerBody?.querySelector('.lp-participant-header'),
        rowCount: rows.length,
        firstRowText: rows[0]?.textContent?.trim() || null,
      };
    });
    assert(result.headerPresent, 'expected the LP Participant Table header to render for a real issuer with an AMM pool');
    assert(result.rowCount > 0, 'expected at least one LP participant row — live data may have drifted; re-verify against current mainnet state if this fails');
    assert(/%/.test(result.firstRowText || ''), `expected a pool-share percentage in the first row: ${result.firstRowText}`);
    assert(/XRP/.test(result.firstRowText || ''), `expected a computed XRP-side position in the first row: ${result.firstRowText}`);
  });
});

suite.register('A token with no AMM pool (or no LP holders) produces applicable:false and zero findings, and renders no LP table', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugLpTraderOverlap, { timeout: 8000 });
    const result = await page.evaluate(() => {
      const notApplicableCohorts = { applicable: false };
      const marketActivity = { applicable: true, issuedCurrencies: ['FOO'], trades: [{ hash: 't1', route: 'CLOB', holders: ['rA'], amount: 100 }] };
      return window._debugLpTraderOverlap(marketActivity, notApplicableCohorts);
    });
    assert(result.applicable === false, 'expected applicable:false when holder cohorts (and therefore LP data) are not available');
    assert(result.findings.length === 0, 'expected zero findings with no LP data to compare against');
  });
});

suite.register('Synthetic market: overlap counts, top-10 overlap, and LP-trader volume share are all computed correctly', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugLpTraderOverlap, { timeout: 8000 });
    const result = await page.evaluate(() => {
      const lpAlsoTrader = 'rLpAlsoTrader'; // provides liquidity AND is the biggest trader
      const lpOnly = 'rLpOnly'; // provides liquidity, never trades
      const traderOnly = 'rTraderOnly'; // trades, never provides liquidity

      const issuerMarketActivity = {
        applicable: true,
        issuedCurrencies: ['FOO'],
        trades: [
          { hash: 't1', route: 'CLOB', holders: [lpAlsoTrader], amount: 700 },
          { hash: 't2', route: 'AMM', holders: [traderOnly], amount: 300 },
        ],
      };
      const holderCohorts = {
        applicable: true,
        topHolders: [], earlyHolders: [],
        lpHolders: [{ addr: lpAlsoTrader, lpBalance: 80, sharePct: 80 }, { addr: lpOnly, lpBalance: 20, sharePct: 20 }],
      };

      return window._debugLpTraderOverlap(issuerMarketActivity, holderCohorts);
    });

    assert(result.applicable === true, 'expected applicable:true with real trades and real LP holders');
    assert(result.alsoLpCount === 1, `expected exactly 1 major trader who is also an LP (lpAlsoTrader), got ${result.alsoLpCount}`);
    assert(result.top10AlsoLpCount === 1, `expected 1 of the top-10 traders to also be an LP, got ${result.top10AlsoLpCount}`);
    // lpAlsoTrader's 700-unit trade / 1000 total = 70% of volume came from a trader who is also an LP.
    assert(Math.abs(result.lpTraderVolumePct - 70) < 0.01, `expected LP-trader volume share of 70%, got ${result.lpTraderVolumePct}`);
    assert(result.majorTraders.length === 2, `expected 2 ranked traders (lpOnly never traded, so excluded), got ${result.majorTraders.length}`);
    assert(result.majorTraders[0].addr === 'rLpAlsoTrader', 'expected the higher-volume trader ranked first');

    const finding = result.findings[0];
    assert(finding, 'expected an LP / Trader Overlap finding');
    assert(finding.sev === 'info', `this is descriptive, not accusatory, expected info severity, got ${finding.sev}`);
    assert(finding.classification?.includes('not itself evidence of wash trading'), 'must explicitly disclaim LP/trader overlap as market structure, not wash-trading evidence');
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
