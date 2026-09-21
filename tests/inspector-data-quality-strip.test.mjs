// Regression guard for the Data Quality / Analysis Coverage strip
// (Inspector-wide roadmap item #6): a persistent, compact summary near the
// top of every inspection — History / Execution reconstruction / Holder
// history / AMM coverage / Analysis version — computed entirely from
// fields the pipeline already tracks (historyCoverage, execution-routing
// stats, AMM LP-line truncation). No new RPC calls, no new analysis.
// Holder history and AMM coverage must read N/A for a non-issuer account
// rather than a fabricated Complete/Partial reading.
import { withPage, connectAndShowDashboard, inspectAddress, makeSuite, assert } from './helpers.mjs';

const suite = makeSuite('Data Quality Strip');

const NON_ISSUER_ACCOUNT = 'rnj7R3QUGzLZc9dg24jSrGabtt1tp1XD7A';
const ISSUER_ACCOUNT = 'rCULtAKrKbQjk1Tpmg5hkw4dpcf9S9KCs';

suite.register('A non-issuer account shows real History/Execution values and correctly gates Holder History + AMM coverage to N/A', async () => {
  await withPage(async (page, { pageErrors }) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, NON_ISSUER_ACCOUNT, { timeout: 90000 });
    await page.waitForTimeout(1500);

    const items = await page.evaluate(() => Object.fromEntries(
      [...document.querySelectorAll('#inspect-dataquality-strip .dq-item')].map(i => [i.querySelector('.dq-item-label')?.textContent, i.querySelector('.dq-item-val')?.textContent])
    ));
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
    assert(items['History'] === 'Complete' || items['History'] === 'Partial' || items['History'] === 'Capped', `expected a real History reading, got: "${items['History']}"`);
    assert(/%$/.test(items['Execution reconstruction'] || '') || items['Execution reconstruction'] === 'N/A', `expected a real percentage or N/A for Execution reconstruction, got: "${items['Execution reconstruction']}"`);
    assert(items['Holder history'] === 'N/A', `expected Holder history N/A for a non-issuer account, got: "${items['Holder history']}"`);
    assert(items['Analysis'], 'expected a real analysis version string to render');
  });
});

suite.register('A known token issuer shows real (non-N/A) Holder History and AMM coverage readings', async () => {
  await withPage(async (page, { pageErrors }) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, ISSUER_ACCOUNT, { timeout: 90000 });
    await page.waitForTimeout(1500);

    const items = await page.evaluate(() => Object.fromEntries(
      [...document.querySelectorAll('#inspect-dataquality-strip .dq-item')].map(i => [i.querySelector('.dq-item-label')?.textContent, i.querySelector('.dq-item-val')?.textContent])
    ));
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
    assert(['Complete', 'Partial'].includes(items['Holder history']), `expected a real Holder History reading for a known issuer, got: "${items['Holder history']}"`);
  });
});

suite.register('Synthetic: computeDataQualitySummary correctly gates isIssuer-only fields and reads real execution-reconstruction percentages', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugComputeDataQualitySummary, { timeout: 8000 });

    const nonIssuer = await page.evaluate(() => window._debugComputeDataQualitySummary(
      { newestToOldestComplete: true }, { stats: { total: 100, unknown: 10 } }, null, false
    ));
    assert(nonIssuer.history.label === 'Complete', `expected Complete history, got ${nonIssuer.history.label}`);
    assert(nonIssuer.execution.label === '90%', `expected 90% execution reconstruction (100-10)/100, got ${nonIssuer.execution.label}`);
    assert(nonIssuer.holderHistory.label === 'N/A', 'expected N/A holder history for a non-issuer');
    assert(nonIssuer.amm.label === 'N/A', 'expected N/A AMM coverage with no pool');

    const issuerWithTruncatedLp = await page.evaluate(() => window._debugComputeDataQualitySummary(
      { hitTxCap: true }, { stats: { total: 0, unknown: 0 } }, { lpLinesTruncated: true }, true
    ));
    assert(issuerWithTruncatedLp.history.label === 'Capped', `expected Capped history when hitTxCap is true and nothing else confirms completeness, got ${issuerWithTruncatedLp.history.label}`);
    assert(issuerWithTruncatedLp.execution.label === 'N/A', 'expected N/A execution reconstruction with zero total executions');
    assert(issuerWithTruncatedLp.holderHistory.label === 'Partial', 'expected Partial holder history for an issuer without oldestToNewestFetched');
    assert(issuerWithTruncatedLp.amm.label === 'Partial', 'expected Partial AMM coverage when LP lines are truncated');
  });
});

suite.register('Synthetic: _renderDataQualityStrip renders all five fields and does not throw for a null summary', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugRenderDataQualityStrip, { timeout: 8000 });
    const el = await page.evaluate(() => {
      document.body.insertAdjacentHTML('beforeend', '<div id="inspect-dataquality-strip"></div>');
      window._debugRenderDataQualityStrip({
        history: { label: 'Complete', tone: 'ok' }, execution: { label: '75%', tone: 'ok' },
        holderHistory: { label: 'Partial', tone: 'warn' }, amm: { label: 'High', tone: 'ok' }, version: 'vTest',
      });
      return document.getElementById('inspect-dataquality-strip').innerHTML;
    });
    assert(/Complete/.test(el) && /75%/.test(el) && /Partial/.test(el) && /High/.test(el) && /vTest/.test(el), `expected all five fields rendered, got: ${el.slice(0, 500)}`);

    const noThrow = await page.evaluate(() => {
      try { window._debugRenderDataQualityStrip(null); return true; } catch { return false; }
    });
    assert(noThrow, 'expected _renderDataQualityStrip to handle a null summary without throwing');
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
