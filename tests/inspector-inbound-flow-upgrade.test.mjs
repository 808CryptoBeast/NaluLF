// Regression guard for Inbound Flow's upgrade to match Drain Risk and
// Market Integrity: a plain-language "In plain terms" summary (source
// concentration, recurring vs. one-time funders), real first/last funding
// dates, and clickable source cards wired into the same generic Trading
// Relationship drawer the Network Map and Wash Trading already use. All
// reuse fields analyseInboundFlow already computes — no new analysis, no
// new RPC calls.
import { withPage, connectAndShowDashboard, inspectAddress, makeSuite, assert } from './helpers.mjs';

const suite = makeSuite('Inbound Flow Upgrade');

const ACTIVE_ACCOUNT = 'rnj7R3QUGzLZc9dg24jSrGabtt1tp1XD7A';

suite.register('A real active account shows a real plain summary, real first/last funding dates (not a mis-computed epoch), and a working Examine button that opens the relationship drawer', async () => {
  await withPage(async (page, { pageErrors }) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, ACTIVE_ACCOUNT, { timeout: 90000 });
    await page.waitForTimeout(1500);

    const result = await page.evaluate(() => {
      const el = document.getElementById('inspect-inbound-body');
      const plainBox = [...el.querySelectorAll('div')].find(d => d.textContent.startsWith('In plain terms:'));
      const stats = Object.fromEntries([...el.querySelectorAll('.flow-stat')].map(s => [s.querySelector('span')?.textContent, s.querySelector('b')?.textContent]));
      const firstRow = el.querySelector('.flow-dest-row');
      firstRow?.querySelector('.mi-rel-examine')?.click();
      return {
        plainText: plainBox?.textContent,
        dateRange: stats['First / last funding'],
        recurringStat: stats['Recurring / one-time funders'],
        drawerOpened: document.getElementById('relationshipDrawerOverlay')?.style.display === 'flex',
      };
    });
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
    assert(result.plainText?.includes('In plain terms:'), 'expected a plain-language summary box');
    assert(/^\d{1,2}\/\d{1,2}\/20\d{2}/.test(result.dateRange || ''), `expected a real, correctly-computed date (this century, not a mis-added epoch offset decades in the future), got: "${result.dateRange}"`);
    assert(/^\d+ \/ \d+$/.test(result.recurringStat || ''), `expected a real recurring/one-time funder count, got: "${result.recurringStat}"`);
    assert(result.drawerOpened, 'expected clicking a source\'s Examine button to open the relationship drawer');
  });
});

suite.register('Synthetic: buildInboundFlowPlainSummary computes real concentration/recurring-funder text and returns null with no sources', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugInboundFlowPlainSummary, { timeout: 8000 });
    const flow = {
      topSources: [{ addr: 'rTopSource000000000000000000000000', totalXrp: 820, entity: null }],
      totalIn: 1000, uniqueSources: 3, topSourceSharePct: 82,
      recurringCount: 2, oneTimeCount: 1, structuredFlag: false,
    };
    const result = await page.evaluate(f => window._debugInboundFlowPlainSummary(f), flow);
    assert(result.tone === 'ok', `expected ok tone with no structured-funding flag, got ${result.tone}`);
    assert(/82%/.test(result.text), `expected the real concentration percentage, got: "${result.text}"`);
    assert(/2 funding source\(s\) sent more than once/.test(result.text), `expected the real recurring-funder count, got: "${result.text}"`);
    assert(/1 sent exactly once/.test(result.text), `expected the real one-time-funder count, got: "${result.text}"`);

    const empty = await page.evaluate(() => window._debugInboundFlowPlainSummary({ topSources: [] }));
    assert(empty === null, 'expected null (not a fabricated summary) when there are no funding sources at all');
  });
});

suite.register('Synthetic: buildInboundFlowPlainSummary escalates to warn tone when a structured-funding pattern is flagged', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugInboundFlowPlainSummary, { timeout: 8000 });
    const flow = {
      topSources: [{ addr: 'rTop00000000000000000000000000000000', totalXrp: 100, entity: null }],
      totalIn: 500, uniqueSources: 5, topSourceSharePct: 20,
      recurringCount: 0, oneTimeCount: 5, structuredFlag: true,
    };
    const result = await page.evaluate(f => window._debugInboundFlowPlainSummary(f), flow);
    assert(result.tone === 'warn', `expected warn tone when structuredFlag is true, got ${result.tone}`);
    assert(/structured-funding note below/.test(result.text), `expected an explicit reference to the structured-funding signal, got: "${result.text}"`);
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
