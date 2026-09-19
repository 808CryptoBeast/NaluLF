// Regression guard for Volume Concentration's plain-language translation:
// a "Trading activity is [extremely/moderately/broadly] concentrated..."
// lead sentence (DOJ/FTC HHI bands, already cited in the whitepaper) before
// the real Top-1/Top-5/Top-10 share and HHI/Gini numbers, which are now
// explicitly labeled as analyst metrics rather than presented bare.
import { withPage, connectAndShowDashboard, inspectAddress, makeSuite, assert } from './helpers.mjs';

const suite = makeSuite('Volume Concentration Plain Language');

suite.register('A real concentrated market shows a real plain-language lead sentence, with Top-1/5/10 share ordered before HHI/Gini', async () => {
  await withPage(async (page, { pageErrors }) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, 'rnj7R3QUGzLZc9dg24jSrGabtt1tp1XD7A', { timeout: 90000 });
    await page.waitForTimeout(1500);

    const result = await page.evaluate(() => {
      const card = document.getElementById('inspect-volconc-body')?.querySelector('.volconc-card');
      if (!card) return { found: false };
      const rows = [...card.querySelectorAll('.wash-stat-row')].map(r => r.textContent.trim());
      return {
        found: true,
        plainText: card.querySelector('.volconc-plain')?.textContent,
        rowOrder: rows,
        top10RowIdx: rows.findIndex(r => r.includes('Top-10')),
        hhiRowIdx: rows.findIndex(r => r.includes('HHI')),
      };
    });
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
    assert(result.found, 'expected at least one Volume Concentration card for this known-active-trader account');
    assert(/concentrated|distributed/.test(result.plainText || ''), `expected a real plain-language concentration sentence, got: "${result.plainText}"`);
    assert(result.top10RowIdx !== -1 && result.hhiRowIdx !== -1, `expected both Top-10 share and HHI rows to render, got: ${JSON.stringify(result.rowOrder)}`);
    assert(result.top10RowIdx < result.hhiRowIdx, `expected Top-1/5/10 share to appear BEFORE HHI/Gini (plain language before analyst metrics), got order: ${JSON.stringify(result.rowOrder)}`);
    assert(/analyst metric/.test(result.rowOrder[result.hhiRowIdx]), 'expected HHI to be explicitly labeled as an analyst metric');
  });
});

suite.register('Synthetic: _volConcPlainLabel picks the correct DOJ/FTC-style band for extreme, moderate, and low concentration', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugVolConcPlainLabel, { timeout: 8000 });
    const extreme = await page.evaluate(() => window._debugVolConcPlainLabel(3000));
    const moderate = await page.evaluate(() => window._debugVolConcPlainLabel(2000));
    const low = await page.evaluate(() => window._debugVolConcPlainLabel(500));
    assert(/extremely concentrated/.test(extreme), `expected "extremely concentrated" at HHI 3000, got: "${extreme}"`);
    assert(/moderately concentrated/.test(moderate), `expected "moderately concentrated" at HHI 2000, got: "${moderate}"`);
    assert(/broadly distributed/.test(low), `expected "broadly distributed" at HHI 500, got: "${low}"`);
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
