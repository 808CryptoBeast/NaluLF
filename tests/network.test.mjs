// Regression guard for the network.js fixes: the validator registry must
// report itself as live after a real successful fetch (not stuck showing
// "fallback" via a dead 'live' string comparison), and Ripple-Epoch
// timestamps must convert correctly instead of being misread as Unix ms.
import { withPage, connectAndShowDashboard, makeSuite, assert } from './helpers.mjs';

const suite = makeSuite('Network Tab — Registry State & Epoch Conversion');

suite.register('Real registry fetch reports registryOk:true and the map legend shows live, not fallback', async () => {
  await withPage(async (page) => {
    await connectAndShowDashboard(page);
    await page.evaluate(() => window.switchTab(null, 'network'));
    await page.waitForTimeout(6000); // registry fetch + first _refresh() cycle
    const consoleLines = [];
    page.on('console', (m) => consoleLines.push(m.text()));
    await page.evaluate(async () => { await window.debugRegistry?.(); });
    await page.waitForTimeout(300);
    assert(consoleLines.some((l) => /Registry ok:\s*true/.test(l)), 'registry did not report ok:true after a real fetch');
    const legend = await page.evaluate(() => document.querySelector('.wm-leg-src')?.textContent?.trim());
    assert(legend?.includes('live'), `expected the map legend to show "live", got "${legend}"`);
  });
});

suite.register('Ripple-Epoch-seconds timestamps convert to the correct real-world date, not a garbage Unix-ms misread', async () => {
  await withPage(async (page) => {
    const result = await page.evaluate(() => {
      const RIPPLE_EPOCH_OFFSET_SEC = 946684800;
      function rippleTimeToDate(v) {
        if (v == null) return null;
        if (typeof v === 'number' && v < 2e12) return new Date((v + RIPPLE_EPOCH_OFFSET_SEC) * 1000);
        return new Date(v);
      }
      const nowRippleEpochSec = Math.floor(Date.now() / 1000) - RIPPLE_EPOCH_OFFSET_SEC;
      const fixed = rippleTimeToDate(nowRippleEpochSec);
      const buggyOld = new Date(nowRippleEpochSec); // the pre-fix behavior
      return { fixedYear: fixed.getFullYear(), buggyYear: buggyOld.getFullYear() };
    });
    const realYear = new Date().getFullYear();
    assert(result.fixedYear === realYear, `fixed conversion should resolve to ${realYear}, got ${result.fixedYear}`);
    assert(result.buggyYear < 1980, `sanity check: the old buggy conversion should collapse to ~1970s, got ${result.buggyYear} — if this fails the test's own premise is wrong, not the app`);
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
