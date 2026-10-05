// Regression coverage for the legacy-section CSS revamp: 7 Inspector areas
// that still had their original, pre-redesign flat styling (Score
// Breakdown, Risk Trend card + range picker, Network Map toggle buttons,
// Top Counterparties rows, XRPL Usage Breakdown hub/branch/donut, and
// Important Events) brought up to the glass-panel language already shipped
// on .audit-row/.acct-cell — reusing the SAME color tokens already live in
// the app (#00d4ff/#00fff0 cyan, etc.), not a new, unshipped palette.
// Account Overview metric cards (.acct-cell) already had this treatment
// before this pass and are intentionally not covered here.
import { withPage, connectAndShowDashboard, inspectAddress, assert } from './helpers.mjs';

const suite = { register: [], run: async () => {
  let pass = 0, fail = 0;
  console.log('\n▶ Legacy Section CSS Revamp');
  for (const { name, fn } of suite.register) {
    try { await fn(); console.log(`  PASS  ${name}`); pass++; }
    catch (err) { console.log(`  FAIL  ${name}`); console.log(`        ${err?.stack || err}`); fail++; }
  }
  return { pass, fail, total: suite.register.length };
}};
const test = (name, fn) => suite.register.push({ name, fn });

const ADDR = 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh';

test('Score Breakdown, Risk Trend card, Network Map toggle, and Ledger Map hub/branch/donut all render with a gradient (glass-panel) background, not the old flat fill', async () => {
  await withPage(async (page, { pageErrors }) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, ADDR, { timeout: 60000 });

    const check = await page.evaluate(() => {
      const bgImg = (sel) => {
        const el = document.querySelector(sel);
        return el ? getComputedStyle(el).backgroundImage : 'MISSING';
      };
      return {
        riskBreakdownCard: bgImg('.risk-breakdown-card'),
        riskBreakdownChipCount: document.querySelectorAll('.risk-breakdown-chip').length,
        subpanelGroup: bgImg('.inspector-subpanel-group'),
        netmapBtnActive: bgImg('.netmap-size-btn.active'),
        ledgermapHub: bgImg('.ledgermap-hub'),
        ledgermapBranch: bgImg('.ledgermap-branch'),
        ledgermapDonut: bgImg('.ledgermap-donut'),
      };
    });

    for (const [key, val] of Object.entries(check)) {
      if (key === 'riskBreakdownChipCount') continue;
      assert(val !== 'MISSING' && val !== 'none', `expected ${key} to have a gradient background, got "${val}"`);
      assert(val.includes('gradient'), `expected ${key} to use a gradient (glass-panel), got "${val}"`);
    }
    assert(check.riskBreakdownChipCount > 0, 'expected at least one Score Breakdown legend chip to render');
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

test('Top Counterparties rows and Important Events items get a gradient hover treatment (resting state stays minimal by design, matching the original row-divider look)', async () => {
  await withPage(async (page, { pageErrors }) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, ADDR, { timeout: 60000 });

    const row = page.locator('.ranked-cp-row').first();
    await row.hover();
    await page.waitForTimeout(300);
    const rowHoverBg = await row.evaluate(el => getComputedStyle(el).backgroundImage);
    assert(rowHoverBg.includes('gradient'), `expected .ranked-cp-row:hover to show a gradient, got "${rowHoverBg}"`);

    await page.evaluate(() => document.getElementById('section-events')?.classList.remove('collapsed'));
    const evItem = page.locator('.events-timeline-item').first();
    await evItem.hover();
    await page.waitForTimeout(300);
    const evHoverBg = await evItem.evaluate(el => getComputedStyle(el).backgroundImage);
    assert(evHoverBg.includes('gradient'), `expected .events-timeline-item:hover to show a gradient, got "${evHoverBg}"`);

    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
