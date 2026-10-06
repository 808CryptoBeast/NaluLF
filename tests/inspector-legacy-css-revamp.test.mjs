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

    // Tree (the default view) keeps its branches collapsed until clicked,
    // so .ranked-cp-row doesn't exist inside Relationship Intelligence yet
    // — Flow renders every relationship unconditionally. Scoped to the
    // panel itself: .ranked-cp-row is also still used, unscoped, by the
    // Full Report's own counterparty list further down the page, and an
    // unscoped .first() would silently grab that row instead (landing
    // under sticky headers that intercept the hover).
    await page.evaluate(() => window.setRelIntelView('flow'));
    await page.waitForTimeout(300);
    const row = page.locator('#inspect-relationship-landscape .ranked-cp-row').first();
    await row.hover();
    // 600ms, not 300: style recalc before a hover transition even starts
    // can itself take a couple hundred ms on a page this size — confirmed
    // flaky at 300ms more than once, reliable at 600ms (see the identical
    // fix/rationale in inspector-overview-redesign.test.mjs).
    await page.waitForTimeout(600);
    const rowHoverBg = await row.evaluate(el => getComputedStyle(el).backgroundImage);
    assert(rowHoverBg.includes('gradient'), `expected .ranked-cp-row:hover to show a gradient, got "${rowHoverBg}"`);

    await page.evaluate(() => document.getElementById('section-events')?.classList.remove('collapsed'));
    // The real bug: .section-body animates max-height/opacity over 280ms on
    // expand (and carries pointer-events:none for part of that). Hovering
    // immediately raced that transition — Playwright computed the target's
    // bounding box mid-animation, so the real mouse landed on a position
    // that had since shifted, and :hover never actually matched (confirmed
    // via el.matches(':hover') === false, not merely a slow style recalc).
    await page.waitForTimeout(350);
    const evItem = page.locator('.events-timeline-item').first();
    await evItem.hover();
    await page.waitForTimeout(600);
    await page.waitForTimeout(600);
    const evHoverBg = await evItem.evaluate(el => getComputedStyle(el).backgroundImage);
    assert(evHoverBg.includes('gradient'), `expected .events-timeline-item:hover to show a gradient, got "${evHoverBg}"`);

    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
