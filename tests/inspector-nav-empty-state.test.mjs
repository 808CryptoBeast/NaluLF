// Regression guard for a real mobile bug: the fixed bottom jump-nav bar
// (#inspector-nav) used to render unconditionally whenever the Inspector
// tab was active — including on the pre-inspection landing page, where it
// has nothing to navigate to (no sections exist yet). Full-width, fixed,
// pointer-events:auto, sitting across the bottom of the screen with no
// inspection behind it — on mobile this reads as "scrolling freezes partway
// down the page" (a dead, non-functional bar quietly consuming the bottom
// of the viewport and its touch input). Now the bar only ever renders once
// a real inspection result is showing, and hides again on inspectorGoBack().
import { withPage, connectAndShowDashboard, inspectAddress, makeSuite, assert } from './helpers.mjs';

const suite = makeSuite('Inspector Nav — Empty-State Visibility');

suite.register('The bottom nav is hidden on the pre-inspection landing page, visible after a real inspection, and hidden again after going back', async () => {
  await withPage(async (page, { pageErrors }) => {
    await connectAndShowDashboard(page);
    await page.evaluate(() => window.switchTab(null, 'inspector'));
    await page.waitForTimeout(500);

    const beforeInspect = await page.evaluate(() => getComputedStyle(document.getElementById('inspector-nav')).display);
    assert(beforeInspect === 'none', `expected the bottom nav hidden before any inspection has run, got display:"${beforeInspect}"`);

    await inspectAddress(page, 'rnj7R3QUGzLZc9dg24jSrGabtt1tp1XD7A', { timeout: 90000 });
    await page.waitForTimeout(1000);
    const afterInspect = await page.evaluate(() => getComputedStyle(document.getElementById('inspector-nav')).display);
    assert(afterInspect === 'block', `expected the bottom nav visible after a real inspection, got display:"${afterInspect}"`);

    // The nav must still actually work once shown — jumping to a section
    // and marking itself active — not just become visible and inert.
    const jumpResult = await page.evaluate(() => {
      const btn = document.querySelector('#inspector-nav .in-btn[data-jump="security"]');
      btn.click();
      return { navStillVisible: getComputedStyle(document.getElementById('inspector-nav')).display === 'block', activeClass: btn.classList.contains('in-btn--active') };
    });
    assert(jumpResult.navStillVisible, 'expected the nav to remain visible after clicking a jump button');
    assert(jumpResult.activeClass, 'expected clicking a jump button to still correctly mark it active');

    await page.evaluate(() => window.inspectorGoBack());
    await page.waitForTimeout(500);
    const afterGoBack = await page.evaluate(() => getComputedStyle(document.getElementById('inspector-nav')).display);
    assert(afterGoBack === 'none', `expected the bottom nav to hide again after returning to the landing page, got display:"${afterGoBack}"`);

    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
