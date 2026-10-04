// Regression guard for a real, confirmed mobile bug: the Dashboard's
// metric-card strip (.dashboard-sticky-strip, made sticky by
// mountMetricCards() in dashboard.js) never released from the top of the
// viewport on mobile.
//
// Root cause: its `position: sticky` containing block is #tab-stream — the
// ENTIRE dashboard tab panel, not a short wrapper scoped to the metrics
// region — so per the CSS spec it stays pinned for the full scroll of the
// tab, all the way to the last pixel of page content. On desktop the strip
// is short (one row across 7 columns) so permanent pinning reads as an
// intentional "live ticker." On mobile the same 6 cards wrap to 2 or even 1
// column, growing the strip to 430-730px+ tall — confirmed live at up to
// ~80% of a phone viewport — and it stayed that tall and pinned for the
// ENTIRE remaining scroll, so every section after it (Why It Matters, Who
// To Watch, Spam Defense, everything) spent almost the whole scroll
// gesture rendering underneath this oversized fixed block. That read as
// "content disappears behind another layer" / "the page can't scroll
// through it" even though the DOM and scrollHeight were entirely correct.
//
// Fixed by reverting the strip to normal static flow under the existing
// mobile breakpoint (max-width: 768px) — confirmed desktop (>768px) keeps
// the original sticky behavior unchanged.
import { withPage, assert } from './helpers.mjs';

const suite = { register: [], run: async () => {
  let pass = 0, fail = 0;
  console.log('\n▶ Dashboard Mobile — Sticky Metric Strip Scroll Release');
  for (const { name, fn } of suite.register) {
    try { await fn(); console.log(`  PASS  ${name}`); pass++; }
    catch (err) { console.log(`  FAIL  ${name}`); console.log(`        ${err?.stack || err}`); fail++; }
  }
  return { pass, fail, total: suite.register.length };
}};
const test = (name, fn) => suite.register.push({ name, fn });

// This fix is a pure CSS width media query (max-width: 768px) — not a
// touch/pointer-based rule — so a plain viewport resize (no isMobile/
// hasTouch emulation, which can't be changed after a page/context is
// already created anyway) is sufficient and accurate for verifying it.
async function loadDashboardAt(page, width, height) {
  await page.setViewportSize({ width, height });
  await page.waitForFunction(() => window.connectXRPL, { timeout: 8000 });
  await page.evaluate(() => window.connectXRPL());
  await page.waitForFunction(() => document.getElementById('connDot')?.classList.contains('live'), { timeout: 20000 });
  await page.evaluate(() => window.showDashboard());
  await page.waitForTimeout(1800);
  await page.evaluate(() => { document.documentElement.style.scrollBehavior = 'auto'; });
}

for (const width of [320, 390, 545]) {
  test(`At ${width}px (mobile), the sticky metric strip releases and scrolling reaches the true bottom of the page`, async () => {
    await withPage(async (page, { pageErrors }) => {
      await loadDashboardAt(page, width, 844);

      // The dashboard keeps mounting async widgets (network health, spam
      // defense, etc.) well after first paint, so scrollHeight can still be
      // growing at the moment of a single scrollTo — re-converge on the
      // bottom a few times rather than trusting one snapshot, so this
      // assertion tests real scroll capability, not a race against content
      // still arriving.
      let prevHeight = -1;
      for (let i = 0; i < 5; i++) {
        await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight));
        await page.waitForTimeout(400);
        const h = await page.evaluate(() => document.body.scrollHeight);
        if (h === prevHeight) break;
        prevHeight = h;
      }
      const result = await page.evaluate(() => {
        const strip = document.querySelector('.dashboard-sticky-strip');
        return {
          scrollY: window.scrollY,
          maxPossible: document.body.scrollHeight - window.innerHeight,
          stripPosition: strip ? getComputedStyle(strip).position : null,
          stripTop: strip ? strip.getBoundingClientRect().top : null,
        };
      });

      assert(result.stripPosition === 'static', `expected the metric strip to NOT be sticky at ${width}px, got position:${result.stripPosition}`);
      assert(Math.abs(result.scrollY - result.maxPossible) < 2, `expected scrolling to reach the true bottom at ${width}px, got scrollY=${result.scrollY} vs maxPossible=${result.maxPossible}`);
      assert(result.stripTop < -100, `expected the metric strip to have scrolled well out of view at ${width}px (it previously stayed pinned at top:0 forever), got stripTop=${result.stripTop}`);
      assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
    });
  });
}

test('At 1300px (desktop), the metric strip KEEPS its original sticky "live ticker" behavior — the mobile fix must not regress desktop', async () => {
  await withPage(async (page, { pageErrors }) => {
    await loadDashboardAt(page, 1300, 900);

    await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight));
    await page.waitForTimeout(400);
    const result = await page.evaluate(() => {
      const strip = document.querySelector('.dashboard-sticky-strip');
      return {
        stripPosition: strip ? getComputedStyle(strip).position : null,
        stripTop: strip ? strip.getBoundingClientRect().top : null,
      };
    });

    assert(result.stripPosition === 'sticky', `expected the metric strip to remain sticky on desktop, got position:${result.stripPosition}`);
    assert(result.stripTop === 0, `expected the sticky strip to be pinned at top:0 on desktop after scrolling, got stripTop=${result.stripTop}`);
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
