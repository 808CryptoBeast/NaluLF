// Regression coverage for Phase 1 of the Inspector 6.0 redesign
// (Investigation Shell + Account Command Bar — see the approved design
// canvas). Below the 1280px breakpoint, nothing changes: single-column
// scroll with the bottom jump-nav exactly as before this phase. At or
// above it, three fixed-position overlays (the same technique the bottom
// jump-nav already used) become a left Investigation Nav rail, a fixed
// top Account Command Bar, and a new right Intelligence Panel.
//
// Also covers two real bugs found while building and verifying this phase:
//  1. _navOnScroll's scrollspy loop didn't skip display:none sections
//     (e.g. #section-checks when there are no open checks) — a hidden
//     element's all-zero getBoundingClientRect() always satisfied its
//     "top <= 150" check and, being last in INSPECTOR_SECTION_SCROLL_ORDER,
//     permanently won over whichever section was actually in view. This
//     bug pre-dates this phase (confirmed by reproducing it on unmodified
//     main) but was only caught while verifying the new shell's nav rail.
//  2. The new fixed-position Command Bar covers the top 64px of the
//     viewport without taking up document flow space, so a nav-jump's
//     scrollIntoView rested a section invisibly underneath it until
//     .inspector-section got scroll-margin-top in the desktop breakpoint.
import { withPage, connectAndShowDashboard, inspectAddress, assert } from './helpers.mjs';

const suite = { register: [], run: async () => {
  let pass = 0, fail = 0;
  console.log('\n▶ Investigation Shell (Phase 1)');
  for (const { name, fn } of suite.register) {
    try { await fn(); console.log(`  PASS  ${name}`); pass++; }
    catch (err) { console.log(`  FAIL  ${name}`); console.log(`        ${err?.stack || err}`); fail++; }
  }
  return { pass, fail, total: suite.register.length };
}};
const test = (name, fn) => suite.register.push({ name, fn });

const ADDR = 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh';

test('Desktop (>=1280px): nav becomes a left rail, Command Bar a fixed top bar, and a new Intelligence Panel appears as a right rail', async () => {
  await withPage(async (page, { pageErrors }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await connectAndShowDashboard(page);
    await inspectAddress(page, ADDR, { timeout: 60000 });

    const shell = await page.evaluate(() => {
      const nav = document.getElementById('inspector-nav');
      const intel = document.getElementById('inspector-intel-panel');
      const bar = document.querySelector('.inspect-risk-banner');
      const navRect = nav.getBoundingClientRect();
      const intelRect = intel.getBoundingClientRect();
      return {
        navLeft: navRect.left, navWidth: Math.round(navRect.width),
        intelRightGap: Math.round(window.innerWidth - intelRect.right), intelWidth: Math.round(intelRect.width),
        barPosition: getComputedStyle(bar).position, barTop: Math.round(bar.getBoundingClientRect().top),
        stateGroupDisplay: getComputedStyle(document.querySelector('.irb-state-group')).display,
        balance: document.getElementById('irb-balance')?.textContent,
        age: document.getElementById('irb-age')?.textContent,
        gridAge: document.querySelector('#inspect-acct-grid .acct-cell-value')?.closest('.acct-cell')?.querySelector('.acct-cell-value')?.textContent,
        coverageHistory: document.getElementById('intel-coverage-history')?.textContent,
        coverageVersion: document.getElementById('intel-coverage-version')?.textContent,
      };
    });

    assert(shell.navLeft === 0 && shell.navWidth === 220, `expected nav as a 220px left rail, got left=${shell.navLeft} width=${shell.navWidth}`);
    assert(shell.intelRightGap === 0 && shell.intelWidth === 300, `expected Intelligence Panel as a 300px right rail, got rightGap=${shell.intelRightGap} width=${shell.intelWidth}`);
    assert(shell.barPosition === 'fixed' && shell.barTop === 0, `expected Command Bar fixed to the top, got position=${shell.barPosition} top=${shell.barTop}`);
    assert(shell.stateGroupDisplay === 'flex', 'expected the compact balance/age state group to be visible in the Command Bar at desktop width');
    assert(shell.balance && shell.balance !== '—' && shell.balance.includes('XRP'), `expected a real balance in the Command Bar, got "${shell.balance}"`);
    assert(shell.age && shell.age !== '—', `expected a real age in the Command Bar, got "${shell.age}"`);
    assert(shell.coverageHistory && shell.coverageHistory !== '—', `expected the Intelligence Panel to show real coverage, got "${shell.coverageHistory}"`);
    assert(shell.coverageVersion && shell.coverageVersion !== '—', `expected the Intelligence Panel to show the analysis version, got "${shell.coverageVersion}"`);
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

test('Mobile (390px): Intelligence Panel stays hidden, nav remains the existing bottom bar, Command Bar is not fixed — unchanged from before this phase', async () => {
  await withPage(async (page, { pageErrors }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await connectAndShowDashboard(page);
    await inspectAddress(page, ADDR, { timeout: 60000 });

    const mobile = await page.evaluate(() => {
      const nav = document.getElementById('inspector-nav');
      const bar = document.querySelector('.inspect-risk-banner');
      return {
        intelDisplay: getComputedStyle(document.getElementById('inspector-intel-panel')).display,
        navPosition: getComputedStyle(nav).position,
        navBottom: Math.round(nav.getBoundingClientRect().bottom),
        barPosition: getComputedStyle(bar).position,
        stateGroupDisplay: getComputedStyle(document.querySelector('.irb-state-group')).display,
      };
    });

    assert(mobile.intelDisplay === 'none', `expected Intelligence Panel hidden on mobile despite the shared inline display:block toggle, got "${mobile.intelDisplay}"`);
    assert(mobile.navPosition === 'fixed' && mobile.navBottom === 844, `expected the nav to remain a fixed bottom bar, got position=${mobile.navPosition} bottom=${mobile.navBottom}`);
    assert(mobile.barPosition === 'static', `expected the Command Bar to stay in normal document flow on mobile, got "${mobile.barPosition}"`);
    assert(mobile.stateGroupDisplay === 'none', 'expected the compact balance/age state group to stay hidden on mobile (the full Account Overview grid already shows these)');
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

test('Desktop content column clears both fixed rails at the breakpoint boundary (1280px) — a real bug: margin:0 auto centered a max-width box on the full viewport, ignoring the rails, so the right rail overlapped content and intercepted its clicks', async () => {
  await withPage(async (page, { pageErrors }) => {
    await page.setViewportSize({ width: 1280, height: 720 });
    await connectAndShowDashboard(page);
    await inspectAddress(page, ADDR, { timeout: 60000 });

    const geom = await page.evaluate(() => {
      const wrap = document.querySelector('.inspector-wrap').getBoundingClientRect();
      const nav = document.getElementById('inspector-nav').getBoundingClientRect();
      const intel = document.getElementById('inspector-intel-panel').getBoundingClientRect();
      return { wrapLeft: wrap.left, wrapRight: wrap.right, navRight: nav.right, intelLeft: intel.left };
    });

    assert(geom.wrapLeft >= geom.navRight, `expected content to start clear of the left nav rail, got wrapLeft=${geom.wrapLeft} navRight=${geom.navRight}`);
    assert(geom.wrapRight <= geom.intelLeft, `expected content to end clear of the right Intelligence Panel, got wrapRight=${geom.wrapRight} intelLeft=${geom.intelLeft}`);
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

test('Desktop nav-jump: clicking a section scrolls it clear of the fixed Command Bar and marks the correct nav button active, even with other sections hidden (display:none)', async () => {
  await withPage(async (page, { pageErrors }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await connectAndShowDashboard(page);
    await inspectAddress(page, ADDR, { timeout: 60000 });

    await page.evaluate(() => document.querySelector('[data-jump="security"]').click());
    await page.waitForTimeout(2500); // smooth-scroll settle

    const result = await page.evaluate(() => ({
      secTop: Math.round(document.getElementById('section-security').getBoundingClientRect().top),
      activeJumps: [...document.querySelectorAll('.in-btn--active')].map(b => b.dataset.jump),
    }));

    assert(result.secTop >= 64, `expected #section-security to rest clear of the 64px fixed Command Bar, got top=${result.secTop}`);
    assert(result.activeJumps.length === 1 && result.activeJumps[0] === 'security', `expected only "security" marked active, got: ${JSON.stringify(result.activeJumps)}`);
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
