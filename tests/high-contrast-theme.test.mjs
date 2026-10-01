// Regression coverage for "High-contrast theme" (roadmap: UX). Scoped as a
// pragmatic partial pass (explicit user decision, not a full token refactor):
// the app's CSS has ~1,000 hardcoded low-opacity rgba(255,255,255,.X)
// borders/text colors across its stylesheets rather than theme variables, so
// this covers the root palette (--bg-primary/--text-primary/etc, which most
// labels/values already read for free) plus the highest-traffic shared
// surfaces (widget/analytics cards, the shared modal shell, form inputs, nav
// buttons) and a strong focus-visible outline. Added as a 5th entry in the
// existing THEMES rotation (gold/cosmic/starry/hawaiian/highcontrast) rather
// than a new, separate theming mechanism.
import { withPage, connectAndShowDashboard, assert } from './helpers.mjs';

const suite = { register: [], run: async () => {
  let pass = 0, fail = 0;
  console.log('\n▶ High Contrast Theme');
  for (const { name, fn } of suite.register) {
    try { await fn(); console.log(`  PASS  ${name}`); pass++; }
    catch (err) { console.log(`  FAIL  ${name}`); console.log(`        ${err?.stack || err}`); fail++; }
  }
  return { pass, fail, total: suite.register.length };
}};
const test = (name, fn) => suite.register.push({ name, fn });

test('Settings: the High Contrast pill renders, applying it sets the body class + persists to localStorage + updates the root CSS palette, and a real card picks up pure black/white', async () => {
  await withPage(async (page, { pageErrors }) => {
    await connectAndShowDashboard(page);
    await page.evaluate(() => window.showProfile());
    await page.waitForTimeout(500);
    await page.evaluate(() => window.switchProfileTab?.('settings'));
    await page.waitForTimeout(300);

    const pill = await page.evaluate(() => {
      const el = document.querySelector('.theme-pill.highcontrast');
      return { exists: !!el, text: el?.textContent };
    });
    assert(pill.exists, 'expected a .theme-pill.highcontrast button in Settings → Appearance');
    assert(pill.text === 'High Contrast', `expected the pill's display text to read "High Contrast", got "${pill.text}"`);

    await page.evaluate(() => document.querySelector('.theme-pill.highcontrast')?.click());
    await page.waitForTimeout(200);

    const after = await page.evaluate(() => ({
      bodyHasClass: document.body.classList.contains('theme-highcontrast'),
      pillActive: document.querySelector('.theme-pill.highcontrast')?.classList.contains('active'),
      persisted: window.localStorage.getItem('naluxrp_theme'),
      rootBg: getComputedStyle(document.body).getPropertyValue('--bg-primary').trim(),
    }));
    assert(after.bodyHasClass, 'expected body to carry the theme-highcontrast class after clicking the pill');
    assert(after.pillActive, 'expected the pill itself to show the active state');
    assert(after.persisted === 'highcontrast', `expected the choice to persist to localStorage, got "${after.persisted}"`);
    assert(after.rootBg === '#000000', `expected --bg-primary to resolve to pure black, got "${after.rootBg}"`);

    await page.evaluate(() => window.switchProfileTab?.('wallets'));
    await page.waitForTimeout(300);
    const card = await page.evaluate(() => {
      const el = document.querySelector('.widget-card') || document.querySelector('.analytics-card');
      if (!el) return null;
      const cs = getComputedStyle(el);
      return { bg: cs.backgroundColor, borderColor: cs.borderColor };
    });
    if (card) {
      assert(card.bg === 'rgb(0, 0, 0)', `expected a real rendered card's background to be forced to pure black under High Contrast, got "${card.bg}"`);
      assert(card.borderColor === 'rgb(255, 255, 255)', `expected a real rendered card's border to be forced to pure white, got "${card.borderColor}"`);
    }
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

test('cycleTheme() includes High Contrast as the 5th theme in rotation, with no duplicates or omissions', async () => {
  await withPage(async (page, { pageErrors }) => {
    await connectAndShowDashboard(page);
    const seen = await page.evaluate(() => {
      const s = new Set();
      for (let i = 0; i < 6; i++) {
        window.cycleTheme();
        s.add(document.body.className.match(/theme-(\w+)/)?.[1]);
      }
      return [...s];
    });
    assert(seen.includes('highcontrast'), `expected cycleTheme() to visit "highcontrast", got ${JSON.stringify(seen)}`);
    assert(seen.length === 5, `expected exactly 5 distinct themes in rotation, got ${seen.length}: ${JSON.stringify(seen)}`);
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
