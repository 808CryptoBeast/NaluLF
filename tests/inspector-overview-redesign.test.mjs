// Regression guard for the Inspector Overview 2.0 visual/interaction
// refresh (roadmap: "futuristic forensic command center" redesign, scoped
// via AskUserQuestion to a full rollout across 9 sections with full
// interactivity on the two structural departures: metric-card hover-expand
// and Signal Composition click-to-expand).
import { withPage, connectAndShowDashboard, inspectAddress, makeSuite, assert } from './helpers.mjs';

const suite = makeSuite('Inspector Overview 2.0 Redesign');

const ADDR = 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh';

suite.register('Account Overview metric cards: hovering or focusing a card with a detail explanation reveals it, via real CSS (not JS-toggled display)', async () => {
  await withPage(async (page, { pageErrors }) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, ADDR, { timeout: 120000 });
    await page.waitForTimeout(1000);

    const cellHandle = await page.evaluateHandle(() =>
      [...document.querySelectorAll('.acct-cell')].find(c => /Wallet Age/.test(c.textContent)));
    assert(await cellHandle.evaluate(el => !!el), 'expected a Wallet Age metric card to render');

    const collapsed = await cellHandle.evaluate(c => {
      const d = c.querySelector('.acct-cell-detail');
      return { hasDetail: !!d, opacity: d ? getComputedStyle(d).opacity : null };
    });
    assert(collapsed.hasDetail, 'expected the card to carry a .acct-cell-detail explanation element');
    assert(Number(collapsed.opacity) < 0.1, `expected the detail to be collapsed (opacity ~0) by default, got ${collapsed.opacity}`);

    await cellHandle.asElement().hover();
    // 600ms, not 350: the transition itself is 200ms, but on a page this
    // size style recalc before it even starts can itself take a couple
    // hundred ms depending on what else changed nearby (confirmed twice
    // now — this is about real recalc cost, not a logic bug: the opacity
    // reliably reaches 1, just not always inside a 150ms safety margin).
    await page.waitForTimeout(600);
    const expanded = await cellHandle.evaluate(c => {
      const d = c.querySelector('.acct-cell-detail');
      return { opacity: getComputedStyle(d).opacity, text: d.textContent };
    });
    assert(Number(expanded.opacity) > 0.8, `expected the detail to expand to near-full opacity on hover, got ${expanded.opacity} — a real CSS minifier bug in this build pipeline previously dropped the ".acct-cell:hover " prefix from this exact rule, silently breaking this`);
    assert(expanded.text.length > 10, `expected real explanatory text in the expanded detail, got: "${expanded.text}"`);

    // Keyboard accessibility: focusing (not just mouse hover) must also reveal it.
    await cellHandle.evaluate(c => c.focus());
    // 600ms, not 350: the transition itself is 200ms, but on a page this
    // size style recalc before it even starts can itself take a couple
    // hundred ms depending on what else changed nearby (confirmed twice
    // now — this is about real recalc cost, not a logic bug: the opacity
    // reliably reaches 1, just not always inside a 150ms safety margin).
    await page.waitForTimeout(600);
    const focusedState = await cellHandle.evaluate(c => getComputedStyle(c.querySelector('.acct-cell-detail')).opacity);
    assert(Number(focusedState) > 0.8, `expected the detail to also expand on keyboard focus (not hover-only), got ${focusedState}`);

    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

suite.register('Signal Composition: clicking a category row expands a panel showing its top findings by confidence, and collapses on a second click', async () => {
  await withPage(async (page, { pageErrors }) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, ADDR, { timeout: 120000 });
    await page.waitForTimeout(1000);

    const rowCount = await page.evaluate(() => document.querySelectorAll('[onclick*="toggleSignalCategory"]').length);
    assert(rowCount > 0, 'expected at least one clickable Signal Composition category row for this known-active account');

    const beforeLen = await page.evaluate(() => document.getElementById('quick-verdict-body').innerHTML.length);
    await page.evaluate(() => document.querySelector('[onclick*="toggleSignalCategory"]').click());
    await page.waitForTimeout(150);
    const afterOpenLen = await page.evaluate(() => document.getElementById('quick-verdict-body').innerHTML.length);
    assert(afterOpenLen > beforeLen, `expected the panel to grow when a category expands, got ${beforeLen} -> ${afterOpenLen}`);

    const hasAriaExpanded = await page.evaluate(() => !!document.querySelector('[onclick*="toggleSignalCategory"][aria-expanded="true"]'));
    assert(hasAriaExpanded, 'expected the expanded row to mark aria-expanded="true"');

    // Click the SAME row again (re-query since the DOM was replaced by re-render) — collapses.
    await page.evaluate(() => document.querySelector('[onclick*="toggleSignalCategory"]').click());
    await page.waitForTimeout(150);
    const afterCloseLen = await page.evaluate(() => document.getElementById('quick-verdict-body').innerHTML.length);
    assert(afterCloseLen === beforeLen, `expected a second click to collapse back to the original content length, got ${beforeLen} vs ${afterCloseLen}`);

    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

suite.register('Signal Composition: the expanded category does not carry over to a fresh inspection of a different account', async () => {
  await withPage(async (page, { pageErrors }) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, ADDR, { timeout: 120000 });
    await page.waitForTimeout(1000);
    await page.evaluate(() => document.querySelector('[onclick*="toggleSignalCategory"]')?.click());
    await page.waitForTimeout(150);
    const wasExpanded = await page.evaluate(() => !!document.querySelector('[onclick*="toggleSignalCategory"][aria-expanded="true"]'));
    assert(wasExpanded, 'expected a category to be expanded before switching accounts');

    await inspectAddress(page, 'rsoLo2S1kiGeCcn6hCUXVrCpGMWLrRrLZz', { timeout: 120000 });
    await page.waitForTimeout(1000);
    const stillExpandedOnNewAccount = await page.evaluate(() => !!document.querySelector('[onclick*="toggleSignalCategory"][aria-expanded="true"]'));
    assert(!stillExpandedOnNewAccount, 'expected the expanded-category state to reset for a freshly inspected account, not carry over stale from the previous one');
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
