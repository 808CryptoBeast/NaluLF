// Regression coverage for Phase 2 of the Inspector 6.1 redesign:
// consolidating the global nav from 30 individual per-detector jump
// buttons down to 11 (7 investigative workspaces + 4 tools), per spec
// §4 ("Keep the global rail simple... do not keep Liquidity/Issuer/NFT/
// Benford/Entropy/Zipf/... as individual global navigation entries").
// INSPECTOR_WORKSPACES/INSPECTOR_TOOLS (inspector.js) are the single
// source of truth the nav markup, click-to-jump, active-highlight, and
// status-dot aggregation are all derived from — see that file's own
// comments for the real 'security' vs. 'drain' active-highlight bug this
// consolidation surfaced and fixed (deriving scrollspy order from the
// THEMATIC workspace grouping instead of true DOM order).
import { withPage, connectAndShowDashboard, inspectAddress, assert } from './helpers.mjs';

const suite = { register: [], run: async () => {
  let pass = 0, fail = 0;
  console.log('\n▶ Investigation Navigator (Phase 2)');
  for (const { name, fn } of suite.register) {
    try { await fn(); console.log(`  PASS  ${name}`); pass++; }
    catch (err) { console.log(`  FAIL  ${name}`); console.log(`        ${err?.stack || err}`); fail++; }
  }
  return { pass, fail, total: suite.register.length };
}};
const test = (name, fn) => suite.register.push({ name, fn });

const ADDR = 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh';
const EXPECTED_LABELS = ['Overview', 'Flow', 'Connections', 'Market', 'Assets', 'Security', 'Forensics', 'Transactions', 'Evidence', 'Report', 'Raw Ledger'];

test('The global nav shows exactly 11 consolidated buttons (7 workspaces + 4 tools) with the expected labels, and every real section is covered by exactly one of them', async () => {
  await withPage(async (page, { pageErrors }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await connectAndShowDashboard(page);
    await inspectAddress(page, ADDR, { timeout: 60000 });

    const check = await page.evaluate(() => {
      const btns = [...document.querySelectorAll('#inspector-nav .in-btn[data-jump-key]')];
      const labels = btns.map(b => b.querySelector('.in-label')?.textContent);
      const coveredBy = new Map();
      btns.forEach(b => b.dataset.jumpSections.split(',').forEach(s => {
        coveredBy.set(s, (coveredBy.get(s) || 0) + 1);
      }));
      const allSectionIds = [...document.querySelectorAll('.inspector-section')].map(s => s.id.replace(/^section-/, ''));
      const uncovered = allSectionIds.filter(id => !coveredBy.has(id));
      const doubleCovered = [...coveredBy.entries()].filter(([, n]) => n > 1).map(([id]) => id);
      return { count: btns.length, labels, uncovered, doubleCovered };
    });

    assert(check.count === 11, `expected exactly 11 nav buttons, got ${check.count}`);
    assert(JSON.stringify(check.labels) === JSON.stringify(EXPECTED_LABELS), `expected labels ${JSON.stringify(EXPECTED_LABELS)}, got ${JSON.stringify(check.labels)}`);
    assert(check.uncovered.length === 0, `sections with no nav button: ${JSON.stringify(check.uncovered)}`);
    assert(check.doubleCovered.length === 0, `sections claimed by more than one button: ${JSON.stringify(check.doubleCovered)}`);
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

test('Clicking a workspace button scrolls to its first member section and marks the workspace active; scrolling further into a LATER member section keeps the SAME workspace active (one-to-many highlighting)', async () => {
  await withPage(async (page, { pageErrors }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await connectAndShowDashboard(page);
    await inspectAddress(page, ADDR, { timeout: 60000 });

    await page.evaluate(() => document.querySelector('[data-jump-key="flow"]').click());
    await page.waitForTimeout(2500);
    const afterClick = await page.evaluate(() => ({
      secTop: Math.round(document.getElementById('section-drain').getBoundingClientRect().top),
      active: [...document.querySelectorAll('.in-btn--active')].map(b => b.dataset.jumpKey),
    }));
    assert(afterClick.active.length === 1 && afterClick.active[0] === 'flow', `expected only "flow" active after clicking it, got ${JSON.stringify(afterClick.active)}`);
    assert(afterClick.secTop >= 64, `expected #section-drain to scroll clear of the fixed Command Bar, got top=${afterClick.secTop}`);

    // Flow's members are drain, flowmotifs, inbound (in that DOM order) —
    // scrolling to 'inbound' (a LATER member, not the jump target) must
    // still show "flow" as active, not fall back to whatever section
    // happens to be nearby (this is the exact bug a first implementation
    // had: deriving scrollspy order from the workspace grouping instead
    // of true DOM order caused an EARLIER, already-scrolled-past section
    // from a different workspace to incorrectly "win").
    await page.evaluate(() => document.getElementById('section-inbound')?.scrollIntoView({ block: 'start' }));
    await page.waitForTimeout(600);
    const afterScroll = await page.evaluate(() => [...document.querySelectorAll('.in-btn--active')].map(b => b.dataset.jumpKey));
    assert(afterScroll.length === 1 && afterScroll[0] === 'flow', `expected "flow" to remain active while scrolled into its own later member section, got ${JSON.stringify(afterScroll)}`);
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

test('Desktop nav labels still render in full at the consolidated set (no clipping regression from Phase 1)', async () => {
  await withPage(async (page, { pageErrors }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await connectAndShowDashboard(page);
    await inspectAddress(page, ADDR, { timeout: 60000 });

    const clipped = await page.evaluate(() => {
      const results = [];
      document.querySelectorAll('#inspector-nav .in-btn .in-label').forEach(label => {
        const rect = label.getBoundingClientRect();
        if (label.scrollWidth > rect.width + 1) results.push({ text: label.textContent, scrollWidth: label.scrollWidth, renderedWidth: rect.width });
      });
      return results;
    });
    assert(clipped.length === 0, `expected every nav label to render at full width, found clipped: ${JSON.stringify(clipped)}`);
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
