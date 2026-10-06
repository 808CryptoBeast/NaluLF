// Regression coverage for Relationship Intelligence — Tree / Flow / Matrix
// / Timeline, four synchronized views over one canonical counterparty
// dataset. This is the second generation of the live Overview relationship
// display: Tree (root -> branches -> significant accounts) is now the
// default, replacing the old single flat 2-column list, which survives
// as the "Flow" tab. renderNetworkMap/buildRankedCounterpartyList (the
// retired bubble graph + Full Report's own ranked list) are untouched —
// see inspector.js's own comments on why those stay intact.
import { withPage, connectAndShowDashboard, inspectAddress, assert } from './helpers.mjs';

const suite = { register: [], run: async () => {
  let pass = 0, fail = 0;
  console.log('\n▶ Relationship Intelligence (Tree/Flow/Matrix/Timeline)');
  for (const { name, fn } of suite.register) {
    try { await fn(); console.log(`  PASS  ${name}`); pass++; }
    catch (err) { console.log(`  FAIL  ${name}`); console.log(`        ${err?.stack || err}`); fail++; }
  }
  return { pass, fail, total: suite.register.length };
}};
const test = (name, fn) => suite.register.push({ name, fn });

const ADDR = 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh';

test('Tree view (default): renders a root badge + 5 branches with real counts, expands a branch to show real rows, and opens the drawer on row click — with no page errors', async () => {
  await withPage(async (page, { pageErrors }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await connectAndShowDashboard(page);
    await inspectAddress(page, ADDR, { timeout: 60000 });

    const tree = await page.evaluate(() => {
      const el = document.getElementById('inspect-relationship-landscape');
      return {
        activeTab: el.querySelector('.rel-intel-tab.active')?.textContent,
        rootBadge: el.querySelector('.rel-intel-root-badge')?.textContent,
        branchLabels: [...el.querySelectorAll('.rel-intel-branch-label')].map(b => b.textContent),
      };
    });
    assert(tree.activeTab === 'Tree', `expected Tree to be the default active tab, got "${tree.activeTab}"`);
    assert(tree.rootBadge && tree.rootBadge.length > 0, 'expected a real root account badge');
    const expectedBranches = ['Funding / Inbound', 'Outbound / Destinations', 'Token / Issuer', 'Known Services', 'Possible Clusters'];
    assert(JSON.stringify(tree.branchLabels) === JSON.stringify(expectedBranches), `expected branches ${JSON.stringify(expectedBranches)}, got ${JSON.stringify(tree.branchLabels)}`);

    await page.evaluate(() => [...document.querySelectorAll('.rel-intel-branch-head')].find(b => b.textContent.includes('Outbound'))?.click());
    await page.waitForTimeout(300);
    const expanded = await page.evaluate(() => {
      const branch = [...document.querySelectorAll('.rel-intel-branch')].find(b => b.textContent.includes('Outbound'));
      return { isExpanded: branch?.classList.contains('expanded'), rowCount: branch?.querySelectorAll('.ranked-cp-row').length };
    });
    assert(expanded.isExpanded, 'expected the Outbound branch to expand on click');
    assert(expanded.rowCount > 0, 'expected real rows inside the expanded branch');

    await page.evaluate(() => document.querySelector('.rel-intel-branch.expanded .ranked-cp-row')?.click());
    await page.waitForTimeout(500);
    const drawerVisible = await page.evaluate(() => document.getElementById('relationshipDrawerOverlay')?.style.display);
    assert(drawerVisible === 'flex', `expected the Relationship Drawer to open from a Tree row click, got "${drawerVisible}"`);
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

test('No row ever overflows its container and bleeds into a neighboring element, in either Tree (expanded branches, full width) or Flow (narrow side-by-side columns)', async () => {
  await withPage(async (page, { pageErrors }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await connectAndShowDashboard(page);
    await inspectAddress(page, ADDR, { timeout: 60000 });

    // Tree branches expand one at a time (expanding a new one collapses
    // the last) — check overflow right after each click, not once at the
    // end, or only the last-expanded branch would ever actually be checked.
    const branchCount = await page.evaluate(() => document.querySelectorAll('.rel-intel-branch-head').length);
    let treeOverflow = [];
    for (let i = 0; i < branchCount; i++) {
      await page.evaluate((idx) => document.querySelectorAll('.rel-intel-branch-head')[idx]?.click(), i);
      await page.waitForTimeout(150);
      const found = await page.evaluate(() => [...document.querySelectorAll('#inspect-relationship-landscape .ranked-cp-row')]
        .filter(r => r.scrollWidth > r.getBoundingClientRect().width + 1)
        .map(r => r.textContent.trim().slice(0, 30)));
      treeOverflow = treeOverflow.concat(found);
    }
    assert(treeOverflow.length === 0, `expected no overflowing rows in Tree view, found: ${JSON.stringify(treeOverflow)}`);

    // Flow: the narrow-column case that caused a real overlap bug previously.
    await page.evaluate(() => window.setRelIntelView('flow'));
    await page.waitForTimeout(300);
    const target = await page.evaluate(() => {
      const t = document.querySelector('.rel-landscape-target')?.getBoundingClientRect();
      const overlapping = [...document.querySelectorAll('#inspect-relationship-landscape .ranked-cp-row')]
        .filter(r => { const rr = r.getBoundingClientRect(); return t && rr.right > t.left && rr.left < t.right; })
        .map(r => r.textContent.trim().slice(0, 30));
      return { overlapping };
    });
    assert(target.overlapping.length === 0, `expected no Flow row to overlap the Target card, found: ${JSON.stringify(target.overlapping)}`);
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

test('Flow view: switching tabs shows the directional 2-column layout (inbound/outbound around a target badge), matching the row count of the underlying dataset', async () => {
  await withPage(async (page, { pageErrors }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await connectAndShowDashboard(page);
    await inspectAddress(page, ADDR, { timeout: 60000 });

    await page.evaluate(() => window.setRelIntelView('flow'));
    await page.waitForTimeout(300);
    const flow = await page.evaluate(() => {
      const el = document.getElementById('inspect-relationship-landscape');
      return {
        activeTab: el.querySelector('.rel-intel-tab.active')?.textContent,
        colCount: el.querySelectorAll('.rel-landscape-col').length,
        targetBadge: el.querySelector('.rel-landscape-target-badge')?.textContent,
      };
    });
    assert(flow.activeTab === 'Flow', `expected Flow to be active, got "${flow.activeTab}"`);
    assert(flow.colCount === 2, `expected exactly 2 columns (inbound/outbound), got ${flow.colCount}`);
    assert(flow.targetBadge && flow.targetBadge.length > 0, 'expected a real target account badge');
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

test('Matrix view: renders a sortable table over every relationship, and clicking a column header re-sorts rows by that column\'s real values', async () => {
  await withPage(async (page, { pageErrors }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await connectAndShowDashboard(page);
    await inspectAddress(page, ADDR, { timeout: 60000 });

    await page.evaluate(() => window.setRelIntelView('matrix'));
    await page.waitForTimeout(300);
    const before = await page.evaluate(() => ({
      activeTab: document.querySelector('.rel-intel-tab.active')?.textContent,
      rowCount: document.querySelectorAll('.rel-intel-matrix-row').length,
    }));
    assert(before.activeTab === 'Matrix', `expected Matrix to be active, got "${before.activeTab}"`);
    assert(before.rowCount > 0, 'expected at least one matrix row');

    await page.evaluate(() => [...document.querySelectorAll('.rel-intel-matrix-sortbtn')].find(b => b.textContent.includes('Tx'))?.click());
    await page.waitForTimeout(300);
    const sorted = await page.evaluate(() => [...document.querySelectorAll('.rel-intel-matrix-row td:nth-child(5)')].map(td => Number(td.textContent)));
    const isDescending = sorted.every((v, i) => i === 0 || sorted[i - 1] >= v);
    assert(isDescending, `expected rows sorted descending by Tx count after clicking that column header, got: ${JSON.stringify(sorted)}`);
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

test('Timeline view: renders a bar per dated relationship on a shared time axis, capped at the top 15 by value for legibility', async () => {
  await withPage(async (page, { pageErrors }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await connectAndShowDashboard(page);
    await inspectAddress(page, ADDR, { timeout: 60000 });

    await page.evaluate(() => window.setRelIntelView('timeline'));
    await page.waitForTimeout(300);
    const timeline = await page.evaluate(() => ({
      activeTab: document.querySelector('.rel-intel-tab.active')?.textContent,
      barCount: document.querySelectorAll('.rel-intel-timeline-bar').length,
      rowCount: document.querySelectorAll('.rel-intel-timeline-row').length,
    }));
    assert(timeline.activeTab === 'Timeline', `expected Timeline to be active, got "${timeline.activeTab}"`);
    assert(timeline.barCount > 0 && timeline.barCount <= 15, `expected 1-15 timeline bars, got ${timeline.barCount}`);
    assert(timeline.rowCount === timeline.barCount, 'expected one row per bar');
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

test('View and expand/sort state reset on a fresh inspection — switching to Matrix and sorting, then re-inspecting, lands back on Tree with nothing expanded', async () => {
  await withPage(async (page, { pageErrors }) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, ADDR, { timeout: 60000 });

    await page.evaluate(() => { window.setRelIntelView('matrix'); window.setRelIntelMatrixSort('tx'); });
    await page.waitForTimeout(300);

    await inspectAddress(page, ADDR, { timeout: 60000 });
    const afterReinspect = await page.evaluate(() => document.querySelector('.rel-intel-tab.active')?.textContent);
    assert(afterReinspect === 'Tree', `expected the view to reset to "Tree" on a fresh inspection, got "${afterReinspect}"`);
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
