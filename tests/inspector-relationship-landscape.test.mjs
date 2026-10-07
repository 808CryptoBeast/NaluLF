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
        rootBadge: el.querySelector('.rel-tree-root-addr')?.textContent,
        branchLabels: [...el.querySelectorAll('.rel-tree-branch-label')].map(b => b.textContent),
        isRealSvgTree: !!el.querySelector('.rel-tree-svg') && document.querySelectorAll('.rel-tree-edge').length > 0,
      };
    });
    assert(tree.activeTab === 'Tree', `expected Tree to be the default active tab, got "${tree.activeTab}"`);
    assert(tree.rootBadge && tree.rootBadge.length > 0, 'expected a real root account badge');
    assert(tree.isRealSvgTree, 'expected Tree to render as a real SVG node-link hierarchy with real connector edges, not an accordion');
    const expectedBranches = ['Funding / Inbound', 'Outbound / Destinations', 'Token / Issuer', 'Known Services', 'Possible Clusters'];
    assert(JSON.stringify(tree.branchLabels) === JSON.stringify(expectedBranches), `expected branches ${JSON.stringify(expectedBranches)}, got ${JSON.stringify(tree.branchLabels)}`);

    await page.evaluate(() => [...document.querySelectorAll('.rel-tree-node--branch')].find(b => b.textContent.includes('Outbound'))?.click());
    await page.waitForTimeout(300);
    const expanded = await page.evaluate(() => {
      const branch = [...document.querySelectorAll('.rel-tree-node--branch')].find(b => b.textContent.includes('Outbound'));
      return { isExpanded: branch?.classList.contains('rel-tree-node--active'), rowCount: document.querySelectorAll('.rel-tree-node--account').length };
    });
    assert(expanded.isExpanded, 'expected the Outbound branch to show as active on click');
    assert(expanded.rowCount > 0, 'expected real account nodes to fan out below the expanded branch');

    await page.evaluate(() => document.querySelector('.rel-tree-node--account')?.click());
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
    const branchCount = await page.evaluate(() => document.querySelectorAll('.rel-tree-node--branch').length);
    let treeOverflow = [];
    for (let i = 0; i < branchCount; i++) {
      await page.evaluate((idx) => document.querySelectorAll('.rel-tree-node--branch')[idx]?.click(), i);
      await page.waitForTimeout(150);
      // These nodes live inside an SVG <foreignObject> whose viewBox scales
      // the whole tree to fit its container — getBoundingClientRect()
      // reports the post-scale screen size, while scrollWidth/clientWidth
      // report the pre-scale SVG user-space layout size. Comparing across
      // those two coordinate systems (as the Flow check below correctly
      // does, since Flow has no such transform) would flag every node as
      // "overflowing" regardless of real layout — scrollWidth vs clientWidth
      // of the SAME element is the only valid same-space comparison here.
      const found = await page.evaluate(() => [...document.querySelectorAll('#inspect-relationship-landscape .rel-tree-node--account')]
        .filter(r => r.scrollWidth > r.clientWidth + 1)
        .map(r => r.textContent.trim().slice(0, 30)));
      treeOverflow = treeOverflow.concat(found);
    }
    assert(treeOverflow.length === 0, `expected no overflowing account nodes in Tree view, found: ${JSON.stringify(treeOverflow)}`);

    // Flow: nodes are laid out at deterministic fixed SVG coordinates now
    // (not auto-flowing divs), so a real overlap would mean a genuine
    // layout-math bug, not a CSS specificity accident like the original
    // case this test was written for.
    await page.evaluate(() => window.setRelIntelView('flow'));
    await page.waitForTimeout(300);
    const target = await page.evaluate(() => {
      const core = document.querySelector('#inspect-relationship-landscape .rel-tree-node--root')?.getBoundingClientRect();
      const overlapping = [...document.querySelectorAll('#inspect-relationship-landscape .rel-tree-node--account')]
        .filter(r => { const rr = r.getBoundingClientRect(); return core && rr.right > core.left && rr.left < core.right; })
        .map(r => r.textContent.trim().slice(0, 30));
      return { overlapping };
    });
    assert(target.overlapping.length === 0, `expected no Flow account node to overlap the Account Core, found: ${JSON.stringify(target.overlapping)}`);
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

test('Flow view: renders a real ribbon diagram (sources/destinations around an Account Core) with a real asset filter built from the actual data, not a fabricated cross-asset scale', async () => {
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
        coreBadge: el.querySelector('.rel-tree-node--root .rel-tree-root-addr')?.textContent,
        accountNodeCount: el.querySelectorAll('.rel-tree-node--account').length,
        ribbonCount: el.querySelectorAll('.rel-flow-ribbon').length,
        assetChips: [...el.querySelectorAll('.rel-flow-asset-chip')].map(c => c.textContent),
        allChipActive: el.querySelector('.rel-flow-asset-chip.active')?.textContent,
      };
    });
    assert(flow.activeTab === 'Flow', `expected Flow to be active, got "${flow.activeTab}"`);
    assert(flow.coreBadge && flow.coreBadge.length > 0, 'expected a real Account Core badge');
    assert(flow.accountNodeCount > 0, 'expected real account nodes around the core');
    assert(flow.ribbonCount === flow.accountNodeCount, `expected one ribbon per account node, got ${flow.ribbonCount} ribbons for ${flow.accountNodeCount} nodes`);
    assert(flow.assetChips[0] === 'All', `expected "All" to be the first asset filter chip, got ${JSON.stringify(flow.assetChips)}`);
    assert(flow.allChipActive === 'All', 'expected "All" to be the default active asset filter');

    // Switching to a specific real asset must not blow up, and must not
    // silently fall back to "All" — same count semantics differ (fewer
    // rows match one specific asset than "All" relationships combined).
    const specificAsset = flow.assetChips[1];
    if (specificAsset) {
      await page.evaluate((a) => window.setRelIntelFlowAsset(a), specificAsset);
      await page.waitForTimeout(300);
      const afterAsset = await page.evaluate(() => ({
        active: document.querySelector('.rel-flow-asset-chip.active')?.textContent,
        note: document.querySelector('.rel-flow-note')?.textContent,
      }));
      assert(afterAsset.active === specificAsset, `expected the clicked asset chip to become active, got "${afterAsset.active}"`);
      assert(!/never mixes/.test(afterAsset.note || ''), 'expected the "All" cross-asset disclaimer to disappear once a specific asset is selected');
    }
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

test('Matrix view: renders a real analyst heat-grid (microbars + switchable heat layers, Account/Role pinned), and clicking a column header re-sorts rows by that column\'s real values', async () => {
  await withPage(async (page, { pageErrors }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await connectAndShowDashboard(page);
    await inspectAddress(page, ADDR, { timeout: 60000 });

    await page.evaluate(() => window.setRelIntelView('matrix'));
    await page.waitForTimeout(300);
    const before = await page.evaluate(() => ({
      activeTab: document.querySelector('.rel-intel-tab.active')?.textContent,
      rowCount: document.querySelectorAll('.rel-intel-matrix-row').length,
      hasNetBars: document.querySelectorAll('.rim-net').length > 0,
      hasReciprocityBars: document.querySelectorAll('.rim-recip-cell .rim-bar').length > 0,
      heatLayers: [...document.querySelectorAll('.rel-intel-matrix-heat-btn')].map(b => b.textContent),
      defaultHeatActive: document.querySelector('.rel-intel-matrix-heat-btn.active')?.textContent,
    }));
    assert(before.activeTab === 'Matrix', `expected Matrix to be active, got "${before.activeTab}"`);
    assert(before.rowCount > 0, 'expected at least one matrix row');
    assert(before.hasNetBars, 'expected a real Net Flow microbar per row, not a plain number');
    assert(before.hasReciprocityBars, 'expected a real Reciprocity microbar per row');
    assert(JSON.stringify(before.heatLayers) === JSON.stringify(['Value', 'Frequency', 'Reciprocity']), `expected the 3 real heat layers, got ${JSON.stringify(before.heatLayers)}`);
    assert(before.defaultHeatActive === 'Value', `expected Value to be the default active heat layer, got "${before.defaultHeatActive}"`);

    await page.evaluate(() => [...document.querySelectorAll('.rel-intel-matrix-sortbtn')].find(b => b.textContent.includes('Activity'))?.click());
    await page.waitForTimeout(300);
    const sorted = await page.evaluate(() => [...document.querySelectorAll('.rel-intel-matrix-row .rim-activity-cell .rim-bar-val')].map(v => Number(v.textContent)));
    const isDescending = sorted.every((v, i) => i === 0 || sorted[i - 1] >= v);
    assert(isDescending, `expected rows sorted descending by Activity (tx count) after clicking that column header, got: ${JSON.stringify(sorted)}`);

    // Heat layer switch must actually change which real column drives the
    // per-row heat tint (--heat custom property), not just toggle a class.
    await page.evaluate(() => window.setRelIntelMatrixHeat('reciprocity'));
    await page.waitForTimeout(300);
    const heatAfter = await page.evaluate(() => ({
      active: document.querySelector('.rel-intel-matrix-heat-btn.active')?.textContent,
      heatVal: document.querySelector('.rel-intel-matrix-row')?.style.getPropertyValue('--heat'),
    }));
    assert(heatAfter.active === 'Reciprocity', `expected Reciprocity to become the active heat layer, got "${heatAfter.active}"`);
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

test('Timeline view: renders real forensic swimlanes — a span bar plus real per-transaction tick marks per dated relationship, on a correctly-dated axis, capped at the top 15 by value for legibility', async () => {
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
      tickCount: document.querySelectorAll('.rel-intel-timeline-tick').length,
      axisYears: [...document.querySelectorAll('.rel-intel-timeline-axis span')].map(s => Number(s.textContent.match(/\d{2}$/)?.[0])),
    }));
    assert(timeline.activeTab === 'Timeline', `expected Timeline to be active, got "${timeline.activeTab}"`);
    assert(timeline.barCount > 0 && timeline.barCount <= 15, `expected 1-15 timeline bars, got ${timeline.barCount}`);
    assert(timeline.rowCount === timeline.barCount, 'expected one row per bar');
    assert(timeline.tickCount > 0, 'expected real per-transaction tick marks inside the swimlanes, not just a bare span bar');
    // Regression: getCloseTime() already adds XRPL_EPOCH, so formatting
    // firstSeen/lastSeen with a SECOND +XRPL_EPOCH silently pushed every
    // axis date ~30 years into the future (a real 2014 date rendered as
    // "Dec 44") — catch any 2-digit axis year outside a sane XRPL range.
    assert(timeline.axisYears.every(y => y >= 12 && y <= 40), `expected axis years within XRPL's real history (~2012-2040), got ${JSON.stringify(timeline.axisYears)} — a stray +XRPL_EPOCH would push these ~30 years into the future`);
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

test('Focus Tunnel: the drawer\'s Focus button dims unrelated rows, lifts the focused row, auto-expands its branch, and Exit Focus clears it cleanly', async () => {
  await withPage(async (page, { pageErrors }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await connectAndShowDashboard(page);
    await inspectAddress(page, ADDR, { timeout: 60000 });

    await page.evaluate(() => [...document.querySelectorAll('.rel-tree-node--branch')].find(b => b.textContent.includes('Outbound'))?.click());
    await page.waitForTimeout(300);
    const focusedAddr = await page.evaluate(() => {
      const row = document.querySelector('.rel-tree-node--account');
      const m = row?.getAttribute('onclick')?.match(/openRelationshipDrawer\('(r[^']+)'\)/);
      row?.click();
      return m?.[1];
    });
    assert(focusedAddr, 'expected a real counterparty address to click into the drawer with');
    await page.waitForTimeout(300);

    const clicked = await page.evaluate(() => {
      const btn = [...document.querySelectorAll('#relDrawerDetail .mi-rel-examine')].find(b => b.textContent.includes('Focus'));
      if (!btn) return false;
      btn.click();
      return true;
    });
    assert(clicked, 'expected a real "Focus" cross-link button in the drawer');
    await page.waitForTimeout(400);

    const afterFocus = await page.evaluate((addr) => ({
      drawerClosed: document.getElementById('relationshipDrawerOverlay')?.style.display === 'none',
      bannerShowsAddr: (document.querySelector('.rel-intel-focus-banner')?.textContent || '').includes(addr.slice(0, 6)),
      focusedRowCount: document.querySelectorAll('.rel-tree-node--account.rel-tree-node--focused').length,
      dimmedRowCount: document.querySelectorAll('.rel-tree-node--account.rel-tree-node--dimmed').length,
    }), focusedAddr);
    assert(afterFocus.drawerClosed, 'expected the drawer to close when Focus is activated');
    assert(afterFocus.bannerShowsAddr, 'expected the focus banner to name the focused account');
    assert(afterFocus.focusedRowCount === 1, `expected exactly one row marked as the focused relationship, got ${afterFocus.focusedRowCount}`);
    assert(afterFocus.dimmedRowCount > 0, 'expected at least one unrelated row to be visually dimmed while focused');

    const exited = await page.evaluate(() => { document.querySelector('.rel-intel-focus-exit')?.click(); return true; });
    assert(exited, 'expected a real Exit Focus button');
    await page.waitForTimeout(300);
    const afterExit = await page.evaluate(() => ({
      bannerGone: !document.querySelector('.rel-intel-focus-banner'),
      noneDimmed: document.querySelectorAll('.rel-tree-node--account.rel-tree-node--dimmed').length === 0,
    }));
    assert(afterExit.bannerGone, 'expected the focus banner to disappear after Exit Focus');
    assert(afterExit.noneDimmed, 'expected no row to remain dimmed after exiting focus');
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

test('Focus Tunnel state does not survive a fresh inspection', async () => {
  await withPage(async (page, { pageErrors }) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, ADDR, { timeout: 60000 });

    await page.evaluate(() => [...document.querySelectorAll('.rel-tree-node--branch')].find(b => b.textContent.includes('Outbound'))?.click());
    await page.waitForTimeout(300);
    // relDrawerFocusPartner is only ever reached, in real use, from a
    // button rendered inside the already-open drawer — go through that
    // same real open-then-click flow rather than calling it standalone.
    await page.evaluate(() => document.querySelector('.rel-tree-node--account')?.click());
    await page.waitForTimeout(300);
    await page.evaluate(() => [...document.querySelectorAll('#relDrawerDetail .mi-rel-examine')].find(b => b.textContent.includes('Focus'))?.click());
    await page.waitForTimeout(300);

    await inspectAddress(page, ADDR, { timeout: 60000 });
    const bannerGone = await page.evaluate(() => !document.querySelector('.rel-intel-focus-banner'));
    assert(bannerGone, 'expected a fresh inspection to clear any stale Focus Tunnel state');
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
