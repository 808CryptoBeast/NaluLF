// Regression guard for two real mobile-overflow bugs found by a live
// 390px-viewport audit of this session's newer features: (1) Top
// Counterparties' ranked-cp-row used fixed pixel widths on every column
// with no responsive behavior, overflowing the viewport by 92px before
// the flexible bar even got space; (2) the risk banner's Copy/Watch
// buttons grew a third sibling (Compare) with a full text label, and all
// three together overflowed by ~69px. Both fixed with a mobile media
// query — this guards the fix stays in place and doesn't silently regress.
import { withPage, connectAndShowDashboard, inspectAddress, makeSuite, assert } from './helpers.mjs';

const suite = makeSuite('Mobile Overflow — New Features');

suite.register('At a 390px mobile viewport, a real inspection with Top Counterparties + risk banner buttons produces no horizontal page overflow', async () => {
  await withPage(async (page) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await connectAndShowDashboard(page);
    await inspectAddress(page, 'rPVMhWBsfF9iMXYj3aAzJVkPDTFNSyWdKy', { timeout: 90000 });
    await page.waitForTimeout(1500);

    const before = await page.evaluate(() => ({
      sw: document.documentElement.scrollWidth,
      cw: document.documentElement.clientWidth,
    }));

    // Expand every collapsed section too — a fix that only holds when
    // collapsed isn't a real fix once the user actually opens something.
    await page.evaluate(() => {
      document.querySelectorAll('.inspector-section.collapsed .section-header').forEach(h => h.click());
    });
    await page.waitForTimeout(500);
    const afterExpand = await page.evaluate(() => ({
      sw: document.documentElement.scrollWidth,
      cw: document.documentElement.clientWidth,
    }));

    // A pre-existing, unrelated ~8px overflow from the shared dashboard nav
    // chrome (.net-btn) is out of scope here — allow a small fixed slack
    // rather than asserting pixel-perfect zero, so this test targets the
    // features it's actually meant to guard.
    assert(before.sw <= before.cw + 10, `expected no significant horizontal overflow before expanding sections, got scrollWidth=${before.sw} vs clientWidth=${before.cw}`);
    assert(afterExpand.sw <= afterExpand.cw + 10, `expected no significant horizontal overflow with all sections expanded, got scrollWidth=${afterExpand.sw} vs clientWidth=${afterExpand.cw}`);
  });
});

suite.register('Relationship Intelligence (Tree/Flow SVG canvases) never overflows the page at a 390px mobile viewport — a wide canvas scrolls within its own container instead of blowing out page width', async () => {
  await withPage(async (page) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await connectAndShowDashboard(page);
    await inspectAddress(page, 'rPVMhWBsfF9iMXYj3aAzJVkPDTFNSyWdKy', { timeout: 90000 });
    await page.waitForTimeout(1500);

    // Tree (the default view) keeps its branches collapsed until clicked —
    // Flow renders every relationship as a real account node unconditionally.
    // Both now render their SVG canvas at a fixed pixel size (nodes never
    // shrink to fit) with overflow-x:auto on the wrapping .rel-tree-canvas
    // — the real invariant at mobile width is that THIS local scroll
    // contains the overflow rather than it leaking out to the whole page.
    await page.evaluate(() => window.setRelIntelView('flow'));
    await page.waitForTimeout(300);

    const result = await page.evaluate(() => {
      const vw = document.documentElement.clientWidth;
      const pageOverflowSw = document.documentElement.scrollWidth;
      const canvas = document.querySelector('#inspect-relationship-landscape .rel-tree-canvas');
      const nodeCount = document.querySelectorAll('#inspect-relationship-landscape .rel-tree-node--account').length;
      return {
        nodeCount,
        pageOverflowSw,
        vw,
        canvasOverflowsLocally: canvas ? canvas.scrollWidth > canvas.clientWidth : false,
      };
    });
    assert(result.nodeCount > 0, 'expected at least one ranked counterparty node to test against');
    assert(result.pageOverflowSw <= result.vw + 10, `expected the SVG canvas's own width to never blow out the page's horizontal scroll, got page scrollWidth=${result.pageOverflowSw} vs viewport=${result.vw}`);
  });
});

suite.register('Risk banner Watch/Compare button text labels are hidden at 390px, leaving icon-only 44px touch targets', async () => {
  await withPage(async (page) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await connectAndShowDashboard(page);
    await inspectAddress(page, 'rPVMhWBsfF9iMXYj3aAzJVkPDTFNSyWdKy', { timeout: 90000 });
    await page.waitForTimeout(1000);

    const result = await page.evaluate(() => {
      const watchBtn = document.getElementById('watchlist-btn');
      const compareBtn = [...document.querySelectorAll('.irb-copy-btn')].find(b => (b.title || '').includes('Compare'));
      return {
        watchLabelDisplay: getComputedStyle(watchBtn.querySelector('.irb-btn-label')).display,
        compareLabelDisplay: getComputedStyle(compareBtn.querySelector('.irb-btn-label')).display,
        watchWidth: Math.round(watchBtn.getBoundingClientRect().width),
        compareWidth: Math.round(compareBtn.getBoundingClientRect().width),
      };
    });
    assert(result.watchLabelDisplay === 'none', `expected the Watch button's text label hidden at 390px, got display:${result.watchLabelDisplay}`);
    assert(result.compareLabelDisplay === 'none', `expected the Compare button's text label hidden at 390px, got display:${result.compareLabelDisplay}`);
    assert(result.watchWidth >= 40 && result.watchWidth <= 50, `expected an icon-sized touch target (~44px) for Watch, got ${result.watchWidth}px`);
    assert(result.compareWidth >= 40 && result.compareWidth <= 50, `expected an icon-sized touch target (~44px) for Compare, got ${result.compareWidth}px`);
  });
});

suite.register('At a wider desktop viewport, both buttons still show their full text labels — the mobile fix does not hide them everywhere', async () => {
  await withPage(async (page) => {
    await page.setViewportSize({ width: 1280, height: 900 });
    await connectAndShowDashboard(page);
    await inspectAddress(page, 'rPVMhWBsfF9iMXYj3aAzJVkPDTFNSyWdKy', { timeout: 90000 });
    await page.waitForTimeout(1000);

    const result = await page.evaluate(() => {
      const watchBtn = document.getElementById('watchlist-btn');
      const compareBtn = [...document.querySelectorAll('.irb-copy-btn')].find(b => (b.title || '').includes('Compare'));
      return {
        watchText: watchBtn.textContent.trim(),
        compareText: compareBtn.textContent.trim(),
        watchLabelDisplay: getComputedStyle(watchBtn.querySelector('.irb-btn-label')).display,
      };
    });
    assert(/Watch/.test(result.watchText), `expected the Watch button to still show its text label at desktop width, got: "${result.watchText}"`);
    assert(/Compare/.test(result.compareText), `expected the Compare button to still show its text label at desktop width, got: "${result.compareText}"`);
    assert(result.watchLabelDisplay !== 'none', 'expected the label span to NOT be display:none at desktop width');
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
