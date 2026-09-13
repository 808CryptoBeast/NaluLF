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

suite.register('Top Counterparties rows fit within a 390px viewport, with the direction column hidden and address/volume/tx columns shrunk', async () => {
  await withPage(async (page) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await connectAndShowDashboard(page);
    await inspectAddress(page, 'rPVMhWBsfF9iMXYj3aAzJVkPDTFNSyWdKy', { timeout: 90000 });
    await page.waitForTimeout(1500);

    const result = await page.evaluate(() => {
      const vw = document.documentElement.clientWidth;
      const rows = [...document.querySelectorAll('#inspect-top-counterparties .ranked-cp-row')];
      if (!rows.length) return { rowCount: 0 };
      const row = rows[0];
      const dir = row.querySelector('.ranked-cp-dir');
      return {
        rowCount: rows.length,
        rowRight: Math.round(row.getBoundingClientRect().right),
        vw,
        dirDisplay: dir ? getComputedStyle(dir).display : 'missing',
        addrWidth: Math.round(row.querySelector('.ranked-cp-addr').getBoundingClientRect().width),
      };
    });
    assert(result.rowCount > 0, 'expected at least one ranked counterparty row to test against');
    assert(result.rowRight <= result.vw + 2, `expected the row to fit within the viewport, got right=${result.rowRight} vs viewport=${result.vw}`);
    assert(result.dirDisplay === 'none', `expected the direction column to be hidden at 390px, got display:${result.dirDisplay}`);
    assert(result.addrWidth <= 100, `expected the address column to shrink below its 150px desktop width at 390px, got ${result.addrWidth}px`);
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
