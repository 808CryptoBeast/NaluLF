// Regression guard for the modern/interactive UI pass on the Inspector:
// (1) live status dots on the jump-nav that mirror each section's own
// already-computed badge severity, (2) a brief highlight confirming which
// card a jump-nav click landed on, (3) continuous crosshair hover-scrub on
// the Balance Reconstruction chart, and (4) hover-focus dimming on the
// Counterparty Network Map. All four are pure presentation layered over
// data the app already computes — no new analysis, no new RPC calls.
import { withPage, connectAndShowDashboard, inspectAddress, makeSuite, assert } from './helpers.mjs';

const suite = makeSuite('Inspector UI Interactivity');

suite.register('Jump-nav buttons show live status dots matching each section\'s own badge severity, with no page errors', async () => {
  await withPage(async (page, { pageErrors }) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, 'rnj7R3QUGzLZc9dg24jSrGabtt1tp1XD7A', { timeout: 90000 });
    await page.waitForTimeout(1500);

    const result = await page.evaluate(() => {
      const drainBadge = document.getElementById('badge-drain');
      const drainDot = document.querySelector('#inspector-nav .in-btn[data-jump="drain"] .in-status-dot');
      const overviewDot = document.querySelector('#inspector-nav .in-btn[data-jump="overview"] .in-status-dot');
      return {
        totalDots: document.querySelectorAll('#inspector-nav .in-status-dot').length,
        drainBadgeClass: drainBadge?.className,
        drainDotClass: drainDot?.className,
        overviewHasNoDot: !overviewDot, // Account Overview has no findings badge to mirror
      };
    });
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
    assert(result.totalDots > 0, 'expected at least one nav status dot to render for this known-flagged account');
    assert(result.overviewHasNoDot, 'expected Account Overview (no badge) to get no fabricated dot');
    // Drain's dot severity must match its own badge, not be independently derived.
    const drainLevel = /crit/.test(result.drainBadgeClass) ? 'crit' : /warn/.test(result.drainBadgeClass) ? 'warn' : /ok/.test(result.drainBadgeClass) ? 'ok' : null;
    if (drainLevel) assert(result.drainDotClass?.includes(`in-status-dot--${drainLevel}`), `expected drain's nav dot (${result.drainDotClass}) to match its badge severity (${result.drainBadgeClass})`);
  });
});

suite.register('Clicking a jump-nav button briefly flashes the target section, then clears the flash on its own', async () => {
  await withPage(async (page, { pageErrors }) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, 'rnj7R3QUGzLZc9dg24jSrGabtt1tp1XD7A', { timeout: 90000 });
    await page.waitForTimeout(1500);

    await page.evaluate(() => document.querySelector('#inspector-nav .in-btn[data-jump="security"]').click());
    const flashedImmediately = await page.evaluate(() => document.getElementById('section-security')?.classList.contains('section-flash'));
    // The CSS animation is nominally 1.1s, but under test-runner CPU
    // contention wall-clock completion can run noticeably longer than the
    // nominal duration (a pattern already documented elsewhere in this
    // suite for collapse transitions) — wait well past it for margin.
    await page.waitForTimeout(2000);
    const flashedAfter = await page.evaluate(() => document.getElementById('section-security')?.classList.contains('section-flash'));

    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
    assert(flashedImmediately, 'expected the section-flash class to apply immediately on a jump-nav click');
    assert(!flashedAfter, 'expected the section-flash class to clear itself once the highlight animation finishes');
  });
});

suite.register('Balance chart: hovering the chart snaps a crosshair + dot to the nearest real data point and drives the shared tooltip', async () => {
  await withPage(async (page, { pageErrors }) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, 'rnj7R3QUGzLZc9dg24jSrGabtt1tp1XD7A', { timeout: 90000 });
    await page.waitForTimeout(1500);

    const result = await page.evaluate(async () => {
      const svg = document.querySelector('#section-drain .balchart-svg');
      if (!svg) return { found: false };
      const capture = svg.querySelector('.balchart-hover-capture');
      const box = capture.getBoundingClientRect();
      capture.dispatchEvent(new MouseEvent('mousemove', { clientX: box.left + box.width * 0.5, clientY: box.top + box.height * 0.5, bubbles: true }));
      await new Promise(r => setTimeout(r, 80));
      const before = {
        crosshairOpacity: svg.querySelector('.balchart-crosshair')?.style.opacity,
        dotOpacity: svg.querySelector('.balchart-hover-dot')?.style.opacity,
        tooltipVisible: document.getElementById('chartTooltip')?.classList.contains('chart-tooltip--visible'),
        tooltipHasDate: /\d{4}-\d{2}-\d{2}/.test(document.getElementById('chartTooltip')?.textContent || ''),
      };
      capture.dispatchEvent(new MouseEvent('mouseleave', { bubbles: true }));
      await new Promise(r => setTimeout(r, 80));
      const after = {
        crosshairOpacity: svg.querySelector('.balchart-crosshair')?.style.opacity,
        tooltipVisible: document.getElementById('chartTooltip')?.classList.contains('chart-tooltip--visible'),
      };
      return { found: true, before, after };
    });

    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
    assert(result.found, 'expected the Balance Reconstruction chart to render for this known-drain-episode account');
    assert(result.before.crosshairOpacity === '1', 'expected the crosshair to appear on hover');
    assert(result.before.dotOpacity === '1', 'expected the hover dot to appear on hover');
    assert(result.before.tooltipVisible, 'expected the shared chart tooltip to appear on hover');
    assert(result.before.tooltipHasDate, `expected the tooltip to show a real date, got: not matched`);
    assert(result.after.crosshairOpacity === '0', 'expected the crosshair to hide on mouseleave');
    assert(!result.after.tooltipVisible, 'expected the tooltip to hide on mouseleave');
  });
});

suite.register('Network map: hovering a node dims every unrelated node/edge, keeps the inspected account\'s own center node at full strength, and resets on mouseleave', async () => {
  await withPage(async (page, { pageErrors }) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, 'rnj7R3QUGzLZc9dg24jSrGabtt1tp1XD7A', { timeout: 90000 });
    await page.waitForTimeout(1500);

    const result = await page.evaluate(async () => {
      const svg = document.querySelector('#inspect-network-map .netmap-svg');
      if (!svg) return { found: false };
      const nodes = [...svg.querySelectorAll('.netmap-node[data-addr]')];
      if (nodes.length < 2) return { found: true, nodeCount: nodes.length };
      const target = nodes[0];
      target.dispatchEvent(new MouseEvent('mouseover', { bubbles: true }));
      await new Promise(r => setTimeout(r, 60));
      const hoveredOpacity = target.style.opacity;
      const otherOpacities = nodes.slice(1).map(n => n.style.opacity);
      const mainNodeOpacity = svg.querySelector('.netmap-node--main')?.style.opacity;
      svg.dispatchEvent(new MouseEvent('mouseleave', { bubbles: true }));
      await new Promise(r => setTimeout(r, 60));
      const restoredOpacities = nodes.map(n => n.style.opacity);
      return { found: true, nodeCount: nodes.length, hoveredOpacity, otherOpacities, mainNodeOpacity, restoredOpacities };
    });

    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
    assert(result.found, 'expected the Counterparty Network Map to render for this known-active account');
    if (result.nodeCount >= 2) {
      assert(result.hoveredOpacity === '1', 'expected the hovered node to stay at full opacity');
      assert(result.otherOpacities.every(o => o !== '1'), `expected every unrelated node to dim, got: ${JSON.stringify(result.otherOpacities)}`);
      assert(result.mainNodeOpacity == null || result.mainNodeOpacity === '' || result.mainNodeOpacity === '1', 'expected the inspected account\'s own center node to never dim');
      assert(result.restoredOpacities.every(o => o === '1'), `expected all nodes to restore to full opacity on mouseleave, got: ${JSON.stringify(result.restoredOpacities)}`);
    }
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
