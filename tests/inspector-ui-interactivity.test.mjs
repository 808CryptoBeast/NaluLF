// Regression guard for the modern/interactive UI pass on the Inspector:
// (1) live status dots on the jump-nav that mirror each section's own
// already-computed badge severity, (2) a brief highlight confirming which
// card a jump-nav click landed on, (3) continuous crosshair hover-scrub on
// the Balance Reconstruction chart, and (4) hover-focus dimming on the
// Counterparty Network Map. All four are pure presentation layered over
// data the app already computes — no new analysis, no new RPC calls.
import { withPage, connectAndShowDashboard, inspectAddress, makeSuite, assert } from './helpers.mjs';

const suite = makeSuite('Inspector UI Interactivity');

suite.register('Jump-nav buttons show live status dots aggregating the WORST badge severity across every section the button now represents (Phase 2: one button covers several sections), with no page errors', async () => {
  await withPage(async (page, { pageErrors }) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, 'rnj7R3QUGzLZc9dg24jSrGabtt1tp1XD7A', { timeout: 90000 });
    await page.waitForTimeout(1500);

    const result = await page.evaluate(() => {
      const LEVEL_RANK = { crit: 3, warn: 2, ok: 1 };
      const levelOf = (badge) => {
        if (!badge) return null;
        if (badge.classList.contains('section-badge--crit')) return 'crit';
        if (badge.classList.contains('section-badge--warn')) return 'warn';
        if (badge.classList.contains('section-badge--ok')) return 'ok';
        return null;
      };
      const btns = [...document.querySelectorAll('#inspector-nav .in-btn[data-jump-key]')];
      const checks = btns.map((b) => {
        const sections = b.dataset.jumpSections.split(',');
        const levels = sections.map((s) => levelOf(document.getElementById('badge-' + s))).filter(Boolean);
        const expected = levels.length ? levels.reduce((worst, l) => LEVEL_RANK[l] > LEVEL_RANK[worst] ? l : worst) : null;
        const dot = b.querySelector('.in-status-dot');
        return { key: b.dataset.jumpKey, expected, actual: dot ? dot.className.replace('in-status-dot ', '').replace('in-status-dot--', '') : null };
      });
      return { totalDots: document.querySelectorAll('#inspector-nav .in-status-dot').length, checks };
    });
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
    assert(result.totalDots > 0, 'expected at least one nav status dot to render for this known-flagged account');
    for (const c of result.checks) {
      assert(c.actual === c.expected, `expected "${c.key}"'s dot to aggregate to "${c.expected}" (worst severity across its own sections' real badges), got "${c.actual}"`);
    }
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

// The old radial Network Map's hover-dim-unrelated-nodes interaction was
// retired along with the map itself (replaced by the Relationship
// Landscape — a ranked list has no equivalent "dim unrelated nodes"
// concept, since rows aren't connected by shared visual edges needing
// disambiguation). No replacement test: there's nothing left to regress.

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
