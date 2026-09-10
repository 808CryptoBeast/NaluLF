// Regression guard for the Counterparty Network Map's node-size metric
// toggle (Volume vs. Tx Count). Volume-only sizing hides a real pattern —
// a spam/dust-memo target can have a huge transaction count but negligible
// XRP amounts and would look like the smallest node on the map. This
// guards: the toggle actually changes rendered node radii, the SAME set of
// nodes is shown regardless of metric (only size changes), and the active
// button / legend text stay in sync with the current metric.
import { withPage, connectAndShowDashboard, inspectAddress, makeSuite, assert } from './helpers.mjs';

const REAL_ACTIVE_ISSUER = 'rCULtAKrKbQjk1Tpmg5hkw4dpcf9S9KCs';

const suite = makeSuite('Network Map — Node Size Metric Toggle');

suite.register('Toggling Volume -> Tx Count changes node radii, keeps the same node set, and updates the active button + legend', async () => {
  await withPage(async (page) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, REAL_ACTIVE_ISSUER, { timeout: 90000 });
    // This account has a very large fetched history; other suites this
    // session bumped their waits to 3-4s for the same reason — 1.5s was
    // marginal and occasionally raced the render under full-suite load.
    await page.waitForTimeout(3500);

    const readState = () => page.evaluate(() => {
      const el = document.getElementById('inspect-network-map');
      const groups = [...el.querySelectorAll('svg g[onclick]')];
      // Each node group's last circle is always one of the two real-size
      // (fill+stroke) circles sharing the node's actual radius — robust
      // regardless of whether an extra blackhole "glow ring" circle
      // (a different, offset radius) precedes it.
      const radii = groups.map(g => Number([...g.querySelectorAll('circle[r]')].pop()?.getAttribute('r')));
      return {
        activeBtn: el.querySelector('.netmap-size-btn.active')?.textContent,
        radii,
        nodeIds: groups.map(g => g.getAttribute('onclick')),
        legendText: [...el.querySelectorAll('span')].map(s => s.textContent).find(t => t.includes('Node size')),
      };
    });

    const before = await readState();
    assert(before.activeBtn === 'Size: Volume', `expected Volume to be the default active metric, got "${before.activeBtn}"`);
    assert(/value moved/.test(before.legendText || ''), `expected legend to describe value-moved sizing by default: ${before.legendText}`);
    assert(before.radii.length > 0, 'expected at least one satellite node to compare radii against');

    await page.click('.netmap-size-btn:has-text("Tx Count")');
    await page.waitForTimeout(300);
    const after = await readState();

    assert(after.activeBtn === 'Size: Tx Count', `expected Tx Count to become active after clicking it, got "${after.activeBtn}"`);
    assert(/transaction count/.test(after.legendText || ''), `expected legend to switch to "transaction count": ${after.legendText}`);
    assert(JSON.stringify(after.nodeIds) === JSON.stringify(before.nodeIds), 'the exact same set of nodes (by click handler / address) must appear regardless of size metric');
    assert(JSON.stringify(after.radii) !== JSON.stringify(before.radii), 'expected at least some node radii to actually change when switching size metric');
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
