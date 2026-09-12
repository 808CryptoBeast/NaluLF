// Regression guard for the Counterparty Network Map's node-size metric
// toggle (Volume vs. Tx Count). Volume-only sizing hides a real pattern —
// a spam/dust-memo target can have a huge transaction count but negligible
// XRP amounts and would look like the smallest node on the map. This
// guards: the toggle actually changes rendered node radii, the SAME set of
// nodes is shown regardless of metric (only size changes), and the active
// button / legend text stay in sync with the current metric.
import { withPage, connectAndShowDashboard, inspectAddress, makeSuite, assert } from './helpers.mjs';

// Bitstamp's hot wallet, not CULT — this test only needs a real, active
// account with a satellite-node-heavy network map (no issuer-specific
// requirement), and spreading live-RPC load across more real accounts
// means a single account's rate-limiting can't take out many test files
// in the same run (CULT alone backed 9 different test files).
const REAL_ACTIVE_ACCOUNT = 'rPVMhWBsfF9iMXYj3aAzJVkPDTFNSyWdKy';

const suite = makeSuite('Network Map — Node Size Metric Toggle');

suite.register('Toggling Volume -> Tx Count changes node radii, keeps the same node set, and updates the active button + legend', async () => {
  await withPage(async (page) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, REAL_ACTIVE_ACCOUNT, { timeout: 90000 });
    // This is an exchange hot wallet with a very large real transaction
    // volume; confirmed live that 3.5s was too short for its network map to
    // finish rendering (toggle buttons not yet mounted), while 6s reliably
    // settles.
    await page.waitForTimeout(6000);

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
