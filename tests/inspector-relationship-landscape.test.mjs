// Regression coverage for the Relationship Intelligence — Landscape view,
// which replaced the old radial bubble "Network Map" and the separate
// "Top Counterparties" ranked list as the live Account Overview display
// (per the Inspector 6.1 spec §31/§45: the bubble graph poorly
// communicated direction, role, and relative importance, and must not
// remain the default). Reuses the exact same canonical
// _buildCounterpartyData/_cpVolume/getEntity data both of those already
// used — see inspector-counterparty-volume.test.mjs for the data-layer
// coverage, which is untouched by this change. renderNetworkMap/
// buildRankedCounterpartyList themselves are kept intact (the Full Report
// still calls buildRankedCounterpartyList directly) — only the live
// Overview mount changed.
import { withPage, connectAndShowDashboard, inspectAddress, assert } from './helpers.mjs';

const suite = { register: [], run: async () => {
  let pass = 0, fail = 0;
  console.log('\n▶ Relationship Landscape');
  for (const { name, fn } of suite.register) {
    try { await fn(); console.log(`  PASS  ${name}`); pass++; }
    catch (err) { console.log(`  FAIL  ${name}`); console.log(`        ${err?.stack || err}`); fail++; }
  }
  return { pass, fail, total: suite.register.length };
}};
const test = (name, fn) => suite.register.push({ name, fn });

const ADDR = 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh';

test('A real active account renders a directional landscape (inbound/outbound columns around a target badge) plus semantic lanes, with no page errors', async () => {
  await withPage(async (page, { pageErrors }) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, ADDR, { timeout: 60000 });

    const check = await page.evaluate(() => {
      const el = document.getElementById('inspect-relationship-landscape');
      return {
        found: !!el,
        oldNetmapGone: !document.getElementById('inspect-network-map'),
        oldTopCpGone: !document.getElementById('inspect-top-counterparties'),
        columnCount: el?.querySelectorAll('.rel-landscape-col').length,
        targetBadge: el?.querySelector('.rel-landscape-target-badge')?.textContent,
        rowCount: el?.querySelectorAll('.ranked-cp-row').length,
        laneLabels: [...el?.querySelectorAll('.rel-landscape-lane-label') || []].map(e => e.textContent),
        hasVerifiedNote: /verified/i.test(el?.innerHTML || ''),
      };
    });

    assert(check.found, 'expected #inspect-relationship-landscape to render');
    assert(check.oldNetmapGone && check.oldTopCpGone, 'expected the old bubble graph and ranked-list mounts to no longer exist in the live DOM');
    assert(check.columnCount === 2, `expected exactly 2 columns (inbound/outbound), got ${check.columnCount}`);
    assert(check.targetBadge && check.targetBadge.length > 0, 'expected a target account badge in the center');
    assert(check.rowCount > 0, 'expected at least one counterparty row for a real active account');
    assert(check.laneLabels.includes('Token / Issuer') && check.laneLabels.includes('Known Services') && check.laneLabels.includes('Possible Clusters'), `expected all 3 semantic lanes, got: ${JSON.stringify(check.laneLabels)}`);
    assert(check.hasVerifiedNote, 'expected an explicit note that relationships shown are verified direct transfers');
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

test('"Show All" expands beyond the default 6-per-column cap, and "Show Fewer" collapses back — state resets on a fresh inspection', async () => {
  await withPage(async (page, { pageErrors }) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, ADDR, { timeout: 60000 });

    const before = await page.evaluate(() => document.querySelectorAll('#inspect-relationship-landscape .ranked-cp-row').length);
    await page.evaluate(() => document.querySelector('.rel-landscape-showall')?.click());
    await page.waitForTimeout(300);
    const afterExpand = await page.evaluate(() => ({
      rowCount: document.querySelectorAll('#inspect-relationship-landscape .ranked-cp-row').length,
      btnText: document.querySelector('.rel-landscape-showall')?.textContent,
    }));
    assert(afterExpand.rowCount >= before, `expected expanding to show at least as many rows, got ${before} -> ${afterExpand.rowCount}`);
    assert(afterExpand.btnText === 'Show Fewer', `expected the button to flip to "Show Fewer", got "${afterExpand.btnText}"`);

    await page.evaluate(() => document.querySelector('.rel-landscape-showall')?.click());
    await page.waitForTimeout(300);
    const afterCollapse = await page.evaluate(() => document.querySelectorAll('#inspect-relationship-landscape .ranked-cp-row').length);
    assert(afterCollapse === before, `expected collapsing back to the original row count, got ${before} -> ${afterCollapse}`);

    // Re-inspecting the same account must not carry the expanded state over.
    await inspectAddress(page, ADDR, { timeout: 60000 });
    const afterReinspect = await page.evaluate(() => document.querySelector('.rel-landscape-showall')?.textContent);
    assert(afterReinspect !== 'Show Fewer', 'expected the "show all" state to reset on a fresh inspection, not carry over from the previous one');
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

test('Clicking a row opens the real Relationship Drawer with real gross/net stats (same shared drawer every other counterparty surface uses)', async () => {
  await withPage(async (page, { pageErrors }) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, ADDR, { timeout: 60000 });

    await page.evaluate(() => document.querySelector('#inspect-relationship-landscape .ranked-cp-row')?.click());
    await page.waitForTimeout(500);
    const state = await page.evaluate(() => ({
      drawerVisible: document.getElementById('relationshipDrawerOverlay')?.style.display,
      headline: document.getElementById('relDrawerHeadline')?.textContent,
    }));
    assert(state.drawerVisible === 'flex', 'expected the Relationship Drawer to open on row click');
    assert(state.headline && state.headline.length > 0, 'expected a real relationship headline');
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
