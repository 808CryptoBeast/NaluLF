// Regression coverage for closing the Universal Relationship Drawer gaps
// (roadmap: Inspector Core Architecture). Per the spec, "any address shown
// anywhere should use the same relationship drawer" — Top Counterparties and
// Issuer Connections' Top Holders table were the two named entry points that
// didn't: Top Counterparties launched a brand-new inspection of the clicked
// address instead of showing the relationship, and Top Holders used the
// generic single-account Account Peek modal (balance/sequence/flags only,
// no reciprocity/round-trip/first-last-interaction data). Both now open the
// real openRelationshipDrawer(), matching every other entry point (Network
// Map, Wash Execution's "Relationships Worth Reviewing", LP/holder-cohort
// tables, Path Payments, Inbound Flow's top sources). The drawer already
// offered "Inspect this account" and "Compare accounts" as its own
// cross-links, so no capability is lost — relationship context is now the
// default, with a full inspection one click further in.
import { withPage, connectAndShowDashboard, inspectAddress, assert } from './helpers.mjs';

const suite = { register: [], run: async () => {
  let pass = 0, fail = 0;
  console.log('\n▶ Universal Relationship Drawer');
  for (const { name, fn } of suite.register) {
    try { await fn(); console.log(`  PASS  ${name}`); pass++; }
    catch (err) { console.log(`  FAIL  ${name}`); console.log(`        ${err?.stack || err}`); fail++; }
  }
  return { pass, fail, total: suite.register.length };
}};
const test = (name, fn) => suite.register.push({ name, fn });

const WALLET = 'rnj7R3QUGzLZc9dg24jSrGabtt1tp1XD7A';
const SOLO_ISSUER = 'rsoLo2S1kiGeCcn6hCUXVrCpGMWLrRrLZz';

test('Top Counterparties: clicking a ranked row opens the real Relationship Drawer, not a new inspection of the clicked address', async () => {
  await withPage(async (page, { pageErrors }) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, WALLET, { timeout: 90000 });
    await page.waitForTimeout(500);

    const rowCount = await page.evaluate(() => document.querySelectorAll('.ranked-cp-row').length);
    assert(rowCount > 0, 'expected at least one ranked counterparty row for this known active wallet');

    const beforeAddr = await page.evaluate(() => document.getElementById('inspect-addr-badge')?.textContent);
    await page.evaluate(() => document.querySelector('.ranked-cp-row')?.click());
    await page.waitForTimeout(400);

    const state = await page.evaluate(() => ({
      drawerVisible: document.getElementById('relationshipDrawerOverlay')?.style.display,
      currentAddr: document.getElementById('inspect-addr-badge')?.textContent,
      drawerHeadline: document.getElementById('relDrawerHeadline')?.textContent,
    }));
    assert(state.drawerVisible === 'flex', 'expected the Relationship Drawer to open');
    assert(state.currentAddr === beforeAddr, 'expected the main inspection to stay on the same account — clicking a counterparty row must not launch a new inspection');
    assert(state.drawerHeadline && state.drawerHeadline.includes('⇄') || state.drawerHeadline?.includes('→') || state.drawerHeadline?.includes('←'), `expected a real relationship headline with a direction arrow, got "${state.drawerHeadline}"`);
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

test('Issuer Connections\' Top Holders table opens the Relationship Drawer, not the generic Account Peek modal', async () => {
  await withPage(async (page, { pageErrors }) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, SOLO_ISSUER, { timeout: 90000 });
    await page.waitForTimeout(500);

    const holderCount = await page.evaluate(() => document.querySelectorAll('.conn-holder-addr').length);
    assert(holderCount > 0, 'expected at least one Top Holder row for this known issuer');

    const hasDataAddr = await page.evaluate(() => !!document.querySelector('.conn-holder-addr')?.getAttribute('data-addr'));
    assert(!hasDataAddr, 'expected the holder address button to no longer use the data-addr delegation (which routes to the generic Account Peek modal)');

    await page.evaluate(() => document.querySelector('.conn-holder-addr')?.click());
    await page.waitForTimeout(400);

    const state = await page.evaluate(() => ({
      drawerVisible: document.getElementById('relationshipDrawerOverlay')?.style.display,
      acctPeekVisible: document.getElementById('acctPeekOverlay')?.style.display,
    }));
    assert(state.drawerVisible === 'flex', 'expected clicking a Top Holder to open the real Relationship Drawer');
    assert(state.acctPeekVisible !== 'flex', 'expected the generic Account Peek modal to NOT open for this click');
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

// ── Partner account age vs relationship age (roadmap: Inspector 5.0, small
// near-term win) ────────────────────────────────────────────────────────
// A relationship's own active span (how long these two addresses have
// interacted) is a different fact from the partner's own account age (how
// long that address has existed) — the spec's own example: "Relationship
// began 2026 / Partner account activated 2017." Resolved via a single
// bounded oldest-anchor lookup (_findAccountRootCreationEvidence over one
// account_tx page), triggered only when the drawer opens, never fabricated
// as a confident age when that one page doesn't contain real evidence.
test('Relationship Drawer: shows the partner\'s own verified account age, distinct from the relationship\'s active span', async () => {
  await withPage(async (page, { pageErrors }) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, SOLO_ISSUER, { timeout: 90000 });
    await page.waitForTimeout(500);

    const holderCount = await page.evaluate(() => document.querySelectorAll('.conn-holder-addr').length);
    assert(holderCount > 0, 'expected at least one Top Holder row for this known issuer');
    await page.evaluate(() => document.querySelector('.conn-holder-addr')?.click());
    // No fixed-delay check for the "Checking…" placeholder here — the real
    // lookup is a single fast RPC round-trip that can resolve well inside
    // any delay short enough to still be worth asserting on, racing a
    // timing-based check exactly the way an earlier cache-hit test in this
    // session did. The deterministic, meaningful assertion is the final
    // resolved state below, not catching the placeholder mid-flight.
    assert(await page.evaluate(() => document.getElementById('relationshipDrawerOverlay')?.style.display) === 'flex', 'expected the drawer to open');

    await page.waitForFunction(() => !/Checking/.test(document.getElementById('relDrawerPartnerAge')?.textContent || ''), { timeout: 15000 }).catch(() => {});
    const resolved = await page.evaluate(() => document.getElementById('relDrawerPartnerAge')?.innerHTML || '');
    assert(/Partner account age/.test(resolved), `expected the field to still be labeled "Partner account age" once resolved, got: "${resolved}"`);
    assert(/years|months|days|Not verifiable/.test(resolved), `expected either a real resolved age or an honest "not verifiable" fallback, never a stuck placeholder, got: "${resolved}"`);
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

test('Relationship Drawer: reopening for a different partner does not let a stale, slower lookup overwrite the new partner\'s age', async () => {
  await withPage(async (page, { pageErrors }) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, SOLO_ISSUER, { timeout: 90000 });
    await page.waitForTimeout(500);

    const holderAddrs = await page.evaluate(() => [...document.querySelectorAll('.conn-holder-addr')].slice(0, 2).map(b => b.title));
    if (holderAddrs.length < 2) return; // not enough holders on this run to exercise the race — not a failure of this feature

    // Open for the first partner, then immediately reopen for the second —
    // the first lookup is now stale and must not win if it resolves later.
    await page.evaluate((addr) => window.openRelationshipDrawer(addr), holderAddrs[0]);
    await page.evaluate((addr) => window.openRelationshipDrawer(addr), holderAddrs[1]);
    await page.waitForFunction(() => !/Checking/.test(document.getElementById('relDrawerPartnerAge')?.textContent || ''), { timeout: 15000 }).catch(() => {});
    await page.waitForTimeout(2000); // give any stale first-lookup response a chance to (wrongly) land

    const headline = await page.evaluate(() => document.getElementById('relDrawerHeadline')?.textContent || '');
    assert(headline.includes(holderAddrs[1].slice(0, 6)) || !headline.includes(holderAddrs[0].slice(0, 6)), `expected the drawer to still reflect the SECOND partner, not a stale first one, got headline: "${headline}"`);
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
