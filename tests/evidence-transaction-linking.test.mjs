// Regression coverage for "Evidence linking" — Finding -> Transaction ->
// Raw JSON (roadmap: Inspector Core Architecture, Phase 1 slice). Before
// this, ~38 of ~40 detectors never populated a finding's `hashes` field, and
// even where populated (Fee Spike, Flow Motifs), neither the Evidence Matrix
// nor the Evidence Inspector ever rendered it — there was no way to get from
// a forensic claim to the real transaction behind it without leaving the
// app. Fixed via a shared `_evidenceHashChips()` renderer wired into both
// `auditRow` and `findingRow` (so every one of the ~12 inline panels that
// reuse findingRow picks this up automatically, not just the Evidence
// Matrix/Inspector), clicking a chip calls the new `window.openTxEvidence`,
// which closes the Evidence Inspector (if open) and opens the real,
// pre-existing Transaction Detail Drawer via `openTxDetailDrawer(hash)`.
// Also retrofits real `hashes` population into Drain Risk (episode
// transactions), Fund Flow (per-destination payments), Security (the
// SetRegularKey tx behind a "key set recently" finding), and Wash
// Execution's round-trip finding (both legs of its strongest-quality pair).
import { withPage, connectAndShowDashboard, inspectAddress, assert } from './helpers.mjs';

const suite = { register: [], run: async () => {
  let pass = 0, fail = 0;
  console.log('\n▶ Evidence Transaction Linking');
  for (const { name, fn } of suite.register) {
    try { await fn(); console.log(`  PASS  ${name}`); pass++; }
    catch (err) { console.log(`  FAIL  ${name}`); console.log(`        ${err?.stack || err}`); fail++; }
  }
  return { pass, fail, total: suite.register.length };
}};
const test = (name, fn) => suite.register.push({ name, fn });

const DRAIN_WALLET = 'rnj7R3QUGzLZc9dg24jSrGabtt1tp1XD7A';

test('A real drain-episode wallet produces findings with real transaction hashes, clickable from the Evidence Inspector straight through to the real Transaction Detail Drawer', async () => {
  await withPage(async (page, { pageErrors }) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, DRAIN_WALLET, { timeout: 90000 });

    const findingsWithHashes = await page.evaluate(() => (window._lastAllFindings || [])
      .map((f, idx) => ({ idx, module: f.module, hashes: f.hashes || [] }))
      .filter(f => f.hashes.length > 0));
    assert(findingsWithHashes.length > 0, 'expected at least one finding with real transaction hashes for this known drain-episode wallet');
    assert(findingsWithHashes.some(f => f.module === 'Asset Drain Behavior'), 'expected Drain Risk findings specifically to carry hashes now');

    const target = findingsWithHashes.find(f => f.module === 'Asset Drain Behavior');
    await page.evaluate((idx) => window.openEvidenceInspector(idx), target.idx);
    await page.waitForTimeout(300);

    const inspectorState = await page.evaluate(() => {
      const overlay = document.getElementById('evidenceInspectorOverlay');
      const chips = [...document.querySelectorAll('#evInspectorDetail .audit-hash-chip')];
      return { visible: overlay?.style.display, chipCount: chips.length };
    });
    assert(inspectorState.visible === 'flex', 'expected the Evidence Inspector to open');
    assert(inspectorState.chipCount > 0, 'expected at least one hash chip rendered in the Evidence Inspector');

    await page.evaluate(() => document.querySelector('#evInspectorDetail .audit-hash-chip')?.click());
    await page.waitForTimeout(400);

    const drawerState = await page.evaluate((expectedHash) => ({
      evInspectorClosed: document.getElementById('evidenceInspectorOverlay')?.style.display === 'none',
      txDrawerVisible: document.getElementById('txDetailOverlay')?.style.display,
      matchesExpected: document.getElementById('txDetailHash')?.textContent === expectedHash,
      summaryHasContent: (document.getElementById('txDetailBody')?.textContent?.length || 0) > 20,
    }), target.hashes[0]);
    assert(drawerState.evInspectorClosed, 'expected clicking a hash chip to close the Evidence Inspector first, not stack two overlays');
    assert(drawerState.txDrawerVisible === 'flex', 'expected the real Transaction Detail Drawer to open');
    assert(drawerState.matchesExpected, 'expected the drawer to show the exact transaction hash that was clicked');
    assert(drawerState.summaryHasContent, 'expected the drawer to render real transaction summary content, not a blank panel');
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

test('The same hash chips render inline wherever findingRow is used directly in a section panel, not only inside the Evidence Matrix/Inspector', async () => {
  await withPage(async (page, { pageErrors }) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, DRAIN_WALLET, { timeout: 90000 });
    await page.waitForTimeout(500);

    const inlineChips = await page.evaluate(() => {
      const section = document.getElementById('section-drain');
      return section ? section.querySelectorAll('.audit-hash-chip').length : -1;
    });
    assert(inlineChips > 0, `expected the inline Drain Risk panel (rendered via findingRow directly, not the Evidence Matrix) to show real hash chips, got ${inlineChips}`);
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
