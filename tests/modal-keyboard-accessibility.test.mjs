// Regression coverage for "Full ARIA label coverage + keyboard navigation"
// (roadmap: UX) — first slice: the app's shared .acct-peek-overlay/
// .acct-peek-box dialog shell (Account Peek, Evidence Inspector, Compare,
// Relationship Drawer, Transaction Detail Drawer) already had role="dialog"/
// aria-modal/aria-label statically, but none of them supported Escape-to-
// close, Tab/Shift+Tab focus trapping, or returning focus to whatever
// triggered the open — a plain display:none/flex toggle with no focus
// management strands keyboard and screen-reader users. Fixed via one shared
// `bindOverlayA11y()` helper in utils.js, wired into each modal's existing
// open()/close() functions. Covers Account Peek (dashboard.js) and the
// Evidence Inspector + Transaction Detail Drawer (inspector.js) directly,
// since the Compare modal and Relationship Drawer share the exact same
// helper and HTML shell already proven working in both of those files.
import { withPage, connectAndShowDashboard, inspectAddress, assert } from './helpers.mjs';

const suite = { register: [], run: async () => {
  let pass = 0, fail = 0;
  console.log('\n▶ Modal Keyboard Accessibility');
  for (const { name, fn } of suite.register) {
    try { await fn(); console.log(`  PASS  ${name}`); pass++; }
    catch (err) { console.log(`  FAIL  ${name}`); console.log(`        ${err?.stack || err}`); fail++; }
  }
  return { pass, fail, total: suite.register.length };
}};
const test = (name, fn) => suite.register.push({ name, fn });

const SOLO_ISSUER = 'rsoLo2S1kiGeCcn6hCUXVrCpGMWLrRrLZz';

test('Account Peek: opening moves focus to the close button, Shift+Tab wraps to the last focusable element, and Escape closes and restores focus to the trigger', async () => {
  await withPage(async (page, { pageErrors }) => {
    await connectAndShowDashboard(page);

    await page.evaluate(() => {
      const btn = document.createElement('button');
      btn.id = 'testTrigger';
      btn.textContent = 'trigger';
      document.body.appendChild(btn);
      btn.focus();
    });

    await page.evaluate(() => {
      const chip = document.createElement('button');
      chip.setAttribute('data-addr', 'rPVMhWBsfF9iMXYj3aAzJVkPDTFNSyWdKy');
      chip.textContent = 'addr chip';
      document.body.appendChild(chip);
      chip.click();
    });
    await page.waitForTimeout(200);

    const afterOpen = await page.evaluate(() => ({
      activeId: document.activeElement?.id,
      overlayVisible: document.getElementById('acctPeekOverlay')?.style.display,
    }));
    assert(afterOpen.overlayVisible === 'flex', 'expected the overlay to be visible after opening');
    assert(afterOpen.activeId === 'acctPeekClose', `expected focus on the close button, got id="${afterOpen.activeId}"`);

    await page.keyboard.down('Shift');
    await page.keyboard.press('Tab');
    await page.keyboard.up('Shift');
    const afterShiftTab = await page.evaluate(() => document.activeElement?.id);
    assert(afterShiftTab !== 'acctPeekClose', 'expected Shift+Tab from the first focusable element to wrap to the last, not stay put');

    await page.keyboard.press('Escape');
    await page.waitForTimeout(200);
    const afterEscape = await page.evaluate(() => ({
      activeId: document.activeElement?.id,
      overlayVisible: document.getElementById('acctPeekOverlay')?.style.display,
    }));
    assert(afterEscape.overlayVisible === 'none', 'expected Escape to close the overlay');
    assert(afterEscape.activeId === 'testTrigger', `expected focus restored to the original trigger, got id="${afterEscape.activeId}"`);
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

test('Evidence Inspector and Transaction Detail Drawer: same open/trap/Escape/focus-restore contract holds for inspector.js-owned modals', async () => {
  await withPage(async (page, { pageErrors }) => {
    await connectAndShowDashboard(page);
    await page.evaluate(() => {
      const btn = document.createElement('button');
      btn.id = 'testTrigger';
      btn.textContent = 'trigger';
      document.body.appendChild(btn);
      btn.focus();
    });

    await inspectAddress(page, SOLO_ISSUER, { timeout: 90000 });
    const hasFindings = await page.evaluate(() => (window._lastAllFindings || []).length > 0);
    assert(hasFindings, 'expected at least one finding to open the Evidence Inspector against');

    await page.evaluate(() => document.getElementById('testTrigger')?.focus());
    await page.evaluate(() => window.openEvidenceInspector(0));
    await page.waitForTimeout(200);
    const evAfterOpen = await page.evaluate(() => ({
      activeId: document.activeElement?.id,
      overlayVisible: document.getElementById('evidenceInspectorOverlay')?.style.display,
    }));
    assert(evAfterOpen.overlayVisible === 'flex', 'expected the Evidence Inspector overlay to be visible');
    assert(evAfterOpen.activeId === 'evInspectorClose', `expected focus on the close button, got id="${evAfterOpen.activeId}"`);

    await page.keyboard.press('Escape');
    await page.waitForTimeout(200);
    const evAfterEscape = await page.evaluate(() => ({
      activeId: document.activeElement?.id,
      overlayVisible: document.getElementById('evidenceInspectorOverlay')?.style.display,
    }));
    assert(evAfterEscape.overlayVisible === 'none', 'expected Escape to close the Evidence Inspector overlay');
    assert(evAfterEscape.activeId === 'testTrigger', `expected focus restored to the trigger, got id="${evAfterEscape.activeId}"`);

    const txHash = await page.evaluate(() => (window._lastTxList || [])[0]?.tx?.hash);
    assert(txHash, 'expected at least one transaction to test the Transaction Detail Drawer with');

    await page.evaluate(() => document.getElementById('testTrigger')?.focus());
    await page.evaluate((h) => window.openTxDetailDrawer(h), txHash);
    await page.waitForTimeout(200);
    const txAfterOpen = await page.evaluate(() => ({
      activeId: document.activeElement?.id,
      overlayVisible: document.getElementById('txDetailOverlay')?.style.display,
    }));
    assert(txAfterOpen.overlayVisible === 'flex', 'expected the Tx Detail overlay to be visible');
    assert(txAfterOpen.activeId === 'txDetailClose', `expected focus on the close button, got id="${txAfterOpen.activeId}"`);

    // 4 focusable elements: close + 3 tabs — Tab 4 times should wrap back to close.
    for (let i = 0; i < 4; i++) await page.keyboard.press('Tab');
    const afterFourTabs = await page.evaluate(() => document.activeElement?.id);
    assert(afterFourTabs === 'txDetailClose', `expected focus to wrap back to the close button after cycling all 4 focusable elements, got id="${afterFourTabs}"`);

    await page.keyboard.press('Escape');
    await page.waitForTimeout(200);
    const txAfterEscape = await page.evaluate(() => ({
      activeId: document.activeElement?.id,
      overlayVisible: document.getElementById('txDetailOverlay')?.style.display,
    }));
    assert(txAfterEscape.overlayVisible === 'none', 'expected Escape to close the Tx Detail overlay');
    assert(txAfterEscape.activeId === 'testTrigger', `expected focus restored to the trigger, got id="${txAfterEscape.activeId}"`);
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
