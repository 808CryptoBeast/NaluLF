// Regression coverage for "Full ARIA label coverage + keyboard navigation"
// (roadmap: UX) — second slice, following the modal-keyboard-accessibility
// work: icon-only buttons with no accessible name. Two shared patterns
// accounted for most of the app's real gaps:
//   1. The Inspector's jump-nav bar and the risk banner's Watch/Compare
//      buttons visually hide their text label via CSS at narrow widths
//      (inspector.css's .in-label/.irb-btn-label collapse), leaving a bare,
//      sometimes-ambiguous emoji with no aria-label. Fixed by deriving
//      aria-label from each button's own visible label text at render time
//      (jump-nav), and keeping aria-label in sync with the dynamically-
//      toggled title text (Watch/Compare). The jump-nav originally held
//      ~30 individual per-detector buttons; Phase 2 of the Inspector 6.1
//      redesign consolidated those into 11 workspace/tool buttons plus a
//      Guide button (12 total) — the aria-label derivation itself is
//      unchanged and still covers every one of them.
//   2. Nine near-identical modal-close "✕" buttons across profile.js/
//      index.html had no aria-label at all.
import { withPage, connectAndShowDashboard, inspectAddress, assert } from './helpers.mjs';

const suite = { register: [], run: async () => {
  let pass = 0, fail = 0;
  console.log('\n▶ Icon Button ARIA Labels');
  for (const { name, fn } of suite.register) {
    try { await fn(); console.log(`  PASS  ${name}`); pass++; }
    catch (err) { console.log(`  FAIL  ${name}`); console.log(`        ${err?.stack || err}`); fail++; }
  }
  return { pass, fail, total: suite.register.length };
}};
const test = (name, fn) => suite.register.push({ name, fn });

const SOLO_ISSUER = 'rsoLo2S1kiGeCcn6hCUXVrCpGMWLrRrLZz';

test('Inspector jump-nav: every button carries an aria-label matching its own visible label text, and the Watch/Compare buttons are correctly labeled (including the Watch toggle state)', async () => {
  await withPage(async (page, { pageErrors }) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, SOLO_ISSUER, { timeout: 90000 });

    const navCheck = await page.evaluate(() => {
      const btns = [...document.querySelectorAll('.in-btn')];
      const mismatches = btns.filter(b => {
        const visible = b.querySelector('.in-label')?.textContent?.trim();
        const aria = b.getAttribute('aria-label');
        return visible && aria !== visible;
      }).map(b => ({ jump: b.dataset.jump, visible: b.querySelector('.in-label')?.textContent, aria: b.getAttribute('aria-label') }));
      return { total: btns.length, mismatches };
    });
    assert(navCheck.total === 12, `expected the consolidated 12-button jump-nav (11 workspace/tool buttons + Guide) to be present, got ${navCheck.total}`);
    assert(navCheck.mismatches.length === 0, `expected every jump-nav button's aria-label to match its own visible text (this derivation keeps them in sync even if a label is renamed), mismatches: ${JSON.stringify(navCheck.mismatches)}`);

    const watchInitial = await page.evaluate(() => document.getElementById('watchlist-btn')?.getAttribute('aria-label'));
    assert(watchInitial === 'Add to watchlist', `expected the Watch button's initial aria-label to be "Add to watchlist", got "${watchInitial}"`);

    await page.evaluate(() => document.getElementById('watchlist-btn')?.click());
    await page.waitForTimeout(100);
    const watchAfterClick = await page.evaluate(() => document.getElementById('watchlist-btn')?.getAttribute('aria-label'));
    assert(watchAfterClick === 'Remove from watchlist', `expected the aria-label to flip to "Remove from watchlist" after toggling watch state, got "${watchAfterClick}"`);

    const compareAria = await page.evaluate(() => [...document.querySelectorAll('.irb-copy-btn')].find(b => b.textContent.includes('Compare'))?.getAttribute('aria-label'));
    assert(compareAria === 'Compare against another account', `expected the Compare button's aria-label, got "${compareAria}"`);

    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

test('Wallet-flow modal close buttons (Send, Wallet Creator) carry aria-label="Close", representative of the 9 fixed instances', async () => {
  await withPage(async (page, { pageErrors }) => {
    await connectAndShowDashboard(page);
    await page.evaluate(() => window.showProfile());
    await page.waitForTimeout(500);

    const sendCloseAria = await page.evaluate(() => {
      document.getElementById('send-modal-overlay')?.classList.add('show');
      return document.querySelector('#send-modal-overlay .modal-close')?.getAttribute('aria-label');
    });
    assert(sendCloseAria === 'Close', `expected the Send modal's close button to have aria-label="Close", got "${sendCloseAria}"`);

    const walletCreatorCloseAria = await page.evaluate(() => {
      document.querySelector('.wallet-creator-overlay, #wallet-creator-overlay')?.classList.add('show');
      return document.querySelector('.wallet-creator-box .modal-close')?.getAttribute('aria-label');
    });
    assert(walletCreatorCloseAria === 'Close', `expected the Wallet Creator's close button to have aria-label="Close", got "${walletCreatorCloseAria}"`);

    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
