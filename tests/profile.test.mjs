// Regression guard for the wallet-drawer preservation fix: renderProfilePage()
// used to wipe an expanded wallet drawer's real content back to a permanent
// "Loading…" spinner on almost every re-render (including the ~5s live-
// ledger tick), because #profile-tab-wallets lives inside the same `wrap`
// that gets wholesale-replaced. Verifies the fix survives both that
// wholesale-rebuild path and a direct renderWalletList()-only call.
import { withPage, freshSignup, connectAndShowDashboard, makeSuite, assert } from './helpers.mjs';

const SOLO_ISSUER = 'rsoLo2S1kiGeCcn6hCUXVrCpGMWLrRrLZz'; // real account, moderate tx history — loads reasonably fast

const suite = makeSuite('Profile — Wallet Drawer Preservation');

suite.register('An expanded wallet drawer with real content survives both renderProfilePage()\'s rebuild and a direct renderWalletList() call', async () => {
  await withPage(async (page) => {
    const ok = await freshSignup(page, { name: 'Drawer Test User', email: 'drawertest@example.com', domain: 'drawertest' });
    assert(ok, 'signup failed');

    await connectAndShowDashboard(page);
    await page.evaluate(() => window.showProfile());
    await page.waitForFunction(() => document.querySelector('#profile-page .profile-wrap'), { timeout: 10000 });

    await page.evaluate((addr) => {
      window.openImportAddressModal();
      document.getElementById('inp-import-address').value = addr;
      window.importWatchOnlyWallet();
    }, SOLO_ISSUER);
    await page.waitForTimeout(600);

    const walletId = await page.evaluate(() => {
      const btn = document.querySelector('.wcard-btn--expand');
      return btn?.getAttribute('onclick')?.match(/toggleWalletDrawer\('([^']+)'\)/)?.[1] || null;
    });
    assert(walletId, 'no wallet card with an expand button found — import may have failed');

    await page.evaluate((id) => window.toggleWalletDrawer(id), walletId);
    // Real live-RPC fetch of this account's tx history — timing varies run
    // to run, more so when other suites' live XRPL calls are contending for
    // the same public node around the same time. 40s is generous headroom,
    // not a claim about typical latency.
    await page.waitForFunction(
      (id) => { const b = document.getElementById(`wcard-drawer-body-${id}`); return b && !b.querySelector('.wdd-loading'); },
      walletId,
      { timeout: 40000 }
    );

    const before = await page.evaluate((id) => document.getElementById(`wcard-drawer-body-${id}`)?.innerHTML, walletId);
    assert(before && !before.includes('wdd-loading'), 'drawer never loaded real content to begin with');

    // Path 1: refreshWalletCard() -> renderWalletList() called directly.
    await page.evaluate((addr) => window.refreshWalletCard(addr), SOLO_ISSUER);
    await page.waitForTimeout(400);
    const afterDirectCall = await page.evaluate((id) => document.getElementById(`wcard-drawer-body-${id}`)?.innerHTML, walletId);
    assert(afterDirectCall === before, 'drawer content was wiped by a direct renderWalletList() call (refreshWalletCard)');

    // Path 2: filterWallets() -> also renderWalletList() directly, and
    // exercises the window.filterWallets wiring fix (it wasn't exposed on
    // window at all before this session's profile.js pass).
    await page.evaluate(() => window.filterWallets(''));
    await page.waitForTimeout(400);
    const afterFilter = await page.evaluate((id) => document.getElementById(`wcard-drawer-body-${id}`)?.innerHTML, walletId);
    assert(afterFilter === before, 'drawer content was wiped by filterWallets()');
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
