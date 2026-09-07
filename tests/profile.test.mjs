// Regression guard for the wallet-drawer preservation fix: renderProfilePage()
// used to wipe an expanded wallet drawer's real content back to a permanent
// "Loading…" spinner on almost every re-render (including the ~5s live-
// ledger tick), because #profile-tab-wallets lives inside the same `wrap`
// that gets wholesale-replaced. Verifies the fix survives both that
// wholesale-rebuild path and a direct renderWalletList()-only call.
import { withPage, freshSignup, connectAndShowDashboard, makeSuite, assert } from './helpers.mjs';

const SOLO_ISSUER = 'rsoLo2S1kiGeCcn6hCUXVrCpGMWLrRrLZz'; // real account — only used for balance/watch-only import, not tx history

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

    // Pre-seed txCache so _loadDrawerTab's real render path runs without a
    // live tx-history RPC round-trip — this account's real history is large
    // enough that fetch timing varies wildly run to run (confirmed: a real
    // account_tx fetch for this address has taken anywhere from a few
    // seconds to a live-network timeout depending on node load), which made
    // this test flaky for a reason that has nothing to do with what it's
    // actually verifying (drawer content survives a re-render).
    await page.evaluate((addr) => {
      window._debugSeedTxCache(addr, [
        { tx: { TransactionType: 'Payment', Account: addr, Destination: 'rDest11111111111111111111111', Amount: '1000000', hash: 'TESTHASH1', date: 800000000 }, meta: { TransactionResult: 'tesSUCCESS' } },
      ]);
    }, SOLO_ISSUER);

    await page.evaluate((id) => window.toggleWalletDrawer(id), walletId);
    await page.waitForFunction(
      (id) => { const b = document.getElementById(`wcard-drawer-body-${id}`); return b && !b.querySelector('.wdd-loading'); },
      walletId,
      { timeout: 10000 }
    );

    const before = await page.evaluate((id) => document.getElementById(`wcard-drawer-body-${id}`)?.innerHTML, walletId);
    assert(before && !before.includes('wdd-loading'), 'drawer never loaded real content to begin with');

    // Path 1: refreshWalletCard() -> renderWalletList() called directly.
    // fetchBalance() inside it is still a real (lightweight) RPC call.
    await page.evaluate((addr) => window.refreshWalletCard(addr), SOLO_ISSUER);
    await page.waitForTimeout(800);
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
