// Regression guard for content-shaped loading skeletons (one of the
// roadmapped-but-unbuilt UX items), replacing two previously-generic
// spinner+"Loading…" states with placeholders shaped like the real content
// that's about to arrive:
//
// 1. The wallet card's drawer body (Transactions/NFTs/DEX/AMM tabs) — each
//    tab now shows a skeleton shaped like its OWN real layout (reusing the
//    exact same row/card wrapper classes the real renderer uses —
//    .wdd-tx-row, .wdd-nft-card, .wdd-order-row — so the skeleton's geometry
//    can't drift out of sync with the content that replaces it).
//
// 2. The Inspector's full-report "Analyzing…" state — the progress spinner/
//    message is unchanged, but a stack of section-shaped skeleton cards now
//    renders alongside it, giving a sense of the multi-section report about
//    to appear instead of blank space below the spinner.
//
// Both reuse a single shared `.skel-bar` shimmer primitive (ui.css), which
// respects prefers-reduced-motion by falling back to a static block.
import { withPage, freshSignup, makeSuite, assert } from './helpers.mjs';

const suite = makeSuite('Loading Skeletons');

async function importTestWallet(page, label) {
  await page.addScriptTag({ url: 'https://cdn.jsdelivr.net/npm/xrpl@4.2.5/build/xrpl-latest-min.js' });
  const { seed } = await page.evaluate(() => { const w = window.xrpl.Wallet.generate(); return { seed: w.seed }; });
  await page.evaluate(() => window.openImportSeedModal());
  await page.evaluate(({ seed, label }) => {
    document.getElementById('inp-import-seed').value = seed;
    document.getElementById('inp-import-seed-pass').value = 'TestPassword123';
    document.getElementById('inp-import-seed-pass-confirm').value = 'TestPassword123';
    document.getElementById('inp-import-seed-label').value = label;
  }, { seed, label });
  await page.evaluate(() => window.executeImportFromSeed());
  await page.waitForTimeout(800);
  await page.evaluate(() => window.tourSkip && window.tourSkip());
  return page.evaluate((label) => JSON.parse(localStorage.getItem('nalulf_wallets') || '[]').find(w => w.label === label)?.id, label);
}

suite.register('Wallet drawer: each tab shows a skeleton shaped like its OWN real content, then real content replaces it', async () => {
  await withPage(async (page, { pageErrors }) => {
    const ok = await freshSignup(page, { name: 'Skel Test', email: 'skel1@test.com', domain: 'skel1' });
    assert(ok, 'signup failed');
    await page.evaluate(() => window.showProfile());
    await page.waitForTimeout(400);
    await page.evaluate(() => window.tourSkip && window.tourSkip());
    const walletId = await importTestWallet(page, 'Skel Wallet');
    assert(walletId, 'expected the imported wallet to be registered');

    // Expanding the drawer (default tab: txns) shows a row-shaped skeleton
    // immediately — checked in the SAME evaluate call as the click, to catch
    // it before the real fetch has any chance to resolve.
    const txnsSkel = await page.evaluate((id) => {
      window.toggleWalletDrawer(id);
      const body = document.getElementById(`wcard-drawer-body-${id}`);
      return {
        hasLoadingWrapper: !!body.querySelector('.wdd-loading'),
        rowCount: body.querySelectorAll('.wdd-tx-row').length,
        skelBarCount: body.querySelectorAll('.skel-bar').length,
      };
    }, walletId);
    assert(txnsSkel.hasLoadingWrapper, 'expected the drawer body to be wrapped in .wdd-loading while loading');
    assert(txnsSkel.rowCount >= 3, `expected several skeleton rows shaped like real tx rows, got ${txnsSkel.rowCount}`);
    assert(txnsSkel.skelBarCount > 0, 'expected real .skel-bar shimmer elements inside the skeleton rows');

    // NFTs tab — grid-shaped skeleton (square thumbnails), not row-shaped.
    const nftsSkel = await page.evaluate((id) => {
      window.switchWalletDrawerTab(id, 'nfts');
      const body = document.getElementById(`wcard-drawer-body-${id}`);
      return {
        cardCount: body.querySelectorAll('.wdd-nft-card').length,
        skelBarCount: body.querySelectorAll('.skel-bar').length,
      };
    }, walletId);
    assert(nftsSkel.cardCount >= 4, `expected several skeleton NFT cards, got ${nftsSkel.cardCount}`);
    assert(nftsSkel.skelBarCount > 0, 'expected .skel-bar shimmer elements inside the NFT skeleton');

    // Orders tab — 4-column row shape (dir badge / pair / seq / cancel button).
    const ordersSkel = await page.evaluate((id) => {
      window.switchWalletDrawerTab(id, 'orders');
      const body = document.getElementById(`wcard-drawer-body-${id}`);
      return {
        rowCount: body.querySelectorAll('.wdd-order-row').length,
        skelBarCount: body.querySelectorAll('.skel-bar').length,
      };
    }, walletId);
    assert(ordersSkel.rowCount >= 3, `expected several skeleton order rows, got ${ordersSkel.rowCount}`);
    assert(ordersSkel.skelBarCount > 0, 'expected .skel-bar shimmer elements inside the orders skeleton');

    // AMM tab — reuses the tx-row icon+lines+trailing shape.
    const ammSkel = await page.evaluate((id) => {
      window.switchWalletDrawerTab(id, 'amm');
      const body = document.getElementById(`wcard-drawer-body-${id}`);
      return {
        rowCount: body.querySelectorAll('.wdd-tx-row').length,
        skelBarCount: body.querySelectorAll('.skel-bar').length,
      };
    }, walletId);
    assert(ammSkel.rowCount >= 3, `expected several skeleton rows for AMM, got ${ammSkel.rowCount}`);
    assert(ammSkel.skelBarCount > 0, 'expected .skel-bar shimmer elements inside the AMM skeleton');

    // Real content eventually replaces the skeleton — no leftover shimmer bars.
    await page.waitForTimeout(2000);
    const settled = await page.evaluate((id) => {
      const body = document.getElementById(`wcard-drawer-body-${id}`);
      return { stillHasSkelBar: body.querySelectorAll('.skel-bar').length > 0 };
    }, walletId);
    assert(!settled.stillHasSkelBar, 'expected the skeleton to be fully replaced by real content once the fetch resolves');

    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

suite.register('Inspector: a report-shaped skeleton renders alongside the progress spinner while an inspection is running, then disappears', async () => {
  await withPage(async (page, { pageErrors }) => {
    const ok = await freshSignup(page, { name: 'Skel Test 2', email: 'skel2@test.com', domain: 'skel2' });
    assert(ok, 'signup failed');
    await page.evaluate(() => window.connectXRPL && window.connectXRPL());
    await page.waitForFunction(() => document.getElementById('connDot')?.classList.contains('live'), { timeout: 15000 }).catch(() => {});
    await page.evaluate(() => window.showDashboard && window.showDashboard());
    await page.evaluate(() => window.switchTab && window.switchTab(document.querySelector('[data-tab="inspector"]'), 'inspector'));
    await page.waitForTimeout(300);
    await page.evaluate(() => { document.getElementById('inspect-addr').value = 'rPVMhWBsfF9iMXYj3aAzJVkPDTFNSyWdKy'; });

    // Fire-and-forget: runInspect() is a slow multi-phase async function —
    // awaiting it here would block until the whole analysis (and its own
    // hide-on-completion) is already done, defeating this check entirely.
    await page.evaluate(() => { window.runInspect(); });
    await page.waitForTimeout(150);
    const midFlight = await page.evaluate(() => {
      const loadingEl = document.getElementById('inspect-loading');
      const skel = document.querySelector('.inspect-loading-skel');
      return {
        loadingVisible: loadingEl ? getComputedStyle(loadingEl).display !== 'none' : false,
        skelSectionCount: skel ? skel.querySelectorAll('.inspect-skel-section').length : 0,
        skelBarCount: skel ? skel.querySelectorAll('.skel-bar').length : 0,
      };
    });
    assert(midFlight.loadingVisible, 'expected the loading state to be visible partway through an inspection');
    assert(midFlight.skelSectionCount >= 3, `expected several report-shaped skeleton sections, got ${midFlight.skelSectionCount}`);
    assert(midFlight.skelBarCount > 0, 'expected .skel-bar shimmer elements inside the report skeleton');

    // Let the (real, live) inspection finish, then confirm the loading state
    // — skeleton included, since it's a child of #inspect-loading — is hidden.
    await page.waitForFunction(() => document.getElementById('inspect-loading')?.style.display === 'none', { timeout: 30000 });
    const settled = await page.evaluate(() => getComputedStyle(document.getElementById('inspect-loading')).display === 'none');
    assert(settled, 'expected the loading state (and its skeleton) to be hidden once the inspection completes');

    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

suite.register('Skeleton shimmer respects prefers-reduced-motion', async () => {
  await withPage(async (page, { pageErrors }) => {
    await page.emulateMedia({ reducedMotion: 'reduce' });
    const ok = await freshSignup(page, { name: 'Skel Test 3', email: 'skel3@test.com', domain: 'skel3' });
    assert(ok, 'signup failed');
    await page.evaluate(() => window.showProfile());
    await page.waitForTimeout(400);
    await page.evaluate(() => window.tourSkip && window.tourSkip());
    const walletId = await importTestWallet(page, 'Skel Wallet 3');

    const animState = await page.evaluate((id) => {
      window.toggleWalletDrawer(id);
      const bar = document.querySelector(`#wcard-drawer-body-${id} .skel-bar`);
      return bar ? getComputedStyle(bar).animationName : null;
    }, walletId);
    assert(animState === 'none', `expected the shimmer animation to be disabled under prefers-reduced-motion, got animationName="${animState}"`);

    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
