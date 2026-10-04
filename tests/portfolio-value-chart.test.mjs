// Regression coverage for "Portfolio value line chart across time using
// balance history" (roadmap: Analytics). Aggregates every MAINNET wallet's
// own already-recorded balance-history snapshots into one combined series —
// each wallet snapshots independently (whenever ITS balance happens to be
// refreshed), so the timestamps don't line up across wallets, and
// _computePortfolioHistory does a real as-of join (each wallet's
// most-recent-known balance as of every OTHER wallet's snapshot moment)
// rather than fabricating interpolated values. Testnet wallets are
// deliberately excluded from the total, since testnet XRP has no real value
// and folding it in would silently distort what "portfolio value" means.
import { withPage, freshSignup, makeSuite, assert } from './helpers.mjs';

const suite = makeSuite('Portfolio Value Chart');

suite.register('Live: the Portfolio Value chart correctly as-of-joins multiple unevenly-sampled mainnet wallet histories and excludes a testnet wallet entirely', async () => {
  await withPage(async (page, { pageErrors }) => {
    const ok = await freshSignup(page, { name: 'Portfolio Test', email: 'portfoliotest@test.com', domain: 'portfoliotest' });
    assert(ok, 'signup failed');
    await page.evaluate(() => window.showProfile());
    await page.waitForTimeout(300);
    await page.evaluate(() => window.tourSkip && window.tourSkip());

    // Hand-computed expected as-of-join result:
    //   T0        A=100 (exact)              B=0   (no snapshot yet)  -> 100
    //   T0+5min   A=100 (carried forward)     B=50  (exact)            -> 150
    //   T0+10min  A=120 (exact)               B=50  (carried forward)  -> 170
    //   T0+15min  A=120 (carried forward)     B=60  (exact)            -> 180
    // Testnet wallet C's 99999 XRP must never appear in any of this.
    await page.evaluate(() => {
      const T0 = Date.now() - 20 * 60_000;
      const walletA = { id: 'wA', label: 'Mainnet A', address: 'rMainnetA00000000000000000000000000', color: '#00fff0', emoji: '💎', algo: 'ed25519', watchOnly: false, testnet: false };
      const walletB = { id: 'wB', label: 'Mainnet B', address: 'rMainnetB00000000000000000000000000', color: '#bd93f9', emoji: '🔥', algo: 'ed25519', watchOnly: false, testnet: false };
      const walletC = { id: 'wC', label: 'Testnet C', address: 'rTestnetC00000000000000000000000000', color: '#ffb86c', emoji: '🧪', algo: 'ed25519', watchOnly: false, testnet: true };
      localStorage.setItem('nalulf_wallets', JSON.stringify([walletA, walletB, walletC]));
      localStorage.setItem('nalulf_balhist_' + walletA.address, JSON.stringify([{ ts: T0, xrp: 100 }, { ts: T0 + 10 * 60_000, xrp: 120 }]));
      localStorage.setItem('nalulf_balhist_' + walletB.address, JSON.stringify([{ ts: T0 + 5 * 60_000, xrp: 50 }, { ts: T0 + 15 * 60_000, xrp: 60 }]));
      localStorage.setItem('nalulf_balhist_' + walletC.address, JSON.stringify([{ ts: T0, xrp: 99999 }]));
    });

    await page.reload({ waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(500);
    await page.evaluate(() => window.showProfile());
    await page.waitForTimeout(300);
    await page.evaluate(() => window.tourSkip && window.tourSkip());
    await page.evaluate(() => window.switchProfileTab('analytics'));
    // renderAnalyticsTab() paints a skeleton immediately, then awaits a real
    // fetchTxHistory() RPC round-trip (for the active wallet) before
    // replacing it with the real cards — that round-trip alone can take
    // well over 500ms, so a fixed wait here was racing real network latency
    // instead of the actual render. Poll for the skeleton's replacement.
    await page.waitForFunction(() => !document.querySelector('#profile-tab-analytics .skeleton-card'), { timeout: 10000 });

    const result = await page.evaluate(() => {
      const card = [...document.querySelectorAll('.analytics-card')].find(c => c.querySelector('.analytics-card-title')?.textContent.includes('Portfolio Value'));
      if (!card) return { found: false };
      return {
        found: true,
        currentValueText: card.querySelector('.bcm-current')?.textContent,
        snapshotCountText: card.querySelector('.bcm-range')?.textContent,
        circleCount: card.querySelectorAll('circle').length,
        mentionsHugeTestnetValue: card.textContent.includes('99999') || card.textContent.includes('100179') || card.textContent.includes('100119'),
      };
    });
    assert(result.found, 'expected a Portfolio Value chart card in the Analytics tab');
    assert(result.currentValueText === '180 XRP', `expected the final as-of-joined value to be exactly 180 XRP, got "${result.currentValueText}"`);
    assert(result.snapshotCountText === '4 snapshots', `expected exactly 4 merged timestamps (2 wallets x 2 snapshots each, none overlapping), got "${result.snapshotCountText}"`);
    assert(result.circleCount === 4, `expected exactly 4 plotted points on the chart, got ${result.circleCount}`);
    assert(!result.mentionsHugeTestnetValue, 'expected the testnet wallet\'s balance to never appear anywhere in the portfolio total');
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

suite.register('Live: with no mainnet wallets at all, the Portfolio Value chart shows an honest empty state naming why, not a broken/blank chart', async () => {
  await withPage(async (page, { pageErrors }) => {
    const ok = await freshSignup(page, { name: 'Portfolio Test 2', email: 'portfoliotest2@test.com', domain: 'portfoliotest2' });
    assert(ok, 'signup failed');
    await page.evaluate(() => window.showProfile());
    await page.waitForTimeout(300);
    await page.evaluate(() => window.tourSkip && window.tourSkip());
    await page.evaluate(() => window.switchProfileTab('analytics'));
    await page.waitForTimeout(500);

    const html = await page.evaluate(() => {
      const card = [...document.querySelectorAll('.analytics-card')].find(c => c.querySelector('.analytics-card-title')?.textContent.includes('Portfolio Value'));
      return card?.innerHTML || '';
    });
    assert(html.includes('analytics-empty-chart'), 'expected an explicit empty-chart state with zero wallets, not a broken/blank chart');
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
