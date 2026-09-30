// Regression coverage for "Date range picker for all charts (7d/30d/90d/all
// time)" (roadmap: Analytics). Covers the two balance-history-based Analytics
// charts (Portfolio Value + per-wallet Balance History, which share one
// picker/localStorage range since they're rendered from the same
// _buildBalanceChartFromHistory pipeline) and the Inspector's Risk Score
// Trend chart (a separate, per-address dataset with its own picker).
import { withPage, connectAndShowDashboard, freshSignup, assert } from './helpers.mjs';

const suite = { register: [], run: async () => {
  let pass = 0, fail = 0;
  console.log('\n▶ Chart Date Range Picker');
  for (const { name, fn } of suite.register) {
    try { await fn(); console.log(`  PASS  ${name}`); pass++; }
    catch (err) { console.log(`  FAIL  ${name}`); console.log(`        ${err?.stack || err}`); fail++; }
  }
  return { pass, fail, total: suite.register.length };
}};
const test = (name, fn) => suite.register.push({ name, fn });

test('Analytics tab: Portfolio Value and Balance History share one range picker, default to All, and narrowing to 7D correctly filters both to a coherent empty state', async () => {
  await withPage(async (page, { pageErrors }) => {
    await connectAndShowDashboard(page);
    await freshSignup(page, { name: 'Range Tester', email: 'ranget@test.com' });

    const seeded = await page.evaluate(() => {
      const now = Date.now();
      const addr = 'rRangePickerTestWallet00000000000000';
      const wallet = { id: 'w1', label: 'Range Wallet', address: addr, testnet: false, color: '#00fff0', emoji: '💎' };
      window.localStorage.setItem('nalulf_wallets', JSON.stringify([wallet]));
      window.localStorage.setItem('naluxrp_active_wallet', 'w1');
      const hist = [];
      for (let d = 120; d >= 0; d -= 10) hist.push({ ts: now - d * 86400000, xrp: 100 + (120 - d) });
      window.localStorage.setItem('nalulf_balhist_' + addr, JSON.stringify(hist));
      return { addr, seededHistLen: hist.length };
    });

    await page.reload();
    await page.waitForFunction(() => window.connectXRPL, { timeout: 8000 });
    await page.evaluate(() => window.connectXRPL());
    await page.waitForFunction(() => document.getElementById('connDot')?.classList.contains('live'), { timeout: 20000 });
    await page.evaluate(() => window.showProfile());
    await page.waitForTimeout(1000);

    const before = await page.evaluate(() => {
      const el = document.getElementById('profile-tab-analytics');
      return {
        pickers: el?.querySelectorAll('.chart-range-picker').length || 0,
        activeBtns: [...(el?.querySelectorAll('.chart-range-btn--active') || [])].map(b => b.textContent),
        circleCounts: [...(el?.querySelectorAll('.balance-chart-svg') || [])].map(svg => svg.querySelectorAll('circle').length),
      };
    });
    assert(before.pickers >= 2, `expected at least 2 range pickers (Portfolio Value + Balance History), got ${before.pickers}`);
    assert(before.activeBtns.length >= 2 && before.activeBtns.every(t => t === 'All'), `expected "All" active by default on every picker, got ${JSON.stringify(before.activeBtns)}`);
    assert(before.circleCounts.every(c => c === seeded.seededHistLen), `expected all ${seeded.seededHistLen} seeded points plotted by default, got ${JSON.stringify(before.circleCounts)}`);

    await page.evaluate(() => {
      const btn = [...document.querySelectorAll('.chart-range-btn')].find(b => b.textContent === '7D');
      btn.click();
    });
    await page.waitForTimeout(300);

    const after = await page.evaluate(() => {
      const el = document.getElementById('profile-tab-analytics');
      return {
        activeBtns: [...el.querySelectorAll('.chart-range-btn--active')].map(b => b.textContent),
        circleCounts: [...el.querySelectorAll('.balance-chart-svg')].map(svg => svg.querySelectorAll('circle').length),
        emptyMsgs: [...el.querySelectorAll('.analytics-empty-chart')].map(d => d.textContent.trim()),
      };
    });
    assert(after.activeBtns.length >= 2 && after.activeBtns.every(t => t === '7D'), `expected both pickers to reflect the shared 7D selection, got ${JSON.stringify(after.activeBtns)}`);
    assert(after.circleCounts.length === 0, `expected the 10-day-spaced seed data to fall under 2 points within a 7D window (empty state, not a sparse chart), got circle counts ${JSON.stringify(after.circleCounts)}`);
    assert(after.emptyMsgs.some(m => m.includes('in this range')), `expected an explicit "in this range" empty-state message distinguishing a narrow filter from genuinely no history, got: ${JSON.stringify(after.emptyMsgs)}`);
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

test('Inspector Risk Score Trend: its own independent range picker filters the seeded history and the point count updates without page errors', async () => {
  await withPage(async (page, { pageErrors }) => {
    await connectAndShowDashboard(page);

    const riskAddr = 'rRiskTrendRangeTest0000000000000000';
    await page.evaluate((riskAddr) => {
      const now = Date.now();
      const riskHist = [];
      for (let d = 120; d >= 0; d -= 15) riskHist.push({ score: 20 + (120 - d) / 3, ts: now - d * 86400000 });
      window.localStorage.setItem('nalulf_risktrend_' + riskAddr, JSON.stringify(riskHist));
      window.switchTab(document.querySelector('.dash-tab[data-tab="inspector"]'), 'inspector');
    }, riskAddr);
    await page.waitForTimeout(300);

    const full = await page.evaluate((riskAddr) => {
      window._debugRenderRiskScoreTrend(riskAddr);
      const el = document.getElementById('inspect-risk-trend');
      return { pickers: el.querySelectorAll('.chart-range-picker').length, circles: el.querySelectorAll('circle').length };
    }, riskAddr);
    assert(full.pickers === 1, `expected exactly 1 range picker on the risk trend chart, got ${full.pickers}`);
    assert(full.circles === 9, `expected all 9 seeded points plotted with the default "All" range, got ${full.circles}`);

    const narrowed = await page.evaluate((riskAddr) => {
      window.setRiskTrendRange(riskAddr, '7d');
      const el = document.getElementById('inspect-risk-trend');
      return { circles: el.querySelectorAll('circle').length, text: el.textContent };
    }, riskAddr);
    assert(narrowed.circles < full.circles, `expected narrowing to 7D to plot fewer points than the full 9, got ${narrowed.circles}`);
    assert(narrowed.text.includes('widen the range') || narrowed.circles >= 2, 'expected either a real (>=2 point) narrowed chart or the explicit "widen the range" hint, not a silently blank chart');
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
