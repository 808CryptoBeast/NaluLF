// Regression coverage for "Risk score trend line — how has this address
// changed over inspections" (roadmap: Security). Distinct from the
// pre-existing LS_INSPECT_HISTORY, which keeps only ONE entry per address
// (overwritten on every re-inspection, feeding the recently-inspected list
// and the single-point "vs last time" diff chip) — this keeps every score
// an address has ever gotten, so a real trend line can be drawn.
//
// _debugRenderRiskScoreTrend is used instead of running 2 real live
// inspections back-to-back — during development, exactly that pattern hit
// real XRPL node rate-limiting ("too much load on the server") from running
// many live inspections in quick succession, which would make a suite
// relying on it flaky under repeated CI runs. Seeding history directly and
// rendering deterministically is both faster and more reliable.
import { withPage, connectAndShowDashboard, inspectAddress, makeSuite, assert } from './helpers.mjs';

const suite = makeSuite('Risk Score Trend');

const SOLO_ISSUER = 'rsoLo2S1kiGeCcn6hCUXVrCpGMWLrRrLZz';

suite.register('Live: a single real inspection records one history entry and shows the honest "builds up over time" empty state', async () => {
  await withPage(async (page, { pageErrors }) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, SOLO_ISSUER, { timeout: 90000 });
    await page.waitForTimeout(500);

    const hist = await page.evaluate((a) => window._debugGetRiskScoreTrendHistory(a), SOLO_ISSUER);
    assert(hist.length === 1, `expected exactly 1 recorded entry after a single inspection, got ${hist.length}`);
    assert(typeof hist[0].score === 'number', `expected a real numeric score to be recorded, got ${JSON.stringify(hist[0])}`);

    const html = await page.evaluate(() => document.getElementById('inspect-risk-trend')?.innerHTML || '');
    assert(html.includes('1 inspection recorded'), `expected an honest "builds up over time" message with the real count, got: ${html.slice(0, 200)}`);
    assert(!html.includes('<svg'), 'expected no chart to render with fewer than 2 data points');
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

suite.register('Deterministic: with 4 seeded historical scores, the trend chart renders all 4 points, computes the correct delta, and colors rising risk red / falling risk green', async () => {
  await withPage(async (page, { pageErrors }) => {
    const addr = 'rSyntheticTrendTest0000000000000000';
    const result = await page.evaluate((a) => {
      // Rising trend: 20 -> 40 -> 60 -> 80 (delta = +60, should render red/up).
      window.localStorage.setItem('nalulf_risktrend_' + a, JSON.stringify([
        { score: 20, ts: Date.now() - 4 * 86400000 },
        { score: 40, ts: Date.now() - 3 * 86400000 },
        { score: 60, ts: Date.now() - 2 * 86400000 },
        { score: 80, ts: Date.now() - 1 * 86400000 },
      ]));
      // _renderRiskScoreTrendChart targets #inspect-risk-trend directly —
      // exists once the Inspector's HTML shell has mounted, regardless of
      // whether a real inspection has run yet.
      window.showDashboard();
      window.switchTab(document.querySelector('[data-tab="inspector"]'), 'inspector');
      window._debugRenderRiskScoreTrend(a);
      const el = document.getElementById('inspect-risk-trend');
      return {
        circleCount: el.querySelectorAll('circle').length,
        mentionsFourInspections: el.textContent.includes('4 inspections'),
        mentionsSixtyPts: el.textContent.includes('60 pts'),
        isRising: el.textContent.includes('▲'),
        redColorUsed: el.innerHTML.includes('#ff5555'),
      };
    }, addr);
    assert(result.circleCount === 4, `expected 4 plotted points, got ${result.circleCount}`);
    assert(result.mentionsFourInspections, 'expected the inspection count label to read "4 inspections"');
    assert(result.mentionsSixtyPts, 'expected the delta label to read "60 pts" (80 - 20)');
    assert(result.isRising, 'expected an "up" arrow for a rising (worsening) risk score');
    assert(result.redColorUsed, 'expected rising risk to be colored red (worse, not "up is good")');
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

suite.register('Deterministic: a falling risk score trend is colored green, not red', async () => {
  await withPage(async (page, { pageErrors }) => {
    const addr = 'rSyntheticFallingTrend00000000000000';
    const result = await page.evaluate((a) => {
      window.localStorage.setItem('nalulf_risktrend_' + a, JSON.stringify([
        { score: 80, ts: Date.now() - 2 * 86400000 },
        { score: 30, ts: Date.now() - 1 * 86400000 },
      ]));
      window.showDashboard();
      window.switchTab(document.querySelector('[data-tab="inspector"]'), 'inspector');
      window._debugRenderRiskScoreTrend(a);
      const el = document.getElementById('inspect-risk-trend');
      return {
        isFalling: el.textContent.includes('▼'),
        greenColorUsed: el.innerHTML.includes('#50fa7b'),
        redColorUsed: el.innerHTML.includes('#ff5555'),
      };
    }, addr);
    assert(result.isFalling, 'expected a "down" arrow for a falling (improving) risk score');
    assert(result.greenColorUsed, 'expected falling risk to be colored green (better)');
    assert(!result.redColorUsed, 'expected no red coloring for an improving trend');
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
