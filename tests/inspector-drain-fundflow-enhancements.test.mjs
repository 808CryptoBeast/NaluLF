// Regression guard for three follow-up enhancements to the combined
// Drain Risk & Fund Flow section: (1) merging the two separate "In plain
// terms" boxes into one shared summary now that the sections are visually
// combined, (2) a Before/During/After balance snapshot for the single
// most notable drain episode (Flow Intelligence spec §16), and (3) cross-
// referencing each episode's destinations against Fund Flow's own
// lifetime top-10 destination list. All three reuse data already computed
// by the two merged sections — no new analysis, no new RPC calls.
import { withPage, connectAndShowDashboard, inspectAddress, makeSuite, assert } from './helpers.mjs';

const suite = makeSuite('Drain Risk + Fund Flow — Merge Follow-ups');

suite.register('A real account with drain episodes shows exactly ONE "In plain terms" box, a real Before/During/After snapshot, and a real cross-reference badge, with no page errors', async () => {
  await withPage(async (page) => {
    const errors = [];
    page.on('pageerror', e => errors.push(e.message));
    await connectAndShowDashboard(page);
    await inspectAddress(page, 'rnj7R3QUGzLZc9dg24jSrGabtt1tp1XD7A', { timeout: 90000 });
    await page.waitForTimeout(1500);

    const simple = await page.evaluate(() => {
      const el = document.getElementById('inspect-drain-body');
      return {
        plainTermsCount: (el.innerHTML.match(/In plain terms:/g) || []).length,
        hasBeforeDuringAfter: /Most Notable Movement/.test(el.innerHTML),
        hasRealBeforeAmount: /Before[\s\S]{0,200}?[\d,]+\.\d{2} XRP/.test(el.innerHTML),
      };
    });
    assert(errors.length === 0, `expected zero page errors, got: ${JSON.stringify(errors)}`);
    assert(simple.plainTermsCount === 1, `expected exactly one merged "In plain terms" box, got ${simple.plainTermsCount}`);
    assert(simple.hasBeforeDuringAfter, 'expected a Before/During/After snapshot for the most notable episode');
    assert(simple.hasRealBeforeAmount, 'expected a real XRP amount in the Before/During/After snapshot');

    await page.evaluate(() => window.toggleAnalystMode());
    await page.waitForTimeout(500);
    const advanced = await page.evaluate(() => ({
      hasCrossRefBadge: /also a top lifetime destination/.test(document.getElementById('inspect-drain-body').innerHTML),
    }));
    await page.evaluate(() => window.toggleAnalystMode());
    assert(advanced.hasCrossRefBadge, 'expected at least one real cross-reference badge for this known-overlap account');
  });
});

suite.register('Synthetic: buildCombinedDrainFundFlowSummary splices both halves together and takes the more severe tone', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugCombinedDrainFundFlowSummary, { timeout: 8000 });
    const flow = {
      destinations: [{ addr: 'rBlackHole00000000000000000000000000', totalXrp: 500, entity: { name: 'Black Hole', type: 'blackhole' } }],
      totalOut: 500, uniqueDests: 1, newWalletDests: [],
    };
    // Drain side is fully clean (tone 'ok'); flow side is critical (black hole) — combined tone must be 'crit'.
    const result = await page.evaluate((f) => window._debugCombinedDrainFundFlowSummary('low', 'none', { applicable: true, verdict: 'normal' }, f), flow);
    assert(result.tone === 'crit', `expected the more severe (flow) tone to win, got ${result.tone}`);
    assert(/Nothing here suggests/.test(result.text), 'expected the drain half\'s text to be present');
    assert(/can never be recovered/.test(result.text), 'expected the flow half\'s text to be present');
  });
});

suite.register('Synthetic: buildCombinedDrainFundFlowSummary falls back to the drain-only reading when there is no outbound flow to report', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugCombinedDrainFundFlowSummary, { timeout: 8000 });
    const result = await page.evaluate(() => window._debugCombinedDrainFundFlowSummary('low', 'none', { applicable: true, verdict: 'normal' }, { destinations: [], totalOut: 0, uniqueDests: 0 }));
    assert(result.tone === 'ok', `expected the drain-only tone, got ${result.tone}`);
    assert(/Nothing here suggests/.test(result.text), 'expected only the drain half\'s text with no fabricated flow clause');
  });
});

suite.register('Synthetic: _renderBeforeDuringAfter renders the real opening/peak/closing balances and dates, and returns empty string for no episode', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugRenderBeforeDuringAfter, { timeout: 8000 });
    const ep = { openingBalanceXrp: 1000, peakBalanceXrp: 1050, closingBalanceXrp: 200, grossOutflowXrp: 850, startDate: 800000000, endDate: 800005000 };
    const html = await page.evaluate((e) => window._debugRenderBeforeDuringAfter(e), ep);
    assert(/1,000 XRP/.test(html), `expected the real opening balance, got: ${html.slice(0, 300)}`);
    assert(/1,050 XRP/.test(html), `expected the real peak balance, got: ${html.slice(0, 300)}`);
    assert(/200 XRP/.test(html), `expected the real closing balance, got: ${html.slice(0, 300)}`);
    assert(/850 XRP/.test(html), `expected the real gross-outflow-during figure, got: ${html.slice(0, 300)}`);

    const empty = await page.evaluate(() => window._debugRenderBeforeDuringAfter(null));
    assert(empty === '', `expected an empty string for no episode, not a broken empty box, got: "${empty}"`);
  });
});

suite.register('Synthetic: _renderEpisodeDestinations badges only the address that actually appears in lifetimeTopAddrs, never the others, and shows no badge at all when omitted', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugRenderEpisodeDestinations, { timeout: 8000 });
    const destinations = [
      { addr: 'rMatchesLifetime00000000000000000000', xrp: 600, entity: null },
      { addr: 'rDoesNotMatch0000000000000000000000', xrp: 400, entity: null },
    ];
    const html = await page.evaluate((d) => {
      const set = new Set(['rMatchesLifetime00000000000000000000']);
      return window._debugRenderEpisodeDestinations(d, 1000, set);
    }, destinations);

    const matchIdx = html.indexOf('rMatchesLifetime');
    const noMatchIdx = html.indexOf('rDoesNotMatch');
    const badgeIdx = html.indexOf('also a top lifetime destination');
    assert(matchIdx !== -1 && noMatchIdx !== -1 && badgeIdx !== -1, 'expected both destinations and the badge to render');
    assert(badgeIdx > matchIdx && badgeIdx < noMatchIdx, 'expected the badge to sit with the matching address\'s row, not the non-matching one');

    const noSet = await page.evaluate((d) => window._debugRenderEpisodeDestinations(d, 1000, null), destinations);
    assert(!noSet.includes('also a top lifetime destination'), 'expected no badge at all when lifetimeTopAddrs is not provided');
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
