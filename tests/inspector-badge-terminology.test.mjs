// Regression guard for a real terminology-consistency bug: several section
// badges (Fee Analysis, Destination Tags, Path Payment Depth, Memo
// Analysis, Live Order Book) rolled their own "nothing found" word
// ("Normal") instead of the shared "OK" every other section uses via
// _setBadge — including, in at least one case (Destination Tags), within
// the SAME render function whose own inline finding row already said
// "OK" for the identical condition. A user scanning down the page saw
// two different words for the exact same "checked, nothing concerning"
// state depending on which section they looked at. Fixed to converge on
// "OK" everywhere, while deliberately leaving the separate, legitimate
// "None"/neutral state (no data to analyse at all — a different claim
// from "analysed and found nothing") untouched.
import { withPage, connectAndShowDashboard, makeSuite, assert } from './helpers.mjs';

const suite = makeSuite('Badge Terminology Consistency');

async function badgeTextFor(page, hookName, badgeId, fixture) {
  return page.evaluate(([hookName, badgeId, fixture]) => {
    window[hookName](fixture);
    return document.getElementById(badgeId)?.textContent;
  }, [hookName, badgeId, fixture]);
}

suite.register('Fee Analysis, Destination Tags, Memo Analysis, and Live Order Book badges all say "OK" (not "Normal") for a clean, analysed-with-no-findings account', async () => {
  await withPage(async (page) => {
    await connectAndShowDashboard(page);
    await page.evaluate(() => window.switchTab(null, 'inspector'));
    await page.waitForFunction(() => window._debugRenderFeeAnalysisPanel && window._debugRenderDestTagPanel && window._debugRenderMemoPanel && window._debugRenderLiveBookPanel, { timeout: 8000 });

    const feeBadge = await badgeTextFor(page, '_debugRenderFeeAnalysisPanel', 'badge-fee-analysis', { signals: [] });
    assert(feeBadge === 'OK', `expected Fee Analysis badge to say "OK" for a clean result, got: "${feeBadge}"`);

    const destTagBadge = await badgeTextFor(page, '_debugRenderDestTagPanel', 'badge-desttag', { signals: [], tagProfiles: [{ name: 'x', txCount: 1, uniqueTags: 1 }] });
    assert(destTagBadge === 'OK', `expected Destination Tags badge to say "OK" for a clean result, got: "${destTagBadge}"`);

    const memoBadge = await badgeTextFor(page, '_debugRenderMemoPanel', 'badge-memos', { signals: [], allMemos: [{ type: 'text', tx: 'h1', text: 'hello' }] });
    assert(memoBadge === 'OK', `expected Memo Analysis badge to say "OK" for a clean result, got: "${memoBadge}"`);

    const liveBookBadge = await badgeTextFor(page, '_debugRenderLiveBookPanel', 'badge-livebook', { signals: [], hasData: true, pair: 'XRP↔FOO', offerCount: 3, ourShare: 0, wallShare: 0 });
    assert(liveBookBadge === 'OK', `expected Live Order Book badge to say "OK" for a clean result, got: "${liveBookBadge}"`);
  });
});

suite.register('Path Payment Depth badge says "OK" (not "Normal") when path payments exist but none are flagged, while genuinely no-data still says "None"', async () => {
  await withPage(async (page) => {
    await connectAndShowDashboard(page);
    await page.evaluate(() => window.switchTab(null, 'inspector'));
    await page.waitForFunction(() => window._debugRenderPathDepthPanel, { timeout: 8000 });

    const cleanBadge = await badgeTextFor(page, '_debugRenderPathDepthPanel', 'badge-pathdepth', { signals: [{ sev: 'ok' }], noData: false });
    assert(cleanBadge === 'OK', `expected "OK" when path payments were analysed with no warn/critical findings, got: "${cleanBadge}"`);

    const noDataBadge = await badgeTextFor(page, '_debugRenderPathDepthPanel', 'badge-pathdepth', { signals: [], noData: true });
    assert(noDataBadge === 'None', `expected the separate, legitimate "None" state (no path payments at all) to be preserved, got: "${noDataBadge}"`);
  });
});

suite.register('Warn/critical states keep their real, informative labels (Elevated/Check/Patterns/Scam text/Wall order) rather than being flattened to generic words', async () => {
  await withPage(async (page) => {
    await connectAndShowDashboard(page);
    await page.evaluate(() => window.switchTab(null, 'inspector'));
    await page.waitForFunction(() => window._debugRenderFeeAnalysisPanel && window._debugRenderMemoPanel, { timeout: 8000 });

    const feeBadge = await badgeTextFor(page, '_debugRenderFeeAnalysisPanel', 'badge-fee-analysis', { signals: [{ sev: 'warn' }] });
    assert(feeBadge === 'Elevated', `expected the informative "Elevated" label preserved for warn-level fee spikes, got: "${feeBadge}"`);

    const memoCritBadge = await badgeTextFor(page, '_debugRenderMemoPanel', 'badge-memos', { signals: [{ sev: 'critical' }], allMemos: [{ type: 'text', tx: 'h1', text: 'urgent claim reward' }] });
    assert(memoCritBadge === 'Scam text', `expected the informative "Scam text" label preserved for critical memo findings, got: "${memoCritBadge}"`);
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
