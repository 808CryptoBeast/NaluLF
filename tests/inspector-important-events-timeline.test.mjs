// Regression guard for the canonical "Important Events" timeline
// (Inspector-wide roadmap item #7): merges already-computed dated events
// from Security (auth/key changes), Drain Risk (episodes), and Fee
// Analysis (fee spikes) into ONE chronological list, each entry clickable
// to jump straight to the section that explains it. Reuses
// buildSecurityTimeline's own output wholesale — no new analysis, no new
// RPC calls.
import { withPage, connectAndShowDashboard, inspectAddress, makeSuite, assert } from './helpers.mjs';

const suite = makeSuite('Important Events Timeline');

const ACTIVE_ACCOUNT = 'rnj7R3QUGzLZc9dg24jSrGabtt1tp1XD7A';

suite.register('A real account with security changes, drain episodes, and fee spikes renders a real chronologically-sorted timeline with no page errors', async () => {
  await withPage(async (page, { pageErrors }) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, ACTIVE_ACCOUNT, { timeout: 90000 });
    await page.waitForTimeout(1500);

    const result = await page.evaluate(() => {
      const items = [...document.querySelectorAll('#inspect-events-body .events-timeline-item')];
      const dates = items.map(it => new Date(it.querySelector('.events-timeline-date').textContent).getTime());
      const sorted = dates.every((d, i) => i === 0 || d >= dates[i - 1]);
      const modules = new Set(items.map(it => it.querySelector('.events-timeline-module')?.textContent?.replace(' →', '')));
      return { itemCount: items.length, sorted, modules: [...modules], badgeText: document.getElementById('badge-events')?.textContent };
    });
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
    assert(result.itemCount > 0, 'expected at least one event for this known-active account');
    assert(result.sorted, 'expected events to render in chronological order');
    assert(result.badgeText === `${result.itemCount} event${result.itemCount === 1 ? '' : 's'}`, `expected the badge to match the real event count, got "${result.badgeText}"`);
  });
});

suite.register('Clicking a Drain Risk event expands the Drain Risk section it links to', async () => {
  await withPage(async (page, { pageErrors }) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, ACTIVE_ACCOUNT, { timeout: 90000 });
    await page.waitForTimeout(1500);

    const result = await page.evaluate(() => {
      const items = [...document.querySelectorAll('#inspect-events-body .events-timeline-item')];
      const drainItem = items.find(it => it.querySelector('.events-timeline-module')?.textContent.includes('Drain Risk'));
      if (!drainItem) return { found: false };
      document.getElementById('section-drain')?.classList.add('collapsed');
      drainItem.click();
      return { found: true, expanded: !document.getElementById('section-drain')?.classList.contains('collapsed') };
    });
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
    if (result.found) assert(result.expanded, 'expected clicking a Drain Risk event to expand the Drain Risk section');
  });
});

suite.register('Synthetic: buildImportantEventsTimeline merges and sorts all three sources, and correctly filters fee entries below the spike threshold', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugBuildImportantEventsTimeline, { timeout: 8000 });
    const securityTimeline = [{ date: 800002000, hash: 'h1', icon: '🔑', label: 'Regular key set', detail: null }];
    const drainEpisodes = [{ startDate: 800001000, classification: 'sweep', grossOutflowXrp: 500, actualDepletionPct: 0.8 }];
    const feeAnalysis = { topFeeHashes: [
      { date: 800003000, hash: 'h2', mult: '150' }, // real spike
      { date: 800000500, hash: 'h3', mult: '3' },   // below threshold — must be excluded
    ] };
    const events = await page.evaluate((args) => window._debugBuildImportantEventsTimeline(...args), [securityTimeline, drainEpisodes, feeAnalysis]);
    assert(events.length === 3, `expected 3 events (1 security + 1 drain + 1 real fee spike, excluding the sub-threshold one), got ${events.length}`);
    assert(events[0].date === 800000500 || events[0].module === 'Drain Risk', `expected chronological order starting with the earliest real event, got: ${JSON.stringify(events.map(e => e.date))}`);
    const dates = events.map(e => e.date);
    assert(dates.every((d, i) => i === 0 || d >= dates[i - 1]), 'expected events sorted ascending by date');
    assert(!events.some(e => e.hash === 'h3'), 'expected the sub-100x fee entry to be excluded, not treated as a spike');
    assert(events.some(e => e.module === 'Security' && e.jumpTo === 'security'), 'expected the security event to carry the correct module/jumpTo');
    assert(events.some(e => e.module === 'Drain Risk' && e.jumpTo === 'drain'), 'expected the drain event to carry the correct module/jumpTo');
    assert(events.some(e => e.module === 'Fee Analysis' && e.jumpTo === 'fee-analysis'), 'expected the fee spike to carry the correct module/jumpTo');
  });
});

suite.register('Synthetic: renderImportantEventsTimeline shows an honest empty state (not a fabricated event) when there is nothing to show', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugRenderImportantEventsTimeline, { timeout: 8000 });
    const html = await page.evaluate(() => {
      document.body.insertAdjacentHTML('beforeend', '<div id="inspect-events-body"></div><span id="badge-events"></span>');
      window._debugRenderImportantEventsTimeline([]);
      return { body: document.getElementById('inspect-events-body').innerHTML, badge: document.getElementById('badge-events').textContent };
    });
    assert(/No dated events/.test(html.body), `expected an honest empty-state message, got: ${html.body.slice(0, 300)}`);
    assert(html.badge === 'None', `expected the badge to read "None", got "${html.badge}"`);
  });
});

suite.register('Drain Risk events show real "Related: N destination(s)" chips with correct singular/plural phrasing', async () => {
  await withPage(async (page, { pageErrors }) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, ACTIVE_ACCOUNT, { timeout: 90000 });
    await page.waitForTimeout(1500);

    const drainRelated = await page.evaluate(() => {
      const items = [...document.querySelectorAll('#inspect-events-body .events-timeline-item')]
        .filter(it => it.querySelector('.events-timeline-module')?.textContent.includes('Drain Risk'));
      return items.map(it => it.querySelector('.events-timeline-related')?.textContent).filter(Boolean);
    });
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
    assert(drainRelated.length > 0, 'expected at least one Drain Risk event with a Related chip for this known-drain-episode account');
    for (const text of drainRelated) {
      assert(/^Related: \d+ destinations?( · .+)?$/.test(text), `expected correctly-pluralized "N destination(s)" phrasing, got: "${text}"`);
    }
  });
});

suite.register('Synthetic: Related chips correctly cross-reference a preceding security event and a drain episode that overlaps a fee spike', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugBuildImportantEventsTimeline, { timeout: 8000 });
    const securityTimeline = [{ date: 800000000, hash: 'h1', icon: '🔑', label: 'Regular key set', detail: null, followedBy: 'a sweep episode moved 500 XRP' }];
    const drainEpisodes = [{ startDate: 800001000, endDate: 800002000, destinations: [{ addr: 'rA' }, { addr: 'rB' }], classification: 'sweep', grossOutflowXrp: 500, actualDepletionPct: 0.9 }];
    const feeAnalysis = { topFeeHashes: [{ date: 800001500, hash: 'h2', mult: '150' }] };
    const events = await page.evaluate((args) => window._debugBuildImportantEventsTimeline(...args), [securityTimeline, drainEpisodes, feeAnalysis]);

    const secEvent = events.find(e => e.module === 'Security');
    assert(secEvent.related.includes('1 drain episode'), `expected the security event to show a "1 drain episode" related chip (it has a real followedBy), got: ${JSON.stringify(secEvent.related)}`);

    const drainEvent = events.find(e => e.module === 'Drain Risk');
    assert(drainEvent.related.some(r => r.includes('2 destinations')), `expected the drain event to show a real "2 destinations" related chip, got: ${JSON.stringify(drainEvent.related)}`);
    assert(drainEvent.related.includes('1 security event nearby'), `expected the drain event to show a "1 security event nearby" chip (the security event precedes it within 24h), got: ${JSON.stringify(drainEvent.related)}`);

    const feeEvent = events.find(e => e.module === 'Fee Analysis');
    assert(feeEvent.related.includes('1 drain episode'), `expected the fee spike (which falls inside the drain episode's window) to show a "1 drain episode" related chip, got: ${JSON.stringify(feeEvent.related)}`);
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
