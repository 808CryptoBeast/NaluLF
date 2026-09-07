// Regression guard for the Security Timeline: the "classic drain setup"
// narrative (auth change -> asset movement shortly after) must be
// detected and cross-referenced, and must NOT fire when there's no
// nearby drain episode or no events at all.
import { withPage, makeSuite, assert } from './helpers.mjs';

const suite = makeSuite('Security Timeline');

suite.register('An externally-submitted RegularKey change followed by a drain episode gets a linked followedBy note', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugBuildSecurityTimeline, { timeout: 8000 });
    const result = await page.evaluate(() => {
      const addr = 'rTESTaddr';
      const NOW = 800000000;
      const txList = [{ tx: { TransactionType: 'SetRegularKey', Account: 'rATTACKERaddr', RegularKey: 'rNewKeyAddr1111111111111111', date: NOW, hash: 'H1' } }];
      const drainEpisodes = [{ startDate: NOW + 8 * 60, classification: 'potential-drain', grossOutflowXrp: 94850.5, actualDepletionPct: 0.94 }];
      return window._debugBuildSecurityTimeline({ masterKeyHistory: [] }, txList, addr, drainEpisodes);
    });
    assert(result.length === 1, `expected 1 timeline event, got ${result.length}`);
    assert(result[0].detail?.includes('not this account'), 'external key change not flagged as submitted by a different account');
    assert(result[0].followedBy?.includes('94,850.5'), 'followedBy note missing the linked drain episode amount');
  });
});

suite.register('A self-submitted RegularKey change with no nearby drain episode gets no followedBy note', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugBuildSecurityTimeline, { timeout: 8000 });
    const result = await page.evaluate(() => {
      const addr = 'rTESTaddr';
      const txList = [{ tx: { TransactionType: 'SetRegularKey', Account: addr, RegularKey: 'rMyOwnKey222222222222222222', date: 800000000, hash: 'H2' } }];
      return window._debugBuildSecurityTimeline({ masterKeyHistory: [] }, txList, addr, []);
    });
    assert(result.length === 1, `expected 1 timeline event, got ${result.length}`);
    assert(!result[0].followedBy, 'a followedBy note appeared with no drain episode present');
  });
});

suite.register('No security-relevant transactions produces an empty timeline (no fabricated events)', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugBuildSecurityTimeline, { timeout: 8000 });
    const result = await page.evaluate(() => window._debugBuildSecurityTimeline({ masterKeyHistory: [] }, [], 'rTESTaddr', []));
    assert(result.length === 0, `expected an empty timeline, got ${result.length} events`);
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
