// Regression coverage for the in-memory account-history cache (roadmap:
// Universal XRPL Full-History Inspection — spec §23-30, 44, 56-57).
// Re-inspecting the same address previously re-paginated the ENTIRE
// transaction history, re-ran the server-retention check, and re-scanned
// for AccountRoot creation evidence from scratch every single time, even
// seconds apart. This caches that expensive part (never the cheap,
// always-fresh current-state calls like balance/sequence/offers) keyed by
// network+address, with a resolver-version field so a future change to the
// wallet-lifetime logic invalidates every previously-cached entry just by
// bumping INSPECTION_RESOLVER_VERSION, and a short TTL so staleness stays
// bounded without needing a real invalidation event.
import { withPage, connectAndShowDashboard, inspectAddress, assert } from './helpers.mjs';

const suite = { register: [], run: async () => {
  let pass = 0, fail = 0;
  console.log('\n▶ Inspection History Cache');
  for (const { name, fn } of suite.register) {
    try { await fn(); console.log(`  PASS  ${name}`); pass++; }
    catch (err) { console.log(`  FAIL  ${name}`); console.log(`        ${err?.stack || err}`); fail++; }
  }
  return { pass, fail, total: suite.register.length };
}};
const test = (name, fn) => suite.register.push({ name, fn });

test('A fresh cache entry is returned, a stale (TTL-expired) one is not, and a resolver-version mismatch invalidates it', async () => {
  await withPage(async (page, { pageErrors }) => {
    await page.waitForFunction(() => window._debugInspectionHistoryCache && window._debugGetCachedInspectionHistory, { timeout: 8000 });
    const result = await page.evaluate(() => {
      const cache = window._debugInspectionHistoryCache;
      const addr = 'rCacheTestAddrAAAAAAAAAAAAAAAAAAAA';
      const network = 'xrpl-mainnet';
      const payload = { txList: [{ tx: { hash: 'h1' } }], historyCoverage: {}, walletAgeDays: 100, walletCreatedTs: 123, walletAgeVerified: true, walletActivationEvidence: null, accountLifetimeHistory: null };

      // Fresh, current-version entry — must be returned.
      cache.set(`${network}:${addr}`, { ...payload, resolverVersion: 1, cachedAtMs: Date.now() });
      const freshHit = window._debugGetCachedInspectionHistory(network, addr);

      // Expired (TTL well in the past) — must NOT be returned.
      cache.set(`${network}:${addr}`, { ...payload, resolverVersion: 1, cachedAtMs: Date.now() - 10 * 60 * 1000 });
      const expiredHit = window._debugGetCachedInspectionHistory(network, addr);

      // Wrong resolver version (simulates a future logic change) — must NOT be returned.
      cache.set(`${network}:${addr}`, { ...payload, resolverVersion: 999, cachedAtMs: Date.now() });
      const versionMismatchHit = window._debugGetCachedInspectionHistory(network, addr);

      // No entry at all for a never-seen address.
      const missingHit = window._debugGetCachedInspectionHistory(network, 'rNeverInspectedAAAAAAAAAAAAAAAAAAA1');

      cache.delete(`${network}:${addr}`);
      return {
        freshHitFound: !!freshHit, freshAgeDays: freshHit?.walletAgeDays,
        expiredHitFound: !!expiredHit,
        versionMismatchHitFound: !!versionMismatchHit,
        missingHitFound: !!missingHit,
      };
    });

    assert(result.freshHitFound === true && result.freshAgeDays === 100, 'expected a fresh, current-version cache entry to be returned intact');
    assert(result.expiredHitFound === false, 'expected a TTL-expired entry to be treated as a miss');
    assert(result.versionMismatchHitFound === false, 'expected a resolver-version mismatch to be treated as a miss');
    assert(result.missingHitFound === false, 'expected no entry for an address never cached');
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

test('Different networks never share a cache entry for the same address string', async () => {
  await withPage(async (page, { pageErrors }) => {
    await page.waitForFunction(() => window._debugInspectionHistoryCache && window._debugGetCachedInspectionHistory, { timeout: 8000 });
    const result = await page.evaluate(() => {
      const cache = window._debugInspectionHistoryCache;
      const addr = 'rSameAddrOnBothNetworksAAAAAAAAAAA1';
      cache.set(`xrpl-mainnet:${addr}`, { walletAgeDays: 2000, resolverVersion: 1, cachedAtMs: Date.now() });
      const testnetHit = window._debugGetCachedInspectionHistory('xrpl-testnet', addr);
      const mainnetHit = window._debugGetCachedInspectionHistory('xrpl-mainnet', addr);
      cache.delete(`xrpl-mainnet:${addr}`);
      return { testnetHitFound: !!testnetHit, mainnetAgeDays: mainnetHit?.walletAgeDays };
    });

    assert(result.testnetHitFound === false, 'expected a mainnet-cached entry to be invisible when queried under testnet for the same address string');
    assert(result.mainnetAgeDays === 2000, 'expected the mainnet entry to still be retrievable under its own network');
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

test('Live: re-inspecting the same real address reuses the cached transaction history instead of re-paginating', async () => {
  await withPage(async (page, { pageErrors }) => {
    await connectAndShowDashboard(page);
    const SOLO_ISSUER = 'rsoLo2S1kiGeCcn6hCUXVrCpGMWLrRrLZz';
    await inspectAddress(page, SOLO_ISSUER, { timeout: 150000 });
    const cacheSizeAfterFirst = await page.evaluate(() => window._debugInspectionHistoryCache.size);

    await page.evaluate((addr) => { document.getElementById('inspect-addr').value = addr; }, SOLO_ISSUER);
    // Polling for the exact "Using cached transaction history…" text is
    // fragile: on a real cache hit, Pass 1/2/server_info are skipped
    // entirely with zero awaited work in between, so that message can be
    // overwritten by the very next synchronous stage within single-digit
    // milliseconds — a fast cache hit flashing by near-instantly is the
    // CORRECT behavior (the whole point of caching), not something to slow
    // down just to make it observable. The robust signal is the ABSENCE of
    // any "Fetching transactions — page N" message, which only appears
    // during real Pass 1 pagination and can't be skipped or rushed past.
    const pollPromise = page.evaluate(() => new Promise((resolve) => {
      const seen = new Set();
      const iv = setInterval(() => {
        const t = document.getElementById('inspect-loading-msg')?.textContent;
        if (t) seen.add(t);
      }, 50);
      setTimeout(() => { clearInterval(iv); resolve([...seen]); }, 30000);
    }));
    await page.evaluate(() => window.runInspect());
    const seenMsgs = await pollPromise;
    await page.waitForTimeout(2000);

    assert(cacheSizeAfterFirst >= 1, 'expected the cache to hold at least one entry after the first inspection');
    const didPaginate = [...seenMsgs].some(m => /^Fetching transactions — page/.test(m));
    assert(!didPaginate, `expected NO page-by-page pagination on a cache hit, but saw real pagination messages: ${JSON.stringify(seenMsgs)}`);
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
