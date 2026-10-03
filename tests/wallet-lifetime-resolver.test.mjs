// Regression coverage for _resolveWalletLifetime — the canonical account-
// age/activation resolver (roadmap: XRPL Account Age / Activation
// Provenance repair). This guards two real, confirmed bugs found while
// building it, both live against the SOLO issuer (rsoLo2S1kiGeCcn6hCUXVrCpGMWLrRrLZz,
// a genuinely ~7-year-old, high-volume account):
//
// 1. "No marker returned" from account_tx pagination does NOT prove an
//    account's full history was reached — a public rippled node can simply
//    stop retaining ledger history at some point and silently return no
//    marker once it runs past its own retention window, reading identically
//    to "genuinely complete." This showed up live as SOLO reading "1 day
//    old, VERIFIED" when its marker chain happened to exhaust after only a
//    few thousand transactions, all from the last day, on a node with
//    limited retention.
// 2. The safety check added for (1) must be FAIL-SAFE in the right
//    direction: if the server_info confirmation call itself fails (a plain
//    network hiccup — not hypothetical, this exact failure reproduced live
//    during development), the resolver must NOT fall back to trusting
//    pagination completeness blindly. For a forensics tool, an unconfirmed
//    check must default to unverified, never to verified.
import { withPage, assert } from './helpers.mjs';

const suite = { register: [], run: async () => {
  let pass = 0, fail = 0;
  console.log('\n▶ Wallet Lifetime Resolver');
  for (const { name, fn } of suite.register) {
    try { await fn(); console.log(`  PASS  ${name}`); pass++; }
    catch (err) { console.log(`  FAIL  ${name}`); console.log(`        ${err?.stack || err}`); fail++; }
  }
  return { pass, fail, total: suite.register.length };
}};
const test = (name, fn) => suite.register.push({ name, fn });

const ADDR = 'rTestAddrAAAAAAAAAAAAAAAAAAAAAAAAA';

function mkTxList(oldestLedgerIndex, oldestDate = 900000000) {
  return [{ tx: { Account: ADDR, TransactionType: 'Payment', hash: 'h1', date: oldestDate, ledger_index: oldestLedgerIndex }, meta: { TransactionResult: 'tesSUCCESS', AffectedNodes: [] } }];
}

test('A marker genuinely running out, confirmed by a server with deep retention well before the oldest found tx, is trusted as VERIFIED', async () => {
  await withPage(async (page, { pageErrors }) => {
    await page.waitForFunction(() => window._debugResolveWalletLifetime, { timeout: 8000 });
    const result = await page.evaluate(({ addr, txList }) => {
      const historyCoverage = { newestToOldestComplete: true, oldestToNewestFetched: false };
      // Oldest tx at ledger 90,000,000; server's earliest retained ledger is
      // genesis-era (32,570) — an enormous, confirmed margin.
      return window._debugResolveWalletLifetime(txList, addr, historyCoverage, 32570);
    }, { addr: ADDR, txList: mkTxList(90000000) });
    assert(result.walletAgeVerified === true, `expected VERIFIED when server retention is confirmed deep, got ${JSON.stringify(result)}`);
    assert(result.possiblyBoundedByServerRetention === false, 'expected possiblyBoundedByServerRetention to be false when confirmed sufficient');
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

test('A marker running out RIGHT AT the server\'s own retention edge (the real SOLO bug) is correctly NOT trusted as verified', async () => {
  await withPage(async (page, { pageErrors }) => {
    await page.waitForFunction(() => window._debugResolveWalletLifetime, { timeout: 8000 });
    const result = await page.evaluate(({ addr, txList }) => {
      const historyCoverage = { newestToOldestComplete: true, oldestToNewestFetched: false };
      // Oldest tx at ledger 91,700,000; server's earliest retained ledger is
      // 91,650,000 — only 50,000 ledgers of margin, right at the server's
      // own edge. This must NOT read as genuine account genesis.
      return window._debugResolveWalletLifetime(txList, addr, historyCoverage, 91650000);
    }, { addr: ADDR, txList: mkTxList(91690000) });
    assert(result.walletAgeVerified === false, `expected UNVERIFIED when the oldest tx sits right at the server's own retention boundary, got ${JSON.stringify(result)}`);
    assert(result.possiblyBoundedByServerRetention === true, 'expected possiblyBoundedByServerRetention to be true for a boundary-adjacent oldest tx');
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

test('CRITICAL fail-safe: if the server_info confirmation itself is unavailable (null), pagination completeness is NOT trusted — defaults to unverified, never verified', async () => {
  await withPage(async (page, { pageErrors }) => {
    await page.waitForFunction(() => window._debugResolveWalletLifetime, { timeout: 8000 });
    const result = await page.evaluate(({ addr, txList }) => {
      const historyCoverage = { newestToOldestComplete: true, oldestToNewestFetched: false };
      // serverEarliestLedger is null — the server_info call failed or
      // returned no usable complete_ledgers. This is the exact scenario
      // that reproduced live during development: a transient network
      // hiccup must never silently promote an unconfirmed age to VERIFIED.
      return window._debugResolveWalletLifetime(txList, addr, historyCoverage, null);
    }, { addr: ADDR, txList: mkTxList(90000000) });
    assert(result.walletAgeVerified === false, `FAIL-SAFE VIOLATION: expected unverified when the confirmation check itself could not run, got ${JSON.stringify(result)}`);
    assert(result.possiblyBoundedByServerRetention === true, 'expected possiblyBoundedByServerRetention to default true (cautious) when unconfirmed');
    assert(result.walletAgeDays != null, 'expected a lower-bound age figure to still be produced (just marked unverified, not withheld entirely)');
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

test('Real AccountRoot creation evidence overrides everything else — VERIFIED regardless of historyCoverage or server retention', async () => {
  await withPage(async (page, { pageErrors }) => {
    await page.waitForFunction(() => window._debugResolveWalletLifetime, { timeout: 8000 });
    const result = await page.evaluate(({ addr }) => {
      const FUNDER = 'rFunderAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
      const txList = [{
        tx: { Account: FUNDER, Destination: addr, TransactionType: 'Payment', hash: 'hcreate', date: 900000000, ledger_index: 90000001 },
        meta: { TransactionResult: 'tesSUCCESS', AffectedNodes: [
          { CreatedNode: { LedgerEntryType: 'AccountRoot', NewFields: { Account: addr, Balance: '20000000' } } },
        ] },
      }];
      // Deliberately hostile historyCoverage/server inputs — real evidence
      // must win regardless.
      const historyCoverage = { newestToOldestComplete: false, oldestToNewestFetched: false };
      return window._debugResolveWalletLifetime(txList, addr, historyCoverage, null);
    }, { addr: ADDR });
    assert(result.walletAgeVerified === true, `expected real AccountRoot evidence to verify regardless of other signals, got ${JSON.stringify(result)}`);
    assert(result.walletActivationEvidence?.transactionHash === 'hcreate', 'expected the real creation evidence to be returned');
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

test('Age is clamped at 0, never negative, for an account created within the same second as the read (ledger-close-time vs. local-clock skew)', async () => {
  await withPage(async (page, { pageErrors }) => {
    await page.waitForFunction(() => window._debugResolveWalletLifetime, { timeout: 8000 });
    const result = await page.evaluate(({ addr }) => {
      const FUNDER = 'rFunderAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
      const RIPPLE_EPOCH = 946684800;
      // A creation timestamp fractionally AFTER "now" in Ripple-epoch
      // seconds — reproduces the exact live failure (a testnet faucet
      // account read back as "-1 days old"): Date.now() - walletCreatedTs
      // comes out as a tiny negative number, and Math.floor rounds that
      // toward -1, not 0, unless clamped.
      const nowRippleSec = Math.floor(Date.now() / 1000) - RIPPLE_EPOCH;
      const txList = [{
        tx: { Account: FUNDER, Destination: addr, TransactionType: 'Payment', hash: 'hjustnow', date: nowRippleSec + 2, ledger_index: 90000001 },
        meta: { TransactionResult: 'tesSUCCESS', AffectedNodes: [
          { CreatedNode: { LedgerEntryType: 'AccountRoot', NewFields: { Account: addr, Balance: '20000000' } } },
        ] },
      }];
      return window._debugResolveWalletLifetime(txList, addr, { newestToOldestComplete: true, oldestToNewestFetched: false }, null);
    }, { addr: ADDR });
    assert(result.walletAgeDays === 0, `expected age clamped to 0 for a just-created account, got ${result.walletAgeDays}`);
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
