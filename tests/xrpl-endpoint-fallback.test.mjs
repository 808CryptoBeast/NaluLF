// Regression coverage for wsSendResilient (roadmap: XRPL Account Age /
// Activation Provenance repair, spec §12-14 "trusted full-history
// fallback"). Found while verifying the AccountRoot-creation-evidence work:
// s1.ripple.com and s2.ripple.com run Clio, which has a documented bug
// returning "Internal error" on account_info for AMM pseudo-accounts
// specifically (confirmed directly via curl against the real endpoint) —
// a load-bearing call like account_info failing used to crash the entire
// inspection. wsSendResilient falls back to a one-off, independent plain
// HTTP JSON-RPC call against one of the OTHER already-configured, already-
// trusted endpoints (never inventing new infrastructure) when the primary
// request fails, without touching the shared persistent WS connection.
//
// This test deliberately exercises the REAL bug against a REAL address
// (rMEJo9H5XvTe17UoAJzj8jtKVvTRcxwngo, the SOLO/XRP AMM pool) rather than
// mocking it — the whole point is proving recovery from an actual upstream
// server defect, not a synthetic stand-in for one.
import { withPage, connectAndShowDashboard, inspectAddress, assert } from './helpers.mjs';

const suite = { register: [], run: async () => {
  let pass = 0, fail = 0;
  console.log('\n▶ XRPL Endpoint Fallback (wsSendResilient)');
  for (const { name, fn } of suite.register) {
    try { await fn(); console.log(`  PASS  ${name}`); pass++; }
    catch (err) { console.log(`  FAIL  ${name}`); console.log(`        ${err?.stack || err}`); fail++; }
  }
  return { pass, fail, total: suite.register.length };
}};
const test = (name, fn) => suite.register.push({ name, fn });

const AMM_POOL = 'rMEJo9H5XvTe17UoAJzj8jtKVvTRcxwngo';

test('Inspecting the SOLO/XRP AMM pool account succeeds end-to-end despite s1.ripple.com\'s real Clio bug on account_info for AMM pseudo-accounts', async () => {
  await withPage(async (page, { pageErrors }) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, AMM_POOL, { timeout: 150000 });

    const result = await page.evaluate(() => ({
      errText: document.getElementById('inspect-err')?.textContent,
      errVisible: document.getElementById('inspect-err')?.style.display,
      headerText: [...document.querySelectorAll('.acct-cell')].find(c => /Wallet Age/.test(c.textContent || ''))?.textContent.replace(/\s+/g, ' ').trim() || null,
    }));

    assert(result.errVisible === 'none' || result.errVisible === '' && !result.errText, `expected no error shown, got errVisible="${result.errVisible}" errText="${result.errText}"`);
    assert(!/Internal error/i.test(result.errText || ''), `expected the Clio "Internal error" to be recovered from via fallback, got: "${result.errText}"`);
    assert(result.headerText, 'expected the account header (including Wallet Age) to render successfully');
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

const REAL_ACCOUNT = 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh';

test('A fallback endpoint that never responds (no error, no close — just silent) does not freeze the whole inspection forever', async () => {
  // Real, confirmed production bug: _httpRpcRequest() used a bare fetch()
  // with no timeout of its own. wsSendResilient() and
  // fetchAcrossOtherEndpoints() both await it in a sequential loop over
  // every OTHER configured endpoint, so ONE unresponsive-but-not-erroring
  // endpoint left that await pending forever and froze the entire calling
  // inspection — confirmed live stuck at "Checking other endpoints for
  // deeper history…" for 240+ seconds with zero progress. Fixed with an
  // AbortController + HTTP_RPC_TIMEOUT_MS (8s) per endpoint attempt.
  // Reproduced here by routing s2.ripple.com's HTTP RPC endpoint to a
  // request that simply never resolves (not an error, not a close — the
  // exact shape of the original bug) and proving the inspection still
  // completes in bounded time instead of hanging indefinitely.
  await withPage(async (page, { pageErrors }) => {
    await page.route('https://s2.ripple.com:51234/**', () => new Promise(() => {}));

    await connectAndShowDashboard(page);

    const started = Date.now();
    await inspectAddress(page, REAL_ACCOUNT, { timeout: 45000 });
    const elapsedMs = Date.now() - started;

    const result = await page.evaluate(() => ({
      hasEvidenceMatrix: !!document.querySelector('#section-evidence-matrix .evmatrix-row'),
      errVisible: document.getElementById('inspect-err')?.style.display,
    }));

    assert(elapsedMs < 45000, `expected the inspection to complete well within the per-endpoint timeout bound, but it took ${elapsedMs}ms (a frozen endpoint would hang indefinitely)`);
    assert(result.hasEvidenceMatrix, 'expected the inspection to finish and render results despite one unresponsive fallback endpoint');
    assert(result.errVisible === 'none' || !result.errVisible, `expected no error shown, got errVisible="${result.errVisible}"`);
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
