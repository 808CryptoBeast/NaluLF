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

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
