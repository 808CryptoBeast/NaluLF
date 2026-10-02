// Regression coverage for consolidating the Inspector's counterparty logic
// (roadmap: Inspector Core Architecture). Fund Flow, Inbound Flow, the
// Relationship Drawer (_computeRelationshipDetail), and Wash Execution's
// round-trip pairing (_roundTripQuality) each independently re-parsed "how
// much of which asset did this Payment move" off raw tx.Amount. Inbound
// Flow's own copy was already more correct — it preferred
// meta.delivered_amount, which differs from tx.Amount for a partial payment
// or cross-currency slippage — while the other three used the less-accurate
// field. Consolidated onto one shared `_extractPaymentAmount(tx, meta)`
// helper used by all four, which both eliminates the duplicate parsing and
// extends the more-correct delivered_amount behavior to the three that
// didn't have it. Verified against two real wallets with live numeric
// before/after comparison: every stat matched exactly except the
// Relationship Drawer's token currency field, which is now pre-decoded
// ASCII instead of raw hex (confirmed render-identical, since the existing
// render code's own hexToAscii() call is idempotent on an already-decoded
// string).
import { withPage, connectAndShowDashboard, inspectAddress, assert } from './helpers.mjs';

const suite = { register: [], run: async () => {
  let pass = 0, fail = 0;
  console.log('\n▶ Shared Payment Amount Extraction');
  for (const { name, fn } of suite.register) {
    try { await fn(); console.log(`  PASS  ${name}`); pass++; }
    catch (err) { console.log(`  FAIL  ${name}`); console.log(`        ${err?.stack || err}`); fail++; }
  }
  return { pass, fail, total: suite.register.length };
}};
const test = (name, fn) => suite.register.push({ name, fn });

const WALLET = 'rnj7R3QUGzLZc9dg24jSrGabtt1tp1XD7A';
const PARTNER = 'rs2dgzYeqYqsk8bvkQR5YPyqsXYcA24MP2'; // real two-way, token+XRP, round-trip relationship

test('Fund Flow, Inbound Flow, the Relationship Drawer, and Wash Execution round-trip pairing agree on real XRP/token totals for a real two-way relationship', async () => {
  await withPage(async (page, { pageErrors }) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, WALLET, { timeout: 90000 });
    await page.waitForTimeout(500);

    const data = await page.evaluate(({ addr, partner }) => {
      const txList = window._lastTxList || [];
      const fundFlow = window._debugFundFlow(txList, addr, new Map());
      const inboundFlow = window._debugAnalyseInboundFlow(txList, addr);
      const rel = window._debugComputeRelationshipDetail(addr, partner, txList, []);
      const payments = txList.filter(({ tx }) => tx.TransactionType === 'Payment');
      const roundTrip = window._debugRoundTripQuality(addr, partner, payments);
      const fundFlowDest = (fundFlow.destinations || []).find(d => d.addr === partner);
      const inboundSrc = (inboundFlow.topSources || []).find(s => s.addr === partner);
      return {
        fundFlowOut: fundFlowDest?.totalXrp ?? null,
        inboundIn: inboundSrc?.totalXrp ?? null,
        relXrpOut: rel.xrpOut,
        relXrpIn: rel.xrpIn,
        relTokenCurrency: rel.tokenFlowList?.[0]?.currency ?? null,
        relTokenInAmt: rel.tokenFlowList?.[0]?.inAmt ?? null,
        roundTripOccurrences: roundTrip?.occurrences ?? null,
      };
    }, { addr: WALLET, partner: PARTNER });

    assert(data.fundFlowOut != null && data.fundFlowOut > 0, `expected Fund Flow to show real outbound XRP to this partner, got ${data.fundFlowOut}`);
    assert(data.inboundIn != null && data.inboundIn > 0, `expected Inbound Flow to show real inbound XRP from this partner, got ${data.inboundIn}`);
    // Fund Flow aggregates ALL outbound to this dest; the Relationship
    // Drawer computes the exact same pairwise total via the shared helper —
    // they must agree now that both route through _extractPaymentAmount.
    assert(Math.abs(data.fundFlowOut - data.relXrpOut) < 0.001, `expected Fund Flow's and the Relationship Drawer's xrpOut to agree exactly, got ${data.fundFlowOut} vs ${data.relXrpOut}`);
    assert(Math.abs(data.inboundIn - data.relXrpIn) < 0.001, `expected Inbound Flow's and the Relationship Drawer's xrpIn to agree exactly, got ${data.inboundIn} vs ${data.relXrpIn}`);
    assert(data.relTokenCurrency === 'CORE', `expected the token currency to be pre-decoded ASCII ("CORE"), not raw hex, got "${data.relTokenCurrency}"`);
    assert(data.relTokenInAmt > 0, `expected a real nonzero token inbound amount, got ${data.relTokenInAmt}`);
    assert(data.roundTripOccurrences > 0, `expected a real round-trip relationship to be detected for this known two-way pair, got ${data.roundTripOccurrences}`);
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

test('The Relationship Drawer UI renders the pre-decoded token currency correctly, with no raw hex leaking through', async () => {
  await withPage(async (page, { pageErrors }) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, WALLET, { timeout: 90000 });
    await page.evaluate((partner) => window.openRelationshipDrawer(partner), PARTNER);
    await page.waitForTimeout(400);

    const drawerHtml = await page.evaluate(() => document.getElementById('relDrawerDetail')?.innerHTML || '');
    assert(drawerHtml.includes('Assets Moved'), 'expected the Assets Moved section to render for this token-and-XRP relationship');
    assert(drawerHtml.includes('CORE'), 'expected the real CORE token currency to render');
    assert(!drawerHtml.includes('434F524500'), 'expected no raw hex currency code to leak through into the rendered drawer');
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
