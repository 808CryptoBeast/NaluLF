// Regression guard for verified-vs-inferred edges on the Network Map
// (Flow Intelligence spec §9-10). Every edge in this map is a REAL,
// ledger-verified direct value transfer (from _buildCounterpartyData) —
// never speculative. The one genuinely INFERRED relationship this app
// computes anywhere is Issuer Connections' mirror-wallet clusters
// (accounts that MAY share a controller — never proof of common
// ownership). This must render as a visually distinct marker on the
// NODE, never blur into the (always-verified) edge itself, and must
// never appear at all when no mirror groups exist.
import { withPage, connectAndShowDashboard, inspectAddress, makeSuite, assert } from './helpers.mjs';

const suite = makeSuite('Network Map — Verified vs Inferred');

const ADDR = 'rInspected00000000000000000000000000';
const CLUSTER_MEMBER = 'rCluster10000000000000000000000000000';
const OTHER_CP = 'rOtherCp0000000000000000000000000000';

function txList() {
  return [
    { tx: { Account: ADDR, Destination: CLUSTER_MEMBER, TransactionType: 'Payment', Amount: '5000000', hash: 'h1', date: 1000 } },
    { tx: { Account: ADDR, Destination: OTHER_CP, TransactionType: 'Payment', Amount: '3000000', hash: 'h2', date: 1000 } },
  ];
}
function mirrorGroups() {
  return [{ accounts: [{ addr: CLUSTER_MEMBER, amt: 500 }, { addr: 'rX1', amt: 500 }, { addr: 'rX2', amt: 500 }], tier: 'Moderate', timingCorrelated: true, issuerCreated: false, confidence: 0.55 }];
}

suite.register('A real active account with no mirror clusters renders the "verified" caption, no inferred markers, and no page errors', async () => {
  await withPage(async (page) => {
    const errors = [];
    page.on('pageerror', e => errors.push(e.message));
    await connectAndShowDashboard(page);
    await inspectAddress(page, 'rPVMhWBsfF9iMXYj3aAzJVkPDTFNSyWdKy', { timeout: 90000 });
    await page.waitForTimeout(1500);

    const result = await page.evaluate(() => {
      const el = document.getElementById('inspect-network-map');
      return {
        hasVerifiedText: /verified/i.test(el?.innerHTML || ''),
        hasClusterLegend: /Possible cluster \(inferred\)/.test(el?.innerHTML || ''),
      };
    });
    assert(errors.length === 0, `expected zero page errors, got: ${JSON.stringify(errors)}`);
    assert(result.hasVerifiedText, 'expected the map to explicitly state its edges are verified');
    assert(!result.hasClusterLegend, 'must not show the inferred-cluster legend when there are no mirror groups');
  });
});

suite.register('Synthetic: a node that is a mirror-cluster member gets a distinct dashed inferred-marker ring, tooltip note, and legend entry', async () => {
  await withPage(async (page) => {
    await connectAndShowDashboard(page);
    await page.evaluate(() => window.switchTab(null, 'inspector'));
    await page.waitForFunction(() => window._debugRenderNetworkMap && document.getElementById('inspect-network-map'), { timeout: 8000 });
    const result = await page.evaluate(([tx, mg, addr]) => {
      window._debugRenderNetworkMap(tx, addr, { totalOut: 0 }, { totalIn: 0 }, mg, 'inspect-network-map');
      const el = document.getElementById('inspect-network-map');
      return {
        hasClusterRing: /rgba\(189,147,249/.test(el.innerHTML),
        hasInferredLegend: /Possible cluster \(inferred\)/.test(el.innerHTML),
        hasInferredCaption: /separate.*inferred.*relationship/i.test(el.innerHTML),
        hasTooltipNote: /INFERRED: possibly part of a 3-wallet cluster/.test(el.innerHTML),
        hasNotVerifiedDisclaimer: /not verified common ownership/.test(el.innerHTML),
      };
    }, [txList(), mirrorGroups(), ADDR]);

    assert(result.hasClusterRing, 'expected a visually distinct dashed ring on the cluster-member node');
    assert(result.hasInferredLegend, 'expected an inferred-cluster legend entry');
    assert(result.hasInferredCaption, 'expected the caption to explicitly separate verified edges from the inferred cluster relationship');
    assert(result.hasTooltipNote, 'expected the tooltip to name the real cluster size');
    assert(result.hasNotVerifiedDisclaimer, 'expected an explicit "not verified common ownership" disclaimer — never equate inferred with proven');
  });
});

suite.register('Synthetic: a counterparty NOT in any mirror group gets no inferred marker, even when other nodes in the same map do', async () => {
  await withPage(async (page) => {
    await connectAndShowDashboard(page);
    await page.evaluate(() => window.switchTab(null, 'inspector'));
    await page.waitForFunction(() => window._debugRenderNetworkMap && document.getElementById('inspect-network-map'), { timeout: 8000 });
    const result = await page.evaluate(([tx, mg, addr, other]) => {
      window._debugRenderNetworkMap(tx, addr, { totalOut: 0 }, { totalIn: 0 }, mg, 'inspect-network-map');
      const el = document.getElementById('inspect-network-map');
      // The "other" counterparty's own <g> block should not carry the cluster note.
      return { mentionsOtherWithInferred: new RegExp(other + '[^|]*INFERRED').test(el.innerHTML) };
    }, [txList(), mirrorGroups(), ADDR, OTHER_CP]);
    assert(!result.mentionsOtherWithInferred, 'a non-cluster-member counterparty must never be marked inferred just because the map contains an inferred node elsewhere');
  });
});

suite.register('No mirror groups passed at all (default param) does not throw and renders normally', async () => {
  await withPage(async (page) => {
    await connectAndShowDashboard(page);
    await page.evaluate(() => window.switchTab(null, 'inspector'));
    await page.waitForFunction(() => window._debugRenderNetworkMap && document.getElementById('inspect-network-map'), { timeout: 8000 });
    const result = await page.evaluate(([tx, addr]) => {
      window._debugRenderNetworkMap(tx, addr, { totalOut: 0 }, { totalIn: 0 });
      const el = document.getElementById('inspect-network-map');
      return { hasSvg: !!el.querySelector('svg'), hasClusterLegend: /Possible cluster \(inferred\)/.test(el.innerHTML) };
    }, [txList(), ADDR]);
    assert(result.hasSvg, 'expected the map to still render with no mirrorGroups argument at all');
    assert(!result.hasClusterLegend, 'must not fabricate an inferred legend with no cluster data');
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
