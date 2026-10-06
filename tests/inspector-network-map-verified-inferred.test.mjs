// Regression guard for verified-vs-inferred relationships on the
// Relationship Landscape (Flow Intelligence spec §9-10; the view itself
// replaced the old radial bubble "Network Map" — see
// inspector-legacy-css-revamp and the Relationship Intelligence rollout).
// Every relationship row is a REAL, ledger-verified direct value transfer
// (from _buildCounterpartyData) — never speculative. The one genuinely
// INFERRED relationship this app computes anywhere is Issuer Connections'
// mirror-wallet clusters (accounts that MAY share a controller — never
// proof of common ownership). This must render as a visually distinct
// badge on the ROW, never blur into the (always-verified) relationship
// itself, and must never appear at all when no mirror groups exist.
import { withPage, connectAndShowDashboard, inspectAddress, makeSuite, assert } from './helpers.mjs';

const suite = makeSuite('Relationship Landscape — Verified vs Inferred');

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
      const el = document.getElementById('inspect-relationship-landscape');
      return {
        hasVerifiedText: /verified/i.test(el?.innerHTML || ''),
        hasClusterBadge: /⚬\s*cluster \(inferred\)/.test(el?.innerHTML || ''),
      };
    });
    assert(errors.length === 0, `expected zero page errors, got: ${JSON.stringify(errors)}`);
    assert(result.hasVerifiedText, 'expected the Relationship Landscape to explicitly state its relationships are verified');
    assert(!result.hasClusterBadge, 'must not show the inferred-cluster badge when there are no mirror groups');
  });
});

suite.register('Synthetic: a row that is a mirror-cluster member gets a distinct dashed inferred-cluster badge with a tooltip note', async () => {
  await withPage(async (page) => {
    await connectAndShowDashboard(page);
    await page.evaluate(() => window.switchTab(null, 'inspector'));
    await page.waitForFunction(() => window._debugRenderRelationshipLandscape && document.getElementById('inspect-relationship-landscape'), { timeout: 8000 });
    const result = await page.evaluate(([tx, mg, addr]) => {
      window._debugRenderRelationshipLandscape(tx, addr, mg, { totalIn: 0 }, 'inspect-relationship-landscape');
      // Tree (the default view) keeps its branches collapsed until clicked
      // — Flow renders every relationship row (and its cluster badge, if
      // any) unconditionally.
      window.setRelIntelView('flow');
      const el = document.getElementById('inspect-relationship-landscape');
      return {
        hasClusterBadge: /⚬\s*cluster \(inferred\)/.test(el.innerHTML),
        hasTooltipNote: /Possibly part of a 3-wallet cluster/.test(el.innerHTML),
        hasNotVerifiedDisclaimer: /not verified common ownership/.test(el.innerHTML),
      };
    }, [txList(), mirrorGroups(), ADDR]);

    assert(result.hasClusterBadge, 'expected a visually distinct inferred-cluster badge on the cluster-member row');
    assert(result.hasTooltipNote, 'expected the tooltip to name the real cluster size');
    assert(result.hasNotVerifiedDisclaimer, 'expected an explicit "not verified common ownership" disclaimer — never equate inferred with proven');
  });
});

suite.register('Synthetic: a counterparty NOT in any mirror group gets no inferred marker, even when other rows in the same landscape do', async () => {
  await withPage(async (page) => {
    await connectAndShowDashboard(page);
    await page.evaluate(() => window.switchTab(null, 'inspector'));
    await page.waitForFunction(() => window._debugRenderRelationshipLandscape && document.getElementById('inspect-relationship-landscape'), { timeout: 8000 });
    const result = await page.evaluate(([tx, mg, addr, other]) => {
      window._debugRenderRelationshipLandscape(tx, addr, mg, { totalIn: 0 }, 'inspect-relationship-landscape');
      window.setRelIntelView('flow');
      const rows = [...document.querySelectorAll('#inspect-relationship-landscape .ranked-cp-row')];
      const otherRow = rows.find(r => r.innerHTML.includes(other));
      return { otherRowHasClusterBadge: otherRow ? /⚬\s*cluster \(inferred\)/.test(otherRow.innerHTML) : null };
    }, [txList(), mirrorGroups(), ADDR, OTHER_CP]);
    assert(result.otherRowHasClusterBadge === false, 'a non-cluster-member counterparty must never be marked inferred just because the landscape contains an inferred row elsewhere');
  });
});

suite.register('No mirror groups passed at all (default param) does not throw and renders normally', async () => {
  await withPage(async (page) => {
    await connectAndShowDashboard(page);
    await page.evaluate(() => window.switchTab(null, 'inspector'));
    await page.waitForFunction(() => window._debugRenderRelationshipLandscape && document.getElementById('inspect-relationship-landscape'), { timeout: 8000 });
    const result = await page.evaluate(([tx, addr]) => {
      window._debugRenderRelationshipLandscape(tx, addr, undefined, { totalIn: 0 }, 'inspect-relationship-landscape');
      window.setRelIntelView('flow');
      const el = document.getElementById('inspect-relationship-landscape');
      return { hasRows: !!el.querySelector('.ranked-cp-row'), hasClusterBadge: /⚬\s*cluster \(inferred\)/.test(el.innerHTML) };
    }, [txList(), ADDR]);
    assert(result.hasRows, 'expected the landscape to still render rows with no mirrorGroups argument at all');
    assert(!result.hasClusterBadge, 'must not fabricate an inferred badge with no cluster data');
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
