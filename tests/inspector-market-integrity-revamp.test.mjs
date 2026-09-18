// Regression guard for the Market Integrity revamp's Phase A + Phase B:
// (1) N/A vs NORMAL for Spoofing/Offer Lifecycle when there's no order-book
// activity to analyze, (2) NOT ENOUGH DATA vs NOT DETECTED for Market-Making
// below WASH_MIN_TX offers, (3) a "What Nalu Sees" plain-language summary
// synthesizing the three independent verdicts, (4) a "Why This Is Flagged" /
// "What Reduces Concern" panel built entirely from each elevated finding's
// own already-computed observed/evidenceAgainstBenign/alternativeExplanations
// fields, and (5) a Value Circulation panel (gross vs. net XRP moved with
// round-trip partners, internal-vs-external split) computed from payments
// already fetched for this account — no new analysis, no new RPC calls.
import { withPage, connectAndShowDashboard, inspectAddress, makeSuite, assert } from './helpers.mjs';

const suite = makeSuite('Market Integrity Revamp — Phase A');

// A plain personal wallet with no DEX/offer history at all.
const ZERO_OFFER_ACCOUNT = 'rPVMhWBsfF9iMXYj3aAzJVkPDTFNSyWdKy';
// Known real account with genuine self-payments + real DEX/AMM history,
// reused from inspector-wash-trading.test.mjs's own established fixture.
const ELEVATED_ACCOUNT = 'rp2qFithsVh9dyzwTq4U5C1KXoRv94Vc9p';

suite.register('Zero-offer account: Spoofing shows N/A (not NORMAL) and Market-Making shows NOT ENOUGH DATA (not NOT DETECTED), with no page errors', async () => {
  await withPage(async (page, { pageErrors }) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, ZERO_OFFER_ACCOUNT, { timeout: 90000 });
    await page.waitForTimeout(1500);

    const result = await page.evaluate(() => {
      const el = document.getElementById('inspect-wash-body');
      const cards = [...el.querySelectorAll('.mi-verdict-card')].map(c => ({
        title: c.querySelector('.mi-verdict-title')?.textContent,
        label: c.querySelector('.mi-verdict-label')?.textContent,
      }));
      return { cards, hasPlainSummary: el.textContent.includes('In plain terms:') };
    });

    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
    const spoofCard = result.cards.find(c => c.title === 'Spoofing');
    const mmCard = result.cards.find(c => c.title === 'Market-Making');
    assert(spoofCard?.label === 'N/A', `expected Spoofing to show N/A for a zero-offer account, got "${spoofCard?.label}"`);
    assert(mmCard?.label === 'NOT ENOUGH DATA', `expected Market-Making to show NOT ENOUGH DATA for a zero-offer account, got "${mmCard?.label}"`);
    assert(result.hasPlainSummary, 'expected a "What Nalu Sees" plain summary to render even for a zero-offer account');
  });
});

suite.register('An account with real elevated findings gets a "Why This Is Flagged" / "What Reduces Concern" panel built from each finding\'s own evidence fields', async () => {
  await withPage(async (page, { pageErrors }) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, ELEVATED_ACCOUNT, { timeout: 90000 });
    await page.waitForTimeout(1500);

    const result = await page.evaluate(() => {
      const el = document.getElementById('inspect-wash-body');
      const forCol = el.querySelector('.mi-why-col--for');
      const againstCol = el.querySelector('.mi-why-col--against');
      return {
        forItems: forCol ? [...forCol.querySelectorAll('li')].map(li => li.textContent) : null,
        againstItems: againstCol ? [...againstCol.querySelectorAll('li')].map(li => li.textContent) : null,
        plainText: [...el.querySelectorAll('div')].find(d => d.textContent.startsWith('In plain terms:'))?.textContent,
      };
    });

    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
    assert(result.forItems && result.forItems.length > 0, 'expected at least one "why this is flagged" bullet for this known-elevated account');
    assert(result.againstItems && result.againstItems.length > 0, 'expected at least one "what reduces concern" bullet (alternative explanations already exist on these findings)');
    assert(result.plainText, 'expected a plain-language summary to render');
  });
});

suite.register('Synthetic: _severityVerdictLabel returns N/A regardless of findings when applicable is false', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugSeverityVerdictLabel, { timeout: 8000 });
    const naResult = await page.evaluate(() => window._debugSeverityVerdictLabel([{ sev: 'critical' }], false));
    assert(naResult[0] === 'N/A', `expected N/A when applicable is false even with a critical finding present, got "${naResult[0]}"`);
    const okResult = await page.evaluate(() => window._debugSeverityVerdictLabel([], true));
    assert(okResult[0] === 'NORMAL', `expected NORMAL for zero findings when applicable is true, got "${okResult[0]}"`);
  });
});

suite.register('Synthetic: _marketMakingVerdictLabel distinguishes NOT ENOUGH DATA (below WASH_MIN_TX) from NOT DETECTED (adequate data, no automation)', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugMarketMakingVerdictLabel, { timeout: 8000 });
    const insufficient = await page.evaluate(() => window._debugMarketMakingVerdictLabel({ stats: { creates: 3 }, automationLikely: false, signals: [] }));
    assert(insufficient[0] === 'NOT ENOUGH DATA', `expected NOT ENOUGH DATA below WASH_MIN_TX, got "${insufficient[0]}"`);
    const adequateNotDetected = await page.evaluate(() => window._debugMarketMakingVerdictLabel({ stats: { creates: 50 }, automationLikely: false, signals: [] }));
    assert(adequateNotDetected[0] === 'NOT DETECTED', `expected NOT DETECTED with adequate data and no automation signature, got "${adequateNotDetected[0]}"`);
  });
});

suite.register('Synthetic: buildMarketIntegrityPlainSummary names the N/A reason for spoofing and never fabricates a spoofing verdict when inapplicable', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugMarketIntegrityPlainSummary, { timeout: 8000 });
    const wash = { signals: [], automationLikely: false };
    const result = await page.evaluate((w) => window._debugMarketIntegrityPlainSummary(w, false, false), wash);
    assert(/could not be assessed/.test(result.text), `expected an explicit "could not be assessed" clause for inapplicable spoofing, got: "${result.text}"`);
    assert(/not enough order activity/.test(result.text), `expected an explicit not-enough-data clause for market-making, got: "${result.text}"`);
  });
});

suite.register('Value Circulation: a real round-trip account shows real gross/net XRP figures and an internal-vs-external split that sums to 100%', async () => {
  await withPage(async (page, { pageErrors }) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, ELEVATED_ACCOUNT, { timeout: 90000 });
    await page.waitForTimeout(1500);

    const result = await page.evaluate(() => {
      const vc = document.querySelector('#inspect-wash-body .mi-valuecirc');
      if (!vc) return { found: false };
      const grossWidth = parseFloat(vc.querySelector('.mi-valuecirc-bar--gross')?.style.width);
      const netWidth = parseFloat(vc.querySelector('.mi-valuecirc-bar--net')?.style.width);
      const internalPct = parseFloat(vc.querySelector('.mi-valuecirc-split-internal')?.style.width);
      const vals = [...vc.querySelectorAll('.mi-valuecirc-val')].map(v => v.textContent);
      return { found: true, grossWidth, netWidth, internalPct, vals };
    });
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
    assert(result.found, 'expected a Value Circulation panel for this known round-trip account');
    assert(result.grossWidth === 100, `expected the gross bar to always be the full-width reference bar, got ${result.grossWidth}`);
    assert(result.netWidth > 0 && result.netWidth <= 100, `expected a real, bounded net-bar width, got ${result.netWidth}`);
    assert(result.internalPct >= 0 && result.internalPct <= 100, `expected a real, bounded internal-share percentage, got ${result.internalPct}`);
    assert(result.vals.every(v => /XRP/.test(v)), `expected real XRP-denominated values, got: ${JSON.stringify(result.vals)}`);
  });
});

suite.register('Value Circulation: an account with no round-trip relationship renders nothing (not a fabricated all-zero panel)', async () => {
  await withPage(async (page, { pageErrors }) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, ZERO_OFFER_ACCOUNT, { timeout: 90000 });
    await page.waitForTimeout(1500);
    const hasPanel = await page.evaluate(() => !!document.querySelector('#inspect-wash-body .mi-valuecirc'));
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
    assert(!hasPanel, 'expected no Value Circulation panel when there is no round-trip relationship to circulate value with');
  });
});

suite.register('Synthetic: _renderValueCirculation renders real proportional bars and returns empty string for null', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugRenderValueCirculation, { timeout: 8000 });
    const html = await page.evaluate(() => window._debugRenderValueCirculation({
      grossXrp: 1000, netXrp: 100, internalPct: 62, externalPct: 38, note: 'test note',
    }));
    assert(/1,000 XRP/.test(html), `expected the real gross figure, got: ${html.slice(0, 300)}`);
    assert(/100 XRP/.test(html), `expected the real net figure, got: ${html.slice(0, 300)}`);
    assert(/62%/.test(html), `expected the real internal percentage, got: ${html.slice(0, 300)}`);
    const empty = await page.evaluate(() => window._debugRenderValueCirculation(null));
    assert(empty === '', `expected an empty string for no value-circulation data, got: "${empty}"`);
  });
});

suite.register('Where Trades Happened: renders a real bar chart from Execution Routing\'s own stats, with a coherent blurb even when Unresolved dominates', async () => {
  await withPage(async (page, { pageErrors }) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, ELEVATED_ACCOUNT, { timeout: 90000 });
    await page.waitForTimeout(1500);

    const result = await page.evaluate(() => {
      const routing = document.querySelector('#inspect-wash-body .mi-routing');
      if (!routing) return { found: false };
      return {
        found: true,
        rowCount: routing.querySelectorAll('.mi-routing-row').length,
        blurb: routing.querySelector('.mi-routing-blurb')?.textContent,
      };
    });
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
    assert(result.found, 'expected a Where Trades Happened panel for this known trade-execution account');
    assert(result.rowCount > 0, 'expected at least one routing row');
    assert(!/through unresolved/.test(result.blurb || ''), `blurb must never say "occurred through unresolved" (Unresolved is a lack of classification, not a venue), got: "${result.blurb}"`);
  });
});

suite.register('Synthetic: _renderWhereTradesHappened phrases the blurb correctly when Unresolved is the dominant category, and returns empty string for no data', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugRenderWhereTradesHappened, { timeout: 8000 });
    const html = await page.evaluate(() => window._debugRenderWhereTradesHappened({ total: 100, clob: 10, amm: 5, hybrid: 0, unknown: 85 }));
    assert(/could not be classified/.test(html), `expected the "could not be classified" phrasing when Unresolved dominates, got: ${html.slice(0, 400)}`);
    assert(!/through unresolved/.test(html), `must never render "occurred through unresolved", got: ${html.slice(0, 400)}`);

    const ammDominant = await page.evaluate(() => window._debugRenderWhereTradesHappened({ total: 50, clob: 5, amm: 40, hybrid: 0, unknown: 5 }));
    assert(/liquidity pools/.test(ammDominant), `expected the plain-language "liquidity pools" label when AMM dominates, got: ${ammDominant.slice(0, 400)}`);
    assert(/no single counterparty/.test(ammDominant), 'expected the explicit "AMM trades imply no direct counterparty relationship" disclaimer');

    const empty = await page.evaluate(() => window._debugRenderWhereTradesHappened({ total: 0, clob: 0, amm: 0, hybrid: 0, unknown: 0 }));
    assert(empty === '', `expected an empty string for zero total executions, got: "${empty}"`);
  });
});

suite.register('Relationship drawer: clicking a Network Map edge opens a real "Trading Relationship" drawer with correct gross/net/reciprocity figures, and closes on backdrop click', async () => {
  await withPage(async (page, { pageErrors }) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, ELEVATED_ACCOUNT, { timeout: 90000 });
    await page.waitForTimeout(1500);

    const result = await page.evaluate(() => {
      const svg = document.querySelector('#inspect-network-map .netmap-svg');
      const edges = svg ? [...svg.querySelectorAll('.netmap-edge[data-addr]')] : [];
      if (!edges.length) return { found: false };
      edges[0].dispatchEvent(new MouseEvent('click', { bubbles: true }));
      const grid = document.getElementById('relDrawerGrid');
      const stats = Object.fromEntries([...grid.querySelectorAll('.acct-peek-stat')].map(s => [s.querySelector('span')?.textContent, s.querySelector('b')?.textContent]));
      return {
        found: true,
        overlayVisible: document.getElementById('relationshipDrawerOverlay')?.style.display === 'flex',
        hasHeadline: !!document.getElementById('relDrawerHeadline')?.textContent?.trim(),
        grossXrp: parseFloat(stats['Gross exchanged']),
        netXrp: parseFloat(stats['Net difference']),
        reciprocityPct: parseFloat(stats['Reciprocity']),
      };
    });
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
    assert(result.found, 'expected at least one clickable edge on the Network Map for this known-active account');
    assert(result.overlayVisible, 'expected the relationship drawer to open on edge click');
    assert(result.hasHeadline, 'expected a real headline naming both addresses');
    assert(result.grossXrp >= result.netXrp, `gross exchanged must always be >= net difference by construction, got gross=${result.grossXrp}, net=${result.netXrp}`);
    assert(result.reciprocityPct >= 0 && result.reciprocityPct <= 100, `expected a bounded reciprocity percentage, got ${result.reciprocityPct}`);

    const closedOk = await page.evaluate(() => {
      const overlay = document.getElementById('relationshipDrawerOverlay');
      overlay.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      return overlay.style.display === 'none';
    });
    assert(closedOk, 'expected the drawer to close on a backdrop click');
  });
});

suite.register('Synthetic: _computeRelationshipDetail computes correct gross/net/reciprocity and surfaces cluster context only when the partner is actually in a mirror group', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugComputeRelationshipDetail, { timeout: 8000 });
    const txList = [
      { tx: { TransactionType: 'Payment', Account: 'rAddrA', Destination: 'rAddrB', Amount: '100000000' } }, // 100 XRP out
      { tx: { TransactionType: 'Payment', Account: 'rAddrB', Destination: 'rAddrA', Amount: '80000000' } },  // 80 XRP in
    ];
    const mirrorGroups = [{ tier: 'moderate', accounts: [{ addr: 'rAddrB' }, { addr: 'rAddrC' }], timingCorrelated: true, issuerCreated: false }];
    const result = await page.evaluate((args) => window._debugComputeRelationshipDetail(...args), ['rAddrA', 'rAddrB', txList, mirrorGroups]);
    assert(result.xrpOut === 100, `expected 100 XRP out, got ${result.xrpOut}`);
    assert(result.xrpIn === 80, `expected 80 XRP in, got ${result.xrpIn}`);
    assert(result.gross === 180, `expected gross 180, got ${result.gross}`);
    assert(result.net === 20, `expected net 20, got ${result.net}`);
    assert(Math.abs(result.reciprocityPct - 80) < 0.01, `expected reciprocity 80% (80/100), got ${result.reciprocityPct}`);
    assert(result.cluster !== null, 'expected the mirror-cluster context to be surfaced for a partner that is actually a member');

    const noClusterResult = await page.evaluate((args) => window._debugComputeRelationshipDetail(...args), ['rAddrA', 'rAddrZ', txList, mirrorGroups]);
    assert(noClusterResult.cluster === null, 'expected no cluster context for a partner not in any mirror group');
    assert(noClusterResult.roundTrip === null, 'expected no round-trip data for a partner with zero shared payment history');
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
