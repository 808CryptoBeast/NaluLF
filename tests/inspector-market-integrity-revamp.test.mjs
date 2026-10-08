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

// A near-brand-new wallet with exactly one total transaction (its own
// funding payment) — zero offers and zero round-trip partners BY
// CONSTRUCTION, not by luck. The previous fixture here
// (rPVMhWBsfF9iMXYj3aAzJVkPDTFNSyWdKy, an ordinary established personal
// wallet) genuinely drifted: real continued on-chain activity gave it a
// real round-trip partner that didn't exist when these tests were written,
// which is expected for any actively-used real address over a long enough
// time horizon. A near-empty wallet is structurally far more durable for
// this purpose since it has almost no transaction history left to develop
// new relationships in, but is still a REAL address with REAL (if minimal)
// data, not a synthetic fixture — if it ever drifts too, the Value
// Circulation test below now fails with a self-diagnosing message instead
// of a bare assert.
const ZERO_OFFER_ACCOUNT = 'rGny7hv9af4zxK1zmqWHLib9VNRecMEhdo';
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
    const result = await page.evaluate(() => {
      const panel = document.querySelector('#inspect-wash-body .mi-valuecirc');
      return {
        hasPanel: !!panel,
        // Real numbers, not just a boolean — this fixture is a real,
        // ordinary mainnet wallet (not a synthetic/frozen address), so its
        // own future payment activity can legitimately give it a new
        // round-trip partner at any time. That's fixture drift, not an app
        // bug: if this ever fails, these figures prove the account's own
        // live state changed rather than leaving a bare "expected false,
        // got true" to re-investigate from scratch. Swap ZERO_OFFER_ACCOUNT
        // for a different ordinary wallet currently free of round-trip
        // activity if this recurs.
        grossXrp: panel?.querySelector('.mi-valuecirc-val')?.textContent || null,
      };
    });
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
    assert(!result.hasPanel, `expected no Value Circulation panel when there is no round-trip relationship to circulate value with — got a real panel showing ${result.grossXrp} of gross activity. This is a real, ordinary mainnet wallet (not a synthetic fixture); its own on-chain activity has likely drifted since this test was written and it now genuinely has a round-trip partner. Swap ZERO_OFFER_ACCOUNT for a different wallet currently free of round-trip activity rather than treating this as an app bug.`);
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

suite.register('Relationship drawer: clicking a Relationship Landscape row opens a real "Trading Relationship" drawer with correct gross/net/reciprocity figures, and closes on backdrop click', async () => {
  await withPage(async (page, { pageErrors }) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, ELEVATED_ACCOUNT, { timeout: 90000 });
    await page.waitForTimeout(1500);

    // Tree (the default view) keeps its branches collapsed until clicked —
    // Flow renders every relationship as a real account node unconditionally.
    await page.evaluate(() => window.setRelIntelView('flow'));
    await page.waitForTimeout(300);

    const result = await page.evaluate(() => {
      const rows = [...document.querySelectorAll('#inspect-relationship-landscape .rel-tree-node--account')];
      if (!rows.length) return { found: false };
      rows[0].dispatchEvent(new MouseEvent('click', { bubbles: true }));
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
    assert(result.found, 'expected at least one clickable row in the Relationship Landscape for this known-active account');
    assert(result.overlayVisible, 'expected the relationship drawer to open on row click');
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

// Regression for a real reported bug: a relationship built entirely on
// issued-token payments showed as an all-zero XRP grid ("0/7 payments,
// 0 XRP") with only a small caveat explaining why issued-token transfers
// weren't counted — looking broken rather than just being about a
// different asset. tokenFlowList (and first/last interaction dates, which
// span BOTH assets) fix that.
suite.register('_computeRelationshipDetail: a relationship built entirely on issued-token payments surfaces a real per-asset breakdown, not an all-zero XRP grid', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugComputeRelationshipDetail, { timeout: 8000 });
    const txList = [
      { tx: { TransactionType: 'Payment', Account: 'rAddrB', Destination: 'rAddrA', Amount: { currency: 'USD', issuer: 'rIssuer00000000000000000000000000000', value: '100' }, date: 800000000 } },
      { tx: { TransactionType: 'Payment', Account: 'rAddrB', Destination: 'rAddrA', Amount: { currency: 'USD', issuer: 'rIssuer00000000000000000000000000000', value: '250' }, date: 800086400 } },
      { tx: { TransactionType: 'Payment', Account: 'rAddrA', Destination: 'rAddrB', Amount: { currency: 'EUR', issuer: 'rIssuer00000000000000000000000000000', value: '40' }, date: 800172800 } },
    ];
    const result = await page.evaluate((args) => window._debugComputeRelationshipDetail(...args), ['rAddrA', 'rAddrB', txList, []]);

    // The XRP-only stats correctly read zero — this is the honest part of
    // the pre-fix behavior, kept as-is.
    assert(result.xrpIn === 0 && result.xrpOut === 0 && result.gross === 0, 'expected XRP stats to stay at 0 for a token-only relationship');
    assert(result.inCount === 2 && result.outCount === 1, `expected inCount 2 / outCount 1 (both currencies pooled), got in=${result.inCount} out=${result.outCount}`);

    // The NEW per-asset breakdown must show what actually moved.
    const usd = result.tokenFlowList.find(t => t.currency === 'USD');
    const eur = result.tokenFlowList.find(t => t.currency === 'EUR');
    assert(usd, 'expected a USD entry in tokenFlowList');
    assert(usd.inAmt === 350 && usd.inCount === 2 && usd.outAmt === 0, `expected USD: 350 in across 2 payments, 0 out, got ${JSON.stringify(usd)}`);
    assert(eur, 'expected a EUR entry in tokenFlowList');
    assert(eur.outAmt === 40 && eur.outCount === 1 && eur.inAmt === 0, `expected EUR: 40 out across 1 payment, 0 in, got ${JSON.stringify(eur)}`);

    // First/last interaction must span BOTH assets, not just the (empty) XRP set.
    assert(result.firstDate === 800000000, `expected firstDate to be the earliest payment regardless of asset, got ${result.firstDate}`);
    assert(result.lastDate === 800172800, `expected lastDate to be the latest payment regardless of asset, got ${result.lastDate}`);
    assert(result.activeSpanDays === 2, `expected a 2-day active span, got ${result.activeSpanDays}`);
  });
});

suite.register('Live regression: the relationship drawer renders First/Last interaction and an Assets Moved breakdown for a real active account, with no page errors', async () => {
  await withPage(async (page, { pageErrors }) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, ELEVATED_ACCOUNT, { timeout: 90000 });
    await page.waitForTimeout(1500);

    const result = await page.evaluate(() => {
      const btn = document.querySelector('.mi-rel-examine, .lp-addr-btn');
      if (!btn) return { found: false };
      btn.click();
      const grid = document.getElementById('relDrawerGrid')?.innerHTML || '';
      const detail = document.getElementById('relDrawerDetail')?.innerHTML || '';
      return {
        found: true,
        overlayVisible: getComputedStyle(document.getElementById('relationshipDrawerOverlay')).display === 'flex',
        hasFirstInteraction: grid.includes('First interaction'),
        hasLastInteraction: grid.includes('Last interaction'),
        detailMentionsAssets: detail.includes('Assets Moved') || detail.includes('XRP-denominated payments only'),
      };
    });
    assert(result.found, 'expected at least one real relationship/Examine trigger on this known-active account');
    assert(result.overlayVisible, 'expected the relationship drawer to actually open');
    assert(result.hasFirstInteraction, 'expected a First interaction stat to render');
    assert(result.hasLastInteraction, 'expected a Last interaction stat to render');
    assert(result.detailMentionsAssets, 'expected the drawer detail to explain or show the asset breakdown');
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

suite.register('_computeRelationshipDetail: classifies the behavioral pattern (direction + frequency) correctly, never as a risk signal', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugComputeRelationshipDetail, { timeout: 8000 });

    const cases = [
      { name: 'primarily inbound + one-time', txs: [{ tx: { TransactionType: 'Payment', Account: 'rB', Destination: 'rA', Amount: '50000000', date: 1 } }], expect: 'Primarily inbound · One-time' },
      { name: 'primarily outbound + recurring', txs: [
        { tx: { TransactionType: 'Payment', Account: 'rA', Destination: 'rB', Amount: '10000000', date: 1 } },
        { tx: { TransactionType: 'Payment', Account: 'rA', Destination: 'rB', Amount: '20000000', date: 2 } },
      ], expect: 'Primarily outbound · Recurring' },
      { name: 'highly reciprocal (>=70% match)', txs: [
        { tx: { TransactionType: 'Payment', Account: 'rA', Destination: 'rB', Amount: '100000000', date: 1 } },
        { tx: { TransactionType: 'Payment', Account: 'rB', Destination: 'rA', Amount: '90000000', date: 2 } },
      ], expect: 'Highly reciprocal · Recurring' },
      { name: 'two-way but not highly reciprocal (<70% match)', txs: [
        { tx: { TransactionType: 'Payment', Account: 'rA', Destination: 'rB', Amount: '100000000', date: 1 } },
        { tx: { TransactionType: 'Payment', Account: 'rB', Destination: 'rA', Amount: '30000000', date: 2 } },
      ], expect: 'Two-way · Recurring' },
    ];
    for (const c of cases) {
      const result = await page.evaluate((args) => window._debugComputeRelationshipDetail(...args), ['rA', 'rB', c.txs, []]);
      assert(result.pattern === c.expect, `[${c.name}] expected pattern "${c.expect}", got "${result.pattern}"`);
    }

    // Token-only relationship (no XRP legs at all) correctly gets NO
    // direction label — the asset breakdown describes it instead, not a
    // fabricated "Primarily inbound" that isn't actually about XRP.
    const tokenOnly = await page.evaluate((args) => window._debugComputeRelationshipDetail(...args),
      ['rA', 'rB', [{ tx: { TransactionType: 'Payment', Account: 'rB', Destination: 'rA', Amount: { currency: 'USD', issuer: 'rIssuer', value: '10' }, date: 1 } }], []]);
    assert(tokenOnly.pattern === 'One-time', `expected a token-only relationship to get frequency-only "One-time" (no direction claim), got "${tokenOnly.pattern}"`);
  });
});

suite.register('_computeRelationshipDetail: when addr is the token issuer, a holder\'s real activity is surfaced as "Observed Token Activity" even with zero direct payments between addr and that holder (e.g. the holder traded with a THIRD party, but the issuer\'s own trustline obligation still makes that balance change ledger-visible to it)', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugComputeRelationshipDetail, { timeout: 8000 });

    const issuer = 'rIssuer00000000000000000000000000';
    const holder = 'rHolderPartner000000000000000000000';
    const thirdParty = 'rThirdPartyTrader0000000000000000000';
    const currency = '464F4F00000000000000000000000000000000'; // hex "FOO"
    // A payment entirely between thirdParty and holder — addr (the
    // issuer) is neither tx.Account nor tx.Destination — but it still
    // moves the issuer's own currency, so the RippleState node the
    // issuer is one side of changes regardless of who submitted it.
    const txList = [{
      tx: { Account: thirdParty, Destination: holder, TransactionType: 'Payment', Amount: { currency, issuer, value: '250' }, date: 800000000, hash: 'h1' },
      meta: {
        TransactionResult: 'tesSUCCESS',
        delivered_amount: { currency, issuer, value: '250' },
        AffectedNodes: [{
          ModifiedNode: {
            LedgerEntryType: 'RippleState',
            FinalFields: {
              Balance: { currency, issuer: 'rrrrrrrrrrrrrrrrrrrrrrrrrrrrrqLQg', value: '-750' },
              LowLimit: { issuer, currency, value: '0' },
              HighLimit: { issuer: holder, currency, value: '1000000' },
            },
            PreviousFields: { Balance: { currency, issuer: 'rrrrrrrrrrrrrrrrrrrrrrrrrrrrrqLQg', value: '-500' } },
          },
        }],
      },
    }];
    const result = await page.evaluate((args) => window._debugComputeRelationshipDetail(...args), [issuer, holder, txList, []]);
    assert(result.tokenFlowList.length === 0, 'expected no direct-Payment token flow (addr was never Account or Destination of this tx)');
    assert(result.observedViaLedger, 'expected observedViaLedger to surface this real, ledger-visible activity instead of showing nothing');
    assert(result.observedViaLedger.cnt === 1, `expected 1 observed transaction, got ${result.observedViaLedger.cnt}`);
    const vol = result.observedViaLedger.tokenVolume.find(t => t.currency === currency);
    assert(vol && Math.abs(vol.amount - 250) < 0.01, `expected 250 units of real observed FOO volume, got ${JSON.stringify(result.observedViaLedger.tokenVolume)}`);

    // The common direct-payment case must be completely unaffected —
    // observedViaLedger only ever fills the gap, never overrides it.
    const directCase = await page.evaluate((args) => window._debugComputeRelationshipDetail(...args),
      ['rA', 'rB', [{ tx: { TransactionType: 'Payment', Account: 'rA', Destination: 'rB', Amount: '50000000', date: 1 } }], []]);
    assert(directCase.observedViaLedger === null, 'expected observedViaLedger to stay null when direct-Payment data already exists');
  });
});

suite.register('Live regression: the relationship drawer shows rank/share among funding sources and real cross-link buttons when opened from Inbound Flow', async () => {
  await withPage(async (page, { pageErrors }) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, 'rPVMhWBsfF9iMXYj3aAzJVkPDTFNSyWdKy', { timeout: 90000 }); // Bitstamp hot wallet — many real inbound sources
    await page.waitForTimeout(1000);
    await page.evaluate(() => window.toggleAnalystMode());
    await page.waitForTimeout(300);

    const result = await page.evaluate(() => {
      const btn = document.querySelector('#inspect-inbound-body .mi-rel-examine');
      if (!btn) return { found: false };
      btn.click();
      const grid = document.getElementById('relDrawerGrid')?.innerHTML || '';
      const detail = document.getElementById('relDrawerDetail')?.innerHTML || '';
      return {
        found: true,
        hasShare: grid.includes('Share of tracked XRP inflow'),
        hasRank: /Rank among funding sources.*#\d+ of \d+/s.test(grid),
        hasPattern: grid.includes('Relationship pattern'),
        hasInspectBtn: detail.includes('Inspect this account'),
        hasCompareBtn: detail.includes('Compare accounts'),
      };
    });
    assert(result.found, 'expected at least one real Examine button in the Inbound Flow panel for this known top-funded account');
    assert(result.hasShare, 'expected "Share of tracked XRP inflow" to render for a known inbound funding source');
    assert(result.hasRank, 'expected a real "#N of M" rank to render for a known inbound funding source');
    assert(result.hasPattern, 'expected a Relationship pattern label to render');
    assert(result.hasInspectBtn, 'expected an "Inspect this account" cross-link button');
    assert(result.hasCompareBtn, 'expected a "Compare accounts" cross-link button');
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

suite.register('Relationship drawer cross-links: Compare pre-fills the partner as Account B and closes the drawer; Inspect re-runs the inspection on the partner', async () => {
  await withPage(async (page, { pageErrors }) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, ELEVATED_ACCOUNT, { timeout: 90000 });
    await page.waitForTimeout(1500);

    const compareResult = await page.evaluate(() => {
      const btn = document.querySelector('.mi-rel-examine, .lp-addr-btn');
      if (!btn) return { found: false };
      btn.click();
      const compareBtn = [...document.querySelectorAll('#relDrawerDetail .mi-rel-examine')].find(b => b.textContent.includes('Compare'));
      if (!compareBtn) return { found: true, hasCompareBtn: false };
      compareBtn.click();
      return {
        found: true, hasCompareBtn: true,
        compareOverlayVisible: getComputedStyle(document.getElementById('compareOverlay')).display !== 'none',
        relDrawerClosed: getComputedStyle(document.getElementById('relationshipDrawerOverlay')).display === 'none',
        compareBFilled: document.getElementById('compareAddrBInput')?.value?.length > 0,
      };
    });
    assert(compareResult.found, 'expected at least one relationship/Examine trigger');
    assert(compareResult.hasCompareBtn, 'expected a Compare accounts cross-link button in the drawer');
    assert(compareResult.compareOverlayVisible, 'expected clicking Compare to actually open the Compare modal');
    assert(compareResult.relDrawerClosed, 'expected the relationship drawer to close when Compare is clicked');
    assert(compareResult.compareBFilled, 'expected the partner address to pre-fill Account B');
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

suite.register('Relationships Worth Reviewing: ranks real distinct counterparties (never the inspected account itself), each opening the drawer via Examine', async () => {
  await withPage(async (page, { pageErrors }) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, ELEVATED_ACCOUNT, { timeout: 90000 });
    await page.waitForTimeout(1500);

    const result = await page.evaluate(() => {
      const rel = document.querySelector('#inspect-wash-body .mi-relationships');
      if (!rel) return { found: false };
      const cards = [...rel.querySelectorAll('.mi-rel-card')].map(c => ({
        partner: c.querySelector('.mi-rel-partner')?.textContent,
        evidence: c.querySelector('.mi-rel-evidence')?.textContent,
      }));
      const firstBtn = rel.querySelector('.mi-rel-examine');
      firstBtn?.click();
      return { found: true, cards, drawerOpen: document.getElementById('relationshipDrawerOverlay')?.style.display === 'flex' };
    });
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
    assert(result.found, 'expected a Relationships Worth Reviewing panel for this known round-trip account');
    assert(result.cards.length > 0, 'expected at least one relationship card');
    assert(result.cards.every(c => c.evidence === 'Strong' || c.evidence === 'Moderate' || c.evidence === 'Weak'), `expected a real evidence label on every card, got: ${JSON.stringify(result.cards)}`);
    // Regression: a self-payment (Account === Destination === addr) must
    // never make this account appear as its own "round-trip counterparty".
    const addrPrefix = ELEVATED_ACCOUNT.slice(0, 8);
    assert(!result.cards.some(c => c.partner?.includes(addrPrefix)), `expected no card naming the inspected account itself as a counterparty, got: ${JSON.stringify(result.cards)}`);
    assert(result.drawerOpen, 'expected clicking Examine to open the relationship drawer');
  });
});

suite.register('Regression: a self-payment never makes an account appear as its own round-trip counterparty in analyseWashExecution or detectFlowMotifs', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugWashExecution && window._debugFlowMotifs, { timeout: 8000 });
    const addr = 'rSelfPayTestAccount0000000000000000';
    const txList = [
      // A genuine self-payment: Account === Destination === addr.
      { tx: { TransactionType: 'Payment', Account: addr, Destination: addr, Amount: '5000000' } },
      // One real, distinct round-trip partner, so the round-trip code path
      // actually runs and isn't just short-circuited by an empty list.
      { tx: { TransactionType: 'Payment', Account: addr, Destination: 'rRealPartner00000000000000000000000', Amount: '10000000' } },
      { tx: { TransactionType: 'Payment', Account: 'rRealPartner00000000000000000000000', Destination: addr, Amount: '9000000' } },
    ];
    const profile = { createdCount: 0, cancelRatio: 0, sizeCV: null, burstWindows: { thirtySec: 0, oneHour: 0 } };
    const offerLifecycles = { list: [] };
    const execResult = await page.evaluate((args) => {
      const [profile, offerLifecycles, txList, addr] = args;
      return window._debugWashExecution(profile, offerLifecycles, txList, addr, false, null);
    }, [profile, offerLifecycles, txList, addr]);
    assert(execResult.stats.roundTrip === 1, `expected exactly 1 real round-trip counterparty (the self-payment must not count), got ${execResult.stats.roundTrip}`);
    assert(!execResult.topRelationships.some(r => r.counterparty === addr), `expected no relationship naming the account as its own counterparty, got: ${JSON.stringify(execResult.topRelationships)}`);

    const motifResult = await page.evaluate((args) => window._debugFlowMotifs(...args), [txList, addr]);
    const selfMotif = motifResult.motifs.find(m => m.type === 'ROUND_TRIP' && m.counterparty === addr);
    assert(!selfMotif, `expected no ROUND_TRIP motif naming the account as its own counterparty, got: ${JSON.stringify(motifResult.motifs)}`);
  });
});

suite.register('Regression: badge-wash, its nav status dot, and the smart-collapse default all agree with the panel\'s own independent verdict cards (not the deprecated combined score)', async () => {
  await withPage(async (page, { pageErrors }) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, ELEVATED_ACCOUNT, { timeout: 90000 });
    await page.waitForTimeout(1500);

    const result = await page.evaluate(() => {
      const execLabel = document.querySelector('#inspect-wash-body .mi-verdict-card:nth-child(1) .mi-verdict-label')?.textContent;
      const spoofLabel = document.querySelector('#inspect-wash-body .mi-verdict-card:nth-child(2) .mi-verdict-label')?.textContent;
      const badge = document.getElementById('badge-wash');
      const navDot = document.querySelector('#inspector-nav .in-btn[data-jump="wash"] .in-status-dot');
      return {
        execLabel, spoofLabel,
        badgeText: badge?.textContent,
        badgeIsElevated: badge?.className.includes('--warn') || badge?.className.includes('--crit'),
        navDotIsElevated: navDot?.className.includes('--warn') || navDot?.className.includes('--crit'),
        sectionOpen: !document.getElementById('section-wash')?.classList.contains('collapsed'),
      };
    });
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
    const ELEVATED_LABELS = new Set(['WATCH', 'ELEVATED']);
    const expectedElevated = ELEVATED_LABELS.has(result.execLabel) || ELEVATED_LABELS.has(result.spoofLabel);
    // The badge must show whichever card actually drove the elevation (or
    // Wash Execution's own label when nothing is elevated) — never a
    // number derived from the deprecated combined score.
    const expectedBadgeText = ELEVATED_LABELS.has(result.execLabel) ? result.execLabel
      : ELEVATED_LABELS.has(result.spoofLabel) ? result.spoofLabel
      : result.execLabel;
    assert(result.badgeText === expectedBadgeText, `expected badge text "${expectedBadgeText}" (derived from the verdict cards: exec="${result.execLabel}", spoof="${result.spoofLabel}"), got "${result.badgeText}"`);
    assert(result.badgeIsElevated === expectedElevated, `expected badge severity (${result.badgeIsElevated}) to match card-derived expectation (${expectedElevated})`);
    assert(result.navDotIsElevated === result.badgeIsElevated, 'expected the nav status dot to always agree with the section badge');
    assert(result.sectionOpen === result.badgeIsElevated, 'expected the smart-collapse default to always agree with the section badge');
  });
});

suite.register('Regression: the Full Report never resurrects the deprecated "wash score X/100" language, and its Market Integrity stat row matches the panel\'s own verdicts', async () => {
  await withPage(async (page, { pageErrors }) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, ELEVATED_ACCOUNT, { timeout: 90000 });
    await page.waitForTimeout(1500);

    const result = await page.evaluate(() => {
      const execLabel = document.querySelector('#inspect-wash-body .mi-verdict-card:nth-child(1) .mi-verdict-label')?.textContent;
      const spoofLabel = document.querySelector('#inspect-wash-body .mi-verdict-card:nth-child(2) .mi-verdict-label')?.textContent;
      const reportBody = document.getElementById('inspect-report-body');
      const reportText = reportBody?.textContent || '';
      const statRow = [...reportBody?.querySelectorAll('.report-stat-row') || []].find(r => r.textContent.includes('Market Integrity'))?.textContent || '';
      return {
        execLabel, spoofLabel,
        mentionsOldScoreLanguage: /wash score/i.test(reportText),
        statRowHasExec: statRow.includes(execLabel || ' '),
        statRowHasSpoof: statRow.includes(spoofLabel || ' '),
      };
    });
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
    assert(!result.mentionsOldScoreLanguage, 'expected the report to never say "wash score X/100" anywhere');
    assert(result.statRowHasExec, `expected the report's Market Integrity stat row to include the real Wash Execution label ("${result.execLabel}")`);
    assert(result.statRowHasSpoof, `expected the report's Market Integrity stat row to include the real Spoofing label ("${result.spoofLabel}")`);
  });
});

suite.register('Synthetic: _washSectionSeverity picks the worse of Wash Execution/Spoofing tone, excludes Market-Making entirely, and never lets N/A escalate severity', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugWashSectionSeverity, { timeout: 8000 });

    const cleanZeroOffers = await page.evaluate(() => window._debugWashSectionSeverity({
      stats: { creates: 0 }, automationLikely: true,
      signals: [{ module: 'Wash Execution', sev: 'ok' }, { module: 'Market-Maker Automation', sev: 'info' }],
    }));
    assert(cleanZeroOffers.tone === 'ok', `expected 'ok' tone when execution is clean and spoofing is N/A (must not escalate), got ${cleanZeroOffers.tone}`);
    assert(cleanZeroOffers.spoofPair[0] === 'N/A', `expected spoofing N/A with zero offers, got ${cleanZeroOffers.spoofPair[0]}`);

    const spoofDrivesIt = await page.evaluate(() => window._debugWashSectionSeverity({
      stats: { creates: 50 }, automationLikely: false,
      signals: [{ module: 'Wash Execution', sev: 'ok' }, { module: 'Spoofing', sev: 'critical' }],
    }));
    assert(spoofDrivesIt.tone === 'crit', `expected spoofing's critical severity to drive the overall tone, got ${spoofDrivesIt.tone}`);
    assert(spoofDrivesIt.label === spoofDrivesIt.spoofPair[0], 'expected the label to come from whichever side actually drove the elevated tone');

    const executionDrivesIt = await page.evaluate(() => window._debugWashSectionSeverity({
      stats: { creates: 50 }, automationLikely: false,
      signals: [{ module: 'Wash Execution', sev: 'warn' }, { module: 'Spoofing', sev: 'ok' }],
    }));
    assert(executionDrivesIt.tone === 'warn', `expected execution's warn severity to drive the overall tone, got ${executionDrivesIt.tone}`);
    assert(executionDrivesIt.label === executionDrivesIt.execPair[0], 'expected the label to come from Wash Execution when it is the elevated side');
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
