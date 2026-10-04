// Regression guard for "Distribution & Market Flow" — the first slice of a
// much larger "Issuer Distribution-to-Market Intelligence" spec (scoped via
// AskUserQuestion into 4 phases; this covers phase 1: does an issuer's
// largest direct token recipients show synchronized selling and/or proceeds
// consolidation?). Also covers a small piece of phase 2 (hop-count tracing)
// that landed here because it reuses phase 1's already-fetched per-cohort-
// wallet transaction page — see _extractHop2Recipients below.
//
// Deliberately on-demand (a button, not part of the automatic analysis
// pass) because it needs one extra account_tx round-trip PER cohort wallet
// (up to 8) — real, non-trivial cost compared to every other analysis in
// this file, which all work from data already fetched for the single
// inspected account.
//
// Two invariants this suite guards specifically, both explicit product
// decisions (not incidental behavior):
// 1. Severity NEVER reaches 'critical', no matter how many evidence
//    families fire — the ledger can show WHAT happened, never WHY, so
//    common ownership/intent is never "established" at any confidence.
// 2. A large distribution share ALONE never produces a "worth reviewing"
//    finding — only real coordinated BEHAVIOR (synchronized selling and/or
//    proceeds consolidation) does; materiality only raises confidence once
//    a behavioral signal already exists, mirroring how the pre-existing
//    mirror-wallet clustering (Issuer Connections) never fires on amount
//    similarity alone without an independent corroborating signal.
import { withPage, freshSignup, connectAndShowDashboard, inspectAddress, makeSuite, assert } from './helpers.mjs';

const suite = makeSuite('Distribution & Market Flow');

const SOLO_ISSUER = 'rsoLo2S1kiGeCcn6hCUXVrCpGMWLrRrLZz';
const REAL_WALLETS = ['rnj7R3QUGzLZc9dg24jSrGabtt1tp1XD7A', 'rPVMhWBsfF9iMXYj3aAzJVkPDTFNSyWdKy', 'rsoLo2S1kiGeCcn6hCUXVrCpGMWLrRrLZz'];

suite.register('_clusterSellTimings: groups wallets whose first sell falls within the sync window, excludes ones outside it and ones that never sold', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugClusterSellTimings, { timeout: 8000 });
    const groups = await page.evaluate(() => {
      const base = 1_000_000_000;
      const cohort = [
        { addr: 'rA', firstSellTs: base },
        { addr: 'rB', firstSellTs: base + 600 },    // 10 min later — inside 6h window
        { addr: 'rC', firstSellTs: base + 3000 },   // 50 min later — inside 6h window
        { addr: 'rD', firstSellTs: base + 100000 }, // ~27.8h later — outside window
        { addr: 'rE', firstSellTs: null },          // never sold
      ];
      return window._debugClusterSellTimings(cohort).map(g => g.map(x => x.addr));
    });
    assert(groups.length === 1, `expected exactly one sync group, got ${groups.length}`);
    assert(groups[0].length === 3 && groups[0].includes('rA') && groups[0].includes('rB') && groups[0].includes('rC'), `expected the group to be exactly [rA,rB,rC], got ${JSON.stringify(groups[0])}`);
  });
});

suite.register('_clusterSellTimings: returns no groups when every wallet is spread far apart', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugClusterSellTimings, { timeout: 8000 });
    const groups = await page.evaluate(() => {
      const base = 1_000_000_000;
      const cohort = [{ addr: 'rA', firstSellTs: base }, { addr: 'rB', firstSellTs: base + 200000 }, { addr: 'rC', firstSellTs: base + 500000 }];
      return window._debugClusterSellTimings(cohort);
    });
    assert(groups.length === 0, `expected no sync groups, got ${groups.length}`);
  });
});

suite.register('_findProceedsConsolidation: requires 2+ DIFFERENT senders to the same destination, not just one wallet paying it repeatedly', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugFindProceedsConsolidation, { timeout: 8000 });
    const diag = await page.evaluate(() => {
      const cohort = [
        { addr: 'rA', proceedsPayments: [{ dest: 'rCommon', xrp: 1000, date: 1 }] },
        { addr: 'rB', proceedsPayments: [{ dest: 'rCommon', xrp: 500, date: 2 }] },
        { addr: 'rC', proceedsPayments: [{ dest: 'rExchange', xrp: 200, date: 3 }] }, // only 1 sender -> not consolidation
      ];
      const result = window._debugFindProceedsConsolidation(cohort);
      return { length: result.length, dest: result[0]?.dest, senderCount: result[0]?.senders.size, totalXrp: result[0]?.totalXrp };
    });
    assert(diag.length === 1, `expected exactly one consolidation destination, got ${diag.length}`);
    assert(diag.dest === 'rCommon', `expected rCommon as the consolidation point, got ${diag.dest}`);
    assert(diag.senderCount === 2, `expected 2 distinct senders, got ${diag.senderCount}`);
    assert(diag.totalXrp === 1500, `expected combined 1500 XRP, got ${diag.totalXrp}`);
  });
});

suite.register('_findProceedsConsolidation: no consolidation when cohort wallets send to different destinations', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugFindProceedsConsolidation, { timeout: 8000 });
    const result = await page.evaluate(() => window._debugFindProceedsConsolidation([
      { addr: 'rA', proceedsPayments: [{ dest: 'rDest1', xrp: 100, date: 1 }] },
      { addr: 'rB', proceedsPayments: [{ dest: 'rDest2', xrp: 100, date: 2 }] },
    ]));
    assert(result.length === 0, `expected no consolidation destinations, got ${result.length}`);
  });
});

suite.register('Findings: no behavioral signal at all (regardless of distribution size) produces a neutral "no pattern" finding, never a warning', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugBuildDistMarketFlowFindings, { timeout: 8000 });
    const findings = await page.evaluate(() => window._debugBuildDistMarketFlowFindings({
      cohort: [{ addr: 'rA', firstSellTs: null }, { addr: 'rB', firstSellTs: null }],
      cohortSharePct: 90, // even a huge distribution share alone must not trigger concern
      syncGroups: [],
      proceedsConsolidation: [],
    }));
    assert(findings.length === 1, `expected exactly one finding, got ${findings.length}`);
    assert(findings[0].sev === 'info', `expected sev:'info' when no behavioral signal fired even with a 90% distribution share, got "${findings[0].sev}"`);
    assert(/No distribution-to-market coordination pattern found/.test(findings[0].headline), `expected the neutral headline, got "${findings[0].headline}"`);
  });
});

suite.register('Findings: exactly ONE behavioral signal with LOW materiality stays sev:info at low confidence', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugBuildDistMarketFlowFindings, { timeout: 8000 });
    const findings = await page.evaluate(() => {
      const syncGroup = [{ addr: 'rA', firstSellTs: 1000 }, { addr: 'rB', firstSellTs: 1500 }];
      return window._debugBuildDistMarketFlowFindings({
        cohort: [{ addr: 'rA', firstSellTs: 1000 }, { addr: 'rB', firstSellTs: 1500 }],
        cohortSharePct: 3, // below the materiality floor
        syncGroups: [syncGroup],
        proceedsConsolidation: [],
      });
    });
    assert(findings[0].sev === 'info', `expected sev:'info' for a single signal with low materiality, got "${findings[0].sev}"`);
    assert(findings[0].confidence === 0.35, `expected confidence 0.35, got ${findings[0].confidence}`);
  });
});

suite.register('Findings: BOTH behavioral signals + high materiality reaches the maximum tier (sev:warn, confidence 0.75) but NEVER critical', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugBuildDistMarketFlowFindings, { timeout: 8000 });
    const findings = await page.evaluate(() => {
      const syncGroup = [{ addr: 'rA', firstSellTs: 1000 }, { addr: 'rB', firstSellTs: 1500 }];
      const consolidation = { dest: 'rCommon', senders: new Set(['rA', 'rB']), totalXrp: 5000, payments: [] };
      return window._debugBuildDistMarketFlowFindings({
        cohort: [{ addr: 'rA', firstSellTs: 1000 }, { addr: 'rB', firstSellTs: 1500 }],
        cohortSharePct: 40,
        syncGroups: [syncGroup],
        proceedsConsolidation: [consolidation],
      });
    });
    const f = findings[0];
    assert(f.sev === 'warn', `expected the maximum evidence tier to be sev:'warn', got "${f.sev}"`);
    assert(f.confidence === 0.75, `expected confidence 0.75, got ${f.confidence}`);
    assert(f.headline === 'Distribution-to-Market Sequence', `expected the neutral headline (never "dump"/"insider"/"rug"), got "${f.headline}"`);
    assert(/does not prove common ownership.*intent/.test(f.classification), `expected the classification to explicitly say intent is not established, got: "${f.classification}"`);
    assert(f.alternativeExplanations.length >= 3, `expected several alternative benign explanations, got ${f.alternativeExplanations.length}`);
    assert(!/dump|rug|insider/i.test(JSON.stringify(f)), 'expected the finding to never use accusatory language (dump/rug/insider)');
  });
});

suite.register('Findings: never reach sev critical even with both signals firing at maximum strength', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugBuildDistMarketFlowFindings, { timeout: 8000 });
    // Try several materiality levels — none should ever push past 'warn'.
    const sevs = await page.evaluate(() => {
      const syncGroup = [{ addr: 'rA', firstSellTs: 1000 }, { addr: 'rB', firstSellTs: 1500 }, { addr: 'rC', firstSellTs: 1600 }];
      const consolidation = { dest: 'rCommon', senders: new Set(['rA', 'rB', 'rC']), totalXrp: 50000, payments: [] };
      return [10, 50, 90, 100].map(pct => window._debugBuildDistMarketFlowFindings({
        cohort: [{ addr: 'rA' }, { addr: 'rB' }, { addr: 'rC' }],
        cohortSharePct: pct,
        syncGroups: [syncGroup],
        proceedsConsolidation: [consolidation],
      })[0].sev);
    });
    assert(sevs.every(s => s !== 'critical'), `expected sev to never be 'critical' at any materiality level, got: ${JSON.stringify(sevs)}`);
  });
});

suite.register('Full render: cohort table and the full evidence-model finding (Observed/Calculated/Inferred/Hypothesis) render correctly', async () => {
  await withPage(async (page, { pageErrors }) => {
    const ok = await freshSignup(page, { name: 'DM Render', email: 'dmrender@test.com', domain: 'dmrender' });
    assert(ok, 'signup failed');
    await connectAndShowDashboard(page);
    await inspectAddress(page, SOLO_ISSUER, { timeout: 90000 });
    await page.waitForFunction(() => window._debugRenderDistMarketFlowResult, { timeout: 8000 });

    await page.evaluate(() => {
      const cohort = [
        { addr: 'rSellerOne00000000000000000000000000', fetchFailed: false, sellOrderCount: 3, firstSellTs: 800000000, proceedsPayments: [{ dest: 'rCommonDest0000000000000000000000000', xrp: 1200, date: 800003600 }], txSampleSize: 120, amountReceived: 8000, sharePct: 40 },
        { addr: 'rSellerTwo00000000000000000000000000', fetchFailed: false, sellOrderCount: 2, firstSellTs: 800001800, proceedsPayments: [{ dest: 'rCommonDest0000000000000000000000000', xrp: 900, date: 800005400 }], txSampleSize: 95, amountReceived: 6000, sharePct: 30 },
        { addr: 'rQuietHolder000000000000000000000000', fetchFailed: false, sellOrderCount: 0, firstSellTs: null, proceedsPayments: [], txSampleSize: 40, amountReceived: 6000, sharePct: 30 },
      ];
      const syncGroups = window._debugClusterSellTimings(cohort);
      const proceedsConsolidation = window._debugFindProceedsConsolidation(cohort);
      const findings = window._debugBuildDistMarketFlowFindings({ cohort, cohortSharePct: 40, syncGroups, proceedsConsolidation });
      window._debugRenderDistMarketFlowResult({ applicable: true, cohort, totalDistributed: 20000, cohortSharePct: 40, syncGroups, proceedsConsolidation, fetchFailures: 0, findings }, 'SOLO');
    });
    await page.waitForTimeout(150);

    const rendered = await page.evaluate(() => {
      const body = document.getElementById('inspect-dist-market-flow-body');
      const badge = document.getElementById('badge-dist-market-flow');
      return {
        badgeText: badge?.textContent,
        badgeIsWarn: badge?.className.includes('--warn'),
        cohortRowCount: body?.querySelectorAll('.conn-holder-row').length,
        hasFindingCard: !!body?.querySelector('.audit-items'),
        bodyText: body?.textContent || '',
      };
    });
    assert(rendered.badgeIsWarn, `expected the badge to show the warn state, got class not containing --warn`);
    assert(rendered.badgeText === 'Review', `expected badge text "Review", got "${rendered.badgeText}"`);
    assert(rendered.cohortRowCount === 3, `expected 3 cohort rows, got ${rendered.cohortRowCount}`);
    assert(rendered.hasFindingCard, 'expected a rendered finding card');
    assert(/Observed/.test(rendered.bodyText) && /Calculated/.test(rendered.bodyText) && /Inferred/.test(rendered.bodyText) && /Hypothesis/.test(rendered.bodyText), 'expected all 4 epistemic tiers (Observed/Calculated/Inferred/Hypothesis) to render');
    assert(/selling since/.test(rendered.bodyText), 'expected sellers to show a "selling since" date in the cohort table');
    assert(/no sell orders seen/.test(rendered.bodyText), 'expected the quiet holder to show "no sell orders seen"');
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

suite.register('Live: the multi-account fetch orchestrator completes against real wallets with zero crashes and a well-formed result', async () => {
  await withPage(async (page, { pageErrors }) => {
    const ok = await freshSignup(page, { name: 'DM Orch', email: 'dmorch@test.com', domain: 'dmorch' });
    assert(ok, 'signup failed');
    await connectAndShowDashboard(page);
    await page.evaluate(() => window.switchTab(null, 'inspector'));
    await page.waitForFunction(() => window._debugAnalyseDistributionMarketFlow, { timeout: 8000 });

    const result = await page.evaluate(async (wallets) => {
      const fakeIssuerConn = { distributions: wallets.map((w, i) => [w, (3 - i) * 1000]), totalIssued: 20000 };
      return window._debugAnalyseDistributionMarketFlow(fakeIssuerConn, 'SOLO');
    }, REAL_WALLETS);

    assert(result.applicable, 'expected the analysis to be applicable with a non-empty cohort');
    assert(result.cohort.length === REAL_WALLETS.length, `expected ${REAL_WALLETS.length} cohort entries, got ${result.cohort.length}`);
    // A single transient RPC timeout against a live public node is expected,
    // tolerable behavior this feature is specifically designed to degrade
    // gracefully from (see fetchFailures in the render layer) — asserting
    // 100% success here would make this test flake on ordinary live-network
    // noise unrelated to any code defect. A majority succeeding is the bar
    // that actually catches a real systemic break (e.g. a malformed request
    // failing for every wallet).
    const succeeded = result.cohort.filter(c => !c.fetchFailed);
    assert(succeeded.length >= 2, `expected at least 2 of ${REAL_WALLETS.length} real-wallet fetches to succeed, got: ${JSON.stringify(result.cohort.map(c => c.fetchFailed))}`);
    assert(succeeded.every(c => c.txSampleSize > 0), 'expected every successfully-fetched cohort wallet to have a real, non-empty transaction sample');
    assert(result.findings.length >= 1, 'expected at least one finding to be produced either way');
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

suite.register('Live: a real issuer with no direct-distribution Payments in its fetched history shows an honest N/A state, not a crash or a fabricated result', async () => {
  await withPage(async (page, { pageErrors }) => {
    const ok = await freshSignup(page, { name: 'DM NA', email: 'dmna@test.com', domain: 'dmna' });
    assert(ok, 'signup failed');
    await connectAndShowDashboard(page);
    await inspectAddress(page, SOLO_ISSUER, { timeout: 90000 });

    const state = await page.evaluate(() => {
      const body = document.getElementById('inspect-dist-market-flow-body');
      return { hasEmptyNote: !!body?.querySelector('.inspect-empty-note'), hasAnalyzeButton: [...(body?.querySelectorAll('button') || [])].some(b => b.textContent.includes('Analyze Distribution')) };
    });
    // Exactly one of these two should be true — either it's genuinely N/A
    // (no distributions found) or it offers the button (distributions were
    // found). Both are honest; what must never happen is neither (blank) or
    // a crash, and pageErrors below guards against the crash case.
    assert(state.hasEmptyNote || state.hasAnalyzeButton, 'expected either an honest N/A note or a real Analyze button — not a blank/broken section');
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

suite.register('_buildMarketSetupTimeline: merges distribution/hop-2/selling/proceeds events into one chronologically-sorted list', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugBuildMarketSetupTimeline, { timeout: 8000 });
    const timeline = await page.evaluate(() => {
      const cohort = [
        { addr: 'rWalletA00000000000000000000000000000', receivedTs: 500, amountReceived: 1000, hop2Recipients: [], firstSellTs: 900, sellOrderCount: 2 },
        { addr: 'rWalletB00000000000000000000000000000', receivedTs: 300, amountReceived: 500, hop2Recipients: [{ dest: 'rHopTarget0000000000000000000000000', amount: 100, firstDate: 700 }], firstSellTs: null, sellOrderCount: 0 },
      ];
      const proceedsConsolidation = [
        { dest: 'rCommonDest0000000000000000000000000', totalXrp: 800, senders: new Set(['rWalletA00000000000000000000000000000']), payments: [{ from: 'rWalletA00000000000000000000000000000', xrp: 800, date: 1000 }] },
      ];
      return window._debugBuildMarketSetupTimeline(cohort, proceedsConsolidation);
    });
    assert(timeline.length === 5, `expected 5 events (2 distributions + 1 hop-2 + 1 sell + 1 proceeds), got ${timeline.length}`);
    const dates = timeline.map(e => e.date);
    assert(dates.every((d, i) => i === 0 || dates[i - 1] <= d), `expected the timeline sorted chronologically, got dates: ${JSON.stringify(dates)}`);
    assert(timeline.some(e => e.module === 'Distribution' && e.date === 300), 'expected a distribution event at date 300');
    assert(timeline.some(e => e.module === 'Distribution' && e.detail === 'hop 2' && e.date === 700), 'expected a hop-2 forward event at date 700');
    assert(timeline.some(e => e.module === 'Selling' && e.date === 900), 'expected a selling event at date 900');
    assert(timeline.some(e => e.module === 'Proceeds' && e.date === 1000), 'expected a proceeds event at date 1000');
  });
});

suite.register('Regression: cohort-table and timeline dates convert raw ripple-epoch to real calendar dates (missing +XRPL_EPOCH previously showed dates ~30 years too early)', async () => {
  await withPage(async (page, { pageErrors }) => {
    const ok = await freshSignup(page, { name: 'Epoch Test', email: 'epochtest@test.com', domain: 'epochtest' });
    assert(ok, 'signup failed');
    await connectAndShowDashboard(page);
    await inspectAddress(page, SOLO_ISSUER, { timeout: 90000 });
    await page.waitForFunction(() => window._debugRenderDistMarketFlowResult, { timeout: 8000 });

    await page.evaluate(() => {
      // A real-world-plausible ripple-epoch timestamp (~2025) — WITHOUT the
      // +XRPL_EPOCH fix, this would render as a mid-1990s date instead.
      const cohort = [{ addr: 'rEpochWallet000000000000000000000000', fetchFailed: false, sellOrderCount: 1, firstSellTs: 800000000, receivedTs: 799000000, proceedsPayments: [], hop2Recipients: [], txSampleSize: 10, amountReceived: 1000, sharePct: 100 }];
      const timeline = window._debugBuildMarketSetupTimeline(cohort, []);
      window._debugRenderDistMarketFlowResult({ applicable: true, cohort, totalDistributed: 1000, cohortSharePct: 5, syncGroups: [], proceedsConsolidation: [], fetchFailures: 0, findings: [{ module: 'Distribution & Market Flow', sev: 'info', headline: 'x', label: 'x', detail: '', observed: [] }], timeline }, 'SOLO');
    });
    await page.waitForTimeout(150);

    const dates = await page.evaluate(() => {
      const body = document.getElementById('inspect-dist-market-flow-body');
      return {
        cohortRowText: body.querySelector('.conn-holder-row')?.textContent,
        timelineDateText: body.querySelector('.events-timeline-date')?.textContent,
      };
    });
    assert(/202[4-9]|203\d/.test(dates.cohortRowText), `expected the cohort row's "selling since" date to show a real ~2025 year, got: "${dates.cohortRowText}"`);
    assert(/199[0-9]/.test(dates.cohortRowText) === false, `expected NO 1990s date in the cohort row (that was the bug), got: "${dates.cohortRowText}"`);
    assert(/202[4-9]|203\d/.test(dates.timelineDateText), `expected the timeline's date to show a real ~2025 year, got: "${dates.timelineDateText}"`);
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

suite.register('_buildIssuerEcosystemGraph: dedupes a wallet appearing as both a hop-2 target AND a proceeds destination into one ring-2 node', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugBuildIssuerEcosystemGraph, { timeout: 8000 });
    const result = await page.evaluate(() => {
      const ISSUER = 'rIssuerEco0000000000000000000000000';
      const A = 'rEcoA0000000000000000000000000000000';
      const B = 'rEcoB0000000000000000000000000000000';
      const SharedDest = 'rEcoSharedDest00000000000000000000000';
      const cohort = [
        { addr: A, amountReceived: 1000, sharePct: 66.6, hop2Recipients: [{ dest: SharedDest, amount: 200, firstDate: 100 }] },
        { addr: B, amountReceived: 500, sharePct: 33.3, hop2Recipients: [] },
      ];
      const proceedsConsolidation = [{ dest: SharedDest, totalXrp: 900, senders: new Set([A, B]), payments: [{ from: A, xrp: 600, date: 200 }, { from: B, xrp: 300, date: 210 }] }];
      const graph = window._debugBuildIssuerEcosystemGraph(ISSUER, { cohort, proceedsConsolidation });
      return {
        centerAddr: graph.center.addr, ring1Count: graph.ring1.length, ring2Count: graph.ring2.length,
        ring2Kind: graph.ring2[0]?.kind, edgeKinds: graph.edges.map(e => e.kind),
      };
    });
    assert(result.centerAddr === 'rIssuerEco0000000000000000000000000', 'expected the center node to be the issuer');
    assert(result.ring1Count === 2, `expected 2 ring-1 nodes, got ${result.ring1Count}`);
    assert(result.ring2Count === 1, `expected the shared destination to collapse into exactly 1 ring-2 node (not 2 duplicates), got ${result.ring2Count}`);
    assert(result.ring2Kind === 'hop2+proceeds', `expected the shared node's kind to combine both roles, got "${result.ring2Kind}"`);
    assert(result.edgeKinds.filter(k => k === 'distribution').length === 2, 'expected 2 distribution edges (issuer to each ring-1 wallet)');
    assert(result.edgeKinds.filter(k => k === 'proceeds').length === 2, 'expected 2 proceeds edges (one per payment)');
    assert(result.edgeKinds.filter(k => k === 'hop2').length === 1, 'expected 1 hop-2 edge');
  });
});

suite.register('_buildIssuerEcosystemGraph: a ring-1 wallet that ALSO receives proceeds is never duplicated as a separate ring-2 node', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugBuildIssuerEcosystemGraph, { timeout: 8000 });
    const result = await page.evaluate(() => {
      const ISSUER = 'rIssuerEco0000000000000000000000000';
      const A = 'rEcoA0000000000000000000000000000000';
      const B = 'rEcoB0000000000000000000000000000000'; // ring-1, also a proceeds destination
      const cohort = [{ addr: A, amountReceived: 1000, sharePct: 66.6, hop2Recipients: [] }, { addr: B, amountReceived: 500, sharePct: 33.3, hop2Recipients: [] }];
      const proceedsConsolidation = [{ dest: B, totalXrp: 100, senders: new Set([A]), payments: [{ from: A, xrp: 100, date: 300 }] }];
      const graph = window._debugBuildIssuerEcosystemGraph(ISSUER, { cohort, proceedsConsolidation });
      return { ring1Count: graph.ring1.length, ring2Count: graph.ring2.length };
    });
    assert(result.ring1Count === 2, `expected 2 ring-1 nodes, got ${result.ring1Count}`);
    assert(result.ring2Count === 0, `expected zero ring-2 nodes — B is already drawn in ring 1, got ${result.ring2Count}`);
  });
});

suite.register('Live: the Issuer Ecosystem graph renders the correct node/edge counts and every edge is a real observed transfer, never labeled a relationship inference', async () => {
  await withPage(async (page, { pageErrors }) => {
    const ok = await freshSignup(page, { name: 'Ecosystem Render', email: 'ecosystemrender@test.com', domain: 'ecosystemrender' });
    assert(ok, 'signup failed');
    await connectAndShowDashboard(page);
    await inspectAddress(page, SOLO_ISSUER, { timeout: 90000 });
    await page.waitForFunction(() => window._debugRenderDistMarketFlowResult, { timeout: 8000 });

    await page.evaluate(() => {
      const cohort = [
        { addr: 'rSellerOne00000000000000000000000000', fetchFailed: false, sellOrderCount: 3, firstSellTs: 800000000, receivedTs: 799000000, proceedsPayments: [{ dest: 'rCommonDest0000000000000000000000000', xrp: 1200, date: 800003600 }], hop2Recipients: [{ dest: 'rHopA00000000000000000000000000000000', amount: 200, firstDate: 799500000 }], txSampleSize: 120, amountReceived: 8000, sharePct: 40 },
        { addr: 'rSellerTwo00000000000000000000000000', fetchFailed: false, sellOrderCount: 2, firstSellTs: 800001800, receivedTs: 799600000, proceedsPayments: [{ dest: 'rCommonDest0000000000000000000000000', xrp: 900, date: 800005400 }], hop2Recipients: [], txSampleSize: 95, amountReceived: 6000, sharePct: 30 },
      ];
      const syncGroups = window._debugClusterSellTimings(cohort);
      const proceedsConsolidation = window._debugFindProceedsConsolidation(cohort);
      const findings = window._debugBuildDistMarketFlowFindings({ cohort, cohortSharePct: 40, syncGroups, proceedsConsolidation });
      const timeline = window._debugBuildMarketSetupTimeline(cohort, proceedsConsolidation);
      window._debugRenderDistMarketFlowResult({ applicable: true, cohort, totalDistributed: 14000, cohortSharePct: 40, syncGroups, proceedsConsolidation, fetchFailures: 0, findings, timeline }, 'SOLO');
    });
    await page.waitForTimeout(200);

    const rendered = await page.evaluate(() => {
      const body = document.getElementById('inspect-dist-market-flow-body');
      return {
        hasGraph: !!body?.querySelector('.ecosystem-graph-svg'),
        circleCount: body?.querySelectorAll('.ecosystem-graph-svg circle').length,
        lineCount: body?.querySelectorAll('.ecosystem-graph-svg line').length,
        legendCount: body?.querySelectorAll('.ecosystem-legend-swatch').length,
        bodyText: body?.textContent || '',
      };
    });
    // 1 issuer + 2 ring-1 recipients + 2 ring-2 (rCommonDest, rHopA) = 5 nodes.
    // 2 distribution + 1 hop-2 + 2 proceeds payments = 5 edges.
    assert(rendered.hasGraph, 'expected the Issuer Ecosystem graph to render');
    assert(rendered.circleCount === 5, `expected 5 node circles, got ${rendered.circleCount}`);
    assert(rendered.lineCount === 5, `expected 5 edges, got ${rendered.lineCount}`);
    assert(rendered.legendCount === 4, `expected a 4-item legend (Issuer/Direct recipient/Hop-2/Proceeds), got ${rendered.legendCount}`);
    assert(/real, observed on-ledger transfer/.test(rendered.bodyText), 'expected the graph caption to explicitly state every edge is a real observed transfer, not an inference');
    assert(!/relationship inferred|possible relationship|likely connected/i.test(rendered.bodyText), 'expected no relationship-inference language near the graph — every edge here is a direct transfer, not an inferred connection');
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

suite.register('_extractHop2Recipients: aggregates repeat forwards to the same destination, excludes other currencies/XRP/inbound payments, sorts by amount', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugExtractHop2Recipients, { timeout: 8000 });
    const result = await page.evaluate(() => {
      const WALLET = 'rHop1Wallet00000000000000000000000000';
      const txList = [
        { tx: { TransactionType: 'Payment', Account: WALLET, Destination: 'rHop2B0000000000000000000000000000000', Amount: { currency: 'FOO', issuer: 'rIssuer', value: '100' }, date: 100 } },
        { tx: { TransactionType: 'Payment', Account: WALLET, Destination: 'rHop2B0000000000000000000000000000000', Amount: { currency: 'FOO', issuer: 'rIssuer', value: '50' }, date: 200 } },
        { tx: { TransactionType: 'Payment', Account: WALLET, Destination: 'rHop2C0000000000000000000000000000000', Amount: { currency: 'FOO', issuer: 'rIssuer', value: '300' }, date: 150 } },
        { tx: { TransactionType: 'Payment', Account: WALLET, Destination: 'rHop2D0000000000000000000000000000000', Amount: { currency: 'BAR', issuer: 'rIssuer', value: '999' }, date: 175 } }, // different currency
        { tx: { TransactionType: 'Payment', Account: WALLET, Destination: 'rHop2E0000000000000000000000000000000', Amount: '5000000', date: 180 } }, // XRP, not the token
        { tx: { TransactionType: 'Payment', Account: 'rSomeoneElse000000000000000000000000', Destination: WALLET, Amount: { currency: 'FOO', issuer: 'rIssuer', value: '10' }, date: 190 } }, // inbound, not outbound from WALLET
      ];
      return window._debugExtractHop2Recipients(txList, WALLET, 'FOO');
    });
    assert(result.length === 2, `expected exactly 2 hop-2 destinations (excluding other-currency/XRP/inbound), got ${result.length}`);
    const b = result.find(r => r.dest === 'rHop2B0000000000000000000000000000000');
    const c = result.find(r => r.dest === 'rHop2C0000000000000000000000000000000');
    assert(b?.amount === 150, `expected the two forwards to rHop2B to aggregate to 150, got ${b?.amount}`);
    assert(c?.amount === 300, `expected rHop2C to show 300, got ${c?.amount}`);
    assert(result[0].dest === c.dest, 'expected results sorted by amount descending (rHop2C first)');
  });
});

// ── Potential Setup Analysis (roadmap: cross-module corroboration) ────────
// Chains Issuer Distribution → Mirror Pattern → Common Funding → Liquidity
// Setup/Withdrawal → Market Activity → Net Selling → Proceeds Consolidation
// into ONE finding, grouping correlated signals into "pattern families" so
// e.g. amount-similarity and issuer-created (which both just restate "this
// IS a mirror group") can't inflate the family count as if they were two
// independent agreements. A helper here builds the minimal cohort shape
// _buildPotentialSetupFinding needs without a live fetch, since the
// function itself is pure.
function _mkSetupCohort(addrs, { sell = [], ammDep = [], ammWith = [] } = {}) {
  return addrs.map(addr => ({
    addr, fetchFailed: false, proceedsPayments: [],
    firstSellTs: sell.includes(addr) ? 900000000 : null,
    ammDeposited: ammDep.includes(addr), ammWithdrew: ammWith.includes(addr),
  }));
}

suite.register('Potential Setup Analysis: fewer than 2 corroborating pattern families produces no finding at all', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugBuildPotentialSetupFinding, { timeout: 8000 });
    const result = await page.evaluate(() => {
      const cohort = [
        { addr: 'rA', fetchFailed: false, proceedsPayments: [], firstSellTs: null, ammDeposited: false, ammWithdrew: false },
        { addr: 'rB', fetchFailed: false, proceedsPayments: [], firstSellTs: null, ammDeposited: false, ammWithdrew: false },
      ];
      // No mirror group, no sync, no consolidation — zero families fire.
      return window._debugBuildPotentialSetupFinding({ cohort, syncGroups: [], proceedsConsolidation: [], mirrorGroup: null });
    });
    assert(result === null, `expected null when fewer than 2 pattern families corroborate, got: ${JSON.stringify(result)}`);
  });
});

suite.register('Potential Setup Analysis: exactly 2 families (Distribution + Selling) produces a low-confidence info finding naming both chain steps', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugBuildPotentialSetupFinding, { timeout: 8000 });
    const result = await page.evaluate(() => {
      const cohort = [
        { addr: 'rA', fetchFailed: false, proceedsPayments: [], firstSellTs: 900000000, ammDeposited: false, ammWithdrew: false },
        { addr: 'rB', fetchFailed: false, proceedsPayments: [], firstSellTs: null, ammDeposited: false, ammWithdrew: false },
      ];
      const mirrorGroup = { approxAmt: 1000, accounts: [{ addr: 'rA', amt: 1000 }, { addr: 'rB', amt: 1000 }], totalFamilies: 2, timingCorrelated: false, issuerCreated: false, commonFunded: false, tier: 'Weak' };
      return window._debugBuildPotentialSetupFinding({ cohort, syncGroups: [], proceedsConsolidation: [], mirrorGroup });
    });
    assert(result, 'expected a finding when exactly 2 families corroborate (Distribution via the mirror group + Selling)');
    assert(result.sev === 'info', `expected sev:'info' at 2 families, got "${result.sev}"`);
    assert(Math.abs(result.confidence - 0.4) < 0.001, `expected confidence 0.4 at 2 families, got ${result.confidence}`);
    assert(/Potential Setup Analysis/.test(result.headline), `expected the headline to name the feature, got: "${result.headline}"`);
    assert(result.observed.some(o => /✓ Mirror Wallet Pattern/.test(o)), `expected the chain to show Mirror Wallet Pattern as fired, got: ${JSON.stringify(result.observed)}`);
    assert(result.observed.some(o => /✓ Net Selling/.test(o)), `expected the chain to show Net Selling as fired, got: ${JSON.stringify(result.observed)}`);
    assert(result.observed.some(o => /— Common Funding/.test(o)), `expected the chain to show Common Funding as NOT fired, got: ${JSON.stringify(result.observed)}`);
    assert(/NOT ESTABLISHED/.test(result.classification), `expected an explicit "ownership identity: NOT ESTABLISHED" disclaimer, got: "${result.classification}"`);
  });
});

suite.register('Potential Setup Analysis: all 6 families corroborating reaches the maximum tier (warn, confidence 0.7) but NEVER critical', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugBuildPotentialSetupFinding, { timeout: 8000 });
    const result = await page.evaluate(() => {
      const cohort = [
        { addr: 'rA', fetchFailed: false, proceedsPayments: [{ dest: 'rConsolidation', xrp: 100, date: 1 }], firstSellTs: 900000000, ammDeposited: true, ammWithdrew: true },
        { addr: 'rB', fetchFailed: false, proceedsPayments: [{ dest: 'rConsolidation', xrp: 100, date: 1 }], firstSellTs: 900000100, ammDeposited: false, ammWithdrew: false },
      ];
      const mirrorGroup = { approxAmt: 1000, accounts: [{ addr: 'rA', amt: 1000 }, { addr: 'rB', amt: 1000 }], totalFamilies: 3, timingCorrelated: true, issuerCreated: true, commonFunded: true, tier: 'Strong' };
      const syncGroups = [[{ addr: 'rA', firstSellTs: 900000000 }, { addr: 'rB', firstSellTs: 900000100 }]];
      const proceedsConsolidation = [{ dest: 'rConsolidation', totalXrp: 200, senders: new Set(['rA', 'rB']), payments: [] }];
      return window._debugBuildPotentialSetupFinding({ cohort, syncGroups, proceedsConsolidation, mirrorGroup });
    });
    assert(result, 'expected a finding when all families corroborate');
    assert(result.sev === 'warn', `expected sev:'warn' at maximum families, got "${result.sev}"`);
    assert(Math.abs(result.confidence - 0.7) < 0.001, `expected confidence 0.7 at maximum families, got ${result.confidence}`);
    assert(result.sev !== 'critical', 'expected NEVER critical, no matter how many families fire — intent is never established from on-ledger shape alone');
    for (const step of ['Issuer Distribution', 'Mirror Wallet Pattern', 'Common Funding', 'Liquidity Setup', 'Liquidity Withdrawal', 'Market Activity', 'Net Selling', 'Proceeds Consolidation']) {
      assert(result.observed.some(o => o.includes(step)), `expected the chain checklist to name "${step}", got: ${JSON.stringify(result.observed)}`);
    }
    assert(result.observed.some(o => /✓ Liquidity Withdrawal/.test(o)), `expected Liquidity Withdrawal to show fired (rA withdrew), got: ${JSON.stringify(result.observed)}`);
  });
});

suite.register('Potential Setup Analysis: Liquidity Setup fires from a holder-cohort LP overlap even without any AMMDeposit transaction in the cohort\'s own fetched page', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugBuildPotentialSetupFinding, { timeout: 8000 });
    const result = await page.evaluate(() => {
      const cohort = [
        { addr: 'rLpHolder', fetchFailed: false, proceedsPayments: [], firstSellTs: 900000000, ammDeposited: false, ammWithdrew: false },
        { addr: 'rB', fetchFailed: false, proceedsPayments: [], firstSellTs: null, ammDeposited: false, ammWithdrew: false },
      ];
      const mirrorGroup = { approxAmt: 1000, accounts: [{ addr: 'rLpHolder', amt: 1000 }, { addr: 'rB', amt: 1000 }], totalFamilies: 2, timingCorrelated: false, issuerCreated: false, commonFunded: false, tier: 'Weak' };
      return window._debugBuildPotentialSetupFinding({ cohort, syncGroups: [], proceedsConsolidation: [], mirrorGroup, lpHolderAddrSet: new Set(['rLpHolder']) });
    });
    assert(result.observed.some(o => /✓ Liquidity Setup/.test(o)), `expected Liquidity Setup to fire from the lpHolderAddrSet overlap alone, got: ${JSON.stringify(result.observed)}`);
  });
});

suite.register('Live: analyseDistributionMarketFlow prefers a qualifying mirror group as its cohort (cohortSource:"mirror-group") when one exists, falling back to top-recipients otherwise', async () => {
  await withPage(async (page) => {
    await connectAndShowDashboard(page);
    await page.waitForFunction(() => window._debugAnalyseDistributionMarketFlow, { timeout: 8000 });

    const result = await page.evaluate(async () => {
      const mirrorGroup = { approxAmt: 1000, accounts: [{ addr: 'rnj7R3QUGzLZc9dg24jSrGabtt1tp1XD7A', amt: 1000 }], totalFamilies: 2, timingCorrelated: false, issuerCreated: true, commonFunded: false, tier: 'Moderate' };
      const issuerConnAnalysis = {
        distributions: [['rnj7R3QUGzLZc9dg24jSrGabtt1tp1XD7A', 1000, 800000000], ['rPVMhWBsfF9iMXYj3aAzJVkPDTFNSyWdKy', 999, 800000001]],
        totalIssued: 10000,
        mirrorGroups: [mirrorGroup],
      };
      const r = await window._debugAnalyseDistributionMarketFlow(issuerConnAnalysis, '5553444F00000000000000000000000000000000');
      return { applicable: r.applicable, cohortSource: r.cohortSource, cohortAddrs: (r.cohort || []).map(c => c.addr) };
    });

    assert(result.applicable, 'expected the orchestrator to run against a real cohort');
    assert(result.cohortSource === 'mirror-group', `expected cohortSource to be "mirror-group" when a qualifying mirror group is present, got "${result.cohortSource}"`);
    assert(result.cohortAddrs.includes('rnj7R3QUGzLZc9dg24jSrGabtt1tp1XD7A'), `expected the cohort to be seeded from the mirror group's own addresses, got: ${JSON.stringify(result.cohortAddrs)}`);
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
