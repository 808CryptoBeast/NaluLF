// Regression guard for Mirror Wallet Cluster confidence tiers (deferred
// forensic-depth item from the codebase audit spec). The old detector was
// a flat detected/not-detected flag: any 3+ accounts receiving similar
// token amounts got the same "warn" severity regardless of how much real
// corroboration existed. This reworks it into the same "independent
// signal families agreeing" corroboration model already used for
// Spoofing elsewhere in this file — amount similarity is always the base
// (weak) signal; corroborating it with PER-GROUP funding-timing
// correlation and/or issuer-direct-account-creation raises the tier to
// Moderate (2 families) or Strong (3 families). Confidence values are
// chosen so _evidenceStrength's existing Strong/Moderate/Weak thresholds
// (>=0.7 / >=0.4 / else) classify them correctly, reusing that function
// rather than inventing a second tier-labeling scheme.
import { withPage, connectAndShowDashboard, makeSuite, assert } from './helpers.mjs';

const suite = makeSuite('Mirror Wallet Cluster — Confidence Tiers');

const ISSUER = 'rIssuer00000000000000000000000000';

function buildFixture() {
  const mkTx = (dest, value, date, hash, created = false) => ({
    tx: { Account: ISSUER, Destination: dest, TransactionType: 'Payment', Amount: { currency: 'FOO', issuer: ISSUER, value: String(value) }, date, hash },
    meta: {
      TransactionResult: 'tesSUCCESS',
      AffectedNodes: created ? [{ CreatedNode: { LedgerEntryType: 'AccountRoot', NewFields: { Account: dest } } }] : [],
    },
  });
  const lines = [{ account: 'rSomeHolder000000000000000000000000', balance: '-99999', currency: 'FOO' }];

  // Group A: 5 accounts, ~1000 tokens each, funded within 5 min AND all issuer-created -> 3 families (Strong)
  const groupA = ['rA1000000000000000000000000000000', 'rA2000000000000000000000000000000', 'rA3000000000000000000000000000000', 'rA4000000000000000000000000000000', 'rA5000000000000000000000000000000'];
  const txA = groupA.map((d, i) => mkTx(d, 1000 + i, 800000000 + i * 60, `hA${i}`, true));

  // Group B: 3 accounts, ~500 tokens each, funded within 5 min but NOT issuer-created -> 2 families (Moderate)
  const groupB = ['rB1000000000000000000000000000000', 'rB2000000000000000000000000000000', 'rB3000000000000000000000000000000'];
  const txB = groupB.map((d, i) => mkTx(d, 500 + i, 900000000 + i * 60, `hB${i}`, false));

  // Group C: 3 accounts, ~200 tokens each, spread over weeks, not issuer-created -> 1 family (Weak)
  const groupC = ['rC1000000000000000000000000000000', 'rC2000000000000000000000000000000', 'rC3000000000000000000000000000000'];
  const txC = groupC.map((d, i) => mkTx(d, 200 + i, 700000000 + i * 700000, `hC${i}`, false));

  return { txList: [...txA, ...txB, ...txC], lines, groupSizes: { A: groupA.length, B: groupB.length, C: groupC.length } };
}

suite.register('3 independent families (amount + timing + issuer-created) produce a Strong tier at 0.75 confidence', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugAnalyseIssuerConnections, { timeout: 8000 });
    const { txList, lines } = buildFixture();
    const result = await page.evaluate(([txList, lines, issuer]) => window._debugAnalyseIssuerConnections(txList, issuer, lines, null), [txList, lines, ISSUER]);

    const strong = result.mirrorGroups.find(g => g.accounts.length === 5);
    assert(strong, 'expected the 5-account group to be detected');
    assert(strong.totalFamilies === 3, `expected 3 families (amount+timing+created), got ${strong.totalFamilies}`);
    assert(strong.timingCorrelated === true && strong.issuerCreated === true, `expected both corroborating signals true, got timing=${strong.timingCorrelated} created=${strong.issuerCreated}`);
    assert(strong.confidence === 0.75, `expected confidence 0.75, got ${strong.confidence}`);
    assert(strong.tier === 'Strong', `expected tier Strong, got ${strong.tier}`);
  });
});

suite.register('2 independent families (amount + timing, no issuer-created) produce a Moderate tier at 0.55 confidence', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugAnalyseIssuerConnections, { timeout: 8000 });
    const { txList, lines } = buildFixture();
    const result = await page.evaluate(([txList, lines, issuer]) => window._debugAnalyseIssuerConnections(txList, issuer, lines, null), [txList, lines, ISSUER]);

    const moderate = result.mirrorGroups.find(g => g.accounts.length === 3 && g.timingCorrelated);
    assert(moderate, 'expected the timing-correlated 3-account group to be detected');
    assert(moderate.totalFamilies === 2, `expected 2 families, got ${moderate.totalFamilies}`);
    assert(moderate.issuerCreated === false, 'expected issuerCreated false for this group');
    assert(moderate.confidence === 0.55, `expected confidence 0.55, got ${moderate.confidence}`);
    assert(moderate.tier === 'Moderate', `expected tier Moderate, got ${moderate.tier}`);
  });
});

suite.register('1 family (amount similarity only, no timing or creation corroboration) produces a Weak tier at 0.35 confidence', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugAnalyseIssuerConnections, { timeout: 8000 });
    const { txList, lines } = buildFixture();
    const result = await page.evaluate(([txList, lines, issuer]) => window._debugAnalyseIssuerConnections(txList, issuer, lines, null), [txList, lines, ISSUER]);

    const weak = result.mirrorGroups.find(g => g.accounts.length === 3 && !g.timingCorrelated);
    assert(weak, 'expected the timing-spread 3-account group to be detected');
    assert(weak.totalFamilies === 1, `expected 1 family, got ${weak.totalFamilies}`);
    assert(weak.timingCorrelated === false && weak.issuerCreated === false, 'expected both corroborating signals false for this group');
    assert(weak.confidence === 0.35, `expected confidence 0.35, got ${weak.confidence}`);
    assert(weak.tier === 'Weak', `expected tier Weak, got ${weak.tier}`);
  });
});

suite.register('Each tier produces a distinct finding: severity scales with family count, and classification text names the actual tier reached', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugAnalyseIssuerConnections, { timeout: 8000 });
    const { txList, lines } = buildFixture();
    const result = await page.evaluate(([txList, lines, issuer]) => window._debugAnalyseIssuerConnections(txList, issuer, lines, null), [txList, lines, ISSUER]);

    const findings = result.signals.filter(s => /accounts each received/.test(s.headline || ''));
    assert(findings.length === 3, `expected 3 mirror-group findings, got ${findings.length}`);

    const strongF = findings.find(f => /Strong evidence/.test(f.headline));
    const moderateF = findings.find(f => /Moderate evidence/.test(f.headline));
    const weakF = findings.find(f => /Weak evidence/.test(f.headline));
    assert(strongF && moderateF && weakF, `expected one finding per tier, got headlines: ${JSON.stringify(findings.map(f => f.headline))}`);

    assert(strongF.sev === 'critical', `expected the 3-family group to reach critical severity, got ${strongF.sev}`);
    assert(moderateF.sev === 'warn', `expected the 2-family group to reach warn severity, got ${moderateF.sev}`);
    assert(weakF.sev === 'info', `expected the 1-family group to stay at info severity, got ${weakF.sev}`);

    assert(/Multiple independent signals corroborate/.test(strongF.classification), 'expected Strong classification to name multiple corroborating signals');
    assert(/Two independent signals agree/.test(moderateF.classification), 'expected Moderate classification to name two signals');
    assert(/weak signal/.test(weakF.classification), 'expected Weak classification to explicitly call itself a weak signal');

    // False-equivalence protection: never claim proof of common ownership.
    assert(!findings.some(f => /proof of common ownership/i.test(f.classification) && !/not.{0,20}proof/i.test(f.classification)), 'must never assert common ownership as proven, only as circumstantial evidence');
  });
});

suite.register('Fewer than 3 accounts in a bucket produces no mirror group at all (the pre-existing minimum-sample gate still holds)', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugAnalyseIssuerConnections, { timeout: 8000 });
    const result = await page.evaluate((issuer) => {
      const mkTx = (dest, value, date, hash) => ({
        tx: { Account: issuer, Destination: dest, TransactionType: 'Payment', Amount: { currency: 'FOO', issuer, value: String(value) }, date, hash },
        meta: { TransactionResult: 'tesSUCCESS', AffectedNodes: [] },
      });
      const lines = [{ account: 'rSomeHolder000000000000000000000000', balance: '-99999', currency: 'FOO' }];
      // Only 2 accounts with a similar amount — below the 3-account minimum.
      const txList = [mkTx('rOnly100000000000000000000000000000', 1000, 800000000, 'h1'), mkTx('rOnly200000000000000000000000000000', 1000, 800000060, 'h2')];
      return window._debugAnalyseIssuerConnections(txList, issuer, lines, null);
    }, ISSUER);
    assert(result.mirrorGroups.length === 0, `expected no mirror groups with only 2 similar-amount accounts, got ${result.mirrorGroups.length}`);
  });
});

suite.register('A real token issuer with no mirror-wallet pattern renders the Issuer Connections panel with no page errors', async () => {
  await withPage(async (page) => {
    const errors = [];
    page.on('pageerror', e => errors.push(e.message));
    await connectAndShowDashboard(page);
    await page.evaluate(() => window.switchTab(null, 'inspector'));
    await page.evaluate((a) => { document.getElementById('inspect-addr').value = a; }, 'rsoLo2S1kiGeCcn6hCUXVrCpGMWLrRrLZz');
    await page.evaluate(() => window.runInspect());
    await page.waitForSelector('#section-evidence-matrix .evmatrix-row', { timeout: 90000 }).catch(() => {});
    await page.waitForTimeout(1000);
    assert(errors.length === 0, `expected zero page errors, got: ${JSON.stringify(errors)}`);
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
