// Regression coverage for common-external-funder detection as a 4th mirror-
// group evidence family in Issuer Connections (roadmap: XRPL Scam, Setup &
// Investigative Intelligence Layer, spec §19-20 "Common Funding
// Intelligence" / "Wallet Creation Cohorts"). Before this, the mirror-group
// clustering that groups an issuer's recipients by received-amount
// similarity could only corroborate with timing correlation or the issuer
// having directly created the account — a confirmed, self-documented gap:
// the existing address-clustering helper explicitly states it "cannot
// detect a shared funding source." This adds that missing signal using
// REAL per-wallet AccountRoot creation evidence (funding account), fetched
// via a capped number of targeted lookups in the main inspect flow, for
// accounts the issuer did NOT create directly.
import { withPage, assert } from './helpers.mjs';

const suite = { register: [], run: async () => {
  let pass = 0, fail = 0;
  console.log('\n▶ Common Funder — Mirror Group 4th Evidence Family');
  for (const { name, fn } of suite.register) {
    try { await fn(); console.log(`  PASS  ${name}`); pass++; }
    catch (err) { console.log(`  FAIL  ${name}`); console.log(`        ${err?.stack || err}`); fail++; }
  }
  return { pass, fail, total: suite.register.length };
}};
const test = (name, fn) => suite.register.push({ name, fn });

const ISSUER = 'rIssuerAAAAAAAAAAAAAAAAAAAAAAAAAAA1';
const FUNDER = 'rCommonFunderBBBBBBBBBBBBBBBBBBBBBB2';
const RECIPIENTS = ['rRecvA000000000000000000000000001', 'rRecvB000000000000000000000000002', 'rRecvC000000000000000000000000003', 'rRecvD000000000000000000000000004'];

function mkDistributionTxList() {
  return RECIPIENTS.map((r, i) => ({
    tx: { Account: ISSUER, Destination: r, TransactionType: 'Payment', hash: 'dist' + i, date: 900000000 + i * 200000, Amount: { currency: 'TST', issuer: ISSUER, value: '1000' } },
    meta: { TransactionResult: 'tesSUCCESS', AffectedNodes: [] },
  }));
}
const LINES = [{ currency: 'TST', balance: '-5000' }];

test('A common external funder shared by most (but not all) non-issuer-created recipients upgrades the mirror-group finding from Weak to Moderate evidence', async () => {
  await withPage(async (page, { pageErrors }) => {
    await page.waitForFunction(() => window._debugAnalyseIssuerConnections, { timeout: 8000 });
    const result = await page.evaluate(({ issuer, lines, txList, recipients, funder }) => {
      const commonFunderByAddr = new Map([[recipients[0], funder], [recipients[1], funder], [recipients[2], funder]]);
      const without = window._debugAnalyseIssuerConnections(txList, issuer, lines, null, new Map());
      const withFunder = window._debugAnalyseIssuerConnections(txList, issuer, lines, null, commonFunderByAddr);
      const pick = (r) => r.signals.find(s => s.module === 'Issuer Connections' && /accounts each received/.test(s.headline || ''));
      return { without: pick(without), withFunder: pick(withFunder) };
    }, { issuer: ISSUER, lines: LINES, txList: mkDistributionTxList(), recipients: RECIPIENTS, funder: FUNDER });

    assert(result.without.sev === 'info' && result.without.confidence === 0.35, `expected the baseline (no funder data) to stay Weak/info/0.35, got ${JSON.stringify(result.without)}`);
    assert(result.withFunder.sev === 'warn' && result.withFunder.confidence === 0.55, `expected common-funder evidence to upgrade to Moderate/warn/0.55, got ${JSON.stringify(result.withFunder)}`);
    assert(result.withFunder.observed.some(o => /3\/4.*share one common external funding account/.test(o)), `expected an observed line citing the 3/4 common-funder evidence, got: ${JSON.stringify(result.withFunder.observed)}`);
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

test('An account the issuer created directly is excluded from the common-funder calculation (issuerCreated already covers it)', async () => {
  await withPage(async (page, { pageErrors }) => {
    await page.waitForFunction(() => window._debugAnalyseIssuerConnections, { timeout: 8000 });
    const result = await page.evaluate(({ issuer, lines, recipients, funder }) => {
      // recipients[0] is issuer-created (CreatedNode present); the other 3
      // share FUNDER — commonFunded should be computed over the 3
      // non-issuer-created accounts only (3/3 = 100%), not diluted by
      // treating the issuer-created one as "funded by someone else."
      const txList = recipients.map((r, i) => ({
        tx: { Account: issuer, Destination: r, TransactionType: 'Payment', hash: 'dist' + i, date: 900000000 + i * 200000, Amount: { currency: 'TST', issuer, value: '1000' } },
        meta: { TransactionResult: 'tesSUCCESS', AffectedNodes: i === 0 ? [{ CreatedNode: { LedgerEntryType: 'AccountRoot', NewFields: { Account: r } } }] : [] },
      }));
      const commonFunderByAddr = new Map([[recipients[1], funder], [recipients[2], funder], [recipients[3], funder]]);
      const withFunder = window._debugAnalyseIssuerConnections(txList, issuer, lines, null, commonFunderByAddr);
      const finding = withFunder.signals.find(s => s.module === 'Issuer Connections' && /accounts each received/.test(s.headline || ''));
      return { finding, mirrorGroup: withFunder.mirrorGroups?.[0] };
    }, { issuer: ISSUER, lines: LINES, recipients: RECIPIENTS, funder: FUNDER });

    assert(result.mirrorGroup?.commonFunded === true, `expected commonFunded=true when 3/3 non-issuer-created accounts share a funder, got ${JSON.stringify(result.mirrorGroup)}`);
    assert(result.mirrorGroup?.issuerCreated === false, 'expected issuerCreated to stay false (only 1/4, below the 0.6 threshold)');
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

test('No common-funder data at all (default empty map) behaves identically to before this feature existed', async () => {
  await withPage(async (page, { pageErrors }) => {
    await page.waitForFunction(() => window._debugAnalyseIssuerConnections, { timeout: 8000 });
    const result = await page.evaluate(({ issuer, lines, txList }) => {
      // No 5th argument at all — exercises the default parameter.
      const r = window._debugAnalyseIssuerConnections(txList, issuer, lines, null);
      return r.mirrorGroups?.[0];
    }, { issuer: ISSUER, lines: LINES, txList: mkDistributionTxList() });

    assert(result?.commonFunded === false, `expected commonFunded to default to false with no funder data, got ${JSON.stringify(result)}`);
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
