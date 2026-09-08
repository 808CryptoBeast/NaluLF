// Regression guard for Issuer Market Activity: aggregate CLOB/AMM/HYBRID
// trading activity across ALL holders of a token this account issues (not
// just this account's own trades). This is possible because every
// trustline for an issued currency has the issuer as one of its two
// parties, so a trade between two arbitrary holders already shows up in
// the issuer's own transaction history — no extra data source needed.
import { withPage, connectAndShowDashboard, inspectAddress, makeSuite, assert } from './helpers.mjs';

// Real, active token issuer (CULT) with genuine third-party DEX/AMM trading
// volume in its token — confirmed live to have zero self-initiated trades
// of its own (all activity below belongs to other holders).
const REAL_ISSUER_ACCOUNT = 'rCULtAKrKbQjk1Tpmg5hkw4dpcf9S9KCs';

const suite = makeSuite('Issuer Market Activity');

suite.register('A real token issuer with genuine third-party trading volume gets an aggregate CLOB/AMM finding, with a data-completeness caveat', async () => {
  await withPage(async (page) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, REAL_ISSUER_ACCOUNT, { timeout: 90000 });
    await page.waitForTimeout(2000); // let the fuller tx-history fetch settle for this high-volume account

    const finding = await page.evaluate(() => (window._lastAllFindings || []).find((f) => f.module === 'Issuer Market Activity'));
    assert(finding, 'expected an Issuer Market Activity finding — live data may have drifted; re-verify against current mainnet state if this fails');
    assert(/CLOB/.test(finding.headline) && /AMM/.test(finding.headline), `headline should report a CLOB/AMM split: ${finding.headline}`);
    assert(/holder/i.test(finding.headline), `headline should report a distinct-holder count: ${finding.headline}`);
    assert(finding.sev === 'info', `this is informational, not accusatory, expected info severity, got ${finding.sev}`);
    assert(finding.classification?.includes('not this issuer account\'s own trading activity'), 'must explicitly disclaim this is holder activity, not the issuer\'s own trades');
  });
});

suite.register('A non-issuer account (no negative-balance obligations) produces applicable:false and zero findings', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugIssuerMarketActivity, { timeout: 8000 });
    const result = await page.evaluate(() => {
      const addr = 'rOrdinaryHolder';
      const lines = [{ account: 'rIssuerX', currency: 'USD', balance: '42.5' }]; // positive = this account HOLDS the token, doesn't issue it
      return window._debugIssuerMarketActivity([], addr, lines, {});
    });
    assert(result.applicable === false, 'a non-issuer account must not run the full aggregate scan');
    assert(result.findings.length === 0, 'expected zero findings for a non-issuer account');
  });
});

suite.register('A synthetic issuer with real CLOB, AMM, and HYBRID trades between two OTHER holders (not the issuer itself) classifies all three correctly', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugIssuerMarketActivity, { timeout: 8000 });
    const result = await page.evaluate(() => {
      const issuer = 'rIssuerAddr';
      const holderA = 'rHolderA';
      const holderB = 'rHolderB';
      const lines = [{ account: holderA, currency: 'FOO', balance: '-500' }]; // negative = issuer's obligation to a holder — confirms this account is the issuer of FOO

      // A CLOB trade between holderA and holderB in the issuer's token —
      // the issuer never appears as tx.Account, only as the trustline
      // counterparty on both sides.
      const clobTx = { TransactionType: 'OfferCreate', Account: holderA, hash: 'clob1', date: 1 };
      const clobMeta = {
        TransactionResult: 'tesSUCCESS',
        AffectedNodes: [
          { ModifiedNode: { FinalFields: { Account: holderB, TakerGets: '1000000', TakerPays: { currency: 'FOO', issuer, value: '10' } }, LedgerEntryType: 'Offer', LedgerIndex: 'OFFER1' } },
          { ModifiedNode: { FinalFields: { Balance: { currency: 'FOO', issuer: 'rrrrrrrrrrrrrrrrrrrrBZbvji', value: '-490' }, HighLimit: { currency: 'FOO', issuer, value: '0' }, LowLimit: { currency: 'FOO', issuer: holderA, value: '0' } }, PreviousFields: { Balance: { currency: 'FOO', issuer: 'rrrrrrrrrrrrrrrrrrrrBZbvji', value: '-500' } }, LedgerEntryType: 'RippleState', LedgerIndex: 'RS_A' } },
          { ModifiedNode: { FinalFields: { Balance: { currency: 'FOO', issuer: 'rrrrrrrrrrrrrrrrrrrrBZbvji', value: '10' }, HighLimit: { currency: 'FOO', issuer, value: '0' }, LowLimit: { currency: 'FOO', issuer: holderB, value: '0' } }, PreviousFields: { Balance: { currency: 'FOO', issuer: 'rrrrrrrrrrrrrrrrrrrrBZbvji', value: '0' } }, LedgerEntryType: 'RippleState', LedgerIndex: 'RS_B' } },
        ],
      };

      // A pure-AMM trade: holderA swaps through an AMM pool for FOO, no
      // Offer node at all, only the AMMID-bearing pool AccountRoot.
      const ammTx = { TransactionType: 'Payment', Account: holderA, Destination: holderA, hash: 'amm1', date: 2 };
      const ammMeta = {
        TransactionResult: 'tesSUCCESS',
        AffectedNodes: [
          { ModifiedNode: { FinalFields: { AMMID: 'POOLID', Account: 'rAmmPool', Balance: '1000' }, PreviousFields: { Balance: '900' }, LedgerEntryType: 'AccountRoot', LedgerIndex: 'AMMACCT' } },
          { ModifiedNode: { FinalFields: { Balance: { currency: 'FOO', issuer: 'rrrrrrrrrrrrrrrrrrrrBZbvji', value: '-480' }, HighLimit: { currency: 'FOO', issuer, value: '0' }, LowLimit: { currency: 'FOO', issuer: holderA, value: '0' } }, PreviousFields: { Balance: { currency: 'FOO', issuer: 'rrrrrrrrrrrrrrrrrrrrBZbvji', value: '-490' } }, LedgerEntryType: 'RippleState', LedgerIndex: 'RS_A2' } },
        ],
      };

      // A HYBRID trade: both an AMM pool node and an Offer node present.
      const hybridTx = { TransactionType: 'Payment', Account: holderB, Destination: holderB, hash: 'hybrid1', date: 3 };
      const hybridMeta = {
        TransactionResult: 'tesSUCCESS',
        AffectedNodes: [
          { ModifiedNode: { FinalFields: { AMMID: 'POOLID', Account: 'rAmmPool', Balance: '1100' }, PreviousFields: { Balance: '1000' }, LedgerEntryType: 'AccountRoot', LedgerIndex: 'AMMACCT2' } },
          { ModifiedNode: { FinalFields: { Account: 'rSomeMaker', TakerGets: '200000', TakerPays: { currency: 'FOO', issuer, value: '2' } }, LedgerEntryType: 'Offer', LedgerIndex: 'OFFER2' } },
          { ModifiedNode: { FinalFields: { Balance: { currency: 'FOO', issuer: 'rrrrrrrrrrrrrrrrrrrrBZbvji', value: '5' }, HighLimit: { currency: 'FOO', issuer, value: '0' }, LowLimit: { currency: 'FOO', issuer: holderB, value: '0' } }, PreviousFields: { Balance: { currency: 'FOO', issuer: 'rrrrrrrrrrrrrrrrrrrrBZbvji', value: '0' } }, LedgerEntryType: 'RippleState', LedgerIndex: 'RS_B2' } },
        ],
      };

      const txList = [{ tx: clobTx, meta: clobMeta }, { tx: ammTx, meta: ammMeta }, { tx: hybridTx, meta: hybridMeta }];
      return window._debugIssuerMarketActivity(txList, issuer, lines, { newestToOldestComplete: true });
    });

    assert(result.applicable === true, 'expected applicable:true for a confirmed issuer');
    assert(result.stats.total === 3, `expected 3 classified trades, got ${result.stats.total}`);
    assert(result.stats.clob === 1 && result.stats.amm === 1 && result.stats.hybrid === 1, `expected 1 each of CLOB/AMM/HYBRID, got ${JSON.stringify(result.stats)}`);
    assert(result.holderCount === 2, `expected 2 distinct holders (holderA, holderB), got ${result.holderCount}`);
    assert(result.dataCompleteness === 'complete', 'expected complete data-completeness when historyCoverage says so');
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
