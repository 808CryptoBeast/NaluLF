// Regression guard for AMM/CLOB/HYBRID execution-route classification
// (_txTouchesAmm, buildExecutionLedger, analyseExecutionRouting) and the
// Wash Execution "no market context" fix that follows from it.
//
// The AMM-detection ground truth (an AMM pool's own AccountRoot node always
// carries an AMMID field in FinalFields whenever a transaction executes
// against it, with no separate LedgerEntryType:"AMM" node) was verified by
// directly querying live XRPL mainnet data for real transactions against
// the SOLO/XRP AMM pool (rMEJo9H5XvTe17UoAJzj8jtKVvTRcxwngo). REAL_AMM_TX
// below is one of those real, unmodified transactions (a self-directed
// cross-currency Payment routed entirely through that AMM pool, no Offer
// involved) — not a synthetic mockup.
import { withPage, makeSuite, assert } from './helpers.mjs';

const REAL_AMM_TX = {
  tx: {
    Account: 'rPBJGLCysYLSrfH6SttjoWkYW3Pvu2qPR',
    Amount: { currency: '534F4C4F00000000000000000000000000000000', issuer: 'rsoLo2S1kiGeCcn6hCUXVrCpGMWLrRrLZz', value: '0.1527755524447556' },
    Destination: 'rPBJGLCysYLSrfH6SttjoWkYW3Pvu2qPR',
    Fee: '10', Flags: 131072, SendMax: '1384', Sequence: 82904593,
    TransactionType: 'Payment', date: 842159271,
    hash: 'AE6072232B56F5745724D1376BFFE84181265989FF6ABE448E5A18ACD09288DA',
    ledger_index: 106838431,
  },
  meta: {
    TransactionResult: 'tesSUCCESS',
    AffectedNodes: [
      { ModifiedNode: { FinalFields: { AMMID: '419A61974BDCB91E0408865D554605F466084BA9A88F75391502502F0578DF89', Account: 'rMEJo9H5XvTe17UoAJzj8jtKVvTRcxwngo', Balance: '32005650791' }, LedgerEntryType: 'AccountRoot', LedgerIndex: '252EADDB7D9FA57AF38E5D94279605E87B35747A7BC51EE4BA480B1A3828B358', PreviousFields: { Balance: '32005649407' } } },
      { ModifiedNode: { FinalFields: { Account: 'rPBJGLCysYLSrfH6SttjoWkYW3Pvu2qPR', Balance: '5889747' }, LedgerEntryType: 'AccountRoot', LedgerIndex: '2CB22820EFB5226E04BF2FF1CCCD025C3092393B6F3747CEAAAF61EA87C406B0', PreviousFields: { Balance: '5891141' } } },
      { ModifiedNode: { FinalFields: { Balance: { currency: '534F4C4F00000000000000000000000000000000', issuer: 'rrrrrrrrrrrrrrrrrrrrBZbvji', value: '-3560634.115775426' }, HighLimit: { currency: '534F4C4F00000000000000000000000000000000', issuer: 'rMEJo9H5XvTe17UoAJzj8jtKVvTRcxwngo', value: '0' }, LowLimit: { currency: '534F4C4F00000000000000000000000000000000', issuer: 'rsoLo2S1kiGeCcn6hCUXVrCpGMWLrRrLZz', value: '0' } }, LedgerEntryType: 'RippleState', LedgerIndex: 'E936D391C35BBC5EB154D2B848CB3339B24AD40451D0091EE5AB86A4B0D2DED5', PreviousFields: { Balance: { currency: '534F4C4F00000000000000000000000000000000', issuer: 'rrrrrrrrrrrrrrrrrrrrBZbvji', value: '-3560634.268566256' } } } },
      { ModifiedNode: { FinalFields: { Balance: { currency: '534F4C4F00000000000000000000000000000000', issuer: 'rrrrrrrrrrrrrrrrrrrrBZbvji', value: '0.1527755524447556' }, HighLimit: { currency: '534F4C4F00000000000000000000000000000000', issuer: 'rsoLo2S1kiGeCcn6hCUXVrCpGMWLrRrLZz', value: '0' }, LowLimit: { currency: '534F4C4F00000000000000000000000000000000', issuer: 'rPBJGLCysYLSrfH6SttjoWkYW3Pvu2qPR', value: '399277132.38133' } }, LedgerEntryType: 'RippleState', LedgerIndex: 'EE3E4E6C6FA7CA79F592883BBEBA483985985BB087E6F1BB0F1282C8DADD97F1', PreviousFields: { Balance: { currency: '534F4C4F00000000000000000000000000000000', issuer: 'rrrrrrrrrrrrrrrrrrrrBZbvji', value: '0' } } } },
    ],
  },
};
const REAL_AMM_ADDR = 'rPBJGLCysYLSrfH6SttjoWkYW3Pvu2qPR';

const suite = makeSuite('AMM/CLOB/HYBRID Execution Routing');

suite.register('_txTouchesAmm detects the real AMMID signal; a plain CLOB fill has none', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugTxTouchesAmm, { timeout: 8000 });
    const result = await page.evaluate((realTx) => {
      const clobMeta = {
        AffectedNodes: [
          { ModifiedNode: { FinalFields: { Account: 'rSomeMaker', TakerGets: '1000000', TakerPays: { currency: 'USD', issuer: 'rIssuer', value: '1' } }, LedgerEntryType: 'Offer', LedgerIndex: 'AAA' } },
          { ModifiedNode: { FinalFields: { Account: 'rTaker', Balance: '999999' }, LedgerEntryType: 'AccountRoot', LedgerIndex: 'BBB' } },
        ],
      };
      return {
        realAmmDetected: window._debugTxTouchesAmm(realTx.meta),
        clobDetected: window._debugTxTouchesAmm(clobMeta),
      };
    }, REAL_AMM_TX);
    assert(result.realAmmDetected === true, 'expected AMMID signal detected on the real AMM-routed transaction');
    assert(result.clobDetected === false, 'a plain CLOB fill (no AMMID anywhere) must not be misdetected as AMM');
  });
});

suite.register('buildExecutionLedger classifies the real transaction as a pure AMM route', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugBuildExecutionLedger, { timeout: 8000 });
    const result = await page.evaluate(({ tx, addr }) => {
      const ledger = window._debugBuildExecutionLedger([{ tx, meta: tx._meta }], addr);
      return ledger.stats;
    }, { tx: { ...REAL_AMM_TX.tx, _meta: REAL_AMM_TX.meta }, addr: REAL_AMM_ADDR });
    assert(result.total === 1, `expected 1 classified execution, got ${result.total}`);
    assert(result.amm === 1, `expected the real transaction to classify as AMM, got amm=${result.amm} clob=${result.clob} hybrid=${result.hybrid}`);
    assert(result.clob === 0 && result.hybrid === 0, 'a pure AMM swap must not also count as CLOB or HYBRID');
  });
});

suite.register('buildExecutionLedger classifies a synthetic CLOB-only fill and a synthetic HYBRID fill correctly', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugBuildExecutionLedger, { timeout: 8000 });
    const result = await page.evaluate(() => {
      const addr = 'rTraderAddr';
      const clobTx = { TransactionType: 'OfferCreate', Account: addr, hash: 'clobhash', date: 1 };
      const clobMeta = {
        TransactionResult: 'tesSUCCESS',
        AffectedNodes: [
          { ModifiedNode: { FinalFields: { Account: 'rCounterparty', TakerGets: '500000', TakerPays: { currency: 'USD', issuer: 'rIssuer', value: '2' } }, LedgerEntryType: 'Offer', LedgerIndex: 'OFFER1' } },
          { ModifiedNode: { FinalFields: { Account: addr, Balance: '4500000' }, PreviousFields: { Balance: '5000000' }, LedgerEntryType: 'AccountRoot', LedgerIndex: 'ACCT1' } },
          { ModifiedNode: { FinalFields: { Balance: { currency: 'USD', issuer: 'rrrrrrrrrrrrrrrrrrrrBZbvji', value: '2' }, HighLimit: { currency: 'USD', issuer: 'rIssuer', value: '0' }, LowLimit: { currency: 'USD', issuer: addr, value: '0' } }, PreviousFields: { Balance: { currency: 'USD', issuer: 'rrrrrrrrrrrrrrrrrrrrBZbvji', value: '0' } }, LedgerEntryType: 'RippleState', LedgerIndex: 'RS1' } },
        ],
      };

      const hybridTx = { TransactionType: 'Payment', Account: addr, Destination: addr, hash: 'hybridhash', date: 2 };
      const hybridMeta = {
        TransactionResult: 'tesSUCCESS',
        AffectedNodes: [
          { ModifiedNode: { FinalFields: { AMMID: 'SOMEAMMID', Account: 'rAmmPool', Balance: '1000' }, PreviousFields: { Balance: '900' }, LedgerEntryType: 'AccountRoot', LedgerIndex: 'AMMACCT' } },
          { ModifiedNode: { FinalFields: { Account: 'rCounterparty2', TakerGets: '300000', TakerPays: { currency: 'USD', issuer: 'rIssuer', value: '1' } }, LedgerEntryType: 'Offer', LedgerIndex: 'OFFER2' } },
          { ModifiedNode: { FinalFields: { Account: addr, Balance: '4200000' }, PreviousFields: { Balance: '4500000' }, LedgerEntryType: 'AccountRoot', LedgerIndex: 'ACCT2' } },
          { ModifiedNode: { FinalFields: { Balance: { currency: 'USD', issuer: 'rrrrrrrrrrrrrrrrrrrrBZbvji', value: '5' }, HighLimit: { currency: 'USD', issuer: 'rIssuer', value: '0' }, LowLimit: { currency: 'USD', issuer: addr, value: '0' } }, PreviousFields: { Balance: { currency: 'USD', issuer: 'rrrrrrrrrrrrrrrrrrrrBZbvji', value: '2' } }, LedgerEntryType: 'RippleState', LedgerIndex: 'RS2' } },
        ],
      };

      const ledger = window._debugBuildExecutionLedger([{ tx: clobTx, meta: clobMeta }, { tx: hybridTx, meta: hybridMeta }], addr);
      return { stats: ledger.stats, routes: ledger.executions.map((e) => e.route) };
    });
    assert(result.stats.total === 2, `expected 2 executions, got ${result.stats.total}`);
    assert(result.stats.clob === 1, `expected 1 CLOB execution, got ${result.stats.clob}`);
    assert(result.stats.hybrid === 1, `expected 1 HYBRID execution, got ${result.stats.hybrid}`);
    assert(result.stats.amm === 0, `HYBRID must not double-count as pure AMM, got amm=${result.stats.amm}`);
  });
});

suite.register('analyseExecutionRouting produces an info-level finding summarizing the route split, and none when there are zero executions', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugExecutionRouting, { timeout: 8000 });
    const result = await page.evaluate(() => {
      const withTrades = window._debugExecutionRouting({ stats: { total: 4, clob: 2, amm: 1, hybrid: 1, unknown: 0, clobPct: 50, ammPct: 25, hybridPct: 25 } });
      const empty = window._debugExecutionRouting({ stats: { total: 0, clob: 0, amm: 0, hybrid: 0, unknown: 0, clobPct: 0, ammPct: 0, hybridPct: 0 } });
      return {
        withTradesCount: withTrades.findings.length,
        headline: withTrades.findings[0]?.headline,
        sev: withTrades.findings[0]?.sev,
        emptyCount: empty.findings.length,
      };
    });
    assert(result.withTradesCount === 1, 'expected exactly one Execution Routing finding when executions exist');
    assert(result.sev === 'info', `Execution Routing is informational, expected info severity, got ${result.sev}`);
    assert(/CLOB/.test(result.headline) && /AMM/.test(result.headline), `headline should mention both CLOB and AMM splits: ${result.headline}`);
    assert(result.emptyCount === 0, 'expected no finding when there are zero classified executions');
  });
});

suite.register('An AMM-only trader with zero CLOB offer history is no longer treated as having "no market context" for a same-currency self-payment', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugWashExecution, { timeout: 8000 });
    const result = await page.evaluate(() => {
      const addr = 'rAmmOnlyTrader';
      const profile = { cancelRatio: 0, sizeCV: null, burstWindows: { thirtySec: 0, oneHour: 0 }, createdCount: 0 };
      const offerLifecycles = { list: [] }; // zero CLOB history — the pre-fix signal
      const payments = [
        { tx: { TransactionType: 'Payment', Account: addr, Destination: addr, Amount: '5000000' } },
        { tx: { TransactionType: 'Payment', Account: addr, Destination: addr, Amount: '5000000' } },
        { tx: { TransactionType: 'Payment', Account: addr, Destination: addr, Amount: '5000000' } },
      ];
      const executionLedgerWithAmm = { stats: { total: 3, clob: 0, amm: 3, hybrid: 0, unknown: 0, clobPct: 0, ammPct: 100, hybridPct: 0 } };
      const executionLedgerEmpty = { stats: { total: 0, clob: 0, amm: 0, hybrid: 0, unknown: 0, clobPct: 0, ammPct: 0, hybridPct: 0 } };

      const withAmm = window._debugWashExecution(profile, offerLifecycles, payments, addr, false, executionLedgerWithAmm);
      const withoutAmm = window._debugWashExecution(profile, offerLifecycles, payments, addr, false, executionLedgerEmpty);
      return {
        withAmm: withAmm.findings.find((f) => f.headline?.includes('self-payment')),
        withoutAmm: withoutAmm.findings.find((f) => f.headline?.includes('self-payment')),
      };
    });
    assert(result.withoutAmm?.applicability?.applicable === false, 'baseline (no AMM activity, no CLOB history) should still be the no-market-context case — regression in the pre-existing behavior');
    assert(result.withAmm, 'expected a self-payment finding when AMM trading history exists');
    assert(
      result.withAmm.applicability == null || result.withAmm.applicability.applicable !== false,
      'an account with real AMM trading history must not be treated as having no market context, even with zero CLOB offers'
    );
    assert(result.withAmm.sev !== 'info' || result.withAmm.classification !== result.withoutAmm.classification, 'the AMM-aware finding should differ from the no-market-context baseline');
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
