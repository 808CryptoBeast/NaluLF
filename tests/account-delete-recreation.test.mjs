// Regression coverage for account delete + recreation lifetime tracking
// (roadmap: XRPL Account Age / Activation Provenance repair, spec §20-22).
// An XRPL address can be deleted via AccountDelete and later reused by
// someone funding a fresh AccountRoot at the same address — a genuinely
// different account in substance. _buildAccountLifetimeHistory pairs every
// creation/deletion event into discrete lifetime segments; the CURRENT
// account must be described by its own (most recent) creation, never by an
// earlier, superseded one. This also pins a correctness fix made to
// _findAccountRootCreationEvidence while building this: it used to return
// the FIRST creation event found, which is only correct when there's
// exactly one — for a recreated address it would wrongly present the
// address's original (deleted) activation as if it were still current.
import { withPage, assert } from './helpers.mjs';

const suite = { register: [], run: async () => {
  let pass = 0, fail = 0;
  console.log('\n▶ Account Delete + Recreation');
  for (const { name, fn } of suite.register) {
    try { await fn(); console.log(`  PASS  ${name}`); pass++; }
    catch (err) { console.log(`  FAIL  ${name}`); console.log(`        ${err?.stack || err}`); fail++; }
  }
  return { pass, fail, total: suite.register.length };
}};
const test = (name, fn) => suite.register.push({ name, fn });

const ADDR = 'rRecreatedAddrAAAAAAAAAAAAAAAAAAAA';
const FUNDER1 = 'rFunder1AAAAAAAAAAAAAAAAAAAAAAAAAA1';
const FUNDER2 = 'rFunder2BBBBBBBBBBBBBBBBBBBBBBBBBB2';

function mkRecreatedTxList() {
  return [
    { tx: { Account: FUNDER1, Destination: ADDR, TransactionType: 'Payment', hash: 'create1', date: 663000000, ledger_index: 60000000 }, meta: { TransactionResult: 'tesSUCCESS', AffectedNodes: [
      { CreatedNode: { LedgerEntryType: 'AccountRoot', NewFields: { Account: ADDR, Balance: '20000000' } } },
    ] } },
    { tx: { Account: ADDR, TransactionType: 'AccountDelete', Destination: FUNDER1, hash: 'delete1', date: 758000000, ledger_index: 75000000 }, meta: { TransactionResult: 'tesSUCCESS', AffectedNodes: [] } },
    { tx: { Account: FUNDER2, Destination: ADDR, TransactionType: 'Payment', hash: 'create2', date: 821000000, ledger_index: 90000000 }, meta: { TransactionResult: 'tesSUCCESS', AffectedNodes: [
      { CreatedNode: { LedgerEntryType: 'AccountRoot', NewFields: { Account: ADDR, Balance: '30000000' } } },
    ] } },
  ];
}

test('A deleted-and-recreated address produces two correctly-paired lifetime segments, with the final one open', async () => {
  await withPage(async (page, { pageErrors }) => {
    await page.waitForFunction(() => window._debugBuildAccountLifetimeHistory, { timeout: 8000 });
    const history = await page.evaluate(({ addr, txList }) => window._debugBuildAccountLifetimeHistory(txList, addr), { addr: ADDR, txList: mkRecreatedTxList() });

    assert(history.deletedAndRecreated === true, 'expected deletedAndRecreated to be true');
    assert(history.lifetimes.length === 2, `expected 2 lifetime segments, got ${history.lifetimes.length}`);
    assert(history.lifetimes[0].createdTxHash === 'create1' && history.lifetimes[0].deletedTxHash === 'delete1', 'expected the first lifetime to be closed by the matching AccountDelete');
    assert(history.lifetimes[1].createdTxHash === 'create2' && history.lifetimes[1].deletedAt === null, 'expected the second lifetime to be open (current)');
    assert(history.earliestKnownHistory.createdTxHash === 'create1', 'expected earliestKnownHistory to point at the original, first-ever creation');
    assert(history.currentLifetime.createdTxHash === 'create2', 'expected currentLifetime to point at the most recent creation');
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

test('_findAccountRootCreationEvidence returns the CURRENT (most recent) activation, not the stale original one, for a recreated address', async () => {
  await withPage(async (page, { pageErrors }) => {
    await page.waitForFunction(() => window._debugFindAccountRootCreationEvidence, { timeout: 8000 });
    const evidence = await page.evaluate(({ addr, txList }) => window._debugFindAccountRootCreationEvidence(txList, addr), { addr: ADDR, txList: mkRecreatedTxList() });

    assert(evidence.transactionHash === 'create2', `expected the CURRENT (second) creation evidence, got hash "${evidence.transactionHash}"`);
    assert(evidence.fundingAccount === FUNDER2, 'expected the current funding account (FUNDER2), not the original one');
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

test('A normal, never-deleted account correctly shows deletedAndRecreated:false with exactly one lifetime', async () => {
  await withPage(async (page, { pageErrors }) => {
    await page.waitForFunction(() => window._debugBuildAccountLifetimeHistory, { timeout: 8000 });
    const history = await page.evaluate(({ addr }) => {
      const txList = [{ tx: { Account: 'rFunderX000000000000000000000000001', Destination: addr, TransactionType: 'Payment', hash: 'createOnly', date: 663000000, ledger_index: 60000000 }, meta: { TransactionResult: 'tesSUCCESS', AffectedNodes: [
        { CreatedNode: { LedgerEntryType: 'AccountRoot', NewFields: { Account: addr, Balance: '20000000' } } },
      ] } }];
      return window._debugBuildAccountLifetimeHistory(txList, addr);
    }, { addr: ADDR });

    assert(history.deletedAndRecreated === false, 'expected deletedAndRecreated to be false for a never-deleted account');
    assert(history.lifetimes.length === 1, `expected exactly 1 lifetime segment, got ${history.lifetimes.length}`);
    assert(history.lifetimes[0].deletedAt === null, 'expected the single lifetime to be open');
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

test('An account with zero creation evidence at all returns an empty, non-crashing lifetime history', async () => {
  await withPage(async (page, { pageErrors }) => {
    await page.waitForFunction(() => window._debugBuildAccountLifetimeHistory, { timeout: 8000 });
    const history = await page.evaluate(({ addr }) => {
      const txList = [{ tx: { Account: addr, TransactionType: 'Payment', hash: 'h1', date: 900000000 }, meta: { TransactionResult: 'tesSUCCESS', AffectedNodes: [] } }];
      return window._debugBuildAccountLifetimeHistory(txList, addr);
    }, { addr: ADDR });

    assert(history.deletedAndRecreated === false, 'expected false when no creation evidence exists at all');
    assert(history.lifetimes.length === 0, 'expected an empty lifetimes array');
    assert(history.earliestKnownHistory === null && history.currentLifetime === null, 'expected both to be null with no evidence');
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
