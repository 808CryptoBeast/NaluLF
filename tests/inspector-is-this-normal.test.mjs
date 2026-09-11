// Regression guard for "Is This Normal?" (beginner-UX spec §35) — a
// standalone comparison of this account's MOST RECENT outbound transfer
// against its own PRIOR history, independent of whether that transfer
// was large enough to trigger a full Drain Risk episode (which requires
// >50% of balance turned over in one window).
//
// Deliberately evaluates the most recent transfer, not the largest-ever
// one — a real design bug caught during development: comparing "the
// biggest transfer this account has ever made" against a baseline that
// necessarily INCLUDES that same transfer trivially lands at the 100th
// percentile every single time (it is, by definition, >= everything else
// in its own sample), so that comparison could never actually
// discriminate normal from unusual. The baseline must exclude the
// transfer being evaluated, the same exclusion principle
// _computeAccountBaseline already uses for Drain Risk's own baseline.
import { withPage, makeSuite, assert } from './helpers.mjs';

const suite = makeSuite('Drain Risk — Is This Normal?');

const ADDR = 'rTestAccount000000000000000000000000000';

function paymentTx(xrp, date, hash) {
  return { tx: { Account: ADDR, TransactionType: 'Payment', Amount: String(xrp * 1e6), date, hash }, meta: { TransactionResult: 'tesSUCCESS' } };
}

suite.register('Too few payments produces applicable:false with an honest reason, not a fabricated percentile', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugIsThisNormal, { timeout: 8000 });
    const txList = [paymentTx(100, 1000, 'h1'), paymentTx(200, 2000, 'h2')];
    const result = await page.evaluate(([txList, addr]) => window._debugIsThisNormal(txList, addr), [txList, ADDR]);
    assert(result.applicable === false, 'expected applicable:false with only 2 payments');
    assert(/not enough history/.test(result.reason), `expected an honest reason, got: ${result.reason}`);
  });
});

suite.register('The most recent transfer being unremarkable relative to PRIOR history (not the max of the whole set) is verdict "normal"', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugIsThisNormal, { timeout: 8000 });
    // Prior payments include some LARGER than the most recent one (200 XRP
    // appears before it) — the most recent (100 XRP) sits comfortably in
    // the middle of its own prior history, not at the top.
    const priorSizes = [50, 60, 70, 80, 90, 100, 110, 130, 200];
    const txList = priorSizes.map((xrp, i) => paymentTx(xrp, 1000 + i * 1000, `p${i}`));
    txList.push(paymentTx(100, 1000 + priorSizes.length * 1000, 'most-recent'));
    const result = await page.evaluate(([txList, addr]) => window._debugIsThisNormal(txList, addr), [txList, ADDR]);

    assert(result.applicable === true, 'expected applicable:true with 10 total payments');
    assert(Math.abs(result.evaluatedTransfer.xrp - 100) < 0.01, `expected the evaluated transfer to be the most recent (100 XRP), got ${result.evaluatedTransfer.xrp}`);
    assert(result.percentile < 95, `expected a percentile well below 95 since the most recent transfer is mid-pack, got ${result.percentile}`);
    assert(result.verdict === 'normal', `expected verdict "normal", got "${result.verdict}"`);
    assert(result.priorAuthChange === false, 'expected no prior auth change');
    assert(/No unusual compromise pattern/.test(result.conclusion), `expected the normal-case conclusion text, got: "${result.conclusion}"`);
  });
});

suite.register('The most recent transfer dwarfing all PRIOR transfers is verdict "unusual-size" with a high percentile', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugIsThisNormal, { timeout: 8000 });
    const priorSizes = [50, 55, 60, 65, 70, 75, 80, 85];
    const txList = priorSizes.map((xrp, i) => paymentTx(xrp, 1000 + i * 1000, `p${i}`));
    txList.push(paymentTx(43000, 1000 + priorSizes.length * 1000, 'most-recent'));
    const result = await page.evaluate(([txList, addr]) => window._debugIsThisNormal(txList, addr), [txList, ADDR]);

    assert(result.verdict === 'unusual-size', `expected verdict "unusual-size" for a 43,000 XRP transfer after 50-85 XRP priors, got "${result.verdict}"`);
    assert(result.percentile >= 95, `expected a percentile >= 95, got ${result.percentile}`);
    assert(/unusually large for THIS account/.test(result.conclusion), `expected the unusual-size conclusion text, got: "${result.conclusion}"`);
  });
});

suite.register('A security/authorization change within 24h before the most recent transfer overrides the verdict, regardless of size', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugIsThisNormal, { timeout: 8000 });
    const priorSizes = [50, 60, 70, 80, 90, 100, 110, 130, 200];
    const txList = priorSizes.map((xrp, i) => paymentTx(xrp, 1000 + i * 1000, `p${i}`));
    const mostRecentDate = 1000 + priorSizes.length * 1000;
    txList.push(paymentTx(100, mostRecentDate, 'most-recent'));
    txList.push({ tx: { Account: ADDR, TransactionType: 'SetRegularKey', date: mostRecentDate - 3600, hash: 'auth1' }, meta: { TransactionResult: 'tesSUCCESS' } });

    const result = await page.evaluate(([txList, addr]) => window._debugIsThisNormal(txList, addr), [txList, ADDR]);
    assert(result.priorAuthChange === true, 'expected priorAuthChange:true (SetRegularKey 1h before the most recent transfer)');
    assert(result.verdict === 'unusual-with-auth-change', `expected verdict "unusual-with-auth-change" even though the transfer size itself was unremarkable, got "${result.verdict}"`);
    assert(/Account Compromise Risk/.test(result.conclusion), `expected the conclusion to point to Account Compromise Risk, got: "${result.conclusion}"`);
  });
});

suite.register('An authorization change OUTSIDE the 24h window before the most recent transfer does not override the verdict', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugIsThisNormal, { timeout: 8000 });
    const priorSizes = [50, 60, 70, 80, 90, 100, 110, 130, 200];
    const txList = priorSizes.map((xrp, i) => paymentTx(xrp, 1000 + i * 1000, `p${i}`));
    const mostRecentDate = 1000 + priorSizes.length * 1000;
    txList.push(paymentTx(100, mostRecentDate, 'most-recent'));
    txList.push({ tx: { Account: ADDR, TransactionType: 'SetRegularKey', date: mostRecentDate - 200000, hash: 'auth1' }, meta: { TransactionResult: 'tesSUCCESS' } }); // well over 24h earlier

    const result = await page.evaluate(([txList, addr]) => window._debugIsThisNormal(txList, addr), [txList, ADDR]);
    assert(result.priorAuthChange === false, 'an auth change well outside the 24h window must not count');
    assert(result.verdict === 'normal', `expected verdict "normal" (auth change too old to be relevant), got "${result.verdict}"`);
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
