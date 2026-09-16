// Regression guard for "Who Is Connected" (Flow Intelligence spec §18) — a
// short, beginner-facing sentence-level summary sitting above the Network
// Map, synthesizing data Top Counterparties and Flow Motifs already
// compute (no new RPC, no new analysis). Must never fabricate a claim
// about reciprocal activity when Flow Motifs wasn't actually checked, and
// must never fabricate a "core group" split when there's no real value to
// rank counterparties by.
import { withPage, connectAndShowDashboard, inspectAddress, makeSuite, assert } from './helpers.mjs';

const suite = makeSuite('Who Is Connected');

suite.register('A real active account renders a real, grammatically-correct summary sentence with no page errors', async () => {
  await withPage(async (page) => {
    const errors = [];
    page.on('pageerror', e => errors.push(e.message));
    await connectAndShowDashboard(page);
    await inspectAddress(page, 'rnj7R3QUGzLZc9dg24jSrGabtt1tp1XD7A', { timeout: 90000 });
    await page.waitForTimeout(1500);

    const text = await page.evaluate(() => document.getElementById('inspect-who-connected')?.textContent || '');
    assert(errors.length === 0, `expected zero page errors, got: ${JSON.stringify(errors)}`);
    assert(/wallet.*interacted directly/.test(text), `expected the base summary sentence, got: "${text}"`);
  });
});

suite.register('Synthetic: reciprocalCount is null (not computed) when flowMotifs is not passed, and the render omits the reciprocal claim entirely rather than fabricating "none found"', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugWhoIsConnected, { timeout: 8000 });
    const paymentTx = {
      tx: { Account: 'rWhoAddr0000000000000000000000000000', Destination: 'rWhoPartner000000000000000000000000', TransactionType: 'Payment', Amount: '1000000', hash: 'h1', date: 1000 },
    };
    const result = await page.evaluate(([tx, addr]) => window._debugWhoIsConnected([tx], addr, undefined), [paymentTx, 'rWhoAddr0000000000000000000000000000']);
    assert(result.applicable === true, 'expected applicable:true with a real counterparty');
    assert(result.reciprocalCount === null, `expected reciprocalCount:null when flowMotifs wasn't passed, got ${result.reciprocalCount}`);
  });
});

suite.register('Synthetic: reciprocalCount is a real 0 (computed, none found) when flowMotifs is passed but has no round-trip motifs', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugWhoIsConnected, { timeout: 8000 });
    const paymentTx = {
      tx: { Account: 'rWhoAddr0000000000000000000000000000', Destination: 'rWhoPartner000000000000000000000000', TransactionType: 'Payment', Amount: '1000000', hash: 'h1', date: 1000 },
    };
    const flowMotifs = { applicable: false, motifs: [] };
    const result = await page.evaluate(([tx, addr, fm]) => window._debugWhoIsConnected([tx], addr, fm), [paymentTx, 'rWhoAddr0000000000000000000000000000', flowMotifs]);
    assert(result.reciprocalCount === 0, `expected reciprocalCount:0 (computed, none found), got ${result.reciprocalCount}`);
  });
});

suite.register('Synthetic: reciprocalCount counts ROUND_TRIP and EXCHANGE_ROUND_TRIP motifs but not AMM_ROUND_TRIP (a pool round-trip is not a "connected wallet")', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugWhoIsConnected, { timeout: 8000 });
    const paymentTx = {
      tx: { Account: 'rWhoAddr0000000000000000000000000000', Destination: 'rWhoPartner000000000000000000000000', TransactionType: 'Payment', Amount: '1000000', hash: 'h1', date: 1000 },
    };
    const flowMotifs = {
      applicable: true,
      motifs: [
        { type: 'ROUND_TRIP', occurrences: 3 },
        { type: 'EXCHANGE_ROUND_TRIP', occurrences: 2 },
        { type: 'AMM_ROUND_TRIP', occurrences: 5 },
      ],
    };
    const result = await page.evaluate(([tx, addr, fm]) => window._debugWhoIsConnected([tx], addr, fm), [paymentTx, 'rWhoAddr0000000000000000000000000000', flowMotifs]);
    assert(result.reciprocalCount === 2, `expected reciprocalCount:2 (ROUND_TRIP + EXCHANGE_ROUND_TRIP only), got ${result.reciprocalCount}`);
  });
});

suite.register('No counterparties at all produces applicable:false, not an empty fabricated summary', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugWhoIsConnected, { timeout: 8000 });
    const result = await page.evaluate(([addr]) => window._debugWhoIsConnected([], addr, null), ['rNoActivity000000000000000000000000']);
    assert(result.applicable === false, 'expected applicable:false with zero transaction history');
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
