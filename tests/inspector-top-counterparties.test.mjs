// Regression guard for "Top Counterparties" in Account Overview — answers
// "what accounts does this address interact with most" without scrolling to
// the Full Report section. Reuses buildRankedCounterpartyList's existing
// data/logic (no new computation); this suite guards the NEW parts: the
// Account Overview mount point, and click-to-inspect on each row (the report
// version never had this — rows were previously inert).
import { withPage, connectAndShowDashboard, inspectAddress, makeSuite, assert } from './helpers.mjs';

const REAL_ACTIVE_ISSUER = 'rCULtAKrKbQjk1Tpmg5hkw4dpcf9S9KCs';

const suite = makeSuite('Account Overview — Top Counterparties');

suite.register('A real active account renders ranked, clickable counterparty rows directly in Account Overview', async () => {
  await withPage(async (page) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, REAL_ACTIVE_ISSUER, { timeout: 90000 });
    await page.waitForTimeout(1500);

    const result = await page.evaluate(() => {
      const el = document.getElementById('inspect-top-counterparties');
      const rows = [...(el?.querySelectorAll('.ranked-cp-row') || [])];
      return {
        headerPresent: /Top Counterparties/.test(el?.innerHTML || ''),
        rowCount: rows.length,
        allRowsClickable: rows.every(r => /^inspectorLoadAddr\('r/.test(r.getAttribute('onclick') || '')),
        cappedAtTen: rows.length <= 10,
      };
    });
    assert(result.headerPresent, 'expected the "Top Counterparties" header to render in Account Overview');
    assert(result.rowCount > 0, 'expected at least one counterparty row for a real active account');
    assert(result.allRowsClickable, 'every row must have a real inspectorLoadAddr(...) click handler — this is the new part report-view rows never had');
    assert(result.cappedAtTen, `Account Overview's at-a-glance list must cap at 10 rows, got ${result.rowCount}`);
  });
});

suite.register('An account with zero counterparties renders an explicit empty state, not a blank/broken block', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugBuildRankedCounterpartyList, { timeout: 8000 });
    const html = await page.evaluate(() => window._debugBuildRankedCounterpartyList([], 'rSomeAddressWithNoHistory000000000'));
    assert(/No counterparty interactions found/.test(html), `expected an explicit empty-state message, got: ${html}`);
  });
});

suite.register('Rows are ranked by volume descending and each carries a real click-to-inspect handler for its own address', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugBuildRankedCounterpartyList, { timeout: 8000 });
    const result = await page.evaluate(() => {
      const addr = 'rInspectedAddr00000000000000000000';
      const cpA = 'rCounterpartyAAAAAAAAAAAAAAAAAAAAA1';
      const cpB = 'rCounterpartyBBBBBBBBBBBBBBBBBBBBB2';
      const txList = [
        { tx: { Account: addr, Destination: cpA, Amount: '5000000000', TransactionType: 'Payment', date: 800000000, hash: 'h1' }, meta: { delivered_amount: '5000000000' } }, // 5000 XRP to A
        { tx: { Account: cpB, Destination: addr, Amount: '100000000', TransactionType: 'Payment', date: 800000100, hash: 'h2' }, meta: { delivered_amount: '100000000' } }, // 100 XRP from B
      ];
      const html = window._debugBuildRankedCounterpartyList(txList, addr);
      const scratch = document.createElement('div');
      scratch.innerHTML = html;
      const rows = [...scratch.querySelectorAll('.ranked-cp-row')];
      return { count: rows.length, firstOnclick: rows[0]?.getAttribute('onclick'), secondOnclick: rows[1]?.getAttribute('onclick') };
    });
    assert(result.count === 2, `expected 2 ranked counterparties, got ${result.count}`);
    assert(result.firstOnclick === "inspectorLoadAddr('rCounterpartyAAAAAAAAAAAAAAAAAAAAA1')", `expected the higher-volume counterparty (A, 5000 XRP) ranked first, got: ${result.firstOnclick}`);
    assert(result.secondOnclick === "inspectorLoadAddr('rCounterpartyBBBBBBBBBBBBBBBBBBBBB2')", `expected the lower-volume counterparty (B, 100 XRP) ranked second, got: ${result.secondOnclick}`);
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
