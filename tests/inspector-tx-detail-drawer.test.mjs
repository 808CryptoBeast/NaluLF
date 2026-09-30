// Regression coverage for the Transaction History upgrade: removing the
// flat 60-row display cap in favor of real "Load more" pagination, adding
// Type/Direction filters, and a real Transaction Detail Drawer (Summary /
// Balance Changes / Raw JSON tabs) reached by clicking any row's 🔬 icon —
// previously a transaction row was a dead-end one-liner with only two
// external links out to third-party explorers.
import { withPage, connectAndShowDashboard, inspectAddress, makeSuite, assert } from './helpers.mjs';

const suite = makeSuite('Transaction History — Filters, Pagination & Detail Drawer');

// Bitstamp hot wallet — thousands of real transactions across many types
// (Payment/TrustSet/OfferCreate/AMMWithdraw/etc), used elsewhere this
// session as a reliable high-volume live fixture.
const HIGH_VOLUME_ACCOUNT = 'rPVMhWBsfF9iMXYj3aAzJVkPDTFNSyWdKy';

suite.register('Live: the timeline is no longer capped at a flat 60 rows — Load More reveals real additional transactions, and a Type filter narrows the list correctly', async () => {
  await withPage(async (page, { pageErrors }) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, HIGH_VOLUME_ACCOUNT, { timeout: 90000 });
    await page.waitForTimeout(1000);
    await page.evaluate(() => window.toggleAnalystMode());
    await page.waitForTimeout(300);

    const initial = await page.evaluate(() => {
      const el = document.getElementById('inspect-tx-timeline');
      return {
        hasFilterBar: !!document.getElementById('tx-filter-type'),
        rowCount: el.querySelectorAll('.tx-row').length,
        loadMoreText: el.querySelector('.tx-more')?.textContent || '',
      };
    });
    assert(initial.hasFilterBar, 'expected the Type/Direction filter bar to render in Advanced mode');
    assert(initial.rowCount === 60, `expected the first page to show exactly 60 rows, got ${initial.rowCount}`);
    assert(/Load more/.test(initial.loadMoreText), `expected a "Load more" control for an account with >60 transactions, got: "${initial.loadMoreText}"`);

    await page.evaluate(() => document.querySelector('.tx-more')?.click());
    await page.waitForTimeout(300);
    const afterLoadMore = await page.evaluate(() => document.querySelectorAll('#inspect-tx-timeline .tx-row').length);
    assert(afterLoadMore === 120, `expected Load More to reveal 60 additional rows (120 total), got ${afterLoadMore}`);

    await page.evaluate(() => {
      const sel = document.getElementById('tx-filter-type');
      sel.value = 'TrustSet';
      sel.dispatchEvent(new Event('change'));
    });
    await page.waitForTimeout(300);
    const filtered = await page.evaluate(() => {
      const rows = [...document.querySelectorAll('#inspect-tx-timeline .tx-row')];
      return { count: rows.length, allTrustSet: rows.every(r => r.querySelector('.tx-type-badge')?.textContent === 'TrustSet') };
    });
    assert(filtered.count > 0, 'expected at least one TrustSet transaction for this known-active account');
    assert(filtered.allTrustSet, 'expected the Type filter to show ONLY TrustSet rows, not a mix');

    // Filtering must reset pagination back to page 1 — the earlier "showing
    // 120 of 5200" state should not silently leak into a freshly-filtered,
    // much smaller result set.
    assert(filtered.count <= 60, `expected the filtered view to reset to a single page (<=60 rows), got ${filtered.count}`);

    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

suite.register('Live: the Transaction Detail Drawer opens from a real row and renders real Summary, Balance Changes, and Raw JSON content, with no page errors', async () => {
  await withPage(async (page, { pageErrors }) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, HIGH_VOLUME_ACCOUNT, { timeout: 90000 });
    await page.waitForTimeout(1000);
    await page.evaluate(() => window.toggleAnalystMode());
    await page.waitForTimeout(300);

    const summary = await page.evaluate(() => {
      const btn = document.querySelector('#inspect-tx-timeline .tx-row .tx-links a[title="Inspect this transaction"]');
      if (!btn) return { found: false };
      btn.click();
      return {
        found: true,
        overlayVisible: getComputedStyle(document.getElementById('txDetailOverlay')).display === 'flex',
        hasHash: (document.getElementById('txDetailHash')?.textContent || '').length > 10,
        body: document.getElementById('txDetailBody')?.innerHTML || '',
      };
    });
    assert(summary.found, 'expected at least one real transaction row with an Inspect trigger');
    assert(summary.overlayVisible, 'expected the Transaction Detail Drawer to actually open');
    assert(summary.hasHash, 'expected a real transaction hash to display in the drawer header');
    assert(summary.body.includes('Result'), 'expected the Summary tab to show the Result field');
    assert(summary.body.includes('Ledger'), 'expected the Summary tab to show the Ledger index');

    const balance = await page.evaluate(() => {
      window.switchTxDetailTab('balance');
      return document.getElementById('txDetailBody')?.innerHTML || '';
    });
    assert(balance.length > 0, 'expected the Balance Changes tab to render something (either real deltas or an honest empty-state)');

    const raw = await page.evaluate(() => {
      window.switchTxDetailTab('raw');
      return document.getElementById('txDetailBody')?.innerHTML || '';
    });
    assert(raw.includes('TransactionType'), 'expected the Raw JSON tab to show the actual transaction JSON');
    assert(raw.includes('Metadata'), 'expected the Raw JSON tab to also show the metadata section');

    assert(pageErrors.length === 0, `expected zero page errors across all 3 tabs, got: ${JSON.stringify(pageErrors)}`);
  });
});

suite.register('Regression: Balance Changes correctly reads extractBalanceDeltas\' real return shape (tokenDeltas/lpDeltas arrays, not the internal Maps it deletes before returning)', async () => {
  await withPage(async (page, { pageErrors }) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, HIGH_VOLUME_ACCOUNT, { timeout: 90000 });
    await page.waitForTimeout(1000);

    // A synthetic Payment with a real RippleState-affecting metadata shape —
    // exercises the exact code path that previously crashed with
    // "Cannot read properties of undefined (reading 'values')" because the
    // drawer read .tokenDeltaMap/.lpDeltaMap, which extractBalanceDeltas
    // deletes (replacing them with plain .tokenDeltas/.lpDeltas arrays)
    // on every path except its early "no AffectedNodes" return.
    const result = await page.evaluate(() => {
      const addr = 'rInspectedAccount0000000000000000000';
      const partner = 'rPartnerAccount00000000000000000000';
      const issuer = 'rIssuerXXXXXXXXXXXXXXXXXXXXXXXXXXX';
      const tx = {
        hash: 'DEADBEEF00000000000000000000000000000000000000000000000000AA',
        TransactionType: 'Payment', Account: partner, Destination: addr,
        Amount: { currency: 'USD', issuer, value: '100' }, Fee: '12', Sequence: 1, date: 800000000,
      };
      const meta = {
        TransactionResult: 'tesSUCCESS',
        AffectedNodes: [{
          ModifiedNode: {
            LedgerEntryType: 'RippleState',
            FinalFields: { Balance: { currency: 'USD', issuer: 'rrrrrrrrrrrrrrrrrrrrBZbvji', value: '-100' }, LowLimit: { issuer: addr, value: '0' }, HighLimit: { issuer, value: '0' } },
            PreviousFields: { Balance: { currency: 'USD', issuer: 'rrrrrrrrrrrrrrrrrrrrBZbvji', value: '0' } },
          },
        }],
      };
      window._lastTxList = [{ tx, meta }];
      window._lastInspectResult = { addr };
      let threw = false, message = '';
      try {
        window.openTxDetailDrawer(tx.hash);
        window.switchTxDetailTab('balance');
      } catch (e) { threw = true; message = e.message; }
      return { threw, message, body: document.getElementById('txDetailBody')?.innerHTML || '' };
    });
    assert(!result.threw, `expected Balance Changes to render without throwing, got: ${result.message}`);
    assert(result.body.includes('USD'), `expected the real USD delta to appear in Balance Changes, got: ${result.body.slice(0, 200)}`);
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
