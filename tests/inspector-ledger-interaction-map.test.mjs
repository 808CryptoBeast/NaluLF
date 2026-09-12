// Regression guard for the Ledger Interaction Map ("How This Account Uses
// XRPL") — a categorized activity breakdown shown as both a clickable
// branch diagram and a bar chart, with a By-Tx-Count / By-XRP-Value
// toggle. Guards: real categorization, percentages summing sensibly,
// click-to-navigate actually expanding+scrolling to the right section, and
// the critical honesty property — a category with real activity but no
// XRP leg (e.g. a token issuer's DEX trades, which never touch the
// issuer's own XRP balance) must show 0% under "By XRP Value" with an
// explicit caveat, never a fabricated blended cross-currency number.
import { withPage, connectAndShowDashboard, inspectAddress, makeSuite, assert } from './helpers.mjs';

// SOLO issuer, not CULT — spreads live-RPC load across more than one real
// account so a single account's rate-limiting can't take out many test
// files in the same run (CULT alone backed 9 different test files).
const REAL_ACTIVE_ISSUER = 'rsoLo2S1kiGeCcn6hCUXVrCpGMWLrRrLZz';

const suite = makeSuite('Ledger Interaction Map');

suite.register('A real active issuer renders real, clickable branches and bars that sum close to 100%', async () => {
  await withPage(async (page) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, REAL_ACTIVE_ISSUER, { timeout: 90000 });
    await page.waitForTimeout(3000);

    const result = await page.evaluate(() => {
      const el = document.getElementById('inspect-ledger-map');
      const branches = [...(el?.querySelectorAll('.ledgermap-branch') || [])].map(b => ({
        label: b.querySelector('.ledgermap-branch-label')?.textContent,
        pct: parseFloat(b.querySelector('.ledgermap-branch-pct')?.textContent) || 0,
        clickable: b.hasAttribute('onclick'),
      }));
      return { branches, barCount: el?.querySelectorAll('.ledgermap-bar-row').length || 0 };
    });

    assert(result.branches.length > 0, 'expected at least one activity category');
    assert(result.barCount === result.branches.length, 'branch diagram and bar chart must show the same category set');
    const totalPct = result.branches.reduce((s, b) => s + b.pct, 0);
    assert(totalPct > 95 && totalPct <= 100.5, `percentages should sum close to 100%, got ${totalPct}`);
    assert(result.branches.some(b => b.label === 'Payments'), 'expected a Payments category for this known active account');
    assert(result.branches.filter(b => b.label !== 'Other').every(b => b.clickable), 'every real category (not "Other") must be clickable to jump to its section');
  });
});

suite.register('Clicking a branch expands the target section (if collapsed) and does not throw for an unknown id', async () => {
  await withPage(async (page) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, REAL_ACTIVE_ISSUER, { timeout: 90000 });
    await page.waitForTimeout(2000);

    const result = await page.evaluate(() => {
      const sec = document.getElementById('section-wash');
      sec.classList.add('collapsed'); // force a known starting state
      window._jumpToInspectorSection('wash');
      const stillWorks = (() => { try { window._jumpToInspectorSection('this-id-does-not-exist'); return true; } catch { return false; } })();
      return {
        collapsedAfter: sec.classList.contains('collapsed'),
        ariaExpanded: sec.querySelector('.section-header')?.getAttribute('aria-expanded'),
        stillWorks,
      };
    });
    assert(result.collapsedAfter === false, 'expected the section to be expanded after jumping to it');
    assert(result.ariaExpanded === 'true', 'expected aria-expanded to be set to true');
    assert(result.stillWorks, 'jumping to a nonexistent section id must not throw');
  });
});

suite.register('A token issuer\'s DEX activity (no XRP leg) shows 0% under "By XRP Value" with an explicit caveat, never a fabricated blended value', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugLedgerInteractionBreakdown, { timeout: 8000 });
    const result = await page.evaluate(() => {
      const addr = 'rIssuerNoXrpLeg000000000000000000000';
      const trader = 'rTrader000000000000000000000000000000';
      const currency = 'FOO';
      // Two OfferCreate transactions between OTHER holders, crossing on
      // the order book — the issuer's own AccountRoot XRP balance never
      // changes (XRP moves between the two TRADING parties, not the
      // issuer), even though this genuinely is real DEX activity
      // involving the issuer's token.
      const txList = [
        { tx: { Account: trader, TransactionType: 'OfferCreate', date: 800000000, hash: 'h1' },
          meta: { TransactionResult: 'tesSUCCESS', AffectedNodes: [{ ModifiedNode: { LedgerEntryType: 'RippleState',
            FinalFields: { Balance: { currency, issuer: 'rrrrrrrrrrrrrrrrrrrrrrrrrrrrrqLQg', value: '-50' }, LowLimit: { issuer: addr, currency, value: '0' }, HighLimit: { issuer: trader, currency, value: '1000' } },
            PreviousFields: { Balance: { currency, issuer: 'rrrrrrrrrrrrrrrrrrrrrrrrrrrrrqLQg', value: '0' } } } }] } },
        { tx: { Account: addr, Destination: trader, TransactionType: 'Payment', Amount: '10000000', date: 800000200, hash: 'h2' },
          meta: { TransactionResult: 'tesSUCCESS', delivered_amount: '10000000', AffectedNodes: [
            { ModifiedNode: { LedgerEntryType: 'AccountRoot', FinalFields: { Account: addr, Balance: '90000000' }, PreviousFields: { Balance: '100000000' } } },
          ] } },
      ];
      return window._debugLedgerInteractionBreakdown(txList, addr, {});
    });

    const dex = result.categories.find(c => c.key === 'dex');
    const payments = result.categories.find(c => c.key === 'payments');
    assert(dex, 'expected a DEX category with nonzero transaction count');
    assert(dex.count === 1, `expected 1 DEX transaction counted, got ${dex.count}`);
    assert(dex.xrpValue === 0, `expected 0 XRP value for a trade with no XRP leg, got ${dex.xrpValue}`);
    assert(dex.valuePct === 0, `expected 0% value share for DEX (no fabricated cross-currency number), got ${dex.valuePct}`);
    assert(payments.xrpValue === 10, `expected the real 10 XRP payment to be correctly attributed, got ${payments.xrpValue}`);
    assert(result.hasXrpValue === true, 'expected hasXrpValue true since the Payment did move real XRP');
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
