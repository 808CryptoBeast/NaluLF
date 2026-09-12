// Regression guard for the counterparty-volume fix: the old
// _buildCounterpartyData only discovered counterparties via tx.Account /
// tx.Destination and only tracked XRP delivered as a plain drops string —
// so ANY token-denominated Payment showed as "0 XRP" moved, and ANY
// OfferCreate/AMM interaction (no Destination field, tx.Account often a
// third party) was invisible entirely. For a token issuer specifically,
// that hid the vast majority of real interactions. The fix reuses
// extractBalanceDeltas (the Balance Change Engine already trusted
// elsewhere in this file) so tokenDeltas'/lpDeltas' real counterparty
// account is discovered regardless of tx shape, and tracks real token
// volume instead of silently zeroing it.
import { withPage, connectAndShowDashboard, inspectAddress, makeSuite, assert } from './helpers.mjs';

// SOLO issuer, not CULT — spreads live-RPC load across more than one real
// account so a single account's rate-limiting can't take out many test
// files in the same run (CULT alone backed 9 different test files).
const REAL_ACTIVE_ISSUER = 'rsoLo2S1kiGeCcn6hCUXVrCpGMWLrRrLZz';

const suite = makeSuite('Counterparty Volume Attribution');

suite.register('A real token issuer discovers far more real counterparties than Account/Destination alone would, with real token volume shown (not "0 XRP")', async () => {
  await withPage(async (page) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, REAL_ACTIVE_ISSUER, { timeout: 90000 });
    await page.waitForTimeout(4000); // this account has a large fetched history; give it room to settle

    const result = await page.evaluate(() => {
      const el = document.getElementById('inspect-top-counterparties');
      const rows = [...(el?.querySelectorAll('.ranked-cp-row') || [])].map(r => r.textContent.replace(/\s+/g, ' ').trim());
      const headerMatch = el?.innerHTML?.match(/of (\d+) addresses/);
      return { rows, totalCounterparties: headerMatch ? Number(headerMatch[1]) : 0 };
    });

    assert(result.totalCounterparties > 50, `expected well over 50 real counterparties for this high-volume issuer (the old Account/Destination-only logic found only ~15) — got ${result.totalCounterparties}`);
    assert(result.rows.length > 0, 'expected at least one ranked row');
    assert(result.rows.some(r => /SOLO/.test(r)), 'expected at least one row showing real SOLO token volume');
    assert(!result.rows.some(r => /\b0 XRP\b/.test(r)), 'no row should show the old misleading "0 XRP" — a token-only relationship must show its real token volume or an explicit "no direct value moved", never a bare zero XRP');
  });
});

suite.register('An OfferCreate-only relationship (no Payment, no Destination field) is discovered as a real counterparty via the trustline delta, invisible to the old Account/Destination check', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugBuildCounterpartyData, { timeout: 8000 });
    const result = await page.evaluate(() => {
      const issuer = 'rIssuer00000000000000000000000000';
      const traderA = 'rTraderA0000000000000000000000000';
      const currency = '464F4F00000000000000000000000000000000'; // hex "FOO"

      // A trade between traderA and some OTHER holder, crossing on the
      // order book. tx.Account is traderA (not the issuer), and there is
      // no Destination field at all — the old code would skip this
      // transaction entirely for the issuer's counterparty map.
      const txList = [{
        tx: { Account: traderA, TransactionType: 'OfferCreate', Sequence: 5, date: 800000000, hash: 'h1' },
        meta: {
          TransactionResult: 'tesSUCCESS',
          AffectedNodes: [{
            ModifiedNode: {
              LedgerEntryType: 'RippleState',
              FinalFields: {
                Balance: { currency, issuer: 'rrrrrrrrrrrrrrrrrrrrrrrrrrrrrqLQg', value: '-500' },
                LowLimit: { issuer, currency, value: '0' },
                HighLimit: { issuer: traderA, currency, value: '1000000' },
              },
              PreviousFields: { Balance: { currency, issuer: 'rrrrrrrrrrrrrrrrrrrrrrrrrrrrrqLQg', value: '-300' } },
            },
          }],
        },
      }];

      return window._debugBuildCounterpartyData(txList, issuer);
    });

    assert(result.length === 1, `expected traderA to be discovered as a real counterparty purely from the trustline delta, got ${result.length} counterpart(ies)`);
    const [cpAddr, d] = result[0];
    assert(cpAddr === 'rTraderA0000000000000000000000000', `expected the discovered counterparty to be traderA, got ${cpAddr}`);
    assert(d.cnt === 1, `expected 1 interaction counted, got ${d.cnt}`);
    assert(Object.keys(d.tokenVolume).length === 1, 'expected exactly one token-volume entry');
    const vol = Object.values(d.tokenVolume)[0];
    assert(Math.abs(vol - 200) < 0.01, `expected 200 units of real token volume (500-300), got ${vol}`);
  });
});

suite.register('A simple XRP Payment still computes correct direction and volume (no regression for the common case)', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugBuildCounterpartyData, { timeout: 8000 });
    const result = await page.evaluate(() => {
      const addr = 'rMyAccount000000000000000000000000';
      const cp = 'rCounterparty00000000000000000000';
      const txList = [{
        tx: { Account: addr, Destination: cp, TransactionType: 'Payment', Amount: '25000000', date: 800000000, hash: 'h1' },
        meta: { TransactionResult: 'tesSUCCESS', delivered_amount: '25000000', AffectedNodes: [
          { ModifiedNode: { LedgerEntryType: 'AccountRoot', FinalFields: { Account: addr, Balance: '75000000' }, PreviousFields: { Balance: '100000000' } } },
          { ModifiedNode: { LedgerEntryType: 'AccountRoot', FinalFields: { Account: cp, Balance: '25000000' }, PreviousFields: { Balance: '0' } } },
        ] },
      }];
      const data = window._debugBuildCounterpartyData(txList, addr);
      const [, d] = data[0];
      return { cnt: d.cnt, xrpOut: d.xrpOut, xrpIn: d.xrpIn, volume: window._debugCpVolume(d) };
    });
    assert(result.cnt === 1, `expected 1 interaction, got ${result.cnt}`);
    assert(Math.abs(result.xrpOut - 25) < 0.01, `expected 25 XRP outbound, got ${result.xrpOut}`);
    assert(result.xrpIn === 0, `expected 0 XRP inbound, got ${result.xrpIn}`);
    assert(result.volume.display === '25 XRP', `expected the display volume to read "25 XRP", got "${result.volume.display}"`);
  });
});

suite.register('A transaction touching multiple counterparties at once does not double-count the XRP delta against each one', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugBuildCounterpartyData, { timeout: 8000 });
    const result = await page.evaluate(() => {
      const addr = 'rMultiParty0000000000000000000000';
      const cpA = 'rPartyA00000000000000000000000000';
      const cpB = 'rPartyB00000000000000000000000000';
      const currency = 'USD';
      // A single cross-currency payment where addr's own XRP balance drops
      // by 10 AND two different trustline counterparties' balances move —
      // the XRP delta must not be attributed in full to BOTH cpA and cpB.
      const txList = [{
        tx: { Account: addr, Destination: cpA, TransactionType: 'Payment', Amount: { currency, issuer: cpA, value: '50' }, date: 800000000, hash: 'h1' },
        meta: {
          TransactionResult: 'tesSUCCESS',
          AffectedNodes: [
            { ModifiedNode: { LedgerEntryType: 'AccountRoot', FinalFields: { Account: addr, Balance: '90000000' }, PreviousFields: { Balance: '100000000' } } },
            { ModifiedNode: { LedgerEntryType: 'RippleState', FinalFields: { Balance: { currency, issuer: 'rrrrrrrrrrrrrrrrrrrrrrrrrrrrrqLQg', value: '50' }, LowLimit: { issuer: addr, currency, value: '0' }, HighLimit: { issuer: cpA, currency, value: '1000' } }, PreviousFields: { Balance: { currency, issuer: 'rrrrrrrrrrrrrrrrrrrrrrrrrrrrrqLQg', value: '0' } } } },
            { ModifiedNode: { LedgerEntryType: 'RippleState', FinalFields: { Balance: { currency, issuer: 'rrrrrrrrrrrrrrrrrrrrrrrrrrrrrqLQg', value: '-50' }, LowLimit: { issuer: cpB, currency, value: '0' }, HighLimit: { issuer: addr, currency, value: '1000' } }, PreviousFields: { Balance: { currency, issuer: 'rrrrrrrrrrrrrrrrrrrrrrrrrrrrrqLQg', value: '0' } } } },
          ],
        },
      }];
      const data = window._debugBuildCounterpartyData(txList, addr);
      return Object.fromEntries(data.map(([cp, d]) => [cp, { xrpOut: d.xrpOut, xrpIn: d.xrpIn }]));
    });
    assert(result['rPartyA00000000000000000000000000'], 'expected party A to be discovered');
    assert(result['rPartyB00000000000000000000000000'], 'expected party B to be discovered');
    const totalXrpOut = result['rPartyA00000000000000000000000000'].xrpOut + result['rPartyB00000000000000000000000000'].xrpOut;
    assert(totalXrpOut <= 10.01, `the 10 XRP delta must not be double-counted across both counterparties (2x10=20 would be the bug) — got total ${totalXrpOut}`);
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
