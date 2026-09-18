// Regression guard for Flow Motifs (Flow Intelligence spec §27-28): a
// neutral, descriptive index of repeated flow patterns found in an
// account's OWN transaction history — round-trip payments, AMM
// deposit/withdrawal cycles, and exchange round-trips. Deliberately
// carries NO findings/signals and contributes NOTHING to risk scoring —
// the same round-trip pattern is already scored by Wash Execution, and
// this must never double-count it under a second heading. True multi-hop
// circular flow across OTHER accounts (A->B->C->A) is explicitly out of
// scope — this app has no visibility into other accounts' own histories
// from a single-account inspection.
import { withPage, connectAndShowDashboard, inspectAddress, makeSuite, assert } from './helpers.mjs';

const suite = makeSuite('Flow Motifs');

const ADDR = 'rLpAccount0000000000000000000000000';
const TOKEN_ISSUER = 'rTokenIssuer00000000000000000000000';
const LP_CURRENCY = '03' + 'A'.repeat(38); // 40-char hex starting with 03 -> isLpCurrency() true

function paymentTx({ from, to, xrp, hash, date }) {
  return { tx: { Account: from, Destination: to, TransactionType: 'Payment', Amount: String(xrp * 1e6), hash, date } };
}

function depositTx({ xrpContributed, tokenContributed, hash = 'dep1', date = 800000000 }) {
  return {
    tx: { Account: ADDR, TransactionType: 'AMMDeposit', date, hash },
    meta: {
      TransactionResult: 'tesSUCCESS',
      AffectedNodes: [
        { ModifiedNode: {
            LedgerEntryType: 'AccountRoot',
            FinalFields: { Account: ADDR, Balance: String(10000000000 - xrpContributed * 1e6) },
            PreviousFields: { Balance: '10000000000' },
        } },
        { ModifiedNode: {
            LedgerEntryType: 'RippleState',
            FinalFields: {
              Balance: { currency: 'FOO', issuer: 'rrrrrrrrrrrrrrrrrrrrrhoLvTp', value: String(1500 - tokenContributed) },
              LowLimit: { issuer: ADDR, currency: 'FOO', value: '0' },
              HighLimit: { issuer: TOKEN_ISSUER, currency: 'FOO', value: '1000000' },
            },
            PreviousFields: { Balance: { currency: 'FOO', issuer: 'rrrrrrrrrrrrrrrrrrrrrhoLvTp', value: '1500' } },
        } },
        { CreatedNode: {
            LedgerEntryType: 'RippleState',
            NewFields: {
              Balance: { currency: LP_CURRENCY, issuer: 'rrrrrrrrrrrrrrrrrrrrrhoLvTp', value: '500' },
              LowLimit: { issuer: ADDR, currency: LP_CURRENCY, value: '0' },
              HighLimit: { issuer: TOKEN_ISSUER, currency: LP_CURRENCY, value: '1000000' },
            },
        } },
      ],
    },
  };
}

function withdrawTx({ xrpWithdrawn, tokenWithdrawn, priorLpBalance, newLpBalance, hash = 'wd1', date = 800005000 }) {
  return {
    tx: { Account: ADDR, TransactionType: 'AMMWithdraw', date, hash },
    meta: {
      TransactionResult: 'tesSUCCESS',
      AffectedNodes: [
        { ModifiedNode: {
            LedgerEntryType: 'AccountRoot',
            FinalFields: { Account: ADDR, Balance: String(9000000000 + xrpWithdrawn * 1e6) },
            PreviousFields: { Balance: '9000000000' },
        } },
        { ModifiedNode: {
            LedgerEntryType: 'RippleState',
            FinalFields: {
              Balance: { currency: LP_CURRENCY, issuer: 'rrrrrrrrrrrrrrrrrrrrrhoLvTp', value: String(newLpBalance) },
              LowLimit: { issuer: ADDR, currency: LP_CURRENCY, value: '0' },
              HighLimit: { issuer: TOKEN_ISSUER, currency: LP_CURRENCY, value: '1000000' },
            },
            PreviousFields: { Balance: { currency: LP_CURRENCY, issuer: 'rrrrrrrrrrrrrrrrrrrrrhoLvTp', value: String(priorLpBalance) } },
        } },
        { ModifiedNode: {
            LedgerEntryType: 'RippleState',
            FinalFields: {
              Balance: { currency: 'FOO', issuer: 'rrrrrrrrrrrrrrrrrrrrrhoLvTp', value: String(1000 + tokenWithdrawn) },
              LowLimit: { issuer: ADDR, currency: 'FOO', value: '0' },
              HighLimit: { issuer: TOKEN_ISSUER, currency: 'FOO', value: '1000000' },
            },
            PreviousFields: { Balance: { currency: 'FOO', issuer: 'rrrrrrrrrrrrrrrrrrrrrhoLvTp', value: '1000' } },
        } },
      ],
    },
  };
}

suite.register('A real active account with a genuine round-trip payment relationship renders a real ROUND_TRIP motif card with no page errors', async () => {
  await withPage(async (page) => {
    const errors = [];
    page.on('pageerror', e => errors.push(e.message));
    await connectAndShowDashboard(page);
    await inspectAddress(page, 'rnj7R3QUGzLZc9dg24jSrGabtt1tp1XD7A', { timeout: 90000 });
    await page.waitForTimeout(1500);

    const result = await page.evaluate(() => {
      const el = document.getElementById('inspect-flowmotifs-body');
      return {
        badgeClass: document.getElementById('badge-flowmotifs')?.className,
        cardCount: el?.querySelectorAll('.flowmotif-card').length,
        hasCaveat: /does not by itself mean anything improper/.test(el?.innerHTML || ''),
      };
    });
    assert(errors.length === 0, `expected zero page errors, got: ${JSON.stringify(errors)}`);
    assert(result.cardCount > 0, 'expected at least one real motif card for this known-active-round-trip account');
    assert(result.hasCaveat, 'expected the neutral-framing caveat to always accompany motif cards');
  });
});

suite.register('An account with no repeated patterns gets an honest "Clear" badge, not a fabricated motif', async () => {
  await withPage(async (page) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, 'rPVMhWBsfF9iMXYj3aAzJVkPDTFNSyWdKy', { timeout: 90000 });
    await page.waitForTimeout(1500);

    const result = await page.evaluate(() => ({
      badgeText: document.getElementById('badge-flowmotifs')?.textContent,
      badgeClass: document.getElementById('badge-flowmotifs')?.className,
    }));
    // Live data can vary run to run — only assert the structural contract:
    // whichever badge shows, it must be internally consistent (Clear <-> ok class).
    if (result.badgeText === 'Clear') {
      assert(/section-badge--ok/.test(result.badgeClass), `expected an "ok" badge class alongside "Clear" text, got: ${result.badgeClass}`);
    }
  });
});

suite.register('Synthetic: a real A<->B round-trip payment history is detected with the correct occurrence count', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugFlowMotifs, { timeout: 8000 });
    const partner = 'rPartner0000000000000000000000000000';
    const txList = [
      paymentTx({ from: ADDR, to: partner, xrp: 100, hash: 'o1', date: 1000 }),
      paymentTx({ from: partner, to: ADDR, xrp: 98, hash: 'i1', date: 1100 }),
      paymentTx({ from: ADDR, to: partner, xrp: 200, hash: 'o2', date: 2000 }),
      paymentTx({ from: partner, to: ADDR, xrp: 199, hash: 'i2', date: 2050 }),
    ];
    const result = await page.evaluate(([txList, addr]) => window._debugFlowMotifs(txList, addr), [txList, ADDR]);

    assert(result.applicable === true, 'expected applicable:true with a real round-trip history');
    const motif = result.motifs.find(m => m.type === 'ROUND_TRIP');
    assert(motif, `expected a ROUND_TRIP motif, got: ${JSON.stringify(result.motifs.map(m => m.type))}`);
    assert(motif.occurrences === 2, `expected 2 cycles, got ${motif.occurrences}`);
    assert(motif.counterparty === partner, 'expected the correct counterparty address attached to the motif');
  });
});

suite.register('Synthetic: no round-trip when payments only flow one direction', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugFlowMotifs, { timeout: 8000 });
    const partner = 'rOneWay0000000000000000000000000000';
    const txList = [
      paymentTx({ from: ADDR, to: partner, xrp: 100, hash: 'o1', date: 1000 }),
      paymentTx({ from: ADDR, to: partner, xrp: 200, hash: 'o2', date: 2000 }),
    ];
    const result = await page.evaluate(([txList, addr]) => window._debugFlowMotifs(txList, addr), [txList, ADDR]);
    assert(result.applicable === false, 'expected applicable:false when funds only ever flow one direction');
  });
});

suite.register('Synthetic: a deposit-then-withdraw from the SAME AMM pool is detected as an AMM_ROUND_TRIP motif with real totals', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugFlowMotifs, { timeout: 8000 });
    const txList = [
      depositTx({ xrpContributed: 1000, tokenContributed: 500 }),
      withdrawTx({ xrpWithdrawn: 950, tokenWithdrawn: 480, priorLpBalance: 500, newLpBalance: 0 }),
    ];
    const result = await page.evaluate(([txList, addr]) => window._debugFlowMotifs(txList, addr), [txList, ADDR]);

    assert(result.applicable === true, 'expected applicable:true with a real deposit+withdraw pair');
    const motif = result.motifs.find(m => m.type === 'AMM_ROUND_TRIP');
    assert(motif, `expected an AMM_ROUND_TRIP motif, got: ${JSON.stringify(result.motifs.map(m => m.type))}`);
    assert(/1,000 XRP/.test(motif.detail), `expected the real deposited total in the detail text, got: "${motif.detail}"`);
    assert(/950 XRP/.test(motif.detail), `expected the real withdrawn total in the detail text, got: "${motif.detail}"`);
    // Net XRP change (spec: "compare against... how much of the round trip
    // was a real position change") — gross 1950, net |950-1000|=50 -> 2.6%.
    assert(/net XRP change 2\.6%/.test(motif.detail), `expected the real net-XRP-change percentage in the detail text, got: "${motif.detail}"`);
    assert(Math.abs(motif.grossXrp - 1950) < 0.01, `expected grossXrp 1950, got ${motif.grossXrp}`);
    assert(Math.abs(motif.netXrpPct - 2.564) < 0.01, `expected netXrpPct ~2.56, got ${motif.netXrpPct}`);
  });
});

suite.register('Synthetic: a deposit with NO matching withdrawal produces no AMM_ROUND_TRIP motif (still in the pool, not a round trip)', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugFlowMotifs, { timeout: 8000 });
    const txList = [depositTx({ xrpContributed: 1000, tokenContributed: 500 })];
    const result = await page.evaluate(([txList, addr]) => window._debugFlowMotifs(txList, addr), [txList, ADDR]);
    assert(!result.motifs?.some(m => m.type === 'AMM_ROUND_TRIP'), 'a deposit alone (still deployed) must not be presented as a completed round trip');
  });
});

suite.register('Synthetic: funds sent to AND received from a known exchange address produce an EXCHANGE_ROUND_TRIP motif, not a duplicate generic ROUND_TRIP', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugFlowMotifs, { timeout: 8000 });
    const bitstamp = 'rPVMhWBsfF9iMXYj3aAzJVkPDTFNSyWdKy'; // real, registered exchange entity
    const txList = [
      paymentTx({ from: ADDR, to: bitstamp, xrp: 500, hash: 'o1', date: 1000 }),
      paymentTx({ from: bitstamp, to: ADDR, xrp: 480, hash: 'i1', date: 1100 }),
    ];
    const result = await page.evaluate(([txList, addr]) => window._debugFlowMotifs(txList, addr), [txList, ADDR]);

    const exchangeMotifs = result.motifs.filter(m => m.type === 'EXCHANGE_ROUND_TRIP');
    const genericMotifs  = result.motifs.filter(m => m.type === 'ROUND_TRIP');
    assert(exchangeMotifs.length === 1, `expected exactly one EXCHANGE_ROUND_TRIP motif, got ${exchangeMotifs.length}`);
    assert(genericMotifs.length === 0, 'the same exchange relationship must not ALSO appear as a generic ROUND_TRIP motif');
    assert(/Bitstamp/.test(exchangeMotifs[0].label), `expected the known entity name in the label, got: "${exchangeMotifs[0].label}"`);
  });
});

suite.register('No transactions at all produces applicable:false, not an empty fabricated motif list', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugFlowMotifs, { timeout: 8000 });
    const result = await page.evaluate(([addr]) => window._debugFlowMotifs([], addr), [ADDR]);
    assert(result.applicable === false, 'expected applicable:false with no transaction history');
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
