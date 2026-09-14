// Regression guard for AMM current-vs-historical LP precision (deferred
// forensic-depth item from the codebase audit spec). tvl/tvl2/ownerPct
// are always a CURRENT snapshot from amm_info; presenting them without
// qualification silently assumes the pool's XRP:token ratio hasn't moved
// since this account deposited. This compares the pool's CURRENT ratio
// against the ratio implied by the account's OWN two-asset deposit
// event(s) — a real, dimensionless fact needing no price feed for either
// leg — and flags a meaningful shift instead of letting a single
// current-snapshot number stand in for the position's whole history
// unqualified. Also adds a genuinely new, honestly-computable stat
// (current XRP-side value = tvl * ownerPct) that was previously missing
// entirely, carefully scoped to the XRP leg only — never combined with
// the token leg into a claimed total value, which would need a price
// feed this app doesn't have.
import { withPage, connectAndShowDashboard, inspectAddress, makeSuite, assert } from './helpers.mjs';

const suite = makeSuite('AMM Composition Shift — Current vs Historical LP Precision');

const ADDR = 'rLpAccount0000000000000000000000000';
const TOKEN_ISSUER = 'rTokenIssuer00000000000000000000000';
const LP_CURRENCY = '03' + 'A'.repeat(38); // 40-char hex starting with 03 -> isLpCurrency() true

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

function lines() {
  return [{ account: TOKEN_ISSUER, currency: LP_CURRENCY, balance: '500', limit: '1000000000' }];
}
function ammInfoMap({ xrp, token, fee = 500, lpSupply = 1000 }) {
  return new Map([[LP_CURRENCY, { amount: String(xrp * 1e6), amount2: { value: String(token) }, trading_fee: fee, lp_token: { value: String(lpSupply) } }]]);
}

suite.register('A pool whose ratio has shifted 300% since deposit (1 XRP/token -> 4 XRP/token) fires a composition-shift finding with the real before/after ratios', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugAmmPositions, { timeout: 8000 });
    const tx = depositTx({ xrpContributed: 1000, tokenContributed: 1000 }); // deposit ratio 1.0
    const result = await page.evaluate(([tx, lines, ammMap]) =>
      window._debugAmmPositions(lines, [tx], [], new Map(ammMap), 'rLpAccount0000000000000000000000000'),
      [tx, lines(), [...ammInfoMap({ xrp: 2000, token: 500 })]] // current ratio 4.0
    );
    const p = result.positions[0];
    assert(p, 'expected one LP position');
    assert(Math.abs(p.compositionShiftPct - 300) < 0.01, `expected a 300% shift, got ${p.compositionShiftPct}`);
    assert(p.currentXrpSideValue === 1000, `expected currentXrpSideValue = tvl(2000) * ownerPct(50%) = 1000, got ${p.currentXrpSideValue}`);

    const finding = result.signals.find(s => /composition has shifted/.test(s.headline || ''));
    assert(finding, 'expected a composition-shift finding to fire above the 20% threshold');
    assert(/~300%/.test(finding.headline), `expected the finding to name the real shift percentage, got: "${finding.headline}"`);
    assert(finding.observed.some(o => /1(\.0+)? XRP per token/.test(o)), `expected the deposit-time ratio in observed, got: ${JSON.stringify(finding.observed)}`);
    assert(finding.observed.some(o => /4(\.0+)? XRP per token/.test(o)), `expected the current ratio in observed, got: ${JSON.stringify(finding.observed)}`);
    assert(/not an impermanent-loss or profit\/loss/i.test(finding.classification), `expected an explicit negated disclaimer, got: "${finding.classification}"`);
    assert(/no price feed|price data/.test(finding.classification), 'expected an explicit disclaimer about the missing price feed for the non-XRP leg');
  });
});

suite.register('A pool whose ratio has NOT meaningfully moved since deposit produces no composition-shift finding, but still computes currentXrpSideValue', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugAmmPositions, { timeout: 8000 });
    const tx = depositTx({ xrpContributed: 1000, tokenContributed: 1000 }); // deposit ratio 1.0
    const result = await page.evaluate(([tx, lines, ammMap]) =>
      window._debugAmmPositions(lines, [tx], [], new Map(ammMap), 'rLpAccount0000000000000000000000000'),
      [tx, lines(), [...ammInfoMap({ xrp: 1050, token: 1000 })]] // current ratio 1.05 -> only a 5% shift
    );
    const p = result.positions[0];
    assert(p.compositionShiftPct < 20, `expected a shift well under the 20% threshold, got ${p.compositionShiftPct}`);
    assert(p.currentXrpSideValue != null, 'expected currentXrpSideValue to still be computed even with no meaningful shift');
    assert(!result.signals.some(s => /composition has shifted/.test(s.headline || '')), 'must not fire a composition-shift finding below the threshold');
  });
});

suite.register('A position with no deposit history at all (e.g. LP tokens received via some other path) computes ownerPct/tvl normally with no composition data and no crash', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugAmmPositions, { timeout: 8000 });
    const result = await page.evaluate(([lines, ammMap]) =>
      window._debugAmmPositions(lines, [], [], new Map(ammMap), 'rLpAccount0000000000000000000000000'),
      [lines(), [...ammInfoMap({ xrp: 2000, token: 500 })]]
    );
    const p = result.positions[0];
    assert(p.ownerPct === 50, `expected ownerPct still computed normally, got ${p.ownerPct}`);
    assert(p.compositionShiftPct === undefined, 'expected no compositionShiftPct without any deposit history to compare against');
    assert(p.currentXrpSideValue === undefined, 'expected no currentXrpSideValue without any deposit history to compare against');
  });
});

suite.register('A single-asset deposit (only XRP, no token leg) is correctly excluded from the ratio comparison, not treated as a false composition shift', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugAmmPositions, { timeout: 8000 });
    // Single-asset deposit: XRP leg only, no RippleState change for the
    // regular token — tokenDeltas will be empty for this event.
    const tx = {
      tx: { Account: ADDR, TransactionType: 'AMMDeposit', date: 800000000, hash: 'dep-single' },
      meta: {
        TransactionResult: 'tesSUCCESS',
        AffectedNodes: [
          { ModifiedNode: { LedgerEntryType: 'AccountRoot', FinalFields: { Account: ADDR, Balance: '9000000000' }, PreviousFields: { Balance: '10000000000' } } },
          { CreatedNode: { LedgerEntryType: 'RippleState', NewFields: {
              Balance: { currency: LP_CURRENCY, issuer: 'rrrrrrrrrrrrrrrrrrrrrhoLvTp', value: '500' },
              LowLimit: { issuer: ADDR, currency: LP_CURRENCY, value: '0' },
              HighLimit: { issuer: TOKEN_ISSUER, currency: LP_CURRENCY, value: '1000000' },
          } } },
        ],
      },
    };
    const result = await page.evaluate(([tx, lines, ammMap]) =>
      window._debugAmmPositions(lines, [tx], [], new Map(ammMap), 'rLpAccount0000000000000000000000000'),
      [tx, lines(), [...ammInfoMap({ xrp: 2000, token: 500 })]]
    );
    const p = result.positions[0];
    assert(p.compositionShiftPct === undefined, 'a single-asset deposit has no real deposit-time ratio to compare against — must not fabricate one');
    assert(!result.signals.some(s => /composition has shifted/.test(s.headline || '')), 'must not fire a composition-shift finding from a single-asset deposit');
  });
});

suite.register('_renderAmmPositionVisual shows the XRP-side-only value clearly labeled, and the composition-shift caveat only when the shift is real', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugRenderAmmPositionVisual, { timeout: 8000 });
    const withShift = await page.evaluate(() => window._debugRenderAmmPositionVisual({
      tvl: 2000, tvl2: 500, ownerPct: 50, feeRate: 0.5, costBasisXrp: 1000,
      currentXrpSideValue: 1000, compositionShiftPct: 300,
    }));
    assert(/XRP leg only, not total/.test(withShift), 'expected the current-value stat to explicitly disclaim being a total');
    assert(/1,000 XRP/.test(withShift), `expected the real currentXrpSideValue rendered, got: ${withShift}`);
    assert(/shifted ~300%/.test(withShift), 'expected the composition-shift caveat to render with the real percentage');

    const noShift = await page.evaluate(() => window._debugRenderAmmPositionVisual({
      tvl: 2000, tvl2: 500, ownerPct: 50, feeRate: 0.5, costBasisXrp: 1000,
      currentXrpSideValue: 1000, compositionShiftPct: 5,
    }));
    assert(!/shifted/.test(noShift), 'must not render the composition-shift caveat when the shift is below the threshold');
  });
});

suite.register('A real token issuer with an AMM pool renders the AMM panel with no page errors (live smoke test)', async () => {
  await withPage(async (page) => {
    const errors = [];
    page.on('pageerror', e => errors.push(e.message));
    await connectAndShowDashboard(page);
    await inspectAddress(page, 'rsoLo2S1kiGeCcn6hCUXVrCpGMWLrRrLZz', { timeout: 90000 });
    await page.waitForTimeout(1500);
    assert(errors.length === 0, `expected zero page errors, got: ${JSON.stringify(errors)}`);
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
