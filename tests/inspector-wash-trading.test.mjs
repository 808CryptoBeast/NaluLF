// Regression guard for the wash-trading false-positive fix: a same-currency
// self-payment with no DEX history and no token involvement touches no
// market at all and must not be flagged as high-confidence wash trading.
// Also covers the applicability/ownerImpact/externalImpact schema fields
// added later, verified via synthetic data (no live account is guaranteed
// to hit every branch, and live mainnet data drifts run to run).
import { withPage, connectAndShowDashboard, inspectAddress, makeSuite, assert } from './helpers.mjs';

const REAL_SELF_PAYMENT_ACCOUNT = 'rp2qFithsVh9dyzwTq4U5C1KXoRv94Vc9p'; // real account with genuine self-payments + real DEX history

const suite = makeSuite('Wash Trading False-Positive Prevention');

suite.register('A real account with self-payments AND real DEX history gets warn/moderate confidence, not a blanket 85% critical', async () => {
  await withPage(async (page) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, REAL_SELF_PAYMENT_ACCOUNT);
    const finding = await page.evaluate(() => {
      const findings = window._lastAllFindings || [];
      const f = findings.find((x) => x.headline?.includes('self-payment'));
      return f ? { sev: f.sev, confidence: f.confidence, hasOwnerImpact: !!f.ownerImpact, hasExternalImpact: !!f.externalImpact } : null;
    });
    assert(finding, 'expected self-payment finding not found — live data may have drifted; re-verify against current mainnet state if this fails');
    assert(finding.sev !== 'critical', `self-payment finding should not be critical severity, got ${finding.sev}`);
    assert(finding.confidence <= 0.6, `expected confidence <=0.6 (not the old blanket 85%), got ${finding.confidence}`);
    assert(finding.hasOwnerImpact, 'missing ownerImpact field on a real market-relevant self-payment finding');
    assert(finding.hasExternalImpact, 'missing externalImpact field on a real market-relevant self-payment finding');
  });
});

suite.register('A synthetic no-market-context self-payment (no DEX, no token) gets applicability:false and info severity', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugWashExecution, { timeout: 8000 });
    const result = await page.evaluate(() => {
      const addr = 'rTESTaddr';
      const profile = { cancelRatio: 0, sizeCV: null, burstWindows: { thirtySec: 0, oneHour: 0 }, createdCount: 0 };
      const offerLifecycles = { list: [] };
      const payments = [
        { tx: { TransactionType: 'Payment', Account: addr, Destination: addr, Amount: '5000000' } },
        { tx: { TransactionType: 'Payment', Account: addr, Destination: addr, Amount: '5000000' } },
        { tx: { TransactionType: 'Payment', Account: addr, Destination: addr, Amount: '5000000' } },
      ];
      const out = window._debugWashExecution(profile, offerLifecycles, payments, addr, false);
      return out.findings.find((f) => f.headline?.includes('self-payment'));
    });
    assert(result, 'no self-payment finding produced for a clear no-market-context case');
    assert(result.sev === 'info', `expected info severity for no-market-context case, got ${result.sev}`);
    assert(result.applicability?.applicable === false, 'expected applicability.applicable === false for a self-payment with no DEX/token context');
    assert(typeof result.applicability?.reason === 'string' && result.applicability.reason.length > 0, 'applicability.reason missing');
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
