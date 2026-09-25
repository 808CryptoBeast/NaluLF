// Regression guard for "Haptic feedback on key security actions" (roadmap:
// UX & Accessibility, tagged iOS).
//
// Scoped to what's actually achievable from a pure web app: navigator.
// vibrate() is a real, standard, supported API on Android Chrome/Firefox/
// Edge, but iOS Safari — even installed as a home-screen PWA — has never
// implemented it in any WebKit version, with no public plan to. The only
// way to get real haptic feedback on iOS from this codebase would be
// wrapping it in a native shell (Capacitor/Cordova), well outside a pure
// web app's scope. hapticPulse() (utils.js) is a thin, always-safe wrapper —
// navigator.vibrate?.(pattern) in a try/catch — that provides real feedback
// where supported and degrades to a harmless no-op everywhere else,
// including iOS. Wired into the 4 key security actions (Emergency Sweep,
// Revoke Regular Key, Clear Signer List, Rotate Key) on SUCCESS only, never
// on a validation failure or a rejected transaction.
import { withPage, freshSignup, makeSuite, assert } from './helpers.mjs';

const suite = makeSuite('Haptic Feedback');

async function importTestWallet(page, label) {
  await page.addScriptTag({ url: 'https://cdn.jsdelivr.net/npm/xrpl@4.2.5/build/xrpl-latest-min.js' });
  const { seed } = await page.evaluate(() => { const w = window.xrpl.Wallet.generate(); return { seed: w.seed }; });
  await page.evaluate(() => window.openImportSeedModal());
  await page.evaluate(({ seed, label }) => {
    document.getElementById('inp-import-seed').value = seed;
    document.getElementById('inp-import-seed-pass').value = 'TestPassword123';
    document.getElementById('inp-import-seed-pass-confirm').value = 'TestPassword123';
    document.getElementById('inp-import-seed-label').value = label;
  }, { seed, label });
  await page.evaluate(() => window.executeImportFromSeed());
  await page.waitForTimeout(800);
  await page.evaluate(() => window.tourSkip && window.tourSkip());
  return page.evaluate((label) => JSON.parse(localStorage.getItem('nalulf_wallets') || '[]').find(w => w.label === label)?.id, label);
}

suite.register('hapticPulse forwards its pattern to navigator.vibrate when supported', async () => {
  await withPage(async (page, { pageErrors }) => {
    await page.waitForFunction(() => window._debugHapticPulse, { timeout: 8000 });
    const result = await page.evaluate(() => {
      const calls = [];
      navigator.vibrate = (pattern) => { calls.push(pattern); return true; };
      window._debugHapticPulse([30, 40, 30]);
      return calls;
    });
    assert(result.length === 1, `expected exactly one navigator.vibrate call, got ${result.length}`);
    assert(JSON.stringify(result[0]) === JSON.stringify([30, 40, 30]), `expected the exact pattern to be forwarded, got ${JSON.stringify(result[0])}`);
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

suite.register('hapticPulse never throws when navigator.vibrate is unsupported (the real iOS Safari case)', async () => {
  await withPage(async (page, { pageErrors }) => {
    await page.waitForFunction(() => window._debugHapticPulse, { timeout: 8000 });
    const result = await page.evaluate(() => {
      navigator.vibrate = undefined;
      let threw = false;
      try { window._debugHapticPulse([30, 40, 30]); } catch { threw = true; }
      return { threw, vibrateIsUndefined: typeof navigator.vibrate === 'undefined' };
    });
    assert(result.vibrateIsUndefined, 'test setup sanity check: navigator.vibrate should read as undefined');
    assert(!result.threw, 'expected hapticPulse to degrade to a silent no-op, not throw, when navigator.vibrate is unsupported');
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

suite.register('A failed security action (validation error or rejected transaction) never triggers haptic feedback — only a real success does', async () => {
  await withPage(async (page, { pageErrors }) => {
    const ok = await freshSignup(page, { name: 'Haptic Test', email: 'haptictest@test.com', domain: 'haptictest' });
    assert(ok, 'signup failed');
    await page.evaluate(() => window.showProfile());
    await page.waitForTimeout(300);
    await page.evaluate(() => window.tourSkip && window.tourSkip());
    const walletId = await importTestWallet(page, 'Haptic Wallet');
    assert(walletId, 'expected the imported wallet to be registered');

    await page.evaluate(() => { window.__vibrateCalls = []; navigator.vibrate = (p) => { window.__vibrateCalls.push(p); return true; }; });

    await page.evaluate((id) => window.openSecurityActionsModal(id, 'revoke'), walletId);
    await page.waitForTimeout(500);
    // A fresh, unfunded wallet has no account on-chain yet — Revoke will
    // fail with a real error, not a synthetic one, exercising the actual
    // failure path this app's own users would hit.
    await page.evaluate(() => window.executeRevokeRegularKey());
    await page.waitForTimeout(500);

    const callsAfterFailure = await page.evaluate(() => window.__vibrateCalls.length);
    assert(callsAfterFailure === 0, `expected zero haptic pulses after a failed action, got ${callsAfterFailure}`);
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
