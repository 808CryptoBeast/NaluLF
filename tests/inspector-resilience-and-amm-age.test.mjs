// Regression coverage for two fixes made while verifying the account-age
// provenance work (roadmap: XRPL Account Age / Activation Provenance
// repair), both found live rather than anticipated in advance:
//
// 1. Phase 1's very first fetch (account_info/account_offers/account_nfts)
//    ran via Promise.all with only account_nfts wrapped in .catch() — a
//    transient rate-limit/busy rejection on EITHER of the other two crashed
//    the entire inspection with a generic, unhelpful "Internal error"
//    instead of degrading gracefully like every other call in this file.
//    This surfaced live while heavily testing today, including hitting a
//    real upstream issue: s1.ripple.com runs Clio, which has a documented
//    bug returning "Internal error" for account_info on AMM pseudo-accounts
//    specifically — an orthogonal third-party endpoint limitation, but the
//    app's OWN failure mode around it (crash vs. clear message) was a real,
//    independently-fixable bug.
// 2. The "⚠ New wallet" badge must not fire for an AMM pool's own
//    AccountRoot (detected via its AMMID field) — ordinary human-wallet
//    age/risk interpretation doesn't apply to a pseudo-account created the
//    moment its AMM was.
import { withPage, connectAndShowDashboard, inspectAddress, assert } from './helpers.mjs';

const suite = { register: [], run: async () => {
  let pass = 0, fail = 0;
  console.log('\n▶ Inspector Resilience + AMM Pseudo-Account Age');
  for (const { name, fn } of suite.register) {
    try { await fn(); console.log(`  PASS  ${name}`); pass++; }
    catch (err) { console.log(`  FAIL  ${name}`); console.log(`        ${err?.stack || err}`); fail++; }
  }
  return { pass, fail, total: suite.register.length };
}};
const test = (name, fn) => suite.register.push({ name, fn });

test('A valid but never-funded address shows a clear "not funded" message, not a generic Internal error', async () => {
  await withPage(async (page, { pageErrors }) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, 'rrrrrrrrrrrrrrrrrrrrrhoLvTp', { timeout: 60000 });
    const result = await page.evaluate(() => ({
      errText: document.getElementById('inspect-err')?.textContent,
      errVisible: document.getElementById('inspect-err')?.style.display,
    }));
    assert(result.errVisible === '', 'expected the error panel to be visible');
    assert(/has not been funded/.test(result.errText), `expected a clear "not funded" message, got: "${result.errText}"`);
    assert(!/Internal error/i.test(result.errText), `expected NO generic "Internal error" text, got: "${result.errText}"`);
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

test('The "New wallet" badge does NOT fire for an AMM pool account (AMMID present), even with a verified low day-count', async () => {
  await withPage(async (page, { pageErrors }) => {
    await connectAndShowDashboard(page);
    await page.evaluate(() => window.switchTab(null, 'inspector'));
    await page.waitForFunction(() => window._debugRenderHeader && document.getElementById('inspect-acct-grid'), { timeout: 8000 });

    const result = await page.evaluate(() => {
      const evidence = { ledgerIndex: 1, transactionHash: 'h', timestamp: 800000000 };
      window._debugRenderHeader('rNormalNewWalletAAAAAAAAAAAAAAAAAA', { Balance: '100000000', Sequence: 5, Flags: 0 }, 100, 10, 0, 5, 10, 2, Date.now() - 2 * 86400000, true, evidence);
      const normalBadge = !!document.querySelector('.acct-cell-new-badge');

      window._debugRenderHeader('rAmmPoolAccountAAAAAAAAAAAAAAAAAAA', { Balance: '100000000', Sequence: 5, Flags: 0, AMMID: '419A61974BDCB91E0408865D554605F466084BA9A88F75391502502F0578DF89' }, 100, 10, 0, 5, 10, 2, Date.now() - 2 * 86400000, true, evidence);
      const ammBadge = !!document.querySelector('.acct-cell-new-badge');

      return { normalBadge, ammBadge };
    });

    assert(result.normalBadge === true, 'expected the badge to fire for an ordinary verified 2-day-old account (control case)');
    assert(result.ammBadge === false, 'expected the badge to NOT fire for an AMM pseudo-account with the identical age/verification inputs');
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
