// Regression guard for Security Audit's Simple/Explain/Analyst contract
// (Inspector-wide roadmap item #10): a plain-language "In plain terms"
// summary always visible, with the dense raw evidence (Recent Security
// Changes, Security Timeline, Current Configuration, Active Flags, Signer
// List, DepositPreauth grants) gated behind the same pre-existing
// app-wide Simple/Advanced toggle (_analystMode) every other upgraded
// section already uses. Security Audit was previously one of ~15 sections
// showing identical dense content regardless of mode.
import { withPage, connectAndShowDashboard, inspectAddress, makeSuite, assert } from './helpers.mjs';

const suite = makeSuite('Security Audit — Plain Summary & Mode Gating');

const ACTIVE_ACCOUNT = 'rnj7R3QUGzLZc9dg24jSrGabtt1tp1XD7A';

suite.register('A real account renders the plain-summary box and correctly gates raw evidence behind Simple/Advanced mode, with no page errors', async () => {
  await withPage(async (page, { pageErrors }) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, ACTIVE_ACCOUNT, { timeout: 90000 });
    await page.waitForTimeout(1500);

    const simpleState = await page.evaluate(() => {
      const el = document.getElementById('inspect-security-body');
      const adv = el.querySelector('.advanced-only');
      const smp = el.querySelector('.simple-only');
      return {
        hasPlainText: el.textContent.includes('In plain terms:'),
        advVisible: adv ? getComputedStyle(adv).display !== 'none' : null,
        smpVisible: smp ? getComputedStyle(smp).display !== 'none' : null,
      };
    });
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
    assert(simpleState.hasPlainText, 'expected the "In plain terms" summary box');
    assert(simpleState.advVisible === false, 'expected the detailed evidence to be hidden in default Simple mode');
    assert(simpleState.smpVisible === true, 'expected the Simple-mode teaser to be visible in default Simple mode');

    await page.evaluate(() => window.toggleAnalystMode());
    await page.waitForTimeout(300);
    const advState = await page.evaluate(() => {
      const el = document.getElementById('inspect-security-body');
      return { advVisible: getComputedStyle(el.querySelector('.advanced-only')).display !== 'none', smpVisible: getComputedStyle(el.querySelector('.simple-only')).display !== 'none' };
    });
    assert(advState.advVisible === true, 'expected the detailed evidence to become visible in Advanced mode');
    assert(advState.smpVisible === false, 'expected the Simple-mode teaser to hide in Advanced mode');
    await page.evaluate(() => window.toggleAnalystMode()); // restore default
  });
});

suite.register('Synthetic: buildSecurityPlainSummary reflects the worst finding severity and names a non-default control state', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugSecurityPlainSummary, { timeout: 8000 });

    const clean = await page.evaluate(() => window._debugSecurityPlainSummary({ findings: [{ sev: 'ok' }] }, { state: 'Normal' }));
    assert(clean.tone === 'ok', `expected ok tone for an all-clean account, got ${clean.tone}`);
    assert(/nothing about/i.test(clean.text), `expected the all-clear framing, got: "${clean.text}"`);

    const warn = await page.evaluate(() => window._debugSecurityPlainSummary({ findings: [{ sev: 'warn' }] }, { state: 'Normal' }));
    assert(warn.tone === 'warn', `expected warn tone, got ${warn.tone}`);

    const critNonDefault = await page.evaluate(() => window._debugSecurityPlainSummary({ findings: [{ sev: 'critical' }] }, { state: 'Blackholed' }));
    assert(critNonDefault.tone === 'crit', `expected crit tone, got ${critNonDefault.tone}`);
    assert(/Blackholed/.test(critNonDefault.text), `expected the non-default control state to be named in the summary, got: "${critNonDefault.text}"`);
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
