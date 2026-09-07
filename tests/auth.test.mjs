// Regression guard for the auth.js correctness fixes: the domain
// auto-fill must keep tracking the name until a REAL manual edit (not
// just its own auto-fill call), a blank domain field must fall back to a
// capped/deduped handle rather than an unchecked raw slug, and a
// corrupted session record must never crash app boot.
import { chromium } from 'playwright';
import { withPage, freshSignup, startServer, stopServer, makeSuite, assert } from './helpers.mjs';

const suite = makeSuite('Auth — Signup Flow');

suite.register('Domain auto-fill keeps tracking the name across multiple keystrokes until a real manual edit', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window.showAuthView, { timeout: 8000 });
    await page.evaluate(() => window.showAuthView('signup'));
    await page.waitForTimeout(150);
    const result = await page.evaluate(() => {
      const nameEl = document.getElementById('inp-signup-name');
      const domainEl = document.getElementById('inp-signup-domain');
      nameEl.value = 'Joh';
      window.validateSignupName();
      const afterFirst = domainEl.value;
      const frozenAfterAutoFill = !!domainEl.dataset.manuallyEdited;
      nameEl.value = 'John Doe';
      window.validateSignupName();
      return { afterFirst, frozenAfterAutoFill, afterSecond: domainEl.value };
    });
    assert(result.afterFirst === 'joh', `expected first auto-fill "joh", got "${result.afterFirst}"`);
    assert(!result.frozenAfterAutoFill, 'auto-fill call itself incorrectly set manuallyEdited, freezing the field after one keystroke');
    assert(result.afterSecond === 'john_doe', `expected domain to keep updating to "john_doe", got "${result.afterSecond}"`);
  });
});

suite.register('A real manual domain edit does freeze the field against further auto-fill', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window.showAuthView, { timeout: 8000 });
    await page.evaluate(() => window.showAuthView('signup'));
    await page.waitForTimeout(150);
    const result = await page.evaluate(() => {
      const nameEl = document.getElementById('inp-signup-name');
      const domainEl = document.getElementById('inp-signup-domain');
      domainEl.value = 'custom_handle';
      window.validateSignupDomain(); // real user oninput/onblur call, no args
      const frozen = !!domainEl.dataset.manuallyEdited;
      nameEl.value = 'Someone Else';
      window.validateSignupName();
      return { frozen, domainAfter: domainEl.value };
    });
    assert(result.frozen, 'a real manual domain edit did not set manuallyEdited');
    assert(result.domainAfter === 'custom_handle', `manual edit was overwritten by further name typing, got "${result.domainAfter}"`);
  });
});

suite.register('Full signup with a blank domain field produces a capped, valid fallback handle and a real persisted vault', async () => {
  await withPage(async (page) => {
    const ok = await freshSignup(page, { name: 'A Very Long Test Display Name That Exceeds Thirty Characters Total', email: 'longnametest@example.com', domain: '' });
    assert(ok, 'signup reported an error');
    const state = await page.evaluate(() => ({
      vaultMeta: !!localStorage.getItem('naluxrp_vault_meta'),
      vaultData: !!localStorage.getItem('naluxrp_vault_data'),
      session: JSON.parse(localStorage.getItem('naluxrp_session') || 'null'),
    }));
    assert(state.vaultMeta && state.vaultData, 'vault was not actually persisted to localStorage');
    assert(state.session?.domain?.length > 0 && state.session.domain.length <= 30, `fallback domain should be 1-30 chars, got "${state.session?.domain}" (${state.session?.domain?.length} chars)`);
    assert(/^[a-z0-9_]+$/.test(state.session.domain), `fallback domain has invalid characters: "${state.session.domain}"`);
  });
});

suite.register('restoreSession() does not throw when a stored session is missing "name"', async () => {
  // No exposed direct call for restoreSession() (it runs automatically at
  // app boot) — verify indirectly: seed a corrupted session via
  // addInitScript (so it's present before boot runs), then confirm the
  // page loads with zero page errors instead of crashing. withPage() isn't
  // used here because it navigates before this test's addInitScript would
  // be registered.
  const { server, baseUrl } = await startServer();
  const browser = await chromium.launch();
  const page = await browser.newPage();
  const pageErrors = [];
  page.on('pageerror', (e) => pageErrors.push(String(e)));
  await page.addInitScript(() => {
    localStorage.setItem('naluxrp_session', JSON.stringify({ email: 'a@b.com' })); // no name
    localStorage.setItem('naluxrp_vault_meta', JSON.stringify({ salt: [1, 2, 3], iterations: 1000, version: 'naluxrp_v2' }));
    localStorage.setItem('naluxrp_vault_data', JSON.stringify({ iv: [1], cipher: [1] }));
  });
  try {
    await page.goto(`${baseUrl}/index.html`);
    await page.waitForFunction(() => window.showAuthView, { timeout: 8000 });
    await page.waitForTimeout(400);
    assert(pageErrors.length === 0, `restoreSession() threw on a corrupted session record: ${pageErrors.join('; ')}`);
  } finally {
    await browser.close().catch(() => {});
    stopServer(server);
  }
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
