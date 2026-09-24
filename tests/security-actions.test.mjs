// Regression guard for two things found and fixed while building the
// Security Remediation feature (Emergency Fund Sweep + Revoke Regular Key):
//
// 1. A real, pre-existing, currently-broken-for-users bug: index.html had a
//    STALE static copy of the Import-Seed/Import-Address/Token-Details
//    modals, left over from before wallet-password encryption was added to
//    the seed-import flow. Since a static element earlier in document order
//    always wins getElementById()/$() lookups over one appended later by
//    JS, this dead copy silently shadowed the real, up-to-date version
//    _mountDynamicModals() builds in profile.js — the stale #import-seed-
//    modal had no #inp-import-seed-pass/-pass-confirm fields at all, so
//    opening it crashed immediately with "Cannot set properties of null."
//    Removed the stale static copy; the dynamic version is now the only one.
//
// 2. The new Security Actions modal (Emergency Sweep, Revoke Regular Key,
//    Clear Signer List), reachable from each non-watch-only wallet card.
import { withPage, freshSignup, makeSuite, assert } from './helpers.mjs';

const suite = makeSuite('Security Actions — Emergency Sweep, Revoke Regular Key & Clear Signer List');

async function importTestWallet(page) {
  await page.addScriptTag({ url: 'https://cdn.jsdelivr.net/npm/xrpl@4.2.5/build/xrpl-latest-min.js' });
  const { seed, address } = await page.evaluate(() => {
    const w = window.xrpl.Wallet.generate();
    return { seed: w.seed, address: w.address };
  });
  await page.evaluate(() => window.openImportSeedModal());
  await page.evaluate((seed) => {
    document.getElementById('inp-import-seed').value = seed;
    document.getElementById('inp-import-seed-pass').value = 'TestPassword123';
    document.getElementById('inp-import-seed-pass-confirm').value = 'TestPassword123';
    document.getElementById('inp-import-seed-label').value = 'Security Test Wallet';
  }, seed);
  await page.evaluate(() => window.executeImportFromSeed());
  await page.waitForTimeout(800);
  return address;
}

suite.register('Regression: opening Import-from-Seed no longer crashes on a stale shadowing modal, and a real import succeeds', async () => {
  await withPage(async (page, { pageErrors }) => {
    const ok = await freshSignup(page, { name: 'Sec Test', email: 'sec1@test.com', domain: 'sectest1' });
    assert(ok, 'signup failed');
    await page.evaluate(() => window.showProfile());
    await page.waitForTimeout(400);

    const modalCounts = await page.evaluate(() => Object.fromEntries(
      ['import-seed-modal', 'import-address-modal', 'token-details-modal'].map(id => [id, document.querySelectorAll('#' + id).length])
    ));
    assert(modalCounts['import-seed-modal'] === 1, `expected exactly one #import-seed-modal, got ${modalCounts['import-seed-modal']} (the stale duplicate is back)`);
    assert(modalCounts['import-address-modal'] === 1, `expected exactly one #import-address-modal, got ${modalCounts['import-address-modal']}`);
    assert(modalCounts['token-details-modal'] === 1, `expected exactly one #token-details-modal, got ${modalCounts['token-details-modal']}`);

    const address = await importTestWallet(page);
    const importError = await page.evaluate(() => document.getElementById('import-seed-error')?.textContent);
    assert(!importError, `expected no import error, got: "${importError}"`);
    const cardExists = await page.evaluate((addr) => [...document.querySelectorAll('.wcard')].some(c => c.textContent.includes('Security Test Wallet')), address);
    assert(cardExists, 'expected the imported wallet to actually render as a card');
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

suite.register('Security Actions modal: opens, identifies an unfunded account honestly, and disables Revoke when there is nothing to revoke', async () => {
  await withPage(async (page, { pageErrors }) => {
    const ok = await freshSignup(page, { name: 'Sec Test 2', email: 'sec2@test.com', domain: 'sectest2' });
    assert(ok, 'signup failed');
    await page.evaluate(() => window.showProfile());
    await page.waitForTimeout(400);
    await importTestWallet(page);

    const walletId = await page.evaluate(() => {
      const btn = [...document.querySelectorAll('.wcard-btn--security')].find(b => b.closest('.wcard')?.textContent.includes('Security Test Wallet'));
      return btn?.getAttribute('onclick')?.match(/'([^']+)'/)?.[1] || null;
    });
    assert(walletId, 'expected a Security button on the imported wallet card');

    await page.evaluate((id) => window.openSecurityActionsModal(id), walletId);
    await page.waitForFunction(() => document.getElementById('revoke-key-status')?.textContent !== 'Checking current key state…', { timeout: 15000 });
    await page.waitForFunction(() => document.getElementById('signerlist-status')?.textContent !== 'Checking current signer list…', { timeout: 15000 });

    const state = await page.evaluate(() => ({
      modalShowing: document.getElementById('security-modal-overlay')?.classList.contains('show'),
      walletName: document.getElementById('security-modal-wallet-name')?.textContent,
      revokeStatus: document.getElementById('revoke-key-status')?.textContent,
      sweepPreview: document.getElementById('sweep-amount-preview')?.textContent,
      revokeBtnDisabled: document.getElementById('revoke-submit-btn')?.disabled,
      signerStatus: document.getElementById('signerlist-status')?.textContent,
      signerBtnDisabled: document.getElementById('signerlist-submit-btn')?.disabled,
    }));
    assert(state.modalShowing, 'expected the Security Actions modal to be open');
    assert(state.walletName === 'Security Test Wallet', `expected the correct wallet name, got "${state.walletName}"`);
    assert(/not found on-chain/i.test(state.revokeStatus), `expected an honest "not found on-chain" status for a fresh unfunded wallet, got: "${state.revokeStatus}"`);
    assert(state.sweepPreview === '0 XRP (unfunded)', `expected the sweep preview to honestly show unfunded, got: "${state.sweepPreview}"`);
    assert(state.revokeBtnDisabled === true, 'expected Revoke to be disabled when there is no regular key to revoke');
    assert(/not found on-chain/i.test(state.signerStatus), `expected an honest "not found on-chain" signer-list status for a fresh unfunded wallet, got: "${state.signerStatus}"`);
    assert(state.signerBtnDisabled === true, 'expected Clear Signer List to be disabled when the account does not even exist on-chain yet');
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

suite.register('Clear Signer List correctly reads a real account\'s live signer-list state (empty for a normal account)', async () => {
  await withPage(async (page, { pageErrors }) => {
    // Read-only check against a real, well-known account with no signer
    // list — confirms getSignerList()'s account_info shape assumption
    // (`signer_lists: []` → treated as "no signer list") against live data,
    // without needing a funded wallet of our own to sign with.
    const result = await page.evaluate(() => new Promise((resolve) => {
      const ws = new WebSocket('wss://xrplcluster.com');
      ws.onopen = () => ws.send(JSON.stringify({ id: 1, command: 'account_info', account: 'rPVMhWBsfF9iMXYj3aAzJVkPDTFNSyWdKy', ledger_index: 'current', signer_lists: true }));
      ws.onmessage = (ev) => { const r = JSON.parse(ev.data); resolve(r.result?.account_data?.signer_lists ?? 'MISSING'); ws.close(); };
      ws.onerror = () => resolve('ERROR');
      setTimeout(() => resolve('TIMEOUT'), 10000);
    }));
    assert(Array.isArray(result), `expected account_info with signer_lists:true to return an array for a real account, got: ${JSON.stringify(result)}`);
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

suite.register('Emergency Sweep validates the destination before ever attempting to sign', async () => {
  await withPage(async (page, { pageErrors }) => {
    const ok = await freshSignup(page, { name: 'Sec Test 3', email: 'sec3@test.com', domain: 'sectest3' });
    assert(ok, 'signup failed');
    await page.evaluate(() => window.showProfile());
    await page.waitForTimeout(400);
    const address = await importTestWallet(page);
    const walletId = await page.evaluate(() => {
      const btn = [...document.querySelectorAll('.wcard-btn--security')].find(b => b.closest('.wcard')?.textContent.includes('Security Test Wallet'));
      return btn?.getAttribute('onclick')?.match(/'([^']+)'/)?.[1] || null;
    });
    await page.evaluate((id) => window.openSecurityActionsModal(id), walletId);
    await page.waitForTimeout(300);

    await page.evaluate(() => { document.getElementById('sweep-dest').value = 'not-a-real-address'; });
    await page.evaluate(() => window.executeEmergencySweep());
    await page.waitForTimeout(200);
    assert(/valid xrpl destination/i.test(await page.evaluate(() => document.getElementById('sweep-error').textContent)), 'expected rejection of an invalid destination address');

    await page.evaluate((addr) => { document.getElementById('sweep-dest').value = addr; }, address);
    await page.evaluate(() => window.executeEmergencySweep());
    await page.waitForTimeout(200);
    assert(/different address/i.test(await page.evaluate(() => document.getElementById('sweep-error').textContent)), 'expected rejection of sweeping a wallet to itself');
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
