// Regression coverage for "Address book — save labels for any inspected
// address" (roadmap: Analytics). Found a real, confirmed-dead-code bug while
// building this out: profile.js's wallet-drawer transaction list read a
// module-level `addrBook` object (`addrBook[tx.Destination]`), but the
// actual address-book storage (addToAddrBook/_getAddrBook/_saveAddrBook) is
// an ARRAY of {id,label,address,createdAt} entries — meaning that lookup
// could never match anything, regardless of what was actually saved. Fixed
// by removing the stale object shadow entirely and exporting a real
// getAddrBookLabel(address) helper both call sites (and the new Inspector
// integration below) now share.
import { withPage, connectAndShowDashboard, inspectAddress, freshSignup, makeSuite, assert } from './helpers.mjs';

const suite = makeSuite('Address Book');

const HIGH_VOLUME_ACCOUNT = 'rPVMhWBsfF9iMXYj3aAzJVkPDTFNSyWdKy'; // Bitstamp hot wallet

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
  return page.evaluate((label) => JSON.parse(localStorage.getItem('nalulf_wallets') || '[]').find(w => w.label === label), label);
}

suite.register('Live: the Inspector\'s Relationship Drawer can save a real counterparty to the address book, immediately reflects it in its own headline, and refreshes the Inbound Flow panel behind it', async () => {
  await withPage(async (page, { pageErrors }) => {
    page.on('dialog', (d) => d.accept('My Test Label'));
    await connectAndShowDashboard(page);
    await inspectAddress(page, HIGH_VOLUME_ACCOUNT, { timeout: 90000 });
    await page.waitForTimeout(1000);
    await page.evaluate(() => window.toggleAnalystMode());
    await page.waitForTimeout(300);

    const opened = await page.evaluate(() => {
      const btn = document.querySelector('#inspect-inbound-body .mi-rel-examine');
      if (!btn) return false;
      btn.click();
      return true;
    });
    assert(opened, 'expected at least one real Examine button in Inbound Flow for this known top-funded account');

    const saveBtnExists = await page.evaluate(() =>
      [...document.querySelectorAll('#relDrawerDetail .mi-rel-examine')].some(b => b.textContent.includes('Save to Address Book')));
    assert(saveBtnExists, 'expected a "Save to Address Book" cross-link button in the drawer');

    await page.evaluate(() => {
      [...document.querySelectorAll('#relDrawerDetail .mi-rel-examine')].find(b => b.textContent.includes('Save to Address Book'))?.click();
    });
    await page.waitForTimeout(400);

    const afterSave = await page.evaluate(() => ({
      headlineHasLabel: document.getElementById('relDrawerHeadline')?.textContent.includes('My Test Label'),
      disabledNow: [...document.querySelectorAll('#relDrawerDetail .mi-rel-examine')].some(b => b.disabled && b.textContent.includes('My Test Label')),
      inboundShowsBadge: document.getElementById('inspect-inbound-body')?.innerHTML.includes('My Test Label'),
    }));
    assert(afterSave.headlineHasLabel, 'expected the drawer headline to update to the newly-saved label immediately');
    assert(afterSave.disabledNow, 'expected the Save button to become a disabled "already saved" indicator showing the label');
    assert(afterSave.inboundShowsBadge, 'expected the already-rendered Inbound Flow panel to refresh and show the new label badge without needing a fresh inspection');
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

suite.register('Regression: the wallet drawer\'s transaction list shows a real saved address-book label for the destination, not always falling through to the raw address (the confirmed dead addrBook[address] lookup bug)', async () => {
  await withPage(async (page, { pageErrors }) => {
    const signedUp = await freshSignup(page, { name: 'AddrBook Test', email: 'addrbooktest@test.com', domain: 'addrbooktest' });
    assert(signedUp, 'signup failed');
    await page.evaluate(() => window.showProfile());
    await page.waitForTimeout(300);
    await page.evaluate(() => window.tourSkip && window.tourSkip());

    const labeledAddr = 'rDrtNsGeAoUWa6Hu12yGBPtLRMESRoyS5W';
    await page.evaluate((addr) => window.addToAddrBook(addr, 'My Test Label'), labeledAddr);

    const wallet = await importTestWallet(page, 'AddrBook Test Wallet');
    assert(wallet?.id, 'expected the imported wallet to be registered with a real id');

    await page.evaluate(({ walletAddr, labeledAddr }) => {
      window._debugSeedTxCache(walletAddr, [{
        TransactionType: 'Payment', Account: walletAddr,
        Destination: labeledAddr, Amount: '1000000', date: 800000000,
        metaData: { TransactionResult: 'tesSUCCESS' },
      }]);
    }, { walletAddr: wallet.address, labeledAddr });

    await page.evaluate((id) => window.toggleWalletDrawer(id), wallet.id);
    await page.waitForTimeout(400);
    const drawerHtml = await page.evaluate((id) => document.getElementById(`wcard-drawer-body-${id}`)?.innerHTML || '', wallet.id);
    assert(drawerHtml.includes('My Test Label'), `expected the wallet drawer to show the real saved label for this destination, got: ${drawerHtml.slice(0, 300)}`);
    assert(!drawerHtml.includes(labeledAddr.slice(0, 8)), 'expected the labeled destination to NOT also show as a raw shortened address');
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

suite.register('Live: the Send modal\'s address-book picker lists saved entries, fills the destination on pick, and resets itself back to the placeholder', async () => {
  await withPage(async (page, { pageErrors }) => {
    const signedUp = await freshSignup(page, { name: 'AB Test 2', email: 'abtest2@test.com', domain: 'abtest2' });
    assert(signedUp, 'signup failed');
    await page.evaluate(() => window.showProfile());
    await page.waitForTimeout(300);
    await page.evaluate(() => window.tourSkip && window.tourSkip());

    const wallet = await importTestWallet(page, 'AB Wallet');
    assert(wallet?.id, 'expected the imported wallet to be registered with a real id');

    const savedAddr = 'rTestAddrBookAccount0000000000000000';
    await page.evaluate((addr) => window.addToAddrBook(addr, 'Direct Add'), savedAddr);

    await page.evaluate((id) => window.openSendModal(id), wallet.id);
    await page.waitForTimeout(200);
    const dropdown = await page.evaluate(() => {
      const sel = document.getElementById('send-addr-book');
      return { hasEntry: [...(sel?.options || [])].some(o => o.textContent.includes('Direct Add')) };
    });
    assert(dropdown.hasEntry, 'expected the Send modal\'s address-book picker to list the saved entry');

    await page.evaluate((addr) => {
      const sel = document.getElementById('send-addr-book');
      sel.value = addr;
      sel.dispatchEvent(new Event('change'));
    }, savedAddr);
    await page.waitForTimeout(200);
    const afterPick = await page.evaluate(() => ({
      destFilled: document.getElementById('send-dest')?.value,
      selectReset: document.getElementById('send-addr-book')?.value === '',
    }));
    assert(afterPick.destFilled === savedAddr, `expected picking an entry to fill the destination field, got "${afterPick.destFilled}"`);
    assert(afterPick.selectReset, 'expected the picker to reset to its placeholder after applying, so it reads as a shortcut, not a second source of truth');
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

suite.register('Live: Settings\' Address Book card lists saved entries and Remove actually deletes them from storage', async () => {
  await withPage(async (page, { pageErrors }) => {
    const signedUp = await freshSignup(page, { name: 'AB Test 3', email: 'abtest3@test.com', domain: 'abtest3' });
    assert(signedUp, 'signup failed');
    await page.evaluate(() => window.showProfile());
    await page.waitForTimeout(300);
    await page.evaluate(() => window.tourSkip && window.tourSkip());

    await page.evaluate(() => window.addToAddrBook('rSettingsAddrBookTest0000000000000000', 'Settings Entry'));
    await page.evaluate(() => window.switchProfileTab('settings'));
    await page.waitForTimeout(300);

    const listedBefore = await page.evaluate(() => document.getElementById('settings-addrbook-list')?.innerHTML.includes('Settings Entry'));
    assert(listedBefore, 'expected the Settings Address Book card to list the saved entry');

    await page.evaluate(() => {
      [...document.querySelectorAll('#settings-addrbook-list button')].find(b => b.textContent.includes('Remove'))?.click();
    });
    await page.waitForTimeout(200);
    const afterRemove = await page.evaluate(() => ({
      goneFromList: !document.getElementById('settings-addrbook-list')?.innerHTML.includes('Settings Entry'),
      goneFromStorage: !(JSON.parse(localStorage.getItem('nalulf_addr_book') || '[]')).some(e => e.label === 'Settings Entry'),
    }));
    assert(afterRemove.goneFromList, 'expected Remove to update the visible list immediately');
    assert(afterRemove.goneFromStorage, 'expected Remove to actually delete the entry from persisted storage, not just hide it');
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
