// Regression guard for the wallet-card "⋯" overflow menu (Trustlines /
// Security Actions / Set Active / Remove Wallet), added to declutter the
// wallet card's action row down to the 4 most-used buttons (Send/Receive/
// Inspect/Details).
//
// Two real bugs were found and fixed while building this, both worth
// guarding against regressing back to:
//
// 1. Render-state race: the menu's open/closed state was originally pure
//    DOM manipulation (toggling a `hidden` attribute), which an unrelated
//    renderWalletList() re-render (e.g. a balance-fetch tick completing)
//    could silently undo mid-use, closing the menu out from under the user
//    with no interaction on their part. Fixed by tracking it as real
//    module-level state (_openMoreMenuWalletId) that survives a rebuild —
//    the same pattern already used for the wallet drawer's expand state.
//
// 2. Invisible-despite-correct-state: .wcard needs BOTH overflow:hidden
//    (rounded corners / decorative gradient) and backdrop-filter (its
//    blur). backdrop-filter, like transform/filter/perspective, makes its
//    element the containing block for position:fixed descendants too — so
//    a dropdown nested inside .wcard could never actually anchor itself to
//    the viewport via position:fixed, no matter its own positioning, and
//    was rendering clipped/off-screen despite a correct (not-hidden) DOM
//    state. Fixed by hoisting the menu OUT of the card entirely: one
//    shared #wcard-more-menu-shared element mounted at body level (the
//    same "single shared overlay" pattern already used for the Evidence
//    Inspector / account-peek modal), repositioned via JS to the clicked
//    button's actual screen coordinates each time it opens.
import { withPage, freshSignup, makeSuite, assert } from './helpers.mjs';

const suite = makeSuite('Wallet Card Overflow Menu');

async function importTestWallet(page, label) {
  await page.addScriptTag({ url: 'https://cdn.jsdelivr.net/npm/xrpl@4.2.5/build/xrpl-latest-min.js' });
  const { seed, address } = await page.evaluate(() => {
    const w = window.xrpl.Wallet.generate();
    return { seed: w.seed, address: w.address };
  });
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
  return address;
}

suite.register('Primary row shows exactly Send/Receive/Inspect/Details, plus a "⋯" trigger', async () => {
  await withPage(async (page, { pageErrors }) => {
    const ok = await freshSignup(page, { name: 'WCM Test', email: 'wcm1@test.com', domain: 'wcm1' });
    assert(ok, 'signup failed');
    await page.evaluate(() => window.showProfile());
    await page.waitForTimeout(400);
    await page.evaluate(() => window.tourSkip && window.tourSkip());
    await importTestWallet(page, 'WCM Wallet');
    await page.waitForTimeout(200);

    const row = await page.evaluate(() => {
      const card = [...document.querySelectorAll('.wcard')].find(c => c.textContent.includes('WCM Wallet'));
      const actions = card?.querySelector('.wcard-actions');
      return {
        buttonTexts: [...(actions?.querySelectorAll(':scope > .wcard-btn') || [])].map(b => b.textContent.trim()),
        hasMore: !!actions?.querySelector('.wcard-btn--more'),
      };
    });
    assert(row.buttonTexts.some(t => t.includes('Send')), 'expected a Send button');
    assert(row.buttonTexts.some(t => t.includes('Receive')), 'expected a Receive button');
    assert(row.buttonTexts.some(t => t.includes('Inspect')), 'expected an Inspect button');
    assert(row.buttonTexts.some(t => t.includes('Details')), 'expected a Details button');
    assert(row.buttonTexts.length === 4, `expected exactly 4 primary buttons, got ${row.buttonTexts.length}: ${JSON.stringify(row.buttonTexts)}`);
    assert(row.hasMore, 'expected a "⋯" overflow trigger button');
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

suite.register('"⋯" opens a real, visible, on-screen menu with Trustlines/Security Actions/Set Active/Remove', async () => {
  await withPage(async (page, { pageErrors }) => {
    const ok = await freshSignup(page, { name: 'WCM Test', email: 'wcm2@test.com', domain: 'wcm2' });
    assert(ok, 'signup failed');
    await page.evaluate(() => window.showProfile());
    await page.waitForTimeout(400);
    await page.evaluate(() => window.tourSkip && window.tourSkip());
    await importTestWallet(page, 'WCM Wallet 2');
    await page.waitForTimeout(200);

    await page.evaluate(() => {
      const card = [...document.querySelectorAll('.wcard')].find(c => c.textContent.includes('WCM Wallet 2'));
      card.querySelector('.wcard-btn--more').click();
    });
    await page.waitForTimeout(150);

    const state = await page.evaluate(() => {
      const menu = document.getElementById('wcard-more-menu-shared');
      const card = [...document.querySelectorAll('.wcard')].find(c => c.textContent.includes('WCM Wallet 2'));
      const btn = card.querySelector('.wcard-btn--more');
      const menuRect = menu.getBoundingClientRect();
      const menuStyle = getComputedStyle(menu);
      return {
        hidden: menu.hasAttribute('hidden'),
        items: [...menu.querySelectorAll('button')].map(b => b.textContent.trim()),
        ariaExpanded: btn.getAttribute('aria-expanded'),
        display: menuStyle.display,
        opacity: parseFloat(menuStyle.opacity),
        rect: { top: menuRect.top, left: menuRect.left, right: menuRect.right, bottom: menuRect.bottom, width: menuRect.width, height: menuRect.height },
        viewport: { w: window.innerWidth, h: window.innerHeight },
      };
    });

    assert(!state.hidden, 'expected the menu to not be hidden after clicking "⋯"');
    assert(state.display === 'flex', `expected computed display:flex, got ${state.display}`);
    assert(state.opacity === 1, `expected full opacity, got ${state.opacity}`);
    assert(state.ariaExpanded === 'true', 'expected the trigger button aria-expanded to be "true"');
    assert(state.items.some(t => t.includes('Trustlines')), 'expected a Trustlines item');
    assert(state.items.some(t => t.includes('Security Actions')), 'expected a Security Actions item');
    assert(state.items.some(t => t.includes('Set Active')), 'expected a Set Active item');
    assert(state.items.some(t => t.includes('Remove Wallet')), 'expected a Remove Wallet item');

    // The core visibility bug this test guards against: a real (not just
    // logical) on-screen position, actually inside the viewport bounds —
    // not clipped by an ancestor's overflow:hidden/backdrop-filter, and not
    // pushed off either edge.
    assert(state.rect.width > 0 && state.rect.height > 0, 'expected the menu to have real, non-zero rendered dimensions');
    assert(state.rect.top >= 0 && state.rect.bottom <= state.viewport.h, `expected the menu to be vertically within the viewport, got top=${state.rect.top} bottom=${state.rect.bottom} viewportH=${state.viewport.h}`);
    assert(state.rect.left >= 0 && state.rect.right <= state.viewport.w, `expected the menu to be horizontally within the viewport, got left=${state.rect.left} right=${state.rect.right} viewportW=${state.viewport.w}`);

    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

suite.register('Menu closes on outside click, on Escape, and on clicking a menu item', async () => {
  await withPage(async (page, { pageErrors }) => {
    const ok = await freshSignup(page, { name: 'WCM Test', email: 'wcm3@test.com', domain: 'wcm3' });
    assert(ok, 'signup failed');
    await page.evaluate(() => window.showProfile());
    await page.waitForTimeout(400);
    await page.evaluate(() => window.tourSkip && window.tourSkip());
    await importTestWallet(page, 'WCM Wallet 3');
    await page.waitForTimeout(200);

    const openMenu = () => page.evaluate(() => {
      const card = [...document.querySelectorAll('.wcard')].find(c => c.textContent.includes('WCM Wallet 3'));
      card.querySelector('.wcard-btn--more').click();
    });
    const isHidden = () => page.evaluate(() => document.getElementById('wcard-more-menu-shared').hasAttribute('hidden'));

    // Outside click
    await openMenu();
    await page.waitForTimeout(100);
    assert(!(await isHidden()), 'expected menu open before outside click');
    await page.mouse.click(5, 5);
    await page.waitForTimeout(100);
    assert(await isHidden(), 'expected menu to close on outside click');

    // Escape
    await openMenu();
    await page.waitForTimeout(100);
    assert(!(await isHidden()), 'expected menu open before Escape');
    await page.keyboard.press('Escape');
    await page.waitForTimeout(100);
    assert(await isHidden(), 'expected menu to close on Escape');

    // Clicking a menu item (Set Active)
    await openMenu();
    await page.waitForTimeout(100);
    const clicked = await page.evaluate(() => {
      const menu = document.getElementById('wcard-more-menu-shared');
      const btn = [...menu.querySelectorAll('button')].find(b => b.textContent.includes('Set Active'));
      if (!btn) return false;
      btn.click();
      return true;
    });
    assert(clicked, 'expected to find a "Set Active" menu item to click (wallet may already be active)');
    await page.waitForTimeout(150);
    assert(await isHidden(), 'expected menu to close after clicking a menu item');

    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

suite.register('Menu survives an unrelated wallet-list re-render (does not silently snap shut)', async () => {
  await withPage(async (page, { pageErrors }) => {
    const ok = await freshSignup(page, { name: 'WCM Test', email: 'wcm4@test.com', domain: 'wcm4' });
    assert(ok, 'signup failed');
    await page.evaluate(() => window.showProfile());
    await page.waitForTimeout(400);
    await page.evaluate(() => window.tourSkip && window.tourSkip());
    await importTestWallet(page, 'WCM Wallet 4');
    await page.waitForTimeout(200);

    await page.evaluate(() => {
      const card = [...document.querySelectorAll('.wcard')].find(c => c.textContent.includes('WCM Wallet 4'));
      card.querySelector('.wcard-btn--more').click();
    });
    await page.waitForTimeout(100);

    // filterWallets('') triggers a full renderWalletList() rebuild, exactly
    // like the balance-fetch/activity-tick re-renders that originally raced
    // the old DOM-only implementation.
    const after = await page.evaluate(() => {
      window.filterWallets && window.filterWallets('');
      const menu = document.getElementById('wcard-more-menu-shared');
      const card = [...document.querySelectorAll('.wcard')].find(c => c.textContent.includes('WCM Wallet 4'));
      const btn = card?.querySelector('.wcard-btn--more');
      return {
        stillOpen: !menu.hasAttribute('hidden'),
        ariaExpanded: btn?.getAttribute('aria-expanded'),
      };
    });
    assert(after.stillOpen, 'expected the menu to remain open across an unrelated renderWalletList() rebuild');
    assert(after.ariaExpanded === 'true', 'expected the (rebuilt) trigger button to be re-marked aria-expanded="true"');

    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
