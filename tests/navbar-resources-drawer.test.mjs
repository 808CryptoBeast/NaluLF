// Regression guard for the top navbar rework: a "Resources" dropdown
// (White Paper / Roadmap) visible on both the landing page and the
// logged-in dashboard, plus a mobile hamburger drawer replacing the old
// pattern of hiding the price/connection/⌘K/help cluster one item at a
// time across several separate breakpoints.
import { withPage, makeSuite, assert } from './helpers.mjs';

const suite = makeSuite('Navbar — Resources Dropdown & Mobile Drawer');

suite.register('Desktop landing: Resources dropdown opens on click, closes on outside click, and links to both docs', async () => {
  await withPage(async (page, { pageErrors }) => {
    await page.setViewportSize({ width: 1400, height: 900 });
    await page.waitForTimeout(500);

    const before = await page.evaluate(() => ({
      hamburgerVisible: getComputedStyle(document.getElementById('navbar-hamburger')).display !== 'none',
      menuVisible: getComputedStyle(document.getElementById('navbar-resources-menu')).display !== 'none',
    }));
    assert(before.hamburgerVisible === false, 'expected the hamburger to be hidden on desktop');
    assert(before.menuVisible === false, 'expected the Resources menu closed by default — regression guard for the [hidden]-vs-author-CSS specificity bug');

    await page.click('#navbar-resources-btn');
    await page.waitForTimeout(150);
    const opened = await page.evaluate(() => {
      const menu = document.getElementById('navbar-resources-menu');
      return {
        visible: getComputedStyle(menu).display !== 'none',
        hasWhitepaper: !!menu.querySelector('a[href="./Whitepaper.html"]'),
        hasRoadmap: !!menu.querySelector('a[href="./Roadmap.html"]'),
      };
    });
    assert(opened.visible, 'expected the Resources menu to open on click');
    assert(opened.hasWhitepaper, 'expected a White Paper link in the Resources menu');
    assert(opened.hasRoadmap, 'expected a Roadmap link in the Resources menu');

    await page.click('body', { position: { x: 5, y: 5 } });
    await page.waitForTimeout(150);
    const closedAfterOutsideClick = await page.evaluate(() => getComputedStyle(document.getElementById('navbar-resources-menu')).display === 'none');
    assert(closedAfterOutsideClick, 'expected clicking outside to close the Resources menu');
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

suite.register('Mobile landing: hamburger opens the drawer (Resources + price), Escape closes it, and the nested Resources dropdown still works inside it', async () => {
  await withPage(async (page, { pageErrors }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await page.waitForTimeout(500);

    const before = await page.evaluate(() => ({
      hamburgerVisible: getComputedStyle(document.getElementById('navbar-hamburger')).display !== 'none',
      drawerVisible: getComputedStyle(document.getElementById('navbar-drawer')).display !== 'none',
    }));
    assert(before.hamburgerVisible, 'expected the hamburger to be visible on mobile');
    assert(before.drawerVisible === false, 'expected the drawer closed by default on mobile');

    await page.click('#navbar-hamburger');
    await page.waitForTimeout(250);
    const opened = await page.evaluate(() => ({
      drawerVisible: getComputedStyle(document.getElementById('navbar-drawer')).display !== 'none',
      ariaExpanded: document.getElementById('navbar-hamburger').getAttribute('aria-expanded'),
    }));
    assert(opened.drawerVisible, 'expected the drawer to open on hamburger click');
    assert(opened.ariaExpanded === 'true', 'expected aria-expanded to flip to true when the drawer opens');

    await page.click('#navbar-resources-btn');
    await page.waitForTimeout(150);
    const resourcesOpenInsideDrawer = await page.evaluate(() => getComputedStyle(document.getElementById('navbar-resources-menu')).display !== 'none');
    assert(resourcesOpenInsideDrawer, 'expected the Resources dropdown to still open correctly nested inside the mobile drawer');

    await page.keyboard.press('Escape');
    await page.waitForTimeout(150);
    const afterEscape = await page.evaluate(() => ({
      drawerOpen: document.getElementById('main-nav').classList.contains('nav-open'),
      menuVisible: getComputedStyle(document.getElementById('navbar-resources-menu')).display !== 'none',
    }));
    assert(afterEscape.drawerOpen === false, 'expected Escape to close the mobile drawer');
    assert(afterEscape.menuVisible === false, 'expected Escape to also close the nested Resources menu');
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

suite.register('Desktop dashboard: price/connection/⌘K/help are inline and Resources stays visible after entering the app', async () => {
  await withPage(async (page, { pageErrors }) => {
    await page.setViewportSize({ width: 1400, height: 900 });
    await page.waitForTimeout(400);
    await page.evaluate(() => { window.connectXRPL?.(); window.showDashboard(); });
    await page.waitForTimeout(800);

    const state = await page.evaluate(() => ({
      connDisplay: getComputedStyle(document.getElementById('navbar-conn')).display,
      cmdkDisplay: getComputedStyle(document.getElementById('cmdk-hint')).display,
      helpDisplay: getComputedStyle(document.getElementById('help-trigger')).display,
      resourcesVisible: getComputedStyle(document.getElementById('navbar-resources')).display !== 'none',
    }));
    assert(state.connDisplay !== 'none', 'expected connection status visible in the dashboard');
    assert(state.cmdkDisplay !== 'none', 'expected the ⌘K hint visible in the dashboard');
    assert(state.helpDisplay !== 'none', 'expected the help button visible in the dashboard');
    assert(state.resourcesVisible, 'expected Resources to remain visible after entering the dashboard, not just on the landing page');
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

suite.register('Mobile dashboard: opening the drawer reveals the real ⌘K text label and a "Help & Glossary" label instead of staying icon-only', async () => {
  await withPage(async (page, { pageErrors }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await page.waitForTimeout(400);
    await page.evaluate(() => { window.connectXRPL?.(); window.showDashboard(); });
    await page.waitForTimeout(800);
    await page.click('#navbar-hamburger');
    await page.waitForTimeout(250);

    const state = await page.evaluate(() => {
      const cmdkText = document.querySelector('#cmdk-hint .cmdk-hint-text');
      const helpAfter = getComputedStyle(document.getElementById('help-trigger'), '::after').content;
      return {
        cmdkTextVisible: cmdkText ? getComputedStyle(cmdkText).display !== 'none' : false,
        helpLabel: helpAfter,
      };
    });
    assert(state.cmdkTextVisible, 'expected the ⌘K hint text to be readable inside the open mobile drawer, not icon-only');
    assert(state.helpLabel.includes('Help'), `expected a real "Help & Glossary" label inside the drawer, got: ${state.helpLabel}`);
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

suite.register('Navigating pages closes an open mobile drawer', async () => {
  await withPage(async (page, { pageErrors }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await page.waitForTimeout(400);
    await page.click('#navbar-hamburger');
    await page.waitForTimeout(200);
    assert(await page.evaluate(() => document.getElementById('main-nav').classList.contains('nav-open')), 'expected the drawer to be open before navigating');

    await page.evaluate(() => { window.connectXRPL?.(); window.showDashboard(); });
    await page.waitForTimeout(500);
    const stillOpen = await page.evaluate(() => document.getElementById('main-nav').classList.contains('nav-open'));
    assert(stillOpen === false, 'expected switching pages to close a left-open mobile drawer');
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
