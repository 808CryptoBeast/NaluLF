// Regression coverage for "Share inspection as link (URL fragment — no
// server needed)" (roadmap: Analytics). A hash fragment (#inspect=rXXXX),
// not a query param — this app already uses the query string for DEX chart
// view state (pair/tf/token/ind, see profile.js's _persistChartViewState) —
// and a fragment is never sent to any server, matching "no server needed"
// literally. Consumed by main.js's boot sequence, which waits for BOTH a
// real session (existing or freshly signed-in) AND a real XRPL connection
// before auto-opening it, since runInspect() silently no-ops while
// disconnected.
import { withPage, freshSignup, makeSuite, assert } from './helpers.mjs';

const suite = makeSuite('Share Inspection Link');

const SOLO_ISSUER = 'rsoLo2S1kiGeCcn6hCUXVrCpGMWLrRrLZz';

suite.register('shareInspectionLink() generates a real #inspect= fragment for the currently-inspected address', async () => {
  await withPage(async (page, { pageErrors }) => {
    await page.evaluate(() => window.connectXRPL && window.connectXRPL());
    await page.waitForFunction(() => document.getElementById('connDot')?.classList.contains('live'), { timeout: 15000 }).catch(() => {});
    await page.evaluate(() => window.showDashboard && window.showDashboard());
    await page.waitForTimeout(300);
    await page.evaluate(() => window.switchTab && window.switchTab(document.querySelector('[data-tab="inspector"]'), 'inspector'));
    await page.waitForTimeout(300);
    await page.evaluate((a) => window.inspectorLoadAddr && window.inspectorLoadAddr(a), SOLO_ISSUER);
    await page.waitForFunction(() => document.querySelector('#section-evidence-matrix .evmatrix-row'), { timeout: 30000 }).catch(() => {});
    await page.waitForTimeout(500);

    const url = await page.evaluate((addr) => {
      // Exercise the exact same construction shareInspectionLink() uses,
      // via window._lastInspectResult, without depending on clipboard
      // permissions being grantable in a headless CI-style context.
      window._lastInspectResult = { ...(window._lastInspectResult || {}), addr };
      let captured = null;
      const origWrite = navigator.clipboard?.writeText?.bind(navigator.clipboard);
      if (navigator.clipboard) navigator.clipboard.writeText = (t) => { captured = t; return Promise.resolve(); };
      window.shareInspectionLink();
      if (navigator.clipboard && origWrite) navigator.clipboard.writeText = origWrite;
      return captured;
    }, SOLO_ISSUER);
    assert(url, 'expected shareInspectionLink to write a real URL to the clipboard');
    assert(url.includes(`#inspect=${SOLO_ISSUER}`), `expected the URL to carry a real #inspect= fragment for the inspected address, got: "${url}"`);
    assert(!url.includes('?'), 'expected a hash fragment, not a query param — this app already uses the query string for DEX chart view state');
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

suite.register('Live: loading the app fresh with #inspect= in the URL, for a session that already exists, auto-opens that exact inspection and clears the fragment afterward', async () => {
  await withPage(async (page, { pageErrors, baseUrl }) => {
    const ok = await freshSignup(page, { name: 'Share Test', email: 'sharetest@test.com', domain: 'sharetest' });
    assert(ok, 'signup failed');

    // A real full reload (not a same-document hash-only navigation, which
    // would never re-fire DOMContentLoaded and so never re-run the boot
    // logic this feature depends on) landing directly on a shared link,
    // with a session that already exists on this device.
    await page.goto('about:blank');
    await page.goto(`${baseUrl}/index.html#inspect=${SOLO_ISSUER}`, { waitUntil: 'domcontentloaded' });
    // SOLO is a high-volume issuer whose full pagination can legitimately
    // run well past 30s under live mainnet RPC load — matching the same
    // 120s budget already used for SOLO elsewhere (e.g.
    // wallet-age-genesis-anchor.test.mjs), rather than a tighter timeout
    // that was timing out on real-but-slow completions, not stuck ones.
    // waitForSelector, not waitForFunction: this Playwright version's
    // waitForFunction(fn, options) 2-arg form silently treats `options` as
    // `arg` and falls back to its own 30000ms default regardless of what's
    // passed — confirmed empirically. waitForSelector(selector, options)
    // has no such ambiguity (selector is never a function) and is what
    // inspectAddress() in helpers.mjs already uses correctly for this exact
    // same wait elsewhere in the suite.
    await page.waitForSelector('#section-evidence-matrix .evmatrix-row', { timeout: 120000 });
    await page.waitForTimeout(300);

    const state = await page.evaluate(() => ({
      onInspectorTab: document.body.className.includes('inspector'),
      addrFieldValue: document.getElementById('inspect-addr')?.value,
      hashCleared: location.hash === '',
    }));
    assert(state.onInspectorTab, 'expected a shared link to land directly on the Inspector tab, not the dashboard default');
    assert(state.addrFieldValue === SOLO_ISSUER, `expected the shared address to be auto-filled and inspected, got "${state.addrFieldValue}"`);
    assert(state.hashCleared, 'expected the #inspect= fragment to be cleared after being applied, so it can\'t re-trigger on a later internal navigation');
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

suite.register('Live: a visitor with NO existing session who opens a shared link is taken to sign-in first, and the pending inspection auto-applies right after they sign up', async () => {
  await withPage(async (page, { pageErrors, baseUrl }) => {
    // withPage already navigated to index.html (no hash) once — going
    // straight to the same path+hash from here would be a same-document
    // navigation (DOMContentLoaded never refires), so force a real reload
    // via about:blank first, exactly like the previous test does.
    await page.goto('about:blank');
    await page.goto(`${baseUrl}/index.html#inspect=${SOLO_ISSUER}`, { waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(500);

    const preSignup = await page.evaluate(() => ({
      hashStillPending: location.hash.includes('inspect='),
      notYetOnInspector: !document.body.className.includes('inspector'),
    }));
    assert(preSignup.hashStillPending, 'expected the fragment to remain pending (not consumed) while there is no session yet');
    assert(preSignup.notYetOnInspector, 'expected a signed-out visitor to land on the normal landing page first, not be force-navigated anywhere');

    const ok = await freshSignup(page, { name: 'Share Test 2', email: 'sharetest2@test.com', domain: 'sharetest2' });
    assert(ok, 'signup failed');
    // Same 120s SOLO budget as the previous test — see its comment on why
    // this is waitForSelector, not waitForFunction.
    await page.waitForSelector('#section-evidence-matrix .evmatrix-row', { timeout: 120000 });
    await page.waitForTimeout(300);

    const postSignup = await page.evaluate(() => ({
      onInspectorTab: document.body.className.includes('inspector'),
      addrFieldValue: document.getElementById('inspect-addr')?.value,
      hashCleared: location.hash === '',
    }));
    assert(postSignup.onInspectorTab, 'expected the pending shared inspection to auto-open right after a fresh signup completes');
    assert(postSignup.addrFieldValue === SOLO_ISSUER, `expected the originally-shared address to be the one inspected, got "${postSignup.addrFieldValue}"`);
    assert(postSignup.hashCleared, 'expected the fragment to be cleared once consumed');
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
