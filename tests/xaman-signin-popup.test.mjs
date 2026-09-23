// Regression guard for a live-reported bug: signing in via Xaman's popup
// completed successfully (scan + approve worked), but the ORIGINAL tab never
// left its "Waiting for Xaman…" state and the popup itself never closed —
// only a manual refresh of the original tab picked up the finished session.
//
// Root cause (traced into xumm-oauth2-pkce's own bundle): preloadXummSdk()
// runs on every page load, including inside the popup once Xumm's server
// redirects it back to our own redirectUrl with the grant in its URL —
// constructing a second, redundant XummPkce instance there that
// independently completes (and *consumes*, since the grant is one-time-use)
// the token exchange entirely within the popup's own JS context. That
// instance's vault/session writes land in real (shared) localStorage, but
// the popup then has no reason of its own to close, and the ORIGINAL tab's
// own in-flight authorize() call — a separate instance, separate Promise —
// never observes any of it and is left waiting on a grant that's already
// been spent.
//
// The fix: _isXummPopup() detects "I am the popup, not the tab that asked to
// sign in" (window.opener set) and, in that context, closes itself once the
// vault/session are written instead of building the dashboard UI inside a
// throwaway ~600x790 window. The opener, in turn, polls the popup's own
// window handle for `.closed` and — if its own authorize() call never
// settles by the time that happens — re-derives the session from the
// now-linked vault in shared localStorage itself, completing the tab the
// user is actually looking at without requiring a manual refresh.
import { startServer, stopServer } from './helpers.mjs';
import { chromium } from 'playwright';

const suite = { cases: [], register(name, fn) { this.cases.push({ name, fn }); } };
function assert(cond, message) { if (!cond) throw new Error(message || 'Assertion failed'); }

function withTimeout(promise, ms, label) {
  return Promise.race([
    promise,
    new Promise((_, rej) => setTimeout(() => rej(new Error(`TIMEOUT after ${ms}ms: ${label}`)), ms)),
  ]);
}

/** Mounts a mock XummPkce at the browser-CONTEXT level (not page level) —
 *  this is what actually propagates into a popup spawned by window.open(),
 *  reproducing the real desktop flow's two-separate-instances structure. */
async function withXummContext(mockScript, fn) {
  const { server, baseUrl } = await startServer();
  const browser = await chromium.launch();
  const context = await browser.newContext();
  await context.addInitScript(mockScript);
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', (e) => errors.push(String(e)));
  try {
    await page.goto(`${baseUrl}/index.html`, { waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(400);
    return await fn(page, context, { errors });
  } finally {
    await browser.close().catch(() => {});
    stopServer(server);
  }
}

suite.register('The reported bug: popup completes the sign-in independently, closes itself, and the original tab finishes without a manual refresh', async () => {
  await withXummContext(() => {
    window.XummPkce = class {
      constructor() {}
      on() {}
      authorize() {
        // Reproduces the real bug exactly: the popup opens and navigates to
        // our own redirectUrl, but this tab's own authorize() call never
        // resolves — matching what preloadXummSdk()'s redundant instance
        // running inside the popup actually causes.
        window.open(window.location.origin + window.location.pathname + '?authorization_code=TESTCODE&state=xyz', 'XummPkceLogin');
        return new Promise(() => {});
      }
      state() { return Promise.resolve({}); }
    };
  }, async (page, context, { errors }) => {
    const popupPromise = context.waitForEvent('page');
    // Fire-and-forget: startXummSignIn()'s own promise depends on authorize()
    // resolving, which by design never happens in this scenario.
    page.evaluate(() => { window.startXummSignIn(); });
    const popup = await withTimeout(popupPromise, 8000, 'popup opening');
    popup.on('pageerror', (e) => errors.push(`[popup] ${e}`));

    await withTimeout(popup.waitForLoadState('domcontentloaded'), 8000, 'popup domcontentloaded');
    await withTimeout(popup.waitForFunction(() => window._debugFinishXummSignup, { timeout: 6000 }), 8000, 'popup debug hook ready');

    const isPopupCtx = await popup.evaluate(() => window._debugIsXummPopup());
    const isMainCtx = await page.evaluate(() => window._debugIsXummPopup());
    assert(isPopupCtx === true, 'expected _isXummPopup() to be true inside the popup');
    assert(isMainCtx === false, 'expected _isXummPopup() to be false in the tab that called startXummSignIn()');

    // Simulate the popup's own redundant instance completing the exchange —
    // this is real app code (_finishXummSignup), not a mock.
    await withTimeout(
      popup.evaluate(() => window._debugFinishXummSignup('rTESTPOPUP1234567890AB', 'Test Popup User', '', 'test_popup_user')),
      8000, 'popup _debugFinishXummSignup call'
    );

    await withTimeout(new Promise((resolve) => { if (popup.isClosed()) return resolve(); popup.once('close', resolve); }), 5000, 'popup self-close');
    assert(popup.isClosed(), 'expected the popup to close itself once the vault/session were written, not stay open');

    await withTimeout(
      page.waitForFunction(() => document.body.classList.contains('dashboard'), { timeout: 5000 }),
      6000, 'original tab reaching the dashboard via the poll fallback'
    );
    const finalState = await page.evaluate(() => ({
      authOverlayShowing: document.getElementById('auth-overlay')?.classList.contains('show'),
      userName: document.getElementById('user-name')?.textContent,
    }));
    assert(finalState.authOverlayShowing === false, 'expected the auth modal to be closed in the original tab, not left showing "Waiting for Xaman…"');
    assert(finalState.userName === 'Test Popup User', `expected the original tab to pick up the real session from the popup, got userName="${finalState.userName}"`);
    assert(errors.length === 0, `expected zero page errors, got: ${JSON.stringify(errors)}`);
  });
});

suite.register('Normal path: when authorize() resolves in the opener directly (no fallback needed), sign-in still completes cleanly with no spurious error toast', async () => {
  await withXummContext(() => {
    window.XummPkce = class {
      constructor() {}
      on() {}
      authorize() {
        const win = window.open(window.location.origin + window.location.pathname, 'XummPkceLogin');
        return new Promise((resolve) => {
          setTimeout(() => {
            win?.close();
            resolve({ me: { account: 'rHAPPYPATH1234567890AB', name: 'Happy Path User', email: '' } });
          }, 250);
        });
      }
      state() { return Promise.resolve({}); }
    };
  }, async (page, context, { errors }) => {
    await page.evaluate(() => {
      window.__sawToastErr = [];
      const orig = window.toastErr;
      window.toastErr = (msg) => { window.__sawToastErr.push(msg); return orig?.(msg); };
    });
    page.evaluate(() => { window.startXummSignIn(); });
    await withTimeout(page.waitForFunction(() => document.body.classList.contains('dashboard'), { timeout: 8000 }), 9000, 'reaching dashboard via the normal authorize() path');

    const state = await page.evaluate(() => ({
      userName: document.getElementById('user-name')?.textContent,
      sawToastErr: window.__sawToastErr,
    }));
    assert(state.userName === 'Happy Path User', `expected the normal path to still work, got userName="${state.userName}"`);
    assert(state.sawToastErr.length === 0, `expected no error toast when the normal path works fine, got: ${JSON.stringify(state.sawToastErr)}`);
    assert(errors.length === 0, `expected zero page errors, got: ${JSON.stringify(errors)}`);
  });
});

let pass = 0, fail = 0;
console.log('\n▶ Xaman Sign-In — Popup Completion & Auto-Close');
for (const { name, fn } of suite.cases) {
  try {
    await fn();
    console.log(`  PASS  ${name}`);
    pass++;
  } catch (err) {
    console.log(`  FAIL  ${name}`);
    console.log(`        ${err?.stack || err}`);
    fail++;
  }
}
const total = suite.cases.length;
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
