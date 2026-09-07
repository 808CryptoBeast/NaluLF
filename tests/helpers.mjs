// Shared test utilities. Tests run against the BUILT app (www/), matching
// what actually ships — run `npm run build` before `npm test` if source
// files changed (run-all.mjs does this automatically).
import { chromium } from 'playwright';
import { spawn, execSync } from 'child_process';
import { fileURLToPath } from 'url';
import path from 'path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const WWW_ROOT = path.join(__dirname, '..', 'www');

let _nextPort = 9500;

export async function startServer() {
  const port = _nextPort++;
  const server = spawn('python3', ['-m', 'http.server', String(port)], { cwd: WWW_ROOT, shell: true });
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('Server did not start within 5s')), 5000);
    server.stdout?.on('data', () => {});
    // python's http.server logs to stderr on startup on some platforms —
    // just give it a moment rather than parsing output, matching the
    // pattern used throughout this session's ad-hoc verification scripts.
    setTimeout(() => { clearTimeout(timer); resolve(); }, 900);
  });
  return { server, port, baseUrl: `http://127.0.0.1:${port}` };
}

export function stopServer(server) {
  if (!server?.pid) return;
  try {
    // On Windows, server.kill() only signals the shell wrapper spawned by
    // {shell:true}, not the actual python.exe grandchild process — taskkill
    // with /T (tree) is required to actually free the port.
    execSync(`taskkill /pid ${server.pid} /T /F`, { stdio: 'ignore' });
  } catch { /* already exited */ }
}

/** Launches a browser, runs fn(page), always cleans up — even on failure. */
export async function withPage(fn) {
  const { server, baseUrl } = await startServer();
  const browser = await chromium.launch();
  const page = await browser.newPage();
  const pageErrors = [];
  page.on('pageerror', (e) => pageErrors.push(String(e)));
  try {
    await page.goto(`${baseUrl}/index.html`);
    return await fn(page, { pageErrors, baseUrl });
  } finally {
    await browser.close().catch(() => {});
    stopServer(server);
  }
}

/** Connects to live XRPL mainnet and shows the dashboard — the common
 *  precondition for every Inspector/network test. */
export async function connectAndShowDashboard(page, { timeout = 20000 } = {}) {
  await page.waitForFunction(() => window.connectXRPL, { timeout: 8000 });
  await page.evaluate(() => window.connectXRPL());
  await page.waitForFunction(() => document.getElementById('connDot')?.classList.contains('live'), { timeout });
  await page.evaluate(() => window.showDashboard());
}

/** Loads an address into the Inspector and waits for analysis to finish.
 *  Uses real mainnet data — live-data drift across runs is expected and
 *  should not be asserted on exact scores/counts, only structural facts. */
export async function inspectAddress(page, addr, { timeout = 90000 } = {}) {
  await page.evaluate(() => window.switchTab(null, 'inspector'));
  await page.evaluate((a) => window.inspectorLoadAddr(a), addr);
  await page.waitForSelector('#section-evidence-matrix .evmatrix-row', { timeout }).catch(() => {});
  await page.waitForTimeout(1200);
}

/** Deterministic captcha bypass (CAPTCHA_WORDS[0] is fixed, so pinning
 *  Math.random to 0 always draws the same word) — the pattern established
 *  throughout this session's signup verification. */
export async function freshSignup(page, { name, email, domain, password = 'Sup3rSecret1' }) {
  await page.evaluate(() => { window.__origRandom = Math.random; Math.random = () => 0; });
  await page.evaluate(() => window.showAuthView('signup'));
  await page.waitForTimeout(150);
  const ok = await page.evaluate(async ({ name, email, domain, password }) => {
    document.getElementById('inp-signup-name').value = name;
    document.getElementById('inp-signup-email').value = email;
    if (domain != null) document.getElementById('inp-signup-domain').value = domain;
    document.getElementById('inp-signup-pass').value = password;
    document.getElementById('inp-signup-confirm').value = password;
    window.refreshCaptcha();
    document.getElementById('inp-captcha').value = 'XRPL'; // CAPTCHA_WORDS[0] under Math.random=0
    await window.submitSignUp();
    await new Promise((r) => setTimeout(r, 250));
    return !document.getElementById('auth-error')?.textContent;
  }, { name, email, domain, password });
  await page.evaluate(() => { Math.random = window.__origRandom; });
  await page.evaluate(() => document.getElementById('celebrate-continue-btn')?.click());
  await page.waitForTimeout(200);
  return ok;
}

/** Minimal test runner: register(name, fn), fn throws on failure (use
 *  assert()), returns a summary. Kept dependency-free rather than pulling
 *  in a test framework for a suite this size. */
export function makeSuite(suiteName) {
  const cases = [];
  const register = (name, fn) => cases.push({ name, fn });
  const run = async () => {
    let pass = 0, fail = 0;
    console.log(`\n▶ ${suiteName}`);
    for (const { name, fn } of cases) {
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
    return { suiteName, pass, fail, total: cases.length };
  };
  return { register, run };
}

export function assert(cond, message) {
  if (!cond) throw new Error(message || 'Assertion failed');
}
