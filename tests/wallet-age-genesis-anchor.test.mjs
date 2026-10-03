// Regression guard for a real reported bug: a high-volume, long-established
// account (SOLO's issuer, rsoLo2S1kiGeCcn6hCUXVrCpGMWLrRrLZz — a token
// popular enough to generate thousands of transactions within a couple of
// days) was showing "Wallet Age: 2 days old" with a "⚠ New wallet" scare
// badge, when the account is actually ~7 years old.
//
// Root cause: Pass 1 (newest→oldest) stops once it hits MAX_TX (a tx-count
// cap, not a true pagination end), leaving `marker1` truthy — i.e. there IS
// more history beyond the fetched window. Pass 2 (a single oldest→newest
// page meant to anchor genesis) was gated on `allRaw.length < MAX_TX`
// instead of on whether Pass 1 actually reached genesis — so for any
// account whose MOST RECENT activity alone exceeds MAX_TX, Pass 2 never
// ran, and wallet age was computed from the oldest transaction within
// Pass 1's capped (and, for a busy account, recent-only) window.
//
// Fixed by gating Pass 2 on `marker1` (Pass 1 genuinely incomplete) rather
// than the raw transaction count, so the genesis-anchoring page always runs
// when it's actually needed — regardless of how much OTHER data Pass 1
// already pulled in.
import { withPage, connectAndShowDashboard, inspectAddress, assert } from './helpers.mjs';

const suite = { register: [], run: async () => {
  let pass = 0, fail = 0;
  console.log('\n▶ Wallet Age — Genesis Anchor Pass');
  for (const { name, fn } of suite.register) {
    try { await fn(); console.log(`  PASS  ${name}`); pass++; }
    catch (err) { console.log(`  FAIL  ${name}`); console.log(`        ${err?.stack || err}`); fail++; }
  }
  return { pass, fail, total: suite.register.length };
}};
const test = (name, fn) => suite.register.push({ name, fn });

const SOLO_ISSUER = 'rsoLo2S1kiGeCcn6hCUXVrCpGMWLrRrLZz';

test('A high-volume, long-established issuer (SOLO) reads as years old, not days — and never shows the "New wallet" badge', async () => {
  await withPage(async (page, { pageErrors }) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, SOLO_ISSUER, { timeout: 120000 });

    const result = await page.evaluate(() => {
      const cell = [...document.querySelectorAll('.acct-cell')].find(c => /Wallet Age/.test(c.textContent || ''));
      return {
        text: cell ? cell.textContent.replace(/\s+/g, ' ').trim() : null,
        hasNewWalletBadge: !!cell?.querySelector('.acct-cell-new-badge'),
      };
    });

    assert(result.text, 'expected a Wallet Age cell to render');
    assert(/years old/.test(result.text), `expected a multi-year age read for a long-established high-volume issuer, got: "${result.text}"`);
    assert(!/\bdays? old\b/.test(result.text), `expected NO "days old" read for this account, got: "${result.text}"`);
    assert(!result.hasNewWalletBadge, 'expected the "⚠ New wallet" badge to NOT render for a 7+ year old account');
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
