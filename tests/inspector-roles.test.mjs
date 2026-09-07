// Role classification must never default an unclassified account to
// "Personal" (spec: "General / Unclassified is not Personal"), and a
// verified token issuer must never be misread as personal either.
// Regression guard for the account-role work done earlier this session.
import { withPage, connectAndShowDashboard, inspectAddress, makeSuite, assert } from './helpers.mjs';

const SOLO_ISSUER = 'rsoLo2S1kiGeCcn6hCUXVrCpGMWLrRrLZz'; // real, verified token issuer
const GENESIS_BLACKHOLE = 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh'; // real, blackholed, not a token issuer

const suite = makeSuite('Account Role Classification');

suite.register('SOLO issuer shows the Account Context block with a Token Issuer badge, never "Personal"', async () => {
  await withPage(async (page) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, SOLO_ISSUER);
    // Scoped to #quick-verdict-body (the hero/role block itself), not the
    // whole page — the full page legitimately mentions "Token Issuer"
    // elsewhere too (e.g. a Notable Counterparties callout naming a KNOWN
    // issuer this account has transacted with, which is a different,
    // correct feature unrelated to this account's own role). innerHTML,
    // not innerText, since a collapsed section makes innerText return
    // empty for content that's genuinely present in the DOM.
    const bodyText = await page.evaluate(() => document.getElementById('quick-verdict-body')?.innerHTML || '');
    assert(bodyText.includes('Account context'), 'missing "Account context" block');
    assert(bodyText.includes('Token Issuer'), 'missing Token Issuer badge/role');
    assert(!bodyText.includes('Personal / general-purpose account') && !bodyText.includes('Personal wallet'), 'a verified issuer was labeled Personal');
  });
});

suite.register('Genesis/blackhole account shows "General / Unclassified" with an explicit non-personal disclaimer, never Token Issuer', async () => {
  await withPage(async (page) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, GENESIS_BLACKHOLE);
    // Scoped to #quick-verdict-body (the hero/role block itself), not the
    // whole page — the full page legitimately mentions "Token Issuer"
    // elsewhere too (e.g. a Notable Counterparties callout naming a KNOWN
    // issuer this account has transacted with, which is a different,
    // correct feature unrelated to this account's own role). innerHTML,
    // not innerText, since a collapsed section makes innerText return
    // empty for content that's genuinely present in the DOM.
    const bodyText = await page.evaluate(() => document.getElementById('quick-verdict-body')?.innerHTML || '');
    assert(bodyText.includes('Account context'), 'missing "Account context" block');
    assert(bodyText.includes('General / Unclassified'), 'unclassified account not labeled General / Unclassified');
    assert(!bodyText.includes('Personal / general-purpose account'), 'an unclassified account was called Personal — the exact false-equivalence this session\'s work was meant to prevent');
    assert(!bodyText.includes('Token Issuer'), 'a non-issuer account was given the Token Issuer badge');
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
