// Regression coverage for real AccountRoot-creation-based wallet-age
// verification (roadmap: XRPL Account Age / Activation Provenance repair).
// Before this, wallet age was ALWAYS derived from "oldest fetched
// transaction's timestamp" — a lower bound at best, and for a high-volume
// account whose Pass-1 fetch window never reaches genesis, sometimes a
// wildly wrong one (see wallet-age-genesis-anchor.test.mjs for that fixed
// bug). This adds a stronger tier of evidence on top: scanning fetched
// transaction metadata for an actual `CreatedNode` of type `AccountRoot`
// matching the inspected address — real, validated, successful ledger
// proof of account activation, not an estimate. When found, wallet age
// becomes genuinely VERIFIED (not just "pagination happened to complete"),
// and the UI surfaces real evidence: creation ledger, transaction hash,
// funding account, initial funding amount.
import { withPage, connectAndShowDashboard, inspectAddress, freshSignup, assert } from './helpers.mjs';

const suite = { register: [], run: async () => {
  let pass = 0, fail = 0;
  console.log('\n▶ AccountRoot Creation Evidence');
  for (const { name, fn } of suite.register) {
    try { await fn(); console.log(`  PASS  ${name}`); pass++; }
    catch (err) { console.log(`  FAIL  ${name}`); console.log(`        ${err?.stack || err}`); fail++; }
  }
  return { pass, fail, total: suite.register.length };
}};
const test = (name, fn) => suite.register.push({ name, fn });

test('_findAccountRootCreationEvidence extracts real evidence from a genuine creation, ignores a failed look-alike, and returns null when no creation event exists', async () => {
  await withPage(async (page, { pageErrors }) => {
    await page.waitForFunction(() => window._debugFindAccountRootCreationEvidence, { timeout: 8000 });

    const result = await page.evaluate(() => {
      const ADDR = 'rNewAccountAAAAAAAAAAAAAAAAAAAAAAA';
      const FUNDER = 'rFunderAccountBBBBBBBBBBBBBBBBBBBBB';
      const genuine = window._debugFindAccountRootCreationEvidence([
        { tx: { Account: ADDR, Destination: FUNDER, TransactionType: 'Payment', hash: 'h2', date: 900000100 }, meta: { TransactionResult: 'tesSUCCESS', AffectedNodes: [] } },
        { tx: { Account: FUNDER, Destination: ADDR, TransactionType: 'Payment', hash: 'h1', date: 900000000, ledger_index: 90000001 }, meta: { TransactionResult: 'tesSUCCESS', AffectedNodes: [
          { CreatedNode: { LedgerEntryType: 'AccountRoot', NewFields: { Account: ADDR, Balance: '20000000' } } },
        ] } },
      ], ADDR);

      const fromFailedTx = window._debugFindAccountRootCreationEvidence([
        { tx: { Account: FUNDER, Destination: ADDR, TransactionType: 'Payment', hash: 'hfail', date: 900000000 }, meta: { TransactionResult: 'tecNO_DST_INSUF_XRP', AffectedNodes: [
          { CreatedNode: { LedgerEntryType: 'AccountRoot', NewFields: { Account: ADDR, Balance: '20000000' } } },
        ] } },
      ], ADDR);

      const noEvidence = window._debugFindAccountRootCreationEvidence([
        { tx: { Account: ADDR, TransactionType: 'Payment', hash: 'h3', date: 900000200 }, meta: { TransactionResult: 'tesSUCCESS', AffectedNodes: [] } },
      ], ADDR);

      return { genuine, fromFailedTx, noEvidence };
    });

    assert(result.genuine?.ledgerIndex === 90000001, `expected ledgerIndex 90000001, got ${JSON.stringify(result.genuine)}`);
    assert(result.genuine?.transactionHash === 'h1', 'expected the creation tx hash to be captured');
    assert(result.genuine?.fundingAccount === 'rFunderAccountBBBBBBBBBBBBBBBBBBBBB', 'expected the funding account to be captured for a Payment-funded creation');
    assert(result.genuine?.initialBalanceDrops === '20000000', 'expected the initial AccountRoot balance to be captured');
    assert(result.fromFailedTx === null, 'expected a failed transaction to NOT count as creation evidence, even with a matching CreatedNode');
    assert(result.noEvidence === null, 'expected null when no AccountRoot creation event exists in the scanned window');
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

test('Live: a genuinely brand-new XRPL testnet account (funded seconds ago via the public faucet) shows a VERIFIED age with real ledger evidence, not an estimate', async () => {
  const faucetRes = await fetch('https://faucet.altnet.rippletest.net/accounts', { method: 'POST', headers: { 'Content-Type': 'application/json' } });
  const faucet = await faucetRes.json();
  const freshAddr = faucet?.account?.address || faucet?.account?.classicAddress;
  assert(freshAddr, `expected the testnet faucet to return a funded account, got: ${JSON.stringify(faucet)}`);
  // Let the funding transaction settle into a validated ledger before inspecting.
  await new Promise(r => setTimeout(r, 4000));

  await withPage(async (page, { pageErrors }) => {
    await connectAndShowDashboard(page);
    await freshSignup(page, { name: 'Test User', email: `test-${Date.now()}@example.com`, domain: 'example.com' });

    await page.evaluate(() => document.querySelector('.net-btn[data-network="xrpl-testnet"]')?.click());
    await page.waitForFunction(() => document.getElementById('connDot')?.classList.contains('live'), { timeout: 25000 });
    await page.waitForTimeout(800);

    await inspectAddress(page, freshAddr, { timeout: 60000 });

    const result = await page.evaluate(() => {
      const cell = [...document.querySelectorAll('.acct-cell')].find(c => /Wallet Age/.test(c.textContent || ''));
      return {
        text: cell ? cell.textContent.replace(/\s+/g, ' ').trim() : null,
        title: cell ? cell.getAttribute('title') : null,
        hasNewWalletBadge: !!cell?.querySelector('.acct-cell-new-badge'),
      };
    });

    assert(result.text, 'expected a Wallet Age cell to render');
    assert(/Created today/.test(result.text), `expected "Created today" for an account funded moments ago, got: "${result.text}"`);
    assert(/verified via AccountRoot creation/.test(result.text), `expected the real-verification note, got: "${result.text}"`);
    assert(!/estimated|Earliest verified activity|At least/.test(result.text), `expected NO lower-bound/estimate language for a cryptographically verified brand-new account, got: "${result.text}"`);
    assert(result.hasNewWalletBadge, 'expected the "New wallet" badge to correctly show for a genuinely verified brand-new account');
    assert(result.title && /AccountRoot creation verified/.test(result.title), `expected the evidence tooltip to be present, got: "${result.title}"`);
    assert(/Transaction: [0-9A-F]{64}/.test(result.title), 'expected a real 64-char creation transaction hash in the evidence tooltip');
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
