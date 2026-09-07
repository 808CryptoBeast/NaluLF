// Regression guard for the AMM/LP + NFT role false-equivalence fixes:
// NFT holder/trader/minter must stay independently classified (holding
// or trading NFTs must never imply minting or project affiliation), and
// AMM analysis must distinguish current vs. closed LP positions purely
// from already-fetched transaction history.
import { withPage, makeSuite, assert } from './helpers.mjs';

const suite = makeSuite('AMM/LP + NFT Role Distinctions');

suite.register('NFT holder-only account gets nft_holder but not nft_minter/nft_trader', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugAccountRoles, { timeout: 8000 });
    const roles = await page.evaluate(() => {
      const addr = 'rTESTaddr';
      const nftAnalysis = window._debugNftRisk([{ NFTokenID: '1', URI: 'ipfs://x' }], [], addr);
      return window._debugAccountRoles([], [], addr, { isIssuer: false }, nftAnalysis).map((r) => r.role);
    });
    assert(roles.includes('nft_holder'), 'holder-only case missing nft_holder role');
    assert(!roles.includes('nft_minter'), 'holder-only case incorrectly got nft_minter');
    assert(!roles.includes('nft_trader'), 'holder-only case incorrectly got nft_trader');
  });
});

suite.register('NFT trader with zero current holdings gets nft_trader but not nft_holder', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugAccountRoles, { timeout: 8000 });
    const roles = await page.evaluate(() => {
      const addr = 'rTESTaddr';
      const traderTx = [{ tx: { TransactionType: 'NFTokenAcceptOffer', Account: addr }, meta: {} }];
      const nftAnalysis = window._debugNftRisk([], traderTx, addr);
      return window._debugAccountRoles([], traderTx, addr, { isIssuer: false }, nftAnalysis).map((r) => r.role);
    });
    assert(roles.includes('nft_trader'), 'trader case missing nft_trader role');
    assert(!roles.includes('nft_holder'), 'trader with zero current NFTs incorrectly got nft_holder');
  });
});

suite.register('A closed AMM position (deposit+withdraw history, zero current balance) is detected purely from tx history', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugAmmPositions, { timeout: 8000 });
    const result = await page.evaluate(() => {
      const addr = 'rTESTaddr';
      const LP_CUR = '0300000000000000000000000000000000000001';
      const OTHER_ISSUER = 'rPoolAccount1111111111111111111111';
      const rsNode = (prevBal, newBal) => ({
        ModifiedNode: {
          LedgerEntryType: 'RippleState',
          FinalFields: { Balance: { currency: LP_CUR, issuer: OTHER_ISSUER, value: String(newBal) }, HighLimit: { issuer: addr }, LowLimit: { issuer: OTHER_ISSUER } },
          PreviousFields: { Balance: { currency: LP_CUR, issuer: OTHER_ISSUER, value: String(prevBal) } },
        },
      });
      const arNode = (prevDrops, newDrops) => ({
        ModifiedNode: { LedgerEntryType: 'AccountRoot', FinalFields: { Account: addr, Balance: String(newDrops) }, PreviousFields: { Balance: String(prevDrops) } },
      });
      const txList = [
        { tx: { TransactionType: 'AMMDeposit', Account: addr, hash: 'DEP1', date: 800000000 }, meta: { AffectedNodes: [rsNode(0, 100), arNode(1000000000, 900000000)] } },
        { tx: { TransactionType: 'AMMWithdraw', Account: addr, hash: 'WD1', date: 800001000 }, meta: { AffectedNodes: [rsNode(100, 0), arNode(900000000, 1050000000)] } },
      ];
      const amm = window._debugAmmPositions([], txList, [], new Map(), addr);
      return { closedPositions: amm.closedPositions, positionsCount: amm.positions.length };
    });
    assert(result.closedPositions.length === 1, `expected 1 closed position, got ${result.closedPositions.length}`);
    assert(result.positionsCount === 0, `expected 0 current positions, got ${result.positionsCount}`);
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
