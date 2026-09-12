// Regression guard for the Account Behavior Explorer — a plain-language
// "what does this account actually do" summary rendered BEFORE the
// risk-score banner (spec: begin with behavior, not a risk number). Built
// entirely from analyses already computed elsewhere; this suite guards the
// synthesis logic itself, especially the real inconsistency caught during
// development: the "dominant activity" story text used raw AMM deposit/
// withdraw counts while the bullet list only checked CURRENT LP positions,
// so an account that fully withdrew its liquidity could have the story
// claim "primarily focused on AMM liquidity provision" while the bullet
// list said nothing about AMM at all.
import { withPage, connectAndShowDashboard, inspectAddress, makeSuite, assert } from './helpers.mjs';

// SOLO issuer, not CULT — spreads live-RPC load across more than one real
// account so a single account's rate-limiting can't take out many test
// files in the same run (CULT alone backed 9 different test files).
const REAL_ACTIVE_ISSUER = 'rsoLo2S1kiGeCcn6hCUXVrCpGMWLrRrLZz';

const suite = makeSuite('Account Behavior Explorer');

suite.register('A real active issuer renders a real story, real bullets, and a real footprint before the risk banner', async () => {
  await withPage(async (page) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, REAL_ACTIVE_ISSUER, { timeout: 90000 });
    await page.waitForTimeout(3000);

    const result = await page.evaluate(() => {
      const behaviorEl = document.getElementById('account-behavior');
      const verdictEl = document.getElementById('quick-verdict');
      const bodyEl = document.getElementById('account-behavior-body');
      // DOM order: behavior section must precede the risk-score verdict.
      const behaviorFirst = !!(behaviorEl.compareDocumentPosition(verdictEl) & Node.DOCUMENT_POSITION_FOLLOWING);
      return {
        behaviorFirst,
        storyLen: bodyEl.innerText.length,
        hasIssuerBullet: /Issues a fungible token/.test(bodyEl.innerHTML),
        hasFootprintNumbers: /transactions/.test(bodyEl.innerHTML) && /counterparties/.test(bodyEl.innerHTML),
      };
    });
    assert(result.behaviorFirst, 'Account Behavior must render before the risk-score Quick Verdict banner — begin with behavior, not risk');
    assert(result.storyLen > 20, 'expected a real, non-empty story paragraph');
    assert(result.hasIssuerBullet, 'expected the real Token Issuer bullet for this known issuer account');
    assert(result.hasFootprintNumbers, 'expected real Ledger Footprint numbers (transactions, counterparties) to render');
  });
});

suite.register('An account with a fully-withdrawn AMM position still shows an AMM bullet — historical activity is not silently dropped just because there is no current position', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugAccountBehaviorProfile, { timeout: 8000 });
    const result = await page.evaluate(() => {
      const addr = 'rClosedLpAccount0000000000000000000';
      const accountRoles = [];
      const issuerAnalysis = { isIssuer: false };
      const ammAnalysis = { positions: [], closedPositions: ['SOME_CURRENCY'], deposits: 3, withdrawals: 3 };
      const nftAnalysis = { nftCount: 0, mintCount: 0, acceptCount: 0 };
      const washAnalysis = { automationLikely: false };
      const offerLifecycles = { list: [] };
      const txList = [];
      const lines = [];
      return window._debugAccountBehaviorProfile(addr, txList, lines, accountRoles, issuerAnalysis, ammAnalysis, nftAnalysis, washAnalysis, offerLifecycles, 100, {}, { signals: [] });
    });
    const ammBullet = result.behaviors.find(b => /AMM/.test(b.text));
    assert(ammBullet, `expected an AMM-related bullet even with zero current positions (3 deposits + 3 withdrawals happened) — got bullets: ${JSON.stringify(result.behaviors)}`);
    assert(/past/.test(ammBullet.text), `expected the bullet to explicitly say this is past/historical activity, not an active position: "${ammBullet.text}"`);
  });
});

suite.register('The "dominant activity" story and the bullet list never disagree about whether AMM activity is mentioned', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugAccountBehaviorProfile, { timeout: 8000 });
    const result = await page.evaluate(() => {
      // AMM deposit/withdraw count dwarfs every other activity type, and
      // there is no current position — this is exactly the shape that
      // exposed the original bug.
      const addr = 'rAmmDominant00000000000000000000000';
      const ammAnalysis = { positions: [], closedPositions: ['X'], deposits: 40, withdrawals: 40 };
      return window._debugAccountBehaviorProfile(
        addr, [], [], [], { isIssuer: false }, ammAnalysis,
        { nftCount: 0, mintCount: 0, acceptCount: 0 }, { automationLikely: false }, { list: [] },
        50, {}, { signals: [] }
      );
    });
    const storyMentionsAmm = /amm/i.test(result.story);
    const bulletsMentionAmm = result.behaviors.some(b => /AMM/.test(b.text));
    assert(storyMentionsAmm === bulletsMentionAmm, `story and bullets must agree on whether AMM is a real theme here — story mentions AMM: ${storyMentionsAmm}, bullets mention AMM: ${bulletsMentionAmm}. Story: "${result.story}". Bullets: ${JSON.stringify(result.behaviors)}`);
  });
});

suite.register('A quiet account with no activity gets an honest "limited activity" story, not a fabricated dominant theme', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugAccountBehaviorProfile, { timeout: 8000 });
    const result = await page.evaluate(() => window._debugAccountBehaviorProfile(
      'rQuiet000000000000000000000000000000', [], [], [], { isIssuer: false },
      { positions: [], closedPositions: [], deposits: 0, withdrawals: 0 },
      { nftCount: 0, mintCount: 0, acceptCount: 0 }, { automationLikely: false }, { list: [] },
      5, {}, { signals: [] }
    ));
    assert(/limited on-ledger activity/.test(result.story), `expected an honest "limited activity" story for a quiet account, got: "${result.story}"`);
    assert(result.behaviors.length === 2, `expected only the baseline "Holds XRP" + "Does not issue a token" bullets for a quiet account, got: ${JSON.stringify(result.behaviors)}`);
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
