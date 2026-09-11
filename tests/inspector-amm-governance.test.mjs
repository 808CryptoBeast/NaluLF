// Regression guard for AMM Governance — Fee Voting (AMMVote) and Auction
// Slot (AMMBid), read directly from amm_info's `vote_slots`/`auction_slot`
// fields (already fetched for every AMM pool this app looks at; this is
// the first time anything reads them). Spec requires these be modeled as
// two SEPARATE mechanisms throughout — a fee vote changes the pool's
// normal trading fee (LP-weighted governance); the auction slot is a
// temporary discounted fee won by bidding LP tokens. Neither is ever
// framed as risk by itself.
import { withPage, connectAndShowDashboard, inspectAddress, makeSuite, assert } from './helpers.mjs';

const REAL_ACTIVE_ISSUER = 'rCULtAKrKbQjk1Tpmg5hkw4dpcf9S9KCs';

const suite = makeSuite('AMM Governance — Fee Voting & Auction Slot');

suite.register('A real pool renders real fee-voter weights and a real auction-slot discount, correctly kept as two separate blocks', async () => {
  await withPage(async (page) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, REAL_ACTIVE_ISSUER, { timeout: 90000 });
    await page.waitForTimeout(3000);

    const result = await page.evaluate(() => {
      const el = document.getElementById('inspect-amm-body');
      const card = el?.querySelector('.ammgov-card');
      return {
        present: !!card,
        hasVoteBlock: !!card?.querySelector('.govvote-block'),
        hasAuctionBlock: !!card?.querySelector('.govauction-block'),
        voteRows: card?.querySelectorAll('.govvote-row').length || 0,
        text: card?.textContent || '',
      };
    });
    assert(result.present, 'expected a real AMM Governance card for this known issuer\'s pool');
    assert(result.hasVoteBlock && result.hasAuctionBlock, 'expected both the Fee Voting block and the Auction Slot block to render, kept visually distinct');
    assert(result.voteRows > 0, 'expected at least one real fee-voter row');
    assert(/proposed/.test(result.text) && /weight/.test(result.text), 'expected real per-voter proposed-fee and weight text');
  });
});

suite.register('analyseAmmGovernance correctly converts XRPL fee/weight units and separates voting from the auction slot', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugAmmGovernance, { timeout: 8000 });
    const result = await page.evaluate(() => {
      const addr = 'rSlotOwner00000000000000000000000000';
      const pool = {
        account: 'rPoolAccount0000000000000000000000000',
        trading_fee: 500, // 0.5%
        vote_slots: [
          { account: 'rVoterA000000000000000000000000000000', trading_fee: 500, vote_weight: 60000 },
          { account: 'rVoterB000000000000000000000000000000', trading_fee: 300, vote_weight: 40000 },
        ],
        auction_slot: {
          account: addr,
          discounted_fee: 50, // 0.05%
          auth_accounts: [{ account: 'rAuthA00000000000000000000000000000' }, { account: 'rAuthB00000000000000000000000000000' }],
          price: { value: '12.5' },
          expiration: '2026-01-01T00:00:00Z',
        },
      };
      return window._debugAmmGovernance(pool, addr);
    });

    assert(Math.abs(result.normalFeePct - 0.5) < 0.001, `expected normal fee 0.5%, got ${result.normalFeePct}`);
    assert(result.voting.voterCount === 2, `expected 2 voters, got ${result.voting.voterCount}`);
    assert(Math.abs(result.voting.top1WeightPct - 60) < 0.01, `expected top voter weight 60%, got ${result.voting.top1WeightPct}`);
    assert(Math.abs(result.voting.top3WeightPct - 100) < 0.01, `expected top-3 weight 100% with only 2 voters, got ${result.voting.top3WeightPct}`);
    assert(result.auctionSlot.applicable, 'expected an active auction slot');
    assert(result.auctionSlot.isOwner === true, 'expected addr to be detected as the slot owner');
    assert(Math.abs(result.auctionSlot.discountedFeePct - 0.05) < 0.001, `expected discounted fee 0.05%, got ${result.auctionSlot.discountedFeePct}`);
    assert(Math.abs(result.auctionSlot.feeReductionPct - 90) < 0.01, `expected 90% fee reduction (0.5 -> 0.05), got ${result.auctionSlot.feeReductionPct}`);
    assert(result.auctionSlot.authAccounts.length === 2, `expected 2 authorized accounts, got ${result.auctionSlot.authAccounts.length}`);
    assert(result.auctionSlot.lpTokensPaid === 12.5, `expected LP tokens bid of 12.5, got ${result.auctionSlot.lpTokensPaid}`);
  });
});

suite.register('No active auction slot is modeled as applicable:false, not a fabricated zero-value slot', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugAmmGovernance, { timeout: 8000 });
    const result = await page.evaluate(() => window._debugAmmGovernance({
      account: 'rPoolNoSlot000000000000000000000000000', trading_fee: 500, vote_slots: [],
      // no auction_slot key at all — matches real rippled behavior when no slot is held
    }, 'rSomeAddr00000000000000000000000000'));
    assert(result.auctionSlot.applicable === false, 'expected applicable:false when rippled omits auction_slot entirely');
    assert(result.voting.voterCount === 0, 'expected zero voters for an empty vote_slots array');
  });
});

suite.register('Fee-vote concentration produces a descriptive finding (never "manipulation"), and only when top voter exceeds 50%', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugAmmGovernanceFindings, { timeout: 8000 });
    const result = await page.evaluate(() => {
      const concentrated = window._debugAmmGovernanceFindings(
        { applicable: true, normalFeePct: 0.5, voting: { voterCount: 3, top1WeightPct: 70, top3WeightPct: 100, ownVote: null }, auctionSlot: { applicable: false } },
        'rAddr', 'FOO'
      );
      const notConcentrated = window._debugAmmGovernanceFindings(
        { applicable: true, normalFeePct: 0.5, voting: { voterCount: 3, top1WeightPct: 40, top3WeightPct: 90, ownVote: null }, auctionSlot: { applicable: false } },
        'rAddr', 'FOO'
      );
      return { concentrated, notConcentrated };
    });
    const finding = result.concentrated.find(f => f.module === 'AMM Fee Governance');
    assert(finding, 'expected a fee-governance finding when top voter exceeds 50%');
    assert(finding.sev === 'info', `must stay info severity, got ${finding.sev}`);
    assert(!/manipulation/i.test(finding.headline + finding.detail), 'must never use the word "manipulation" for fee-vote concentration');
    assert(/not manipulation/i.test(finding.classification), 'classification must explicitly disclaim manipulation');
    assert(!result.notConcentrated.some(f => f.module === 'AMM Fee Governance'), 'must NOT fire when top voter is below the 50% concentration threshold');
  });
});

suite.register('Auction-slot ownership/authorization produces a finding framed as a verified relationship, never as evidence of common ownership', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugAmmGovernanceFindings, { timeout: 8000 });
    const result = await page.evaluate(() => {
      const owner = window._debugAmmGovernanceFindings(
        { applicable: true, normalFeePct: 0.5, voting: { voterCount: 0, top1WeightPct: 0, top3WeightPct: 0, ownVote: null },
          auctionSlot: { applicable: true, slotOwner: 'rAddr', authAccounts: ['rX', 'rY'], isOwner: true, isAuthorized: false, normalFeePct: 0.5, discountedFeePct: 0.05, feeReductionPct: 90 } },
        'rAddr', 'FOO'
      );
      const neitherOwnerNorAuth = window._debugAmmGovernanceFindings(
        { applicable: true, normalFeePct: 0.5, voting: { voterCount: 0, top1WeightPct: 0, top3WeightPct: 0, ownVote: null },
          auctionSlot: { applicable: true, slotOwner: 'rOther', authAccounts: [], isOwner: false, isAuthorized: false, normalFeePct: 0.5, discountedFeePct: 0.05, feeReductionPct: 90 } },
        'rAddr', 'FOO'
      );
      return { owner, neitherOwnerNorAuth };
    });
    const finding = result.owner.find(f => f.module === 'AMM Auction Slot');
    assert(finding, 'expected an auction-slot finding when the inspected account is the slot owner');
    assert(/verified on-ledger protocol relationships, not evidence of common ownership/.test(finding.classification), 'must explicitly disclaim common-ownership inference from authorization');
    assert(!result.neitherOwnerNorAuth.some(f => f.module === 'AMM Auction Slot'), 'must NOT fire when the inspected account is neither the owner nor authorized');
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
