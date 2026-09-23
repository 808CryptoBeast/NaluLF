// Regression guard for real false positives found during a dedicated
// false-positive audit pass over the Inspector's severity-bearing findings,
// each confirmed live against real accounts before being fixed.
//
// 1. Volume Concentration's "too few actors to trust an extreme severity"
//    gate compared the raw address count against the 5-actor floor, but the
//    headline/HHI are computed from the CLUSTERED estimate (which only ever
//    merges addresses down, never splits them up). A market with e.g. 6 raw
//    addresses that clustered down to 3 real economic actors cleared the
//    raw-count floor and stayed CRITICAL, even though the tool's own
//    clustering concluded there were too few real participants to trust
//    that severity — confirmed live against the SOLO issuer (BITx: 5 raw
//    addresses / 2 clustered actors; PLX: 6 raw / 3 clustered; USDC: 5 raw /
//    4 clustered — all three wrongly stayed CRITICAL).
//
// 2. Memo-Drain Correlation re-derived its own severity purely from a drain
//    episode's `classification`, completely bypassing the corroboration
//    gate analyseAssetDrainBehavior itself uses before ever reaching
//    'critical' — meaning a scam-pattern memo (a common, near-routine
//    occurrence on XRPL) landing within a generous 72-hour window of ANY
//    sweep/potential-drain-classified episode could re-escalate a finding
//    Drain Risk itself had already capped at 'warn' for lack of
//    corroboration. Confirmed live: an active DEX trader's two large,
//    already-correctly-WARN-only transfers got pushed to CRITICAL purely
//    because an inbound scam memo happened to land in that window.
//
// 3. analyseLiveOrderBook's "wall order" WARN branch fired for a large
//    order belonging to ANY address currently in the book, not the
//    inspected wallet's own — a completely unrelated third party's live
//    limit order — yet rendered inside THIS wallet's own report and, via
//    analyseSpoofingScore's live-snapshot injection, fed straight into
//    THIS wallet's own Spoofing score. Confirmed live across several
//    unrelated real accounts (an exchange, two issuers, an active trader)
//    that happened to be trading a pair where some other trader currently
//    held a large order — something no account has any control over.
//
// 4. analyseAccountCompromiseRisk's "master key disabled + regular key
//    present" check fired an unconditional CRITICAL "Classic drain setup
//    detected" — but that exact on-chain state also describes a well-known,
//    recommended self-custody pattern (cold-store the master seed, sign
//    day-to-day with a regular key instead). The tool cannot tell those two
//    scenarios apart from state alone; the one thing that actually
//    discriminates them is WHO set the currently-active regular key, which
//    this check ignored entirely even though a separate, correctly-scoped
//    check elsewhere in the same function already computes exactly that.
//
// 5. analyseNftRisk's "near-zero-price NFT offer" check had two compounding
//    issues: it matched ANY NFTokenCreateOffer regardless of the
//    tfSellNFToken flag, so an ordinary lowball BUY offer (which costs the
//    creator nothing — not remotely a drain vector) could be mislabeled a
//    "sell offer... drain vector"; and among genuine sell offers, it never
//    checked `Destination` — a Destination-restricted near-zero sell offer
//    is the standard, legitimate mechanism for gifting an NFT to one known
//    recipient (only that address can ever accept it), not the open,
//    accept-by-anyone shape real NFT-drain scams rely on.
//
// 6. analyseInboundFlow's "structured inbound pattern" check clustered
//    payments by rounded AMOUNT only, with no check on how many DISTINCT
//    senders made up that cluster. "Structuring/layering" specifically
//    means splitting funds ACROSS multiple sources to evade detection — a
//    single sender repeatedly paying the same round amount (a salary, a
//    subscription, a scheduled transfer) buckets identically but has
//    nothing to do with layering, and would have been mislabeled
//    "Structured inbound pattern... can indicate layering" purely from its
//    own mundane, single-source recurring income.
//
// 7. analyseShannonsEntropy's low-amount-entropy check unconditionally
//    called repetitive amounts "a bot or scripted actor" at 'warn' —
//    technically true, but for a KNOWN EXCHANGE address specifically, a
//    high-volume custodial system repeating standard deposit/withdrawal
//    amounts is the ordinary, expected shape of the job, not evidence of
//    concealment. Confirmed live: Bitstamp's hot wallet showed H=0.01 bits.
//
// 8. analyseZipfsLaw's "single amount dominates" check had the identical
//    false positive: a known exchange repeating one standard deposit/
//    withdrawal amount across most transactions was called "a hallmark of
//    scripted or wash-trading activity" at 'warn'. Confirmed live:
//    Bitstamp's hot wallet showed one amount dominating 86% of
//    transactions.
import { withPage, connectAndShowDashboard, inspectAddress, makeSuite, assert } from './helpers.mjs';

const suite = makeSuite('Inspector False-Positive Audit — Confirmed Fixes');

const SOLO_ISSUER = 'rsoLo2S1kiGeCcn6hCUXVrCpGMWLrRrLZz';
const ACTIVE_TRADER = 'rnj7R3QUGzLZc9dg24jSrGabtt1tp1XD7A';

function hex(s) { return Buffer.from(s, 'utf8').toString('hex').toUpperCase(); }

suite.register('Volume Concentration: a market with 6 raw addresses clustering down to only 4 real economic actors is capped below CRITICAL, not left at CRITICAL because it cleared the raw-address floor', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugAnalyseVolumeConcentration, { timeout: 8000 });

    const txList = [];
    // Each sender gets its own time block, spaced 100,000s apart — the
    // clustering pass also merges senders whose timestamps land within 30s
    // of each other at least 3 times, so senders NOT meant to cluster must
    // stay far enough apart in time to avoid tripping that heuristic too.
    let blockBase = 800000000;
    const push = (account, value, memoText, count) => {
      for (let i = 0; i < count; i++) {
        txList.push({ tx: {
          Account: account, date: blockBase + i,
          TakerGets: { currency: 'FOO', issuer: 'rIssuer00000000000000000000000000', value: String(value) },
          ...(memoText ? { Memos: [{ Memo: { MemoData: hex(memoText) } }] } : {}),
        } });
      }
      blockBase += 100000;
    };
    // Cluster A (sender1+sender2, shared memo) = 120 total, cluster B
    // (sender3+sender4, shared memo) = 20, plus two unmerged singletons at
    // 5 each — 4 real clusters from 6 raw addresses, 50 trades (clears the
    // separate trade-count sample-size gate on its own). Memo-based merging
    // doesn't depend on timing at all, so putting sender1/sender2 in
    // separate time blocks is fine — the shared memo alone unions them.
    push('rSender1000000000000000000000000000', 4, 'SAMEOWNERONE', 25);
    push('rSender2000000000000000000000000000', 4, 'SAMEOWNERONE', 5);
    push('rSender3000000000000000000000000000', 2, 'SAMEOWNERTWO', 5);
    push('rSender4000000000000000000000000000', 2, 'SAMEOWNERTWO', 5);
    push('rSender5000000000000000000000000000', 1, null, 5);
    push('rSender6000000000000000000000000000', 1, null, 5);

    const result = await page.evaluate((tl) => window._debugAnalyseVolumeConcentration(tl, 'rTestAccount0000000000000000000000'), txList);
    const c = result.concentrations.find(x => x.currency === 'FOO');
    assert(c, 'expected a FOO concentration entry to be computed');
    assert(c.rawActorCount === 6, `expected 6 raw addresses, got ${c.rawActorCount}`);
    assert(c.estimatedActorClusters === 4, `expected clustering to merge down to 4 real actors, got ${c.estimatedActorClusters}`);
    assert(c.hhi > 2500, `expected HHI to clear the 2500 critical threshold on its own, got ${c.hhi}`);

    const finding = result.signals.find(s => s.headline?.startsWith('FOO:'));
    assert(finding, 'expected a FOO signal to be pushed');
    assert(finding.sev !== 'critical', `expected severity capped below critical since only 4 real actors were found (below the 5-actor floor), got sev="${finding.sev}"`);
    assert(finding.observed.some(o => o.includes('estimated distinct economic actor')), 'expected the capped-severity explanation to cite the CLUSTERED actor estimate, not just the raw address count');
  });
});

suite.register('Volume Concentration: a market with 5+ raw addresses that genuinely cluster down to 5+ real actors still reaches CRITICAL (the fix narrows the gate, it does not disable it)', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugAnalyseVolumeConcentration, { timeout: 8000 });
    const txList = [];
    let blockBase = 800000000;
    const push = (account, value, count) => {
      for (let i = 0; i < count; i++) {
        txList.push({ tx: { Account: account, date: blockBase + i, TakerGets: { currency: 'BAR', issuer: 'rIssuer00000000000000000000000000', value: String(value) } } });
      }
      blockBase += 100000;
    };
    // 6 distinct, unclustered senders (separate time blocks, no shared
    // memos) — one holds the overwhelming majority, so HHI is extreme AND
    // there are genuinely >=5 real actors involved.
    push('rBig00000000000000000000000000000000', 10, 40);
    push('rSmallA00000000000000000000000000000', 1, 2);
    push('rSmallB00000000000000000000000000000', 1, 2);
    push('rSmallC00000000000000000000000000000', 1, 2);
    push('rSmallD00000000000000000000000000000', 1, 2);
    push('rSmallE00000000000000000000000000000', 1, 2);

    const result = await page.evaluate((tl) => window._debugAnalyseVolumeConcentration(tl, 'rTestAccount0000000000000000000000'), txList);
    const c = result.concentrations.find(x => x.currency === 'BAR');
    assert(c.estimatedActorClusters === 6, `expected 6 unmerged actors, got ${c.estimatedActorClusters}`);
    const finding = result.signals.find(s => s.headline?.startsWith('BAR:'));
    assert(finding.sev === 'critical', `expected a genuinely 6-actor, extreme-HHI market to still reach critical, got sev="${finding.sev}"`);
  });
});

suite.register('Memo-Drain Correlation never escalates a drain episode past what Drain Risk\'s own corroboration check already concluded for that episode', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugMemoDrainCorrelation, { timeout: 8000 });

    // An episode with NO corroborating signals (no auth-change, no
    // first-time-recipient spike, no liquidate-then-withdraw, no size
    // anomaly) — analyseAssetDrainBehavior itself would only ever rate this
    // 'info', never 'critical', regardless of classification.
    const uncorroboratedEpisode = {
      startDate: 1000000, classification: 'sweep', grossOutflowXrp: 1000, actualDepletionPct: 0.9,
      windowSec: 86400, triggeredByAuthChange: false, isCorroborated: false,
    };
    const memoAnalysis = { scamMemos: [{ sender: 'rScammer0000000000000000000000000000', date: 999900 }] };
    const drainAnalysis = { episodes: [uncorroboratedEpisode] };

    const uncorroboratedResult = await page.evaluate(
      ({ memoAnalysis, drainAnalysis }) => window._debugMemoDrainCorrelation(memoAnalysis, drainAnalysis, 'rVictim0000000000000000000000000000', false),
      { memoAnalysis, drainAnalysis }
    );
    assert(uncorroboratedResult.signals.length === 1, 'expected exactly one correlation finding');
    assert(uncorroboratedResult.signals[0].sev !== 'critical', `expected an uncorroborated sweep episode to stay below critical despite the memo, got sev="${uncorroboratedResult.signals[0].sev}"`);

    // The same episode, but WITH corroboration this time — should be free
    // to reach critical, confirming the fix narrows the gate rather than
    // disabling escalation entirely.
    const corroboratedEpisode = { ...uncorroboratedEpisode, isCorroborated: true };
    const corroboratedResult = await page.evaluate(
      ({ memoAnalysis, drainAnalysis }) => window._debugMemoDrainCorrelation(memoAnalysis, drainAnalysis, 'rVictim0000000000000000000000000000', false),
      { memoAnalysis, drainAnalysis: { episodes: [corroboratedEpisode] } }
    );
    assert(corroboratedResult.signals[0].sev === 'critical', `expected a genuinely corroborated sweep episode to still reach critical, got sev="${corroboratedResult.signals[0].sev}"`);
  });
});

suite.register('Live regression: the SOLO issuer and the active DEX trader no longer show the two confirmed false positives', async () => {
  await withPage(async (page, { pageErrors }) => {
    await connectAndShowDashboard(page);

    await inspectAddress(page, SOLO_ISSUER, { timeout: 90000 });
    const soloFindings = await page.evaluate(() => (window._lastAllFindings || []).map(f => ({ module: f.module, headline: f.headline || f.label, sev: f.sev })));
    const badVolConc = soloFindings.filter(f => f.module === 'Volume Concentration' && f.sev === 'critical' && /~[1-4] estimated economic actor/.test(f.headline || ''));
    assert(badVolConc.length === 0, `expected no CRITICAL Volume Concentration finding with fewer than 5 estimated actors, got: ${JSON.stringify(badVolConc)}`);

    await inspectAddress(page, ACTIVE_TRADER, { timeout: 90000 });
    const traderFindings = await page.evaluate(() => (window._lastAllFindings || []).map(f => ({ module: f.module, headline: f.headline || f.label, sev: f.sev })));
    const badMemoDrain = traderFindings.filter(f => f.module === 'Memo-Drain Correlation' && f.sev === 'critical');
    assert(badMemoDrain.length === 0, `expected the active DEX trader's Memo-Drain Correlation finding to no longer be CRITICAL, got: ${JSON.stringify(badMemoDrain)}`);
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

suite.register('Live Order Book: a wall order belonging to a THIRD PARTY is downgraded to info and reworded, not left as an unattributed "warn" inside this wallet\'s report', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugAnalyseLiveOrderBook, { timeout: 8000 });
    const addr = 'rInspectedWallet00000000000000000000';
    const thirdParty = 'rSomeoneElse000000000000000000000000';
    const liveOrderBook = {
      pair: 'XRP↔FOO+rIssuer',
      offers: [
        { Account: thirdParty, TakerGets: String(60_000_000) }, // 60 XRP — the wall
        { Account: addr, TakerGets: String(20_000_000) },
        { Account: 'rOther0000000000000000000000000000000', TakerGets: String(20_000_000) },
      ],
    };
    const result = await page.evaluate(({ liveOrderBook, addr }) => window._debugAnalyseLiveOrderBook(liveOrderBook, addr), { liveOrderBook, addr });
    const wallFinding = result.signals.find(s => /wall order/i.test(s.label));
    assert(wallFinding, 'expected a wall-order signal to fire (60% > 40% threshold)');
    assert(wallFinding.sev === 'info', `expected a third-party wall to be 'info', not a risk-bearing severity, got sev="${wallFinding.sev}"`);
    assert(/third-party/i.test(wallFinding.label), `expected the label to explicitly say this is a third party's order, got: "${wallFinding.label}"`);
  });
});

suite.register('Spoofing score: a third-party (non-critical) live-book signal is never counted as evidence about the inspected wallet, but the wallet\'s OWN active wall order still is', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugSpoofingScore, { timeout: 8000 });
    const baseArgs = { profile: {}, offerLifecycles: { list: [] }, txList: [], addr: 'rInspectedWallet00000000000000000000' };

    const withThirdPartyWarn = await page.evaluate((args) => window._debugSpoofingScore(
      args.profile, args.offerLifecycles, args.txList, args.addr,
      { signals: [{ sev: 'info', label: 'Third-party wall order in this market: 60% of book depth' }] }
    ), baseArgs);
    assert(!withThirdPartyWarn.findings.some(f => /wall order/i.test(f.label || f.headline || '')), 'expected an info-level third-party wall signal to never be injected into this wallet\'s own Spoofing findings');
    assert(withThirdPartyWarn.score === 0, `expected a third-party signal to add nothing to this wallet's own Spoofing score, got ${withThirdPartyWarn.score}`);

    const withOwnCritical = await page.evaluate((args) => window._debugSpoofingScore(
      args.profile, args.offerLifecycles, args.txList, args.addr,
      { signals: [{ sev: 'critical', label: 'Active wall order: this wallet controls 60% of current book depth' }] }
    ), baseArgs);
    assert(withOwnCritical.findings.some(f => /wall order/i.test(f.label || f.headline || '')), 'expected the wallet\'s OWN active wall order (critical) to still be counted as Spoofing evidence');
    assert(withOwnCritical.score >= 20, `expected the wallet's own active wall order to still add to the Spoofing score, got ${withOwnCritical.score}`);
  });
});

suite.register('Account Compromise Risk: master-key-disabled + regular-key is NOT unconditionally "Classic drain setup detected" — severity depends on who actually set the active regular key', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugAnalyseAccountCompromiseRisk, { timeout: 8000 });
    const owner = 'rOwnerAccount000000000000000000000000';
    const regKey = 'rRegularKey00000000000000000000000000';
    const attacker = 'rAttackerAccount0000000000000000000000';
    const DISABLE_MASTER = 0x00100000;
    const acct = { Account: owner, RegularKey: regKey };

    // Self-set regular key — the legitimate cold-storage self-custody
    // pattern. Must NOT read as "Classic drain setup detected" at critical.
    const selfSet = await page.evaluate(({ acct, flags, owner, regKey }) => window._debugAnalyseAccountCompromiseRisk(
      acct, flags, [], [{ tx: { TransactionType: 'SetRegularKey', Account: owner, RegularKey: regKey, date: 1000 } }], [], []
    ), { acct, flags: DISABLE_MASTER, owner, regKey });
    const selfSetFinding = selfSet.signals.find(s => /regular key/i.test(s.label));
    assert(selfSetFinding, 'expected a regular-key-related signal');
    assert(selfSetFinding.sev !== 'critical', `expected a self-set regular key to NOT be critical, got sev="${selfSetFinding.sev}"`);
    assert(!/classic drain setup detected$/i.test(selfSetFinding.label), `expected the alarmist unqualified label to be gone for the self-set case, got: "${selfSetFinding.label}"`);

    // Externally-set regular key — this IS the genuine compromise pattern.
    const externalSet = await page.evaluate(({ acct, flags, attacker, regKey }) => window._debugAnalyseAccountCompromiseRisk(
      acct, flags, [], [{ tx: { TransactionType: 'SetRegularKey', Account: attacker, RegularKey: regKey, date: 1000 } }], [], []
    ), { acct, flags: DISABLE_MASTER, attacker, regKey });
    const externalFinding = externalSet.signals.find(s => /regular key/i.test(s.label));
    assert(externalFinding.sev === 'critical', `expected an externally-set regular key to still be critical, got sev="${externalFinding.sev}"`);
    assert(externalSet.riskLevel === 'critical', 'expected overall riskLevel to be critical for a genuinely externally-set regular key');

    // No visible SetRegularKey in history at all — honest uncertainty, not
    // a confident accusation either way.
    const noHistory = await page.evaluate(({ acct, flags }) => window._debugAnalyseAccountCompromiseRisk(acct, flags, [], [], [], []), { acct, flags: DISABLE_MASTER });
    const noHistoryFinding = noHistory.signals.find(s => /regular key/i.test(s.label));
    assert(noHistoryFinding.sev === 'warn', `expected the no-visible-history case to be a hedged 'warn', not critical or ok, got sev="${noHistoryFinding.sev}"`);
    assert(/isn't in the fetched history|can't be confirmed/i.test(noHistoryFinding.detail), `expected honest uncertainty language when the setting transaction isn't visible, got: "${noHistoryFinding.detail}"`);
  });
});

suite.register('NFT Risk: an open (no-Destination) near-zero sell offer stays critical, a Destination-restricted one is treated as a likely gift, and a low-price BUY offer is never called a "sell offer"', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugNftRisk, { timeout: 8000 });
    const addr = 'rNftOwner00000000000000000000000000000';
    const TF_SELL_NFTOKEN = 0x00000001;

    const openSell = { tx: { TransactionType: 'NFTokenCreateOffer', Account: addr, Flags: TF_SELL_NFTOKEN, Amount: '0' } };
    const openResult = await page.evaluate(({ addr, tx }) => window._debugNftRisk([], [tx], addr), { addr, tx: openSell });
    const openFlag = openResult.flags.find(f => /sell offer/i.test(f.label));
    assert(openFlag && openFlag.sev === 'critical', `expected an open (no-Destination) near-zero sell offer to stay critical, got: ${JSON.stringify(openFlag)}`);
    assert(/open to anyone/i.test(openFlag.label), `expected the label to make clear this offer is open to anyone, got: "${openFlag.label}"`);

    const giftSell = { tx: { TransactionType: 'NFTokenCreateOffer', Account: addr, Flags: TF_SELL_NFTOKEN, Amount: '0', Destination: 'rMyFriend000000000000000000000000000' } };
    const giftResult = await page.evaluate(({ addr, tx }) => window._debugNftRisk([], [tx], addr), { addr, tx: giftSell });
    const giftFlag = giftResult.flags.find(f => /sell offer/i.test(f.label));
    assert(giftFlag && giftFlag.sev !== 'critical', `expected a Destination-restricted near-zero sell offer to NOT be critical, got: ${JSON.stringify(giftFlag)}`);
    assert(!giftResult.flags.some(f => f.sev === 'critical'), 'expected no critical NFT flag at all when the only near-zero offer is Destination-restricted');

    const lowBuy = { tx: { TransactionType: 'NFTokenCreateOffer', Account: addr, Flags: 0, Amount: '500000' } }; // no tfSellNFToken — a buy offer
    const buyResult = await page.evaluate(({ addr, tx }) => window._debugNftRisk([], [tx], addr), { addr, tx: lowBuy });
    assert(!buyResult.flags.some(f => /sell offer/i.test(f.label)), `expected a low-price BUY offer (no tfSellNFToken flag) to never be labeled a "sell offer", got: ${JSON.stringify(buyResult.flags)}`);
  });
});

suite.register('Inbound Flow: a single recurring payer sending the same round amount is NOT called "structured funding" / layering, but genuinely multi-source clustering still is', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugAnalyseInboundFlow, { timeout: 8000 });
    const addr = 'rRecipient0000000000000000000000000000';
    let date = 900000000;

    // One single employer paying the same 500 XRP "salary" repeatedly —
    // clusters at >40% of inbound activity, but from exactly one sender.
    const singleSourceTxs = [];
    for (let i = 0; i < 8; i++) {
      singleSourceTxs.push({ tx: { TransactionType: 'Payment', Account: 'rEmployer000000000000000000000000000', Destination: addr, Amount: String(500_000_000), date: date + i * 604800 }, meta: {} });
    }
    const singleResult = await page.evaluate(({ addr, txs }) => window._debugAnalyseInboundFlow(txs, addr), { addr, txs: singleSourceTxs });
    assert(singleResult.structuredFlag === false, `expected a single recurring payer to NOT be flagged as structured funding, got structuredFlag=${singleResult.structuredFlag}`);
    assert(singleResult.recurringSingleSourceFlag === true, 'expected the recurring-single-source case to be explicitly identified as such');
    assert(!singleResult.signals.some(s => /layering/i.test(s.detail || '')), 'expected no layering language for a single recurring payer');
    assert(singleResult.signals.some(s => /recurring payment/i.test(s.label || '')), 'expected a "recurring payment pattern" signal instead');

    // The same amount and count, but from 8 DIFFERENT senders — the
    // genuinely structuring-consistent shape.
    const multiSourceTxs = [];
    for (let i = 0; i < 8; i++) {
      multiSourceTxs.push({ tx: { TransactionType: 'Payment', Account: `rSender${i}00000000000000000000000000`, Destination: addr, Amount: String(500_000_000), date: date + i * 3600 }, meta: {} });
    }
    const multiResult = await page.evaluate(({ addr, txs }) => window._debugAnalyseInboundFlow(txs, addr), { addr, txs: multiSourceTxs });
    assert(multiResult.structuredFlag === true, `expected genuinely multi-source clustering to still be flagged as structured funding, got structuredFlag=${multiResult.structuredFlag}`);
    assert(multiResult.recurringSingleSourceFlag === false, 'expected the multi-source case to NOT be misclassified as recurring-single-source');
  });
});

suite.register("Shannon's Entropy: a known exchange's repetitive amounts are framed as expected custodial behavior (info), not an accusatory 'bot or scripted actor' warning", async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugShannonsEntropy, { timeout: 8000 });
    const BITSTAMP = 'rPVMhWBsfF9iMXYj3aAzJVkPDTFNSyWdKy'; // real, registered exchange entity
    const repetitiveTxList = Array.from({ length: 40 }, (_, i) => ({
      tx: { TransactionType: 'Payment', Account: BITSTAMP, Destination: `rCustomer${i}00000000000000000000000000`, Amount: '100000000', date: 800000000 + i * 60 },
    }));

    const exchangeResult = await page.evaluate((txList) => window._debugShannonsEntropy(txList, 'rPVMhWBsfF9iMXYj3aAzJVkPDTFNSyWdKy'), repetitiveTxList);
    const exchangeFinding = exchangeResult.signals.find(s => /amount entropy/i.test(s.label));
    assert(exchangeFinding, 'expected an amount-entropy signal to fire');
    assert(exchangeFinding.sev !== 'warn', `expected a known exchange's repetitive amounts to not be 'warn', got sev="${exchangeFinding.sev}"`);
    assert(!/bot or scripted actor/i.test(exchangeFinding.detail), `expected the accusatory "bot or scripted actor" framing to be gone for a known exchange, got: "${exchangeFinding.detail}"`);
    assert(/known exchange/i.test(exchangeFinding.label), `expected the label to explicitly acknowledge this is a known exchange, got: "${exchangeFinding.label}"`);

    // The same repetitive-amounts shape from an UNKNOWN address should
    // still warn — the fix narrows the false positive, it doesn't disable
    // the underlying signal for accounts with no such explanation.
    const unknownTxList = repetitiveTxList.map(e => ({ tx: { ...e.tx, Account: 'rUnknownWallet000000000000000000000000' } }));
    const unknownResult = await page.evaluate((txList) => window._debugShannonsEntropy(txList, 'rUnknownWallet000000000000000000000000'), unknownTxList);
    const unknownFinding = unknownResult.signals.find(s => /amount entropy/i.test(s.label));
    assert(unknownFinding.sev === 'warn', `expected the same repetitive-amounts pattern from an unknown address to still warn, got sev="${unknownFinding.sev}"`);
  });
});

suite.register("Zipf's Law: a known exchange's dominant round amount is framed as expected custodial behavior (info), not a wash-trading 'hallmark' warning", async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugAnalyseZipfsLaw, { timeout: 8000 });
    const BITSTAMP = 'rPVMhWBsfF9iMXYj3aAzJVkPDTFNSyWdKy'; // real, registered exchange entity
    const dominantAmtTxList = Array.from({ length: 40 }, (_, i) => ({
      tx: { TransactionType: 'Payment', Account: BITSTAMP, Destination: `rCustomer${i}00000000000000000000000000`, Amount: '100000000', date: 800000000 + i * 60 },
    }));

    const exchangeResult = await page.evaluate((txList) => window._debugAnalyseZipfsLaw(txList, 'rPVMhWBsfF9iMXYj3aAzJVkPDTFNSyWdKy'), dominantAmtTxList);
    const exchangeFinding = exchangeResult.signals.find(s => /dominates/i.test(s.label));
    assert(exchangeFinding, 'expected a dominant-amount signal to fire');
    assert(exchangeFinding.sev !== 'warn', `expected a known exchange's dominant amount to not be 'warn', got sev="${exchangeFinding.sev}"`);
    assert(!/hallmark of scripted or wash-trading/i.test(exchangeFinding.detail), `expected the accusatory "hallmark" framing to be gone for a known exchange, got: "${exchangeFinding.detail}"`);
    assert(/known exchange/i.test(exchangeFinding.label), `expected the label to explicitly acknowledge this is a known exchange, got: "${exchangeFinding.label}"`);

    const unknownTxList = dominantAmtTxList.map(e => ({ tx: { ...e.tx, Account: 'rUnknownWallet000000000000000000000000' } }));
    const unknownResult = await page.evaluate((txList) => window._debugAnalyseZipfsLaw(txList, 'rUnknownWallet000000000000000000000000'), unknownTxList);
    const unknownFinding = unknownResult.signals.find(s => /dominates/i.test(s.label));
    assert(unknownFinding.sev === 'warn', `expected the same dominant-amount pattern from an unknown address to still warn, got sev="${unknownFinding.sev}"`);
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
