// Regression coverage for Market-Maker Automation's alternative-explanation
// signals (roadmap: Inspector Core Architecture — Market Execution model
// scoping). Before this change, "behavior consistent with automated
// market-making" was inferred purely from order SHAPE (cancel ratio, size
// uniformity, burst timing, overall fill rate) — a spoofing/layering scheme
// dressed up with uniform sizing could satisfy every one of those checks.
// Four real alternative-explanation signals were added, each answering a
// question genuine market-making should satisfy that spoofing generally
// won't: broad counterparties (buildOfferBehaviorProfile's
// distinctCounterpartyCount), two-sided quoting (twoSidedRatio), external
// vs. self fills (externalFillPct, using buildOfferLifecycles' new
// selfCounterpartiesAtCreation/route fields), and inventory management
// (the new `inventory` object's driftRatio/reversions). All four are
// tri-state (true/false/null) so "no data available" is never silently
// read as "fails the test."
import { withPage, assert } from './helpers.mjs';

const suite = { register: [], run: async () => {
  let pass = 0, fail = 0;
  console.log('\n▶ Market-Maker Automation — Alternative-Explanation Signals');
  for (const { name, fn } of suite.register) {
    try { await fn(); console.log(`  PASS  ${name}`); pass++; }
    catch (err) { console.log(`  FAIL  ${name}`); console.log(`        ${err?.stack || err}`); fail++; }
  }
  return { pass, fail, total: suite.register.length };
}};
const test = (name, fn) => suite.register.push({ name, fn });

const ADDR = 'rMakerAAAAAAAAAAAAAAAAAAAAAAAAAAA1';

function mkOffer({ getsC, getsV, paysC, paysV, date, counterparties = [], selfCounterparties = [], consumedEvents = [], crossedGets = 0, route = null }) {
  return {
    takerGetsOriginal: { currency: getsC, issuer: getsC === 'XRP' ? null : 'rIssuer000000000000000000000000001', value: getsV },
    takerPaysOriginal: { currency: paysC, issuer: paysC === 'XRP' ? null : 'rIssuer000000000000000000000000001', value: paysV },
    createDate: date, status: 'cancelled', timeRestingSeconds: 60,
    counterpartiesAtCreation: counterparties, selfCounterpartiesAtCreation: selfCounterparties,
    consumedEvents, crossedAtCreation: { gets: crossedGets, pays: 0 }, route,
  };
}

test('A genuine-market-maker-shaped history (broad counterparties, two-sided, mostly external fills, reverting inventory) scores higher confidence with zero contradicting evidence', async () => {
  await withPage(async (page, { pageErrors }) => {
    await page.waitForFunction(() => window._debugBuildOfferBehaviorProfile && window._debugAnalyseMarketMakerAutomation, { timeout: 8000 });
    const { profile, finding } = await page.evaluate(({ addr }) => {
      const list = [];
      for (let i = 0; i < 25; i++) {
        const sellsXrp = i % 2 === 0;
        list.push({
          takerGetsOriginal: { currency: sellsXrp ? 'XRP' : 'USD', value: 100 },
          takerPaysOriginal: { currency: sellsXrp ? 'USD' : 'XRP', value: 100 },
          createDate: 800000000 + i * 20, status: 'cancelled', timeRestingSeconds: 60,
          counterpartiesAtCreation: [], selfCounterpartiesAtCreation: [],
          consumedEvents: [{ counterpartyAccount: `rCounterparty${i % 8}AAAAAAAAAAAAAAAA`, gets: 100, pays: 100 }],
          crossedAtCreation: { gets: 0, pays: 0 }, route: null,
        });
      }
      const profile = window._debugBuildOfferBehaviorProfile({ list }, [], addr);
      const automation = window._debugAnalyseMarketMakerAutomation(profile, { list }, [], addr, { realizedFillPctOverall: 40 });
      return { profile, finding: automation.findings[0] };
    }, { addr: ADDR });

    assert(profile.distinctCounterpartyCount === 8, `expected 8 distinct counterparties, got ${profile.distinctCounterpartyCount}`);
    assert(profile.externalFillPct === 100, `expected 100% external fills, got ${profile.externalFillPct}`);
    assert(Math.abs(profile.twoSidedRatio - 0.48) < 1e-9, `expected a ~0.48 two-sided ratio, got ${profile.twoSidedRatio}`);
    assert(profile.inventory.reversions === 0 && profile.inventory.driftRatio === 1, `expected a flat/managed inventory shape, got ${JSON.stringify(profile.inventory)}`);
    assert(finding.sev === 'info', `expected the automation-likely finding, got sev ${finding.sev}`);
    assert(finding.evidenceAgainstBenign.length === 0, `expected zero contradicting evidence for a genuine market-maker shape, got: ${JSON.stringify(finding.evidenceAgainstBenign)}`);
    assert(finding.confidence === 0.8, `expected confidence 0.8 (base 0.6 + 4 corroborating signals x0.05), got ${finding.confidence}`);
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

test('A spoofing-shaped history (one counterparty pool, one-directional, mostly self-fills, runaway inventory) scores lower confidence with all 4 signals contradicting', async () => {
  await withPage(async (page, { pageErrors }) => {
    await page.waitForFunction(() => window._debugBuildOfferBehaviorProfile && window._debugAnalyseMarketMakerAutomation, { timeout: 8000 });
    const { profile, finding } = await page.evaluate(({ addr }) => {
      const list = [];
      for (let i = 0; i < 25; i++) {
        list.push({
          takerGetsOriginal: { currency: 'XRP', value: 100 },
          takerPaysOriginal: { currency: 'USD', value: 100 },
          createDate: 800000000 + i * 20, status: 'cancelled', timeRestingSeconds: 60,
          counterpartiesAtCreation: [], selfCounterpartiesAtCreation: i % 3 === 0 ? [{ account: addr, gets: 100, pays: 100 }] : [],
          consumedEvents: i % 3 === 0 ? [{ counterpartyAccount: null, gets: 100, pays: 100 }] : [],
          crossedAtCreation: { gets: 0, pays: 0 }, route: null,
        });
      }
      const profile = window._debugBuildOfferBehaviorProfile({ list }, [], addr);
      const automation = window._debugAnalyseMarketMakerAutomation(profile, { list }, [], addr, { realizedFillPctOverall: 40 });
      return { profile, finding: automation.findings[0] };
    }, { addr: ADDR });

    assert(profile.distinctCounterpartyCount === 0, `expected 0 distinct counterparties, got ${profile.distinctCounterpartyCount}`);
    assert(profile.externalFillPct === 0, `expected 0% external fills (all self), got ${profile.externalFillPct}`);
    assert(profile.twoSidedRatio === 0, `expected a one-directional (0) two-sided ratio, got ${profile.twoSidedRatio}`);
    assert(profile.inventory.reversions === 0 && profile.inventory.driftRatio > 10, `expected a runaway, non-reverting inventory shape, got ${JSON.stringify(profile.inventory)}`);
    assert(finding.evidenceAgainstBenign.length === 4, `expected all 4 signals to contradict the market-making explanation, got: ${JSON.stringify(finding.evidenceAgainstBenign)}`);
    assert(finding.confidence < 0.4, `expected confidence meaningfully below the 0.6 base after 4 contradicting signals, got ${finding.confidence}`);
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

test('Zero identifiable fills reads as "no data" (null), not as a failed test — counterparty/fill signals are omitted while creation-derivable signals (two-sided, inventory) still apply', async () => {
  await withPage(async (page, { pageErrors }) => {
    await page.waitForFunction(() => window._debugBuildOfferBehaviorProfile && window._debugAnalyseMarketMakerAutomation, { timeout: 8000 });
    const { profile, finding } = await page.evaluate(({ addr }) => {
      const list = [];
      for (let i = 0; i < 25; i++) {
        list.push({
          takerGetsOriginal: { currency: 'XRP', value: 100 },
          takerPaysOriginal: { currency: 'USD', value: 100 },
          createDate: 800000000 + i * 20, status: 'cancelled', timeRestingSeconds: 60,
          counterpartiesAtCreation: [], selfCounterpartiesAtCreation: [],
          consumedEvents: [], crossedAtCreation: { gets: 0, pays: 0 }, route: null,
        });
      }
      const profile = window._debugBuildOfferBehaviorProfile({ list }, [], addr);
      const automation = window._debugAnalyseMarketMakerAutomation(profile, { list }, [], addr, { realizedFillPctOverall: 40 });
      return { profile, finding: automation.findings[0] };
    }, { addr: ADDR });

    assert(profile.externalFillPct === null, `expected null externalFillPct with zero identifiable fills, got ${profile.externalFillPct}`);
    assert(!finding.observed.some(o => /distinct counterpart/.test(o)), 'expected no counterparty-count observed line when no fill data exists');
    assert(!finding.observed.some(o => /identifiable fills/.test(o)), 'expected no external-fill observed line when no fill data exists');
    assert(!finding.evidenceAgainstBenign.some(e => /distinct counterpart/.test(e)), 'expected the unknown broad-counterparties signal to NOT be reported as contradicting evidence');
    assert(finding.evidenceAgainstBenign.some(e => /one direction/.test(e)), 'expected the one-directional-quoting signal (derivable from creation records alone) to still fire');
    assert(finding.evidenceAgainstBenign.some(e => /drifting/.test(e)), 'expected the runaway-inventory signal (derivable from creation records alone) to still fire');
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

test('buildOfferLifecycles distinguishes a real external counterparty from a self-trade at offer creation, and records the execution route', async () => {
  await withPage(async (page, { pageErrors }) => {
    await page.waitForFunction(() => window._debugOfferLifecycles, { timeout: 8000 });
    const result = await page.evaluate((addr) => {
      const other = 'rOtherTraderAAAAAAAAAAAAAAAAAAAAAA';
      const txList = [
        // Creates an offer that immediately crosses a DIFFERENT account's resting offer.
        {
          tx: { Account: addr, TransactionType: 'OfferCreate', Sequence: 1, hash: 'h1', date: 800000000, TakerGets: '100000000', TakerPays: { currency: 'USD', issuer: 'rIssuer00000000000000000000000001', value: '100' }, Flags: 0 },
          meta: {
            TransactionResult: 'tesSUCCESS',
            AffectedNodes: [
              { DeletedNode: { LedgerEntryType: 'Offer', FinalFields: { Account: other, TakerGets: '0', TakerPays: { currency: 'USD', issuer: 'rIssuer00000000000000000000000001', value: '0' } } } },
              { ModifiedNode: { LedgerEntryType: 'AccountRoot', FinalFields: { Account: addr, Balance: '899900000' }, PreviousFields: { Balance: '1000000000' } } },
              { ModifiedNode: { LedgerEntryType: 'RippleState', FinalFields: { Balance: { currency: 'USD', issuer: 'rIssuer00000000000000000000000001', value: '100' }, HighLimit: { issuer: addr }, LowLimit: { issuer: 'rIssuer00000000000000000000000001' } }, PreviousFields: { Balance: { currency: 'USD', issuer: 'rIssuer00000000000000000000000001', value: '0' } } } },
            ],
          },
        },
      ];
      const offerLifecycles = window._debugOfferLifecycles(txList, addr, {});
      return { record: offerLifecycles.list[0] };
    }, 'rSelfAddrAAAAAAAAAAAAAAAAAAAAAAAA1');

    assert(result.record.counterpartiesAtCreation.length === 1, `expected 1 external counterparty at creation, got ${JSON.stringify(result.record.counterpartiesAtCreation)}`);
    assert(result.record.selfCounterpartiesAtCreation.length === 0, `expected 0 self-counterparties for a real external fill, got ${JSON.stringify(result.record.selfCounterpartiesAtCreation)}`);
    assert('route' in result.record, 'expected the offer lifecycle record to carry a route field');
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
