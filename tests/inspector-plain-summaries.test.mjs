// Regression guard for the "In plain terms" beginner-facing summaries
// added to Drain Risk and Fund Flow Tracer, plus the Simple/Advanced mode
// gating that hides the dense per-episode/per-transaction evidence behind
// a real, pre-existing app-wide toggle (_analystMode) rather than a new
// one-off mechanism. These summaries synthesize data the sections already
// compute — no new analysis, no new severity/confidence scoring — so they
// must never contradict the detailed evidence they sit above, and must
// never appear/disappear inconsistently between modes.
import { withPage, connectAndShowDashboard, inspectAddress, makeSuite, assert } from './helpers.mjs';

const suite = makeSuite('Plain-English Summaries — Drain Risk & Fund Flow');

suite.register('Drain Risk: a real account renders the plain-summary box, visible level subtitles, and correct Simple/Advanced gating with no page errors', async () => {
  await withPage(async (page) => {
    const errors = [];
    page.on('pageerror', e => errors.push(e.message));
    await connectAndShowDashboard(page);
    await inspectAddress(page, 'rPVMhWBsfF9iMXYj3aAzJVkPDTFNSyWdKy', { timeout: 90000 });
    await page.waitForTimeout(1500);

    const simpleState = await page.evaluate(() => {
      const el = document.getElementById('inspect-drain-body');
      const adv = el.querySelector('.advanced-only');
      const smp = el.querySelector('.simple-only');
      return {
        hasPlainText: el.textContent.includes('In plain terms:'),
        hasCompromiseSub: el.textContent.includes('Could someone else have taken control'),
        hasBehaviorSub: el.textContent.includes('Is money actually leaving in an unusual way'),
        advVisible: adv ? getComputedStyle(adv).display !== 'none' : null,
        smpVisible: smp ? getComputedStyle(smp).display !== 'none' : null,
      };
    });
    assert(errors.length === 0, `expected zero page errors, got: ${JSON.stringify(errors)}`);
    assert(simpleState.hasPlainText, 'expected the "In plain terms" summary box');
    assert(simpleState.hasCompromiseSub && simpleState.hasBehaviorSub, 'expected visible plain-language subtitles under both risk-level badges');
    assert(simpleState.advVisible === false, 'expected the detailed evidence to be hidden in default Simple mode');
    assert(simpleState.smpVisible === true, 'expected the Simple-mode teaser to be visible in default Simple mode');

    await page.evaluate(() => window.toggleAnalystMode());
    await page.waitForTimeout(300);
    const advState = await page.evaluate(() => {
      const el = document.getElementById('inspect-drain-body');
      const adv = el.querySelector('.advanced-only');
      const smp = el.querySelector('.simple-only');
      return { advVisible: getComputedStyle(adv).display !== 'none', smpVisible: getComputedStyle(smp).display !== 'none' };
    });
    assert(advState.advVisible === true, 'expected the detailed evidence to become visible in Advanced mode');
    assert(advState.smpVisible === false, 'expected the Simple-mode teaser to hide in Advanced mode');
    await page.evaluate(() => window.toggleAnalystMode()); // restore default for other tests sharing the page lifecycle
  });
});

suite.register('Fund Flow: a real account with real outbound flow renders a real plain-summary sentence and gates the raw timeline the same way', async () => {
  await withPage(async (page) => {
    const errors = [];
    page.on('pageerror', e => errors.push(e.message));
    await connectAndShowDashboard(page);
    await inspectAddress(page, 'rnj7R3QUGzLZc9dg24jSrGabtt1tp1XD7A', { timeout: 90000 });
    await page.waitForTimeout(1500);

    const result = await page.evaluate(() => {
      const el = document.getElementById('inspect-fundflow-body');
      const adv = el.querySelector('.advanced-only');
      const smp = el.querySelector('.simple-only');
      return {
        hasPlainText: el.textContent.includes('In plain terms:'),
        mentionsOutboundXrp: /outbound XRP/.test(el.textContent),
        advVisible: adv ? getComputedStyle(adv).display !== 'none' : null,
        smpVisible: smp ? getComputedStyle(smp).display !== 'none' : null,
      };
    });
    assert(errors.length === 0, `expected zero page errors, got: ${JSON.stringify(errors)}`);
    assert(result.hasPlainText, 'expected the "In plain terms" summary box for an account with real outbound flow');
    assert(result.mentionsOutboundXrp, 'expected the summary to actually describe outbound XRP flow');
    assert(result.advVisible === false, 'expected the raw outflow timeline hidden in default Simple mode');
    assert(result.smpVisible === true, 'expected the Simple-mode teaser visible in default Simple mode');
  });
});

suite.register('Synthetic: buildDrainPlainSummary picks the auth-change-preceded case over a plain elevated-behavior reading, with critical tone', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugDrainPlainSummary, { timeout: 8000 });
    const result = await page.evaluate(() => window._debugDrainPlainSummary('low', 'high', { applicable: true, verdict: 'unusual-with-auth-change' }));
    assert(result.tone === 'crit', `expected critical tone for an auth-change-preceded transfer, got ${result.tone}`);
    assert(/security settings changed/.test(result.text), `expected the auth-change framing, got: "${result.text}"`);
  });
});

suite.register('Synthetic: buildDrainPlainSummary flags elevated compromise risk even when behavior looks clean', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugDrainPlainSummary, { timeout: 8000 });
    const result = await page.evaluate(() => window._debugDrainPlainSummary('critical', 'none', { applicable: false }));
    assert(result.tone === 'crit', `expected critical tone, got ${result.tone}`);
    assert(/control may have changed hands/.test(result.text), `expected the compromise framing, got: "${result.text}"`);
  });
});

suite.register('Synthetic: buildDrainPlainSummary flags elevated drain behavior when compromise risk is clean', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugDrainPlainSummary, { timeout: 8000 });
    const result = await page.evaluate(() => window._debugDrainPlainSummary('low', 'high', { applicable: false }));
    assert(result.tone === 'warn', `expected warn tone for high (not critical) behavior, got ${result.tone}`);
    assert(/larger-than-usual amount/.test(result.text), `expected the drain-behavior framing, got: "${result.text}"`);
  });
});

suite.register('Synthetic: buildDrainPlainSummary reports an all-clear "ok" reading when nothing is elevated', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugDrainPlainSummary, { timeout: 8000 });
    const result = await page.evaluate(() => window._debugDrainPlainSummary('low', 'none', { applicable: true, verdict: 'normal' }));
    assert(result.tone === 'ok', `expected ok tone for a fully clean account, got ${result.tone}`);
    assert(/nothing here suggests/i.test(result.text), `expected the all-clear framing, got: "${result.text}"`);
  });
});

suite.register('Synthetic: buildFundFlowPlainSummary returns null (not an empty fabricated box) when there are no outbound destinations', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugFundFlowPlainSummary, { timeout: 8000 });
    const result = await page.evaluate(() => window._debugFundFlowPlainSummary({ destinations: [], totalOut: 0, uniqueDests: 0 }));
    assert(result === null, 'expected null with no outbound destinations, not a fabricated summary');
  });
});

suite.register('Synthetic: buildFundFlowPlainSummary uses singular phrasing and critical tone for a single black-hole destination', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugFundFlowPlainSummary, { timeout: 8000 });
    const flow = {
      destinations: [{ addr: 'rBlackHole00000000000000000000000000', totalXrp: 500, entity: { name: 'Black Hole', type: 'blackhole' } }],
      totalOut: 500, uniqueDests: 1, newWalletDests: [],
    };
    const result = await page.evaluate((f) => window._debugFundFlowPlainSummary(f), flow);
    assert(result.tone === 'crit', `expected critical tone for a black-hole destination, got ${result.tone}`);
    assert(/single destination/.test(result.text), `expected singular phrasing, got: "${result.text}"`);
    assert(/can never be recovered/.test(result.text), `expected the irrecoverable-funds framing, got: "${result.text}"`);
  });
});

suite.register('Synthetic: buildFundFlowPlainSummary computes a real percentage and warn tone when a new-wallet destination is present', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugFundFlowPlainSummary, { timeout: 8000 });
    const flow = {
      destinations: [{ addr: 'rTopDest0000000000000000000000000000', totalXrp: 750, entity: null }],
      totalOut: 1000, uniqueDests: 3, newWalletDests: [{ addr: 'rTopDest0000000000000000000000000000' }],
    };
    const result = await page.evaluate((f) => window._debugFundFlowPlainSummary(f), flow);
    assert(result.tone === 'warn', `expected warn tone with a new-wallet destination present, got ${result.tone}`);
    assert(/75%/.test(result.text), `expected the real computed percentage (750\/1000=75%), got: "${result.text}"`);
    assert(/2 other destinations/.test(result.text), `expected the correct remaining-destination count (3-1=2), got: "${result.text}"`);
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
