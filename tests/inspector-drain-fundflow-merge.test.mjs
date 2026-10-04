// Regression guard for merging Fund Flow Tracer into Drain Risk into one
// combined "Drain Risk & Fund Flow" section, plus surfacing the REAL
// per-episode destination breakdown _enrichDrainEpisode already computed
// internally (previously used only to derive text like "70% went to a
// single destination," never actually shown). The merge must be a real
// structural nesting — Fund Flow's body/badge living inside Drain Risk's
// own .section-body — not just visual proximity, so collapsing the
// section hides both halves together (the collapse mechanism specifically
// targets .section-body, which is why this was tested directly rather
// than assumed).
import { withPage, connectAndShowDashboard, inspectAddress, makeSuite, assert } from './helpers.mjs';

const suite = makeSuite('Drain Risk + Fund Flow Merge');

suite.register('section-fundflow no longer exists as its own section; its content is nested inside the combined Drain Risk section, rendered, with no page errors', async () => {
  await withPage(async (page) => {
    const errors = [];
    page.on('pageerror', e => errors.push(e.message));
    await connectAndShowDashboard(page);
    await inspectAddress(page, 'rnj7R3QUGzLZc9dg24jSrGabtt1tp1XD7A', { timeout: 90000 });
    await page.waitForTimeout(1500);

    const result = await page.evaluate(() => ({
      fundflowSectionExists: !!document.getElementById('section-fundflow'),
      drainSectionTitle: document.querySelector('#section-drain .widget-title')?.textContent,
      fundflowBodyIsInsideDrainSection: !!document.getElementById('section-drain')?.contains(document.getElementById('inspect-fundflow-body')),
      fundflowBadgeIsInsideDrainSection: !!document.getElementById('section-drain')?.contains(document.getElementById('badge-fundflow')),
      fundflowContentRendered: (document.getElementById('inspect-fundflow-body')?.innerHTML?.length || 0) > 100,
      hasTopDestinations: /Top Destinations/.test(document.getElementById('inspect-fundflow-body')?.innerHTML || ''),
      noOrphanFundflowNavButton: !document.querySelector('.in-btn[data-jump="fundflow"]'),
      drainNavButtonStillExists: !!document.querySelector('.in-btn[data-jump="drain"]'),
    }));

    assert(errors.length === 0, `expected zero page errors, got: ${JSON.stringify(errors)}`);
    assert(!result.fundflowSectionExists, 'expected section-fundflow to no longer exist as its own section');
    assert(/Drain Risk/.test(result.drainSectionTitle) && /Fund Flow/.test(result.drainSectionTitle), `expected the combined section title to name both halves, got: "${result.drainSectionTitle}"`);
    assert(result.fundflowBodyIsInsideDrainSection, 'expected Fund Flow\'s render target to be a real DOM descendant of section-drain, not just visually adjacent');
    assert(result.fundflowBadgeIsInsideDrainSection, 'expected Fund Flow\'s badge to be nested inside the combined section too');
    assert(result.fundflowContentRendered, 'expected real Fund Flow content to render inside the merged section');
    assert(result.hasTopDestinations, 'expected the Top Destinations list to be part of the merged content');
    assert(result.noOrphanFundflowNavButton, 'expected the old separate "Flow" nav button to be removed, not left pointing at a dead section');
    assert(result.drainNavButtonStillExists, 'expected the "Drain" nav button to still exist and now cover the combined section');
  });
});

suite.register('Collapsing the combined section hides the Fund Flow content too — it is a real nested child of .section-body, not a sibling that escapes the collapse mechanism', async () => {
  await withPage(async (page) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, 'rnj7R3QUGzLZc9dg24jSrGabtt1tp1XD7A', { timeout: 90000 });
    await page.waitForTimeout(1500);

    await page.evaluate(() => document.getElementById('section-drain').classList.add('collapsed'));
    // The CSS transition is only .28s, but this section grew substantially
    // taller with the Before/During/After + cross-reference additions —
    // under test-runner CPU contention the transition can take noticeably
    // longer in wall-clock time than its nominal duration to actually
    // finish, so this waits well past that nominal duration for margin.
    await page.waitForTimeout(1000);

    const result = await page.evaluate(() => {
      const body = document.getElementById('inspect-drain-body');
      const cs = getComputedStyle(body);
      return {
        bodyContainsFundflow: body.contains(document.getElementById('inspect-fundflow-body')),
        maxHeight: cs.maxHeight,
        opacity: cs.opacity,
      };
    });
    assert(result.bodyContainsFundflow, 'expected inspect-fundflow-body to be a real descendant of the collapsible .section-body element');
    assert(result.maxHeight === '0px', `expected the collapsed section's max-height to be 0px (hiding Fund Flow along with everything else), got ${result.maxHeight}`);
    assert(result.opacity === '0', `expected the collapsed section's opacity to be 0, got ${result.opacity}`);
  });
});

suite.register('A real drain episode shows its own "Where this movement\'s funds went" destination breakdown in Advanced mode, with a real address and percentage', async () => {
  await withPage(async (page) => {
    const errors = [];
    page.on('pageerror', e => errors.push(e.message));
    await connectAndShowDashboard(page);
    await inspectAddress(page, 'rnj7R3QUGzLZc9dg24jSrGabtt1tp1XD7A', { timeout: 90000 });
    await page.waitForTimeout(1500);
    await page.evaluate(() => window.toggleAnalystMode());
    await page.waitForTimeout(500);

    const result = await page.evaluate(() => {
      const el = document.getElementById('inspect-drain-body');
      const idx = el.innerHTML.indexOf("Where this movement's funds went");
      return {
        hasDestBlock: idx !== -1,
        hasRealAddressButton: /addr-link mono cut" data-addr="r[a-zA-Z0-9]{20,}"/.test(el.innerHTML),
        hasPercentage: /\(\d+%\)/.test(el.innerHTML),
      };
    });
    await page.evaluate(() => window.toggleAnalystMode()); // restore default

    assert(errors.length === 0, `expected zero page errors, got: ${JSON.stringify(errors)}`);
    assert(result.hasDestBlock, 'expected at least one episode to show its own destination breakdown for this known-drain-episode account');
    assert(result.hasRealAddressButton, 'expected a real clickable address in the destination breakdown');
    assert(result.hasPercentage, 'expected a real percentage-of-episode-outflow figure');
  });
});

suite.register('Synthetic: _renderEpisodeDestinations renders real ranked rows with correct percentages, and returns empty string for no destination data', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugRenderEpisodeDestinations, { timeout: 8000 });
    const destinations = [
      { addr: 'rDestA00000000000000000000000000000', xrp: 750, entity: { name: 'Kraken', type: 'exchange' } },
      { addr: 'rDestB00000000000000000000000000000', xrp: 250, entity: null },
    ];
    const html = await page.evaluate((d) => window._debugRenderEpisodeDestinations(d, 1000), destinations);
    assert(/Where this movement's funds went/.test(html), 'expected the section label');
    assert(/rDestA0000…0000000/.test(html) || /rDestA/.test(html), 'expected the first destination address to appear');
    assert(/75%/.test(html), `expected the correct percentage (750\/1000=75%), got HTML containing: ${html.slice(0, 400)}`);
    assert(/25%/.test(html), `expected the correct percentage for the second destination (250\/1000=25%), got HTML containing: ${html.slice(0, 400)}`);
    assert(/Kraken/.test(html), 'expected the known-entity name to appear for the tagged destination');

    const empty = await page.evaluate(() => window._debugRenderEpisodeDestinations(null, 1000));
    assert(empty === '', `expected an empty string for no destination data, not a broken empty box, got: "${empty}"`);
    const emptyArr = await page.evaluate(() => window._debugRenderEpisodeDestinations([], 1000));
    assert(emptyArr === '', `expected an empty string for an empty destinations array, got: "${emptyArr}"`);
  });
});

// ── Contradiction fixes (roadmap: Inspector 5.0 overhaul, "never render
// mutually contradictory text") ──────────────────────────────────────────
// Two real, reproduced bugs on a 13+ year old real account
// (rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh): (1) Fund Flow said "No inbound or
// outbound XRP flow found" while its OWN Top Destinations table listed real
// nonzero transfers, and (2) the Drain Risk plain summary said "shows signs
// that control may have changed hands... commonly appears in account
// takeovers" for an account whose own finding said the opposite ("could be
// deliberate self-custody hardening").

suite.register('_extractPaymentAmount: a pre-amendment "unavailable" delivered_amount is excluded from totals, not NaN-poisoning the entire sum', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugFundFlow, { timeout: 8000 });
    const result = await page.evaluate(() => {
      const addr = 'rSender0000000000000000000000000000000';
      const dest = 'rDest00000000000000000000000000000000';
      const txList = [
        // A real, normal 1000 XRP payment.
        { tx: { TransactionType: 'Payment', Account: addr, Destination: dest, Amount: '1000000000', date: 100 }, meta: { TransactionResult: 'tesSUCCESS' } },
        // A pre-amendment partial payment whose delivered_amount is the
        // literal string "unavailable" — the real XRPL data shape that
        // caused this bug.
        { tx: { TransactionType: 'Payment', Account: addr, Destination: dest, Amount: '500000000', date: 200 }, meta: { TransactionResult: 'tesSUCCESS', delivered_amount: 'unavailable' } },
      ];
      return window._debugFundFlow(txList, addr, new Map());
    });
    const dest = result.destinations[0];
    assert(dest.totalXrp === 1000, `expected the real 1000 XRP payment to count, with the "unavailable" one excluded (not NaN-poisoning the total), got totalXrp=${dest.totalXrp}`);
    assert(dest.hasUnknownAmount === true, 'expected hasUnknownAmount to flag that this destination\'s total may be incomplete');
    assert(result.totalOut === 1000, `expected the top-level totalOut to be the real 1000 (not NaN/0), got ${result.totalOut}`);
    assert(result.unknownAmountCount === 1, `expected unknownAmountCount to be 1, got ${result.unknownAmountCount}`);
    assert(!Number.isNaN(result.totalOut), 'expected totalOut to never be NaN');
  });
});

suite.register('_extractPaymentAmount: the same "unavailable" guard applies to Inbound Flow (analyseInboundFlow), not just outbound', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugAnalyseInboundFlow, { timeout: 8000 });
    const result = await page.evaluate(() => {
      const addr = 'rRecipient0000000000000000000000000000';
      const src = 'rSource000000000000000000000000000000';
      const txList = [
        { tx: { TransactionType: 'Payment', Account: src, Destination: addr, Amount: '2000000', date: 100 }, meta: { TransactionResult: 'tesSUCCESS' } },
        { tx: { TransactionType: 'Payment', Account: src, Destination: addr, Amount: '9999999', date: 200 }, meta: { TransactionResult: 'tesSUCCESS', delivered_amount: 'unavailable' } },
      ];
      return window._debugAnalyseInboundFlow(txList, addr);
    });
    assert(result.totalIn === 2, `expected the real 2 XRP payment to count with the unavailable one excluded, got totalIn=${result.totalIn}`);
    assert(!Number.isNaN(result.totalIn), 'expected totalIn to never be NaN');
    assert(result.unknownAmountCount === 1, `expected unknownAmountCount to be 1, got ${result.unknownAmountCount}`);
  });
});

suite.register('buildDrainPlainSummary: self-set regular key reads as deliberate hardening (ok tone, no alarming "takeovers" language), unknown-setter reads as an honest data-coverage caveat (warn tone), and a genuinely different account stays critical', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugBuildDrainPlainSummary, { timeout: 8000 });
    const result = await page.evaluate(() => ({
      selfSet: window._debugBuildDrainPlainSummary('medium', 'none', null, 'self-set'),
      unknownSetter: window._debugBuildDrainPlainSummary('medium', 'none', null, 'unknown-setter'),
      differentAccount: window._debugBuildDrainPlainSummary('critical', 'none', null, 'different-account'),
    }));
    assert(result.selfSet.tone === 'ok', `expected self-set to read as 'ok' tone, got "${result.selfSet.tone}"`);
    assert(!/commonly appears in account takeovers/.test(result.selfSet.text), `expected self-set to NOT use alarming takeover language, got: "${result.selfSet.text}"`);
    assert(/hardening/.test(result.selfSet.text), `expected self-set to name the hardening pattern, got: "${result.selfSet.text}"`);

    assert(result.unknownSetter.tone === 'warn', `expected unknown-setter to read as 'warn' (not crit), got "${result.unknownSetter.tone}"`);
    assert(!/commonly appears in account takeovers/.test(result.unknownSetter.text), `expected unknown-setter to NOT use alarming takeover language, got: "${result.unknownSetter.text}"`);
    assert(/predates the analysed transaction history|can't be confirmed/.test(result.unknownSetter.text), `expected unknown-setter to honestly name the data-coverage gap, got: "${result.unknownSetter.text}"`);

    assert(result.differentAccount.tone === 'crit', `expected a genuinely different-account key change to stay critical, got "${result.differentAccount.tone}"`);
    assert(/control may have changed hands/.test(result.differentAccount.text), `expected the different-account case to keep the real alarm language, got: "${result.differentAccount.text}"`);
  });
});

suite.register('Live regression: a 13+ year old real account with no SetRegularKey in its capped history shows consistent, non-contradictory Fund Flow and Drain Risk text', async () => {
  await withPage(async (page, { pageErrors }) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh', { timeout: 120000 });
    await page.waitForTimeout(1500);

    const result = await page.evaluate(() => {
      const drainEl = document.getElementById('inspect-drain-body');
      const fundflowHtml = document.getElementById('inspect-fundflow-body')?.innerHTML || '';
      const plainBox = [...drainEl.querySelectorAll('div')].find(d => d.innerHTML.includes('In plain terms:'));
      return {
        plainTermsText: plainBox?.textContent || '',
        hasNoFlowMsg: /No inbound or outbound XRP flow found/.test(fundflowHtml),
        hasTopDestinations: /Top Destinations/.test(fundflowHtml),
      };
    });

    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
    assert(!/control may have changed hands/.test(result.plainTermsText), `expected no alarming "control may have changed hands" text for an account with no confirmed takeover evidence, got: "${result.plainTermsText}"`);
    // The real contradiction: "no flow found" must never appear alongside a
    // real, populated Top Destinations table in the SAME panel.
    assert(!(result.hasNoFlowMsg && result.hasTopDestinations), `expected Fund Flow to never show "no flow found" alongside a real Top Destinations list — got hasNoFlowMsg=${result.hasNoFlowMsg}, hasTopDestinations=${result.hasTopDestinations}`);
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
