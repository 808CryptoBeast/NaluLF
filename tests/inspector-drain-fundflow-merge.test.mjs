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

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
