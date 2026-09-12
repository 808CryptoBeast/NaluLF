// Regression guard for "Follow the Money" (beginner-UX spec §17-18) — a
// chronological, plain-English narrative of where an account's funds came
// from and went. Deliberately synthesizes ONLY data Fund Flow, Inbound
// Flow, and Drain Risk already compute — no new RPC calls, no new
// analysis. Must never fabricate a direction of flow that didn't happen
// (e.g. claiming funds "went" somewhere when there are zero outbound
// Payments) and must never render at all for an account with no tracked
// Payment flow in either direction.
import { withPage, connectAndShowDashboard, inspectAddress, makeSuite, assert } from './helpers.mjs';

const suite = makeSuite('Follow the Money');

function inboundFlow({ uniqueSources, totalIn, topSources }) {
  return { uniqueSources, totalIn, topSources };
}
function fundFlow({ uniqueDests, totalOut, topDests }) {
  return { uniqueDests, totalOut, topDests };
}

suite.register('A real active account renders the Follow the Money block alongside Account Journey with no page errors', async () => {
  await withPage(async (page) => {
    const errors = [];
    page.on('pageerror', e => errors.push(e.message));
    await connectAndShowDashboard(page);
    await inspectAddress(page, 'rPVMhWBsfF9iMXYj3aAzJVkPDTFNSyWdKy', { timeout: 90000 });
    await page.waitForTimeout(1500);

    const result = await page.evaluate(() => {
      const el = document.getElementById('account-behavior-body');
      const items = [...(el?.querySelectorAll('.security-timeline-item') || [])];
      const ftmItems = items.filter(item => !item.querySelector('.security-timeline-date'));
      return {
        titles: ftmItems.map(i => i.querySelector('.security-timeline-label')?.textContent),
        anyJourneyItems: items.length > ftmItems.length,
      };
    });

    assert(errors.length === 0, `expected zero page errors, got: ${JSON.stringify(errors)}`);
    assert(result.titles.some(t => /Where the funds came from|Where the funds went/.test(t || '')), `expected at least one Follow the Money chapter, got: ${JSON.stringify(result.titles)}`);
  });
});

suite.register('Inbound-only flow: real numbers in the inbound chapter, an honest "no outbound" fallback, and no fabricated net-position chapter', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugFollowTheMoney, { timeout: 8000 });
    const inbound = inboundFlow({ uniqueSources: 3, totalIn: 300, topSources: [{ addr: 'rSrc1', totalXrp: 200, entity: null }] });
    const outbound = fundFlow({ uniqueDests: 0, totalOut: 0, topDests: [] });

    const result = await page.evaluate(([inbound, outbound]) => window._debugFollowTheMoney(outbound, inbound, [], 'rAddr'), [inbound, outbound]);

    assert(result.applicable === true, 'expected applicable:true when inbound flow exists');
    const titles = result.chapters.map(c => c.title);
    assert(titles.includes('Where the funds came from'), `expected an inbound chapter, got: ${JSON.stringify(titles)}`);
    assert(titles.includes('Where the funds went'), `expected the no-outbound fallback chapter, got: ${JSON.stringify(titles)}`);
    assert(!titles.includes('Net position (tracked history)'), 'must not fabricate a net-position comparison when only one direction of flow exists');
    const inChapter = result.chapters.find(c => c.title === 'Where the funds came from');
    assert(/300 XRP/.test(inChapter.text) && /3 source/.test(inChapter.text) && /67%/.test(inChapter.text), `expected real numbers in the inbound narrative, got: "${inChapter.text}"`);
    const outChapter = result.chapters.find(c => c.title === 'Where the funds went');
    assert(/No outbound Payment transactions/.test(outChapter.text), 'expected an honest no-outbound message, not a fabricated destination');
  });
});

suite.register('Outbound-only flow, single destination: correct singular phrasing and no fabricated net-position chapter', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugFollowTheMoney, { timeout: 8000 });
    const inbound = inboundFlow({ uniqueSources: 0, totalIn: 0, topSources: [] });
    const outbound = fundFlow({ uniqueDests: 1, totalOut: 500, topDests: [{ addr: 'rDest1', totalXrp: 500, entity: { name: 'Kraken', type: 'exchange' } }] });

    const result = await page.evaluate(([inbound, outbound]) => window._debugFollowTheMoney(outbound, inbound, [], 'rAddr'), [inbound, outbound]);

    const outChapter = result.chapters.find(c => c.title === 'Where the funds went');
    assert(/single destination: Kraken/.test(outChapter.text), `expected singular-destination phrasing naming the known entity, got: "${outChapter.text}"`);
    assert(!result.chapters.some(c => c.title === 'Net position (tracked history)'), 'must not fabricate net position with zero inbound');
  });
});

suite.register('Both directions present: a real net-position chapter with correct direction and magnitude', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugFollowTheMoney, { timeout: 8000 });
    const inbound = inboundFlow({ uniqueSources: 2, totalIn: 1000, topSources: [{ addr: 'rSrc1', totalXrp: 900, entity: null }] });
    const outbound = fundFlow({ uniqueDests: 2, totalOut: 400, topDests: [{ addr: 'rDest1', totalXrp: 300, entity: null }] });

    const result = await page.evaluate(([inbound, outbound]) => window._debugFollowTheMoney(outbound, inbound, [], 'rAddr'), [inbound, outbound]);

    const net = result.chapters.find(c => c.title === 'Net position (tracked history)');
    assert(net, 'expected a net-position chapter when both directions have real flow');
    assert(/net inflow of 600 XRP/.test(net.text), `expected correct net inflow direction/magnitude (1000-400=600), got: "${net.text}"`);
  });
});

suite.register('A drain episode is surfaced as a "notable movement window" chapter, picking the highest-depletion episode when multiple exist', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugFollowTheMoney, { timeout: 8000 });
    const inbound = inboundFlow({ uniqueSources: 1, totalIn: 100, topSources: [{ addr: 'rSrc1', totalXrp: 100, entity: null }] });
    const outbound = fundFlow({ uniqueDests: 1, totalOut: 100, topDests: [{ addr: 'rDest1', totalXrp: 100, entity: null }] });
    const episodes = [
      { startDate: 1000, endDate: 2000, grossOutflowXrp: 50, grossTurnoverPct: 0.5, actualDepletionPct: 0.1, classification: 'pass-through' },
      { startDate: 3000, endDate: 4000, grossOutflowXrp: 90, grossTurnoverPct: 0.9, actualDepletionPct: 0.85, classification: 'potential-drain' },
    ];

    const result = await page.evaluate(([inbound, outbound, episodes]) => window._debugFollowTheMoney(outbound, inbound, episodes, 'rAddr'), [inbound, outbound, episodes]);

    const ep = result.chapters.find(c => c.title === 'A notable movement window');
    assert(ep, 'expected a notable-movement-window chapter when drain episodes exist');
    assert(/a potential drain/.test(ep.text), `expected the HIGHEST-depletion episode (potential-drain, 85%) to be picked over the lower one (pass-through, 10%), got: "${ep.text}"`);
    assert(/90 XRP/.test(ep.text) && /85%/.test(ep.text), `expected real numbers from the chosen episode, got: "${ep.text}"`);
  });
});

suite.register('No inbound and no outbound flow at all produces applicable:false, not an empty fabricated narrative', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugFollowTheMoney, { timeout: 8000 });
    const inbound = inboundFlow({ uniqueSources: 0, totalIn: 0, topSources: [] });
    const outbound = fundFlow({ uniqueDests: 0, totalOut: 0, topDests: [] });

    const result = await page.evaluate(([inbound, outbound]) => window._debugFollowTheMoney(outbound, inbound, [], 'rAddr'), [inbound, outbound]);
    assert(result.applicable === false, 'expected applicable:false when there is no tracked Payment flow in either direction');
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
