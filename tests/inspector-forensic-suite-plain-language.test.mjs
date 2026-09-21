// Regression guard for the Forensic Analytics Suite's plain-language
// translation layer: every engine (Benford's Law, Shannon's Entropy,
// Zipf's Law, Time Series, Offer/Flow Coupling) now leads with four short
// layers — What it checks / What Nalu found / Why it matters / What it
// does NOT prove — instead of a raw stat table alone. The four static
// layers are per-engine boilerplate; only "What Nalu found" is dynamic,
// built from that engine's own real verdict/stats. Benford's own richer
// bespoke explainer is kept as-is (not replaced) but gains the specific
// "algorithmic trading can naturally violate Benford" caveat.
import { withPage, connectAndShowDashboard, inspectAddress, makeSuite, assert } from './helpers.mjs';

const suite = makeSuite('Forensic Suite Plain Language');

const ACTIVE_ACCOUNT = 'rnj7R3QUGzLZc9dg24jSrGabtt1tp1XD7A';

suite.register('A real active account renders the 4-layer header with real dynamic findings for Entropy, Zipf, Time Series, and Offer/Flow Coupling, with no page errors', async () => {
  await withPage(async (page, { pageErrors }) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, ACTIVE_ACCOUNT, { timeout: 90000 });
    await page.waitForTimeout(1500);

    const result = await page.evaluate(() => {
      const engines = ['entropy', 'zipf', 'timeseries', 'granger'];
      const out = {};
      for (const eng of engines) {
        const layer = document.getElementById(`inspect-${eng}-body`)?.querySelector('.forensic-4layer');
        const rows = layer ? [...layer.querySelectorAll('.forensic-4layer-row')].map(r => r.querySelector('.forensic-4layer-label')?.textContent) : null;
        const foundText = layer?.querySelectorAll('.forensic-4layer-text')[1]?.textContent;
        out[eng] = { hasAllFourLayers: rows?.length === 4, labels: rows, foundText };
      }
      return out;
    });
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
    for (const eng of ['entropy', 'zipf', 'timeseries', 'granger']) {
      assert(result[eng].hasAllFourLayers, `expected all 4 layers for ${eng}, got labels: ${JSON.stringify(result[eng].labels)}`);
      assert(result[eng].labels.join('|') === 'What it checks|What Nalu found|Why it matters|What it does NOT prove', `expected the exact 4-layer order for ${eng}, got: ${JSON.stringify(result[eng].labels)}`);
      assert(result[eng].foundText && result[eng].foundText.length > 10, `expected real dynamic content in "What Nalu found" for ${eng}, got: "${result[eng].foundText}"`);
    }
  });
});

suite.register('Benford\'s Law explicitly names algorithmic trading as a natural (non-fraudulent) cause of deviation', async () => {
  await withPage(async (page, { pageErrors }) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, ACTIVE_ACCOUNT, { timeout: 90000 });
    await page.waitForTimeout(1500);

    const benfordText = await page.evaluate(() => document.getElementById('inspect-benfords-body')?.textContent || '');
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
    // Only assertable when this account's Benford verdict actually reached
    // high-deviation (live data — not guaranteed every run); otherwise just
    // confirm the panel rendered without error.
    if (/high-deviation|too calculated/.test(benfordText)) {
      assert(/algorithmic/i.test(benfordText), `expected an explicit "algorithmic trading" caveat on a high-deviation verdict, got: ${benfordText.slice(0, 500)}`);
    } else {
      assert(benfordText.length > 0, 'expected the Benford panel to render some content regardless of verdict');
    }
  });
});

suite.register('Synthetic: _renderForensicFourLayer renders all four labels with the real per-engine text supplied, in order', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugRenderForensicFourLayer, { timeout: 8000 });
    const html = await page.evaluate(() => window._debugRenderForensicFourLayer({
      checks: 'CHECKS_TEXT', found: 'FOUND_TEXT', matters: 'MATTERS_TEXT', doesNotProve: 'DOES_NOT_PROVE_TEXT',
    }));
    const checksIdx = html.indexOf('CHECKS_TEXT');
    const foundIdx = html.indexOf('FOUND_TEXT');
    const mattersIdx = html.indexOf('MATTERS_TEXT');
    const doesNotIdx = html.indexOf('DOES_NOT_PROVE_TEXT');
    assert(checksIdx !== -1 && foundIdx !== -1 && mattersIdx !== -1 && doesNotIdx !== -1, `expected all four texts to render, got: ${html.slice(0, 600)}`);
    assert(checksIdx < foundIdx && foundIdx < mattersIdx && mattersIdx < doesNotIdx, 'expected the four layers to render in checks->found->matters->doesNotProve order');
  });
});

suite.register('Each Forensic Suite engine\'s own accordion badge is populated with a real, distinct state — not permanently blank', async () => {
  await withPage(async (page, { pageErrors }) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, ACTIVE_ACCOUNT, { timeout: 90000 });
    await page.waitForTimeout(1500);

    const badges = await page.evaluate(() => {
      const ids = ['badge-benfords', 'badge-entropy', 'badge-zipf', 'badge-timeseries', 'badge-granger'];
      return Object.fromEntries(ids.map(id => [id, document.getElementById(id)?.textContent?.trim()]));
    });
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
    for (const [id, text] of Object.entries(badges)) {
      assert(!!text, `expected ${id} to have a real, non-blank badge text, got: "${text}"`);
    }
  });
});

suite.register('Regression: Shannon\'s Entropy reports verdict "insufficient" (not "normal") when none of its 4 sub-metrics could be computed', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugShannonsEntropy && window._debugSetForensicEngineBadge, { timeout: 8000 });
    const thinTxList = Array.from({ length: 5 }, (_, i) => ({
      tx: { TransactionType: 'Payment', Account: 'rTestAddr000000000000000000000000000', Destination: 'rOther00000000000000000000000000000', Amount: String(1000000 + i), date: 800000000 + i * 1000 },
    }));
    const result = await page.evaluate((txList) => window._debugShannonsEntropy(txList, 'rTestAddr000000000000000000000000000'), thinTxList);
    assert(result.verdict === 'insufficient', `expected verdict "insufficient" for a thin-history account where nothing could be computed, got "${result.verdict}"`);
    assert(result.signals.length === 1 && /[Ii]nsufficient/.test(result.signals[0].label), 'expected the single "insufficient data" finding');

    const badge = await page.evaluate((v) => {
      document.body.insertAdjacentHTML('beforeend', '<span id="badge-test-entropy-2"></span>');
      window._debugSetForensicEngineBadge('badge-test-entropy-2', v);
      const el = document.getElementById('badge-test-entropy-2');
      return { text: el.textContent, cls: el.className };
    }, result.verdict);
    assert(badge.text === 'Insufficient Data', `expected the badge to read "Insufficient Data", not "Normal" or blank, got "${badge.text}"`);
    assert(badge.cls.includes('--neutral'), `expected a neutral (not ok/green) tone for insufficient data, got "${badge.cls}"`);
  });
});

suite.register('Synthetic: _setForensicEngineBadge maps every known verdict to a distinct, correctly-toned label', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugSetForensicEngineBadge, { timeout: 8000 });
    const cases = [
      ['insufficient', 'Insufficient Data', '--neutral'],
      ['normal', 'Normal', '--ok'],
      ['elevated', 'Elevated', '--warn'],
      ['anomalous', 'Anomalous', '--crit'],
      ['strong-coupling', 'Strong Coupling', '--crit'],
      ['high-deviation', 'High Deviation', '--crit'],
      ['moderate-deviation', 'Moderate', '--warn'],
    ];
    for (const [verdict, expectedText, expectedToneClass] of cases) {
      const result = await page.evaluate((v) => {
        const id = 'badge-test-' + v;
        document.body.insertAdjacentHTML('beforeend', `<span id="${id}"></span>`);
        window._debugSetForensicEngineBadge(id, v);
        const el = document.getElementById(id);
        return { text: el.textContent, cls: el.className };
      }, verdict);
      assert(result.text === expectedText, `expected verdict "${verdict}" to show text "${expectedText}", got "${result.text}"`);
      assert(result.cls.includes(expectedToneClass), `expected verdict "${verdict}" to include tone class "${expectedToneClass}", got "${result.cls}"`);
    }
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
