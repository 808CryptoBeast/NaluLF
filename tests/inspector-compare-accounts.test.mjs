// Regression guard for "Compare Accounts" (beginner-UX spec §57) — a
// side-by-side forensic summary of two accounts. Deliberately does NOT
// duplicate any analysis logic: it captures the same globals every
// inspection already caches (window._lastInspectResult/_lastCategoryRisk/
// _lastBalXrp) for the account already showing, then runs one real
// second inspection (the same runInspect() the main Inspect button
// calls) and captures those globals again — two snapshots, zero new
// forensic computation.
import { withPage, connectAndShowDashboard, inspectAddress, makeSuite, assert } from './helpers.mjs';

const suite = makeSuite('Compare Accounts');

suite.register('Opening Compare with no inspection yet shows a clear message rather than a broken modal', async () => {
  await withPage(async (page) => {
    const errors = [];
    page.on('pageerror', e => errors.push(e.message));
    page.on('dialog', d => d.accept());
    await connectAndShowDashboard(page);
    await page.evaluate(() => window.switchTab(null, 'inspector'));
    await page.evaluate(() => window.openCompareModal());
    await page.waitForTimeout(200);
    const overlayVisible = await page.evaluate(() => document.getElementById('compareOverlay')?.style.display === 'flex');
    assert(!overlayVisible, 'the compare modal must not open when there is no current inspection to compare from');
    assert(errors.length === 0, `expected zero page errors, got: ${JSON.stringify(errors)}`);
  });
});

suite.register('A real end-to-end comparison between two different real accounts renders a full side-by-side summary with no page errors', async () => {
  await withPage(async (page) => {
    const errors = [];
    page.on('pageerror', e => errors.push(e.message));
    await connectAndShowDashboard(page);
    await inspectAddress(page, 'rPVMhWBsfF9iMXYj3aAzJVkPDTFNSyWdKy', { timeout: 90000 });
    await page.waitForTimeout(1500);

    await page.evaluate(() => window.openCompareModal());
    const addrAText = await page.evaluate(() => document.getElementById('compareAddrA')?.textContent);
    assert(/rPVMhWBs/.test(addrAText || ''), `expected Account A to show the currently-inspected address, got: "${addrAText}"`);

    await page.fill('#compareAddrBInput', 'rsoLo2S1kiGeCcn6hCUXVrCpGMWLrRrLZz');
    await page.evaluate(() => window.runAccountComparison());
    await page.waitForSelector('#compareStepResult', { state: 'visible', timeout: 90000 });
    await page.waitForTimeout(500);

    const result = await page.evaluate(() => {
      const el = document.getElementById('compareStepResult');
      return {
        hasRiskScoreRow: /Overall Risk Score/.test(el?.innerHTML || ''),
        hasCategorySection: /By Risk Category/.test(el?.innerHTML || ''),
        hasFindingsSection: /Top Findings/.test(el?.innerHTML || ''),
        labelCount: (el?.innerHTML.match(/class="compare-label"/g) || []).length,
        inputHidden: document.getElementById('compareStepInput')?.style.display === 'none',
      };
    });
    assert(result.hasRiskScoreRow, 'expected an Overall Risk Score row');
    assert(result.hasCategorySection, 'expected a By Risk Category section');
    assert(result.hasFindingsSection, 'expected a Top Findings section');
    // 4 top-line rows (risk score, wallet age, balance, tx count) + 7 risk categories = 11
    assert(result.labelCount === 11, `expected 11 labeled rows (4 top-line + 7 categories), got ${result.labelCount}`);
    assert(result.inputHidden, 'expected the input step to be hidden once results render');
    assert(errors.length === 0, `expected zero page errors, got: ${JSON.stringify(errors)}`);
  });
});

suite.register('An invalid address for Account B is rejected with a clear error, without running a second inspection', async () => {
  await withPage(async (page) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, 'rPVMhWBsfF9iMXYj3aAzJVkPDTFNSyWdKy', { timeout: 90000 });
    await page.waitForTimeout(1000);

    await page.evaluate(() => window.openCompareModal());
    await page.fill('#compareAddrBInput', 'not-a-real-address');
    await page.evaluate(() => window.runAccountComparison());
    await page.waitForTimeout(300);

    const result = await page.evaluate(() => ({
      errVisible: document.getElementById('compareInputErr')?.style.display !== 'none',
      errText: document.getElementById('compareInputErr')?.textContent,
      resultShown: document.getElementById('compareStepResult')?.style.display === '',
    }));
    assert(result.errVisible, 'expected a visible error for an invalid address');
    assert(/Invalid address/.test(result.errText || ''), `expected an "Invalid address" message, got: "${result.errText}"`);
    assert(!result.resultShown, 'must not proceed to the results view on invalid input');
  });
});

suite.register('Comparing an account against itself is rejected with a clear error', async () => {
  await withPage(async (page) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, 'rPVMhWBsfF9iMXYj3aAzJVkPDTFNSyWdKy', { timeout: 90000 });
    await page.waitForTimeout(1000);

    await page.evaluate(() => window.openCompareModal());
    await page.fill('#compareAddrBInput', 'rPVMhWBsfF9iMXYj3aAzJVkPDTFNSyWdKy');
    await page.evaluate(() => window.runAccountComparison());
    await page.waitForTimeout(300);

    const result = await page.evaluate(() => ({
      errVisible: document.getElementById('compareInputErr')?.style.display !== 'none',
      errText: document.getElementById('compareInputErr')?.textContent,
    }));
    assert(result.errVisible, 'expected a visible error when comparing an account against itself');
    assert(/different address/.test(result.errText || ''), `expected a "different address" message, got: "${result.errText}"`);
  });
});

suite.register('_captureCompareSnapshot only returns data for the account that was JUST inspected, never a stale mismatch', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugCaptureCompareSnapshot, { timeout: 8000 });
    const result = await page.evaluate(() => {
      // Simulate the cached globals belonging to a DIFFERENT address than
      // the one being asked about — must not silently return mismatched data.
      window._lastInspectResult = { addr: 'rSomeOtherAddr00000000000000000000', riskScore: 50, walletAgeDays: 10, walletAgeVerified: true, txCount: 5 };
      window._lastCategoryRisk = {};
      window._lastAllFindings = [];
      window._lastBalXrp = 100;
      return window._debugCaptureCompareSnapshot('rNotTheCachedAddr000000000000000000');
    });
    assert(result === null, `expected null for a mismatched address, got: ${JSON.stringify(result)}`);
  });
});

suite.register('_renderCompareResult colors risk scores by severity band and shows an honest empty-state for a side with no findings', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugRenderCompareResult, { timeout: 8000 });
    // topFindings is passed through as-is by _renderCompareResult — sorting
    // by confidence is _captureCompareSnapshot's job (tested separately
    // below), so this fixture is pre-sorted to isolate what this test
    // actually checks: color banding and the empty-state fallback.
    const snapA = {
      addr: 'rAccountA00000000000000000000000000', riskScore: 82, walletAgeDays: 400, walletAgeVerified: true,
      txCount: 120, balXrp: 5000, categoryRisk: { security: { score: 90 }, 'market-integrity': { score: 10 } },
      topFindings: [
        { sev: 'critical', confidence: 0.9, headline: 'strong finding' },
        { sev: 'warn', confidence: 0.4, headline: 'weak finding' },
      ],
    };
    const snapB = {
      addr: 'rAccountB00000000000000000000000000', riskScore: 20, walletAgeDays: 50, walletAgeVerified: false,
      txCount: 30, balXrp: 100, categoryRisk: {}, topFindings: [],
    };
    const html = await page.evaluate(([a, b]) => window._debugRenderCompareResult(a, b), [snapA, snapB]);

    assert(/#ff5555/.test(html) && html.indexOf('#ff5555') < html.indexOf('82'), 'expected the high risk score (82) to be colored in the critical (red) band');
    assert(/#50fa7b/.test(html), 'expected the low risk score (20) to be colored in the ok (green) band');
    const strongIdx = html.indexOf('strong finding');
    const weakIdx = html.indexOf('weak finding');
    assert(strongIdx !== -1 && weakIdx !== -1 && strongIdx < weakIdx, 'expected the given finding order to be preserved (rendering does not reorder)');
    assert(/No critical\/warning findings/.test(html), 'expected an honest empty-state note for the side with no findings, not a blank column');
  });
});

suite.register('_captureCompareSnapshot sorts topFindings by confidence descending and excludes "ok"-severity findings', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugCaptureCompareSnapshot, { timeout: 8000 });
    const result = await page.evaluate(() => {
      window._lastInspectResult = { addr: 'rSnapTestAddr000000000000000000000', riskScore: 55, walletAgeDays: 30, walletAgeVerified: true, txCount: 12 };
      window._lastCategoryRisk = {};
      window._lastBalXrp = 250;
      window._lastAllFindings = [
        { sev: 'warn', confidence: 0.4, headline: 'weak finding' },
        { sev: 'critical', confidence: 0.9, headline: 'strong finding' },
        { sev: 'ok', confidence: 0.95, headline: 'should be excluded — ok severity' },
        { sev: 'warn', confidence: 0.6, headline: 'medium finding' },
      ];
      return window._debugCaptureCompareSnapshot('rSnapTestAddr000000000000000000000');
    });
    assert(result, 'expected a real snapshot for the matching address');
    const headlines = result.topFindings.map(f => f.headline);
    assert(headlines.length === 3, `expected 3 findings (ok-severity excluded), got: ${JSON.stringify(headlines)}`);
    assert(JSON.stringify(headlines) === JSON.stringify(['strong finding', 'medium finding', 'weak finding']), `expected descending-confidence order, got: ${JSON.stringify(headlines)}`);
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
