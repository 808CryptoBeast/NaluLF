// Regression coverage for "Inspector export to PDF — shareable investigation
// report" (roadmap: Security). Found already fully built and working while
// auditing the roadmap against its own actual source — printInspectorReport()
// opens a real popup with clean print styling, the full report content, and
// a working window.print() trigger — just mismarked as `todo`.
import { withPage, connectAndShowDashboard, inspectAddress, makeSuite, assert } from './helpers.mjs';

const suite = makeSuite('Inspector Report — PDF Export');

const SOLO_ISSUER = 'rsoLo2S1kiGeCcn6hCUXVrCpGMWLrRrLZz';

suite.register('printInspectorReport opens a real popup with the actual report content, a working print button, and a title naming the inspected address', async () => {
  await withPage(async (page, { pageErrors }) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, SOLO_ISSUER, { timeout: 90000 });
    await page.waitForTimeout(1000);

    const reportBodyLen = await page.evaluate(() => document.getElementById('inspect-report-body')?.innerHTML.length || 0);
    assert(reportBodyLen > 1000, `expected the Full Report to have real generated content before printing, got length ${reportBodyLen}`);

    const [popup] = await Promise.all([
      page.waitForEvent('popup', { timeout: 10000 }),
      page.evaluate(() => window.printInspectorReport()),
    ]);
    await popup.waitForLoadState('domcontentloaded');
    await popup.waitForTimeout(300);

    const popupCheck = await popup.evaluate(() => ({
      titleHasAddr: document.title.includes('rsoLo2S1kiGeCcn6hCUXVrCpGMWLrRrLZz'),
      hasPrintButton: !!document.querySelector('button'),
      bodyLength: document.body.innerHTML.length,
      hasPrintMediaRule: [...document.styleSheets].some(ss => {
        try { return [...ss.cssRules].some(r => r.media?.mediaText?.includes('print')); } catch { return false; }
      }),
    }));
    assert(popupCheck.titleHasAddr, `expected the popup title to name the inspected address, got: "${popupCheck.titleHasAddr}"`);
    assert(popupCheck.hasPrintButton, 'expected a real "Print / Save as PDF" button in the popup');
    assert(popupCheck.bodyLength > 1000, `expected the popup to carry the real report content, got length ${popupCheck.bodyLength}`);
    assert(popupCheck.hasPrintMediaRule, 'expected an @media print rule (hiding the button, tightening margins) so the printed/saved PDF doesn\'t include UI chrome');
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);

    await popup.close();
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
