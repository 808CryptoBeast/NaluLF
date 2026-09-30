// Regression coverage for "Export analytics + inspection data as CSV"
// (roadmap: Analytics) — one row per finding across every module, using the
// exact same data-URI-download technique profile.js's own exportTxCSV
// already uses for transaction exports, so this app has one consistent CSV
// export pattern rather than two different ones.
import { withPage, connectAndShowDashboard, inspectAddress, makeSuite, assert } from './helpers.mjs';
import fs from 'fs';

const suite = makeSuite('Inspector Report — CSV Export');

const ACTIVE_ACCOUNT = 'rnj7R3QUGzLZc9dg24jSrGabtt1tp1XD7A'; // known to have many real findings

suite.register('exportInspectorReportCSV downloads a real CSV with one row per finding, a correct header, and a filename naming the inspected address', async () => {
  await withPage(async (page, { pageErrors }) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, ACTIVE_ACCOUNT, { timeout: 90000 });
    await page.waitForTimeout(500);

    const findingsCount = await page.evaluate(() => (window._lastAllFindings || []).length);
    assert(findingsCount > 0, 'expected real findings for this known-active account before testing export');

    const [download] = await Promise.all([
      page.waitForEvent('download', { timeout: 10000 }),
      page.evaluate(() => window.exportInspectorReportCSV()),
    ]);
    const path = await download.path();
    const content = fs.readFileSync(path, 'utf-8');
    const lines = content.trim().split('\n');

    assert(download.suggestedFilename().includes('rnj7R3QUGzLZ'), `expected the filename to name the inspected address, got: "${download.suggestedFilename()}"`);
    assert(download.suggestedFilename().endsWith('.csv'), 'expected a .csv file');
    assert(lines[0] === '"Module","Category","Severity","Confidence","Headline","Detail"', `expected a real CSV header row, got: "${lines[0]}"`);
    assert(lines.length === findingsCount + 1, `expected exactly one CSV row per finding (${findingsCount}) plus the header, got ${lines.length} lines`);
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

suite.register('exportInspectorReportCSV warns instead of downloading an empty file when there are no findings to export', async () => {
  await withPage(async (page, { pageErrors }) => {
    await page.evaluate(() => { window._lastAllFindings = []; window._lastInspectResult = null; });
    let downloadFired = false;
    page.on('download', () => { downloadFired = true; });
    await page.evaluate(() => window.exportInspectorReportCSV());
    await page.waitForTimeout(300);
    assert(!downloadFired, 'expected no download to fire when there are no findings');
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
