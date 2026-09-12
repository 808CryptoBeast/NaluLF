// Regression guard for the Evidence Pyramid (beginner-UX spec §48) — a
// visual summary of how many findings sit at each Strong/Moderate/Weak
// reliability tier. Deliberately reuses the EXACT SAME per-finding
// _evidenceStrength classification already used for each Evidence Matrix
// row (no new scoring logic), and uses a FIXED visual band-width scale
// rather than literal count-proportional widths — a literal
// count-proportional pyramid could render upside-down (more strong
// findings than weak ones is common and correct), which would undermine
// the "less-but-more-decisive at the top" metaphor the shape is meant to
// convey. Real counts are always shown as numbers regardless of band width.
import { withPage, connectAndShowDashboard, inspectAddress, makeSuite, assert } from './helpers.mjs';

const suite = makeSuite('Evidence Pyramid');

suite.register('A real active account with a real mix of findings renders 3 bands with correct real counts summing to the total', async () => {
  await withPage(async (page) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, 'rnj7R3QUGzLZc9dg24jSrGabtt1tp1XD7A', { timeout: 90000 });
    await page.waitForTimeout(3000);

    const result = await page.evaluate(() => {
      const el = document.getElementById('inspect-evidence-matrix-body');
      const bands = [...(el?.querySelectorAll('.evpyramid-band') || [])].map(b => b.querySelector('.evpyramid-band-label')?.textContent);
      const titleText = el?.querySelector('.evpyramid-title')?.textContent;
      const totalFindings = (window._lastAllFindings || []).length;
      return { bands, titleText, totalFindings };
    });

    assert(result.bands.length === 3, `expected exactly 3 bands (Strong/Moderate/Weak), got ${result.bands.length}`);
    assert(/Strong/.test(result.bands[0]) && /Moderate/.test(result.bands[1]) && /Weak/.test(result.bands[2]), `expected bands in Strong/Moderate/Weak order, got: ${JSON.stringify(result.bands)}`);
    const counts = result.bands.map(b => Number(b.match(/\((\d+)\)/)?.[1]));
    assert(counts.every(c => Number.isFinite(c)), `expected a real numeric count in each band label, got: ${JSON.stringify(result.bands)}`);
    const sum = counts.reduce((a, b) => a + b, 0);
    assert(/Evidence Pyramid — \d+ finding/.test(result.titleText), `expected a real total in the title, got: "${result.titleText}"`);
    const titleTotal = Number(result.titleText.match(/(\d+) finding/)?.[1]);
    assert(sum === titleTotal, `expected the 3 band counts to sum to the title's total, got sum=${sum} vs title=${titleTotal}`);
  });
});

suite.register('buildEvidencePyramid correctly buckets by confidence using the same thresholds as _evidenceStrength (>=0.7 Strong, >=0.4 Moderate, else Weak), and excludes ok-severity/no-confidence findings', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugEvidencePyramid, { timeout: 8000 });
    const findings = [
      { sev: 'warn', confidence: 0.9, headline: 'strong one' },
      { sev: 'critical', confidence: 0.75, headline: 'strong two' },
      { sev: 'warn', confidence: 0.55, headline: 'moderate one' },
      { sev: 'warn', confidence: 0.4, headline: 'moderate two' },
      { sev: 'info', confidence: 0.2, headline: 'weak one' },
      { sev: 'info', confidence: 0.39, headline: 'weak two' },
      { sev: 'ok', confidence: 0.9, headline: 'excluded — ok severity' },
      { sev: 'warn', confidence: null, headline: 'excluded — no confidence' },
    ];
    const result = await page.evaluate((findings) => window._debugEvidencePyramid(findings), findings);

    assert(result.applicable === true, 'expected applicable:true');
    assert(result.tiers.Strong.length === 2, `expected 2 Strong findings, got ${result.tiers.Strong.length}`);
    assert(result.tiers.Moderate.length === 2, `expected 2 Moderate findings, got ${result.tiers.Moderate.length}`);
    assert(result.tiers.Weak.length === 2, `expected 2 Weak findings, got ${result.tiers.Weak.length}`);
    assert(result.total === 6, `expected total=6 (ok-severity and no-confidence findings excluded), got ${result.total}`);
  });
});

suite.register('No findings at all produces applicable:false, not an empty fabricated pyramid', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugEvidencePyramid, { timeout: 8000 });
    const result = await page.evaluate(() => window._debugEvidencePyramid([]));
    assert(result.applicable === false, 'expected applicable:false with zero findings');
  });
});

suite.register('Only ok-severity findings (a genuinely clean account) produces applicable:false — the pyramid must not render for a wallet with no real findings to summarize', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugEvidencePyramid, { timeout: 8000 });
    const result = await page.evaluate(() => window._debugEvidencePyramid([
      { sev: 'ok', confidence: 0.9, headline: 'all clear 1' },
      { sev: 'ok', confidence: 0.8, headline: 'all clear 2' },
    ]));
    assert(result.applicable === false, 'expected applicable:false when every finding is ok-severity');
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
