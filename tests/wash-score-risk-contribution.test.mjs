// Regression coverage for fixing the legacy wash-score dependency in the
// headline Risk Score (roadmap: Inspector Core Architecture). The deprecated
// combined wash.score (execution.score + spoofing.score) used to feed
// computeOverallRisk's "Wash Trading" 0-15pt contribution and the matching
// Risk Breakdown panel line directly — even though badges, the nav status
// dot, smart-collapse, and the Full Report had already migrated to the
// three independent verdicts (Wash Execution / Spoofing / Market-Making)
// via _washSectionSeverity. That meant the headline number could disagree
// with what the Market Integrity section itself was telling the reader.
// Fixed via a shared `_washRiskScoreContribution(wash)` (crit=15, warn=7,
// ok=0, derived from _washSectionSeverity's tone) used by both
// computeOverallRisk and buildRiskBreakdown, so they can't drift from each
// other or from the section's own badge. The legacy wash.score itself is
// untouched and still drives the Wash panel's own disclaimed legacy bar
// ("kept for continuity") — only its role in the headline score changed.
import { withPage, connectAndShowDashboard, assert } from './helpers.mjs';

const suite = { register: [], run: async () => {
  let pass = 0, fail = 0;
  console.log('\n▶ Wash Score Risk Contribution');
  for (const { name, fn } of suite.register) {
    try { await fn(); console.log(`  PASS  ${name}`); pass++; }
    catch (err) { console.log(`  FAIL  ${name}`); console.log(`        ${err?.stack || err}`); fail++; }
  }
  return { pass, fail, total: suite.register.length };
}};
const test = (name, fn) => suite.register.push({ name, fn });

test('_washRiskScoreContribution agrees with _washSectionSeverity (the same source badges/nav/report already use) across every severity combination, and ignores the deprecated combined wash.score entirely', async () => {
  await withPage(async (page, { pageErrors }) => {
    await connectAndShowDashboard(page);

    const results = await page.evaluate(() => {
      const mk = (sev) => ({ module: 'Wash Execution', sev });
      const mkSpoof = (sev) => ({ module: 'Spoofing', sev });
      const cases = [
        { name: 'clean', wash: { score: 0, stats: { creates: 20 }, signals: [mk('ok')] }, expectTone: 'ok', expectPts: 0 },
        { name: 'low-evidence (info) execution', wash: { score: 0, stats: { creates: 20 }, signals: [mk('info')] }, expectTone: 'ok', expectPts: 0 },
        { name: 'warn execution', wash: { score: 0, stats: { creates: 20 }, signals: [mk('warn')] }, expectTone: 'warn', expectPts: 7 },
        { name: 'critical execution', wash: { score: 0, stats: { creates: 20 }, signals: [mk('critical')] }, expectTone: 'crit', expectPts: 15 },
        { name: 'warn spoofing only', wash: { score: 0, stats: { creates: 20 }, signals: [mk('ok'), mkSpoof('warn')] }, expectTone: 'warn', expectPts: 7 },
        { name: 'critical spoofing only', wash: { score: 0, stats: { creates: 20 }, signals: [mk('ok'), mkSpoof('critical')] }, expectTone: 'crit', expectPts: 15 },
        // A high legacy combined score must NOT, by itself, produce any
        // contribution if the independent verdicts both read clean/N-A —
        // this is the exact case the migration was meant to fix.
        { name: 'high legacy score but clean independent verdicts', wash: { score: 95, stats: { creates: 20 }, signals: [mk('ok')] }, expectTone: 'ok', expectPts: 0 },
      ];
      return cases.map(c => ({
        name: c.name,
        tone: window._debugWashSectionSeverity(c.wash).tone,
        pts: window._debugWashRiskScoreContribution(c.wash),
        expectTone: c.expectTone,
        expectPts: c.expectPts,
      }));
    });

    for (const r of results) {
      assert(r.tone === r.expectTone, `[${r.name}] expected tone "${r.expectTone}", got "${r.tone}"`);
      assert(r.pts === r.expectPts, `[${r.name}] expected Risk Score contribution ${r.expectPts}, got ${r.pts}`);
    }
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
