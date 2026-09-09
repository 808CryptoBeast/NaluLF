// Regression guard for the three independent Wash / Spoofing / Market-Making
// verdict cards (spec: "these can coexist" — an account can show elevated
// wash-execution evidence AND a high probability of legitimate automation
// AND low spoofing evidence, all at once). Guards against these collapsing
// back into one combined score, and against Market-Making ever coloring red
// (it's a behavioral characteristic, not an accusation).
import { withPage, connectAndShowDashboard, inspectAddress, makeSuite, assert } from './helpers.mjs';

const REAL_DEX_TRADER = 'rnj7R3QUGzLZc9dg24jSrGabtt1tp1XD7A';

const suite = makeSuite('Market Integrity — Independent Verdict Cards');

suite.register('A real active DEX trader renders exactly 3 independent verdict cards with real, possibly-disagreeing labels', async () => {
  await withPage(async (page) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, REAL_DEX_TRADER, { timeout: 90000 });
    await page.waitForTimeout(1500);

    const result = await page.evaluate(() => {
      const washBody = document.getElementById('inspect-wash-body');
      const cards = [...(washBody?.querySelectorAll('.mi-verdict-card') || [])].map(c => ({
        title: c.querySelector('.mi-verdict-title')?.textContent,
        label: c.querySelector('.mi-verdict-label')?.textContent,
        tone: [...c.classList].find(cl => cl.startsWith('mi-verdict-card--')),
      }));
      return { cards, noteText: washBody?.querySelector('.mi-verdict-note')?.textContent };
    });

    assert(result.cards.length === 3, `expected exactly 3 verdict cards, got ${result.cards.length}`);
    assert(result.cards[0].title === 'Wash Execution', 'expected first card to be Wash Execution');
    assert(result.cards[1].title === 'Spoofing', 'expected second card to be Spoofing');
    assert(result.cards[2].title === 'Market-Making', 'expected third card to be Market-Making');
    assert(result.cards.every(c => c.label && c.tone), 'every card must have a real label and tone class');
    assert(/independent/.test(result.noteText || ''), 'expected an explicit note that these verdicts are independent and can disagree');
  });
});

suite.register('_severityVerdictLabel maps worst-of-group severity correctly, not an average or a sum', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugSeverityVerdictLabel, { timeout: 8000 });
    const result = await page.evaluate(() => ({
      empty: window._debugSeverityVerdictLabel([]),
      allOk: window._debugSeverityVerdictLabel([{ sev: 'ok' }, { sev: 'ok' }]),
      oneInfo: window._debugSeverityVerdictLabel([{ sev: 'ok' }, { sev: 'info' }]),
      oneWarnAmongOk: window._debugSeverityVerdictLabel([{ sev: 'ok' }, { sev: 'warn' }, { sev: 'ok' }]),
      oneCriticalAmongMany: window._debugSeverityVerdictLabel([{ sev: 'warn' }, { sev: 'critical' }, { sev: 'info' }, { sev: 'ok' }]),
    }));
    assert(result.empty[0] === 'NORMAL', `empty findings should read NORMAL, got ${result.empty[0]}`);
    assert(result.allOk[0] === 'NORMAL', `all-ok findings should read NORMAL, got ${result.allOk[0]}`);
    assert(result.oneInfo[0] === 'LOW EVIDENCE', `one info finding should read LOW EVIDENCE, got ${result.oneInfo[0]}`);
    assert(result.oneWarnAmongOk[0] === 'WATCH', `one warn among ok findings should read WATCH (worst-of, not averaged), got ${result.oneWarnAmongOk[0]}`);
    assert(result.oneCriticalAmongMany[0] === 'ELEVATED', `one critical among lesser findings should read ELEVATED (worst-of), got ${result.oneCriticalAmongMany[0]}`);
    assert(result.oneCriticalAmongMany[1] === 'crit', 'critical verdict must carry the crit tone for red styling');
  });
});

suite.register('Market-Making verdict never uses a severity tone (crit/warn) even when automation is detected — it is a characteristic, not an accusation', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugMarketMakingVerdictLabel, { timeout: 8000 });
    const result = await page.evaluate(() => {
      const notDetected = window._debugMarketMakingVerdictLabel({ automationLikely: false, signals: [] });
      const highProbability = window._debugMarketMakingVerdictLabel({
        automationLikely: true,
        signals: [{ module: 'Market-Maker Automation', confidence: 0.6 }],
      });
      const ambiguous = window._debugMarketMakingVerdictLabel({
        automationLikely: true,
        signals: [{ module: 'Market-Maker Automation', confidence: 0.4 }],
      });
      return { notDetected, highProbability, ambiguous };
    });
    assert(result.notDetected[0] === 'NOT DETECTED', `expected NOT DETECTED, got ${result.notDetected[0]}`);
    assert(result.highProbability[0] === 'HIGH PROBABILITY', `expected HIGH PROBABILITY at confidence 0.6, got ${result.highProbability[0]}`);
    assert(result.ambiguous[0] === 'AMBIGUOUS', `expected AMBIGUOUS at confidence 0.4, got ${result.ambiguous[0]}`);
    for (const [, tone] of [result.notDetected, result.highProbability, result.ambiguous]) {
      assert(tone !== 'crit' && tone !== 'warn', `Market-Making tone must never be crit/warn (found "${tone}") — it must not read as an accusation`);
    }
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
