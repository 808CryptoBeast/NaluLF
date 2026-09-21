// Regression guard for rolling out the Simple/Explain/Analyst contract
// (Inspector-wide roadmap item #10) across the remaining sections that had
// no Simple/Advanced split at all before this pass: Path Payment Depth,
// Destination Tags, Volume Concentration, AMM/Liquidity, Token Issuer, NFT
// Analysis, Fee Analysis, Memos, Escrow Depth, Checks, Trustlines,
// Transaction History, and Issuer Connections. Each now shows a plain-
// language summary (or, for pure reference data like Trustlines/Transaction
// History, a plain count/fingerprint) always, with the dense raw evidence
// gated behind the same pre-existing app-wide _analystMode toggle Drain
// Risk/Wash Trading/Security Audit already use. All summaries reuse fields
// each section's own analysis already computes — no new analysis.
import { withPage, connectAndShowDashboard, inspectAddress, makeSuite, assert } from './helpers.mjs';

const suite = makeSuite('Simple/Explain/Analyst Contract Rollout');

const RICH_ACCOUNT = 'rnj7R3QUGzLZc9dg24jSrGabtt1tp1XD7A';

const SECTIONS = [
  ['desttag', 'inspect-desttag-body'],
  ['volconc', 'inspect-volconc-body'],
  ['amm', 'inspect-amm-body'],
  ['issuer', 'inspect-issuer-body'],
  ['nft', 'inspect-nft-body'],
  ['fee-analysis', 'inspect-fee-analysis-body'],
  ['trustlines', 'inspect-trust-body'],
  ['tx', 'inspect-tx-timeline'],
  ['issuer-connections', 'inspect-issuer-connections-body'],
];

suite.register('Every newly-gated section correctly hides dense content in Simple mode and reveals it in Advanced mode, with no page errors', async () => {
  await withPage(async (page, { pageErrors }) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, RICH_ACCOUNT, { timeout: 90000 });
    await page.waitForTimeout(1500);

    const readGating = () => page.evaluate((sections) => Object.fromEntries(sections.map(([key, id]) => {
      const el = document.getElementById(id);
      if (!el) return [key, { found: false }];
      const adv = el.querySelector('.advanced-only');
      const smp = el.querySelector('.simple-only');
      return [key, {
        found: true,
        advVisible: adv ? getComputedStyle(adv).display !== 'none' : null,
        smpVisible: smp ? getComputedStyle(smp).display !== 'none' : null,
      }];
    })), SECTIONS);

    const simple = await readGating();
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
    for (const [key, state] of Object.entries(simple)) {
      assert(state.found, `expected section "${key}" to render`);
      if (state.advVisible !== null) assert(state.advVisible === false, `expected "${key}"'s advanced content hidden in Simple mode, got advVisible=${state.advVisible}`);
      if (state.smpVisible !== null) assert(state.smpVisible === true, `expected "${key}"'s Simple-mode teaser visible in Simple mode, got smpVisible=${state.smpVisible}`);
    }

    await page.evaluate(() => window.toggleAnalystMode());
    await page.waitForTimeout(400);
    const advanced = await readGating();
    for (const [key, state] of Object.entries(advanced)) {
      if (state.advVisible !== null) assert(state.advVisible === true, `expected "${key}"'s advanced content visible in Advanced mode, got advVisible=${state.advVisible}`);
      if (state.smpVisible !== null) assert(state.smpVisible === false, `expected "${key}"'s Simple-mode teaser hidden in Advanced mode, got smpVisible=${state.smpVisible}`);
    }
    await page.evaluate(() => window.toggleAnalystMode()); // restore default
  });
});

suite.register('Path Payment Depth correctly gates synthetic findings behind Advanced mode', async () => {
  await withPage(async (page, { pageErrors }) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, RICH_ACCOUNT, { timeout: 90000 });
    await page.waitForTimeout(1500);
    await page.waitForFunction(() => window._debugRenderPathDepthPanel, { timeout: 8000 });

    const result = await page.evaluate(() => {
      window._debugRenderPathDepthPanel({ signals: [{ sev: 'warn', label: 'Test', detail: 'Test' }], roundTripCount: 2, deepHopCount: 1, selfRoutedCount: 0 });
      const el = document.getElementById('inspect-pathdepth-body');
      return {
        advVisible: getComputedStyle(el.querySelector('.advanced-only')).display !== 'none',
        smpVisible: getComputedStyle(el.querySelector('.simple-only')).display !== 'none',
      };
    });
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
    assert(result.advVisible === false, 'expected Path Depth\'s advanced content hidden in default Simple mode');
    assert(result.smpVisible === true, 'expected Path Depth\'s Simple-mode teaser visible in default Simple mode');
  });
});

suite.register('Synthetic: each plain-summary builder produces the correct tone and honest text for its section\'s own data shape', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugPathDepthPlainSummary && window._debugDestTagPlainSummary && window._debugAmmPlainSummary && window._debugIssuerPlainSummary && window._debugNftPlainSummary && window._debugFeeAnalysisPlainSummary && window._debugIssuerConnectionsPlainSummary, { timeout: 8000 });

    const pathDepth = await page.evaluate(() => window._debugPathDepthPlainSummary({ signals: [{ sev: 'warn' }], roundTripCount: 3, deepHopCount: 0, selfRoutedCount: 0 }));
    assert(pathDepth.tone === 'warn' && /round-trip/.test(pathDepth.text), `expected a real round-trip mention, got: "${pathDepth.text}"`);

    const destTagNone = await page.evaluate(() => window._debugDestTagPlainSummary({ signals: [], tagProfiles: [] }));
    assert(destTagNone.tone === 'ok' && /No exchange payments/.test(destTagNone.text), `expected the honest no-tags reading, got: "${destTagNone.text}"`);

    const amm = await page.evaluate(() => window._debugAmmPlainSummary({ signals: [], positions: [] }));
    assert(/does not currently hold/.test(amm.text), `expected the no-position reading, got: "${amm.text}"`);

    const issuerNotIssuer = await page.evaluate(() => window._debugIssuerPlainSummary({ isIssuer: false, signals: [] }, 3));
    assert(/does not issue/.test(issuerNotIssuer.text), `expected the non-issuer reading, got: "${issuerNotIssuer.text}"`);

    const nftNone = await page.evaluate(() => window._debugNftPlainSummary({ flags: [] }, []));
    assert(/does not currently hold any NFTs/.test(nftNone.text), `expected the no-NFT reading, got: "${nftNone.text}"`);

    const fee = await page.evaluate(() => window._debugFeeAnalysisPlainSummary({ signals: [{ sev: 'warn' }], avgFeeMultiplier: 15, spikeCount: 3 }));
    assert(/15x/.test(fee.text) && /3 transaction/.test(fee.text), `expected the real fee multiplier and spike count, got: "${fee.text}"`);

    const issuerConnNotIssuer = await page.evaluate(() => window._debugIssuerConnectionsPlainSummary({ totalIssued: 0, signals: [], topHolders: [], mirrorGroups: [] }));
    assert(/does not issue/.test(issuerConnNotIssuer.text), `expected the no-issuance reading, got: "${issuerConnNotIssuer.text}"`);

    const issuerConnConcentrated = await page.evaluate(() => window._debugIssuerConnectionsPlainSummary({
      totalIssued: 1000, holderCount: 5, signals: [{ sev: 'warn' }], topHolders: [{ balance: 900 }], mirrorGroups: [{ tier: 'moderate' }],
    }));
    assert(/90%/.test(issuerConnConcentrated.text), `expected the real top-holder percentage (900/1000=90%), got: "${issuerConnConcentrated.text}"`);
    assert(/mirror-wallet cluster/.test(issuerConnConcentrated.text) && /inferred, not verified/.test(issuerConnConcentrated.text), `expected the mirror-cluster caveat, got: "${issuerConnConcentrated.text}"`);
  });
});

suite.register('Memos, Escrow Depth, and Checks each show a plain summary and correctly gate their raw content behind Advanced mode', async () => {
  await withPage(async (page, { pageErrors }) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, RICH_ACCOUNT, { timeout: 90000 });
    await page.waitForTimeout(1500);
    await page.waitForFunction(() => window._debugRenderMemoPanel && window._debugRenderEscrowDepthPanel && window._debugRenderCheckPanel, { timeout: 8000 });

    const result = await page.evaluate(() => {
      window._debugRenderMemoPanel({ signals: [{ sev: 'warn', label: 'Test' }], allMemos: [{ type: 'Payment', tx: 'ABC123', text: 'hello' }] });
      window._debugRenderEscrowDepthPanel({ signals: [], hasThirdParty: true, escrows: [{ isThirdParty: true, amtXrp: 10, daysToFinish: 5 }] });
      window._debugRenderCheckPanel({ signals: [], checks: [{ sender: 'rA', dest: 'rB', amtXrp: 10, expired: false }] });
      const check = (id) => {
        const el = document.getElementById(id);
        const adv = el.querySelector('.advanced-only');
        const smp = el.querySelector('.simple-only');
        return { hasPlainText: el.textContent.includes('In plain terms:'), advVisible: adv ? getComputedStyle(adv).display !== 'none' : null, smpVisible: smp ? getComputedStyle(smp).display !== 'none' : null };
      };
      return { memos: check('inspect-memos-body'), escrow: check('inspect-escrow-depth-body'), checks: check('inspect-checks-body') };
    });
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
    for (const [name, state] of Object.entries(result)) {
      assert(state.hasPlainText, `expected "${name}" to show a plain-language summary`);
      assert(state.advVisible === false, `expected "${name}"'s raw content hidden in default Simple mode`);
      assert(state.smpVisible === true, `expected "${name}"'s Simple-mode teaser visible in default Simple mode`);
    }
  });
});

suite.register('Synthetic: _computeTxTypeFingerprint tallies real percentages that sum to ~100%', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugComputeTxTypeFingerprint, { timeout: 8000 });
    const txList = [
      { tx: { TransactionType: 'Payment' } }, { tx: { TransactionType: 'Payment' } },
      { tx: { TransactionType: 'OfferCreate' } },
    ];
    const fp = await page.evaluate((tl) => window._debugComputeTxTypeFingerprint(tl), txList);
    const payment = fp.find(f => f.type === 'Payment');
    const offer = fp.find(f => f.type === 'OfferCreate');
    assert(Math.abs(payment.pct - 66.67) < 0.1, `expected Payment at ~66.7%, got ${payment.pct}`);
    assert(Math.abs(offer.pct - 33.33) < 0.1, `expected OfferCreate at ~33.3%, got ${offer.pct}`);
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
