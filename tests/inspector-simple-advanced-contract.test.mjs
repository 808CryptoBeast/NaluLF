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

// Regression for a real bug reported live: 3 group headers (Counterparties
// & Relationships, Liquidity / AMM, Issuer Intelligence) have EVERY one of
// their member sections in the Simple-mode hide list, but the group header
// itself was never included — Simple mode showed a bare, empty-looking
// label with nothing under it before the next group's own header, reading
// as broken. Market & DEX Activity is the control case: its own Wash
// Trading section stays visible in Simple mode, so that group must NOT be
// hidden even though it also contains simple-hidden siblings (Volume
// Concentration, Live Order Book).
suite.register('Group headers with EVERY member section hidden in Simple mode are hidden themselves, not left as an empty label', async () => {
  await withPage(async (page, { pageErrors }) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, RICH_ACCOUNT, { timeout: 90000 });
    await page.waitForTimeout(1500);

    const vis = () => page.evaluate(() => {
      const v = (id) => { const el = document.getElementById(id); return el ? getComputedStyle(el).display !== 'none' : null; };
      return {
        counterparties: v('group-counterparties'), liquidity: v('group-liquidity'), issuer: v('group-issuer'),
        market: v('group-market'), wash: v('section-wash'),
      };
    });

    const simple = await vis();
    assert(simple.counterparties === false, `expected group-counterparties hidden in Simple mode, got ${simple.counterparties}`);
    assert(simple.liquidity === false, `expected group-liquidity hidden in Simple mode, got ${simple.liquidity}`);
    assert(simple.issuer === false, `expected group-issuer hidden in Simple mode, got ${simple.issuer}`);
    assert(simple.market === true, 'expected group-market to stay visible in Simple mode (Wash Trading has real Simple-mode content)');
    assert(simple.wash === true, 'expected section-wash itself to stay visible in Simple mode');

    await page.evaluate(() => window.toggleAnalystMode());
    await page.waitForTimeout(300);
    const advanced = await vis();
    assert(advanced.counterparties === true, 'expected group-counterparties visible again in Advanced mode');
    assert(advanced.liquidity === true, 'expected group-liquidity visible again in Advanced mode');
    assert(advanced.issuer === true, 'expected group-issuer visible again in Advanced mode');
    await page.evaluate(() => window.toggleAnalystMode()); // restore default

    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

// Regression for a real "is this a bug?" report: the Transaction Type
// Breakdown counts every transaction TOUCHING this account (sender OR
// counterparty — e.g. someone else's OfferCreate crossing this account's
// own trustline), while Wash Trading's own Offer Creates/Offer Cancels
// stats count only orders THIS account placed. Both numbers are
// independently correct but measure different things with no on-screen
// explanation — a classic misattribution-shaped gap. A caption should make
// the distinction explicit rather than requiring reading the source.
suite.register('Transaction Type Breakdown honestly captions its scope (touches this account, not just initiated by it)', async () => {
  await withPage(async (page, { pageErrors }) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, RICH_ACCOUNT, { timeout: 90000 });
    await page.waitForTimeout(1500);

    const caption = await page.evaluate(() => document.getElementById('inspect-tx-timeline')?.textContent || '');
    assert(caption.includes('sender OR counterparty'), 'expected the Transaction Type Breakdown to caption that it counts both sent AND received/affected transactions');
    assert(caption.includes('Wash Trading'), 'expected the caption to point to Wash Trading\'s own narrower Offer Creates/Cancels counts for comparison');
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

// ── The real 3-tier split (roadmap: Inspector 5.0, small near-term win) ───
// Everything above tested a binary Simple/Advanced split under a name that
// was already aspirationally "Simple/Explain/Analyst." This section tests
// the real 3-way depth mode: setDepthMode('simple'|'explain'|'analyst') as
// the actual app-wide control, with toggleAnalystMode() kept as a straight
// simple<->analyst flip (skipping the middle tier) specifically so the many
// existing tests above — and in other files — that call it expecting a
// binary jump keep working unmodified.
suite.register('setDepthMode: Explain shows evidence/classification content that Simple hides, but Analyst-only raw content (confidence %, hash chips) stays hidden until the Analyst tier specifically', async () => {
  await withPage(async (page) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, RICH_ACCOUNT, { timeout: 90000 });
    await page.waitForTimeout(1500);

    const read = () => page.evaluate(() => {
      const el = document.getElementById('inspect-result');
      return {
        classes: [...el.classList].filter(c => c.startsWith('mode-') || c.startsWith('depth-')),
        hasVisibleAdvancedContent: [...el.querySelectorAll('.advanced-only')].some(n => getComputedStyle(n).display !== 'none'),
        hasVisibleAnalystContent: [...el.querySelectorAll('.analyst-only-inline, .analyst-only-block')].some(n => getComputedStyle(n).display !== 'none'),
      };
    });

    const simpleState = await read();
    assert(simpleState.classes.includes('mode-simple'), `expected mode-simple by default, got: ${JSON.stringify(simpleState.classes)}`);
    assert(!simpleState.hasVisibleAdvancedContent, 'expected no visible .advanced-only content in Simple mode');
    assert(!simpleState.hasVisibleAnalystContent, 'expected no visible analyst-only content in Simple mode');

    await page.evaluate(() => window.setDepthMode('explain'));
    const explainState = await read();
    assert(explainState.classes.includes('mode-advanced') && !explainState.classes.includes('depth-analyst'), `expected mode-advanced without depth-analyst in Explain tier, got: ${JSON.stringify(explainState.classes)}`);
    assert(explainState.hasVisibleAdvancedContent, 'expected .advanced-only (evidence/classification) content to be visible in Explain mode');
    assert(!explainState.hasVisibleAnalystContent, 'expected analyst-only raw content (confidence %, hash chips) to STILL be hidden in Explain mode — that is the entire point of the 3rd tier');

    await page.evaluate(() => window.setDepthMode('analyst'));
    const analystState = await read();
    assert(analystState.classes.includes('depth-analyst'), `expected depth-analyst class in Analyst tier, got: ${JSON.stringify(analystState.classes)}`);
    assert(analystState.hasVisibleAnalystContent, 'expected analyst-only raw content to become visible in Analyst mode');

    await page.evaluate(() => window.setDepthMode('simple')); // restore default for other tests sharing the page lifecycle
  });
});

suite.register('toggleAnalystMode() stays a straight simple<->analyst flip for backward compatibility — it never lands on the middle Explain tier', async () => {
  await withPage(async (page) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, RICH_ACCOUNT, { timeout: 90000 });
    await page.waitForTimeout(1500);

    const getMode = () => page.evaluate(() => {
      const el = document.getElementById('inspect-result');
      return el.classList.contains('depth-analyst') ? 'analyst' : el.classList.contains('mode-advanced') ? 'explain' : 'simple';
    });

    assert(await getMode() === 'simple', 'expected the default mode to be simple');
    await page.evaluate(() => window.toggleAnalystMode());
    assert(await getMode() === 'analyst', `expected toggleAnalystMode() to jump straight to analyst (not explain), got "${await getMode()}"`);
    await page.evaluate(() => window.toggleAnalystMode());
    assert(await getMode() === 'simple', 'expected toggleAnalystMode() to flip back to simple');

    // Even starting from the middle tier, the legacy toggle jumps to analyst
    // rather than cycling — it has no concept of a 3rd state.
    await page.evaluate(() => window.setDepthMode('explain'));
    await page.evaluate(() => window.toggleAnalystMode());
    assert(await getMode() === 'analyst', `expected toggleAnalystMode() from Explain to land on analyst, got "${await getMode()}"`);
    await page.evaluate(() => window.setDepthMode('simple')); // restore default
  });
});

suite.register('The 3-way depth control buttons reflect the active tier via aria-pressed and a visual active state', async () => {
  await withPage(async (page) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, RICH_ACCOUNT, { timeout: 90000 });
    await page.waitForTimeout(1500);

    await page.evaluate(() => window.setDepthMode('explain'));
    const result = await page.evaluate(() => {
      const btns = [...document.querySelectorAll('#depth-mode-group [data-depth]')];
      return btns.map(b => ({ depth: b.dataset.depth, pressed: b.getAttribute('aria-pressed'), active: b.classList.contains('depth-mode-btn--active') }));
    });
    const explainBtn = result.find(b => b.depth === 'explain');
    const simpleBtn = result.find(b => b.depth === 'simple');
    assert(explainBtn.pressed === 'true' && explainBtn.active, `expected the Explain button to be marked pressed+active, got: ${JSON.stringify(explainBtn)}`);
    assert(simpleBtn.pressed === 'false' && !simpleBtn.active, `expected the Simple button to NOT be marked pressed/active while Explain is selected, got: ${JSON.stringify(simpleBtn)}`);
    await page.evaluate(() => window.setDepthMode('simple')); // restore default
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
