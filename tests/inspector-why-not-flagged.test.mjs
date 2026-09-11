// Regression guard for the "Why wasn't this flagged as a drain?" checklist
// on pass-through Drain Risk episodes. This is spec section §37's own
// worked example almost verbatim: a large-looking gross outflow that Nalu
// correctly does NOT classify as a drain, with the specific reasons shown
// as an explicit checklist rather than just a severity label. The
// checklist itself (auth-change / new-recipient / liquidate-then-withdraw
// / size-anomaly checks) was ALREADY built for sweep/potential-drain
// episodes — this closes the gap where pass-through episodes (the most
// common "why wasn't this flagged" case, and literally the spec's own
// example) got no checklist at all, just a bare classification label.
import { withPage, connectAndShowDashboard, inspectAddress, makeSuite, assert } from './helpers.mjs';

// Bitstamp hot wallet — confirmed earlier this session to reliably produce
// real pass-through episodes (large turnover, near-zero net depletion).
const REAL_PASS_THROUGH_ACCOUNT = 'rPVMhWBsfF9iMXYj3aAzJVkPDTFNSyWdKy';

const suite = makeSuite('Drain Risk — Why Wasn\'t This Flagged');

suite.register('A real high-volume hot wallet renders Drain Risk without error, and if a pass-through episode is currently present its checklist is well-formed', async () => {
  await withPage(async (page, { pageErrors }) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, REAL_PASS_THROUGH_ACCOUNT, { timeout: 90000 });
    await page.waitForTimeout(3000);

    const result = await page.evaluate(() => {
      const findings = (window._lastAllFindings || []).filter(f => f.module === 'Asset Drain Behavior');
      const passThrough = findings.find(f => f.classification?.includes('Pass-through'));
      return { txCount: window._lastTxList?.length || 0, found: !!passThrough, observed: passThrough?.observed || [], sev: passThrough?.sev };
    });

    // This is a real, constantly-active exchange hot wallet — whether a
    // >50% single-window turnover episode falls inside the currently
    // fetched tx-history window genuinely varies minute to minute as new
    // ledger activity occurs. The exact checklist LOGIC is deterministically
    // covered by the two synthetic tests below; this live check only
    // confirms the pipeline runs cleanly against real data, and validates
    // the checklist's shape on the rare run where a pass-through episode
    // happens to be present right now.
    assert(result.txCount > 0, 'expected real transaction history to have loaded for this account');
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
    if (result.found) {
      assert(result.sev === 'info', `pass-through must stay info severity, got ${result.sev}`);
      const headerIdx = result.observed.findIndex(o => /wasn.t flagged as a drain/i.test(o));
      assert(headerIdx >= 0, `expected a "why wasn't this flagged as a drain" header in observed: ${JSON.stringify(result.observed)}`);
      const checklistItems = result.observed.slice(headerIdx + 1);
      assert(checklistItems.length >= 4, `expected at least 4 checklist items after the header, got ${checklistItems.length}`);
      assert(checklistItems.some(c => /largely offset the outflow/.test(c)), 'expected the pass-through-specific lead item explaining inflow offset the outflow');
      assert(checklistItems.every(c => c.startsWith('✓') || c.startsWith('⚠')), `every checklist item must be marked ✓ or ⚠, got: ${JSON.stringify(checklistItems)}`);
    }
  });
});

suite.register('A synthetic clean pass-through (repeat destination, no auth change, no liquidation, thin size history) gets all 5 checkmarks clear', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugAssetDrainBehavior, { timeout: 8000 });
    const result = await page.evaluate(() => {
      const addr = 'rPassThroughTest0000000000000000000';
      const cpOut = 'rOutDest000000000000000000000000000';
      const cpIn = 'rInSource00000000000000000000000000';
      const acctRoot = (bal, prevBal) => ({ ModifiedNode: { LedgerEntryType: 'AccountRoot', FinalFields: { Account: addr, Balance: String(bal) }, PreviousFields: { Balance: String(prevBal) } } });

      const txList = [
        // A small prior payment to cpOut, well outside any drain window
        // (>3 days before), so cpOut counts as a previously-used
        // destination without itself contributing to the episode.
        { tx: { Account: addr, Destination: cpOut, TransactionType: 'Payment', Amount: '5000000', date: 799700000, hash: 'h0' },
          meta: { TransactionResult: 'tesSUCCESS', AffectedNodes: [acctRoot(1000000000, 1005000000)] } },
        // The real episode: 800 XRP out, 780 XRP back in within 100s.
        { tx: { Account: addr, Destination: cpOut, TransactionType: 'Payment', Amount: '800000000', date: 800000000, hash: 'h1' },
          meta: { TransactionResult: 'tesSUCCESS', AffectedNodes: [acctRoot(200000000, 1000000000)] } },
        { tx: { Account: cpIn, Destination: addr, TransactionType: 'Payment', Amount: '780000000', date: 800000100, hash: 'h2' },
          meta: { TransactionResult: 'tesSUCCESS', delivered_amount: '780000000', AffectedNodes: [acctRoot(980000000, 200000000)] } },
      ];

      const result = window._debugAssetDrainBehavior(txList, addr, 980, {}, false);
      const passThrough = result.findings.find(f => f.classification?.includes('Pass-through'));
      return { episodeCount: result.episodes.length, classification: result.episodes[0]?.classification, observed: passThrough?.observed || [] };
    });

    assert(result.episodeCount === 1, `expected exactly 1 merged episode (24h and 3d windows cover the same tx pair), got ${result.episodeCount}`);
    assert(result.classification === 'pass-through', `expected pass-through classification, got ${result.classification}`);
    const headerIdx = result.observed.findIndex(o => /wasn.t flagged as a drain/i.test(o));
    assert(headerIdx >= 0, `expected the why-not-flagged header, got observed: ${JSON.stringify(result.observed)}`);
    const checklistItems = result.observed.slice(headerIdx + 1);
    assert(checklistItems.length === 5, `expected exactly 5 checklist items (pass-through lead + 4 general), got ${checklistItems.length}: ${JSON.stringify(checklistItems)}`);
    assert(checklistItems.every(c => c.startsWith('✓')), `expected all 5 items clear (repeat destination, no auth change, no liquidation, thin baseline) for this fixture, got: ${JSON.stringify(checklistItems)}`);
    assert(checklistItems[0].includes('780') && checklistItems[0].includes('offset'), `expected the first item to be the pass-through-specific inflow-offset explanation, got: "${checklistItems[0]}"`);
  });
});

suite.register('A synthetic pass-through with an all-new destination shows the new-recipient item as fired (⚠), not silently hidden', async () => {
  await withPage(async (page) => {
    await page.waitForFunction(() => window._debugAssetDrainBehavior, { timeout: 8000 });
    const result = await page.evaluate(() => {
      const addr = 'rPassThroughNewDest00000000000000000';
      const cpOut = 'rBrandNewDest00000000000000000000000';
      const cpIn = 'rInSource20000000000000000000000000';
      const acctRoot = (bal, prevBal) => ({ ModifiedNode: { LedgerEntryType: 'AccountRoot', FinalFields: { Account: addr, Balance: String(bal) }, PreviousFields: { Balance: String(prevBal) } } });

      // No prior payment to cpOut anywhere in history — it's a genuinely
      // first-time destination for this pass-through episode.
      const txList = [
        { tx: { Account: addr, Destination: cpOut, TransactionType: 'Payment', Amount: '800000000', date: 800000000, hash: 'h1' },
          meta: { TransactionResult: 'tesSUCCESS', AffectedNodes: [acctRoot(200000000, 1000000000)] } },
        { tx: { Account: cpIn, Destination: addr, TransactionType: 'Payment', Amount: '780000000', date: 800000100, hash: 'h2' },
          meta: { TransactionResult: 'tesSUCCESS', delivered_amount: '780000000', AffectedNodes: [acctRoot(980000000, 200000000)] } },
      ];
      const result = window._debugAssetDrainBehavior(txList, addr, 980, {}, false);
      const passThrough = result.findings.find(f => f.classification?.includes('Pass-through'));
      return { observed: passThrough?.observed || [] };
    });
    const fired = result.observed.filter(o => o.startsWith('⚠'));
    assert(fired.length === 1, `expected exactly 1 fired (⚠) item for the 100%-new-destination case, got ${fired.length}: ${JSON.stringify(result.observed)}`);
    assert(/first-time recipient/.test(fired[0]), `expected the fired item to be about first-time recipients, got: "${fired[0]}"`);
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
