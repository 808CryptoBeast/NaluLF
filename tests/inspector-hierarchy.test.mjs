// Regression guard for the Inspector's ACCOUNT PROFILE section-hierarchy
// reorg: every section must appear exactly once (no duplicate ids from a
// botched reorder), every section must sit under a labeled group divider
// in the intended order, and every render target must still populate with
// real content after the move (moving a <section> wrapper is only safe if
// every render function still finds its target purely by element id).
import { withPage, connectAndShowDashboard, inspectAddress, makeSuite, assert } from './helpers.mjs';

const TEST_ACCOUNT = 'rnj7R3QUGzLZc9dg24jSrGabtt1tp1XD7A'; // real, active DEX trader — exercises most panels

const EXPECTED_ORDER = [
  '[GROUP: Account Overview]', 'section-overview',
  '[GROUP: Security]', 'section-security',
  '[GROUP: Balance & Asset Activity]', 'section-drain', 'section-fundflow', 'section-inbound', 'section-trustlines',
  '[GROUP: Transaction Behavior]', 'section-tx', 'section-pathdepth',
  '[GROUP: Counterparties & Relationships]', 'section-issuer-connections', 'section-desttag',
  '[GROUP: Market & DEX Activity]', 'section-wash', 'section-volconc', 'section-livebook',
  '[GROUP: Liquidity / AMM]', 'section-amm',
  '[GROUP: Issuer Intelligence]', 'section-issuer',
  '[GROUP: NFT Activity]', 'section-nft',
  '[GROUP: Forensic Findings]', 'section-evidence-matrix', 'section-forensic-suite', 'section-fee-analysis', 'section-memos',
  '[GROUP: Advanced / Raw Ledger Data]', 'section-escrow-depth', 'section-checks', 'section-report',
];

const suite = makeSuite('Inspector — ACCOUNT PROFILE Hierarchy');

suite.register('Sections render in the exact intended group/order with zero duplicate ids', async () => {
  await withPage(async (page) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, TEST_ACCOUNT);

    const result = await page.evaluate(() => {
      const container = document.getElementById('inspect-result');
      const children = [...container.querySelectorAll('.inspector-group-header, .inspector-section')];
      const order = children.map((el) => el.classList.contains('inspector-group-header')
        ? `[GROUP: ${el.querySelector('.inspector-group-title')?.textContent}]`
        : el.id);

      const idCounts = {};
      document.querySelectorAll('[id^="section-"]').forEach((e) => { idCounts[e.id] = (idCounts[e.id] || 0) + 1; });
      const duplicateIds = Object.entries(idCounts).filter(([, c]) => c > 1).map(([id]) => id);

      return { order, duplicateIds };
    });

    assert(result.duplicateIds.length === 0, `duplicate section ids found: ${result.duplicateIds.join(', ')}`);
    assert(
      JSON.stringify(result.order) === JSON.stringify(EXPECTED_ORDER),
      `section/group order does not match the intended hierarchy.\nExpected: ${EXPECTED_ORDER.join(' > ')}\nActual:   ${result.order.join(' > ')}`
    );
  });
});

suite.register('Render targets populate with real content after the reorder (moving a <section> wrapper does not break its render function)', async () => {
  await withPage(async (page) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, TEST_ACCOUNT);

    const lens = await page.evaluate(() => ({
      overview: document.getElementById('inspect-acct-grid')?.innerHTML?.length || 0,
      security: document.getElementById('inspect-security-body')?.innerHTML?.length || 0,
      wash: document.getElementById('inspect-wash-body')?.innerHTML?.length || 0,
      amm: document.getElementById('inspect-amm-body')?.innerHTML?.length || 0,
      evidenceMatrix: document.getElementById('inspect-evidence-matrix-body')?.innerHTML?.length || 0,
      report: document.getElementById('inspect-report-body')?.innerHTML?.length || 0,
    }));
    for (const [name, len] of Object.entries(lens)) {
      assert(len > 0, `${name}'s render target is empty after the reorg — its render function may no longer be finding it by id`);
    }
  });
});

suite.register('Nav bar exposes a jump button for every section id, and the scroll-spy order list has no duplicates', async () => {
  await withPage(async (page) => {
    await connectAndShowDashboard(page);
    await inspectAddress(page, TEST_ACCOUNT);

    const result = await page.evaluate(() => {
      const navIds = new Set([...document.querySelectorAll('#inspector-nav .in-btn[data-jump]')].map((b) => b.dataset.jump));
      const sectionIds = [...document.querySelectorAll('.inspector-section')].map((s) => s.id.replace(/^section-/, ''));
      const missingFromNav = sectionIds.filter((id) => !navIds.has(id));
      return { missingFromNav, navCount: navIds.size };
    });
    assert(result.missingFromNav.length === 0, `sections with no nav jump button: ${result.missingFromNav.join(', ')}`);
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };
