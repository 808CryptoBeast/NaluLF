/* =====================================================
   help.js — Searchable Glossary / Help Panel
   ===================================================== */
import { $, $$, escHtml } from './utils.js';
import { PI_ISSUER_EXPLANATIONS } from './profile.js';

const ENTRIES = [
  // ── App Features ──
  { cat: 'App', term: 'Live Stream', body: 'A real-time feed of the XRP Ledger as it closes — new ledgers, transaction volume, and network metrics as they happen. No refresh needed.' },
  { cat: 'App', term: 'Inspector', body: 'Full forensic analysis of any XRPL address, yours or anyone else\'s: trust lines, fund flow tracking, and a multi-engine Forensic Analytics Suite that looks for non-organic behavior patterns.' },
  { cat: 'App', term: 'Network Health', body: 'Live validator and node health — latency probing across public XRPL endpoints, so you can see which server is actually fastest to connect to right now.' },
  { cat: 'App', term: 'Project Intelligence', body: 'Token-level analysis for any issued asset: liquidity depth (AMM + live order book), holder concentration, LP token concentration, and issuer risk flags, rolled into one inspectable Strength score.' },
  { cat: 'App', term: 'Portfolio Analytics', body: 'Balance history, an activity heatmap, and fund-flow breakdowns for your own wallets — under Profile.' },
  { cat: 'App', term: 'Command Palette (Ctrl+K)', body: 'Press Ctrl+K (or /) from anywhere to jump to any page instantly. Paste in an XRPL address and it offers to inspect it directly, without navigating first.' },
  { cat: 'App', term: 'Wallet Vault', body: 'Your keys are encrypted client-side with AES-256-GCM and never leave your device — there is no server that could be breached to expose them. Your password isn\'t the encryption key directly; it\'s run through PBKDF2 (150,000 rounds) first, which is deliberately slow to make brute-forcing it harder. But naming an algorithm isn\'t a blanket guarantee: the encryption is only as strong as your password, it does nothing against malware or a keylogger reading your password as you type it, and since nothing is stored on a server, there\'s no password reset — your only way back in without your password is a backup you export yourself, in advance.' },

  // ── On-Chain & Forensic Concepts ──
  { cat: 'On-Chain', term: 'Trustline', body: 'A trustline is what lets an account hold a token that isn\'t XRP. You must explicitly create one to a token\'s issuer before you can receive that token — this is an XRPL-specific safeguard against unwanted tokens landing in your wallet.' },
  { cat: 'On-Chain', term: 'AMM / Liquidity Pool', body: 'An Automated Market Maker pool holds reserves of two assets (e.g. XRP and a token) and prices trades algorithmically based on the ratio between them. Deeper reserves generally mean less price impact per trade.' },
  { cat: 'On-Chain', term: 'Order Book Depth / Slippage', body: 'How much of an asset is actually available to buy or sell at each price level on the live DEX order book. Thin depth means a modest-sized trade can move the price a lot — that price movement is slippage.' },
  { cat: 'On-Chain', term: 'Holder Concentration', body: 'What percentage of a token\'s total supply sits in the top 1, 5, or 10 wallets. High concentration means a small number of holders could crash the price by selling — a common signal used to spot rug-pull risk.' },
  { cat: 'On-Chain', term: 'LP Token Concentration', body: 'AMM pools issue their own "LP tokens" representing a share of the pool. If a handful of addresses hold most of the LP tokens, they can pull most of the pool\'s liquidity out at once, collapsing tradability.' },
  { cat: 'On-Chain', term: 'Issuer', body: 'The XRPL account that created a token and controls certain settings on it (freeze, clawback, auth requirements). Every issued token has exactly one issuer address — it\'s effectively that token\'s "admin account."' },
  { cat: 'On-Chain', term: 'Clawback', body: PI_ISSUER_EXPLANATIONS.clawbackEnabled },
  { cat: 'On-Chain', term: 'Global Freeze', body: PI_ISSUER_EXPLANATIONS.globalFreeze },
  { cat: 'On-Chain', term: 'Freeze-Capable', body: PI_ISSUER_EXPLANATIONS.freezeCapable },
  { cat: 'On-Chain', term: 'Require Auth', body: PI_ISSUER_EXPLANATIONS.requireAuth },
  { cat: 'On-Chain', term: 'Blackholed / Black Hole Address', body: PI_ISSUER_EXPLANATIONS.blackholed },
  { cat: 'On-Chain', term: 'Fund Flow', body: 'Where XRP actually goes after leaving a wallet — tracing outbound payments to their destinations, flagging known exchanges, black-hole addresses, and brand-new wallets receiving large transfers (a common drain-attack pattern).' },
  { cat: 'On-Chain', term: 'Convergence Signal', body: 'The Forensic Analytics Suite runs several independent detection engines. When two or more flag the same address using unrelated methods, that agreement ("convergence") is a stronger signal than any single engine alone — a single flag can be a false positive, convergence usually isn\'t.' },
];

let query = '';

export function openHelp(presetQuery = '') {
  const overlay = $('helpOverlay');
  const input = $('helpInput');
  if (!overlay || !input) return;
  overlay.classList.add('show');
  query = presetQuery;
  input.value = presetQuery;
  _render();
  presetQuery ? input.select() : input.focus();
}

export function closeHelp() {
  $('helpOverlay')?.classList.remove('show');
}

export function filterHelp(q) {
  query = q;
  _render();
}

export function setupHelpListeners() {
  const overlay = $('helpOverlay');
  const input = $('helpInput');
  if (!overlay || !input) return;
  input.addEventListener('input', () => filterHelp(input.value));
  overlay.addEventListener('click', e => { if (e.target === overlay) closeHelp(); });
}

function _matches(entry, q) {
  if (!q) return true;
  const hay = `${entry.term} ${entry.body}`.toLowerCase();
  return hay.includes(q);
}

function _render() {
  const list = $('helpList');
  if (!list) return;
  const q = query.toLowerCase().trim();
  const filtered = ENTRIES.filter(e => _matches(e, q));

  if (!filtered.length) {
    list.innerHTML = `<div class="help-empty">No matches for "${escHtml(query)}".</div>`;
    return;
  }

  const cats = ['App', 'On-Chain'];
  const catLabel = { App: 'App Features', 'On-Chain': 'On-Chain & Forensic Concepts' };
  list.innerHTML = cats.map(cat => {
    const items = filtered.filter(e => e.cat === cat);
    if (!items.length) return '';
    return `
      <div class="help-cat-label">${escHtml(catLabel[cat])}</div>
      ${items.map(e => `
        <div class="help-entry">
          <div class="help-term">${escHtml(e.term)}</div>
          <div class="help-body">${escHtml(e.body)}</div>
        </div>`).join('')}`;
  }).join('');
}
