/* =====================================================
   cmdk.js — Command Palette (Ctrl+K / /)
   ===================================================== */
import { $, $$, escHtml, isValidXrpAddress } from './utils.js';
import { switchTab } from './nav.js';

// Jumps that need the profile page mounted first — showProfile() rebuilds
// .xrpl-profile-dashboard from scratch, so the target section's element
// doesn't exist yet in the same tick; the delay just gives that render a
// moment to land before scrollIntoView looks for it.
function _jumpToProfile(fn) {
  window.showProfile?.();
  setTimeout(() => fn?.(), 250);
}

const COMMANDS = [
  { label: '🌊 Live Stream',      hint: 'Dashboard → Stream tab',    action: () => switchTab(document.querySelector('[data-tab="stream"]'),    'stream') },
  { label: '🔍 Inspector',        hint: 'Dashboard → Inspector tab', action: () => switchTab(document.querySelector('[data-tab="inspector"]'), 'inspector') },
  { label: '📡 Network Health',   hint: 'Dashboard → Network tab',   action: () => switchTab(document.querySelector('[data-tab="network"]'),   'network') },
  { label: '👤 Profile',          hint: 'View your profile',         action: () => window.showProfile?.() },
  { label: '💎 Wallets',          hint: 'Profile → Wallets',                 action: () => _jumpToProfile(() => window.switchProfileTab?.('wallets')) },
  { label: '📊 Portfolio Analytics', hint: 'Profile → Balance history, heatmap, flow', action: () => _jumpToProfile(() => window.switchProfileTab?.('analytics')) },
  { label: '🔗 Social Links',     hint: 'Profile → Connect Discord, X, GitHub…', action: () => _jumpToProfile(() => window.switchProfileTab?.('social')) },
  { label: '📜 Activity Log',     hint: 'Profile → Recent account activity', action: () => _jumpToProfile(() => window.switchProfileTab?.('activity')) },
  { label: '⚙️ Settings',         hint: 'Profile → Preferences & AI Explanations', action: () => _jumpToProfile(() => window.switchProfileTab?.('settings')) },
  { label: '🔬 Analyze a Project', hint: 'Liquidity depth, holder/LP concentration, issuer risk', action: () => _jumpToProfile(() => window.jumpToProjectIntelLookup?.()) },
  { label: '🧭 Replay App Tour',  hint: 'Retake the onboarding walkthrough', action: () => { window.showDashboard?.(); setTimeout(() => window.startTour?.(), 300); } },
  { label: '🔑 Sign In',          hint: 'Open auth',                 action: () => window._openAuth?.('login') },
  { label: '✨ Sign Up',          hint: 'Create account',            action: () => window._openAuth?.('signup') },
  { label: '🏠 Landing Page',     hint: 'Go home',                   action: () => window._goHome?.() },
  { label: '🎨 Cycle Theme',      hint: 'gold → cosmic → starry →', action: () => window._cycleTheme?.() },
];

/** Runs on every keystroke — pastes-in address detection, no lookup or
 *  network call, just the same synchronous format check the Inspector
 *  itself does before ever touching the network. This is the one
 *  documented cmdk capability ("inspect any address") that had no actual
 *  implementation anywhere in this file. */
function _dynamicCommandsFor(query) {
  const q = query.trim();
  if (!isValidXrpAddress(q)) return [];
  return [{
    label: `🔍 Inspect ${q.slice(0, 8)}…${q.slice(-6)}`,
    hint: 'Run the full account inspection on this address',
    action: () => {
      switchTab(document.querySelector('[data-tab="inspector"]'), 'inspector');
      setTimeout(() => {
        const input = document.getElementById('inspect-addr');
        if (input) input.value = q;
        window.runInspect?.();
      }, 200);
    },
  }];
}

let activeIndex = 0;
let filtered    = [...COMMANDS];

export function openCmdk(prefill = '') {
  const overlay = $('cmdkOverlay');
  const input   = $('cmdkInput');
  if (!overlay || !input) return;

  overlay.classList.add('show');
  input.value = prefill || '';
  renderList(prefill);
  input.focus();
}

export function closeCmdk() {
  $('cmdkOverlay')?.classList.remove('show');
}

export function setupCmdkListeners() {
  const overlay = $('cmdkOverlay');
  const input   = $('cmdkInput');
  if (!overlay || !input) return;

  // Filter as user types
  input.addEventListener('input', () => renderList(input.value));

  // Keyboard nav
  input.addEventListener('keydown', e => {
    if (e.key === 'ArrowDown') { e.preventDefault(); move(1); }
    if (e.key === 'ArrowUp')   { e.preventDefault(); move(-1); }
    if (e.key === 'Enter')     { e.preventDefault(); runActive(); }
    if (e.key === 'Escape')    { closeCmdk(); }
  });

  // Click outside to close
  overlay.addEventListener('click', e => { if (e.target === overlay) closeCmdk(); });
}

/* ── Helpers ── */
function renderList(query = '') {
  const list = $('cmdkList');
  if (!list) return;

  const q = query.toLowerCase().trim();
  // Dynamic commands (address detection) go first — pasting a real address
  // should offer "inspect this" as the obvious top result, not buried under
  // static commands that happen to also match some substring.
  const dynamic = _dynamicCommandsFor(query);
  filtered = q
    ? [...dynamic, ...COMMANDS.filter(c => c.label.toLowerCase().includes(q) || c.hint.toLowerCase().includes(q))]
    : [...dynamic, ...COMMANDS];

  activeIndex = 0;

  list.innerHTML = filtered.length
    ? filtered.map((c, i) => `
        <button class="cmdk-item${i === 0 ? ' is-active' : ''}" data-index="${i}">
          <span class="cmdk-label">${escHtml(c.label)}</span>
          <span class="cmdk-hint2">${escHtml(c.hint)}</span>
        </button>`).join('')
    : `<div class="cmdk-section-label">No results</div>`;

  list.querySelectorAll('.cmdk-item').forEach(btn => {
    btn.addEventListener('click', () => run(Number(btn.dataset.index)));
  });
}

function move(dir) {
  const items = $$('#cmdkList .cmdk-item');
  if (!items.length) return;
  items[activeIndex]?.classList.remove('is-active');
  activeIndex = (activeIndex + dir + items.length) % items.length;
  items[activeIndex]?.classList.add('is-active');
  items[activeIndex]?.scrollIntoView({ block: 'nearest' });
}

function run(index) {
  const cmd = filtered[index];
  if (cmd) { closeCmdk(); cmd.action(); }
}

function runActive() { run(activeIndex); }