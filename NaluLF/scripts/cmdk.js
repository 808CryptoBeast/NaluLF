/* =====================================================
   cmdk.js — Command Palette (Ctrl+K / /)
   ===================================================== */
import { $, $$, escHtml } from './utils.js';
import { switchTab } from './nav.js';

const COMMANDS = [
  { label: '🌊 Live Stream',      hint: 'Dashboard → Stream tab',    action: () => switchTab(document.querySelector('[data-tab="stream"]'),    'stream') },
  { label: '🔍 Inspector',        hint: 'Dashboard → Inspector tab', action: () => switchTab(document.querySelector('[data-tab="inspector"]'), 'inspector') },
  { label: '📡 Network Health',   hint: 'Dashboard → Network tab',   action: () => switchTab(document.querySelector('[data-tab="network"]'),   'network') },
  { label: '🔑 Sign In',          hint: 'Open auth',                 action: () => window._openAuth?.('login') },
  { label: '✨ Sign Up',          hint: 'Create account',            action: () => window._openAuth?.('signup') },
  { label: '🏠 Landing Page',     hint: 'Go home',                   action: () => window._goHome?.() },
  { label: '🎨 Cycle Theme',      hint: 'gold → cosmic → starry →', action: () => window._cycleTheme?.() },
];

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
  filtered = q
    ? COMMANDS.filter(c => c.label.toLowerCase().includes(q) || c.hint.toLowerCase().includes(q))
    : [...COMMANDS];

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