/* =====================================================
   utils.js — DOM · Validators · Formatters · Storage · Toast
   ===================================================== */

/* ── DOM ── */
export const $ = id => document.getElementById(id);
export const $$ = sel => [...document.querySelectorAll(sel)];

const FOCUSABLE_SEL = 'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

// Shared keyboard-accessibility wiring for the app's dialog/drawer overlays
// (Account Peek, Evidence Inspector, Compare, Relationship Drawer,
// Transaction Detail Drawer — all built on the same .acct-peek-overlay/
// .acct-peek-box shell). Call once per overlay right after mounting it,
// passing the overlay's own close function: wires Escape-to-close (scoped to
// this overlay, so it's a no-op while hidden) and Tab/Shift+Tab focus
// trapping. Attaches `overlay._a11yFocusIn`/`_a11yFocusOut` for the modal's
// own open()/close() to call — moving focus into the dialog on open and
// restoring it to whatever triggered the open on close, since a plain
// display:none/flex toggle with no focus management strands keyboard and
// screen-reader users wherever the mouse/tap last left focus.
export function bindOverlayA11y(overlay, close) {
  let lastFocused = null;

  overlay.addEventListener('keydown', (e) => {
    if (overlay.style.display === 'none') return;
    if (e.key === 'Escape') { e.stopPropagation(); close(); return; }
    if (e.key !== 'Tab') return;
    const focusable = [...overlay.querySelectorAll(FOCUSABLE_SEL)].filter(el => el.offsetParent !== null);
    if (!focusable.length) return;
    const first = focusable[0], last = focusable[focusable.length - 1];
    if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
  });

  overlay._a11yFocusIn = () => {
    lastFocused = document.activeElement;
    const focusable = [...overlay.querySelectorAll(FOCUSABLE_SEL)].filter(el => el.offsetParent !== null);
    focusable[0]?.focus?.();
  };
  overlay._a11yFocusOut = () => {
    lastFocused?.focus?.();
    lastFocused = null;
  };
}

export function escHtml(s) {
  // Escapes single quotes too (&#39;) — several call sites (network.js in
  // particular) interpolate this into single-quoted onclick="...('...')"
  // attributes built from untrusted upstream data (registry proxies,
  // third-party APIs); a literal quote there breaks out of the JS string
  // literal. &#39; is valid inside both single- and double-quoted HTML
  // attributes and in text content, so this is safe everywhere escHtml is
  // already used.
  return String(s ?? '')
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

/* ── Validators ── */
export function isValidXrpAddress(a) {
  return /^r[1-9A-HJ-NP-Za-km-z]{25,34}$/.test(String(a ?? '').trim());
}
export function isTxHash(h) {
  return /^[A-Fa-f0-9]{64}$/.test(String(h ?? '').trim());
}
export function isLedgerIndex(v) {
  const s = String(v ?? '').trim();
  if (!/^\d{1,10}$/.test(s)) return false;
  const n = Number(s);
  return Number.isFinite(n) && n > 0;
}

/* ── Formatters ── */
export function xrpFromDrops(drops) {
  return (Number(drops) / 1_000_000).toFixed(6);
}
export function fmt(n, decimals = 2) {
  if (n == null || !Number.isFinite(n)) return '—';
  return n.toLocaleString(undefined, { maximumFractionDigits: decimals });
}
export function shortAddr(a) {
  if (!a) return '';
  return `${a.slice(0, 8)}…${a.slice(-6)}`;
}

/* ── localStorage (safe wrappers) ── */
export function safeGet(key) {
  try { return localStorage.getItem(key); } catch { return null; }
}
export function safeSet(key, val) {
  try { localStorage.setItem(key, val); } catch {}
}
export function safeRemove(key) {
  try { localStorage.removeItem(key); } catch {}
}
export function safeJson(s, fallback = null) {
  try { return JSON.parse(s); } catch { return fallback; }
}

/* ── Toast notifications ── */
export function toast(msg, type = 'info', duration = 3000) {
  const box = $('notifications');
  if (!box) return;
  const div = document.createElement('div');
  div.className = `notification ${type}`;
  div.textContent = msg;
  box.appendChild(div);
  setTimeout(() => div.remove(), duration);
}
export const toastInfo = msg => toast(msg, 'info',  2500);
export const toastWarn = msg => toast(msg, 'warn',  4000);
export const toastErr  = msg => toast(msg, 'error', 5000);

// Tactile confirmation for key security actions (Emergency Sweep, Revoke
// Regular Key, Clear Signer List, Rotate Key) — a short vibration pulse on
// success. navigator.vibrate is a real, standard API, but iOS Safari (even
// installed as a home-screen PWA) has never implemented it in any WebKit
// version, with no public plan to — the only way to get real haptic feedback
// on iOS from this codebase would be wrapping it in a native shell
// (Capacitor/Cordova), well outside a pure web app's scope. Degrades to a
// harmless no-op everywhere unsupported (iOS Safari, desktop browsers,
// older Android) and provides real feedback on platforms that DO support it
// (Android Chrome/Firefox/Edge).
export function hapticPulse(pattern = 40) {
  try { navigator.vibrate?.(pattern); } catch { /* not supported, or not allowed in this context */ }
}