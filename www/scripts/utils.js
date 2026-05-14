/* =====================================================
   utils.js — DOM · Validators · Formatters · Storage · Toast
   ===================================================== */

/* ── DOM ── */
export const $ = id => document.getElementById(id);
export const $$ = sel => [...document.querySelectorAll(sel)];

export function escHtml(s) {
  return String(s ?? '')
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
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