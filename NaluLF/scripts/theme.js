/* =====================================================
   theme.js — Theme System (gold / cosmic / starry / hawaiian)
   ===================================================== */
import { THEMES, LS_THEME } from './config.js';
import { safeGet, safeSet } from './utils.js';
import { state } from './state.js';

export function setTheme(t) {
  if (!THEMES.includes(t)) t = 'gold';
  state.currentTheme = t;
  THEMES.forEach(th => document.body.classList.remove(`theme-${th}`));
  document.body.classList.add(`theme-${t}`);
  safeSet(LS_THEME, t);
}

export function cycleTheme() {
  const idx = THEMES.indexOf(state.currentTheme);
  setTheme(THEMES[(idx + 1) % THEMES.length]);
}

export function restoreTheme() {
  const saved = safeGet(LS_THEME);
  setTheme(THEMES.includes(saved) ? saved : 'gold');
}