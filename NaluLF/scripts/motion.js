/* =====================================================
   motion.js — Reduced-Motion Preference
   ===================================================== */
import { LS_REDUCE_MOTION } from './config.js';
import { safeGet, safeSet } from './utils.js';

const MOTION_PREFS = ['system', 'reduce', 'full'];

function _osPrefersReduced() {
  return window.matchMedia?.('(prefers-reduced-motion: reduce)').matches ?? false;
}

function _apply(pref) {
  const reduce = pref === 'reduce' || (pref === 'system' && _osPrefersReduced());
  document.body.classList.toggle('reduce-motion', reduce);
}

export function getMotionPreference() {
  const saved = safeGet(LS_REDUCE_MOTION);
  return MOTION_PREFS.includes(saved) ? saved : 'system';
}

export function setMotionPreference(pref) {
  if (!MOTION_PREFS.includes(pref)) pref = 'system';
  safeSet(LS_REDUCE_MOTION, pref);
  _apply(pref);
}

// Called once at boot (mirrors theme.js's restoreTheme()). Also reacts live
// to the OS-level setting changing while the app is open — someone toggling
// their OS accessibility setting shouldn't need to reload this page for it
// to take effect, as long as they haven't overridden it with an explicit
// in-app choice.
export function restoreMotionPreference() {
  _apply(getMotionPreference());
  window.matchMedia?.('(prefers-reduced-motion: reduce)').addEventListener?.('change', () => {
    if (getMotionPreference() === 'system') _apply('system');
  });
}
