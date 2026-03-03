/* =====================================================
   auth.js — Auth Modal: open · close · submit · logout
   ===================================================== */
import { $, safeGet, safeSet, safeRemove, safeJson } from './utils.js';
import { state } from './state.js';
import { showDashboard, showLandingPage } from './nav.js';
import { connectXRPL } from './xrpl.js';

const LS_SESSION = 'naluxrp_session';

/* ── Open / close ── */
export function openAuth(mode = 'login') {
  const overlay = $('auth-overlay');
  if (overlay) overlay.classList.add('show');
  setAuthMode(mode);
}

export function closeAuth() {
  const overlay = $('auth-overlay');
  if (overlay) overlay.classList.remove('show');
  clearAuthError();
}

export function setAuthMode(mode) {
  const isLogin  = mode === 'login';
  const title    = $('auth-modal-title');
  const sub      = $('auth-sub');
  const submitBtn= $('auth-submit');
  const loginTab = $('tab-login-btn');
  const signupTab= $('tab-signup-btn');
  const handleFld= $('field-handle');

  if (title)     title.textContent     = isLogin ? 'Welcome back' : 'Create account';
  if (sub)       sub.textContent       = isLogin ? 'Sign in to access your dashboard.' : 'Free account. No wallet needed.';
  if (submitBtn) submitBtn.textContent = isLogin ? 'Sign In →' : 'Sign Up →';
  if (loginTab)  loginTab.classList.toggle('active', isLogin);
  if (signupTab) signupTab.classList.toggle('active', !isLogin);
  if (handleFld) handleFld.style.display = isLogin ? 'none' : '';

  clearAuthError();
  $('auth-overlay')?.setAttribute('data-mode', mode);
}

/* ── Submit (client-side mock — swap for real API later) ── */
export function submitAuth() {
  const mode     = $('auth-overlay')?.getAttribute('data-mode') || 'login';
  const email    = $('inp-email')?.value.trim() || '';
  const password = $('inp-pass')?.value || '';
  const handle   = $('inp-handle')?.value.trim() || '';

  clearAuthError();

  if (!email)    return showAuthError('Email is required.');
  if (!email.includes('@')) return showAuthError('Enter a valid email address.');
  if (password.length < 6)  return showAuthError('Password must be at least 6 characters.');
  if (mode === 'signup' && !handle) return showAuthError('Display name is required.');

  const name = mode === 'signup' ? handle : email.split('@')[0];
  state.session = { name, email };
  safeSet(LS_SESSION, JSON.stringify(state.session));

  closeAuth();
  applySession(state.session);
  showDashboard();
  connectXRPL();
}

/* ── Logout ── */
export function logout() {
  state.session = null;
  safeRemove(LS_SESSION);
  showLandingPage();
  window.dispatchEvent(new Event('naluxrp:logout'));
}

/* ── Restore session from localStorage ── */
export function restoreSession() {
  const saved = safeJson(safeGet(LS_SESSION));
  if (saved?.email) {
    state.session = saved;
    applySession(saved);
    return true;
  }
  return false;
}

/* ── Helpers ── */
function applySession(session) {
  const avatar   = $('user-avatar');
  const nameEl   = $('user-name');
  if (avatar)  avatar.textContent  = session.name.charAt(0).toUpperCase();
  if (nameEl)  nameEl.textContent  = session.name;
}

function showAuthError(msg) {
  const errEl = $('auth-error');
  if (errEl) errEl.textContent = msg;
}
function clearAuthError() {
  const errEl = $('auth-error');
  if (errEl) errEl.textContent = '';
}