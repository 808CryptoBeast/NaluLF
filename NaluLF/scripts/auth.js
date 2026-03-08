/* =====================================================
   auth.js — Sign In · Sign Up · Forgot Password
   ─────────────────────────────────────────────────────
   Crypto backend (unchanged — CryptoVault):
   • PBKDF2 (150k iterations, SHA-256) → AES-256-GCM
   • Seeds & keys encrypted before any localStorage write
   • Password never stored — only used for key derivation
   • Auto-lock after 30 min inactivity
   ===================================================== */
import { $, safeGet, safeSet, safeRemove, safeJson, toastInfo, toastErr } from './utils.js';
import { state } from './state.js';
import { showDashboard, showLandingPage } from './nav.js';
import { connectXRPL } from './xrpl.js';

const LS_VAULT_META = 'naluxrp_vault_meta';
const LS_VAULT_DATA = 'naluxrp_vault_data';
const LS_SESSION    = 'naluxrp_session';
const PBKDF2_ITERS  = 150_000;
const VAULT_VER     = 'naluxrp_v2';

/* ═══════════════════════════════════════════════════
   CryptoVault — all encryption lives here, invisible to users
═══════════════════════════════════════════════════ */
export const CryptoVault = {
  _key: null, _vault: null, _lockTimer: null,
  AUTO_LOCK_MS: 30 * 60 * 1000,

  get isUnlocked() { return this._key !== null && this._vault !== null; },
  get vault()      { return this._vault; },

  hasVault() {
    return !!safeGet(LS_VAULT_META) && !!safeGet(LS_VAULT_DATA);
  },

  async create(password, name, email) {
    const salt = crypto.getRandomValues(new Uint8Array(32));
    this._key  = await this._deriveKey(password, salt);
    this._vault = {
      checksum: VAULT_VER,
      identity: { name, email, createdAt: new Date().toISOString() },
      profile: {}, wallets: [], social: {},
    };
    safeSet(LS_VAULT_META, JSON.stringify({ salt: Array.from(salt), iterations: PBKDF2_ITERS, version: VAULT_VER }));
    await this._persist();
    this._startLockTimer();
    return this._vault;
  },

  async unlock(password) {
    const meta = safeJson(safeGet(LS_VAULT_META));
    if (!meta) throw new Error('No account found on this device. Please create one first.');
    this._key = await this._deriveKey(password, new Uint8Array(meta.salt));
    let vault;
    try {
      const stored = safeJson(safeGet(LS_VAULT_DATA));
      if (!stored) throw new Error('missing');
      vault = await this._decrypt(stored);
    } catch {
      this._key = null;
      throw new Error('Incorrect password. Please try again.');
    }
    if (vault?.checksum !== VAULT_VER) {
      this._key = null;
      throw new Error('Account data appears corrupted. Restore from a backup file.');
    }
    this._vault = vault;
    this._startLockTimer();
    return this._vault;
  },

  async update(fn) {
    if (!this.isUnlocked) throw new Error('Please sign in to continue.');
    fn(this._vault);
    await this._persist();
  },

  lock() {
    this._key = null; this._vault = null;
    clearTimeout(this._lockTimer); this._lockTimer = null;
  },

  resetTimer() { if (this.isUnlocked) this._startLockTimer(); },

  async changePassword(newPassword) {
    if (!this.isUnlocked) throw new Error('Please sign in first.');
    const newSalt = crypto.getRandomValues(new Uint8Array(32));
    this._key = await this._deriveKey(newPassword, newSalt);
    safeSet(LS_VAULT_META, JSON.stringify({ salt: Array.from(newSalt), iterations: PBKDF2_ITERS, version: VAULT_VER }));
    await this._persist();
  },

  async exportBlob() {
    if (!this.isUnlocked) throw new Error('Sign in before exporting.');
    const blob = { vault: safeJson(safeGet(LS_VAULT_DATA)), meta: safeJson(safeGet(LS_VAULT_META)), exportedAt: new Date().toISOString() };
    const url  = URL.createObjectURL(new Blob([JSON.stringify(blob, null, 2)], { type: 'application/json' }));
    Object.assign(document.createElement('a'), { href: url, download: `naluxrp-backup-${Date.now()}.json` }).click();
    URL.revokeObjectURL(url);
  },

  async _deriveKey(password, salt) {
    const enc = new TextEncoder();
    const km  = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: PBKDF2_ITERS, hash: 'SHA-256' },
      km, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
    );
  },
  async _encrypt(data) {
    const iv  = crypto.getRandomValues(new Uint8Array(12));
    const enc = new TextEncoder();
    const buf = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, this._key, enc.encode(JSON.stringify(data)));
    return { iv: Array.from(iv), cipher: Array.from(new Uint8Array(buf)) };
  },
  async _decrypt(stored) {
    const dec   = new TextDecoder();
    const plain = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: new Uint8Array(stored.iv) },
      this._key, new Uint8Array(stored.cipher).buffer
    );
    return JSON.parse(dec.decode(plain));
  },
  async _persist() {
    if (!this._key || !this._vault) return;
    safeSet(LS_VAULT_DATA, JSON.stringify(await this._encrypt(this._vault)));
  },
  _startLockTimer() {
    clearTimeout(this._lockTimer);
    this._lockTimer = setTimeout(() => {
      this.lock();
      window.dispatchEvent(new CustomEvent('naluxrp:vault-locked'));
    }, this.AUTO_LOCK_MS);
  },
};

/* ═══════════════════════════════════════════════════
   View management — login | signup | forgot
═══════════════════════════════════════════════════ */
let _captcha = { a: 0, b: 0 };

export function openAuth(mode) {
  if (!CryptoVault.hasVault() && mode !== 'signup') mode = 'signup';
  else mode = mode || 'login';
  $('auth-overlay')?.classList.add('show');
  showAuthView(mode);
}

export function closeAuth() {
  $('auth-overlay')?.classList.remove('show');
  _clearError();
}

export function showAuthView(view) {
  // Hide all views, show requested
  $$auth('.auth-view').forEach(el => el.classList.remove('active'));
  $(`auth-view-${view}`)?.classList.add('active');
  $('auth-overlay')?.setAttribute('data-view', view);

  // Tab active states
  $('tab-login-btn') ?.classList.toggle('active', view === 'login');
  $('tab-signup-btn')?.classList.toggle('active', view === 'signup');

  // Show/hide tab row — hide on forgot view
  const tabRow = $('auth-tab-row');
  if (tabRow) tabRow.style.display = view === 'forgot' ? 'none' : '';

  // Generate new captcha when showing signup
  if (view === 'signup') _refreshCaptcha();

  _clearError();
}

/* ═══════════════════════════════════════════════════
   Captcha — simple client-side math challenge
═══════════════════════════════════════════════════ */
function _refreshCaptcha() {
  _captcha.a = Math.floor(Math.random() * 9) + 1;
  _captcha.b = Math.floor(Math.random() * 9) + 1;
  const q = $('captcha-question');
  if (q) q.textContent = `${_captcha.a} + ${_captcha.b} = ?`;
  const inp = $('inp-captcha');
  if (inp) inp.value = '';
}

export function refreshCaptcha() { _refreshCaptcha(); }

function _verifyCaptcha() {
  const val = parseInt($('inp-captcha')?.value || '', 10);
  return val === _captcha.a + _captcha.b;
}

/* ═══════════════════════════════════════════════════
   Sign In
═══════════════════════════════════════════════════ */
export async function submitSignIn() {
  const email    = $('inp-login-email')?.value.trim() || '';
  const password = $('inp-login-pass')?.value         || '';
  _clearError();
  if (!email)    return _showError('Enter your email address.');
  if (!password) return _showError('Enter your password.');

  const btn = $('signin-btn');
  _setLoading(btn, true, 'Signing in…');

  try {
    const vault   = await CryptoVault.unlock(password);
    state.session = { name: vault.identity.name, email: vault.identity.email };
    safeSet(LS_SESSION, JSON.stringify(state.session));
    closeAuth();
    _applySession(state.session);
    showDashboard();
    connectXRPL();
    window.dispatchEvent(new CustomEvent('naluxrp:vault-ready', { detail: CryptoVault.vault }));
  } catch (err) {
    _showError(err.message);
  } finally {
    _setLoading(btn, false, 'Sign In →');
  }
}

/* ═══════════════════════════════════════════════════
   Sign Up
═══════════════════════════════════════════════════ */
export async function submitSignUp() {
  const name     = $('inp-signup-name')?.value.trim()     || '';
  const email    = $('inp-signup-email')?.value.trim()    || '';
  const password = $('inp-signup-pass')?.value            || '';
  const confirm  = $('inp-signup-confirm')?.value         || '';
  _clearError();

  if (!name)                               return _showError('Enter a display name.');
  if (!email || !email.includes('@'))      return _showError('Enter a valid email address.');
  if (password.length < 8)                 return _showError('Password must be at least 8 characters.');
  if (!_pwStrong(password))                return _showError('Include at least one uppercase letter, lowercase letter, and number.');
  if (password !== confirm)                return _showError('Passwords do not match.');
  if (!_verifyCaptcha())                   { _refreshCaptcha(); return _showError('Incorrect answer — try the new question.'); }

  const btn = $('signup-btn');
  _setLoading(btn, true, 'Creating account…');

  try {
    await CryptoVault.create(password, name, email);
    state.session = { name, email };
    safeSet(LS_SESSION, JSON.stringify(state.session));
    closeAuth();
    _applySession(state.session);
    showDashboard();
    connectXRPL();
    window.dispatchEvent(new CustomEvent('naluxrp:vault-ready', { detail: CryptoVault.vault }));
  } catch (err) {
    _showError(err.message);
    _refreshCaptcha();
  } finally {
    _setLoading(btn, false, 'Create Account →');
  }
}

/* ═══════════════════════════════════════════════════
   Forgot Password
   ─────────────────────────────────────────────────
   Important: because data is encrypted locally with
   the user's password, there is no server-side reset.
   We give users two options:
   1. Restore from an exported backup file
   2. Wipe and start fresh (loses all wallet metadata —
      wallets still exist on-chain and can be re-added)
═══════════════════════════════════════════════════ */
export function showForgotView() {
  showAuthView('forgot');
  // Reset forgot sub-steps
  $$auth('.forgot-step').forEach(el => el.style.display = 'none');
  $('forgot-step-options')?.style && ($('forgot-step-options').style.display = '');
}

export function forgotRestoreFromFile() {
  // Trigger file picker for backup JSON
  const input = document.createElement('input');
  input.type  = 'file';
  input.accept= '.json,application/json';
  input.onchange = async e => {
    const file = e.target.files[0];
    if (!file) return;
    try {
      const text = await file.text();
      const blob = JSON.parse(text);
      if (!blob?.vault || !blob?.meta) throw new Error('Invalid backup file format.');
      // Restore raw encrypted data — user must then sign in with original password
      safeSet(LS_VAULT_DATA, JSON.stringify(blob.vault));
      safeSet(LS_VAULT_META, JSON.stringify(blob.meta));
      toastInfo('Backup restored. Sign in with your original password.');
      showAuthView('login');
    } catch (err) {
      toastErr('Could not read backup: ' + err.message);
    }
  };
  input.click();
}

export function forgotWipeConfirm() {
  $$auth('.forgot-step').forEach(el => el.style.display = 'none');
  $('forgot-step-wipe')?.style && ($('forgot-step-wipe').style.display = '');
  const inp = $('inp-wipe-confirm');
  if (inp) inp.value = '';
}

export function forgotWipeExecute() {
  const val = $('inp-wipe-confirm')?.value.trim() || '';
  if (val !== 'DELETE') return _showError('Type DELETE exactly to confirm.');
  safeRemove(LS_VAULT_META);
  safeRemove(LS_VAULT_DATA);
  safeRemove(LS_SESSION);
  CryptoVault.lock();
  state.session = null;
  toastInfo('Account cleared. Create a new one to get started.');
  closeAuth();
  showAuthView('signup');
  window.dispatchEvent(new Event('naluxrp:logout'));
}

export function forgotBackToOptions() {
  $$auth('.forgot-step').forEach(el => el.style.display = 'none');
  $('forgot-step-options')?.style && ($('forgot-step-options').style.display = '');
  _clearError();
}

/* ═══════════════════════════════════════════════════
   Session
═══════════════════════════════════════════════════ */
export function logout() {
  CryptoVault.lock();
  state.session = null;
  safeRemove(LS_SESSION);
  showLandingPage();
  window.dispatchEvent(new Event('naluxrp:logout'));
}

export function restoreSession() {
  const saved = safeJson(safeGet(LS_SESSION));
  if (saved?.email && CryptoVault.hasVault()) {
    state.session = saved;
    _applySession(saved);
    return true;
  }
  return false;
}

/* ═══════════════════════════════════════════════════
   Enter key support
═══════════════════════════════════════════════════ */
export function authKeydown(e) {
  if (e.key !== 'Enter') return;
  const view = $('auth-overlay')?.getAttribute('data-view') || 'login';
  if (view === 'login')  submitSignIn();
  if (view === 'signup') submitSignUp();
}

/* ─── Helpers ─────────────────────────────────────── */
function _pwStrong(pw) {
  return /[A-Z]/.test(pw) && /[a-z]/.test(pw) && /[0-9]/.test(pw);
}
function _applySession(s) {
  const a = $('user-avatar'), n = $('user-name');
  if (a) a.textContent = s.name.charAt(0).toUpperCase();
  if (n) n.textContent = s.name;
}
function _showError(msg) {
  const el = $('auth-error');
  if (el) { el.textContent = msg; el.style.display = ''; }
}
function _clearError() {
  const el = $('auth-error');
  if (el) el.textContent = '';
}
function _setLoading(btn, loading, label) {
  if (!btn) return;
  btn.disabled    = loading;
  btn.textContent = label;
}
function $$auth(sel) {
  return Array.from(document.querySelectorAll(sel));
}

/* ─── Activity resets auto-lock timer ─────────────── */
['click','keydown','mousemove','touchstart'].forEach(ev =>
  document.addEventListener(ev, () => CryptoVault.resetTimer(), { passive: true })
);

window.addEventListener('naluxrp:vault-locked', () => {
  state.vaultLocked = true;
  toastInfo('🔒 Signed out for security. Sign in again to use your wallet.');
});

/* ─── UI helpers exposed to HTML ───────────────────── */
window.togglePwVisibility = function(inputId, btn) {
  const inp  = $(inputId);
  if (!inp) return;
  const show = inp.type === 'password';
  inp.type   = show ? 'text' : 'password';
  btn.textContent = show ? '🙈' : '👁';
};

window.updatePwStrength = function(pw) {
  const fill  = $('pw-strength-fill');
  const label = $('pw-strength-label');
  if (!fill || !label) return;
  let score = 0;
  if (pw.length >= 8)              score++;
  if (/[A-Z]/.test(pw))            score++;
  if (/[a-z]/.test(pw))            score++;
  if (/[0-9]/.test(pw))            score++;
  if (/[^A-Za-z0-9]/.test(pw))     score++;
  const levels = [
    { w: '0%',   bg: 'transparent',  txt: '' },
    { w: '20%',  bg: '#ff5555',       txt: 'Very weak' },
    { w: '40%',  bg: '#ff8c42',       txt: 'Weak' },
    { w: '60%',  bg: '#ffb86c',       txt: 'Fair' },
    { w: '80%',  bg: '#00d4ff',       txt: 'Good' },
    { w: '100%', bg: '#50fa7b',       txt: 'Strong ✓' },
  ];
  const lvl = levels[score] || levels[0];
  fill.style.width      = lvl.w;
  fill.style.background = lvl.bg;
  label.textContent     = lvl.txt;
  label.style.color     = lvl.bg;
};