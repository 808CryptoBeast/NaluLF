/* =====================================================
   auth.js — Sign In · Sign Up · Forgot Password
   ===================================================== */
import { $, safeGet, safeSet, safeRemove, safeJson, toastInfo, toastErr } from './utils.js';
import { state } from './state.js';
import { showDashboard, showLandingPage } from './nav.js';
import { connectXRPL } from './xrpl.js';

const LS_VAULT_META   = 'naluxrp_vault_meta';
const LS_VAULT_DATA   = 'naluxrp_vault_data';
const LS_SESSION      = 'naluxrp_session';
const LS_USED_NAMES   = 'nalulf_used_names';
const LS_USED_EMAILS  = 'nalulf_used_emails';
const LS_USED_DOMAINS = 'nalulf_used_domains';
const PBKDF2_ITERS    = 150_000;
const VAULT_VER       = 'naluxrp_v2';

/* ═══════════════════════════════════════════════════════
   CryptoVault — AES-256-GCM encrypted, PBKDF2 150k iters
═══════════════════════════════════════════════════════ */
export const CryptoVault = {
  _key: null, _vault: null, _lockTimer: null,
  AUTO_LOCK_MS: 30 * 60 * 1000,

  get isUnlocked() { return this._key !== null && this._vault !== null; },
  get vault()      { return this._vault; },

  hasVault() {
    return !!safeGet(LS_VAULT_META) && !!safeGet(LS_VAULT_DATA);
  },

  async create(password, name, email, domain) {
    const salt       = crypto.getRandomValues(new Uint8Array(32));
    this._key        = await this._deriveKey(password, salt);
    const safeDomain = (domain || name).toLowerCase().replace(/[^a-z0-9_]/g, '');
    this._vault = {
      checksum: VAULT_VER,
      identity: { name, email, domain: safeDomain, createdAt: new Date().toISOString() },
      profile: {}, wallets: [], social: {}
    };
    safeSet(LS_VAULT_META, JSON.stringify({ salt: Array.from(salt), iterations: PBKDF2_ITERS, version: VAULT_VER }));
    await this._persist();
    this._startLockTimer();
    return this._vault;
  },

  async unlock(password) {
    const meta = safeJson(safeGet(LS_VAULT_META));
    if (!meta) throw new Error('No account found. Create one first.');
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
      throw new Error('Account data corrupted. Restore from backup.');
    }
    this._vault = vault;
    this._startLockTimer();
    return this._vault;
  },

  async update(fn) {
    if (!this.isUnlocked) throw new Error('Sign in to continue.');
    fn(this._vault);
    await this._persist();
  },

  lock() {
    this._key = null; this._vault = null;
    clearTimeout(this._lockTimer); this._lockTimer = null;
  },

  resetTimer() { if (this.isUnlocked) this._startLockTimer(); },

  async changePassword(newPassword) {
    if (!this.isUnlocked) throw new Error('Sign in first.');
    const newSalt = crypto.getRandomValues(new Uint8Array(32));
    this._key     = await this._deriveKey(newPassword, newSalt);
    safeSet(LS_VAULT_META, JSON.stringify({ salt: Array.from(newSalt), iterations: PBKDF2_ITERS, version: VAULT_VER }));
    await this._persist();
  },

  async exportBlob() {
    if (!this.isUnlocked) throw new Error('Sign in before exporting.');
    const blob = {
      vault:      safeJson(safeGet(LS_VAULT_DATA)),
      meta:       safeJson(safeGet(LS_VAULT_META)),
      exportedAt: new Date().toISOString()
    };
    const url = URL.createObjectURL(new Blob([JSON.stringify(blob, null, 2)], { type: 'application/json' }));
    Object.assign(document.createElement('a'), { href: url, download: `naluxrp-backup-${Date.now()}.json` }).click();
    URL.revokeObjectURL(url);
  },

  async _deriveKey(password, salt) {
    const enc = new TextEncoder();
    const km  = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: PBKDF2_ITERS, hash: 'SHA-256' },
      km,
      { name: 'AES-GCM', length: 256 },
      false, ['encrypt', 'decrypt']
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
      this._key,
      new Uint8Array(stored.cipher).buffer
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

/* ═══════════════════════════════════════════════════════
   View management
═══════════════════════════════════════════════════════ */
let _signupStep = 1;

export function openAuth(mode) {
  if (!CryptoVault.hasVault()) {
    showAuthView('welcome');
  } else {
    showAuthView(mode || 'login');
  }
  $('auth-overlay')?.classList.add('show');
}

export function closeAuth() {
  $('auth-overlay')?.classList.remove('show');
  _clearError();
  _signupStep = 1;
  _setSignupStep(1);
}

export function showAuthView(view) {
  $$auth('.auth-view').forEach(el => el.classList.remove('active'));
  $(`auth-view-${view}`)?.classList.add('active');
  $('auth-overlay')?.setAttribute('data-view', view);
  const hideTabs = ['welcome', 'forgot', 'sync', 'celebrate', 'syncaware'].includes(view);
  const tabRow   = $('auth-tab-row');
  if (tabRow) tabRow.style.display = hideTabs ? 'none' : '';
  $('tab-login-btn') ?.classList.toggle('active', view === 'login');
  $('tab-signup-btn')?.classList.toggle('active', view === 'signup');
  $('tab-sync-btn')  ?.classList.toggle('active', view === 'sync');
  if (view === 'signup') { _signupStep = 1; _setSignupStep(1); _refreshCaptcha(); }
  _clearError();
}

/* ═══════════════════════════════════════════════════════
   Three-step signup
═══════════════════════════════════════════════════════ */
function _setSignupStep(step) {
  [1, 2, 3].forEach(n => {
    const el  = $(`signup-step-${n}`);
    if (el)  el.style.display = n === step ? '' : 'none';
    const dot = $(`signup-dot-${n}`);
    if (dot) {
      dot.classList.toggle('active', n === step);
      dot.classList.toggle('done',   n < step);
    }
  });
  const labels = ['', 'Step 1 of 3 — Identity', 'Step 2 of 3 — Security', 'Step 3 of 3 — Sync setup'];
  const sl = $('signup-step-label');
  if (sl) sl.textContent = labels[step] || '';
}

export function signupNext() {
  _clearError();
  if (_signupStep === 1) {
    const name   = $('inp-signup-name')?.value.trim()   || '';
    const email  = $('inp-signup-email')?.value.trim()  || '';
    const domain = $('inp-signup-domain')?.value.trim() || '';
    if (!name  || name.length < 3)        return _showError('Display name must be at least 3 characters.');
    if (_isNameTaken(name))               return _showError(`"${name}" is already in use on this device.`);
    if (!email || !email.includes('@'))   return _showError('Enter a valid email address.');
    if (_isEmailTaken(email))             return _showError('That email is already registered on this device.');
    if (domain && _isDomainTaken(domain)) return _showError(`@${domain} is already taken on this device.`);
    if (domain && !/^[a-z0-9_]{2,30}$/.test(domain)) return _showError('Handle: 2-30 lowercase letters, numbers, underscores only.');
    _signupStep = 2;
    _setSignupStep(2);
    _refreshCaptcha();
    setTimeout(() => $('inp-signup-pass')?.focus(), 80);
  } else if (_signupStep === 2) {
    const password = $('inp-signup-pass')?.value    || '';
    const confirm  = $('inp-signup-confirm')?.value || '';
    if (!password || password.length < 8) return _showError('Password must be at least 8 characters.');
    if (!_pwStrong(password))             return _showError('Add uppercase, lowercase, and a number.');
    if (password !== confirm)             return _showError('Passwords do not match.');
    if (!_verifyCaptcha()) { _refreshCaptcha(); return _showError('Type the word from the image exactly.'); }
    _signupStep = 3;
    _setSignupStep(3);
    const nameEl = $('syncaware-name');
    const name   = $('inp-signup-name')?.value.trim() || 'there';
    if (nameEl) nameEl.textContent = name.split(' ')[0];
  }
}

export function signupBack() {
  if (_signupStep > 1) {
    _signupStep--;
    _setSignupStep(_signupStep);
    _clearError();
    if (_signupStep === 1) setTimeout(() => $('inp-signup-name')?.focus(), 80);
  }
}

/* ═══════════════════════════════════════════════════════
   Canvas Captcha
═══════════════════════════════════════════════════════ */
const CAPTCHA_WORDS = [
  'XRPL','LEDGER','VAULT','CRYPTO','BLOCK','TOKEN','CHAIN','WAVE',
  'ATLAS','FORGE','NEXUS','ORBIT','PRISM','DELTA','NOVA','SONIC',
  'PIXEL','GHOST','FLARE','SPARK','TITAN','LUNAR','STORM','PROXY',
  'CIPHER','RELAY','PULSE','SCOUT'
];
let _captchaWord = '';

function _refreshCaptcha() {
  _captchaWord = CAPTCHA_WORDS[Math.floor(Math.random() * CAPTCHA_WORDS.length)];
  const canvas = document.getElementById('captcha-canvas');
  const inp    = $('inp-captcha');
  if (inp) inp.value = '';
  if (!canvas) return;
  const ctx = canvas.getContext('2d'), W = canvas.width, H = canvas.height;
  ctx.clearRect(0, 0, W, H);
  ctx.fillStyle = '#080f1e'; ctx.fillRect(0, 0, W, H);
  ctx.strokeStyle = 'rgba(0,255,240,.05)'; ctx.lineWidth = 1;
  for (let x = 0; x < W; x += 18) { ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, H); ctx.stroke(); }
  for (let y = 0; y < H; y += 18) { ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(W, y); ctx.stroke(); }
  for (let i = 0; i < 55; i++) {
    ctx.fillStyle = `rgba(${Math.random() > .5 ? '0,255,240' : '160,180,255'},${(Math.random() * .22 + .05).toFixed(2)})`;
    ctx.beginPath(); ctx.arc(Math.random() * W, Math.random() * H, Math.random() * 2 + .5, 0, Math.PI * 2); ctx.fill();
  }
  for (let i = 0; i < 4; i++) {
    ctx.strokeStyle = `rgba(0,255,240,${(Math.random() * .1 + .03).toFixed(2)})`;
    ctx.lineWidth = 1; ctx.beginPath(); ctx.moveTo(0, Math.random() * H);
    ctx.bezierCurveTo(W * .3, Math.random() * H, W * .7, Math.random() * H, W, Math.random() * H);
    ctx.stroke();
  }
  const letters = _captchaWord.split(''), startX = (W - letters.length * 26) / 2 + 8;
  letters.forEach((ch, i) => {
    const x = startX + i * 26 + (Math.random() * 8 - 4), y = H / 2 + 8 + (Math.random() * 10 - 5);
    ctx.save(); ctx.translate(x, y); ctx.rotate(Math.random() * .35 - .175);
    ctx.shadowColor = 'rgba(0,255,240,.5)'; ctx.shadowBlur = 8;
    ctx.fillStyle = `rgb(${Math.random() > .4 ? '180,255,240' : '140,200,255'})`;
    ctx.font = `bold ${24 + Math.random() * 4}px 'JetBrains Mono','Courier New',monospace`;
    ctx.fillText(ch, 0, 0); ctx.restore();
  });
}

export function refreshCaptcha() { _refreshCaptcha(); }

function _verifyCaptcha() {
  return ($('inp-captcha')?.value || '').trim().toUpperCase() === _captchaWord;
}

/* ═══════════════════════════════════════════════════════
   Username / email / domain registry (local device only)
   NOTE: these registries only prevent duplicates on the
   same browser — there is no server-side enforcement.
═══════════════════════════════════════════════════════ */
function _isNameTaken(name) {
  return (safeJson(safeGet(LS_USED_NAMES)) || []).some(n => n.toLowerCase() === name.toLowerCase());
}
function _isEmailTaken(email) {
  return (safeJson(safeGet(LS_USED_EMAILS)) || []).some(e => e.toLowerCase() === email.toLowerCase());
}
function _isDomainTaken(domain) {
  return (safeJson(safeGet(LS_USED_DOMAINS)) || []).some(d => d.toLowerCase() === domain.toLowerCase());
}
function _registerNameEmailDomain(name, email, domain) {
  const names   = safeJson(safeGet(LS_USED_NAMES))   || [];
  const emails  = safeJson(safeGet(LS_USED_EMAILS))  || [];
  const domains = safeJson(safeGet(LS_USED_DOMAINS)) || [];
  if (!names.includes(name.toLowerCase()))               names.push(name.toLowerCase());
  if (!emails.includes(email.toLowerCase()))             emails.push(email.toLowerCase());
  if (domain && !domains.includes(domain.toLowerCase())) domains.push(domain.toLowerCase());
  safeSet(LS_USED_NAMES,   JSON.stringify(names));
  safeSet(LS_USED_EMAILS,  JSON.stringify(emails));
  safeSet(LS_USED_DOMAINS, JSON.stringify(domains));
}

/* ═══════════════════════════════════════════════════════
   Sign In
═══════════════════════════════════════════════════════ */
export async function submitSignIn() {
  const email    = $('inp-login-email')?.value.trim() || '';
  const password = $('inp-login-pass')?.value         || '';
  _clearError();
  if (!email)    return _showError('Enter your email address.');
  if (!password) return _showError('Enter your password.');
  const btn = $('signin-btn');
  _setLoading(btn, true, 'Signing in…');
  try {
    const vault = await CryptoVault.unlock(password);
    state.session = { name: vault.identity.name, email: vault.identity.email, domain: vault.identity.domain || '' };
    safeSet(LS_SESSION, JSON.stringify(state.session));
    closeAuth();
    _applySession(state.session);
    showDashboard();
    connectXRPL();
    window.dispatchEvent(new CustomEvent('naluxrp:vault-ready', { detail: CryptoVault.vault }));
    _dismissLockBanner();
  } catch (err) {
    _showError(err.message);
    $('auth-modal-inner')?.classList.add('shake');
    setTimeout(() => $('auth-modal-inner')?.classList.remove('shake'), 500);
  } finally {
    _setLoading(btn, false, 'Sign In →');
  }
}

/* ═══════════════════════════════════════════════════════
   Sign Up  (triggered from step 3 "Create Account" btn)
═══════════════════════════════════════════════════════ */
export async function submitSignUp() {
  const name     = $('inp-signup-name')?.value.trim()   || '';
  const email    = $('inp-signup-email')?.value.trim()  || '';
  const domain   = $('inp-signup-domain')?.value.trim() || name.toLowerCase().replace(/[^a-z0-9_]/g, '_');
  const password = $('inp-signup-pass')?.value    || '';
  const confirm  = $('inp-signup-confirm')?.value || '';
  _clearError();
  if (!password || password.length < 8) return _showError('Password must be at least 8 characters.');
  if (!_pwStrong(password))             return _showError('Add uppercase, lowercase, and a number.');
  if (password !== confirm)             return _showError('Passwords do not match.');
  if (!_verifyCaptcha()) {
    _refreshCaptcha();
    _signupStep = 2; _setSignupStep(2);
    return _showError('Type the word from the image exactly.');
  }
  const btn = $('signup-btn');
  _setLoading(btn, true, 'Creating vault…');
  try {
    await CryptoVault.create(password, name, email, domain);
    _registerNameEmailDomain(name, email, domain);
    state.session = { name, email, domain };
    safeSet(LS_SESSION, JSON.stringify(state.session));
    _applySession(state.session);
    _showCelebration(name, () => {
      closeAuth();
      showDashboard();
      connectXRPL();
      window.dispatchEvent(new CustomEvent('naluxrp:vault-ready', { detail: CryptoVault.vault }));
      setTimeout(_showBackupReminder, 3500);
    });
  } catch (err) {
    _showError(err.message);
    _refreshCaptcha();
    _signupStep = 2; _setSignupStep(2);
  } finally {
    _setLoading(btn, false, 'Create Account →');
  }
}

/* ═══════════════════════════════════════════════════════
   Celebration screen
═══════════════════════════════════════════════════════ */
function _showCelebration(name, onDone) {
  showAuthView('celebrate');
  const el = $('celebrate-name');
  if (el) el.textContent = name.split(' ')[0];
  const timer = setTimeout(onDone, 2800);
  const btn   = $('celebrate-continue-btn');
  if (btn) btn.onclick = () => { clearTimeout(timer); onDone(); };
}

/* ═══════════════════════════════════════════════════════
   Forgot Password
═══════════════════════════════════════════════════════ */
export function showForgotView() {
  showAuthView('forgot');
  $$auth('.forgot-step').forEach(el => el.style.display = 'none');
  const opts = $('forgot-step-options');
  if (opts) opts.style.display = '';
}

export function forgotRestoreFromFile() {
  const input = document.createElement('input');
  input.type = 'file'; input.accept = '.json,application/json';
  input.onchange = async e => {
    const file = e.target.files[0]; if (!file) return;
    try {
      const text = await file.text(), blob = JSON.parse(text);
      if (!blob?.vault || !blob?.meta) throw new Error('Invalid backup file.');
      safeSet(LS_VAULT_DATA, JSON.stringify(blob.vault));
      safeSet(LS_VAULT_META, JSON.stringify(blob.meta));
      toastInfo('Backup restored — sign in with your original password.');
      showAuthView('login');
    } catch (err) { toastErr('Could not read backup: ' + err.message); }
  };
  input.click();
}

export function forgotWipeConfirm() {
  $$auth('.forgot-step').forEach(el => el.style.display = 'none');
  const wipe = $('forgot-step-wipe');
  if (wipe) wipe.style.display = '';
  const inp = $('inp-wipe-confirm');
  if (inp) inp.value = '';
}

export function forgotWipeExecute() {
  const val = $('inp-wipe-confirm')?.value.trim() || '';
  if (val !== 'DELETE') return _showError('Type DELETE exactly.');
  safeRemove(LS_VAULT_META); safeRemove(LS_VAULT_DATA); safeRemove(LS_SESSION);
  CryptoVault.lock(); state.session = null;
  toastInfo('Account cleared. Create a new one.');
  closeAuth(); showAuthView('signup');
  window.dispatchEvent(new Event('naluxrp:logout'));
}

export function forgotBackToOptions() {
  $$auth('.forgot-step').forEach(el => el.style.display = 'none');
  const opts = $('forgot-step-options');
  if (opts) opts.style.display = '';
  _clearError();
}

/* ═══════════════════════════════════════════════════════
   Vault Sync — export code overlay
═══════════════════════════════════════════════════════ */
export function exportVaultSyncCode() {
  const vd = safeGet(LS_VAULT_DATA), vm = safeGet(LS_VAULT_META);
  if (!vd || !vm) { toastErr('No vault to export.'); return; }
  const payload = btoa(JSON.stringify({ vault: JSON.parse(vd), meta: JSON.parse(vm) }));
  const overlay = document.createElement('div');
  overlay.id = 'sync-code-overlay';
  overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.92);backdrop-filter:blur(14px);z-index:99999;display:flex;align-items:center;justify-content:center;padding:20px;';
  overlay.innerHTML = `<div style="background:#0d1829;border:1.5px solid rgba(0,255,240,.22);border-radius:22px;padding:28px;max-width:500px;width:100%;box-shadow:0 28px 70px rgba(0,0,0,.95);"><div style="font-size:1rem;font-weight:900;margin-bottom:6px;color:#00fff0;">📱 Vault Sync Code</div><p style="font-size:.82rem;color:rgba(255,255,255,.55);margin-bottom:16px;line-height:1.6;">On your new device open NaluLF → <strong style="color:rgba(255,255,255,.8)">📱 New Device</strong> tab, paste this code and enter your password.</p><textarea readonly id="sync-code-output" style="width:100%;height:110px;background:#060e1a;border:1px solid rgba(255,255,255,.12);border-radius:10px;color:rgba(0,255,240,.85);font-family:monospace;font-size:.7rem;padding:10px;resize:none;box-sizing:border-box;" spellcheck="false">${payload}</textarea><div style="display:flex;gap:10px;margin-top:14px;justify-content:flex-end;"><button onclick="document.getElementById('sync-code-overlay').remove()" style="padding:9px 16px;background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.12);border-radius:9px;color:rgba(255,255,255,.65);font-size:.85rem;font-weight:700;cursor:pointer;font-family:inherit;">Close</button><button onclick="navigator.clipboard.writeText(document.getElementById('sync-code-output').value).then(()=>{this.textContent='✓ Copied!';setTimeout(()=>this.textContent='Copy Code',2000)})" style="padding:9px 18px;background:linear-gradient(135deg,#00d4ff,#00fff0);border:none;border-radius:9px;color:#000;font-size:.85rem;font-weight:900;cursor:pointer;font-family:inherit;">Copy Code</button></div></div>`;
  document.body.appendChild(overlay);
  overlay.addEventListener('click', e => { if (e.target === overlay) overlay.remove(); });
}

/* ═══════════════════════════════════════════════════════
   Vault Sync — import via pasted code
═══════════════════════════════════════════════════════ */
export async function submitSyncImport() {
  const code = $('inp-sync-code')?.value.trim() || '';
  const pass = $('inp-sync-pass')?.value        || '';
  _clearError();
  if (!code) return _showError('Paste your vault sync code or load a backup file first.');
  if (!pass) return _showError('Enter the password from your original device.');
  const btn = document.querySelector('#auth-view-sync .auth-submit-btn');
  if (btn) { btn.disabled = true; btn.textContent = 'Importing…'; }
  try {
    let decoded;
    try   { decoded = JSON.parse(atob(code)); }
    catch {
      try   { decoded = JSON.parse(code); }
      catch { throw new Error('Invalid sync code. Paste the full code from your other device.'); }
    }
    if (!decoded?.vault || !decoded?.meta) throw new Error('Invalid sync code format — make sure you copied the entire code.');
    safeSet(LS_VAULT_DATA, JSON.stringify(decoded.vault));
    safeSet(LS_VAULT_META, JSON.stringify(decoded.meta));
    const vault = await CryptoVault.unlock(pass);
    state.session = { name: vault.identity.name, email: vault.identity.email, domain: vault.identity.domain || '' };
    safeSet(LS_SESSION, JSON.stringify(state.session));
    closeAuth();
    _applySession(state.session);
    showDashboard();
    connectXRPL();
    window.dispatchEvent(new CustomEvent('naluxrp:vault-ready', { detail: CryptoVault.vault }));
    toastInfo('✅ Account imported to this device!');
  } catch (err) {
    const isWrongPw = err.message.includes('decrypt') || err.message.includes('Incorrect');
    _showError(isWrongPw ? 'Wrong password — use the password from your original device.' : 'Could not import: ' + err.message);
    safeRemove(LS_VAULT_DATA);
    safeRemove(LS_VAULT_META);
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Import & Sign In →'; }
  }
}

/* ═══════════════════════════════════════════════════════
   Vault Sync — load from .json backup file
   Pre-fills the sync code textarea so the user just
   enters their password and clicks "Import & Sign In".
═══════════════════════════════════════════════════════ */
export function syncImportFromFile() {
  const input = document.createElement('input');
  input.type = 'file'; input.accept = '.json,application/json';
  input.onchange = async e => {
    const file = e.target.files[0]; if (!file) return;
    try {
      const text = await file.text();
      const blob = JSON.parse(text);
      if (!blob?.vault || !blob?.meta) throw new Error('Invalid backup file format.');
      const codeEl = $('inp-sync-code');
      if (codeEl) codeEl.value = btoa(JSON.stringify({ vault: blob.vault, meta: blob.meta }));
      const fb = $('sync-file-feedback');
      if (fb) { fb.textContent = `✓ File loaded: ${file.name}`; fb.style.color = '#50fa7b'; }
      $('inp-sync-pass')?.focus();
    } catch (err) {
      toastErr('Could not read backup: ' + err.message);
    }
  };
  input.click();
}

/* ═══════════════════════════════════════════════════════
   Session
═══════════════════════════════════════════════════════ */
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

/* ═══════════════════════════════════════════════════════
   Lock banner
═══════════════════════════════════════════════════════ */
function _showLockBanner() {
  if ($('vault-lock-banner')) return;
  const banner = document.createElement('div');
  banner.id = 'vault-lock-banner'; banner.className = 'vault-lock-banner';
  banner.innerHTML = `<span class="vlb-icon">🔒</span><span class="vlb-text">Vault locked for security after 30 min of inactivity.</span><button class="vlb-btn" onclick="openAuth('login')">Unlock →</button><button class="vlb-close" onclick="this.closest('.vault-lock-banner').remove()" title="Dismiss">✕</button>`;
  document.body.prepend(banner);
  requestAnimationFrame(() => banner.classList.add('show'));
}

function _dismissLockBanner() {
  const el = $('vault-lock-banner');
  if (el) { el.classList.remove('show'); setTimeout(() => el.remove(), 300); }
}

/* ═══════════════════════════════════════════════════════
   Backup reminder
═══════════════════════════════════════════════════════ */
function _showBackupReminder() {
  if ($('backup-reminder-banner') || !CryptoVault.hasVault()) return;
  const banner = document.createElement('div');
  banner.id = 'backup-reminder-banner'; banner.className = 'backup-reminder-banner';
  banner.innerHTML = `<span class="brb-icon">⚠️</span><div class="brb-body"><strong>Back up your vault</strong> — you'll lose access if browser storage is cleared. <button class="brb-btn" onclick="window.exportVaultBackup?.()">Export Backup</button></div><button class="brb-close" onclick="this.closest('.backup-reminder-banner').remove()">✕</button>`;
  const profilePage = document.getElementById('profile-page');
  if (profilePage) profilePage.prepend(banner); else document.body.prepend(banner);
  requestAnimationFrame(() => banner.classList.add('show'));
}

/* ═══════════════════════════════════════════════════════
   Keyboard navigation
═══════════════════════════════════════════════════════ */
export function authKeydown(e) {
  const view = $('auth-overlay')?.getAttribute('data-view') || 'login';
  if (e.key === 'Enter') {
    if (view === 'login')  submitSignIn();
    if (view === 'signup') { if (_signupStep < 3) signupNext(); else submitSignUp(); }
    if (view === 'sync')   submitSyncImport();
  }
  if (e.key === 'Tab') {
    const modal = $('auth-modal-inner'); if (!modal) return;
    const focusable = Array.from(modal.querySelectorAll('button:not([disabled]),input,textarea,select'))
      .filter(el => el.offsetParent !== null);
    if (!focusable.length) return;
    const first = focusable[0], last = focusable[focusable.length - 1];
    if (e.shiftKey  && document.activeElement === first) { e.preventDefault(); last.focus(); }
    if (!e.shiftKey && document.activeElement === last)  { e.preventDefault(); first.focus(); }
  }
}

/* ═══════════════════════════════════════════════════════
   Inline field validation (attached to window for
   inline onblur/oninput handlers in HTML)
═══════════════════════════════════════════════════════ */
function _fieldOk(id)    { const el = $(id); el?.classList.add('valid');    el?.classList.remove('invalid'); }
function _fieldErr(id)   { const el = $(id); el?.classList.add('invalid');  el?.classList.remove('valid');   }
function _fieldReset(id) { const el = $(id); el?.classList.remove('valid', 'invalid'); }

window.validateSignupName = () => {
  const v    = $('inp-signup-name')?.value.trim() || '';
  const hint = $('hint-signup-name');
  if (!v) { _fieldReset('inp-signup-name'); if (hint) hint.textContent = ''; return; }
  if (v.length < 3)    { _fieldErr('inp-signup-name'); if (hint) hint.textContent = 'At least 3 characters'; return; }
  if (_isNameTaken(v)) { _fieldErr('inp-signup-name'); if (hint) hint.textContent = 'Already in use on this device'; return; }
  _fieldOk('inp-signup-name'); if (hint) hint.textContent = '✓ Looks good!';
  const domainEl = $('inp-signup-domain');
  if (domainEl && !domainEl.dataset.manuallyEdited) {
    domainEl.value = v.toLowerCase().replace(/[^a-z0-9]/g, '_').replace(/_+/g, '_').replace(/^_|_$/g, '');
    window.validateSignupDomain();
  }
};

window.validateSignupEmail = () => {
  const v    = $('inp-signup-email')?.value.trim() || '';
  const hint = $('hint-signup-email');
  if (!v) { _fieldReset('inp-signup-email'); if (hint) hint.textContent = ''; return; }
  if (!v.includes('@') || !v.includes('.')) { _fieldErr('inp-signup-email'); if (hint) hint.textContent = 'Enter a valid email'; return; }
  if (_isEmailTaken(v)) { _fieldErr('inp-signup-email'); if (hint) hint.textContent = 'Already registered on this device'; return; }
  _fieldOk('inp-signup-email'); if (hint) hint.textContent = '✓ Available';
};

window.validateSignupDomain = () => {
  const v    = $('inp-signup-domain')?.value.trim() || '';
  const hint = $('hint-signup-domain');
  const el   = $('inp-signup-domain');
  if (!v) { _fieldReset('inp-signup-domain'); if (hint) hint.textContent = ''; return; }
  if (!/^[a-z0-9_]{2,30}$/.test(v)) { _fieldErr('inp-signup-domain'); if (hint) hint.textContent = '2-30 chars: a-z, 0-9, underscore only'; return; }
  if (_isDomainTaken(v))             { _fieldErr('inp-signup-domain'); if (hint) hint.textContent = 'Already taken on this device'; return; }
  _fieldOk('inp-signup-domain'); if (hint) hint.textContent = `✓ @${v}`;
  if (el) el.dataset.manuallyEdited = '1';
};

window.validateLoginEmail = () => {
  const v = $('inp-login-email')?.value.trim() || '';
  if (!v) return _fieldReset('inp-login-email');
  v.includes('@') ? _fieldOk('inp-login-email') : _fieldErr('inp-login-email');
};

/* ═══════════════════════════════════════════════════════
   New-device sync method toggle (code vs file)
═══════════════════════════════════════════════════════ */
window.switchSyncMethod = function(method) {
  const isCode = method === 'code';
  document.getElementById('sync-method-code')?.classList.toggle('sync-method-card--active', isCode);
  document.getElementById('sync-method-file')?.classList.toggle('sync-method-card--active', !isCode);
  const codeSection = document.getElementById('sync-code-section');
  const fileSection = document.getElementById('sync-file-section');
  const codeSteps   = document.getElementById('sync-method-code-steps');
  const fileSteps   = document.getElementById('sync-method-file-steps');
  if (codeSection) codeSection.style.display = isCode ? '' : 'none';
  if (fileSection) fileSection.style.display = isCode ? 'none' : '';
  if (codeSteps)   codeSteps.style.display   = isCode ? '' : 'none';
  if (fileSteps)   fileSteps.style.display   = isCode ? 'none' : '';
};

/* ═══════════════════════════════════════════════════════
   Password visibility toggle + strength meter
═══════════════════════════════════════════════════════ */
window.togglePwVisibility = function(inputId, btn) {
  const inp = $(inputId); if (!inp) return;
  const show = inp.type === 'password';
  inp.type = show ? 'text' : 'password';
  btn.textContent = show ? '🙈' : '👁';
};

window.updatePwStrength = function(pw) {
  const fill  = $('pw-strength-fill');
  const label = $('pw-strength-label');
  if (!fill || !label) return;
  let score = 0;
  if (pw.length >= 8)          score++;
  if (/[A-Z]/.test(pw))        score++;
  if (/[a-z]/.test(pw))        score++;
  if (/[0-9]/.test(pw))        score++;
  if (/[^A-Za-z0-9]/.test(pw)) score++;
  const levels = [
    { w: '0%',   bg: 'transparent', txt: ''          },
    { w: '20%',  bg: '#ff5555',     txt: 'Very weak' },
    { w: '40%',  bg: '#ff8c42',     txt: 'Weak'      },
    { w: '60%',  bg: '#ffb86c',     txt: 'Fair'      },
    { w: '80%',  bg: '#00d4ff',     txt: 'Good'      },
    { w: '100%', bg: '#50fa7b',     txt: 'Strong ✓'  },
  ];
  const lvl = levels[score] || levels[0];
  fill.style.width      = lvl.w;
  fill.style.background = lvl.bg;
  label.textContent     = lvl.txt;
  label.style.color     = lvl.bg;
};

/* ═══════════════════════════════════════════════════════
   Private helpers
═══════════════════════════════════════════════════════ */
function _pwStrong(pw)    { return /[A-Z]/.test(pw) && /[a-z]/.test(pw) && /[0-9]/.test(pw); }
function _applySession(s) {
  const a = $('user-avatar'), n = $('user-name');
  if (a) a.textContent = s.name.charAt(0).toUpperCase();
  if (n) n.textContent = s.name;
}
function _showError(msg)  { const el = $('auth-error'); if (el) { el.textContent = msg; el.style.display = ''; } }
function _clearError()    { const el = $('auth-error'); if (el) el.textContent = ''; }
function _setLoading(btn, loading, label) { if (!btn) return; btn.disabled = loading; btn.textContent = label; }
function $$auth(sel)      { return Array.from(document.querySelectorAll(sel)); }

/* ═══════════════════════════════════════════════════════
   Global event listeners
═══════════════════════════════════════════════════════ */
['click', 'keydown', 'mousemove', 'touchstart'].forEach(ev =>
  document.addEventListener(ev, () => CryptoVault.resetTimer(), { passive: true })
);

window.addEventListener('naluxrp:vault-locked', () => {
  state.vaultLocked = true;
  _showLockBanner();
});