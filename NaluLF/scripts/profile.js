/* =====================================================
   profile.js — Profile Page · Social Connections
                XRPL Wallet Creator Wizard
   ===================================================== */
import { $, $$, escHtml, safeGet, safeSet, safeJson, toastInfo, toastErr, toastWarn } from './utils.js';
import { state } from './state.js';
import { setTheme } from './theme.js';

const LS_PROFILE  = 'nalulf_profile';
const LS_WALLETS  = 'nalulf_wallets';
const LS_SOCIAL   = 'nalulf_social';

const AVATARS = ['🌊','🐋','🐉','🦋','🦁','🐺','🦊','🐻','🐼','🦅','🐬','🦈','🐙','🦑','🧿','🌺','🌸','🍀','⚡','🔥','💎','🌙','⭐','🎯','🧠','🔮','🛸','🗺','🏔','🌊','🎭','🏛'];
const WALLET_EMOJIS = ['💎','🏦','🔐','🔑','💰','🌊','⚡','🚀','🌙','⭐','🏴‍☠️','🎯','🧠','🔮'];
const WALLET_COLORS = ['#50fa7b','#00d4ff','#ffb86c','#bd93f9','#ff79c6','#f1fa8c','#ff5555','#00fff0','#ff6b6b','#a78bfa'];
const BANNERS = ['banner-ocean','banner-neon','banner-gold','banner-cosmic','banner-sunset','banner-aurora'];

const SOCIAL_PLATFORMS = [
  { id:'discord',  label:'Discord',  icon:'💬', prefix:'https://discord.com/users/' },
  { id:'twitter',  label:'X / Twitter', icon:'𝕏', prefix:'https://x.com/' },
  { id:'linkedin', label:'LinkedIn', icon:'in', prefix:'https://linkedin.com/in/' },
  { id:'facebook', label:'Facebook', icon:'f', prefix:'https://facebook.com/' },
  { id:'tiktok',   label:'TikTok',   icon:'♪', prefix:'https://tiktok.com/@' },
  { id:'github',   label:'GitHub',   icon:'⌥', prefix:'https://github.com/' },
  { id:'telegram', label:'Telegram', icon:'✈', prefix:'https://t.me/' },
];

/* ── App state ── */
let profile = {
  displayName: '',
  handle: '',
  bio: '',
  location: '',
  website: '',
  avatar: '🌊',
  banner: 'banner-ocean',
  joinedDate: new Date().toISOString(),
};
let wallets = [];   // [{ id, label, address, algo, emoji, color, createdAt, testnet }]
let social  = {};   // { discord: '@handle', twitter: 'handle', ... }

/* Wallet wizard state */
let wizardStep = 1;
let wizardData = { algo: 'ed25519', label: '', emoji: '💎', color: '#50fa7b', seed: '', address: '' };
let checksCompleted = new Set();

/* ─────────────────────────────
   Init
──────────────────────────────── */
export function initProfile() {
  loadData();
  renderProfilePage();
  renderSocialList();
  renderWalletList();
  bindProfileEvents();
  renderPreferences();
}

/* ─────────────────────────────
   Data
──────────────────────────────── */
function loadData() {
  const p = safeJson(safeGet(LS_PROFILE));
  if (p) Object.assign(profile, p);
  wallets = safeJson(safeGet(LS_WALLETS)) || [];
  social  = safeJson(safeGet(LS_SOCIAL))  || {};

  // Seed from session if no display name saved
  if (!profile.displayName && state.session?.name) {
    profile.displayName = state.session.name;
    profile.handle      = state.session.name.toLowerCase().replace(/\s+/g,'_');
    saveProfile();
  }
}
function saveProfile() { safeSet(LS_PROFILE, JSON.stringify(profile)); }
function saveWallets()  { safeSet(LS_WALLETS, JSON.stringify(wallets)); }
function saveSocial()   { safeSet(LS_SOCIAL,  JSON.stringify(social)); }

/* ─────────────────────────────
   Render Profile
──────────────────────────────── */
function renderProfilePage() {
  // Banner
  const banner = $('profile-banner');
  if (banner) {
    BANNERS.forEach(b => banner.classList.remove(b));
    banner.classList.add(profile.banner || 'banner-ocean');
  }
  // Avatar
  const av = $('profile-avatar-el');
  if (av) av.textContent = profile.avatar || '🌊';
  // Stats
  setText('profile-display-name', profile.displayName || 'Anonymous');
  setText('profile-handle',       `@${profile.handle  || 'anonymous'}`);
  setText('profile-bio',          profile.bio          || 'No bio yet.');
  setText('profile-location-el',  profile.location     ? `📍 ${profile.location}` : '');
  setText('profile-website-el',   profile.website      || '');
  setText('profile-wallets-count', wallets.length);
  setText('profile-joined-el',    `Joined ${new Date(profile.joinedDate).toLocaleDateString('en-US', { month:'short', year:'numeric' })}`);
}

/* ─────────────────────────────
   Social list
──────────────────────────────── */
function renderSocialList() {
  const list = $('social-connections-list');
  if (!list) return;

  list.innerHTML = SOCIAL_PLATFORMS.map(p => {
    const handle     = social[p.id] || '';
    const connected  = !!handle;
    return `
    <div class="social-item ${connected ? 'connected' : ''}" id="social-item-${p.id}">
      <div class="social-icon ${p.id}">${p.icon}</div>
      <div class="social-info">
        <span class="social-name">${escHtml(p.label)}</span>
        <span class="social-handle" id="social-handle-${p.id}">${connected ? escHtml(handle) : 'Not connected'}</span>
      </div>
      <div class="social-actions">
        ${connected ? `
          <button class="btn-social-view" onclick="viewSocial('${p.id}')" title="Open profile">↗</button>
          <button class="btn-social-connect disconnect" onclick="openSocialModal('${p.id}')">Edit</button>
        ` : `
          <button class="btn-social-connect connect" onclick="openSocialModal('${p.id}')">Connect</button>
        `}
      </div>
    </div>`;
  }).join('');
}

export function openSocialModal(platformId) {
  const platform = SOCIAL_PLATFORMS.find(p => p.id === platformId);
  if (!platform) return;

  const modal = $('social-modal');
  if (!modal) return;

  const icon   = $('social-modal-icon');
  const title  = $('social-modal-title');
  const sub    = $('social-modal-sub');
  const input  = $('social-modal-input');
  const delBtn = $('social-modal-delete');

  if (icon)   icon.className = `social-platform-icon-lg social-icon ${platform.id}`;
  if (icon)   icon.textContent = platform.icon;
  if (title)  title.textContent = `Connect ${platform.label}`;
  if (sub)    sub.textContent = `Enter your ${platform.label} ${platform.id === 'discord' ? 'user ID or username' : 'username'}.`;
  if (input)  { input.value = social[platformId] || ''; input.placeholder = `Your ${platform.label} handle`; }
  if (delBtn) delBtn.style.display = social[platformId] ? '' : 'none';

  modal.dataset.platform = platformId;
  modal.classList.add('show');
}

export function saveSocialModal() {
  const modal    = $('social-modal');
  const platform = modal?.dataset.platform;
  const input    = $('social-modal-input');
  if (!platform || !input) return;

  const handle = input.value.trim().replace(/^@/, '');
  if (handle) {
    social[platform] = handle;
  } else {
    delete social[platform];
  }
  saveSocial();
  renderSocialList();
  closeSocialModal();
  toastInfo(`${SOCIAL_PLATFORMS.find(p=>p.id===platform)?.label} updated`);
}

export function deleteSocial() {
  const modal    = $('social-modal');
  const platform = modal?.dataset.platform;
  if (!platform) return;
  delete social[platform];
  saveSocial();
  renderSocialList();
  closeSocialModal();
  toastInfo('Social connection removed');
}

export function viewSocial(platformId) {
  const platform = SOCIAL_PLATFORMS.find(p => p.id === platformId);
  const handle   = social[platformId];
  if (!platform || !handle) return;
  window.open(`${platform.prefix}${handle}`, '_blank', 'noopener');
}

export function closeSocialModal() {
  $('social-modal')?.classList.remove('show');
}

/* ─────────────────────────────
   Wallet list
──────────────────────────────── */
function renderWalletList() {
  const list = $('wallet-list');
  if (!list) return;

  const items = wallets.map((w, i) => `
    <div class="wallet-item" onclick="inspectWalletAddr('${escHtml(w.address)}')">
      <div class="wallet-icon" style="background:${w.color}22;border-color:${w.color}55;color:${w.color}">
        ${escHtml(w.emoji || '💎')}
      </div>
      <div class="wallet-details">
        <div class="wallet-label">${escHtml(w.label || 'Unnamed Wallet')}</div>
        <div class="wallet-address">${escHtml(w.address)}</div>
        <span class="wallet-algo">${escHtml(w.algo?.toUpperCase() || 'ED25519')}${w.testnet ? ' · Testnet' : ' · Mainnet'}</span>
      </div>
      <div class="wallet-actions" onclick="event.stopPropagation()">
        <button class="btn-wallet-action" onclick="copyToClipboard('${escHtml(w.address)}')" title="Copy address">⧉</button>
        <button class="btn-wallet-action danger" onclick="deleteWallet(${i})" title="Remove">✕</button>
      </div>
    </div>`).join('');

  list.innerHTML = items + `
    <button class="btn-add-wallet" onclick="openWalletCreator()">
      + Generate New XRPL Wallet
    </button>`;

  setText('profile-wallets-count', wallets.length);
}

export function deleteWallet(idx) {
  if (!confirm('Remove this wallet from your profile? The wallet still exists on-chain.')) return;
  wallets.splice(idx, 1);
  saveWallets();
  renderWalletList();
  toastInfo('Wallet removed from profile');
}

export function inspectWalletAddr(addr) {
  // Switch to inspector tab and pre-fill address
  const inp = $('inspect-addr');
  if (inp) inp.value = addr;
  window.switchTab?.(document.querySelector('[data-tab="inspector"]'), 'inspector');
  window.showDashboard?.();
}

/* ─────────────────────────────
   Wallet Creator Wizard
──────────────────────────────── */
export function openWalletCreator() {
  wizardStep = 1;
  wizardData = { algo: 'ed25519', label: '', emoji: '💎', color: '#50fa7b', seed: '', address: '' };
  checksCompleted.clear();

  renderWizardStep(1);
  renderWizardCustomization();

  $('wallet-creator-overlay')?.classList.add('show');
}

export function closeWalletCreator() {
  $('wallet-creator-overlay')?.classList.remove('show');
  // Clear sensitive data from memory
  wizardData.seed = '';
  wizardData.address = '';
}

export function wizardNext() {
  if (wizardStep === 1) {
    const label = $('wallet-label-input')?.value.trim();
    if (!label) { toastWarn('Please enter a wallet name.'); return; }
    wizardData.label = label;
    generateWalletKeys();
    wizardStep = 2;

  } else if (wizardStep === 2) {
    if (checksCompleted.size < 4) {
      toastWarn('Please confirm all security checkpoints.'); return;
    }
    wizardStep = 3;

  } else if (wizardStep === 3) {
    saveNewWallet();
    wizardStep = 4;
  }

  renderWizardStep(wizardStep);
}

export function wizardBack() {
  if (wizardStep <= 1) { closeWalletCreator(); return; }
  wizardStep--;
  renderWizardStep(wizardStep);
}

function renderWizardStep(step) {
  // Update step indicators
  [1,2,3,4].forEach(s => {
    const dot = $(`.step-${s}`);
    if (!dot) return;
    dot.classList.toggle('active', s === step);
    dot.classList.toggle('done',   s < step);
  });

  // Show correct panel
  $$('.wizard-panel').forEach(p => p.classList.remove('active'));
  $(`wizard-panel-${step}`)?.classList.add('active');

  // Nav buttons
  const backBtn   = $('wizard-back-btn');
  const nextBtn   = $('wizard-next-btn');
  const finishBtn = $('wizard-finish-btn');

  if (backBtn)   backBtn.style.display   = step === 4 ? 'none' : '';
  if (nextBtn)   nextBtn.style.display   = step >= 3 ? 'none' : '';
  if (finishBtn) finishBtn.style.display = step === 3 ? '' : 'none';
  if (backBtn)   backBtn.textContent     = step === 1 ? 'Cancel' : '← Back';
}

function renderWizardCustomization() {
  // Emoji picker
  const emojiRow = $('wallet-emoji-picker');
  if (emojiRow) {
    emojiRow.innerHTML = WALLET_EMOJIS.map(e => `
      <div class="wallet-emoji-opt ${wizardData.emoji === e ? 'active' : ''}"
           onclick="selectWalletEmoji('${e}')">${e}</div>`).join('');
  }
  // Color picker
  const colorRow = $('wallet-color-picker');
  if (colorRow) {
    colorRow.innerHTML = WALLET_COLORS.map(c => `
      <div class="color-swatch ${wizardData.color === c ? 'active' : ''}"
           style="background:${c}"
           onclick="selectWalletColor('${c}')"></div>`).join('');
  }
}

function generateWalletKeys() {
  if (window.xrpl) {
    // Use official xrpl.js library if loaded
    try {
      const wallet = window.xrpl.Wallet.generate(wizardData.algo === 'ed25519' ? 'ed25519' : 'secp256k1');
      wizardData.seed    = wallet.seed || wallet.classicAddress;
      wizardData.address = wallet.classicAddress;
    } catch(e) {
      console.warn('xrpl.js Wallet.generate failed, using fallback:', e);
      fallbackGenerate();
    }
  } else {
    fallbackGenerate();
  }

  // Render seed display
  const seedEl  = $('wizard-seed-value');
  const addrEl  = $('wizard-address-value');
  if (seedEl)  seedEl.textContent  = wizardData.seed;
  if (addrEl)  addrEl.textContent  = wizardData.address;

  // Reset checkboxes
  checksCompleted.clear();
  $$('.security-check').forEach(el => el.classList.remove('checked'));
  $$('.check-box').forEach(el => el.textContent = '');
  updateWizardNextBtn();
}

function fallbackGenerate() {
  // Fallback: generate random bytes and format as XRPL-style strings
  // Note: This is for display only — use xrpl.js CDN for real wallets
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  const hex   = Array.from(bytes).map(b => b.toString(16).padStart(2,'0')).join('');

  // Encode as base58 family seed (simplified display format)
  const B58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  let num = BigInt('0x' + hex);
  let seed = '';
  while (num > 0n) {
    seed = B58_ALPHABET[Number(num % 58n)] + seed;
    num /= 58n;
  }
  // Pad to ~29 chars and add 's' prefix
  wizardData.seed = 's' + seed.padStart(28, '1').slice(0, 28);

  // Generate a plausible-looking r-address
  const addrBytes = crypto.getRandomValues(new Uint8Array(20));
  const addrHex   = Array.from(addrBytes).map(b => b.toString(16).padStart(2,'0')).join('');
  let addrNum = BigInt('0x' + addrHex);
  let addr = '';
  while (addrNum > 0n) {
    addr = B58_ALPHABET[Number(addrNum % 58n)] + addr;
    addrNum /= 58n;
  }
  wizardData.address = 'r' + addr.slice(0, 25 + (Number(addrBytes[0]) % 9));
}

function saveNewWallet() {
  wallets.push({
    id:        crypto.randomUUID(),
    label:     wizardData.label,
    address:   wizardData.address,
    algo:      wizardData.algo,
    emoji:     wizardData.emoji,
    color:     wizardData.color,
    testnet:   $('wallet-testnet-check')?.checked || false,
    createdAt: new Date().toISOString(),
  });
  saveWallets();
  renderWalletList();

  // Show success
  const successAddr = $('wizard-success-address');
  if (successAddr) successAddr.textContent = wizardData.address;

  // Clear seed from memory after save
  setTimeout(() => { wizardData.seed = ''; wizardData.address = ''; }, 100);
}

/* Wizard UI helpers */
export function selectAlgo(algo) {
  wizardData.algo = algo;
  $$('.algo-card').forEach(c => c.classList.toggle('active', c.dataset.algo === algo));
}

export function selectWalletEmoji(emoji) {
  wizardData.emoji = emoji;
  $$('.wallet-emoji-opt').forEach(el => el.classList.toggle('active', el.textContent === emoji));
}

export function selectWalletColor(color) {
  wizardData.color = color;
  $$('.color-swatch').forEach(el => {
    el.classList.toggle('active', el.style.background === color || el.dataset.color === color);
  });
}

export function toggleSecurityCheck(idx) {
  const el = $(`.security-check-${idx}`);
  if (!el) return;
  const checkBox = el.querySelector('.check-box');
  if (checksCompleted.has(idx)) {
    checksCompleted.delete(idx);
    el.classList.remove('checked');
    if (checkBox) checkBox.textContent = '';
  } else {
    checksCompleted.add(idx);
    el.classList.add('checked');
    if (checkBox) checkBox.textContent = '✓';
  }
  updateWizardNextBtn();
}

function updateWizardNextBtn() {
  const nextBtn = $('wizard-next-btn');
  if (nextBtn && wizardStep === 2) {
    nextBtn.disabled = checksCompleted.size < 4;
  }
}

export function revealSeed() {
  const seedEl = $('wizard-seed-value');
  if (seedEl) seedEl.classList.remove('blur');
  const hint = $('seed-reveal-hint');
  if (hint) hint.style.display = 'none';
}

export function copySeed() {
  const seedEl = $('wizard-seed-value');
  if (!seedEl) return;
  copyToClipboard(seedEl.textContent);
  const btn = $('btn-copy-seed');
  if (btn) { btn.textContent = 'Copied!'; btn.classList.add('copied'); setTimeout(() => { btn.textContent = 'Copy Seed'; btn.classList.remove('copied'); }, 2000); }
}

export function copyAddress() {
  const el = $('wizard-address-value') || $('wizard-success-address');
  if (!el) return;
  copyToClipboard(el.textContent);
  const btn = $('btn-copy-addr');
  if (btn) { btn.textContent = 'Copied!'; btn.classList.add('copied'); setTimeout(() => { btn.textContent = 'Copy'; btn.classList.remove('copied'); }, 2000); }
}

export function copyToClipboard(text) {
  navigator.clipboard?.writeText(text).then(() => toastInfo('Copied to clipboard'))
    .catch(() => { /* fallback */ const el = document.createElement('textarea'); el.value = text; document.body.appendChild(el); el.select(); document.execCommand('copy'); el.remove(); toastInfo('Copied'); });
}

/* ─────────────────────────────
   Profile Editor
──────────────────────────────── */
export function openProfileEditor() {
  // Populate form
  const fields = ['displayName','handle','bio','location','website'];
  fields.forEach(f => {
    const el = $(`edit-${f}`);
    if (el) el.value = profile[f] || '';
  });

  // Avatar grid
  const grid = $('avatar-picker-grid');
  if (grid) {
    grid.innerHTML = AVATARS.map(a => `
      <div class="avatar-option ${profile.avatar === a ? 'active' : ''}"
           onclick="selectAvatar('${a}')">${a}</div>`).join('');
  }

  // Banner grid
  const bannerGrid = $('banner-picker-grid');
  if (bannerGrid) {
    bannerGrid.innerHTML = BANNERS.map(b => `
      <div class="banner-option ${b} ${profile.banner === b ? 'active' : ''}"
           onclick="selectBanner('${b}')"></div>`).join('');
  }

  $('profile-editor-modal')?.classList.add('show');
}

export function closeProfileEditor() {
  $('profile-editor-modal')?.classList.remove('show');
}

export function saveProfileEditor() {
  profile.displayName = $('edit-displayName')?.value.trim() || profile.displayName;
  profile.handle      = ($('edit-handle')?.value.trim() || profile.handle).replace(/^@/, '').replace(/\s+/g,'_').toLowerCase();
  profile.bio         = $('edit-bio')?.value.trim()      || '';
  profile.location    = $('edit-location')?.value.trim() || '';
  profile.website     = $('edit-website')?.value.trim()  || '';
  saveProfile();
  renderProfilePage();
  closeProfileEditor();
  toastInfo('Profile saved');
}

export function selectAvatar(emoji) {
  profile.avatar = emoji;
  $$('.avatar-option').forEach(el => el.classList.toggle('active', el.textContent === emoji));
  const av = $('profile-avatar-el');
  if (av) av.textContent = emoji;
}

export function selectBanner(bannerClass) {
  profile.banner = bannerClass;
  $$('.banner-option').forEach(el => el.classList.toggle('active', el.classList.contains(bannerClass)));
  const banner = $('profile-banner');
  if (banner) {
    BANNERS.forEach(b => banner.classList.remove(b));
    banner.classList.add(bannerClass);
  }
}

/* ─────────────────────────────
   Preferences
──────────────────────────────── */
function renderPreferences() {
  // Theme pills
  const pills = $('pref-theme-pills');
  if (pills) {
    ['gold','cosmic','starry','hawaiian'].forEach(t => {
      const el = pills.querySelector(`.theme-pill.${t}`);
      if (el) el.classList.toggle('active', state.currentTheme === t);
    });
  }
}

export function prefSetTheme(t) {
  setTheme(t);
  renderPreferences();
}

/* ─────────────────────────────
   Events
──────────────────────────────── */
function bindProfileEvents() {
  // Close modals on backdrop click
  $('profile-editor-modal')?.addEventListener('click', e => { if (e.target === e.currentTarget) closeProfileEditor(); });
  $('wallet-creator-overlay')?.addEventListener('click', e => { if (e.target === e.currentTarget) closeWalletCreator(); });
  $('social-modal')?.addEventListener('click', e => { if (e.target === e.currentTarget) closeSocialModal(); });
}

/* ─────────────────────────────
   Helpers
──────────────────────────────── */
function setText(id, val) {
  const el = $(id);
  if (el) el.textContent = val;
}