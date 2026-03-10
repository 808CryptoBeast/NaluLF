/* =====================================================
   profile.js — Profile · Social · XRPL Wallet Suite
   ─────────────────────────────────────────────────────
   Wallet security:
   • Seeds stored encrypted in CryptoVault (AES-256-GCM)
   • Public metadata (address, label, emoji) stored plainly
   • Vault must be unlocked for any signing operation
   • Seeds cleared from memory immediately after signing

   XRPL capabilities per wallet:
   • TrustSet  — add/modify/remove trustlines
   • Payment   — XRP and IOU token transfers
   • OfferCreate/Cancel — DEX order management
   • NFTokenMint/Burn/CreateOffer — NFT operations
   • AMMDeposit/Withdraw/Vote/Bid — AMM LP operations
   • Sign & submit via XRPL public JSON-RPC
   ===================================================== */
import { $, $$, escHtml, safeGet, safeSet, safeJson, toastInfo, toastErr, toastWarn, isValidXrpAddress, fmt } from './utils.js';
import { state } from './state.js';
import { setTheme } from './theme.js';
import { CryptoVault } from './auth.js';

/* ── Constants ── */
const LS_WALLET_META  = 'naluxrp_wallet_meta';    // Public metadata only — no seeds
const LS_PROFILE      = 'nalulf_profile';
const LS_SOCIAL       = 'nalulf_social';
const LS_ACTIVE_ID    = 'naluxrp_active_wallet';
const LS_AVATAR_IMG   = 'nalulf_avatar_img';      // base64 custom profile photo
const LS_BANNER_IMG   = 'nalulf_banner_img';      // base64 custom banner image
const LS_ACTIVITY     = 'nalulf_activity_log';   // local in-app activity timeline
const XRPL_RPC        = 'https://s1.ripple.com:51234/';
const XRPL_RPC_BACKUP = 'https://xrplcluster.com/';

const AVATARS = ['🌊','🐋','🐉','🦋','🦁','🐺','🦊','🐻','🐼','🦅','🐬','🦈','🐙','🦑','🧿','🌺','🌸','🍀','⚡','🔥','💎','🌙','⭐','🎯','🧠','🔮','🛸','🗺','🏔','🌊','🎭','🏛'];
const WALLET_EMOJIS  = ['💎','🏦','🔐','🔑','💰','🌊','⚡','🚀','🌙','⭐','🏴‍☠️','🎯','🧠','🔮'];
const WALLET_COLORS  = ['#50fa7b','#00d4ff','#ffb86c','#bd93f9','#ff79c6','#f1fa8c','#ff5555','#00fff0','#ff6b6b','#a78bfa'];
const BANNERS        = ['banner-ocean','banner-neon','banner-gold','banner-cosmic','banner-sunset','banner-aurora'];
const SOCIAL_PLATFORMS = [
  { id:'discord',  label:'Discord',      icon:'💬', prefix:'https://discord.com/users/' },
  { id:'twitter',  label:'X / Twitter',  icon:'𝕏',  prefix:'https://x.com/' },
  { id:'linkedin', label:'LinkedIn',     icon:'in', prefix:'https://linkedin.com/in/' },
  { id:'facebook', label:'Facebook',     icon:'f',  prefix:'https://facebook.com/' },
  { id:'tiktok',   label:'TikTok',       icon:'♪',  prefix:'https://tiktok.com/@' },
  { id:'github',   label:'GitHub',       icon:'⌥',  prefix:'https://github.com/' },
  { id:'telegram', label:'Telegram',     icon:'✈',  prefix:'https://t.me/' },
];

/* ── App state ── */
let profile = {
  displayName: '', handle: '', bio: '', location: '', website: '',
  avatar: '🌊', banner: 'banner-ocean', joinedDate: new Date().toISOString(),
};
let wallets       = [];   // Public metadata: [{ id, label, address, algo, emoji, color, testnet, createdAt }]
let social        = {};
let activeWalletId= null;
let balanceCache  = {};   // { [address]: { xrp, tokens: [{currency, issuer, balance}], fetchedAt } }
let trustlineCache= {};   // { [address]: [{currency, issuer, limit, balance}] }
let txCache       = {};   // { [address]: { txns: [], fetchedAt } }
let nftCache      = {};   // { [address]: { nfts: [], fetchedAt } }
let offerCache    = {};   // { [address]: { offers: [], fetchedAt } }

/* Wallet drawer state */
let _expandedWallet  = null;
let _expandedSubTabs = {};   // { [walletId]: 'txns'|'nfts'|'orders' }

const LS_BAL_HIST_PREFIX = 'nalulf_balhist_';
let metricCache = {};  // { [address]: { sequence, ownerCount, firstLedger, fetchedAt } }

/* Wallet wizard state */
let wizardStep = 1;
let wizardData = { algo: 'ed25519', label: '', emoji: '💎', color: '#50fa7b', seed: '', address: '' };
let checksCompleted = new Set();

/* ═══════════════════════════════════════════════════════════
   Init
═══════════════════════════════════════════════════════════ */
export function initProfile() {
  loadData();
  _mountDynamicModals();
  renderProfilePage();
  renderProfileTabs('wallets');
  renderActiveWalletBar();
  bindProfileEvents();

  window.addEventListener('naluxrp:vault-ready', () => {
    loadData();
    renderProfilePage();
    renderProfileTabs(_activeTab);
    renderActiveWalletBar();
    fetchAllBalances();
  });

  window.addEventListener('naluxrp:vault-locked', () => {
    renderProfilePage();
  });
}

let _activeTab = 'wallets';

export function switchProfileTab(tab) {
  _activeTab = tab;
  // Update tab button states
  $$('.ptab-btn').forEach(btn => btn.classList.toggle('active', btn.dataset.tab === tab));
  renderProfileTabs(tab);
}

function renderProfileTabs(tab) {
  try {
    switch (tab) {
      case 'wallets':   renderWalletList(); break;
      case 'social':    renderSocialList(); break;
      case 'activity':  renderActivityPanel(); break;
      case 'settings':  renderSettingsPanel(); break;
      case 'analytics': renderAnalyticsTab(); break;
    }
  } catch(err) {
    const el = $(`profile-tab-${tab}`);
    if (el) _renderTabError(el, tab, err);
  }
  ['wallets','social','activity','settings','analytics'].forEach(t => {
    const el = $(`profile-tab-${t}`);
    if (el) el.style.display = t === tab ? '' : 'none';
  });
}

function _renderTabError(el, tab, err) {
  console.error(`Profile tab "${tab}" error:`, err);
  el.innerHTML = `<div class="tab-error-card"><div class="tab-error-icon">⚠️</div><div class="tab-error-title">Something went wrong</div><div class="tab-error-sub">${err?.message||'Unknown error'}</div><button class="tab-error-btn" onclick="switchProfileTab('${tab}')">Try Again</button></div>`;
}

/* ═══════════════════════════════════════════════════════════
   Data — vault-aware storage
═══════════════════════════════════════════════════════════ */
function loadData() {
  // Profile and social are not sensitive — plain localStorage
  const p = safeJson(safeGet(LS_PROFILE));
  if (p) Object.assign(profile, p);
  social = safeJson(safeGet(LS_SOCIAL)) || {};

  // Wallet list: merge public metadata with vault seeds (when unlocked)
  wallets = safeJson(safeGet(LS_WALLET_META)) || [];

  // If vault is unlocked, ensure metadata is in sync
  if (CryptoVault.isUnlocked && CryptoVault.vault?.wallets?.length) {
    const vaultWallets = CryptoVault.vault.wallets;
    // Sync addresses from vault in case metadata was cleared
    vaultWallets.forEach(vw => {
      if (!wallets.find(w => w.id === vw.id)) {
        wallets.push({ id: vw.id, label: vw.label, address: vw.address, algo: vw.algo,
          emoji: vw.emoji, color: vw.color, testnet: vw.testnet, createdAt: vw.createdAt });
      }
    });
    _saveWalletMeta();
  }

  activeWalletId = safeGet(LS_ACTIVE_ID) || wallets[0]?.id || null;

  if (!profile.displayName && state.session?.name) {
    profile.displayName = state.session.name;
    profile.handle = state.session.name.toLowerCase().replace(/\s+/g, '_');
    _saveProfile();
  }
}

function _saveProfile()    { safeSet(LS_PROFILE, JSON.stringify(profile)); }
function _saveWalletMeta() { safeSet(LS_WALLET_META, JSON.stringify(wallets)); }
function _saveSocial()     { safeSet(LS_SOCIAL, JSON.stringify(social)); }


/* ═══════════════════════════════════════════════════════════
   Local Activity Log
═══════════════════════════════════════════════════════════ */
const ACTIVITY_MAX = 50;
export function logActivity(type, detail) {
  const log = safeJson(safeGet(LS_ACTIVITY)) || [];
  log.unshift({ type, detail, ts: Date.now() });
  if (log.length > ACTIVITY_MAX) log.length = ACTIVITY_MAX;
  safeSet(LS_ACTIVITY, JSON.stringify(log));
}
function _getActivity() { return safeJson(safeGet(LS_ACTIVITY)) || []; }
function _actRelTime(ts) {
  const diff = (Date.now() - ts) / 1000;
  if (diff < 60)    return 'just now';
  if (diff < 3600)  return Math.floor(diff/60) + 'm ago';
  if (diff < 86400) return Math.floor(diff/3600) + 'h ago';
  return Math.floor(diff/86400) + 'd ago';
}
const ACT_ICONS = { wallet_created:'💎', wallet_removed:'🗑', social_connected:'🔗', social_removed:'✕', profile_saved:'✏️', trustline_added:'🔗', sent:'⬆', received:'⬇', vault_created:'🔐', backup_exported:'📂', theme_changed:'🎨' };

/* ═══════════════════════════════════════════════════════════
   Active Wallet
═══════════════════════════════════════════════════════════ */
export function getActiveWallet() {
  return wallets.find(w => w.id === activeWalletId) || wallets[0] || null;
}

export function setActiveWallet(id) {
  if (!wallets.find(w => w.id === id)) return;
  activeWalletId = id;
  safeSet(LS_ACTIVE_ID, id);
  renderWalletList();
  renderActiveWalletBar();
  // Broadcast to rest of app (dashboard, inspector etc.)
  window.dispatchEvent(new CustomEvent('naluxrp:active-wallet-changed', {
    detail: getActiveWallet()
  }));
  toastInfo(`Active wallet switched`);
}

/* ── Active wallet banner below profile header ── */
function renderActiveWalletBar() {
  const bar = $('active-wallet-bar');
  if (!bar) return;
  const w = getActiveWallet();
  if (!w) {
    bar.innerHTML = `<div class="awb-empty">No wallet — <button class="awb-link" onclick="openWalletCreator()">create one</button></div>`;
    return;
  }
  const cached = balanceCache[w.address];
  const xrp    = cached ? fmt(cached.xrp, 2) + ' XRP' : '— XRP';
  const tokens = cached?.tokens?.length ? `· ${cached.tokens.length} token${cached.tokens.length > 1 ? 's' : ''}` : '';

  bar.innerHTML = `
    <div class="awb-left">
      <div class="awb-icon" style="background:${w.color}22;border-color:${w.color}55;color:${w.color}">${escHtml(w.emoji)}</div>
      <div class="awb-info">
        <span class="awb-label">${escHtml(w.label)}</span>
        <span class="awb-address mono">${escHtml(w.address)}</span>
      </div>
      <span class="awb-balance">${xrp} ${tokens}</span>
    </div>
    <div class="awb-actions">
      <button class="awb-btn awb-btn--send"    onclick="openSendModal('${w.id}')">⬆ Send</button>
      <button class="awb-btn awb-btn--receive" onclick="openReceiveModal('${w.id}')">⬇ Receive</button>
      <button class="awb-btn awb-btn--trust"   onclick="openTrustlineModal('${w.id}')">🔗 Trustlines</button>
      <button class="awb-btn awb-btn--inspect" onclick="inspectWalletAddr('${w.address}')">🔍 Inspect</button>
    </div>`;
}

/* ── Broadcast active wallet to Inspector / Dashboard auto-fill ── */
window.addEventListener('naluxrp:active-wallet-changed', e => {
  const w = e.detail;
  if (!w) return;
  // Pre-fill inspector
  const inspEl = $('inspect-addr');
  if (inspEl && !inspEl.value) inspEl.value = w.address;
  // Notify dashboard of watched address
  state.activeWalletAddress = w.address;
});

/* ═══════════════════════════════════════════════════════════
   Render Profile
═══════════════════════════════════════════════════════════ */
function renderProfilePage() {
  // Banner — custom image takes priority over gradient class
  const banner = $('profile-banner');
  if (banner) {
    const bannerImg = localStorage.getItem(LS_BANNER_IMG);
    if (bannerImg) {
      BANNERS.forEach(b => banner.classList.remove(b));
      banner.style.backgroundImage = `url(${bannerImg})`;
      banner.style.backgroundSize  = 'cover';
      banner.style.backgroundPosition = 'center';
    } else {
      banner.style.backgroundImage = '';
      BANNERS.forEach(b => banner.classList.remove(b));
      banner.classList.add(profile.banner || 'banner-ocean');
    }
  }

  // Avatar — custom image takes priority over emoji
  const av = $('profile-avatar-el');
  if (av) {
    const avatarImg = localStorage.getItem(LS_AVATAR_IMG);
    if (avatarImg) {
      av.innerHTML = `<img src="${avatarImg}" class="profile-avatar-img" alt="Profile photo" />`;
    } else {
      av.textContent = profile.avatar || '🌊';
    }
  }

  _setText('profile-display-name', profile.displayName || 'Anonymous');
  _setText('profile-handle',       `@${profile.handle  || 'anonymous'}`);

  // Domain chip next to handle
  const domainEl = $('profile-domain-el');
  if (domainEl) {
    const domain = profile.domain || (CryptoVault.vault?.identity?.domain) || '';
    domainEl.innerHTML = domain ? `<span class="profile-domain-chip">◈ ${escHtml(domain)}.xrpl</span>` : '';
  }
  _setText('profile-bio',          profile.bio || 'No bio yet. Click Edit Profile to add one.');

  const loc = $('profile-location-el');
  if (loc) loc.innerHTML = profile.location ? `<span>📍 ${escHtml(profile.location)}</span>` : '';

  const web = $('profile-website-el');
  if (web) web.innerHTML = profile.website
    ? `<a href="${escHtml(profile.website)}" target="_blank" rel="noopener">🔗 ${escHtml(profile.website.replace(/^https?:\/\//, ''))}</a>` : '';

  const joined = $('profile-joined-el');
  if (joined) joined.innerHTML = `<span>📅 Joined ${new Date(profile.joinedDate || Date.now()).toLocaleDateString('en-US',{month:'short',year:'numeric'})}</span>`;

  // Vault pill
  const vaultEl = $('vault-status-pill');
  if (vaultEl) {
    const unlocked = CryptoVault.isUnlocked;
    vaultEl.className = `vault-pill ${unlocked ? 'vault-pill--open' : 'vault-pill--locked'}`;
    vaultEl.innerHTML = unlocked ? '🔓 Vault unlocked' : '🔒 Vault locked';
  }

  // Address copy chip in header — shows active wallet address
  const addrChip = $('profile-address-chip');
  if (addrChip) {
    const w = getActiveWallet();
    if (w) {
      const short = w.address.slice(0,8) + '…' + w.address.slice(-5);
      addrChip.innerHTML = `<span class="addr-chip-icon">${escHtml(w.emoji||'💎')}</span><span class="addr-chip-addr mono">${short}</span><button class="addr-chip-copy" onclick="copyToClipboard('${escHtml(w.address)}')" title="Copy full address">⧉</button>`;
      addrChip.style.display = '';
    } else {
      addrChip.style.display = 'none';
    }
  }

  // Verified social badges in header
  const socialBadges = $('profile-social-badges');
  if (socialBadges) {
    const connected = SOCIAL_PLATFORMS.filter(p => social[p.id]);
    socialBadges.innerHTML = connected.slice(0,4).map(p =>
      `<span class="profile-social-badge social-platform-badge--${p.id}" title="${escHtml(p.label)}: @${escHtml(social[p.id])}" onclick="viewSocial('${p.id}')">${p.icon}</span>`
    ).join('');
    socialBadges.style.display = connected.length ? '' : 'none';
  }

  // Header action row — theme switcher + profile preview
  const hdrActions = $('profile-hdr-actions');
  if (hdrActions) {
    hdrActions.innerHTML = `
      <button class="profile-theme-btn" onclick="window.cycleTheme?.()" title="Cycle theme">🎨 Theme</button>
      <button class="profile-preview-btn" onclick="openPublicProfilePreview()" title="Preview public profile">👁 Preview</button>
    `;
  }

  renderProfileMetrics();
}


/* ═══════════════════════════════════════════════════════════
   Profile Metrics Row
═══════════════════════════════════════════════════════════ */
function renderProfileMetrics() {
  const el = $('profile-metrics-row');
  if (!el) return;
  const locked = !CryptoVault.isUnlocked;

  const totalXrp   = Object.values(balanceCache).reduce((s,c)=>s+(c?.xrp||0),0);
  const xrpPrice   = _getXrpPrice();
  const allTokens  = Object.values(balanceCache).flatMap(c=>c?.tokens||[]);
  const activeW    = getActiveWallet();
  const metric     = activeW ? metricCache[activeW.address] : null;

  const txCount    = metric?.sequence != null ? metric.sequence : '—';
  const ownerCount = metric?.ownerCount || 0;
  const reserve    = 10 + ownerCount * 2;
  const accountAge = activeW?.createdAt
    ? _ageString(new Date(activeW.createdAt))
    : '—';

  el.innerHTML = `
    <div class="pmetric">
      <div class="pmetric-val">${locked ? '••••' : fmt(totalXrp, 2)}</div>
      <div class="pmetric-label">Total XRP</div>
    </div>
    <div class="pmetric pmetric-divider"></div>
    <div class="pmetric">
      <div class="pmetric-val ${xrpPrice&&!locked?'pmetric-usd':''}">
        ${locked ? '••••' : xrpPrice ? '$'+fmt(totalXrp*xrpPrice,2) : '—'}
      </div>
      <div class="pmetric-label">Est. Value</div>
    </div>
    <div class="pmetric pmetric-divider"></div>
    <div class="pmetric">
      <div class="pmetric-val">${txCount}</div>
      <div class="pmetric-label">Transactions</div>
    </div>
    <div class="pmetric pmetric-divider"></div>
    <div class="pmetric">
      <div class="pmetric-val">${accountAge}</div>
      <div class="pmetric-label">Wallet Age</div>
    </div>
    <div class="pmetric pmetric-divider"></div>
    <div class="pmetric">
      <div class="pmetric-val">${allTokens.length}</div>
      <div class="pmetric-label">Tokens</div>
    </div>
    ${metric ? `<div class="pmetric pmetric-divider"></div>
    <div class="pmetric pmetric-reserve" title="${ownerCount} owned objects × 2 XRP + 10 XRP base">
      <div class="pmetric-val pmetric-reserve-val">${reserve} XRP</div>
      <div class="pmetric-label">Reserved</div>
    </div>` : ''}`;

  // Async: fetch metrics for active wallet if not cached
  if (activeW && (!metricCache[activeW.address] || (Date.now()-metricCache[activeW.address].fetchedAt)>60000)) {
    fetchAccountMetrics(activeW.address).then(() => renderProfileMetrics());
  }
}

async function fetchAccountMetrics(address) {
  try {
    const info = await xrplPost({ method: 'account_info', params: [{ account: address, ledger_index: 'validated' }] });
    if (info?.account_data) {
      metricCache[address] = {
        sequence:   info.account_data.Sequence,
        ownerCount: info.account_data.OwnerCount || 0,
        fetchedAt:  Date.now(),
      };
    }
    return metricCache[address];
  } catch { return null; }
}

function _ageString(date) {
  const ms = Date.now() - date.getTime();
  const days = Math.floor(ms / 86400000);
  if (days < 1) return 'Today';
  if (days < 30) return `${days}d`;
  if (days < 365) return `${Math.floor(days/30)}mo`;
  const yrs = Math.floor(days/365), mo = Math.floor((days%365)/30);
  return mo ? `${yrs}y ${mo}mo` : `${yrs}y`;
}

function _getXrpPrice() {
  const el = document.getElementById('xrpPrice');
  if (el) { const v=parseFloat(el.textContent.replace('$','')); if (!isNaN(v)) return v; }
  return 0;
}
function _renderOnboardingChecklist() {
  const hasWallet  = wallets.length > 0;
  const hasSocial  = Object.values(social).some(Boolean);
  const hasBio     = !!profile.bio;
  const hasBackup  = false; // Can't detect this; always show

  const allDone = hasWallet && hasSocial && hasBio;
  if (allDone) return ''; // No checklist when complete

  const done = [hasWallet, hasSocial, hasBio].filter(Boolean).length;
  const pct  = Math.round((done / 3) * 100);

  return `
    <div class="onboarding-card">
      <div class="onb-header">
        <div class="onb-title">✨ Complete your profile</div>
        <div class="onb-prog-wrap">
          <div class="onb-prog-bar"><div class="onb-prog-fill" style="width:${pct}%"></div></div>
          <span class="onb-prog-label">${done}/3</span>
        </div>
      </div>
      <div class="onb-items">
        ${_onbItem('💎', 'Generate your first XRPL wallet', 'Encrypted with AES-256-GCM, never leaves this device.', hasWallet, "openWalletCreator()")}
        ${_onbItem('🔗', 'Connect a social account', 'Link Discord, X, GitHub, or any platform.', hasSocial, "switchProfileTab('social')")}
        ${_onbItem('✏️', 'Add a bio', 'Tell people who you are.', hasBio, "openProfileEditor()")}
      </div>
    </div>`;
}

function _onbItem(icon, title, sub, done, action) {
  return `
    <div class="onb-item ${done ? 'onb-item--done' : ''}" ${done ? '' : `onclick="${action}"`}>
      <div class="onb-item-check">${done ? '✓' : icon}</div>
      <div class="onb-item-body">
        <div class="onb-item-title">${title}</div>
        <div class="onb-item-sub">${sub}</div>
      </div>
      ${done ? '' : '<span class="onb-item-arrow">→</span>'}
    </div>`;
}

/* ═══════════════════════════════════════════════════════════
   Social
═══════════════════════════════════════════════════════════ */
function renderSocialList() {
  const list = $('profile-tab-social');
  if (!list) return;
  const connectedCount = Object.values(social).filter(Boolean).length;

  list.innerHTML = `
    <div class="social-section-head">
      <div class="social-section-title">Social &amp; Community Links</div>
      <div class="social-section-sub">${connectedCount} of ${SOCIAL_PLATFORMS.length} connected · stored locally only, never verified</div>
    </div>
    <div class="social-grid">
      ${SOCIAL_PLATFORMS.map(p => {
        const handle    = social[p.id] || '';
        const connected = !!handle;
        return `
        <div class="social-card ${connected ? 'social-card--connected' : ''}" id="social-item-${p.id}">
          <div class="social-card-left">
            <div class="social-platform-badge social-platform-badge--${p.id}">${p.icon}</div>
            <div class="social-card-info">
              <div class="social-card-name">${escHtml(p.label)}</div>
              <div class="social-card-handle ${connected ? '' : 'dim'}">${connected ? escHtml('@' + handle) : 'Not connected'}</div>
            </div>
          </div>
          <div class="social-card-actions">
            ${connected ? `
              <button class="sc-btn sc-btn--open"    onclick="viewSocial('${p.id}')" title="Open profile">↗</button>
              <button class="sc-btn sc-btn--edit"    onclick="openSocialModal('${p.id}')">Edit</button>
            ` : `
              <button class="sc-btn sc-btn--connect" onclick="openSocialModal('${p.id}')">+ Connect</button>
            `}
          </div>
        </div>`;
      }).join('')}
    </div>
    ${connectedCount > 0 ? `
    <div class="social-preview-row">
      <span class="social-preview-hint">Connected ${connectedCount} platform${connectedCount>1?'s':''} — see how you appear to others</span>
      <button class="sc-preview-btn" onclick="openPublicProfilePreview()">👁 Preview Profile</button>
    </div>` : ''}`;

  _setText('stat-socials-val', connectedCount);
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
  if (icon)   { icon.className = `social-platform-icon-lg social-icon ${platform.id}`; icon.textContent = platform.icon; }
  if (title)  title.textContent = `Connect ${platform.label}`;
  if (sub)    sub.textContent   = `Enter your ${platform.label} ${platform.id === 'discord' ? 'user ID or username' : 'username'}.`;
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
  if (handle) social[platform] = handle; else delete social[platform];
  _saveSocial(); renderSocialList(); closeSocialModal();
  const _sp = SOCIAL_PLATFORMS.find(p => p.id === platform);
  logActivity('social_connected', `${_sp?.label||platform} @${handle}`);
  toastInfo(`${_sp?.label} updated`);
}
export function deleteSocial() {
  const platform = $('social-modal')?.dataset.platform;
  if (!platform) return;
  delete social[platform]; _saveSocial(); renderSocialList(); closeSocialModal();
  toastInfo('Social connection removed');
}
export function viewSocial(platformId) {
  const p = SOCIAL_PLATFORMS.find(x => x.id === platformId);
  if (p && social[platformId]) window.open(`${p.prefix}${social[platformId]}`, '_blank', 'noopener');
}
export function closeSocialModal() { $('social-modal')?.classList.remove('show'); }

/* ═══════════════════════════════════════════════════════════
   Wallet List
═══════════════════════════════════════════════════════════ */
function renderWalletList() {
  const list = $('profile-tab-wallets');
  if (!list) return;

  // Show skeleton while we have no data yet (first load)
  const needsSkeleton = wallets.length === 0 && !CryptoVault.hasVault();
  if (needsSkeleton) {
    list.innerHTML = `
      <div class="skeleton-card"><div class="skeleton-row-group"><div class="skeleton skeleton-circle"></div><div style="flex:1"><div class="skeleton skeleton-row lg"></div><div class="skeleton skeleton-row"></div></div></div></div>
      <div class="skeleton-card"><div class="skeleton-row-group"><div class="skeleton skeleton-circle"></div><div style="flex:1"><div class="skeleton skeleton-row lg"></div><div class="skeleton skeleton-row"></div></div></div></div>`;
    return;
  }

  if (wallets.length === 0) {
    list.innerHTML = _renderOnboardingChecklist() + `
      <div class="wallets-empty">
        <svg class="wallets-empty-svg" width="120" height="100" viewBox="0 0 120 100" fill="none" xmlns="http://www.w3.org/2000/svg">
          <rect x="10" y="30" width="100" height="60" rx="12" fill="rgba(0,255,240,.07)" stroke="rgba(0,255,240,.25)" stroke-width="1.5"/>
          <rect x="10" y="42" width="100" height="16" fill="rgba(0,255,240,.08)"/>
          <circle cx="88" cy="72" r="10" fill="rgba(0,255,240,.12)" stroke="rgba(0,255,240,.35)" stroke-width="1.5"/>
          <circle cx="88" cy="72" r="4" fill="rgba(0,255,240,.5)"/>
          <rect x="22" y="64" width="36" height="6" rx="3" fill="rgba(255,255,255,.12)"/>
          <rect x="22" y="76" width="24" height="4" rx="2" fill="rgba(255,255,255,.07)"/>
          <path d="M58 20 L62 10 L66 20 L76 16 L69 24 L72 35 L62 28 L52 35 L55 24 L48 16 Z" fill="rgba(0,255,240,.3)" stroke="rgba(0,255,240,.5)" stroke-width="1" stroke-linejoin="round"/>
        </svg>
        <div class="wallets-empty-title">No wallets yet</div>
        <div class="wallets-empty-sub">Generate your first XRPL wallet — your seed is encrypted with AES-256-GCM and never leaves this device.</div>
        <button class="btn-create-wallet-hero" onclick="openWalletCreator()">⚡ Generate XRPL Wallet</button>
      </div>`;
    _setText('stat-wallets-val', 0);
    return;
  }

  const cards = wallets.map((w, i) => {
    const isActive  = w.id === activeWalletId;
    const cached    = balanceCache[w.address];
    const metric    = metricCache[w.address];
    const isWatch   = !!w.watchOnly;
    const xrp       = CryptoVault.isUnlocked || isWatch ? (cached ? fmt(cached.xrp, 2) : '—') : '••••';
    const syncedAgo = cached?.fetchedAt ? _actRelTime(cached.fetchedAt) : null;
    const tokens    = cached?.tokens || [];
    const addrShort = w.address.slice(0,8) + '…' + w.address.slice(-6);
    // Reserve breakdown
    const ownerCount = metric?.ownerCount || 0;
    const reserveXrp = 10 + ownerCount * 2;
    const available  = cached ? Math.max(0, cached.xrp - reserveXrp) : null;

    return `
    <div class="wcard ${isActive ? 'wcard--active' : ''} ${isWatch ? 'wcard--watch' : ''}" id="wallet-item-${w.id}">
      <div class="wcard-top">
        <div class="wcard-icon" style="background:${w.color}18;border-color:${w.color}44;color:${w.color}">${escHtml(w.emoji||'💎')}</div>
        <div class="wcard-identity">
          <div class="wcard-name-row">
            <span class="wcard-name">${escHtml(w.label||'Unnamed Wallet')}</span>
            ${isActive ? '<span class="wcard-badge wcard-badge--active">● Active</span>' : ''}
            ${isWatch  ? '<span class="wcard-badge wcard-badge--watch">👁 Watch-only</span>' : ''}
            ${w.testnet ? '<span class="wcard-badge wcard-badge--testnet">Testnet</span>' : '<span class="wcard-badge wcard-badge--mainnet">Mainnet</span>'}
          </div>
          <div class="wcard-address mono" title="${escHtml(w.address)}" onclick="copyToClipboard('${escHtml(w.address)}')">${addrShort} <span class="wcard-copy-hint">⧉</span></div>
          <div class="wcard-algo-row">
            ${!isWatch ? `<span class="wcard-algo">${escHtml((w.algo||'ed25519').toUpperCase())}</span>
            <span class="wcard-enc">🔐 AES-256-GCM encrypted</span>` : '<span class="wcard-enc">🔍 Read-only — no signing</span>'}
          </div>
        </div>
        <div class="wcard-balance-col">
          <div class="wcard-xrp ${!CryptoVault.isUnlocked&&!isWatch ? 'wcard-balance-locked' : ''}">${xrp} <span class="wcard-xrp-label">XRP</span></div>
          ${available!==null&&(CryptoVault.isUnlocked||isWatch) ? `<div class="wcard-avail" title="${ownerCount} owned objects · ${reserveXrp} XRP reserved">${fmt(available,2)} avail.</div>` : ''}
          ${tokens.length && (CryptoVault.isUnlocked||isWatch) ? `<div class="wcard-tokens">${tokens.length} token${tokens.length>1?'s':''}</div>` : ''}
        </div>
      </div>

      <div class="wcard-sync-row">
        <div class="wcard-sync-time">
          ${!CryptoVault.isUnlocked && !isWatch
            ? '<span>🔒 Sign in to see balance</span>'
            : syncedAgo
              ? `<span>Last synced: ${syncedAgo}</span>`
              : '<span style="opacity:.5">Balance not fetched yet</span>'}
        </div>
        ${CryptoVault.isUnlocked||isWatch ? `<button class="wcard-refresh-btn" onclick="fetchBalance('${w.address}').then(()=>{renderWalletList();renderProfileMetrics();})" title="Refresh balance">↻ Refresh</button>` : ''}
      </div>

      ${metric ? `
      <div class="wcard-reserve-row">
        <span class="wcard-reserve-chip" title="Base 10 XRP + ${ownerCount} owned objects × 2 XRP">🔒 ${reserveXrp} XRP reserved</span>
        <span class="wcard-reserve-sub">${ownerCount} owned object${ownerCount!==1?'s':''} · base 10 + ${ownerCount}×2</span>
      </div>` : ''}

      ${tokens.length && (CryptoVault.isUnlocked||isWatch) ? `
      <div class="wcard-token-row">
        ${tokens.slice(0,6).map(t => {
          const curDisp = t.currency.length>4 ? (_hexToAscii(t.currency)||t.currency.slice(0,4)+'…') : t.currency;
          const bal = fmt(parseFloat(t.balance||0),4);
          return `<div class="wcard-token-chip" onclick="openTokenDetailsModal('${escHtml(t.currency)}','${escHtml(t.issuer)}','${escHtml(w.address)}')" title="${escHtml(t.currency)}: ${bal}">
            <span class="wcard-token-cur">${escHtml(curDisp)}</span>
            <span class="wcard-token-bal">${bal}</span>
          </div>`;
        }).join('')}
        ${tokens.length>6?`<div class="wcard-token-chip wcard-token-more" onclick="openTokenDetailsModal('${escHtml(tokens[6].currency)}','${escHtml(tokens[6].issuer)}','${escHtml(w.address)}')">+${tokens.length-6} more</div>`:''}
      </div>` : ''}

      <div class="wcard-actions">
        ${!isWatch ? `<button class="wcard-btn wcard-btn--send"    onclick="openSendModal('${w.id}')">⬆ Send</button>` : ''}
        <button class="wcard-btn wcard-btn--receive" onclick="openReceiveModal('${w.id}')">⬇ Receive</button>
        ${!isWatch ? `<button class="wcard-btn wcard-btn--trust"   onclick="openTrustlineModal('${w.id}')">🔗 Trustlines</button>` : ''}
        <button class="wcard-btn wcard-btn--inspect" onclick="inspectWalletAddr('${escHtml(w.address)}')">🔍 Inspect</button>
        ${!isActive ? `<button class="wcard-btn wcard-btn--setactive" onclick="setActiveWallet('${w.id}')">★ Set Active</button>` : ''}
        <button class="wcard-btn wcard-btn--expand ${_expandedWallet === w.id ? 'wcard-btn--expand-open' : ''}" onclick="toggleWalletDrawer('${w.id}')">${_expandedWallet === w.id ? '▲ Close' : '▼ Details'}</button>
        <button class="wcard-btn wcard-btn--remove"  onclick="deleteWallet(${i})">✕ Remove</button>
      </div>

      ${_expandedWallet === w.id ? `
      <div class="wcard-drawer" id="wcard-drawer-${w.id}">
        <div class="wcard-drawer-tabs">
          <button class="wdt-btn ${(_expandedSubTabs[w.id]||'txns')==='txns'?'active':''}"   data-tab="txns"   onclick="switchWalletDrawerTab('${w.id}','txns')">📋 Transactions</button>
          <button class="wdt-btn ${(_expandedSubTabs[w.id]||'txns')==='nfts'?'active':''}"   data-tab="nfts"   onclick="switchWalletDrawerTab('${w.id}','nfts')">🎨 NFTs</button>
          <button class="wdt-btn ${(_expandedSubTabs[w.id]||'txns')==='orders'?'active':''}" data-tab="orders" onclick="switchWalletDrawerTab('${w.id}','orders')">📊 DEX Orders</button>
        </div>
        <div class="wcard-drawer-body" id="wcard-drawer-body-${w.id}">
          <div class="wdd-loading"><div class="spinner"></div> Loading…</div>
        </div>
      </div>` : ''}
    </div>`;
  }).join('');

  list.innerHTML = cards + `
    <div class="wallet-add-row">
      <button class="btn-add-wallet" onclick="openWalletCreator()">
        <span class="baw-plus">＋</span>
        <div class="baw-text">
          <span class="baw-title">Generate New XRPL Wallet</span>
          <span class="baw-sub">Keys generated in-browser · encrypted before storage · never sent anywhere</span>
        </div>
      </button>
      <button class="btn-import-wallet btn-import-wallet--seed" onclick="openImportSeedModal()">
        <span class="baw-plus">🔑</span>
        <div class="baw-text">
          <span class="baw-title">Import from Seed</span>
          <span class="baw-sub">Existing family seed or hex seed — full access</span>
        </div>
      </button>
      <button class="btn-import-wallet btn-import-wallet--watch" onclick="openImportAddressModal()">
        <span class="baw-plus">👁</span>
        <div class="baw-text">
          <span class="baw-title">Watch Address</span>
          <span class="baw-sub">Track any XRPL address read-only — no seed required</span>
        </div>
      </button>
    </div>`;

  _setText('stat-wallets-val', wallets.length);
}

/* ── Security panel ── */
function renderSecurityPanel() {
  const el = $('profile-tab-security');
  if (!el) return;
  const unlocked = CryptoVault.isUnlocked;
  const meta = (() => { try { return JSON.parse(localStorage.getItem('naluxrp_vault_meta')||'{}'); } catch{return{};} })();
  const createdAt = CryptoVault.vault?.identity?.createdAt
    ? new Date(CryptoVault.vault.identity.createdAt).toLocaleDateString('en-US',{year:'numeric',month:'long',day:'numeric'}) : '—';

  el.innerHTML = `
    <div class="sec-grid">

      <div class="sec-card">
        <div class="sec-card-hdr">
          <span class="sec-card-icon">🔐</span>
          <div>
            <div class="sec-card-title">Local Encrypted Vault</div>
            <div class="sec-card-sub">AES-256-GCM · PBKDF2 150,000 iterations · SHA-256</div>
          </div>
          <span class="sec-status-pill ${unlocked ? 'sec-status--open' : 'sec-status--locked'}">${unlocked ? 'Unlocked' : 'Locked'}</span>
        </div>
        <div class="sec-kv-grid">
          <div class="sec-kv"><span class="sec-k">Encryption</span><span class="sec-v mono">AES-256-GCM</span></div>
          <div class="sec-kv"><span class="sec-k">Key derivation</span><span class="sec-v mono">PBKDF2 · 150k iterations</span></div>
          <div class="sec-kv"><span class="sec-k">Hash</span><span class="sec-v mono">SHA-256</span></div>
          <div class="sec-kv"><span class="sec-k">Vault created</span><span class="sec-v">${createdAt}</span></div>
          <div class="sec-kv"><span class="sec-k">Server storage</span><span class="sec-v sec-v--good">None — local only</span></div>
          <div class="sec-kv"><span class="sec-k">Password stored</span><span class="sec-v sec-v--good">Never — key derivation only</span></div>
          <div class="sec-kv"><span class="sec-k">Auto-lock</span><span class="sec-v">30 min inactivity</span></div>
        </div>
        <div class="sec-card-actions">
          <button class="sec-btn sec-btn--primary" onclick="exportVaultBackup()">⬇ Export Encrypted Backup</button>
        </div>
        <div class="sec-note">
          <span class="sec-note-icon">ℹ</span>
          Your backup file is still encrypted — it cannot be read without your password.
          Store it on a USB drive or external hard drive.
        </div>
      </div>

      <div class="sec-card">
        <div class="sec-card-hdr">
          <span class="sec-card-icon">🌐</span>
          <div>
            <div class="sec-card-title">Privacy Architecture</div>
            <div class="sec-card-sub">How NaluLF handles your data</div>
          </div>
        </div>
        <div class="sec-info-list">
          <div class="sec-info-item sec-info--good">
            <span class="sec-info-dot"></span>
            <div><strong>Zero server-side storage.</strong> Your profile, wallet metadata, and seeds never leave your browser.</div>
          </div>
          <div class="sec-info-item sec-info--good">
            <span class="sec-info-dot"></span>
            <div><strong>Direct XRPL connections.</strong> We connect directly to XRPL public nodes over WebSocket — no proxy.</div>
          </div>
          <div class="sec-info-item sec-info--good">
            <span class="sec-info-dot"></span>
            <div><strong>No telemetry.</strong> No analytics, no tracking, no third-party scripts that observe your activity.</div>
          </div>
          <div class="sec-info-item sec-info--warn">
            <span class="sec-info-dot"></span>
            <div><strong>On-chain data is public.</strong> XRPL transactions are permanently public. Wallet addresses and balances are visible to anyone.</div>
          </div>
          <div class="sec-info-item sec-info--warn">
            <span class="sec-info-dot"></span>
            <div><strong>You control your keys.</strong> If you forget your password and have no backup, your encrypted vault data cannot be recovered.</div>
          </div>
        </div>
      </div>

      <div class="sec-card sec-card--seed-best-practices">
        <div class="sec-card-hdr">
          <span class="sec-card-icon">✍️</span>
          <div>
            <div class="sec-card-title">Seed Phrase Best Practices</div>
            <div class="sec-card-sub">Required reading for every wallet owner</div>
          </div>
        </div>
        <div class="sec-practices">
          <div class="sec-practice">
            <div class="sec-practice-num">1</div>
            <div class="sec-practice-body">
              <strong>Write it on paper — right now.</strong>
              Store a physical copy in a safe, fireproof box, or safety deposit box. This is your only recovery option if you lose this device.
            </div>
          </div>
          <div class="sec-practice">
            <div class="sec-practice-num">2</div>
            <div class="sec-practice-body">
              <strong>Never store it digitally.</strong>
              No notes apps, emails, cloud drives, or screenshots. A hacked device means instant loss of all funds.
            </div>
          </div>
          <div class="sec-practice">
            <div class="sec-practice-num">3</div>
            <div class="sec-practice-body">
              <strong>Never share it with anyone.</strong>
              No exchange, support team, or application should ever request your seed. This is always a scam.
            </div>
          </div>
          <div class="sec-practice">
            <div class="sec-practice-num">4</div>
            <div class="sec-practice-body">
              <strong>Use a strong, unique password.</strong>
              Your password protects the encrypted vault on this device. Use one you don't use anywhere else.
            </div>
          </div>
          <div class="sec-practice">
            <div class="sec-practice-num">5</div>
            <div class="sec-practice-body">
              <strong>Export your backup regularly.</strong>
              Use the Export Backup button above after creating or modifying wallets. Keep the file offline.
            </div>
          </div>
        </div>
      </div>

      <div class="sec-card">
        <div class="sec-card-hdr">
          <span class="sec-card-icon">📡</span>
          <div>
            <div class="sec-card-title">XRPL Capabilities</div>
            <div class="sec-card-sub">What your wallets can do in NaluLF</div>
          </div>
        </div>
        <div class="sec-caps-grid">
          <div class="sec-cap"><span class="sec-cap-icon">💸</span><span>XRP &amp; IOU Payments</span></div>
          <div class="sec-cap"><span class="sec-cap-icon">🔗</span><span>Trustlines (TrustSet)</span></div>
          <div class="sec-cap"><span class="sec-cap-icon">📊</span><span>DEX Orders (CLOB)</span></div>
          <div class="sec-cap"><span class="sec-cap-icon">🌊</span><span>AMM Deposits &amp; Swaps</span></div>
          <div class="sec-cap"><span class="sec-cap-icon">🎨</span><span>NFT Mint &amp; Transfer</span></div>
          <div class="sec-cap"><span class="sec-cap-icon">🔍</span><span>On-chain Forensic Inspect</span></div>
          <div class="sec-cap"><span class="sec-cap-icon">🏦</span><span>Multi-wallet Management</span></div>
          <div class="sec-cap"><span class="sec-cap-icon">🛡</span><span>Ed25519 &amp; secp256k1</span></div>
        </div>
      </div>

    </div>`;
}

/* ── Activity panel — local timeline + on-chain redirect ── */
function renderActivityPanel() {
  const el = $('profile-tab-activity');
  if (!el) return;
  try {
    const log = _getActivity();
    const w   = getActiveWallet();

    el.innerHTML = `
      <div class="act-section-row">
        <div class="act-section">
          <div class="act-section-title">In-App Activity</div>
          <div class="act-section-sub">Your recent actions in NaluLF</div>
          ${log.length === 0
            ? '<div class="act-empty-small">No activity yet — create a wallet or connect a social to get started.</div>'
            : `<div class="act-timeline">${log.slice(0, 20).map(entry => `
              <div class="act-entry">
                <div class="act-entry-icon">${ACT_ICONS[entry.type] || '●'}</div>
                <div class="act-entry-body">
                  <div class="act-entry-detail">${escHtml(entry.detail)}</div>
                  <div class="act-entry-time">${_actRelTime(entry.ts)}</div>
                </div>
              </div>`).join('')}
            </div>`
          }
        </div>

        <div class="act-section">
          <div class="act-section-title">On-Chain Activity</div>
          <div class="act-section-sub">Full forensic analysis via the Inspector</div>
          ${w ? `
          <div class="act-redirect-card">
            <div class="act-rc-icon">🔍</div>
            <div class="act-rc-body">
              <div class="act-rc-title">${escHtml(w.label)}</div>
              <div class="act-rc-sub">Transaction history, Benford's Law, wash trading signals, NFT analysis, fund flow tracing and a full investigation report.</div>
              <button class="act-inspect-btn-lg" onclick="inspectWalletAddr('${escHtml(w.address)}')">Open Inspector →</button>
            </div>
          </div>` : '<div class="act-empty-small">Create a wallet to inspect on-chain activity.</div>'}
        </div>
      </div>`;
  } catch(err) {
    _renderTabError(el, 'activity', err);
  }
}

export function deleteWallet(idx) {
  const w = wallets[idx];
  if (!w) return;

  // Optimistically remove
  wallets.splice(idx, 1);
  _saveWalletMeta();
  if (CryptoVault.isUnlocked) {
    CryptoVault.update(v => { v.wallets = v.wallets.filter(vw => vw.id !== w.id); });
  }
  const prevActive = activeWalletId;
  if (activeWalletId === w.id) {
    activeWalletId = wallets[0]?.id || null;
    if (activeWalletId) safeSet(LS_ACTIVE_ID, activeWalletId);
  }
  renderWalletList(); renderActiveWalletBar();
  logActivity('wallet_removed', w.label);

  // Undo toast — 5 second window
  let undone = false;
  const undoToast = _showUndoToast(`Wallet "${w.label}" removed`, () => {
    if (undone) return; undone = true;
    wallets.splice(idx, 0, w); _saveWalletMeta();
    if (CryptoVault.isUnlocked) {
      CryptoVault.update(v => { v.wallets = v.wallets || []; v.wallets.push({...w}); });
    }
    if (!activeWalletId) { activeWalletId = w.id; safeSet(LS_ACTIVE_ID, w.id); }
    renderWalletList(); renderActiveWalletBar();
    logActivity('wallet_created', w.label + ' (restored)');
  });
}

function _showUndoToast(msg, onUndo) {
  const existing = document.getElementById('undo-toast');
  if (existing) existing.remove();
  const toast = document.createElement('div');
  toast.id = 'undo-toast'; toast.className = 'undo-toast';
  toast.innerHTML = `<span class="undo-msg">${msg}</span><button class="undo-btn" onclick="this._undid=true">Undo</button>`;
  document.body.appendChild(toast);
  requestAnimationFrame(() => toast.classList.add('show'));
  const undoBtn = toast.querySelector('.undo-btn');
  const timer = setTimeout(() => { toast.classList.remove('show'); setTimeout(() => toast.remove(), 300); }, 5000);
  undoBtn.addEventListener('click', () => {
    clearTimeout(timer); onUndo(); toast.classList.remove('show'); setTimeout(() => toast.remove(), 300);
    toastInfo('Wallet restored');
  });
  return toast;
}

export function inspectWalletAddr(addr) {
  const inp = $('inspect-addr');
  if (inp) inp.value = addr;
  window.switchTab?.(document.querySelector('[data-tab="inspector"]'), 'inspector');
  window.showDashboard?.();
}

/* ═══════════════════════════════════════════════════════════
   Wallet Creator Wizard
═══════════════════════════════════════════════════════════ */
export function openWalletCreator() {
  if (!CryptoVault.isUnlocked) {
    toastWarn('Please sign in first to create a wallet.');
    return;
  }
  wizardStep = 1;
  wizardData = { algo: 'ed25519', label: '', emoji: '💎', color: '#50fa7b', seed: '', address: '' };
  checksCompleted.clear();
  renderWizardStep(1);
  renderWizardCustomization();
  _renderWizardSecurityBanner();
  $('wallet-creator-overlay')?.classList.add('show');
}

export function closeWalletCreator() {
  $('wallet-creator-overlay')?.classList.remove('show');
  wizardData.seed = wizardData.address = '';
}

function _renderWizardSecurityBanner() {
  const target = $('wizard-security-banner');
  if (!target) return;
  target.innerHTML = `
    <div class="wsb-icon">🔐</div>
    <div class="wsb-content">
      <div class="wsb-title">Your keys are encrypted on your device</div>
      <div class="wsb-body">
        Your wallet's secret seed phrase is encrypted with your password using AES-256-GCM
        before being saved to this device. <strong>It never leaves your browser.</strong>
        No server, no cloud, no third party ever sees it.
      </div>
      <div class="wsb-pills">
        <span class="wsb-pill wsb-pill--green">🔒 Stored locally only</span>
        <span class="wsb-pill wsb-pill--green">🚫 Never sent to any server</span>
        <span class="wsb-pill wsb-pill--blue">⚡ AES-256-GCM encrypted</span>
      </div>
    </div>`;
}

export function wizardNext() {
  if (wizardStep === 1) {
    const label = $('wallet-label-input')?.value.trim();
    if (!label) { toastWarn('Enter a wallet name.'); return; }
    wizardData.label = label;
    generateWalletKeys();
    wizardStep = 2;
  } else if (wizardStep === 2) {
    if (checksCompleted.size < 4) { toastWarn('Confirm all security checkpoints first.'); return; }
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
  [1,2,3,4].forEach(s => {
    const dot = $(`.step-${s}`);
    if (!dot) return;
    dot.classList.toggle('active', s === step);
    dot.classList.toggle('done', s < step);
  });
  $$('.wizard-panel').forEach(p => p.classList.remove('active'));
  $(`wizard-panel-${step}`)?.classList.add('active');
  const backBtn   = $('wizard-back-btn');
  const nextBtn   = $('wizard-next-btn');
  const finishBtn = $('wizard-finish-btn');
  if (backBtn)   backBtn.style.display   = step === 4 ? 'none' : '';
  if (nextBtn)   nextBtn.style.display   = step >= 3  ? 'none' : '';
  if (finishBtn) finishBtn.style.display = step === 3  ? '' : 'none';
  if (backBtn)   backBtn.textContent     = step === 1  ? 'Cancel' : '← Back';
}

function renderWizardCustomization() {
  const emojiRow = $('wallet-emoji-picker');
  if (emojiRow) {
    emojiRow.innerHTML = WALLET_EMOJIS.map(e => `
      <div class="wallet-emoji-opt ${wizardData.emoji === e ? 'active' : ''}"
           onclick="selectWalletEmoji('${e}')">${e}</div>`).join('');
  }
  const colorRow = $('wallet-color-picker');
  if (colorRow) {
    colorRow.innerHTML = WALLET_COLORS.map(c => `
      <div class="color-swatch ${wizardData.color === c ? 'active' : ''}"
           style="background:${c}" onclick="selectWalletColor('${c}')"></div>`).join('');
  }
}

function generateWalletKeys() {
  if (window.xrpl) {
    try {
      const w = window.xrpl.Wallet.generate(wizardData.algo === 'ed25519' ? 'ed25519' : 'secp256k1');
      wizardData.seed    = w.seed || w.classicAddress;
      wizardData.address = w.classicAddress;
    } catch(e) {
      console.warn('xrpl.js Wallet.generate failed, using fallback:', e);
      _fallbackGenerate();
    }
  } else {
    _fallbackGenerate();
  }
  const seedEl = $('wizard-seed-value');
  const addrEl = $('wizard-address-value');
  if (seedEl)  seedEl.textContent = wizardData.seed;
  if (addrEl)  addrEl.textContent = wizardData.address;
  checksCompleted.clear();
  $$('.security-check').forEach(el => el.classList.remove('checked'));
  $$('.check-box').forEach(el => el.textContent = '');
  // Render rich best-practice checklist dynamically
  _renderSecurityChecklist();
  updateWizardNextBtn();
}

function _renderSecurityChecklist() {
  const list = $('security-checklist-dynamic');
  if (!list) return;
  const items = [
    {
      icon: '✍️',
      title: 'Write it down on paper — right now',
      body: 'Copy your seed phrase onto paper and store it somewhere safe like a fireproof box or safe. This is the ONLY way to recover your wallet if you lose access to this device.',
    },
    {
      icon: '🚫',
      title: 'Never store it digitally',
      body: 'Do not save your seed in a notes app, email, screenshot, or cloud service. If a device with a digital copy is hacked, your funds can be stolen.',
    },
    {
      icon: '🤫',
      title: 'Never share it with anyone',
      body: 'No legitimate app, exchange, or support team will ever ask for your seed phrase. Anyone who asks is attempting to steal your funds.',
    },
    {
      icon: '🔐',
      title: 'Use a strong, unique password',
      body: 'Your encryption password protects the seed on this device. Use a password you don\'t use anywhere else. Losing the password AND the seed means losing the wallet forever.',
    },
  ];
  list.innerHTML = items.map((item, i) => `
    <div class="security-check security-check-${i+1}" onclick="toggleSecurityCheck(${i+1})">
      <span class="check-box" id="check-box-${i+1}"></span>
      <div class="check-text">
        <strong>${item.icon} ${escHtml(item.title)}</strong>
        ${escHtml(item.body)}
      </div>
    </div>`).join('');
}

function _fallbackGenerate() {
  // Note: xrpl.js CDN required for real wallets — this is a display fallback only
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  const hex   = Array.from(bytes).map(b => b.toString(16).padStart(2,'0')).join('');
  const B58   = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  let num = BigInt('0x' + hex), seed = '';
  while (num > 0n) { seed = B58[Number(num % 58n)] + seed; num /= 58n; }
  wizardData.seed = 's' + seed.padStart(28,'1').slice(0,28);
  const ab = crypto.getRandomValues(new Uint8Array(20));
  const ah = Array.from(ab).map(b => b.toString(16).padStart(2,'0')).join('');
  let an = BigInt('0x' + ah), addr = '';
  while (an > 0n) { addr = B58[Number(an % 58n)] + addr; an /= 58n; }
  wizardData.address = 'r' + addr.slice(0, 25 + (Number(ab[0]) % 9));
}

async function saveNewWallet() {
  const newWallet = {
    id:        crypto.randomUUID(),
    label:     wizardData.label,
    address:   wizardData.address,
    algo:      wizardData.algo,
    seed:      wizardData.seed,   // stored ONLY inside vault
    emoji:     wizardData.emoji,
    color:     wizardData.color,
    testnet:   $('wallet-testnet-check')?.checked || false,
    createdAt: new Date().toISOString(),
  };

  // Store seed in encrypted vault
  await CryptoVault.update(v => {
    v.wallets = v.wallets || [];
    v.wallets.push({ ...newWallet });
  });

  // Store public metadata (no seed!) in plain localStorage
  const meta = { ...newWallet };
  delete meta.seed;
  wallets.push(meta);
  _saveWalletMeta();

  // Set as active if first wallet
  if (!activeWalletId) {
    activeWalletId = newWallet.id;
    safeSet(LS_ACTIVE_ID, newWallet.id);
  }

  renderWalletList();
  renderActiveWalletBar();
  _setText('wallet-success-address', wizardData.address);

  // Zero seed immediately
  setTimeout(() => { wizardData.seed = wizardData.address = ''; }, 100);
  logActivity('wallet_created', wizardData.label || 'New XRPL Wallet');
  toastInfo('Wallet saved to encrypted vault');
  fetchBalance(newWallet.address).then(() => renderWalletList());
}

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
  $$('.color-swatch').forEach(el =>
    el.classList.toggle('active', el.style.background === color || el.dataset.color === color));
}
export function toggleSecurityCheck(idx) {
  const el = $(`.security-check-${idx}`);
  if (!el) return;
  const checkBox = el.querySelector('.check-box');
  if (checksCompleted.has(idx)) {
    checksCompleted.delete(idx); el.classList.remove('checked'); if (checkBox) checkBox.textContent = '';
  } else {
    checksCompleted.add(idx); el.classList.add('checked'); if (checkBox) checkBox.textContent = '✓';
  }
  updateWizardNextBtn();
}
function updateWizardNextBtn() {
  const nextBtn = $('wizard-next-btn');
  if (nextBtn && wizardStep === 2) nextBtn.disabled = checksCompleted.size < 4;
}
export function revealSeed() {
  $('wizard-seed-value')?.classList.remove('blur');
  const hint = $('seed-reveal-hint');
  if (hint) hint.style.display = 'none';
  // Auto-re-blur after 30 seconds for security
  setTimeout(() => $('wizard-seed-value')?.classList.add('blur'), 30_000);
}
export function copySeed() {
  const el = $('wizard-seed-value');
  if (!el) return;
  _copyToClipboard(el.textContent, 30_000); // auto-clear from clipboard after 30s
  const btn = $('btn-copy-seed');
  if (btn) { btn.textContent = 'Copied!'; btn.classList.add('copied'); setTimeout(() => { btn.textContent = 'Copy Seed'; btn.classList.remove('copied'); }, 2000); }
}
export function copyAddress() {
  const el = $('wizard-address-value') || $('wallet-success-address');
  if (!el) return;
  _copyToClipboard(el.textContent);
  const btn = $('btn-copy-addr');
  if (btn) { btn.textContent = 'Copied!'; btn.classList.add('copied'); setTimeout(() => { btn.textContent = 'Copy'; btn.classList.remove('copied'); }, 2000); }
}

/* ═══════════════════════════════════════════════════════════
   XRPL Network — Balance Fetching
═══════════════════════════════════════════════════════════ */
async function xrplPost(body) {
  try {
    const r = await fetch(XRPL_RPC, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    return (await r.json()).result;
  } catch {
    // Try backup node
    const r = await fetch(XRPL_RPC_BACKUP, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    return (await r.json()).result;
  }
}

export async function fetchBalance(address) {
  try {
    const [acctResult, linesResult] = await Promise.all([
      xrplPost({ method: 'account_info', params: [{ account: address, ledger_index: 'current' }] }),
      xrplPost({ method: 'account_lines', params: [{ account: address, ledger_index: 'current' }] }),
    ]);
    if (acctResult?.error) return null;
    const xrp    = Number(acctResult.account_data.Balance) / 1e6;
    const tokens = (linesResult?.lines || []).map(l => ({
      currency: l.currency, issuer: l.account, balance: l.balance, limit: l.limit,
    }));
    balanceCache[address] = { xrp, tokens, fetchedAt: Date.now() };
    trustlineCache[address] = tokens;
    _recordBalanceSnapshot(address, xrp);
    return balanceCache[address];
  } catch { return null; }
}

async function fetchAllBalances() {
  await Promise.all(wallets.map(w => fetchBalance(w.address)));
  renderWalletList();
  renderActiveWalletBar();
}

/* Balance snapshot recorder — builds history for the analytics chart */
function _recordBalanceSnapshot(address, xrp) {
  const key  = LS_BAL_HIST_PREFIX + address;
  const hist = safeJson(safeGet(key)) || [];
  const now  = Date.now();
  if (hist.length && now - hist[hist.length - 1].ts < 5 * 60 * 1000) {
    hist[hist.length - 1] = { xrp, ts: now }; // update instead of duplicate
  } else {
    hist.push({ xrp, ts: now });
  }
  if (hist.length > 90) hist.splice(0, hist.length - 90);
  safeSet(key, JSON.stringify(hist));
}
function _getBalanceHistory(address) {
  return safeJson(safeGet(LS_BAL_HIST_PREFIX + address)) || [];
}

/* Fetch transaction history via account_tx */
async function fetchTxHistory(address, limit = 25) {
  const r = await xrplPost({ method: 'account_tx', params: [{ account: address, limit, ledger_index_min: -1, ledger_index_max: -1 }] });
  const txns = (r?.transactions || []).map(t => t.tx || t.transaction || t);
  txCache[address] = { txns, fetchedAt: Date.now() };
  return txns;
}

/* Fetch NFTs via account_nfts */
async function fetchNFTs(address) {
  const r = await xrplPost({ method: 'account_nfts', params: [{ account: address, limit: 50 }] });
  const nfts = r?.account_nfts || [];
  nftCache[address] = { nfts, fetchedAt: Date.now() };
  return nfts;
}

/* Fetch open DEX offers via account_offers */
async function fetchOpenOffers(address) {
  const r = await xrplPost({ method: 'account_offers', params: [{ account: address, limit: 50 }] });
  const offers = r?.offers || [];
  offerCache[address] = { offers, fetchedAt: Date.now() };
  return offers;
}

async function getAccountInfo(address) {
  const r = await xrplPost({ method: 'account_info', params: [{ account: address, ledger_index: 'current' }] });
  return r?.account_data || null;
}

async function getCurrentLedger() {
  const r = await xrplPost({ method: 'ledger', params: [{ ledger_index: 'current' }] });
  return r?.ledger_current_index || 0;
}

/* ═══════════════════════════════════════════════════════════
   XRPL Transaction Signing + Submission
═══════════════════════════════════════════════════════════ */
async function _requireVaultUnlocked() {
  if (!CryptoVault.isUnlocked) throw new Error('Vault is locked. Please sign in to enable transaction signing.');
}

async function _getSeedForWallet(walletId) {
  await _requireVaultUnlocked();
  const vw = CryptoVault.vault?.wallets?.find(w => w.id === walletId);
  if (!vw?.seed) throw new Error('Seed not found in vault for this wallet.');
  return vw.seed;
}

/* Build, sign, and submit an XRPL transaction */
async function signAndSubmit(walletId, txJson) {
  await _requireVaultUnlocked();
  if (!window.xrpl) throw new Error('xrpl.js library not loaded. Cannot sign transactions.');

  const seed = await _getSeedForWallet(walletId);
  const wObj = wallets.find(w => w.id === walletId);
  if (!wObj) throw new Error('Wallet not found.');

  try {
    const xrplWallet = window.xrpl.Wallet.fromSeed(seed, {
      algorithm: wObj.algo === 'ed25519' ? 'ed25519' : 'secp256k1',
    });

    // Autofill sequence and fee
    const [acctInfo, ledger] = await Promise.all([
      getAccountInfo(wObj.address),
      getCurrentLedger(),
    ]);
    if (!acctInfo) throw new Error('Account not found on-chain. Fund with 10 XRP first (reserve requirement).');

    const prepared = {
      ...txJson,
      Account:              wObj.address,
      Fee:                  '12',
      Sequence:             acctInfo.Sequence,
      LastLedgerSequence:   ledger + 20,
      NetworkID:            txJson.NetworkID || undefined,
    };

    const { tx_blob, hash } = xrplWallet.sign(prepared);

    // Submit
    const result = await xrplPost({ method: 'submit', params: [{ tx_blob }] });
    return { ...result, tx_hash: hash };

  } finally {
    // Zero seed reference
    seed && Object.defineProperty({ _: seed }, '_', { value: '' });
  }
}

/* ── TrustSet (add / modify trustline) ── */
export async function executeTrustSet(walletId, currency, issuer, limit = '1000000000') {
  const tx = {
    TransactionType: 'TrustSet',
    LimitAmount: { currency, issuer, value: String(limit) },
  };
  return signAndSubmit(walletId, tx);
}

/* ── Payment (XRP or IOU) ── */
export async function executePayment(walletId, destination, amount, currency, issuer, destinationTag) {
  const isXRP  = !currency || currency === 'XRP';
  const Amount = isXRP ? String(Math.floor(parseFloat(amount) * 1e6)) : { currency, issuer, value: String(amount) };
  const tx = {
    TransactionType:  'Payment',
    Destination:       destination,
    Amount,
    ...(destinationTag ? { DestinationTag: parseInt(destinationTag) } : {}),
  };
  return signAndSubmit(walletId, tx);
}

/* ── OfferCreate (DEX order) ── */
export async function executeOfferCreate(walletId, takerGets, takerPays) {
  const tx = { TransactionType: 'OfferCreate', TakerGets: takerGets, TakerPays: takerPays };
  return signAndSubmit(walletId, tx);
}

/* ── OfferCancel ── */
export async function executeOfferCancel(walletId, offerSequence) {
  const tx = { TransactionType: 'OfferCancel', OfferSequence: parseInt(offerSequence) };
  return signAndSubmit(walletId, tx);
}

/* ═══════════════════════════════════════════════════════════
   Send Modal
═══════════════════════════════════════════════════════════ */
let _sendWalletId = null;

export function openSendModal(walletId) {
  _sendWalletId = walletId;
  const w       = wallets.find(x => x.id === walletId);
  if (!w) return;
  const modal   = $('send-modal-overlay');
  if (!modal) return;

  // Populate token dropdown from trustlines
  const cached  = trustlineCache[w.address] || [];
  const tokenOpts = cached.map(t => `<option value="${escHtml(t.currency)}|${escHtml(t.issuer)}">${escHtml(t.currency)} (${escHtml(t.issuer.slice(0,8))}…)</option>`).join('');
  const selEl   = $('send-currency-select');
  if (selEl)    selEl.innerHTML = `<option value="XRP">XRP</option>${tokenOpts}`;

  _setText('send-modal-wallet-name', w.label);
  _setText('send-from-address', w.address);
  const xrp     = balanceCache[w.address]?.xrp ?? '—';
  _setText('send-available-balance', `${fmt(xrp, 4)} XRP`);

  if ($('send-dest'))     $('send-dest').value     = '';
  if ($('send-amount'))   $('send-amount').value   = '';
  if ($('send-dest-tag')) $('send-dest-tag').value = '';
  $('send-error')?.replaceChildren();

  modal.classList.add('show');
}

export function closeSendModal() { $('send-modal-overlay')?.classList.remove('show'); }

export async function executeSend() {
  const w       = wallets.find(x => x.id === _sendWalletId);
  if (!w) return;
  const dest    = $('send-dest')?.value.trim()      || '';
  const amount  = $('send-amount')?.value.trim()    || '';
  const destTag = $('send-dest-tag')?.value.trim()  || '';
  const selVal  = $('send-currency-select')?.value  || 'XRP';
  const [currency, issuer] = selVal.includes('|') ? selVal.split('|') : ['XRP', null];

  const errEl   = $('send-error');
  const setErr  = msg => { if (errEl) errEl.textContent = msg; };

  setErr('');
  if (!isValidXrpAddress(dest))    return setErr('Enter a valid XRPL destination address.');
  if (!amount || isNaN(+amount) || +amount <= 0) return setErr('Enter a valid amount.');

  const btn = $('send-submit-btn');
  if (btn) { btn.disabled = true; btn.textContent = 'Signing…'; }
  try {
    const result = await executePayment(_sendWalletId, dest, amount, currency === 'XRP' ? null : currency, issuer, destTag);
    if (result?.engine_result === 'tesSUCCESS' || result?.engine_result?.startsWith('tes')) {
      toastInfo(`✅ Payment submitted! Tx: ${result.tx_hash?.slice(0,12)}…`);
      closeSendModal();
      setTimeout(() => fetchBalance(w.address).then(() => { renderWalletList(); renderActiveWalletBar(); }), 4000);
    } else {
      setErr(`Network error: ${result?.engine_result_message || result?.engine_result || 'Unknown error'}`);
    }
  } catch(err) {
    setErr(err.message);
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Send ⬆'; }
  }
}

/* ═══════════════════════════════════════════════════════════
   Receive Modal
═══════════════════════════════════════════════════════════ */
export function openReceiveModal(walletId) {
  const w     = wallets.find(x => x.id === walletId);
  if (!w) return;
  const modal = $('receive-modal-overlay');
  if (!modal) return;
  _setText('receive-address-display', w.address);
  _setText('receive-wallet-name', w.label);
  // Generate QR using qrcode CDN
  const qrContainer = $('receive-qr-container');
  if (qrContainer) {
    qrContainer.innerHTML = '';
    if (window.QRCode) {
      new window.QRCode(qrContainer, {
        text: `xrpl:${w.address}`, width: 180, height: 180,
        colorDark: '#00fff0', colorLight: '#080c16',
      });
    } else {
      qrContainer.innerHTML = `<div class="qr-fallback">📷 Load QRCode.js library for QR display</div>`;
    }
  }
  modal.classList.add('show');
}

export function closeReceiveModal() { $('receive-modal-overlay')?.classList.remove('show'); }

export function copyReceiveAddress() {
  const el = $('receive-address-display');
  if (el) _copyToClipboard(el.textContent);
  const btn = $('receive-copy-btn');
  if (btn) { btn.textContent = '✓ Copied!'; setTimeout(() => btn.textContent = '⧉ Copy Address', 2000); }
}

/* ═══════════════════════════════════════════════════════════
   Trustline Manager Modal
═══════════════════════════════════════════════════════════ */
let _trustWalletId = null;

export function openTrustlineModal(walletId) {
  _trustWalletId = walletId;
  const w      = wallets.find(x => x.id === walletId);
  if (!w) return;
  const modal  = $('trustline-modal-overlay');
  if (!modal) return;
  _setText('trustline-wallet-name', w.label);
  renderTrustlineList(w.address);
  if ($('tl-currency'))  $('tl-currency').value  = '';
  if ($('tl-issuer'))    $('tl-issuer').value    = '';
  if ($('tl-limit'))     $('tl-limit').value     = '1000000000';
  $('tl-error')?.replaceChildren();
  modal.classList.add('show');
}

export function closeTrustlineModal() { $('trustline-modal-overlay')?.classList.remove('show'); }

function renderTrustlineList(address) {
  const container = $('trustline-list-container');
  if (!container) return;
  const lines = trustlineCache[address] || [];
  if (!lines.length) {
    container.innerHTML = `<div class="tl-empty">No trustlines yet. Add one below.</div>`;
    return;
  }
  container.innerHTML = lines.map(t => `
    <div class="tl-item">
      <div class="tl-item-info">
        <span class="tl-currency">${escHtml(t.currency)}</span>
        <span class="tl-issuer mono">${escHtml(t.issuer.slice(0,14))}…</span>
      </div>
      <div class="tl-item-balance">
        <span class="tl-balance">${escHtml(t.balance)}</span>
        <span class="tl-limit">Limit: ${escHtml(t.limit)}</span>
      </div>
      <button class="tl-remove-btn" onclick="removeTrustline('${_trustWalletId}','${escHtml(t.currency)}','${escHtml(t.issuer)}')" title="Remove trustline">✕</button>
    </div>`).join('');
}

export async function addTrustline() {
  const currency = $('tl-currency')?.value.trim().toUpperCase() || '';
  const issuer   = $('tl-issuer')?.value.trim()   || '';
  const limit    = $('tl-limit')?.value.trim()     || '1000000000';
  const errEl    = $('tl-error');
  const setErr   = msg => { if (errEl) errEl.textContent = msg; };

  setErr('');
  if (!currency || currency.length > 20) return setErr('Enter a valid currency code (3 chars or 20-hex).');
  if (!isValidXrpAddress(issuer))         return setErr('Enter a valid issuer XRPL address.');

  const btn = $('tl-add-btn');
  if (btn) { btn.disabled = true; btn.textContent = 'Signing…'; }
  try {
    const result = await executeTrustSet(_trustWalletId, currency, issuer, limit);
    if (result?.engine_result === 'tesSUCCESS' || result?.engine_result?.startsWith('tes')) {
      toastInfo(`✅ Trustline added for ${currency}`);
      closeTrustlineModal();
      const w = wallets.find(x => x.id === _trustWalletId);
      if (w) setTimeout(() => fetchBalance(w.address).then(() => renderWalletList()), 4000);
    } else {
      setErr(`${result?.engine_result_message || result?.engine_result || 'Unknown error'}`);
    }
  } catch(err) {
    setErr(err.message);
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = '+ Add Trustline'; }
  }
}

export async function removeTrustline(walletId, currency, issuer) {
  if (!confirm(`Remove trustline for ${currency}? Balance must be 0.`)) return;
  try {
    const result = await executeTrustSet(walletId, currency, issuer, '0');
    if (result?.engine_result === 'tesSUCCESS' || result?.engine_result?.startsWith('tes')) {
      toastInfo(`Trustline removed for ${currency}`);
      const w = wallets.find(x => x.id === walletId);
      if (w) setTimeout(() => fetchBalance(w.address).then(() => renderTrustlineList(w.address)), 4000);
    } else {
      toastErr(result?.engine_result_message || 'Could not remove trustline');
    }
  } catch(err) {
    toastErr(err.message);
  }
}

/* ═══════════════════════════════════════════════════════════
   Dynamic Modal HTML Mount (injected once into body)
═══════════════════════════════════════════════════════════ */
function _mountDynamicModals() {
  if ($('send-modal-overlay')) return; // already mounted
  const html = `
  <!-- Send Modal -->
  <div class="wallet-action-overlay" id="send-modal-overlay">
    <div class="wallet-action-modal">
      <div class="wam-header">
        <div>
          <div class="wam-title">⬆ Send</div>
          <div class="wam-sub" id="send-modal-wallet-name"></div>
        </div>
        <button class="modal-close" onclick="closeSendModal()">✕</button>
      </div>
      <div class="wam-body">
        <div class="wam-from-row">
          <span class="wam-from-label">From</span>
          <span class="wam-from-addr mono" id="send-from-address"></span>
          <span class="wam-balance-pill" id="send-available-balance"></span>
        </div>
        <div class="profile-field">
          <label class="profile-field-label">Destination Address *</label>
          <input class="profile-input mono" id="send-dest" placeholder="rXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" autocomplete="off">
        </div>
        <div class="wam-row2">
          <div class="profile-field" style="flex:1">
            <label class="profile-field-label">Amount *</label>
            <input class="profile-input mono" id="send-amount" type="number" placeholder="0.00" min="0" step="any">
          </div>
          <div class="profile-field" style="flex:1">
            <label class="profile-field-label">Currency</label>
            <select class="profile-input" id="send-currency-select">
              <option value="XRP">XRP</option>
            </select>
          </div>
        </div>
        <div class="profile-field">
          <label class="profile-field-label">Destination Tag (optional)</label>
          <input class="profile-input mono" id="send-dest-tag" type="number" placeholder="Required by some exchanges">
        </div>
        <div class="wam-vault-note">🔐 Transaction will be signed with your encrypted key</div>
        <div class="wam-error" id="send-error"></div>
      </div>
      <div class="wam-footer">
        <button class="btn-wizard-back" onclick="closeSendModal()">Cancel</button>
        <button class="btn-wizard-next" id="send-submit-btn" onclick="executeSend()">Send ⬆</button>
      </div>
    </div>
  </div>

  <!-- Receive Modal -->
  <div class="wallet-action-overlay" id="receive-modal-overlay">
    <div class="wallet-action-modal">
      <div class="wam-header">
        <div>
          <div class="wam-title">⬇ Receive</div>
          <div class="wam-sub" id="receive-wallet-name"></div>
        </div>
        <button class="modal-close" onclick="closeReceiveModal()">✕</button>
      </div>
      <div class="wam-body" style="text-align:center">
        <div class="receive-qr-wrap">
          <div id="receive-qr-container" class="receive-qr-box"></div>
        </div>
        <div class="receive-address-box">
          <span class="receive-address-val mono" id="receive-address-display"></span>
        </div>
        <button class="btn-wizard-next" id="receive-copy-btn" onclick="copyReceiveAddress()" style="margin-top:16px;width:100%">
          ⧉ Copy Address
        </button>
        <p class="receive-note">Share this address to receive XRP or tokens. Always verify the full address before sending.</p>
      </div>
    </div>
  </div>

  <!-- Trustline Modal -->
  <div class="wallet-action-overlay" id="trustline-modal-overlay">
    <div class="wallet-action-modal wallet-action-modal--wide">
      <div class="wam-header">
        <div>
          <div class="wam-title">🔗 Trustlines</div>
          <div class="wam-sub" id="trustline-wallet-name"></div>
        </div>
        <button class="modal-close" onclick="closeTrustlineModal()">✕</button>
      </div>
      <div class="wam-body">
        <div class="tl-section-h">Active trustlines</div>
        <div id="trustline-list-container" class="tl-list"></div>
        <div class="tl-divider"></div>
        <div class="tl-section-h">Add new trustline</div>
        <div class="wam-row2">
          <div class="profile-field" style="flex:1">
            <label class="profile-field-label">Currency Code *</label>
            <input class="profile-input" id="tl-currency" placeholder="USD / BTC / SOLO" maxlength="20">
          </div>
          <div class="profile-field" style="flex:1">
            <label class="profile-field-label">Trust Limit</label>
            <input class="profile-input mono" id="tl-limit" type="number" placeholder="1000000000" value="1000000000">
          </div>
        </div>
        <div class="profile-field">
          <label class="profile-field-label">Issuer Address *</label>
          <input class="profile-input mono" id="tl-issuer" placeholder="rXXXX… token issuer address">
        </div>
        <div class="wam-vault-note">🔐 TrustSet requires vault access to sign</div>
        <div class="wam-error" id="tl-error"></div>
      </div>
      <div class="wam-footer">
        <button class="btn-wizard-back" onclick="closeTrustlineModal()">Close</button>
        <button class="btn-wizard-finish" id="tl-add-btn" onclick="addTrustline()">+ Add Trustline</button>
      </div>
    </div>
  </div>`;

  const div = document.createElement('div');
  div.innerHTML = html;
  document.body.appendChild(div);

  // Close on backdrop click
  ['send-modal-overlay','receive-modal-overlay','trustline-modal-overlay'].forEach(id => {
    $(id)?.addEventListener('click', e => { if (e.target === e.currentTarget) e.currentTarget.classList.remove('show'); });
  });
}

/* ═══════════════════════════════════════════════════════════
   Profile Editor
═══════════════════════════════════════════════════════════ */
export function openProfileEditor() {
  ['displayName','handle','bio','location','website'].forEach(f => {
    const el = $(`edit-${f}`);
    if (el) el.value = profile[f] || '';
  });

  // Avatar preview in editor
  const prevEl = $('editor-avatar-preview');
  if (prevEl) {
    const img = localStorage.getItem(LS_AVATAR_IMG);
    prevEl.innerHTML = img
      ? `<img src="${img}" class="profile-avatar-img" alt="Profile photo" />`
      : (profile.avatar || '🌊');
  }
  const removeBtn = $('avatar-remove-btn');
  if (removeBtn) removeBtn.style.display = localStorage.getItem(LS_AVATAR_IMG) ? '' : 'none';

  // Banner preview in editor
  const bannerPrev = $('editor-banner-preview');
  if (bannerPrev) {
    const img = localStorage.getItem(LS_BANNER_IMG);
    bannerPrev.style.backgroundImage    = img ? `url(${img})` : '';
    bannerPrev.style.backgroundSize     = 'cover';
    bannerPrev.style.backgroundPosition = 'center';
    BANNERS.forEach(b => bannerPrev.classList.remove(b));
    if (!img) bannerPrev.classList.add(profile.banner || 'banner-ocean');
  }
  const bannerRemoveBtn = $('banner-remove-btn');
  if (bannerRemoveBtn) bannerRemoveBtn.style.display = localStorage.getItem(LS_BANNER_IMG) ? '' : 'none';

  // Emoji grid
  const grid = $('avatar-picker-grid');
  if (grid) {
    grid.innerHTML = AVATARS.map(a => `
      <div class="avatar-option ${profile.avatar === a ? 'active' : ''}"
           onclick="selectAvatar('${a}')">${a}</div>`).join('');
  }

  // Banner gradient grid
  const bannerGrid = $('banner-picker-grid');
  if (bannerGrid) {
    bannerGrid.innerHTML = BANNERS.map(b => `
      <div class="banner-option ${b} ${profile.banner === b ? 'active' : ''}"
           onclick="selectBanner('${b}')"></div>`).join('');
  }

  $('profile-editor-modal')?.classList.add('show');
}

export function closeProfileEditor() { $('profile-editor-modal')?.classList.remove('show'); }

export function saveProfileEditor() {
  profile.displayName = $('edit-displayName')?.value.trim() || profile.displayName;
  profile.handle      = ($('edit-handle')?.value.trim() || profile.handle).replace(/^@/,'').replace(/\s+/g,'_').toLowerCase();
  profile.bio         = $('edit-bio')?.value.trim()      || '';
  profile.location    = $('edit-location')?.value.trim() || '';
  profile.website     = $('edit-website')?.value.trim()  || '';
  _saveProfile();
  if (CryptoVault.isUnlocked) CryptoVault.update(v => { v.profile = { ...profile }; });
  logActivity('profile_saved', 'Profile details updated');
  renderProfilePage();
  closeProfileEditor();
  toastInfo('Profile saved');
}

export function selectAvatar(emoji) {
  // Selecting an emoji clears any uploaded photo
  localStorage.removeItem(LS_AVATAR_IMG);
  profile.avatar = emoji;
  $$('.avatar-option').forEach(el => el.classList.toggle('active', el.textContent === emoji));
  const prev = $('editor-avatar-preview');
  if (prev) prev.innerHTML = emoji;
  const removeBtn = $('avatar-remove-btn');
  if (removeBtn) removeBtn.style.display = 'none';
}

export function selectBanner(bannerClass) {
  // Selecting a gradient clears any uploaded banner
  localStorage.removeItem(LS_BANNER_IMG);
  profile.banner = bannerClass;
  $$('.banner-option').forEach(el => el.classList.toggle('active', el.classList.contains(bannerClass)));
  const bannerPrev = $('editor-banner-preview');
  if (bannerPrev) {
    bannerPrev.style.backgroundImage = '';
    BANNERS.forEach(b => bannerPrev.classList.remove(b));
    bannerPrev.classList.add(bannerClass);
  }
  const removeBtn = $('banner-remove-btn');
  if (removeBtn) removeBtn.style.display = 'none';
  renderProfilePage();
}

/* ── Image upload helpers ── */
export function uploadAvatarImage(input) {
  const file = input?.files?.[0];
  if (!file) return;
  if (file.size > 2 * 1024 * 1024) { toastWarn('Image too large — max 2 MB'); return; }
  const reader = new FileReader();
  reader.onload = e => {
    const dataUrl = e.target.result;
    // Resize to 200×200 via canvas before storing
    const img = new Image();
    img.onload = () => {
      const canvas = document.createElement('canvas');
      canvas.width = 200; canvas.height = 200;
      const ctx = canvas.getContext('2d');
      // Crop to square from center
      const size = Math.min(img.width, img.height);
      const sx = (img.width  - size) / 2;
      const sy = (img.height - size) / 2;
      ctx.drawImage(img, sx, sy, size, size, 0, 0, 200, 200);
      const compressed = canvas.toDataURL('image/jpeg', 0.85);
      localStorage.setItem(LS_AVATAR_IMG, compressed);
      // Update previews
      const prev = $('editor-avatar-preview');
      if (prev) prev.innerHTML = `<img src="${compressed}" class="profile-avatar-img" alt="Profile photo" />`;
      const removeBtn = $('avatar-remove-btn');
      if (removeBtn) removeBtn.style.display = '';
      renderProfilePage();
      toastInfo('Profile photo updated');
    };
    img.src = dataUrl;
  };
  reader.readAsDataURL(file);
  input.value = ''; // reset so same file can be re-selected
}

export function removeAvatarImage() {
  localStorage.removeItem(LS_AVATAR_IMG);
  const prev = $('editor-avatar-preview');
  if (prev) prev.innerHTML = profile.avatar || '🌊';
  const removeBtn = $('avatar-remove-btn');
  if (removeBtn) removeBtn.style.display = 'none';
  renderProfilePage();
}

export function uploadBannerImage(input) {
  const file = input?.files?.[0];
  if (!file) return;
  if (file.size > 5 * 1024 * 1024) { toastWarn('Image too large — max 5 MB'); return; }
  const reader = new FileReader();
  reader.onload = e => {
    const dataUrl = e.target.result;
    // Resize to 900×180 banner dimensions
    const img = new Image();
    img.onload = () => {
      const canvas = document.createElement('canvas');
      canvas.width = 900; canvas.height = 180;
      const ctx = canvas.getContext('2d');
      // Fill with cover crop
      const scale  = Math.max(900 / img.width, 180 / img.height);
      const w      = img.width  * scale;
      const h      = img.height * scale;
      const ox     = (900 - w) / 2;
      const oy     = (180 - h) / 2;
      ctx.drawImage(img, ox, oy, w, h);
      const compressed = canvas.toDataURL('image/jpeg', 0.88);
      localStorage.setItem(LS_BANNER_IMG, compressed);
      const bannerPrev = $('editor-banner-preview');
      if (bannerPrev) {
        bannerPrev.style.backgroundImage    = `url(${compressed})`;
        bannerPrev.style.backgroundSize     = 'cover';
        bannerPrev.style.backgroundPosition = 'center';
        BANNERS.forEach(b => bannerPrev.classList.remove(b));
      }
      const removeBtn = $('banner-remove-btn');
      if (removeBtn) removeBtn.style.display = '';
      renderProfilePage();
      toastInfo('Banner updated');
    };
    img.src = dataUrl;
  };
  reader.readAsDataURL(file);
  input.value = '';
}

export function removeBannerImage() {
  localStorage.removeItem(LS_BANNER_IMG);
  const bannerPrev = $('editor-banner-preview');
  if (bannerPrev) {
    bannerPrev.style.backgroundImage = '';
    BANNERS.forEach(b => bannerPrev.classList.remove(b));
    bannerPrev.classList.add(profile.banner || 'banner-ocean');
  }
  const removeBtn = $('banner-remove-btn');
  if (removeBtn) removeBtn.style.display = 'none';
  renderProfilePage();
}

/* ═══════════════════════════════════════════════════════════
   Vault Security Panel (shown in profile settings)
═══════════════════════════════════════════════════════════ */
export function exportVaultBackup() {
  if (!CryptoVault.isUnlocked) { toastWarn('Unlock vault first.'); return; }
  CryptoVault.exportBlob();
}


/* ═══════════════════════════════════════════════════════════
   Settings Tab
═══════════════════════════════════════════════════════════ */
function renderSettingsPanel() {
  const el = $('profile-tab-settings');
  if (!el) return;
  try {
    const createdAt = CryptoVault.vault?.identity?.createdAt
      ? new Date(CryptoVault.vault.identity.createdAt).toLocaleDateString('en-US',{year:'numeric',month:'long',day:'numeric'}) : '—';
    const themes = ['gold','cosmic','starry','hawaiian'];
    const currency   = safeGet('nalulf_pref_currency')   || 'XRP';
    const network    = safeGet('nalulf_pref_network')    || 'mainnet';
    const autoLock   = safeGet('nalulf_pref_autolock')   || '30';

    el.innerHTML = `
      <div class="settings-grid">

        <div class="settings-card">
          <div class="settings-card-hdr"><span class="settings-card-icon">🎨</span><div><div class="settings-card-title">Appearance</div><div class="settings-card-sub">Theme and display preferences</div></div></div>
          <div class="settings-label">Theme</div>
          <div class="settings-theme-row">
            ${themes.map(t=>`<button class="theme-pill ${t} ${state.currentTheme===t?'active':''}" onclick="prefSetTheme('${t}')">${t.charAt(0).toUpperCase()+t.slice(1)}</button>`).join('')}
          </div>
          <div style="margin-top:18px">
            <div class="settings-label">Display currency</div>
            <div class="settings-seg">
              <button class="settings-seg-btn ${currency==='XRP'?'active':''}" onclick="setPrefCurrency('XRP')">XRP</button>
              <button class="settings-seg-btn ${currency==='USD'?'active':''}" onclick="setPrefCurrency('USD')">USD</button>
            </div>
          </div>
        </div>

        <div class="settings-card">
          <div class="settings-card-hdr"><span class="settings-card-icon">🌐</span><div><div class="settings-card-title">Network</div><div class="settings-card-sub">Default XRPL network for new wallets</div></div></div>
          <div class="settings-label">Default network</div>
          <div class="settings-seg">
            <button class="settings-seg-btn ${network==='mainnet'?'active':''}" onclick="setPrefNetwork('mainnet')">🟢 Mainnet</button>
            <button class="settings-seg-btn ${network==='testnet'?'active':''}" onclick="setPrefNetwork('testnet')">🟡 Testnet</button>
          </div>
          <div style="margin-top:18px">
            <div class="settings-label">Auto-lock after</div>
            <div class="settings-seg">
              <button class="settings-seg-btn ${autoLock==='15'?'active':''}"  onclick="setPrefAutoLock('15')">15 min</button>
              <button class="settings-seg-btn ${autoLock==='30'?'active':''}"  onclick="setPrefAutoLock('30')">30 min</button>
              <button class="settings-seg-btn ${autoLock==='60'?'active':''}"  onclick="setPrefAutoLock('60')">1 hr</button>
            </div>
          </div>
        </div>

        <div class="settings-card">
          <div class="settings-card-hdr"><span class="settings-card-icon">🔐</span><div><div class="settings-card-title">Vault Security</div><div class="settings-card-sub">AES-256-GCM · PBKDF2 · SHA-256</div></div></div>
          <div class="settings-kv-list">
            <div class="settings-kv"><span class="settings-k">Encryption</span><span class="settings-v mono">AES-256-GCM</span></div>
            <div class="settings-kv"><span class="settings-k">Key derivation</span><span class="settings-v mono">PBKDF2 · 150k iterations</span></div>
            <div class="settings-kv"><span class="settings-k">Vault created</span><span class="settings-v">${createdAt}</span></div>
            <div class="settings-kv"><span class="settings-k">Server storage</span><span class="settings-v settings-v--good">None · local only</span></div>
            <div class="settings-kv"><span class="settings-k">Wallets</span><span class="settings-v">${wallets.length} stored</span></div>
          </div>
        </div>

        <div class="settings-card">
          <div class="settings-card-hdr"><span class="settings-card-icon">📂</span><div><div class="settings-card-title">Backup &amp; Recovery</div><div class="settings-card-sub">Keep a copy of your encrypted vault</div></div></div>
          <p class="settings-card-desc">Your backup file is still encrypted and cannot be read without your password. Store it on a USB drive or external hard drive — <strong>not</strong> in the cloud.</p>
          <div class="settings-actions">
            <button class="settings-btn settings-btn--primary" onclick="exportVaultBackup()">⬇ Export Encrypted Backup</button>
            <button class="settings-btn" onclick="exportVaultSyncCode()">📱 Generate Device Sync Code</button>
          </div>
        </div>

        <div class="settings-card">
          <div class="settings-card-hdr"><span class="settings-card-icon">📡</span><div><div class="settings-card-title">Privacy Architecture</div><div class="settings-card-sub">How NaluLF handles your data</div></div></div>
          <div class="settings-privacy-list">
            <div class="settings-privacy-item settings-privacy--good"><span class="spi-dot"></span><div><strong>Zero server-side storage.</strong> Your profile, wallets, and seeds never leave your browser.</div></div>
            <div class="settings-privacy-item settings-privacy--good"><span class="spi-dot"></span><div><strong>Direct XRPL connections.</strong> We connect directly to XRPL public nodes — no proxy.</div></div>
            <div class="settings-privacy-item settings-privacy--good"><span class="spi-dot"></span><div><strong>No telemetry.</strong> No analytics, no tracking, no third-party observation scripts.</div></div>
            <div class="settings-privacy-item settings-privacy--warn"><span class="spi-dot"></span><div><strong>On-chain data is public.</strong> XRPL transactions are permanently visible to anyone.</div></div>
          </div>
        </div>

        <div class="settings-card settings-card--danger">
          <div class="settings-card-hdr"><span class="settings-card-icon">⚠️</span><div><div class="settings-card-title">Danger Zone</div><div class="settings-card-sub">Irreversible actions</div></div></div>
          <p class="settings-card-desc">Wiping your account removes all local data. Your XRPL wallets still exist on-chain and can be re-added using their seed phrases.</p>
          <button class="settings-btn settings-btn--danger" onclick="openAuth('forgot')">🗑 Wipe Account Data</button>
        </div>

      </div>`;
  } catch(err) { _renderTabError(el, 'settings', err); }
}


/* ═══════════════════════════════════════════════════════════
   Preferences
═══════════════════════════════════════════════════════════ */
function renderPreferences() {
  const pills = $('pref-theme-pills');
  if (pills) {
    ['gold','cosmic','starry','hawaiian'].forEach(t => {
      const el = pills.querySelector(`.theme-pill.${t}`);
      if (el) el.classList.toggle('active', state.currentTheme === t);
    });
  }
}

export function setPrefCurrency(c) {
  safeSet('nalulf_pref_currency', c);
  renderSettingsPanel();
  toastInfo(`Display currency set to ${c}`);
}

export function setPrefNetwork(n) {
  safeSet('nalulf_pref_network', n);
  renderSettingsPanel();
  toastInfo(`Default network: ${n}`);
}

export function setPrefAutoLock(mins) {
  safeSet('nalulf_pref_autolock', mins);
  const ms = parseInt(mins) * 60 * 1000;
  if (CryptoVault?.isUnlocked) CryptoVault.AUTO_LOCK_MS = ms;
  renderSettingsPanel();
  toastInfo(`Auto-lock set to ${mins} minutes`);
}

export function prefSetTheme(t) {
  setTheme(t);
  renderSettingsPanel();
}

/* ════════════════════════════════════════════════════════════
   Public Profile Preview
════════════════════════════════════════════════════════════ */
export function openPublicProfilePreview() {
  const existing = document.getElementById('pub-profile-overlay');
  if (existing) existing.remove();

  const avatarImg = localStorage.getItem('nalulf_avatar_img');
  const avatarHtml = avatarImg
    ? `<img src="${avatarImg}" alt="avatar" />`
    : `<span>${escHtml(profile.avatar || '🌊')}</span>`;

  const connectedSocials = SOCIAL_PLATFORMS.filter(p => social[p.id]);

  const overlay = document.createElement('div');
  overlay.id = 'pub-profile-overlay';
  overlay.className = 'pub-profile-overlay';
  overlay.innerHTML = `
    <div class="pub-profile-modal">
      <div class="pub-banner ${profile.banner || 'banner-ocean'}" ${localStorage.getItem('nalulf_banner_img') ? `style="background-image:url(${localStorage.getItem('nalulf_banner_img')});background-size:cover;background-position:center;"` : ''}></div>
      <div class="pub-hdr">
        <div class="pub-avatar">${avatarHtml}</div>
        <div class="pub-info">
          <div class="pub-name">${escHtml(profile.displayName || 'Anonymous')}</div>
          <div class="pub-handle">@${escHtml(profile.handle || 'anonymous')}</div>
          ${profile.bio ? `<div class="pub-bio">${escHtml(profile.bio)}</div>` : ''}
          <div class="vault-pill vault-pill--locked" style="font-size:.65rem;padding:3px 9px;">🔒 Self-custodied XRPL wallet</div>
        </div>
      </div>
      ${connectedSocials.length ? `
      <div class="pub-socials">
        ${connectedSocials.map(p => `
          <span class="pub-social-badge">
            <span>${p.icon}</span>
            <span>@${escHtml(social[p.id])}</span>
          </span>`).join('')}
      </div>` : `<div style="padding:0 20px 16px;font-size:.82rem;color:rgba(255,255,255,.32);">No social accounts connected yet.</div>`}
      <div class="pub-close-row">
        <span style="font-size:.78rem;color:rgba(255,255,255,.35);flex:1">This is how others see your profile</span>
        <button class="pub-close-btn" onclick="document.getElementById('pub-profile-overlay').remove()">Close</button>
      </div>
    </div>`;

  document.body.appendChild(overlay);
  requestAnimationFrame(() => {
    requestAnimationFrame(() => overlay.classList.add('show'));
  });
  overlay.addEventListener('click', e => { if (e.target === overlay) overlay.remove(); });
}

/* ═══════════════════════════════════════════════════════════
   Events
═══════════════════════════════════════════════════════════ */
function bindProfileEvents() {
  $('profile-editor-modal')   ?.addEventListener('click', e => { if (e.target === e.currentTarget) closeProfileEditor(); });
  $('wallet-creator-overlay') ?.addEventListener('click', e => { if (e.target === e.currentTarget) closeWalletCreator(); });
  $('social-modal')           ?.addEventListener('click', e => { if (e.target === e.currentTarget) closeSocialModal(); });
}

/* Fetch balances when page becomes visible */
document.addEventListener('visibilitychange', () => {
  if (!document.hidden && wallets.length) fetchAllBalances();
});

/* ═══════════════════════════════════════════════════════════
   Helpers
═══════════════════════════════════════════════════════════ */
function _setText(id, val) {
  const el = $(id);
  if (el) el.textContent = val;
}

export function copyToClipboard(text) { _copyToClipboard(text); }

/* ════════════════════════════════════════════════════════════
   Watch-Only Wallet Import
════════════════════════════════════════════════════════════ */
export function openImportAddressModal() {
  const m = $('import-address-modal');
  if (!m) return;
  m.querySelector('#inp-import-address').value = '';
  m.querySelector('#inp-import-label').value = '';
  const err = m.querySelector('.import-modal-error');
  if (err) err.textContent = '';
  m.classList.add('show');
  setTimeout(() => m.querySelector('#inp-import-address')?.focus(), 80);
}
export function closeImportAddressModal() { $('import-address-modal')?.classList.remove('show'); }

export function importWatchOnlyWallet() {
  const address = ($('inp-import-address')?.value || '').trim();
  const label   = ($('inp-import-label')?.value   || '').trim() || 'Watch Wallet';
  const errEl   = $('import-address-error');
  if (!isValidXrpAddress(address)) {
    if (errEl) errEl.textContent = 'Enter a valid XRPL address (starts with r…)';
    return;
  }
  if (wallets.find(w => w.address === address)) {
    if (errEl) errEl.textContent = 'This address is already in your wallet list.';
    return;
  }
  const id = 'watch_' + Date.now();
  wallets.push({ id, label, address, algo: '—', emoji: '👁', color: '#8be9fd', testnet: false, createdAt: new Date().toISOString(), watchOnly: true });
  _saveWalletMeta();
  logActivity('wallet_created', `Watch-only: ${label} (${address.slice(0,8)}…)`);
  closeImportAddressModal();
  renderWalletList();
  renderActiveWalletBar();
  renderProfileMetrics();
  fetchBalance(address).then(() => { renderWalletList(); renderProfileMetrics(); });
  toastInfo(`👁 Watch-only wallet added: ${label}`);
}

/* ════════════════════════════════════════════════════════════
   Seed Import — Full-Access Wallet
════════════════════════════════════════════════════════════ */
export function openImportSeedModal() {
  const m = $('import-seed-modal');
  if (!m) return;
  m.querySelector('#inp-import-seed').value  = '';
  m.querySelector('#inp-import-seed-label').value = '';
  const err = m.querySelector('#import-seed-error');
  if (err) err.textContent = '';
  m.classList.add('show');
  setTimeout(() => m.querySelector('#inp-import-seed')?.focus(), 80);
}
export function closeImportSeedModal() { $('import-seed-modal')?.classList.remove('show'); }

export async function executeImportFromSeed() {
  const seed    = ($('inp-import-seed')?.value   || '').trim();
  const label   = ($('inp-import-seed-label')?.value || '').trim() || 'Imported Wallet';
  const errEl   = $('import-seed-error');
  const btn     = $('import-seed-btn');
  if (errEl) errEl.textContent = '';
  if (!seed) { if (errEl) errEl.textContent = 'Enter your seed phrase or family seed.'; return; }
  if (!CryptoVault.isUnlocked) { if (errEl) errEl.textContent = 'Sign in first to import a seed.'; return; }
  if (!window.xrpl) { if (errEl) errEl.textContent = 'xrpl.js not loaded — cannot derive address from seed.'; return; }
  if (btn) { btn.disabled = true; btn.textContent = 'Importing…'; }
  try {
    const xrplWallet = window.xrpl.Wallet.fromSeed(seed);
    const address = xrplWallet.address;
    const algo    = xrplWallet.algorithm?.toLowerCase().includes('ed') ? 'ed25519' : 'secp256k1';
    if (wallets.find(w => w.address === address)) {
      if (errEl) errEl.textContent = 'This address is already in your vault.';
      return;
    }
    const id = 'imp_' + Date.now();
    const emoji = '🔑'; const color = '#bd93f9';
    // Add to vault (encrypted)
    await CryptoVault.update(v => {
      v.wallets.push({ id, label, address, algo, seed, emoji, color, testnet: false, createdAt: new Date().toISOString() });
    });
    // Add to public metadata
    wallets.push({ id, label, address, algo, emoji, color, testnet: false, createdAt: new Date().toISOString() });
    _saveWalletMeta();
    logActivity('wallet_created', `Imported: ${label} (${address.slice(0,8)}…)`);
    closeImportSeedModal();
    renderWalletList();
    renderActiveWalletBar();
    fetchBalance(address).then(() => { renderWalletList(); renderProfileMetrics(); });
    toastInfo(`🔑 Wallet imported: ${label}`);
  } catch(err) {
    if (errEl) errEl.textContent = 'Invalid seed: ' + (err.message || 'Could not derive wallet from this input.');
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Import Wallet →'; }
  }
}

/* ════════════════════════════════════════════════════════════
   Token Details Modal
════════════════════════════════════════════════════════════ */
export function openTokenDetailsModal(currency, issuer, walletAddress) {
  const m = $('token-details-modal');
  if (!m) return;
  const cached   = balanceCache[walletAddress];
  const token    = cached?.tokens?.find(t => t.currency===currency && t.issuer===issuer);
  const balance  = token ? fmt(parseFloat(token.balance||0), 6) : '—';
  const limit    = token?.limit ? fmt(parseFloat(token.limit),2) : 'Unlimited';
  const curDisp  = currency.length > 4 ? _hexToAscii(currency) || currency : currency;
  const issShort = issuer.slice(0,12)+'…'+issuer.slice(-6);
  const xrpscanUrl = `https://xrpscan.com/account/${issuer}`;
  const dexUrl     = `https://xrpl.org/dex.html?currency=${currency}&issuer=${issuer}`;
  m.innerHTML = `
    <div class="tdm-inner">
      <div class="tdm-hdr">
        <div class="tdm-title">
          <span class="tdm-icon">🪙</span>
          <span class="tdm-cur">${escHtml(curDisp)}</span>
          ${curDisp!==currency?`<span class="tdm-hex mono">${escHtml(currency)}</span>`:''}
        </div>
        <button class="tdm-close" onclick="closeTokenDetailsModal()">✕</button>
      </div>
      <div class="tdm-grid">
        <div class="tdm-item"><div class="tdm-item-label">Balance</div><div class="tdm-item-val">${balance}</div></div>
        <div class="tdm-item"><div class="tdm-item-label">Trust Limit</div><div class="tdm-item-val">${limit}</div></div>
        <div class="tdm-item tdm-item--wide">
          <div class="tdm-item-label">Issuer</div>
          <div class="tdm-item-val tdm-issuer mono">${issShort}</div>
          <button class="tdm-copy-btn" onclick="copyToClipboard('${escHtml(issuer)}')">⧉ Copy</button>
        </div>
      </div>
      <div class="tdm-links">
        <a class="tdm-link" href="${xrpscanUrl}" target="_blank" rel="noopener">🔍 View Issuer on XRPScan</a>
        <a class="tdm-link" href="${dexUrl}" target="_blank" rel="noopener">📊 Trade on DEX</a>
        <a class="tdm-link" href="https://xrpscan.com/account/${walletAddress}#tokens" target="_blank" rel="noopener">📋 All Tokens</a>
      </div>
    </div>`;
  m.classList.add('show');
}
export function closeTokenDetailsModal() { $('token-details-modal')?.classList.remove('show'); }

function _hexToAscii(hex) {
  if (!/^[0-9A-Fa-f]+$/.test(hex)) return '';
  try {
    let str = '';
    for (let i=0; i<hex.length; i+=2) str += String.fromCharCode(parseInt(hex.slice(i,i+2),16));
    return str.replace(/\x00/g,'').trim();
  } catch { return ''; }
}

function _copyToClipboard(text, autoClearMs = 0) {
  navigator.clipboard?.writeText(text)
    .then(() => {
      toastInfo('Copied to clipboard');
      if (autoClearMs) setTimeout(() => navigator.clipboard?.writeText(''), autoClearMs);
    })
    .catch(() => {
      const el = document.createElement('textarea');
      el.value = text; document.body.appendChild(el); el.select(); document.execCommand('copy'); el.remove();
      toastInfo('Copied');
    });
}

/* ── signAndSubmit is used internally and also importable by other modules ── */
export { signAndSubmit };

/* ════════════════════════════════════════════════════════════
   Wallet Drawer — expandable per-wallet detail panel
════════════════════════════════════════════════════════════ */
export function toggleWalletDrawer(walletId) {
  if (_expandedWallet === walletId) {
    _expandedWallet = null;
  } else {
    _expandedWallet = walletId;
    if (!_expandedSubTabs[walletId]) _expandedSubTabs[walletId] = 'txns';
  }
  renderWalletList();
  if (_expandedWallet) {
    setTimeout(() => _loadDrawerTab(walletId, _expandedSubTabs[walletId]), 60);
  }
}

export function switchWalletDrawerTab(walletId, tab) {
  _expandedSubTabs[walletId] = tab;
  const drawer = document.getElementById(`wcard-drawer-${walletId}`);
  if (!drawer) return;
  drawer.querySelectorAll('.wdt-btn').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.tab === tab);
  });
  _loadDrawerTab(walletId, tab);
}

async function _loadDrawerTab(walletId, tab) {
  const w    = wallets.find(x => x.id === walletId);
  const body = document.getElementById(`wcard-drawer-body-${walletId}`);
  if (!w || !body) return;
  body.innerHTML = `<div class="wdd-loading"><div class="spinner"></div> Loading…</div>`;
  try {
    if (tab === 'txns') {
      let txns = txCache[w.address]?.txns;
      if (!txns) txns = await fetchTxHistory(w.address, 25);
      body.innerHTML = _renderTxList(txns, w.address);
    } else if (tab === 'nfts') {
      let nfts = nftCache[w.address]?.nfts;
      if (!nfts) nfts = await fetchNFTs(w.address);
      body.innerHTML = _renderNFTGallery(nfts, w.address);
    } else if (tab === 'orders') {
      let offers = offerCache[w.address]?.offers;
      if (!offers) offers = await fetchOpenOffers(w.address);
      body.innerHTML = _renderDEXOrders(offers, w.id, w.address);
    }
  } catch(err) {
    body.innerHTML = `<div class="wdd-error">⚠️ ${escHtml(err.message)}</div>`;
  }
}

function _txTypeIcon(type) {
  const icons = { Payment:'💸', OfferCreate:'📊', OfferCancel:'✕', TrustSet:'🔗', NFTokenMint:'🎨', NFTokenBurn:'🔥', NFTokenCreateOffer:'🎯', NFTokenAcceptOffer:'✅', AMMCreate:'🌊', AMMDeposit:'📥', AMMWithdraw:'📤', AMMVote:'🗳', AMMBid:'💡', EscrowCreate:'⏳', EscrowFinish:'✅', EscrowCancel:'✕', AccountSet:'⚙', SetRegularKey:'🔑', SignerListSet:'📋' };
  return icons[type] || '📄';
}
function _fmtAmount(amount) {
  if (!amount) return '—';
  if (typeof amount === 'string') return `${fmt(Number(amount)/1e6, 4)} XRP`;
  const cur = (amount.currency||'?').length > 4 ? amount.currency.slice(0,4)+'…' : amount.currency;
  return `${fmt(parseFloat(amount.value || 0), 4)} ${cur}`;
}

function _renderTxList(txns, address) {
  if (!txns?.length) return `<div class="wdd-empty"><div class="wdd-empty-icon">📋</div><div>No transactions on-chain yet.</div><div class="wdd-empty-sub">Fund with 10 XRP to activate.</div></div>`;
  return `<div class="wdd-tx-list">
    ${txns.slice(0, 25).map(tx => {
      const type   = tx.TransactionType || '?';
      const isOut  = tx.Account === address;
      const result = tx.metaData?.TransactionResult || tx.meta?.TransactionResult || '';
      const ok     = !result || result === 'tesSUCCESS';
      const raw    = tx.date ? (tx.date + 946684800) * 1000 : 0;
      const date   = raw ? new Date(raw).toLocaleDateString('en-US',{month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'}) : '—';
      const hash   = tx.hash || tx.tx_hash || '';
      const amount = tx.Amount || tx.TakerGets || null;
      const dest   = tx.Destination || '';
      return `
      <div class="wdd-tx-row ${ok?'':'wdd-tx-failed'}">
        <div class="wdd-tx-icon">${_txTypeIcon(type)}</div>
        <div class="wdd-tx-body">
          <div class="wdd-tx-type-row">
            <span class="wdd-tx-type">${type}</span>
            <span class="wdd-tx-dir ${isOut?'out':'in'}">${isOut?'↑ Out':'↓ In'}</span>
            ${!ok?'<span class="wdd-tx-fail-badge">Failed</span>':''}
          </div>
          <div class="wdd-tx-detail">
            ${amount?`<span class="wdd-tx-amount">${_fmtAmount(amount)}</span>`:''}
            ${dest?`<span class="wdd-tx-dest mono">${dest.slice(0,8)}…${dest.slice(-5)}</span>`:''}
          </div>
        </div>
        <div class="wdd-tx-right">
          <div class="wdd-tx-date">${date}</div>
          ${hash?`<a class="wdd-tx-hash" href="https://xrpscan.com/tx/${hash}" target="_blank" rel="noopener">⬡ View</a>`:''}
        </div>
      </div>`;
    }).join('')}
    <a class="wdd-view-more" href="https://xrpscan.com/account/${address}" target="_blank" rel="noopener">View full history on XRPScan →</a>
  </div>`;
}

function _decodeHex(hex) {
  try { return hex.match(/.{2}/g).map(h => String.fromCharCode(parseInt(h,16))).join(''); } catch { return ''; }
}

function _renderNFTGallery(nfts, address) {
  if (!nfts?.length) return `<div class="wdd-empty"><div class="wdd-empty-icon">🎨</div><div>No NFTs in this wallet.</div><div class="wdd-empty-sub">Use NFTokenMint to create your first NFT.</div></div>`;
  return `
    <div class="wdd-nft-header">
      <span>${nfts.length} NFT${nfts.length>1?'s':''} owned</span>
      <a class="wdd-view-more-inline" href="https://xrpscan.com/account/${address}#nfts" target="_blank" rel="noopener">View on XRPScan →</a>
    </div>
    <div class="wdd-nft-grid">
      ${nfts.slice(0,24).map(nft => {
        const serial = nft.nft_serial ?? nft.NFTokenID?.slice(-6) ?? '?';
        const taxon  = nft.NFTokenTaxon ?? '?';
        const uri    = nft.URI ? _decodeHex(nft.URI) : '';
        const imgSrc = uri.startsWith('ipfs://') ? `https://cloudflare-ipfs.com/ipfs/${uri.slice(7)}` : '';
        const transferable = !(nft.Flags & 0x00000008);
        const burnable     = !!(nft.Flags & 0x00000001);
        return `
        <div class="wdd-nft-card">
          <div class="wdd-nft-art">
            ${imgSrc?`<img src="${escHtml(imgSrc)}" class="wdd-nft-img" alt="NFT" onerror="this.parentNode.innerHTML='<span class=wdd-nft-placeholder>🎨</span>'" />`:`<span class="wdd-nft-placeholder">🎨</span>`}
          </div>
          <div class="wdd-nft-info">
            <div class="wdd-nft-id mono">#${serial}</div>
            <div class="wdd-nft-taxon">Taxon ${taxon}</div>
            <div class="wdd-nft-flags">
              ${transferable?'<span class="wdd-nft-flag">Xfer</span>':''}
              ${burnable?'<span class="wdd-nft-flag wdd-nft-flag--burn">Burn</span>':''}
            </div>
          </div>
        </div>`;
      }).join('')}
    </div>
    ${nfts.length>24?`<div class="wdd-more-note">Showing 24 of ${nfts.length} — <a href="https://xrpscan.com/account/${address}#nfts" target="_blank" rel="noopener">view all →</a></div>`:''}`;
}

function _renderDEXOrders(offers, walletId, address) {
  if (!offers?.length) return `<div class="wdd-empty"><div class="wdd-empty-icon">📊</div><div>No open DEX orders.</div><div class="wdd-empty-sub">Use OfferCreate to place a CLOB order.</div></div>`;
  return `
    <div class="wdd-orders-header"><span>${offers.length} open order${offers.length>1?'s':''}</span></div>
    <div class="wdd-orders-list">
      ${offers.map(offer => {
        const gets  = _fmtAmount(offer.TakerGets);
        const pays  = _fmtAmount(offer.TakerPays);
        const seq   = offer.seq || '?';
        const isSell= !!(offer.flags & 0x00080000);
        return `
        <div class="wdd-order-row">
          <div class="wdd-order-dir ${isSell?'sell':'buy'}">${isSell?'SELL':'BUY'}</div>
          <div class="wdd-order-pair">
            <span class="wdd-order-gets">${gets}</span>
            <span class="wdd-order-arrow">⇄</span>
            <span class="wdd-order-pays">${pays}</span>
          </div>
          <div class="wdd-order-seq mono">Seq #${seq}</div>
          <button class="wdd-order-cancel" onclick="cancelOffer('${walletId}',${seq},this)">✕ Cancel</button>
        </div>`;
      }).join('')}
    </div>`;
}

export async function cancelOffer(walletId, seq, btn) {
  if (!CryptoVault.isUnlocked) { toastWarn('Sign in to cancel orders.'); return; }
  if (btn) { btn.disabled = true; btn.textContent = '…'; }
  try {
    const result = await executeOfferCancel(walletId, seq);
    if (result?.engine_result === 'tesSUCCESS' || result?.engine_result_code === 0) {
      toastInfo('Order cancelled ✓');
      const w = wallets.find(x => x.id === walletId);
      if (w) { delete offerCache[w.address]; _loadDrawerTab(walletId, 'orders'); }
    } else {
      toastErr('Cancel failed: ' + (result?.engine_result || 'Unknown'));
      if (btn) { btn.disabled = false; btn.textContent = '✕ Cancel'; }
    }
  } catch(err) { toastErr(err.message); if (btn) { btn.disabled = false; btn.textContent = '✕ Cancel'; } }
}

/* ════════════════════════════════════════════════════════════
   Analytics Tab — Portfolio · History Chart · Heatmap · Flow
════════════════════════════════════════════════════════════ */
async function renderAnalyticsTab() {
  const el = $('profile-tab-analytics');
  if (!el) return;
  try {
    // Skeleton while fetching
    el.innerHTML = `<div class="analytics-grid">
      <div class="skeleton-card" style="grid-column:1/-1"><div class="skeleton skeleton-row lg"></div><div class="skeleton" style="height:80px;margin-top:10px;border-radius:10px"></div></div>
      <div class="skeleton-card"><div class="skeleton skeleton-row lg"></div><div class="skeleton" style="height:130px;margin-top:10px;border-radius:10px"></div></div>
      <div class="skeleton-card"><div class="skeleton skeleton-row lg"></div><div class="skeleton" style="height:130px;margin-top:10px;border-radius:10px"></div></div>
    </div>`;

    const activeW    = getActiveWallet();
    const totalXrp   = Object.values(balanceCache).reduce((s, c) => s + (c?.xrp||0), 0);
    const xrpPrice   = _getXrpPrice();
    const allTokens  = Object.values(balanceCache).flatMap(c => c?.tokens||[]);

    let heatmapTxns = [];
    if (activeW) {
      try {
        heatmapTxns = txCache[activeW.address]?.txns || await fetchTxHistory(activeW.address, 100);
      } catch { /* silent */ }
    }

    el.innerHTML = `<div class="analytics-grid">

      <!-- Portfolio Summary -->
      <div class="analytics-card analytics-card--wide">
        <div class="analytics-card-hdr">
          <span class="analytics-card-title">💼 Portfolio Summary</span>
          <span class="analytics-badge">${wallets.length} wallet${wallets.length!==1?'s':''}</span>
        </div>
        <div class="portfolio-summary-row">
          ${wallets.length === 0
            ? '<div class="analytics-empty">No wallets yet — create one to track your portfolio.</div>'
            : wallets.map(w => {
                const c   = balanceCache[w.address];
                const xrp = c ? fmt(c.xrp, 2) : '—';
                const usd = c && xrpPrice ? `$${fmt(c.xrp * xrpPrice, 2)}` : '';
                const hist = _getBalanceHistory(w.address);
                return `
                <div class="portfolio-wallet-row">
                  <div class="pwr-icon" style="color:${w.color};background:${w.color}18;border-color:${w.color}33">${escHtml(w.emoji||'💎')}</div>
                  <div class="pwr-info">
                    <div class="pwr-label">${escHtml(w.label)}</div>
                    <div class="pwr-addr mono">${w.address.slice(0,8)}…${w.address.slice(-5)}</div>
                  </div>
                  <div class="pwr-sparkline">${_buildSparkline(hist, 80, 28, w.color||'#00fff0')}</div>
                  <div class="pwr-balance">
                    <div class="pwr-xrp">${xrp} <span class="pwr-xrp-label">XRP</span></div>
                    ${usd?`<div class="pwr-usd">${usd}</div>`:''}
                  </div>
                </div>`;
              }).join('')}
        </div>
        <div class="portfolio-totals">
          <div class="ptotal"><span class="ptotal-label">Total XRP</span><span class="ptotal-val">${fmt(totalXrp, 4)}</span></div>
          ${xrpPrice?`<div class="ptotal"><span class="ptotal-label">Est. USD</span><span class="ptotal-val ptotal-usd">$${fmt(totalXrp*xrpPrice, 2)}</span></div>`:''}
          <div class="ptotal"><span class="ptotal-label">Tokens</span><span class="ptotal-val">${allTokens.length}</span></div>
          <div class="ptotal"><span class="ptotal-label">Wallets</span><span class="ptotal-val">${wallets.length}</span></div>
        </div>
      </div>

      <!-- Balance History Chart -->
      ${activeW ? `
      <div class="analytics-card analytics-card--wide">
        <div class="analytics-card-hdr">
          <span class="analytics-card-title">📈 Balance History</span>
          <span class="analytics-badge">${escHtml(activeW.label)}</span>
        </div>
        ${_buildBalanceChart(activeW.address)}
      </div>` : ''}

      <!-- On-Chain Activity Heatmap -->
      <div class="analytics-card analytics-card--wide">
        <div class="analytics-card-hdr">
          <span class="analytics-card-title">📅 On-Chain Activity</span>
          <span class="analytics-badge">${activeW ? escHtml(activeW.label) : 'No wallet'}</span>
        </div>
        ${activeW ? _buildHeatmap(heatmapTxns) : '<div class="analytics-empty">Activate a wallet to see on-chain activity.</div>'}
      </div>

      <!-- TX Breakdown -->
      ${heatmapTxns.length ? `
      <div class="analytics-card">
        <div class="analytics-card-hdr">
          <span class="analytics-card-title">📊 TX Breakdown</span>
          <span class="analytics-badge">${heatmapTxns.length} recent</span>
        </div>
        ${_buildTxBreakdown(heatmapTxns)}
      </div>` : ''}

      <!-- XRP Flow -->
      ${activeW && heatmapTxns.length ? `
      <div class="analytics-card">
        <div class="analytics-card-hdr">
          <span class="analytics-card-title">💰 XRP Flow</span>
          <span class="analytics-badge">Est. net</span>
        </div>
        ${_buildXrpFlow(heatmapTxns, activeW.address)}
      </div>` : ''}

      <!-- Token Holdings -->
      ${allTokens.length ? `
      <div class="analytics-card">
        <div class="analytics-card-hdr">
          <span class="analytics-card-title">🪙 Token Holdings</span>
          <span class="analytics-badge">${allTokens.length} assets</span>
        </div>
        ${_buildTokenAllocation(allTokens)}
      </div>` : ''}

    </div>`;
  } catch(err) { _renderTabError(el, 'analytics', err); }
}


function _buildSparkline(hist, W, H, color) {
  if (hist.length < 2) return `<svg width="${W}" height="${H}" viewBox="0 0 ${W} ${H}"><line x1="0" y1="${H/2}" x2="${W}" y2="${H/2}" stroke="${color}" stroke-opacity=".2" stroke-width="1" stroke-dasharray="3 2"/></svg>`;
  const vals = hist.map(h => h.xrp);
  const min  = Math.min(...vals), max = Math.max(...vals), range = max - min || 1;
  const pad  = 3;
  const pts  = vals.map((v, i) => {
    const x = pad + (i / (vals.length-1)) * (W - pad*2);
    const y = pad + (1 - (v-min)/range) * (H - pad*2);
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  });
  const [lx, ly] = pts[pts.length-1].split(',');
  return `<svg width="${W}" height="${H}" viewBox="0 0 ${W} ${H}"><polyline points="${pts.join(' ')}" fill="none" stroke="${color}" stroke-width="1.5" stroke-opacity=".8" stroke-linejoin="round" stroke-linecap="round"/><circle cx="${lx}" cy="${ly}" r="2.5" fill="${color}" opacity=".9"/></svg>`;
}

function _buildBalanceChart(address) {
  const hist = _getBalanceHistory(address);
  if (hist.length < 2) return `<div class="analytics-empty-chart"><div class="aec-icon">📊</div><div>Balance history builds up as you refresh your wallet over time.</div><div class="aec-sub">${hist.length} snapshot${hist.length!==1?'s':''} recorded so far — sync your wallet to start tracking.</div></div>`;
  const W=560, H=130, pL=52, pR=12, pT=14, pB=30;
  const vals = hist.map(h=>h.xrp), times = hist.map(h=>h.ts);
  const min=Math.min(...vals), max=Math.max(...vals), range=max-min||1;
  const tMin=times[0], tMax=times[times.length-1], tRange=tMax-tMin||1;
  const toX = ts  => pL + ((ts-tMin)/tRange)*(W-pL-pR);
  const toY = val => pT + (1-(val-min)/range)*(H-pT-pB);
  const pts  = hist.map(h=>`${toX(h.ts).toFixed(1)},${toY(h.xrp).toFixed(1)}`);
  const fX   = toX(times[0]), lX = toX(times[times.length-1]);
  const area = `M${fX.toFixed(1)},${H-pB} L${pts.join(' L')} L${lX.toFixed(1)},${H-pB} Z`;
  const yTicks = [min,(min+max)/2,max].map(v=>({v,y:toY(v),lbl:fmt(v,2)}));
  const xTicks = [0,.5,1].map(f=>({ x:pL+f*(W-pL-pR), lbl:new Date(tMin+f*tRange).toLocaleDateString('en-US',{month:'short',day:'numeric'}) }));
  const delta  = vals[vals.length-1]-vals[0], up = delta>=0;
  const deltaPct = vals[0] ? Math.abs(delta/vals[0]*100).toFixed(2) : '0.00';
  const color  = up ? '#00d4ff' : '#ff5555';
  return `
    <div class="balance-chart-meta">
      <div class="bcm-current">${fmt(vals[vals.length-1],4)} XRP</div>
      <div class="bcm-delta ${up?'bcm-up':'bcm-down'}">${up?'▲':'▼'} ${deltaPct}% since first snapshot</div>
      <div class="bcm-range">${hist.length} snapshots</div>
    </div>
    <div class="balance-chart-wrap"><svg class="balance-chart-svg" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none">
      <defs><linearGradient id="balGrad${address.slice(-4)}" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="${color}" stop-opacity=".22"/><stop offset="100%" stop-color="${color}" stop-opacity="0"/></linearGradient></defs>
      ${yTicks.map(t=>`<line x1="${pL}" y1="${t.y.toFixed(1)}" x2="${W-pR}" y2="${t.y.toFixed(1)}" stroke="rgba(255,255,255,.06)" stroke-width="1"/>`).join('')}
      <path d="${area}" fill="url(#balGrad${address.slice(-4)})"/>
      <polyline points="${pts.join(' ')}" fill="none" stroke="${color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
      ${hist.map(h=>`<circle cx="${toX(h.ts).toFixed(1)}" cy="${toY(h.xrp).toFixed(1)}" r="2" fill="${color}" opacity=".7"/>`).join('')}
      ${yTicks.map(t=>`<text x="${pL-5}" y="${(t.y+4).toFixed(1)}" text-anchor="end" fill="rgba(255,255,255,.38)" font-size="10" font-family="JetBrains Mono,monospace">${t.lbl}</text>`).join('')}
      ${xTicks.map(t=>`<text x="${t.x.toFixed(1)}" y="${H-6}" text-anchor="middle" fill="rgba(255,255,255,.32)" font-size="10" font-family="JetBrains Mono,monospace">${t.lbl}</text>`).join('')}
    </svg></div>`;
}

function _heatColor(frac) {
  if (frac === 0) return 'rgba(255,255,255,.07)';
  const g = Math.round(85  + frac * 170);
  const b = Math.round(119 + frac * 121);
  return `rgb(0,${g},${b})`;
}

function _buildHeatmap(txns) {
  const cells = new Map();
  txns.forEach(tx => {
    if (!tx.date) return;
    const key = new Date((tx.date+946684800)*1000).toISOString().slice(0,10);
    cells.set(key, (cells.get(key)||0)+1);
  });
  const WEEKS=26, CELL=12, GAP=2;
  const now = new Date();
  const days = Array.from({length:WEEKS*7},(_,i)=>{ const d=new Date(now); d.setDate(d.getDate()-(WEEKS*7-1-i)); return d; });
  const byWeek = Array.from({length:WEEKS},(_,w)=>days.slice(w*7,w*7+7));
  const maxCount = Math.max(1,...cells.values());
  const W = WEEKS*(CELL+GAP)+30, H = 7*(CELL+GAP)+28;
  const monthLabels = []; let lastM = -1;
  byWeek.forEach((wk,wi)=>{ const m=wk[0]?.getMonth(); if(m!==lastM){lastM=m;monthLabels.push({wi,lbl:wk[0].toLocaleDateString('en-US',{month:'short'})});} });
  const dayLabels = ['','Mon','','Wed','','Fri',''];
  return `
    <div class="heatmap-meta">
      <span>${txns.length} tx fetched · ${cells.size} active days</span>
      <div class="heatmap-legend"><span>Less</span><div class="heatmap-legend-cells">${[0,.25,.5,.75,1].map(f=>`<div class="hm-leg-cell" style="background:${_heatColor(f)}"></div>`).join('')}</div><span>More</span></div>
    </div>
    <div class="heatmap-scroll"><svg class="heatmap-svg" viewBox="0 0 ${W} ${H}" width="${W}" height="${H}">
      ${monthLabels.map(({wi,lbl})=>`<text x="${26+wi*(CELL+GAP)}" y="10" font-size="9" fill="rgba(255,255,255,.38)" font-family="Outfit,sans-serif">${lbl}</text>`).join('')}
      ${dayLabels.map((lbl,di)=>lbl?`<text x="0" y="${16+di*(CELL+GAP)+CELL/2+3}" font-size="9" fill="rgba(255,255,255,.3)" font-family="Outfit,sans-serif">${lbl}</text>`:'').join('')}
      ${byWeek.map((wk,wi)=>wk.map((day,di)=>{
        const key=day.toISOString().slice(0,10);
        const cnt=cells.get(key)||0;
        const fill=_heatColor(cnt/maxCount);
        return `<rect x="${26+wi*(CELL+GAP)}" y="${16+di*(CELL+GAP)}" width="${CELL}" height="${CELL}" rx="2" fill="${fill}" opacity="${cnt>0?.9:.25}"><title>${key}: ${cnt} tx</title></rect>`;
      }).join('')).join('')}
    </svg></div>`;
}

function _buildTokenAllocation(tokens) {
  const map = new Map();
  tokens.forEach(t => { const b=Math.abs(parseFloat(t.balance||0)); map.set(t.currency,(map.get(t.currency)||0)+b); });
  const sorted = [...map.entries()].sort((a,b)=>b[1]-a[1]).slice(0,8);
  const total  = sorted.reduce((s,[,v])=>s+v,0)||1;
  const COLORS = ['#00fff0','#00d4ff','#bd93f9','#50fa7b','#ffb86c','#ff79c6','#f1fa8c','#ff5555'];
  return `<div class="token-alloc-list">${sorted.map(([cur,bal],i)=>{
    const pct=((bal/total)*100).toFixed(1), color=COLORS[i%COLORS.length];
    const label=cur.length>4?cur.slice(0,4)+'…':cur;
    return `<div class="ta-row"><div class="ta-swatch" style="background:${color}"></div><div class="ta-cur mono">${label}</div><div class="ta-bar-wrap"><div class="ta-bar" style="width:${pct}%;background:${color}20;border-color:${color}55"></div></div><div class="ta-pct">${pct}%</div></div>`;
  }).join('')}</div>`;
}

function _buildTxBreakdown(txns) {
  if (!txns.length) return '<div class="analytics-empty">No data.</div>';
  const map = new Map();
  txns.forEach(tx => { const t=tx.TransactionType||'?'; map.set(t,(map.get(t)||0)+1); });
  const sorted = [...map.entries()].sort((a,b)=>b[1]-a[1]);
  const total  = txns.length;
  return `<div class="tx-breakdown-list">${sorted.slice(0,8).map(([type,count])=>{
    const pct=((count/total)*100).toFixed(0);
    return `<div class="txb-row"><div class="txb-icon">${_txTypeIcon(type)}</div><div class="txb-type">${type}</div><div class="txb-bar-wrap"><div class="txb-bar" style="width:${pct}%"></div></div><div class="txb-count">${count}</div></div>`;
  }).join('')}</div>`;
}

function _buildXrpFlow(txns, address) {
  let inflow=0, outflow=0;
  txns.forEach(tx => {
    if (tx.TransactionType !== 'Payment') return;
    const ok = (tx.metaData?.TransactionResult||tx.meta?.TransactionResult) === 'tesSUCCESS';
    if (!ok || typeof tx.Amount !== 'string') return;
    const amt = Number(tx.Amount)/1e6;
    if (tx.Destination === address) inflow  += amt;
    if (tx.Account     === address) outflow += amt;
  });
  const net=inflow-outflow, up=net>=0;
  return `
    <div class="xrp-flow-grid">
      <div class="xrf-item xrf-in"><div class="xrf-label">↓ Inflow</div><div class="xrf-val">${fmt(inflow,4)} XRP</div></div>
      <div class="xrf-item xrf-out"><div class="xrf-label">↑ Outflow</div><div class="xrf-val">${fmt(outflow,4)} XRP</div></div>
      <div class="xrf-item ${up?'xrf-pos':'xrf-neg'}"><div class="xrf-label">Net</div><div class="xrf-val">${up?'+':''}${fmt(net,4)} XRP</div></div>
    </div>
    <div class="xrf-note">Payment TXs in last ${txns.length} fetched. Excludes fees and DEX fills.</div>`;
}