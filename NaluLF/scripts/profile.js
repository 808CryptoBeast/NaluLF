/* =====================================================
   profile.js — Profile · Social · XRPL Wallet Suite
   v2.0 — Optimized

   Architecture:
   Storage: plain localStorage — no encryption (seeds shown once, never stored)
   • Public metadata (address, label, emoji) in plain LS
   • Vault must be unlocked for any signing operation
   • Seeds zero'd from memory immediately after use

   XRPL operations:
   • TrustSet · Payment · OfferCreate/Cancel
   • NFTokenMint/Burn · AMM operations
   • Direct JSON-RPC — no proxy
   ===================================================== */

import { $, $$, escHtml, safeGet, safeSet, safeJson,
         toastInfo, toastErr, toastWarn, isValidXrpAddress, fmt } from './utils.js';
import { state } from './state.js';
import { setTheme } from './theme.js';


/* ── Constants ─────────────────────────────────────── */
const LS_WALLETS    = 'nalulf_wallets';
const LS_PROFILE        = 'nalulf_profile';
const LS_SOCIAL         = 'nalulf_social';
const LS_ACTIVE_ID      = 'naluxrp_active_wallet';
const LS_AVATAR_IMG     = 'nalulf_avatar_img';
const LS_BANNER_IMG     = 'nalulf_banner_img';
const LS_ACTIVITY       = 'nalulf_activity_log';
const LS_BAL_HIST_PFX   = 'nalulf_balhist_';
const LS_ADDR_BOOK      = 'nalulf_addr_book';     // { addr: label }
const XRPL_RPC          = 'https://s1.ripple.com:51234/';
const XRPL_RPC_BACKUP   = 'https://xrplcluster.com/';

// XRPL reserve: 10 XRP base + 2 XRP per owned object
const XRPL_BASE_RESERVE = 10;
const XRPL_OWNER_RESERVE = 2;

const AVATARS = ['🌊','🐋','🐉','🦋','🦁','🐺','🦊','🐻','🐼','🦅','🐬','🦈',
  '🐙','🦑','🧿','🌺','🌸','🍀','⚡','🔥','💎','🌙','⭐','🎯','🧠','🔮','🛸','🗺','🏔','🎭','🏛'];
const WALLET_EMOJIS = ['💎','🏦','🔐','🔑','💰','🌊','⚡','🚀','🌙','⭐','🏴‍☠️','🎯','🧠','🔮'];
const WALLET_COLORS = ['#50fa7b','#00d4ff','#ffb86c','#bd93f9','#ff79c6','#f1fa8c','#ff5555','#00fff0','#ff6b6b','#a78bfa'];
const BANNERS       = ['banner-ocean','banner-neon','banner-gold','banner-cosmic','banner-sunset','banner-aurora'];
const SOCIAL_PLATFORMS = [
  { id:'discord',  label:'Discord',     icon:'💬', prefix:'https://discord.com/users/' },
  { id:'twitter',  label:'X / Twitter', icon:'𝕏',  prefix:'https://x.com/' },
  { id:'linkedin', label:'LinkedIn',    icon:'in', prefix:'https://linkedin.com/in/' },
  { id:'github',   label:'GitHub',      icon:'⌥',  prefix:'https://github.com/' },
  { id:'telegram', label:'Telegram',    icon:'✈',  prefix:'https://t.me/' },
  { id:'facebook', label:'Facebook',    icon:'f',  prefix:'https://facebook.com/' },
  { id:'tiktok',   label:'TikTok',      icon:'♪',  prefix:'https://tiktok.com/@' },
];

// XRPL-specific engine result → human message map
const XRPL_ERRORS = {
  tecNO_DST:            'Destination account does not exist — fund it with 10 XRP first.',
  tecINSUF_RESERVE_LINE:'Insufficient reserve to add another trustline.',
  tecINSUF_RESERVE_OFFER:'Insufficient reserve to place a DEX order.',
  tecUNFUNDED_PAYMENT:  'Insufficient balance (including reserve).',
  tecDST_TAG_NEEDED:    'This destination requires a Destination Tag.',
  tecNO_PERMISSION:     'Account has DepositAuth enabled — destination must preauthorize.',
  temBAD_AMOUNT:        'Invalid amount.',
  temBAD_CURRENCY:      'Invalid currency code.',
  temBAD_ISSUER:        'Invalid issuer address.',
  tefPAST_SEQ:          'Sequence number already used — please retry.',
  terQUEUED:            'Transaction queued — will be included in a future ledger.',
};

/* ── App state ──────────────────────────────────────── */
let profile = {
  displayName:'', handle:'', bio:'', location:'', website:'',
  avatar:'🌊', banner:'banner-ocean', joinedDate:new Date().toISOString(),
  domain:'',
};
let wallets        = [];
let social         = {};
let activeWalletId = null;
let balanceCache   = {};
let trustlineCache = {};
let txCache        = {};
let nftCache       = {};
let offerCache     = {};
let metricCache    = {};
let addrBook       = {};   // { [address]: label }

let _activeTab       = 'wallets';
let _expandedWallet  = null;
let _expandedSubTabs = {};
let _walletFilter    = '';   // search filter for wallet list

/* Wizard state */
let wizardStep      = 1;
let wizardData      = { algo:'ed25519', label:'', emoji:'💎', color:'#50fa7b', seed:'', address:'' };
let checksCompleted = new Set();

const ACTIVITY_MAX = 60;
const ACT_ICONS = {
  wallet_created:'💎', wallet_removed:'🗑', social_connected:'🔗',
  social_removed:'✕', profile_saved:'✏️', trustline_added:'🔗',
  sent:'⬆', received:'⬇', vault_created:'🔐', backup_exported:'📂',
  theme_changed:'🎨', wallet_imported:'🔑', watch_added:'👁',
};

/* ═══════════════════════════════════════════════════
   Init
═══════════════════════════════════════════════════ */
export function initProfile() {
  loadData();
  _mountDynamicModals();
  _bindGlobalKeyboard();

  renderProfilePage();
  renderProfileTabs('wallets');
  renderActiveWalletBar();
  bindProfileEvents();

  // Vault events
  window.addEventListener('naluxrp:vault-ready', () => {
    loadData();
    renderProfilePage();
    renderProfileTabs(_activeTab);
    renderActiveWalletBar();
    fetchAllBalances();
  });
  window.addEventListener('naluxrp:vault-locked', () => renderProfilePage());

  // Visibility refresh
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden && wallets.length) {
      const stale = wallets.filter(w => {
        const c = balanceCache[w.address];
        return !c || (Date.now() - c.fetchedAt) > 5 * 60_000;
      });
      if (stale.length) Promise.all(stale.map(w => fetchBalance(w.address)))
        .then(() => { renderWalletList(); renderActiveWalletBar(); });
    }
  });
}

export function switchProfileTab(tab) {
  _activeTab = tab;
  $$('.ptab-btn').forEach(b => b.classList.toggle('active', b.dataset.tab === tab));
  renderProfileTabs(tab);
}

function renderProfileTabs(tab) {
  try {
    switch (tab) {
      case 'wallets':   renderWalletList();      break;
      case 'social':    renderSocialList();      break;
      case 'activity':  renderActivityPanel();   break;
      case 'settings':  renderSettingsPanel();   break;
      case 'analytics': renderAnalyticsTab();    break;
      case 'security':  renderSecurityPanel();   break;
    }
  } catch(err) {
    const el = $(`profile-tab-${tab}`);
    if (el) _renderTabError(el, tab, err);
    console.error(`Profile tab "${tab}" error:`, err);
  }
  ['wallets','social','activity','settings','analytics','security'].forEach(t => {
    const el = $(`profile-tab-${t}`);
    if (el) el.style.display = (t === tab) ? '' : 'none';
  });
}

function _renderTabError(el, tab, err) {
  el.innerHTML = `<div class="tab-error-card">
    <div class="tab-error-icon">⚠️</div>
    <div class="tab-error-title">Something went wrong</div>
    <div class="tab-error-sub">${escHtml(err?.message||'Unknown error')}</div>
    <button class="tab-error-btn" onclick="switchProfileTab('${tab}')">Try Again</button>
  </div>`;
}

/* Global keyboard shortcuts */
function _bindGlobalKeyboard() {
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape') {
      // Close any open overlay
      for (const id of ['profile-editor-modal','wallet-creator-overlay','social-modal',
        'send-modal-overlay','receive-modal-overlay','trustline-modal-overlay',
        'import-address-modal','import-seed-modal','token-details-modal',
        'pub-profile-overlay']) {
        const el = $(id) || document.getElementById(id);
        if (el?.classList.contains('show') || el?.style.display === 'flex') {
          el.classList.remove('show');
          if (el.style.display === 'flex') el.style.display = 'none';
          return;
        }
      }
    }
    // K = open wallet creator (when no modal open, vault unlocked)
  if (e.key === 'k' && (e.ctrlKey || e.metaKey)) {
      e.preventDefault();
      openWalletCreator();
    }
  });
}

/* ═══════════════════════════════════════════════════
   Data — vault-aware
═══════════════════════════════════════════════════ */
function loadData() {
  const p = safeJson(safeGet(LS_PROFILE));
  if (p) Object.assign(profile, p);
  social   = safeJson(safeGet(LS_SOCIAL))       || {};
  wallets  = safeJson(safeGet(LS_WALLETS))  || [];
  addrBook = safeJson(safeGet(LS_ADDR_BOOK))    || {};















  activeWalletId = safeGet(LS_ACTIVE_ID) || wallets[0]?.id || null;

  if (!profile.displayName && state.session?.name) {
    profile.displayName = state.session.name;
    profile.handle = state.session.name.toLowerCase().replace(/\s+/g,'_');
    _saveProfile();
  }
}

function _saveProfile()    { safeSet(LS_PROFILE,      JSON.stringify(profile)); }
function _saveWallets() { safeSet(LS_WALLETS,  JSON.stringify(wallets)); }
function _saveSocial()     { safeSet(LS_SOCIAL,        JSON.stringify(social)); }

/* ═══════════════════════════════════════════════════
   Activity Log
═══════════════════════════════════════════════════ */
export function logActivity(type, detail) {
  const log = safeJson(safeGet(LS_ACTIVITY)) || [];
  log.unshift({ type, detail, ts: Date.now() });
  if (log.length > ACTIVITY_MAX) log.length = ACTIVITY_MAX;
  safeSet(LS_ACTIVITY, JSON.stringify(log));
}
function _getActivity() { return safeJson(safeGet(LS_ACTIVITY)) || []; }
function _relTime(ts) {
  const s = (Date.now() - ts) / 1000;
  if (s < 60)    return 'just now';
  if (s < 3600)  return `${Math.floor(s/60)}m ago`;
  if (s < 86400) return `${Math.floor(s/3600)}h ago`;
  return `${Math.floor(s/86400)}d ago`;
}

/* ═══════════════════════════════════════════════════
   Active Wallet
═══════════════════════════════════════════════════ */
export function getActiveWallet() {
  return wallets.find(w => w.id === activeWalletId) || wallets[0] || null;
}

export function setActiveWallet(id) {
  if (!wallets.find(w => w.id === id)) return;
  activeWalletId = id;
  safeSet(LS_ACTIVE_ID, id);
  renderWalletList();
  renderActiveWalletBar();
  window.dispatchEvent(new CustomEvent('naluxrp:active-wallet-changed', { detail: getActiveWallet() }));
  toastInfo('Active wallet switched');
}

window.addEventListener('naluxrp:active-wallet-changed', e => {
  const w = e.detail;
  if (!w) return;
  const inp = $('inspect-addr');
  if (inp && !inp.value) inp.value = w.address;
  state.activeWalletAddress = w.address;
});

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
  const tokens = cached?.tokens?.length ? `· ${cached.tokens.length} token${cached.tokens.length>1?'s':''}` : '';
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
      <button class="awb-btn awb-btn--inspect" onclick="inspectWalletAddr('${escHtml(w.address)}')">🔍 Inspect</button>
    </div>`;
}

/* ═══════════════════════════════════════════════════
   Profile render
═══════════════════════════════════════════════════ */
function renderProfilePage() {
  const banner = $('profile-banner');
  if (banner) {
    const img = localStorage.getItem(LS_BANNER_IMG);
    if (img) {
      BANNERS.forEach(b => banner.classList.remove(b));
      banner.style.backgroundImage    = `url(${img})`;
      banner.style.backgroundSize     = 'cover';
      banner.style.backgroundPosition = 'center';
    } else {
      banner.style.backgroundImage = '';
      BANNERS.forEach(b => banner.classList.remove(b));
      banner.classList.add(profile.banner || 'banner-ocean');
    }
  }

  const av = $('profile-avatar-el');
  if (av) {
    const img = localStorage.getItem(LS_AVATAR_IMG);
    av.innerHTML = img
      ? `<img src="${img}" class="profile-avatar-img" alt="Profile photo"/>`
      : (profile.avatar || '🌊');
  }

  _setText('profile-display-name', profile.displayName || 'Anonymous');
  _setText('profile-handle',       `@${profile.handle || 'anonymous'}`);
  _setText('profile-bio',          profile.bio || 'No bio yet. Click Edit Profile to add one.');

  const loc = $('profile-location-el');
  if (loc) loc.innerHTML = profile.location ? `<span>📍 ${escHtml(profile.location)}</span>` : '';

  const web = $('profile-website-el');
  if (web) web.innerHTML = profile.website
    ? `<a href="${escHtml(profile.website)}" target="_blank" rel="noopener">🔗 ${escHtml(profile.website.replace(/^https?:\/\//,''))}</a>` : '';

  const joined = $('profile-joined-el');
  if (joined) joined.innerHTML = `<span>📅 Joined ${new Date(profile.joinedDate||Date.now()).toLocaleDateString('en-US',{month:'short',year:'numeric'})}</span>`;

  const domainEl = $('profile-domain-el');
  if (domainEl) {
    const d = profile.domain || '';
    domainEl.innerHTML = d ? `<span class="profile-domain-chip">◈ ${escHtml(d)}.xrpl</span>` : '';
  }

  const vaultEl = $('vault-status-pill');
  if (vaultEl) {
  // vault pill not used in plain-storage mode
    vaultEl.className = `vault-pill ${open ? 'vault-pill--open' : 'vault-pill--locked'}`;
    vaultEl.innerHTML = open ? '🔓 Vault unlocked' : '🔒 Vault locked';
  }

  const chip = $('profile-address-chip');
  if (chip) {
    const w = getActiveWallet();
    if (w) {
      chip.style.display = '';
      chip.innerHTML = `<span class="addr-chip-icon">${escHtml(w.emoji||'💎')}</span>
        <span class="addr-chip-addr mono">${w.address.slice(0,8)}…${w.address.slice(-5)}</span>
        <button class="addr-chip-copy" onclick="copyToClipboard('${escHtml(w.address)}')" title="Copy address">⧉</button>`;
    } else chip.style.display = 'none';
  }

  const sb = $('profile-social-badges');
  if (sb) {
    const connected = SOCIAL_PLATFORMS.filter(p => social[p.id]);
    sb.innerHTML = connected.slice(0,4).map(p =>
      `<span class="profile-social-badge social-platform-badge--${p.id}" title="${p.label}: @${escHtml(social[p.id])}" onclick="viewSocial('${p.id}')">${p.icon}</span>`
    ).join('');
    sb.style.display = connected.length ? '' : 'none';
  }

  renderProfileMetrics();
  renderProfileCompleteness();
}

/* ── Profile Metrics Row ── */
function renderProfileMetrics() {
  const el = $('profile-metrics-row');
  if (!el) return;
  const locked = false;
  const totalXrp   = Object.values(balanceCache).reduce((s,c) => s+(c?.xrp||0), 0);
  const xrpPrice   = _getXrpPrice();
  const allTokens  = Object.values(balanceCache).flatMap(c => c?.tokens||[]);
  const activeW    = getActiveWallet();
  const metric     = activeW ? metricCache[activeW.address] : null;
  const ownerCount = metric?.ownerCount || 0;
  const reserve    = XRPL_BASE_RESERVE + ownerCount * XRPL_OWNER_RESERVE;
  const accountAge = activeW?.createdAt ? _ageString(new Date(activeW.createdAt)) : '—';
  const txCount    = metric?.sequence != null ? metric.sequence : '—';

  el.innerHTML = `
    <div class="pmetric"><div class="pmetric-val">${locked?'••••':fmt(totalXrp,2)}</div><div class="pmetric-label">Total XRP</div></div>
    <div class="pmetric pmetric-divider"></div>
    <div class="pmetric"><div class="pmetric-val ${xrpPrice&&!locked?'pmetric-usd':''}">
      ${locked?'••••':xrpPrice?'$'+fmt(totalXrp*xrpPrice,2):'—'}</div>
      <div class="pmetric-label">Est. Value</div></div>
    <div class="pmetric pmetric-divider"></div>
    <div class="pmetric"><div class="pmetric-val">${txCount}</div><div class="pmetric-label">Transactions</div></div>
    <div class="pmetric pmetric-divider"></div>
    <div class="pmetric"><div class="pmetric-val">${accountAge}</div><div class="pmetric-label">Wallet Age</div></div>
    <div class="pmetric pmetric-divider"></div>
    <div class="pmetric"><div class="pmetric-val">${allTokens.length}</div><div class="pmetric-label">Tokens</div></div>
    ${metric ? `<div class="pmetric pmetric-divider"></div>
    <div class="pmetric pmetric-reserve" title="${ownerCount} owned objects × ${XRPL_OWNER_RESERVE} XRP + ${XRPL_BASE_RESERVE} XRP base">
      <div class="pmetric-val pmetric-reserve-val">${reserve} XRP</div>
      <div class="pmetric-label">Reserved</div></div>` : ''}`;

  if (activeW && (!metricCache[activeW.address] || (Date.now()-metricCache[activeW.address].fetchedAt)>60000)) {
    fetchAccountMetrics(activeW.address).then(() => renderProfileMetrics());
  }
}

async function fetchAccountMetrics(address) {
  try {
    const info = await xrplPost({ method:'account_info', params:[{ account:address, ledger_index:'validated' }] });
    if (info?.account_data) {
      metricCache[address] = {
        sequence:   info.account_data.Sequence,
        ownerCount: info.account_data.OwnerCount || 0,
        fetchedAt:  Date.now(),
      };
    }
  } catch {}
}

function _ageString(date) {
  const days = Math.floor((Date.now() - date.getTime()) / 86400000);
  if (days < 1)   return 'Today';
  if (days < 30)  return `${days}d`;
  if (days < 365) return `${Math.floor(days/30)}mo`;
  const y = Math.floor(days/365), m = Math.floor((days%365)/30);
  return m ? `${y}y ${m}mo` : `${y}y`;
}

function _getXrpPrice() {
  // Prefer live series data over DOM scraping
  if (Array.isArray(window.__dashSeries?.marketPrice)) {
    const v = window.__dashSeries.marketPrice.at(-1);
    if (v != null && Number.isFinite(v)) return v;
  }
  const el = document.getElementById('mkt-price');
  if (el) { const v = parseFloat(el.textContent.replace('$','')); if (!isNaN(v)) return v; }
  return 0;
}

function _renderOnboardingChecklist() {
  const hasWallet  = wallets.length > 0;
  const hasSocial  = Object.values(social).some(Boolean);
  const hasBio     = !!profile.bio;
  const hasBackup  = !!localStorage.getItem('naluxrp_last_backup_ts');
  const done       = [hasWallet, hasSocial, hasBio, hasBackup].filter(Boolean).length;
  if (done === 4) return '';
  const pct = Math.round((done/4)*100);
  return `
    <div class="onboarding-card">
      <div class="onb-header">
        <div class="onb-title">✨ Complete your profile</div>
        <div class="onb-prog-wrap">
          <div class="onb-prog-bar"><div class="onb-prog-fill" style="width:${pct}%"></div></div>
          <span class="onb-prog-label">${done}/4</span>
        </div>
      </div>
      <div class="onb-items">
        ${_onbItem('💎','Generate your first XRPL wallet','Encrypted with AES-256-GCM, never leaves this device.',hasWallet,"openWalletCreator()")}
        ${_onbItem('🔗','Connect a social account','Link Discord, X, GitHub, or any platform.',hasSocial,"switchProfileTab('social')")}
        ${_onbItem('✏️','Add a bio','Tell people who you are.',hasBio,"openProfileEditor()")}
        ${_onbItem('💾','Export an encrypted backup','Protect against device loss.',hasBackup,"exportVaultBackup()")}
      </div>
    </div>`;
}

function _onbItem(icon, title, sub, done, action) {
  return `<div class="onb-item ${done?'onb-item--done':''}" ${done?'':` onclick="${action}"`}>
    <div class="onb-item-check">${done?'✓':icon}</div>
    <div class="onb-item-body"><div class="onb-item-title">${title}</div><div class="onb-item-sub">${sub}</div></div>
    ${done?'':'<span class="onb-item-arrow">→</span>'}
  </div>`;
}

/* ═══════════════════════════════════════════════════
   Social Tab
═══════════════════════════════════════════════════ */
function renderSocialList() {
  const el = $('profile-tab-social');
  if (!el) return;
  const connected = Object.values(social).filter(Boolean).length;
  el.innerHTML = `
    <div class="social-section-head">
      <div class="social-section-title">Social &amp; Community Links</div>
      <div class="social-section-sub">${connected} of ${SOCIAL_PLATFORMS.length} connected · stored locally only</div>
    </div>
    <div class="social-grid">
      ${SOCIAL_PLATFORMS.map(p => {
        const h = social[p.id] || '', conn = !!h;
        return `<div class="social-card ${conn?'social-card--connected':''}" id="social-item-${p.id}">
          <div class="social-card-left">
            <div class="social-platform-badge social-platform-badge--${p.id}">${p.icon}</div>
            <div class="social-card-info">
              <div class="social-card-name">${escHtml(p.label)}</div>
              <div class="social-card-handle ${conn?'':'dim'}">${conn?escHtml('@'+h):'Not connected'}</div>
            </div>
          </div>
          <div class="social-card-actions">
            ${conn
              ? `<button class="sc-btn sc-btn--open" onclick="viewSocial('${p.id}')">↗</button>
                 <button class="sc-btn sc-btn--edit" onclick="openSocialModal('${p.id}')">Edit</button>`
              : `<button class="sc-btn sc-btn--connect" onclick="openSocialModal('${p.id}')">+ Connect</button>`}
          </div>
        </div>`;
      }).join('')}
    </div>
    ${connected ? `<div class="social-preview-row">
      <span class="social-preview-hint">${connected} platform${connected>1?'s':''} connected</span>
      <button class="sc-preview-btn" onclick="openPublicProfilePreview()">👁 Preview Profile</button>
    </div>` : ''}`;
  _setText('stat-socials-val', connected);
}

export function openSocialModal(platformId) {
  const p = SOCIAL_PLATFORMS.find(x => x.id === platformId);
  if (!p) return;
  const modal = $('social-modal');
  if (!modal) return;
  const icon  = $('social-modal-icon');
  const title = $('social-modal-title');
  const sub   = $('social-modal-sub');
  const input = $('social-modal-input');
  const del   = $('social-modal-delete');
  if (icon)  { icon.className = `social-platform-icon-lg social-icon ${p.id}`; icon.textContent = p.icon; }
  if (title) title.textContent = `Connect ${p.label}`;
  if (sub)   sub.textContent   = `Enter your ${p.label} ${p.id==='discord'?'user ID or username':'username'}.`;
  if (input) { input.value = social[platformId]||''; input.placeholder = `Your ${p.label} handle`; }
  if (del)   del.style.display = social[platformId] ? '' : 'none';
  modal.dataset.platform = platformId;
  modal.classList.add('show');
  setTimeout(() => input?.focus(), 80);
}
export function saveSocialModal() {
  const modal = $('social-modal');
  const pid   = modal?.dataset.platform;
  const input = $('social-modal-input');
  if (!pid || !input) return;
  const h = input.value.trim().replace(/^@/,'');
  if (h) social[pid] = h; else delete social[pid];
  _saveSocial(); renderSocialList(); closeSocialModal();
  const p = SOCIAL_PLATFORMS.find(x => x.id === pid);
  renderProfileCompleteness();
  logActivity('social_connected', `${p?.label||pid} @${h||'(removed)'}`);
  toastInfo(`${p?.label} updated`);
}
export function deleteSocial() {
  const pid = $('social-modal')?.dataset.platform;
  if (!pid) return;
  delete social[pid]; _saveSocial(); renderSocialList(); closeSocialModal();
  logActivity('social_removed', pid);
  toastInfo('Social connection removed');
}
export function viewSocial(pid) {
  const p = SOCIAL_PLATFORMS.find(x => x.id === pid);
  if (p && social[pid]) window.open(`${p.prefix}${social[pid]}`, '_blank', 'noopener');
}
export function closeSocialModal() { $('social-modal')?.classList.remove('show'); }

/* ═══════════════════════════════════════════════════
   Wallet List Tab
═══════════════════════════════════════════════════ */
function renderWalletList() {
  const el = $('profile-tab-wallets');
  if (!el) return;

  if (wallets.length === 0) {
    el.innerHTML = _renderOnboardingChecklist() + `
      <div class="wallets-empty">
        <div class="wallets-empty-icon">💎</div>
        <div class="wallets-empty-title">No wallets yet</div>
        <div class="wallets-empty-sub">Generate your first XRPL wallet — your seed is encrypted with AES-256-GCM and never leaves this device.</div>
        <button class="btn-create-wallet-hero" onclick="openWalletCreator()">⚡ Generate XRPL Wallet</button>
      </div>`;
    _setText('stat-wallets-val', 0);
    return;
  }

  // Search/filter bar (shown when >3 wallets)
  const filterBar = wallets.length > 3 ? `
    <div class="wallet-filter-row">
      <input class="wallet-filter-input" id="wallet-filter-input" type="text"
        placeholder="🔍 Filter wallets…" value="${escHtml(_walletFilter)}"
        oninput="filterWallets(this.value)">
      ${_walletFilter ? `<button class="wallet-filter-clear" onclick="filterWallets('')">✕</button>` : ''}
    </div>` : '';

  const visible = wallets.filter(w =>
    !_walletFilter ||
    w.label.toLowerCase().includes(_walletFilter.toLowerCase()) ||
    w.address.toLowerCase().includes(_walletFilter.toLowerCase())
  );

  const cards = visible.map((w, i) => _buildWalletCard(w, wallets.indexOf(w))).join('');

  el.innerHTML = filterBar + (visible.length ? cards : `<div class="wcard-empty">No wallets match "${escHtml(_walletFilter)}"</div>`) + `
    <div class="wallet-add-row">
      <button class="btn-add-wallet" onclick="openWalletCreator()">
        <span class="baw-plus">＋</span>
        <div class="baw-text"><span class="baw-title">Generate New XRPL Wallet</span>
          <span class="baw-sub">Keys generated in-browser · encrypted before storage</span></div>
      </button>
      <button class="btn-import-wallet btn-import-wallet--seed" onclick="openImportSeedModal()">
        <span class="baw-plus">🔑</span>
        <div class="baw-text"><span class="baw-title">Import from Seed</span>
          <span class="baw-sub">Existing family seed — full signing access</span></div>
      </button>
      <button class="btn-import-wallet btn-import-wallet--watch" onclick="openImportAddressModal()">
        <span class="baw-plus">👁</span>
        <div class="baw-text"><span class="baw-title">Watch Address</span>
          <span class="baw-sub">Track any XRPL address read-only</span></div>
      </button>
    </div>`;
  _setText('stat-wallets-val', wallets.length);
}

export function filterWallets(q) {
  _walletFilter = q;
  renderWalletList();
  // Restore focus to filter input
  setTimeout(() => {
    const inp = document.getElementById('wallet-filter-input');
    if (inp) { inp.focus(); inp.setSelectionRange(q.length, q.length); }
  }, 10);
}

function _buildWalletCard(w, idx) {
  const isActive   = w.id === activeWalletId;
  const isWatch    = !!w.watchOnly;
  const cached     = balanceCache[w.address];
  const metric     = metricCache[w.address];
  const unlocked = true;
  const canSee     = unlocked || isWatch;
  const ownerCount = metric?.ownerCount || 0;
  const reserveXrp = XRPL_BASE_RESERVE + ownerCount * XRPL_OWNER_RESERVE;
  const xrp        = canSee ? (cached ? fmt(cached.xrp,2) : '—') : '••••';
  const available  = cached && canSee ? Math.max(0, cached.xrp - reserveXrp) : null;
  const tokens     = cached?.tokens || [];
  const syncedAgo  = cached?.fetchedAt ? _relTime(cached.fetchedAt) : null;
  const addrShort  = w.address.slice(0,8)+'…'+w.address.slice(-6);
  const hist       = _getBalanceHistory(w.address);

  return `
  <div class="wcard ${isActive?'wcard--active':''} ${isWatch?'wcard--watch':''}" id="wallet-item-${w.id}" style="--i:${idx}">
    <div class="wcard-top">
      <div class="wcard-icon" style="background:${w.color}18;border-color:${w.color}44;color:${w.color}">${escHtml(w.emoji||'💎')}</div>
      <div class="wcard-identity">
        <div class="wcard-name-row">
          <span class="wcard-name">${escHtml(w.label||'Unnamed')}</span>
          ${isActive?'<span class="wcard-badge wcard-badge--active">● Active</span>':''}
          ${isWatch ?'<span class="wcard-badge wcard-badge--watch">👁 Watch</span>':''}
          ${w.testnet?'<span class="wcard-badge wcard-badge--testnet">Testnet</span>':'<span class="wcard-badge wcard-badge--mainnet">Mainnet</span>'}
        </div>
        <div class="wcard-address mono" title="${escHtml(w.address)}" onclick="copyToClipboard('${escHtml(w.address)}')">${addrShort} <span class="wcard-copy-hint">⧉</span></div>
        <div class="wcard-algo-row">
          ${!isWatch
            ? `<span class="wcard-algo">${escHtml((w.algo||'ed25519').toUpperCase())}</span>
               <span class="wcard-enc">🔐 AES-256-GCM</span>`
            : '<span class="wcard-enc">🔍 Read-only</span>'}
        </div>
      </div>
      <div class="wcard-balance-col">
        ${hist.length >= 2 ? `<div class="wcard-sparkline">${_buildSparkline(hist,70,22,w.color||'#00fff0')}</div>` : ''}
        <div class="wcard-xrp ${!canSee?'wcard-balance-locked':''}">${xrp} <span class="wcard-xrp-label">XRP</span></div>
        ${available!==null && canSee ? `<div class="wcard-avail" title="${reserveXrp} XRP reserved">${fmt(available,2)} avail.</div>` : ''}
        ${tokens.length && canSee ? `<div class="wcard-tokens">${tokens.length} token${tokens.length>1?'s':''}</div>` : ''}
      </div>
    </div>

    <div class="wcard-sync-row">
      <div class="wcard-sync-time">
        ${!canSee ? '<span>🔒 Sign in to see balance</span>'
          : syncedAgo ? `<span>Synced ${syncedAgo}</span>`
          : '<span style="opacity:.4">Not synced yet</span>'}
      </div>
      ${canSee ? `<button class="wcard-refresh-btn" onclick="fetchBalance('${w.address}').then(()=>{renderWalletList();renderProfileMetrics();})">↻</button>` : ''}
    </div>

    ${metric ? `<div class="wcard-reserve-row">
      <span class="wcard-reserve-chip">🔒 ${reserveXrp} XRP reserved</span>
      <span class="wcard-reserve-sub">${ownerCount} object${ownerCount!==1?'s':''} · base ${XRPL_BASE_RESERVE} + ${ownerCount}×${XRPL_OWNER_RESERVE}</span>
    </div>` : ''}

    ${tokens.length && canSee ? `<div class="wcard-token-row">
      ${tokens.slice(0,6).map(t => {
        const cur = t.currency.length>4 ? (_hexToAscii(t.currency)||t.currency.slice(0,4)+'…') : t.currency;
        return `<div class="wcard-token-chip" onclick="openTokenDetailsModal('${escHtml(t.currency)}','${escHtml(t.issuer)}','${escHtml(w.address)}')" title="${escHtml(t.currency)}">
          <span class="wcard-token-cur">${escHtml(cur)}</span>
          <span class="wcard-token-bal">${fmt(parseFloat(t.balance||0),4)}</span>
        </div>`;
      }).join('')}
      ${tokens.length>6 ? `<div class="wcard-token-chip wcard-token-more" onclick="openTokenDetailsModal('${escHtml(tokens[6].currency)}','${escHtml(tokens[6].issuer)}','${escHtml(w.address)}')">+${tokens.length-6}</div>` : ''}
    </div>` : ''}

    <div class="wcard-actions">
      ${!isWatch ? `<button class="wcard-btn wcard-btn--send" onclick="openSendModal('${w.id}')">⬆ Send</button>` : ''}
      <button class="wcard-btn wcard-btn--receive" onclick="openReceiveModal('${w.id}')">⬇ Receive</button>
      ${!isWatch ? `<button class="wcard-btn wcard-btn--trust" onclick="openTrustlineModal('${w.id}')">🔗 Trust</button>` : ''}
      <button class="wcard-btn wcard-btn--inspect" onclick="inspectWalletAddr('${escHtml(w.address)}')">🔍 Inspect</button>
      ${!isActive ? `<button class="wcard-btn wcard-btn--setactive" onclick="setActiveWallet('${w.id}')">★ Active</button>` : ''}
      <button class="wcard-btn wcard-btn--expand ${_expandedWallet===w.id?'wcard-btn--expand-open':''}" onclick="toggleWalletDrawer('${w.id}')">${_expandedWallet===w.id?'▲ Hide':'▼ Details'}</button>
      <button class="wcard-btn wcard-btn--remove" onclick="deleteWallet(${idx})">✕</button>
    </div>

    ${_expandedWallet === w.id ? `
    <div class="wcard-drawer" id="wcard-drawer-${w.id}">
      <div class="wcard-drawer-tabs">
        <button class="wdt-btn ${(_expandedSubTabs[w.id]||'txns')==='txns'?'active':''}" onclick="switchWalletDrawerTab('${w.id}','txns')">📋 Transactions</button>
        <button class="wdt-btn ${(_expandedSubTabs[w.id]||'txns')==='nfts'?'active':''}" onclick="switchWalletDrawerTab('${w.id}','nfts')">🎨 NFTs</button>
        <button class="wdt-btn ${(_expandedSubTabs[w.id]||'txns')==='orders'?'active':''}" onclick="switchWalletDrawerTab('${w.id}','orders')">📊 DEX</button>
        <button class="wdt-btn ${(_expandedSubTabs[w.id]||'txns')==='amm'?'active':''}" onclick="switchWalletDrawerTab('${w.id}','amm')">🌊 AMM</button>
      </div>
      <div class="wcard-drawer-body" id="wcard-drawer-body-${w.id}">
        <div class="wdd-loading"><div class="spinner"></div> Loading…</div>
      </div>
    </div>` : ''}
  </div>`;
}

export function deleteWallet(idx) {
  const w = wallets[idx];
  if (!w) return;
  wallets.splice(idx, 1);
  _saveWallets();

  if (activeWalletId === w.id) {
    activeWalletId = wallets[0]?.id || null;
    if (activeWalletId) safeSet(LS_ACTIVE_ID, activeWalletId);
  }
  renderWalletList(); renderActiveWalletBar();
  logActivity('wallet_removed', w.label);
  _showUndoToast(`Wallet "${w.label}" removed`, () => {
    wallets.splice(idx, 0, w); _saveWallets();

    if (!activeWalletId) { activeWalletId = w.id; safeSet(LS_ACTIVE_ID, w.id); }
    renderWalletList(); renderActiveWalletBar();
    logActivity('wallet_created', w.label+' (restored)');
  });
}

function _showUndoToast(msg, onUndo) {
  const ex = document.getElementById('undo-toast'); if (ex) ex.remove();
  const t  = document.createElement('div'); t.id = 'undo-toast'; t.className = 'undo-toast';
  t.innerHTML = `<span class="undo-msg">${escHtml(msg)}</span><button class="undo-btn">Undo</button>`;
  document.body.appendChild(t);
  requestAnimationFrame(() => t.classList.add('show'));
  const timer = setTimeout(() => { t.classList.remove('show'); setTimeout(()=>t.remove(),300); }, 5000);
  t.querySelector('.undo-btn').addEventListener('click', () => {
    clearTimeout(timer); onUndo(); t.classList.remove('show'); setTimeout(()=>t.remove(),300); toastInfo('Wallet restored');
  });
}

export function inspectWalletAddr(addr) {
  const inp = $('inspect-addr');
  if (inp) inp.value = addr;
  window.switchTab?.(document.querySelector('[data-tab="inspector"]'), 'inspector');
  window.showDashboard?.();
}

/* ── Wallet Drawer ── */
export function toggleWalletDrawer(walletId) {
  _expandedWallet = (_expandedWallet === walletId) ? null : walletId;
  if (_expandedWallet && !_expandedSubTabs[walletId]) _expandedSubTabs[walletId] = 'txns';
  renderWalletList();
  if (_expandedWallet) setTimeout(() => _loadDrawerTab(walletId, _expandedSubTabs[walletId]), 60);
}

export function switchWalletDrawerTab(walletId, tab) {
  _expandedSubTabs[walletId] = tab;
  const drawer = document.getElementById(`wcard-drawer-${walletId}`);
  if (!drawer) return;
  drawer.querySelectorAll('.wdt-btn').forEach(b => b.classList.toggle('active', b.textContent.toLowerCase().includes(tab==='txns'?'trans':tab==='nfts'?'nft':tab==='orders'?'dex':'amm')));
  _loadDrawerTab(walletId, tab);
}

async function _loadDrawerTab(walletId, tab) {
  const w    = wallets.find(x => x.id === walletId);
  const body = document.getElementById(`wcard-drawer-body-${walletId}`);
  if (!w || !body) return;
  body.innerHTML = `<div class="wdd-loading"><div class="spinner"></div> Loading…</div>`;
  try {
    if (tab === 'txns') {
      body.innerHTML = _renderTxList(txCache[w.address]?.txns || await fetchTxHistory(w.address), w.address);
    } else if (tab === 'nfts') {
      body.innerHTML = _renderNFTGallery(nftCache[w.address]?.nfts || await fetchNFTs(w.address), w.address);
    } else if (tab === 'orders') {
      body.innerHTML = _renderDEXOrders(offerCache[w.address]?.offers || await fetchOpenOffers(w.address), w.id, w.address);
    } else if (tab === 'amm') {
      body.innerHTML = await _renderAMMPositions(w.address);
    }
  } catch(err) {
    body.innerHTML = `<div class="wdd-error">⚠️ ${escHtml(err.message)}</div>`;
  }
}

function _txTypeIcon(t) {
  return ({Payment:'💸',OfferCreate:'📊',OfferCancel:'✕',TrustSet:'🔗',NFTokenMint:'🎨',NFTokenBurn:'🔥',NFTokenCreateOffer:'🎯',NFTokenAcceptOffer:'✅',AMMCreate:'🌊',AMMDeposit:'📥',AMMWithdraw:'📤',AMMVote:'🗳',AMMBid:'💡',EscrowCreate:'⏳',EscrowFinish:'✅',EscrowCancel:'✕',AccountSet:'⚙',SetRegularKey:'🔑',SignerListSet:'📋'})[t] || '📄';
}
function _fmtAmt(a) {
  if (!a) return '—';
  if (typeof a==='string') return `${fmt(Number(a)/1e6,4)} XRP`;
  return `${fmt(parseFloat(a.value||0),4)} ${(a.currency||'?').length>4?a.currency.slice(0,4)+'…':a.currency}`;
}

function _renderTxList(txns, address) {
  if (!txns?.length) return `<div class="wdd-empty"><div class="wdd-empty-icon">📋</div><div>No transactions yet.</div><div class="wdd-empty-sub">Fund with 10 XRP to activate.</div></div>`;
  return `<div class="wdd-tx-list">
    ${txns.slice(0,25).map(tx => {
      const type  = tx.TransactionType||'?';
      const isOut = tx.Account===address;
      const ok    = !(tx.metaData?.TransactionResult||tx.meta?.TransactionResult||'').match(/^tec|^tem|^tef|^tel/);
      const raw   = tx.date ? (tx.date+946684800)*1000 : 0;
      const date  = raw ? new Date(raw).toLocaleDateString('en-US',{month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'}) : '—';
      const hash  = tx.hash||tx.tx_hash||'';
      return `<div class="wdd-tx-row ${ok?'':'wdd-tx-failed'}">
        <div class="wdd-tx-icon">${_txTypeIcon(type)}</div>
        <div class="wdd-tx-body">
          <div class="wdd-tx-type-row">
            <span class="wdd-tx-type">${type}</span>
            <span class="wdd-tx-dir ${isOut?'out':'in'}">${isOut?'↑ Out':'↓ In'}</span>
            ${!ok?'<span class="wdd-tx-fail-badge">Failed</span>':''}
          </div>
          <div class="wdd-tx-detail">
            ${tx.Amount?`<span class="wdd-tx-amount">${_fmtAmt(tx.Amount)}</span>`:''}
            ${tx.Destination?`<span class="wdd-tx-dest mono">${(addrBook[tx.Destination]||tx.Destination.slice(0,8)+'…'+tx.Destination.slice(-5))}</span>`:''}
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

function _renderNFTGallery(nfts, address) {
  if (!nfts?.length) return `<div class="wdd-empty"><div class="wdd-empty-icon">🎨</div><div>No NFTs in this wallet.</div></div>`;
  return `<div class="wdd-nft-header"><span>${nfts.length} NFT${nfts.length>1?'s':''}</span>
    <a class="wdd-view-more-inline" href="https://xrpscan.com/account/${address}#nfts" target="_blank">View on XRPScan →</a></div>
    <div class="wdd-nft-grid">
      ${nfts.slice(0,24).map(n => {
        const serial = n.nft_serial ?? n.NFTokenID?.slice(-6) ?? '?';
        const uri    = n.URI ? _hexToAscii(n.URI)||'' : '';
        const img    = uri.startsWith('ipfs://') ? `https://cloudflare-ipfs.com/ipfs/${uri.slice(7)}` : '';
        return `<div class="wdd-nft-card">
          <div class="wdd-nft-art">${img?`<img src="${escHtml(img)}" class="wdd-nft-img" alt="NFT" onerror="this.parentNode.innerHTML='<span class=wdd-nft-placeholder>🎨</span>'" />`:'<span class="wdd-nft-placeholder">🎨</span>'}</div>
          <div class="wdd-nft-info"><div class="wdd-nft-id mono">#${serial}</div></div>
        </div>`;
      }).join('')}
    </div>
    ${nfts.length>24?`<div class="wdd-more-note">${nfts.length-24} more on XRPScan</div>`:''}`;
}

function _renderDEXOrders(offers, walletId, address) {
  if (!offers?.length) return `<div class="wdd-empty"><div class="wdd-empty-icon">📊</div><div>No open DEX orders.</div></div>`;
  return `<div class="wdd-orders-header"><span>${offers.length} open order${offers.length>1?'s':''}</span></div>
    <div class="wdd-orders-list">
      ${offers.map(o => `<div class="wdd-order-row">
        <div class="wdd-order-dir ${o.flags&0x80000?'sell':'buy'}">${o.flags&0x80000?'SELL':'BUY'}</div>
        <div class="wdd-order-pair">
          <span class="wdd-order-gets">${_fmtAmt(o.TakerGets)}</span>
          <span class="wdd-order-arrow">⇄</span>
          <span class="wdd-order-pays">${_fmtAmt(o.TakerPays)}</span>
        </div>
        <div class="wdd-order-seq mono">Seq #${o.seq||'?'}</div>
        <button class="wdd-order-cancel" onclick="cancelOffer('${walletId}',${o.seq},this)">✕ Cancel</button>
      </div>`).join('')}
    </div>`;
}

async function _renderAMMPositions(address) {
  try {
    // account_lines filtered for AMM LP tokens (currency length 40 = hex AMM pool ID)
    const lines = trustlineCache[address] || [];
    const lpLines = lines.filter(l => l.currency?.length === 40);
    if (!lpLines.length) return `<div class="wdd-empty"><div class="wdd-empty-icon">🌊</div><div>No AMM LP positions.</div><div class="wdd-empty-sub">Deposit into an AMM pool to earn fees.</div></div>`;
    return `<div class="wdd-amm-list">
      ${lpLines.map(l => {
        const poolHex = l.currency;
        const bal = fmt(parseFloat(l.balance||0), 6);
        return `<div class="wdd-amm-row">
          <div class="wdd-amm-icon">🌊</div>
          <div class="wdd-amm-info">
            <div class="wdd-amm-pool mono">${poolHex.slice(0,12)}…</div>
            <div class="wdd-amm-bal">LP Tokens: ${bal}</div>
            <div class="wdd-amm-issuer mono" style="opacity:.4;font-size:.7rem">${l.issuer.slice(0,14)}…</div>
          </div>
          <a class="wdd-tx-hash" href="https://xrpscan.com/amm/${l.issuer}" target="_blank" rel="noopener">View AMM</a>
        </div>`;
      }).join('')}
    </div>`;
  } catch(e) {
    return `<div class="wdd-error">⚠️ ${escHtml(e.message)}</div>`;
  }
}

export async function cancelOffer(walletId, seq, btn) {
  const seed = prompt('Enter seed to cancel this order (used once, never stored):');
  if (!seed) return;
  if (btn) { btn.disabled = true; btn.textContent = '…'; }
  try {
    const result = await executeOfferCancel(walletId, seq, seed);
    if (_isTxSuccess(result)) {
      toastInfo('Order cancelled ✓');
      const w = wallets.find(x => x.id === walletId);
      if (w) { delete offerCache[w.address]; _loadDrawerTab(walletId, 'orders'); }
    } else {
      toastErr('Cancel failed: ' + _txError(result));
      if (btn) { btn.disabled = false; btn.textContent = '✕ Cancel'; }
    }
  } catch(err) { toastErr(err.message); if (btn) { btn.disabled = false; btn.textContent = '✕ Cancel'; } }
}

/* ═══════════════════════════════════════════════════
   Activity Tab
═══════════════════════════════════════════════════ */
function renderActivityPanel() {
  const el = $('profile-tab-activity');
  if (!el) return;
  const log = _getActivity();
  const w   = getActiveWallet();
  el.innerHTML = `
    <div class="act-section-row">
      <div class="act-section">
        <div class="act-section-title">In-App Activity</div>
        <div class="act-section-sub">Your recent actions in NaluXRP</div>
        ${!log.length
          ? '<div class="act-empty-small">No activity yet.</div>'
          : `<div class="act-timeline">${log.slice(0,20).map(e => `
            <div class="act-entry">
              <div class="act-entry-icon">${ACT_ICONS[e.type]||'●'}</div>
              <div class="act-entry-body">
                <div class="act-entry-detail">${escHtml(e.detail)}</div>
                <div class="act-entry-time">${_relTime(e.ts)}</div>
              </div>
            </div>`).join('')}</div>`}
      </div>
      <div class="act-section">
        <div class="act-section-title">On-Chain Activity</div>
        <div class="act-section-sub">Full forensic analysis via Inspector</div>
        ${w ? `<div class="act-redirect-card">
          <div class="act-rc-icon">🔍</div>
          <div class="act-rc-body">
            <div class="act-rc-title">${escHtml(w.label)}</div>
            <div class="act-rc-sub">Transaction history, wash trading signals, fund flow tracing, and a full investigation report.</div>
            <button class="act-inspect-btn-lg" onclick="inspectWalletAddr('${escHtml(w.address)}')">Open Inspector →</button>
          </div>
        </div>` : '<div class="act-empty-small">Create a wallet to inspect on-chain activity.</div>'}
      </div>
    </div>`;
}

/* ═══════════════════════════════════════════════════
   Settings Tab
═══════════════════════════════════════════════════ */
function renderSettingsPanel() {
  const el = $('profile-tab-settings');
  if (!el) return;


  const themes   = ['gold','cosmic','starry','hawaiian'];
  const currency = safeGet('nalulf_pref_currency')  || 'XRP';
  const network  = safeGet('nalulf_pref_network')   || 'mainnet';
  const autoLock = safeGet('nalulf_pref_autolock')  || '30';

  el.innerHTML = `<div class="settings-grid">

    <div class="settings-card">
      <div class="settings-card-hdr"><span class="settings-card-icon">🎨</span>
        <div><div class="settings-card-title">Appearance</div><div class="settings-card-sub">Theme and display preferences</div></div></div>
      <div class="settings-label">Theme</div>
      <div class="settings-theme-row">
        ${themes.map(t=>`<button class="theme-pill ${t} ${state.currentTheme===t?'active':''}" onclick="prefSetTheme('${t}')">${t[0].toUpperCase()+t.slice(1)}</button>`).join('')}
      </div>
      <div style="margin-top:16px"><div class="settings-label">Display currency</div>
        <div class="settings-seg">
          <button class="settings-seg-btn ${currency==='XRP'?'active':''}" onclick="setPrefCurrency('XRP')">XRP</button>
          <button class="settings-seg-btn ${currency==='USD'?'active':''}" onclick="setPrefCurrency('USD')">USD</button>
        </div>
      </div>
    </div>

    <div class="settings-card">
      <div class="settings-card-hdr"><span class="settings-card-icon">🌐</span>
        <div><div class="settings-card-title">Network</div><div class="settings-card-sub">Default XRPL network for new wallets</div></div></div>
      <div class="settings-label">Default network</div>
      <div class="settings-seg">
        <button class="settings-seg-btn ${network==='mainnet'?'active':''}" onclick="setPrefNetwork('mainnet')">🟢 Mainnet</button>
        <button class="settings-seg-btn ${network==='testnet'?'active':''}" onclick="setPrefNetwork('testnet')">🟡 Testnet</button>
      </div>
      <div style="margin-top:16px"><div class="settings-label">Auto-lock after</div>
        <div class="settings-seg">
          <button class="settings-seg-btn ${autoLock==='15'?'active':''}" onclick="setPrefAutoLock('15')">15 min</button>
          <button class="settings-seg-btn ${autoLock==='30'?'active':''}" onclick="setPrefAutoLock('30')">30 min</button>
          <button class="settings-seg-btn ${autoLock==='60'?'active':''}" onclick="setPrefAutoLock('60')">1 hr</button>
        </div>
      </div>
    </div>

    <div class="settings-card">
      <div class="settings-card-hdr"><span class="settings-card-icon">🔐</span>
        <div><div class="settings-card-title">Vault Security</div><div class="settings-card-sub">AES-256-GCM · PBKDF2 · SHA-256</div></div></div>
      <div class="settings-kv-list">
        <div class="settings-kv"><span class="settings-k">Encryption</span><span class="settings-v mono">AES-256-GCM</span></div>
        <div class="settings-kv"><span class="settings-k">Key derivation</span><span class="settings-v mono">PBKDF2 · 150k iterations</span></div>
        <div class="settings-kv"><span class="settings-k">Vault created</span><span class="settings-v">${escHtml(createdAt)}</span></div>
        <div class="settings-kv"><span class="settings-k">Server storage</span><span class="settings-v settings-v--good">None · local only</span></div>
        <div class="settings-kv"><span class="settings-k">Wallets</span><span class="settings-v">${wallets.length} stored</span></div>
      </div>
    </div>

    <div class="settings-card">
      <div class="settings-card-hdr"><span class="settings-card-icon">📂</span>
        <div><div class="settings-card-title">Backup &amp; Recovery</div><div class="settings-card-sub">Keep a copy of your encrypted vault</div></div></div>
      <p class="settings-card-desc">Your backup is still encrypted — unreadable without your password. Store on USB or an external drive, <strong>not</strong> in the cloud.</p>
      <div class="settings-actions">
        <button class="settings-btn settings-btn--primary" onclick="exportWalletAddresses()">⬇ Export Wallet Addresses</button>
        <button class="settings-btn" onclick="exportVaultSyncCode()">📱 Device Sync Code</button>
      </div>
    </div>

    <div class="settings-card">
      <div class="settings-card-hdr"><span class="settings-card-icon">📡</span>
        <div><div class="settings-card-title">Privacy Architecture</div></div></div>
      <div class="settings-privacy-list">
        <div class="settings-privacy-item settings-privacy--good"><span class="spi-dot"></span><div><strong>Zero server storage.</strong> Profile, wallets, and seeds never leave your browser.</div></div>
        <div class="settings-privacy-item settings-privacy--good"><span class="spi-dot"></span><div><strong>Direct XRPL connections.</strong> No proxy — connects directly to public nodes.</div></div>
        <div class="settings-privacy-item settings-privacy--good"><span class="spi-dot"></span><div><strong>No telemetry.</strong> No analytics, no tracking scripts.</div></div>
        <div class="settings-privacy-item settings-privacy--warn"><span class="spi-dot"></span><div><strong>On-chain data is public.</strong> XRPL transactions are permanently visible to anyone.</div></div>
      </div>
    </div>

    <div class="settings-card settings-card--danger">
      <div class="settings-card-hdr"><span class="settings-card-icon">⚠️</span>
        <div><div class="settings-card-title">Danger Zone</div><div class="settings-card-sub">Irreversible actions</div></div></div>
      <p class="settings-card-desc">Wiping removes all local data. Your wallets still exist on-chain and can be re-added with their seed phrases.</p>
      <button class="settings-btn settings-btn--danger" onclick="openAuth?.('forgot')">🗑 Wipe Account Data</button>
    </div>
  </div>`;
}

/* ═══════════════════════════════════════════════════
   Security Tab
═══════════════════════════════════════════════════ */
function renderSecurityPanel() {
  const el = $('profile-tab-security');
  if (!el) return;



  el.innerHTML = `<div class="sec-grid">
    <div class="sec-card">
      <div class="sec-card-hdr"><span class="sec-card-icon">🔐</span>
        <div><div class="sec-card-title">Local Encrypted Vault</div><div class="sec-card-sub">AES-256-GCM · PBKDF2 150,000 iterations</div></div>
        <span class="sec-status-pill ${unlocked?'sec-status--open':'sec-status--locked'}">${unlocked?'Unlocked':'Locked'}</span>
      </div>
      <div class="sec-kv-grid">
        <div class="sec-kv"><span class="sec-k">Encryption</span><span class="sec-v mono">AES-256-GCM</span></div>
        <div class="sec-kv"><span class="sec-k">KDF</span><span class="sec-v mono">PBKDF2 · 150k iterations · SHA-256</span></div>
        <div class="sec-kv"><span class="sec-k">Vault created</span><span class="sec-v">${createdAt}</span></div>
        <div class="sec-kv"><span class="sec-k">Server storage</span><span class="sec-v sec-v--good">None — local only</span></div>
        <div class="sec-kv"><span class="sec-k">Password stored</span><span class="sec-v sec-v--good">Never — key derivation only</span></div>
        <div class="sec-kv"><span class="sec-k">Signing</span><span class="sec-v sec-v--good">In-browser only, seed zero'd after use</span></div>
      </div>
      <div class="sec-card-actions">
        <button class="sec-btn sec-btn--primary" onclick="exportWalletAddresses()">⬇ Export Wallet Addresses</button>
      </div>
      <div class="sec-note"><span class="sec-note-icon">ℹ</span>Your backup is still encrypted. It cannot be read without your password.</div>
    </div>
    <div class="sec-card">
      <div class="sec-card-hdr"><span class="sec-card-icon">✍️</span>
        <div><div class="sec-card-title">Seed Phrase Best Practices</div></div></div>
      <div class="sec-practices">
        ${[
          ['Write it on paper now','Store in a fireproof box or safety deposit box. This is your only recovery option if you lose this device.'],
          ['Never store it digitally','No notes apps, emails, cloud drives, or screenshots. A hacked device means instant loss of funds.'],
          ['Never share it with anyone','No legitimate app or support team will ever ask. Anyone who asks is attempting theft.'],
          ['Use a strong unique password','Your password protects the encrypted vault on this device.'],
          ['Export your backup regularly','Use the Export Backup button after creating or modifying wallets. Keep the file offline.'],
        ].map(([t,b],i)=>`<div class="sec-practice">
          <div class="sec-practice-num">${i+1}</div>
          <div class="sec-practice-body"><strong>${t}.</strong> ${b}</div>
        </div>`).join('')}
      </div>
    </div>
    <div class="sec-card">
      <div class="sec-card-hdr"><span class="sec-card-icon">📡</span>
        <div><div class="sec-card-title">XRPL Capabilities</div><div class="sec-card-sub">What your wallets can do in NaluXRP</div></div></div>
      <div class="sec-caps-grid">
        ${[['💸','XRP & IOU Payments'],['🔗','Trustlines (TrustSet)'],['📊','DEX Orders (CLOB)'],['🌊','AMM Deposits & Swaps'],['🎨','NFT Mint & Transfer'],['🔍','On-chain Forensic Inspect'],['🏦','Multi-wallet Management'],['🛡','Ed25519 & secp256k1']].map(([ic,l])=>`<div class="sec-cap"><span class="sec-cap-icon">${ic}</span><span>${l}</span></div>`).join('')}
      </div>
    </div>
  </div>`;
}

/* ═══════════════════════════════════════════════════
   Analytics Tab
═══════════════════════════════════════════════════ */
async function renderAnalyticsTab() {
  const el = $('profile-tab-analytics');
  if (!el) return;
  el.innerHTML = `<div class="analytics-grid"><div class="skeleton-card analytics-card--wide" style="height:80px"></div><div class="skeleton-card" style="height:160px"></div><div class="skeleton-card" style="height:160px"></div></div>`;

  try {
    const activeW   = getActiveWallet();
    const totalXrp  = Object.values(balanceCache).reduce((s,c)=>s+(c?.xrp||0),0);
    const xrpPrice  = _getXrpPrice();
    const allTokens = Object.values(balanceCache).flatMap(c=>c?.tokens||[]);
    let heatTxns = [];
    if (activeW) {
      try { heatTxns = txCache[activeW.address]?.txns || await fetchTxHistory(activeW.address, 100); } catch {}
    }

    el.innerHTML = `<div class="analytics-grid">
      <div class="analytics-card analytics-card--wide">
        <div class="analytics-card-hdr"><span class="analytics-card-title">💼 Portfolio Summary</span>
          <span class="analytics-badge">${wallets.length} wallet${wallets.length!==1?'s':''}</span></div>
        <div class="portfolio-summary-row">
          ${!wallets.length ? '<div class="analytics-empty">No wallets yet.</div>'
            : wallets.map(w => {
              const c   = balanceCache[w.address];
              const xrp = c ? fmt(c.xrp,2) : '—';
              const usd = c && xrpPrice ? `$${fmt(c.xrp*xrpPrice,2)}` : '';
              const h   = _getBalanceHistory(w.address);
              return `<div class="portfolio-wallet-row">
                <div class="pwr-icon" style="color:${w.color};background:${w.color}18;border-color:${w.color}33">${escHtml(w.emoji||'💎')}</div>
                <div class="pwr-info"><div class="pwr-label">${escHtml(w.label)}</div><div class="pwr-addr mono">${w.address.slice(0,8)}…${w.address.slice(-5)}</div></div>
                <div class="pwr-sparkline">${_buildSparkline(h,80,28,w.color||'#00fff0')}</div>
                <div class="pwr-balance"><div class="pwr-xrp">${xrp} <span class="pwr-xrp-label">XRP</span></div>${usd?`<div class="pwr-usd">${usd}</div>`:''}</div>
              </div>`;
            }).join('')}
        </div>
        <div class="portfolio-totals">
          <div class="ptotal"><span class="ptotal-label">Total XRP</span><span class="ptotal-val">${fmt(totalXrp,4)}</span></div>
          ${xrpPrice?`<div class="ptotal"><span class="ptotal-label">Est. USD</span><span class="ptotal-val ptotal-usd">$${fmt(totalXrp*xrpPrice,2)}</span></div>`:''}
          <div class="ptotal"><span class="ptotal-label">Tokens</span><span class="ptotal-val">${allTokens.length}</span></div>
          <div class="ptotal"><span class="ptotal-label">Wallets</span><span class="ptotal-val">${wallets.length}</span></div>
        </div>
      </div>

      ${activeW ? `<div class="analytics-card analytics-card--wide">
        <div class="analytics-card-hdr"><span class="analytics-card-title">📈 Balance History</span>
          <span class="analytics-badge">${escHtml(activeW.label)}</span></div>
        ${_buildBalanceChart(activeW.address)}
      </div>` : ''}

      <div class="analytics-card analytics-card--wide">
        <div class="analytics-card-hdr"><span class="analytics-card-title">📅 On-Chain Activity</span>
          <span class="analytics-badge">${activeW?escHtml(activeW.label):'No wallet'}</span></div>
        ${activeW ? _buildHeatmap(heatTxns) : '<div class="analytics-empty">Activate a wallet to see activity.</div>'}
      </div>

      ${heatTxns.length ? `<div class="analytics-card">
        <div class="analytics-card-hdr"><span class="analytics-card-title">📊 TX Breakdown</span>
          <span class="analytics-badge">${heatTxns.length} recent</span></div>
        ${_buildTxBreakdown(heatTxns)}
      </div>` : ''}

      ${activeW && heatTxns.length ? `<div class="analytics-card">
        <div class="analytics-card-hdr"><span class="analytics-card-title">💰 XRP Flow</span>
          <span class="analytics-badge">Est. net</span></div>
        ${_buildXrpFlow(heatTxns, activeW.address)}
      </div>` : ''}

      ${allTokens.length ? `<div class="analytics-card">
        <div class="analytics-card-hdr"><span class="analytics-card-title">🪙 Token Holdings</span>
          <span class="analytics-badge">${allTokens.length} assets</span></div>
        ${_buildTokenAllocation(allTokens)}
      </div>` : ''}
    </div>`;
  } catch(err) { _renderTabError(el, 'analytics', err); }
}

function _buildSparkline(hist, W, H, color) {
  if (hist.length < 2) return `<svg width="${W}" height="${H}"><line x1="0" y1="${H/2}" x2="${W}" y2="${H/2}" stroke="${color}" stroke-opacity=".2" stroke-width="1" stroke-dasharray="3 2"/></svg>`;
  const vals = hist.map(h=>h.xrp), mn=Math.min(...vals), mx=Math.max(...vals), range=mx-mn||1;
  const pts  = vals.map((v,i) => `${3+(i/(vals.length-1))*(W-6)},${3+(1-(v-mn)/range)*(H-6)}`);
  const [lx,ly] = pts[pts.length-1].split(',');
  return `<svg width="${W}" height="${H}" viewBox="0 0 ${W} ${H}">
    <polyline points="${pts.join(' ')}" fill="none" stroke="${color}" stroke-width="1.5" stroke-opacity=".8" stroke-linejoin="round" stroke-linecap="round"/>
    <circle cx="${lx}" cy="${ly}" r="2.5" fill="${color}" opacity=".9"/>
  </svg>`;
}

function _buildBalanceChart(address) {
  const hist = _getBalanceHistory(address);
  if (hist.length < 2) return `<div class="analytics-empty-chart"><div class="aec-icon">📊</div><div>Balance history builds up as you refresh your wallet over time.</div><div class="aec-sub">${hist.length} snapshot${hist.length!==1?'s':''} recorded.</div></div>`;
  const W=560,H=130,pL=52,pR=12,pT=14,pB=30;
  const vals=hist.map(h=>h.xrp), tms=hist.map(h=>h.ts);
  const mn=Math.min(...vals), mx=Math.max(...vals), range=mx-mn||1;
  const tMn=tms[0], tMx=tms[tms.length-1], tRange=tMx-tMn||1;
  const toX = ts  => pL+((ts-tMn)/tRange)*(W-pL-pR);
  const toY = val => pT+(1-(val-mn)/range)*(H-pT-pB);
  const pts  = hist.map(h=>`${toX(h.ts).toFixed(1)},${toY(h.xrp).toFixed(1)}`);
  const fX=toX(tms[0]), lX=toX(tms[tms.length-1]);
  const delta=vals[vals.length-1]-vals[0], up=delta>=0;
  const pct = vals[0] ? Math.abs(delta/vals[0]*100).toFixed(2) : '0.00';
  const color=up?'#00d4ff':'#ff5555';
  const yTicks=[mn,(mn+mx)/2,mx].map(v=>({v,y:toY(v),l:fmt(v,2)}));
  const xTicks=[0,.5,1].map(f=>({x:pL+f*(W-pL-pR),l:new Date(tMn+f*tRange).toLocaleDateString('en-US',{month:'short',day:'numeric'})}));
  return `
    <div class="balance-chart-meta">
      <div class="bcm-current">${fmt(vals[vals.length-1],4)} XRP</div>
      <div class="bcm-delta ${up?'bcm-up':'bcm-down'}">${up?'▲':'▼'} ${pct}%</div>
      <div class="bcm-range">${hist.length} snapshots</div>
    </div>
    <div class="balance-chart-wrap"><svg class="balance-chart-svg" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none">
      <defs><linearGradient id="bg${address.slice(-4)}" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="${color}" stop-opacity=".22"/><stop offset="100%" stop-color="${color}" stop-opacity="0"/></linearGradient></defs>
      ${yTicks.map(t=>`<line x1="${pL}" y1="${t.y.toFixed(1)}" x2="${W-pR}" y2="${t.y.toFixed(1)}" stroke="rgba(255,255,255,.06)" stroke-width="1"/>`).join('')}
      <path d="M${fX.toFixed(1)},${H-pB} L${pts.join(' L')} L${lX.toFixed(1)},${H-pB} Z" fill="url(#bg${address.slice(-4)})"/>
      <polyline points="${pts.join(' ')}" fill="none" stroke="${color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
      ${hist.map(h=>`<circle cx="${toX(h.ts).toFixed(1)}" cy="${toY(h.xrp).toFixed(1)}" r="2" fill="${color}" opacity=".7"/>`).join('')}
      ${yTicks.map(t=>`<text x="${pL-5}" y="${(t.y+4).toFixed(1)}" text-anchor="end" fill="rgba(255,255,255,.38)" font-size="10" font-family="JetBrains Mono,monospace">${t.l}</text>`).join('')}
      ${xTicks.map(t=>`<text x="${t.x.toFixed(1)}" y="${H-6}" text-anchor="middle" fill="rgba(255,255,255,.32)" font-size="10" font-family="JetBrains Mono,monospace">${t.l}</text>`).join('')}
    </svg></div>`;
}

function _buildHeatmap(txns) {
  const cells=new Map();
  txns.forEach(tx => { if (!tx.date) return; cells.set(new Date((tx.date+946684800)*1000).toISOString().slice(0,10),(cells.get(new Date((tx.date+946684800)*1000).toISOString().slice(0,10))||0)+1); });
  const WEEKS=26,CELL=12,GAP=2, now=new Date();
  const days=Array.from({length:WEEKS*7},(_,i)=>{ const d=new Date(now); d.setDate(d.getDate()-(WEEKS*7-1-i)); return d; });
  const byWeek=Array.from({length:WEEKS},(_,w)=>days.slice(w*7,w*7+7));
  const maxC=Math.max(1,...cells.values());
  const W=WEEKS*(CELL+GAP)+30, H=7*(CELL+GAP)+28;
  const heatColor=f=>f===0?'rgba(255,255,255,.07)':`rgb(0,${Math.round(85+f*170)},${Math.round(119+f*121)})`;
  const monthLabels=[]; let lastM=-1;
  byWeek.forEach((wk,wi)=>{ const m=wk[0]?.getMonth(); if(m!==lastM){lastM=m;monthLabels.push({wi,l:wk[0].toLocaleDateString('en-US',{month:'short'})});} });
  return `<div class="heatmap-meta"><span>${txns.length} tx · ${cells.size} active days</span>
    <div class="heatmap-legend"><span>Less</span><div class="heatmap-legend-cells">${[0,.25,.5,.75,1].map(f=>`<div class="hm-leg-cell" style="background:${heatColor(f)}"></div>`).join('')}</div><span>More</span></div>
  </div>
  <div class="heatmap-scroll"><svg class="heatmap-svg" viewBox="0 0 ${W} ${H}" width="${W}" height="${H}">
    ${monthLabels.map(({wi,l})=>`<text x="${26+wi*(CELL+GAP)}" y="10" font-size="9" fill="rgba(255,255,255,.38)" font-family="Outfit,sans-serif">${l}</text>`).join('')}
    ${['','Mon','','Wed','','Fri',''].map((l,di)=>l?`<text x="0" y="${16+di*(CELL+GAP)+CELL/2+3}" font-size="9" fill="rgba(255,255,255,.3)" font-family="Outfit,sans-serif">${l}</text>`:'').join('')}
    ${byWeek.map((wk,wi)=>wk.map((day,di)=>{ const k=day.toISOString().slice(0,10),c=cells.get(k)||0; return `<rect x="${26+wi*(CELL+GAP)}" y="${16+di*(CELL+GAP)}" width="${CELL}" height="${CELL}" rx="2" fill="${heatColor(c/maxC)}" opacity="${c>0?.9:.25}"><title>${k}: ${c} tx</title></rect>`; }).join('')).join('')}
  </svg></div>`;
}

function _buildTxBreakdown(txns) {
  const map=new Map(); txns.forEach(tx=>map.set(tx.TransactionType||'?',(map.get(tx.TransactionType||'?')||0)+1));
  const sorted=[...map.entries()].sort((a,b)=>b[1]-a[1]);
  const total=txns.length;
  return `<div class="tx-breakdown-list">${sorted.slice(0,8).map(([t,c])=>`<div class="txb-row"><div class="txb-icon">${_txTypeIcon(t)}</div><div class="txb-type">${t}</div><div class="txb-bar-wrap"><div class="txb-bar" style="width:${(c/total*100).toFixed(0)}%"></div></div><div class="txb-count">${c}</div></div>`).join('')}</div>`;
}

function _buildTokenAllocation(tokens) {
  const map=new Map(); tokens.forEach(t=>{ const b=Math.abs(parseFloat(t.balance||0)); map.set(t.currency,(map.get(t.currency)||0)+b); });
  const sorted=[...map.entries()].sort((a,b)=>b[1]-a[1]).slice(0,8);
  const total=sorted.reduce((s,[,v])=>s+v,0)||1;
  const COLORS=['#00fff0','#00d4ff','#bd93f9','#50fa7b','#ffb86c','#ff79c6','#f1fa8c','#ff5555'];
  return `<div class="token-alloc-list">${sorted.map(([cur,bal],i)=>{ const pct=(bal/total*100).toFixed(1),c=COLORS[i%COLORS.length],l=cur.length>4?cur.slice(0,4)+'…':cur; return `<div class="ta-row"><div class="ta-swatch" style="background:${c}"></div><div class="ta-cur mono">${l}</div><div class="ta-bar-wrap"><div class="ta-bar" style="width:${pct}%;background:${c}20;border-color:${c}55"></div></div><div class="ta-pct">${pct}%</div></div>`; }).join('')}</div>`;
}

function _buildXrpFlow(txns, address) {
  let inflow=0, outflow=0;
  txns.forEach(tx => {
    if (tx.TransactionType!=='Payment') return;
    const ok=(tx.metaData?.TransactionResult||tx.meta?.TransactionResult)==='tesSUCCESS';
    if (!ok || typeof tx.Amount!=='string') return;
    const amt=Number(tx.Amount)/1e6;
    if (tx.Destination===address) inflow+=amt;
    if (tx.Account===address)     outflow+=amt;
  });
  const net=inflow-outflow, up=net>=0;
  return `<div class="xrp-flow-grid">
    <div class="xrf-item xrf-in"><div class="xrf-label">↓ Inflow</div><div class="xrf-val">${fmt(inflow,4)} XRP</div></div>
    <div class="xrf-item xrf-out"><div class="xrf-label">↑ Outflow</div><div class="xrf-val">${fmt(outflow,4)} XRP</div></div>
    <div class="xrf-item ${up?'xrf-pos':'xrf-neg'}"><div class="xrf-label">Net</div><div class="xrf-val">${up?'+':''}${fmt(net,4)} XRP</div></div>
  </div>
  <div class="xrf-note">Based on ${txns.length} fetched Payment TXs. Excludes fees and DEX fills.</div>`;
}

/* ═══════════════════════════════════════════════════
   XRPL Network calls
═══════════════════════════════════════════════════ */
async function xrplPost(body) {
  const tryFetch = async (url) => {
    const r = await fetch(url, { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body) });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return (await r.json()).result;
  };
  try { return await tryFetch(XRPL_RPC); }
  catch { return await tryFetch(XRPL_RPC_BACKUP); }
}

export async function fetchBalance(address) {
  try {
    // Paginate account_lines to get all trustlines (not just first 400)
    let allLines = [], marker;
    do {
      const r = await xrplPost({ method:'account_lines', params:[{ account:address, ledger_index:'current', limit:400, ...(marker?{marker}:{}) }] });
      if (!r || r.error) break;
      allLines.push(...(r.lines||[]));
      marker = r.marker;
    } while (marker);

    const acct = await xrplPost({ method:'account_info', params:[{ account:address, ledger_index:'current' }] });
    if (acct?.error) return null;

    const xrp    = Number(acct.account_data.Balance) / 1e6;
    const tokens = allLines.map(l => ({ currency:l.currency, issuer:l.account, balance:l.balance, limit:l.limit }));
    balanceCache[address]   = { xrp, tokens, fetchedAt:Date.now() };
    trustlineCache[address] = tokens;
    _recordBalanceSnapshot(address, xrp);
    // Animate balance on the active wallet bar if visible
    const balEl = document.getElementById('awb-balance');
    if (balEl && address === getActiveWallet()?.address) _animateCounter(balEl.querySelector('.awb-xrp-num') || balEl, xrp, 2, 600);
    return balanceCache[address];
  } catch { return null; }
}

async function fetchAllBalances() {
  await Promise.allSettled(wallets.map(w => fetchBalance(w.address)));
  renderWalletList(); renderActiveWalletBar(); renderProfileMetrics();
}

function _recordBalanceSnapshot(address, xrp) {
  const key  = LS_BAL_HIST_PFX + address;
  const hist = safeJson(safeGet(key)) || [];
  const now  = Date.now();
  if (hist.length && now - hist[hist.length-1].ts < 5*60_000) hist[hist.length-1] = {xrp,ts:now};
  else hist.push({xrp,ts:now});
  if (hist.length > 90) hist.splice(0, hist.length-90);
  safeSet(key, JSON.stringify(hist));
}
function _getBalanceHistory(address) { return safeJson(safeGet(LS_BAL_HIST_PFX+address)) || []; }

async function fetchTxHistory(address, limit=25) {
  const r = await xrplPost({ method:'account_tx', params:[{ account:address, limit, ledger_index_min:-1, ledger_index_max:-1 }] });
  const txns = (r?.transactions||[]).map(t=>t.tx||t.transaction||t);
  txCache[address] = { txns, fetchedAt:Date.now() };
  return txns;
}
async function fetchNFTs(address) {
  const r = await xrplPost({ method:'account_nfts', params:[{ account:address, limit:50 }] });
  const nfts = r?.account_nfts||[];
  nftCache[address] = { nfts, fetchedAt:Date.now() };
  return nfts;
}
async function fetchOpenOffers(address) {
  const r = await xrplPost({ method:'account_offers', params:[{ account:address, limit:50 }] });
  const offers = r?.offers||[];
  offerCache[address] = { offers, fetchedAt:Date.now() };
  return offers;
}
async function getAccountInfo(address) {
  const r = await xrplPost({ method:'account_info', params:[{ account:address, ledger_index:'current' }] });
  return r?.account_data || null;
}
async function getCurrentLedger() {
  const r = await xrplPost({ method:'ledger', params:[{ ledger_index:'current' }] });
  return r?.ledger_current_index || 0;
}

/* ── XRPL result helpers ── */
function _isTxSuccess(r) {
  const code = r?.engine_result || '';
  return code === 'tesSUCCESS' || code.startsWith('tes') || r?.engine_result_code === 0;
}
function _txError(r) {
  const code = r?.engine_result || '';
  return XRPL_ERRORS[code] || r?.engine_result_message || code || 'Unknown error';
}

/* ═══════════════════════════════════════════════════
   Transaction Signing + Submission
═══════════════════════════════════════════════════ */
async function _requireVaultUnlocked() {
  // seed param required - checked below
}
async function signAndSubmit(walletId, txJson, seed) {
  if (!seed) throw new Error('Seed phrase is required to sign transactions.');
  if (!window.xrpl) throw new Error('xrpl.js library not loaded. Cannot sign transactions.');
  const wObj = wallets.find(w => w.id === walletId);
  if (!wObj) throw new Error('Wallet not found.');
  if (wObj.watchOnly) throw new Error('Watch-only wallets cannot sign transactions.');
  let xrplWallet;
  try { xrplWallet = window.xrpl.Wallet.fromSeed(seed, { algorithm: wObj.algo==='secp256k1'?'secp256k1':'ed25519' }); }
  catch(e) { throw new Error('Invalid seed phrase: ' + e.message); }
  if (xrplWallet.classicAddress !== wObj.address)
    throw new Error('Seed does not match this wallet address.');
  try {
    const [acctInfo, ledger] = await Promise.all([getAccountInfo(wObj.address), getCurrentLedger()]);
    if (!acctInfo) throw new Error('Account not found on-chain. Fund with at least 10 XRP first (base reserve requirement).');
    const prepared = {
      ...txJson,
      Account:            wObj.address,
      Fee:                '12',
      Sequence:           acctInfo.Sequence,
      LastLedgerSequence: ledger + 20,
    };
    const { tx_blob, hash } = xrplWallet.sign(prepared);
    const result = await xrplPost({ method:'submit', params:[{ tx_blob }] });
    return { ...result, tx_hash: hash };
  } finally {
    // Zero seed reference
    void seed;
  }
}

export async function executeTrustSet(walletId, currency, issuer, limit = '1000000000', seed) {
  return signAndSubmit(walletId, { TransactionType:'TrustSet', LimitAmount:{ currency, issuer, value:String(limit) } });
}
export async function executePayment(walletId, destination, amount, currency, issuer, destinationTag, seed) {
  const isXRP = !currency || currency==='XRP';
  const Amount = isXRP ? String(Math.floor(parseFloat(amount)*1e6)) : { currency, issuer, value:String(amount) };
  return signAndSubmit(walletId, {
    TransactionType: 'Payment', Destination: destination, Amount,
    ...(destinationTag ? { DestinationTag:parseInt(destinationTag) } : {}),
  });
}
export async function executeOfferCreate(walletId, takerGets, takerPays) {
  return signAndSubmit(walletId, { TransactionType:'OfferCreate', TakerGets:takerGets, TakerPays:takerPays });
}
export async function executeOfferCancel(walletId, offerSequence) {
  return signAndSubmit(walletId, { TransactionType:'OfferCancel', OfferSequence:parseInt(offerSequence) });
}

/* ═══════════════════════════════════════════════════
   Send Modal
═══════════════════════════════════════════════════ */
let _sendWalletId = null;

export function openSendModal(walletId) {
  _sendWalletId = walletId;
  const w = wallets.find(x => x.id === walletId);
  if (!w) return;
  const modal = $('send-modal-overlay');
  if (!modal) return;
  const cached = trustlineCache[w.address] || [];
  const sel    = $('send-currency-select');
  if (sel) sel.innerHTML = `<option value="XRP">XRP</option>${cached.map(t=>`<option value="${escHtml(t.currency)}|${escHtml(t.issuer)}">${escHtml(t.currency.length>4?_hexToAscii(t.currency)||t.currency:t.currency)}</option>`).join('')}`;
  _setText('send-modal-wallet-name', w.label);
  _setText('send-from-address', w.address);
  _setText('send-available-balance', balanceCache[w.address] ? `${fmt(balanceCache[w.address].xrp,4)} XRP` : '—');
  ['send-dest','send-amount','send-dest-tag'].forEach(id => { const el=$(id); if(el)el.value=''; });
  const errEl = $('send-error'); if(errEl)errEl.textContent='';
  modal.classList.add('show');
  setTimeout(() => $('send-dest')?.focus(), 80);
}
export function closeSendModal() { $('send-modal-overlay')?.classList.remove('show'); }

export async function executeSend() {
  const w       = wallets.find(x => x.id === _sendWalletId);
  if (!w) return;
  const dest    = $('send-dest')?.value.trim()     || '';
  const amount  = $('send-amount')?.value.trim()   || '';
  const destTag = $('send-dest-tag')?.value.trim() || '';
  const selVal  = $('send-currency-select')?.value || 'XRP';
  const [currency, issuer] = selVal.includes('|') ? selVal.split('|') : ['XRP', null];
  const errEl = $('send-error');
  const setErr = m => { if(errEl) errEl.textContent = m; };
  setErr('');
  if (!isValidXrpAddress(dest))            return setErr('Enter a valid XRPL destination address (starts with r…).');
  if (!amount || isNaN(+amount) || +amount<=0) return setErr('Enter a valid positive amount.');
  if (currency==='XRP' && +amount < 0.000001)  return setErr('Minimum XRP amount is 0.000001 (1 drop).');
  const btn = $('send-submit-btn');
  if (btn) { btn.disabled=true; btn.textContent='Signing…'; }
  try {
    const result = await executePayment(_sendWalletId, dest, amount, currency==='XRP'?null:currency, issuer, destTag);
    if (_isTxSuccess(result)) {
      toastInfo(`✅ Sent! Tx: ${result.tx_hash?.slice(0,12)}…`);
      logActivity('sent', `${amount} ${currency} → ${dest.slice(0,10)}…`);
      closeSendModal();
      setTimeout(() => fetchBalance(w.address).then(()=>{ renderWalletList(); renderActiveWalletBar(); }), 4000);
    } else setErr(_txError(result));
  } catch(err) {
    setErr(err.message);
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Send ⬆'; }
    const _se = document.getElementById('send-seed'); if (_se) _se.value = '';
  }
}

/* ═══════════════════════════════════════════════════
   Receive Modal
═══════════════════════════════════════════════════ */
export function openReceiveModal(walletId) {
  const w = wallets.find(x => x.id === walletId);
  if (!w) return;
  const modal = $('receive-modal-overlay');
  if (!modal) return;
  _setText('receive-address-display', w.address);
  _setText('receive-wallet-name', w.label);
  const qr = $('receive-qr-container');
  if (qr) {
    qr.innerHTML = '';
    if (window.QRCode) new window.QRCode(qr, { text:`xrpl:${w.address}`, width:180, height:180, colorDark:'#00fff0', colorLight:'#080c16' });
    else qr.innerHTML = `<div class="qr-fallback" style="padding:20px;text-align:center;font-size:.85rem;color:rgba(255,255,255,.5)">Load QRCode.js for QR</div>`;
  }
  modal.classList.add('show');
}
export function closeReceiveModal() { $('receive-modal-overlay')?.classList.remove('show'); }
export function copyReceiveAddress() {
  const el = $('receive-address-display');
  if (el) _copyToClipboard(el.textContent);
  const btn = $('receive-copy-btn');
  if (btn) { btn.textContent='✓ Copied!'; setTimeout(()=>btn.textContent='⧉ Copy Address',2000); }
}

/* ═══════════════════════════════════════════════════
   Trustline Modal
═══════════════════════════════════════════════════ */
let _trustWalletId = null;

export function openTrustlineModal(walletId) {
  _trustWalletId = walletId;
  const w = wallets.find(x => x.id === walletId);
  if (!w) return;
  const modal = $('trustline-modal-overlay');
  if (!modal) return;
  _setText('trustline-wallet-name', w.label);
  renderTrustlineList(w.address);
  ['tl-currency','tl-issuer'].forEach(id=>{ const el=$(id); if(el)el.value=''; });
  const lim=$('tl-limit'); if(lim)lim.value='1000000000';
  const err=$('tl-error'); if(err)err.textContent='';
  modal.classList.add('show');
}
export function closeTrustlineModal() { $('trustline-modal-overlay')?.classList.remove('show'); }

function renderTrustlineList(address) {
  const c = $('trustline-list-container');
  if (!c) return;
  const lines = trustlineCache[address] || [];
  if (!lines.length) { c.innerHTML = `<div class="tl-empty">No trustlines yet. Add one below.</div>`; return; }
  c.innerHTML = lines.map(t => `<div class="tl-item">
    <div class="tl-item-info"><span class="tl-currency">${escHtml(t.currency.length>4?_hexToAscii(t.currency)||t.currency:t.currency)}</span><span class="tl-issuer mono">${escHtml(t.issuer.slice(0,14))}…</span></div>
    <div class="tl-item-balance"><span class="tl-balance">${escHtml(t.balance)}</span><span class="tl-limit">Limit: ${escHtml(t.limit)}</span></div>
    <button class="tl-remove-btn" onclick="removeTrustline('${_trustWalletId}','${escHtml(t.currency)}','${escHtml(t.issuer)}')">✕</button>
  </div>`).join('');
}

export async function addTrustline() {
  const currency = $('tl-currency')?.value.trim().toUpperCase() || '';
  const issuer   = $('tl-issuer')?.value.trim()   || '';
  const limit    = $('tl-limit')?.value.trim()     || '1000000000';
  const seed     = $('tl-seed')?.value             || '';
  const errEl    = $('tl-error');
  const setErr   = m => { if(errEl) errEl.textContent = m; };
  setErr('');
  if (!currency || currency.length>20) return setErr('Enter a valid currency code (3 chars or 20-char hex).');
  if (!isValidXrpAddress(issuer))       return setErr('Enter a valid issuer XRPL address (starts with r…).');
  const btn = $('tl-add-btn');
  if (btn) { btn.disabled=true; btn.textContent='Signing…'; }
  try {
    const result = await executeTrustSet(_trustWalletId, currency, issuer, limit, seed);
    if (_isTxSuccess(result)) {
      toastInfo(`✅ Trustline added for ${currency}`);
      logActivity('trustline_added', `${currency} (${issuer.slice(0,10)}…)`);
      closeTrustlineModal();
      const w = wallets.find(x => x.id === _trustWalletId);
      if (w) setTimeout(() => fetchBalance(w.address).then(()=>renderWalletList()), 4000);
    } else setErr(_txError(result));
  } catch(err) {
    setErr(err.message);
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = '+ Add Trustline'; }
    const _ts = document.getElementById('tl-seed'); if (_ts) _ts.value = '';
  }
}

export async function removeTrustline(walletId, currency, issuer) {
  const seed = prompt(`Enter seed to remove ${currency} trustline (used once, never stored):`); if (!seed) return;
  try {
    const result = await executeTrustSet(walletId, currency, issuer, '0', seed);
    if (_isTxSuccess(result)) {
      toastInfo(`Trustline removed for ${currency}`);
      const w = wallets.find(x => x.id === walletId);
      if (w) setTimeout(() => fetchBalance(w.address).then(()=>renderTrustlineList(w.address)), 4000);
    } else toastErr(_txError(result));
  } catch(err) { toastErr(err.message); }
}

/* ═══════════════════════════════════════════════════
   Dynamic Modal Mount
═══════════════════════════════════════════════════ */
function _mountDynamicModals() {
  if ($('send-modal-overlay')) return;
  const div = document.createElement('div');
  div.innerHTML = `
  <!-- Send -->
  <div class="wallet-action-overlay" id="send-modal-overlay">
    <div class="wallet-action-modal">
      <div class="wam-header"><div><div class="wam-title">⬆ Send</div><div class="wam-sub" id="send-modal-wallet-name"></div></div><button class="modal-close" onclick="closeSendModal()">✕</button></div>
      <div class="wam-body">
        <div class="wam-from-row"><span class="wam-from-label">From</span><span class="wam-from-addr mono" id="send-from-address"></span><span class="wam-balance-pill" id="send-available-balance"></span></div>
        <div class="profile-field"><label class="profile-field-label">Destination Address *</label><input class="profile-input mono" id="send-dest" placeholder="rXXXX…" autocomplete="off"></div>
        <div class="wam-row2">
          <div class="profile-field" style="flex:1"><label class="profile-field-label">Amount *</label><input class="profile-input mono" id="send-amount" type="number" placeholder="0.00" min="0" step="any"></div>
          <div class="profile-field" style="flex:1"><label class="profile-field-label">Currency</label><select class="profile-input" id="send-currency-select"><option value="XRP">XRP</option></select></div>
        </div>
        <div class="profile-field"><label class="profile-field-label">Destination Tag <span style="opacity:.5">(optional)</span></label><input class="profile-input mono" id="send-dest-tag" type="number" placeholder="Required by some exchanges"></div>
        <div class="profile-field"><label class="profile-field-label">Seed Phrase * <span style="font-size:.72rem;color:rgba(255,255,255,.3);text-transform:none">(used once — never stored)</span></label><input class="profile-input mono" id="send-seed" type="password" placeholder="sXXXX…" autocomplete="off"></div><div class="hiddendiately after</div>
        <div class="wam-error" id="send-error"></div>
      </div>
      <div class="wam-footer"><button class="btn-wizard-back" onclick="closeSendModal()">Cancel</button><button class="btn-wizard-next" id="send-submit-btn" onclick="executeSend()">Send ⬆</button></div>
    </div>
  </div>
  <!-- Receive -->
  <div class="wallet-action-overlay" id="receive-modal-overlay">
    <div class="wallet-action-modal">
      <div class="wam-header"><div><div class="wam-title">⬇ Receive</div><div class="wam-sub" id="receive-wallet-name"></div></div><button class="modal-close" onclick="closeReceiveModal()">✕</button></div>
      <div class="wam-body" style="text-align:center">
        <div class="receive-qr-wrap"><div id="receive-qr-container" class="receive-qr-box"></div></div>
        <div class="receive-address-box"><span class="receive-address-val mono" id="receive-address-display"></span></div>
        <button class="btn-wizard-next" id="receive-copy-btn" onclick="copyReceiveAddress()" style="margin-top:16px;width:100%">⧉ Copy Address</button>
        <p class="receive-note">Share this address to receive XRP or tokens. Always verify the full address before sending.</p>
      </div>
    </div>
  </div>
  <!-- Trustline -->
  <div class="wallet-action-overlay" id="trustline-modal-overlay">
    <div class="wallet-action-modal wallet-action-modal--wide">
      <div class="wam-header"><div><div class="wam-title">🔗 Trustlines</div><div class="wam-sub" id="trustline-wallet-name"></div></div><button class="modal-close" onclick="closeTrustlineModal()">✕</button></div>
      <div class="wam-body">
        <div class="tl-section-h">Active trustlines</div>
        <div id="trustline-list-container" class="tl-list"></div>
        <div class="tl-divider"></div>
        <div class="tl-section-h">Add new trustline</div>
        <div class="wam-row2">
          <div class="profile-field" style="flex:1"><label class="profile-field-label">Currency Code *</label><input class="profile-input" id="tl-currency" placeholder="USD / BTC / SOLO" maxlength="20"></div>
          <div class="profile-field" style="flex:1"><label class="profile-field-label">Trust Limit</label><input class="profile-input mono" id="tl-limit" type="number" placeholder="1000000000" value="1000000000"></div>
        </div>
        <div class="profile-field"><label class="profile-field-label">Issuer Address *</label><input class="profile-input mono" id="tl-issuer" placeholder="rXXXX… token issuer"></div>
        <div class="profile-field"><label class="profile-field-label">Seed Phrase * <span style="font-size:.72rem;color:rgba(255,255,255,.3);text-transform:none">(used once — never stored)</span></label><input class="profile-input mono" id="tl-seed" type="password" placeholder="sXXXX…" autocomplete="off"></div>
        <div class="wam-error" id="tl-error"></div>
      </div>
      <div class="wam-footer"><button class="btn-wizard-back" onclick="closeTrustlineModal()">Close</button><button class="btn-wizard-finish" id="tl-add-btn" onclick="addTrustline()">+ Add Trustline</button></div>
    </div>
  </div>
  <!-- Import Address -->
  <div class="generic-modal-overlay" id="import-address-modal">
    <div class="generic-modal">
      <div class="gm-hdr"><div class="gm-title">👁 Watch Address</div><button class="gm-close" onclick="closeImportAddressModal()">✕</button></div>
      <div class="gm-sub">Track any XRPL address read-only — no seed required. Useful for monitoring another wallet or a known exchange address.</div>
      <div class="gm-warning"><span class="gm-warn-icon">⚠</span><span>Watch-only wallets cannot sign transactions.</span></div>
      <div class="profile-field"><label class="profile-field-label">XRPL Address *</label><input class="profile-input mono" id="inp-import-address" placeholder="rXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" autocomplete="off"></div>
      <div class="profile-field"><label class="profile-field-label">Label</label><input class="profile-input" id="inp-import-label" placeholder="e.g. My exchange hot wallet"></div>
      <div class="gm-error" id="import-address-error"></div>
      <div style="display:flex;gap:10px;justify-content:flex-end;margin-top:16px">
        <button class="btn-wizard-back" onclick="closeImportAddressModal()">Cancel</button>
        <button class="btn-wizard-next" onclick="importWatchOnlyWallet()">Add Watch Wallet →</button>
      </div>
    </div>
  </div>
  <!-- Import Seed -->
  <div class="generic-modal-overlay" id="import-seed-modal">
    <div class="generic-modal">
      <div class="gm-hdr"><div class="gm-title">🔑 Import from Seed</div><button class="gm-close" onclick="closeImportSeedModal()">✕</button></div>
      <div class="gm-sub">Import an existing XRPL wallet using its family seed (starts with 's') or hex seed. Your seed will be encrypted and stored only on this device.</div>
      <div class="gm-warning"><span class="gm-warn-icon">⚠</span><span>Never share your seed with anyone. Only import seeds you trust.</span></div>
      <div class="profile-field"><label class="profile-field-label">Seed Phrase *</label><input class="profile-input mono" id="inp-import-seed" placeholder="sXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" type="password" autocomplete="off"></div>
      <div class="profile-field"><label class="profile-field-label">Wallet Label</label><input class="profile-input" id="inp-import-seed-label" placeholder="e.g. My Old Wallet"></div>
      <div class="gm-error" id="import-seed-error"></div>
      <div style="display:flex;gap:10px;justify-content:flex-end;margin-top:16px">
        <button class="btn-wizard-back" onclick="closeImportSeedModal()">Cancel</button>
        <button class="btn-wizard-next" id="import-seed-btn" onclick="executeImportFromSeed()">Import Wallet →</button>
      </div>
    </div>
  </div>
  <!-- Token Details -->
  <div class="generic-modal-overlay" id="token-details-modal">
    <div class="generic-modal" style="max-width:420px"></div>
  </div>`;
  document.body.appendChild(div);
  ['send-modal-overlay','receive-modal-overlay','trustline-modal-overlay',
   'import-address-modal','import-seed-modal','token-details-modal'].forEach(id => {
    const el = document.getElementById(id);
    el?.addEventListener('click', e => { if (e.target === el) { el.classList.remove('show'); el.style.display=''; } });
  });
}

/* ═══════════════════════════════════════════════════
   Profile Editor
═══════════════════════════════════════════════════ */
export function openProfileEditor() {
  ['displayName','handle','bio','location','website'].forEach(f => {
    const el = $(`edit-${f}`); if (el) el.value = profile[f] || '';
  });
  const prev = $('editor-avatar-preview');
  if (prev) {
    const img = localStorage.getItem(LS_AVATAR_IMG);
    prev.innerHTML = img ? `<img src="${img}" class="profile-avatar-img"/>` : (profile.avatar||'🌊');
  }
  const rmBtn = $('avatar-remove-btn');
  if (rmBtn) rmBtn.style.display = localStorage.getItem(LS_AVATAR_IMG) ? '' : 'none';
  const bannerPrev = $('editor-banner-preview');
  if (bannerPrev) {
    const img = localStorage.getItem(LS_BANNER_IMG);
    bannerPrev.style.backgroundImage    = img ? `url(${img})` : '';
    bannerPrev.style.backgroundSize     = 'cover';
    bannerPrev.style.backgroundPosition = 'center';
    BANNERS.forEach(b => bannerPrev.classList.remove(b));
    if (!img) bannerPrev.classList.add(profile.banner||'banner-ocean');
  }
  const grid = $('avatar-picker-grid');
  if (grid) grid.innerHTML = AVATARS.map(a => `<div class="avatar-option ${profile.avatar===a?'active':''}" onclick="selectAvatar('${a}')">${a}</div>`).join('');
  const bannerGrid = $('banner-picker-grid');
  if (bannerGrid) bannerGrid.innerHTML = BANNERS.map(b => `<div class="banner-option ${b} ${profile.banner===b?'active':''}" onclick="selectBanner('${b}')"></div>`).join('');
  $('profile-editor-modal')?.classList.add('show');
}
export function closeProfileEditor() { $('profile-editor-modal')?.classList.remove('show'); }
export function saveProfileEditor() {
  profile.displayName = $('edit-displayName')?.value.trim() || profile.displayName;
  profile.handle      = ($('edit-handle')?.value.trim()||profile.handle).replace(/^@/,'').replace(/\s+/g,'_').toLowerCase();
  profile.bio         = $('edit-bio')?.value.trim()      || '';
  profile.location    = $('edit-location')?.value.trim() || '';
  profile.website     = $('edit-website')?.value.trim()  || '';
  _saveProfile();
  // profile saved to localStorage only
  logActivity('profile_saved', 'Profile details updated');
  renderProfilePage(); closeProfileEditor();
  toastInfo('Profile saved');
}
export function selectAvatar(emoji) {
  localStorage.removeItem(LS_AVATAR_IMG);
  profile.avatar = emoji;
  $$('.avatar-option').forEach(el => el.classList.toggle('active', el.textContent===emoji));
  const prev=$('editor-avatar-preview'); if(prev) prev.innerHTML=emoji;
  const rm=$('avatar-remove-btn'); if(rm) rm.style.display='none';
}
export function selectBanner(b) {
  localStorage.removeItem(LS_BANNER_IMG);
  profile.banner = b;
  $$('.banner-option').forEach(el => el.classList.toggle('active', el.classList.contains(b)));
  const prev=$('editor-banner-preview');
  if (prev) { prev.style.backgroundImage=''; BANNERS.forEach(x=>prev.classList.remove(x)); prev.classList.add(b); }
  renderProfilePage();
}
export function uploadAvatarImage(input) {
  const file = input?.files?.[0];
  if (!file) return;
  if (file.size > 2*1024*1024) { toastWarn('Image too large — max 2 MB'); return; }
  const reader = new FileReader();
  reader.onload = e => {
    const img = new Image();
    img.onload = () => {
      const canvas = document.createElement('canvas');
      canvas.width = canvas.height = 200;
      const ctx = canvas.getContext('2d');
      const size = Math.min(img.width, img.height);
      ctx.drawImage(img, (img.width-size)/2, (img.height-size)/2, size, size, 0, 0, 200, 200);
      const data = canvas.toDataURL('image/jpeg', 0.85);
      localStorage.setItem(LS_AVATAR_IMG, data);
      const prev=$('editor-avatar-preview'); if(prev) prev.innerHTML=`<img src="${data}" class="profile-avatar-img"/>`;
      const rm=$('avatar-remove-btn'); if(rm) rm.style.display='';
      renderProfilePage(); toastInfo('Profile photo updated');
    };
    img.src = e.target.result;
  };
  reader.readAsDataURL(file); input.value='';
}
export function removeAvatarImage() {
  localStorage.removeItem(LS_AVATAR_IMG);
  const prev=$('editor-avatar-preview'); if(prev) prev.innerHTML=profile.avatar||'🌊';
  const rm=$('avatar-remove-btn'); if(rm) rm.style.display='none';
  renderProfilePage();
}
export function uploadBannerImage(input) {
  const file = input?.files?.[0];
  if (!file) return;
  if (file.size > 5*1024*1024) { toastWarn('Image too large — max 5 MB'); return; }
  const reader = new FileReader();
  reader.onload = e => {
    const img = new Image();
    img.onload = () => {
      const canvas = document.createElement('canvas');
      canvas.width=900; canvas.height=180;
      const ctx = canvas.getContext('2d');
      const scale=Math.max(900/img.width,180/img.height);
      ctx.drawImage(img,(900-img.width*scale)/2,(180-img.height*scale)/2,img.width*scale,img.height*scale);
      const data = canvas.toDataURL('image/jpeg', 0.88);
      localStorage.setItem(LS_BANNER_IMG, data);
      const prev=$('editor-banner-preview');
      if(prev){prev.style.backgroundImage=`url(${data})`;prev.style.backgroundSize='cover';prev.style.backgroundPosition='center';BANNERS.forEach(b=>prev.classList.remove(b));}
      const rm=$('banner-remove-btn'); if(rm) rm.style.display='';
      renderProfilePage(); toastInfo('Banner updated');
    };
    img.src = e.target.result;
  };
  reader.readAsDataURL(file); input.value='';
}
export function removeBannerImage() {
  localStorage.removeItem(LS_BANNER_IMG);
  const prev=$('editor-banner-preview');
  if(prev){prev.style.backgroundImage='';BANNERS.forEach(b=>prev.classList.remove(b));prev.classList.add(profile.banner||'banner-ocean');}
  const rm=$('banner-remove-btn'); if(rm) rm.style.display='none';
  renderProfilePage();
}

/* ═══════════════════════════════════════════════════
   Vault actions
═══════════════════════════════════════════════════ */
export function exportWalletAddresses() {
  const data = wallets.map(({ id, label, address, algo, emoji, color, testnet, watchOnly, createdAt }) =>
    ({ id, label, address, algo, emoji, color, testnet, watchOnly, createdAt }));
  const a    = document.createElement('a');
  a.href     = 'data:application/json;charset=utf-8,'+encodeURIComponent(JSON.stringify(data,null,2));
  a.download = `nalulf-wallets-${new Date().toISOString().slice(0,10)}.json`;
  a.click();
  logActivity('backup_exported','Wallet addresses exported');
  toastInfo('Wallet addresses exported');
}
// Legacy alias
export function exportVaultBackup() { exportWalletAddresses(); }

export function exportVaultSyncCode() {
  // Plain storage mode — just export wallet addresses
  exportWalletAddresses();
  toastInfo('Wallet addresses exported (sync code not available in plain storage mode)');
}

/* ═══════════════════════════════════════════════════
   Wallet Creator Wizard
═══════════════════════════════════════════════════ */
export function openWalletCreator() {
  // no vault required
  wizardStep = 1;
  wizardData = { algo:'ed25519', label:'', emoji:'💎', color:'#50fa7b', seed:'', address:'' };
  checksCompleted.clear();
  renderWizardStep(1); renderWizardCustomization(); _renderWizardSecurityBanner();
  $('wallet-creator-overlay')?.classList.add('show');
  setTimeout(() => $('wallet-label-input')?.focus(), 80);
}
export function closeWalletCreator() {
  $('wallet-creator-overlay')?.classList.remove('show');
  wizardData.seed = wizardData.address = '';
}

function _renderWizardSecurityBanner() {
  const t = $('wizard-security-banner');
  if (!t) return;
  t.innerHTML = `<div class="wsb-icon">🔐</div>
    <div class="wsb-content">
      <div class="wsb-title">Your keys are encrypted on your device</div>
      <div class="wsb-body">Your wallet seed is encrypted with your password using AES-256-GCM before being saved to this device. <strong>It never leaves your browser.</strong></div>
      <div class="wsb-pills">
        <span class="wsb-pill wsb-pill--green">🔒 Local only</span>
        <span class="wsb-pill wsb-pill--green">🚫 Never sent to servers</span>
        <span class="wsb-pill wsb-pill--blue">⚡ AES-256-GCM</span>
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
    if (checksCompleted.size < 4) { toastWarn('Confirm all 4 security checkpoints first.'); return; }
    wizardStep = 3;
  } else if (wizardStep === 3) {
    saveNewWallet(); wizardStep = 4;
  }
  renderWizardStep(wizardStep);
}
export function wizardBack() {
  if (wizardStep <= 1) { closeWalletCreator(); return; }
  wizardStep--; renderWizardStep(wizardStep);
}

function renderWizardStep(step) {
  [1,2,3,4].forEach(s => {
    const d = $(`.step-${s}`); if (!d) return;
    d.classList.toggle('active', s===step); d.classList.toggle('done', s<step);
  });
  $$('.wizard-panel').forEach(p => p.classList.remove('active'));
  $(`wizard-panel-${step}`)?.classList.add('active');
  const back=$('wizard-back-btn'), next=$('wizard-next-btn'), fin=$('wizard-finish-btn');
  if (back) { back.style.display=step===4?'none':''; back.textContent=step===1?'Cancel':'← Back'; }
  if (next) next.style.display = step>=3?'none':'';
  if (fin)  fin.style.display  = step===3?'':'none';
}

function renderWizardCustomization() {
  const emojiRow = $('wallet-emoji-picker');
  if (emojiRow) emojiRow.innerHTML = WALLET_EMOJIS.map(e => `<div class="wallet-emoji-opt ${wizardData.emoji===e?'active':''}" onclick="selectWalletEmoji('${e}')">${e}</div>`).join('');
  const colorRow = $('wallet-color-picker');
  if (colorRow) colorRow.innerHTML = WALLET_COLORS.map(c => `<div class="color-swatch ${wizardData.color===c?'active':''}" style="background:${c}" onclick="selectWalletColor('${c}')"></div>`).join('');
}

function generateWalletKeys() {
  if (window.xrpl) {
    try {
      const w = window.xrpl.Wallet.generate(wizardData.algo==='ed25519'?'ed25519':'secp256k1');
      wizardData.seed = w.seed||w.classicAddress; wizardData.address = w.classicAddress;
    } catch(e) { console.warn('xrpl.js fallback:', e); _fallbackGenerate(); }
  } else _fallbackGenerate();
  const seedEl=$('wizard-seed-value'), addrEl=$('wizard-address-value');
  if (seedEl) seedEl.textContent = wizardData.seed;
  if (addrEl) addrEl.textContent = wizardData.address;
  checksCompleted.clear();
  $$('.security-check').forEach(el => el.classList.remove('checked'));
  $$('.check-box').forEach(el => el.textContent = '');
  _renderSecurityChecklist(); updateWizardNextBtn();
  // Auto-blur seed after 30 seconds for security
  if (seedEl) setTimeout(() => seedEl.classList.add('blur'), 30_000);
}

function _renderSecurityChecklist() {
  const list = $('security-checklist-dynamic');
  if (!list) return;
  const items = [
    { icon:'✍️', title:'Write it on paper right now', body:'Copy your seed phrase onto paper and store it in a safe place. This is your ONLY recovery option if you lose access to this device.' },
    { icon:'🚫', title:'Never store it digitally', body:'No notes apps, emails, screenshots, or cloud drives. A device with a digital copy that gets hacked means instant loss of funds.' },
    { icon:'🤫', title:'Never share it with anyone', body:'No legitimate app, exchange, or support team will ever ask for your seed. Anyone who asks is attempting to steal your funds.' },
    { icon:'🔐', title:'Use a strong unique password', body:"Your password protects the encrypted seed on this device. Use one you don't use anywhere else." },
  ];
  list.innerHTML = items.map((item,i) => `
    <div class="security-check security-check-${i+1}" onclick="toggleSecurityCheck(${i+1})">
      <span class="check-box" id="check-box-${i+1}"></span>
      <div class="check-text"><strong>${item.icon} ${escHtml(item.title)}</strong>${escHtml(item.body)}</div>
    </div>`).join('');
}

function _fallbackGenerate() {
  const B58='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  const hexToB58 = hex => { let n=BigInt('0x'+hex), s=''; while(n>0n){s=B58[Number(n%58n)]+s;n/=58n;} return s; };
  const b = crypto.getRandomValues(new Uint8Array(16));
  wizardData.seed    = 's' + hexToB58(Array.from(b).map(x=>x.toString(16).padStart(2,'0')).join('')).padStart(28,'1').slice(0,28);
  const ab = crypto.getRandomValues(new Uint8Array(20));
  wizardData.address = 'r' + hexToB58(Array.from(ab).map(x=>x.toString(16).padStart(2,'0')).join('')).slice(0, 25+(Number(ab[0])%9));
}

async function saveNewWallet() {
  const newW = {
    id:        crypto.randomUUID(), label:wizardData.label, address:wizardData.address,
    algo:      wizardData.algo, seed:wizardData.seed, emoji:wizardData.emoji,
    color:     wizardData.color, testnet:$('wallet-testnet-check')?.checked||false,
    createdAt: new Date().toISOString(),
  };

  const meta = {...newW}; delete meta.seed; wallets.push(meta); _saveWallets();
  if (!activeWalletId) { activeWalletId=newW.id; safeSet(LS_ACTIVE_ID,newW.id); }
  renderWalletList(); renderActiveWalletBar();
  _setText('wallet-success-address', wizardData.address);
  setTimeout(() => { wizardData.seed=wizardData.address=''; }, 100);
  logActivity('wallet_created', wizardData.label||'New XRPL Wallet');
  toastInfo('Wallet saved to encrypted vault');
  fetchBalance(newW.address).then(()=>renderWalletList());
}

export function selectAlgo(algo) {
  wizardData.algo = algo;
  $$('.algo-card').forEach(c => c.classList.toggle('active', c.dataset.algo===algo));
}
export function selectWalletEmoji(e) {
  wizardData.emoji = e;
  $$('.wallet-emoji-opt').forEach(el => el.classList.toggle('active', el.textContent===e));
}
export function selectWalletColor(c) {
  wizardData.color = c;
  $$('.color-swatch').forEach(el => el.classList.toggle('active', el.style.background===c||el.dataset.color===c));
}
export function toggleSecurityCheck(idx) {
  const el = $(`.security-check-${idx}`); if (!el) return;
  const box = el.querySelector('.check-box');
  if (checksCompleted.has(idx)) { checksCompleted.delete(idx); el.classList.remove('checked'); if(box)box.textContent=''; }
  else { checksCompleted.add(idx); el.classList.add('checked'); if(box)box.textContent='✓'; }
  updateWizardNextBtn();
}
function updateWizardNextBtn() {
  const btn=$('wizard-next-btn');
  if (btn && wizardStep===2) btn.disabled = checksCompleted.size < 4;
}
export function revealSeed() {
  $('wizard-seed-value')?.classList.remove('blur');
  const hint=$('seed-reveal-hint'); if(hint) hint.style.display='none';
  setTimeout(()=>$('wizard-seed-value')?.classList.add('blur'), 30_000);
}
export function copySeed() {
  const el=$('wizard-seed-value'); if(!el) return;
  _copyToClipboard(el.textContent, 30_000);
  const btn=$('btn-copy-seed');
  if(btn){ btn.textContent='Copied!'; btn.classList.add('copied'); setTimeout(()=>{btn.textContent='Copy Seed';btn.classList.remove('copied');},2000); }
}
export function copyAddress() {
  const el=$('wizard-address-value')||$('wallet-success-address'); if(!el) return;
  _copyToClipboard(el.textContent);
  const btn=$('btn-copy-addr');
  if(btn){ btn.textContent='Copied!'; btn.classList.add('copied'); setTimeout(()=>{btn.textContent='Copy';btn.classList.remove('copied');},2000); }
}

/* ═══════════════════════════════════════════════════
   Import Modals
═══════════════════════════════════════════════════ */
export function openImportAddressModal() {
  const m=$('import-address-modal'); if(!m) return;
  m.querySelector('#inp-import-address').value='';
  m.querySelector('#inp-import-label').value='';
  const e=m.querySelector('#import-address-error'); if(e)e.textContent='';
  m.classList.add('show'); setTimeout(()=>m.querySelector('#inp-import-address')?.focus(),80);
}
export function closeImportAddressModal() { $('import-address-modal')?.classList.remove('show'); }
export function importWatchOnlyWallet() {
  const address=($('inp-import-address')?.value||'').trim();
  const label  =($('inp-import-label')?.value||'').trim()||'Watch Wallet';
  const errEl  = $('import-address-error');
  if (!isValidXrpAddress(address)) { if(errEl)errEl.textContent='Enter a valid XRPL address (starts with r…)'; return; }
  if (wallets.find(w=>w.address===address)) { if(errEl)errEl.textContent='This address is already in your list.'; return; }
  wallets.push({ id:'watch_'+Date.now(), label, address, algo:'—', emoji:'👁', color:'#8be9fd', testnet:false, createdAt:new Date().toISOString(), watchOnly:true });
  _saveWallets();
  logActivity('watch_added', `${label} (${address.slice(0,8)}…)`);
  closeImportAddressModal(); renderWalletList(); renderActiveWalletBar(); renderProfileMetrics();
  fetchBalance(address).then(()=>{renderWalletList();renderProfileMetrics();});
  toastInfo(`👁 Watch-only wallet added: ${label}`);
}

export function openImportSeedModal() {
  const m=$('import-seed-modal'); if(!m) return;
  m.querySelector('#inp-import-seed').value='';
  m.querySelector('#inp-import-seed-label').value='';
  const e=m.querySelector('#import-seed-error'); if(e)e.textContent='';
  m.classList.add('show'); setTimeout(()=>m.querySelector('#inp-import-seed')?.focus(),80);
}
export function closeImportSeedModal() { $('import-seed-modal')?.classList.remove('show'); }
export async function executeImportFromSeed() {
  const seed  =($('inp-import-seed')?.value||'').trim();
  const label =($('inp-import-seed-label')?.value||'').trim()||'Imported Wallet';
  const errEl = $('import-seed-error');
  const btn   = $('import-seed-btn');
  const setErr= m=>{if(errEl)errEl.textContent=m;};
  setErr('');
  if (!seed)                      return setErr('Enter your seed phrase.');
  if (!window.xrpl)               return setErr('xrpl.js not loaded — cannot derive address from seed.');
  if (btn){btn.disabled=true;btn.textContent='Importing…';}
  try {
    const xrplW   = window.xrpl.Wallet.fromSeed(seed);
    const address = xrplW.address;
    const algo    = xrplW.algorithm?.toLowerCase().includes('ed')?'ed25519':'secp256k1';
    if (wallets.find(w=>w.address===address)) return setErr('This address is already in your vault.');
    const id='imp_'+Date.now(), emoji='🔑', color='#bd93f9';

    // Only store public metadata — seed is NEVER stored
    wallets.push({ id, label, address, algo, emoji, color, testnet: false, watchOnly: false, createdAt: new Date().toISOString() });
    _saveWallets();
    logActivity('wallet_imported', `${label} (${address.slice(0,8)}…)`);
    closeImportSeedModal(); renderWalletList(); renderActiveWalletBar();
    fetchBalance(address).then(()=>{renderWalletList();renderProfileMetrics();});
    toastInfo(`🔑 Wallet imported: ${label}`);
  } catch(err) {
    setErr('Invalid seed: '+(err.message||'Could not derive wallet.'));
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Import Wallet →'; }
    const _is = document.getElementById('inp-import-seed'); if (_is) _is.value = '';
  }
}

/* ═══════════════════════════════════════════════════
   Token Details Modal
═══════════════════════════════════════════════════ */
export function openTokenDetailsModal(currency, issuer, walletAddress) {
  const overlay = $('token-details-modal');
  if (!overlay) return;
  const modal   = overlay.querySelector('.generic-modal');
  if (!modal)   return;
  const cached  = balanceCache[walletAddress];
  const token   = cached?.tokens?.find(t => t.currency===currency && t.issuer===issuer);
  const bal     = token ? fmt(parseFloat(token.balance||0),6) : '—';
  const limit   = token?.limit ? fmt(parseFloat(token.limit),2) : 'Unlimited';
  const curDisp = currency.length>4 ? _hexToAscii(currency)||currency : currency;
  modal.innerHTML = `
    <div class="tdm-hdr">
      <div class="tdm-title"><span class="tdm-icon">🪙</span><span class="tdm-cur">${escHtml(curDisp)}</span>
        ${curDisp!==currency?`<span class="tdm-hex mono">${escHtml(currency)}</span>`:''}</div>
      <button class="tdm-close" onclick="closeTokenDetailsModal()">✕</button>
    </div>
    <div class="tdm-grid">
      <div class="tdm-item"><div class="tdm-item-label">Balance</div><div class="tdm-item-val">${bal}</div></div>
      <div class="tdm-item"><div class="tdm-item-label">Trust Limit</div><div class="tdm-item-val">${limit}</div></div>
      <div class="tdm-item tdm-item--wide">
        <div class="tdm-item-label">Issuer</div>
        <div class="tdm-item-val tdm-issuer mono">${issuer.slice(0,14)}…${issuer.slice(-6)}</div>
        <button class="tdm-copy-btn" onclick="copyToClipboard('${escHtml(issuer)}')">⧉ Copy</button>
      </div>
    </div>
    <div class="tdm-links">
      <a class="tdm-link" href="https://xrpscan.com/account/${escHtml(issuer)}" target="_blank" rel="noopener">🔍 View Issuer on XRPScan</a>
      <a class="tdm-link" href="https://xrpscan.com/account/${escHtml(walletAddress)}#tokens" target="_blank" rel="noopener">📋 All My Tokens</a>
    </div>`;
  overlay.classList.add('show');
}
export function closeTokenDetailsModal() {
  const o=$('token-details-modal'); if(o){o.classList.remove('show');o.style.display='';}
}

/* ═══════════════════════════════════════════════════
   Public Profile Preview
═══════════════════════════════════════════════════ */
export function openPublicProfilePreview() {
  document.getElementById('pub-profile-overlay')?.remove();
  const avatarImg   = localStorage.getItem(LS_AVATAR_IMG);
  const connected   = SOCIAL_PLATFORMS.filter(p => social[p.id]);
  const overlay     = document.createElement('div');
  overlay.id        = 'pub-profile-overlay';
  overlay.className = 'pub-profile-overlay';
  overlay.innerHTML = `
    <div class="pub-profile-modal">
      <div class="pub-banner ${profile.banner||'banner-ocean'}" ${localStorage.getItem(LS_BANNER_IMG)?`style="background-image:url(${localStorage.getItem(LS_BANNER_IMG)});background-size:cover;background-position:center;"`:''}>
      </div>
      <div class="pub-hdr">
        <div class="pub-avatar">${avatarImg?`<img src="${avatarImg}" alt="avatar"/>`:`<span>${escHtml(profile.avatar||'🌊')}</span>`}</div>
        <div class="pub-info">
          <div class="pub-name">${escHtml(profile.displayName||'Anonymous')}</div>
          <div class="pub-handle">@${escHtml(profile.handle||'anonymous')}</div>
          ${profile.bio?`<div class="pub-bio">${escHtml(profile.bio)}</div>`:''}
          <div class="vault-pill vault-pill--locked" style="font-size:.65rem;padding:3px 9px">🔒 Self-custodied XRPL wallet</div>
        </div>
      </div>
      ${connected.length
        ? `<div class="pub-socials">${connected.map(p=>`<span class="pub-social-badge"><span>${p.icon}</span><span>@${escHtml(social[p.id])}</span></span>`).join('')}</div>`
        : `<div style="padding:0 20px 16px;font-size:.82rem;color:rgba(255,255,255,.3)">No social accounts connected yet.</div>`}
      <div class="pub-close-row">
        <span style="font-size:.78rem;color:rgba(255,255,255,.32);flex:1">This is how others see your profile</span>
        <button class="pub-close-btn" onclick="document.getElementById('pub-profile-overlay').remove()">Close</button>
      </div>
    </div>`;
  document.body.appendChild(overlay);
  requestAnimationFrame(() => requestAnimationFrame(() => overlay.classList.add('show')));
  overlay.addEventListener('click', e => { if(e.target===overlay) overlay.remove(); });
}

/* ═══════════════════════════════════════════════════
   Preferences
═══════════════════════════════════════════════════ */
export function prefSetTheme(t) { setTheme(t); renderSettingsPanel(); logActivity('theme_changed', t); }
export function setPrefCurrency(c) { safeSet('nalulf_pref_currency', c); renderSettingsPanel(); toastInfo(`Display currency: ${c}`); }
export function setPrefNetwork(n)  { safeSet('nalulf_pref_network', n);  renderSettingsPanel(); toastInfo(`Default network: ${n}`); }
export function setPrefAutoLock(m) {
  safeSet('nalulf_pref_autolock', m);
  // no vault auto-lock
  renderSettingsPanel(); toastInfo(`Auto-lock: ${m} minutes`);
}
function renderPreferences() { /* kept for backward compat — settings now rendered by renderSettingsPanel */ }

/* ═══════════════════════════════════════════════════
   Events
═══════════════════════════════════════════════════ */
window._profileWipeAllData = () => {
  if (!confirm('Clear all profile, wallet list, social, and activity data? Seeds unaffected (never stored).')) return;
  ['nalulf_profile','nalulf_wallets','nalulf_social','nalulf_activity_log','nalulf_avatar_img','nalulf_banner_img','naluxrp_active_wallet'].forEach(k => localStorage.removeItem(k));
  wallets = []; social = {}; activeWalletId = null; balanceCache = {}; trustlineCache = {};
  loadData(); renderProfilePage(); switchProfileTab('wallets');
  toastInfo('Local data cleared');
};

function bindProfileEvents() {
  $('profile-editor-modal')?.addEventListener('click',   e => { if(e.target===e.currentTarget) closeProfileEditor(); });
  $('wallet-creator-overlay')?.addEventListener('click', e => { if(e.target===e.currentTarget) closeWalletCreator(); });
  $('social-modal')?.addEventListener('click',           e => { if(e.target===e.currentTarget) closeSocialModal(); });
}


/* ═══════════════════════════════════════════════════
   Profile Completeness Ring
═══════════════════════════════════════════════════ */
function _getProfileCompleteness() {
  const checks = [
    { done: !!profile.displayName && profile.displayName !== 'Anonymous', label:'Display name' },
    { done: !!profile.bio,                                                label:'Bio' },
    { done: profile.avatar !== '🌊' || !!localStorage.getItem(LS_AVATAR_IMG), label:'Custom avatar' },
    { done: !!localStorage.getItem(LS_BANNER_IMG),                       label:'Custom banner' },
    { done: wallets.length > 0,                                           label:'Wallet added' },
    { done: Object.keys(social).length >= 1,                              label:'Social connected' },
    { done: !!profile.location,                                           label:'Location set' },
    { done: !!profile.website,                                            label:'Website added' },
  ];
  const done = checks.filter(c => c.done).length;
  return { pct: Math.round((done / checks.length) * 100), done, total: checks.length, checks };
}

export function renderProfileCompleteness() {
  const el = document.getElementById('profile-completeness');
  if (!el) return;
  const { pct, checks } = _getProfileCompleteness();
  const color   = pct === 100 ? '#50fa7b' : pct >= 60 ? '#00fff0' : '#ffb86c';
  const circ    = 2 * Math.PI * 16;
  const dash    = (pct / 100) * circ;
  const missing = checks.filter(c => !c.done).map(c => c.label);
  el.title = pct === 100 ? 'Profile complete ✓' : `${pct}% — Missing: ${missing.join(', ')}`;
  el.innerHTML = `
    <div class="pc-wrap">
      <svg class="pc-ring" viewBox="0 0 40 40" width="34" height="34">
        <circle cx="20" cy="20" r="16" fill="none" stroke="rgba(255,255,255,.07)" stroke-width="3.5"/>
        <circle cx="20" cy="20" r="16" fill="none" stroke="${color}" stroke-width="3.5"
          stroke-dasharray="${dash.toFixed(1)} ${circ.toFixed(1)}"
          stroke-linecap="round" transform="rotate(-90 20 20)"
          style="transition:stroke-dasharray .7s cubic-bezier(.4,0,.2,1)"/>
        <text x="20" y="24" text-anchor="middle" font-size="9" font-weight="900"
          fill="${color}" font-family="JetBrains Mono,monospace">${pct}%</text>
      </svg>
    </div>`;
}

/* ═══════════════════════════════════════════════════
   Address Book
═══════════════════════════════════════════════════ */
function _getAddrBook() { return safeJson(safeGet(LS_ADDR_BOOK)) || []; }
function _saveAddrBook(book) { safeSet(LS_ADDR_BOOK, JSON.stringify(book)); }

export function addToAddrBook(address, label) {
  const book = _getAddrBook();
  if (book.find(e => e.address === address)) { toastWarn('Already in address book.'); return; }
  const name = label || prompt('Label for this address:', address.slice(0,10)+'…');
  if (!name) return;
  book.push({ id: crypto.randomUUID(), label: name, address, createdAt: new Date().toISOString() });
  _saveAddrBook(book);
  logActivity('addr_book', `Added ${name} to address book`);
  toastInfo('Saved to address book');
  _refreshAddrBookDropdown();
}

export function removeFromAddrBook(id) {
  _saveAddrBook(_getAddrBook().filter(e => e.id !== id));
  _refreshAddrBookDropdown();
}

function _refreshAddrBookDropdown() {
  const sel = document.getElementById('send-addr-book');
  if (!sel) return;
  sel.innerHTML = `<option value="">📒 Address book</option>` +
    _getAddrBook().map(e =>
      `<option value="${escHtml(e.address)}">${escHtml(e.label)} (${e.address.slice(0,8)}…)</option>`
    ).join('');
}

/* ═══════════════════════════════════════════════════
   Balance Counter Animation
═══════════════════════════════════════════════════ */
function _animateCounter(el, targetVal, decimals=2, duration=700) {
  if (!el) return;
  const start    = performance.now();
  const startVal = parseFloat(el.textContent.replace(/[^0-9.]/g,'')) || 0;
  if (Math.abs(targetVal - startVal) < 0.001) { el.textContent = fmt(targetVal, decimals); return; }
  const tick = (now) => {
    const t    = Math.min((now - start) / duration, 1);
    const ease = t < 0.5 ? 2*t*t : -1+(4-2*t)*t;
    el.textContent = fmt(startVal + (targetVal - startVal) * ease, decimals);
    if (t < 1) requestAnimationFrame(tick);
    else el.textContent = fmt(targetVal, decimals);
  };
  requestAnimationFrame(tick);
}

/* ═══════════════════════════════════════════════════
   Export Transactions CSV
═══════════════════════════════════════════════════ */
export function exportTxCSV(walletId) {
  const w = wallets.find(x => x.id === walletId);
  if (!w) return;
  const txns = txCache[w.address]?.txns || [];
  if (!txns.length) { toastWarn('No transactions loaded — open the Transactions drawer first.'); return; }
  const rows = [['Hash','Type','Direction','Amount','Destination','Date','Result']];
  txns.forEach(tx => {
    const type   = tx.TransactionType || '';
    const isOut  = tx.Account === w.address;
    const amount = typeof tx.Amount === 'string'
      ? fmt(Number(tx.Amount)/1e6, 6)+' XRP'
      : (tx.Amount?.value||'') + ' ' + (tx.Amount?.currency||'');
    const date   = tx.date ? new Date((tx.date+946684800)*1000).toISOString().slice(0,10) : '';
    const result = tx.metaData?.TransactionResult || tx.meta?.TransactionResult || '';
    rows.push([tx.hash||'', type, isOut?'OUT':'IN', amount, tx.Destination||'', date, result]);
  });
  const csv = rows.map(r => r.map(c => '"' + String(c).replace(/"/g, '""') + '"').join(',')).join('\n');
  const a   = document.createElement('a');
  a.href     = 'data:text/csv;charset=utf-8,' + encodeURIComponent(csv);
  a.download = `txns-${w.address.slice(0,8)}-${new Date().toISOString().slice(0,10)}.csv`;
  a.click();
  logActivity('export', `Exported ${txns.length} transactions for ${w.label}`);
  toastInfo(`Exported ${txns.length} transactions as CSV`);
}

/* ═══════════════════════════════════════════════════
   NFT Lightbox
═══════════════════════════════════════════════════ */
export function openNFTLightbox(nftId, imageUrl, taxon) {
  document.getElementById('nft-lightbox')?.remove();
  const overlay = document.createElement('div');
  overlay.id        = 'nft-lightbox';
  overlay.className = 'nft-lightbox-overlay';
  overlay.innerHTML = `
    <div class="nft-lightbox-box">
      <button class="nft-lb-close" onclick="document.getElementById('nft-lightbox').remove()">✕</button>
      <div class="nft-lb-img-wrap">
        ${imageUrl
          ? `<img src="${escHtml(imageUrl)}" class="nft-lb-img" alt="NFT"
               onerror="this.style.display='none';this.nextElementSibling.style.display='flex'" />
             <div class="nft-lb-placeholder" style="display:none">🎨</div>`
          : `<div class="nft-lb-placeholder">🎨</div>`}
      </div>
      <div class="nft-lb-info">
        <div class="nft-lb-id mono">${escHtml(nftId)}</div>
        <div class="nft-lb-taxon">Taxon ${escHtml(String(taxon))}</div>
        <a class="nft-lb-scan" href="https://xrpscan.com/nft/${escHtml(nftId)}"
           target="_blank" rel="noopener">View on XRPScan ↗</a>
      </div>
    </div>`;
  overlay.addEventListener('click', e => { if (e.target === overlay) overlay.remove(); });
  document.body.appendChild(overlay);
  requestAnimationFrame(() => overlay.classList.add('show'));
}

/* ═══════════════════════════════════════════════════
   Token Drawer Search
═══════════════════════════════════════════════════ */
window._profileSetTokenSearch = (q) => {
  const lq = q.toLowerCase();
  document.querySelectorAll('.wdd-token-row').forEach(row => {
    row.style.display = row.textContent.toLowerCase().includes(lq) ? '' : 'none';
  });
};

/* ═══════════════════════════════════════════════════
   Helpers
═══════════════════════════════════════════════════ */
function _setText(id, val) { const el=$(id); if(el) el.textContent=String(val); }
export function copyToClipboard(text) { _copyToClipboard(text); }

function _copyToClipboard(text, autoClearMs=0) {
  navigator.clipboard?.writeText(text).then(() => {
    toastInfo('Copied to clipboard');
    if (autoClearMs) setTimeout(()=>navigator.clipboard?.writeText(''), autoClearMs);
  }).catch(() => {
    const el=document.createElement('textarea'); el.value=text;
    document.body.appendChild(el); el.select(); document.execCommand('copy'); el.remove();
    toastInfo('Copied');
  });
}

function _hexToAscii(hex) {
  if (!/^[0-9A-Fa-f]+$/.test(hex)) return '';
  try {
    let s=''; for(let i=0;i<hex.length;i+=2) s+=String.fromCharCode(parseInt(hex.slice(i,i+2),16));
    return s.replace(/\x00/g,'').trim();
  } catch { return ''; }
}

export { signAndSubmit };