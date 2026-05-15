/* =====================================================
  profile.js — Profile · Social · XRPL Wallet Suite
  v2.0 — Optimized

  Architecture:
  Storage: localStorage with encrypted seed vault
  • Public metadata (address, label, emoji) in plain LS
  • Seeds encrypted at rest with AES-GCM + PBKDF2
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
const XRPL_RPC          = 'https://xrplcluster.com/';
const XRPL_RPC_BACKUP   = 'https://s2.ripple.com:51234/';
const CORS_GET_PROXIES = [
  (url) => `https://corsproxy.io/?${encodeURIComponent(url)}`,
  (url) => `https://api.allorigins.win/raw?url=${encodeURIComponent(url)}`,
];
const XRPSCAN_TOKENS_URL = 'https://api.xrpscan.com/api/v1/tokens';

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

const XRPL_JS_CDN = 'https://cdn.jsdelivr.net/npm/xrpl@4.2.5/build/xrpl-latest-min.js';
const WALLET_KDF_ITERATIONS = 210_000;

let _xrplLoadPromise = null;

function _bytesToB64(bytes) {
  return btoa(String.fromCharCode(...bytes));
}

function _b64ToBytes(b64) {
  const raw = atob(b64);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i += 1) out[i] = raw.charCodeAt(i);
  return out;
}

async function ensureXrplLoaded() {
  if (window.xrpl?.Wallet) return true;
  if (!_xrplLoadPromise) {
    _xrplLoadPromise = new Promise((resolve, reject) => {
      const existing = document.querySelector('script[data-xrpl-lib="1"]');
      if (existing) {
        existing.addEventListener('load', () => resolve(true), { once: true });
        existing.addEventListener('error', () => reject(new Error('Failed to load xrpl.js')), { once: true });
        return;
      }
      const s = document.createElement('script');
      s.src = XRPL_JS_CDN;
      s.async = true;
      s.defer = true;
      s.dataset.xrplLib = '1';
      s.onload = () => resolve(true);
      s.onerror = () => reject(new Error('Failed to load xrpl.js'));
      document.head.appendChild(s);
    }).finally(() => {
      if (!window.xrpl?.Wallet) _xrplLoadPromise = null;
    });
  }
  await _xrplLoadPromise;
  return !!window.xrpl?.Wallet;
}

async function _deriveWalletKey(passphrase, saltBytes, iterations = WALLET_KDF_ITERATIONS) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    enc.encode(passphrase),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt: saltBytes, iterations },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function _encryptSeed(seed, passphrase) {
  const enc = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await _deriveWalletKey(passphrase, salt, WALLET_KDF_ITERATIONS);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(seed));
  return {
    v: 1,
    kdf: 'PBKDF2-SHA256',
    iter: WALLET_KDF_ITERATIONS,
    alg: 'AES-GCM-256',
    salt: _bytesToB64(salt),
    iv: _bytesToB64(iv),
    ct: _bytesToB64(new Uint8Array(ct)),
  };
}

async function _decryptSeed(encSeed, passphrase) {
  if (!encSeed?.ct || !encSeed?.salt || !encSeed?.iv) throw new Error('Wallet seed blob is invalid.');
  const key = await _deriveWalletKey(passphrase, _b64ToBytes(encSeed.salt), encSeed.iter || WALLET_KDF_ITERATIONS);
  const pt = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: _b64ToBytes(encSeed.iv) },
    key,
    _b64ToBytes(encSeed.ct)
  );
  return new TextDecoder().decode(pt);
}

async function _resolveSeedForSigning(wObj, providedSeed) {
  const directSeed = (providedSeed || '').trim();
  if (directSeed) return directSeed;

  if (wObj?.encSeed) {
    const passphrase = prompt('Enter your wallet password to decrypt and sign this transaction:');
    if (!passphrase) throw new Error('Wallet password is required to sign.');
    try {
      return await _decryptSeed(wObj.encSeed, passphrase);
    } catch {
      throw new Error('Could not decrypt wallet seed. Check your wallet password and try again.');
    }
  }

  const fallbackSeed = prompt('Enter the wallet seed to sign this transaction (used once, not stored):');
  if (!fallbackSeed) throw new Error('Seed phrase is required to sign transactions.');
  return fallbackSeed.trim();
}

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

let marketSnapshot = { loading: false, data: null, error: '' };
let nftSnapshot = { loading: false, items: [], error: '' };
let userAmmSnapshot = { loading: false, pools: [], error: '' };
let explorerAmmSnapshot = { loading: false, pools: [], error: '' };
let customPoolSnapshot = { loading: false, pool: null, error: '' };
let dexSnapshot = {
  pair: 'BITSTAMP:XRPUSD',
  interval: '15',
  chartType: 'candles',
  stats: null,
  loading: false,
  error: '',
  comparePair: '',
  indicators: {
    sma20: true,
    ema20: false,
    wma20: false,
    bb20: false,
    vwap: false,
  },
};
let tokenDiscoverySnapshot = { loading: false, tokens: [], filtered: [], trending: [], error: '', query: '', total: 0, lastSyncAt: 0 };
let recentTxSnapshot = { loading: false, items: [], error: '' };
const _marketCache = new Map();
let _chartLibPromise = null;
let _dexLiveListenerBound = false;
let _lastLedgerDrivenRefresh = 0;
let _lastXrplSpotAt = 0;
let _dexChartRuntime = {
  chart: null,
  volumeSeries: null,
  activeSeries: null,
  compareSeries: null,
  indicatorSeries: [],
  resizeObserver: null,
  chartType: '',
};
const _dexBarCache = new Map();
let _dexMountSeq = 0;

const LS_SEED_BACKUP_STATUS = 'naluxrp_seed_backed_up';
const LS_WATCHLIST = 'naluxrp_token_watchlist';
const LS_CHART_LAYOUT = 'naluxrp_chart_layout';

const DEMO_XRPL_TOKENS = [
  { symbol: 'XRP', name: 'XRP Ledger Native', marketCap: '$124.3B', source: 'CoinGecko' },
  { symbol: 'RLUSD', name: 'Ripple USD', marketCap: '$312.0M', source: 'Static sample' },
  { symbol: 'SOLOGENIC', name: 'Sologenic', marketCap: '$96.4M', source: 'Static sample' },
];

const DEX_PAIR_OPTIONS = [
  { id: 'BITSTAMP:XRPUSD', label: 'XRP / USD (Coinbase + XRPL)', source: 'coinbase', ticker: 'xrpusd' },
  { id: 'BINANCE:XRPUSDT', label: 'XRP / USD (Coinbase mirror)', source: 'coinbase', ticker: 'XRPUSDT' },
  { id: 'BINANCE:ETHUSDT', label: 'ETH / USD (Coinbase)', source: 'coinbase', ticker: 'ETHUSDT' },
  { id: 'BINANCE:BTCUSDT', label: 'BTC / USD (Coinbase)', source: 'coinbase', ticker: 'BTCUSDT' },
  { id: 'BINANCE:SOLUSDT', label: 'SOL / USD (Coinbase)', source: 'coinbase', ticker: 'SOLUSDT' },
];

const CHART_INTERVAL_OPTIONS = [
  { value: '1', label: '1m' },
  { value: '3', label: '3m' },
  { value: '5', label: '5m' },
  { value: '15', label: '15m' },
  { value: '30', label: '30m' },
  { value: '60', label: '1h' },
  { value: '120', label: '2h' },
  { value: '240', label: '4h' },
  { value: 'D', label: '1D' },
  { value: 'W', label: '1W' },
  { value: 'M', label: '1M' },
];

const CHART_STYLE_MAP = {
  candles: 1,
  line: 2,
  area: 3,
  bars: 0,
  heikin_ashi: 8,
  hollow_candles: 9,
};

const AMM_EXPLORER_SEEDS = [
  {
    label: 'XRP/USD (Bitstamp)',
    asset: { currency: 'XRP' },
    asset2: { currency: 'USD', issuer: 'rhub8VRN55s94qWKDv6jmDy1pUykJzF3wq' },
  },
  {
    label: 'XRP/EUR (Bitstamp)',
    asset: { currency: 'XRP' },
    asset2: { currency: 'EUR', issuer: 'rhub8VRN55s94qWKDv6jmDy1pUykJzF3wq' },
  },
  {
    label: 'XRP/USDC (Gatehub)',
    asset: { currency: 'XRP' },
    asset2: { currency: 'USDC', issuer: 'rKveEyR1SrkWbJX214xcfH43ZsoGMb3PEv' },
  },
];

let _activeTab       = 'wallets';
let _expandedWallet  = null;
let _expandedSubTabs = {};
let _walletFilter    = '';   // search filter for wallet list

/* Wizard state */
let wizardStep      = 1;
let wizardData      = { algo:'ed25519', label:'', emoji:'💎', color:'#50fa7b', seed:'', address:'', passphrase:'' };
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
  ensureXrplLoaded().catch(() => {
    toastWarn('Could not preload xrpl.js. Wallet generation/signing will require network access when used.');
  });

  renderProfilePage();
  renderProfileTabs('wallets');
  renderActiveWalletBar();
  bindProfileEvents();
  _bindDexLiveListeners();
  refreshXrplDashboard({ silent: true });

  window.addEventListener('naluxrp:pagechange', e => {
    if (e?.detail?.pageId === 'profile') refreshXrplDashboard({ silent: true });
  });

  // Vault events
  window.addEventListener('naluxrp:vault-ready', () => {
    loadData();
    renderProfilePage();
    renderProfileTabs(_activeTab);
    renderActiveWalletBar();
    fetchAllBalances();
    refreshXrplDashboard({ silent: true });
  });
  window.addEventListener('naluxrp:vault-locked', () => {
    renderProfilePage();
    refreshXrplDashboard({ silent: true });
  });

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

function _bindDexLiveListeners() {
  if (_dexLiveListenerBound) return;
  _dexLiveListenerBound = true;

  window.addEventListener('xrpl-ledger', () => {
    const now = Date.now();
    if ((now - _lastLedgerDrivenRefresh) < 5000) return;
    _lastLedgerDrivenRefresh = now;
    if (!document.querySelector('#profile-page .profile-wrap .xrpl-profile-dashboard')) return;

    _enrichWithXrplReference().then(() => {
      const ageMs = Date.now() - _lastXrplSpotAt;
      if (ageMs > 15_000) return;
      _dexBarCache.clear();
      renderProfilePage();
    }).catch(() => {});
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
  const wrap = document.querySelector('#profile-page .profile-wrap');
  if (!wrap) return;

  const wallet = getActiveWallet();
  const address = wallet?.address || '';
  const network = _networkBadge();
  const avatarImg = localStorage.getItem(LS_AVATAR_IMG);
  const hasSigningWallet = wallets.some(w => !w.watchOnly);
  const seedBackedUp = safeGet(LS_SEED_BACKUP_STATUS) === '1';
  const balance = balanceCache[address]?.xrp;
  const chartPairOptions = DEX_PAIR_OPTIONS.map(p => `<option value="${escHtml(p.id)}" ${dexSnapshot.pair === p.id ? 'selected' : ''}>${escHtml(p.label)}</option>`).join('');
  const comparePairOptions = DEX_PAIR_OPTIONS.map(p => `<option value="${escHtml(p.id)}" ${dexSnapshot.comparePair === p.id ? 'selected' : ''}>${escHtml(p.label)}</option>`).join('');
  const chartIntervals = CHART_INTERVAL_OPTIONS.map(o => `<option value="${escHtml(o.value)}" ${dexSnapshot.interval === o.value ? 'selected' : ''}>${escHtml(o.label)}</option>`).join('');

  wrap.innerHTML = `
    <div class="xrpl-profile-dashboard">
      <header class="xpd-header xpd-header--stack">
        <div>
          <h1 class="xpd-title">XRPL Portfolio Intelligence Terminal</h1>
          <p class="xpd-subtitle">Profile identity, market intelligence, DEX charting, NFT inventory, and AMM liquidity in one secure workspace.</p>
        </div>
        <div class="xpd-header-badges">
          <span class="xpd-badge ${network.kind}">${network.label}</span>
          <span class="xpd-badge security">Local signing only · private keys stay in-browser</span>
          ${address ? `<span class="xpd-badge mono">${address.slice(0, 10)}...${address.slice(-8)}</span>` : '<span class="xpd-badge warn">No active wallet selected</span>'}
          <button class="xpd-action" onclick="refreshXrplDashboard()">Refresh all</button>
        </div>
      </header>

      <div class="xpd-layout-grid">
        <aside class="xpd-profile-card" aria-label="Profile identity">
          <div class="xpd-profile-top">
            <div class="xpd-avatar-shell" title="${escHtml(profile.displayName || 'Anonymous')}" onclick="openProfileEditor()">
              ${avatarImg ? `<img src="${avatarImg}" alt="Profile avatar" class="xpd-avatar-img" />` : `<span class="xpd-avatar-fallback">${escHtml(profile.avatar || (wallet?.emoji || '🌊'))}</span>`}
            </div>
            <div class="xpd-profile-meta">
              <h2 class="xpd-display-name">${escHtml(profile.displayName || 'Anonymous')}</h2>
              <p class="xpd-bio">${escHtml(profile.bio || 'No bio set. Click edit profile to add one.')}</p>
              <button class="xpd-action" onclick="openProfileEditor()">Edit profile</button>
            </div>
          </div>
          <div class="xpd-profile-list">
            <div class="xpd-item-row">
              <span class="xpd-item-label">Wallet</span>
              <div class="xpd-wallet-inline">
                ${address ? `<span class="mono xpd-wallet-chip" title="${escHtml(address)}">${address}</span><button class="xpd-mini-btn" onclick="copyToClipboard('${escHtml(address)}')">Copy</button>` : '<span class="xpd-empty">No wallet selected</span>'}
              </div>
            </div>
            <div class="xpd-item-row">
              <span class="xpd-item-label">XRP Balance</span>
              <span class="xpd-item-value">${Number.isFinite(balance) ? `${fmt(balance, 4)} XRP` : '—'}</span>
            </div>
            <div class="xpd-item-row">
              <span class="xpd-item-label">Network</span>
              <span class="xpd-item-value">${network.label}</span>
            </div>
            <div class="xpd-item-row">
              <span class="xpd-item-label">Vault status</span>
              <span class="xpd-item-value">${hasSigningWallet ? 'Vault ready' : 'Watch-only mode'}</span>
            </div>
            <div class="xpd-item-row xpd-item-row--toggle">
              <span class="xpd-item-label">Seed phrase backed up</span>
              <button class="xpd-toggle ${seedBackedUp ? 'on' : ''}" onclick="toggleSeedBackupStatus()" aria-pressed="${seedBackedUp ? 'true' : 'false'}">${seedBackedUp ? 'Yes' : 'No'}</button>
            </div>
          </div>
        </aside>

        <div class="xpd-main-stack">
          <section class="xpd-section xpd-section--chart" aria-label="DEX chart">
            <div class="xpd-section-head">
              <h2>XRPL DEX Chart</h2>
              <div class="xpd-chart-toolbar">
                <select class="xpd-input" onchange="setDexPair(this.value)">${chartPairOptions}</select>
                <select class="xpd-input" onchange="setDexInterval(this.value)">${chartIntervals}</select>
                <select class="xpd-input" onchange="setDexChartType(this.value)">
                  <option value="candles" ${dexSnapshot.chartType === 'candles' ? 'selected' : ''}>Candlestick</option>
                  <option value="line" ${dexSnapshot.chartType === 'line' ? 'selected' : ''}>Line</option>
                  <option value="area" ${dexSnapshot.chartType === 'area' ? 'selected' : ''}>Area</option>
                  <option value="bars" ${dexSnapshot.chartType === 'bars' ? 'selected' : ''}>Bar</option>
                  <option value="heikin_ashi" ${dexSnapshot.chartType === 'heikin_ashi' ? 'selected' : ''}>Heikin Ashi</option>
                  <option value="hollow_candles" ${dexSnapshot.chartType === 'hollow_candles' ? 'selected' : ''}>Hollow Candle</option>
                </select>
                <select class="xpd-input" onchange="setComparePair(this.value)">
                  <option value="" ${!dexSnapshot.comparePair ? 'selected' : ''}>No Compare</option>
                  ${comparePairOptions}
                </select>
                <button class="xpd-action" onclick="refreshDexChart()">Refresh</button>
                <button class="xpd-action" onclick="toggleChartFullscreen()">Fullscreen</button>
                <button class="xpd-action" onclick="exportChartPng()">PNG</button>
                <button class="xpd-action" onclick="toggleTerminalTheme()">Theme</button>
                <button class="xpd-action" onclick="saveChartLayoutPreset()">Save Layout</button>
                <button class="xpd-action" onclick="loadChartLayoutPreset()">Load Layout</button>
              </div>
            </div>
            ${_renderDexSection()}
          </section>

          <section class="xpd-section" aria-label="XRPL market data">
            <div class="xpd-section-head">
              <h2>XRPL Market Data</h2>
              <button class="xpd-action" onclick="refreshMarketData()">Refresh market</button>
            </div>
            ${_renderMarketSection()}
          </section>
        </div>
      </div>

      <section class="xpd-section" aria-label="Token discovery and watchlist">
        <div class="xpd-section-head">
          <h2>Token Discovery and Watchlists</h2>
          <button class="xpd-action" onclick="refreshTokenDiscovery()">Refresh tokens</button>
        </div>
        ${_renderTokenDiscoverySection()}
      </section>

      <div class="xpd-dual-grid">
        <section class="xpd-section" aria-label="NFT gallery">
          <div class="xpd-section-head">
            <h2>NFT Gallery</h2>
            <button class="xpd-action" onclick="refreshNftGallery()">Refresh NFTs</button>
          </div>
          ${_renderNftSection(address)}
        </section>

        <section class="xpd-section" aria-label="AMM pools and DEX liquidity">
          <div class="xpd-section-head">
            <h2>AMM, DEX, and Liquidity Pools</h2>
            <button class="xpd-action" onclick="refreshAmmPools()">Refresh pools</button>
          </div>
          ${_renderAmmSection(address)}
        </section>
      </div>

      <section class="xpd-section" aria-label="Portfolio and recent transactions">
        <div class="xpd-section-head">
          <h2>Portfolio and Recent Transactions</h2>
          <button class="xpd-action" onclick="refreshRecentTransactions()">Refresh tx</button>
        </div>
        ${_renderPortfolioAndTxSection(address)}
      </section>
    </div>`;

  _mountDexWidget();
}

function _networkBadge() {
  const key = String(state.currentNetwork || '').toLowerCase();
  if (key.includes('testnet')) return { label: 'XRPL Testnet', kind: 'testnet' };
  if (key.includes('mainnet')) return { label: 'XRPL Mainnet', kind: 'mainnet' };
  if (key.includes('xahau')) return { label: 'Xahau Network', kind: 'xahau' };
  return { label: `Network: ${escHtml(state.currentNetwork || 'Unknown')}`, kind: 'unknown' };
}

function _renderDexSection() {
  const stats = dexSnapshot.stats;
  const online = state.wsConn?.readyState === 1;
  return `
    ${dexSnapshot.error ? `<div class="xpd-error">${escHtml(dexSnapshot.error)}</div>` : ''}
    <div class="xpd-chart-stats">
      <div class="xpd-pill" title="Current price">${stats?.price != null ? `$${fmt(stats.price, 4)}` : 'Price —'}</div>
      <div class="xpd-pill" title="24h change">${stats?.changePct != null ? `${stats.changePct >= 0 ? '+' : ''}${fmt(stats.changePct, 2)}%` : '24h —'}</div>
      <div class="xpd-pill" title="24h high">${stats?.high != null ? `High $${fmt(stats.high, 4)}` : 'High —'}</div>
      <div class="xpd-pill" title="24h low">${stats?.low != null ? `Low $${fmt(stats.low, 4)}` : 'Low —'}</div>
      <div class="xpd-pill" title="XRPL orderbook spot">${stats?.xrplSpot != null ? `XRPL Spot $${fmt(stats.xrplSpot, 4)}` : 'XRPL Spot —'}</div>
      <div class="xpd-pill" title="Chart source">${escHtml(stats?.source || 'Source pending')}</div>
      <div class="xpd-pill" title="Streaming status">${online ? '● Live stream connected' : '● Stream offline'}</div>
    </div>
    <div class="xpd-indicator-row">
      <label><input type="checkbox" ${dexSnapshot.indicators.sma20 ? 'checked' : ''} onchange="toggleIndicator('sma20', this.checked)"/> SMA20</label>
      <label><input type="checkbox" ${dexSnapshot.indicators.ema20 ? 'checked' : ''} onchange="toggleIndicator('ema20', this.checked)"/> EMA20</label>
      <label><input type="checkbox" ${dexSnapshot.indicators.wma20 ? 'checked' : ''} onchange="toggleIndicator('wma20', this.checked)"/> WMA20</label>
      <label><input type="checkbox" ${dexSnapshot.indicators.bb20 ? 'checked' : ''} onchange="toggleIndicator('bb20', this.checked)"/> Bollinger(20)</label>
      <label><input type="checkbox" ${dexSnapshot.indicators.vwap ? 'checked' : ''} onchange="toggleIndicator('vwap', this.checked)"/> VWAP</label>
    </div>
    <div class="xpd-chart-wrap"><div id="xpd-tv-widget" class="xpd-tv-widget"></div></div>
    <p class="xpd-note">Custom in-app chart defaults to XRP/USD and supports intraday to monthly views. Bars use available market feeds while XRPL orderbook spot is shown when reachable.</p>`;
}

function _renderMarketSection() {
  if (marketSnapshot.loading) {
    return '<div class="xpd-loading">Loading XRP market snapshot...</div>';
  }
  if (marketSnapshot.error) {
    return `<div class="xpd-error">${escHtml(marketSnapshot.error)}</div>`;
  }
  const m = marketSnapshot.data;
  if (!m) return '<div class="xpd-empty">Market data is not available yet.</div>';
  const up = m.change24h >= 0;
  return `
    <div class="xpd-market-grid">
      <article class="xpd-stat-card">
        <span class="xpd-stat-label">XRP Price</span>
        <strong class="xpd-stat-value">$${fmt(m.priceUsd, 4)}</strong>
      </article>
      <article class="xpd-stat-card">
        <span class="xpd-stat-label">24h Change</span>
        <strong class="xpd-stat-value ${up ? 'up' : 'down'}">${up ? '+' : ''}${fmt(m.change24h, 2)}%</strong>
      </article>
      <article class="xpd-stat-card">
        <span class="xpd-stat-label">24h Volume</span>
        <strong class="xpd-stat-value">$${_fmtCompact(m.volume24h)}</strong>
      </article>
      <article class="xpd-stat-card">
        <span class="xpd-stat-label">Market Cap</span>
        <strong class="xpd-stat-value">$${_fmtCompact(m.marketCap)}</strong>
      </article>
    </div>
    <div class="xpd-token-strip">
      ${DEMO_XRPL_TOKENS.map(t => `<div class="xpd-token-pill" title="${escHtml(`${t.symbol} ${t.name}`)}"><span class="sym xpd-pill-text">${t.symbol}</span><span class="xpd-pill-text">${escHtml(t.name)}</span><span class="cap xpd-pill-text">${t.marketCap}</span></div>`).join('')}
    </div>
    <p class="xpd-note">Top XRPL token cards are static examples when direct DEX market-cap feeds are unavailable.</p>`;
}

function _renderNftSection(address) {
  if (!address) return '<div class="xpd-empty">Select or create a wallet to load NFTs.</div>';
  if (nftSnapshot.loading) return '<div class="xpd-loading">Loading account NFTs...</div>';
  if (nftSnapshot.error) return `<div class="xpd-error">${escHtml(nftSnapshot.error)}</div>`;
  if (!nftSnapshot.items.length) return '<div class="xpd-empty">No NFTs found for this wallet.</div>';
  return `<div class="xpd-nft-grid">${nftSnapshot.items.map(_renderNftCard).join('')}</div>`;
}

function _renderNftCard(nft) {
  const shortId = `${nft.id.slice(0, 12)}...${nft.id.slice(-10)}`;
  return `<article class="xpd-nft-card">
    <div class="xpd-nft-media">
      ${nft.image ? `<img src="${escHtml(nft.image)}" alt="NFT ${escHtml(shortId)}" loading="lazy" onerror="this.closest('.xpd-nft-media').innerHTML='<div class=&quot;xpd-nft-placeholder&quot;>NFT</div>'"/>` : '<div class="xpd-nft-placeholder">NFT</div>'}
    </div>
    <div class="xpd-nft-body">
      <div class="xpd-nft-id mono" title="${escHtml(nft.id)}">${escHtml(shortId)}</div>
      <button class="xpd-action" onclick="sendNft('${escHtml(nft.id)}')">Send NFT</button>
    </div>
  </article>`;
}

function _renderAmmSection(address) {
  const walletPools = _renderWalletPoolArea(address);
  const explorerPools = _renderExplorerPoolsArea();
  const custom = _renderCustomPoolArea();
  return `<div class="xpd-amm-columns">${walletPools}${explorerPools}${custom}</div>`;
}

function _getWatchlist() {
  return (safeJson(safeGet(LS_WATCHLIST)) || []).filter(Boolean);
}

function _setWatchlist(next) {
  const normalized = [...new Set((next || []).filter(Boolean))];
  safeSet(LS_WATCHLIST, JSON.stringify(normalized));
}

function _resolveWatchToken(key, tokenByKey) {
  if (tokenByKey.has(key)) return tokenByKey.get(key);
  const old = tokenDiscoverySnapshot.tokens.find(t => t.symbol === key);
  return old || null;
}

function _renderTokenDiscoverySection() {
  const q = tokenDiscoverySnapshot.query || '';
  const watch = _getWatchlist();
  const list = tokenDiscoverySnapshot.filtered.length ? tokenDiscoverySnapshot.filtered : tokenDiscoverySnapshot.tokens;
  const top = list.slice(0, 240);
  const trending = tokenDiscoverySnapshot.trending.slice(0, 14);
  const tokenByKey = new Map(tokenDiscoverySnapshot.tokens.map(t => [_tokenKey(t), t]));

  return `
    <div class="xpd-token-grid">
      <div class="xpd-token-col">
        <div class="xpd-search-row">
          <input class="xpd-input" placeholder="Search symbol, token, issuer" value="${escHtml(q)}" oninput="searchTokens(this.value)" />
          <div class="xpd-note">Loaded ${_fmtCompact(tokenDiscoverySnapshot.total || list.length)} issued tokens · showing ${_fmtCompact(top.length)}${tokenDiscoverySnapshot.lastSyncAt ? ` · synced ${new Date(tokenDiscoverySnapshot.lastSyncAt).toLocaleTimeString()}` : ''}</div>
        </div>
        ${tokenDiscoverySnapshot.loading ? '<div class="xpd-loading">Loading XRPL issued token registry...</div>' : ''}
        ${tokenDiscoverySnapshot.error ? `<div class="xpd-error">${escHtml(tokenDiscoverySnapshot.error)}</div>` : ''}
        <div class="xpd-token-list">${top.map(t => {
          const key = _tokenKey(t);
          return `
          <div class="xpd-token-row" title="${escHtml(`${t.symbol} ${t.name}`)}">
            <div class="xpd-token-main">
              <strong>${escHtml(t.symbol)}</strong>
              <span>${escHtml(t.name)}</span>
              ${t.issuer ? `<span class="mono xpd-pill-text">${escHtml(t.issuer)}</span>` : ''}
            </div>
            <div class="xpd-token-actions">
              <span>${t.price != null ? `$${fmt(t.price, 6)}` : '—'}</span>
              ${Number.isFinite(t.holders) ? `<span title="Holders">${_fmtCompact(t.holders)} holders</span>` : ''}
              <button class="xpd-mini-btn" onclick="addTokenToWatchlist('${escHtml(key)}')">Watch</button>
              <button class="xpd-mini-btn" onclick="openTokenOnChart('${escHtml(key)}')">Chart</button>
            </div>
          </div>`;
        }).join('')}</div>
      </div>
      <div class="xpd-token-col">
        <h3>Watchlist</h3>
        <div class="xpd-watchlist">${watch.length ? watch.map(key => {
          const t = _resolveWatchToken(key, tokenByKey);
          const label = t ? `${t.symbol} · ${t.name}` : key;
          const px = t?.price != null ? `$${fmt(t.price, 6)}` : '—';
          return `<div class="xpd-token-row"><span>${escHtml(label)}</span><div class="xpd-token-actions"><span>${px}</span><button class="xpd-mini-btn" onclick="openTokenOnChart('${escHtml(key)}')">Chart</button><button class="xpd-mini-btn" onclick="removeTokenFromWatchlist('${escHtml(key)}')">Remove</button></div></div>`;
        }).join('') : '<div class="xpd-empty">No watchlist tokens yet.</div>'}</div>
        <h3>Trending</h3>
        <div class="xpd-watchlist">${trending.length ? trending.map(t => `<div class="xpd-token-row"><span>${escHtml(t.symbol)} · ${escHtml(t.name)}</span><span>${t.volume24h != null ? `$${_fmtCompact(t.volume24h)} vol` : (t.marketCap != null ? `$${_fmtCompact(t.marketCap)} mcap` : '—')}</span></div>`).join('') : '<div class="xpd-empty">No trending data.</div>'}</div>
      </div>
    </div>`;
}

function _renderPortfolioAndTxSection(address) {
  const totalXrp = Object.values(balanceCache).reduce((s, c) => s + (c?.xrp || 0), 0);
  const usd = marketSnapshot.data?.priceUsd ? totalXrp * marketSnapshot.data.priceUsd : 0;
  const txItems = recentTxSnapshot.items.slice(0, 8);
  return `
    <div class="xpd-token-grid">
      <div class="xpd-token-col">
        <div class="xpd-market-grid">
          <article class="xpd-stat-card"><span class="xpd-stat-label">Portfolio XRP</span><strong class="xpd-stat-value">${fmt(totalXrp, 4)}</strong></article>
          <article class="xpd-stat-card"><span class="xpd-stat-label">Portfolio USD</span><strong class="xpd-stat-value">${usd ? `$${fmt(usd, 2)}` : '—'}</strong></article>
          <article class="xpd-stat-card"><span class="xpd-stat-label">Wallets</span><strong class="xpd-stat-value">${wallets.length}</strong></article>
          <article class="xpd-stat-card"><span class="xpd-stat-label">Network Stream</span><strong class="xpd-stat-value">${state.wsConn?.readyState === 1 ? 'Online' : 'Offline'}</strong></article>
        </div>
      </div>
      <div class="xpd-token-col">
        ${recentTxSnapshot.loading ? '<div class="xpd-loading">Loading recent transactions...</div>' : ''}
        ${recentTxSnapshot.error ? `<div class="xpd-error">${escHtml(recentTxSnapshot.error)}</div>` : ''}
        <div class="xpd-watchlist">${address ? (txItems.length ? txItems.map(tx => `<div class="xpd-token-row"><span class="mono">${escHtml((tx.hash || '').slice(0, 12))}...</span><span>${escHtml(tx.TransactionType || 'Unknown')}</span></div>`).join('') : '<div class="xpd-empty">No recent transactions.</div>') : '<div class="xpd-empty">Select wallet to view transactions.</div>'}</div>
      </div>
    </div>`;
}

function _renderWalletPoolArea(address) {
  if (!address) return '<div class="xpd-amm-card"><h3>Your liquidity positions</h3><div class="xpd-empty">No active wallet.</div></div>';
  if (userAmmSnapshot.loading) return '<div class="xpd-amm-card"><h3>Your liquidity positions</h3><div class="xpd-loading">Loading account_objects and LP balances...</div></div>';
  if (userAmmSnapshot.error) return `<div class="xpd-amm-card"><h3>Your liquidity positions</h3><div class="xpd-error">${escHtml(userAmmSnapshot.error)}</div></div>`;
  if (!userAmmSnapshot.pools.length) {
    return '<div class="xpd-amm-card"><h3>Your liquidity positions</h3><div class="xpd-empty">No AMM entries or LP-token balances detected for this wallet yet.</div></div>';
  }
  return `<div class="xpd-amm-card"><h3>Your liquidity positions</h3><div class="xpd-pool-list">${userAmmSnapshot.pools.map(p => `
    <div class="xpd-pool-item">
      <div class="pool-pair xpd-pill-text" title="${escHtml(p.pair)}">${escHtml(p.pair)}</div>
      <div class="pool-meta">LP Balance: ${escHtml(p.lpBalance)} · Est. Value: ${escHtml(p.estimatedValue)}</div>
      <div class="pool-meta">Trading Fee: ${escHtml(p.tradingFee || '—')} · TVL: ${escHtml(p.tvl || 'Unavailable')}</div>
    </div>`).join('')}</div></div>`;
}

function _renderExplorerPoolsArea() {
  if (explorerAmmSnapshot.loading) return '<div class="xpd-amm-card"><h3>General pool explorer</h3><div class="xpd-loading">Loading amm_info for known pools...</div></div>';
  if (explorerAmmSnapshot.error) return `<div class="xpd-amm-card"><h3>General pool explorer</h3><div class="xpd-error">${escHtml(explorerAmmSnapshot.error)}</div></div>`;
  if (!explorerAmmSnapshot.pools.length) return '<div class="xpd-amm-card"><h3>General pool explorer</h3><div class="xpd-empty">No seeded pools returned on this network.</div></div>';
  return `<div class="xpd-amm-card"><h3>General pool explorer</h3><div class="xpd-pool-list">${explorerAmmSnapshot.pools.map(p => `
    <div class="xpd-pool-item">
      <div class="pool-pair xpd-pill-text" title="${escHtml(p.label)}">${escHtml(p.label)}</div>
      <div class="pool-meta">Reserves: ${escHtml(p.reserveA)} / ${escHtml(p.reserveB)}</div>
      <div class="pool-meta">Trading Fee: ${escHtml(p.tradingFee)} bps · Total LP: ${escHtml(p.totalLp)} · TVL: ${escHtml(p.tvl || 'Unavailable')}</div>
    </div>`).join('')}</div></div>`;
}

function _renderCustomPoolArea() {
  return `<div class="xpd-amm-card">
    <h3>Lookup custom pool</h3>
    <div class="xpd-form-grid">
      <input id="xpd-asset1-currency" class="xpd-input" placeholder="Asset 1 currency (e.g. XRP)" />
      <input id="xpd-asset1-issuer" class="xpd-input" placeholder="Asset 1 issuer (optional for XRP)" />
      <input id="xpd-asset2-currency" class="xpd-input" placeholder="Asset 2 currency (e.g. USD)" />
      <input id="xpd-asset2-issuer" class="xpd-input" placeholder="Asset 2 issuer" />
    </div>
    <div class="xpd-row-actions"><button class="xpd-action" onclick="loadCustomAmmPool()">Load pool</button><button class="xpd-action" onclick="refreshPoolExplorer()">Refresh known pools</button></div>
    ${customPoolSnapshot.loading ? '<div class="xpd-loading">Loading pool...</div>' : ''}
    ${customPoolSnapshot.error ? `<div class="xpd-error">${escHtml(customPoolSnapshot.error)}</div>` : ''}
    ${customPoolSnapshot.pool ? `<div class="xpd-pool-item"><div class="pool-pair xpd-pill-text" title="${escHtml(customPoolSnapshot.pool.label)}">${escHtml(customPoolSnapshot.pool.label)}</div><div class="pool-meta">Reserves: ${escHtml(customPoolSnapshot.pool.reserveA)} / ${escHtml(customPoolSnapshot.pool.reserveB)}</div><div class="pool-meta">Trading Fee: ${escHtml(customPoolSnapshot.pool.tradingFee)} bps · Total LP: ${escHtml(customPoolSnapshot.pool.totalLp)} · TVL: ${escHtml(customPoolSnapshot.pool.tvl || 'Unavailable')}</div></div>` : ''}
  </div>`;
}

function _fmtCompact(v) {
  if (!Number.isFinite(Number(v))) return '—';
  return new Intl.NumberFormat('en-US', { notation: 'compact', maximumFractionDigits: 2 }).format(Number(v));
}

function _parseXrplAmount(amount) {
  if (typeof amount === 'string') return `${fmt(Number(amount) / 1e6, 4)} XRP`;
  if (amount && typeof amount === 'object') return `${fmt(Number(amount.value || 0), 4)} ${amount.currency || 'UNK'}`;
  return '—';
}

function _decodeHexUri(hex) {
  if (!hex || typeof hex !== 'string') return '';
  try {
    const clean = hex.trim();
    if (!/^[0-9A-Fa-f]+$/.test(clean) || clean.length % 2 !== 0) return clean;
    const bytes = new Uint8Array(clean.length / 2);
    for (let i = 0; i < clean.length; i += 2) bytes[i / 2] = parseInt(clean.slice(i, i + 2), 16);
    return new TextDecoder().decode(bytes);
  } catch {
    return '';
  }
}

function _normalizeMetadataUri(uri) {
  if (!uri) return '';
  if (uri.startsWith('ipfs://')) return `https://ipfs.io/ipfs/${uri.slice(7)}`;
  if (uri.startsWith('ar://')) return `https://arweave.net/${uri.slice(5)}`;
  return uri;
}

async function _resolveNftImage(nft) {
  const uri = _normalizeMetadataUri(_decodeHexUri(nft.URI || nft.uri || ''));
  if (!uri) return '';
  if (/\.(png|jpg|jpeg|gif|webp|svg)$/i.test(uri)) return uri;
  try {
    const res = await fetch(uri, { method: 'GET' });
    if (!res.ok) return '';
    const meta = await res.json();
    const image = meta?.image || meta?.image_url || meta?.thumbnail;
    return _normalizeMetadataUri(image || '');
  } catch {
    return '';
  }
}

async function _fetchJson(url, { timeoutMs = 9000, allowProxy = true } = {}) {
  const doFetch = async (target) => {
    const signal = typeof AbortSignal?.timeout === 'function' ? AbortSignal.timeout(timeoutMs) : undefined;
    const res = await fetch(target, { method: 'GET', mode: 'cors', cache: 'no-store', signal });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  };

  try {
    return await doFetch(url);
  } catch (firstErr) {
    if (!allowProxy) throw firstErr;
    for (const mk of CORS_GET_PROXIES) {
      try {
        return await doFetch(mk(url));
      } catch {
        // try next proxy
      }
    }
    throw firstErr;
  }
}

async function _loadMarketData() {
  marketSnapshot.loading = true;
  marketSnapshot.error = '';
  renderProfilePage();
  try {
    const ticker = await _fetchJson('https://api.exchange.coinbase.com/products/XRP-USD/ticker');
    const candles = await _fetchJson('https://api.exchange.coinbase.com/products/XRP-USD/candles?granularity=86400');
    const day = Array.isArray(candles) && candles.length ? candles[0] : null;
    const price = Number(ticker?.price || 0);
    const open = day ? Number(day[3] || 0) : price;
    const high = day ? Number(day[2] || price) : price;
    const low = day ? Number(day[1] || price) : price;
    const vol = day ? Number(day[5] || 0) : 0;
    marketSnapshot.data = {
      priceUsd: price,
      change24h: open ? ((price - open) / open) * 100 : 0,
      volume24h: vol * price,
      marketCap: Number(marketSnapshot.data?.marketCap || 0),
      high24h: high,
      low24h: low,
    };
  } catch (err) {
    marketSnapshot.error = err?.message || 'Could not load market data right now.';
    marketSnapshot.data = null;
  } finally {
    marketSnapshot.loading = false;
    renderProfilePage();
  }
}

async function _loadNftData(address) {
  nftSnapshot.loading = true;
  nftSnapshot.error = '';
  nftSnapshot.items = [];
  renderProfilePage();
  if (!address) {
    nftSnapshot.loading = false;
    renderProfilePage();
    return;
  }
  try {
    let marker;
    const all = [];
    do {
      const r = await xrplPost({ method: 'account_nfts', params: [{ account: address, limit: 100, ...(marker ? { marker } : {}) }] });
      all.push(...(r?.account_nfts || []));
      marker = r?.marker;
    } while (marker);

    const items = await Promise.all(all.slice(0, 80).map(async nft => ({
      id: nft.NFTokenID || nft.nf_token_id || 'Unknown',
      image: await _resolveNftImage(nft),
    })));

    nftSnapshot.items = items;
  } catch (err) {
    nftSnapshot.error = err?.message || 'Could not load NFTs for this wallet.';
  } finally {
    nftSnapshot.loading = false;
    renderProfilePage();
  }
}

async function _loadUserAmmData(address) {
  userAmmSnapshot.loading = true;
  userAmmSnapshot.error = '';
  userAmmSnapshot.pools = [];
  renderProfilePage();
  if (!address) {
    userAmmSnapshot.loading = false;
    renderProfilePage();
    return;
  }
  try {
    const pools = [];
    let marker;
    do {
      const r = await xrplPost({ method: 'account_objects', params: [{ account: address, type: 'amm', limit: 200, ...(marker ? { marker } : {}) }] });
      const entries = r?.account_objects || [];
      entries.forEach(obj => {
        const a = _parseXrplAmount(obj.Asset || obj.amount);
        const b = _parseXrplAmount(obj.Asset2 || obj.amount2);
        const aSym = (a.split(' ').pop() || 'AssetA');
        const bSym = (b.split(' ').pop() || 'AssetB');
        pools.push({
          pair: `${aSym}/${bSym}`,
          lpBalance: obj.LPTokenBalance ? _parseXrplAmount(obj.LPTokenBalance) : 'Not reported',
          estimatedValue: 'Estimate unavailable',
          tradingFee: obj.TradingFee != null ? `${obj.TradingFee} bps` : '—',
          tvl: 'Unavailable',
        });
      });
      marker = r?.marker;
    } while (marker);

    const linesResp = await xrplPost({ method: 'account_lines', params: [{ account: address, limit: 200 }] });
    const lpLines = (linesResp?.lines || []).filter(l => typeof l.currency === 'string' && l.currency.length >= 16 && Number(l.balance) > 0);
    lpLines.forEach(line => {
      pools.push({
        pair: `LP Token ${line.currency.slice(0, 8)}...`,
        lpBalance: `${fmt(Number(line.balance), 4)} ${line.currency.slice(0, 8)}...`,
        estimatedValue: 'Estimate unavailable',
        tradingFee: '—',
        tvl: 'Unavailable',
      });
    });

    userAmmSnapshot.pools = pools;
  } catch (err) {
    userAmmSnapshot.error = err?.message || 'Could not load account AMM objects.';
  } finally {
    userAmmSnapshot.loading = false;
    renderProfilePage();
  }
}

async function _fetchAmmInfoPair(pair) {
  try {
    const r = await xrplPost({ method: 'amm_info', params: [{ asset: pair.asset, asset2: pair.asset2 }] });
    const amm = r?.amm;
    if (!amm) return null;
    return {
      label: pair.label,
      reserveA: _parseXrplAmount(amm.amount),
      reserveB: _parseXrplAmount(amm.amount2),
      tradingFee: String(amm.trading_fee ?? '—'),
      totalLp: _parseXrplAmount(amm.lp_token || amm.lp_token_balance),
      tvl: _estimateTvl(amm.amount, amm.amount2),
    };
  } catch {
    return null;
  }
}

function _estimateTvl(amountA, amountB) {
  const toNumber = (a) => {
    if (typeof a === 'string') return Number(a) / 1e6;
    if (a && typeof a === 'object') return Number(a.value || 0);
    return 0;
  };
  const tvl = toNumber(amountA) + toNumber(amountB);
  if (!Number.isFinite(tvl) || tvl <= 0) return 'Unavailable';
  return `${fmt(tvl, 4)} (asset units)`;
}

async function _loadExplorerAmmData() {
  explorerAmmSnapshot.loading = true;
  explorerAmmSnapshot.error = '';
  renderProfilePage();
  try {
    const rows = await Promise.all(AMM_EXPLORER_SEEDS.map(_fetchAmmInfoPair));
    explorerAmmSnapshot.pools = rows.filter(Boolean);
  } catch (err) {
    explorerAmmSnapshot.error = err?.message || 'Could not load AMM explorer data.';
    explorerAmmSnapshot.pools = [];
  } finally {
    explorerAmmSnapshot.loading = false;
    renderProfilePage();
  }
}

export async function loadCustomAmmPool() {
  const c1 = (document.getElementById('xpd-asset1-currency')?.value || '').trim().toUpperCase();
  const i1 = (document.getElementById('xpd-asset1-issuer')?.value || '').trim();
  const c2 = (document.getElementById('xpd-asset2-currency')?.value || '').trim().toUpperCase();
  const i2 = (document.getElementById('xpd-asset2-issuer')?.value || '').trim();

  if (!c1 || !c2) {
    customPoolSnapshot.error = 'Enter both asset currency codes first.';
    renderProfilePage();
    return;
  }

  const a1 = c1 === 'XRP' ? { currency: 'XRP' } : { currency: c1, issuer: i1 };
  const a2 = c2 === 'XRP' ? { currency: 'XRP' } : { currency: c2, issuer: i2 };
  if ((c1 !== 'XRP' && !i1) || (c2 !== 'XRP' && !i2)) {
    customPoolSnapshot.error = 'Issuer is required for non-XRP assets.';
    renderProfilePage();
    return;
  }

  customPoolSnapshot.loading = true;
  customPoolSnapshot.error = '';
  customPoolSnapshot.pool = null;
  renderProfilePage();

  const result = await _fetchAmmInfoPair({ label: `${c1}/${c2}`, asset: a1, asset2: a2 });
  customPoolSnapshot.loading = false;
  if (!result) customPoolSnapshot.error = 'Pool not found or unavailable on this network.';
  else customPoolSnapshot.pool = result;
  renderProfilePage();
}

function _currentPairOption() {
  return DEX_PAIR_OPTIONS.find(p => p.id === dexSnapshot.pair) || DEX_PAIR_OPTIONS[0];
}

function _intervalToMinutes(interval) {
  if (interval === 'D') return 1440;
  if (interval === 'W') return 10080;
  if (interval === 'M') return 43200;
  const n = Number(interval);
  return Number.isFinite(n) && n > 0 ? n : 60;
}

function _coinbaseProductFromTicker(ticker) {
  const map = {
    xrpusd: 'XRP-USD',
    XRPUSDT: 'XRP-USD',
    ETHUSDT: 'ETH-USD',
    BTCUSDT: 'BTC-USD',
    SOLUSDT: 'SOL-USD',
  };
  return map[ticker] || null;
}

async function _fetchDexStats() {
  const pair = _currentPairOption();
  dexSnapshot.loading = true;
  dexSnapshot.error = '';
  try {
    const product = _coinbaseProductFromTicker(pair.ticker);
    if (product) {
      const tj = await _fetchJson(`https://api.exchange.coinbase.com/products/${product}/ticker`);
      const cj = await _fetchJson(`https://api.exchange.coinbase.com/products/${product}/candles?granularity=86400`);
      const day = Array.isArray(cj) && cj.length ? cj[0] : null;
      const price = Number(tj.price || 0);
      const open = day ? Number(day[3]) : price;
      dexSnapshot.stats = {
        price,
        high: day ? Number(day[2]) : price,
        low: day ? Number(day[1]) : price,
        changePct: open ? ((price - open) / open) * 100 : 0,
        baseSource: 'Coinbase',
        source: 'Coinbase',
      };
      await _enrichWithXrplReference();
      if (!marketSnapshot.data && dexSnapshot.stats.price) {
        marketSnapshot.data = {
          priceUsd: dexSnapshot.stats.price,
          change24h: dexSnapshot.stats.changePct,
          volume24h: day ? Number(day[5] || 0) * dexSnapshot.stats.price : 0,
          marketCap: Number(marketSnapshot.data?.marketCap || 0),
        };
      }
      return;
    }

    throw new Error('Chart stats unavailable for selected pair.');
  } catch (err) {
    dexSnapshot.error = err?.message || 'DEX chart stats unavailable right now.';
  } finally {
    dexSnapshot.loading = false;
  }
}

async function _enrichWithXrplReference() {
  try {
    const quote = await xrplPost({
      method: 'book_offers',
      params: [{
        taker_gets: { currency: 'USD', issuer: 'rhub8VRN55s94qWKDv6jmDy1pUykJzF3wq' },
        taker_pays: { currency: 'XRP' },
        limit: 1,
      }],
    });
    const first = quote?.offers?.[0];
    if (!first) return;
    const gets = Number(first.TakerGets?.value || 0);
    const pays = typeof first.TakerPays === 'string' ? Number(first.TakerPays) / 1e6 : Number(first.TakerPays?.value || 0);
    if (gets > 0 && pays > 0) {
      const px = gets / pays;
      _lastXrplSpotAt = Date.now();
      if (!dexSnapshot.stats) dexSnapshot.stats = {};
      dexSnapshot.stats.xrplSpot = px;
      dexSnapshot.stats.price = px;
      const base = dexSnapshot.stats.baseSource || dexSnapshot.stats.source || 'Market feed';
      dexSnapshot.stats.source = `${base} + XRPL live`;
      if (marketSnapshot.data) marketSnapshot.data.priceUsd = px;
    }
  } catch {
    // Best-effort enrichment only.
  }
}

async function _ensureChartLibLoaded() {
  if (window.LightweightCharts?.createChart) return true;
  if (!_chartLibPromise) {
    _chartLibPromise = new Promise((resolve, reject) => {
      const existing = document.querySelector('script[data-lw-chart="1"]');
      if (existing) {
        existing.addEventListener('load', () => resolve(true), { once: true });
        existing.addEventListener('error', () => reject(new Error('Chart library failed to load.')), { once: true });
        return;
      }
      const s = document.createElement('script');
      s.src = 'https://unpkg.com/lightweight-charts@4.2.2/dist/lightweight-charts.standalone.production.js';
      s.async = true;
      s.defer = true;
      s.dataset.lwChart = '1';
      s.onload = () => resolve(true);
      s.onerror = () => reject(new Error('Chart library failed to load.'));
      document.head.appendChild(s);
    }).finally(() => {
      if (!window.LightweightCharts?.createChart) _chartLibPromise = null;
    });
  }
  await _chartLibPromise;
  return !!window.LightweightCharts?.createChart;
}

function _intervalToBinance(interval) {
  const map = {
    '1': '1m', '3': '3m', '5': '5m', '15': '15m', '30': '30m',
    '60': '1h', '120': '2h', '240': '4h',
    D: '1d', W: '1w', M: '1M',
  };
  return map[interval] || '1h';
}

function _intervalToSeconds(interval) {
  const mins = _intervalToMinutes(interval);
  return mins * 60;
}

function _intervalToCoinbaseGranularity(interval) {
  const mins = _intervalToMinutes(interval);
  if (mins <= 1) return 60;
  if (mins <= 5) return 300;
  if (mins <= 15) return 900;
  if (mins <= 60) return 3600;
  if (mins <= 360) return 21600;
  return 86400;
}

function _toHeikinAshi(candles) {
  if (!candles.length) return candles;
  const out = [];
  for (let i = 0; i < candles.length; i += 1) {
    const c = candles[i];
    const close = (c.open + c.high + c.low + c.close) / 4;
    const prev = out[i - 1];
    const open = prev ? (prev.open + prev.close) / 2 : (c.open + c.close) / 2;
    const high = Math.max(c.high, open, close);
    const low = Math.min(c.low, open, close);
    out.push({ ...c, open, high, low, close });
  }
  return out;
}

function _sma(data, len) {
  const out = [];
  let sum = 0;
  for (let i = 0; i < data.length; i += 1) {
    sum += data[i].close;
    if (i >= len) sum -= data[i - len].close;
    if (i >= len - 1) out.push({ time: data[i].time, value: sum / len });
  }
  return out;
}

function _ema(data, len) {
  const out = [];
  if (!data.length) return out;
  const k = 2 / (len + 1);
  let ema = data[0].close;
  for (let i = 0; i < data.length; i += 1) {
    ema = i === 0 ? data[i].close : (data[i].close * k) + (ema * (1 - k));
    if (i >= len - 1) out.push({ time: data[i].time, value: ema });
  }
  return out;
}

function _wma(data, len) {
  const out = [];
  const denom = (len * (len + 1)) / 2;
  for (let i = len - 1; i < data.length; i += 1) {
    let wsum = 0;
    for (let j = 0; j < len; j += 1) {
      wsum += data[i - j].close * (len - j);
    }
    out.push({ time: data[i].time, value: wsum / denom });
  }
  return out;
}

function _bbands(data, len = 20, mult = 2) {
  const mid = _sma(data, len);
  const upper = [];
  const lower = [];
  for (let i = len - 1; i < data.length; i += 1) {
    const slice = data.slice(i - len + 1, i + 1);
    const avg = mid[i - (len - 1)].value;
    const variance = slice.reduce((s, c) => s + Math.pow(c.close - avg, 2), 0) / len;
    const sd = Math.sqrt(variance);
    upper.push({ time: data[i].time, value: avg + (sd * mult) });
    lower.push({ time: data[i].time, value: avg - (sd * mult) });
  }
  return { upper, lower };
}

function _vwap(data) {
  const out = [];
  let pv = 0;
  let vol = 0;
  for (let i = 0; i < data.length; i += 1) {
    const typical = (data[i].high + data[i].low + data[i].close) / 3;
    pv += typical * (data[i].volume || 0);
    vol += (data[i].volume || 0);
    if (vol > 0) out.push({ time: data[i].time, value: pv / vol });
  }
  return out;
}

async function _fetchBarsByPair(pair, interval) {
  const cacheKey = `${pair.id}:${interval}`;
  const cached = _dexBarCache.get(cacheKey);
  if (cached && (Date.now() - cached.ts) < 60_000) return cached.data;

  let candles = [];
  const product = _coinbaseProductFromTicker(pair.ticker);
  if (!product) throw new Error('Bars unavailable for selected pair/interval.');
  const granularity = _intervalToCoinbaseGranularity(interval);
  const rows = await _fetchJson(`https://api.exchange.coinbase.com/products/${product}/candles?granularity=${granularity}`);
  candles = rows.map(r => ({
    time: Number(r[0]),
    low: Number(r[1]),
    high: Number(r[2]),
    open: Number(r[3]),
    close: Number(r[4]),
    volume: Number(r[5]),
  })).sort((a, b) => a.time - b.time);

  _dexBarCache.set(cacheKey, { ts: Date.now(), data: candles });
  return candles;
}

async function _fetchDexBars() {
  const pair = _currentPairOption();
  let candles = await _fetchBarsByPair(pair, dexSnapshot.interval);

  const liveSpot = Number(dexSnapshot.stats?.xrplSpot || dexSnapshot.stats?.price || 0);
  if (Number.isFinite(liveSpot) && liveSpot > 0 && candles.length) {
    const iv = Math.max(60, _intervalToSeconds(dexSnapshot.interval));
    const nowTs = Math.floor(Date.now() / 1000);
    const bucket = Math.floor(nowTs / iv) * iv;
    const last = candles[candles.length - 1];
    if (last.time === bucket) {
      last.high = Math.max(last.high, liveSpot);
      last.low = Math.min(last.low, liveSpot);
      last.close = liveSpot;
    } else if (last.time < bucket) {
      candles.push({
        time: bucket,
        open: last.close,
        high: Math.max(last.close, liveSpot),
        low: Math.min(last.close, liveSpot),
        close: liveSpot,
        volume: 0,
      });
    }
  }

  if (dexSnapshot.chartType === 'heikin_ashi') candles = _toHeikinAshi(candles);
  return candles;
}

function _normalizeBars(candles) {
  if (!Array.isArray(candles)) return [];
  const cleaned = candles
    .map(c => ({
      time: Number(c.time),
      open: Number(c.open),
      high: Number(c.high),
      low: Number(c.low),
      close: Number(c.close),
      volume: Number(c.volume || 0),
    }))
    .filter(c => Number.isFinite(c.time)
      && Number.isFinite(c.open)
      && Number.isFinite(c.high)
      && Number.isFinite(c.low)
      && Number.isFinite(c.close)
      && c.time > 0)
    .sort((a, b) => a.time - b.time);

  // Lightweight Charts is strict about ascending unique timestamps.
  const deduped = [];
  for (let i = 0; i < cleaned.length; i += 1) {
    const curr = cleaned[i];
    const prev = deduped[deduped.length - 1];
    if (prev && prev.time === curr.time) deduped[deduped.length - 1] = curr;
    else deduped.push(curr);
  }
  return deduped;
}

function _destroyDexChart() {
  if (_dexChartRuntime.resizeObserver) {
    try { _dexChartRuntime.resizeObserver.disconnect(); } catch {}
  }
  if (_dexChartRuntime.chart) {
    _dexChartRuntime.chart.remove();
    _dexChartRuntime = {
      chart: null,
      volumeSeries: null,
      activeSeries: null,
      compareSeries: null,
      indicatorSeries: [],
      resizeObserver: null,
      chartType: '',
    };
  }
}

async function _mountDexWidget() {
  const seq = ++_dexMountSeq;
  const el = document.getElementById('xpd-tv-widget');
  if (!el) return;
  try {
    const raw = await _fetchDexBars();
    const data = _normalizeBars(raw);
    if (seq !== _dexMountSeq) return;
    if (!data.length) throw new Error('No chart bars returned for selected pair/timeframe.');

    const host = document.getElementById('xpd-tv-widget');
    if (!host || seq !== _dexMountSeq) return;

    _destroyDexChart();
    host.innerHTML = '';
    const width = Math.max(320, host.clientWidth || host.parentElement?.clientWidth || 320);
    const height = 460;
    const right = 56;
    const left = 10;
    const top = 10;
    const bottom = 24;
    const chartH = Math.floor(height * 0.76);
    const volumeTop = chartH + 6;
    const volumeH = height - volumeTop - bottom;

    const view = data.slice(Math.max(0, data.length - 90));
    const step = Math.max(2, (width - left - right) / Math.max(1, view.length - 1));
    const xs = (_, i) => left + (i * step);

    const lows = view.map(v => v.low);
    const highs = view.map(v => v.high);
    let yMin = Math.min(...lows);
    let yMax = Math.max(...highs);
    const pad = Math.max((yMax - yMin) * 0.08, 0.0008);
    yMin -= pad;
    yMax += pad;
    const y = (v) => {
      const r = Math.max(1e-9, yMax - yMin);
      return top + ((yMax - v) / r) * (chartH - top);
    };

    const volMax = Math.max(1, ...view.map(v => v.volume || 0));
    const vy = (v) => volumeTop + (1 - ((v || 0) / volMax)) * Math.max(1, volumeH);

    const linePathFromMap = (valueMap) => {
      const pts = view
        .map((c, i) => ({ x: xs(c, i), y: valueMap.get(c.time) }))
        .filter(p => Number.isFinite(p.y));
      if (!pts.length) return '';
      return pts.map((p, i) => `${i === 0 ? 'M' : 'L'}${p.x.toFixed(2)},${y(p.y).toFixed(2)}`).join(' ');
    };

    const closePath = view
      .map((c, i) => `${i === 0 ? 'M' : 'L'}${xs(c, i).toFixed(2)},${y(c.close).toFixed(2)}`)
      .join(' ');

    const volumeBars = view.map((c, i) => {
      const x = xs(c, i) - Math.max(1, step * 0.34);
      const bw = Math.max(1.2, step * 0.68);
      const yy = vy(c.volume);
      const h = Math.max(1, volumeTop + volumeH - yy);
      const color = c.close >= c.open ? 'rgba(80,250,123,0.42)' : 'rgba(255,85,85,0.42)';
      return `<rect x="${x.toFixed(2)}" y="${yy.toFixed(2)}" width="${bw.toFixed(2)}" height="${h.toFixed(2)}" fill="${color}" />`;
    }).join('');

    let mainSeries = '';
    if (dexSnapshot.chartType === 'line') {
      mainSeries = `<path d="${closePath}" fill="none" stroke="#11d9ff" stroke-width="2.2" />`;
    } else if (dexSnapshot.chartType === 'area') {
      const baseY = volumeTop - 2;
      mainSeries = `<path d="${closePath} L ${xs(view[view.length - 1], view.length - 1).toFixed(2)},${baseY.toFixed(2)} L ${xs(view[0], 0).toFixed(2)},${baseY.toFixed(2)} Z" fill="url(#xpdAreaFill)" /><path d="${closePath}" fill="none" stroke="#11d9ff" stroke-width="2" />`;
    } else if (dexSnapshot.chartType === 'bars') {
      mainSeries = view.map((c, i) => {
        const xx = xs(c, i);
        const color = c.close >= c.open ? '#50fa7b' : '#ff6e6e';
        return `<line x1="${xx.toFixed(2)}" y1="${y(c.high).toFixed(2)}" x2="${xx.toFixed(2)}" y2="${y(c.low).toFixed(2)}" stroke="${color}" stroke-width="1.4" /><line x1="${(xx - 3).toFixed(2)}" y1="${y(c.open).toFixed(2)}" x2="${xx.toFixed(2)}" y2="${y(c.open).toFixed(2)}" stroke="${color}" stroke-width="1.4" /><line x1="${xx.toFixed(2)}" y1="${y(c.close).toFixed(2)}" x2="${(xx + 3).toFixed(2)}" y2="${y(c.close).toFixed(2)}" stroke="${color}" stroke-width="1.4" />`;
      }).join('');
    } else {
      const hollow = dexSnapshot.chartType === 'hollow_candles';
      mainSeries = view.map((c, i) => {
        const xx = xs(c, i);
        const color = c.close >= c.open ? '#50fa7b' : '#ff6e6e';
        const bodyW = Math.max(1.4, step * 0.52);
        const by = Math.min(y(c.open), y(c.close));
        const bh = Math.max(1.2, Math.abs(y(c.close) - y(c.open)));
        return `<line x1="${xx.toFixed(2)}" y1="${y(c.high).toFixed(2)}" x2="${xx.toFixed(2)}" y2="${y(c.low).toFixed(2)}" stroke="${color}" stroke-width="1.2" /><rect x="${(xx - bodyW / 2).toFixed(2)}" y="${by.toFixed(2)}" width="${bodyW.toFixed(2)}" height="${bh.toFixed(2)}" fill="${hollow ? 'transparent' : color}" stroke="${color}" stroke-width="1.1" />`;
      }).join('');
    }

    const indicatorPaths = [];
    if (dexSnapshot.indicators.sma20) {
      const m = new Map(_sma(data, 20).map(v => [v.time, v.value]));
      indicatorPaths.push(`<path d="${linePathFromMap(m)}" fill="none" stroke="#f1fa8c" stroke-width="1.2" />`);
    }
    if (dexSnapshot.indicators.ema20) {
      const m = new Map(_ema(data, 20).map(v => [v.time, v.value]));
      indicatorPaths.push(`<path d="${linePathFromMap(m)}" fill="none" stroke="#ffb86c" stroke-width="1.2" />`);
    }
    if (dexSnapshot.indicators.wma20) {
      const m = new Map(_wma(data, 20).map(v => [v.time, v.value]));
      indicatorPaths.push(`<path d="${linePathFromMap(m)}" fill="none" stroke="#bd93f9" stroke-width="1.2" />`);
    }
    if (dexSnapshot.indicators.vwap) {
      const m = new Map(_vwap(data).map(v => [v.time, v.value]));
      indicatorPaths.push(`<path d="${linePathFromMap(m)}" fill="none" stroke="#80ffea" stroke-width="1.1" />`);
    }
    if (dexSnapshot.indicators.bb20) {
      const bb = _bbands(data, 20, 2);
      const u = new Map(bb.upper.map(v => [v.time, v.value]));
      const l = new Map(bb.lower.map(v => [v.time, v.value]));
      indicatorPaths.push(`<path d="${linePathFromMap(u)}" fill="none" stroke="#ff79c6" stroke-width="1" stroke-dasharray="5 3" />`);
      indicatorPaths.push(`<path d="${linePathFromMap(l)}" fill="none" stroke="#ff79c6" stroke-width="1" stroke-dasharray="5 3" />`);
    }

    let comparePath = '';
    if (dexSnapshot.comparePair) {
      const pair = DEX_PAIR_OPTIONS.find(p => p.id === dexSnapshot.comparePair);
      if (pair) {
        const cmp = _normalizeBars(await _fetchBarsByPair(pair, dexSnapshot.interval));
        const m = new Map(cmp.map(v => [v.time, v.close]));
        const d = linePathFromMap(m);
        if (d) comparePath = `<path d="${d}" fill="none" stroke="#ffffff" stroke-width="1.2" opacity="0.86" />`;
      }
    }

    const levels = 6;
    const grid = Array.from({ length: levels }, (_, i) => {
      const yy = top + ((chartH - top) * (i / (levels - 1)));
      const val = yMax - ((yMax - yMin) * (i / (levels - 1)));
      return `<line x1="${left}" y1="${yy.toFixed(2)}" x2="${(width - right)}" y2="${yy.toFixed(2)}" stroke="rgba(148,208,245,0.12)" stroke-width="1" /><text x="${(width - right + 6)}" y="${(yy + 3).toFixed(2)}" fill="rgba(221,245,255,0.9)" font-size="11">${fmt(val, 2)}</text>`;
    }).join('');

    const latest = view[view.length - 1];
    const lastY = y(latest.close);
    const priceTag = `<line x1="${left}" y1="${lastY.toFixed(2)}" x2="${(width - right)}" y2="${lastY.toFixed(2)}" stroke="rgba(0,212,255,0.3)" stroke-width="1" stroke-dasharray="4 4" /><rect x="${(width - right + 2)}" y="${(lastY - 9).toFixed(2)}" width="46" height="16" rx="5" fill="${latest.close >= latest.open ? '#49f57f' : '#ffd96b'}" /><text x="${(width - right + 7)}" y="${(lastY + 2).toFixed(2)}" fill="#09202b" font-size="11" font-weight="700">${fmt(latest.close, 2)}</text>`;

    host.innerHTML = `
      <svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}" class="xpd-svg-chart" role="img" aria-label="XRPL price chart">
        <defs>
          <linearGradient id="xpdAreaFill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stop-color="rgba(17,217,255,0.36)" />
            <stop offset="100%" stop-color="rgba(17,217,255,0.04)" />
          </linearGradient>
        </defs>
        <rect x="0" y="0" width="${width}" height="${height}" fill="transparent" />
        ${grid}
        ${volumeBars}
        ${mainSeries}
        ${indicatorPaths.join('')}
        ${comparePath}
        ${priceTag}
      </svg>`;

    _dexChartRuntime = { chart: null, volumeSeries: null, activeSeries: null, compareSeries: null, indicatorSeries: [], resizeObserver: null, chartType: dexSnapshot.chartType };
  } catch (err) {
    if (seq !== _dexMountSeq) return;
    dexSnapshot.error = err?.message || 'Could not initialize chart widget.';
    const host = document.getElementById('xpd-tv-widget');
    if (host) host.innerHTML = `<div class="xpd-error">${escHtml(dexSnapshot.error)}</div>`;
  }
}

export function toggleSeedBackupStatus() {
  const next = safeGet(LS_SEED_BACKUP_STATUS) === '1' ? '0' : '1';
  safeSet(LS_SEED_BACKUP_STATUS, next);
  renderProfilePage();
}

export async function setDexPair(pair) {
  if (!DEX_PAIR_OPTIONS.some(p => p.id === pair)) return;
  dexSnapshot.pair = pair;
  await _fetchDexStats();
  renderProfilePage();
}

export async function setDexInterval(interval) {
  dexSnapshot.interval = interval;
  await _fetchDexStats();
  renderProfilePage();
}

export function setDexChartType(chartType) {
  dexSnapshot.chartType = chartType;
  renderProfilePage();
}

export async function refreshDexChart() {
  await _fetchDexStats();
  renderProfilePage();
}

export function toggleIndicator(key, enabled) {
  if (!(key in dexSnapshot.indicators)) return;
  dexSnapshot.indicators[key] = !!enabled;
  renderProfilePage();
}

export function setComparePair(pairId) {
  dexSnapshot.comparePair = pairId || '';
  renderProfilePage();
}

export function toggleTerminalTheme() {
  const light = document.body.classList.contains('theme-gold');
  setTheme(light ? 'cosmic' : 'gold');
  renderProfilePage();
}

export function toggleChartFullscreen() {
  const wrap = document.querySelector('.xpd-chart-wrap');
  if (!wrap) return;
  if (document.fullscreenElement) document.exitFullscreen();
  else wrap.requestFullscreen?.();
}

export function exportChartPng() {
  const svg = document.querySelector('#xpd-tv-widget svg');
  if (svg) {
    const serializer = new XMLSerializer();
    const source = serializer.serializeToString(svg);
    const svgBlob = new Blob([source], { type: 'image/svg+xml;charset=utf-8' });
    const url = URL.createObjectURL(svgBlob);
    const img = new Image();
    img.onload = () => {
      const canvas = document.createElement('canvas');
      canvas.width = svg.viewBox.baseVal.width || svg.clientWidth || 1200;
      canvas.height = svg.viewBox.baseVal.height || svg.clientHeight || 460;
      const ctx = canvas.getContext('2d');
      if (!ctx) { URL.revokeObjectURL(url); toastWarn('Could not render chart image.'); return; }
      ctx.drawImage(img, 0, 0);
      const a = document.createElement('a');
      a.download = `xrpl-chart-${Date.now()}.png`;
      a.href = canvas.toDataURL('image/png');
      a.click();
      URL.revokeObjectURL(url);
    };
    img.onerror = () => {
      URL.revokeObjectURL(url);
      toastWarn('Chart image export failed.');
    };
    img.src = url;
    return;
  }

  const canvas = document.querySelector('#xpd-tv-widget canvas');
  if (!canvas) { toastWarn('Chart image is not ready yet.'); return; }
  const a = document.createElement('a');
  a.download = `xrpl-chart-${Date.now()}.png`;
  a.href = canvas.toDataURL('image/png');
  a.click();
}

export function saveChartLayoutPreset() {
  safeSet(LS_CHART_LAYOUT, JSON.stringify({
    pair: dexSnapshot.pair,
    interval: dexSnapshot.interval,
    chartType: dexSnapshot.chartType,
    comparePair: dexSnapshot.comparePair,
    indicators: dexSnapshot.indicators,
  }));
  toastInfo('Chart layout saved.');
}

export function loadChartLayoutPreset() {
  const saved = safeJson(safeGet(LS_CHART_LAYOUT));
  if (!saved) { toastWarn('No saved chart layout found.'); return; }
  dexSnapshot.pair = saved.pair || dexSnapshot.pair;
  dexSnapshot.interval = saved.interval || dexSnapshot.interval;
  dexSnapshot.chartType = saved.chartType || dexSnapshot.chartType;
  dexSnapshot.comparePair = saved.comparePair || '';
  dexSnapshot.indicators = { ...dexSnapshot.indicators, ...(saved.indicators || {}) };
  renderProfilePage();
}

function _normalizeTokenCode(code) {
  const v = String(code || '').trim();
  if (/^[0-9A-F]{40}$/i.test(v)) {
    const raw = v.replace(/(00)+$/g, '');
    if (/^[0-9A-F]+$/i.test(raw) && raw.length % 2 === 0) {
      try {
        const bytes = new Uint8Array(raw.length / 2);
        for (let i = 0; i < raw.length; i += 2) bytes[i / 2] = parseInt(raw.slice(i, i + 2), 16);
        const txt = new TextDecoder().decode(bytes).replace(/\0/g, '').trim();
        if (txt) return txt.toUpperCase();
      } catch {
        // continue fallback
      }
    }
  }
  return v.toUpperCase();
}

function _tokenKey(token) {
  return `${token.symbol}|${token.issuer || ''}`;
}

function _tokenFromXrplScanRow(row) {
  const symbol = _normalizeTokenCode(row.code || row.currency || '');
  const issuer = String(row.issuer || row.IssuingAccount?.account || '').trim();
  const price = Number(row.price ?? row.metrics?.price ?? 0);
  const marketcap = Number(row.marketcap ?? row.metrics?.marketcap ?? 0);
  const volume24h = Number(row.metrics?.volume_24h ?? 0);
  const name = row.meta?.token?.name || row.IssuingAccount?.name || symbol || 'Unknown Token';
  const holderCount = Number(row.holders ?? row.metrics?.holders ?? row.metrics?.trustlines ?? 0);

  return {
    symbol,
    name,
    issuer,
    tokenId: row.id || `${symbol}.${issuer}`,
    price: Number.isFinite(price) && price > 0 ? price : null,
    marketCap: Number.isFinite(marketcap) && marketcap > 0 ? marketcap : null,
    volume24h: Number.isFinite(volume24h) ? volume24h : null,
    holders: Number.isFinite(holderCount) ? holderCount : null,
    change24h: null,
    verified: !!row.IssuingAccount?.verified,
    score: Number(row.score || 0) || null,
  };
}

async function _loadTokenDiscoveryData() {
  tokenDiscoverySnapshot.loading = true;
  tokenDiscoverySnapshot.error = '';
  try {
    const now = Date.now();
    const cached = _marketCache.get('tokens');
    if (cached && (now - cached.ts) < 60_000) {
      tokenDiscoverySnapshot.tokens = cached.data;
      tokenDiscoverySnapshot.total = cached.total || cached.data.length;
      tokenDiscoverySnapshot.lastSyncAt = cached.ts;
      tokenDiscoverySnapshot.filtered = _filterTokens(tokenDiscoverySnapshot.query, cached.data);
      tokenDiscoverySnapshot.trending = _rankTrending(cached.data);
      tokenDiscoverySnapshot.loading = false;
      return;
    }

    const pageSize = 500;
    const maxPages = 6;
    const allRows = [];
    for (let page = 1; page <= maxPages; page += 1) {
      const rows = await _fetchJson(`${XRPSCAN_TOKENS_URL}?page=${page}&limit=${pageSize}`, { allowProxy: false, timeoutMs: 12000 });
      if (!Array.isArray(rows) || !rows.length) break;
      allRows.push(...rows);
      if (rows.length < pageSize) break;
    }

    const parsed = allRows
      .map(_tokenFromXrplScanRow)
      .filter(t => !!t.symbol && !!t.issuer);

    const xrpNative = {
      symbol: 'XRP',
      name: 'XRP Ledger Native',
      issuer: '',
      tokenId: 'XRP',
      price: marketSnapshot.data?.priceUsd || dexSnapshot.stats?.price || null,
      marketCap: marketSnapshot.data?.marketCap || null,
      volume24h: marketSnapshot.data?.volume24h || null,
      holders: null,
      change24h: marketSnapshot.data?.change24h || dexSnapshot.stats?.changePct || null,
      verified: true,
      score: 1,
    };

    const unique = new Map();
    [xrpNative, ...parsed].forEach(t => {
      const key = _tokenKey(t);
      if (!unique.has(key)) unique.set(key, t);
    });

    const tokens = [...unique.values()];
    _marketCache.set('tokens', { ts: now, data: tokens, total: tokens.length });

    tokenDiscoverySnapshot.tokens = tokens;
    tokenDiscoverySnapshot.total = tokens.length;
    tokenDiscoverySnapshot.lastSyncAt = now;
    tokenDiscoverySnapshot.filtered = _filterTokens(tokenDiscoverySnapshot.query, tokens);
    tokenDiscoverySnapshot.trending = _rankTrending(tokens);
  } catch (err) {
    tokenDiscoverySnapshot.error = err?.message || 'Could not load XRPL token discovery data.';
  } finally {
    tokenDiscoverySnapshot.loading = false;
  }
}

function _filterTokens(query, tokens) {
  const q = String(query || '').trim().toLowerCase();
  if (!q) return tokens;
  return tokens.filter(t => `${t.symbol} ${t.name} ${t.issuer} ${t.tokenId || ''}`.toLowerCase().includes(q));
}

function _rankTrending(tokens) {
  return [...tokens].sort((a, b) => {
    const aVol = Number(a.volume24h || 0);
    const bVol = Number(b.volume24h || 0);
    if (bVol !== aVol) return bVol - aVol;
    const aCap = Number(a.marketCap || 0);
    const bCap = Number(b.marketCap || 0);
    return bCap - aCap;
  }).slice(0, 24);
}

async function _loadRecentTransactionsData(address) {
  recentTxSnapshot.loading = true;
  recentTxSnapshot.error = '';
  recentTxSnapshot.items = [];
  if (!address) { recentTxSnapshot.loading = false; return; }
  try {
    const txs = await fetchTxHistory(address, 20);
    recentTxSnapshot.items = txs || [];
  } catch (err) {
    recentTxSnapshot.error = err?.message || 'Could not load recent transactions.';
  } finally {
    recentTxSnapshot.loading = false;
  }
}

export function searchTokens(query) {
  tokenDiscoverySnapshot.query = query;
  tokenDiscoverySnapshot.filtered = _filterTokens(query, tokenDiscoverySnapshot.tokens);
  renderProfilePage();
}

export function addTokenToWatchlist(tokenKeyOrSymbol) {
  const key = String(tokenKeyOrSymbol || '').trim();
  if (!key) return;
  const list = _getWatchlist();
  if (!list.includes(key)) list.push(key);
  _setWatchlist(list);
  renderProfilePage();
}

export function removeTokenFromWatchlist(tokenKeyOrSymbol) {
  const key = String(tokenKeyOrSymbol || '').trim();
  const list = _getWatchlist().filter(s => s !== key);
  _setWatchlist(list);
  renderProfilePage();
}

export function openTokenOnChart(tokenKeyOrSymbol) {
  const raw = String(tokenKeyOrSymbol || '').trim();
  const symbol = raw.includes('|') ? raw.split('|')[0] : raw;
  const mapped = {
    XRP: 'BITSTAMP:XRPUSD',
    RLUSD: 'BITSTAMP:XRPUSD',
    SOLO: 'BINANCE:XRPUSDT',
    CORE: 'BINANCE:XRPUSDT',
    COREUM: 'BINANCE:XRPUSDT',
    USDV: 'BINANCE:XRPUSDT',
    BTC: 'BINANCE:BTCUSDT',
    ETH: 'BINANCE:ETHUSDT',
    SOL: 'BINANCE:SOLUSDT',
  };
  if (mapped[symbol]) {
    dexSnapshot.pair = mapped[symbol];
  } else {
    dexSnapshot.pair = 'BITSTAMP:XRPUSD';
    toastInfo(`No direct pair for ${symbol} yet. Showing XRP chart while token stays in watchlist.`);
  }
  renderProfilePage();
}

export async function refreshTokenDiscovery() {
  await _loadTokenDiscoveryData();
  renderProfilePage();
}

export async function refreshRecentTransactions() {
  const address = getActiveWallet()?.address || '';
  await _loadRecentTransactionsData(address);
  renderProfilePage();
}

export async function refreshXrplDashboard({ silent = false } = {}) {
  const address = getActiveWallet()?.address || '';
  if (!silent) toastInfo('Refreshing XRPL dashboard data...');
  await Promise.allSettled([
    _fetchDexStats(),
    _loadMarketData(),
    _loadTokenDiscoveryData(),
    _loadRecentTransactionsData(address),
    _loadNftData(address),
    _loadUserAmmData(address),
    _loadExplorerAmmData(),
  ]);
  renderProfilePage();
}

export function refreshMarketData() {
  return _loadMarketData();
}

export function refreshNftGallery() {
  return _loadNftData(getActiveWallet()?.address || '');
}

export function refreshAmmPools() {
  return _loadUserAmmData(getActiveWallet()?.address || '');
}

export function refreshPoolExplorer() {
  return _loadExplorerAmmData();
}

export function sendNft(nftId) {
  toastInfo(`NFT ${nftId.slice(0, 12)}... selected. Send flow can be wired to NFTokenCreateOffer.`);
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
  const seed = prompt('Optional seed to cancel this order (leave blank to use wallet password):');
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
  try {
    if (state.wsConn?.readyState === 1) {
      const { wsSend } = await import('./xrpl.js');
      const payload = { command: body?.method, ...(body?.params?.[0] || {}) };
      const msg = await wsSend(payload);
      if (msg?.status === 'error') throw new Error(msg.error_message || msg.error || 'XRPL RPC error');
      return msg?.result || null;
    }
  } catch {
    // Fall through to HTTPS JSON-RPC fallback.
  }

  const tryFetch = async (url) => {
    const r = await fetch(url, {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify(body),
      mode: 'cors',
    });
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
  await ensureXrplLoaded();
  if (!window.xrpl) throw new Error('xrpl.js library not loaded. Cannot sign transactions.');
  const wObj = wallets.find(w => w.id === walletId);
  if (!wObj) throw new Error('Wallet not found.');
  if (wObj.watchOnly) throw new Error('Watch-only wallets cannot sign transactions.');
  const seedToUse = await _resolveSeedForSigning(wObj, seed);
  let xrplWallet;
  try { xrplWallet = window.xrpl.Wallet.fromSeed(seedToUse, { algorithm: wObj.algo==='secp256k1'?'secp256k1':'ed25519' }); }
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
    void seedToUse;
  }
}

export async function executeTrustSet(walletId, currency, issuer, limit = '1000000000', seed) {
  return signAndSubmit(walletId, { TransactionType:'TrustSet', LimitAmount:{ currency, issuer, value:String(limit) } }, seed);
}
export async function executePayment(walletId, destination, amount, currency, issuer, destinationTag, seed) {
  const isXRP = !currency || currency==='XRP';
  const Amount = isXRP ? String(Math.floor(parseFloat(amount)*1e6)) : { currency, issuer, value:String(amount) };
  return signAndSubmit(walletId, {
    TransactionType: 'Payment', Destination: destination, Amount,
    ...(destinationTag ? { DestinationTag:parseInt(destinationTag) } : {}),
  }, seed);
}
export async function executeOfferCreate(walletId, takerGets, takerPays, seed) {
  return signAndSubmit(walletId, { TransactionType:'OfferCreate', TakerGets:takerGets, TakerPays:takerPays }, seed);
}
export async function executeOfferCancel(walletId, offerSequence, seed) {
  return signAndSubmit(walletId, { TransactionType:'OfferCancel', OfferSequence:parseInt(offerSequence) }, seed);
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
    const seed = $('send-seed')?.value || '';
    const result = await executePayment(_sendWalletId, dest, amount, currency==='XRP'?null:currency, issuer, destTag, seed);
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
  const seed = prompt(`Optional seed for ${currency} trustline removal (leave blank to use wallet password):`);
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
        <div class="profile-field"><label class="profile-field-label">Seed Phrase <span style="font-size:.72rem;color:rgba(255,255,255,.3);text-transform:none">(optional if wallet is encrypted)</span></label><input class="profile-input mono" id="send-seed" type="password" placeholder="Leave blank to use wallet password" autocomplete="off"></div>
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
        <div class="profile-field"><label class="profile-field-label">Seed Phrase <span style="font-size:.72rem;color:rgba(255,255,255,.3);text-transform:none">(optional if wallet is encrypted)</span></label><input class="profile-input mono" id="tl-seed" type="password" placeholder="Leave blank to use wallet password" autocomplete="off"></div>
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
      <div class="profile-field"><label class="profile-field-label">Wallet Password *</label><input class="profile-input" id="inp-import-seed-pass" type="password" placeholder="At least 10 characters" autocomplete="new-password"></div>
      <div class="profile-field"><label class="profile-field-label">Confirm Password *</label><input class="profile-input" id="inp-import-seed-pass-confirm" type="password" placeholder="Re-enter wallet password" autocomplete="new-password"></div>
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
  // Export public wallet metadata only (encrypted seeds are not exported)
  exportWalletAddresses();
  toastInfo('Wallet addresses exported (encrypted seeds are not included).');
}

/* ═══════════════════════════════════════════════════
   Wallet Creator Wizard
═══════════════════════════════════════════════════ */
export function openWalletCreator() {
  // no vault required
  wizardStep = 1;
  wizardData = { algo:'ed25519', label:'', emoji:'💎', color:'#50fa7b', seed:'', address:'', passphrase:'' };
  checksCompleted.clear();
  renderWizardStep(1); renderWizardCustomization(); _renderWizardSecurityBanner();
  $('wallet-creator-overlay')?.classList.add('show');
  setTimeout(() => $('wallet-label-input')?.focus(), 80);
}
export function closeWalletCreator() {
  $('wallet-creator-overlay')?.classList.remove('show');
  wizardData.seed = wizardData.address = wizardData.passphrase = '';
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

export async function wizardNext() {
  if (wizardStep === 1) {
    const label = $('wallet-label-input')?.value.trim();
    const passphrase = $('wallet-pass-input')?.value || '';
    const passphraseConfirm = $('wallet-pass-confirm')?.value || '';
    if (!label) { toastWarn('Enter a wallet name.'); return; }
    if (passphrase.length < 10) { toastWarn('Use a wallet password with at least 10 characters.'); return; }
    if (passphrase !== passphraseConfirm) { toastWarn('Wallet password confirmation does not match.'); return; }
    wizardData.label = label;
    wizardData.passphrase = passphrase;
    if (!generateWalletKeys()) return;
    wizardStep = 2;
  } else if (wizardStep === 2) {
    if (checksCompleted.size < 4) { toastWarn('Confirm all 4 security checkpoints first.'); return; }
    wizardStep = 3;
  } else if (wizardStep === 3) {
    try {
      await saveNewWallet();
      wizardStep = 4;
    } catch {
      return;
    }
  }
  renderWizardStep(wizardStep);
}
export function wizardBack() {
  if (wizardStep <= 1) { closeWalletCreator(); return; }
  wizardStep--; renderWizardStep(wizardStep);
}

function renderWizardStep(step) {
  [1,2,3,4].forEach(s => {
    const d = document.querySelector(`.step-${s}`);
    if (!d) return;
    d.classList.toggle('active', s===step);
    d.classList.toggle('done', s<step);
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
  if (!window.xrpl?.Wallet) {
    toastErr('xrpl.js is not available yet. Please wait a moment and try again.');
    ensureXrplLoaded().catch(() => {});
    return false;
  }
  try {
    const w = window.xrpl.Wallet.generate(wizardData.algo==='ed25519'?'ed25519':'secp256k1');
    wizardData.seed = w.seed || '';
    wizardData.address = w.classicAddress;
  } catch (e) {
    toastErr('Failed to generate a valid XRPL wallet: ' + (e?.message || 'Unknown error'));
    return false;
  }
  const seedEl=$('wizard-seed-value'), addrEl=$('wizard-address-value');
  if (seedEl) seedEl.textContent = wizardData.seed;
  if (addrEl) addrEl.textContent = wizardData.address;
  checksCompleted.clear();
  $$('.security-check').forEach(el => el.classList.remove('checked'));
  $$('.check-box').forEach(el => el.textContent = '');
  _renderSecurityChecklist(); updateWizardNextBtn();
  // Auto-blur seed after 30 seconds for security
  if (seedEl) setTimeout(() => seedEl.classList.add('blur'), 30_000);
  return true;
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

async function saveNewWallet() {
  const encSeed = await _encryptSeed(wizardData.seed, wizardData.passphrase);
  const wallet = {
    id:        crypto.randomUUID(),
    label:     wizardData.label,
    address:   wizardData.address,
    algo:      wizardData.algo,
    emoji:     wizardData.emoji,
    color:     wizardData.color,
    testnet:   $('wallet-testnet-check')?.checked || false,
    watchOnly: false,
    encSeed,
    createdAt: new Date().toISOString(),
  };

  wallets.push(wallet);
  _saveWallets();
  if (!activeWalletId) { activeWalletId = wallet.id; safeSet(LS_ACTIVE_ID, wallet.id); }
  renderWalletList(); renderActiveWalletBar();
  _setText('wallet-success-address', wizardData.address);
  setTimeout(() => { wizardData.seed=''; wizardData.address=''; wizardData.passphrase=''; }, 100);
  logActivity('wallet_created', wizardData.label||'New XRPL Wallet');
  toastInfo('Wallet created and encrypted locally');
  fetchBalance(wallet.address).then(()=>renderWalletList());
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
  const el = document.querySelector(`.security-check-${idx}`);
  if (!el) return;
  const box = el.querySelector('.check-box');
  if (checksCompleted.has(idx)) {
    checksCompleted.delete(idx);
    el.classList.remove('checked');
    if (box) box.textContent='';
  } else {
    checksCompleted.add(idx);
    el.classList.add('checked');
    if (box) box.textContent='✓';
  }
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
  m.querySelector('#inp-import-seed-pass').value='';
  m.querySelector('#inp-import-seed-pass-confirm').value='';
  m.querySelector('#inp-import-seed-label').value='';
  const e=m.querySelector('#import-seed-error'); if(e)e.textContent='';
  m.classList.add('show'); setTimeout(()=>m.querySelector('#inp-import-seed')?.focus(),80);
}
export function closeImportSeedModal() { $('import-seed-modal')?.classList.remove('show'); }
export async function executeImportFromSeed() {
  const seed  =($('inp-import-seed')?.value||'').trim();
  const label =($('inp-import-seed-label')?.value||'').trim()||'Imported Wallet';
  const passphrase = ($('inp-import-seed-pass')?.value || '').trim();
  const passphraseConfirm = ($('inp-import-seed-pass-confirm')?.value || '').trim();
  const errEl = $('import-seed-error');
  const btn   = $('import-seed-btn');
  const setErr= m=>{if(errEl)errEl.textContent=m;};
  setErr('');
  if (!seed)                      return setErr('Enter your seed phrase.');
  if (passphrase.length < 10)     return setErr('Use a wallet password with at least 10 characters.');
  if (passphrase !== passphraseConfirm) return setErr('Wallet password confirmation does not match.');
  await ensureXrplLoaded();
  if (!window.xrpl)               return setErr('xrpl.js not loaded — cannot derive address from seed.');
  if (btn){btn.disabled=true;btn.textContent='Importing…';}
  try {
    const xrplW   = window.xrpl.Wallet.fromSeed(seed);
    const address = xrplW.address;
    const algo    = xrplW.algorithm?.toLowerCase().includes('ed')?'ed25519':'secp256k1';
    if (wallets.find(w=>w.address===address)) return setErr('This address is already in your vault.');
    const id='imp_'+Date.now(), emoji='🔑', color='#bd93f9';
    const encSeed = await _encryptSeed(seed, passphrase);

    wallets.push({ id, label, address, algo, emoji, color, testnet: false, watchOnly: false, encSeed, createdAt: new Date().toISOString() });
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
    const _ip = document.getElementById('inp-import-seed-pass'); if (_ip) _ip.value = '';
    const _ic = document.getElementById('inp-import-seed-pass-confirm'); if (_ic) _ic.value = '';
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
  if (!confirm('Clear all profile, wallet list, social, and activity data? Encrypted wallet seeds saved on this device will be deleted.')) return;
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
  const canUseAsyncClipboard = !!navigator.clipboard?.writeText && document.hasFocus();

  if (canUseAsyncClipboard) {
    navigator.clipboard.writeText(text).then(() => {
      toastInfo('Copied to clipboard');
      if (autoClearMs) {
        setTimeout(() => {
          if (document.hasFocus() && navigator.clipboard?.writeText) {
            navigator.clipboard.writeText('').catch(() => {});
          }
        }, autoClearMs);
      }
    }).catch(() => {
      const el=document.createElement('textarea');
      el.value=text;
      document.body.appendChild(el);
      el.select();
      document.execCommand('copy');
      el.remove();
      toastInfo('Copied');
    });
    return;
  }

  const el=document.createElement('textarea');
  el.value=text;
  document.body.appendChild(el);
  el.select();
  document.execCommand('copy');
  el.remove();
  toastInfo('Copied');
}

function _hexToAscii(hex) {
  if (!/^[0-9A-Fa-f]+$/.test(hex)) return '';
  try {
    let s=''; for(let i=0;i<hex.length;i+=2) s+=String.fromCharCode(parseInt(hex.slice(i,i+2),16));
    return s.replace(/\x00/g,'').trim();
  } catch { return ''; }
}

export { signAndSubmit };