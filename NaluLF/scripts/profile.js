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

import { $, $$, escHtml, safeGet, safeSet, safeJson, safeRemove,
         toastInfo, toastErr, toastWarn, isValidXrpAddress, fmt, shortAddr } from './utils.js';
import { state } from './state.js';
import { setTheme } from './theme.js';
import { CryptoVault } from './auth.js';
import { fetchProjectIntel } from './project-intel.js';


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
const AI_DEFAULT_MODEL = 'claude-opus-5';
const AI_MODEL_OPTIONS = [
  { id: 'claude-opus-5',   label: 'Claude Opus 5 — most capable, highest cost' },
  { id: 'claude-sonnet-5', label: 'Claude Sonnet 5 — strong, cheaper' },
  { id: 'claude-haiku-4-5', label: 'Claude Haiku 4.5 — fastest, cheapest' },
];
const XRPSCAN_TOKENS_URL = 'https://api.xrpscan.com/api/v1/tokens';
const COINGECKO_MARKETS_URL = 'https://api.coingecko.com/api/v3/coins/markets';
const BITHOMP_TOKENS_URL = 'https://bithomp.com/api/v2/tokens';
const XRPL_TO_TOKENS_URL = 'https://api.xrpl.to/api/tokens';
const ENABLE_BITHOMP_SOURCE = false;

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

// These 5, plus dexSnapshot and tokenDiscoverySnapshot below, are all
// auto-fetched by refreshXrplDashboard() the moment the profile page becomes
// active — but that fetch is async, so the very first render (using this
// default state, before any loader has run) used to show "no data" rather
// than "loading," a false-empty flash on every page visit. Defaulting to
// loading:true is safe specifically because refreshXrplDashboard's
// Promise.allSettled + each loader's own try/finally guarantee every one of
// these gets set back to false shortly after, on both success and failure —
// there's no path that leaves it permanently stuck. customPoolSnapshot is
// deliberately excluded: it's user-triggered on demand (loadCustomAmmPool),
// never auto-fetched, so "not loading, no data yet" is its correct default.
let marketSnapshot = { loading: true, data: null, error: '' };
let nftSnapshot = { loading: true, items: [], error: '' };
let userAmmSnapshot = { loading: true, pools: [], error: '' };
let explorerAmmSnapshot = { loading: true, pools: [], error: '' };
let customPoolSnapshot = { loading: false, pool: null, error: '' };
let dexSnapshot = {
  pair: 'BITSTAMP:XRPUSD',
  interval: '15',
  chartType: 'candles',
  stats: null,
  loading: true, // see the comment above marketSnapshot — same first-paint-flash fix
  error: '',
  comparePair: '',
  indicators: {
    sma20: true,
    ema20: false,
    wma20: false,
    bb20: false,
    vwap: false,
    ichimoku: false,
    macd: false,
    rsi: false,
    atr: false,
    adx: false,
    aroon: false,
    cci: false,
    williamsr: false,
    mfi: false,
    obv: false,
    adline: false,
    cmf: false,
    stoch: false,
    uo: false,
    stdev: false,
    donchian: false,
    keltner: false,
    supertrend: false,
    pivots: false,
    sar: false,
    vortex: false,
    elderRay: false,
  },
  tokenFocusKey: '',
  drawingTool: 'none',
  drawings: [],
  alerts: [],
  indicatorMenuOpen: false,
  moreMenuOpen: false,
  indicatorQuery: '',
  indicatorSettings: {},
  settingsOpenFor: null,
  threeEnabled: true,
  selectedIndicator: 'sma20',
  selectedEducationTab: 'indicator',
  educationCollapsed: false,
  educationHint: '',
  chartMeta: {
    tokenKey: 'XRP|',
    symbol: 'XRP',
    source: 'Coinbase + XRPL live',
    last: null,
    high: null,
    low: null,
    mode: 'pair', // pair | token-direct | token-proxy | fallback
  },
};
let tokenDiscoverySnapshot = {
  loading: true, // see the comment above marketSnapshot — same first-paint-flash fix
  tokens: [],
  filtered: [],
  trending: [],
  error: '',
  query: '',
  total: 0,
  lastSyncAt: 0,
  filters: { type: 'all', minCap: 0, minVol: 0, hasDex: false },
  selectedTokenKey: '',
  listLimit: 240,
};
let recentTxSnapshot = { loading: true, items: [], error: '' }; // see the comment above marketSnapshot
let projectIntelSnapshot = { loading: false, error: '', data: null, tokenKey: '', expandedSubScore: '' };
const _marketCache = new Map();
let _chartLibPromise = null;
let _threeChartPromise = null;
let _dexLiveListenerBound = false;
let _lastLedgerDrivenRefresh = 0;
let _lastXrplSpotAt = 0;
let _tokenSearchDebounce = null;
const _tokenSourceCooldownUntil = {
  xrplto: 0,
};
let _dexChartRuntime = {
  chart: null,
  volumeSeries: null,
  activeSeries: null,
  compareSeries: null,
  indicatorSeries: [],
  indicatorPriceLines: [],
  priceLines: [],
  resizeObserver: null,
  chartType: '',
  configKey: '',
  legendEl: null,
  renderLegend: null,
  ichimokuData: null,
  indicatorLegendItems: [],
  alertPriceLines: [],
};
let _chartAtmosphereRuntime = {
  renderer: null,
  scene: null,
  camera: null,
  points: null,
  raf: 0,
  host: null,
  resizeHandler: null,
};
const _dexBarCache = new Map();
let _dexMountSeq = 0;
// Tracks which focused tokenKey we've already warned about having no real
// market data, so _fetchDexBars (which reruns on every ~3-4s live-ledger
// tick) doesn't spam the same toast repeatedly — reset whenever a fetch
// succeeds or the user focuses a different token.
let _lastNoMarketWarnedKey = '';

/* ═══════════════════════════════════════
   Full price history (inception-to-date)
   ═══════════════════════════════════════
   Coinbase's candles endpoint only ever returns the most recent ~300 bars
   per request — nowhere near a coin's full trading history. This paginates
   backward with start/end windows until Coinbase runs out of data, then (for
   the 4 majors, where we know the CoinGecko id) extends further back with
   CoinGecko's market_chart/range, which commonly has daily data going back
   much closer to a coin's actual listing/launch than Coinbase does (e.g.
   Coinbase only listed XRP-USD in 2019; CoinGecko's XRP history goes back to
   2013). The historical (non-today) portion never changes, so it's cached
   in localStorage indefinitely — only the live tail gets refetched. */
const LS_FULL_HISTORY_PREFIX = 'naluxrp_hist_v1_';
// Hard caps so an automatic, on-every-load fetch can't runaway-loop or
// hammer these free public APIs into rate-limiting this browser. 60 pages
// at daily granularity is ~49 years — enough for any listed asset's full
// Coinbase history. Intraday is capped much lower since even a few years of
// 1-minute bars is millions of candles no browser chart should try to hold.
const FULL_HISTORY_MAX_PAGES_DAILY = 60;
const FULL_HISTORY_MAX_PAGES_INTRADAY = 25;
const FULL_HISTORY_PAGE_DELAY_MS = 200;
const _sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const LS_SEED_BACKUP_STATUS = 'naluxrp_seed_backed_up';
const LS_WATCHLIST = 'naluxrp_token_watchlist';
const LS_CHART_LAYOUT = 'naluxrp_chart_layout';
const LS_SELECTED_TOKEN = 'naluxrp_selected_token';
const LS_3D_EFFECTS = 'naluxrp_chart_3d';
const LS_PRICE_ALERTS = 'naluxrp_price_alerts';

function _isProfilePageActive() {
  return state.currentPage === 'profile' && !document.hidden;
}

const DEMO_XRPL_TOKENS = [
  { symbol: 'XRP', name: 'XRP Ledger Native', marketCap: '$124.3B', source: 'CoinGecko' },
  { symbol: 'RLUSD', name: 'Ripple USD', marketCap: '$312.0M', source: 'Static sample' },
  { symbol: 'SOLOGENIC', name: 'Sologenic', marketCap: '$96.4M', source: 'Static sample' },
];

const DEX_PAIR_OPTIONS = [
  { id: 'BITSTAMP:XRPUSD', label: 'XRP / USD (Coinbase + XRPL)', source: 'coinbase', ticker: 'xrpusd', symbol: 'XRP', coingeckoId: 'ripple' },
  { id: 'BINANCE:XRPUSDT', label: 'XRP / USD (Coinbase mirror)', source: 'coinbase', ticker: 'XRPUSDT', symbol: 'XRP', coingeckoId: 'ripple' },
  { id: 'BINANCE:ETHUSDT', label: 'ETH / USD (Coinbase)', source: 'coinbase', ticker: 'ETHUSDT', symbol: 'ETH', coingeckoId: 'ethereum' },
  { id: 'BINANCE:BTCUSDT', label: 'BTC / USD (Coinbase)', source: 'coinbase', ticker: 'BTCUSDT', symbol: 'BTC', coingeckoId: 'bitcoin' },
  { id: 'BINANCE:SOLUSDT', label: 'SOL / USD (Coinbase)', source: 'coinbase', ticker: 'SOLUSDT', symbol: 'SOL', coingeckoId: 'solana' },
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

const DRAW_TOOL_OPTIONS = [
  { key: 'none', label: 'Cursor' },
  { key: 'hline', label: 'Horizontal Line' },
];

const INDICATOR_GROUPS = {
  trend: ['sma20', 'ema20', 'wma20', 'ichimoku', 'adx', 'aroon', 'sar', 'supertrend', 'vortex', 'elderRay', 'macd'],
  momentum: ['rsi', 'stoch', 'cci', 'williamsr', 'mfi', 'uo'],
  volume: ['obv', 'adline', 'cmf', 'vwap'],
  volatility: ['bb20', 'keltner', 'atr', 'donchian', 'stdev'],
  advanced: ['pivots'],
};

const INDICATOR_META = {
  sma20: { name: 'SMA 20', what: 'Simple average of closing prices over 20 periods.', purpose: 'Baseline trend smoothing.', apply: 'Use slope and price relation for trend confirmation.', mistake: 'Assuming one crossover equals full trend reversal.', bias: 'Check higher timeframe trend first.' },
  ema20: { name: 'EMA 20', what: 'Weighted moving average that reacts faster.', purpose: 'Track momentum shifts early.', apply: 'Use with structure breaks for continuation entries.', mistake: 'Overtrading every touch.', bias: 'Wait for confirmation candle close.' },
  wma20: { name: 'WMA 20', what: 'Linear weighted average favoring recent closes.', purpose: 'Balance noise and reactivity.', apply: 'Useful for dynamic pullback zones.', mistake: 'Treating it as support in chop.', bias: 'Confirm with volatility context.' },
  ichimoku: { name: 'Ichimoku Cloud', what: 'Multi-line trend, momentum, and support/resistance framework.', purpose: 'One-glance regime detection.', apply: 'Favor trades aligned with cloud direction and conversion/base line confluence.', mistake: 'Ignoring lagging span context.', bias: 'Only take signals in clear trend phases.' },
  macd: { name: 'MACD', what: 'Difference between fast and slow EMAs with signal line.', purpose: 'Momentum and trend acceleration.', apply: 'Use histogram contraction/expansion and line cross with structure.', mistake: 'Late entries from isolated crosses.', bias: 'Match cross direction with market structure.' },
  rsi: { name: 'RSI', what: 'Relative strength oscillator from 0-100.', purpose: 'Momentum strength and exhaustion.', apply: '40-80 bull range, 20-60 bear range is often more useful than 30/70 alone.', mistake: 'Shorting every overbought reading in uptrends.', bias: 'Use RSI with trend filters and divergence context.' },
  stoch: { name: 'Stochastic', what: 'Close location relative to recent range.', purpose: 'Short-term momentum turns.', apply: 'Best in ranges or pullbacks within trend.', mistake: 'Treating every cross as signal.', bias: 'Require structure or support/resistance confluence.' },
  cci: { name: 'CCI', what: 'Deviation from statistical mean.', purpose: 'Identify cyclical overextensions.', apply: 'Look for trend-aligned re-entry after reset.', mistake: 'Using fixed thresholds in all regimes.', bias: 'Adapt thresholds to volatility.' },
  williamsr: { name: 'Williams %R', what: 'Inverse stochastic oscillator.', purpose: 'Range extremes and momentum snapbacks.', apply: 'Use with market regime filter.', mistake: 'Fading trends blindly.', bias: 'Avoid countertrend trades without invalidation levels.' },
  mfi: { name: 'MFI', what: 'Volume-weighted RSI style oscillator.', purpose: 'Money flow pressure.', apply: 'Combine with volume spikes for conviction.', mistake: 'Ignoring thin liquidity distortions.', bias: 'Cross-check on multiple venues when possible.' },
  uo: { name: 'Ultimate Oscillator', what: 'Weighted momentum across multiple windows.', purpose: 'Reduce single-window false signals.', apply: 'Divergences can be strong with structure breaks.', mistake: 'Using without trend filter.', bias: 'Require two independent confirmations.' },
  obv: { name: 'On Balance Volume', what: 'Cumulative signed volume.', purpose: 'Volume pressure trend.', apply: 'Look for OBV breaks before price breaks.', mistake: 'Trusting OBV in sparse data periods.', bias: 'Check liquidity quality first.' },
  adline: { name: 'Accumulation/Distribution', what: 'Volume flow using close location in candle.', purpose: 'Detect stealth accumulation/distribution.', apply: 'Use for divergence against price trend.', mistake: 'Ignoring wick distortions.', bias: 'Validate with average volume regime.' },
  cmf: { name: 'Chaikin Money Flow', what: 'Normalized accumulation/distribution over window.', purpose: 'Money flow bias.', apply: 'Sustained above/below zero is more meaningful than single crosses.', mistake: 'Reacting to one-bar flips.', bias: 'Use persistence thresholds.' },
  vwap: { name: 'VWAP', what: 'Volume weighted average price.', purpose: 'Institutional execution benchmark.', apply: 'Use as intraday mean reversion or trend continuation anchor.', mistake: 'Ignoring session resets.', bias: 'Define session context explicitly.' },
  bb20: { name: 'Bollinger Bands', what: 'Moving average with standard deviation envelopes.', purpose: 'Volatility expansion/contraction.', apply: 'Squeezes can precede breakouts; walks indicate trend.', mistake: 'Assuming every upper-band touch is sell.', bias: 'Pair with trend and volume confirmation.' },
  keltner: { name: 'Keltner Channel', what: 'EMA center with ATR-based envelopes.', purpose: 'Trend-aware volatility channel.', apply: 'Break/hold beyond band can mark trend strength.', mistake: 'Using fixed ATR multiplier everywhere.', bias: 'Tune per asset volatility.' },
  atr: { name: 'ATR', what: 'Average true range.', purpose: 'Position sizing and stop calibration.', apply: 'Use ATR multiples for stops/targets.', mistake: 'Using fixed pip stops in all regimes.', bias: 'Normalize risk by volatility.' },
  donchian: { name: 'Donchian Channels', what: 'Highest high / lowest low bands.', purpose: 'Breakout systems.', apply: 'Use channel breaks with trend filter.', mistake: 'Ignoring false breakout environment.', bias: 'Wait for close confirmation.' },
  stdev: { name: 'Standard Deviation', what: 'Dispersion of price from mean.', purpose: 'Volatility regime shifts.', apply: 'Expand risk controls during high dispersion.', mistake: 'Mistaking volatility for direction.', bias: 'Separate volatility from trend.' },
  adx: { name: 'ADX', what: 'Trend strength metric independent of direction.', purpose: 'Regime filter.', apply: 'Use +DI/-DI with ADX slope.', mistake: 'Trading direction off ADX alone.', bias: 'Combine with directional structure.' },
  aroon: { name: 'Aroon', what: 'Time since highs/lows.', purpose: 'Trend emergence detection.', apply: 'Aroon up/down crosses near extremes can flag regime shifts.', mistake: 'Using in high-noise micro ranges.', bias: 'Require multi-candle confirmation.' },
  pivots: { name: 'Pivot Points', what: 'Session-based support/resistance levels.', purpose: 'Map likely reaction zones.', apply: 'Use confluence with order flow and trend.', mistake: 'Treating pivots as guaranteed reversal levels.', bias: 'Plan invalidation before entry.' },
  sar: { name: 'Parabolic SAR', what: 'Trailing stop indicator with acceleration factor.', purpose: 'Trend trailing and stop logic.', apply: 'Works best in persistent trends.', mistake: 'Using in sideways chop.', bias: 'Filter with ADX or structure.' },
  supertrend: { name: 'Supertrend', what: 'ATR-based trend-following overlay.', purpose: 'Trend direction and trailing stop.', apply: 'Follow flips when volatility supports continuation.', mistake: 'Chasing every flip in range.', bias: 'Use higher timeframe confirmation.' },
  vortex: { name: 'Vortex', what: 'Positive/negative trend movement lines.', purpose: 'Trend turning points.', apply: 'Crosses with expansion can mark trend shifts.', mistake: 'Ignoring low-liquidity noise.', bias: 'Confirm with volume and structure.' },
  elderRay: { name: 'Elder Ray', what: 'Bull/Bear power versus EMA baseline.', purpose: 'Pressure around trend mean.', apply: 'Look for divergence and trend continuation.', mistake: 'Using without baseline trend direction.', bias: 'Anchor decisions to trend context.' },
};

// Every field each indicator's settings popover (gear icon on its chip)
// exposes — periods and per-line colors, read by _populateIndicatorSeries's
// f()/getLen() helpers and rendered generically by
// _renderIndicatorSettingsPopover. Fixed/semantic colors that wouldn't mean
// anything as a single user-editable swatch (pivot levels' 5 distinct
// colors) are intentionally left out.
const INDICATOR_FIELD_SCHEMA = {
  sma20: [{ id: 'length', label: 'Length', type: 'number', default: 20 }, { id: 'color', label: 'Color', type: 'color', default: '#f1c40f' }],
  ema20: [{ id: 'length', label: 'Length', type: 'number', default: 20 }, { id: 'color', label: 'Color', type: 'color', default: '#ffb86c' }],
  wma20: [{ id: 'length', label: 'Length', type: 'number', default: 20 }, { id: 'color', label: 'Color', type: 'color', default: '#bd93f9' }],
  vwap: [{ id: 'color', label: 'Color', type: 'color', default: '#80ffea' }],
  bb20: [{ id: 'length', label: 'Length', type: 'number', default: 20 }, { id: 'color', label: 'Band Color', type: 'color', default: '#ff79c6' }],
  ichimoku: [
    { id: 'tenkanLen', label: 'Tenkan Length', type: 'number', default: 9 },
    { id: 'kijunLen', label: 'Kijun Length', type: 'number', default: 26 },
    { id: 'senkouBLen', label: 'Senkou B Length', type: 'number', default: 52 },
    { id: 'tenkanColor', label: 'Tenkan Color', type: 'color', default: '#ffde59' },
    { id: 'kijunColor', label: 'Kijun Color', type: 'color', default: '#6ecbff' },
    { id: 'bullColor', label: 'Cloud Bull Color', type: 'color', default: '#46ffa0' },
    { id: 'bearColor', label: 'Cloud Bear Color', type: 'color', default: '#ff7878' },
  ],
  donchian: [{ id: 'length', label: 'Length', type: 'number', default: 20 }, { id: 'color', label: 'Color', type: 'color', default: '#9cfb8c' }],
  keltner: [{ id: 'length', label: 'Length', type: 'number', default: 20 }, { id: 'color', label: 'Color', type: 'color', default: '#7ee7ff' }],
  supertrend: [{ id: 'color', label: 'Color', type: 'color', default: '#8bffde' }],
  sar: [{ id: 'color', label: 'Color', type: 'color', default: '#ffaf7a' }],
  elderRay: [{ id: 'bullColor', label: 'Bull Color', type: 'color', default: '#5fff9d' }, { id: 'bearColor', label: 'Bear Color', type: 'color', default: '#ff9d9d' }],
  rsi: [{ id: 'length', label: 'Length', type: 'number', default: 14 }, { id: 'color', label: 'Color', type: 'color', default: '#a6ff4d' }],
  atr: [{ id: 'length', label: 'Length', type: 'number', default: 14 }, { id: 'color', label: 'Color', type: 'color', default: '#ffb86c' }],
  stdev: [{ id: 'color', label: 'Color', type: 'color', default: '#b2a3ff' }],
  stoch: [
    { id: 'length', label: 'Length', type: 'number', default: 14 },
    { id: 'kColor', label: '%K Color', type: 'color', default: '#9ee8ff' },
    { id: 'dColor', label: '%D Color', type: 'color', default: '#ffd86b' },
  ],
  macd: [
    { id: 'fastLen', label: 'Fast Length', type: 'number', default: 12 },
    { id: 'slowLen', label: 'Slow Length', type: 'number', default: 26 },
    { id: 'signalLen', label: 'Signal Length', type: 'number', default: 9 },
    { id: 'lineColor', label: 'MACD Color', type: 'color', default: '#8fd9ff' },
    { id: 'signalColor', label: 'Signal Color', type: 'color', default: '#ffcf8e' },
  ],
  obv: [{ id: 'color', label: 'Color', type: 'color', default: '#8cf9ff' }],
  adline: [{ id: 'color', label: 'Color', type: 'color', default: '#ffb7ff' }],
  cmf: [{ id: 'length', label: 'Length', type: 'number', default: 20 }, { id: 'color', label: 'Color', type: 'color', default: '#f8ff87' }],
  williamsr: [{ id: 'length', label: 'Length', type: 'number', default: 14 }, { id: 'color', label: 'Color', type: 'color', default: '#ff9adf' }],
  cci: [{ id: 'length', label: 'Length', type: 'number', default: 20 }, { id: 'color', label: 'Color', type: 'color', default: '#b8ff8e' }],
  mfi: [{ id: 'length', label: 'Length', type: 'number', default: 14 }, { id: 'color', label: 'Color', type: 'color', default: '#7bffd2' }],
  uo: [{ id: 'color', label: 'Color', type: 'color', default: '#ffd36f' }],
  adx: [
    { id: 'length', label: 'Length', type: 'number', default: 14 },
    { id: 'adxColor', label: 'ADX Color', type: 'color', default: '#9fd8ff' },
    { id: 'plusColor', label: '+DI Color', type: 'color', default: '#73ffc0' },
    { id: 'minusColor', label: '-DI Color', type: 'color', default: '#ff9797' },
  ],
  aroon: [
    { id: 'length', label: 'Length', type: 'number', default: 14 },
    { id: 'upColor', label: 'Up Color', type: 'color', default: '#6cffb0' },
    { id: 'downColor', label: 'Down Color', type: 'color', default: '#ff8f8f' },
  ],
  vortex: [
    { id: 'length', label: 'Length', type: 'number', default: 14 },
    { id: 'plusColor', label: 'VI+ Color', type: 'color', default: '#d6a8ff' },
    { id: 'minusColor', label: 'VI- Color', type: 'color', default: '#ffb0f3' },
  ],
};

const INDICATOR_DEEP_INTEL = {
  sma20: { creator: 'Early quantitative analysts (1900s tape reading era)', era: 'Formalized in the early 20th century', math: 'Arithmetic mean of the last N closes.', context: 'Designed to smooth noisy tape data for trend direction visibility.', regime: 'Best in directional trends, weaker in mean-reverting chop.' },
  ema20: { creator: 'Modern technical analysts adapting exponential smoothing', era: 'Popularized in 1960s-1980s', math: 'Recursive weighted mean with alpha = 2/(N+1).', context: 'Improves responsiveness versus SMA while preserving trend structure.', regime: 'Useful for pullback entries in trending environments.' },
  ichimoku: { creator: 'Goichi Hosoda', era: 'Developed pre-WW2, published 1969', math: 'Median-price lines (9/26/52) plus shifted cloud projections.', context: 'Built as a full market regime system: trend, momentum, support/resistance in one frame.', regime: 'Most reliable when cloud slope and price acceptance align.' },
  macd: { creator: 'Gerald Appel', era: 'Late 1970s', math: 'MACD = EMA(12)-EMA(26), signal=EMA(9) of MACD, histogram=spread.', context: 'Tracks trend acceleration/deceleration, not just direction.', regime: 'Strong in trend transitions, noisy in low-volatility ranges.' },
  rsi: { creator: 'J. Welles Wilder Jr.', era: '1978', math: 'RSI = 100 - 100/(1+RS), RS = avg gain / avg loss.', context: 'Measures internal momentum pressure rather than price level alone.', regime: 'Range shifts (bull/bear RSI zones) matter more than static 30/70.' },
  adx: { creator: 'J. Welles Wilder Jr.', era: '1978', math: 'Smoothed directional movement (+DI/-DI) transformed into trend-strength index.', context: 'Separates trend strength from trend direction.', regime: 'Filter trades: momentum systems improve when ADX slope rises.' },
  aroon: { creator: 'Tushar Chande', era: '1995', math: 'Time since recent high/low scaled to 0-100.', context: 'Focuses on trend freshness instead of pure magnitude.', regime: 'Good at identifying emergent trend phases and late-trend fatigue.' },
  cci: { creator: 'Donald Lambert', era: '1980', math: 'Deviation of typical price from moving average normalized by mean deviation.', context: 'Originally commodity cycle tool for identifying statistical extremes.', regime: 'Works better with volatility-aware thresholds than fixed +/-100.' },
  williamsr: { creator: 'Larry Williams', era: '1970s', math: 'Position of close within rolling high-low range, scaled negative.', context: 'Fast oscillator for short-horizon exhaustion and reversion timing.', regime: 'Most effective in bounded ranges; trend filters prevent fade traps.' },
  mfi: { creator: 'Gene Quong and Avrum Soudack', era: '1989', math: 'RSI-style transform using typical price * volume money flow.', context: 'Adds participation/volume dimension to momentum analysis.', regime: 'Useful where volume quality is high; weaker on fragmented liquidity.' },
  obv: { creator: 'Joseph Granville', era: '1963', math: 'Cumulative signed volume based on close direction.', context: 'Detects accumulation/distribution before obvious price moves.', regime: 'Best when confirmed with structure breaks and volume regime shifts.' },
  vwap: { creator: 'Institutional execution desks', era: '1980s electronic execution era', math: 'Cumulative price*volume divided by cumulative volume.', context: 'Execution benchmark and intraday fair-value reference.', regime: 'Most meaningful intraday and around session anchor resets.' },
  bb20: { creator: 'John Bollinger', era: '1980s', math: 'SMA +/- k * standard deviation.', context: 'Captures volatility contraction/expansion around a mean.', regime: 'Band walks imply trend persistence; squeezes imply potential expansion.' },
  atr: { creator: 'J. Welles Wilder Jr.', era: '1978', math: 'Smoothed average of true range components.', context: 'Volatility unit for risk sizing and adaptive stops.', regime: 'Risk engine input rather than directional signal.' },
  donchian: { creator: 'Richard Donchian', era: '1940s-1950s', math: 'Rolling highest-high and lowest-low channels.', context: 'Classic breakout trend-following framework.', regime: 'Performs in sustained directional moves, whipsaws in compression.' },
  supertrend: { creator: 'Olivier Seban', era: '2009', math: 'ATR envelope with trend-state switching logic.', context: 'Simplifies trend-following and stop-trailing into one overlay.', regime: 'Good in clean trends; combine with structure/ADX in chop.' },
  vortex: { creator: 'Etienne Botes and Douglas Siepman', era: '2010', math: 'Normalized positive/negative movement vectors over rolling true range.', context: 'Detects trend emergence and directional dominance shifts.', regime: 'Improves when paired with volatility and liquidity filters.' },
};

const DRAWING_EDU_HINTS = {
  hline: 'Horizontal levels represent reaction zones. Respect zone width and liquidity sweeps.',
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
  dexSnapshot.threeEnabled = safeGet(LS_3D_EFFECTS) !== '0';
  _restoreChartStateFromLocation();
  ensureXrplLoaded().catch(() => {
    toastWarn('Could not preload xrpl.js. Wallet generation/signing will require network access when used.');
  });

  renderProfilePage();
  renderActiveWalletBar();
  bindProfileEvents();
  _bindDexLiveListeners();
  if (_isProfilePageActive()) refreshXrplDashboard({ silent: true });

  window.addEventListener('naluxrp:pagechange', e => {
    if (e?.detail?.pageId === 'profile') {
      refreshXrplDashboard({ silent: true });
    } else if (_chartAtmosphereRuntime.raf) {
      // The chart atmosphere is a WebGL scene rendering every frame via
      // requestAnimationFrame — switchPage() only hides #profile-page with
      // display:none, it doesn't unmount it, so without this the GPU/CPU
      // work kept running full-tilt for a canvas nobody could see, for as
      // long as the app stayed open on a different page. It remounts fresh
      // (_mountDexWidget/_mountChartAtmosphere) the next time the profile
      // page's DEX chart actually renders.
      _destroyChartAtmosphere();
    }
  });

  document.addEventListener('click', (ev) => {
    const indicatorWrap = document.querySelector('.xpd-indicator-menu-wrap');
    if (indicatorWrap && !indicatorWrap.contains(ev.target) && dexSnapshot.indicatorMenuOpen) {
      dexSnapshot.indicatorMenuOpen = false;
      renderProfilePage();
    }
    const moreWrap = document.querySelector('.xpd-more-menu-wrap');
    if (moreWrap && !moreWrap.contains(ev.target) && dexSnapshot.moreMenuOpen) {
      dexSnapshot.moreMenuOpen = false;
      renderProfilePage();
    }
    if (dexSnapshot.settingsOpenFor) {
      const wrap = document.querySelector('.xpd-indicator-settings')?.closest('.xpd-indicator-chip-wrap');
      if (wrap && !wrap.contains(ev.target)) {
        dexSnapshot.settingsOpenFor = null;
        renderProfilePage();
      }
    }
  });

  // Vault events
  window.addEventListener('naluxrp:vault-ready', () => {
    loadData();
    renderProfilePage();
    renderActiveWalletBar();
    fetchAllBalances();
    refreshXrplDashboard({ silent: true, force: true });
  });
  window.addEventListener('naluxrp:vault-locked', () => {
    renderProfilePage();
    refreshXrplDashboard({ silent: true, force: true });
  });

  // Visibility refresh
  document.addEventListener('visibilitychange', () => {
    if (!_isProfilePageActive()) return;
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

function _restoreChartStateFromLocation() {
  const params = new URLSearchParams(window.location.search);
  const pair = params.get('pair') || '';
  const tf = params.get('tf') || '';
  const token = params.get('token') || safeGet(LS_SELECTED_TOKEN) || '';
  const ind = params.get('ind') || '';
  if (pair && DEX_PAIR_OPTIONS.some(p => p.id === pair)) dexSnapshot.pair = pair;
  if (tf && CHART_INTERVAL_OPTIONS.some(p => p.value === tf)) dexSnapshot.interval = tf;
  if (ind) {
    const enabled = new Set(ind.split(',').map(s => s.trim()).filter(Boolean));
    Object.keys(dexSnapshot.indicators).forEach(k => { dexSnapshot.indicators[k] = enabled.has(k); });
  }
  if (token) {
    dexSnapshot.tokenFocusKey = token;
    tokenDiscoverySnapshot.selectedTokenKey = token;
  }
}

function _persistChartViewState() {
  const params = new URLSearchParams(window.location.search);
  params.set('pair', dexSnapshot.pair || 'BITSTAMP:XRPUSD');
  params.set('tf', dexSnapshot.interval || '15');
  if (dexSnapshot.tokenFocusKey) params.set('token', dexSnapshot.tokenFocusKey);
  else params.delete('token');
  const enabled = Object.entries(dexSnapshot.indicators).filter(([, v]) => !!v).map(([k]) => k).join(',');
  if (enabled) params.set('ind', enabled); else params.delete('ind');
  const newUrl = `${window.location.pathname}?${params.toString()}${window.location.hash || ''}`;
  window.history.replaceState(null, '', newUrl);
  if (dexSnapshot.tokenFocusKey) safeSet(LS_SELECTED_TOKEN, dexSnapshot.tokenFocusKey);
}

function _scrollToChartSection() {
  const el = document.getElementById('xpd-chart-section');
  if (!el) return;
  el.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function _bindDexLiveListeners() {
  if (_dexLiveListenerBound) return;
  _dexLiveListenerBound = true;

  window.addEventListener('xrpl-ledger', () => {
    const now = Date.now();
    if ((now - _lastLedgerDrivenRefresh) < 5000) return;
    _lastLedgerDrivenRefresh = now;
    // state.currentPage, not querySelector — switchPage() only ever hides
    // #profile-page with display:none, it never removes it from the DOM, so
    // once the profile page had been visited once this element is always
    // "found" and this guard did nothing. That meant every ledger close
    // (~3-4s) kept re-fetching the XRPL orderbook price and doing a full
    // renderProfilePage() innerHTML rebuild indefinitely, even while parked
    // on the Dashboard or Inspector tab.
    if (state.currentPage !== 'profile') return;
    if (!document.querySelector('#profile-page .profile-wrap .xrpl-profile-dashboard')) return;

    _enrichWithXrplReference().then(() => {
      const ageMs = Date.now() - _lastXrplSpotAt;
      if (ageMs > 15_000) return;
      // This full-page re-render runs on every live ledger close (~3-4s).
      // Skip it while the user is mid-interaction — typing in a field or
      // has a dropdown open — otherwise the whole page (and their in-
      // progress input/menu) gets yanked out from under them every few
      // seconds. It'll just catch up on the next ledger tick instead.
      const active = document.activeElement;
      const isTyping = active && /^(INPUT|TEXTAREA|SELECT)$/.test(active.tagName);
      if (isTyping || dexSnapshot.moreMenuOpen || dexSnapshot.indicatorMenuOpen) return;
      _dexBarCache.clear();
      renderProfilePage();
    }).catch(() => {});
  });
}

// Was originally a tab-switcher (hide every #profile-tab-* section except
// the active one), from before this page became one continuous scroll —
// renderProfilePage() now unconditionally renders every section on every
// pass (see its direct calls to renderWalletList/renderActivityPanel/
// renderAnalyticsTab/renderSocialList/renderSettingsPanel), so the hide/
// show logic this used to do was already a no-op in practice: any section
// it hid via inline style got reset to visible by the very next re-render
// (renderProfilePage rebuilds .xrpl-profile-dashboard's innerHTML from
// scratch on essentially every user action and every ~3-4s live-ledger
// tick, discarding whatever inline styles were on the old nodes). The two
// real callers of switchProfileTab() — the onboarding checklist's "Connect
// a social account" item, and the post-wallet-creation flow — read as
// "take the user to that section," so give them a section they can
// actually see landing on, instead of a switch that visually did nothing.
export function switchProfileTab(tab) {
  const el = $(`profile-tab-${tab}`);
  if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
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
  dexSnapshot.alerts = safeJson(safeGet(LS_PRICE_ALERTS)) || [];















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
function _saveAlerts()     { safeSet(LS_PRICE_ALERTS, JSON.stringify(dexSnapshot.alerts || [])); }

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

  // This function rebuilds the ENTIRE page via innerHTML on almost every
  // interaction (wallet refreshes, tab switches, the ~5s live-ledger tick,
  // etc.) — including #xpd-tv-widget, the DEX chart's host element. That
  // meant Lightweight Charts' actual canvas got thrown away and a brand new
  // (empty) placeholder took its place every single time, even though
  // _mountDexWidget() still held a reference to the now-orphaned chart
  // object — which is what made the chart appear to disappear and reappear
  // every few seconds. Detach the existing chart host here, before the
  // rebuild, and splice it back into the new markup afterward so
  // _mountDexWidget() can decide whether to actually reuse it (same pair/
  // interval/indicators) or mount fresh into it.
  const previousChartHost = document.getElementById('xpd-tv-widget');
  const canReuseChartHost = !!(previousChartHost && _dexChartRuntime.chart);
  if (previousChartHost) previousChartHost.remove();

  // Same problem, same fix, for the ambient 3D particle background behind
  // the chart (_mountChartAtmosphere) — its host was getting torn down and
  // its whole WebGL scene rebuilt from scratch on every render too, which is
  // heavier and more visually disruptive than the chart rebuild was.
  const previousAtmosphereHost = document.getElementById('xpd-chart-atmosphere');
  const canReuseAtmosphereHost = !!(previousAtmosphereHost && _chartAtmosphereRuntime.renderer);
  if (previousAtmosphereHost) previousAtmosphereHost.remove();

  const wallet = getActiveWallet();
  const address = wallet?.address || '';
  const network = _networkBadge();
  const avatarImg = localStorage.getItem(LS_AVATAR_IMG);
  const hasSigningWallet = wallets.some(w => !w.watchOnly);
  const seedBackedUp = safeGet(LS_SEED_BACKUP_STATUS) === '1';
  const balance = balanceCache[address]?.xrp;
  const portfolioTotalXrp = Object.values(balanceCache).reduce((s, c) => s + (c?.xrp || 0), 0);
  const portfolioUsd = marketSnapshot.data?.priceUsd ? portfolioTotalXrp * marketSnapshot.data.priceUsd : 0;
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
          <a class="xpd-badge" href="https://pikoverse.xyz" target="_blank" rel="noopener">🌐 Part of the Pikoverse ecosystem</a>
          <span class="xpd-badge ${network.kind}">${network.label}</span>
          <span class="xpd-badge security">Local signing only · private keys stay in-browser</span>
          ${address ? `<span class="xpd-badge mono">${address.slice(0, 10)}...${address.slice(-8)}</span>` : '<span class="xpd-badge warn">No active wallet selected</span>'}
          <button class="xpd-action xpd-action--primary" onclick="openWalletCreator()"><span class="xai">＋</span>Add Wallet</button>
          <button class="xpd-action xpd-action--primary" onclick="refreshXrplDashboard()"><span class="xai">⟳</span>Refresh all</button>
          <button class="xpd-action" onclick="jumpToProjectIntelLookup()" title="Jump straight to the project-analysis lookup, further down this page"><span class="xai">🔬</span>Analyze a Project</button>
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
          <div class="xpd-sidebar-snapshot">
            <span class="xpd-sidebar-snapshot-label">Portfolio Snapshot</span>
            <div class="xpd-sidebar-snapshot-row">
              <span>Total XRP</span>
              <strong>${fmt(portfolioTotalXrp, 4)}</strong>
            </div>
            <div class="xpd-sidebar-snapshot-row">
              <span>Est. USD</span>
              <strong>${portfolioUsd ? `$${fmt(portfolioUsd, 2)}` : '—'}</strong>
            </div>
            <div class="xpd-sidebar-snapshot-row">
              <span>Wallets</span>
              <strong>${wallets.length}</strong>
            </div>
          </div>
        </aside>

        <div class="xpd-main-stack">
          <section id="xpd-chart-section" class="xpd-section xpd-section--chart" aria-label="DEX chart">
            <div class="xpd-section-head">
              <h2>XRPL DEX Chart</h2>
              <div class="xpd-chart-toolbar">
                <div class="xpd-toolbar-group">
                  <span class="xpd-toolbar-group-label">Data</span>
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
                </div>
                <div class="xpd-toolbar-group">
                  <span class="xpd-toolbar-group-label">View</span>
                  <button class="xpd-action xpd-action--primary" onclick="refreshDexChart()" title="Refresh"><span class="xai">⟳</span>Refresh</button>
                  <button class="xpd-action xpd-action--icon" onclick="zoomChartIn()" title="Zoom In" aria-label="Zoom In">🔍+</button>
                  <button class="xpd-action xpd-action--icon" onclick="zoomChartOut()" title="Zoom Out" aria-label="Zoom Out">🔍−</button>
                  <button class="xpd-action xpd-action--icon" onclick="panChartLeft()" title="Pan Left" aria-label="Pan Left">←</button>
                  <button class="xpd-action xpd-action--icon" onclick="panChartRight()" title="Pan Right" aria-label="Pan Right">→</button>
                  <button class="xpd-action xpd-action--icon" onclick="resetChartView()" title="Reset View" aria-label="Reset View">⤾</button>
                  <button class="xpd-action xpd-action--icon" onclick="toggleChartFullscreen()" title="Fullscreen" aria-label="Fullscreen">⛶</button>
                </div>
                <div class="xpd-toolbar-group">
                  <span class="xpd-toolbar-group-label">Tools</span>
                  <select class="xpd-input" onchange="setDrawingTool(this.value)">
                    ${DRAW_TOOL_OPTIONS.map(o => `<option value="${o.key}" ${dexSnapshot.drawingTool === o.key ? 'selected' : ''}>Draw: ${o.label}</option>`).join('')}
                  </select>
                  <button class="xpd-action xpd-action--icon" onclick="clearAllDrawings()" title="Clear Lines" aria-label="Clear Lines">🧹</button>
                  <button class="xpd-action xpd-action--icon" onclick="addPriceAlert()" title="Set Price Alert" aria-label="Set Price Alert">🔔</button>
                  ${_renderIndicatorDropdown()}
                  <button class="xpd-action xpd-action--icon" onclick="exportChartPng()" title="Export PNG" aria-label="Export PNG">🖼️</button>
                  <button class="xpd-action xpd-action--icon" onclick="copyChartLink()" title="Copy Chart Link" aria-label="Copy Chart Link">🔗</button>
                </div>
                <div class="xpd-toolbar-group xpd-more-menu-wrap">
                  <button class="xpd-action xpd-action--icon" onclick="event.stopPropagation(); toggleChartMoreMenu()" title="More settings" aria-label="More settings">⋯</button>
                  ${dexSnapshot.moreMenuOpen ? `
                    <div class="xpd-more-menu" role="menu" aria-label="Chart preferences">
                      <button class="xpd-more-menu-item" onclick="toggleThreeEffects()"><span class="xai">🧊</span>${dexSnapshot.threeEnabled ? '3D Background: On' : '3D Background: Off'}</button>
                      <button class="xpd-more-menu-item" onclick="toggleTerminalTheme()"><span class="xai">🌓</span>Toggle Theme</button>
                      <button class="xpd-more-menu-item" onclick="saveChartLayoutPreset()"><span class="xai">💾</span>Save Layout</button>
                      <button class="xpd-more-menu-item" onclick="loadChartLayoutPreset()"><span class="xai">📂</span>Load Layout</button>
                    </div>
                  ` : ''}
                </div>
              </div>
            </div>
            ${_renderDexSection()}
          </section>

          <section class="xpd-section" aria-label="XRPL market data">
            <div class="xpd-section-head">
              <h2>XRPL Market Data</h2>
              <button class="xpd-action" onclick="refreshMarketData()"><span class="xai">⟳</span>Refresh market</button>
            </div>
            ${_renderMarketSection()}
          </section>
        </div>
      </div>

      ${_renderChartEducationPanel()}

      <section class="xpd-section" aria-label="Token discovery and watchlist">
        <div class="xpd-section-head">
          <h2>Token Discovery and Watchlists</h2>
          <button class="xpd-action" onclick="refreshTokenDiscovery()"><span class="xai">⟳</span>Refresh tokens</button>
        </div>
        ${_renderTokenDiscoverySection()}
      </section>

      ${(projectIntelSnapshot.loading || projectIntelSnapshot.error || projectIntelSnapshot.data) ? `
      <section class="xpd-section" aria-label="Project intelligence" id="xpd-project-intel-section">
        ${_renderProjectIntelSection()}
      </section>` : ''}

      <div class="xpd-dual-grid">
        <section class="xpd-section" aria-label="NFT gallery">
          <div class="xpd-section-head">
            <h2>NFT Gallery</h2>
            <button class="xpd-action" onclick="refreshNftGallery()"><span class="xai">⟳</span>Refresh NFTs</button>
          </div>
          ${_renderNftSection(address)}
        </section>

        <section class="xpd-section" aria-label="AMM pools and DEX liquidity">
          <div class="xpd-section-head">
            <h2>AMM, DEX, and Liquidity Pools</h2>
            <button class="xpd-action" onclick="refreshAmmPools()"><span class="xai">⟳</span>Refresh pools</button>
          </div>
          ${_renderAmmSection(address)}
        </section>
      </div>

      <section class="xpd-section" aria-label="Portfolio and recent transactions">
        <div class="xpd-section-head">
          <h2>Portfolio and Recent Transactions</h2>
          <button class="xpd-action" onclick="refreshRecentTransactions()"><span class="xai">⟳</span>Refresh tx</button>
        </div>
        ${_renderPortfolioAndTxSection(address)}
      </section>

      <section class="xpd-section" aria-label="Activity and analytics">
        <div class="xpd-section-head">
          <h2>Activity &amp; Analytics</h2>
        </div>
        <div id="profile-tab-activity"></div>
        <div id="profile-tab-analytics" style="margin-top:16px"></div>
      </section>

      <section class="xpd-section" aria-label="Social and community links">
        <div class="xpd-section-head">
          <h2>Social &amp; Community Links</h2>
        </div>
        <div id="profile-tab-social"></div>
      </section>

      <section class="xpd-section" aria-label="Preferences and settings">
        <div class="xpd-section-head">
          <h2>Preferences &amp; Settings</h2>
        </div>
        <div id="profile-tab-settings"></div>
      </section>
    </div>`;

  if (canReuseChartHost) {
    const freshPlaceholder = document.getElementById('xpd-tv-widget');
    if (freshPlaceholder) freshPlaceholder.replaceWith(previousChartHost);
  }
  if (canReuseAtmosphereHost) {
    const freshAtmospherePlaceholder = document.getElementById('xpd-chart-atmosphere');
    if (freshAtmospherePlaceholder) freshAtmospherePlaceholder.replaceWith(previousAtmosphereHost);
  }

  _mountDexWidget();
  renderActivityPanel();
  renderAnalyticsTab();
  renderSocialList();
  renderSettingsPanel();
}

function _networkBadge() {
  const key = String(state.currentNetwork || '').toLowerCase();
  if (key.includes('testnet')) return { label: 'XRPL Testnet', kind: 'testnet' };
  if (key.includes('mainnet')) return { label: 'XRPL Mainnet', kind: 'mainnet' };
  if (key.includes('xahau')) return { label: 'Xahau Network', kind: 'xahau' };
  return { label: `Network: ${escHtml(state.currentNetwork || 'Unknown')}`, kind: 'unknown' };
}

function _renderIndicatorDropdown() {
  const q = String(dexSnapshot.indicatorQuery || '').trim().toLowerCase();
  const groups = [
    { key: 'trend', label: 'Trend', icon: '📈' },
    { key: 'momentum', label: 'Momentum', icon: '⚡' },
    { key: 'volume', label: 'Volume', icon: '📊' },
    { key: 'volatility', label: 'Volatility', icon: '🌪️' },
    { key: 'advanced', label: 'Custom', icon: '🧠' },
  ];
  return `
    <div class="xpd-indicator-menu-wrap">
      <button class="xpd-action xpd-action--add" onclick="event.stopPropagation(); toggleIndicatorMenu()">+ Indicator</button>
      ${dexSnapshot.indicatorMenuOpen ? `
        <div class="xpd-indicator-menu" role="menu" aria-label="Indicator menu">
          <input class="xpd-input xpd-indicator-search" placeholder="Search indicators..." value="${escHtml(dexSnapshot.indicatorQuery || '')}" oninput="setIndicatorQuery(this.value)" />
          ${groups.map(group => {
            const keys = (INDICATOR_GROUPS[group.key] || []).filter(k => {
              if (!q) return true;
              const nm = (INDICATOR_META[k]?.name || k).toLowerCase();
              return nm.includes(q);
            });
            if (!keys.length) return '';
            return `
              <details class="xpd-indicator-group" open>
                <summary>${group.icon} ${group.label}</summary>
                <div class="xpd-indicator-items">
                  ${keys.map(k => `<button class="xpd-indicator-item" title="${escHtml(INDICATOR_META[k]?.what || '')}" onclick="addIndicatorFromMenu('${k}')">${escHtml(INDICATOR_META[k]?.name || k)}</button>`).join('')}
                </div>
              </details>`;
          }).join('')}
        </div>
      ` : ''}
    </div>`;
}

function _renderDexSection() {
  const stats = dexSnapshot.stats;
  const online = state.wsConn?.readyState === 1;
  const chartMeta = dexSnapshot.chartMeta || {};
  const activeIndicators = Object.entries(dexSnapshot.indicators).filter(([, enabled]) => !!enabled).map(([k]) => k);
  const focusRaw = String(dexSnapshot.tokenFocusKey || '');
  const focusSymbol = focusRaw.includes('|') ? focusRaw.split('|')[0] : focusRaw;
  const focusedToken = tokenDiscoverySnapshot.tokens.find(t => _tokenKey(t) === focusRaw)
    || tokenDiscoverySnapshot.tokens.find(t => String(t.symbol || '').toUpperCase() === String(focusSymbol || '').toUpperCase())
    || null;
  const isFocusedNonXrp = !!focusedToken && String(focusedToken.symbol || '').toUpperCase() !== 'XRP' && Number.isFinite(Number(focusedToken.price || 0));
  const displayPrice = Number.isFinite(Number(chartMeta.last)) ? Number(chartMeta.last) : (isFocusedNonXrp ? Number(focusedToken.price || 0) : stats?.price);
  const displayHigh = Number.isFinite(Number(chartMeta.high)) ? Number(chartMeta.high) : stats?.high;
  const displayLow = Number.isFinite(Number(chartMeta.low)) ? Number(chartMeta.low) : stats?.low;
  // Falls back to chartMeta.symbol (whichever DEX pair is actually selected —
  // BTC, ETH, SOL, …), not a hardcoded 'XRP'. This header used to claim
  // "Active Chart Token: XRP" even while looking at the BTC/USD chart, since
  // it had its own separate fallback that never accounted for the non-XRP
  // pair options.
  const activeTokenLabel = focusedToken
    ? `${String(focusedToken.symbol || '').toUpperCase()}${focusedToken.issuer ? ` · ${focusedToken.issuer.slice(0, 10)}...` : ''}`
    : String(chartMeta.symbol || 'XRP').toUpperCase();
  const sourceLabel = String(chartMeta.source || (isFocusedNonXrp ? 'Coinbase + token proxy' : (stats?.source || 'Source pending')));
  return `
    ${dexSnapshot.error ? `<div class="xpd-error">${escHtml(dexSnapshot.error)}</div>` : ''}
    <div class="xpd-chart-stats">
      <div class="xpd-pill" title="Current price">${displayPrice != null ? `$${fmt(displayPrice, isFocusedNonXrp ? 6 : 4)}` : 'Price —'}</div>
      <div class="xpd-pill" title="24h change">${stats?.changePct != null ? `${stats.changePct >= 0 ? '+' : ''}${fmt(stats.changePct, 2)}%` : '24h —'}</div>
      <div class="xpd-pill" title="24h high">${displayHigh != null ? `High $${fmt(displayHigh, isFocusedNonXrp ? 6 : 4)}` : 'High —'}</div>
      <div class="xpd-pill" title="24h low">${displayLow != null ? `Low $${fmt(displayLow, isFocusedNonXrp ? 6 : 4)}` : 'Low —'}</div>
      <div class="xpd-pill" title="XRPL orderbook spot">${isFocusedNonXrp ? `Token Spot $${fmt(Number(focusedToken?.price || 0), 6)}` : (stats?.xrplSpot != null ? `XRPL Spot $${fmt(stats.xrplSpot, 4)}` : 'XRPL Spot —')}</div>
      <div class="xpd-pill" title="Streaming status">${online ? '● Live stream connected' : '● Stream offline'}</div>
      ${focusedToken ? `<div class="xpd-pill" title="Token focus">Token Focus: ${escHtml(focusedToken.symbol)} ${focusedToken.price != null ? `($${fmt(focusedToken.price, 6)})` : ''}</div>` : ''}
    </div>
    <div class="xpd-indicator-row">
      ${activeIndicators.length ? activeIndicators.map(k => `<div class="xpd-indicator-chip-wrap"><div class="xpd-indicator-chip" title="${escHtml(INDICATOR_META[k]?.what || '')}"><span>${escHtml(INDICATOR_META[k]?.name || k)}</span><button class="xpd-mini-btn" onclick="event.stopPropagation(); openIndicatorSettings('${k}')">⚙</button><button class="xpd-mini-btn" onclick="removeIndicator('${k}')">✕</button></div>${_renderIndicatorSettingsPopover(k)}</div>`).join('') : '<span class="xpd-empty">No indicators enabled. Use + Indicator.</span>'}
    </div>
    ${(() => {
      const scopeKey = _alertScopeKey();
      const scoped = (dexSnapshot.alerts || []).filter(a => a.tokenKey === scopeKey);
      if (!scoped.length) return '';
      return `
      <div class="xpd-indicator-row">
        ${scoped.map(a => `
          <div class="xpd-indicator-chip" data-alert-id="${escHtml(a.id)}" title="Notify when price crosses $${fmt(a.price, 6)}">
            <span>🔔 $${fmt(a.price, 6)}</span>
            <button class="xpd-mini-btn" onclick="removePriceAlert('${a.id}')">✕</button>
          </div>`).join('')}
      </div>`;
    })()}
    ${dexSnapshot.educationHint ? `<div class="xpd-note">${escHtml(dexSnapshot.educationHint)}</div>` : ''}
    <div class="xpd-chart-wrap">
      <div class="xpd-chart-active-head">
        <div class="xpd-chart-active-left">
          <span class="xpd-chart-active-label">Active Chart Token</span>
          <strong class="xpd-chart-active-token" title="${escHtml(activeTokenLabel)}">${escHtml(activeTokenLabel)}</strong>
        </div>
        <div class="xpd-chart-active-right">
          <span class="xpd-chart-active-chip">Mode: ${escHtml(chartMeta.mode || 'pair')}</span>
          <span class="xpd-chart-active-chip" title="${escHtml(sourceLabel)}">Source: ${escHtml(sourceLabel)}</span>
        </div>
      </div>
      <div id="xpd-chart-atmosphere" class="xpd-chart-atmosphere" aria-hidden="true"></div>
      <div id="xpd-tv-widget" class="xpd-tv-widget"></div>
    </div>
    <p class="xpd-note">Professional chart controls: wheel zoom, hold-and-drag pan, horizontal price-line marking, and token-focused context ribbons for faster execution decisions.</p>`;
}

function _renderChartEducationPanel() {
  const key = dexSnapshot.selectedIndicator || 'sma20';
  const meta = INDICATOR_META[key] || INDICATOR_META.sma20;
  const deep = INDICATOR_DEEP_INTEL[key] || null;
  const collapsed = dexSnapshot.educationCollapsed;
  return `
    <div class="xpd-edu-panel ${collapsed ? 'collapsed' : ''}">
      <div class="xpd-edu-head">
        <h3>Indicator Intelligence and Bias Control</h3>
        <button class="xpd-mini-btn" onclick="toggleEducationPanel()">${collapsed ? 'Expand' : 'Collapse'}</button>
      </div>
      ${collapsed ? '' : `
        <div class="xpd-edu-tabs">
          <button class="xpd-mini-btn ${dexSnapshot.selectedEducationTab === 'indicator' ? 'active' : ''}" onclick="selectEducationTab('indicator')">Indicator Guide</button>
          <button class="xpd-mini-btn ${dexSnapshot.selectedEducationTab === 'psychology' ? 'active' : ''}" onclick="selectEducationTab('psychology')">Trading Psychology</button>
          <button class="xpd-mini-btn ${dexSnapshot.selectedEducationTab === 'practice' ? 'active' : ''}" onclick="selectEducationTab('practice')">Best Practices</button>
        </div>
        ${dexSnapshot.selectedEducationTab === 'indicator' ? `
          <div class="xpd-edu-content">
            <h4 class="xpd-edu-title">${escHtml(meta.name)}</h4>
            ${_eduRow('What it measures', meta.what)}
            ${_eduRow('Original purpose', meta.purpose)}
            ${_eduRow('How to apply', meta.apply)}
            ${_eduRow('Common mistake', meta.mistake)}
            ${_eduRow('Bias reduction tip', meta.bias)}
            ${deep ? `
              ${_eduRow('Created by / Era', `${deep.creator} · ${deep.era}`)}
              ${_eduRow('Core math', deep.math)}
              ${_eduRow('Historical context', deep.context)}
              ${_eduRow('Best market regime', deep.regime)}
            ` : ''}
          </div>
        ` : ''}
        ${dexSnapshot.selectedEducationTab === 'psychology' ? `
          <div class="xpd-edu-content">
            ${_eduRow('Confirmation Bias', 'Require at least two independent signals before entering.')}
            ${_eduRow('Anchoring', 'Do not anchor to entry price; respect invalidation and current structure.')}
            ${_eduRow('Overfitting', 'More indicators is not better; build a repeatable checklist.')}
            ${_eduRow('Risk Discipline', 'Position size by volatility and stop distance, not conviction.')}
          </div>
        ` : ''}
        ${dexSnapshot.selectedEducationTab === 'practice' ? `
          <ol class="xpd-edu-steps">
            <li>Start with trend context (higher timeframe).</li>
            <li>Add one momentum and one volatility indicator.</li>
            <li>Mark levels with drawings before taking a trade.</li>
            <li>Define entry, invalidation, and target before execution.</li>
            <li>Journal whether setup matched your rules.</li>
          </ol>
        ` : ''}
      `}
    </div>`;
}

function _eduRow(label, value) {
  return `<div class="xpd-edu-row"><span class="xpd-edu-label">${escHtml(label)}</span><span class="xpd-edu-value">${escHtml(value)}</span></div>`;
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
  // .filtered is always _filterTokens(query, tokens) — kept in sync on every
  // assignment to .tokens — so it's already "all tokens" when there's no
  // active search/filter. Falling back to .tokens whenever .filtered was
  // merely empty meant a search or filter combo that genuinely matched
  // nothing silently showed the entire unfiltered registry instead of a
  // "no results" state — actively misleading, not just a missing empty state.
  const list = tokenDiscoverySnapshot.filtered;
  const limit = Math.max(120, Number(tokenDiscoverySnapshot.listLimit || 240));
  const top = list.slice(0, limit);
  const trending = tokenDiscoverySnapshot.trending.slice(0, 14);
  const tokenByKey = new Map(tokenDiscoverySnapshot.tokens.map(t => [_tokenKey(t), t]));
  const selected = tokenByKey.get(tokenDiscoverySnapshot.selectedTokenKey) || null;
  const f = tokenDiscoverySnapshot.filters || { type: 'all', minCap: 0, minVol: 0, hasDex: false };

  return `
    <div class="xpd-token-grid">
      <div class="xpd-token-col">
        <div class="xpd-search-row">
          <input class="xpd-input" list="xpd-token-suggest" placeholder="Search symbol, token, issuer" value="${escHtml(q)}" oninput="searchTokens(this.value)" />
          <datalist id="xpd-token-suggest">${tokenDiscoverySnapshot.tokens.slice(0, 80).map(t => `<option value="${escHtml(t.symbol)}">${escHtml(t.name)}</option>`).join('')}</datalist>
          <div class="xpd-note">Loaded ${_fmtCompact(tokenDiscoverySnapshot.total || list.length)} issued tokens · showing ${_fmtCompact(top.length)} of ${_fmtCompact(list.length)}${tokenDiscoverySnapshot.lastSyncAt ? ` · synced ${new Date(tokenDiscoverySnapshot.lastSyncAt).toLocaleTimeString()}` : ''}</div>
          <div class="xpd-lookup-row" title="The search box above only finds tokens already in the loaded registry — use this to chart any XRPL issued currency directly by its currency code and issuer address.">
            <span class="xpd-lookup-label">Look up any issued asset</span>
            <div class="xpd-lookup-fields">
              <input id="xpd-lookup-currency" class="xpd-input" placeholder="Currency (e.g. SOLO)" maxlength="20" />
              <input id="xpd-lookup-issuer" class="xpd-input mono" placeholder="Issuer address (r...)" />
              <button class="xpd-action xpd-action--primary" onclick="lookupIssuedAsset()"><span class="xai">🔎</span>Load</button>
              <button class="xpd-action" onclick="lookupAndAnalyzeProject()" title="Loads the token and jumps straight to its Project Strength dashboard"><span class="xai">🔬</span>Analyze Project</button>
            </div>
          </div>
          <div class="xpd-token-filters">
            <select class="xpd-input" onchange="setTokenFilter('type', this.value)">
              <option value="all" ${f.type === 'all' ? 'selected' : ''}>All Types</option>
              <option value="standard" ${f.type === 'standard' ? 'selected' : ''}>Standard</option>
              <option value="mpt" ${f.type === 'mpt' ? 'selected' : ''}>MPT</option>
              <option value="stablecoin" ${f.type === 'stablecoin' ? 'selected' : ''}>Stablecoin</option>
              <option value="meme" ${f.type === 'meme' ? 'selected' : ''}>Meme</option>
            </select>
            <select class="xpd-input" onchange="setTokenFilter('minCap', Number(this.value))">
              <option value="0" ${Number(f.minCap) === 0 ? 'selected' : ''}>Any Market Cap</option>
              <option value="1000000" ${Number(f.minCap) === 1000000 ? 'selected' : ''}>Cap > $1M</option>
              <option value="10000000" ${Number(f.minCap) === 10000000 ? 'selected' : ''}>Cap > $10M</option>
              <option value="100000000" ${Number(f.minCap) === 100000000 ? 'selected' : ''}>Cap > $100M</option>
            </select>
            <select class="xpd-input" onchange="setTokenFilter('minVol', Number(this.value))">
              <option value="0" ${Number(f.minVol) === 0 ? 'selected' : ''}>Any 24h Volume</option>
              <option value="10000" ${Number(f.minVol) === 10000 ? 'selected' : ''}>Vol > $10k</option>
              <option value="100000" ${Number(f.minVol) === 100000 ? 'selected' : ''}>Vol > $100k</option>
              <option value="1000000" ${Number(f.minVol) === 1000000 ? 'selected' : ''}>Vol > $1M</option>
            </select>
            <label><input type="checkbox" ${f.hasDex ? 'checked' : ''} onchange="setTokenFilter('hasDex', this.checked)"/> Has active DEX</label>
          </div>
          ${list.length > top.length ? `<div class="xpd-row-actions"><button class="xpd-mini-btn" onclick="showMoreIssuedTokens()">Show More</button><button class="xpd-mini-btn" onclick="showAllIssuedTokens()">Show All</button><button class="xpd-mini-btn" onclick="resetIssuedTokenLimit()">Reset</button></div>` : ''}
        </div>
        ${tokenDiscoverySnapshot.loading ? '<div class="xpd-loading">Loading XRPL issued token registry...</div>' : ''}
        ${tokenDiscoverySnapshot.error ? `<div class="xpd-error">${escHtml(tokenDiscoverySnapshot.error)}</div>` : ''}
        ${(!top.length && !tokenDiscoverySnapshot.loading) ? `<div class="xpd-empty">No tokens match${q ? ` "${escHtml(q)}"` : ' the current filters'}. <button class="xpd-mini-btn" onclick="clearTokenFilters()">Clear search & filters</button></div>` : ''}
        <div class="xpd-token-list">${top.map(t => {
          const key = _tokenKey(t);
          const safeKey = _encodeForInlineHandler(key);
          const qh = String(q || '').trim();
          return `
          <div class="xpd-token-row xpd-token-row--clickable" title="${escHtml(`${t.symbol} ${t.name}`)}" onclick="openTokenOnChart(decodeURIComponent('${safeKey}'))">
            <div class="xpd-token-main">
              <strong>${_highlightMatch(t.symbol, qh)}</strong>
              <span>${_highlightMatch(t.name, qh)}</span>
              ${t.issuer ? `<span class="mono xpd-pill-text">${escHtml(t.issuer)}</span>` : ''}
            </div>
            <div class="xpd-token-actions">
              <span>${t.price != null ? `$${fmt(t.price, 6)}` : '—'}</span>
              ${Number.isFinite(t.holders) ? `<span title="Holders">${_fmtCompact(t.holders)} holders</span>` : ''}
              <button class="xpd-mini-btn" onclick="event.stopPropagation(); addTokenToWatchlist(decodeURIComponent('${safeKey}'))">Watch</button>
              <button class="xpd-mini-btn" onclick="event.stopPropagation(); openTokenOnChart(decodeURIComponent('${safeKey}'))">Chart</button>
              <button class="xpd-mini-btn" onclick="event.stopPropagation(); selectTokenDetails(decodeURIComponent('${safeKey}'))">Details</button>
              ${t.issuer ? `<button class="xpd-mini-btn xpd-mini-btn--accent" onclick="event.stopPropagation(); openProjectIntel(decodeURIComponent('${safeKey}'))" title="Project Strength — liquidity depth, holder/LP concentration, issuer risk">🔬 Strength</button>` : ''}
            </div>
          </div>`;
        }).join('')}</div>
      </div>
      <div class="xpd-token-col">
        ${selected ? `<div class="xpd-token-detail-card">
          <h3>${escHtml(selected.symbol)} · ${escHtml(selected.name)}</h3>
          <div class="pool-meta">Issuer: <span class="mono">${escHtml(selected.issuer || 'Native XRP')}</span></div>
          <div class="pool-meta">Token ID: <span class="mono">${escHtml(selected.tokenId || '—')}</span></div>
          <div class="pool-meta">Price: ${selected.price != null ? `$${fmt(selected.price, 6)}` : '—'} · 24h Vol: ${selected.volume24h != null ? `$${_fmtCompact(selected.volume24h)}` : '—'}</div>
          <div class="pool-meta">Market Cap: ${selected.marketCap != null ? `$${_fmtCompact(selected.marketCap)}` : '—'} · Holders: ${selected.holders != null ? _fmtCompact(selected.holders) : '—'}</div>
          <div class="xpd-row-actions">
            <button class="xpd-mini-btn" onclick="openTokenOnChart(decodeURIComponent('${_encodeForInlineHandler(_tokenKey(selected))}'))">Switch Main Chart</button>
            ${selected.issuer ? `<button class="xpd-mini-btn" onclick="window.open('https://xrpscan.com/account/${escHtml(selected.issuer)}','_blank')">View Issuer</button>` : ''}
            ${selected.issuer ? `<button class="xpd-mini-btn xpd-mini-btn--accent" onclick="openProjectIntel(decodeURIComponent('${_encodeForInlineHandler(_tokenKey(selected))}'))">🔬 Project Strength</button>` : ''}
          </div>
        </div>` : ''}
        <h3>Watchlist</h3>
        <div class="xpd-watchlist">${watch.length ? watch.map(key => {
          const t = _resolveWatchToken(key, tokenByKey);
          const label = t ? `${t.symbol} · ${t.name}` : key;
          const px = t?.price != null ? `$${fmt(t.price, 6)}` : '—';
          const safeKey = _encodeForInlineHandler(key);
          return `<div class="xpd-token-row xpd-token-row--clickable" onclick="openTokenOnChart(decodeURIComponent('${safeKey}'))"><span>${escHtml(label)}</span><div class="xpd-token-actions"><span>${px}</span><button class="xpd-mini-btn" onclick="event.stopPropagation(); openTokenOnChart(decodeURIComponent('${safeKey}'))">Chart</button><button class="xpd-mini-btn" onclick="event.stopPropagation(); removeTokenFromWatchlist(decodeURIComponent('${safeKey}'))">Remove</button></div></div>`;
        }).join('') : '<div class="xpd-empty">No watchlist tokens yet.</div>'}</div>
        <h3>Trending</h3>
        <div class="xpd-watchlist">${trending.length ? trending.map(t => `<div class="xpd-token-row xpd-token-row--clickable" onclick="openTokenOnChart(decodeURIComponent('${_encodeForInlineHandler(_tokenKey(t))}'))"><span>${escHtml(t.symbol)} · ${escHtml(t.name)}</span><span>${t.volume24h != null ? `$${_fmtCompact(t.volume24h)} vol` : (t.marketCap != null ? `$${_fmtCompact(t.marketCap)} mcap` : '—')}</span></div>`).join('') : '<div class="xpd-empty">No trending data.</div>'}</div>
      </div>
    </div>`;
}

/* ═══════════════════════════════════════════════════
   Project Intelligence — token/project-level dashboard.
   Distinct from the account-level Inspector: given a {symbol, issuer}
   token, computes AMM liquidity, DEX depth/price-impact, holder and LP
   concentration, and issuer risk flags, rolled into an inspectable
   composite score. All fetching/scoring logic lives in project-intel.js —
   this is the render + interaction layer only.
═══════════════════════════════════════════════════ */
/** Header-level shortcut so reaching Project Intelligence doesn't require
 *  scrolling down to Token Discovery and finding the lookup fields first —
 *  this jumps straight there and focuses the currency input. */
export function jumpToProjectIntelLookup() {
  const el = document.getElementById('xpd-lookup-currency');
  if (!el) { toastWarn('Token Discovery hasn\'t loaded yet — give it a moment and try again.'); return; }
  el.scrollIntoView({ behavior: 'smooth', block: 'center' });
  setTimeout(() => el.focus(), 350);
}

export async function openProjectIntel(tokenKeyOrSymbol) {
  const raw = String(tokenKeyOrSymbol || '').trim();
  if (!raw) return;
  const resolved = raw.includes('|')
    ? tokenDiscoverySnapshot.tokens.find(t => _tokenKey(t) === raw)
    : tokenDiscoverySnapshot.tokens.find(t => String(t.symbol || '').toUpperCase() === raw.toUpperCase());
  if (!resolved?.issuer) {
    toastWarn('Project Intelligence needs a token with a known issuer.');
    return;
  }
  projectIntelSnapshot = { loading: true, error: '', data: null, tokenKey: _tokenKey(resolved), expandedSubScore: '' };
  renderProfilePage();
  setTimeout(() => document.getElementById('xpd-project-intel-section')?.scrollIntoView({ behavior: 'smooth', block: 'start' }), 30);

  try {
    const data = await fetchProjectIntel(resolved);
    projectIntelSnapshot = { loading: false, error: '', data, tokenKey: _tokenKey(resolved), expandedSubScore: '' };
  } catch (err) {
    projectIntelSnapshot = { loading: false, error: err?.message || 'Could not load project intelligence.', data: null, tokenKey: _tokenKey(resolved), expandedSubScore: '' };
  }
  renderProfilePage();
}

export function toggleProjectIntelSubScore(key) {
  projectIntelSnapshot.expandedSubScore = projectIntelSnapshot.expandedSubScore === key ? '' : key;
  renderProfilePage();
}

export function closeProjectIntel() {
  projectIntelSnapshot = { loading: false, error: '', data: null, tokenKey: '', expandedSubScore: '' };
  renderProfilePage();
}

const PI_SUBSCORE_META = {
  liquidity:     { label: 'Liquidity',     icon: '💧' },
  distribution:  { label: 'Distribution',  icon: '🧮' },
  marketQuality: { label: 'Market Quality',icon: '📊' },
  lpStability:   { label: 'LP Stability',  icon: '🏦' },
  issuerRisk:    { label: 'Issuer Risk',   icon: '🛡' },
};

function _piScoreColor(score) {
  return score >= 75 ? '#50fa7b' : score >= 50 ? '#f1fa8c' : score >= 25 ? '#ffb86c' : '#ff5555';
}

function _piScoreWord(score) {
  return score >= 75 ? 'STRONG' : score >= 50 ? 'MODERATE' : score >= 25 ? 'WEAK' : 'VERY WEAK';
}

function _renderProjectIntelSection() {
  if (projectIntelSnapshot.loading) {
    return `<div class="xpd-section-head"><h2>🔬 Project Intelligence</h2></div>
      <div class="xpd-loading">Fetching AMM state, order-book depth, holder and LP concentration, and issuer flags…</div>`;
  }
  if (projectIntelSnapshot.error) {
    return `<div class="xpd-section-head"><h2>🔬 Project Intelligence</h2>
      <button class="xpd-action" onclick="closeProjectIntel()">✕ Close</button></div>
      <div class="xpd-error">${escHtml(projectIntelSnapshot.error)}</div>`;
  }
  const d = projectIntelSnapshot.data;
  if (!d) return '';

  const s = d.strength;
  const overallColor = _piScoreColor(s.overall);

  const subScoreBars = s.dimensionsLive.map(key => {
    const meta = PI_SUBSCORE_META[key];
    const sub = s.subScores[key];
    const expanded = projectIntelSnapshot.expandedSubScore === key;
    return `
      <div class="pi-subscore ${expanded ? 'pi-subscore--open' : ''}" onclick="toggleProjectIntelSubScore('${key}')">
        <div class="pi-subscore-row">
          <span class="pi-subscore-label">${meta.icon} ${meta.label}</span>
          <span class="pi-subscore-val" style="color:${_piScoreColor(sub.score)}">${sub.score}</span>
        </div>
        <div class="pi-subscore-bar"><div class="pi-subscore-fill" style="width:${sub.score}%;background:${_piScoreColor(sub.score)}"></div></div>
        ${expanded ? `<div class="pi-subscore-detail">${Object.entries(sub.inputs).map(([k, v]) => `
          <div class="pi-kv"><span>${escHtml(_piHumanizeKey(k))}</span><span class="mono">${escHtml(_piFmtVal(v))}</span></div>
        `).join('')}</div>` : ''}
      </div>`;
  }).join('');

  return `
    <div class="xpd-section-head">
      <h2>🔬 Project Intelligence — ${escHtml(d.token.symbol)}</h2>
      <div class="xpd-section-head-actions">
        <button class="xpd-action" onclick="copyProjectIntelForAi()" title="Copy every metric on this page as plain text, ready to paste into ChatGPT, Claude, or any model you use">📋 Copy for AI</button>
        <button class="xpd-action" onclick="closeProjectIntel()">✕ Close</button>
      </div>
    </div>
    <div class="pi-methodology-note">
      Under this app's own methodology, ${escHtml(d.token.symbol)}'s measurable on-ledger structure currently scores as shown below.
      This is not investment advice, and a high score is not a claim that this is a good investment — it reflects only the
      five dimensions computable from a live snapshot (Liquidity, Distribution, Market Quality, LP Stability, Issuer Risk).
      Network Activity, Treasury Health, and Project Transparency need historical tracking this app doesn't yet do, and are
      not included. Click any dimension below to see exactly what it's computed from.
    </div>
    <div class="pi-header-card">
      <div class="pi-score-big" style="color:${overallColor}">${s.overall}<span class="pi-score-max">/100</span></div>
      <div class="pi-score-word" style="color:${overallColor}">${_piScoreWord(s.overall)}</div>
      <div class="pi-issuer-line mono">Issuer: ${escHtml(d.token.issuer)}</div>
    </div>
    <div class="pi-subscore-grid">${subScoreBars}</div>

    <div class="pi-cards-grid">
      ${_renderPiLiquidityCard(d)}
      ${_renderPiHoldersCard('Holder Concentration', d.holders, '👥')}
      ${_renderPiHoldersCard('LP Token Concentration', d.lp, '🏦')}
      ${_renderPiIssuerCard(d.issuerRisk)}
    </div>`;
}

function _piHumanizeKey(k) {
  return k.replace(/([A-Z])/g, ' $1').replace(/^./, c => c.toUpperCase()).trim();
}
function _piFmtVal(v) {
  if (v == null) return '—';
  if (typeof v === 'boolean') return v ? 'Yes' : 'No';
  if (typeof v === 'number') return Number.isInteger(v) ? String(v) : fmt(v, 2);
  return String(v);
}

function _renderPiLiquidityCard(d) {
  const amm = d.amm, ob = d.orderBook;
  const ammBlock = amm?.exists ? `
    <div class="pi-kv"><span>XRP reserve</span><span class="mono">${fmt(amm.xrpReserve, 2)} XRP</span></div>
    <div class="pi-kv"><span>Token reserve</span><span class="mono">${fmt(amm.tokenReserve, 2)}</span></div>
    <div class="pi-kv"><span>LP token supply</span><span class="mono">${fmt(amm.lpSupply, 2)}</span></div>
    <div class="pi-kv"><span>Trading fee</span><span class="mono">${fmt(amm.tradingFeePct, 3)}%</span></div>
    ${amm.auctionSlot ? `<div class="pi-kv"><span>Auction slot discount</span><span class="mono">${fmt(amm.auctionSlot.discountedFeePct, 3)}%</span></div>` : ''}
    ${amm.voteSlots?.length ? `<div class="pi-kv"><span>Fee-vote participants</span><span class="mono">${amm.voteSlots.length}</span></div>` : ''}
  ` : `<div class="inspect-empty-note">No AMM pool found for this pair.</div>`;

  const depthRows = (levels, label) => levels?.length ? `
    <div class="pi-depth-title">${label}</div>
    <table class="pi-depth-table"><thead><tr><th>Impact</th><th>XRP</th><th>Tokens</th></tr></thead><tbody>
    ${levels.map(l => `<tr><td>${l.pct}%</td><td class="mono">${fmt(l.xrpAtOffer, 1)}</td><td class="mono">${_fmtCompact(l.tokenAtOffer)}${l.bookExhausted ? ' <span title="Visible order book fully consumed before reaching this price-impact level — real depth may be less than shown, book is thin.">⚠</span>' : ''}</td></tr>`).join('')}
    </tbody></table>` : '';

  const obBlock = ob?.exists ? `
    <div class="pi-kv"><span>Buy price</span><span class="mono">${fmt(ob.buyPriceXrp, 6)} XRP</span></div>
    <div class="pi-kv"><span>Sell price</span><span class="mono">${fmt(ob.sellPriceXrp, 6)} XRP</span></div>
    <div class="pi-kv"><span>Spread</span><span class="mono">${ob.spreadPct != null ? fmt(ob.spreadPct, 2) + '%' : '—'}</span></div>
    ${depthRows(ob.buyDepth, 'DEX Depth — buying with XRP')}
    ${depthRows(ob.sellDepth, 'DEX Depth — selling for XRP')}
  ` : `<div class="inspect-empty-note">No live order book found for this pair.</div>`;

  return `
    <div class="sec-card pi-card">
      <div class="sec-card-hdr"><span class="sec-card-icon">💧</span><div><div class="sec-card-title">Liquidity Intelligence</div><div class="sec-card-sub">AMM pool + real DEX depth, not just TVL</div></div></div>
      ${ammBlock}
      <hr class="pi-hr" />
      ${obBlock}
    </div>`;
}

function _renderPiHoldersCard(title, hd, icon) {
  if (!hd?.exists) return `
    <div class="sec-card pi-card">
      <div class="sec-card-hdr"><span class="sec-card-icon">${icon}</span><div><div class="sec-card-title">${escHtml(title)}</div></div></div>
      <div class="inspect-empty-note">No holder data found.</div>
    </div>`;
  const rows = (hd.topHolders || []).slice(0, 8).map((h, i) => `
    <div class="pi-holder-row">
      <span class="pi-holder-rank">${i + 1}</span>
      <a href="https://xrpscan.com/account/${escHtml(h.address)}" target="_blank" rel="noopener" class="mono pi-holder-addr">${escHtml(h.address.slice(0, 8))}…${escHtml(h.address.slice(-5))}</a>
      <span class="mono">${_fmtCompact(h.balance)}</span>
      <span class="mono pi-holder-pct">${hd.totalSampled > 0 ? fmt(h.balance / hd.totalSampled * 100, 1) : '0.0'}%</span>
    </div>`).join('');
  return `
    <div class="sec-card pi-card">
      <div class="sec-card-hdr"><span class="sec-card-icon">${icon}</span><div><div class="sec-card-title">${escHtml(title)}</div><div class="sec-card-sub">${_fmtCompact(hd.holderCount)} holders${hd.sampleOnly ? ' (sampled, capped)' : ''}</div></div></div>
      <div class="pi-kv"><span>Top 1</span><span class="mono">${fmt(hd.top1Pct, 1)}%</span></div>
      <div class="pi-kv"><span>Top 5</span><span class="mono">${fmt(hd.top5Pct, 1)}%</span></div>
      <div class="pi-kv"><span>Top 10</span><span class="mono">${fmt(hd.top10Pct, 1)}%</span></div>
      <hr class="pi-hr" />
      ${rows}
    </div>`;
}

export const PI_ISSUER_EXPLANATIONS = {
  clawbackEnabled: 'The issuer has the technical capability to reclaim issued balances under XRPL\'s clawback mechanism. Consider the project\'s stated policy and use case.',
  globalFreeze: 'The issuer has currently frozen all trustlines for this currency — holders cannot move balances until it\'s lifted.',
  freezeCapable: 'The issuer retains the ability to freeze individual trustlines. Common and not inherently malicious, but a real capability worth knowing about.',
  requireAuth: 'The issuer must approve each trustline before it can hold a balance — restricts who can hold this token.',
  blackholed: 'The issuer has permanently disabled its master key and holds no regular key — issuer-side control of the account is no longer possible.',
};

function _renderPiIssuerCard(risk) {
  if (!risk?.exists) return `
    <div class="sec-card pi-card">
      <div class="sec-card-hdr"><span class="sec-card-icon">🛡</span><div><div class="sec-card-title">Issuer Risk</div></div></div>
      <div class="inspect-empty-note">Could not load issuer account state.</div>
    </div>`;
  const flagRow = (key, active, isPositive) => `
    <div class="finding finding--${active ? (isPositive ? 'ok' : 'warn') : 'ok'}">
      <span class="finding-sev ${active ? (isPositive ? 'sev-ok' : 'sev-warn') : 'sev-ok'}">${active ? (isPositive ? 'YES' : '⚠') : 'NO'}</span>
      <div class="finding-body">
        <div class="finding-label">${_piHumanizeKey(key)}</div>
        <div class="finding-detail">${escHtml(PI_ISSUER_EXPLANATIONS[key] || '')}</div>
      </div>
    </div>`;
  return `
    <div class="sec-card pi-card">
      <div class="sec-card-hdr"><span class="sec-card-icon">🛡</span><div><div class="sec-card-title">Issuer Risk</div><div class="sec-card-sub">Token controls — neutral facts, not a verdict</div></div></div>
      ${flagRow('clawbackEnabled', risk.clawbackEnabled, false)}
      ${flagRow('globalFreeze', risk.globalFreeze, false)}
      ${flagRow('freezeCapable', risk.freezeCapable, false)}
      ${flagRow('requireAuth', risk.requireAuth, false)}
      ${flagRow('blackholed', risk.blackholed, true)}
    </div>`;
}

export function copyProjectIntelForAi() {
  const d = projectIntelSnapshot.data;
  if (!d) return;
  _copyToClipboard(_buildPiAiPrompt(d));
}

function _piDepthLines(levels, label) {
  if (!levels?.length) return '';
  const rows = levels.map(l => `    ${l.pct}% impact: ${fmt(l.xrpAtOffer, 1)} XRP / ${_fmtCompact(l.tokenAtOffer)} tokens${l.bookExhausted ? ' (book exhausted before this level — real depth may be less than shown)' : ''}`).join('\n');
  return `  ${label}:\n${rows}`;
}

function _piHolderBlockText(label, hd) {
  const out = [`${label}:`];
  if (!hd?.exists) { out.push('  No data found.'); return out.join('\n'); }
  out.push(`  Holder count: ${hd.holderCount}${hd.sampleOnly ? ' (sampled, capped)' : ''}`);
  out.push(`  Top 1 holds: ${fmt(hd.top1Pct, 1)}%`);
  out.push(`  Top 5 hold: ${fmt(hd.top5Pct, 1)}%`);
  out.push(`  Top 10 hold: ${fmt(hd.top10Pct, 1)}%`);
  (hd.topHolders || []).slice(0, 10).forEach((h, i) => {
    const pct = hd.totalSampled > 0 ? fmt(h.balance / hd.totalSampled * 100, 2) : '0.00';
    out.push(`    #${i + 1} ${h.address}: ${_fmtCompact(h.balance)} (${pct}%)`);
  });
  return out.join('\n');
}

function _buildPiAiPrompt(d) {
  const s = d.strength, amm = d.amm, ob = d.orderBook, risk = d.issuerRisk;
  const lines = [];

  lines.push(`XRPL TOKEN ANALYSIS — ${d.token.symbol}${d.token.name ? ` (${d.token.name})` : ''}`);
  lines.push(`Issuer: ${d.token.issuer}`);
  lines.push(`Currency code: ${d.token.currency}`);
  lines.push(`Snapshot taken: ${new Date(d.fetchedAt).toISOString()}`);
  lines.push('');
  lines.push(`OVERALL STRENGTH SCORE: ${s.overall}/100 (${_piScoreWord(s.overall)})`);
  lines.push('Methodology note: this score covers only 5 point-in-time-computable dimensions (Liquidity, Distribution, Market Quality, LP Stability, Issuer Risk). Network Activity, Treasury Health, and Project Transparency are NOT included — they would require historical tracking this tool does not do.');
  lines.push('');
  lines.push('SUB-SCORES:');
  s.dimensionsLive.forEach(key => {
    const meta = PI_SUBSCORE_META[key];
    const sub = s.subScores[key];
    lines.push(`- ${meta.label}: ${sub.score}/100`);
    Object.entries(sub.inputs || {}).forEach(([k, v]) => {
      lines.push(`    ${_piHumanizeKey(k)}: ${_piFmtVal(v)}`);
    });
  });
  lines.push('');

  lines.push('LIQUIDITY — AMM POOL:');
  if (amm?.exists) {
    lines.push(`  XRP reserve: ${fmt(amm.xrpReserve, 2)}`);
    lines.push(`  Token reserve: ${fmt(amm.tokenReserve, 2)}`);
    lines.push(`  LP token supply: ${fmt(amm.lpSupply, 2)}`);
    lines.push(`  Trading fee: ${fmt(amm.tradingFeePct, 3)}%`);
    if (amm.auctionSlot) lines.push(`  Auction slot discounted fee: ${fmt(amm.auctionSlot.discountedFeePct, 3)}%`);
    if (amm.voteSlots?.length) lines.push(`  Fee-vote participants: ${amm.voteSlots.length}`);
  } else {
    lines.push('  No AMM pool found for this pair.');
  }
  lines.push('');

  lines.push('LIQUIDITY — LIVE ORDER BOOK (DEX):');
  if (ob?.exists) {
    lines.push(`  Buy price: ${fmt(ob.buyPriceXrp, 6)} XRP`);
    lines.push(`  Sell price: ${fmt(ob.sellPriceXrp, 6)} XRP`);
    lines.push(`  Spread: ${ob.spreadPct != null ? fmt(ob.spreadPct, 2) + '%' : '—'}`);
    const buyDepth = _piDepthLines(ob.buyDepth, 'Depth buying with XRP');
    const sellDepth = _piDepthLines(ob.sellDepth, 'Depth selling for XRP');
    if (buyDepth) lines.push(buyDepth);
    if (sellDepth) lines.push(sellDepth);
  } else {
    lines.push('  No live order book found for this pair.');
  }
  lines.push('');

  lines.push(_piHolderBlockText('HOLDER CONCENTRATION', d.holders));
  lines.push('');
  lines.push(_piHolderBlockText('LP TOKEN CONCENTRATION', d.lp));
  lines.push('');

  lines.push('ISSUER RISK FLAGS:');
  if (risk?.exists) {
    lines.push(`  Clawback enabled: ${risk.clawbackEnabled ? 'YES' : 'No'} — ${PI_ISSUER_EXPLANATIONS.clawbackEnabled}`);
    lines.push(`  Global freeze active: ${risk.globalFreeze ? 'YES' : 'No'} — ${PI_ISSUER_EXPLANATIONS.globalFreeze}`);
    lines.push(`  Freeze-capable: ${risk.freezeCapable ? 'YES' : 'No'} — ${PI_ISSUER_EXPLANATIONS.freezeCapable}`);
    lines.push(`  Requires auth to hold: ${risk.requireAuth ? 'YES' : 'No'} — ${PI_ISSUER_EXPLANATIONS.requireAuth}`);
    lines.push(`  Issuer blackholed: ${risk.blackholed ? 'YES' : 'No'} — ${PI_ISSUER_EXPLANATIONS.blackholed}`);
  } else {
    lines.push('  Could not load issuer account state.');
  }
  lines.push('');

  lines.push('---');
  lines.push("Please analyze this XRPL token's on-chain data above. Explain in plain language what these metrics suggest about the token's liquidity health, holder/LP concentration risk, and issuer-side control risk. Point out anything that looks like a red flag or an unusually strong/weak signal, and note any limits in what this data can and can't tell me (e.g. it's a point-in-time snapshot, not history).");

  return lines.join('\n');
}

function _highlightMatch(value, query) {
  const text = String(value || '');
  const q = String(query || '').trim();
  if (!q) return escHtml(text);
  const idx = text.toLowerCase().indexOf(q.toLowerCase());
  if (idx < 0) return escHtml(text);
  const a = escHtml(text.slice(0, idx));
  const b = escHtml(text.slice(idx, idx + q.length));
  const c = escHtml(text.slice(idx + q.length));
  return `${a}<mark class="xpd-hit">${b}</mark>${c}`;
}

function _renderPortfolioAndTxSection(address) {
  const totalXrp = Object.values(balanceCache).reduce((s, c) => s + (c?.xrp || 0), 0);
  const usd = marketSnapshot.data?.priceUsd ? totalXrp * marketSnapshot.data.priceUsd : 0;
  const txItems = recentTxSnapshot.items.slice(0, 8);
  return `
    <div class="xpd-token-grid">
      <div class="xpd-token-col">
        <div class="xpd-market-grid">
          <article class="xpd-stat-card xpd-token-row--clickable" onclick="openTokenOnChart('XRP')"><span class="xpd-stat-label">Portfolio XRP</span><strong class="xpd-stat-value">${fmt(totalXrp, 4)}</strong></article>
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
      <div class="xpd-pool-row"><span class="xpd-pool-row-label">LP Balance</span><span class="xpd-pool-row-value" title="${escHtml(p.lpBalance)}">${escHtml(p.lpBalance)}</span></div>
      <div class="xpd-pool-row"><span class="xpd-pool-row-label">Est. Value</span><span class="xpd-pool-row-value">${escHtml(p.estimatedValue)}</span></div>
      <div class="xpd-pool-row"><span class="xpd-pool-row-label">Trading Fee</span><span class="xpd-pool-row-value">${escHtml(p.tradingFee || '—')}</span></div>
      <div class="xpd-pool-row"><span class="xpd-pool-row-label">TVL</span><span class="xpd-pool-row-value">${escHtml(p.tvl || 'Unavailable')}</span></div>
    </div>`).join('')}</div></div>`;
}

function _renderExplorerPoolsArea() {
  if (explorerAmmSnapshot.loading) return '<div class="xpd-amm-card"><h3>General pool explorer</h3><div class="xpd-loading">Loading amm_info for known pools...</div></div>';
  if (explorerAmmSnapshot.error) return `<div class="xpd-amm-card"><h3>General pool explorer</h3><div class="xpd-error">${escHtml(explorerAmmSnapshot.error)}</div></div>`;
  if (!explorerAmmSnapshot.pools.length) return '<div class="xpd-amm-card"><h3>General pool explorer</h3><div class="xpd-empty">No seeded pools returned on this network.</div></div>';
  return `<div class="xpd-amm-card"><h3>General pool explorer</h3><div class="xpd-pool-list">${explorerAmmSnapshot.pools.map(p => `
    <div class="xpd-pool-item">
      <div class="pool-pair xpd-pill-text" title="${escHtml(p.label)}">${escHtml(p.label)}</div>
      <div class="xpd-pool-row"><span class="xpd-pool-row-label">Reserves</span><span class="xpd-pool-row-value">${escHtml(p.reserveA)} / ${escHtml(p.reserveB)}</span></div>
      <div class="xpd-pool-row"><span class="xpd-pool-row-label">Trading Fee</span><span class="xpd-pool-row-value">${escHtml(p.tradingFee)} bps</span></div>
      <div class="xpd-pool-row"><span class="xpd-pool-row-label">Total LP</span><span class="xpd-pool-row-value mono" title="${escHtml(p.totalLp)}">${escHtml(p.totalLp)}</span></div>
      <div class="xpd-pool-row"><span class="xpd-pool-row-label">TVL</span><span class="xpd-pool-row-value">${escHtml(p.tvl || 'Unavailable')}</span></div>
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
    <div class="xpd-row-actions"><button class="xpd-action" onclick="loadCustomAmmPool()"><span class="xai">🔎</span>Load pool</button><button class="xpd-action" onclick="refreshPoolExplorer()"><span class="xai">⟳</span>Refresh known pools</button></div>
    ${customPoolSnapshot.loading ? '<div class="xpd-loading">Loading pool...</div>' : ''}
    ${customPoolSnapshot.error ? `<div class="xpd-error">${escHtml(customPoolSnapshot.error)}</div>` : ''}
    ${customPoolSnapshot.pool ? `<div class="xpd-pool-item">
      <div class="pool-pair xpd-pill-text" title="${escHtml(customPoolSnapshot.pool.label)}">${escHtml(customPoolSnapshot.pool.label)}</div>
      <div class="xpd-pool-row"><span class="xpd-pool-row-label">Reserves</span><span class="xpd-pool-row-value">${escHtml(customPoolSnapshot.pool.reserveA)} / ${escHtml(customPoolSnapshot.pool.reserveB)}</span></div>
      <div class="xpd-pool-row"><span class="xpd-pool-row-label">Trading Fee</span><span class="xpd-pool-row-value">${escHtml(customPoolSnapshot.pool.tradingFee)} bps</span></div>
      <div class="xpd-pool-row"><span class="xpd-pool-row-label">Total LP</span><span class="xpd-pool-row-value mono" title="${escHtml(customPoolSnapshot.pool.totalLp)}">${escHtml(customPoolSnapshot.pool.totalLp)}</span></div>
      <div class="xpd-pool-row"><span class="xpd-pool-row-label">TVL</span><span class="xpd-pool-row-value">${escHtml(customPoolSnapshot.pool.tvl || 'Unavailable')}</span></div>
    </div>` : ''}
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

/** OnTheDex only accepts 5|15|60|240|D|W — snap the app's finer intervals to the nearest one. */
function _intervalToOnTheDex(interval) {
  if (interval === 'M') return 'W';
  if (interval === 'D' || interval === 'W') return interval;
  const mins = _intervalToMinutes(interval);
  for (const step of [5, 15, 60, 240]) {
    if (mins <= step) return String(step);
  }
  return 'D';
}

/** Real XRPL-DEX OHLC (in XRP terms) for any currency+issuer pair — works for any issued asset, not just Coinbase/CoinGecko-listed majors. */
async function _fetchOnTheDexBars(currency, issuer, interval, bars = 200) {
  const base = issuer ? `${currency}.${issuer}` : currency;
  const iv = _intervalToOnTheDex(interval);
  const clampedBars = Math.min(2000, Math.max(20, Number(bars) || 200));
  const url = `https://api.onthedex.live/public/v1/ohlc?base=${encodeURIComponent(base)}&quote=XRP&interval=${iv}&bars=${clampedBars}`;
  const payload = await _fetchJson(url, { timeoutMs: 10000 });
  const rows = Array.isArray(payload?.data?.ohlc) ? payload.data.ohlc : [];
  return rows
    .map(r => ({
      time: Number(r.t),
      open: Number(r.o),
      high: Number(r.h),
      low: Number(r.l),
      close: Number(r.c),
      volume: Number(r.vb || 0),
    }))
    .filter(c => Number.isFinite(c.time) && [c.open, c.high, c.low, c.close].every(Number.isFinite))
    .sort((a, b) => a.time - b.time);
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

function _coinbaseProductFromSymbol(symbol) {
  const map = {
    XRP: 'XRP-USD',
    BTC: 'BTC-USD',
    ETH: 'ETH-USD',
    SOL: 'SOL-USD',
    USDC: 'USDC-USD',
  };
  return map[String(symbol || '').toUpperCase()] || null;
}

// Same overlapping-mount thundering-herd risk as _fetchBarsByPair (this can
// run a full Coinbase pagination or a 2000-bar OnTheDex pull, either of
// which can take several seconds — long enough for the live-ledger tick to
// re-trigger this before the first call finishes).
const _focusedTokenBarsInFlight = new Map();

async function _fetchBarsForFocusedToken(focusedToken, interval) {
  if (!focusedToken) return null;
  const key = `${_tokenKey(focusedToken)}:${interval}`;
  const existing = _focusedTokenBarsInFlight.get(key);
  if (existing) return existing;
  const work = _fetchBarsForFocusedTokenInner(focusedToken, interval);
  _focusedTokenBarsInFlight.set(key, work);
  try {
    return await work;
  } finally {
    _focusedTokenBarsInFlight.delete(key);
  }
}

async function _fetchBarsForFocusedTokenInner(focusedToken, interval) {
  const symbol = String(focusedToken.symbol || '').toUpperCase();
  if (!symbol || symbol === 'XRP') return null;

  const directProduct = _coinbaseProductFromSymbol(symbol);
  if (directProduct) {
    try {
      const granularity = _intervalToCoinbaseGranularity(interval);
      const maxPages = granularity === 86400 ? FULL_HISTORY_MAX_PAGES_DAILY : FULL_HISTORY_MAX_PAGES_INTRADAY;
      const { candles, reachedStart } = await _paginateCoinbaseHistory(directProduct, granularity, maxPages);
      if (candles.length) {
        const depth = reachedStart ? `${new Date(candles[0].time * 1000).getUTCFullYear()}–present` : `last ${candles.length} bars`;
        return { candles, source: `Coinbase direct (${directProduct}, ${depth})`, mode: 'token-direct' };
      }
    } catch {
      // continue to other sources
    }
  }

  const issuer = String(focusedToken.issuer || '').trim();
  if (issuer) {
    try {
      const xrpBars = await _fetchOnTheDexBars(symbol, issuer, interval, 2000);
      if (xrpBars.length) {
        const xrpUsd = Number(dexSnapshot.stats?.xrplSpot || dexSnapshot.stats?.price || 0);
        const candles = xrpUsd > 0
          ? xrpBars.map(c => ({
              time: c.time,
              open: c.open * xrpUsd,
              high: c.high * xrpUsd,
              low: c.low * xrpUsd,
              close: c.close * xrpUsd,
              volume: c.volume,
            }))
          : xrpBars;
        return { candles, source: `OnTheDex XRPL DEX (${symbol}/XRP)`, mode: 'token-direct' };
      }
    } catch {
      // continue to fallback
    }
  }

  return null;
}

function _applyChartMeta(candles, { mode = 'pair', source = 'Source pending', tokenKey = '' } = {}) {
  const arr = Array.isArray(candles) ? candles : [];
  if (!arr.length) {
    dexSnapshot.chartMeta = {
      tokenKey: tokenKey || dexSnapshot.tokenFocusKey || 'XRP|',
      symbol: (tokenKey && tokenKey.split('|')[0]) || 'XRP',
      source,
      last: null,
      high: null,
      low: null,
      mode,
    };
    return;
  }
  const last = arr[arr.length - 1];
  const highs = arr.map(c => Number(c.high)).filter(v => Number.isFinite(v));
  const lows = arr.map(c => Number(c.low)).filter(v => Number.isFinite(v));
  const key = tokenKey || dexSnapshot.tokenFocusKey || 'XRP|';
  dexSnapshot.chartMeta = {
    tokenKey: key,
    symbol: key.split('|')[0] || 'XRP',
    source,
    last: Number(last.close),
    high: highs.length ? Math.max(...highs) : Number(last.high),
    low: lows.length ? Math.min(...lows) : Number(last.low),
    mode,
  };
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
      // xrplSpot is XRP's own orderbook price and gets set unconditionally —
      // the "XRPL Spot" pill (_renderDexSection) always reads it regardless
      // of which pair is on-screen. But stats.price/.source drive the
      // SELECTED PAIR's own OHLC display and the live-candle patch in
      // _fetchDexBars — this call runs after every _fetchDexStats(), for
      // every pair, so unconditionally overwriting them here used to
      // replace BTC/ETH/SOL's real Coinbase price with XRP's ~$1 price on
      // every single stats refresh, corrupting their charts' last candle.
      dexSnapshot.stats.xrplSpot = px;
      if (String(_currentPairOption().symbol || 'XRP').toUpperCase() === 'XRP') {
        dexSnapshot.stats.price = px;
        const base = dexSnapshot.stats.baseSource || dexSnapshot.stats.source || 'Market feed';
        dexSnapshot.stats.source = `${base} + XRPL live`;
        if (marketSnapshot.data) marketSnapshot.data.priceUsd = px;
      }
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

async function _ensureThreeLoaded() {
  if (window.THREE?.Scene) return true;
  if (!_threeChartPromise) {
    _threeChartPromise = new Promise((resolve, reject) => {
      const existing = document.querySelector('script[data-three-chart="1"]');
      if (existing) {
        existing.addEventListener('load', () => resolve(true), { once: true });
        existing.addEventListener('error', () => reject(new Error('Three.js failed to load.')), { once: true });
        return;
      }
      const s = document.createElement('script');
      s.src = 'https://unpkg.com/three@0.166.1/build/three.min.js';
      s.async = true;
      s.defer = true;
      s.dataset.threeChart = '1';
      s.onload = () => resolve(true);
      s.onerror = () => reject(new Error('Three.js failed to load.'));
      document.head.appendChild(s);
    }).finally(() => {
      if (!window.THREE?.Scene) _threeChartPromise = null;
    });
  }
  await _threeChartPromise;
  return !!window.THREE?.Scene;
}

function _destroyChartAtmosphere() {
  if (_chartAtmosphereRuntime.resizeHandler) {
    try { window.removeEventListener('resize', _chartAtmosphereRuntime.resizeHandler); } catch {}
  }
  if (_chartAtmosphereRuntime.raf) {
    cancelAnimationFrame(_chartAtmosphereRuntime.raf);
  }
  if (_chartAtmosphereRuntime.renderer?.domElement?.parentElement) {
    try { _chartAtmosphereRuntime.renderer.domElement.parentElement.removeChild(_chartAtmosphereRuntime.renderer.domElement); } catch {}
  }
  if (_chartAtmosphereRuntime.renderer) {
    try { _chartAtmosphereRuntime.renderer.dispose(); } catch {}
  }
  _chartAtmosphereRuntime = { renderer: null, scene: null, camera: null, points: null, raf: 0, host: null, resizeHandler: null };
}

async function _mountChartAtmosphere() {
  const host = document.getElementById('xpd-chart-atmosphere');
  if (!host) return;
  // Purely decorative and never needs fresh data — if it's already running
  // and its canvas is still attached (renderProfilePage() now preserves this
  // host across rebuilds), there's nothing to update, so skip the
  // teardown/recreate entirely instead of rebuilding the whole WebGL scene
  // on every render.
  if (_chartAtmosphereRuntime.renderer && host.contains(_chartAtmosphereRuntime.renderer.domElement)) return;
  if ((navigator.hardwareConcurrency || 4) <= 3) return;
  try {
    await _ensureThreeLoaded();
    if (!window.THREE?.Scene) return;

    _destroyChartAtmosphere();

    const THREE = window.THREE;
    const width = Math.max(1, host.clientWidth || 640);
    const height = Math.max(1, host.clientHeight || 460);
    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(52, width / height, 0.1, 1000);
    camera.position.z = 46;

    const renderer = new THREE.WebGLRenderer({ alpha: true, antialias: true });
    renderer.setPixelRatio(Math.min(2, window.devicePixelRatio || 1));
    renderer.setSize(width, height);
    host.appendChild(renderer.domElement);

    const count = 900;
    const vertices = new Float32Array(count * 3);
    for (let i = 0; i < count; i += 1) {
      const j = i * 3;
      vertices[j] = (Math.random() - 0.5) * 90;
      vertices[j + 1] = (Math.random() - 0.5) * 40;
      vertices[j + 2] = (Math.random() - 0.5) * 24;
    }
    const geo = new THREE.BufferGeometry();
    geo.setAttribute('position', new THREE.BufferAttribute(vertices, 3));
    const mat = new THREE.PointsMaterial({
      color: 0x4dd8ff,
      size: 0.25,
      transparent: true,
      opacity: 0.26,
      depthWrite: false,
    });
    const points = new THREE.Points(geo, mat);
    scene.add(points);

    let frame = 0;
    let lastActiveDraw = 0;
    const animate = () => {
      frame += 1;
      const change = Number(dexSnapshot.stats?.changePct || 0);
      const volatility = Math.min(4, Math.max(0.35, Math.abs(change) / 2.2));
      const warm = change > 0 ? 0xffb85a : 0xff6e9f;
      const cool = 0x4dd8ff;
      mat.color.setHex(Math.abs(change) > 1.5 ? warm : cool);
      points.rotation.y += 0.0009 * volatility;
      points.rotation.x = Math.sin(frame * 0.0015 * volatility) * 0.08;
      points.position.y = Math.sin(frame * 0.003 * volatility) * 0.7;
      if (!document.hidden || (Date.now() - lastActiveDraw) > 350) {
        renderer.render(scene, camera);
        lastActiveDraw = Date.now();
      }
      _chartAtmosphereRuntime.raf = requestAnimationFrame(animate);
    };

    const onResize = () => {
      const w = Math.max(1, host.clientWidth || 640);
      const h = Math.max(1, host.clientHeight || 460);
      camera.aspect = w / h;
      camera.updateProjectionMatrix();
      renderer.setSize(w, h);
    };
    window.addEventListener('resize', onResize, { passive: true });

    _chartAtmosphereRuntime = { renderer, scene, camera, points, raf: 0, host, resizeHandler: onResize };
    animate();
  } catch {
    // Atmosphere layer is decorative; never block core chart rendering.
  }
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

function _resolveFocusedToken() {
  const focusRaw = String(dexSnapshot.tokenFocusKey || '');
  if (!focusRaw) return null;
  const sym = focusRaw.includes('|') ? focusRaw.split('|')[0] : focusRaw;
  return tokenDiscoverySnapshot.tokens.find(t => _tokenKey(t) === focusRaw)
    || tokenDiscoverySnapshot.tokens.find(t => String(t.symbol || '').toUpperCase() === String(sym || '').toUpperCase())
    || null;
}

function _resolveFallbackBasePrice() {
  const focused = _resolveFocusedToken();
  const focusedPx = Number(focused?.price || 0);
  if (Number.isFinite(focusedPx) && focusedPx > 0) return focusedPx;
  const xrplSpot = Number(dexSnapshot.stats?.xrplSpot || 0);
  if (Number.isFinite(xrplSpot) && xrplSpot > 0) return xrplSpot;
  const statsPx = Number(dexSnapshot.stats?.price || 0);
  if (Number.isFinite(statsPx) && statsPx > 0) return statsPx;
  return 1;
}

function _buildFallbackBars(interval, basePrice = 1, count = 220) {
  const iv = Math.max(60, _intervalToSeconds(interval));
  const now = Math.floor(Date.now() / 1000);
  const start = (Math.floor(now / iv) * iv) - (count * iv);
  let close = Math.max(0.000001, Number(basePrice) || 1);
  const bars = [];
  for (let i = 0; i < count; i += 1) {
    const t = start + (i * iv);
    const open = close;
    // deterministic wave + low-noise drift so UX stays stable without network candles
    const drift = Math.sin((i + 1) / 9) * 0.004 + Math.cos((i + 3) / 17) * 0.002;
    close = Math.max(0.000001, open * (1 + drift));
    const high = Math.max(open, close) * (1 + Math.abs(drift) * 0.55 + 0.0015);
    const low = Math.min(open, close) * Math.max(0.000001, 1 - (Math.abs(drift) * 0.55 + 0.0015));
    bars.push({
      time: t,
      open: Number(open),
      high: Number(high),
      low: Number(low),
      close: Number(close),
      volume: Math.max(0, Math.round((Math.abs(drift) * 12000) + (i % 13) * 55)),
    });
  }
  return bars;
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

function _rsi(data, len = 14) {
  const out = [];
  if (data.length <= len) return out;
  let gain = 0;
  let loss = 0;
  for (let i = 1; i <= len; i += 1) {
    const d = data[i].close - data[i - 1].close;
    gain += d > 0 ? d : 0;
    loss += d < 0 ? -d : 0;
  }
  let avgGain = gain / len;
  let avgLoss = loss / len;
  for (let i = len + 1; i < data.length; i += 1) {
    const d = data[i].close - data[i - 1].close;
    avgGain = ((avgGain * (len - 1)) + (d > 0 ? d : 0)) / len;
    avgLoss = ((avgLoss * (len - 1)) + (d < 0 ? -d : 0)) / len;
    const rs = avgLoss > 0 ? avgGain / avgLoss : 100;
    out.push({ time: data[i].time, value: 100 - (100 / (1 + rs)) });
  }
  return out;
}

function _atr(data, len = 14) {
  const tr = [];
  for (let i = 0; i < data.length; i += 1) {
    const prevClose = i > 0 ? data[i - 1].close : data[i].close;
    tr.push(Math.max(data[i].high - data[i].low, Math.abs(data[i].high - prevClose), Math.abs(data[i].low - prevClose)));
  }
  const out = [];
  let prev = tr.slice(0, len).reduce((s, v) => s + v, 0) / Math.max(1, len);
  for (let i = len; i < data.length; i += 1) {
    prev = ((prev * (len - 1)) + tr[i]) / len;
    out.push({ time: data[i].time, value: prev });
  }
  return out;
}

function _stochastic(data, len = 14, smooth = 3) {
  const k = [];
  for (let i = len - 1; i < data.length; i += 1) {
    const slice = data.slice(i - len + 1, i + 1);
    const hh = Math.max(...slice.map(c => c.high));
    const ll = Math.min(...slice.map(c => c.low));
    const v = hh !== ll ? ((data[i].close - ll) / (hh - ll)) * 100 : 50;
    k.push({ time: data[i].time, value: v });
  }
  const d = [];
  for (let i = smooth - 1; i < k.length; i += 1) {
    const s = k.slice(i - smooth + 1, i + 1).reduce((a, b) => a + b.value, 0) / smooth;
    d.push({ time: k[i].time, value: s });
  }
  return { k, d };
}

function _macd(data, fast = 12, slow = 26, signalLen = 9) {
  const fastEma = _ema(data, fast);
  const slowEma = _ema(data, slow);
  const slowMap = new Map(slowEma.map(v => [v.time, v.value]));
  const line = fastEma
    .filter(v => slowMap.has(v.time))
    .map(v => ({ time: v.time, value: v.value - slowMap.get(v.time) }));
  const signal = [];
  if (line.length) {
    const k = 2 / (signalLen + 1);
    let ema = line[0].value;
    for (let i = 0; i < line.length; i += 1) {
      ema = i === 0 ? line[i].value : (line[i].value * k) + (ema * (1 - k));
      if (i >= signalLen - 1) signal.push({ time: line[i].time, value: ema });
    }
  }
  const sigMap = new Map(signal.map(v => [v.time, v.value]));
  const hist = line.filter(v => sigMap.has(v.time)).map(v => ({ time: v.time, value: v.value - sigMap.get(v.time) }));
  return { line, signal, hist };
}

function _ichimoku(data, tenkanLen = 9, kijunLen = 26, senkouBLen = 52) {
  const line = (len) => {
    const out = [];
    for (let i = len - 1; i < data.length; i += 1) {
      const s = data.slice(i - len + 1, i + 1);
      out.push({ time: data[i].time, value: (Math.max(...s.map(c => c.high)) + Math.min(...s.map(c => c.low))) / 2 });
    }
    return out;
  };
  const tenkan = line(tenkanLen);
  const kijun = line(kijunLen);
  const kijunMap = new Map(kijun.map(v => [v.time, v.value]));
  const senkouA = tenkan.filter(v => kijunMap.has(v.time)).map(v => ({ time: v.time, value: (v.value + kijunMap.get(v.time)) / 2 }));
  const senkouB = line(senkouBLen);
  const chikou = data.map(c => ({ time: c.time, value: c.close }));
  return { tenkan, kijun, senkouA, senkouB, chikou };
}

function _donchian(data, len = 20) {
  const upper = [];
  const lower = [];
  const mid = [];
  for (let i = len - 1; i < data.length; i += 1) {
    const s = data.slice(i - len + 1, i + 1);
    const hi = Math.max(...s.map(c => c.high));
    const lo = Math.min(...s.map(c => c.low));
    upper.push({ time: data[i].time, value: hi });
    lower.push({ time: data[i].time, value: lo });
    mid.push({ time: data[i].time, value: (hi + lo) / 2 });
  }
  return { upper, lower, mid };
}

function _keltner(data, len = 20, mult = 2) {
  const mid = _ema(data, len);
  const atr = _atr(data, len);
  const atrMap = new Map(atr.map(v => [v.time, v.value]));
  const upper = [];
  const lower = [];
  mid.forEach(v => {
    if (atrMap.has(v.time)) {
      const a = atrMap.get(v.time) * mult;
      upper.push({ time: v.time, value: v.value + a });
      lower.push({ time: v.time, value: v.value - a });
    }
  });
  return { upper, lower, mid };
}

function _volumeOscillators(data) {
  const obv = [];
  const adline = [];
  let obvVal = 0;
  let adVal = 0;
  for (let i = 0; i < data.length; i += 1) {
    if (i > 0) {
      const prev = data[i - 1];
      if (data[i].close > prev.close) obvVal += data[i].volume || 0;
      if (data[i].close < prev.close) obvVal -= data[i].volume || 0;
    }
    const denom = (data[i].high - data[i].low) || 1;
    const mfm = ((data[i].close - data[i].low) - (data[i].high - data[i].close)) / denom;
    adVal += mfm * (data[i].volume || 0);
    obv.push({ time: data[i].time, value: obvVal });
    adline.push({ time: data[i].time, value: adVal });
  }
  return { obv, adline };
}

function _dmiAdx(data, len = 14) {
  if (data.length < len + 2) return { adx: [], plusDi: [], minusDi: [] };
  const tr = [];
  const plusDm = [];
  const minusDm = [];
  for (let i = 1; i < data.length; i += 1) {
    const upMove = data[i].high - data[i - 1].high;
    const downMove = data[i - 1].low - data[i].low;
    plusDm.push(upMove > downMove && upMove > 0 ? upMove : 0);
    minusDm.push(downMove > upMove && downMove > 0 ? downMove : 0);
    tr.push(Math.max(
      data[i].high - data[i].low,
      Math.abs(data[i].high - data[i - 1].close),
      Math.abs(data[i].low - data[i - 1].close),
    ));
  }
  let trSmooth = tr.slice(0, len).reduce((s, v) => s + v, 0);
  let plusSmooth = plusDm.slice(0, len).reduce((s, v) => s + v, 0);
  let minusSmooth = minusDm.slice(0, len).reduce((s, v) => s + v, 0);
  const plusDi = [];
  const minusDi = [];
  const dxSeries = [];
  for (let i = len; i < tr.length; i += 1) {
    trSmooth = trSmooth - (trSmooth / len) + tr[i];
    plusSmooth = plusSmooth - (plusSmooth / len) + plusDm[i];
    minusSmooth = minusSmooth - (minusSmooth / len) + minusDm[i];
    const pdi = trSmooth > 0 ? (100 * plusSmooth) / trSmooth : 0;
    const mdi = trSmooth > 0 ? (100 * minusSmooth) / trSmooth : 0;
    const dx = (pdi + mdi) > 0 ? (100 * Math.abs(pdi - mdi)) / (pdi + mdi) : 0;
    const time = data[i + 1].time;
    plusDi.push({ time, value: pdi });
    minusDi.push({ time, value: mdi });
    dxSeries.push({ time, value: dx });
  }
  const adx = [];
  if (dxSeries.length >= len) {
    let adxVal = dxSeries.slice(0, len).reduce((s, v) => s + v.value, 0) / len;
    for (let i = len; i < dxSeries.length; i += 1) {
      adxVal = ((adxVal * (len - 1)) + dxSeries[i].value) / len;
      adx.push({ time: dxSeries[i].time, value: adxVal });
    }
  }
  return { adx, plusDi, minusDi };
}

function _aroon(data, len = 14) {
  const up = [];
  const down = [];
  for (let i = len - 1; i < data.length; i += 1) {
    const slice = data.slice(i - len + 1, i + 1);
    let hiIdx = 0;
    let loIdx = 0;
    for (let j = 1; j < slice.length; j += 1) {
      if (slice[j].high >= slice[hiIdx].high) hiIdx = j;
      if (slice[j].low <= slice[loIdx].low) loIdx = j;
    }
    const periodsSinceHigh = (len - 1) - hiIdx;
    const periodsSinceLow = (len - 1) - loIdx;
    up.push({ time: data[i].time, value: ((len - periodsSinceHigh) / len) * 100 });
    down.push({ time: data[i].time, value: ((len - periodsSinceLow) / len) * 100 });
  }
  return { up, down };
}

function _vortex(data, len = 14) {
  const plus = [];
  const minus = [];
  if (data.length < len + 2) return { plus, minus };
  for (let i = len; i < data.length; i += 1) {
    let trSum = 0;
    let vmPlus = 0;
    let vmMinus = 0;
    for (let j = i - len + 1; j <= i; j += 1) {
      const prev = data[j - 1];
      const cur = data[j];
      trSum += Math.max(cur.high - cur.low, Math.abs(cur.high - prev.close), Math.abs(cur.low - prev.close));
      vmPlus += Math.abs(cur.high - prev.low);
      vmMinus += Math.abs(cur.low - prev.high);
    }
    plus.push({ time: data[i].time, value: trSum > 0 ? vmPlus / trSum : 0 });
    minus.push({ time: data[i].time, value: trSum > 0 ? vmMinus / trSum : 0 });
  }
  return { plus, minus };
}

function _supertrend(data, len = 10, mult = 3) {
  const atr = _atr(data, len);
  const atrMap = new Map(atr.map(v => [v.time, v.value]));
  const out = [];
  let prevUpper = 0;
  let prevLower = 0;
  let prevTrendUp = true;
  data.forEach((c, i) => {
    if (i === 0 || !atrMap.has(c.time)) return;
    const hl2 = (c.high + c.low) / 2;
    const a = atrMap.get(c.time);
    let upper = hl2 + (mult * a);
    let lower = hl2 - (mult * a);
    if (i > 1) {
      if (upper > prevUpper && data[i - 1].close <= prevUpper) upper = prevUpper;
      if (lower < prevLower && data[i - 1].close >= prevLower) lower = prevLower;
    }
    const trendUp = c.close > upper ? true : c.close < lower ? false : prevTrendUp;
    const value = trendUp ? lower : upper;
    out.push({ time: c.time, value, trendUp: trendUp ? 1 : 0 });
    prevUpper = upper;
    prevLower = lower;
    prevTrendUp = trendUp;
  });
  return out;
}

function _mfi(data, len = 14) {
  const out = [];
  if (data.length <= len) return out;
  const flow = data.map((c, i) => {
    const tp = (c.high + c.low + c.close) / 3;
    const prevTp = i > 0 ? (data[i - 1].high + data[i - 1].low + data[i - 1].close) / 3 : tp;
    const raw = tp * (c.volume || 0);
    return { time: c.time, pos: tp >= prevTp ? raw : 0, neg: tp < prevTp ? raw : 0 };
  });
  for (let i = len; i < flow.length; i += 1) {
    const s = flow.slice(i - len + 1, i + 1);
    const pos = s.reduce((a, b) => a + b.pos, 0);
    const neg = s.reduce((a, b) => a + b.neg, 0);
    const ratio = neg > 0 ? pos / neg : 100;
    out.push({ time: flow[i].time, value: 100 - (100 / (1 + ratio)) });
  }
  return out;
}

function _williamsR(data, len = 14) {
  const out = [];
  for (let i = len - 1; i < data.length; i += 1) {
    const s = data.slice(i - len + 1, i + 1);
    const hh = Math.max(...s.map(c => c.high));
    const ll = Math.min(...s.map(c => c.low));
    const value = hh !== ll ? ((hh - data[i].close) / (hh - ll)) * -100 : -50;
    out.push({ time: data[i].time, value });
  }
  return out;
}

function _cci(data, len = 20) {
  const out = [];
  const tp = data.map(c => ({ time: c.time, value: (c.high + c.low + c.close) / 3 }));
  for (let i = len - 1; i < tp.length; i += 1) {
    const s = tp.slice(i - len + 1, i + 1);
    const ma = s.reduce((a, b) => a + b.value, 0) / len;
    const md = s.reduce((a, b) => a + Math.abs(b.value - ma), 0) / len;
    const cci = md > 0 ? (tp[i].value - ma) / (0.015 * md) : 0;
    out.push({ time: tp[i].time, value: cci });
  }
  return out;
}

function _ultimateOscillator(data) {
  if (data.length < 30) return [];
  const bp = [];
  const tr = [];
  for (let i = 1; i < data.length; i += 1) {
    const prevClose = data[i - 1].close;
    const minL = Math.min(data[i].low, prevClose);
    const maxH = Math.max(data[i].high, prevClose);
    bp.push({ time: data[i].time, value: data[i].close - minL });
    tr.push({ time: data[i].time, value: maxH - minL });
  }
  const sumRange = (arr, end, len) => arr.slice(end - len + 1, end + 1).reduce((a, b) => a + b.value, 0);
  const out = [];
  for (let i = 27; i < bp.length; i += 1) {
    const avg7 = sumRange(bp, i, 7) / Math.max(1e-9, sumRange(tr, i, 7));
    const avg14 = sumRange(bp, i, 14) / Math.max(1e-9, sumRange(tr, i, 14));
    const avg28 = sumRange(bp, i, 28) / Math.max(1e-9, sumRange(tr, i, 28));
    out.push({ time: bp[i].time, value: 100 * ((4 * avg7) + (2 * avg14) + avg28) / 7 });
  }
  return out;
}

function _cmf(data, len = 20) {
  const out = [];
  const mfv = data.map(c => {
    const denom = (c.high - c.low) || 1;
    const mfm = ((c.close - c.low) - (c.high - c.close)) / denom;
    return { time: c.time, value: mfm * (c.volume || 0), volume: c.volume || 0 };
  });
  for (let i = len - 1; i < mfv.length; i += 1) {
    const s = mfv.slice(i - len + 1, i + 1);
    const flow = s.reduce((a, b) => a + b.value, 0);
    const vol = s.reduce((a, b) => a + b.volume, 0);
    out.push({ time: mfv[i].time, value: vol > 0 ? flow / vol : 0 });
  }
  return out;
}

function _parseCoinbaseRows(rows) {
  return (Array.isArray(rows) ? rows : [])
    .map(r => ({
      time: Number(r[0]),
      low: Number(r[1]),
      high: Number(r[2]),
      open: Number(r[3]),
      close: Number(r[4]),
      volume: Number(r[5]),
    }))
    .filter(c => Number.isFinite(c.time) && [c.open, c.high, c.low, c.close].every(Number.isFinite));
}

function _mergeCandleSeries(a, b) {
  const byTime = new Map();
  for (const c of a) byTime.set(c.time, c);
  for (const c of b) byTime.set(c.time, c); // second series wins on timestamp overlap
  return Array.from(byTime.values()).sort((x, y) => x.time - y.time);
}

/** Pages backward from now in ~300-bar windows until Coinbase returns
 *  nothing further back (the genuine start of its data for this product) or
 *  maxPages is hit — a plain unpaginated request only ever returns the most
 *  recent ~300 bars, nowhere near a coin's actual trading history. */
async function _paginateCoinbaseHistory(product, granularitySec, maxPages) {
  const all = [];
  let endTs = Math.floor(Date.now() / 1000);
  let reachedStart = false;
  for (let page = 0; page < maxPages; page += 1) {
    const startTs = endTs - (granularitySec * 300);
    const url = `https://api.exchange.coinbase.com/products/${product}/candles?granularity=${granularitySec}`
      + `&start=${new Date(startTs * 1000).toISOString()}&end=${new Date(endTs * 1000).toISOString()}`;
    let rows;
    try {
      rows = await _fetchJson(url, { timeoutMs: 10000 });
    } catch {
      break; // network hiccup mid-pagination — keep whatever was already paged
    }
    const parsed = _parseCoinbaseRows(rows);
    if (!parsed.length) { reachedStart = true; break; }
    all.push(...parsed);
    endTs = startTs;
    if (page < maxPages - 1) await _sleep(FULL_HISTORY_PAGE_DELAY_MS);
  }
  return { candles: _mergeCandleSeries(all, []), reachedStart };
}

/** Extends daily history further back than Coinbase has using CoinGecko's
 *  market_chart/range — that endpoint only has price points (no real OHLC),
 *  so each day becomes a flat O=H=L=C candle. Coarser than genuine OHLC, but
 *  far better than nothing for the years before an exchange's own listing
 *  date (Coinbase only listed XRP-USD in 2019; CoinGecko's XRP history goes
 *  back to 2013, much closer to actual token inception). */
async function _fetchCoinGeckoDailyRangeCandles(geckoId, fromTs, toTs) {
  if (!geckoId || !Number.isFinite(fromTs) || !Number.isFinite(toTs) || toTs <= fromTs) return [];
  try {
    const url = `https://api.coingecko.com/api/v3/coins/${geckoId}/market_chart/range?vs_currency=usd&from=${fromTs}&to=${toTs}`;
    const payload = await _fetchJson(url, { timeoutMs: 15000 });
    const prices = Array.isArray(payload?.prices) ? payload.prices : [];
    return prices
      .map(([ms, price]) => ({
        time: Math.floor(Number(ms) / 1000 / 86400) * 86400,
        open: Number(price), high: Number(price), low: Number(price), close: Number(price),
        volume: 0,
      }))
      .filter(c => Number.isFinite(c.time) && Number.isFinite(c.close) && c.close > 0)
      .sort((a, b) => a.time - b.time);
  } catch {
    return [];
  }
}

/** One-time (then cached forever in localStorage) full-history pull for a
 *  Coinbase-backed pair: page Coinbase back to its real start, then — for
 *  the 4 majors with a known CoinGecko id — extend further with CoinGecko so
 *  "full history" gets meaningfully closer to actual token inception instead
 *  of stopping wherever Coinbase happened to list the pair. The historical
 *  portion never changes, so only the live tail gets re-fetched on repeat
 *  visits instead of re-paginating everything from scratch every time. */
async function _fetchFullHistoryForPair(pair, product, interval) {
  const granularity = _intervalToCoinbaseGranularity(interval);
  const isDaily = granularity === 86400;
  const cacheKey = `${LS_FULL_HISTORY_PREFIX}${pair.id}:${granularity}`;

  const cached = safeJson(safeGet(cacheKey));
  if (cached?.candles?.length && cached.reachedStart) {
    const tail = await _paginateCoinbaseHistory(product, granularity, 1);
    const merged = _mergeCandleSeries(cached.candles, tail.candles);
    // Refresh the cache with the merged tail so the next visit's "just the
    // tail" fetch starts from an up-to-date last-known bar.
    safeSet(cacheKey, JSON.stringify({ candles: merged, reachedStart: true, source: cached.source, cachedAt: Date.now() }));
    return { candles: merged, source: cached.source };
  }

  const maxPages = isDaily ? FULL_HISTORY_MAX_PAGES_DAILY : FULL_HISTORY_MAX_PAGES_INTRADAY;
  const paged = await _paginateCoinbaseHistory(product, granularity, maxPages);
  let candles = paged.candles;
  let source = candles.length
    ? `Coinbase (${new Date(candles[0].time * 1000).getUTCFullYear()}–present, ${candles.length} bars)`
    : 'Coinbase';

  if (isDaily && paged.reachedStart && pair.coingeckoId && candles.length) {
    const earliest = candles[0].time;
    const extra = await _fetchCoinGeckoDailyRangeCandles(pair.coingeckoId, 0, earliest);
    if (extra.length) {
      candles = _mergeCandleSeries(extra, candles);
      source = `CoinGecko (${new Date(candles[0].time * 1000).getUTCFullYear()}+) + Coinbase (${new Date(earliest * 1000).getUTCFullYear()}–present)`;
    }
  } else if (!isDaily && !paged.reachedStart) {
    source = `Coinbase (last ${candles.length} bars — full inception history is daily/weekly/monthly only)`;
  }

  if (candles.length) {
    safeSet(cacheKey, JSON.stringify({ candles, reachedStart: paged.reachedStart, source, cachedAt: Date.now() }));
  }
  return { candles, source };
}

// The full-history pagination below can take 10-25+ seconds — long enough
// that the ~3-4s live-ledger tick re-triggers _mountDexWidget (and thus this
// function) several times before the first call ever finishes and writes to
// _dexBarCache. Without de-duping, each of those overlapping calls started
// its own independent multi-request pagination run against Coinbase, which
// is how a single chart view turned into 250+ requests and tripped rate
// limits. Concurrent calls for the same cacheKey now just await whichever
// fetch is already in flight instead of starting a new one.
const _dexBarsInFlight = new Map();

async function _fetchBarsByPair(pair, interval) {
  const cacheKey = `${pair.id}:${interval}`;
  const cached = _dexBarCache.get(cacheKey);
  if (cached && (Date.now() - cached.ts) < 60_000 && Array.isArray(cached.data) && cached.data.length) return cached.data;

  const existing = _dexBarsInFlight.get(cacheKey);
  if (existing) return existing;

  const work = (async () => {
    let candles = [];
    let sourceLabel = '';
    const product = _coinbaseProductFromTicker(pair.ticker);
    if (product) {
      try {
        const full = await _fetchFullHistoryForPair(pair, product, interval);
        candles = full.candles;
        sourceLabel = full.source;
      } catch {
        candles = [];
      }
    }

    if (!Array.isArray(candles) || !candles.length) {
      const fallback = _buildFallbackBars(interval, _resolveFallbackBasePrice());
      _dexBarCache.set(cacheKey, { ts: Date.now(), data: fallback, sourceLabel: '' });
      return fallback;
    }

    _dexBarCache.set(cacheKey, { ts: Date.now(), data: candles, sourceLabel });
    return candles;
  })();

  _dexBarsInFlight.set(cacheKey, work);
  try {
    return await work;
  } finally {
    _dexBarsInFlight.delete(cacheKey);
  }
}

async function _fetchDexBars() {
  const pair = _currentPairOption();
  let candles = await _fetchBarsByPair(pair, dexSnapshot.interval);
  // _fetchBarsByPair's in-memory cache carries the full-history source label
  // (how far back the data actually goes) when it fetched via
  // _fetchFullHistoryForPair — prefer that over the generic ticker-stats
  // source so the "Source" chip reflects real depth once a token/proxy fetch
  // hasn't already overridden it below.
  const barsSourceLabel = _dexBarCache.get(`${pair.id}:${dexSnapshot.interval}`)?.sourceLabel;
  let source = barsSourceLabel || String(dexSnapshot.stats?.source || 'Coinbase + XRPL live');
  let mode = 'pair';

  const focused = _resolveFocusedToken();
  const focusSymbol = String(focused?.symbol || '').toUpperCase();
  // Falls back to the *currently selected pair's* symbol (BTC, ETH, SOL, …),
  // not a hardcoded 'XRP' — chartMeta.tokenKey/.symbol feed the alert prompt,
  // alert-crossed toast, and layout save/load labels, all of which used to
  // mislabel every non-XRP pair as "XRP" whenever no wallet token was
  // drilled into.
  const focusKey = focused ? _tokenKey(focused) : `${pair.symbol || 'XRP'}|`;

  if (focused && focusSymbol && focusSymbol !== 'XRP') {
    const direct = await _fetchBarsForFocusedToken(focused, dexSnapshot.interval);
    if (direct?.candles?.length) {
      candles = direct.candles;
      source = direct.source;
      mode = direct.mode;
    }
  }

  // dexSnapshot.stats.xrplSpot is an XRPL-orderbook-sourced reference price
  // that's ALWAYS for XRP, regardless of which DEX pair is selected (see
  // _enrichWithXrplReference) — it's more precise than the Coinbase ticker
  // for XRP specifically, but using it here unconditionally meant selecting
  // BTC/ETH/SOL still patched the chart's last candle with XRP's ~$1 price,
  // corrupting its low/close (high/open survived only because Math.max
  // against a tiny XRP price is a no-op). Only prefer xrplSpot when the
  // selected pair actually IS XRP; otherwise stats.price already holds that
  // pair's own live ticker price.
  const pairIsXrp = String(pair.symbol || 'XRP').toUpperCase() === 'XRP';
  const liveSpot = Number((pairIsXrp ? dexSnapshot.stats?.xrplSpot : null) ?? dexSnapshot.stats?.price ?? 0);
  if (mode === 'pair' && Number.isFinite(liveSpot) && liveSpot > 0 && candles.length) {
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

  // If direct token bars are unavailable, project pair bars to token price scale.
  // proxyBase is "what asset candles is currently denominated in" — the
  // selected pair's own asset, not always XRP (same xrplSpot mixup as above).
  const focusPrice = Number(focused?.price || 0);
  if (mode === 'pair' && focused && focusSymbol && focusSymbol !== 'XRP' && Number.isFinite(focusPrice) && focusPrice > 0 && candles.length) {
    const proxyBase = Number((pairIsXrp ? dexSnapshot.stats?.xrplSpot : null) ?? dexSnapshot.stats?.price ?? candles[candles.length - 1]?.close ?? 0);
    if (Number.isFinite(proxyBase) && proxyBase > 0) {
      const ratio = focusPrice / proxyBase;
      if (Number.isFinite(ratio) && ratio > 0) {
        candles = candles.map(c => ({
          ...c,
          open: c.open * ratio,
          high: c.high * ratio,
          low: c.low * ratio,
          close: c.close * ratio,
        }));
        source = 'Coinbase pair + token spot proxy';
        mode = 'token-proxy';
      }
    }
  }

  if (!candles.length) {
    candles = _buildFallbackBars(dexSnapshot.interval, _resolveFallbackBasePrice());
    source = focused && focusSymbol !== 'XRP' ? 'Synthetic fallback (token-focused)' : 'Synthetic fallback';
    mode = 'fallback';
  }

  // Neither the real OnTheDex/Coinbase market nor the price-scaled proxy
  // came through for this focused token — the chart is about to render
  // whatever `pair`'s own unrelated data is, labeled with this token's name
  // (see _renderDexSection's "Active Chart Token"). Without this, that
  // combination reads as "I picked SOLO and it's just silently showing me
  // something else," with nothing on screen explaining why. One toast per
  // focused token, not one per ~3-4s live-ledger re-render.
  if (focused && focusSymbol !== 'XRP' && (mode === 'pair' || mode === 'fallback')) {
    if (_lastNoMarketWarnedKey !== focusKey) {
      _lastNoMarketWarnedKey = focusKey;
      toastWarn(`No market data found for ${focused.symbol} yet — showing ${pair.symbol || 'XRP'} for reference.`);
    }
  } else if (focusKey) {
    _lastNoMarketWarnedKey = '';
  }

  if (dexSnapshot.chartType === 'heikin_ashi') candles = _toHeikinAshi(candles);
  _applyChartMeta(candles, { mode, source, tokenKey: focusKey || 'XRP|' });
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

function _chartPriceDecimals(view, yMin, yMax) {
  const ref = Number(view?.[view.length - 1]?.close || 0);
  if (!Number.isFinite(ref) || ref <= 0) return 6;
  const range = Math.max(1e-12, Math.abs(Number(yMax) - Number(yMin)));
  const rel = range / Math.max(1e-12, Math.abs(ref));
  if (ref >= 1000) return rel < 0.01 ? 4 : 2;
  if (ref >= 1) return rel < 0.01 ? 6 : 4;
  if (ref >= 0.01) return rel < 0.03 ? 8 : 6;
  return 8;
}

// Deliberately does NOT touch the chart atmosphere (see _mountChartAtmosphere/
// _destroyChartAtmosphere) — that WebGL scene's own lifecycle is driven by
// dexSnapshot.threeEnabled (toggled in _mountDexWidget and setThreeEffects),
// independent of the price/indicator chart. This used to call
// _destroyChartAtmosphere() unconditionally, which tore the whole particle
// scene down and rebuilt it from scratch on every indicator/pair/chart-type
// change even while threeEnabled stayed true — exactly the WebGL flash the
// atmosphere-reuse optimization was meant to avoid.
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
      indicatorPriceLines: [],
      priceLines: [],
      resizeObserver: null,
      chartType: '',
      configKey: '',
      legendEl: null,
      renderLegend: null,
      ichimokuData: null,
      indicatorLegendItems: [],
      alertPriceLines: [],
    };
  }
}

/**
 * Computes every enabled indicator and hands the resulting series to
 * whichever `sinks` it's given — either "create a new chart series" (full
 * mount) or "update the existing series at the next index" (fast-path data
 * refresh, see _mountDexWidget). Same math, same call order either way, so
 * the two stay in lockstep as long as dexSnapshot.indicators/indicatorSettings
 * haven't changed (which the fast path's configKey check already guarantees).
 */
function _populateIndicatorSeries(data, sinks) {
  const { addOverlay, addOsc, addOscHist, addPriceLevel } = sinks;
  const getLen = (k, fallback) => {
    const v = Number(dexSnapshot.indicatorSettings?.[k]?.length);
    return Number.isFinite(v) && v > 1 ? Math.min(500, Math.max(2, v)) : fallback;
  };
  const f = (key, fieldId, fallback) => {
    const v = dexSnapshot.indicatorSettings?.[key]?.[fieldId];
    if (v == null || v === '') return fallback;
    const field = (INDICATOR_FIELD_SCHEMA[key] || []).find(x => x.id === fieldId);
    if (field?.type === 'number') {
      const n = Number(v);
      return Number.isFinite(n) && n > 1 ? Math.min(500, Math.max(2, n)) : fallback;
    }
    return v;
  };

  const ind = dexSnapshot.indicators;
  if (ind.sma20) addOverlay(_sma(data, getLen('sma20', 20)), f('sma20', 'color', '#f1c40f'), 1.2, false, 'SMA');
  if (ind.ema20) addOverlay(_ema(data, getLen('ema20', 20)), f('ema20', 'color', '#ffb86c'), 1.2, false, 'EMA');
  if (ind.wma20) addOverlay(_wma(data, getLen('wma20', 20)), f('wma20', 'color', '#bd93f9'), 1.2, false, 'WMA');
  if (ind.vwap) addOverlay(_vwap(data), f('vwap', 'color', '#80ffea'), 1.2, false, 'VWAP');
  if (ind.bb20) {
    const color = f('bb20', 'color', '#ff79c6');
    const bb = _bbands(data, getLen('bb20', 20), 2);
    addOverlay(bb.upper, color, 1, true, 'BB Upper');
    addOverlay(bb.lower, color, 1, true, 'BB Lower');
  }
  if (ind.ichimoku) {
    const ich = _ichimoku(data, f('ichimoku', 'tenkanLen', 9), f('ichimoku', 'kijunLen', 26), f('ichimoku', 'senkouBLen', 52));
    addOverlay(ich.tenkan, f('ichimoku', 'tenkanColor', '#ffde59'), 1.2, false, 'Tenkan');
    addOverlay(ich.kijun, f('ichimoku', 'kijunColor', '#6ecbff'), 1.2, false, 'Kijun');
    addOverlay(ich.senkouA, 'rgba(70,255,160,0.8)', 1, true, 'Senkou A');
    addOverlay(ich.senkouB, 'rgba(255,120,120,0.8)', 1, true, 'Senkou B');
    addOverlay(ich.chikou, 'rgba(220,220,255,0.6)', 0.9, true, 'Chikou');
  }
  if (ind.donchian) {
    const color = f('donchian', 'color', '#9cfb8c');
    const d = _donchian(data, getLen('donchian', 20));
    addOverlay(d.upper, color, 1, true, 'Donchian Upper');
    addOverlay(d.lower, color, 1, true, 'Donchian Lower');
    addOverlay(d.mid, 'rgba(156,251,140,0.6)', 1.2, false, 'Donchian Mid');
  }
  if (ind.keltner) {
    const color = f('keltner', 'color', '#7ee7ff');
    const k = _keltner(data, getLen('keltner', 20), 2);
    addOverlay(k.upper, color, 1, true, 'Keltner Upper');
    addOverlay(k.lower, color, 1, true, 'Keltner Lower');
    addOverlay(k.mid, 'rgba(126,231,255,0.66)', 1.2, false, 'Keltner Mid');
  }
  if (ind.pivots && data.length >= 2) {
    const prev = data[data.length - 2];
    const p = (prev.high + prev.low + prev.close) / 3;
    const r1 = (2 * p) - prev.low;
    const s1 = (2 * p) - prev.high;
    const r2 = p + (prev.high - prev.low);
    const s2 = p - (prev.high - prev.low);
    addPriceLevel(p, '#f6f6f6', 'P');
    addPriceLevel(r1, '#61ffb0', 'R1');
    addPriceLevel(s1, '#ff8f8f', 'S1');
    addPriceLevel(r2, 'rgba(97,255,176,0.6)', 'R2');
    addPriceLevel(s2, 'rgba(255,143,143,0.6)', 'S2');
  }
  if (ind.supertrend || ind.sar || ind.elderRay) {
    const ema14 = _ema(data, 14);
    if (ind.supertrend) addOverlay(_supertrend(data, 10, 3), f('supertrend', 'color', '#8bffde'), 1.3, false, 'Supertrend');
    if (ind.sar) addOverlay(ema14.map(v => ({ time: v.time, value: v.value * 0.998 })), f('sar', 'color', '#ffaf7a'), 1, true, 'SAR');
    if (ind.elderRay) {
      const map = new Map(ema14.map(v => [v.time, v.value]));
      const bull = data.filter(c => map.has(c.time)).map(c => ({ time: c.time, value: c.high - map.get(c.time) }));
      const bear = data.filter(c => map.has(c.time)).map(c => ({ time: c.time, value: c.low - map.get(c.time) }));
      addOsc(bull, f('elderRay', 'bullColor', '#5fff9d'), 'Elder Bull');
      addOsc(bear, f('elderRay', 'bearColor', '#ff9d9d'), 'Elder Bear');
    }
  }
  if (ind.rsi) addOsc(_rsi(data, getLen('rsi', 14)), f('rsi', 'color', '#a6ff4d'), 'RSI');
  if (ind.atr) addOsc(_atr(data, getLen('atr', 14)), f('atr', 'color', '#ffb86c'), 'ATR');
  if (ind.stdev) {
    const ma = _sma(data, 20);
    const maMap = new Map(ma.map(v => [v.time, v.value]));
    const st = data.filter(c => maMap.has(c.time)).map(c => ({ time: c.time, value: Math.abs(c.close - maMap.get(c.time)) }));
    addOsc(st, f('stdev', 'color', '#b2a3ff'), 'StdDev');
  }
  if (ind.stoch) {
    const stoch = _stochastic(data, getLen('stoch', 14), 3);
    addOsc(stoch.k, f('stoch', 'kColor', '#9ee8ff'), '%K');
    addOsc(stoch.d, f('stoch', 'dColor', '#ffd86b'), '%D');
  }
  if (ind.macd) {
    const m = _macd(data, f('macd', 'fastLen', 12), f('macd', 'slowLen', 26), f('macd', 'signalLen', 9));
    addOsc(m.line, f('macd', 'lineColor', '#8fd9ff'), 'MACD');
    addOsc(m.signal, f('macd', 'signalColor', '#ffcf8e'), 'Signal');
    if (m.hist?.length) addOscHist(m.hist);
  }
  const volOsc = _volumeOscillators(data);
  if (ind.obv) addOsc(volOsc.obv, f('obv', 'color', '#8cf9ff'), 'OBV');
  if (ind.adline) addOsc(volOsc.adline, f('adline', 'color', '#ffb7ff'), 'A/D');
  if (ind.cmf) addOsc(_cmf(data, getLen('cmf', 20)), f('cmf', 'color', '#f8ff87'), 'CMF');
  if (ind.williamsr) addOsc(_williamsR(data, getLen('williamsr', 14)), f('williamsr', 'color', '#ff9adf'), 'Williams %R');
  if (ind.cci) addOsc(_cci(data, getLen('cci', 20)), f('cci', 'color', '#b8ff8e'), 'CCI');
  if (ind.mfi) addOsc(_mfi(data, getLen('mfi', 14)), f('mfi', 'color', '#7bffd2'), 'MFI');
  if (ind.uo) addOsc(_ultimateOscillator(data), f('uo', 'color', '#ffd36f'), 'UO');
  if (ind.adx) {
    const dmi = _dmiAdx(data, getLen('adx', 14));
    addOsc(dmi.adx, f('adx', 'adxColor', '#9fd8ff'), 'ADX');
    addOsc(dmi.plusDi, f('adx', 'plusColor', '#73ffc0'), '+DI');
    addOsc(dmi.minusDi, f('adx', 'minusColor', '#ff9797'), '-DI');
  }
  if (ind.aroon) {
    const ar = _aroon(data, getLen('aroon', 14));
    addOsc(ar.up, f('aroon', 'upColor', '#6cffb0'), 'Aroon Up');
    addOsc(ar.down, f('aroon', 'downColor', '#ff8f8f'), 'Aroon Down');
  }
  if (ind.vortex) {
    const vtx = _vortex(data, getLen('vortex', 14));
    addOsc(vtx.plus.map(v => ({ time: v.time, value: v.value * 100 })), f('vortex', 'plusColor', '#d6a8ff'), 'VI+');
    addOsc(vtx.minus.map(v => ({ time: v.time, value: v.value * 100 })), f('vortex', 'minusColor', '#ffb0f3'), 'VI-');
  }
}

/**
 * Ichimoku's cloud (the shaded region between Senkou A/B) needs a genuine
 * fill bounded by two moving lines, which Lightweight Charts' built-in
 * series types can't draw on their own — so this paints it directly as an
 * SVG overlay on top of the chart's own host element, using the same
 * series.priceToCoordinate()/timeScale.timeToCoordinate() conversions the
 * chart itself uses, split into separate bullish/bearish-tinted polygons at
 * every Senkou A/B crossover (the traditional TradingView look).
 */
function _ensureIchimokuCloudSvg(host) {
  let svg = host.querySelector(':scope > svg.xpd-ichimoku-cloud-svg');
  if (!svg) {
    svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('class', 'xpd-ichimoku-cloud-svg');
    // Appended LAST (on top), not first — the chart's own layout.background
    // is a fully opaque solid fill, so placing this behind it (as an
    // earlier sibling) made the cloud completely invisible, painted over
    // before it ever reached the screen. Sitting on top with partial
    // opacity lets the candles/grid show through instead.
    host.appendChild(svg);
  }
  return svg;
}

function _removeIchimokuCloudSvg(host) {
  host?.querySelector(':scope > svg.xpd-ichimoku-cloud-svg')?.remove();
}

function _drawIchimokuCloud(chart, series, host, senkouA, senkouB) {
  if (!chart || !series || !host) return;
  const width = host.clientWidth || 0;
  const height = host.clientHeight || 0;
  if (!width || !height || !senkouA?.length || !senkouB?.length) return;

  const svg = _ensureIchimokuCloudSvg(host);
  svg.setAttribute('width', width);
  svg.setAttribute('height', height);
  svg.setAttribute('viewBox', `0 0 ${width} ${height}`);

  const ichCfg = dexSnapshot.indicatorSettings?.ichimoku || {};
  const bullColor = ichCfg.bullColor || '#46ffa0';
  const bearColor = ichCfg.bearColor || '#ff7878';
  const bMap = new Map(senkouB.map(p => [p.time, p.value]));
  const timeScale = chart.timeScale();

  const points = [];
  for (const pa of senkouA) {
    const bv = bMap.get(pa.time);
    if (bv == null) continue;
    const x = timeScale.timeToCoordinate(pa.time);
    const ya = series.priceToCoordinate(pa.value);
    const yb = series.priceToCoordinate(bv);
    if (x == null || ya == null || yb == null) continue;
    points.push({ x, ya, yb, bullish: pa.value >= bv });
  }

  let polys = '';
  let segStart = 0;
  for (let i = 1; i <= points.length; i += 1) {
    const boundary = i === points.length || points[i].bullish !== points[segStart].bullish;
    if (!boundary) continue;
    const seg = points.slice(segStart, i);
    if (seg.length >= 2) {
      const top = seg.map(p => `${p.x.toFixed(1)},${p.ya.toFixed(1)}`).join(' ');
      const bottom = seg.slice().reverse().map(p => `${p.x.toFixed(1)},${p.yb.toFixed(1)}`).join(' ');
      const fill = seg[0].bullish ? bullColor : bearColor;
      polys += `<polygon points="${top} ${bottom}" fill="${escHtml(fill)}" opacity="0.22" />`;
    }
    segStart = i;
  }
  svg.innerHTML = polys;
}

/** Called after every mount AND every fast-path data refresh so the cloud
 *  never lags behind the rest of the chart, and removed the moment the
 *  indicator gets turned off. */
function _syncIchimokuCloud(data, chart, series, host) {
  if (!dexSnapshot.indicators.ichimoku) {
    _removeIchimokuCloudSvg(host);
    _dexChartRuntime.ichimokuData = null;
    return;
  }
  const ichCfg = dexSnapshot.indicatorSettings?.ichimoku || {};
  const ich = _ichimoku(data, Number(ichCfg.tenkanLen) || 9, Number(ichCfg.kijunLen) || 26, Number(ichCfg.senkouBLen) || 52);
  _dexChartRuntime.ichimokuData = { senkouA: ich.senkouA, senkouB: ich.senkouB };
  _drawIchimokuCloud(chart, series, host, ich.senkouA, ich.senkouB);
}

/** The cloud SVG caches its width/height/point coordinates at draw time —
 *  a plain ResizeObserver/fullscreen resize changes the chart's canvas size
 *  without necessarily firing subscribeVisibleLogicalRangeChange (that's
 *  wired to pan/zoom, not layout), so without this the cloud silently goes
 *  stale and misaligned after any resize. Call after every host resize. */
function _refreshIchimokuCloudOnResize() {
  const d = _dexChartRuntime.ichimokuData;
  const host = document.getElementById('xpd-tv-widget');
  if (d && _dexChartRuntime.chart && _dexChartRuntime.activeSeries && host) {
    _drawIchimokuCloud(_dexChartRuntime.chart, _dexChartRuntime.activeSeries, host, d.senkouA, d.senkouB);
  }
}

async function _mountDexWidget() {
  const seq = ++_dexMountSeq;
  const el = document.getElementById('xpd-tv-widget');
  if (!el) return;
  // First-ever mount for this pair (nothing to show yet, so nothing else
  // fills the gap) can now take several seconds while full history pages
  // in from Coinbase/CoinGecko — without this the chart area just sits
  // completely blank, which reads as broken/stuck rather than loading.
  if (!_dexChartRuntime.chart) el.innerHTML = '<div class="xpd-loading">Loading full price history…</div>';
  try {
    if (dexSnapshot.threeEnabled) _mountChartAtmosphere();
    else _destroyChartAtmosphere();
    const raw = await _fetchDexBars();
    const data = _normalizeBars(raw);
    if (seq !== _dexMountSeq) return;
    if (!data.length) throw new Error('No chart bars returned for selected pair/timeframe.');
    _checkPriceAlerts(data);

    // This function reruns on almost every interaction anywhere on the page,
    // including a full pass on every ~5s live-ledger tick (see
    // _bindDexLiveListeners) — previously that meant tearing the whole chart
    // out and rebuilding it from scratch every few seconds, which is what
    // made it look like the chart kept disappearing and reappearing. When
    // nothing about the chart's own configuration changed since the last
    // mount, just refresh the data on the existing chart instead.
    const configKey = JSON.stringify({
      pair: dexSnapshot.pair,
      interval: dexSnapshot.interval,
      chartType: dexSnapshot.chartType,
      comparePair: dexSnapshot.comparePair,
      indicators: dexSnapshot.indicators,
      indicatorSettings: dexSnapshot.indicatorSettings,
      threeEnabled: dexSnapshot.threeEnabled,
    });
    // Compare-pair and freehand drawings aren't (yet) updated by the fast
    // path, so only skip it when either is in play — indicators ARE handled
    // below via _populateIndicatorSeries with update-in-place sinks.
    const fastPathEligible = !dexSnapshot.comparePair && !(dexSnapshot.drawings || []).length;

    if (fastPathEligible && _dexChartRuntime.chart && _dexChartRuntime.configKey === configKey) {
      const seriesData = dexSnapshot.chartType === 'heikin_ashi' ? _toHeikinAshi(data) : data;
      if (dexSnapshot.chartType === 'line' || dexSnapshot.chartType === 'area') {
        _dexChartRuntime.activeSeries.setData(seriesData.map(c => ({ time: c.time, value: c.close })));
      } else {
        _dexChartRuntime.activeSeries.setData(seriesData);
      }
      _dexChartRuntime.volumeSeries.setData(data.map(c => ({
        time: c.time,
        value: c.volume || 0,
        color: c.close >= c.open ? 'rgba(38,166,154,0.5)' : 'rgba(239,83,80,0.5)',
      })));

      // Re-run the exact same indicator computation in the exact same order
      // as the last full mount — since configKey (which includes indicators/
      // indicatorSettings) matched, the same series exist at the same
      // indexes, so this just refreshes their data instead of recreating them.
      let seriesIdx = 0;
      let priceLineIdx = 0;
      const newLegendItems = [];
      const updateOverlay = (points, color, lineWidth, dashed, label) => {
        const s = _dexChartRuntime.indicatorSeries[seriesIdx++];
        if (points?.length) {
          s?.setData(points);
          if (label && s) newLegendItems.push({ label, color, series: s, points });
        }
      };
      const updateOsc = (points, color, title) => {
        const s = _dexChartRuntime.indicatorSeries[seriesIdx++];
        if (points?.length) {
          s?.setData(points);
          if (title && s) newLegendItems.push({ label: title, color, series: s, points });
        }
      };
      const updateOscHist = (points) => {
        const s = _dexChartRuntime.indicatorSeries[seriesIdx++];
        if (points?.length) s?.setData(points.map(v => ({ time: v.time, value: v.value, color: v.value >= 0 ? 'rgba(99,255,157,0.45)' : 'rgba(255,126,126,0.45)' })));
      };
      const updatePriceLevel = (price) => {
        const line = _dexChartRuntime.indicatorPriceLines[priceLineIdx++];
        if (Number.isFinite(price)) line?.applyOptions({ price });
      };
      _populateIndicatorSeries(data, { addOverlay: updateOverlay, addOsc: updateOsc, addOscHist: updateOscHist, addPriceLevel: updatePriceLevel });
      _dexChartRuntime.indicatorLegendItems = newLegendItems;
      _syncIchimokuCloud(data, _dexChartRuntime.chart, _dexChartRuntime.activeSeries, el);
      _syncPriceAlertLines(_dexChartRuntime.activeSeries);

      const last = data[data.length - 1];
      _dexChartRuntime.renderLegend?.(last.open, last.high, last.low, last.close, last.volume);
      return;
    }

    if (!(await _ensureChartLibLoaded())) throw new Error('Chart library failed to load.');
    if (seq !== _dexMountSeq) return;

    const host = document.getElementById('xpd-tv-widget');
    if (!host || seq !== _dexMountSeq) return;

    // Remember the user's current zoom/pan before tearing the chart down —
    // this function reruns on a ~5s live-ledger timer, pair/interval
    // changes, etc., and always defaulting back to fitContent() would reset
    // anyone's zoom every few seconds even when nothing they care about
    // changed.
    let previousVisibleRange = null;
    try { previousVisibleRange = _dexChartRuntime.chart?.timeScale().getVisibleLogicalRange() || null; } catch {}

    _destroyDexChart();
    host.innerHTML = '';

    const LWC = window.LightweightCharts;
    const width = Math.max(320, host.clientWidth || host.parentElement?.clientWidth || 320);
    // Read the CSS-driven height instead of hardcoding it, since the container's
    // height now scales up on wider desktop viewports (see .xpd-tv-widget).
    const height = Math.max(360, host.clientHeight || 460);
    const lows = data.map(c => c.low);
    const highs = data.map(c => c.high);
    const priceDp = _chartPriceDecimals(data, Math.min(...lows), Math.max(...highs));
    const priceFormat = { type: 'price', precision: priceDp, minMove: Math.pow(10, -priceDp) };
    const upColor = '#26a69a';
    const downColor = '#ef5350';

    const chart = LWC.createChart(host, {
      width,
      height,
      layout: { background: { type: LWC.ColorType.Solid, color: '#131722' }, textColor: '#d1d4dc' },
      grid: {
        vertLines: { color: '#242832' },
        horzLines: { color: '#242832' },
      },
      rightPriceScale: { borderColor: 'rgba(197,203,206,0.3)' },
      leftPriceScale: { visible: false, borderColor: 'rgba(197,203,206,0.3)' },
      timeScale: { borderColor: 'rgba(197,203,206,0.3)', timeVisible: true, secondsVisible: false },
      crosshair: { mode: LWC.CrosshairMode.Normal },
      handleScroll: true,
      handleScale: true,
    });

    const seriesData = dexSnapshot.chartType === 'heikin_ashi' ? _toHeikinAshi(data) : data;
    let activeSeries;
    if (dexSnapshot.chartType === 'line') {
      activeSeries = chart.addLineSeries({ color: '#2962ff', lineWidth: 2, priceFormat });
      activeSeries.setData(seriesData.map(c => ({ time: c.time, value: c.close })));
    } else if (dexSnapshot.chartType === 'area') {
      activeSeries = chart.addAreaSeries({
        lineColor: '#2962ff', topColor: 'rgba(41,98,255,0.36)', bottomColor: 'rgba(41,98,255,0.04)', lineWidth: 2, priceFormat,
      });
      activeSeries.setData(seriesData.map(c => ({ time: c.time, value: c.close })));
    } else if (dexSnapshot.chartType === 'bars') {
      activeSeries = chart.addBarSeries({ upColor, downColor, priceFormat });
      activeSeries.setData(seriesData);
    } else {
      const hollow = dexSnapshot.chartType === 'hollow_candles';
      activeSeries = chart.addCandlestickSeries({
        upColor: hollow ? 'rgba(0,0,0,0)' : upColor,
        downColor,
        borderUpColor: upColor,
        borderDownColor: downColor,
        wickUpColor: upColor,
        wickDownColor: downColor,
        borderVisible: true,
        priceFormat,
      });
      activeSeries.setData(seriesData);
    }

    const volumeSeries = chart.addHistogramSeries({ priceFormat: { type: 'volume' }, priceScaleId: 'vol' });
    // Volume always keeps the bottom 15% of the pane; oscillators (below)
    // get a separate 17% band just above it so the two never visually
    // overlap (both used to share the exact same bottom slice).
    chart.priceScale('vol').applyOptions({ scaleMargins: { top: 0.85, bottom: 0 } });
    volumeSeries.setData(data.map(c => ({
      time: c.time,
      value: c.volume || 0,
      color: c.close >= c.open ? 'rgba(38,166,154,0.5)' : 'rgba(239,83,80,0.5)',
    })));

    // Hover legend — TradingView-style O/H/L/C/Vol readout that tracks the
    // crosshair, falling back to the latest bar when the mouse isn't over
    // the chart at all.
    const legendEl = document.createElement('div');
    legendEl.className = 'xpd-chart-legend';
    host.appendChild(legendEl);
    const fmtLegendPrice = v => Number.isFinite(v) ? v.toFixed(priceDp) : '—';
    // indicatorReadings: [{label, color, value}] for whatever's active RIGHT
    // NOW (read from _dexChartRuntime so it stays current across fast-path
    // refreshes and indicator add/remove, not just what existed when this
    // closure was first created).
    const renderLegend = (o, h, l, c, v, indicatorReadings) => {
      const up = c >= o;
      const indicatorHtml = (indicatorReadings || [])
        .map(r => `<span style="color:${escHtml(r.color)}">${escHtml(r.label)} <b>${fmtLegendPrice(r.value)}</b></span>`)
        .join('');
      legendEl.innerHTML = `
        <span>O <b>${fmtLegendPrice(o)}</b></span>
        <span>H <b>${fmtLegendPrice(h)}</b></span>
        <span>L <b>${fmtLegendPrice(l)}</b></span>
        <span class="${up ? 'xpd-legend-up' : 'xpd-legend-down'}">C <b>${fmtLegendPrice(c)}</b></span>
        ${v != null ? `<span>Vol <b>${_fmtCompact(v)}</b></span>` : ''}
        ${indicatorHtml}
      `;
    };
    const lastBar = seriesData[seriesData.length - 1];
    const lastVol = data[data.length - 1]?.volume;
    const showLastBar = () => {
      if (!lastBar) return;
      const o = lastBar.open ?? lastBar.value, h = lastBar.high ?? lastBar.value, l = lastBar.low ?? lastBar.value, c = lastBar.close ?? lastBar.value;
      const readings = (_dexChartRuntime.indicatorLegendItems || [])
        .map(item => ({ label: item.label, color: item.color, value: item.points?.[item.points.length - 1]?.value }))
        .filter(r => Number.isFinite(r.value));
      renderLegend(o, h, l, c, lastVol, readings);
    };
    showLastBar();
    chart.subscribeCrosshairMove((param) => {
      if (!param.time) { showLastBar(); return; }
      const bar = param.seriesData?.get(activeSeries);
      if (!bar) { showLastBar(); return; }
      const vol = param.seriesData?.get(volumeSeries);
      const o = bar.open ?? bar.value, h = bar.high ?? bar.value, l = bar.low ?? bar.value, c = bar.close ?? bar.value;
      const readings = (_dexChartRuntime.indicatorLegendItems || [])
        .map(item => ({ label: item.label, color: item.color, value: param.seriesData?.get(item.series)?.value }))
        .filter(r => Number.isFinite(r.value));
      renderLegend(o, h, l, c, vol?.value, readings);
    });

    let hasOsc = false;
    const ensureOscScale = () => {
      if (hasOsc) return;
      hasOsc = true;
      chart.priceScale('osc').applyOptions({ scaleMargins: { top: 0.65, bottom: 0.18 } });
    };

    const indicatorSeries = [];
    const indicatorPriceLines = [];
    const indicatorLegendItems = [];
    const addOverlay = (points, color, lineWidth = 1.2, dashed = false, label = '') => {
      if (!points?.length) return;
      const s = chart.addLineSeries({
        color, lineWidth, lineStyle: dashed ? LWC.LineStyle.Dashed : LWC.LineStyle.Solid,
        priceLineVisible: false, lastValueVisible: false,
      });
      s.setData(points);
      indicatorSeries.push(s);
      if (label) indicatorLegendItems.push({ label, color, series: s, points });
    };
    const addOsc = (points, color, title = '') => {
      if (!points?.length) return;
      ensureOscScale();
      const s = chart.addLineSeries({
        color, lineWidth: 1.2, priceScaleId: 'osc', title, priceLineVisible: false, lastValueVisible: false,
      });
      s.setData(points);
      indicatorSeries.push(s);
      if (title) indicatorLegendItems.push({ label: title, color, series: s, points });
    };
    const addOscHist = (points) => {
      if (!points?.length) return;
      ensureOscScale();
      const s = chart.addHistogramSeries({ priceScaleId: 'osc', priceLineVisible: false, lastValueVisible: false });
      s.setData(points.map(v => ({ time: v.time, value: v.value, color: v.value >= 0 ? 'rgba(99,255,157,0.45)' : 'rgba(255,126,126,0.45)' })));
      indicatorSeries.push(s);
    };
    const addPriceLevel = (price, color, title = '') => {
      if (!Number.isFinite(price)) return;
      indicatorPriceLines.push(activeSeries.createPriceLine({ price, color, lineWidth: 1, lineStyle: LWC.LineStyle.Dashed, axisLabelVisible: true, title }));
    };

    _populateIndicatorSeries(data, { addOverlay, addOsc, addOscHist, addPriceLevel });
    _syncIchimokuCloud(data, chart, activeSeries, host);
    chart.timeScale().subscribeVisibleLogicalRangeChange(_refreshIchimokuCloudOnResize);

    // Compare overlays as normalized "% change since the start of this view"
    // rather than raw price on a hidden scale — SOL's ~$75 plotted against
    // XRP's ~$1 on the same axis was meaningless, and the hidden scale still
    // left an orphaned last-value price tag floating with nothing to
    // reference. A visible left-hand % scale is what actually answers "which
    // moved more, in relative terms" — the point of comparing two assets.
    let compareSeries = null;
    if (dexSnapshot.comparePair) {
      const pair = DEX_PAIR_OPTIONS.find(p => p.id === dexSnapshot.comparePair);
      if (pair) {
        const cmp = _normalizeBars(await _fetchBarsByPair(pair, dexSnapshot.interval));
        if (seq === _dexMountSeq && cmp.length) {
          const base = cmp[0].close || 1;
          compareSeries = chart.addLineSeries({
            color: '#ffd166',
            lineWidth: 1.4,
            priceScaleId: 'left',
            priceLineVisible: false,
            lastValueVisible: true,
            priceFormat: { type: 'custom', formatter: v => `${v >= 0 ? '+' : ''}${v.toFixed(2)}%`, minMove: 0.01 },
          });
          chart.priceScale('left').applyOptions({ visible: true, borderColor: 'rgba(255,209,102,0.35)' });
          compareSeries.setData(cmp.map(c => ({ time: c.time, value: ((c.close / base) - 1) * 100 })));
        }
      }
    } else {
      chart.priceScale('left').applyOptions({ visible: false });
    }

    // The compare-pair fetch above is the last await before this mount
    // commits its chart/series to _dexChartRuntime — if a newer mount
    // (pair/interval/indicator change fired while this one was still
    // awaiting) has already finished and taken over the runtime state, this
    // stale mount must not clobber it (and would otherwise orphan the
    // newer chart's resizeObserver/WebGL handles with nothing left to
    // dispose them).
    if (seq !== _dexMountSeq) { try { chart.remove(); } catch {} return; }

    // Simple horizontal price-line drawing tool (advanced freeform tools were dropped in favor of the library's native primitive).
    const priceLines = (dexSnapshot.drawings || [])
      .filter(d => Number.isFinite(d?.price))
      .map(d => activeSeries.createPriceLine({ price: d.price, color: '#78e5ff', lineWidth: 2, lineStyle: LWC.LineStyle.Dashed, axisLabelVisible: true, title: 'Line' }));

    chart.subscribeClick((param) => {
      if (dexSnapshot.drawingTool !== 'hline' || !param.point) return;
      const price = activeSeries.coordinateToPrice(param.point.y);
      if (!Number.isFinite(price)) return;
      dexSnapshot.drawings = [...(dexSnapshot.drawings || []), { price }].slice(-50);
      priceLines.push(activeSeries.createPriceLine({ price, color: '#78e5ff', lineWidth: 2, lineStyle: LWC.LineStyle.Dashed, axisLabelVisible: true, title: 'Line' }));
    });

    if (previousVisibleRange && Number.isFinite(previousVisibleRange.from) && Number.isFinite(previousVisibleRange.to)) {
      try { chart.timeScale().setVisibleLogicalRange(previousVisibleRange); }
      catch { chart.timeScale().fitContent(); }
    } else {
      chart.timeScale().fitContent();
    }

    const resizeObserver = new ResizeObserver(() => {
      chart.applyOptions({ width: Math.max(320, host.clientWidth || 320) });
      _refreshIchimokuCloudOnResize();
    });
    resizeObserver.observe(host);

    _dexChartRuntime = {
      chart, volumeSeries, activeSeries, compareSeries, indicatorSeries, indicatorPriceLines, priceLines, resizeObserver,
      chartType: dexSnapshot.chartType,
      configKey,
      legendEl,
      renderLegend,
      indicatorLegendItems,
      alertPriceLines: [],
    };
    _syncPriceAlertLines(activeSeries);
  } catch (err) {
    if (seq !== _dexMountSeq) return;
    dexSnapshot.error = err?.message || 'Could not initialize chart widget.';
    // renderProfilePage() (and therefore this remount) fires on almost any
    // interaction anywhere on the page — wallet refreshes, NFT reloads, tab
    // switches — not just chart changes. If a chart is already mounted and
    // this failure happened before we tore it down (e.g. a transient
    // network/rate-limit hiccup on the re-fetch), leave the working chart
    // alone and just warn instead of wiping a perfectly good chart out to
    // an error box on every unrelated click.
    if (_dexChartRuntime.chart) {
      toastWarn(dexSnapshot.error);
      return;
    }
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
  _persistChartViewState();
  renderProfilePage();
}

export async function setDexInterval(interval) {
  dexSnapshot.interval = interval;
  await _fetchDexStats();
  _persistChartViewState();
  renderProfilePage();
}

export function setDexChartType(chartType) {
  dexSnapshot.chartType = chartType;
  _persistChartViewState();
  renderProfilePage();
}

export async function refreshDexChart() {
  await _fetchDexStats();
  renderProfilePage();
}

export function toggleIndicator(key, enabled) {
  if (!(key in dexSnapshot.indicators)) return;
  dexSnapshot.indicators[key] = !!enabled;
  if (enabled) {
    dexSnapshot.selectedIndicator = key;
    dexSnapshot.selectedEducationTab = 'indicator';
  }
  _persistChartViewState();
  renderProfilePage();
}

export function toggleIndicatorMenu() {
  dexSnapshot.indicatorMenuOpen = !dexSnapshot.indicatorMenuOpen;
  renderProfilePage();
}

export function toggleChartMoreMenu() {
  dexSnapshot.moreMenuOpen = !dexSnapshot.moreMenuOpen;
  renderProfilePage();
}

export function setIndicatorQuery(value) {
  dexSnapshot.indicatorQuery = String(value || '');
  if (!dexSnapshot.indicatorMenuOpen) dexSnapshot.indicatorMenuOpen = true;
  renderProfilePage();
}

export function addIndicatorFromMenu(indicatorKey) {
  const key = String(indicatorKey || '').trim();
  if (!(key in dexSnapshot.indicators)) return;
  dexSnapshot.indicators[key] = true;
  dexSnapshot.selectedIndicator = key;
  dexSnapshot.selectedEducationTab = 'indicator';
  _persistChartViewState();
  renderProfilePage();
}

export function removeIndicator(indicatorKey) {
  const key = String(indicatorKey || '').trim();
  if (!(key in dexSnapshot.indicators)) return;
  dexSnapshot.indicators[key] = false;
  _persistChartViewState();
  renderProfilePage();
}

function _renderIndicatorSettingsPopover(key) {
  if (dexSnapshot.settingsOpenFor !== key) return '';
  const cfg = dexSnapshot.indicatorSettings[key] || {};
  const fields = INDICATOR_FIELD_SCHEMA[key] || [];
  return `
    <div class="xpd-indicator-settings" role="dialog" aria-label="${escHtml(INDICATOR_META[key]?.name || key)} settings">
      <div class="xpd-indicator-settings-title">${escHtml(INDICATOR_META[key]?.name || key)} settings</div>
      ${fields.map(field => {
        const value = cfg[field.id] ?? field.default;
        if (field.type === 'number') {
          return `
            <label class="xpd-indicator-settings-field">
              <span>${escHtml(field.label)}</span>
              <input id="xpd-ind-${field.id}-${key}" class="xpd-input" type="number" min="2" max="500" value="${value}" />
            </label>`;
        }
        return `
          <label class="xpd-indicator-settings-field">
            <span>${escHtml(field.label)}</span>
            <input id="xpd-ind-${field.id}-${key}" class="xpd-indicator-color-input" type="color" value="${value}" />
          </label>`;
      }).join('')}
      ${!fields.length ? '<div class="xpd-note">This indicator has no adjustable settings yet.</div>' : ''}
      <div class="xpd-indicator-settings-actions">
        <button class="xpd-mini-btn" onclick="resetIndicatorSettings('${key}')">Reset</button>
        <button class="xpd-mini-btn" onclick="closeIndicatorSettings()">Cancel</button>
        <button class="xpd-action xpd-action--primary" onclick="applyIndicatorSettings('${key}')">Save</button>
      </div>
    </div>`;
}

export function openIndicatorSettings(indicatorKey) {
  const key = String(indicatorKey || '').trim();
  if (!(key in dexSnapshot.indicators)) return;
  dexSnapshot.settingsOpenFor = dexSnapshot.settingsOpenFor === key ? null : key;
  renderProfilePage();
}

export function closeIndicatorSettings() {
  dexSnapshot.settingsOpenFor = null;
  renderProfilePage();
}

export function applyIndicatorSettings(indicatorKey) {
  const key = String(indicatorKey || '').trim();
  if (!(key in dexSnapshot.indicators)) return;
  const cfg = dexSnapshot.indicatorSettings[key] || {};
  const next = { ...cfg };
  for (const field of INDICATOR_FIELD_SCHEMA[key] || []) {
    const el = document.getElementById(`xpd-ind-${field.id}-${key}`);
    if (!el) continue;
    if (field.type === 'number') {
      next[field.id] = Math.max(2, Math.min(500, Number(el.value) || cfg[field.id] || field.default));
    } else {
      next[field.id] = el.value;
    }
  }
  dexSnapshot.indicatorSettings[key] = next;
  dexSnapshot.settingsOpenFor = null;
  renderProfilePage();
}

export function resetIndicatorSettings(indicatorKey) {
  const key = String(indicatorKey || '').trim();
  delete dexSnapshot.indicatorSettings[key];
  dexSnapshot.settingsOpenFor = null;
  renderProfilePage();
}

export function copyChartLink() {
  _persistChartViewState();
  copyToClipboard(window.location.href);
  toastInfo('Chart link copied.');
}

export function toggleThreeEffects() {
  dexSnapshot.threeEnabled = !dexSnapshot.threeEnabled;
  safeSet(LS_3D_EFFECTS, dexSnapshot.threeEnabled ? '1' : '0');
  if (!dexSnapshot.threeEnabled) _destroyChartAtmosphere();
  renderProfilePage();
}

export function setThreeEffects(enabled) {
  const next = !!enabled;
  if (dexSnapshot.threeEnabled === next) return;
  dexSnapshot.threeEnabled = next;
  safeSet(LS_3D_EFFECTS, dexSnapshot.threeEnabled ? '1' : '0');
  if (!dexSnapshot.threeEnabled) _destroyChartAtmosphere();
  renderProfilePage();
}

export function setComparePair(pairId) {
  dexSnapshot.comparePair = pairId || '';
  _persistChartViewState();
  renderProfilePage();
}

export function setIndicatorFromDropdown(indicatorKey) {
  const key = String(indicatorKey || '').trim();
  if (!key || !(key in dexSnapshot.indicators)) return;
  dexSnapshot.indicators[key] = true;
  dexSnapshot.selectedIndicator = key;
  renderProfilePage();
}

export function setDrawingTool(tool) {
  const key = String(tool || 'none');
  if (!DRAW_TOOL_OPTIONS.some(o => o.key === key)) return;
  dexSnapshot.drawingTool = key;
  dexSnapshot.educationHint = DRAWING_EDU_HINTS[key] || '';
  renderProfilePage();
}

// What's actually rendered on the chart right now — chartMeta.tokenKey
// already resolves to the drilled-into wallet token when one is focused, or
// else the selected DEX pair's own symbol (see _fetchDexBars). Alerts key
// off this instead of dexSnapshot.pair so an alert set while a token is
// focused stays attached to that token rather than silently reattaching to
// whatever the pair dropdown happens to say.
function _alertScopeKey() {
  return dexSnapshot.chartMeta?.tokenKey || dexSnapshot.tokenFocusKey || `${_currentPairOption().symbol || 'XRP'}|`;
}

export function addPriceAlert() {
  const current = Number(dexSnapshot.chartMeta?.last);
  const input = prompt(`Alert me when ${dexSnapshot.chartMeta?.symbol || 'price'} crosses:`, Number.isFinite(current) ? current.toFixed(6) : '');
  if (input == null) return;
  const price = Number(input);
  if (!Number.isFinite(price) || price <= 0) { toastWarn('Enter a valid price.'); return; }
  dexSnapshot.alerts = [...(dexSnapshot.alerts || []), {
    id: `alert_${Date.now()}`,
    tokenKey: _alertScopeKey(),
    price,
    createdAt: new Date().toISOString(),
  }];
  _saveAlerts();
  renderProfilePage();
  toastInfo(`Alert set at $${fmt(price, 6)}`);
}

export function removePriceAlert(id) {
  dexSnapshot.alerts = (dexSnapshot.alerts || []).filter(a => a.id !== id);
  _saveAlerts();
  renderProfilePage();
}

/** Draws a dotted line + axis tag for every alert on whatever's currently
 *  focused (see _alertScopeKey) — called from both the full-mount and
 *  fast-path so it always reflects dexSnapshot.alerts even though alerts
 *  aren't part of configKey (adding/removing one already goes through a
 *  full renderProfilePage()). */
function _syncPriceAlertLines(series) {
  if (!series) return;
  const LWC = window.LightweightCharts;
  for (const line of _dexChartRuntime.alertPriceLines || []) {
    try { series.removePriceLine(line); } catch {}
  }
  const matching = (dexSnapshot.alerts || []).filter(a => a.tokenKey === _alertScopeKey());
  _dexChartRuntime.alertPriceLines = matching.map(a => series.createPriceLine({
    price: a.price,
    color: '#ffb703',
    lineWidth: 2,
    lineStyle: LWC?.LineStyle?.Dotted ?? 2,
    axisLabelVisible: true,
    title: '🔔 Alert',
  }));
}

/** Fires once per real crossover (not just "currently above/below") and
 *  removes the alert afterward — a one-shot notification, same mental model
 *  as most price-alert features. Checked on every fresh candle fetch for
 *  whichever token/pair is on-screen. */
function _checkPriceAlerts(data) {
  if (data.length < 2) return;
  const scopeKey = _alertScopeKey();
  const matching = (dexSnapshot.alerts || []).filter(a => a.tokenKey === scopeKey);
  if (!matching.length) return;
  const prev = data[data.length - 2].close;
  const curr = data[data.length - 1].close;
  const stillActive = [];
  let triggeredAny = false;
  for (const a of matching) {
    const crossedUp = prev < a.price && curr >= a.price;
    const crossedDown = prev > a.price && curr <= a.price;
    if (crossedUp || crossedDown) {
      toastInfo(`🔔 ${dexSnapshot.chartMeta?.symbol || 'Price'} crossed $${fmt(a.price, 6)} (${crossedUp ? '↑' : '↓'} now $${fmt(curr, 6)})`);
      triggeredAny = true;
      // _checkPriceAlerts runs from inside _mountDexWidget (itself called
      // from renderProfilePage()), so a full renderProfilePage() here would
      // re-enter and re-fetch on every ledger tick. Drop the fired alert's
      // chip directly instead of waiting for the next natural re-render.
      document.querySelector(`.xpd-indicator-chip[data-alert-id="${a.id}"]`)?.remove();
    } else {
      stillActive.push(a);
    }
  }
  if (triggeredAny) {
    dexSnapshot.alerts = [...(dexSnapshot.alerts || []).filter(a => a.tokenKey !== scopeKey), ...stillActive];
    _saveAlerts();
  }
}

export function clearAllDrawings() {
  const series = _dexChartRuntime.activeSeries;
  if (series) {
    for (const line of _dexChartRuntime.priceLines || []) {
      try { series.removePriceLine(line); } catch {}
    }
  }
  _dexChartRuntime.priceLines = [];
  dexSnapshot.drawings = [];
}

function _rescaleChartLogicalRange(scaleFactor, shiftFraction = 0) {
  const ts = _dexChartRuntime.chart?.timeScale();
  if (!ts) return;
  const r = ts.getVisibleLogicalRange();
  if (!r) return;
  const span = (r.to - r.from) * scaleFactor;
  const mid = ((r.to + r.from) / 2) + ((r.to - r.from) * shiftFraction);
  ts.setVisibleLogicalRange({ from: mid - span / 2, to: mid + span / 2 });
}

export function zoomChartIn() {
  _rescaleChartLogicalRange(0.8);
}

export function zoomChartOut() {
  _rescaleChartLogicalRange(1.25);
}

export function panChartLeft() {
  _rescaleChartLogicalRange(1, -0.2);
}

export function panChartRight() {
  _rescaleChartLogicalRange(1, 0.2);
}

export function resetChartView() {
  _dexChartRuntime.chart?.timeScale().fitContent();
}

export function toggleEducationPanel() {
  dexSnapshot.educationCollapsed = !dexSnapshot.educationCollapsed;
  renderProfilePage();
}

export function selectEducationTab(tab) {
  if (!['indicator', 'psychology', 'practice'].includes(tab)) return;
  dexSnapshot.selectedEducationTab = tab;
  renderProfilePage();
}

export function toggleTerminalTheme() {
  const light = document.body.classList.contains('theme-gold');
  setTheme(light ? 'cosmic' : 'gold');
  renderProfilePage();
}

let _chartFullscreenListenerBound = false;

function _resizeChartToHost() {
  const host = document.getElementById('xpd-tv-widget');
  if (host && _dexChartRuntime.chart) {
    _dexChartRuntime.chart.applyOptions({ width: Math.max(320, host.clientWidth || 320), height: Math.max(320, host.clientHeight || 460) });
    _refreshIchimokuCloudOnResize();
  }
}

export function toggleChartFullscreen() {
  const wrap = document.querySelector('.xpd-chart-wrap');
  if (!wrap) return;
  if (!_chartFullscreenListenerBound) {
    _chartFullscreenListenerBound = true;
    document.addEventListener('fullscreenchange', () => {
      // Two rAFs: the fullscreen transition (and the :fullscreen CSS it triggers)
      // hasn't necessarily finished laying out on the same tick the event fires.
      requestAnimationFrame(() => requestAnimationFrame(_resizeChartToHost));
    });
  }
  if (document.fullscreenElement) document.exitFullscreen();
  else wrap.requestFullscreen?.();
}

export function exportChartPng() {
  const chart = _dexChartRuntime.chart;
  if (!chart) { toastWarn('Chart image is not ready yet.'); return; }
  const canvas = chart.takeScreenshot();
  const a = document.createElement('a');
  a.download = `xrpl-chart-${Date.now()}.png`;
  a.href = canvas.toDataURL('image/png');
  a.click();
}

// Keyed per-symbol (by token-direct focus key when one's active, otherwise
// the DEX pair id) so saving a layout for one token doesn't clobber
// whatever was already saved for another — switching from XRP to SOL and
// hitting "Save Layout" used to silently overwrite the XRP preset.
function _chartLayoutKey() {
  return dexSnapshot.tokenFocusKey || dexSnapshot.pair || 'default';
}

export function saveChartLayoutPreset() {
  const all = safeJson(safeGet(LS_CHART_LAYOUT)) || {};
  const key = _chartLayoutKey();
  all[key] = {
    interval: dexSnapshot.interval,
    chartType: dexSnapshot.chartType,
    comparePair: dexSnapshot.comparePair,
    indicators: dexSnapshot.indicators,
    indicatorSettings: dexSnapshot.indicatorSettings,
  };
  safeSet(LS_CHART_LAYOUT, JSON.stringify(all));
  toastInfo(`Chart layout saved for ${dexSnapshot.chartMeta?.symbol || key}.`);
}

export function loadChartLayoutPreset() {
  const all = safeJson(safeGet(LS_CHART_LAYOUT)) || {};
  const key = _chartLayoutKey();
  const saved = all[key];
  if (!saved) { toastWarn(`No saved layout for ${dexSnapshot.chartMeta?.symbol || key} yet.`); return; }
  dexSnapshot.interval = saved.interval || dexSnapshot.interval;
  dexSnapshot.chartType = saved.chartType || dexSnapshot.chartType;
  dexSnapshot.comparePair = saved.comparePair || '';
  dexSnapshot.indicators = { ...dexSnapshot.indicators, ...(saved.indicators || {}) };
  dexSnapshot.indicatorSettings = { ...dexSnapshot.indicatorSettings, ...(saved.indicatorSettings || {}) };
  _persistChartViewState();
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

/** Security-relevant — do not replace with plain encodeURIComponent().
 *  Token rows embed a token key inside onclick="fn(decodeURIComponent('${...}'))",
 *  a single-quoted JS string literal in an HTML attribute. encodeURIComponent()
 *  deliberately leaves ' ( ) ! ~ * unescaped (RFC 3986 "unreserved" set) — it's
 *  a URI-safety encoder, not a JS-string-literal-safety encoder, and those are
 *  different threat models. A raw ' in its output terminates the surrounding
 *  string literal early, and token symbol/name are NOT trustworthy: for any
 *  40-hex-digit XRPL currency code, _normalizeTokenCode() hex-decodes it into
 *  arbitrary UTF-8 text via TextDecoder — anyone can issue a token whose
 *  currency code decodes to text containing a ' followed by arbitrary
 *  executable JS, built entirely from encodeURIComponent-safe characters
 *  (letters, digits, '.', '(', ')'), and have it picked up by the public
 *  token registries this app pulls from. Manually escaping the one
 *  unreserved-but-breakout-capable character (') to its percent-encoded form
 *  closes that gap; decodeURIComponent() on the receiving end still decodes
 *  %27 back to ' correctly, so this is a transparent drop-in replacement. */
function _encodeForInlineHandler(str) {
  return encodeURIComponent(str).replace(/'/g, '%27');
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

function _tokenFromCoinGeckoRow(row) {
  const symbol = _normalizeTokenCode(row?.symbol || '');
  const name = String(row?.name || symbol || 'Unknown Token');
  const price = Number(row?.current_price || 0);
  const marketCap = Number(row?.market_cap || 0);
  const volume24h = Number(row?.total_volume || 0);
  const change24h = Number(row?.price_change_percentage_24h || 0);
  return {
    symbol,
    name,
    issuer: '',
    tokenId: `cg:${row?.id || symbol}`,
    price: Number.isFinite(price) && price > 0 ? price : null,
    marketCap: Number.isFinite(marketCap) && marketCap > 0 ? marketCap : null,
    volume24h: Number.isFinite(volume24h) && volume24h > 0 ? volume24h : null,
    holders: null,
    change24h: Number.isFinite(change24h) ? change24h : null,
    verified: false,
    score: null,
  };
}

function _tokenFromBithompRow(row) {
  const symbol = _normalizeTokenCode(row?.currency || row?.token || '');
  const issuer = String(row?.issuer || row?.account || '').trim();
  const name = String(row?.name || symbol || 'Unknown Token');
  const price = Number(row?.price || row?.market?.price || 0);
  const marketCap = Number(row?.marketcap || row?.marketCap || 0);
  const volume24h = Number(row?.volume24h || row?.volume || 0);
  return {
    symbol,
    name,
    issuer,
    tokenId: `bithomp:${symbol}.${issuer || 'na'}`,
    price: Number.isFinite(price) && price > 0 ? price : null,
    marketCap: Number.isFinite(marketCap) && marketCap > 0 ? marketCap : null,
    volume24h: Number.isFinite(volume24h) && volume24h > 0 ? volume24h : null,
    holders: Number.isFinite(Number(row?.holders || 0)) ? Number(row?.holders || 0) : null,
    change24h: Number.isFinite(Number(row?.change24h || 0)) ? Number(row?.change24h || 0) : null,
    verified: !!row?.verified,
    score: null,
  };
}

function _tokenFromXrplToRow(row) {
  const symbol = _normalizeTokenCode(row?.symbol || row?.currency || '');
  const issuer = String(row?.issuer || row?.issuerAddress || '').trim();
  const name = String(row?.name || symbol || 'Unknown Token');
  const price = Number(row?.price || 0);
  const volume24h = Number(row?.volume24h || 0);
  return {
    symbol,
    name,
    issuer,
    tokenId: `xrplto:${symbol}.${issuer || 'na'}`,
    price: Number.isFinite(price) && price > 0 ? price : null,
    marketCap: Number.isFinite(Number(row?.marketCap || 0)) ? Number(row?.marketCap || 0) : null,
    volume24h: Number.isFinite(volume24h) && volume24h > 0 ? volume24h : null,
    holders: Number.isFinite(Number(row?.holders || 0)) ? Number(row?.holders || 0) : null,
    change24h: Number.isFinite(Number(row?.change24h || 0)) ? Number(row?.change24h || 0) : null,
    verified: !!row?.verified,
    score: null,
  };
}

async function _loadTokenDiscoveryData() {
  if (!_isProfilePageActive()) return;
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
    const maxPages = 12;
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

    const sourceJobs = [
      _fetchJson(`${COINGECKO_MARKETS_URL}?vs_currency=usd&order=market_cap_desc&per_page=250&page=1&sparkline=false`, { timeoutMs: 12000 }).catch(() => []),
      Date.now() < (_tokenSourceCooldownUntil.xrplto || 0)
        ? Promise.resolve([])
        : _fetchJson(XRPL_TO_TOKENS_URL, { timeoutMs: 12000, allowProxy: false }).catch((err) => {
          const msg = String(err?.message || '');
          if (msg.includes('429')) _tokenSourceCooldownUntil.xrplto = Date.now() + (5 * 60 * 1000);
          return [];
        }),
    ];
    if (ENABLE_BITHOMP_SOURCE) {
      sourceJobs.push(_fetchJson(BITHOMP_TOKENS_URL, { timeoutMs: 12000, allowProxy: false }).catch(() => []));
    }
    const [cgRows, xrplToRows, btRows = []] = await Promise.all(sourceJobs);

    const cgTokens = Array.isArray(cgRows) ? cgRows.map(_tokenFromCoinGeckoRow).filter(t => !!t.symbol) : [];
    const btTokens = Array.isArray(btRows) ? btRows.map(_tokenFromBithompRow).filter(t => !!t.symbol) : [];
    const xrplToTokens = Array.isArray(xrplToRows) ? xrplToRows.map(_tokenFromXrplToRow).filter(t => !!t.symbol) : [];

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
    [xrpNative, ...parsed, ...btTokens, ...xrplToTokens, ...cgTokens].forEach(t => {
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
  const f = tokenDiscoverySnapshot.filters || { type: 'all', minCap: 0, minVol: 0, hasDex: false };
  return tokens.filter(t => {
    if (q && !`${t.symbol} ${t.name} ${t.issuer} ${t.tokenId || ''}`.toLowerCase().includes(q)) return false;
    if (Number(f.minCap || 0) > 0 && Number(t.marketCap || 0) < Number(f.minCap || 0)) return false;
    if (Number(f.minVol || 0) > 0 && Number(t.volume24h || 0) < Number(f.minVol || 0)) return false;
    if (f.hasDex && !(Number(t.volume24h || 0) > 0 || Number(t.holders || 0) > 100)) return false;
    if (f.type && f.type !== 'all') {
      const sym = String(t.symbol || '').toLowerCase();
      const nm = String(t.name || '').toLowerCase();
      const isStable = /usd|usdc|usdt|rlusd|eur|gbp/.test(sym) || /stable/.test(nm);
      const isMeme = /meme|dog|cat|frog|shib|pepe/.test(sym) || /meme/.test(nm);
      const isMpt = /mpt/.test(sym) || /multi-purpose/.test(nm);
      if (f.type === 'stablecoin' && !isStable) return false;
      if (f.type === 'meme' && !isMeme) return false;
      if (f.type === 'mpt' && !isMpt) return false;
      if (f.type === 'standard' && (isStable || isMeme || isMpt)) return false;
    }
    return true;
  });
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
  if (_tokenSearchDebounce) clearTimeout(_tokenSearchDebounce);
  _tokenSearchDebounce = setTimeout(() => {
    tokenDiscoverySnapshot.listLimit = 240;
    tokenDiscoverySnapshot.filtered = _filterTokens(tokenDiscoverySnapshot.query, tokenDiscoverySnapshot.tokens);
    renderProfilePage();
  }, 300);
}

export function setTokenFilter(field, value) {
  tokenDiscoverySnapshot.filters = { ...tokenDiscoverySnapshot.filters, [field]: value };
  tokenDiscoverySnapshot.listLimit = 240;
  tokenDiscoverySnapshot.filtered = _filterTokens(tokenDiscoverySnapshot.query, tokenDiscoverySnapshot.tokens);
  renderProfilePage();
}

/** One-shot reset for the "no tokens match" empty state's recovery button —
 *  same effect as clearing the search box and every filter individually, but
 *  as a single state update + render instead of five. */
export function clearTokenFilters() {
  if (_tokenSearchDebounce) clearTimeout(_tokenSearchDebounce);
  tokenDiscoverySnapshot.query = '';
  tokenDiscoverySnapshot.filters = { type: 'all', minCap: 0, minVol: 0, hasDex: false };
  tokenDiscoverySnapshot.listLimit = 240;
  tokenDiscoverySnapshot.filtered = _filterTokens('', tokenDiscoverySnapshot.tokens);
  renderProfilePage();
}

export function showMoreIssuedTokens() {
  tokenDiscoverySnapshot.listLimit = Math.min(5000, Number(tokenDiscoverySnapshot.listLimit || 240) + 240);
  renderProfilePage();
}

export function showAllIssuedTokens() {
  const list = tokenDiscoverySnapshot.filtered; // see the comment in _renderTokenDiscoverySection
  tokenDiscoverySnapshot.listLimit = Math.min(5000, Math.max(240, list.length));
  renderProfilePage();
}

export function resetIssuedTokenLimit() {
  tokenDiscoverySnapshot.listLimit = 240;
  renderProfilePage();
}

export function selectTokenDetails(tokenKey) {
  tokenDiscoverySnapshot.selectedTokenKey = tokenKey || '';
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

export async function openTokenOnChart(tokenKeyOrSymbol) {
  const raw = String(tokenKeyOrSymbol || '').trim();
  if (!raw) return;
  const symbol = String(raw.includes('|') ? raw.split('|')[0] : raw).toUpperCase();
  const resolvedToken = raw.includes('|')
    ? tokenDiscoverySnapshot.tokens.find(t => _tokenKey(t) === raw)
    : tokenDiscoverySnapshot.tokens.find(t => String(t.symbol || '').toUpperCase() === String(symbol || '').toUpperCase());
  tokenDiscoverySnapshot.selectedTokenKey = resolvedToken ? _tokenKey(resolvedToken) : (raw.includes('|') ? raw : tokenDiscoverySnapshot.selectedTokenKey);
  dexSnapshot.tokenFocusKey = tokenDiscoverySnapshot.selectedTokenKey || raw;
  // Only BTC/ETH/SOL have their own dedicated DEX_PAIR_OPTIONS entry with a
  // reliable direct Coinbase feed — for every other token (the other 700+ in
  // Token Discovery, including well-known ones like SOLO/CORE/RLUSD) XRP/USD
  // is just the reference base _fetchDexBars uses for live-candle patching
  // and proxy-scaling. It is NOT a claim that this token has no market: the
  // token-focus mechanism (_fetchBarsForFocusedToken, driven by
  // dexSnapshot.tokenFocusKey above) independently tries a real OnTheDex/
  // Coinbase market for THIS token regardless of what pair is selected here.
  // This used to preemptively toast "No direct pair — showing XRP chart" for
  // every one of those 700+ tokens before that fetch even ran, which read as
  // "this app can't show your token" even when it was about to succeed.
  const directPairSymbols = { BTC: 'BINANCE:BTCUSDT', ETH: 'BINANCE:ETHUSDT', SOL: 'BINANCE:SOLUSDT' };
  dexSnapshot.pair = directPairSymbols[symbol] || 'BITSTAMP:XRPUSD';

  // Show token focus and move user to chart immediately, then refresh market stats.
  _persistChartViewState();
  renderProfilePage();
  setTimeout(() => _scrollToChartSection(), 20);

  await _fetchDexStats();
  _persistChartViewState();
  renderProfilePage();
}

export async function loadToken(tokenSymbol) {
  return openTokenOnChart(tokenSymbol);
}

export async function refreshTokenDiscovery() {
  await _loadTokenDiscoveryData();
  renderProfilePage();
}

/**
 * Loads ANY XRPL issued asset directly by currency code + issuer address —
 * bypassing the pre-loaded token discovery registry entirely (that list is
 * capped to whatever the registry source returns, so brand-new or obscure
 * issued currencies never show up in the search box above). The chart's own
 * data path already supports any currency+issuer pair via OnTheDex
 * (_fetchBarsForFocusedToken), so this just needs a token record the normal
 * chart-focus resolution can find.
 */
export async function lookupIssuedAsset() {
  const currencyEl = document.getElementById('xpd-lookup-currency');
  const issuerEl = document.getElementById('xpd-lookup-issuer');
  const currency = String(currencyEl?.value || '').trim().toUpperCase();
  const issuer = String(issuerEl?.value || '').trim();

  if (!currency) { toastWarn('Enter a currency code first.'); return; }
  if (!issuer || !isValidXrpAddress(issuer)) { toastWarn('Enter a valid XRPL issuer address.'); return; }

  const key = `${currency}|${issuer}`;
  let token = tokenDiscoverySnapshot.tokens.find(t => _tokenKey(t) === key);
  if (!token) {
    token = { symbol: currency, name: currency, issuer, price: null, marketCap: null, volume24h: null, holders: null, tokenId: '' };
    tokenDiscoverySnapshot.tokens = [...tokenDiscoverySnapshot.tokens, token];
    // Every other assignment to .tokens immediately recomputes .filtered from
    // it — this was the one path that didn't, which is what let the search
    // list's "filtered.length ? filtered : tokens" fallback below seem
    // necessary. Keeping this in sync lets that fallback be removed outright.
    tokenDiscoverySnapshot.filtered = _filterTokens(tokenDiscoverySnapshot.query, tokenDiscoverySnapshot.tokens);
  }
  tokenDiscoverySnapshot.selectedTokenKey = key;
  if (currencyEl) currencyEl.value = '';
  if (issuerEl) issuerEl.value = '';
  await openTokenOnChart(key);
}

/** One-stop path for someone who already knows the currency+issuer they
 *  want to analyze and doesn't want to search the token registry, pick it
 *  from a list, then dig for a small button in a sub-panel first — the
 *  path this used to require. Reuses lookupIssuedAsset()'s validation/
 *  registration rather than duplicating it; the field values are read here
 *  first since lookupIssuedAsset() clears them as one of its side effects. */
export async function lookupAndAnalyzeProject() {
  const currency = String(document.getElementById('xpd-lookup-currency')?.value || '').trim().toUpperCase();
  const issuer = String(document.getElementById('xpd-lookup-issuer')?.value || '').trim();
  if (!currency) { toastWarn('Enter a currency code first.'); return; }
  if (!issuer || !isValidXrpAddress(issuer)) { toastWarn('Enter a valid XRPL issuer address.'); return; }
  const key = `${currency}|${issuer}`;
  await lookupIssuedAsset();
  await openProjectIntel(key);
}

export async function refreshRecentTransactions() {
  const address = getActiveWallet()?.address || '';
  await _loadRecentTransactionsData(address);
  renderProfilePage();
}

export async function refreshXrplDashboard({ silent = false, force = false } = {}) {
  if (!force && !_isProfilePageActive()) return;
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
  }, () => {
    // Only reachable if the undo window passed without being used — deleting
    // it immediately in deleteWallet() would wipe the balance-history
    // sparkline the moment someone hits Undo. Without this at all, though,
    // nalulf_balhist_<address> outlives the wallet forever: nothing else
    // ever removes it, so every wallet a user creates-then-deletes leaves a
    // permanent orphaned localStorage entry behind.
    if (w.address) safeRemove(LS_BAL_HIST_PFX + w.address);
  });
}

function _showUndoToast(msg, onUndo, onExpire) {
  const ex = document.getElementById('undo-toast'); if (ex) ex.remove();
  const t  = document.createElement('div'); t.id = 'undo-toast'; t.className = 'undo-toast';
  t.innerHTML = `<span class="undo-msg">${escHtml(msg)}</span><button class="undo-btn">Undo</button>`;
  document.body.appendChild(t);
  requestAnimationFrame(() => t.classList.add('show'));
  const timer = setTimeout(() => { t.classList.remove('show'); setTimeout(()=>t.remove(),300); onExpire?.(); }, 5000);
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
  // See the identical comment in removeTrustline() — prompt() returning
  // null (Cancel/Esc) vs '' (OK, left blank) used to be indistinguishable
  // by the time it reached signAndSubmit, so clicking Cancel here silently
  // led to a second, different-looking prompt instead of aborting.
  if (seed === null) return;
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
      <div style="margin-top:16px"><div class="settings-label">3D immersive background</div>
        <div class="settings-seg">
          <button class="settings-seg-btn ${dexSnapshot.threeEnabled?'active':''}" onclick="setThreeEffects(true)">On</button>
          <button class="settings-seg-btn ${!dexSnapshot.threeEnabled?'active':''}" onclick="setThreeEffects(false)">Off</button>
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
        <div class="settings-kv"><span class="settings-k">Vault created</span><span class="settings-v">${escHtml(CryptoVault.vault?.identity?.createdAt ? new Date(CryptoVault.vault.identity.createdAt).toLocaleDateString() : '—')}</span></div>
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

    ${renderAiSettingsCard()}

    <div class="settings-card settings-card--danger">
      <div class="settings-card-hdr"><span class="settings-card-icon">⚠️</span>
        <div><div class="settings-card-title">Danger Zone</div><div class="settings-card-sub">Irreversible actions</div></div></div>
      <p class="settings-card-desc">Wiping removes all local data. Your wallets still exist on-chain and can be re-added with their seed phrases.</p>
      <button class="settings-btn settings-btn--danger" onclick="openAuth?.('forgot')">🗑 Wipe Account Data</button>
    </div>
  </div>`;
}

/* ── AI Explanations settings card ──
   Anthropic's API rejects direct browser-origin requests outright
   ("Disallowed CORS origin"), regardless of whose key is used — there is
   no client-only way to call it. The proxy URL points at a small,
   stateless Cloudflare Worker (see /cloudflare-worker) whose only job is
   relaying the request server-to-server to route around that; it never
   stores the key. Both the key and proxy URL live only in this vault,
   encrypted the same as wallet seeds — never sent anywhere except to the
   proxy (and from there, straight to Anthropic). */
let _aiSettingsEditing = false;

function renderAiSettingsCard() {
  const ai = CryptoVault.vault?.ai || {};
  const hasKey = !!ai.apiKey;
  const editing = _aiSettingsEditing || !hasKey;

  if (!editing) {
    return `
    <div class="settings-card">
      <div class="settings-card-hdr"><span class="settings-card-icon">🤖</span>
        <div><div class="settings-card-title">AI Explanations</div><div class="settings-card-sub">Claude-generated account analysis</div></div></div>
      <div class="settings-kv-list">
        <div class="settings-kv"><span class="settings-k">API key</span><span class="settings-v settings-v--good">✓ Configured</span></div>
        <div class="settings-kv"><span class="settings-k">Proxy</span><span class="settings-v mono" title="${escHtml(ai.proxyUrl || '')}">${escHtml(shortAddr(ai.proxyUrl || '') || '—')}</span></div>
        <div class="settings-kv"><span class="settings-k">Model</span><span class="settings-v mono">${escHtml(ai.model || AI_DEFAULT_MODEL)}</span></div>
      </div>
      <div class="settings-actions">
        <button class="settings-btn" onclick="editAiSettings()">Change</button>
        <button class="settings-btn settings-btn--danger" onclick="clearAiSettings()">Remove</button>
      </div>
    </div>`;
  }

  return `
    <div class="settings-card">
      <div class="settings-card-hdr"><span class="settings-card-icon">🤖</span>
        <div><div class="settings-card-title">AI Explanations</div><div class="settings-card-sub">Bring your own Anthropic API key</div></div></div>
      <p class="settings-card-desc">
        Requires a tiny stateless relay to work around Anthropic's browser CORS policy — it never sees or stores your key.
        <a href="https://github.com/anthropics" target="_blank" rel="noopener" style="color:var(--accent)">Deploy your own</a> or ask whoever runs this instance for the proxy URL.
      </p>
      <div class="settings-label">Anthropic API key</div>
      <input id="ai-settings-key" class="xrpl-input" type="password" placeholder="sk-ant-..." value="${escHtml(ai.apiKey || '')}" autocomplete="off" spellcheck="false" style="margin-bottom:10px" />
      <div class="settings-label">Proxy Worker URL</div>
      <input id="ai-settings-proxy" class="xrpl-input" type="text" placeholder="https://your-worker.workers.dev" value="${escHtml(ai.proxyUrl || '')}" autocomplete="off" spellcheck="false" style="margin-bottom:10px" />
      <div class="settings-label">Model <span style="opacity:.55;font-weight:400">— you're billed per request on your own key, so this is your cost/quality tradeoff</span></div>
      <select id="ai-settings-model" class="xrpl-input">
        ${AI_MODEL_OPTIONS.map(m => `<option value="${m.id}" ${(ai.model || AI_DEFAULT_MODEL) === m.id ? 'selected' : ''}>${escHtml(m.label)}</option>`).join('')}
      </select>
      <div class="settings-actions" style="margin-top:12px">
        <button class="settings-btn settings-btn--primary" onclick="saveAiSettings()">Save</button>
        ${hasKey ? `<button class="settings-btn" onclick="editAiSettings(false)">Cancel</button>` : ''}
      </div>
    </div>`;
}

export function editAiSettings(on = true) {
  _aiSettingsEditing = on;
  renderSettingsPanel();
}

export async function saveAiSettings() {
  const apiKey   = $('ai-settings-key')?.value.trim();
  const proxyUrl = $('ai-settings-proxy')?.value.trim();
  const model    = $('ai-settings-model')?.value.trim() || AI_DEFAULT_MODEL;
  if (!apiKey || !proxyUrl) { toastWarn('Enter both the API key and the proxy URL.'); return; }
  if (!/^https?:\/\//.test(proxyUrl)) { toastWarn('Proxy URL must start with http:// or https://'); return; }
  await CryptoVault.update(v => { v.ai = { apiKey, proxyUrl, model }; });
  _aiSettingsEditing = false;
  toastInfo('AI settings saved.');
  renderSettingsPanel();
}

export async function clearAiSettings() {
  await CryptoVault.update(v => { delete v.ai; });
  toastInfo('AI settings removed.');
  renderSettingsPanel();
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

      <div class="analytics-card">
        <div class="analytics-card-hdr"><span class="analytics-card-title">📊 TX Breakdown</span>
          <span class="analytics-badge">${heatTxns.length} recent</span></div>
        ${heatTxns.length ? _buildTxBreakdown(heatTxns) : '<div class="analytics-empty-chart"><div class="aec-icon">📊</div><div>Transaction breakdown builds up as this wallet transacts.</div></div>'}
      </div>

      <div class="analytics-card">
        <div class="analytics-card-hdr"><span class="analytics-card-title">💰 XRP Flow</span>
          <span class="analytics-badge">Est. net</span></div>
        ${(activeW && heatTxns.length) ? _buildXrpFlow(heatTxns, activeW.address) : `<div class="analytics-empty-chart"><div class="aec-icon">💰</div><div>${activeW ? 'XRP flow needs at least one transaction to estimate.' : 'Activate a wallet to see XRP flow.'}</div></div>`}
      </div>

      <div class="analytics-card">
        <div class="analytics-card-hdr"><span class="analytics-card-title">🪙 Token Holdings</span>
          <span class="analytics-badge">${allTokens.length} assets</span></div>
        ${allTokens.length ? _buildTokenAllocation(allTokens) : '<div class="analytics-empty-chart"><div class="aec-icon">🪙</div><div>No token trustlines held by any wallet yet.</div></div>'}
      </div>
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
  // Unlike _buildBalanceChart just above it in the analytics tab (which has
  // an explicit "not enough data yet" state for < 2 snapshots), this always
  // rendered the full 26-week grid regardless of transaction count — for a
  // brand-new wallet that's a wall of uniformly faint gray cells with no
  // explanation, not an empty state.
  if (!txns.length) {
    return `<div class="analytics-empty-chart"><div class="aec-icon">📅</div><div>Activity heatmap fills in as this wallet transacts.</div></div>`;
  }
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
export async function xrplPost(body) {
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
  // prompt() returns null specifically for Cancel/Esc, vs '' for OK-with-
  // nothing-typed — but signAndSubmit's _resolveSeedForSigning does
  // `(providedSeed || '').trim()`, which can't tell those apart, so
  // clicking Cancel here used to fall through to a second, differently-
  // worded prompt asking for the wallet password/seed again instead of
  // actually cancelling — worse, that prompt not only claimed the trustline
  // removal was still happening, it also submits a real, fee-costing XRPL
  // transaction if the user gives in and enters it there instead.
  if (seed === null) { toastInfo('Trustline removal cancelled.'); return; }
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