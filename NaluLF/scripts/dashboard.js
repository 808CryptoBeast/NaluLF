/* =====================================================
   FILE: scripts/dashboard.js
   Dashboard — Metrics · Charts · Stream · DEX Patterns · Reporting · Spam Defense POC

   Key fixes in this version:
   - ✅ Account Peek modal: fixed element lookups (no '#'), fills Plain-English note + Recent context
   - ✅ Modal UX: pauses ledger stream animation while open (stops the “ticking” feel)
   - ✅ Spam Defense POC: aligned grid rows + all fields populated
   - ✅ Landscape Report: richer “layman” explanation + concrete “who to watch” list
   - ✅ Derived: compute advanced metrics before friction uses it
   ===================================================== */

import { $, $$, escHtml, shortAddr, toastInfo, toastWarn, isValidXrpAddress } from './utils.js';
import { state } from './state.js';
import { TX_COLORS } from './config.js';
import { switchNetwork, wsSend } from './xrpl.js';

/* ─────────────────────────────
   Tunables
──────────────────────────────── */
const MAX_TX_SAMPLE = 180;

const TREND_WINDOW = 12;
const MA_WINDOW = 5;

const LS_COMPACT_MODE = 'naluxrp_compact_mode';

/* Whale threshold (XRP) */
const WHALE_XRP = 100_000;

/* DEX window */
const DEX_WINDOW = 18;
const DEX_MIN_FOR_SIGNALS = 16;

/* Extra dashboard modules */
const DEX_PRESSURE_MAX = 96;          // ~ last 96 ledgers in chart
const NFT_MINT_MAX     = 96;
const AUTO_BRIDGE_MAX  = 96;

const MARKET_POLL_MS   = 5 * 60_000;  // 5 min
const MARKET_POINTS    = 72;          // 72 points (hours)

/* Stream */
const STREAM_QUEUE_MAX  = 80;
const STALL_TIMEOUT_MS  = 10_000;

/* ─────────────────────────────────────────────────────────────────────────
   Spam Defense POC — client-side ratchet + SHA-512Half on-ledger credential

   XRPL context:
   • Fees are network-wide and validator-controlled — this POC does NOT change
     base fees. Instead it generates signed evidence that a gateway/relayer/
     policy layer can use to demand a bond or credential before providing service.
   • Proof hashes use SHA-512Half — the same algorithm XRPL uses internally for
     transaction hashes, ledger hashes, and payment channel IDs.
   • Credential tx: sender self-payment or EscrowCreate with DestTag + Memo.
     The memo must contain the exact SHA-512Half proof hash to be valid.
   • Bond amounts grow exponentially per level so the cost of sustained
     manipulation escalates faster than the profit motive.

   Level → Bond schedule  (base=10, growth=2):
     L0=10 L1=20 L2=40 L3=80 L4=160 L5=320 L6=640 L7=1280 L8=2560 XRP
─────────────────────────────────────────────────────────────────────────── */
const SPAM_MAX_TRACKED    = 20;       // max suspect rows shown
const SPAM_RATCHET_MAX    = 8;        // highest ratchet level
const SPAM_STRIKES_TO_LVL = 3;        // strikes needed to advance one level
const SPAM_STRIKE_UP      = 0.70;     // suspicion score threshold → +1 strike
const SPAM_STRIKE_DOWN    = 0.35;     // suspicion score threshold → −1 strike
const SPAM_DECAY_QUIET    = 12;       // ledgers of silence before strike decay
const SPAM_BOND_BASE_XRP  = 10;       // L0 bond (XRP)
const SPAM_BOND_GROWTH    = 2;        // bond = base × growth^level
const SPAM_CRED_TAG_BASE  = 61_000;   // DestinationTag = base + level
const SPAM_MEMO_PREFIX    = 'NALU-SPAM-PROOF:';  // followed by SHA-512Half hash
const LS_SPAM_VERIFIED    = 'naluxrp_spam_verified';  // localStorage key
const LS_SPAM_ALLOWLIST   = 'naluxrp_spam_allowlist'; // localStorage key

/* Known-good entity allow-list — addresses that should never be flagged.
   Includes major exchanges that legitimately dominate DEX activity.
   Mirrors the inspector.js KNOWN_ENTITIES list for consistency. */
const SPAM_ALLOWLIST_BUILTIN = new Set([
  /* Bitstamp */  'rPVMhWBsfF9iMXYj3aAzJVkPDTFNSyWdKy','rvYAfWj5gh67oV6fW32ZzP3Aw4Eubs59B','rrpNnNLKrartuEqfJGpqyDwPj1BBN1ih7',
  /* Binance */   'rN7n3473SaZBCG4dFL83w7PB9judJ7qdDo','rEb8TK3gBgk5auZkwc6sHnwrGVJH8DuaLh',
  /* Bitso */     'rBKPS4oLSaV2KVVuHH8EpQqMGgGefGFQs7',
  /* Gate.io */   'rfk5bwaKCoNU84fTzdqWQowqnNaZorDmiV','rGFuMiw48HdbnrUbkRYDTvT5i9imC5fvv9',
  /* Kraken */    'rwYHCs2EYBMBvRXFmxDrCUSorPsuqCck7t','rLHzPsX6oXkzU2qL12kHCH8G8cnZv1rBJh',
  /* Uphold */    'ra5nK24KXen9AHvsdFTKHSANinZseWnPcX',
  /* Bittrex */   'rGWrZyax5eXbi5gs49MRZKkE9eKNL9p4B',
  /* Bithumb */   'rHsMUQFzBb7S6GnQFVgNirqvHRcLpAn5dU',
  /* Coinone */   'rDsbeomae4FXwgQTJp9Rs64Qg9vDiTCdBv',
  /* Huobi */     'rMQ98K56yXJbDGv49ZSmW51sLn94Xe1mu1',
  /* Coinbase */  'rKiCet8SdvWxPXnAgYarFUXMh1zCPz432Y',
  /* OKX */       'r9mhdcT2K7FdCGDEPqfbMJwVXsXCqEr5bP',
  /* Bybit */     'r4GDFMLGJUKMjNEycBKPGnRSNXyNVLQLHi',
  /* KuCoin */    'rUA1S9qobBkxLqzdfGEzh5wm5KdLfbf8bx',
  /* MEXC */      'rHtbQzmN4BDaEBnGSXp3AZaZAuZamNVsME',
  /* GateHub */   'rhub8VRN55s94qWKDv6jmDy1pUykJzF3wq','razqnFn6FqBaYBdNaGnVzmGaNE6XPRQ9bG',
  /* Ripple */    'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh','r9cZA1mLK5R5Am25ArfXFmqgNwjZgnfk59',
  /* XAMAN */     'rPEPPER7kfTD9w2To4CQk6UCfuHM9c6GDY',
  /* SOLO */      'rsoLo2S1kiGeCcn6hCUXVrCpGMWLrRrLZz',
]);

/* ─────────────────────────────
   Rolling series (charts)
──────────────────────────────── */
const series = {
  dexPressure: [], // numbers (offer tx total per ledger)
  nftMints: [],    // numbers (NFTokenMint per ledger)
  nftBurns: [],    // numbers (NFTokenBurn per ledger)
  autoBridge: [],  // numbers (path payments per ledger)
  marketPrice: [], // numbers (USD)
  marketVol: [],   // numbers (USD volume)
};

let marketTimer = null;
let _marketRun = 0;

/* ─────────────────────────────
   Rolling derived state
──────────────────────────────── */
const behaviorState = { acct: new Map() }; // addr -> { ledgers:[], intervals:[], total }
const pairState = { window: [], totals: new Map(), maxLedgers: 12 };

const dexState = { window: [], smoothCancelPerMin: null, smoothBurst: null };

/* Spam defense state */
const spamState = {
  // Core ratchet state — persisted across ledgers
  // addr → { score, strikes, level, lastSeenLedger, verifiedLedger,
  //          scoreHistory: number[], threatType: string, signalBreakdown: {} }
  byAddr: new Map(),
  selectedAddr: null,
  selectedProof: null,        // last built proof object (async)
  // User-managed allow-list (manual overrides — loaded from localStorage)
  allowList: new Set(),
  // Verified credential cache (survives page reload)
  verifiedCache: new Map(),   // addr → { ledgerIndex, hash }
};

/* Mounted flags */
let explainersMounted = false;
let legendMounted = false;
let trendMiniMounted = false;
let patternMounted = false;
let landscapeMounted = false;
let dexMounted = false;
let riskMounted = false;
let bottomNavMounted = false;
let compactBound = false;
let accordionBound = false;
let clickDelegationBound = false;
let acctPeekMounted = false;
let advancedMounted = false;
let spamMounted = false;
let whaleFeedMounted = false;
let networkHealthMounted = false;
let sessionStatsMounted = false;
let customizerMounted = false;
let customizerActive = false;

/* UI pause flags */
let _uiModalOpen = false;

/* ─────────────────────────────
   DOM cache — avoid repeated getElementById every ledger
──────────────────────────────── */
const _dc = {};
function _el(id) {
  if (!_dc[id]) _dc[id] = document.getElementById(id);
  return _dc[id];
}

/* ─────────────────────────────
   Throttle map — prevent heavy renders every single ledger
──────────────────────────────── */
const _throttle = new Map();
function _shouldRender(key, ledgerIndex, everyN = 2) {
  const last = _throttle.get(key) ?? -999;
  if ((Number(ledgerIndex) - last) < everyN) return false;
  _throttle.set(key, Number(ledgerIndex));
  return true;
}

/* ─────────────────────────────
   Session stats
──────────────────────────────── */
const sessionStats = {
  ledgersProcessed: 0,
  startTime: Date.now(),
  totalTx: 0,
  whaleCount: 0,
  feeSpikes: 0,
  botDetections: 0,
  dexAlerts: 0,
};

/* ─────────────────────────────
   Whale alert feed
──────────────────────────────── */
const whaleAlerts = [];
const WHALE_FEED_MAX = 40;

/* ─────────────────────────────
   Smart alert config
──────────────────────────────── */
const ALERT_CONFIG = {
  whaleTxXrp:       100_000,
  feeSpikeMultiple:  5,
  botCvThreshold:    0.20,
  dexCancelAlert:    0.75,
  clusterMinSize:    5,
};
let _lastAlertLedger = 0;

/* Dashboard customizer state */
const LS_WIDGET_ORDER  = 'naluxrp_widget_order';
const LS_WIDGET_HIDDEN = 'naluxrp_widget_hidden';
let _dragSrc = null;

/* Global pause/resume state */
let _globalPaused = false;
let _pauseBtnMounted = false;

/* Friction/regime history for sparkline (last 30 ledgers) */
const _frictionHistory = [];  // [{ li, friction, regime }]
const FRICTION_HIST_MAX = 30;
let _lastReconnectLedger = 0; // ledger index of last reconnect

/* ─────────────────────────────
   Public
──────────────────────────────── */
export function initDashboard() {
  bindNetworkButtons();
  mountMetricCards();
  mountAdvancedModules();
  mountSpamDefensePOC();

  initCharts();
  initLedgerStream();

  injectSectionExplainers();
  mountLedgerLegend();
  mountTrendMiniBlocks();

  mountAccountPeekModal();
  bindAddressClickDelegation();

  mountPatternDetectionCard();
  mountLandscapeBrief();
  mountDexPatternMonitor();
  mountRiskWidget();
  mountWhaleFeed();
  mountNetworkHealthCard();
  mountSessionStatsPanel();

  startMarketHistory();

  mountPauseButton();
  mountFrictionSparkline();
  mountDashboardCustomizer();
  mountBottomNav();
  mountCompactToggle();
  bindAccordionDelegation();

  window.addEventListener('xrpl-connection', (e) => {
    const connected = !!e?.detail?.connected;
    if (connected) _flashReconnect();
  });

  window.addEventListener('xrpl-ledger', (e) => {
    const s = e.detail;
    const li = Number(s.ledgerIndex || 0);

    // Session counters
    sessionStats.ledgersProcessed++;
    sessionStats.totalTx += Number(s.txPerLedger || 0);

    // Invalidate hot DOM cache entries re-rendered each ledger
    ['risk-badge','risk-regime','risk-friction','risk-signalcount',
     'landscape-badge','dexp-badge','dexP-badge','ab-badge','nft-badge',
     'whale-badge','ss-badge','health-badge','pattern-badge'].forEach(id => delete _dc[id]);

    updateMetricCards(s);
    updateChartsAndTrendMini();
    updateTxMix();
    updateLedgerLog();
    pushLedgerCard(s.latestLedger);

    // Whale detection runs every ledger
    detectWhales(s.recentTransactions || [], li);

    // Push friction to rolling history for sparkline
    const derived = computeDerived(s);
    _frictionHistory.push({ li, friction: derived.friction, regime: derived.regime });
    while (_frictionHistory.length > FRICTION_HIST_MAX) _frictionHistory.shift();
    _updateFrictionSparkline();

    // Respect global pause (user pressed pause button)
    if (_globalPaused) return;

    // Throttled heavy renders
    if (_shouldRender('breadcrumbs', li, 1)) renderBreadcrumbs(derived.breadcrumbs);
    if (_shouldRender('clusters',    li, 2)) renderClusters(derived.clusters);
    if (_shouldRender('narratives',  li, 2)) renderNarratives(derived.narratives);
    if (_shouldRender('landscape',   li, 3)) updateLandscapeBrief(derived);

    updatePatternDetectionCard(s.txTypes, derived.hhi);
    updateDexPatternMonitor(derived.dexPatterns);
    updateRiskWidget(derived);
    updateAdvancedModules(derived);
    updateSpamDefensePOC(derived);
    updateSessionStatsPanel();

    // Smart alerts — max once per 8 ledgers to prevent spam
    if (li - _lastAlertLedger >= 8) _checkAndFireAlerts(derived, li);
  });
}

/* ─────────────────────────────
   Helpers
──────────────────────────────── */
function setText(id, val) {
  const el = $(id);
  if (el) el.textContent = String(val);
}
function clamp(n, lo, hi) { return Math.max(lo, Math.min(hi, n)); }
function mean(arr) { return arr?.length ? arr.reduce((a,b)=>a+b,0)/arr.length : null; }
function stdev(arr) {
  if (!arr || arr.length < 2) return null;
  const m = mean(arr);
  const v = mean(arr.map((x)=> (x-m)**2));
  return Math.sqrt(v);
}
function lastN(arr, n) { return arr?.length ? arr.slice(Math.max(0, arr.length - n)) : []; }
function movingAverage(data, k) {
  const out = [];
  for (let i=0;i<data.length;i++){
    const a = Math.max(0, i-k+1);
    out.push(mean(data.slice(a, i+1)));
  }
  return out;
}
function fmtPct(p, digits=0){
  if (p==null || !Number.isFinite(p)) return '—';
  const sign = p>=0 ? '↑':'↓';
  return `${sign}${Math.abs(p).toFixed(digits)}%`;
}
function safeNum(n, digits=2){ return (n==null || !Number.isFinite(n)) ? '—' : Number(n).toFixed(digits); }
function fmtXrp(xrp){
  if (xrp==null || !Number.isFinite(xrp)) return '—';
  const v = Number(xrp);
  if (v === 0) return '0 XRP';
  if (v >= 1000) return `${v.toLocaleString(undefined,{maximumFractionDigits:2})} XRP`;
  if (v >= 1) return `${v.toFixed(4)} XRP`;
  if (v >= 0.01) return `${v.toFixed(5)} XRP`;
  return `${v.toFixed(6)} XRP`;
}
function hexToRgba(input, alpha=1){
  if (!input) return null;
  const a = clamp(Number(alpha),0,1);
  const s = String(input).trim();
  if (s.startsWith('rgba(')) return s;
  if (s.startsWith('rgb(')){
    const m = s.match(/^rgb\(\s*([0-9]+)\s*,\s*([0-9]+)\s*,\s*([0-9]+)\s*\)$/i);
    if (!m) return null;
    const r=clamp(Number(m[1]),0,255), g=clamp(Number(m[2]),0,255), b=clamp(Number(m[3]),0,255);
    return `rgba(${r},${g},${b},${a})`;
  }
  if (s[0]==='#'){
    let hex = s.slice(1);
    if (hex.length===3) hex = hex.split('').map(c=>c+c).join('');
    if (hex.length!==6) return null;
    const r=parseInt(hex.slice(0,2),16), g=parseInt(hex.slice(2,4),16), b=parseInt(hex.slice(4,6),16);
    if (![r,g,b].every(Number.isFinite)) return null;
    return `rgba(${r},${g},${b},${a})`;
  }
  return null;
}
function smooth(prev,next,alpha=0.45){
  if (next==null || !Number.isFinite(next)) return prev;
  if (prev==null || !Number.isFinite(prev)) return next;
  return prev*(1-alpha)+next*alpha;
}
/**
 * sha512Half(str) — XRPL-native hash function.
 *
 * XRPL uses SHA-512Half (first 256 bits of SHA-512, rendered as 64 hex chars)
 * for transaction hashes, ledger hashes, payment channel IDs, and escrow
 * condition IDs.  Using it here makes proof hashes consistent with the rest
 * of the XRPL ecosystem and unambiguous to any validator or gateway.
 *
 * Returns: Promise<string> — 64 hex chars  (256-bit / 32-byte prefix of SHA-512)
 * Falls back to a deterministic but non-cryptographic FNV1a string if the
 * Web Crypto API is unavailable (Node.js test environments, old browsers).
 */
async function sha512Half(str) {
  if (typeof crypto !== 'undefined' && crypto.subtle) {
    const buf   = new TextEncoder().encode(str);
    const full  = await crypto.subtle.digest('SHA-512', buf);   // 64 bytes
    const half  = new Uint8Array(full, 0, 32);                  // first 32 bytes
    return Array.from(half).map(b => b.toString(16).padStart(2,'0')).join('');
  }
  // Non-crypto fallback (clearly marked — should not appear in production)
  let h = 0x811c9dc5n;
  for (let i = 0; i < str.length; i++) {
    h ^= BigInt(str.charCodeAt(i));
    h = BigInt.asUintN(32, h * 0x01000193n);
  }
  return 'FALLBACK-NON-CRYPTO-' + h.toString(16).padStart(8,'0').repeat(4).slice(0,44);
}

/* ─────────────────────────────
   Address click + Account Peek
──────────────────────────────── */
function mountAccountPeekModal() {
  if (acctPeekMounted) return;
  acctPeekMounted = true;
  if (document.getElementById('acctPeekOverlay')) return;

  const overlay = document.createElement('div');
  overlay.id = 'acctPeekOverlay';
  overlay.className = 'acct-peek-overlay';
  overlay.style.display = 'none';

  overlay.innerHTML = `
    <div class="acct-peek-box" role="dialog" aria-modal="true" aria-label="Account details">
      <button class="acct-peek-close" id="acctPeekClose" aria-label="Close">✕</button>

      <div class="acct-peek-head">
        <div style="min-width:0">
          <div class="acct-peek-title">Account</div>
          <div class="acct-peek-addr mono cut" id="acctPeekAddr">—</div>
        </div>
        <button class="acct-peek-inspect" id="acctPeekInspect">Open in Inspector →</button>
      </div>

      <div class="acct-peek-grid">
        <div class="acct-peek-stat"><span>Balance</span><b id="acctPeekBal">—</b></div>
        <div class="acct-peek-stat"><span>Sequence</span><b id="acctPeekSeq">—</b></div>
        <div class="acct-peek-stat"><span>OwnerCount</span><b id="acctPeekOwner">—</b></div>
        <div class="acct-peek-stat"><span>Flags</span><b id="acctPeekFlags">—</b></div>
      </div>

      <div class="acct-peek-section">
        <div class="acct-peek-h">Plain-English note</div>
        <div class="acct-peek-note" id="acctPeekNote">—</div>
      </div>

      <div class="acct-peek-section">
        <div class="acct-peek-h">Recent context</div>
        <div class="acct-peek-note" id="acctPeekCtx">—</div>
      </div>
    </div>
  `;

  document.body.appendChild(overlay);

  const close = () => {
    overlay.style.display = 'none';
    overlay.removeAttribute('data-addr');
    document.body.classList.remove('modal-open');
    _uiModalOpen = false;
    _streamPaused = false;
  };

  overlay.addEventListener('click', (e) => { if (e.target === overlay) close(); });
  $('acctPeekClose')?.addEventListener('click', close);

  $('acctPeekInspect')?.addEventListener('click', async () => {
    const addr = overlay.getAttribute('data-addr');
    if (addr) await openInspectorForAddress(addr);
    close();
  });
}

function bindAddressClickDelegation() {
  if (clickDelegationBound) return;
  clickDelegationBound = true;

  document.addEventListener('click', (e) => {
    const btn = e.target.closest?.('[data-addr]');
    if (!btn) return;
    const addr = btn.getAttribute('data-addr');
    if (!addr) return;
    e.preventDefault();
    openAccountPeek(addr);
  });
}

function _dexCtxForAddr(addr) {
  if (!addr || !dexState?.window?.length) return null;
  let create=0,cancel=0,totalWin=0;
  for (const w of dexState.window){
    totalWin += Number(w.total||0);
    create += Number(w.byActorCreate?.get(addr)||0);
    cancel += Number(w.byActorCancel?.get(addr)||0);
  }
  const total = create+cancel;
  if (!total) return null;
  const cancelRatio = total ? cancel/total : 0;
  const share = totalWin ? total/totalWin : null;
  return { create, cancel, total, cancelRatio, share };
}
function _botCtxForAddr(addr){
  const st = behaviorState?.acct?.get(addr);
  if (!st || !st.intervals || st.intervals.length < 6) return null;
  const mu=mean(st.intervals), sd=stdev(st.intervals);
  if (!mu || sd==null) return null;
  const cv = sd/mu;
  return { cv, total: st.total||0 };
}

async function openAccountPeek(addr) {
  if (!isValidXrpAddress(addr)) return;
  const overlay = document.getElementById('acctPeekOverlay');
  if (!overlay) return;

  overlay.style.display = 'flex';
  overlay.setAttribute('data-addr', addr);
  document.body.classList.add('modal-open');
  _uiModalOpen = true;
  _streamPaused = true;

  setText('acctPeekAddr', addr);
  setText('acctPeekBal', '…');
  setText('acctPeekSeq', '…');
  setText('acctPeekOwner', '…');
  setText('acctPeekFlags', '…');

  const note = $('acctPeekNote');
  const ctx  = $('acctPeekCtx');
  if (note) note.textContent = 'Fetching account_info…';
  if (ctx)  ctx.textContent  = 'Building context…';

  const seen = behaviorState.acct.get(addr);
  const appearances = seen?.ledgers?.length || 0;

  try {
    if (!state.wsConn || state.wsConn.readyState !== 1) {
      if (note) note.textContent = 'Not connected to XRPL. Connect first.';
      return;
    }

    const info = await wsSend({ command:'account_info', account: addr, ledger_index:'validated', strict:true });
    const d = info?.result?.account_data;

    const drops = Number(d?.Balance ?? NaN);
    const balXrp = Number.isFinite(drops) ? drops/1e6 : null;

    setText('acctPeekBal', balXrp==null ? '—' : `${balXrp.toLocaleString(undefined,{maximumFractionDigits:6})} XRP`);
    setText('acctPeekSeq', d?.Sequence ?? '—');
    setText('acctPeekOwner', d?.OwnerCount ?? '—');
    setText('acctPeekFlags', d?.Flags != null ? `0x${Number(d.Flags).toString(16)}` : '—');

    if (note) {
      const lines = [];
      if (balXrp != null && balXrp >= WHALE_XRP) lines.push('Large balance (whale-sized).');

      const bot = _botCtxForAddr(addr);
      if (bot && bot.cv < 0.35 && bot.total > 10) lines.push(`Bot-like timing signal (CV ${bot.cv.toFixed(2)}).`);

      const dex = _dexCtxForAddr(addr);
      if (dex) {
        const cPct = Math.round(dex.cancelRatio*100);
        const share = dex.share != null ? Math.round(dex.share*100) : null;
        lines.push(`DEX activity: ${dex.total} offer tx in window.`);
        lines.push(`Creates ${dex.create}, cancels ${dex.cancel} (${cPct}% cancels).`);
        if (share != null) lines.push(`~${share}% of window activity.`);
      }

      const sp = spamState.byAddr.get(addr);
      if (sp) {
        const bond = spamBondForLevel(sp.level);
        lines.push(`Spam-defense: score ${(sp.score*100).toFixed(0)}% · level L${sp.level} · bond ${bond.toLocaleString()} XRP.`);
        if (sp.verifiedLedger != null) lines.push(`Credential verified at ledger #${Number(sp.verifiedLedger).toLocaleString()}.`);
      }

      if (appearances >= 6) lines.push(`Shows up often in recent ledgers (${appearances} times).`);
      if (!lines.length) lines.push('No obvious red flags from this quick read.');

      note.textContent = lines.join(' ');
    }

    if (ctx) {
      const last = seen?.ledgers?.at(-1);
      const dex  = _dexCtxForAddr(addr);
      const dexLine = dex ? `DEX window: ${dex.total} (creates ${dex.create}, cancels ${dex.cancel})` : null;
      const whaleLines = whaleAlerts.filter(w => w.from === addr || w.to === addr).slice(0, 3);
      const whaleLine = whaleLines.length
        ? `${whaleLines.length} whale tx in session (${whaleLines.map(w => (w.amtXrp >= 1e6 ? (w.amtXrp/1e6).toFixed(1)+'M' : (w.amtXrp/1000).toFixed(0)+'K') + ' XRP').join(', ')})`
        : null;
      const sp = spamState.byAddr.get(addr);
      const spamLine = sp ? `Spam-defense: L${sp.level} · score ${Math.round(sp.score*100)}%` : null;
      ctx.textContent = [
        last ? `Last seen around ledger #${Number(last).toLocaleString()}` : 'Not in recent window.',
        dexLine, whaleLine, spamLine,
      ].filter(Boolean).join(' · ');
    }
  } catch (err) {
    if (note) note.textContent = `Lookup failed: ${String(err?.message || err)}`;
    if (ctx)  ctx.textContent  = '—';
  }
}

async function openInspectorForAddress(addr) {
  if (!isValidXrpAddress(addr)) return;

  const tabBtn = document.querySelector('.dash-tab[data-tab="inspector"]');
  const panel = document.getElementById('tab-inspector');

  const ensureTab = async () => {
    if (panel && panel.style.display !== 'none') return true;
    if (typeof window.switchTab === 'function' && tabBtn) window.switchTab(tabBtn, 'inspector');
    else tabBtn?.click();
    await new Promise(r => setTimeout(r, 80));
    return panel ? panel.style.display !== 'none' : true;
  };

  for (let i=0;i<6;i++){
    const ok = await ensureTab();
    if (ok) break;
    await new Promise(r => setTimeout(r, 80));
  }

  const input = document.getElementById('inspect-addr');
  if (input) { input.value = addr; input.focus(); }

  await new Promise(r => setTimeout(r, 60));
  if (typeof window.runInspect === 'function') window.runInspect();
  else toastWarn('Inspector not ready yet.');
}

/* ─────────────────────────────
   Network selector
──────────────────────────────── */
function bindNetworkButtons() {
  $$('.net-btn[data-network]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const net = btn.getAttribute('data-network');

      $$('.net-btn').forEach((b) => {
        b.classList.toggle('active', b === btn);
        b.setAttribute('aria-pressed', String(b === btn));
      });

      behaviorState.acct.clear();
      pairState.window = [];
      pairState.totals = new Map();
      dexState.window = [];
      dexState.smoothCancelPerMin = null;
      dexState.smoothBurst = null;

      ledgerQueue.length  = 0;
      seenLedgers.clear();
      _halfLen            = 0;
      _rawOffset          = 0;
      _streamLoopWidth    = 0;
      _streamLastTS       = 0;
      _streamNeedsMeasure = true;
      _lastCardTs         = 0;
      _stallOverlayShown  = false;
      _pinnedIndex        = null;
      _streamPaused       = false;
      _cardStepPx    = 0;
      _targetOffset  = 0;
      _hasTarget     = false;

      const track = $('ledgerStreamTrack');
      if (track) { track.innerHTML=''; track.style.transform='translateX(0px)'; }
      applyStreamTint(null, null);

      resetAdvancedSeries();

      spamState.byAddr.clear();
      spamState.selectedAddr  = null;
      spamState.selectedProof = null;
      // Keep allow-list and verified cache across network switches
      _loadAllowList();
      _initVerifiedCache();
      renderSpamProof(null);

      switchNetwork(net);
      startMarketHistory({ force: true });
    });
  });
}

/* ─────────────────────────────
   Metric cards
──────────────────────────────── */
const _closeHistory = [];
const CLOSE_HIST_MAX = 8;
let _lastFeeXrp = null;
let _lastLedgerWall = 0;
let _ageTimerRAF = null;

function mountMetricCards() {
  const grid = document.querySelector('.dashboard-metric-grid');
  if (!grid) return;

  // Mark the parent .dashboard-metrics section for sticky positioning
  const metricsSection = grid.closest('.dashboard-metrics') || grid.parentElement;
  if (metricsSection) metricsSection.classList.add('dashboard-sticky-strip');

  grid.innerHTML = `
    <article class="metric-card mc-ledger">
      <div class="mc-label">Ledger Index</div>
      <div class="mc-value mono" id="d2-ledger-index">—</div>
      <div class="mc-sparkline-row">
        <canvas id="d2-close-sparkline" class="mc-sparkline" width="88" height="22" title="Close time history (last 8 ledgers)"></canvas>
        <span class="mc-sub mc-age-timer" id="d2-ledger-age-timer">—</span>
      </div>
      <div class="mc-sub" id="d2-ledger-age">—</div>
    </article>

    <article class="metric-card mc-tps">
      <div class="mc-label">TX / Second</div>
      <div class="mc-value" id="d2-tps">—</div>
      <div class="mc-sub" id="d2-tps-trend">Waiting…</div>
    </article>

    <article class="metric-card mc-tpl">
      <div class="mc-label">TX / Ledger</div>
      <div class="mc-value" id="d2-tx-per-ledger">—</div>
      <div class="mc-sub" id="d2-tx-spread">Waiting…</div>
    </article>

    <article class="metric-card mc-fee">
      <div class="mc-label">Avg Fee</div>
      <div class="mc-fee-row">
        <span class="mc-value mono" id="d2-fee-value">—</span>
        <span class="mc-fee-delta" id="d2-fee-delta" aria-label="Fee trend"></span>
      </div>
      <div class="mc-sub" id="d2-fee-pressure">Waiting…</div>
    </article>

    <article class="metric-card mc-sr">
      <div class="mc-label">Success Rate</div>
      <div class="mc-value" id="d2-success-rate">—</div>
      <div class="mc-sub" id="d2-success-note">Waiting…</div>
    </article>

    <article class="metric-card mc-load">
      <div class="mc-label">Network Load</div>
      <div class="mc-value" id="d2-network-capacity">—</div>
      <div class="mc-sub" id="d2-capacity-note">Waiting…</div>
    </article>

    <article class="metric-card mc-dom">
      <div class="mc-label">Dominant TX</div>
      <div class="mc-value" id="d2-dominant-type">—</div>
      <div class="mc-sub" id="d2-dominance-score">Waiting…</div>
    </article>
  `;
}

function updateMetricCards(s) {
  const li = s.ledgerIndex ? Number(s.ledgerIndex) : null;
  setText('d2-ledger-index', li ? li.toLocaleString() : '—');

  const ct = s.latestLedger?.closeTimeSec != null ? Number(s.latestLedger.closeTimeSec) : null;

  const ageEl = $('d2-ledger-age');
  if (ageEl) {
    if (ct != null) {
      ageEl.textContent = `${ct < 2 ? ct.toFixed(2) : ct.toFixed(1)}s close`;
      ageEl.style.color  = ct <= 3 ? '#50fa7b' : ct <= 6 ? '#ffb86c' : '#ff6e6e';
    } else {
      ageEl.textContent  = 'Waiting…';
      ageEl.style.color  = '';
    }
  }

  if (ct != null) {
    _closeHistory.push(ct);
    if (_closeHistory.length > CLOSE_HIST_MAX) _closeHistory.shift();
    _drawCloseSparkline();
  }

  _lastLedgerWall = Date.now();
  _startAgeTimer();

  if (s.tps != null) {
    const tps = Number(s.tps);
    const tpsEl = $('d2-tps');
    if (tpsEl) {
      tpsEl.textContent = tps.toFixed(1);
      tpsEl.style.color = tps < 10 ? 'rgba(255,255,255,.65)'
        : tps < 40  ? '#50fa7b'
        : tps < 80  ? '#ffb86c'
        : '#ff6e6e';
    }
    const trendEl = $('d2-tps-trend');
    if (trendEl) {
      const hist = state.tpsHistory || [];
      const avg = hist.length > 2
        ? (hist.slice(-10).reduce((a,b)=>a+b,0) / Math.min(hist.length,10)).toFixed(1)
        : null;
      const label = tps < 10 ? 'Low' : tps < 40 ? 'Normal' : tps < 80 ? 'High' : 'Peak';
      trendEl.textContent = avg ? `${label} · avg ${avg}` : label;
      trendEl.style.color = tps < 10 ? 'rgba(255,255,255,.55)'
        : tps < 40  ? '#50fa7b'
        : tps < 80  ? '#ffb86c'
        : '#ff6e6e';
    }
  }

  const tpl = (s.latestLedger?.totalTx ?? s.txPerLedger) || 0;
  const tplEl = $('d2-tx-per-ledger');
  if (tplEl) {
    tplEl.textContent = tpl > 0 ? tpl.toLocaleString() : '—';
    tplEl.style.color = tpl < 10   ? 'rgba(255,255,255,.65)'
      : tpl < 150  ? '#50fa7b'
      : tpl < 400  ? '#ffb86c'
      : '#ff6e6e';
  }
  const spreadEl = $('d2-tx-spread');
  if (spreadEl && tpl > 0) {
    spreadEl.textContent = tpl < 10  ? 'Very light'
      : tpl < 50   ? 'Light'
      : tpl < 150  ? 'Normal'
      : tpl < 400  ? 'High volume'
      : 'Very high volume';
    spreadEl.style.color = tpl < 150 ? '' : tpl < 400 ? '#ffb86c' : '#ff6e6e';
  }

  const feeXrp = s.avgFee != null ? Number(s.avgFee)
    : (s.latestLedger?.avgFee != null ? Number(s.latestLedger.avgFee) : null);

  if (feeXrp != null) {
    const drops = Math.round(feeXrp * 1e6);
    const feeEl = $('d2-fee-value');
    if (feeEl) {
      feeEl.textContent = fmtXrp(feeXrp);
      feeEl.style.color = drops <= 15  ? '#50fa7b'
        : drops <= 50  ? 'rgba(255,255,255,.9)'
        : drops <= 200 ? '#ffb86c'
        : '#ff6e6e';
    }

    const deltaEl = $('d2-fee-delta');
    if (deltaEl) {
      if (_lastFeeXrp != null) {
        const ratio = feeXrp / _lastFeeXrp;
        if (ratio > 1.05) {
          deltaEl.textContent = '↑';
          deltaEl.style.color = '#ff6e6e';
          deltaEl.title = `+${((ratio-1)*100).toFixed(0)}% vs prev ledger`;
        } else if (ratio < 0.95) {
          deltaEl.textContent = '↓';
          deltaEl.style.color = '#50fa7b';
          deltaEl.title = `-${((1-ratio)*100).toFixed(0)}% vs prev ledger`;
        } else {
          deltaEl.textContent = '→';
          deltaEl.style.color = 'rgba(255,255,255,.35)';
          deltaEl.title = 'Stable vs prev ledger';
        }
      } else deltaEl.textContent = '';
    }
    _lastFeeXrp = feeXrp;

    const pressEl = $('d2-fee-pressure');
    if (pressEl) {
      const label = drops <= 15 ? 'Base fee'
        : drops <= 50  ? `${drops} drops`
        : drops <= 200 ? `${drops} drops · Elevated`
        : `${drops} drops · Surge`;
      pressEl.textContent = label;
      pressEl.style.color = drops <= 50 ? '' : drops <= 200 ? '#ffb86c' : '#ff6e6e';
    }
  }

  const sr = s.successRate != null ? Number(s.successRate)
    : (s.latestLedger?.successRate != null ? Number(s.latestLedger.successRate) : null);

  if (sr != null) {
    const srEl = $('d2-success-rate');
    if (srEl) {
      srEl.textContent = `${sr.toFixed(1)}%`;
      srEl.style.color = sr >= 90 ? '#50fa7b' : sr >= 75 ? '#ffb86c' : '#ff6e6e';
    }
    const srNote = $('d2-success-note');
    if (srNote) {
      const failPct = (100 - sr).toFixed(1);
      srNote.textContent = sr >= 90 ? `${failPct}% failed · Normal`
        : sr >= 75 ? `${failPct}% failed · Watch`
        : `${failPct}% failed · Alert`;
      srNote.style.color = sr >= 90 ? '' : sr >= 75 ? '#ffb86c' : '#ff6e6e';
    }
  }

  const capPct = tpl > 0 ? Math.min(100, (tpl/500)*100) : null;
  const capEl = $('d2-network-capacity');
  const capNote = $('d2-capacity-note');
  if (capPct != null) {
    if (capEl) {
      capEl.textContent = `${capPct.toFixed(1)}%`;
      capEl.style.color = capPct < 20 ? 'rgba(255,255,255,.65)'
        : capPct < 50 ? '#50fa7b'
        : capPct < 80 ? '#ffb86c'
        : '#ff6e6e';
    }
    if (capNote) {
      capNote.textContent = capPct < 20 ? 'Low usage'
        : capPct < 50 ? 'Moderate'
        : capPct < 80 ? 'Heavy'
        : 'Near capacity';
      capNote.style.color = capPct < 50 ? '' : capPct < 80 ? '#ffb86c' : '#ff6e6e';
    }
  }

  const txTypes = s.txTypes || {};
  const txEntries = Object.entries(txTypes).sort(([,a],[,b]) => b - a);
  if (txEntries.length) {
    const [domType, domCount] = txEntries[0];
    const total = txEntries.reduce((a,[,c])=>a+c,0) || 1;
    const pct = ((domCount/total)*100).toFixed(0);
    const C = typeof TX_COLORS !== 'undefined' ? TX_COLORS : {};

    const domEl = $('d2-dominant-type');
    if (domEl) { domEl.textContent = domType; domEl.style.color = C[domType] || 'rgba(255,255,255,.9)'; }

    const scoreEl = $('d2-dominance-score');
    if (scoreEl) {
      const second = txEntries[1];
      scoreEl.textContent = second ? `${pct}% · 2nd: ${second[0]}` : `${pct}% of txs`;
    }
  }

  const sl = $('stream-loading');
  if (sl) sl.style.display = 'none';
}

function _drawCloseSparkline() {
  const canvas = $('d2-close-sparkline');
  if (!canvas || !canvas.getContext) return;
  const data = _closeHistory;
  if (data.length < 2) return;

  const W = canvas.width, H = canvas.height;
  const ctx = canvas.getContext('2d');
  ctx.clearRect(0,0,W,H);

  const max = Math.max(...data, 4);
  const barW = Math.floor((W - (data.length-1)) / data.length);
  const gap = 1;

  data.forEach((v,i)=>{
    const barH = Math.max(3, Math.round((v/max)*(H-2)));
    const x = i*(barW+gap);
    const y = H-barH;
    const color = v<=3 ? 'rgba(80,250,123,.80)'
      : v<=6 ? 'rgba(255,184,108,.80)'
      : 'rgba(255,110,110,.85)';
    ctx.fillStyle = color;

    const r = Math.min(2, barW/2);
    ctx.beginPath();
    ctx.moveTo(x+r,y);
    ctx.lineTo(x+barW-r,y);
    ctx.quadraticCurveTo(x+barW,y,x+barW,y+r);
    ctx.lineTo(x+barW,H);
    ctx.lineTo(x,H);
    ctx.lineTo(x,y+r);
    ctx.quadraticCurveTo(x,y,x+r,y);
    ctx.closePath();
    ctx.fill();

    if (i===data.length-1){
      ctx.fillStyle = 'rgba(255,255,255,.18)';
      ctx.fillRect(x,y,barW,Math.min(3,barH));
    }
  });
}

function _startAgeTimer() {
  if (_ageTimerRAF) cancelAnimationFrame(_ageTimerRAF);
  let lastUpdate = 0;
  const tick = (ts) => {
    if (ts-lastUpdate >= 120){
      lastUpdate = ts;
      const el = $('d2-ledger-age-timer');
      if (el && _lastLedgerWall>0){
        const age = (Date.now()-_lastLedgerWall)/1000;
        el.textContent = `${age.toFixed(1)}s ago`;
        el.style.color = age < 4 ? 'rgba(255,255,255,.55)' : age < 7 ? '#ffb86c' : '#ff6e6e';
        el.style.opacity = age >= 7 ? (0.6 + 0.4*Math.sin(Date.now()/300)).toFixed(2) : '1';
      }
    }
    _ageTimerRAF = requestAnimationFrame(tick);
  };
  _ageTimerRAF = requestAnimationFrame(tick);
}

/* ─────────────────────────────
   TX Mix
──────────────────────────────── */
function updateTxMix() {
  const el = $('tx-mix');
  if (!el) return;

  const entries = Object.entries(state.txMixAccum || {})
    .filter(([, v]) => v > 0)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 10);

  const total = entries.reduce((s, [, v]) => s + v, 0);
  if (!total) return;

  el.innerHTML = entries.map(([type, count]) => {
    const pct = ((count / total) * 100).toFixed(1);
    const color = TX_COLORS[type] || '#6b7280';
    return `
      <div class="tx-mix-row">
        <span class="tx-mix-label">${escHtml(type)}</span>
        <div class="tx-mix-bar">
          <div class="tx-mix-fill" style="width:${pct}%;background:${color}"></div>
        </div>
        <span class="tx-mix-pct">${pct}%</span>
      </div>`;
  }).join('');
}

/* ─────────────────────────────
   Charts + Trend mini blocks
──────────────────────────────── */
class MiniChart {
  constructor(canvasId, color = '#00fff0', mode = 'area') {
    this.canvasId = canvasId;
    this.canvas = $(canvasId);
    this.color = color;
    this.mode = mode;
  }
  _resolveCanvas() {
    if (!this.canvas) this.canvas = $(this.canvasId);
    return this.canvas;
  }
  draw(data) {
    const canvas = this._resolveCanvas();
    if (!canvas || !data?.length) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const W = (canvas.width = canvas.offsetWidth || 300);
    const H = (canvas.height = canvas.offsetHeight || 180);
    ctx.clearRect(0, 0, W, H);
    if (data.length < 2) return;

    const min = Math.min(...data) * 0.9;
    const max = Math.max(...data) * 1.05 || 1;
    const norm = (v) => 1 - (v - min) / (max - min || 1);

    const pad = { l: 10, r: 10, t: 10, b: 12 };
    const cw = W - pad.l - pad.r;
    const ch = H - pad.t - pad.b;
    const step = cw / (data.length - 1);
    const pts = data.map((v, i) => [pad.l + i * step, pad.t + norm(v) * ch]);

    const m = mean(data);
    if (m != null) {
      const y = pad.t + norm(m) * ch;
      ctx.beginPath();
      ctx.moveTo(pad.l, y);
      ctx.lineTo(pad.l + cw, y);
      ctx.strokeStyle = 'rgba(255,255,255,0.16)';
      ctx.lineWidth = 1;
      ctx.stroke();
    }

    if (data.length >= MA_WINDOW + 2) {
      const ma = movingAverage(data, MA_WINDOW);
      const maPts = ma.map((v, i) => [pad.l + i * step, pad.t + norm(v) * ch]);
      ctx.beginPath();
      maPts.forEach(([x, y], i) => (i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y)));
      ctx.strokeStyle = 'rgba(255,255,255,0.22)';
      ctx.lineWidth = 1.5;
      ctx.stroke();
    }

    if (this.mode === 'bar') {
      const bw = Math.max(1, step - 3);
      data.forEach((v, i) => {
        const h = (1 - norm(v)) * ch;
        const x = pad.l + i * step - bw / 2;
        const grad = ctx.createLinearGradient(0, pad.t, 0, pad.t + ch);
        grad.addColorStop(0, this.color);
        grad.addColorStop(1, this.color + '33');
        ctx.fillStyle = grad;
        ctx.fillRect(x, pad.t + ch - h, bw, h);
      });
      return;
    }

    const grad = ctx.createLinearGradient(0, pad.t, 0, pad.t + ch);
    grad.addColorStop(0, this.color + 'aa');
    grad.addColorStop(1, this.color + '11');

    ctx.beginPath();
    pts.forEach(([x, y], i) => (i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y)));
    ctx.lineTo(pts.at(-1)[0], pad.t + ch);
    ctx.lineTo(pts[0][0], pad.t + ch);
    ctx.closePath();
    ctx.fillStyle = grad;
    ctx.fill();

    ctx.beginPath();
    pts.forEach(([x, y], i) => (i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y)));
    ctx.strokeStyle = this.color;
    ctx.lineWidth = 2;
    ctx.lineJoin = 'round';
    ctx.stroke();
  }
}

const charts = {};

function initCharts() {
  charts.tps = new MiniChart('chart-tps', '#50fa7b', 'area');
  charts.fee = new MiniChart('chart-fee', '#ffb86c', 'area');
  charts.tps2 = new MiniChart('chart-tps2', '#50fa7b', 'bar');
  charts.fee2 = new MiniChart('chart-fee2', '#ffb86c', 'area');

  charts.dexPressure = new MiniChart('chart-dex-pressure', '#00d4ff', 'bar');
  charts.nftMints    = new MiniChart('chart-nft-mints',    '#bd93f9', 'bar');
  charts.nftBurns    = new MiniChart('chart-nft-burns',    '#ff5555', 'bar');
  charts.autoBridge  = new MiniChart('chart-autobridge',   '#f1fa8c', 'bar');
  charts.marketPrice = new MiniChart('chart-market-price', '#50fa7b', 'area');
  charts.marketVol   = new MiniChart('chart-market-vol',   '#8be9fd', 'bar');
}

function calcTrendStats(seriesArr, windowN = TREND_WINDOW) {
  const raw = lastN(seriesArr, windowN).filter((x) => Number.isFinite(x));
  if (!raw.length) return { cur: null, avg: null, deltaPct: null, vol: null };
  const cur = raw.at(-1);
  const avg = mean(raw);
  const vol = stdev(raw);
  const deltaPct = (avg && avg !== 0) ? ((cur - avg) / avg) * 100 : null;
  return { cur, avg, deltaPct, vol };
}

function mountTrendMiniBlocks() {
  if (trendMiniMounted) return;
  trendMiniMounted = true;

  const addMini = (canvasId, rootId) => {
    const c = $(canvasId);
    if (!c) return;
    const card = c.closest('.widget-card');
    const header = card?.querySelector('.widget-header');
    if (!header) return;
    if (document.getElementById(rootId)) return;

    const box = document.createElement('div');
    box.className = 'trend-mini';
    box.id = rootId;
    box.innerHTML = `
      <div class="trend-mini-row">
        <div class="trend-mini-cell"><span class="trend-mini-k">Now</span><span class="trend-mini-v" data-k="now">—</span></div>
        <div class="trend-mini-cell"><span class="trend-mini-k">Avg</span><span class="trend-mini-v" data-k="avg">—</span></div>
      </div>
      <div class="trend-mini-row">
        <div class="trend-mini-cell"><span class="trend-mini-k">Δ</span><span class="trend-mini-v" data-k="delta">—</span></div>
        <div class="trend-mini-cell"><span class="trend-mini-k">σ</span><span class="trend-mini-v" data-k="sigma">—</span></div>
      </div>
    `;
    header.appendChild(box);
  };

  addMini('chart-tps', 'tpsTrendMini');
  addMini('chart-fee', 'feeTrendMini');
  addMini('chart-tps2', 'tpsTrendMini2');
  addMini('chart-fee2', 'feeTrendMini2');
}

function updateTrendMini(rootId, st, decimals, suffix) {
  const root = document.getElementById(rootId);
  if (!root) return;

  const set = (k, v) => {
    const el = root.querySelector(`[data-k="${k}"]`);
    if (el) el.textContent = v;
  };

  if (st.cur == null) {
    set('now', '—'); set('avg', '—'); set('delta', '—'); set('sigma', '—');
    return;
  }

  set('now', `${Number(st.cur).toFixed(decimals)}${suffix}`);
  set('avg', st.avg != null ? `${Number(st.avg).toFixed(decimals)}${suffix}` : '—');
  set('delta', st.deltaPct == null ? '—' : fmtPct(st.deltaPct, 0));
  set('sigma', st.vol == null ? '—' : `${Number(st.vol).toFixed(Math.max(0, decimals - 1))}${suffix}`);
}

function updateChartsAndTrendMini() {
  charts.tps?.draw(state.tpsHistory);
  charts.fee?.draw(state.feeHistory);
  charts.tps2?.draw(state.tpsHistory);
  charts.fee2?.draw(state.feeHistory);

  const tps = calcTrendStats(state.tpsHistory, TREND_WINDOW);
  const fee = calcTrendStats(state.feeHistory, TREND_WINDOW);

  updateTrendMini('tpsTrendMini', tps, 2, '');
  updateTrendMini('tpsTrendMini2', tps, 2, '');
  updateTrendMini('feeTrendMini', fee, 0, 'd');
  updateTrendMini('feeTrendMini2', fee, 0, 'd');

  charts.dexPressure?.draw(series.dexPressure);
  charts.nftMints?.draw(series.nftMints);
  charts.nftBurns?.draw(series.nftBurns);
  charts.autoBridge?.draw(series.autoBridge);
  charts.marketPrice?.draw(series.marketPrice);
  charts.marketVol?.draw(series.marketVol);
}

/* ─────────────────────────────
   Ledger log
──────────────────────────────── */
function updateLedgerLog() {
  const logEl = $('ledger-log');
  const loadEl = $('ledger-log-loading');
  const countEl = $('ledger-log-count');
  if (!logEl || !(state.ledgerLog || []).length) return;

  if (loadEl) loadEl.style.display = 'none';
  if (countEl) countEl.textContent = state.ledgerLog.length;

  const tabEl = $('tab-network');
  if (!tabEl || tabEl.style.display === 'none') return;

  logEl.innerHTML =
    `<div class="ledger-log-row log-head">
      <span>Ledger</span><span>TXs</span><span>TPS</span><span>Close</span><span>Time</span>
    </div>` +
    state.ledgerLog.slice(0, 60).map((r) => `
      <div class="ledger-log-row">
        <span class="log-index">#${r.ledgerIndex.toLocaleString()}</span>
        <span class="log-tx">${r.txCount}</span>
        <span class="log-tps">${r.tps}</span>
        <span class="log-close">${r.closeTimeSec}s</span>
        <span class="log-time">${r.time}</span>
      </div>`).join('');
}

/* ─────────────────────────────
   Stream — ledger-driven loop deck
──────────────────────────────── */
const ledgerQueue  = [];
const seenLedgers  = new Set();
let _halfLen = 0;

let _streamRAF          = null;
let _streamLastTS       = 0;
let _rawOffset          = 0;
let _streamLoopWidth    = 0;
let _streamNeedsMeasure = true;
let _measureAttempts    = 0;
let _streamPaused       = false;
let _lastCardTs         = 0;
let _stallOverlayShown  = false;
let _pinnedIndex        = null;

let _cardStepPx    = 0;
let _targetOffset  = 0;
let _hasTarget     = false;
const LERP_TAU     = 0.18;

function initLedgerStream() {
  spawnParticles();
  startStreamAnimation();
}

function spawnParticles() {
  const layer = $('ledgerStreamParticles');
  if (!layer) return;
  layer.innerHTML = '';
  for (let i = 0; i < 14; i++) {
    const p = document.createElement('div');
    p.className = 'ledger-particle';
    p.style.left = Math.random() * 100 + '%';
    p.style.top  = (20 + Math.random() * 60) + '%';
    p.style.animationDuration = (6 + Math.random() * 8) + 's';
    p.style.animationDelay    = (Math.random() * 5) + 's';
    layer.appendChild(p);
  }
}

function startStreamAnimation() {
  if (_streamRAF) return;

  const shell = $('ledgerStreamShell');
  if (shell) {
    shell.addEventListener('mouseenter', () => { _streamPaused = true;  });
    shell.addEventListener('mouseleave', () => { if (!_uiModalOpen) _streamPaused = false; });
  }

  const track = $('ledgerStreamTrack');
  if (track) {
    track.addEventListener('click', (e) => {
      const card = e.target.closest('article.ledger-card');
      if (!card) return;
      const idx = Number(card.dataset.ledgerIndex);
      if (!Number.isFinite(idx)) return;

      if (e.shiftKey) {
        if (_pinnedIndex === idx) {
          _pinnedIndex = null;
          if (!_uiModalOpen) _streamPaused = false;
          _updatePinnedHighlight();
        } else {
          _pinnedIndex  = idx;
          _streamPaused = true;
          _updatePinnedHighlight();
        }
      } else {
        _openInspectorForLedger(idx);
      }
    });
  }

  const step = (ts) => {
    if (!_streamLastTS) _streamLastTS = ts;
    const dt = Math.min(0.05, (ts - _streamLastTS) / 1000);
    _streamLastTS = ts;

    const tr = $('ledgerStreamTrack');
    if (tr && _halfLen > 0) {
      if (_streamNeedsMeasure) {
        const full = tr.scrollWidth || 0;
        if (full > 100) {
          _streamLoopWidth    = Math.floor(full / 2);
          _streamNeedsMeasure = false;
          _measureAttempts    = 0;
          if (_halfLen > 0) _cardStepPx = _streamLoopWidth / _halfLen;
        } else {
          _measureAttempts++;
          if (_measureAttempts > 30) {
            _streamNeedsMeasure = false;
            _measureAttempts    = 0;
          }
          _streamRAF = requestAnimationFrame(step);
          return;
        }
      }

      if (_streamLoopWidth > 0 && !_streamPaused && _hasTarget) {
        const alpha = Math.min(1, dt / LERP_TAU);
        _rawOffset += (_targetOffset - _rawOffset) * alpha;

        if (Math.abs(_targetOffset - _rawOffset) < 0.5) _rawOffset = _targetOffset;

        const visual = _rawOffset % _streamLoopWidth;
        tr.style.transform = `translateX(${-visual}px)`;
      }

      if (!_streamPaused && Math.floor(ts / 250) !== Math.floor((ts - dt * 1000) / 250)) {
        const now = Date.now();
        const cards = tr.querySelectorAll('article.ledger-card[data-arrival-ts]');
        const maxAge = 120000;
        cards.forEach(c => {
          const age = now - Number(c.dataset.arrivalTs || now);
          const opacity = Math.max(0.52, 1 - (age / maxAge) * 0.48);
          c.style.opacity = opacity.toFixed(3);
        });
      }

      if (_lastCardTs > 0) {
        const stalled = (Date.now() - _lastCardTs) > STALL_TIMEOUT_MS;
        _setStallOverlay(stalled);
      }
    }

    _streamRAF = requestAnimationFrame(step);
  };

  _streamRAF = requestAnimationFrame(step);
  window.addEventListener('resize', () => { _streamNeedsMeasure = true; });
}

function _computeTargetOffset() {
  if (_cardStepPx <= 0 || _streamLoopWidth <= 0 || _halfLen === 0) return _rawOffset;

  const shell     = $('ledgerStreamShell');
  const shellW    = shell ? (shell.offsetWidth || 800) : 800;
  const cardW     = _cardStepPx - 14;
  const newestRight = (_halfLen - 1) * _cardStepPx + cardW;
  let targetVisual = newestRight - shellW + 18;

  targetVisual = Math.max(0, targetVisual);

  const currentLoop = Math.floor(_rawOffset / _streamLoopWidth);
  let target = currentLoop * _streamLoopWidth + targetVisual;

  if (target < _rawOffset - 2) target += _streamLoopWidth;

  return target;
}

function _setStallOverlay(show) {
  if (show === _stallOverlayShown) return;
  _stallOverlayShown = show;
  const shell = $('ledgerStreamShell');
  if (!shell) return;

  let overlay = shell.querySelector('.stream-stall-overlay');
  if (show) {
    if (!overlay) {
      overlay = document.createElement('div');
      overlay.className = 'stream-stall-overlay';
      overlay.innerHTML = '<span class="stream-stall-dot"></span> Waiting for ledgers…';
      shell.appendChild(overlay);
    }
  } else {
    overlay?.remove();
  }
}

function _updatePinnedHighlight() {
  document.querySelectorAll('.ledger-card').forEach(card => {
    const idx = Number(card.dataset.ledgerIndex);
    card.classList.toggle('ledger-card--pinned', idx === _pinnedIndex);
  });
}

function _openInspectorForLedger(ledgerIdx) {
  const tabBtn = document.querySelector('.dash-tab[data-tab="inspector"]');
  if (typeof window.switchTab === 'function' && tabBtn) window.switchTab(tabBtn, 'inspector');
  else tabBtn?.click();

  const input  = document.getElementById('inspect-addr');
  if (input) {
    input.placeholder = `Ledger #${ledgerIdx.toLocaleString()} — paste an address`;
    input.focus();
  }
}

function _flashReconnect() {
  const shell = $('ledgerStreamShell');
  if (!shell) return;
  shell.classList.remove('stream-reconnect-flash');
  void shell.offsetWidth;
  shell.classList.add('stream-reconnect-flash');
  setTimeout(() => shell.classList.remove('stream-reconnect-flash'), 1200);

  // Show "Reconnected — rebuilding baseline" banner for 3 ledgers
  _lastReconnectLedger = _frictionHistory.at(-1)?.li ?? 0;
  _showReconnectBanner();
}

function _showReconnectBanner() {
  let banner = document.getElementById('reconnect-banner');
  if (!banner) {
    banner = document.createElement('div');
    banner.id = 'reconnect-banner';
    banner.className = 'reconnect-banner';
    const main = document.querySelector('.dashboard-col-main');
    if (main) main.prepend(banner);
  }
  banner.style.display = '';
  banner.innerHTML = `
    <span class="reconnect-dot"></span>
    <span>Reconnected — rebuilding signal baseline (<span id="reconnect-countdown">3</span> ledgers)</span>
    <button onclick="document.getElementById('reconnect-banner').style.display='none'"
      style="margin-left:auto;background:none;border:none;color:inherit;opacity:.5;cursor:pointer;font-size:.9rem">✕</button>`;

  let countdown = 3;
  const interval = setInterval(() => {
    const el = document.getElementById('reconnect-countdown');
    if (el) el.textContent = countdown;
    countdown--;
    if (countdown < 0) {
      clearInterval(interval);
      const b = document.getElementById('reconnect-banner');
      if (b) b.style.display = 'none';
    }
  }, 4000); // roughly one ledger per 4s
}

function renderLedgerStream() {
  const track = $('ledgerStreamTrack');
  if (!track) return;

  const loading = $('stream-loading');
  if (loading) loading.style.display = 'none';

  if (ledgerQueue.length === 0) {
    track.innerHTML = '<div style="padding:40px;opacity:.6">Waiting for ledgers…</div>';
    _halfLen = 0;
    _streamNeedsMeasure = true;
    return;
  }

  const sorted = [...ledgerQueue].sort((a, b) => a.ledgerIndex - b.ledgerIndex);
  const html = sorted.map((l, i) =>
    buildLedgerCardHtml(l, { prevIndex: i > 0 ? sorted[i - 1].ledgerIndex : null })
  );

  track.innerHTML = html.concat(html).join('');
  _halfLen = sorted.length;

  _streamNeedsMeasure = true;
  requestAnimationFrame(() => {
    const full = $('ledgerStreamTrack')?.scrollWidth || 0;
    if (full > 100) {
      _streamLoopWidth = Math.floor(full / 2);
      _cardStepPx      = _halfLen > 0 ? _streamLoopWidth / _halfLen : 0;
      _targetOffset    = _computeTargetOffset();
      _hasTarget       = true;
      _streamNeedsMeasure = false;
    }
  });
}

function pushLedgerCard(ledger) {
  if (!ledger) return;

  const ledgerIdx = Number(ledger.ledgerIndex ?? NaN);
  if (!Number.isFinite(ledgerIdx)) return;

  if (seenLedgers.has(ledgerIdx)) return;
  seenLedgers.add(ledgerIdx);
  ledgerQueue.push(ledger);

  if (ledgerQueue.length > STREAM_QUEUE_MAX) {
    const evicted = ledgerQueue.splice(0, ledgerQueue.length - STREAM_QUEUE_MAX);
    evicted.forEach(e => seenLedgers.delete(e.ledgerIndex));
  }

  _lastCardTs = Date.now();
  _setStallOverlay(false);

  _updateFeeBaseline(ledger.avgFee != null ? Number(ledger.avgFee) : null);

  const { auraClass, domColor } = dominantInfoFromLedger(ledger);
  applyStreamTint(auraClass, domColor);

  const loading = $('stream-loading');
  if (loading) loading.style.display = 'none';

  const track = $('ledgerStreamTrack');
  if (!track) return;

  if (_halfLen === 0) {
    renderLedgerStream();
    return;
  }

  const prevMax = ledgerQueue.length >= 2
    ? ledgerQueue[ledgerQueue.length - 2].ledgerIndex
    : 0;
  if (ledgerIdx < prevMax) {
    renderLedgerStream();
    return;
  }

  const H = _halfLen;
  const html = buildLedgerCardHtml(ledger);

  const t1 = document.createElement('template');
  t1.innerHTML = html;
  const node1 = t1.content.firstElementChild;
  const pivot  = track.children[H];
  if (pivot) track.insertBefore(node1, pivot);
  else track.appendChild(node1);

  const t2 = document.createElement('template');
  t2.innerHTML = html;
  track.appendChild(t2.content.firstElementChild);

  _halfLen = H + 1;
  _streamNeedsMeasure = true;

  requestAnimationFrame(() => {
    if (_cardStepPx <= 0 && _streamLoopWidth > 0 && _halfLen > 0) {
      _cardStepPx = _streamLoopWidth / _halfLen;
    }
    _targetOffset = _computeTargetOffset();
    _hasTarget = true;
  });
}

const _feeWindow = [];
const FEE_WINDOW_SIZE = 20;

function _updateFeeBaseline(feeXrp) {
  if (feeXrp == null || !Number.isFinite(feeXrp)) return;
  _feeWindow.push(feeXrp);
  if (_feeWindow.length > FEE_WINDOW_SIZE) _feeWindow.shift();
}

function _feeBaseline() {
  if (_feeWindow.length === 0) return null;
  return _feeWindow.reduce((a, b) => a + b, 0) / _feeWindow.length;
}

function buildLedgerCardHtml(ledger, opts = {}) {
  const { ledgerIndex, closeTimeSec, totalTx, txTypes, avgFee } = ledger;
  const t = txTypes || {};
  const total = totalTx ?? 0;

  const domEntry = Object.entries(t).sort(([, a], [, b]) => b - a)[0];
  const domType  = domEntry?.[0] || 'Other';
  const aura     = dominantAuraClassFromType(domType);

  const C      = typeof TX_COLORS !== 'undefined' ? TX_COLORS : {};
  const col    = (k) => C[k] || '#6b7280';
  const domClr = col(domType);
  const border = hexToRgba(domClr, 0.45) || domClr;
  const glow   = hexToRgba(domClr, 0.14) || domClr;

  const closeDisplay = closeTimeSec == null ? '—'
    : closeTimeSec < 2 ? `${Number(closeTimeSec).toFixed(2)}s`
    : `${Number(closeTimeSec).toFixed(1)}s`;

  const tpsVal = (total > 0 && closeTimeSec > 0)
    ? (total / closeTimeSec).toFixed(1)
    : null;

  const feeXrp = avgFee != null ? Number(avgFee) : null;
  const feeDisplay = feeXrp != null ? fmtXrp(feeXrp) : '—';
  const baseline = _feeBaseline();
  const isSpike = feeXrp != null && baseline != null && feeXrp > baseline * 3;

  const gapCount = opts.prevIndex != null ? (Number(ledgerIndex) - opts.prevIndex - 1) : 0;
  const gapBadge = gapCount > 0
    ? `<div class="stream-gap-badge" title="${gapCount} ledger(s) missing">···&nbsp;${gapCount} gap</div>`
    : '';

  const pct = (v) => total > 0 ? `${((v / total) * 100).toFixed(1)}%` : '0%';
  const txRow = (label, count, colorX) => {
    if (!count) return '';
    return `<div class="ledger-type-row">
      <span class="ledger-type-label cut">${escHtml(label)}</span>
      <div class="ledger-type-bar"><div class="ledger-type-fill" style="width:${pct(count)};background:${colorX}"></div></div>
      <span class="ledger-type-count">${count}</span>
    </div>`;
  };

  const ammTotal = (t.AMMCreate || 0) + (t.AMMDeposit || 0) + (t.AMMWithdraw || 0) + (t.AMMVote || 0);
  const arrivalTs = Date.now();

  return `${gapBadge}<article class="ledger-card ledger-card--${aura} ledger-card--entry${isSpike ? ' ledger-card--fee-spike' : ''}"
    data-ledger-index="${Number(ledgerIndex ?? 0)}"
    data-arrival-ts="${arrivalTs}"
    style="border-color:${border};box-shadow:0 0 22px ${glow};flex-shrink:0">
    <div class="ledger-card-inner">
      <div class="ledger-card-header">
        <span class="ledger-id">#${(ledgerIndex || 0).toLocaleString()}</span>
        <div class="ledger-meta">
          <span class="ledger-tag cut" style="border-color:${border};color:${domClr}">${escHtml(domType)}</span>
          ${isSpike ? '<span class="fee-spike-badge" title="Fee spike: 3× baseline">🔥</span>' : ''}
        </div>
      </div>
      <div class="ledger-main-row">
        <div class="ledger-main-stat"><span class="ledger-stat-label">TXs</span><span class="ledger-stat-value">${total}</span></div>
        <div class="ledger-main-stat"><span class="ledger-stat-label">Close</span><span class="ledger-stat-value">${closeDisplay}</span></div>
        <div class="ledger-main-stat"><span class="ledger-stat-label">Avg Fee</span><span class="ledger-stat-value${isSpike ? ' fee-spike-value' : ''}">${feeDisplay}</span></div>
        ${tpsVal != null ? `<div class="ledger-main-stat"><span class="ledger-stat-label">TPS</span><span class="ledger-stat-value">${tpsVal}</span></div>` : ''}
      </div>
      <div class="ledger-type-bars">
        ${txRow('Payment',     t.Payment,     col('Payment'))}
        ${txRow('OfferCreate', t.OfferCreate, col('OfferCreate'))}
        ${txRow('OfferCancel', t.OfferCancel, col('OfferCancel'))}
        ${txRow('TrustSet',    t.TrustSet,    col('TrustSet'))}
        ${txRow('NFT Mint',    t.NFTokenMint, col('NFTokenMint'))}
        ${ammTotal ? txRow('AMM', ammTotal, col('AMMCreate')) : ''}
        ${txRow('EscrowCreate', t.EscrowCreate, '#6b7280')}
        ${(t.Other || 0) > 0 ? txRow('Other', t.Other, '#6b7280') : ''}
      </div>
    </div>
  </article>`;
}

function dominantAuraClassFromType(txType) {
  const t = String(txType || '');
  if (t === 'Payment') return 'payment';
  if (t.startsWith('Offer')) return 'offer';
  if (t.startsWith('NFToken')) return 'nft';
  if (t === 'TrustSet') return 'trust';
  if (t.startsWith('AMM')) return 'amm';
  return 'other';
}

function dominantInfoFromLedger(ledger) {
  const sorted = Object.entries(ledger.txTypes || {}).sort(([, a], [, b]) => b - a);
  const dominantTx = sorted[0]?.[0] || 'Other';
  const auraClass = dominantAuraClassFromType(dominantTx);
  const domColor = TX_COLORS[dominantTx] || TX_COLORS.Other || '#6b7280';
  return { dominantTx, auraClass, domColor };
}

function applyStreamTint(auraClass, domColor) {
  const shell = $('ledgerStreamShell');
  if (!shell) return;

  if (!auraClass || !domColor) {
    shell.style.removeProperty('--streamTintStrong');
    shell.style.removeProperty('--streamTintSoft');
    shell.style.removeProperty('--streamTintBorder');
    return;
  }

  const strong = hexToRgba(domColor, 0.16) || 'rgba(0,255,240,0.14)';
  const soft = hexToRgba(domColor, 0.06) || 'rgba(0,255,240,0.06)';
  const border = hexToRgba(domColor, 0.22) || 'rgba(0,255,240,0.22)';

  shell.style.setProperty('--streamTintStrong', strong);
  shell.style.setProperty('--streamTintSoft', soft);
  shell.style.setProperty('--streamTintBorder', border);
  shell.dataset.tint = auraClass;
}

/* ─────────────────────────────
   Derived analytics
──────────────────────────────── */
function computeDerived(s) {
  const txs = Array.isArray(s.recentTransactions) ? s.recentTransactions.slice(0, MAX_TX_SAMPLE) : [];
  const txTypes = s.txTypes || {};
  const li = Number(s.ledgerIndex || 0);

  const tot = Object.values(txTypes).reduce((a, b) => a + b, 0) || 1;
  let hhi = 0;
  for (const c of Object.values(txTypes)) {
    const p = c / tot;
    hhi += p * p;
  }

  const thisPairs = buildPairMapFromTxs(txs);
  addWindowMap(pairState, thisPairs);

  const breadcrumbs = buildBreadcrumbs(pairState.totals, thisPairs);
  const clusters = buildClusters(pairState.totals);

  const behavior = updateBehavior(li, txs);
  const dexPatterns = updateDexPatterns(li, s.latestLedger?.closeTimeSec, txs);

  // compute advanced BEFORE friction uses it
  const advanced = computeAdvancedMetrics({ txs, txTypes, dexPatterns });

  const repeats = breadcrumbs.filter((p) => p.count >= 2).length;
  const friction = computeFrictionScore({
    hhi,
    repeats,
    dex: dexPatterns,
    bots: behavior.bots?.length || 0,
    advanced,
  });

  const regime = classifyRegime({
    friction,
    tps: calcTrendStats(state.tpsHistory),
    fee: calcTrendStats(state.feeHistory),
  });

  const narratives = buildNarratives({ s, txTypes, hhi, dexPatterns, behavior, friction, regime, breadcrumbs, clusters, advanced });

  return { s, txs, txTypes, hhi, behavior, dexPatterns, friction, regime, breadcrumbs, clusters, narratives, advanced };
}

function buildPairMapFromTxs(txs) {
  const m = new Map();
  for (const tx of txs) {
    const from = tx?.account;
    const to = tx?.destination;
    if (!from || !to) continue;
    const key = `${from}|${to}`;
    m.set(key, (m.get(key) || 0) + 1);
  }
  return m;
}

function addWindowMap(pairSt, newMap) {
  pairSt.window.unshift(newMap);
  for (const [k, v] of newMap.entries()) {
    pairSt.totals.set(k, (pairSt.totals.get(k) || 0) + v);
  }
  while (pairSt.window.length > pairSt.maxLedgers) {
    const old = pairSt.window.pop();
    for (const [k, v] of old.entries()) {
      const next = (pairSt.totals.get(k) || 0) - v;
      if (next <= 0) pairSt.totals.delete(k);
      else pairSt.totals.set(k, next);
    }
  }
}

function buildBreadcrumbs(totals, latest) {
  const entries = [...totals.entries()].map(([k, c]) => ({ k, c })).sort((a, b) => b.c - a.c);
  const repeats = entries.filter((e) => e.c >= 2);
  const base = repeats.length ? repeats : [...latest.entries()].map(([k, c]) => ({ k, c }));
  return base.slice(0, 10).map(({ k, c }) => {
    const [from, to] = k.split('|');
    return { from, to, count: c };
  });
}

function buildClusters(totals) {
  const edges = [...totals.entries()].filter(([, c]) => c >= 2);
  const use = edges.length ? edges : [...totals.entries()];

  const adj = new Map();
  for (const [k] of use) {
    const [a, b] = k.split('|');
    if (!a || !b) continue;
    if (!adj.has(a)) adj.set(a, new Set());
    if (!adj.has(b)) adj.set(b, new Set());
    adj.get(a).add(b);
    adj.get(b).add(a);
  }

  const seen = new Set();
  const comps = [];

  for (const node of adj.keys()) {
    if (seen.has(node)) continue;

    const stack = [node];
    const members = [];
    seen.add(node);

    while (stack.length) {
      const cur = stack.pop();
      members.push(cur);
      for (const nxt of adj.get(cur) || []) {
        if (!seen.has(nxt)) {
          seen.add(nxt);
          stack.push(nxt);
        }
      }
    }

    if (members.length < 2) continue;

    let hub = members[0];
    let hubDeg = -1;
    for (const m of members) {
      const deg = (adj.get(m) || new Set()).size;
      if (deg > hubDeg) { hubDeg = deg; hub = m; }
    }

    comps.push({ members, size: members.length, hub });
  }

  comps.sort((a, b) => b.size - a.size);
  return comps.slice(0, 6);
}

function updateBehavior(li, txs) {
  const acctCounts = new Map();
  for (const tx of txs) {
    const a = tx?.account;
    if (!a) continue;
    acctCounts.set(a, (acctCounts.get(a) || 0) + 1);
  }

  for (const [acct, cnt] of acctCounts.entries()) {
    if (!behaviorState.acct.has(acct)) {
      behaviorState.acct.set(acct, { ledgers: [], intervals: [], total: 0 });
    }
    const st = behaviorState.acct.get(acct);
    const last = st.ledgers.at(-1);
    st.ledgers.push(li);
    if (last != null && li > last) st.intervals.push(li - last);
    if (st.ledgers.length > 30) st.ledgers.shift();
    if (st.intervals.length > 29) st.intervals.shift();
    st.total += cnt;
  }

  const bots = [];
  for (const [acct, st] of behaviorState.acct.entries()) {
    if (st.intervals.length < 6) continue;
    const mu = mean(st.intervals);
    const sd = stdev(st.intervals);
    if (!mu || sd == null) continue;
    const cv = sd / mu;
    if (cv < 0.35 && st.total > 10) bots.push({ acct, cv, total: st.total });
  }
  bots.sort((a, b) => a.cv - b.cv || b.total - a.total);

  return { bots: bots.slice(0, 6), uniqueActors: acctCounts.size };
}

/* ─────────────────────────────
   DEX Pattern Monitor (stream-based, no polling)
──────────────────────────────── */
function updateDexPatterns(li, closeTimeSec, txs) {
  let create = 0;
  let cancel = 0;

  const byActor = new Map();
  const byActorCreate = new Map();
  const byActorCancel = new Map();

  for (const tx of txs) {
    const t = tx?.type;
    const a = tx?.account;
    if (!a) continue;

    if (t === 'OfferCreate') {
      create += 1;
      byActor.set(a, (byActor.get(a) || 0) + 1);
      byActorCreate.set(a, (byActorCreate.get(a) || 0) + 1);
    } else if (t === 'OfferCancel') {
      cancel += 1;
      byActor.set(a, (byActor.get(a) || 0) + 1);
      byActorCancel.set(a, (byActorCancel.get(a) || 0) + 1);
    }
  }

  const total = create + cancel;
  const cancelRatio = total ? cancel / total : 0;

  const cancelsPerMinRaw =
    closeTimeSec != null && Number(closeTimeSec) > 0
      ? (cancel / Number(closeTimeSec)) * 60
      : null;

  dexState.smoothCancelPerMin = smooth(dexState.smoothCancelPerMin, cancelsPerMinRaw, 0.45);

  dexState.window.unshift({
    li,
    closeTimeSec: closeTimeSec ?? null,
    create,
    cancel,
    total,
    cancelRatio,
    cancelsPerMin: dexState.smoothCancelPerMin,
    byActor,
    byActorCreate,
    byActorCancel,
  });

  while (dexState.window.length > DEX_WINDOW) dexState.window.pop();

  const sum = { create: 0, cancel: 0, total: 0 };
  const aggActor = new Map();
  const aggCancel = new Map();
  const aggCreate = new Map();

  for (const w of dexState.window) {
    sum.create += w.create;
    sum.cancel += w.cancel;
    sum.total += w.total;

    for (const [a, c] of w.byActor.entries()) aggActor.set(a, (aggActor.get(a) || 0) + c);
    for (const [a, c] of w.byActorCancel.entries()) aggCancel.set(a, (aggCancel.get(a) || 0) + c);
    for (const [a, c] of w.byActorCreate.entries()) aggCreate.set(a, (aggCreate.get(a) || 0) + c);
  }

  const topActor = topN(aggActor, 5);
  const topCanceller = topN(aggCancel, 5);
  const topMaker = topN(aggCreate, 5);

  const topShare = sum.total ? (topActor[0]?.count || 0) / sum.total : 0;

  let actorHHI = 0;
  if (sum.total) {
    for (const c of aggActor.values()) {
      const p = c / sum.total;
      actorHHI += p * p;
    }
  }

  const totals = dexState.window.map((x) => x.total).filter(Number.isFinite);
  const avgTotal = mean(totals) || 0;
  const burstRaw = avgTotal > 0 ? ((total - avgTotal) / avgTotal) * 100 : null;
  dexState.smoothBurst = smooth(dexState.smoothBurst, burstRaw, 0.40);

  const signals = [];
  if (sum.total >= DEX_MIN_FOR_SIGNALS && cancelRatio >= 0.65) signals.push('Lots of cancels (looks like quote-stuffing/spam)');
  if (sum.total >= DEX_MIN_FOR_SIGNALS && topShare >= 0.35) signals.push('One actor dominates DEX activity');
  if (sum.total >= DEX_MIN_FOR_SIGNALS && (dexState.smoothCancelPerMin || 0) >= 18) signals.push('Fast cancelling (high churn)');
  if (dexState.smoothBurst != null && Math.abs(dexState.smoothBurst) >= 45) signals.push('Sudden DEX burst');

  return {
    now: { li, create, cancel, total, cancelRatio, cancelsPerMin: dexState.smoothCancelPerMin },
    window: { ...sum, cancelRatio: sum.total ? sum.cancel / sum.total : 0 },
    topShare,
    actorHHI,
    burstPct: dexState.smoothBurst,
    topActor,
    topCanceller,
    topMaker,
    signals,
  };
}

function topN(map, n) {
  return [...map.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, n)
    .map(([acct, count]) => ({ acct, count }));
}

/* ─────────────────────────────
   Advanced metrics (DEX pressure, Autobridge flows, NFT minting)
──────────────────────────────── */
function computeAdvancedMetrics({ txs, txTypes, dexPatterns }) {
  const offerTotal = Number(txTypes?.OfferCreate || 0) + Number(txTypes?.OfferCancel || 0);

  const mints = Number(txTypes?.NFTokenMint || 0);
  const burns = Number(txTypes?.NFTokenBurn || 0);

  // Path payments / autobridge heuristic:
  let pathPays = 0;
  const pathActors = new Map();
  const pathPairs = new Map();

  for (const tx of txs) {
    if (tx?.type !== 'Payment') continue;

    const paths = tx?.paths || tx?.Paths;
    const hasPaths = Array.isArray(paths) && paths.length > 0;
    const hasSendMax = tx?.sendmax != null || tx?.SendMax != null;
    const hasDeliverMax = tx?.delivermax != null || tx?.DeliverMax != null;
    const isPathPay = hasPaths || hasSendMax || hasDeliverMax;

    if (!isPathPay) continue;

    pathPays += 1;

    const a = tx?.account;
    const d = tx?.destination;
    if (a) pathActors.set(a, (pathActors.get(a) || 0) + 1);
    if (a && d) {
      const k = `${a}|${d}`;
      pathPairs.set(k, (pathPairs.get(k) || 0) + 1);
    }
  }

  const topPathActors = [...pathActors.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5)
    .map(([acct, count]) => ({ acct, count }));

  const topPathPairs = [...pathPairs.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5)
    .map(([k, count]) => {
      const [from, to] = k.split('|');
      return { from, to, count };
    });

  const dexCancelPct = dexPatterns?.now?.total ? Math.round((dexPatterns.now.cancelRatio || 0) * 100) : 0;
  const dexTopSharePct = dexPatterns?.topShare != null ? Math.round(dexPatterns.topShare * 100) : 0;

  // Roundness index (Payments)
  const payAmounts = txs
    .filter(tx => tx?.type === 'Payment')
    .map(tx => (typeof tx?.amountXrp === 'number' ? tx.amountXrp : null))
    .filter(v => v != null && v > 0 && Number.isFinite(v));

  const roundMagn = [100, 1_000, 10_000];
  const roundCount = payAmounts.filter(v => roundMagn.some(m => Math.abs(v % m) < 1e-9 && v / m >= 1)).length;
  const roundnessIdx = payAmounts.length >= 5 ? Math.round((roundCount / payAmounts.length) * 100) : null;

  const selfTradeCount = txs.filter(tx =>
    tx?.type === 'Payment' && tx?.account && tx?.destination &&
    tx.account === tx.destination
  ).length;

  // ── AMM / LP enrichment ────────────────────────────────────────────────
  const ammCreate  = Number(txTypes?.AMMCreate   || 0);
  const ammDeposit = Number(txTypes?.AMMDeposit  || 0);
  const ammWithdraw= Number(txTypes?.AMMWithdraw || 0);
  const ammVote    = Number(txTypes?.AMMVote     || 0);
  const ammBid     = Number(txTypes?.AMMBid      || 0);
  const ammDelete  = Number(txTypes?.AMMDelete   || 0);
  const lpTotal    = ammCreate + ammDeposit + ammWithdraw + ammVote + ammBid + ammDelete;
  const lpNetFlow  = ammDeposit - ammWithdraw;
  const lpRatio    = (ammDeposit + ammWithdraw) > 0
    ? Math.round((ammDeposit / (ammDeposit + ammWithdraw)) * 100) : null;
  const lpActors = new Set();
  for (const tx of txs) {
    if (['AMMCreate','AMMDeposit','AMMWithdraw','AMMVote','AMMBid'].includes(tx?.type) && tx?.account)
      lpActors.add(tx.account);
  }
  const lpUniqueActors = lpActors.size;

  // ── Avg path depth ────────────────────────────────────────────────────
  let totalPathDepth = 0, pathWithDepth = 0;
  for (const tx of txs) {
    if (tx?.type === 'Payment' && Array.isArray(tx?.paths) && tx.paths.length > 0) {
      totalPathDepth += tx.paths.length; pathWithDepth++;
    }
  }
  const avgPathDepth = pathWithDepth > 0 ? (totalPathDepth / pathWithDepth).toFixed(1) : null;

  return {
    offerTotal, dexCancelPct, dexTopSharePct,
    mints, burns, pathPays, topPathActors, topPathPairs,
    roundnessIdx, selfTradeCount,
    ammCreate, ammDeposit, ammWithdraw, ammVote, ammBid, ammDelete,
    lpTotal, lpNetFlow, lpRatio, lpUniqueActors,
    avgPathDepth,
  };
}

/* ─────────────────────────────
   Friction / Regime
──────────────────────────────── */
function computeFrictionScore({ hhi, repeats, dex, bots, advanced }) {
  const cHHI = clamp((hhi - 0.22) / 0.25, 0, 1) * 22;
  const cRep = clamp((repeats - 2) / 6, 0, 1) * 12;

  const dexCancel = dex?.window?.cancelRatio ?? 0;
  const dexTopShare = dex?.topShare ?? 0;
  const dexChurn = dex?.now?.cancelsPerMin ?? 0;

  const cDexC = clamp((dexCancel - 0.50) / 0.50, 0, 1) * 18;
  const cDexT = clamp((dexTopShare - 0.25) / 0.50, 0, 1) * 18;
  const cChurn = clamp(dexChurn / 25, 0, 1) * 10;

  const cBots = clamp(bots / 6, 0, 1) * 10;

  const cRound  = advanced?.roundnessIdx != null ? clamp((advanced.roundnessIdx - 30) / 40, 0, 1) * 8 : 0;
  const cSelf   = advanced?.selfTradeCount > 0 ? Math.min(8, advanced.selfTradeCount * 4) : 0;
  const cPath   = advanced?.pathPays != null ? clamp(advanced.pathPays / 30, 0, 1) * 6 : 0;

  return Math.round(cHHI + cRep + cDexC + cDexT + cChurn + cBots + cRound + cSelf + cPath);
}

function classifyRegime({ friction, tps, fee }) {
  const feeShock = fee?.deltaPct != null && Math.abs(fee.deltaPct) >= 35;
  const tpsShock = tps?.deltaPct != null && Math.abs(tps.deltaPct) >= 25;

  if (friction >= 75) return 'Manipulated';
  if (feeShock || tpsShock) return 'Stressed';
  if ((tps?.cur ?? 0) >= 12 || (tps?.avg ?? 0) >= 10) return 'Active';
  return 'Quiet';
}

/* ─────────────────────────────
   Narratives
──────────────────────────────── */
function buildNarratives({ s, txTypes, hhi, dexPatterns, behavior, friction, regime, breadcrumbs, clusters, advanced }) {
  const out = [];

  const tpsSt = calcTrendStats(state.tpsHistory, TREND_WINDOW);
  const feeSt = calcTrendStats(state.feeHistory, TREND_WINDOW);

  const dom = Object.entries(txTypes || {}).sort(([, a], [, b]) => b - a)[0]?.[0] || '—';
  const totalTx = Number(s.txPerLedger || 0);

  out.push({
    sentiment: regime === 'Manipulated' ? 'warn' : regime === 'Stressed' ? 'warn' : regime === 'Active' ? 'up' : 'ok',
    title: `Overall: ${regime} · Risk score ${friction}/100`,
    detail: `Heuristic score from concentration, repeats, DEX churn, bot-like timing, and routing indicators. It's a signal, not proof.`,
  });

  out.push({
    sentiment: 'ok',
    title: `Ledger snapshot: #${Number(s.ledgerIndex || 0).toLocaleString()} · ${totalTx} tx · most common: ${dom}`,
    detail: `TPS ${safeNum(tpsSt.cur, 2)} (avg ${safeNum(tpsSt.avg, 2)} · ${fmtPct(tpsSt.deltaPct, 0)}). Fee ${feeSt.cur != null ? fmtXrp(feeSt.cur) : '—'} (avg ${feeSt.avg != null ? fmtXrp(feeSt.avg) : '—'} · ${fmtPct(feeSt.deltaPct, 0)}).`,
  });

  const conc = hhi >= 0.35 ? 'high' : hhi >= 0.25 ? 'medium' : 'low';
  out.push({
    sentiment: hhi >= 0.35 ? 'warn' : 'ok',
    title: `Transaction mix: ${conc} concentration (HHI ${hhi.toFixed(2)})`,
    detail: hhi >= 0.35
      ? 'A few tx types dominate. Patterns look “stronger,” but can be misleading.'
      : 'Mix is broad. Strong signals usually come from behavior, not just tx type.',
  });

  if (dexPatterns.window.total) {
    const cancelPct = Math.round(dexPatterns.window.cancelRatio * 100);
    const topPct = Math.round(dexPatterns.topShare * 100);
    out.push({
      sentiment: dexPatterns.signals.length ? 'warn' : 'ok',
      title: `DEX monitor: ${dexPatterns.window.total} offer tx (window) · cancels ${cancelPct}% · top actor ~${topPct}%`,
      detail: dexPatterns.signals.length ? `Signals: ${dexPatterns.signals.join(' · ')}` : 'No strong DEX-pattern signals right now.',
      addr: dexPatterns.topActor[0]?.acct || null,
    });
  }

  const repeats = breadcrumbs.filter((p) => p.count >= 2).length;
  if (repeats >= 2) {
    out.push({
      sentiment: 'new',
      title: `Repeating counterparties: ${repeats} recurring pair(s)`,
      detail: 'Repeated interactions can be routing loops, bots, or coordinated flows. Click addresses for a quick read.',
    });
  }

  if (clusters?.length && clusters[0]?.size >= 3) {
    out.push({
      sentiment: 'new',
      title: `Cluster forming: ${clusters[0].size} wallets · hub ${shortAddr(clusters[0].hub)}`,
      detail: 'Clusters are co-activity groups (not identity proof). Use as “likely related behavior.”',
      addr: clusters[0].hub,
    });
  }

  if (behavior.bots?.length) {
    const top = behavior.bots[0];
    out.push({
      sentiment: 'warn',
      title: `Bot-like timing: ${behavior.bots.length} candidate(s)`,
      detail: `Low variance in repeated appearances. Top: ${shortAddr(top.acct)} (CV ${top.cv.toFixed(2)}).`,
      addr: top.acct,
    });
  }

  if (advanced?.pathPays) {
    const top = advanced.topPathActors?.[0];
    out.push({
      sentiment: advanced.pathPays >= 18 ? 'warn' : 'ok',
      title: `Autobridge-ish routing: ${advanced.pathPays} path payments (ledger sample)`,
      detail: top ? `Most active routing wallet: ${shortAddr(top.acct)} (${top.count}).` : 'Paths/SendMax/DeliverMax appear frequently in the sample.',
      addr: top?.acct || null,
    });
  }

  if (advanced?.selfTradeCount) {
    out.push({
      sentiment: 'warn',
      title: `Self-transfer signal: ${advanced.selfTradeCount} payment(s) where sender = receiver`,
      detail: 'Self-transfers can be benign (housekeeping) or used to fake activity. Treat as a watch signal.',
    });
  }

  if ((advanced?.roundnessIdx ?? 0) >= 45) {
    out.push({
      sentiment: 'warn',
      title: `Round-number bias: ${advanced.roundnessIdx}% of payments are exact multiples of 100/1,000/10,000`,
      detail: 'Round-number bias often shows scripted behavior (bots) rather than human payments.',
    });
  }

  return out.slice(0, 12);
}

/* ─────────────────────────────
   Render: Breadcrumbs / Clusters / Narratives
──────────────────────────────── */
function renderBreadcrumbs(pairs) {
  const el = $('d2-breadcrumb-list');
  const meta = $('d2-breadcrumb-meta');
  if (!el) return;

  if (!pairs.length) {
    el.innerHTML = `<div class="gateway-item" style="opacity:.6">Watching for repeated interactions…</div>`;
    if (meta) meta.textContent = '—';
    return;
  }

  const repeats = pairs.filter((p) => p.count >= 2).length;
  if (meta) meta.textContent = repeats ? `${repeats} repeats` : `Top interactions`;

  el.innerHTML = pairs.slice(0, 10).map((p) => `
    <div class="gateway-item gateway-row">
      <div class="gateway-left mono cut">
        <button class="addr-link mono cut gw-from" data-addr="${escHtml(p.from)}">${escHtml(shortAddr(p.from))}</button>
        <span class="gw-arrow">→</span>
        <button class="addr-link mono cut gw-to" data-addr="${escHtml(p.to)}">${escHtml(shortAddr(p.to))}</button>
      </div>
      <span class="gw-count">${p.count}×</span>
    </div>`).join('');
}

function renderClusters(clusters) {
  const el = $('d2-cluster-list');
  const meta = $('d2-cluster-persistence');
  if (!el) return;

  if (!clusters.length) {
    el.innerHTML = `<div class="gateway-item" style="opacity:.6">Building clusters… (needs repeated activity)</div>`;
    if (meta) meta.textContent = '—';
    return;
  }

  if (meta) meta.textContent = `${clusters.length} group${clusters.length !== 1 ? 's' : ''}`;

  el.innerHTML = clusters.slice(0, 6).map((c, i) => {
    const hue = (i * 67 + 120) % 360;
    const color = `hsl(${hue},70%,60%)`;
    const preview = c.members.slice(0, 4);

    return `
      <div class="gateway-item cluster-item">
        <div class="cluster-head">
          <span class="cluster-title" style="color:${color}">Group ${i + 1}</span>
          <span class="cluster-meta">${c.size} wallets</span>
        </div>
        <div class="cluster-preview">
          <span class="cluster-chip-h">Hub:</span>
          <button class="addr-chip mono" data-addr="${escHtml(c.hub)}">${escHtml(shortAddr(c.hub))}</button>
        </div>
        <div class="cluster-preview">
          <span class="cluster-chip-h">Members:</span>
          ${preview.map((a) => `<button class="addr-chip mono" data-addr="${escHtml(a)}">${escHtml(shortAddr(a))}</button>`).join('')}
          ${c.members.length > preview.length ? `<span class="cluster-more">+${c.members.length - preview.length}</span>` : ''}
        </div>
      </div>`;
  }).join('');
}

function renderNarratives(narratives) {
  const el = $('d2-delta-narratives');
  if (!el) return;

  if (!narratives.length) {
    el.innerHTML = `<div class="gateway-item" style="opacity:.6">Building baseline — narratives appear after 1–2 ledgers…</div>`;
    return;
  }

  const colors = { up: '#50fa7b', down: '#ff5555', new: '#00d4ff', warn: '#ffb86c', ok: 'rgba(255,255,255,.85)' };

  el.innerHTML = narratives.map((n) => {
    const color = colors[n.sentiment] || 'rgba(255,255,255,.85)';
    const addrBtn = n.addr && isValidXrpAddress(n.addr)
      ? `<button class="addr-link narrative-addr" data-addr="${escHtml(n.addr)}">Peek</button>`
      : '';

    return `
      <details class="gateway-item narrative-item">
        <summary style="color:${color}">
          <span class="narrative-title">${escHtml(n.title || n.text || '')}</span>
          ${addrBtn}
        </summary>
        <div class="narrative-detail">${escHtml(n.detail || '')}</div>
      </details>`;
  }).join('');
}

/* ─────────────────────────────
   Explainers + legend
──────────────────────────────── */
function injectSectionExplainers() {
  if (explainersMounted) return;
  explainersMounted = true;

  const helpByAria = new Map([
    ['Pattern detection', 'Quick “at a glance” read. If one thing dominates, patterns are easier to spot (but can be noisy).'],
    ['Live ledger stream', 'Each card is a validated ledger. Glow color shows what activity dominated that ledger. Click a card to jump to inspector.'],
    ['Wallet breadcrumbs', 'Shows who repeatedly interacts with who. Click an address for an account peek.'],
    ['Cluster inference', 'Groups wallets that move together. Not identity proof. Use it as “likely related behavior.”'],
    ['Delta narratives', 'Plain-English summary of what changed: load, fees, DEX churn, repeats, bot-like timing.'],
  ]);

  document.querySelectorAll('section.widget-card[aria-label], div.widget-card[aria-label]').forEach((node) => {
    const aria = node.getAttribute('aria-label') || '';
    const help = helpByAria.get(aria);
    if (!help) return;

    const header = node.querySelector('.widget-header');
    if (!header) return;
    if (node.querySelector('.widget-help')) return;

    const p = document.createElement('p');
    p.className = 'widget-help';
    p.textContent = help;
    header.insertAdjacentElement('afterend', p);
  });
}

function mountLedgerLegend() {
  if (legendMounted) return;
  legendMounted = true;

  const streamCard = document.querySelector('.ledger-stream-card');
  if (!streamCard) return;
  if (streamCard.querySelector('.ledger-legend')) return;

  const help = streamCard.querySelector('.widget-help');
  const header = streamCard.querySelector('.widget-header');

  const legend = document.createElement('div');
  legend.className = 'ledger-legend';
  legend.setAttribute('aria-label', 'Ledger glow legend');
  legend.innerHTML = `
    <span class="legend-label">Glow key:</span>
    <span class="legend-chip payment">Payment</span>
    <span class="legend-chip offer">DEX</span>
    <span class="legend-chip nft">NFT</span>
    <span class="legend-chip trust">Trust</span>
    <span class="legend-chip amm">AMM</span>
    <span class="legend-chip other">Other</span>
  `;

  if (help) help.insertAdjacentElement('afterend', legend);
  else if (header) header.insertAdjacentElement('afterend', legend);
  else streamCard.prepend(legend);
}

/* ─────────────────────────────
   Landscape Brief (expanded)
──────────────────────────────── */
function mountLandscapeBrief() {
  if (landscapeMounted) return;
  landscapeMounted = true;

  const main = document.querySelector('.dashboard-col-main');
  if (!main) return;

  const card = document.createElement('section');
  card.className = 'widget-card';
  card.id = 'landscape-card';
  card.setAttribute('aria-label', 'Landscape brief');

  card.innerHTML = `
    <div class="widget-header">
      <span class="widget-title">🧾 Landscape Report</span>
      <span class="widget-tag mono cut" id="landscape-badge">—</span>
      <button onclick="window.printLandscapeReport()" title="Print or save as PDF"
        style="background:rgba(0,212,255,.07);border:1px solid rgba(0,212,255,.18);
               color:var(--accent,#00d4ff);border-radius:8px;padding:5px 10px;
               font-size:.72rem;cursor:pointer;flex-shrink:0">🖨 Print</button>
    </div>
    <p class="widget-help">
      “In plain English”: what’s happening now, why it matters, and who to watch.
      These are <b>signals</b> (not proof).
    </p>

    <div class="landscape-brief" id="landscape-text">Waiting for data…</div>

    <div class="landscape-callout">
      <div class="landscape-callout-h">Why it matters</div>
      <div class="landscape-list" id="landscape-why"></div>
    </div>

    <div class="landscape-callout">
      <div class="landscape-callout-h">Who to watch right now</div>
      <div class="landscape-watchlist" id="landscape-watchlist"></div>
    </div>

    <div class="landscape-grid">
      <div class="landscape-box">
        <div class="landscape-h">What’s happening</div>
        <div class="landscape-list" id="landscape-now"></div>
      </div>
      <div class="landscape-box">
        <div class="landscape-h">What to watch next</div>
        <div class="landscape-list" id="landscape-watch"></div>
      </div>
    </div>
  `;

  main.prepend(card);
}

function updateLandscapeBrief(d) {
  const badge = $('landscape-badge');
  if (badge) badge.textContent = `${d.regime} · Risk ${d.friction}/100`;

  const s = d.s;
  const txTypes = d.txTypes || {};
  const dom = Object.entries(txTypes).sort(([, a], [, b]) => b - a)[0]?.[0] || '—';

  const tpsSt = calcTrendStats(state.tpsHistory, TREND_WINDOW);
  const feeSt = calcTrendStats(state.feeHistory, TREND_WINDOW);

  const dex = d.dexPatterns;
  const dexCancelPct = dex?.window?.total ? Math.round(dex.window.cancelRatio * 100) : 0;

  const brief = $('landscape-text');
  if (brief) {
    const li = Number(s.ledgerIndex || 0).toLocaleString();
    const txCount = Number(s.txPerLedger || 0);
    const close = s.latestLedger?.closeTimeSec != null ? Number(s.latestLedger.closeTimeSec).toFixed(2) + 's' : '—';
    const tps = tpsSt.cur != null ? `${safeNum(tpsSt.cur, 2)} TPS` : '—';
    const fee = feeSt.cur != null ? `${fmtXrp(feeSt.cur)} fee` : '—';
    const sr = s.successRate != null ? `${Number(s.successRate).toFixed(1)}% success` : '—';

    const dexLine = dex?.window?.total
      ? `DEX offers are <b>${dex.window.total}</b> (window), with <b>${dexCancelPct}% cancels</b>.`
      : `DEX offers look quiet right now.`;

    brief.innerHTML = `
      <b>Right now:</b> Ledger <b>#${li}</b> closed in <b>${close}</b> with <b>${txCount}</b> transactions.
      Network is at <b>${tps}</b>, with <b>${fee}</b>, and <b>${sr}</b>.
      Most common activity was <b>${escHtml(dom)}</b>. ${dexLine}
    `;
  }

  const whyEl = $('landscape-why');
  const watchlistEl = $('landscape-watchlist');
  const nowEl = $('landscape-now');
  const watchEl = $('landscape-watch');

  const nowItems = [];
  const watchItems = [];
  const whyItems = [];

  // Why it matters (layman)
  if (d.regime === 'Manipulated') {
    whyItems.push('Risk score is very high. Patterns like churn, loops, or single-actor dominance often correlate with manipulated activity.');
  } else if (d.regime === 'Stressed') {
    whyItems.push('The network is behaving “abnormally” (spikes in TPS or fees). This can be organic bursts or bots pushing volume.');
  } else if (d.regime === 'Active') {
    whyItems.push('The network is busy. Patterns are easier to detect because there’s more data per minute.');
  } else {
    whyItems.push('The network is quiet. Signals are weaker; a few bots can dominate a small sample.');
  }

  if (dex?.signals?.length) {
    whyItems.push(`DEX churn signals: <b>${escHtml(dex.signals.join(' · '))}</b>. Heavy OfferCreate/Cancel churn can indicate quote-stuffing/spoofing-like behavior.`);
  }

  if (d.advanced?.selfTradeCount > 0) {
    whyItems.push(`Detected <b>${d.advanced.selfTradeCount}</b> self-transfer payment(s) in the sample. Can be benign, but can also be used to fake activity.`);
  }
  if ((d.advanced?.roundnessIdx ?? 0) >= 45) {
    whyItems.push(`Round-number bias is high (<b>${d.advanced.roundnessIdx}%</b>). That often indicates automation rather than human behavior.`);
  }
  if (d.advanced?.pathPays >= 18) {
    whyItems.push(`Path payments are heavy (<b>${d.advanced.pathPays}</b> in sample). Lots of routing can mean arbitrage bots or automated bridge traffic.`);
  }

  if (whyEl) whyEl.innerHTML = whyItems.map((x) => `<div class="landscape-row">${x}</div>`).join('');

  // What's happening
  nowItems.push(`Overall mode: <b>${escHtml(d.regime)}</b> (risk score <b>${d.friction}/100</b>).`);
  nowItems.push(`Traffic: <b>${safeNum(tpsSt.cur, 2)}</b> TPS (avg ${safeNum(tpsSt.avg, 2)} · ${fmtPct(tpsSt.deltaPct, 0)}).`);
  nowItems.push(`Fees: <b>${feeSt.cur != null ? fmtXrp(feeSt.cur) : '—'}</b> (avg ${feeSt.avg != null ? fmtXrp(feeSt.avg) : '—'} · ${fmtPct(feeSt.deltaPct, 0)}).`);

  if (dex?.window?.total) {
    const top = dex.topActor?.[0];
    nowItems.push(`DEX activity: <b>${dex.window.total}</b> offer tx (window) · cancels <b>${dexCancelPct}%</b> · churn <b>${safeNum(dex.now.cancelsPerMin, 1)}</b>/min.`);
    if (top) nowItems.push(`Most active DEX wallet: <button class="addr-link mono" data-addr="${escHtml(top.acct)}">${escHtml(shortAddr(top.acct))}</button> (${top.count}).`);
  } else {
    nowItems.push(`DEX activity: <b>quiet</b> (few OfferCreate/OfferCancel).`);
  }

  // Watch next (concrete)
  const repeats = d.breadcrumbs.filter((p) => p.count >= 2).length;
  if (repeats) watchItems.push(`Repeating interactions: <b>${repeats}</b> pair(s) keep showing up.`);
  if (d.behavior?.bots?.length) {
    const topBot = d.behavior.bots[0];
    watchItems.push(`Bot-like timing: top candidate <button class="addr-link mono" data-addr="${escHtml(topBot.acct)}">${escHtml(shortAddr(topBot.acct))}</button> (CV ${topBot.cv.toFixed(2)}).`);
  }
  if (dex?.signals?.length) watchItems.push(`DEX signals: <b>${escHtml(dex.signals.join(' · '))}</b>`);
  if (d.clusters?.length) watchItems.push(`Largest cluster: <b>${d.clusters[0].size}</b> wallets · hub <button class="addr-link mono" data-addr="${escHtml(d.clusters[0].hub)}">${escHtml(shortAddr(d.clusters[0].hub))}</button>.`);
  if (d.advanced?.pathPays) watchItems.push(`Autobridge/path flow: <b>${d.advanced.pathPays}</b> path payments detected in sample.`);

  if (!watchItems.length) watchItems.push('Nothing urgent stands out in the current window.');

  if (nowEl) nowEl.innerHTML = nowItems.map((x) => `<div class="landscape-row">${x}</div>`).join('');
  if (watchEl) watchEl.innerHTML = watchItems.map((x) => `<div class="landscape-row">${x}</div>`).join('');

  // Who to watch (ranked + reasons)
  if (watchlistEl) {
    const watch = buildWatchList(d);
    watchlistEl.innerHTML = watch.length
      ? watch.map(w => `
        <div class="landscape-watchitem">
          <button class="addr-link mono cut" data-addr="${escHtml(w.addr)}">${escHtml(shortAddr(w.addr))}</button>
          <div class="landscape-watchwhy">${w.why}</div>
        </div>
      `).join('')
      : `<div style="opacity:.75">No clear “top suspect” yet — need a few more ledgers to build a baseline.</div>`;
  }
}

function buildWatchList(d) {
  const out = [];
  const add = (addr, why) => {
    if (!addr || !isValidXrpAddress(addr)) return;
    if (out.some(x => x.addr === addr)) return;
    out.push({ addr, why });
  };

  if (d.behavior?.bots?.length) {
    const b = d.behavior.bots[0];
    add(b.acct, `Bot-like timing (CV <span class="mono">${b.cv.toFixed(2)}</span>). High regularity is common in spam & automation.`);
  }

  const dex = d.dexPatterns;
  if (dex?.topActor?.length) {
    const top = dex.topActor[0];
    const share = dex.topShare != null ? Math.round(dex.topShare * 100) : null;
    const churn = dex.now?.cancelsPerMin != null ? dex.now.cancelsPerMin.toFixed(1) : '—';
    if (share != null && share >= 25) {
      add(top.acct, `Dominates DEX activity (~<span class="mono">${share}%</span> share). Cancels/min <span class="mono">${churn}</span> — watch for quote-stuffing/spoofing.`);
    }
  }

  if (dex?.topCanceller?.length) {
    const c = dex.topCanceller[0];
    if (c.count >= 6) add(c.acct, `Top canceller (<span class="mono">${c.count}</span>). Heavy cancels can be a manipulation signal.`);
  }

  const pairs = d.breadcrumbs || [];
  const best = pairs[0];
  if (best?.from && best?.to) {
    const rev = pairs.find(p => p.from === best.to && p.to === best.from);
    if (rev && rev.count >= 3 && best.count >= 3) {
      add(best.from, `Ping‑pong loop with ${shortAddr(best.to)} (<span class="mono">${best.count}×</span> / <span class="mono">${rev.count}×</span>). Can be wash-like routing.`);
      add(best.to, `Ping‑pong loop with ${shortAddr(best.from)} (<span class="mono">${rev.count}×</span> / <span class="mono">${best.count}×</span>).`);
    } else if (best.count >= 10) {
      add(best.from, `Repeated counterparty flow to ${shortAddr(best.to)} (<span class="mono">${best.count}×</span>). Persistent repetition often indicates automation.`);
    }
  }

  if (d.clusters?.length && d.clusters[0].size >= 3) {
    add(d.clusters[0].hub, `Cluster hub of <span class="mono">${d.clusters[0].size}</span> wallets. Coordination is a common feature of wash/loop tactics.`);
  }

  if (d.advanced?.topPathActors?.length) {
    const p = d.advanced.topPathActors[0];
    if (p.count >= 6) add(p.acct, `Heavy path‑payment routing (<span class="mono">${p.count}</span>). Often correlates with arbitrage bots.`);
  }

  return out.slice(0, 6);
}

/* ─────────────────────────────
   DEX Pattern Monitor (UI)
──────────────────────────────── */
function mountDexPatternMonitor() {
  if (dexMounted) return;
  dexMounted = true;

  const side = document.querySelector('.dashboard-col-side');
  if (!side) return;

  const card = document.createElement('section');
  card.className = 'widget-card';
  card.id = 'dex-pattern-card';
  card.setAttribute('aria-label', 'DEX pattern monitor');

  card.innerHTML = `
    <div class="widget-header">
      <span class="widget-title">🧠 DEX Pattern Monitor</span>
      <span class="widget-tag mono cut" id="dexp-badge">Waiting…</span>
    </div>
    <p class="widget-help">
      Tracks OfferCreate/OfferCancel patterns from the live ledger stream. No order-book polling.
      These are signals (not proof of manipulation).
    </p>

    <div class="dex-metrics">
      <div class="dex-row">
        <span class="dex-k">Cancel ratio</span>
        <div class="dex-bar"><div class="dex-bar-fill" id="dexp-cancel-bar" style="width:0%"></div></div>
        <span class="dex-v mono" id="dexp-cancel-val">—</span>
      </div>
      <div class="dex-row">
        <span class="dex-k">Top actor share</span>
        <div class="dex-bar"><div class="dex-bar-fill" id="dexp-topshare-bar" style="width:0%"></div></div>
        <span class="dex-v mono" id="dexp-topshare-val">—</span>
      </div>
      <div class="dex-row">
        <span class="dex-k">Burst vs avg</span>
        <div class="dex-bar"><div class="dex-bar-fill" id="dexp-burst-bar" style="width:0%"></div></div>
        <span class="dex-v mono" id="dexp-burst-val">—</span>
      </div>
    </div>

    <div class="dex-mini">
      <div><span>Cancels/min</span><b class="mono" id="dexp-cpm">—</b></div>
      <div><span>Actor HHI</span><b class="mono" id="dexp-hhi">—</b></div>
      <div><span>Offer tx (win)</span><b class="mono" id="dexp-totalwin">—</b></div>
    </div>

    <div class="dex-signals" id="dexp-signals"></div>

    <div class="dex-subgrid">
      <div class="dex-subbox">
        <div class="dex-subh">Top cancellers</div>
        <div class="dex-list" id="dexp-cancellers">—</div>
      </div>
      <div class="dex-subbox">
        <div class="dex-subh">Top makers</div>
        <div class="dex-list" id="dexp-makers">—</div>
      </div>
    </div>
  `;

  side.prepend(card);
}

function updateDexPatternMonitor(dex) {
  if (!document.getElementById('dex-pattern-card')) return;

  const totalWin = dex.window.total || 0;
  const cancelPct = totalWin ? Math.round(dex.window.cancelRatio * 100) : 0;
  const topPct = totalWin ? Math.round(dex.topShare * 100) : 0;

  setText('dexp-badge', totalWin ? `${totalWin} offer tx · ${cancelPct}% cancels` : 'Quiet');

  const cancelBar = $('dexp-cancel-bar');
  if (cancelBar) cancelBar.style.width = `${clamp(cancelPct, 0, 100)}%`;
  setText('dexp-cancel-val', totalWin ? `${cancelPct}%` : '—');

  const topBar = $('dexp-topshare-bar');
  if (topBar) topBar.style.width = `${clamp(topPct, 0, 100)}%`;
  setText('dexp-topshare-val', totalWin ? `${topPct}%` : '—');

  const burst = dex.burstPct;
  const burstAbs = burst == null ? 0 : Math.min(100, Math.abs(burst));
  const burstBar = $('dexp-burst-bar');
  if (burstBar) burstBar.style.width = `${burstAbs}%`;
  setText('dexp-burst-val', burst == null ? '—' : fmtPct(burst, 0));

  setText('dexp-cpm', dex.now.cancelsPerMin == null ? '—' : dex.now.cancelsPerMin.toFixed(1));
  setText('dexp-hhi', totalWin ? dex.actorHHI.toFixed(2) : '—');
  setText('dexp-totalwin', totalWin ? `${totalWin}` : '—');

  const sigEl = $('dexp-signals');
  if (sigEl) {
    sigEl.innerHTML = dex.signals.length
      ? dex.signals.map((s) => `<span class="sig-pill warn">${escHtml(s)}</span>`).join('')
      : `<span class="sig-pill ok">No strong DEX signals</span>`;
  }

  const cancEl = $('dexp-cancellers');
  if (cancEl) {
    cancEl.innerHTML = dex.topCanceller?.length
      ? dex.topCanceller.slice(0, 5).map((x) => `
        <div class="dex-rowline">
          <button class="addr-link mono cut" data-addr="${escHtml(x.acct)}">${escHtml(shortAddr(x.acct))}</button>
          <span class="mono">${x.count}</span>
        </div>`).join('')
      : `<div style="opacity:.7">—</div>`;
  }

  const makEl = $('dexp-makers');
  if (makEl) {
    makEl.innerHTML = dex.topMaker?.length
      ? dex.topMaker.slice(0, 5).map((x) => `
        <div class="dex-rowline">
          <button class="addr-link mono cut" data-addr="${escHtml(x.acct)}">${escHtml(shortAddr(x.acct))}</button>
          <span class="mono">${x.count}</span>
        </div>`).join('')
      : `<div style="opacity:.7">—</div>`;
  }
}

/* ─────────────────────────────
   Risk widget
──────────────────────────────── */
function mountRiskWidget() {
  if (riskMounted) return;
  riskMounted = true;

  const main = document.querySelector('.dashboard-col-main');
  if (!main) return;

  const card = document.createElement('section');
  card.className = 'widget-card';
  card.id = 'risk-card';
  card.setAttribute('aria-label', 'Risk panel');

  card.innerHTML = `
    <div class="widget-header">
      <span class="widget-title">⚠️ Risk &amp; Deep Ledger Analytics</span>
      <span class="widget-tag mono cut" id="risk-badge">—</span>
    </div>
    <p class="widget-help">
      Transparent heuristics: concentration + repeats + DEX churn + bot-like timing + routing indicators. Signals only.
    </p>

    <div class="risk-top">
      <div class="risk-stat"><span>Regime</span><b id="risk-regime">—</b></div>
      <div class="risk-stat"><span>Risk score</span><b id="risk-friction">—</b></div>
      <div class="risk-stat"><span>Signals</span><b id="risk-signalcount">—</b></div>
    </div>

    <div class="risk-pills" id="risk-pills"></div>

    <div class="risk-grid">
      <div class="risk-box risk-collapsible">
        <button class="risk-box-toggle" data-target="risk-bots" aria-expanded="true">
          <span class="risk-box-h">🤖 Bot-like timing</span><span class="risk-box-chevron">▾</span>
        </button>
        <div id="risk-bots" class="risk-list risk-collapsible-body"></div>
      </div>
      <div class="risk-box risk-collapsible">
        <button class="risk-box-toggle" data-target="risk-amm" aria-expanded="true">
          <span class="risk-box-h">💧 AMM / LP activity</span><span class="risk-box-chevron">▾</span>
        </button>
        <div id="risk-amm" class="risk-list risk-collapsible-body"></div>
      </div>
      <div class="risk-box risk-collapsible">
        <button class="risk-box-toggle" data-target="risk-path" aria-expanded="true">
          <span class="risk-box-h">🧭 Routing / path flow</span><span class="risk-box-chevron">▾</span>
        </button>
        <div id="risk-path" class="risk-list risk-collapsible-body"></div>
      </div>
      <div class="risk-box risk-collapsible">
        <button class="risk-box-toggle" data-target="risk-notes" aria-expanded="true">
          <span class="risk-box-h">📌 Notes</span><span class="risk-box-chevron">▾</span>
        </button>
        <div class="risk-list risk-collapsible-body" id="risk-notes"></div>
      </div>
    </div>
  `;

  card.querySelectorAll('.risk-box-toggle').forEach(btn => {
    btn.addEventListener('click', () => {
      const target = btn.getAttribute('data-target');
      const body = document.getElementById(target);
      if (!body) return;
      const open = btn.getAttribute('aria-expanded') !== 'false';
      btn.setAttribute('aria-expanded', open ? 'false' : 'true');
      body.classList.toggle('risk-collapsed', open);
      btn.querySelector('.risk-box-chevron').textContent = open ? '▸' : '▾';
      try { localStorage.setItem('risk_collapsed_' + target, open ? '1' : '0'); } catch {}
    });
    const target = btn.getAttribute('data-target');
    try {
      if (localStorage.getItem('risk_collapsed_' + target) === '1') {
        btn.setAttribute('aria-expanded', 'false');
        document.getElementById(target)?.classList.add('risk-collapsed');
        btn.querySelector('.risk-box-chevron').textContent = '▸';
      }
    } catch {}
  });

  main.appendChild(card);
}

function updateRiskWidget(d) {
  if (!document.getElementById('risk-card')) return;

  setText('risk-badge',        `Risk ${d.friction}/100`);
  setText('risk-regime',       d.regime);
  setText('risk-friction',     `${d.friction}/100`);

  const signals = [];
  if (d.hhi >= 0.35) signals.push({ cls: 'warn', t: 'High concentration' });
  if (d.breadcrumbs.filter(p => p.count >= 2).length >= 3) signals.push({ cls: 'new', t: 'Repeating counterparties' });
  if (d.behavior?.bots?.length)            signals.push({ cls: 'warn', t: 'Bot-like timing' });
  if (d.dexPatterns?.signals?.length)      signals.push({ cls: 'warn', t: 'DEX churn signals' });
  if (d.advanced?.selfTradeCount > 0)      signals.push({ cls: 'warn', t: `Self-transfer: ${d.advanced.selfTradeCount}` });
  if ((d.advanced?.roundnessIdx ?? 0) >= 45) signals.push({ cls: 'warn', t: `Round-number bias ${d.advanced.roundnessIdx}%` });
  if (d.advanced?.pathPays > 0)            signals.push({ cls: 'warn', t: `Path flow: ${d.advanced.pathPays}` });

  setText('risk-signalcount', `${signals.length}`);

  const pills = $('risk-pills');
  if (pills) pills.innerHTML = signals.length
    ? signals.map(s => `<span class="sig-pill ${s.cls}">${escHtml(s.t)}</span>`).join('')
    : `<span class="sig-pill ok">No elevated signals</span>`;

  // ── Bot panel — type-grouped ────────────────────────────────────────────
  const botsEl = $('risk-bots');
  if (botsEl) {
    const bots = d.behavior?.bots || [];
    if (bots.length) {
      const byType = {};
      for (const b of bots) {
        const t = b.botType || 'Periodic';
        if (!byType[t]) byType[t] = [];
        byType[t].push(b);
      }
      const typeOrder = ['Market Maker','Arbitrage','Flood / Spam','Periodic'];
      botsEl.innerHTML = typeOrder.filter(t => byType[t]).map(t => {
        const group = byType[t];
        const color = group[0].botTypeColor || 'rgba(255,255,255,.8)';
        return `<div class="bot-type-group">
          <div class="bot-type-label" style="color:${color}">${t}</div>
          ${group.map(b => `
            <div class="risk-row bot-row">
              <button class="addr-link mono cut" data-addr="${escHtml(b.acct)}" title="${escHtml(b.acct)}">${escHtml(shortAddr(b.acct))}</button>
              <div class="bot-row-meta">
                <span class="mono bot-cv" style="color:${b.cv < 0.10 ? '#ff5555' : b.cv < 0.20 ? '#ffb86c' : 'rgba(255,255,255,.65)'}">CV ${b.cv.toFixed(2)}</span>
                <span class="bot-total mono">${b.total}tx</span>
              </div>
            </div>
            ${b.botDesc ? `<div class="bot-desc">${escHtml(b.botDesc)}</div>` : ''}
          `).join('')}
        </div>`;
      }).join('');
    } else {
      botsEl.innerHTML = `<div style="opacity:.7;font-size:.84rem">No periodic bots detected yet</div>`;
    }
  }

  // ── AMM panel — full breakdown ──────────────────────────────────────────
  const ammEl = $('risk-amm');
  if (ammEl) {
    const adv = d.advanced || {};
    const { ammCreate=0, ammDeposit=0, ammWithdraw=0, ammVote=0, ammBid=0,
            lpTotal=0, lpNetFlow=0, lpRatio, lpUniqueActors=0 } = adv;
    if (lpTotal === 0) {
      ammEl.innerHTML = `<div style="opacity:.6;font-size:.84rem">No AMM activity in this ledger</div>`;
    } else {
      const netColor = lpNetFlow > 0 ? '#50fa7b' : lpNetFlow < 0 ? '#ff5555' : 'rgba(255,255,255,.5)';
      ammEl.innerHTML = `
        <div class="amm-chips">
          ${ammCreate   ? `<span class="amm-chip amm-create">🆕 Create ×${ammCreate}</span>` : ''}
          ${ammDeposit  ? `<span class="amm-chip amm-dep">↓ Deposit ×${ammDeposit}</span>` : ''}
          ${ammWithdraw ? `<span class="amm-chip amm-wd">↑ Withdraw ×${ammWithdraw}</span>` : ''}
          ${ammVote     ? `<span class="amm-chip amm-vote">🗳 Vote ×${ammVote}</span>` : ''}
          ${ammBid      ? `<span class="amm-chip amm-bid">📣 Bid ×${ammBid}</span>` : ''}
        </div>
        <div class="risk-row" style="margin-top:8px"><span>Net LP flow</span>
          <span class="mono" style="color:${netColor}">${lpNetFlow > 0 ? '+' + lpNetFlow + ' (adding LP)' : lpNetFlow < 0 ? lpNetFlow + ' (removing LP)' : '0 (balanced)'}</span></div>
        ${lpRatio != null ? `<div class="risk-row"><span>Deposit ratio</span><span class="mono">${lpRatio}% depositing</span></div>` : ''}
        <div class="risk-row"><span>Unique LP actors</span><span class="mono">${lpUniqueActors || '—'}</span></div>
        <div class="risk-row"><span>Total LP ops</span><span class="mono">${lpTotal}</span></div>`;
    }
  }

  // ── Path / routing panel ────────────────────────────────────────────────
  const pathEl = $('risk-path');
  if (pathEl) {
    const adv = d.advanced || {};
    const top  = adv.topPathActors?.[0];
    const top2 = adv.topPathActors?.[1];
    const selfColor  = adv.selfTradeCount  > 0    ? '#ff5555'  : 'rgba(255,255,255,.5)';
    const roundColor = (adv.roundnessIdx ?? 0) >= 45 ? '#ff5555' : (adv.roundnessIdx ?? 0) >= 25 ? '#ffb86c' : 'rgba(255,255,255,.5)';
    pathEl.innerHTML = `
      <div class="risk-row"><span>Path payments</span><span class="mono">${adv.pathPays ?? '—'}</span></div>
      ${adv.avgPathDepth != null ? `<div class="risk-row"><span>Avg path depth</span><span class="mono">${adv.avgPathDepth} hops</span></div>` : ''}
      ${top ? `<div class="risk-row"><span>Top router</span>
        <button class="addr-link mono cut" data-addr="${escHtml(top.acct)}">${escHtml(shortAddr(top.acct))}</button></div>
        <div class="risk-row" style="opacity:.75"><span style="padding-left:8px">↳ count</span><span class="mono">${top.count}</span></div>` : ''}
      ${top2 ? `<div class="risk-row" style="opacity:.7"><span>2nd router</span>
        <button class="addr-link mono cut" data-addr="${escHtml(top2.acct)}">${escHtml(shortAddr(top2.acct))}</button></div>` : ''}
      <div class="risk-row" style="margin-top:4px;border-top:1px solid rgba(255,255,255,.05);padding-top:8px">
        <span>Round-number %</span><span class="mono" style="color:${roundColor}">${adv.roundnessIdx != null ? adv.roundnessIdx + '%' : '—'}</span></div>
      <div class="risk-row"><span>Self-transfers</span><span class="mono" style="color:${selfColor}">${adv.selfTradeCount ?? 0}</span></div>`;
  }

  const notes = $('risk-notes');
  if (notes) notes.innerHTML = `
    <div style="opacity:.85">Signals are not proof. Use them to choose what to inspect.</div>
    <div style="opacity:.85">DEX monitor uses OfferCreate/OfferCancel only — no orderbook polling.</div>
    <div style="opacity:.85">Click any address to peek, then "Open in Inspector".</div>`;
}

/* ─────────────────────────────
   Advanced dashboard modules (UI + update)
──────────────────────────────── */
function mountAdvancedModules() {
  if (advancedMounted) return;
  advancedMounted = true;

  const side = document.querySelector('.dashboard-col-side');
  if (!side) return;

  // DEX Pressure
  if (!document.getElementById('dex-pressure-card')) {
    const card = document.createElement('section');
    card.className = 'widget-card';
    card.id = 'dex-pressure-card';
    card.setAttribute('aria-label', 'DEX pressure');
    card.innerHTML = `
      <div class="widget-header">
        <span class="widget-title">📉 DEX Pressure</span>
        <span class="widget-tag mono cut" id="dexP-badge">Waiting…</span>
      </div>
      <p class="widget-help">
        OfferCreate + OfferCancel per ledger (pressure proxy). Cancel ratio and top-actor share come from the DEX Pattern window.
      </p>
      <div style="height:130px;"><canvas id="chart-dex-pressure" class="mini-chart"></canvas></div>
      <div class="dex-mini">
        <div><span>Offer tx</span><b class="mono" id="dexP-now">—</b></div>
        <div><span>Cancel%</span><b class="mono" id="dexP-cancel">—</b></div>
        <div><span>Top share</span><b class="mono" id="dexP-share">—</b></div>
      </div>
    `;
    side.prepend(card);
  }

  // Autobridge / Path payments
  if (!document.getElementById('autobridge-card')) {
    const card = document.createElement('section');
    card.className = 'widget-card';
    card.id = 'autobridge-card';
    card.setAttribute('aria-label', 'Autobridge');
    card.innerHTML = `
      <div class="widget-header">
        <span class="widget-title">🧭 Autobridge / Path Payments</span>
        <span class="widget-tag mono cut" id="ab-badge">Waiting…</span>
      </div>
      <p class="widget-help">
        Heuristic: payments that include Paths (or SendMax/DeliverMax). Proxy for routing/autobridge flows.
      </p>
      <div style="height:130px;"><canvas id="chart-autobridge" class="mini-chart"></canvas></div>
      <div class="dex-mini">
        <div><span>Path pays</span><b class="mono" id="ab-now">—</b></div>
        <div><span>Top actor</span><b class="mono cut" id="ab-top-actor">—</b></div>
        <div><span>Pairs</span><b class="mono" id="ab-pairs">—</b></div>
      </div>
      <div class="dex-subbox" style="margin-top:10px;">
        <div class="dex-subh">Top path pairs</div>
        <div class="dex-list" id="ab-top-pairs">—</div>
      </div>
    `;
    side.prepend(card);
  }

  // NFT minting
  if (!document.getElementById('nft-mint-card')) {
    const card = document.createElement('section');
    card.className = 'widget-card';
    card.id = 'nft-mint-card';
    card.setAttribute('aria-label', 'NFT minting');
    card.innerHTML = `
      <div class="widget-header">
        <span class="widget-title">🎨 NFT Minting</span>
        <span class="widget-tag mono cut" id="nft-badge">Waiting…</span>
      </div>
      <p class="widget-help">
        NFTokenMint and NFTokenBurn per ledger (live stream). Shows both mints and burns so you can spot churn/spam.
      </p>
      <div style="height:110px;margin-bottom:10px;"><canvas id="chart-nft-mints" class="mini-chart"></canvas></div>
      <div style="height:90px;"><canvas id="chart-nft-burns" class="mini-chart"></canvas></div>
      <div class="dex-mini" style="margin-top:10px;">
        <div><span>Mints</span><b class="mono" id="nft-mints-now">—</b></div>
        <div><span>Burns</span><b class="mono" id="nft-burns-now">—</b></div>
        <div><span>Net</span><b class="mono" id="nft-net-now">—</b></div>
      </div>
    `;
    side.prepend(card);
  }

  // Market history
  if (!document.getElementById('market-card')) {
    const card = document.createElement('section');
    card.className = 'widget-card';
    card.id = 'market-card';
    card.setAttribute('aria-label', 'Market history');
    card.innerHTML = `
      <div class="widget-header">
        <span class="widget-title">💹 Market History</span>
        <span class="widget-tag mono cut" id="mkt-badge">Loading…</span>
      </div>
      <p class="widget-help">
        Client-only hourly history (public APIs). Updates every 5 minutes. If history is unavailable, falls back to current tick.
      </p>
      <div style="height:130px;"><canvas id="chart-market-price" class="mini-chart"></canvas></div>
      <div style="height:90px;margin-top:10px;"><canvas id="chart-market-vol" class="mini-chart"></canvas></div>
      <div class="dex-mini" style="margin-top:10px;">
        <div><span>Price</span><b class="mono" id="mkt-price">—</b></div>
        <div><span>~24h</span><b class="mono" id="mkt-chg">—</b></div>
        <div><span>Updated</span><b class="mono" id="mkt-upd">—</b></div>
      </div>
    `;
    side.prepend(card);
  }
}

function resetAdvancedSeries() {
  series.dexPressure = [];
  series.nftMints = [];
  series.nftBurns = [];
  series.autoBridge = [];
  _throttle.clear();
  Object.keys(_dc).forEach(k => delete _dc[k]);
  _renderAdvancedBadges({ offerTotal: null, dexCancelPct: null, dexTopSharePct: null, mints: null, burns: null, pathPays: null, topPathActors: [], topPathPairs: [] });
}

function _pushSeries(arr, val, maxN) {
  arr.push(Number(val || 0));
  while (arr.length > maxN) arr.shift();
}

function updateAdvancedModules(d) {
  const adv = d?.advanced;
  if (!adv) return;

  _pushSeries(series.dexPressure, adv.offerTotal, DEX_PRESSURE_MAX);
  _pushSeries(series.nftMints, adv.mints, NFT_MINT_MAX);
  _pushSeries(series.nftBurns, adv.burns, NFT_MINT_MAX);
  _pushSeries(series.autoBridge, adv.pathPays, AUTO_BRIDGE_MAX);

  _renderAdvancedBadges(adv);

  charts.dexPressure?.draw(series.dexPressure);
  charts.nftMints?.draw(series.nftMints);
  charts.nftBurns?.draw(series.nftBurns);
  charts.autoBridge?.draw(series.autoBridge);
}

function _renderAdvancedBadges(adv) {
  if (document.getElementById('dex-pressure-card')) {
    setText('dexP-badge', adv.offerTotal == null ? 'Waiting…' : `${adv.offerTotal} offer tx`);
    setText('dexP-now', adv.offerTotal == null ? '—' : adv.offerTotal);
    setText('dexP-cancel', adv.dexCancelPct == null ? '—' : `${adv.dexCancelPct}%`);
    setText('dexP-share', adv.dexTopSharePct == null ? '—' : `${adv.dexTopSharePct}%`);
  }

  if (document.getElementById('autobridge-card')) {
    setText('ab-badge', adv.pathPays == null ? 'Waiting…' : `${adv.pathPays} path pays`);
    setText('ab-now', adv.pathPays == null ? '—' : adv.pathPays);

    const topActor = adv.topPathActors?.[0];
    setText('ab-top-actor', topActor ? shortAddr(topActor.acct) : '—');
    setText('ab-pairs', adv.topPathPairs?.length ? adv.topPathPairs.length : '—');

    const list = $('ab-top-pairs');
    if (list) {
      list.innerHTML = adv.topPathPairs?.length
        ? adv.topPathPairs.map(p => `
          <div class="dex-rowline">
            <span class="mono cut">${escHtml(shortAddr(p.from))}</span>
            <span style="opacity:.7">→</span>
            <span class="mono cut">${escHtml(shortAddr(p.to))}</span>
            <span class="mono">${p.count}</span>
          </div>`).join('')
        : `<div style="opacity:.7">—</div>`;
    }
  }

  if (document.getElementById('nft-mint-card')) {
    const net = (Number(adv.mints || 0) - Number(adv.burns || 0));
    setText('nft-badge', (adv.mints == null && adv.burns == null) ? 'Waiting…' : `${adv.mints || 0} mints · ${adv.burns || 0} burns`);
    setText('nft-mints-now', adv.mints == null ? '—' : adv.mints);
    setText('nft-burns-now', adv.burns == null ? '—' : adv.burns);
    setText('nft-net-now', `${net}`);
  }
}

/* ─────────────────────────────
   Market History (client-only)
──────────────────────────────── */
function startMarketHistory({ force = false } = {}) {
  if (marketTimer && !force) return;

  if (marketTimer) {
    clearInterval(marketTimer);
    marketTimer = null;
  }

  fetchMarketHistory();
  marketTimer = setInterval(fetchMarketHistory, MARKET_POLL_MS);
}

async function fetchMarketHistory() {
  const run = ++_marketRun;
  setText('mkt-badge', 'Loading…');

  // Prefer CryptoCompare histohour
  try {
    const url = `https://min-api.cryptocompare.com/data/v2/histohour?fsym=XRP&tsym=USD&limit=${MARKET_POINTS - 1}`;
    const res = await fetch(url, { cache: 'no-store' });
    if (!res.ok) throw new Error('market history failed');
    const j = await res.json();
    const rows = j?.Data?.Data;
    if (!Array.isArray(rows) || rows.length < 10) throw new Error('no history');

    if (run !== _marketRun) return;

    const prices = rows.map(r => Number(r.close)).filter(Number.isFinite);
    const vols   = rows.map(r => Number(r.volumeto)).filter(Number.isFinite);

    series.marketPrice = prices.slice(-MARKET_POINTS);
    series.marketVol   = vols.slice(-MARKET_POINTS);

    const last = series.marketPrice.at(-1);
    const prev = series.marketPrice.length > 24 ? series.marketPrice.at(-25) : series.marketPrice.at(0);
    const chg = (prev && last) ? ((last - prev) / prev) * 100 : null;

    setText('mkt-badge', last ? `$${last.toFixed(4)}` : '—');
    setText('mkt-price', last ? `$${last.toFixed(4)}` : '—');
    setText('mkt-chg', chg == null ? '—' : fmtPct(chg, 2));
    setText('mkt-upd', new Date().toLocaleTimeString());

    charts.marketPrice?.draw(series.marketPrice);
    charts.marketVol?.draw(series.marketVol);
    return;
  } catch {
    // fallback to current tick
  }

  try {
    const res = await fetch('https://api.coinpaprika.com/v1/tickers/xrp-xrp', { cache: 'no-store' });
    if (!res.ok) throw new Error('tick failed');
    const j = await res.json();
    if (run !== _marketRun) return;

    const price = Number(j?.quotes?.USD?.price);
    const vol = Number(j?.quotes?.USD?.volume_24h);
    const chg = Number(j?.quotes?.USD?.percent_change_24h);

    if (Number.isFinite(price)) {
      _pushSeries(series.marketPrice, price, MARKET_POINTS);
      if (Number.isFinite(vol)) _pushSeries(series.marketVol, vol, MARKET_POINTS);
    }

    setText('mkt-badge', Number.isFinite(price) ? `$${price.toFixed(4)}` : '—');
    setText('mkt-price', Number.isFinite(price) ? `$${price.toFixed(4)}` : '—');
    setText('mkt-chg', Number.isFinite(chg) ? `${chg >= 0 ? '↑' : '↓'}${Math.abs(chg).toFixed(2)}%` : '—');
    setText('mkt-upd', new Date().toLocaleTimeString());

    charts.marketPrice?.draw(series.marketPrice);
    charts.marketVol?.draw(series.marketVol);
  } catch {
    setText('mkt-badge', 'Unavailable');
  }
}

/* ─────────────────────────────
   Spam Defense POC (UI + deterministic “ratchet”)
──────────────────────────────── */
function mountSpamDefensePOC() {
  if (spamMounted) return;
  spamMounted = true;

  // Spam Defense is a wide card — goes in the full-width zone below the two columns
  let fullwidthZone = document.querySelector('.dashboard-fullwidth');
  if (!fullwidthZone) {
    fullwidthZone = document.createElement('div');
    fullwidthZone.className = 'dashboard-fullwidth';
    // Insert after .dashboard-columns
    const cols = document.querySelector('.dashboard-columns');
    if (cols) cols.insertAdjacentElement('afterend', fullwidthZone);
    else document.querySelector('.dashboard-page')?.appendChild(fullwidthZone);
  }

  if (document.getElementById('spam-defense-card')) return;

  const card = document.createElement('section');
  card.className = 'widget-card';
  card.id = 'spam-defense-card';
  card.setAttribute('aria-label', 'Spam defense');

  // Initialise persistence
  _loadAllowList();
  _initVerifiedCache();

  card.innerHTML = `
    <div class="widget-header" style="flex-wrap:wrap;gap:8px">
      <span class="widget-title">🛡️ Spam Defense POC</span>
      <span class="widget-tag mono cut" id="spam-badge">Watching…</span>
      <div style="margin-left:auto;display:flex;gap:6px;flex-wrap:wrap">
        <button class="spam-btn" onclick="exportSpamReputation()" title="Export full reputation list as JSON">⬇ Export</button>
        <label class="spam-btn" style="cursor:pointer" title="Import a previously exported reputation file">
          ⬆ Import<input type="file" accept=".json" style="display:none" onchange="importSpamReputation(this.files[0]);this.value=''">
        </label>
        <button class="spam-btn" id="spam-sim-toggle" onclick="_toggleBondSim()">📐 Bond Sim</button>
      </div>
    </div>
    <p class="widget-help">
      Deterministic <b>ratchet level</b> + <b>XRPL-native SHA-512Half on-ledger credential</b> concept.
      Proof hashes use <b>SHA-512Half</b> — the same algorithm XRPL uses for transaction and ledger hashes.
      XRPL fees are network-wide and validator-controlled — this produces <b>provable evidence</b>
      that a gateway/relayer can enforce independently (bond + credential before service).
    </p>

    <div class="spam-summary" id="spam-summary-grid">
      <div><span>Suspects</span><b id="spam-count">—</b></div>
      <div><span>Max level</span><b id="spam-maxlvl">—</b></div>
      <div><span>Verified</span><b id="spam-verified">—</b></div>
      <div><span>Allowlisted</span><b id="spam-allowcount">—</b></div>
      <div><span>Session bonds</span><b id="spam-bondusd">—</b></div>
      <div><span>Hash alg</span><b style="color:#00d4ff">SHA-512Half</b></div>
    </div>

    <!-- Bond curve simulator (hidden by default) -->
    <div id="spam-sim-panel" style="display:none;margin:12px 0;padding:12px;border-radius:14px;border:1px solid rgba(0,212,255,.15);background:rgba(0,212,255,.04)">
      <div style="font-weight:800;margin-bottom:10px;font-size:.85rem">📐 Bond Curve Simulator</div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:10px">
        <label style="font-size:.78rem;opacity:.7">
          Base XRP (L0)
          <input type="range" id="sim-base" min="1" max="500" step="1" value="${SPAM_BOND_BASE_XRP}"
            oninput="_renderBondSim()" style="width:100%;margin-top:4px">
          <span id="sim-base-val" class="mono" style="font-size:.72rem">${SPAM_BOND_BASE_XRP} XRP</span>
        </label>
        <label style="font-size:.78rem;opacity:.7">
          Growth factor
          <input type="range" id="sim-growth" min="1.2" max="4" step="0.1" value="${SPAM_BOND_GROWTH}"
            oninput="_renderBondSim()" style="width:100%;margin-top:4px">
          <span id="sim-growth-val" class="mono" style="font-size:.72rem">${SPAM_BOND_GROWTH}×</span>
        </label>
      </div>
      <div id="sim-table" class="mono" style="font-size:.78rem;display:grid;grid-template-columns:repeat(9,1fr);gap:4px;text-align:center"></div>
    </div>

    <div class="dex-subbox">
      <div class="dex-subh" style="display:flex;justify-content:space-between;align-items:center">
        <span>Suspects — ratchet levels</span>
        <span style="font-size:.72rem;opacity:.5">Click row to expand · Proof button for credential</span>
      </div>
      <div id="spam-list"></div>
    </div>

    <div class="spam-proof" id="spam-proof" style="display:none">
      <div style="font-weight:1000;margin-bottom:8px;display:flex;align-items:center;gap:10px">
        Selected proof
        <span style="font-size:.72rem;opacity:.5;font-weight:400">SHA-512Half (XRPL-native)</span>
      </div>
      <div style="margin-bottom:6px;font-size:.82rem">
        Hash: <span class="mono spam-proof-hash-display" id="spam-proof-hash" style="color:#00d4ff;word-break:break-all"></span>
      </div>
      <div style="font-size:.82rem;opacity:.85;margin-bottom:4px">Canonical proof JSON:</div>
      <pre class="mono" id="spam-proof-json" style="max-height:220px;overflow:auto"></pre>
      <div class="spam-proof-actions">
        <button class="spam-btn" id="spam-copy-hash">Copy hash</button>
        <button class="spam-btn" id="spam-copy-json">Copy JSON</button>
        <button class="spam-btn" id="spam-print-proof">🖨 Print proof</button>
      </div>
      <div style="margin-top:12px;font-weight:1000;font-size:.9rem">Credential step (on-ledger)</div>
      <div style="margin-top:6px" id="spam-cred-step"></div>
    </div>
  `;

  fullwidthZone.appendChild(card);

  $('spam-copy-hash')?.addEventListener('click', () => _copyToClipboard($('spam-proof-hash')?.textContent || ''));
  $('spam-copy-json')?.addEventListener('click', () => _copyToClipboard($('spam-proof-json')?.textContent || ''));
  $('spam-print-proof')?.addEventListener('click', _printSpamProof);
  _renderBondSim();
}

/* ── Bond simulator toggle ── */
window._toggleBondSim = function() {
  const p = $('spam-sim-panel');
  if (!p) return;
  const open = p.style.display !== 'none';
  p.style.display = open ? 'none' : '';
  const btn = $('spam-sim-toggle');
  if (btn) btn.style.color = open ? '' : '#00d4ff';
};

/* ── Bond simulator render ── */
window._renderBondSim = function() {
  const baseEl   = document.getElementById('sim-base');
  const growthEl = document.getElementById('sim-growth');
  const tableEl  = document.getElementById('sim-table');
  if (!tableEl) return;

  const base   = Number(baseEl?.value   || SPAM_BOND_BASE_XRP);
  const growth = Number(growthEl?.value || SPAM_BOND_GROWTH);
  const xrpPx  = series.marketPrice.at(-1) ?? null;

  if (document.getElementById('sim-base-val'))   document.getElementById('sim-base-val').textContent   = base + ' XRP';
  if (document.getElementById('sim-growth-val')) document.getElementById('sim-growth-val').textContent = growth + '×';

  let html = '';
  for (let lvl = 0; lvl <= SPAM_RATCHET_MAX; lvl++) {
    const xrp = Math.round(base * (growth ** lvl));
    const usd = xrpPx ? '$' + (xrp * xrpPx).toLocaleString(undefined, { maximumFractionDigits: 0 }) : '';
    const color = lvl < 3 ? '#50fa7b' : lvl < 6 ? '#ffb86c' : '#ff5555';
    html += `<div style="padding:5px;border-radius:6px;background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.07)">
      <div style="font-size:.65rem;opacity:.5">L${lvl}</div>
      <div style="color:${color};font-weight:800">${xrp >= 1000 ? (xrp/1000).toFixed(1)+'k' : xrp}</div>
      ${usd ? `<div style="font-size:.62rem;opacity:.45">${usd}</div>` : ''}
    </div>`;
  }
  tableEl.innerHTML = html;
};

async function _copyToClipboard(text) {
  try {
    await navigator.clipboard.writeText(String(text || ''));
    toastInfo('Copied');
  } catch {
    toastWarn('Copy failed (browser blocked clipboard).');
  }
}

function spamBondForLevel(level) {
  const lvl = clamp(Number(level) || 0, 0, SPAM_RATCHET_MAX);
  return Math.round(SPAM_BOND_BASE_XRP * (SPAM_BOND_GROWTH ** lvl));
}

/* ── Allow-list persistence ── */
function _loadAllowList() {
  try {
    const saved = JSON.parse(localStorage.getItem(LS_SPAM_ALLOWLIST) || '[]');
    spamState.allowList = new Set(saved);
  } catch { spamState.allowList = new Set(); }
}
function _saveAllowList() {
  try { localStorage.setItem(LS_SPAM_ALLOWLIST, JSON.stringify([...spamState.allowList])); } catch {}
}
function _addToAllowList(addr) {
  if (!isValidXrpAddress(addr)) return;
  spamState.allowList.add(addr);
  _saveAllowList();
  spamState.byAddr.delete(addr);
  toastInfo(`${shortAddr(addr)} added to allow-list — will no longer be flagged`);
}
window._spamAllowAddr = _addToAllowList;  // exposed for HTML onclick

/* ── Verified credential cache ── */
function _loadVerifiedCache() {
  try { return JSON.parse(localStorage.getItem(LS_SPAM_VERIFIED) || '{}'); } catch { return {}; }
}
function _saveVerifiedCache(obj) {
  try { localStorage.setItem(LS_SPAM_VERIFIED, JSON.stringify(obj)); } catch {}
}
function _initVerifiedCache() {
  const obj = _loadVerifiedCache();
  for (const [addr, data] of Object.entries(obj)) {
    spamState.verifiedCache.set(addr, data);
  }
}

/* ── Reputation export/import ── */
window.exportSpamReputation = function() {
  const entries = [...spamState.byAddr.entries()].map(([addr, st]) => ({
    addr,
    level:       st.level,
    strikes:     st.strikes,
    score:       +(st.score || 0).toFixed(4),
    threatType:  st.threatType || 'Unknown',
    verified:    !!st.verifiedLedger,
    verifiedLedger: st.verifiedLedger ?? null,
    lastSeen:    st.lastSeenLedger ?? null,
  }));
  const data = {
    v: 2,
    network:     state.currentNetwork || 'xrpl-mainnet',
    exportedAt:  new Date().toISOString(),
    allowList:   [...spamState.allowList],
    suspects:    entries,
    policy: {
      bondBaseXrp: SPAM_BOND_BASE_XRP,
      bondGrowth:  SPAM_BOND_GROWTH,
      ratchetMax:  SPAM_RATCHET_MAX,
    },
  };
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href     = url;
  a.download = `naluxrp_reputation_${new Date().toISOString().slice(0,10)}.json`;
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  URL.revokeObjectURL(url);
  toastInfo('Reputation list exported');
};

window.importSpamReputation = function(file) {
  if (!file) return;
  const reader = new FileReader();
  reader.onload = e => {
    try {
      const data = JSON.parse(e.target.result);
      if (!data.suspects) throw new Error('Invalid format');
      let imported = 0;
      for (const s of data.suspects) {
        if (!isValidXrpAddress(s.addr)) continue;
        const prev = spamState.byAddr.get(s.addr) || {};
        spamState.byAddr.set(s.addr, {
          ...prev,
          level:       s.level ?? 0,
          strikes:     s.strikes ?? 0,
          score:       s.score ?? 0,
          threatType:  s.threatType ?? 'Unknown',
          verifiedLedger: s.verifiedLedger ?? null,
          lastSeenLedger: s.lastSeen ?? null,
          scoreHistory: [],
          signalBreakdown: {},
        });
        imported++;
      }
      if (data.allowList?.length) {
        for (const addr of data.allowList) if (isValidXrpAddress(addr)) spamState.allowList.add(addr);
        _saveAllowList();
      }
      toastInfo(`Imported ${imported} reputation entries`);
    } catch (err) { toastWarn('Import failed: ' + err.message); }
  };
  reader.readAsText(file);
};

function updateSpamDefensePOC(d) {
  if (!document.getElementById('spam-defense-card')) return;

  const suspects = scoreSuspects(d);
  const maxLvl   = suspects.reduce((m, s) => Math.max(m, s.level), 0);
  const verified = suspects.filter(s => s.verified).length;
  const xrpPx    = series.marketPrice.at(-1) ?? null;

  // Session total bond obligation (sum of all suspects' bond requirements, in USD)
  const totalBondXrp = suspects.reduce((sum, s) => sum + spamBondForLevel(s.level), 0);
  const bondUsdStr   = xrpPx ? `~$${(totalBondXrp * xrpPx).toLocaleString(undefined,{maximumFractionDigits:0})}` : `${totalBondXrp} XRP`;

  setText('spam-count',      suspects.length);
  setText('spam-maxlvl',     `L${maxLvl}`);
  setText('spam-verified',   verified);
  setText('spam-allowcount', spamState.allowList.size);
  setText('spam-bondusd',    bondUsdStr);
  setText('spam-badge',      suspects.length ? `${suspects.length} tracked · max L${maxLvl}` : 'Quiet');

  const list = $('spam-list');
  if (list) {
    if (!suspects.length) {
      list.innerHTML = `<div class="spam-empty">No suspects flagged — allow-list has ${SPAM_ALLOWLIST_BUILTIN.size} known-good entities.</div>`;
    } else {
      list.innerHTML = suspects.map(s => {
        const bondXrp  = spamBondForLevel(s.level);
        const bondUsd  = xrpPx ? ` (~$${(bondXrp * xrpPx).toFixed(0)})` : '';
        const lvlColor = s.level >= 6 ? '#ff5555' : s.level >= 3 ? '#ffb86c' : '#50fa7b';
        const scColor  = s.score >= 0.7 ? '#ff5555' : s.score >= 0.4 ? '#ffb86c' : '#50fa7b';
        const threatColor = {
          'Payment Flooder':'#ff5555','Quote Stuffer':'#ff5555','Wash Trader':'#ff5555',
          'DEX Bot':'#ffb86c','Arb Router':'#00d4ff','Periodic Bot':'#bd93f9',
        }[s.threatType] || 'rgba(255,255,255,.6)';
        const credBadge = s.verified
          ? `<span class="spam-cred-chip">✔ L${s.level} verified</span>` : '';

        // Score history sparkline (10 values → tiny bar chart inline)
        const sparkSvg = _spamScoreSparkline(s.scoreHistory || []);

        return `
          <div class="spam-card" data-spam-addr="${escHtml(s.addr)}">
            <div class="spam-card-top">
              <button class="addr-link mono spam-card-addr" data-addr="${escHtml(s.addr)}">${escHtml(shortAddr(s.addr))}</button>
              <div class="spam-card-actions">
                <button class="spam-btn" data-action="expand"  data-spam-addr="${escHtml(s.addr)}">▾ Detail</button>
                <button class="spam-btn" data-action="proof"   data-spam-addr="${escHtml(s.addr)}">Proof</button>
                <button class="spam-btn" data-action="allow"   data-spam-addr="${escHtml(s.addr)}" title="Trust this address permanently">✓ Allow</button>
                <button class="spam-btn spam-btn-clear" data-action="clear" data-spam-addr="${escHtml(s.addr)}">✕</button>
              </div>
            </div>
            <div class="spam-card-meta">
              <span class="spam-meta-chip">Level <b style="color:${lvlColor}">L${s.level}</b></span>
              <span class="spam-meta-chip">Score <b style="color:${scColor}">${Math.round(s.score*100)}%</b></span>
              <span class="spam-meta-chip" style="color:${threatColor}">${escHtml(s.threatType)}</span>
              <span class="spam-meta-chip">Bond <b>${bondXrp >= 1000?(bondXrp/1000).toFixed(1)+'k':bondXrp} XRP${bondUsd}</b></span>
              ${credBadge}
              <span title="Score trend — last ${(s.scoreHistory||[]).length} ledgers" style="margin-left:auto">${sparkSvg}</span>
            </div>
            <!-- Expandable signal breakdown (hidden by default) -->
            <div class="spam-breakdown" id="spam-bd-${escHtml(s.addr.slice(0,10))}" style="display:none">
              ${_renderSignalBreakdown(s.breakdown, s.strikes)}
            </div>
          </div>`;
      }).join('');
    }
  }

  if (!spamDelegationBound) bindSpamDelegation();

  // Refresh selected proof if visible
  if (spamState.selectedAddr) {
    const cur = spamState.byAddr.get(spamState.selectedAddr);
    if (!cur) renderSpamProof(null);
    else {
      buildSpamProof(spamState.selectedAddr, cur, d.s.ledgerIndex)
        .then(proof => renderSpamProof(proof));
    }
  }

  // Refresh bond sim if open
  if (document.getElementById('spam-sim-panel')?.style.display !== 'none') {
    window._renderBondSim?.();
  }
}

/* ── Inline score history sparkline (SVG) ── */
function _spamScoreSparkline(history) {
  if (!history?.length) return '';
  const W = 42, H = 14;
  const max = 1;
  const step = W / Math.max(1, history.length - 1);
  const pts = history.map((v, i) => `${(i * step).toFixed(1)},${(H - 2 - (v / max) * (H - 4)).toFixed(1)}`).join(' ');
  const last  = history.at(-1) ?? 0;
  const color = last >= 0.7 ? '#ff5555' : last >= 0.4 ? '#ffb86c' : '#50fa7b';
  return `<svg width="${W}" height="${H}" xmlns="http://www.w3.org/2000/svg" style="overflow:visible">
    <polyline points="${pts}" fill="none" stroke="${color}" stroke-width="1.5" stroke-linejoin="round"/>
    <circle cx="${((history.length-1)*step).toFixed(1)}" cy="${(H - 2 - (last/max)*(H-4)).toFixed(1)}"
      r="2" fill="${color}"/>
  </svg>`;
}

/* ── Signal breakdown panel (expandable row) ── */
function _renderSignalBreakdown(bd = {}, strikes = 0) {
  const rows = [
    { label: 'Bot timing',       val: bd.bot       ?? 0, desc: bd.botType ? `Type: ${bd.botType}` : 'Low variance in repeated ledger appearances' },
    { label: 'DEX dominance',    val: bd.dexDom     ?? 0, desc: 'Share of offer tx window controlled by this address' },
    { label: 'Cancel pattern',   val: bd.cancelPat  ?? 0, desc: 'Heavy OfferCancel activity relative to creates' },
    { label: 'Ping-pong loop',   val: bd.pingPong   ?? 0, desc: 'Bidirectional repeated payments between two addresses' },
    { label: 'Path routing',     val: bd.pathRoute  ?? 0, desc: 'High path-payment count — common in arb bots' },
    { label: 'Self-transfer',    val: bd.selfTrade  ?? 0, desc: 'Payments where sender = receiver' },
    { label: 'Round-number pay', val: bd.roundPay   ?? 0, desc: 'Unusual bias toward exact round-number payment amounts' },
  ].filter(r => r.val > 0.001);

  if (!rows.length) return `<div style="opacity:.5;font-size:.78rem;padding:6px 0">No significant signal breakdown available yet.</div>`;

  return `
    <div style="margin-top:8px;border-top:1px solid rgba(255,255,255,.06);padding-top:8px">
      <div style="font-size:.7rem;opacity:.45;text-transform:uppercase;letter-spacing:.08em;margin-bottom:6px">
        Signal breakdown · ${strikes} strike${strikes!==1?'s':''} accumulated
      </div>
      ${rows.map(r => {
        const pct   = Math.round(r.val * 100);
        const color = pct >= 30 ? '#ff5555' : pct >= 15 ? '#ffb86c' : '#50fa7b';
        return `<div style="margin-bottom:6px">
          <div style="display:flex;justify-content:space-between;font-size:.76rem;margin-bottom:2px">
            <span style="opacity:.8">${escHtml(r.label)}</span>
            <span class="mono" style="color:${color}">${pct}%</span>
          </div>
          <div style="height:4px;background:rgba(255,255,255,.07);border-radius:2px;overflow:hidden">
            <div style="height:100%;width:${Math.min(100,pct*2.5)}%;background:${color};border-radius:2px"></div>
          </div>
          <div style="font-size:.68rem;opacity:.4;margin-top:1px">${escHtml(r.desc)}</div>
        </div>`;
      }).join('')}
    </div>`;
}

let spamDelegationBound = false;
function bindSpamDelegation() {
  if (spamDelegationBound) return;
  spamDelegationBound = true;

  document.addEventListener('click', (e) => {
    const btn = e.target.closest?.('button[data-action][data-spam-addr]');
    if (!btn) return;
    const action = btn.getAttribute('data-action');
    const addr   = btn.getAttribute('data-spam-addr');
    if (!addr) return;

    if (action === 'proof') {
      const st = spamState.byAddr.get(addr);
      if (!st) return;
      spamState.selectedAddr = addr;
      // Show loading state immediately
      const box = $('spam-proof');
      if (box) {
        box.style.display = '';
        const hashEl = $('spam-proof-hash');
        if (hashEl) hashEl.textContent = 'Computing SHA-512Half…';
      }
      buildSpamProof(addr, st, state.ledgerLog?.[0]?.ledgerIndex || null)
        .then(proof => { spamState.selectedProof = proof; renderSpamProof(proof); })
        .catch(err => toastWarn('Proof build failed: ' + err.message));
      return;
    }

    if (action === 'clear') {
      spamState.byAddr.delete(addr);
      if (spamState.selectedAddr === addr) renderSpamProof(null);
      toastInfo('Cleared from session');
      return;
    }

    if (action === 'allow') {
      _addToAllowList(addr);
      spamState.byAddr.delete(addr);
      if (spamState.selectedAddr === addr) renderSpamProof(null);
      return;
    }

    if (action === 'expand') {
      const addrKey = addr.slice(0,10);
      const bd  = document.getElementById('spam-bd-' + addrKey);
      if (!bd) return;
      const open = bd.style.display !== 'none';
      bd.style.display = open ? 'none' : '';
      btn.textContent  = open ? '▾ Detail' : '▴ Hide';
      return;
    }
  });
}

function renderSpamProof(proof) {
  const box = $('spam-proof');
  if (!box) return;

  if (!proof) {
    box.style.display = 'none';
    return;
  }

  box.style.display = '';
  setText('spam-proof-hash', proof.hash);
  const pre = $('spam-proof-json');
  if (pre) pre.textContent = proof.canonicalJson;

  const step = $('spam-cred-step');
  if (step) {
    step.innerHTML = `
      <div style="opacity:.9">
        To “credential” this address at level <b>L${proof.level}</b>, do:
      </div>
      <ul style="margin:8px 0 0 18px;opacity:.9">
        <li><b>EscrowCreate</b> locking <b>${proof.policy.bondRequiredXrp} XRP</b> to <b>itself</b> for ~24h (strong bond; funds are locked).</li>
        <li>Include a Memo that starts with <span class="mono">${SPAM_MEMO_PREFIX}</span> and then the proof hash.</li>
        <li>Alternatively (cheap): send a 1-drop self-payment with <b>DestinationTag=${SPAM_CRED_TAG_BASE + proof.level}</b> and the same memo.</li>
      </ul>
      <div style="opacity:.75;margin-top:8px">
        This dashboard will mark it verified once it sees a matching on-ledger tx in the stream.
      </div>
    `;
  }
}

function scoreSuspects(d) {
  // Ensure allow-list is loaded
  if (!spamState.allowList.size) _loadAllowList();

  const candidates = new Set();
  (d.behavior?.bots || []).forEach(b => candidates.add(b.acct));
  (d.dexPatterns?.topActor    || []).forEach(x => candidates.add(x.acct));
  (d.dexPatterns?.topCanceller|| []).forEach(x => candidates.add(x.acct));
  (d.dexPatterns?.topMaker    || []).forEach(x => candidates.add(x.acct));
  (d.breadcrumbs || []).forEach(p => { candidates.add(p.from); candidates.add(p.to); });
  (d.clusters    || []).forEach(c => { candidates.add(c.hub); (c.members||[]).forEach(m=>candidates.add(m)); });
  (d.advanced?.topPathActors || []).forEach(x => candidates.add(x.acct));

  const nowLedger = Number(d.s.ledgerIndex || 0) || null;
  const recentTx  = d.txs || [];
  const out = [];

  for (const addr of candidates) {
    if (!isValidXrpAddress(addr)) continue;

    // ── Allow-list check (built-in exchanges + user overrides) ──
    if (SPAM_ALLOWLIST_BUILTIN.has(addr) || spamState.allowList.has(addr)) continue;

    const { score, breakdown } = suspicionScore(addr, d);
    const threatType = _classifyThreat(breakdown);

    const prev = spamState.byAddr.get(addr) || {
      strikes: 0, level: 0, score: 0,
      verifiedLedger: null, lastSeenLedger: null,
      scoreHistory: [], threatType: 'Unknown', signalBreakdown: {},
    };

    // ── Ratchet logic ────────────────────────────────────────────
    let strikes = prev.strikes || 0;
    if (score >= SPAM_STRIKE_UP)   strikes += 1;
    else if (score <= SPAM_STRIKE_DOWN) strikes = Math.max(0, strikes - 1);

    // ── Decay: if address has been quiet, reduce strikes ─────────
    const lastSeen   = prev.lastSeenLedger || nowLedger;
    const silentFor  = nowLedger ? (nowLedger - lastSeen) : 0;
    if (silentFor > SPAM_DECAY_QUIET && score < SPAM_STRIKE_DOWN) {
      const decaySteps = Math.floor(silentFor / SPAM_DECAY_QUIET);
      strikes = Math.max(0, strikes - decaySteps);
    }

    const level = clamp(Math.floor(strikes / SPAM_STRIKES_TO_LVL), 0, SPAM_RATCHET_MAX);

    // ── Score history (sparkline) ─────────────────────────────────
    const scoreHistory = [...(prev.scoreHistory || []), score].slice(-10);

    // ── Verified credential (localStorage-cached) ────────────────
    const cachedVerified = spamState.verifiedCache.get(addr);
    let verifiedLedger = prev.verifiedLedger ?? cachedVerified?.ledgerIndex ?? null;
    if (!verifiedLedger) {
      verifiedLedger = detectCredential(addr, level, recentTx, nowLedger);
      if (verifiedLedger) {
        // Check memo actually contains the correct hash prefix
        // (hash verification happens asynchronously — we do it in background)
        _verifyCredentialAsync(addr, level, nowLedger);
      }
    }

    const next = {
      score, strikes, level, verifiedLedger,
      lastSeenLedger: nowLedger,
      scoreHistory, threatType, signalBreakdown: breakdown,
    };
    spamState.byAddr.set(addr, next);
    out.push({ addr, score, strikes, level,
               verified: !!verifiedLedger, verifiedLedger,
               scoreHistory, threatType, breakdown });
  }

  out.sort((a, b) => (b.level - a.level) || (b.score - a.score));
  return out.slice(0, SPAM_MAX_TRACKED);
}

/* ── Threat type classification from signal breakdown ── */
function _classifyThreat(bd) {
  const { bot=0, dexDom=0, cancelPat=0, pingPong=0, pathRoute=0, selfTrade=0, roundPay=0 } = bd;
  const dexTotal = dexDom + cancelPat;
  if (bot > 0.25 && (bd.botType === 'Flood / Spam' || roundPay > 0.05))
    return 'Payment Flooder';
  if (bot > 0.20 && dexTotal > 0.15)
    return 'DEX Bot';
  if (dexTotal > 0.30 && cancelPat > 0.10)
    return 'Quote Stuffer';
  if (pingPong > 0.10)
    return 'Wash Trader';
  if (pathRoute > 0.10)
    return 'Arb Router';
  if (bot > 0.20)
    return 'Periodic Bot';
  return 'Multi-Signal';
}

/* ── Suspicion score: returns { score, breakdown } ── */
function suspicionScore(addr, d) {
  const breakdown = {
    bot: 0, botType: null, dexDom: 0, cancelPat: 0,
    pingPong: 0, pathRoute: 0, selfTrade: 0, roundPay: 0,
  };

  // Bot-like timing (up to 0.40)
  const bot = (d.behavior?.bots || []).find(x => x.acct === addr);
  if (bot) {
    const cvScore = clamp((0.35 - bot.cv) / 0.35, 0, 1);
    breakdown.bot    = +(0.40 * (0.5 + 0.5 * cvScore)).toFixed(3);
    breakdown.botType = bot.botType || 'Periodic';
  }

  // DEX dominance (up to 0.30)
  const dex = d.dexPatterns;
  const topShare = dex?.topActor?.[0]?.acct === addr ? (dex.topShare || 0) : 0;
  if (topShare > 0)
    breakdown.dexDom = +(0.30 * clamp((topShare - 0.20) / 0.40, 0, 1)).toFixed(3);

  // Cancel pattern (up to 0.20)
  const canceller = (dex?.topCanceller || []).find(x => x.acct === addr);
  if (canceller)
    breakdown.cancelPat = +(0.20 * clamp(canceller.count / 20, 0, 1)).toFixed(3);

  // Ping-pong / self-loop (up to 0.20 + 0.15)
  const pairs     = d.breadcrumbs || [];
  const selfLoop  = pairs.find(p => p.from === addr && p.to === addr);
  if (selfLoop)
    breakdown.selfTrade = +(0.20 * clamp(selfLoop.count / 20, 0, 1)).toFixed(3);

  const best = pairs[0];
  if (best && (best.from === addr || best.to === addr)) {
    const rev = pairs.find(p => p.from === best.to && p.to === best.from);
    if (rev && rev.count >= 3 && best.count >= 3) breakdown.pingPong = 0.15;
  }

  // Path routing (up to 0.15)
  const pathActor = (d.advanced?.topPathActors || []).find(x => x.acct === addr);
  if (pathActor)
    breakdown.pathRoute = +(0.15 * clamp(pathActor.count / 25, 0, 1)).toFixed(3);

  // Round-number payment bias (up to 0.10) — NEW signal
  const roundIdx = d.advanced?.roundnessIdx;
  if (roundIdx != null && roundIdx >= 45) {
    // Only penalise if this address is in top path actors (correlated)
    if (pathActor || bot)
      breakdown.roundPay = +(0.10 * clamp((roundIdx - 45) / 35, 0, 1)).toFixed(3);
  }

  const score = clamp(
    breakdown.bot + breakdown.dexDom + breakdown.cancelPat +
    breakdown.pingPong + breakdown.pathRoute + breakdown.selfTrade + breakdown.roundPay,
    0, 1
  );
  return { score, breakdown };
}

/* ── Detect credential tx in stream ── */
function detectCredential(addr, level, txs, nowLedger) {
  if (!txs?.length) return null;
  const wantTag = SPAM_CRED_TAG_BASE + level;

  for (const tx of txs) {
    if (tx?.account !== addr) continue;

    if (tx.type === 'EscrowCreate' && tx.destination === addr) {
      const amt  = typeof tx.amountXrp === 'number' ? tx.amountXrp : null;
      const need = spamBondForLevel(level);
      if (amt != null && amt >= need) {
        const memo = stringifyMemos(tx.memos);
        if (memo.startsWith(SPAM_MEMO_PREFIX)) return nowLedger; // hash verified async
      }
    }

    if (tx.type === 'Payment' && tx.destination === addr) {
      if (Number(tx.destinationTag) === wantTag) {
        const memo = stringifyMemos(tx.memos);
        if (memo.startsWith(SPAM_MEMO_PREFIX)) return nowLedger;
      }
    }
  }
  return null;
}

/* ── Async hash verification for credential memos ── */
async function _verifyCredentialAsync(addr, level, nowLedger) {
  const st = spamState.byAddr.get(addr);
  if (!st) return;

  try {
    const proof = await buildSpamProof(addr, st, nowLedger);
    const expectedPrefix = SPAM_MEMO_PREFIX + proof.hash;

    // Search recent txs in ledger log for the credential memo
    const recentTxs = state.ledgerLog?.flatMap(l => l.transactions || []) || [];
    const matched = recentTxs.some(tx => {
      if (tx?.account !== addr) return false;
      const memo = stringifyMemos(tx.memos);
      return memo.startsWith(expectedPrefix);
    });

    if (matched) {
      // Persist verified status to localStorage
      const cache = _loadVerifiedCache();
      cache[addr] = { ledgerIndex: nowLedger, hash: proof.hash, level };
      _saveVerifiedCache(cache);
      spamState.verifiedCache.set(addr, { ledgerIndex: nowLedger, hash: proof.hash });
      toastInfo(`✔ Credential verified for ${shortAddr(addr)} at L${level}`);
    }
  } catch (e) {
    // Hash verification failed — leave unverified
  }
}

/* ── StringifyMemos: hex-decode XRPL memo fields ── */
function stringifyMemos(memos) {
  if (!Array.isArray(memos)) return '';
  const parts = [];
  for (const m of memos) {
    const memo = m?.Memo || m?.memo || null;
    if (!memo) continue;
    const data = memo.MemoData || memo.memo_data || '';
    try {
      // XRPL encodes MemoData as hex. Decode to ASCII/UTF-8.
      if (typeof data === 'string' && /^[0-9A-Fa-f]+$/.test(data) && data.length % 2 === 0) {
        const bytes = Uint8Array.from(data.match(/../g), h => parseInt(h, 16));
        parts.push(new TextDecoder().decode(bytes));
      } else if (typeof data === 'string') {
        parts.push(data);
      }
    } catch {}
  }
  return parts.join(' ');
}

/* ── Build proof object (async — uses real SHA-512Half) ── */
async function buildSpamProof(addr, st, ledgerIndex) {
  const level = st.level || 0;
  const bondXrp = spamBondForLevel(level);
  const xrpPrice = series.marketPrice.at(-1) ?? null;
  const bondUsd  = xrpPrice ? (bondXrp * xrpPrice).toFixed(2) : null;

  const policy = {
    hashAlgorithm:   'SHA-512Half',  // XRPL-native — first 256 bits of SHA-512
    ratchetMax:      SPAM_RATCHET_MAX,
    strikesToLevel:  SPAM_STRIKES_TO_LVL,
    strikeUp:        SPAM_STRIKE_UP,
    strikeDown:      SPAM_STRIKE_DOWN,
    decayLedgers:    SPAM_DECAY_QUIET,
    bondBaseXrp:     SPAM_BOND_BASE_XRP,
    bondGrowthFactor: SPAM_BOND_GROWTH,
    bondRequiredXrp: bondXrp,
    bondRequiredUsd: bondUsd,
    credTagBase:     SPAM_CRED_TAG_BASE,
    memoPrefix:      SPAM_MEMO_PREFIX,
    credentialTag:   SPAM_CRED_TAG_BASE + level,
  };

  const obj = {
    v:            2,
    hashAlg:      'SHA-512Half',
    network:      state.currentNetwork || 'xrpl-mainnet',
    address:      addr,
    ledgerIndex:  ledgerIndex != null ? Number(ledgerIndex) : null,
    level,
    threatType:   st.threatType || 'Unknown',
    score:        Number((st.score || 0).toFixed(4)),
    strikes:      Number(st.strikes || 0),
    signalBreakdown: st.signalBreakdown || {},
    credential: {
      destinationTag: SPAM_CRED_TAG_BASE + level,
      memoFormat:     SPAM_MEMO_PREFIX + '<SHA-512Half-of-this-proof>',
      verifiedLedger: st.verifiedLedger ?? null,
    },
    policy,
    note: 'Generated by NaluXRP Spam Defense POC. Hash uses XRPL-native SHA-512Half (first 256 bits of SHA-512). A gateway or relayer policy can require the indicated bond/credential before providing service to this address.',
    generatedAt: new Date().toISOString(),
  };

  // Canonical JSON (sorted keys, no whitespace) → SHA-512Half
  const canonicalJson = JSON.stringify(obj, Object.keys(obj).sort(), 0);
  const hash = await sha512Half(canonicalJson);

  // Embed the self-referencing hash into the memo format
  obj.credential.memoFormat = SPAM_MEMO_PREFIX + hash;
  // Reserialise with the embedded hash so the full JSON is self-consistent
  const finalJson = JSON.stringify(obj, null, 2);

  return { hash, canonicalJson: finalJson, level, policy, threatType: st.threatType };
}



/* ── Print spam proof ── */
function _printSpamProof() {
  const proof = spamState.selectedProof;
  if (!proof) { toastWarn('Generate a proof first using the Proof button.'); return; }
  const addr = spamState.selectedAddr || '—';
  const xrpPx = series.marketPrice.at(-1) ?? null;
  const bondXrp = proof.policy.bondRequiredXrp;
  const bondUsd = xrpPx ? ` (~$${(bondXrp * xrpPx).toFixed(0)} USD)` : '';
  const hashWarning = proof.hash.startsWith('FALLBACK')
    ? '<div style="padding:8px 12px;background:#fff3cd;border:1px solid #f0ad4e;border-radius:4px;margin-bottom:12px">⚠ Hash is non-cryptographic (SubtleCrypto unavailable). Do NOT use for enforcement.</div>'
    : '';
  const w = window.open('', '_blank', 'width=760,height=660');
  w.document.write(`<!DOCTYPE html><html><head>
    <title>NaluXRP Spam Proof — ${addr}</title>
    <style>
      body{font-family:-apple-system,system-ui,sans-serif;background:#fff;color:#111;margin:36px;line-height:1.6;font-size:14px}
      h1{font-size:1.15rem;margin-bottom:4px}
      .meta{color:#555;font-size:.82rem;margin-bottom:18px}
      .section{margin-bottom:16px}
      .section-h{font-weight:700;font-size:.85rem;border-bottom:2px solid #eee;padding-bottom:4px;margin-bottom:8px}
      .hash-box{font-family:monospace;font-size:.76rem;word-break:break-all;background:#f0f8ff;
                border:1px solid #c0d8f0;padding:10px;border-radius:4px;margin:6px 0;color:#005080}
      pre{font-family:monospace;font-size:.72rem;background:#f8f8f8;padding:12px;border-radius:4px;
          max-height:320px;overflow:auto;border:1px solid #eee;white-space:pre-wrap;word-break:break-all}
      .pill{display:inline-block;padding:2px 8px;border-radius:999px;background:#f0f0f0;
            font-size:.78rem;font-weight:700;margin-right:4px}
      button{padding:8px 18px;background:#111;color:#fff;border:none;border-radius:4px;cursor:pointer;margin-bottom:18px}
      @media print{button{display:none}}
    </style></head><body>
    <button onclick="window.print()">🖨 Print / Save as PDF</button>
    ${hashWarning}
    <h1>🛡️ NaluXRP Spam Defense Proof</h1>
    <div class="meta">
      Address: <b>${addr}</b> &nbsp;·&nbsp;
      Level: <b>L${proof.level}</b> &nbsp;·&nbsp;
      Type: <b>${proof.threatType || 'Unknown'}</b> &nbsp;·&nbsp;
      Bond: <b>${bondXrp.toLocaleString()} XRP${bondUsd}</b><br>
      Generated: ${new Date().toLocaleString()} &nbsp;·&nbsp;
      Hash algorithm: <b>SHA-512Half (XRPL-native)</b>
    </div>
    <div class="section">
      <div class="section-h">SHA-512Half Proof Hash</div>
      <div class="hash-box">${proof.hash}</div>
      <div style="font-size:.75rem;color:#555;margin-top:4px">
        SHA-512Half = first 256 bits of SHA-512 — same algorithm used by XRPL for transaction and ledger hashes.
      </div>
    </div>
    <div class="section">
      <div class="section-h">Credential Steps</div>
      <p style="font-size:.85rem"><b>Option A (Bond Escrow):</b> EscrowCreate from suspect address to itself,
        ${bondXrp.toLocaleString()} XRP, finish ~25,000 ledgers from now, memo = <code>${SPAM_MEMO_PREFIX}${proof.hash}</code></p>
      <p style="font-size:.85rem"><b>Option B (1-drop payment):</b> Payment of 1 drop to itself,
        DestinationTag = ${SPAM_CRED_TAG_BASE + proof.level}, same memo.</p>
    </div>
    <div class="section">
      <div class="section-h">Canonical Proof JSON (v2)</div>
      <pre>${proof.canonicalJson.replace(/</g,'&lt;').replace(/>/g,'&gt;')}</pre>
    </div>
    </body></html>`);
  w.document.close();
}

/* ═══════════════════════════════════════════════════
   PATTERN DETECTION CARD
═══════════════════════════════════════════════════ */
let _patternCanvas = null;

function mountPatternDetectionCard() {
  if (patternMounted) return;
  patternMounted = true;
  let card = document.querySelector('[aria-label="Pattern detection"]');
  if (!card) {
    card = document.createElement('section');
    card.className = 'widget-card';
    card.setAttribute('aria-label', 'Pattern detection');
    const main = document.querySelector('.dashboard-col-main');
    if (!main) return;
    const metricSection = main.querySelector('.dashboard-metrics');
    if (metricSection) metricSection.insertAdjacentElement('afterend', card);
    else main.prepend(card);
  }
  card.innerHTML = `
    <div class="widget-header">
      <span class="widget-title">&#129504; Dominant Pattern</span>
      <span class="widget-tag mono cut" id="pattern-badge">Waiting for ledger data…</span>
    </div>
    <p class="widget-help">Quick "at a glance" read. If one thing dominates, patterns are easier to spot (but can be noisy).</p>
    <div class="pattern-body">
      <div class="pattern-donut-wrap">
        <canvas id="pattern-donut-canvas" width="160" height="160"></canvas>
        <div class="pattern-donut-center" id="pattern-donut-center"><span style="opacity:.45">&#8212;</span></div>
      </div>
      <div class="pattern-stats">
        <div class="pattern-stat-row"><span class="pattern-stat-k">Type</span><span class="pattern-stat-v mono" id="pattern-dom-type">&#8212;</span></div>
        <div class="pattern-stat-row"><span class="pattern-stat-k">Dominance</span><span class="pattern-stat-v mono" id="pattern-dom-pct">&#8212;</span></div>
        <div class="pattern-stat-row"><span class="pattern-stat-k">Runner-up</span><span class="pattern-stat-v mono" id="pattern-2nd-type">&#8212;</span></div>
        <div class="pattern-stat-row"><span class="pattern-stat-k">Mix (HHI)</span><span class="pattern-stat-v mono" id="pattern-hhi">&#8212;</span></div>
      </div>
    </div>`;
  _patternCanvas = document.getElementById('pattern-donut-canvas');
}

function updatePatternDetectionCard(txTypes, hhi) {
  if (!patternMounted) return;
  const C = typeof TX_COLORS !== 'undefined' ? TX_COLORS : {};
  const entries = Object.entries(txTypes || {}).filter(([,v]) => v > 0).sort(([,a],[,b]) => b - a);
  if (!entries.length) return;
  const total = entries.reduce((s,[,v]) => s+v, 0) || 1;
  const [domType, domCount] = entries[0];
  const pct = Math.round((domCount / total) * 100);
  const second = entries[1];
  const badge = $('pattern-badge');
  if (badge) badge.textContent = domType + ' · ' + pct + '%';
  const typeEl = $('pattern-dom-type');
  if (typeEl) { typeEl.textContent = domType; typeEl.style.color = C[domType] || 'rgba(255,255,255,.9)'; }
  setText('pattern-dom-pct', pct + '% of ledger');
  if (second) {
    const sp = Math.round((second[1] / total) * 100);
    const el = $('pattern-2nd-type');
    if (el) { el.textContent = second[0] + ' (' + sp + '%)'; el.style.color = C[second[0]] || 'rgba(255,255,255,.7)'; }
  } else { setText('pattern-2nd-type', '—'); }
  const hhiEl = $('pattern-hhi');
  if (hhiEl && hhi != null) {
    hhiEl.textContent = hhi.toFixed(3);
    hhiEl.style.color = hhi >= 0.35 ? '#ff5555' : hhi >= 0.25 ? '#ffb86c' : '#50fa7b';
  }
  const center = $('pattern-donut-center');
  if (center) center.innerHTML = '<span style="color:' + (C[domType]||'#fff') + ';font-size:1.15rem">' + pct + '%</span>';
  _drawPatternDonut(entries, total, C);
}

function _drawPatternDonut(entries, total, C) {
  const canvas = _patternCanvas || $('pattern-donut-canvas');
  if (!canvas?.getContext) return;
  const ctx = canvas.getContext('2d');
  const cx = canvas.width/2, cy = canvas.height/2;
  const outerR = Math.min(canvas.width, canvas.height)/2 - 6;
  const innerR = outerR * 0.56;
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  const top = entries.slice(0, 7);
  const other = entries.slice(7).reduce((s,[,v]) => s+v, 0);
  const segs = other > 0 ? [...top, ['Other', other]] : [...top];
  let angle = -Math.PI/2;
  for (const [type, count] of segs) {
    const sweep = (count/total)*Math.PI*2;
    const fill = hexToRgba(C[type] || '#6b7280', 0.88) || '#6b7280';
    ctx.beginPath();
    ctx.moveTo(cx + Math.cos(angle)*innerR, cy + Math.sin(angle)*innerR);
    ctx.arc(cx, cy, outerR, angle, angle+sweep);
    ctx.arc(cx, cy, innerR, angle+sweep, angle, true);
    ctx.closePath();
    ctx.fillStyle = fill;
    ctx.fill();
    ctx.strokeStyle = 'rgba(0,8,20,0.85)';
    ctx.lineWidth = 2;
    ctx.stroke();
    angle += sweep;
  }
  ctx.beginPath();
  ctx.arc(cx, cy, innerR - 1, 0, Math.PI*2);
  ctx.fillStyle = 'rgba(0,21,36,0.94)';
  ctx.fill();
}

/* ═══════════════════════════════════════════════════
   WHALE ALERT FEED
═══════════════════════════════════════════════════ */
function detectWhales(txs, ledgerIndex) {
  for (const tx of txs) {
    if (tx?.type !== 'Payment') continue;
    const xrp = typeof tx?.amountXrp === 'number' ? tx.amountXrp : null;
    if (xrp == null || xrp < ALERT_CONFIG.whaleTxXrp) continue;
    whaleAlerts.unshift({ ts: Date.now(), ledgerIndex, from: tx.account || '—', to: tx.destination || '—', amtXrp: xrp, hash: tx.hash || '' });
    sessionStats.whaleCount++;
  }
  while (whaleAlerts.length > WHALE_FEED_MAX) whaleAlerts.pop();
  renderWhaleFeed();
}

function mountWhaleFeed() {
  if (whaleFeedMounted) return;
  whaleFeedMounted = true;
  const side = document.querySelector('.dashboard-col-side');
  if (!side) return;
  const card = document.createElement('section');
  card.className = 'widget-card';
  card.id = 'whale-feed-card';
  card.setAttribute('aria-label', 'Whale alert feed');
  card.innerHTML = `
    <div class="widget-header">
      <span class="widget-title">🐋 Whale Alert Feed</span>
      <span class="widget-tag mono cut" id="whale-badge">Watching…</span>
    </div>
    <p class="widget-help">Payments ≥ ${ALERT_CONFIG.whaleTxXrp.toLocaleString()} XRP from the live stream. Click address to peek.</p>
    <div id="whale-feed-list" style="max-height:260px;overflow-y:auto">
      <div style="opacity:.5;font-size:.82rem;padding:8px 0">Watching for large transfers…</div>
    </div>`;
  side.prepend(card);
}

function renderWhaleFeed() {
  const list = $('whale-feed-list');
  if (!list) return;
  const badge = $('whale-badge');
  if (badge) badge.textContent = whaleAlerts.length ? `${whaleAlerts.length} alerts` : 'Watching…';
  if (!whaleAlerts.length) {
    list.innerHTML = `<div style="opacity:.5;font-size:.82rem;padding:8px 0">No whale transactions yet.</div>`;
    return;
  }
  list.innerHTML = whaleAlerts.slice(0, 20).map(w => {
    const amt = w.amtXrp >= 1_000_000 ? `${(w.amtXrp/1_000_000).toFixed(2)}M`
      : w.amtXrp >= 1_000 ? `${(w.amtXrp/1_000).toFixed(0)}K` : w.amtXrp.toFixed(0);
    const age = Math.floor((Date.now() - w.ts) / 1000);
    const ageStr = age < 60 ? `${age}s` : age < 3600 ? `${Math.floor(age/60)}m` : `${Math.floor(age/3600)}h`;
    return `<div style="border-bottom:1px solid rgba(255,255,255,.05);padding:7px 0">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:3px">
        <span>🐋</span><span style="font-size:.95rem;font-weight:700;color:#50fa7b">${amt} XRP</span>
        <span style="font-size:.7rem;opacity:.45;margin-left:auto">${ageStr} · #${w.ledgerIndex.toLocaleString()}</span>
      </div>
      <div style="display:flex;gap:4px;align-items:center;font-size:.74rem">
        <button class="addr-link mono cut" data-addr="${escHtml(w.from)}" style="max-width:100px">${escHtml(shortAddr(w.from))}</button>
        <span style="opacity:.5">→</span>
        <button class="addr-link mono cut" data-addr="${escHtml(w.to)}" style="max-width:100px">${escHtml(shortAddr(w.to))}</button>
        ${w.hash ? `<a href="https://livenet.xrpl.org/transactions/${escHtml(w.hash)}" target="_blank" rel="noopener" style="margin-left:auto;color:var(--accent,#00d4ff);font-size:.7rem;text-decoration:none">🔗</a>` : ''}
      </div>
    </div>`;
  }).join('');
}

/* ═══════════════════════════════════════════════════
   NETWORK HEALTH CARD
═══════════════════════════════════════════════════ */
function mountNetworkHealthCard() {
  if (networkHealthMounted) return;
  networkHealthMounted = true;
  const main = document.querySelector('.dashboard-col-main');
  if (!main) return;
  const card = document.createElement('section');
  card.className = 'widget-card';
  card.id = 'network-health-card';
  card.setAttribute('aria-label', 'Network health');
  card.innerHTML = `
    <div class="widget-header">
      <span class="widget-title">💚 Network Health Score</span>
      <span class="widget-tag mono cut" id="health-badge">—</span>
    </div>
    <p class="widget-help">Composite: TPS health + fee stability + success rate + close time. Separate from the risk score (which tracks manipulation patterns).</p>
    <div style="display:flex;align-items:center;gap:16px;padding:8px 0 12px">
      <div style="text-align:center;flex-shrink:0">
        <div style="font-size:2.4rem;font-weight:900;line-height:1" id="health-score">—</div>
        <div style="font-size:.65rem;text-transform:uppercase;letter-spacing:.1em;opacity:.5;margin-top:2px">/100</div>
      </div>
      <div style="flex:1"><div style="display:flex;flex-direction:column;gap:5px" id="health-bars"></div></div>
    </div>`;
  const landscape = document.getElementById('landscape-card');
  if (landscape) main.insertBefore(card, landscape);
  else main.prepend(card);
}

function updateNetworkHealthCard(s) {
  if (!document.getElementById('network-health-card')) return;
  const tpsSt = calcTrendStats(state.tpsHistory,  TREND_WINDOW);
  const feeSt = calcTrendStats(state.feeHistory,   TREND_WINDOW);
  const sr    = s.successRate != null ? Number(s.successRate) : null;
  const close = s.latestLedger?.closeTimeSec != null ? Number(s.latestLedger.closeTimeSec) : null;
  const tpsScore  = tpsSt.cur != null ? clamp(Math.round((Math.min(tpsSt.cur,50)/50)*25),0,25) : 12;
  const feeScore  = feeSt.deltaPct != null ? clamp(Math.round(25-(Math.abs(feeSt.deltaPct)/100)*25),0,25) : 12;
  const srScore   = sr  != null ? clamp(Math.round((sr/100)*25),0,25) : 12;
  const clScore   = close != null ? clamp(Math.round(25-Math.max(0,(close-3)/7)*25),0,25) : 12;
  const total = tpsScore + feeScore + srScore + clScore;
  const color = total >= 75 ? '#50fa7b' : total >= 50 ? '#ffb86c' : '#ff5555';
  const label = total >= 75 ? 'Healthy' : total >= 50 ? 'Degraded' : 'Stressed';
  const scoreEl = $('health-score');
  if (scoreEl) { scoreEl.textContent = total; scoreEl.style.color = color; }
  const hbadge = $('health-badge');
  if (hbadge) { hbadge.textContent = label; hbadge.style.color = color; }
  const bars = $('health-bars');
  if (bars) {
    bars.innerHTML = [
      { label:'TPS',        score:tpsScore,  note:tpsSt.cur != null ? `${tpsSt.cur.toFixed(1)} tx/s` : '—' },
      { label:'Fee Stable', score:feeScore,  note:feeSt.deltaPct != null ? fmtPct(feeSt.deltaPct,0)+' vs avg' : '—' },
      { label:'Success',    score:srScore,   note:sr != null ? `${sr.toFixed(1)}%` : '—' },
      { label:'Close Time', score:clScore,   note:close != null ? `${close.toFixed(1)}s` : '—' },
    ].map(c => {
      const pct = (c.score/25)*100;
      const col = c.score >= 20 ? '#50fa7b' : c.score >= 12 ? '#ffb86c' : '#ff5555';
      return `<div style="display:flex;align-items:center;gap:8px">
        <span style="font-size:.7rem;min-width:68px;opacity:.7">${c.label}</span>
        <div style="flex:1;height:5px;background:rgba(255,255,255,.08);border-radius:3px;overflow:hidden">
          <div style="height:100%;width:${pct}%;background:${col};border-radius:3px"></div></div>
        <span style="font-size:.7rem;min-width:48px;text-align:right;opacity:.65">${c.note}</span>
      </div>`;
    }).join('');
  }
}

/* ═══════════════════════════════════════════════════
   SESSION STATS PANEL
═══════════════════════════════════════════════════ */
function mountSessionStatsPanel() {
  if (sessionStatsMounted) return;
  sessionStatsMounted = true;
  const side = document.querySelector('.dashboard-col-side');
  if (!side) return;
  const card = document.createElement('section');
  card.className = 'widget-card';
  card.id = 'session-stats-card';
  card.setAttribute('aria-label', 'Session stats');
  card.innerHTML = `
    <div class="widget-header">
      <span class="widget-title">📈 Session Stats</span>
      <span class="widget-tag mono cut" id="ss-badge">—</span>
    </div>
    <div class="dex-mini" style="flex-wrap:wrap;gap:8px">
      <div><span>Ledgers</span><b class="mono" id="ss-ledgers">0</b></div>
      <div><span>Total Tx</span><b class="mono" id="ss-tx">0</b></div>
      <div><span>Whale Alerts</span><b class="mono" id="ss-whales">0</b></div>
      <div><span>Fee Spikes</span><b class="mono" id="ss-feespikes">0</b></div>
      <div><span>Bots Seen</span><b class="mono" id="ss-bots">0</b></div>
      <div><span>DEX Alerts</span><b class="mono" id="ss-dexalerts">0</b></div>
      <div><span>Uptime</span><b class="mono" id="ss-time">0m</b></div>
    </div>`;
  side.appendChild(card);
}

function updateSessionStatsPanel() {
  if (!document.getElementById('session-stats-card')) return;
  const mins = Math.floor((Date.now() - sessionStats.startTime) / 60000);
  setText('ss-ledgers',   sessionStats.ledgersProcessed.toLocaleString());
  setText('ss-tx',        sessionStats.totalTx.toLocaleString());
  setText('ss-whales',    sessionStats.whaleCount);
  setText('ss-feespikes', sessionStats.feeSpikes);
  setText('ss-bots',      sessionStats.botDetections);
  setText('ss-dexalerts', sessionStats.dexAlerts);
  setText('ss-time',      `${mins}m`);
  setText('ss-badge',     `${sessionStats.ledgersProcessed} ledgers`);
}

/* ═══════════════════════════════════════════════════
   SMART ALERT SYSTEM
═══════════════════════════════════════════════════ */
function _checkAndFireAlerts(d, ledgerIndex) {
  _lastAlertLedger = ledgerIndex;

  if (whaleAlerts.length && whaleAlerts[0].ledgerIndex === ledgerIndex) {
    const w = whaleAlerts[0];
    const amt = w.amtXrp >= 1e6 ? `${(w.amtXrp/1e6).toFixed(1)}M` : `${(w.amtXrp/1000).toFixed(0)}K`;
    toastInfo(`🐋 Whale: ${amt} XRP  ${shortAddr(w.from)} → ${shortAddr(w.to)}`);
  }

  const baseline = _feeBaseline();
  const curFee = state.feeHistory?.at(-1);
  if (curFee && baseline && curFee > baseline * ALERT_CONFIG.feeSpikeMultiple) {
    sessionStats.feeSpikes++;
    toastWarn(`🔥 Fee spike: ${fmtXrp(curFee)} (${Math.round(curFee/baseline)}× baseline)`);
  }

  const newBots = (d.behavior?.bots || []).filter(b => b.cv < ALERT_CONFIG.botCvThreshold && b.total > 8);
  if (newBots.length) {
    sessionStats.botDetections = Math.max(sessionStats.botDetections, newBots.length);
    if (newBots[0].botType === 'Flood / Spam')
      toastWarn(`🤖 Spam bot: ${shortAddr(newBots[0].acct)} (CV ${newBots[0].cv.toFixed(2)})`);
  }

  if (d.dexPatterns?.window?.cancelRatio >= ALERT_CONFIG.dexCancelAlert && d.dexPatterns?.window?.total >= 20) {
    sessionStats.dexAlerts++;
    toastWarn(`🧠 DEX: ${Math.round(d.dexPatterns.window.cancelRatio*100)}% cancel ratio — possible quote-stuffing`);
  }

  if (d.clusters?.[0]?.size >= ALERT_CONFIG.clusterMinSize)
    toastInfo(`🕸 Cluster: ${d.clusters[0].size} wallets around ${shortAddr(d.clusters[0].hub)}`);

  if (d.friction >= 75 && d.regime === 'Manipulated')
    toastWarn(`⚠️ Risk score: ${d.friction}/100 — ${d.regime} regime`);

  updateNetworkHealthCard(d.s);
}

/* ═══════════════════════════════════════════════════
   DASHBOARD CUSTOMIZER
═══════════════════════════════════════════════════ */
function mountDashboardCustomizer() {
  if (customizerMounted) return;
  customizerMounted = true;

  const btn = document.createElement('button');
  btn.id = 'customize-btn';
  btn.className = 'customize-btn';
  btn.setAttribute('aria-pressed', 'false');
  btn.innerHTML = '⚙ Customize';
  document.querySelector('.dashboard-header')?.appendChild(btn);

  const panel = document.createElement('div');
  panel.id = 'customize-panel';
  panel.className = 'customize-panel';
  panel.setAttribute('aria-label', 'Dashboard customizer');
  panel.innerHTML = `
    <div class="customize-panel-head">
      <span class="customize-panel-title">⚙ Customize Dashboard</span>
      <button class="customize-close" id="customize-close">✕</button>
    </div>
    <p class="customize-help">Drag cards to reorder · toggle visibility · changes save automatically.</p>
    <div class="customize-list" id="customize-list"></div>
    <div style="display:flex;gap:8px;margin-top:10px">
      <button class="customize-reset" id="customize-reset">Reset to default</button>
      <button class="customize-reset" id="customize-export"
        style="background:rgba(0,212,255,.08);border-color:rgba(0,212,255,.2);color:var(--accent,#00d4ff)">Export Config</button>
    </div>`;
  document.body.appendChild(panel);

  btn.addEventListener('click', () => toggleCustomizer());
  document.getElementById('customize-close')?.addEventListener('click', () => toggleCustomizer(false));
  document.getElementById('customize-reset')?.addEventListener('click', () => {
    try { localStorage.removeItem(LS_WIDGET_ORDER); localStorage.removeItem(LS_WIDGET_HIDDEN); } catch {}
    applyWidgetOrder(); applyWidgetHidden(); renderCustomizerList();
  });
  document.getElementById('customize-export')?.addEventListener('click', () => {
    try {
      const data = {
        order:  JSON.parse(localStorage.getItem(LS_WIDGET_ORDER)  || '[]'),
        hidden: JSON.parse(localStorage.getItem(LS_WIDGET_HIDDEN) || '[]'),
        alertConfig: ALERT_CONFIG,
      };
      navigator.clipboard?.writeText(JSON.stringify(data, null, 2));
      toastInfo('Config copied to clipboard');
    } catch { toastWarn('Export failed'); }
  });

  applyWidgetOrder();
  applyWidgetHidden();
}

function toggleCustomizer(force) {
  const panel = document.getElementById('customize-panel');
  const btn   = document.getElementById('customize-btn');
  if (!panel || !btn) return;
  customizerActive = force != null ? force : !customizerActive;
  panel.classList.toggle('customize-panel--open', customizerActive);
  btn.setAttribute('aria-pressed', String(customizerActive));
  btn.textContent = customizerActive ? '✕ Close' : '⚙ Customize';
  if (customizerActive) renderCustomizerList();
  document.querySelector('.dashboard-col-side')?.classList.toggle('customize-mode', customizerActive);
}

function _getWidgetCards() {
  return [...(document.querySelector('.dashboard-col-side')?.querySelectorAll(':scope > .widget-card') || [])];
}
function _widgetId(card)    { return card.id || card.getAttribute('aria-label') || ''; }
function _widgetTitle(card) { return card.querySelector('.widget-title')?.textContent?.trim() || _widgetId(card); }

function applyWidgetOrder() {
  const side = document.querySelector('.dashboard-col-side');
  if (!side) return;
  let order;
  try { order = JSON.parse(localStorage.getItem(LS_WIDGET_ORDER) || 'null'); } catch { order = null; }
  if (!Array.isArray(order) || !order.length) return;
  const map = new Map(_getWidgetCards().map(c => [_widgetId(c), c]));
  order.forEach(id => { const c = map.get(id); if (c) side.appendChild(c); });
}

function applyWidgetHidden() {
  let hidden;
  try { hidden = JSON.parse(localStorage.getItem(LS_WIDGET_HIDDEN) || '[]'); } catch { hidden = []; }
  _getWidgetCards().forEach(card => card.classList.toggle('widget-hidden', hidden.includes(_widgetId(card))));
}

function saveWidgetOrder() {
  try { localStorage.setItem(LS_WIDGET_ORDER, JSON.stringify(_getWidgetCards().map(c => _widgetId(c)))); } catch {}
}

function toggleWidgetHidden(id) {
  let hidden;
  try { hidden = JSON.parse(localStorage.getItem(LS_WIDGET_HIDDEN) || '[]'); } catch { hidden = []; }
  hidden = hidden.includes(id) ? hidden.filter(x => x !== id) : [...hidden, id];
  try { localStorage.setItem(LS_WIDGET_HIDDEN, JSON.stringify(hidden)); } catch {}
  applyWidgetHidden();
  renderCustomizerList();
}

function renderCustomizerList() {
  const list = document.getElementById('customize-list');
  if (!list) return;
  let hidden;
  try { hidden = JSON.parse(localStorage.getItem(LS_WIDGET_HIDDEN) || '[]'); } catch { hidden = []; }
  list.innerHTML = '';
  _getWidgetCards().forEach(card => {
    const id    = _widgetId(card);
    const title = _widgetTitle(card);
    const vis   = !hidden.includes(id);
    const row   = document.createElement('div');
    row.className = 'customize-row';
    row.setAttribute('draggable', 'true');
    row.dataset.widgetId = id;
    row.innerHTML = `
      <span class="customize-drag-handle" title="Drag to reorder">⠿</span>
      <span class="customize-row-title">${escHtml(title)}</span>
      <button class="customize-vis-btn ${vis ? 'vis-on' : 'vis-off'}" data-id="${escHtml(id)}">${vis ? '👁 Visible' : '🚫 Hidden'}</button>`;
    row.addEventListener('dragstart', e => {
      _dragSrc = row;
      e.dataTransfer.effectAllowed = 'move';
      row.classList.add('customize-dragging');
    });
    row.addEventListener('dragend', () => {
      row.classList.remove('customize-dragging');
      list.querySelectorAll('.customize-row').forEach(r => r.classList.remove('customize-over'));
      const newOrder = [...list.querySelectorAll('.customize-row')].map(r => r.dataset.widgetId);
      const side = document.querySelector('.dashboard-col-side');
      if (side) {
        const map = new Map(_getWidgetCards().map(c => [_widgetId(c), c]));
        newOrder.forEach(wid => { const c = map.get(wid); if (c) side.appendChild(c); });
      }
      saveWidgetOrder();
    });
    row.addEventListener('dragover', e => {
      e.preventDefault(); e.dataTransfer.dropEffect = 'move';
      if (_dragSrc && _dragSrc !== row) {
        list.querySelectorAll('.customize-row').forEach(r => r.classList.remove('customize-over'));
        row.classList.add('customize-over');
        const rows = [...list.querySelectorAll('.customize-row')];
        if (rows.indexOf(_dragSrc) < rows.indexOf(row)) list.insertBefore(_dragSrc, row.nextSibling);
        else list.insertBefore(_dragSrc, row);
      }
    });
    row.addEventListener('dragleave', () => row.classList.remove('customize-over'));
    row.addEventListener('drop', e => e.preventDefault());
    row.querySelector('.customize-vis-btn')?.addEventListener('click', () => toggleWidgetHidden(id));
    list.appendChild(row);
  });
}


/* ═══════════════════════════════════════════════════
   FEATURE 1: GLOBAL PAUSE / RESUME BUTTON
   A persistent button in the header — click to freeze
   all ledger updates while you read. Unlike hover-pause
   which only pauses the stream animation, this stops
   all update renders so numbers stop changing.
═══════════════════════════════════════════════════ */
function mountPauseButton() {
  if (_pauseBtnMounted) return;
  _pauseBtnMounted = true;

  const header = document.querySelector('.dashboard-header');
  if (!header) return;
  if (document.getElementById('global-pause-btn')) return;

  const btn = document.createElement('button');
  btn.id = 'global-pause-btn';
  btn.className = 'global-pause-btn';
  btn.setAttribute('aria-pressed', 'false');
  btn.title = 'Pause all updates — numbers stop changing so you can read';
  btn.innerHTML = '⏸ Live';

  btn.addEventListener('click', () => {
    _globalPaused = !_globalPaused;
    btn.setAttribute('aria-pressed', String(_globalPaused));
    btn.innerHTML = _globalPaused ? '▶ Paused' : '⏸ Live';
    btn.classList.toggle('global-pause-btn--paused', _globalPaused);
    // Also pause the stream animation
    _streamPaused = _globalPaused && !_uiModalOpen ? _globalPaused : _streamPaused;

    // Show a non-intrusive pause overlay on the metric strip
    const strip = document.querySelector('.dashboard-sticky-strip');
    if (strip) strip.classList.toggle('metrics-paused', _globalPaused);
  });

  // Insert before customize button if it exists, else append
  const customizeBtn = document.getElementById('customize-btn');
  if (customizeBtn) header.insertBefore(btn, customizeBtn);
  else header.appendChild(btn);
}

/* ═══════════════════════════════════════════════════
   FEATURE 3: FRICTION / REGIME HISTORY SPARKLINE
   A 30-ledger sparkline of the friction score sitting
   next to the Risk badge on the landscape and risk cards.
   Color: green (0-25), orange (26-60), red (61+).
   Also shows the regime as a tiny colored dot history.
═══════════════════════════════════════════════════ */
let _frictionSparkMounted = false;

function mountFrictionSparkline() {
  if (_frictionSparkMounted) return;
  _frictionSparkMounted = true;

  // Create the sparkline container — injected after the risk-badge in the risk card
  // We defer actual injection until the risk card is mounted
  // So we attach to the risk card after it exists via a short poll
  const tryAttach = (attempts = 0) => {
    const riskHeader = document.querySelector('#risk-card .widget-header');
    const landscapeHeader = document.querySelector('#landscape-card .widget-header');
    if ((!riskHeader && !landscapeHeader) && attempts < 20) {
      setTimeout(() => tryAttach(attempts + 1), 300);
      return;
    }

    // Inject into risk card header
    if (riskHeader && !riskHeader.querySelector('.friction-sparkline-wrap')) {
      const wrap = document.createElement('div');
      wrap.className = 'friction-sparkline-wrap';
      wrap.title = 'Risk score — last 30 ledgers';
      wrap.innerHTML = '<canvas id="friction-sparkline-canvas" width="80" height="22"></canvas>';
      riskHeader.appendChild(wrap);
    }
    // Inject into landscape card header (smaller version)
    if (landscapeHeader && !landscapeHeader.querySelector('.friction-sparkline-wrap')) {
      const wrap = document.createElement('div');
      wrap.className = 'friction-sparkline-wrap';
      wrap.title = 'Risk score history';
      wrap.innerHTML = '<canvas id="friction-sparkline-canvas-2" width="60" height="18"></canvas>';
      landscapeHeader.appendChild(wrap);
    }
    _updateFrictionSparkline();
  };
  tryAttach();
}

function _updateFrictionSparkline() {
  if (!_frictionHistory.length) return;
  _drawFrictionSparkline('friction-sparkline-canvas', 80, 22);
  _drawFrictionSparkline('friction-sparkline-canvas-2', 60, 18);
}

function _drawFrictionSparkline(canvasId, W, H) {
  const canvas = document.getElementById(canvasId);
  if (!canvas?.getContext) return;
  const ctx = canvas.getContext('2d');
  ctx.clearRect(0, 0, W, H);

  const data = _frictionHistory;
  if (data.length < 2) return;

  const max = 100;
  const step = W / (data.length - 1);
  const pts = data.map((d, i) => [i * step, H - 2 - (d.friction / max) * (H - 4)]);

  // Danger zone fill above 60
  const dangerY = H - 2 - (60 / max) * (H - 4);
  ctx.fillStyle = 'rgba(255,85,85,.07)';
  ctx.fillRect(0, 0, W, dangerY);

  // Area fill
  const grad = ctx.createLinearGradient(0, 0, 0, H);
  grad.addColorStop(0, 'rgba(255,184,108,.35)');
  grad.addColorStop(1, 'rgba(255,184,108,.05)');
  ctx.beginPath();
  pts.forEach(([x, y], i) => i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y));
  ctx.lineTo(pts.at(-1)[0], H);
  ctx.lineTo(0, H);
  ctx.closePath();
  ctx.fillStyle = grad;
  ctx.fill();

  // Line — color based on latest value
  const latest = data.at(-1).friction;
  const lineColor = latest < 26 ? '#50fa7b' : latest < 61 ? '#ffb86c' : '#ff5555';
  ctx.beginPath();
  pts.forEach(([x, y], i) => i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y));
  ctx.strokeStyle = lineColor;
  ctx.lineWidth = 1.5;
  ctx.lineJoin = 'round';
  ctx.stroke();

  // Latest value dot
  const [lx, ly] = pts.at(-1);
  ctx.beginPath();
  ctx.arc(lx, ly, 2.5, 0, Math.PI * 2);
  ctx.fillStyle = lineColor;
  ctx.fill();
}

/* ═══════════════════════════════════════════════════
   FEATURE 5: PRINT LANDSCAPE REPORT
   Opens a print-ready HTML window of the current
   Landscape Report state.
═══════════════════════════════════════════════════ */
window.printLandscapeReport = function() {
  const card = document.getElementById('landscape-card');
  if (!card) return;

  const li = document.getElementById('d2-ledger-index')?.textContent || '—';
  const badge = document.getElementById('landscape-badge')?.textContent || '';
  const now = new Date().toLocaleString();

  const w = window.open('', '_blank', 'width=860,height=700');
  w.document.write(`<!DOCTYPE html><html><head>
  <title>NaluXRP Landscape Report — Ledger ${li}</title>
  <style>
    body { font-family: -apple-system, system-ui, sans-serif; background:#fff; color:#111;
           margin: 40px; line-height: 1.6; font-size: 14px; }
    h1 { font-size: 1.4rem; margin-bottom: 4px; }
    .meta { color: #555; font-size: .85rem; margin-bottom: 24px; }
    .section { margin-bottom: 20px; }
    .section-h { font-size: 1rem; font-weight: 800; border-bottom: 2px solid #eee;
                 padding-bottom: 6px; margin-bottom: 10px; }
    .row { padding: 5px 0; border-bottom: 1px solid #f0f0f0; font-size: .88rem; }
    .row:last-child { border-bottom: none; }
    .watchitem { padding: 8px 10px; border-left: 3px solid #ffb86c;
                 margin-bottom: 8px; background: #fffbf3; border-radius: 0 4px 4px 0; }
    .watchitem b { font-size: .9rem; }
    .watchitem p { margin: 4px 0 0; color: #555; font-size: .82rem; }
    button { display: block; margin: 0 auto 20px;
             padding: 10px 24px; background: #111; color: #fff;
             border: none; border-radius: 6px; cursor: pointer; font-size: .9rem; }
    @media print { button { display: none; } body { margin: 20px; } }
  </style>
  </head><body>
  <button onclick="window.print()">🖨 Print / Save as PDF</button>
  <h1>🧾 NaluXRP Landscape Report</h1>
  <div class="meta">Ledger #${li} · ${badge} · Generated ${now}</div>`);

  // Extract text content from each section
  const sections = [
    { id: 'landscape-text',       label: 'Situation Summary' },
    { id: 'landscape-why',        label: 'Why It Matters' },
    { id: 'landscape-now',        label: 'What Is Happening' },
    { id: 'landscape-watch',      label: 'What To Watch Next' },
    { id: 'landscape-watchlist',  label: 'Who To Watch' },
  ];

  for (const { id, label } of sections) {
    const el = document.getElementById(id);
    if (!el || !el.textContent.trim()) continue;

    w.document.write(`<div class="section"><div class="section-h">${label}</div>`);

    if (id === 'landscape-watchlist') {
      const items = el.querySelectorAll('.landscape-watchitem');
      if (items.length) {
        for (const item of items) {
          const addr = item.querySelector('.addr-link')?.textContent || '—';
          const why  = item.querySelector('.landscape-watchwhy')?.textContent || '';
          w.document.write(`<div class="watchitem"><b>${addr}</b><p>${why}</p></div>`);
        }
      } else {
        w.document.write(`<div class="row">${el.textContent.trim()}</div>`);
      }
    } else {
      const rows = el.querySelectorAll('.landscape-row');
      if (rows.length) {
        for (const row of rows) w.document.write(`<div class="row">${row.innerHTML}</div>`);
      } else {
        w.document.write(`<div class="row">${el.innerHTML}</div>`);
      }
    }
    w.document.write('</div>');
  }

  w.document.write('</body></html>');
  w.document.close();
};

/* ─────────────────────────────
   Bottom nav (mobile)
──────────────────────────────── */
function mountBottomNav() {
  if (bottomNavMounted) return;
  bottomNavMounted = true;

  const dash = document.getElementById('dashboard');
  if (!dash) return;
  if (document.getElementById('dash-bottom-nav')) return;

  const nav = document.createElement('nav');
  nav.id = 'dash-bottom-nav';
  nav.setAttribute('aria-label', 'Dashboard quick nav');
  nav.innerHTML = `
    <button data-go="stream" class="bn-btn"><span>🌊</span><small>Stream</small></button>
    <button data-go="inspector" class="bn-btn"><span>🔍</span><small>Inspect</small></button>
    <button data-go="network" class="bn-btn"><span>📡</span><small>Health</small></button>
    <button data-go="dex" class="bn-btn"><span>🧠</span><small>DEX</small></button>
    <button data-go="risk" class="bn-btn"><span>⚠️</span><small>Risk</small></button>
  `;
  dash.appendChild(nav);

  const goTab = (tab) => document.querySelector(`.dash-tab[data-tab="${tab}"]`)?.click();

  nav.addEventListener('click', (e) => {
    const b = e.target.closest('button[data-go]');
    if (!b) return;
    const go = b.dataset.go;

    if (go === 'stream' || go === 'inspector' || go === 'network') {
      goTab(go);
      return;
    }

    goTab('stream');
    setTimeout(() => {
      const id = go === 'dex' ? 'dex-pattern-card' : 'risk-card';
      document.getElementById(id)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }, 80);
  });
}

/* ─────────────────────────────
   Compact / accordion mode
──────────────────────────────── */
function mountCompactToggle() {
  if (compactBound) return;
  compactBound = true;

  const header = document.querySelector('.dashboard-header');
  if (!header) return;
  if (document.getElementById('compactToggleBtn')) return;

  const btn = document.createElement('button');
  btn.id = 'compactToggleBtn';
  btn.type = 'button';
  btn.className = 'dash-accordion-toggle';
  btn.textContent = 'Compact: OFF';
  header.appendChild(btn);

  const apply = (on, persist = true) => {
    document.body.classList.toggle('dash-accordion', on);
    btn.textContent = on ? 'Compact: ON' : 'Compact: OFF';
    if (persist) {
      try { localStorage.setItem(LS_COMPACT_MODE, on ? '1' : '0'); } catch {}
    }
    if (on) {
      const first = document.querySelector('.dashboard-col-side .widget-card');
      if (first) first.classList.add('is-open');
    } else {
      document.querySelectorAll('.dashboard-col-side .widget-card.is-open')
        .forEach((c) => c.classList.remove('is-open'));
    }
  };

  let saved = null;
  try { saved = localStorage.getItem(LS_COMPACT_MODE); } catch {}

  if (saved === '1') apply(true, false);
  else if (saved === '0') apply(false, false);
  else apply(window.matchMedia?.('(max-width: 600px)')?.matches ?? false, false);

  btn.addEventListener('click', () => apply(!document.body.classList.contains('dash-accordion'), true));
}

function bindAccordionDelegation() {
  if (accordionBound) return;
  accordionBound = true;

  const side = document.querySelector('.dashboard-col-side');
  if (!side) return;

  side.addEventListener('click', (e) => {
    if (!document.body.classList.contains('dash-accordion')) return;

    const t = e.target;
    if (t?.closest?.('button, a, input, textarea, select, kbd')) return;

    const card = t?.closest?.('.widget-card');
    if (!card) return;

    const isOpen = card.classList.contains('is-open');

    side.querySelectorAll('.widget-card.is-open').forEach((c) => {
      if (c !== card) c.classList.remove('is-open');
    });

    card.classList.toggle('is-open', !isOpen);
  });
}