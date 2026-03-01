/* =====================================================
   scripts/dashboard.js — Metrics · Charts · Stream · DEX Patterns · Reporting
   Changes:
   - Layman landscape report
   - Replace orderbook microstructure with DEX Pattern Monitor (no book_offers)
   - Better explainers
   - Address peek modal -> Inspector works reliably (tab switch + fill + run)
   ===================================================== */

import { $, $$, escHtml, shortAddr, toastInfo, toastWarn, isValidXrpAddress } from './utils.js';
import { state } from './state.js';
import { TX_COLORS } from './config.js';
import { switchNetwork, wsSend } from './xrpl.js';

/* ─────────────────────────────
   Tunables
──────────────────────────────── */
const STREAM_MAX_CARDS = 12;
const MAX_TX_SAMPLE = 180;

const TREND_WINDOW = 12;
const MA_WINDOW = 5;

const LS_COMPACT_MODE = 'naluxrp_compact_mode';

/* Whale threshold (XRP) */
const WHALE_XRP = 100_000;

/* DEX window */
const DEX_WINDOW = 18; // rolling ledgers used for DEX pattern monitor
const DEX_MIN_FOR_SIGNALS = 16;

/* ─────────────────────────────
   Rolling derived state
──────────────────────────────── */
const behaviorState = {
  acct: new Map(), // acct -> { ledgers:number[], intervals:number[], total:number }
};

const pairState = {
  window: [],
  totals: new Map(),
  maxLedgers: 12,
};

const dexState = {
  window: [], // [{ li, closeTimeSec, create, cancel, total, cancelsPerMin, byActor: Map, byActorCancel: Map, byActorCreate: Map }]
  smoothCancelPerMin: null,
  smoothBurst: null,
};

/* Mounted flags */
let explainersMounted = false;
let legendMounted = false;
let trendMiniMounted = false;
let landscapeMounted = false;
let dexMounted = false;
let riskMounted = false;
let bottomNavMounted = false;
let compactBound = false;
let accordionBound = false;
let clickDelegationBound = false;
let acctPeekMounted = false;

/* Stream animation */
let streamOffset = 0;

/* ─────────────────────────────
   Public
──────────────────────────────── */
export function initDashboard() {
  bindNetworkButtons();
  initCharts();
  initLedgerStream();

  injectSectionExplainers();
  mountLedgerLegend();
  mountTrendMiniBlocks();

  mountAccountPeekModal();
  bindAddressClickDelegation();

  mountLandscapeBrief();
  mountDexPatternMonitor();
  mountRiskWidget();

  mountBottomNav();
  mountCompactToggle();
  bindAccordionDelegation();

  window.addEventListener('xrpl-connection', (e) => {
    const connected = !!e?.detail?.connected;
    if (!connected) {
      // no-op (DEX monitor is stream-based, no extra polling)
    }
  });

  window.addEventListener('xrpl-ledger', (e) => {
    const s = e.detail;

    updateMetricCards(s);
    updateChartsAndTrendMini();
    updateTxMix();
    updateLedgerLog();

    pushLedgerCard(s.latestLedger);

    const derived = computeDerived(s);

    renderBreadcrumbs(derived.breadcrumbs);
    renderClusters(derived.clusters);
    renderNarratives(derived.narratives);

    updateDexPatternMonitor(derived.dexPatterns);
    updateLandscapeBrief(derived);
    updateRiskWidget(derived);
  });
}

/* ─────────────────────────────
   Helpers
──────────────────────────────── */
function setText(id, val) {
  const el = $(id);
  if (el) el.textContent = String(val);
}

function clamp(n, lo, hi) {
  return Math.max(lo, Math.min(hi, n));
}

function mean(arr) {
  if (!arr?.length) return null;
  return arr.reduce((a, b) => a + b, 0) / arr.length;
}

function stdev(arr) {
  if (!arr || arr.length < 2) return null;
  const m = mean(arr);
  const v = mean(arr.map((x) => (x - m) ** 2));
  return Math.sqrt(v);
}

function lastN(arr, n) {
  if (!arr?.length) return [];
  return arr.slice(Math.max(0, arr.length - n));
}

function movingAverage(data, k) {
  const out = [];
  for (let i = 0; i < data.length; i++) {
    const a = Math.max(0, i - k + 1);
    out.push(mean(data.slice(a, i + 1)));
  }
  return out;
}

function fmtPct(p, digits = 0) {
  if (p == null || !Number.isFinite(p)) return '—';
  const sign = p >= 0 ? '↑' : '↓';
  return `${sign}${Math.abs(p).toFixed(digits)}%`;
}

function safeNum(n, digits = 2) {
  if (n == null || !Number.isFinite(n)) return '—';
  return Number(n).toFixed(digits);
}

/* Converts "#RRGGBB" / "#RGB" / "rgb(...)" into "rgba(r,g,b,a)" */
function hexToRgba(input, alpha = 1) {
  if (!input) return null;
  const a = clamp(Number(alpha), 0, 1);
  const s = String(input).trim();

  if (s.startsWith('rgba(')) return s;

  if (s.startsWith('rgb(')) {
    const m = s.match(/^rgb\(\s*([0-9]+)\s*,\s*([0-9]+)\s*,\s*([0-9]+)\s*\)$/i);
    if (!m) return null;
    const r = clamp(Number(m[1]), 0, 255);
    const g = clamp(Number(m[2]), 0, 255);
    const b = clamp(Number(m[3]), 0, 255);
    return `rgba(${r},${g},${b},${a})`;
  }

  if (s[0] === '#') {
    let hex = s.slice(1);
    if (hex.length === 3) hex = hex.split('').map((c) => c + c).join('');
    if (hex.length !== 6) return null;
    const r = parseInt(hex.slice(0, 2), 16);
    const g = parseInt(hex.slice(2, 4), 16);
    const b = parseInt(hex.slice(4, 6), 16);
    if (![r, g, b].every(Number.isFinite)) return null;
    return `rgba(${r},${g},${b},${a})`;
  }

  return null;
}

function smooth(prev, next, alpha = 0.45) {
  if (next == null || !Number.isFinite(next)) return prev;
  if (prev == null || !Number.isFinite(prev)) return next;
  return prev * (1 - alpha) + next * alpha;
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
        <div>
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
  };

  overlay.addEventListener('click', (e) => {
    if (e.target === overlay) close();
  });

  $('#acctPeekClose')?.addEventListener('click', close);

  $('#acctPeekInspect')?.addEventListener('click', async () => {
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

async function openAccountPeek(addr) {
  if (!isValidXrpAddress(addr)) return;

  const overlay = document.getElementById('acctPeekOverlay');
  if (!overlay) return;

  overlay.style.display = '';
  overlay.setAttribute('data-addr', addr);

  setText('acctPeekAddr', addr);
  setText('acctPeekBal', '…');
  setText('acctPeekSeq', '…');
  setText('acctPeekOwner', '…');
  setText('acctPeekFlags', '…');

  const note = $('#acctPeekNote');
  const ctx = $('#acctPeekCtx');
  if (note) note.textContent = 'Fetching account_info…';
  if (ctx) ctx.textContent = '—';

  const seen = behaviorState.acct.get(addr);
  const appearances = seen?.ledgers?.length || 0;

  try {
    if (!state.wsConn || state.wsConn.readyState !== 1) {
      if (note) note.textContent = 'Not connected to XRPL. Connect first.';
      return;
    }

    const info = await wsSend({ command: 'account_info', account: addr, ledger_index: 'validated', strict: true });
    const d = info?.result?.account_data;

    const drops = Number(d?.Balance ?? NaN);
    const balXrp = Number.isFinite(drops) ? drops / 1e6 : null;

    setText('acctPeekBal', balXrp == null ? '—' : `${balXrp.toLocaleString(undefined, { maximumFractionDigits: 6 })} XRP`);
    setText('acctPeekSeq', d?.Sequence ?? '—');
    setText('acctPeekOwner', d?.OwnerCount ?? '—');
    setText('acctPeekFlags', d?.Flags != null ? `0x${Number(d.Flags).toString(16)}` : '—');

    if (note) {
      const lines = [];
      if (balXrp != null && balXrp >= WHALE_XRP) lines.push('Large balance (whale-sized).');
      if (appearances >= 6) lines.push(`Shows up often in recent ledgers (${appearances} times).`);
      if (!lines.length) lines.push('No obvious red flags from this quick read.');
      note.textContent = lines.join(' ');
    }

    if (ctx) {
      const last = seen?.ledgers?.at(-1);
      ctx.textContent = last ? `Last seen around ledger #${Number(last).toLocaleString()}` : 'Not seen in recent window.';
    }
  } catch (err) {
    if (note) note.textContent = `Lookup failed: ${String(err?.message || err)}`;
  }
}

/* Robust inspector navigation: uses window.switchTab if available, else clicks tab, retries until panel visible */
async function openInspectorForAddress(addr) {
  if (!isValidXrpAddress(addr)) return;

  const tabBtn = document.querySelector('.dash-tab[data-tab="inspector"]');
  const panel = document.getElementById('tab-inspector');

  const ensureTab = async () => {
    if (panel && panel.style.display !== 'none') return true;

    // Prefer the real handler if present (your main.js exposes window.switchTab)
    if (typeof window.switchTab === 'function' && tabBtn) {
      window.switchTab(tabBtn, 'inspector');
    } else {
      tabBtn?.click();
    }

    // wait a tick for DOM updates
    await new Promise((r) => setTimeout(r, 80));
    return panel ? panel.style.display !== 'none' : true;
  };

  // Try a few times (some browsers delay style updates)
  for (let i = 0; i < 6; i++) {
    const ok = await ensureTab();
    if (ok) break;
    await new Promise((r) => setTimeout(r, 80));
  }

  const input = document.getElementById('inspect-addr');
  if (input) {
    input.value = addr;
    input.focus();
  }

  // Run inspect if global bridge exists
  await new Promise((r) => setTimeout(r, 60));
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

      applyStreamTint(null, null);

      switchNetwork(net);
    });
  });
}

/* ─────────────────────────────
   Metric cards
──────────────────────────────── */
function updateMetricCards(s) {
  setText('d2-ledger-index', s.ledgerIndex ? Number(s.ledgerIndex).toLocaleString() : '—');
  setText('d2-ledger-age', s.latestLedger?.closeTimeSec != null ? `${Number(s.latestLedger.closeTimeSec).toFixed(2)}s` : '—');

  if (s.tps != null) {
    setText('d2-tps', Number(s.tps).toFixed(2));
    setText('d2-tps-trend', s.tps < 5 ? 'Low' : s.tps < 15 ? 'Normal' : s.tps < 30 ? 'High' : 'Very High');
  }

  const txPerLedger = s.txPerLedger ?? 0;
  const capPct = Math.min(100, (Number(txPerLedger) / 1000) * 100);
  setText('d2-network-capacity', `${capPct.toFixed(1)}%`);
  setText('d2-capacity-note', capPct < 30 ? 'Quiet' : capPct < 60 ? 'Normal' : capPct < 85 ? 'Busy' : 'Very Busy');
  setText('d2-tx-per-ledger', txPerLedger || '—');
  setText('d2-tx-spread', txPerLedger < 10 ? 'Very light' : txPerLedger < 50 ? 'Light' : txPerLedger < 150 ? 'Normal' : 'High volume');

  const avgFeeXrp = s.avgFee || 0;
  const avgFeeDrops = avgFeeXrp * 1e6;
  setText('d2-fee-pressure', avgFeeXrp < 0.00001 ? 'Low' : avgFeeXrp < 0.00002 ? 'Normal' : avgFeeXrp < 0.00005 ? 'Medium' : 'High');
  setText('d2-fee-note', `${avgFeeDrops.toFixed(0)} drops avg`);

  const srEl = $('d2-success-rate');
  if (srEl) {
    const sr = Number(s.successRate ?? 0);
    srEl.textContent = s.successRate != null ? `${sr.toFixed(1)}%` : '—';
    srEl.style.color = sr >= 98 ? '#50fa7b' : sr >= 95 ? '#ffb86c' : '#ff5555';
  }

  const txTypes = s.txTypes || {};
  if (Object.keys(txTypes).length) {
    const dom = Object.entries(txTypes).sort(([, a], [, b]) => b - a)[0];
    const total = Object.values(txTypes).reduce((a, b) => a + b, 0) || 1;
    const pct = ((dom[1] / total) * 100).toFixed(0);

    setText('d2-dominant-type', dom[0]);
    setText('d2-dominance-score', `${pct}%`);

    const bar = $('d2-dominance-bar');
    if (bar) bar.style.width = `${pct}%`;

    setText('d2-pattern-flags', total > 200 ? 'Busy' : total > 100 ? 'Active' : 'Normal');
    setText('d2-pattern-explain', `${dom[0]} is most common (${pct}% of txs)`);
  }

  const sl = $('stream-loading');
  if (sl) sl.style.display = 'none';
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
    this.canvas = $(canvasId);
    this.color = color;
    this.mode = mode;
  }

  draw(data) {
    if (!this.canvas || !data?.length) return;
    const ctx = this.canvas.getContext('2d');

    const W = (this.canvas.width = this.canvas.offsetWidth || 300);
    const H = (this.canvas.height = this.canvas.offsetHeight || 180);
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

    // baseline
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

    // MA line
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

    // area fill
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

    // line
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
}

function calcTrendStats(series, windowN = TREND_WINDOW) {
  const raw = lastN(series, windowN).filter((x) => Number.isFinite(x));
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
   Stream (cards + tint)
─────────────���────────────────── */
function initLedgerStream() {
  spawnParticles();
  animateStream();
}

function spawnParticles() {
  const layer = $('ledgerStreamParticles');
  if (!layer) return;
  layer.innerHTML = '';
  for (let i = 0; i < 18; i++) {
    const p = document.createElement('div');
    p.className = 'ledger-particle';
    const size = Math.random() * 6 + 4;
    const top = Math.random() * 100;
    const dur = Math.random() * 8 + 6;
    const del = Math.random() * 10;
    Object.assign(p.style, {
      width: `${size}px`,
      height: `${size}px`,
      top: `${top}%`,
      left: '-10px',
      animationDuration: `${dur}s`,
      animationDelay: `${del}s`,
    });
    layer.appendChild(p);
  }
}

function animateStream() {
  const track = $('ledgerStreamTrack');
  if (!track) return;

  let lastTime = 0;
  let lastMeasureTs = 0;
  let cardStepPx = 438;

  const measureStep = () => {
    const first = track.children?.[0];
    if (!first) return;
    const rect = first.getBoundingClientRect();
    const style = getComputedStyle(track);
    const gapStr = (style.columnGap && style.columnGap !== 'normal') ? style.columnGap : (style.gap || '0px');
    const gap = parseFloat(String(gapStr).split(' ')[0]) || 0;
    const w = rect.width || 0;
    if (w > 0) cardStepPx = w + gap;
  };

  function step(ts) {
    if (ts - lastMeasureTs > 600) {
      measureStep();
      lastMeasureTs = ts;
    }

    if (ts - lastTime > 16) {
      streamOffset -= 0.6;

      // More robust than children.length * step (handles variable widths better)
      const trackWidth = track.scrollWidth || (track.children.length * cardStepPx);

      // Loop back halfway to create a conveyor effect
      if (trackWidth > 0 && streamOffset < -(trackWidth / 2)) {
        streamOffset += trackWidth / 2;
      }

      track.style.transform = `translateX(${streamOffset}px)`;
      lastTime = ts;
    }
    requestAnimationFrame(step);
  }

  measureStep();
  requestAnimationFrame(step);
}

function dominantAuraClass(txType) {
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
  const auraClass = dominantAuraClass(dominantTx);
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

/**
 * When we remove the left-most card while the track is mid-translate,
 * the conveyor will "snap" unless we compensate the offset.
 */
function removeFirstCardAndPreserveOffset(track) {
  const first = track.firstElementChild;
  if (!first) return;

  const rect = first.getBoundingClientRect();
  const style = getComputedStyle(track);
  const gapStr = (style.columnGap && style.columnGap !== 'normal') ? style.columnGap : (style.gap || '0px');
  const gap = parseFloat(String(gapStr).split(' ')[0]) || 0;

  const step = (rect.width || 0) + gap;

  // Compensate for removing a left-side element:
  // shifting the track right by "step" keeps the motion continuous.
  streamOffset += step;

  track.removeChild(first);
}

function pushLedgerCard(ledger) {
  const track = $('ledgerStreamTrack');
  if (!track || !ledger) return;

  const loading = $('stream-loading');
  if (loading) loading.style.display = 'none';

  const { dominantTx, auraClass, domColor } = dominantInfoFromLedger(ledger);
  applyStreamTint(auraClass, domColor);

  const card = buildLedgerCard(ledger, dominantTx, auraClass, domColor);

  // IMPORTANT: Oldest on the LEFT, newest appended on the RIGHT
  track.appendChild(card);

  // Cap the list: remove from the LEFT (oldest) and preserve motion continuity
  while (track.children.length > STREAM_MAX_CARDS) {
    removeFirstCardAndPreserveOffset(track);
  }
}

function buildLedgerCard(ledger, dominantTx, auraClass, domColor) {
  const { ledgerIndex, closeTimeSec, totalTx, txTypes, avgFee } = ledger;

  const sorted = Object.entries(txTypes || {}).sort(([, a], [, b]) => b - a);
  const top = sorted.slice(0, 4);
  const total = top.reduce((s, [, c]) => s + c, 0) || 1;

  const card = document.createElement('div');
  card.className = `ledger-card ledger-card--${auraClass}`;

  const border = hexToRgba(domColor, 0.45) || domColor;
  const glow = hexToRgba(domColor, 0.14) || domColor;
  card.style.borderColor = border;
  card.style.boxShadow = `0 0 22px ${glow}`;

  card.innerHTML = `
    <div class="ledger-card-inner">
      <div class="ledger-card-header">
        <span class="ledger-id">#${(ledgerIndex || 0).toLocaleString()}</span>
        <div class="ledger-meta">
          <span class="ledger-tag cut" style="border-color:${border};color:${domColor}">
            ${escHtml(dominantTx)}
          </span>
        </div>
      </div>

      <div class="ledger-main-row">
        <div class="ledger-main-stat">
          <span class="ledger-stat-label">TXs</span>
          <span class="ledger-stat-value">${totalTx ?? 0}</span>
        </div>
        <div class="ledger-main-stat">
          <span class="ledger-stat-label">Close</span>
          <span class="ledger-stat-value">${closeTimeSec != null ? Number(closeTimeSec).toFixed(2) + 's' : '—'}</span>
        </div>
        <div class="ledger-main-stat">
          <span class="ledger-stat-label">Avg Fee</span>
          <span class="ledger-stat-value">${avgFee != null ? (Number(avgFee) * 1e6).toFixed(`*


/* ─────────────────────────────
   Derived analytics
──────────────────────────────── */
function computeDerived(s) {
  const txs = Array.isArray(s.recentTransactions) ? s.recentTransactions.slice(0, MAX_TX_SAMPLE) : [];
  const txTypes = s.txTypes || {};
  const li = Number(s.ledgerIndex || 0);

  // HHI over tx types
  const tot = Object.values(txTypes).reduce((a, b) => a + b, 0) || 1;
  let hhi = 0;
  for (const c of Object.values(txTypes)) {
    const p = c / tot;
    hhi += p * p;
  }

  // rolling counterparties
  const thisPairs = buildPairMapFromTxs(txs);
  addWindowMap(pairState, thisPairs);

  const breadcrumbs = buildBreadcrumbs(pairState.totals, thisPairs);
  const clusters = buildClusters(pairState.totals);

  // behavior / bots
  const behavior = updateBehavior(li, txs);

  // dex patterns (windowed)
  const dexPatterns = updateDexPatterns(li, s.latestLedger?.closeTimeSec, txs);

  // friction score (transparent heuristics)
  const repeats = breadcrumbs.filter((p) => p.count >= 2).length;
  const friction = computeFrictionScore({
    hhi,
    repeats,
    dex: dexPatterns,
    bots: behavior.bots?.length || 0,
  });

  const regime = classifyRegime({
    friction,
    tps: calcTrendStats(state.tpsHistory),
    fee: calcTrendStats(state.feeHistory),
  });

  const narratives = buildNarratives({ s, txTypes, hhi, dexPatterns, behavior, friction, regime, breadcrumbs, clusters });

  return { s, txs, txTypes, hhi, behavior, dexPatterns, friction, regime, breadcrumbs, clusters, narratives };
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
   Uses OfferCreate/OfferCancel from recentTransactions
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

  // push window entry
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

  // aggregate across window
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

  // actor HHI (concentration of DEX activity)
  let actorHHI = 0;
  if (sum.total) {
    for (const c of aggActor.values()) {
      const p = c / sum.total;
      actorHHI += p * p;
    }
  }

  // burst: current vs avg window
  const totals = dexState.window.map((x) => x.total).filter(Number.isFinite);
  const avgTotal = mean(totals) || 0;
  const burstRaw = avgTotal > 0 ? ((total - avgTotal) / avgTotal) * 100 : null;
  dexState.smoothBurst = smooth(dexState.smoothBurst, burstRaw, 0.40);

  // simple pattern signals (layman)
  const signals = [];
  if (sum.total >= DEX_MIN_FOR_SIGNALS && cancelRatio >= 0.65) signals.push('Lots of cancels (looks like “testing” or spam)');
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
   Friction / Regime
──────────────────────────────── */
function computeFrictionScore({ hhi, repeats, dex, bots }) {
  const cHHI = clamp((hhi - 0.22) / 0.25, 0, 1) * 22;
  const cRep = clamp((repeats - 2) / 6, 0, 1) * 12;

  const dexCancel = dex?.window?.cancelRatio ?? 0;
  const dexTopShare = dex?.topShare ?? 0;
  const dexChurn = dex?.now?.cancelsPerMin ?? 0;

  const cDexC = clamp((dexCancel - 0.50) / 0.50, 0, 1) * 18;
  const cDexT = clamp((dexTopShare - 0.25) / 0.50, 0, 1) * 18;
  const cChurn = clamp(dexChurn / 25, 0, 1) * 10;

  const cBots = clamp(bots / 6, 0, 1) * 10;

  return Math.round(cHHI + cRep + cDexC + cDexT + cChurn + cBots);
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
   Narratives (richer, expandable)
──────────────────────────────── */
function buildNarratives({ s, txTypes, hhi, dexPatterns, behavior, friction, regime, breadcrumbs, clusters }) {
  const out = [];

  const tpsSt = calcTrendStats(state.tpsHistory, TREND_WINDOW);
  const feeSt = calcTrendStats(state.feeHistory, TREND_WINDOW);

  const dom = Object.entries(txTypes || {}).sort(([, a], [, b]) => b - a)[0]?.[0] || '—';
  const totalTx = Number(s.txPerLedger || 0);

  out.push({
    sentiment: regime === 'Manipulated' ? 'warn' : regime === 'Stressed' ? 'warn' : regime === 'Active' ? 'up' : 'ok',
    title: `Overall: ${regime} · Risk score ${friction}/100`,
    detail: `This is a simple score from: concentration, repeats, DEX cancels/churn, and bot-like timing. It is a signal, not proof.`,
  });

  out.push({
    sentiment: 'ok',
    title: `Ledger snapshot: #${Number(s.ledgerIndex || 0).toLocaleString()} · ${totalTx} tx · most common: ${dom}`,
    detail: `TPS ${safeNum(tpsSt.cur, 2)} (avg ${safeNum(tpsSt.avg, 2)} · ${fmtPct(tpsSt.deltaPct, 0)}). Fee ${safeNum(feeSt.cur, 0)}d (avg ${safeNum(feeSt.avg, 0)}d · ${fmtPct(feeSt.deltaPct, 0)}).`,
  });

  const conc = hhi >= 0.35 ? 'high' : hhi >= 0.25 ? 'medium' : 'low';
  out.push({
    sentiment: hhi >= 0.35 ? 'warn' : 'ok',
    title: `Transaction mix: ${conc} concentration (HHI ${hhi.toFixed(2)})`,
    detail: hhi >= 0.35
      ? 'A few tx types dominate. That can make “pattern” signals stronger (or noisier).'
      : 'Mix is broad. Strong signals usually come from behavior, not just tx type.',
  });

  if (dexPatterns.window.total) {
    const cancelPct = Math.round(dexPatterns.window.cancelRatio * 100);
    const topPct = Math.round(dexPatterns.topShare * 100);
    out.push({
      sentiment: cancelPct >= 65 && dexPatterns.window.total >= DEX_MIN_FOR_SIGNALS ? 'warn' : 'ok',
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

  if (clusters?.length && clusters[0]?.size >= 4) {
    out.push({
      sentiment: 'new',
      title: `Cluster forming: ${clusters[0].size} wallets · hub ${shortAddr(clusters[0].hub)}`,
      detail: 'Clusters are co-activity groups (not identity). Click hub/members to inspect.',
      addr: clusters[0].hub,
    });
  }

  if (behavior.bots?.length) {
    const top = behavior.bots[0];
    out.push({
      sentiment: 'warn',
      title: `Bot-like timing: ${behavior.bots.length} candidate(s)`,
      detail: `Low variance in repeated appearances (ledger-to-ledger). Top: ${shortAddr(top.acct)} (CV ${top.cv.toFixed(2)}).`,
      addr: top.acct,
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
    ['Live ledger stream', 'Each card is a validated ledger. Glow color shows what type of activity dominated that ledger.'],
    ['Wallet breadcrumbs', 'Shows who repeatedly interacts with who. Click an address for a simple account peek.'],
    ['Cluster inference', 'Groups wallets that move together. Not identity proof. Use it as “likely related behavior.”'],
    ['Delta narratives', 'Plain-English summary of what changed: load, fees, DEX patterns, repeats, bots. Expand for details.'],
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
   Landscape Brief (LAYMAN REPORT)
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
    </div>
    <p class="widget-help">
      “In plain English”: what’s happening now, why it matters, and what to watch. Signals only (not proof).
    </p>

    <div class="landscape-brief" id="landscape-text">Waiting for data…</div>

    <div class="landscape-grid">
      <div class="landscape-box">
        <div class="landscape-h">What’s happening</div>
        <div class="landscape-list" id="landscape-now"></div>
      </div>
      <div class="landscape-box">
        <div class="landscape-h">What to watch</div>
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

  // One paragraph "report"
  const brief = $('landscape-text');
  if (brief) {
    const li = Number(s.ledgerIndex || 0).toLocaleString();
    const txCount = Number(s.txPerLedger || 0);
    const close = s.latestLedger?.closeTimeSec != null ? Number(s.latestLedger.closeTimeSec).toFixed(2) + 's' : '—';
    const tps = tpsSt.cur != null ? `${safeNum(tpsSt.cur, 2)} TPS` : '—';
    const fee = feeSt.cur != null ? `${safeNum(feeSt.cur, 0)} drops fee` : '—';
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

  // What’s happening (bullets)
  const nowEl = $('landscape-now');
  const watchEl = $('landscape-watch');

  const nowItems = [];
  const watchItems = [];

  nowItems.push(`Overall mode: <b>${escHtml(d.regime)}</b> (risk score <b>${d.friction}/100</b>).`);
  nowItems.push(`Traffic: <b>${safeNum(tpsSt.cur, 2)}</b> TPS (avg ${safeNum(tpsSt.avg, 2)} · ${fmtPct(tpsSt.deltaPct, 0)}).`);
  nowItems.push(`Fees: <b>${safeNum(feeSt.cur, 0)}</b> drops (avg ${safeNum(feeSt.avg, 0)} · ${fmtPct(feeSt.deltaPct, 0)}).`);

  if (dex?.window?.total) {
    const top = dex.topActor?.[0];
    nowItems.push(`DEX activity: <b>${dex.window.total}</b> offer tx (window) · cancels <b>${dexCancelPct}%</b>.`);
    if (top) nowItems.push(`Most active DEX wallet: <button class="addr-link mono" data-addr="${escHtml(top.acct)}">${escHtml(shortAddr(top.acct))}</button> (${top.count}).`);
  } else {
    nowItems.push(`DEX activity: <b>quiet</b> (few OfferCreate/OfferCancel).`);
  }

  // Watchlist
  const repeats = d.breadcrumbs.filter((p) => p.count >= 2).length;
  if (repeats) watchItems.push(`Repeating interactions: <b>${repeats}</b> pair(s) keep showing up.`);
  if (d.behavior?.bots?.length) {
    const topBot = d.behavior.bots[0];
    watchItems.push(`Bot-like timing: top candidate <button class="addr-link mono" data-addr="${escHtml(topBot.acct)}">${escHtml(shortAddr(topBot.acct))}</button> (CV ${topBot.cv.toFixed(2)}).`);
  }
  if (dex?.signals?.length) watchItems.push(`DEX signals: <b>${escHtml(dex.signals.join(' · '))}</b>`);
  if (d.clusters?.length) watchItems.push(`Largest cluster: <b>${d.clusters[0].size}</b> wallets · hub <button class="addr-link mono" data-addr="${escHtml(d.clusters[0].hub)}">${escHtml(shortAddr(d.clusters[0].hub))}</button>.`);

  if (!watchItems.length) watchItems.push('Nothing urgent stands out in the current window.');

  if (nowEl) nowEl.innerHTML = nowItems.map((x) => `<div class="landscape-row">${x}</div>`).join('');
  if (watchEl) watchEl.innerHTML = watchItems.map((x) => `<div class="landscape-row">${x}</div>`).join('');
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
      Tracks OfferCreate/OfferCancel patterns from the live ledger stream. No order-book polling, no rate limits.
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
      <span class="widget-title">⚠️ Risk & Deep Ledger Analytics</span>
      <span class="widget-tag mono cut" id="risk-badge">—</span>
    </div>
    <p class="widget-help">
      Transparent heuristics: concentration + repeats + DEX cancels/churn + bot-like timing. Signals only.
    </p>

    <div class="risk-top">
      <div class="risk-stat"><span>Regime</span><b id="risk-regime">—</b></div>
      <div class="risk-stat"><span>Risk score</span><b id="risk-friction">—</b></div>
      <div class="risk-stat"><span>Signals</span><b id="risk-signalcount">—</b></div>
    </div>

    <div class="risk-pills" id="risk-pills"></div>

    <div class="risk-grid">
      <div class="risk-box">
        <div class="risk-box-h">🤖 Bot-like timing</div>
        <div id="risk-bots" class="risk-list"></div>
      </div>
      <div class="risk-box">
        <div class="risk-box-h">💧 AMM / LP activity</div>
        <div id="risk-amm" class="risk-list"></div>
      </div>
      <div class="risk-box">
        <div class="risk-box-h">📌 Notes</div>
        <div class="risk-list" id="risk-notes"></div>
      </div>
    </div>
  `;

  main.appendChild(card);
}

function updateRiskWidget(d) {
  if (!document.getElementById('risk-card')) return;

  setText('risk-badge', `Risk ${d.friction}/100`);
  setText('risk-regime', d.regime);
  setText('risk-friction', `${d.friction}/100`);

  const signals = [];

  if (d.hhi >= 0.35) signals.push({ cls: 'warn', t: 'High concentration' });

  const repeats = d.breadcrumbs.filter((p) => p.count >= 2).length;
  if (repeats >= 3) signals.push({ cls: 'new', t: 'Repeating counterparties' });

  if (d.behavior?.bots?.length) signals.push({ cls: 'warn', t: 'Bot-like timing' });

  if (d.dexPatterns?.signals?.length) signals.push({ cls: 'warn', t: 'DEX pattern signals' });

  setText('risk-signalcount', `${signals.length}`);

  const pills = $('risk-pills');
  if (pills) pills.innerHTML = signals.length
    ? signals.map((s) => `<span class="sig-pill ${s.cls}">${escHtml(s.t)}</span>`).join('')
    : `<span class="sig-pill ok">No elevated signals</span>`;

  const botsEl = $('risk-bots');
  if (botsEl) {
    const bots = d.behavior?.bots || [];
    botsEl.innerHTML = bots.length
      ? bots.map((b) => `
        <div class="risk-row">
          <button class="addr-link mono cut" data-addr="${escHtml(b.acct)}">${escHtml(shortAddr(b.acct))}</button>
          <span class="mono">CV ${b.cv.toFixed(2)}</span>
        </div>`).join('')
      : `<div style="opacity:.7">No periodic bots detected yet (needs repeated appearances)</div>`;
  }

  const ammEl = $('risk-amm');
  if (ammEl) {
    const t = d.txTypes || {};
    const ammCreate = Number(t.AMMCreate || 0);
    const ammDep = Number(t.AMMDeposit || 0);
    const ammW = Number(t.AMMWithdraw || 0);
    const ammVote = Number(t.AMMVote || 0);
    const lp = ammCreate + ammDep + ammW + ammVote;

    ammEl.innerHTML = `
      <div class="risk-row"><span>AMMCreate</span><span class="mono">${ammCreate}</span></div>
      <div class="risk-row"><span>Deposit</span><span class="mono">${ammDep}</span></div>
      <div class="risk-row"><span>Withdraw</span><span class="mono">${ammW}</span></div>
      <div class="risk-row"><span>Total LP/AMM</span><span class="mono">${lp}</span></div>
    `;
  }

  const notes = $('risk-notes');
  if (notes) {
    notes.innerHTML = `
      <div style="opacity:.85">These are “signals”, not proof.</div>
      <div style="opacity:.85">DEX monitor uses OfferCreate/OfferCancel only (no orderbook polling).</div>
      <div style="opacity:.85">Click any address to peek, then “Open in Inspector”.</div>
    `;
  }
}

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
