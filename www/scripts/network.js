/* =====================================================
   network.js — Network Health (throttled + backoff)
   Only polls when Network tab is visible.
   ===================================================== */

import { $, escHtml, toastWarn } from './utils.js';
import { state } from './state.js';
import { wsSend } from './xrpl.js';
import { ENDPOINTS_BY_NETWORK } from './config.js';

const POLL_INTERVAL_MS = 60_000;
const REFRESH_MIN_GAP_MS = 10_000;
const LOAD_BACKOFF_MS = 120_000;

const LATENCY_TIMEOUT_MS = 8000;
const LATENCY_COOLDOWN_MS = 120_000;
const LATENCY_GAP_MS = 250;

let pollTimer = null;
let initDone = false;

let refreshing = false;
let lastRefreshAt = 0;
let backoffUntil = 0;

let lastLatencyAt = 0;
let latencyRunId = 0;

export function initNetwork() {
  if (initDone) return;
  initDone = true;

  window.addEventListener('xrpl-connected', () => {
    syncPollingToVisibility();
    if (isNetworkTabVisible()) {
      refreshAll({ force: true });
      measureLatency({ force: false });
    }
  });

  window.addEventListener('xrpl-disconnected', () => stopPolling());

  $('btn-network-refresh')?.addEventListener('click', () => {
    refreshAll({ force: true });
    measureLatency({ force: true });
  });

  const btn = document.querySelector('.dash-tab[data-tab="network"]');
  btn?.addEventListener('click', () => {
    syncPollingToVisibility();
    refreshAll({ force: true });
    measureLatency({ force: false });
  });

  observeNetworkTabVisibility();
}

function isNetworkTabVisible() {
  const tab = $('tab-network');
  if (!tab) return false;
  return tab.style.display !== 'none';
}

function observeNetworkTabVisibility() {
  const tab = $('tab-network');
  if (!tab) return;

  const obs = new MutationObserver(() => syncPollingToVisibility());
  obs.observe(tab, { attributes: true, attributeFilter: ['style', 'class'] });
}

function syncPollingToVisibility() {
  if (isNetworkTabVisible()) startPolling();
  else stopPolling();
}

function startPolling() {
  if (pollTimer) return;
  refreshAll({ force: false });

  pollTimer = window.setInterval(() => {
    if (!isNetworkTabVisible()) return;
    refreshAll({ force: false });
  }, POLL_INTERVAL_MS);
}

function stopPolling() {
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = null;
}

async function refreshAll({ force = false } = {}) {
  if (!isNetworkTabVisible() && !force) return;

  const now = Date.now();
  if (!force && now - lastRefreshAt < REFRESH_MIN_GAP_MS) return;
  if (!force && refreshing) return;
  if (!force && now < backoffUntil) return;

  refreshing = true;
  lastRefreshAt = now;
  setRefreshSpinner(true);

  try {
    await fetchServerInfo();
    await fetchFeeInfo();
  } catch (e) {
    const msg = String(e?.message || e || '');
    console.warn('Network refresh error:', msg);

    if (msg.toLowerCase().includes('too much load')) {
      backoffUntil = Date.now() + LOAD_BACKOFF_MS;
      toastWarn?.('Rate-limited by node. Backing off ~2 minutes.');
    }
  } finally {
    setRefreshSpinner(false);
    refreshing = false;
  }
}

function setRefreshSpinner(on) {
  const btn = $('btn-network-refresh');
  if (btn) btn.classList.toggle('spinning', on);
}

async function fetchServerInfo() {
  const res = await wsSend({ command: 'server_info' });
  const info = res?.result?.info;
  if (!info) return;

  setText('net-version', info.build_version || '—');
  setText('net-host', info.hostid || '—');
  setText('net-peers', info.peers ?? '—');
  setText('net-validated', info.validated_ledger?.seq?.toLocaleString() ?? '—');
}

async function fetchFeeInfo() {
  const res = await wsSend({ command: 'fee' });
  const drops = res?.result?.drops;
  if (!drops) return;

  const open = Number(drops.open_ledger_fee || 10) / 1e6;
  setText('net-ref-fee', `${(open * 1e6).toFixed(0)} drops (${open.toFixed(6)} XRP)`);
}

export async function measureLatency({ force = false } = {}) {
  if (!isNetworkTabVisible() && !force) return;

  const now = Date.now();
  if (!force && now - lastLatencyAt < LATENCY_COOLDOWN_MS) return;
  lastLatencyAt = now;

  const listEl = $('latency-list');
  if (!listEl) return;

  const all = ENDPOINTS_BY_NETWORK[state.currentNetwork] || [];
  const endpoints = all.slice(0, 3); // only first 3 to avoid console spam + failures

  const run = ++latencyRunId;

  listEl.innerHTML = endpoints.map((ep, i) => `
    <div class="latency-row" id="lat-row-${i}">
      <span class="latency-endpoint">${escHtml(ep.url)}</span>
      <div class="latency-bar-wrap"><div class="latency-bar-fill" style="width:0%" id="lat-bar-${i}"></div></div>
      <span class="latency-val pinging" id="lat-val-${i}">—</span>
    </div>`).join('');

  for (let i = 0; i < endpoints.length; i++) {
    if (run !== latencyRunId) return;
    await pingEndpoint(endpoints[i], i);
    await delay(LATENCY_GAP_MS);
  }
}

async function pingEndpoint(ep, idx) {
  const valEl = $(`lat-val-${idx}`);
  const barEl = $(`lat-bar-${idx}`);
  if (valEl) valEl.textContent = '…';

  const t0 = performance.now();

  try {
    const ws = new WebSocket(ep.url);

    await new Promise((res, rej) => {
      const t = setTimeout(() => rej(new Error('timeout')), LATENCY_TIMEOUT_MS);
      ws.onopen = () => { clearTimeout(t); res(true); };
      ws.onerror = () => { clearTimeout(t); rej(new Error('connect-failed')); };
    });

    const ms = Math.round(performance.now() - t0);
    try { ws.close(); } catch {}

    const cls = ms < 100 ? 'fast' : ms < 300 ? 'med' : 'slow';
    const pct = Math.min(100, (ms / 500) * 100);

    if (valEl) { valEl.textContent = `${ms}ms`; valEl.className = `latency-val ${cls}`; }
    if (barEl) barEl.style.width = `${pct}%`;
  } catch {
    if (valEl) { valEl.textContent = 'timeout'; valEl.className = 'latency-val slow'; }
    if (barEl) barEl.style.width = '0%';
  }
}

function setText(id, val) {
  const el = $(id);
  if (el) el.textContent = val;
}

function delay(ms) {
  return new Promise(r => setTimeout(r, ms));
}