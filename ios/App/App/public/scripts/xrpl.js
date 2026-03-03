/* =====================================================
   FILE: scripts/xrpl.js
   xrpl.js — WebSocket Engine · Ledger Processing
   Dispatches: xrpl-ledger · xrpl-connection · xrpl-connected
   ===================================================== */
import {
  ENDPOINTS_BY_NETWORK,
  CHART_WINDOW,
  LEDGER_LOG_MAX,
  WS_TIMEOUT_MS,
  MAX_RECONNECT_DELAY
} from './config.js';

import { $, toastWarn } from './utils.js';
import { state } from './state.js';

/* ─────────────────────────────
   Endpoint helpers
──────────────────────────────── */
function endpointsForNetwork() {
  return ENDPOINTS_BY_NETWORK[state.currentNetwork] || ENDPOINTS_BY_NETWORK['xrpl-mainnet'];
}
function nextEndpoint() {
  const eps = endpointsForNetwork();
  const ep = eps[state.endpointIdx % eps.length];
  state.endpointIdx++;
  return ep;
}

/* ─────────────────────────────
   Connect / disconnect
──────────────────────────────── */
export function connectXRPL() {
  if (state.wsConn && state.wsConn.readyState <= 1) return;

  const ep = nextEndpoint();
  console.log(`🌊 Connecting → ${ep.name} (${ep.url})`);
  setConnState('connecting', ep.name);

  const ws = new WebSocket(ep.url);
  state.wsConn = ws;

  ws.onopen = () => {
    console.log(`✅ Connected: ${ep.name}`);
    state.wsRetry = 0;
    // Reset gating on every fresh connection
    _ledgerReqInFlight       = false;
    _latestWantedIndex       = null;
    _lastProcessedIndex      = 0;
    setConnState('connected', ep.name);
    window.dispatchEvent(new Event('xrpl-connected'));
    subscribeStream();
  };

  ws.onclose = () => {
    console.log(`🔌 Disconnected: ${ep.name}`);
    setConnState('disconnected', '');
    window.dispatchEvent(new Event('xrpl-disconnected'));
    scheduleReconnect();
  };

  ws.onerror = () => ws.close();
  ws.onmessage = (e) => {
    try { handleMessage(JSON.parse(e.data)); } catch {}
  };
}

export function disconnectXRPL() {
  clearTimeout(state.reconnectTimer);
  if (state.wsConn) {
    state.wsConn.onclose = null;
    state.wsConn.close();
    state.wsConn = null;
  }
  setConnState('disconnected', '');
}

export function reconnectXRPL(forced = false) {
  disconnectXRPL();
  if (forced) state.wsRetry = 0;
  if (state.session) setTimeout(connectXRPL, 200);
}

/* ─────────────────────────────
   Internal helpers
──────────────────────────────── */
function scheduleReconnect() {
  if (state.reconnectTimer) return;
  const delay = Math.min(MAX_RECONNECT_DELAY, 1500 * Math.pow(1.6, state.wsRetry++));
  console.log(`⏳ Reconnect in ${(delay / 1000).toFixed(1)}s`);
  state.reconnectTimer = setTimeout(() => {
    state.reconnectTimer = null;
    if (state.session) connectXRPL();
  }, delay);
}

function subscribeStream() {
  wsSend({ id: 'sub_ledger', command: 'subscribe', streams: ['ledger'] }).catch(() => {});
}

export function wsSend(payload) {
  return new Promise((resolve, reject) => {
    if (!state.wsConn || state.wsConn.readyState !== 1) return reject(new Error('Not connected'));

    const id = `req_${++state.reqId}`;
    payload.id = id;

    const timer = setTimeout(() => {
      delete state.pendingReqs[id];
      reject(new Error('Timeout'));
    }, WS_TIMEOUT_MS);

    state.pendingReqs[id] = { resolve, reject, timer };
    state.wsConn.send(JSON.stringify(payload));
  });
}

/* ─────────────────────────────
   Ledger request gating
   One request in-flight at a time; always fetches the newest wanted index.
──────────────────────────────── */
let _ledgerReqInFlight  = false;
let _latestWantedIndex  = null;
let _lastProcessedIndex = 0;

function _onLedgerClosed(ledgerIndex) {
  const li = Number(ledgerIndex);
  if (!Number.isFinite(li)) return;
  _latestWantedIndex = Math.max(_latestWantedIndex || 0, li);
  _maybeRequest();
}

function _maybeRequest() {
  if (!state.wsConn || state.wsConn.readyState !== 1) return;
  if (_ledgerReqInFlight) return;
  if (_latestWantedIndex == null) return;
  if (_latestWantedIndex <= _lastProcessedIndex) return;
  _fetch(_latestWantedIndex);
}

function _fetch(ledgerIndex) {
  _ledgerReqInFlight = true;
  wsSend({ command: 'ledger', ledger_index: ledgerIndex, transactions: true, expand: true })
    .then((msg) => {
      const li = Number(msg.result?.ledger?.ledger_index ?? ledgerIndex);
      if (Number.isFinite(li)) _lastProcessedIndex = Math.max(_lastProcessedIndex, li);
      processLedger(msg.result);
    })
    .catch((err) => console.warn('Ledger req failed:', err.message))
    .finally(() => {
      _ledgerReqInFlight = false;
      _maybeRequest(); // catch up if newer closed while we were fetching
    });
}

/* ─────────────────────────────
   Message handler
──────────────────────────────── */
function handleMessage(msg) {
  // Resolve pending promise
  if (msg.id && state.pendingReqs[msg.id]) {
    const { resolve, reject, timer } = state.pendingReqs[msg.id];
    clearTimeout(timer);
    delete state.pendingReqs[msg.id];
    if (msg.status === 'error') reject(new Error(msg.error_message || msg.error || 'XRPL error'));
    else resolve(msg);
    return;
  }

  if (msg.type === 'ledgerClosed') {
    _onLedgerClosed(msg.ledger_index);
  }
}

/* ─────────────────────────────
   Amount parsing (safe)
──────────────────────────────── */
function parseAmount(a) {
  if (a == null) return { amountXrp: null, amountIssued: null, raw: null };

  // XRP drops string
  if (typeof a === 'string') {
    const drops = Number(a);
    if (!Number.isFinite(drops)) return { amountXrp: null, amountIssued: null, raw: a };
    return { amountXrp: drops / 1e6, amountIssued: null, raw: a };
  }

  // Issued currency object: { currency, issuer, value }
  if (typeof a === 'object' && a.value != null && a.currency) {
    const v = Number(a.value);
    const c = String(a.currency);
    const i = String(a.issuer || '');
    return {
      amountXrp: null,
      amountIssued: Number.isFinite(v) ? `${v} ${c}${i ? `/${i.slice(0, 6)}…` : ''}` : `${a.value} ${c}`,
      raw: a,
    };
  }

  return { amountXrp: null, amountIssued: null, raw: a };
}

/* ─────────────────────────────
   Ledger processing
   Fires: xrpl-ledger custom event
──────────────────────────────── */
function processLedger(result) {
  const ledger = result?.ledger;
  if (!ledger) return;

  const li = Number(ledger.ledger_index ?? 0);
  const txs = Array.isArray(ledger.transactions) ? ledger.transactions : [];
  const closeT = new Date((Number(ledger.close_time ?? 0) + 946684800) * 1000);

  // Close-time delta
  let closeTimeSec = null;
  if (state.lastCloseTs) {
    const delta = closeT - state.lastCloseTs;
    if (delta > 0 && delta < 30000) closeTimeSec = delta / 1000;
  }
  state.lastCloseTs = closeT;

  const tps = closeTimeSec ? txs.length / closeTimeSec : null;

  // Categorise
  const typeCounts = {};
  let totalFees = 0;
  let successCount = 0;

  txs.forEach((tx) => {
    const t = tx.TransactionType || 'Other';
    typeCounts[t] = (typeCounts[t] || 0) + 1;
    totalFees += Number(tx.Fee || 0);

    const res = tx.metaData?.TransactionResult || tx.meta?.TransactionResult;
    if (res === 'tesSUCCESS') successCount++;
  });

  const avgFee = txs.length ? totalFees / txs.length : 0;
  const successRate = txs.length ? (successCount / txs.length) * 100 : 100;

  // Rolling history (store drops for charts, convert to XRP later)
  if (tps !== null) {
    state.tpsHistory.push(tps);
    if (state.tpsHistory.length > CHART_WINDOW) state.tpsHistory.shift();
  }
  state.feeHistory.push(avgFee);
  if (state.feeHistory.length > CHART_WINDOW) state.feeHistory.shift();

  // TX mix accumulator
  Object.entries(typeCounts).forEach(([t, c]) => {
    state.txMixAccum[t] = (state.txMixAccum[t] || 0) + c;
  });

  // Ledger log
  state.ledgerLog.unshift({
    ledgerIndex: li,
    txCount: txs.length,
    tps: tps != null ? tps.toFixed(2) : '—',
    closeTimeSec: closeTimeSec != null ? closeTimeSec.toFixed(2) : '—',
    time: new Date().toLocaleTimeString(),
  });
  if (state.ledgerLog.length > LEDGER_LOG_MAX) state.ledgerLog.pop();

  // Recent txs (enriched)
  const recentTransactions = txs.slice(0, 60).map((tx) => {
    const res = tx.metaData?.TransactionResult || tx.meta?.TransactionResult;

    // Prefer Amount, else DeliverMax/SendMax if present
    const a = tx.Amount ?? tx.DeliverMax ?? tx.SendMax ?? null;
    const amt = parseAmount(a);

    return {
      hash: tx.hash,
      type: tx.TransactionType,
      account: tx.Account,
      destination: tx.Destination,
      fee: Number(tx.Fee || 0),
      ledgerIndex: li,
      result: res,

      // For whale/bot/risk panels:
      amountXrp: amt.amountXrp,
      amountIssued: amt.amountIssued,
      amountRaw: amt.raw,

      // For DEX / quick-cancel proxy:
      sequence: tx.Sequence,
      offerSequence: tx.OfferSequence,
      takerGets: tx.TakerGets,
      takerPays: tx.TakerPays,
    };
  });

  const xrplState = {
    ledgerIndex: li,
    ledgerTime: closeT,
    tps,
    txPerLedger: txs.length,
    avgFee: avgFee / 1e6, // XRP
    successRate,
    txTypes: typeCounts,
    latestLedger: {
      ledgerIndex: li,
      closeTime: closeT,
      closeTimeSec,
      totalTx: txs.length,
      txTypes: typeCounts,
      avgFee: avgFee / 1e6,
      successRate,
    },
    recentTransactions,
  };

  window.dispatchEvent(new CustomEvent('xrpl-ledger', { detail: xrplState }));
}

/* ─────────────────────────────
   Connection state → DOM + event
──────────────────────────────── */
function setConnState(connState, name) {
  state.connectionState = connState;

  const dot = $('connDot');
  const text = $('connText');

  const dot2 = $('connDot2');
  const text2 = $('connText2');

  const inspBtn = $('inspect-btn');
  const inspWarn = $('inspect-warn');

  if (dot) dot.classList.toggle('live', connState === 'connected');
  if (dot2) dot2.classList.toggle('live', connState === 'connected');

  const msg =
    connState === 'connected' ? `LIVE – ${name}` :
    connState === 'connecting' ? 'Connecting…' :
    'Disconnected';

  if (text) {
    text.textContent = msg;
    text.style.color = connState === 'connected' ? '#50fa7b' : connState === 'connecting' ? '#ffb86c' : '#ff5555';
  }
  if (text2) {
    text2.textContent = msg;
    text2.style.color = connState === 'connected' ? '#50fa7b' : connState === 'connecting' ? '#ffb86c' : '#ff5555';
  }

  if (inspBtn) inspBtn.disabled = connState !== 'connected';
  if (inspWarn) inspWarn.style.display = connState !== 'connected' ? '' : 'none';

  window.dispatchEvent(new CustomEvent('xrpl-connection', {
    detail: { connected: connState === 'connected', server: name, state: connState }
  }));
}

/* ─────────────────────────────
   Network switch
──────────────────────────────── */
export function switchNetwork(net) {
  if (net === state.currentNetwork) return;

  state.currentNetwork = net;
  state.endpointIdx = 0;
  state.wsRetry = 0;

  state.ledgerLog = [];
  state.tpsHistory = [];
  state.feeHistory = [];
  state.txMixAccum = {};
  state.lastCloseTs = null;

  _ledgerReqInFlight  = false;
  _latestWantedIndex  = null;
  _lastProcessedIndex = 0;

  reconnectXRPL(true);
  window.dispatchEvent(new CustomEvent('xrpl-connection', { detail: { connected: false, server: '', state: 'connecting' } }));
}