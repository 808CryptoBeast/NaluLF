/* =====================================================
   inspector.js — Deep Account Inspector
   Analyses: security posture, drain risk, NFT exploits,
   wash trading, token issuer manipulation, AMM positions.
   ===================================================== */
import { $, $$, escHtml, isValidXrpAddress, shortAddr, fmt, safeGet, safeSet, safeRemove, safeJson } from './utils.js';
import { state } from './state.js';
import { wsSend } from './xrpl.js';

/* ─────────────────────────────
   Constants
──────────────────────────────── */

// XRPL account flags
const FLAGS = {
  lsfPasswordSpent:  0x00010000,
  lsfRequireDestTag: 0x00020000,
  lsfRequireAuth:    0x00040000,
  lsfDisallowXRP:    0x00080000,
  lsfDisableMaster:  0x00100000,
  lsfNoFreeze:       0x00200000,
  lsfGlobalFreeze:   0x00400000,
  lsfDefaultRipple:  0x00800000,
  lsfDepositAuth:    0x01000000,
};

// NFT flag bits
const NFT_FLAGS = {
  lsfBurnable:    0x0001,
  lsfOnlyXRP:     0x0002,
  lsfTrustLine:   0x0004,
  lsfTransferable:0x0008,
};

// TX types that are high-risk if in history
const DRAIN_TX_TYPES = new Set([
  'SetRegularKey', 'SignerListSet', 'AccountSet', 'AccountDelete',
  'EscrowCreate', 'PaymentChannelCreate', 'DepositPreauth',
]);

// Wash trading: suspicious cancel ratio threshold
const WASH_CANCEL_RATIO  = 0.55;  // >55% cancels of creates = suspicious
const WASH_SELF_RATIO     = 0.15;  // >15% payments round-trip
const WASH_MIN_TX         = 20;    // minimum tx count to score
const XRPL_EPOCH          = 946684800; // seconds between 1970-01-01 and 2000-01-01

/* ─────────────────────────────
   Known Exchange / Entity Registry
──────────────────────────────── */
const KNOWN_ENTITIES = new Map([
  // ── Major Exchanges ─────────────────────────────────────────────────────
  ['rPVMhWBsfF9iMXYj3aAzJVkPDTFNSyWdKy', { name: 'Bitstamp',  type: 'exchange' }],
  ['rvYAfWj5gh67oV6fW32ZzP3Aw4Eubs59B',  { name: 'Bitstamp',  type: 'exchange' }],
  ['rrpNnNLKrartuEqfJGpqyDwPj1BBN1ih7',  { name: 'Bitstamp',  type: 'exchange' }],
  ['rN7n3473SaZBCG4dFL83w7PB9judJ7qdDo', { name: 'Binance',   type: 'exchange' }],
  ['rEb8TK3gBgk5auZkwc6sHnwrGVJH8DuaLh', { name: 'Binance',  type: 'exchange' }],
  ['rBKPS4oLSaV2KVVuHH8EpQqMGgGefGFQs7', { name: 'Bitso',    type: 'exchange' }],
  ['rfk5bwaKCoNU84fTzdqWQowqnNaZorDmiV',  { name: 'Gate.io',  type: 'exchange' }],
  ['rGFuMiw48HdbnrUbkRYDTvT5i9imC5fvv9', { name: 'Gate.io',  type: 'exchange' }],
  ['rwYHCs2EYBMBvRXFmxDrCUSorPsuqCck7t', { name: 'Kraken',   type: 'exchange' }],
  ['rLHzPsX6oXkzU2qL12kHCH8G8cnZv1rBJh', { name: 'Kraken',  type: 'exchange' }],
  ['ra5nK24KXen9AHvsdFTKHSANinZseWnPcX', { name: 'Uphold',   type: 'exchange' }],
  ['rGWrZyax5eXbi5gs49MRZKkE9eKNL9p4B',  { name: 'Bittrex',  type: 'exchange' }],
  ['rDsbeomae4FXwgQTJp9Rs64Qg9vDiTCdBv', { name: 'Coinone',  type: 'exchange' }],
  ['rHsMUQFzBb7S6GnQFVgNirqvHRcLpAn5dU', { name: 'Bithumb',  type: 'exchange' }],
  ['rMQ98K56yXJbDGv49ZSmW51sLn94Xe1mu1', { name: 'Huobi',    type: 'exchange' }],
  ['rHcFoo6a9qT5NHiVn1THwX3B4QF2VQKWZ',  { name: 'Huobi',    type: 'exchange' }],
  ['rKiCet8SdvWxPXnAgYarFUXMh1zCPz432Y', { name: 'Coinbase', type: 'exchange' }],
  ['rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh', { name: 'Coinbase', type: 'exchange' }],
  ['r9mhdcT2K7FdCGDEPqfbMJwVXsXCqEr5bP', { name: 'OKX',      type: 'exchange' }],
  ['r32U8WFxhqEAVkKcTb1GGRR1VH2oaFdexN', { name: 'OKX',      type: 'exchange' }],
  ['r4GDFMLGJUKMjNEycBKPGnRSNXyNVLQLHi', { name: 'Bybit',    type: 'exchange' }],
  ['rBETszU65yYoFcYdRkiGqFaYmhZpHWC7sj', { name: 'Bybit',    type: 'exchange' }],
  ['rMWUykAmNQDaM9poSes8VLDZDDkEoutilities', { name: 'KuCoin', type: 'exchange' }],
  ['rUA1S9qobBkxLqzdfGEzh5wm5KdLfbf8bx', { name: 'KuCoin',   type: 'exchange' }],
  ['rHtbQzmN4BDaEBnGSXp3AZaZAuZamNVsME', { name: 'MEXC',     type: 'exchange' }],
  ['rDN1gPWW3XQFXVJFQSiJxPHGZiRLMVSi7K', { name: 'MEXC',     type: 'exchange' }],
  ['rB3gZey7VWHoDokMt3tCiXBSRmaZi5xJi9', { name: 'Crypto.com', type: 'exchange' }],
  ['rhub8VRN55s94qWKDv6jmDy1pUykJzF3wq', { name: 'GateHub',  type: 'exchange' }],
  ['razqnFn6FqBaYBdNaGnVzmGaNE6XPRQ9bG', { name: 'GateHub',  type: 'exchange' }],
  ['rGQdkxNBQeQC1WTQDQ2F2QoGBZxYcMxBBg', { name: 'GateHub',  type: 'exchange' }],
  ['rpXTzCuXtjiPDFysxq8uNmtZBe9Xo97JbW', { name: 'Bitbank',  type: 'exchange' }],
  ['rsuUjfWxrACCAwGQDsNeZUhpzXf1n1NK5Z', { name: 'Bitbank',  type: 'exchange' }],
  ['r9oxUGJqMfMEhGBxrMJnmNvVh1LKkMv7fz', { name: 'Coincheck', type: 'exchange' }],

  // ── Ripple / XRPL Labs Operational ──────────────────────────────────────
  ['rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh', { name: 'Genesis (Black Hole)', type: 'blackhole' }],
  ['r9cZA1mLK5R5Am25ArfXFmqgNwjZgnfk59', { name: 'Black Hole #2',        type: 'blackhole' }],
  ['rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh', { name: 'Genesis Wallet',       type: 'ripple' }],
  ['rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh', { name: 'Ripple Labs Ops',      type: 'ripple' }],

  // ── Known Wallet Apps & Infrastructure ──────────────────────────────────
  ['rPEPPER7kfTD9w2To4CQk6UCfuHM9c6GDY', { name: 'XAMAN (XUMM)', type: 'wallet' }],
  ['rBj4eVRWn6mCELVTNkVFDfGNByE9VFTM3R', { name: 'XAMAN',        type: 'wallet' }],

  // ── AMM / DEX Infrastructure ─────────────────────────────────────────────
  ['rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh', { name: 'XRPL AMM Engine', type: 'dex' }],

  // ── Notable Token Issuers ────────────────────────────────────────────────
  ['rsoLo2S1kiGeCcn6hCUXVrCpGMWLrRrLZz', { name: 'SOLO Issuer',     type: 'issuer' }],
  ['rcoreNywaoz2ZCVt2sc3JiEi7G7MpZxZgm', { name: 'CORE Token',      type: 'issuer' }],
  ['rhXo4TcWbLY4GqTSmscMpgZ1KMXFBi9V55', { name: 'XRPL DeFi Pool',  type: 'issuer' }],

  // ── Known Validator / Validator Operator Wallets ────────────────────────
  ['rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh', { name: 'UNL Validator Set', type: 'validator' }],
]);

/** Look up an entity by address. */
function getEntity(addr) {
  return KNOWN_ENTITIES.get(addr) || null;
}



/* ─────────────────────────────
   State
──────────────────────────────── */
let _currentAddr    = null;
let _inspectAbort   = false;
let _pulseInterval  = null;  // kept for destroyInspector cleanup compatibility
let _xrpPriceUSD    = null;  // cached XRP/USD price — fetched once per session
let _xrpPriceFetched = false;

/* ─────────────────────────────
   XRP Price (CoinGecko, cached)
──────────────────────────────── */
async function _fetchXrpPrice() {
  if (_xrpPriceFetched) return _xrpPriceUSD;
  _xrpPriceFetched = true;
  try {
    const r = await fetch('https://api.coingecko.com/api/v3/simple/price?ids=ripple&vs_currencies=usd', {
      signal: AbortSignal.timeout(4000),
    });
    if (!r.ok) return null;
    const d = await r.json();
    _xrpPriceUSD = d?.ripple?.usd ?? null;
  } catch { _xrpPriceUSD = null; }
  return _xrpPriceUSD;
}

function _usd(xrp) {
  if (!_xrpPriceUSD || !xrp) return '';
  const val = xrp * _xrpPriceUSD;
  if (val >= 1_000_000) return ` (~$${(val/1_000_000).toFixed(2)}M)`;
  if (val >= 1_000)     return ` (~$${(val/1_000).toFixed(1)}K)`;
  return ` (~$${val.toFixed(2)})`;
}
/* ─────────────────────────────
   Lazy DOM cache (populated once after mount)
──────────────────────────────── */
let _dom = null;
function _getDOM() {
  if (_dom) return _dom;
  _dom = {
    input:   () => document.getElementById('inspect-addr'),
    err:     document.getElementById('inspect-err'),
    result:  document.getElementById('inspect-result'),
    empty:   document.getElementById('inspect-empty'),
    loading: document.getElementById('inspect-loading'),
    loadMsg: document.getElementById('inspect-loading-msg'),
    warn:    document.getElementById('inspect-warn'),
    badge:   document.getElementById('inspect-addr-badge'),
    score:   document.getElementById('inspect-risk-score'),
    label:   document.getElementById('inspect-risk-label'),
  };
  return _dom;
}
// Called after HTML mounts to warm the cache
function _warmDOMCache() { _dom = null; _getDOM(); }



/* ─────────────────────────────
   Init
──────────────────────────────── */
export function initInspector() {
  _mountInspectorHTML();
  _mountInspectorNav();
  _mountHowToOverlay();

  $('inspect-addr')?.addEventListener('keydown', e => {
    if (e.key === 'Enter') runInspect();
  });

  // Paste full address → auto-run
  $('inspect-addr')?.addEventListener('paste', () => {
    setTimeout(() => {
      const v = $('inspect-addr')?.value.trim();
      if (v && isValidXrpAddress(v)) runInspect();
    }, 60);
  });

  // Section collapse (delegated to the panel)
  document.getElementById('tab-inspector')?.addEventListener('click', e => {
    const hdr = e.target.closest('.section-header');
    if (!hdr) return;
    hdr.closest('.inspector-section')?.classList.toggle('collapsed');
  });

  // Bottom nav section jumps
  document.getElementById('inspector-nav')?.addEventListener('click', e => {
    const btn = e.target.closest('[data-jump]');
    if (!btn) return;
    const sec = document.getElementById('section-' + btn.dataset.jump);
    if (sec) { sec.classList.remove('collapsed'); sec.scrollIntoView({ behavior: 'smooth', block: 'start' }); }
    _navSetActive(btn.dataset.jump);
  });

  // Scroll → highlight active section in nav
  // Scoped scroll listener - only processes when inspector is active
  // Debounced scroll listener - 80ms throttle
  let _scrollTick = false;
  window.addEventListener('scroll', () => {
    if (!_scrollTick) {
      _scrollTick = true;
      requestAnimationFrame(() => { _navOnScroll(); _scrollTick = false; });
    }
  }, { passive: true });

  window.runInspect         = runInspect;
  window.inspectorCopyAddr  = _copyAddr;
  window.showInspectorHowTo = _showHowTo;
  window.hideInspectorHowTo = _hideHowTo;

  // Warm DOM cache after HTML is in place
  _warmDOMCache();

  // Populate initial state dashboard
  initInspectorDashboard();

  // Re-populate wallets & recent each time the inspector tab is switched to
  window.addEventListener('naluxrp:tabchange', e => {
    if (e.detail?.tabId === 'inspector') {
      _loadWallets();
      _loadRecentHistory();
    }
  });
}

/* ─────────────────────────────
   Public: pre-fill + run from profile
──────────────────────────────── */
function inspectAddress(addr) {
  const inp = $('inspect-addr');
  if (inp) inp.value = addr;
  runInspect();
}

/* ─────────────────────────────
   Main entry
──────────────────────────────── */
export async function runInspect() {
  const d     = _getDOM();
  const addr  = d.input()?.value.trim() || '';

  // Reset UI (single batch)
  [d.err, d.result, d.empty, d.warn].forEach(el => el && (el.style.display = 'none'));
  _inspectAbort = true;  // cancel any in-progress inspect

  if (!addr) { if (d.empty) d.empty.style.display = ''; return; }

  if (!isValidXrpAddress(addr)) {
    if (d.err) { d.err.textContent = `⚠ Invalid address: ${escHtml(addr)}`; d.err.style.display = ''; }
    return;
  }

  if (state.connectionState !== 'connected') {
    if (d.warn) d.warn.style.display = '';
    return;
  }

  _currentAddr  = addr;
  _inspectAbort = false;
  const _setMsg = m => {
    if (!d.loading) return;
    d.loading.style.display = '';
    if (d.loadMsg) d.loadMsg.textContent = m;
  };
  _setMsg('Fetching account data…');

  try {
    // ── Phase 1: Parallel core fetches ─────────────────────────────────────
    const [infoRes, linesRes, offersRes, nftRes, objRes] = await Promise.all([
      wsSend({ command: 'account_info',    account: addr, ledger_index: 'validated' }),
      wsSend({ command: 'account_lines',   account: addr, ledger_index: 'validated' }),
      wsSend({ command: 'account_offers',  account: addr, ledger_index: 'validated' }),
      wsSend({ command: 'account_nfts',    account: addr, ledger_index: 'validated' }).catch(() => null),
      wsSend({ command: 'account_objects', account: addr, ledger_index: 'validated', limit: 400 }).catch(() => null),
    ]);

    if (_inspectAbort) return;

    const acct    = infoRes?.result?.account_data || {};
    const lines   = linesRes?.result?.lines       || [];
    const offers  = offersRes?.result?.offers      || [];
    const nfts    = nftRes?.result?.account_nfts   || [];
    const objects = objRes?.result?.account_objects || [];

    // ── Phase 1b: Supplemental API calls (gateway_balances + AMM info + price) ──
    _setMsg('Fetching token supply, AMM data & price…');
    const lpLines = lines.filter(l => l.currency && (l.currency.startsWith('03') || l.currency.length === 40));

    // Fetch top active trading pair for live order book check (wash trading)
    // We'll use it for book_offers after we know the wallet's most-traded pair from txList
    const [gatewayRes, xrpPrice, ...ammInfoResults] = await Promise.all([
      wsSend({ command: 'gateway_balances', account: addr, ledger_index: 'validated' }).catch(() => null),
      _fetchXrpPrice(),  // XRP/USD price — cached after first call
      ...lpLines.slice(0, 5).map(l =>
        wsSend({ command: 'amm_info', asset: { currency: 'XRP' }, asset2: { currency: l.currency, issuer: l.account }, ledger_index: 'validated' })
          .catch(() => null)
      ),
    ]);

    const gatewayBalances = gatewayRes?.result || null;
    const ammInfoMap = new Map();
    lpLines.slice(0, 5).forEach((l, i) => {
      if (ammInfoResults[i]?.result?.amm) {
        ammInfoMap.set(l.currency, ammInfoResults[i].result.amm);
      }
    });

    // Wallet creation date: find the earliest ledger this account appears in
    // account_info gives us Sequence; the first tx in Pass B will give us the real date
    // We'll compute walletAgeDays after txList is assembled

    if (_inspectAbort) return;
    _setMsg('Fetching transaction history (pass 1 of 3)…');

    // ── Phase 2: Three-pass transaction history ──────────────────────────────
    // Pass A (newest 400, forward:false)  — recent activity: wash, security, drain, NFT, Benford
    // Pass B (oldest 500, forward:true)   — genesis period: anchors time-series span
    // Pass C (mid 400 via marker)         — fills gap if wallet has >400 txs total
    const [txResRecent, txResOldest] = await Promise.all([
      wsSend({ command: 'account_tx', account: addr,
               limit: 400, ledger_index_min: -1, ledger_index_max: -1, forward: false }).catch(() => null),
      wsSend({ command: 'account_tx', account: addr,
               limit: 500, ledger_index_min: -1, ledger_index_max: -1, forward: true  }).catch(() => null),
    ]);

    if (_inspectAbort) return;

    // Pass C: if recent fetch has a marker (more pages exist), fetch a mid-range page
    let txResMid = null;
    const recentMarker = txResRecent?.result?.marker;
    if (recentMarker) {
      _setMsg('Fetching transaction history (pass 3 of 3 — middle range)…');
      txResMid = await wsSend({
        command: 'account_tx', account: addr,
        limit: 400, ledger_index_min: -1, ledger_index_max: -1, forward: false,
        marker: recentMarker,
      }).catch(() => null);
      if (_inspectAbort) return;
    }

    if (d.loading) d.loading.style.display = 'none';

    // Merge all three passes: dedup by hash, sort oldest-first
    const allRaw = [
      ...(txResRecent?.result?.transactions || []),
      ...(txResOldest?.result?.transactions || []),
      ...(txResMid?.result?.transactions    || []),
    ];
    const seenHashes = new Set();
    const mergedRaw  = [];
    for (const item of allRaw) {
      const hash = item.tx_json?.hash || item.tx?.hash || item.hash || null;
      if (hash && seenHashes.has(hash)) continue;
      if (hash) seenHashes.add(hash);
      mergedRaw.push(item);
    }
    const txList = normaliseTxList(mergedRaw)
      .sort((a, b) => (a.tx.date ?? 0) - (b.tx.date ?? 0));

    // ── Wallet age: find creation date from oldest tx ───────────────────────
    const RIPPLE_EPOCH = 946684800;
    let walletAgeDays = null;
    let walletCreatedTs = null;
    if (txList.length > 0) {
      const oldest = txList[0].tx;
      if (oldest?.date) {
        walletCreatedTs = (oldest.date + RIPPLE_EPOCH) * 1000;
        walletAgeDays = Math.floor((Date.now() - walletCreatedTs) / 86400000);
      }
    }

    // ── Live order book check (Feature: detect active spoofing) ──────────
    // Find the wallet's most-traded token pair from offers in txList
    const pairCounts = new Map();
    for (const {tx} of txList) {
      if (tx.TransactionType !== 'OfferCreate' || !tx.TakerPays || !tx.TakerGets) continue;
      const getCurr = o => typeof o === 'string' ? 'XRP' : `${o.currency}+${o.issuer||''}`;
      const pair = [getCurr(tx.TakerPays), getCurr(tx.TakerGets)].sort().join('↔');
      pairCounts.set(pair, (pairCounts.get(pair) || 0) + 1);
    }
    let liveOrderBook = null;
    if (pairCounts.size > 0) {
      // Get the dominant pair and fetch current live book
      const topPairKey = [...pairCounts.entries()].sort((a,b) => b[1]-a[1])[0][0];
      const [payStr, getStr] = topPairKey.split('↔');
      const parseCurr = s => s === 'XRP' ? { currency: 'XRP' }
        : { currency: s.split('+')[0], issuer: s.split('+')[1] };
      const bookRes = await wsSend({
        command: 'book_offers',
        taker_pays: parseCurr(payStr),
        taker_gets: parseCurr(getStr),
        limit: 20,
        ledger_index: 'validated',
      }).catch(() => null);
      if (bookRes?.result?.offers?.length) {
        liveOrderBook = { pair: topPairKey, offers: bookRes.result.offers };
      }
    }

    // ── Phase 2b: Counterparty age check (top 5 outbound destinations) ──────
    // Checks how new/old the top receiving wallets are.
    // A wallet created 2 ledgers ago receiving 10,000 XRP is a strong mule indicator.
    const outboundDests = [...new Set(
      txList
        .filter(({tx}) => tx.TransactionType === 'Payment' && tx.Account === addr && tx.Destination)
        .map(({tx}) => tx.Destination)
    )].slice(0, 6);

    const destAgeMap = new Map();
    if (outboundDests.length) {
      const destInfoResults = await Promise.all(
        outboundDests.map(d =>
          wsSend({ command: 'account_info', account: d, ledger_index: 'validated' }).catch(() => null)
        )
      );
      outboundDests.forEach((d, i) => {
        const data = destInfoResults[i]?.result?.account_data;
        if (data) destAgeMap.set(d, { sequence: data.Sequence || 0, balance: Number(data.Balance || 0) / 1e6 });
      });
    }

    // ── Phase 3: Render ─────────────────────────────────────────────────────
    renderAll(addr, acct, lines, offers, nfts, objects, txList, {
      gatewayBalances, ammInfoMap, destAgeMap,
      walletAgeDays, walletCreatedTs, liveOrderBook,
    });

    if (d.result) d.result.style.display = '';

    // Save to history + show risk score diff vs previous inspection
    const riskVal = d.score ? Number(d.score.textContent) : null;
    _renderRiskScoreDiff(addr, isNaN(riskVal) ? null : riskVal);
    addInspectHistory(addr, isNaN(riskVal) ? null : riskVal);

  } catch (err) {
    if (_inspectAbort) return;
    if (d.loading) d.loading.style.display = 'none';
    if (d.err)     { d.err.textContent = `Error: ${escHtml(err.message)}`; d.err.style.display = ''; }
  }
}

/* ─────────────────────────────
   Normalise tx list
   Handles both old {tx, meta} and new {transaction, metadata} shapes
──────────────────────────────── */
function normaliseTxList(raw) {
  // Support both classic format ({ tx, meta }) and newer rippled v2 format
  // ({ tx_json, metadata, date, hash } — date/hash live at item level in v2).
  return raw.map(item => {
    const tx   = item.tx_json || item.tx || item.transaction || {};
    const meta = item.metadata || item.meta || {};
    // In v2, date (Ripple epoch seconds) is at item level — inject it.
    if (tx.date == null && item.date != null) tx.date = item.date;
    // hash is also at item level in v2 — inject it.
    if (!tx.hash && item.hash) tx.hash = item.hash;
    return { tx, meta };
  });
}

/* ─────────────────────────────
   Master render
──────────────────────────────── */
function renderAll(addr, acct, lines, offers, nfts, objects, txList, extraData = {}) {
  const {
    gatewayBalances = null, ammInfoMap = new Map(), destAgeMap = new Map(),
    walletAgeDays = null, walletCreatedTs = null, liveOrderBook = null,
  } = extraData;
  const balXrp   = Number(acct.Balance || 0) / 1e6;
  const ownerCnt = Number(acct.OwnerCount || 0);
  const reserve  = 10 + ownerCnt * 2;
  const flags    = Number(acct.Flags || 0);
  const sequence = acct.Sequence ?? '—';

  // Extract sub-objects
  const signerLists    = objects.filter(o => o.LedgerEntryType === 'SignerList');
  const escrows        = objects.filter(o => o.LedgerEntryType === 'Escrow');
  const paychans       = objects.filter(o => o.LedgerEntryType === 'PayChannel');
  const depositAuths   = objects.filter(o => o.LedgerEntryType === 'DepositPreauth');
  const checks         = objects.filter(o => o.LedgerEntryType === 'Check');

  // ── Analysis passes ─────────────────────────────────────────────────────
  const securityAudit      = analyseSecurityPosture(acct, flags, signerLists, txList);
  const drainAnalysis      = analyseDrainRisk(acct, flags, signerLists, txList, paychans, escrows);
  const nftAnalysis        = analyseNftRisk(nfts, txList, addr);
  const washAnalysis       = analyseWashTrading(txList, addr, lines);
  const issuerAnalysis     = analyseTokenIssuer(acct, lines, flags, txList);
  const ammAnalysis        = analyseAmmPositions(lines, txList, objects, ammInfoMap);
  const benfordsAnalysis   = analyseBenfordsLaw(txList);
  const volConcAnalysis    = analyseVolumeConcentration(txList, addr);

  // ── Forensic Analytics Suite (4 new engines) ────────────────────────────
  const entropyAnalysis    = analyseShannonsEntropy(txList, addr);
  const zipfAnalysis       = analyseZipfsLaw(txList, addr);
  const timeSeriesAnalysis = analyseTimeSeries(txList);
  const grangerAnalysis    = analyseGrangerCausality(txList, addr);

  // ── New deep analysis ────────────────────────────────────────────────────
  const fundFlowAnalysis      = analyseFundFlow(txList, addr, destAgeMap);
  const feeAnalysis           = analyseFeeSpikePattern(txList);
  const destTagAnalysis       = analyseDestTagPatterns(txList, addr);
  const pathDepthAnalysis     = analysePathPaymentDepth(txList, addr);
  const issuerConnAnalysis    = analyseIssuerConnections(txList, addr, lines, gatewayBalances);
  const inboundFlowAnalysis   = analyseInboundFlow(txList, addr);
  const memoAnalysis          = analyseMemos(txList, addr);
  const escrowDepthAnalysis   = analyseEscrowDepth(objects, txList, addr);
  const checkAnalysis         = analyseChecks(objects);
  const liveBookAnalysis      = analyseLiveOrderBook(liveOrderBook, addr);

  // Overall risk score (0–100)
  const riskScore = computeOverallRisk(securityAudit, drainAnalysis, nftAnalysis, washAnalysis, benfordsAnalysis, volConcAnalysis, entropyAnalysis, zipfAnalysis, timeSeriesAnalysis, grangerAnalysis, feeAnalysis);

  // ── Render sections ──────────────────────────────────────────────────────
  renderHeader(addr, acct, balXrp, reserve, ownerCnt, sequence, riskScore, walletAgeDays, walletCreatedTs);
  renderSecurityAudit(securityAudit, acct, flags, signerLists, depositAuths);
  renderDrainAnalysis(drainAnalysis, paychans, escrows, checks);
  renderFundFlowPanel(fundFlowAnalysis);
  renderNftPanel(nftAnalysis, nfts);
  renderWashPanel(washAnalysis);
  renderBenfordsPanel(benfordsAnalysis);
  renderVolConcPanel(volConcAnalysis);
  renderEntropyPanel(entropyAnalysis);
  renderZipfPanel(zipfAnalysis);
  renderTimeSeriesPanel(timeSeriesAnalysis);
  renderGrangerPanel(grangerAnalysis);
  renderForensicSuitePanel(benfordsAnalysis, entropyAnalysis, zipfAnalysis, timeSeriesAnalysis, grangerAnalysis);
  renderIssuerPanel(issuerAnalysis, lines);
  renderIssuerConnectionsPanel(issuerConnAnalysis, lines);
  renderFeeAnalysisPanel(feeAnalysis);
  renderDestTagPanel(destTagAnalysis);
  renderPathDepthPanel(pathDepthAnalysis);
  renderAmmPanel(ammAnalysis, lines);
  renderInboundFlowPanel(inboundFlowAnalysis);
  renderMemoPanel(memoAnalysis);
  renderEscrowDepthPanel(escrowDepthAnalysis);
  renderCheckPanel(checkAnalysis);
  renderLiveBookPanel(liveBookAnalysis);
  renderRiskBreakdown(riskScore, securityAudit, drainAnalysis, nftAnalysis, washAnalysis,
    benfordsAnalysis, volConcAnalysis, entropyAnalysis, zipfAnalysis, timeSeriesAnalysis,
    grangerAnalysis, feeAnalysis, inboundFlowAnalysis, memoAnalysis);
  renderTrustlines(lines);
  renderTxTimeline(txList, addr);

  // ── Full Report section (always rendered last) ───────────────────────────
  // Cache txList so the CSV export button in the report can access it
  window._lastTxList = txList;

  const reportContainer = $('inspect-report-body');
  if (reportContainer) {
    renderFullReport(
      reportContainer,
      addr, acct, balXrp, riskScore,
      securityAudit, drainAnalysis, nftAnalysis, washAnalysis,
      benfordsAnalysis, volConcAnalysis, issuerAnalysis,
      ammAnalysis, fundFlowAnalysis, issuerConnAnalysis, txList,
      entropyAnalysis, zipfAnalysis, timeSeriesAnalysis, grangerAnalysis,
      { feeAnalysis, destTagAnalysis, pathDepthAnalysis, gatewayBalances,
        inboundFlowAnalysis, memoAnalysis, escrowDepthAnalysis, checkAnalysis,
        liveBookAnalysis, walletAgeDays, walletCreatedTs }
    );
  }
}


/* ── Fund Flow Tracer ────────────────────────────── */
function analyseFundFlow(txList, addr, destAgeMap = new Map()) {
  const destinations = new Map();
  const drainSeq     = [];

  for (const { tx, meta } of txList) {
    if (tx.TransactionType !== 'Payment') continue;
    if (tx.Account !== addr) continue; // outbound only

    const dest = tx.Destination;
    if (!dest) continue;

    let amtXrp   = 0;
    let amtToken = null;
    const raw = tx.Amount;
    if (typeof raw === 'string') {
      amtXrp = Number(raw) / 1e6;
    } else if (raw?.value) {
      amtToken = { value: Number(raw.value), currency: hexToAscii(raw.currency), issuer: raw.issuer };
    }

    // Path payment detection
    const hasPaths  = Array.isArray(tx.Paths) && tx.Paths.length > 0;
    const hasSendMax = tx.SendMax != null;
    const isPathPay  = hasPaths || hasSendMax;

    // Hop count from Paths
    const hopCount = hasPaths
      ? tx.Paths.reduce((mx, p) => Math.max(mx, (p || []).length + 1), 1)
      : (isPathPay ? 2 : 1);

    const ts  = getCloseTime(tx);
    const rec = { dest, amtXrp, amtToken, ts, isPathPay, hopCount, hash: tx.hash || tx.Hash || '', ledger: tx.ledger_index || tx.LedgerIndex || 0, destTag: tx.DestinationTag };

    drainSeq.push(rec);

    if (!destinations.has(dest)) {
      destinations.set(dest, {
        addr: dest,
        totalXrp:  0,
        txCount:   0,
        firstSeen: ts,
        lastSeen:  ts,
        entity:    getEntity(dest) || null,
        pathCount: 0,
        maxHops:   1,
        tokens:    new Map(),
      });
    }
    const d = destinations.get(dest);
    d.totalXrp  += amtXrp;
    d.txCount++;
    d.lastSeen   = Math.max(d.lastSeen, ts);
    d.firstSeen  = Math.min(d.firstSeen, ts);
    if (isPathPay) { d.pathCount++; d.maxHops = Math.max(d.maxHops, hopCount); }
    if (amtToken) {
      const k = `${amtToken.currency}.${shortAddr(amtToken.issuer || '')}`;
      d.tokens.set(k, (d.tokens.get(k) || 0) + amtToken.value);
    }
  }

  const topDests = [...destinations.values()]
    .sort((a, b) => b.totalXrp - a.totalXrp || b.txCount - a.txCount)
    .slice(0, 10)
    .map(d => ({ ...d, tokens: [...d.tokens.entries()].map(([k, v]) => ({ k, v })) }));

  const totalOut    = topDests.reduce((s, d) => s + d.totalXrp, 0);
  const totalPathPay = drainSeq.filter(o => o.isPathPay).length;

  // Counterparty age flags: new wallets receiving large amounts are drain mules
  const newWalletDests = topDests.filter(d => {
    const age = destAgeMap.get(d.addr);
    return age && age.sequence < 10 && d.totalXrp > 10;
  });

  // Known-exchange destinations
  const exchangeDests = topDests.filter(d => d.entity?.type === 'exchange');
  const blackHoleDests= topDests.filter(d => d.entity?.type === 'blackhole');

  // Timeline — sort chronologically, cap at 30
  const timeline = [...drainSeq]
    .filter(o => o.amtXrp > 0.01 || o.amtToken)
    .sort((a, b) => a.ts - b.ts)
    .slice(0, 30);

  return {
    timeline,
    destinations: topDests,
    totalOut,
    totalPathPay,
    uniqueDests: destinations.size,
    exchangeDests,
    blackHoleDests,
    newWalletDests,
  };
}

/* ── Issuer Connection Analysis ──────────────────── */
function analyseIssuerConnections(txList, addr, lines, gatewayBalances = null) {
  // Extract true total supply from gateway_balances if available.
  // gateway_balances.obligations is { currency: totalAmount, ... }
  let _gatewayTotal = null;
  if (gatewayBalances?.obligations) {
    const vals = Object.values(gatewayBalances.obligations);
    if (vals.length === 1) {
      _gatewayTotal = Number(vals[0]) || null;
    } else if (vals.length > 1) {
      // Multiple currencies — can't sum across currencies, leave as null
      _gatewayTotal = null;
    }
  }
  const signals      = [];
  const distributions = new Map(); // destAddr → total tokens received from issuer
  const receiveTime  = new Map();
  const createdAccts = new Set();

  // Walk tx history: look for outbound token payments (negative-balance lines = we issued)
  const issuedCurrencies = new Set(
    lines.filter(l => Number(l.balance) < 0).map(l => hexToAscii(l.currency))
  );

  for (const { tx, meta } of txList) {
    if (tx.Account !== addr) continue;

    // Account creation detection: payment to new account creates it
    if (tx.TransactionType === 'Payment') {
      const created = meta?.AffectedNodes?.some?.(n =>
        n.CreatedNode?.LedgerEntryType === 'AccountRoot' &&
        n.CreatedNode?.NewFields?.Account === tx.Destination
      );
      if (created && tx.Destination) createdAccts.add(tx.Destination);

      // Token distribution tracking
      const amt = tx.Amount;
      if (typeof amt === 'object' && amt?.value && amt?.currency) {
        const curr = hexToAscii(amt.currency);
        if (issuedCurrencies.has(curr)) {
          const val = Number(amt.value);
          const dest = tx.Destination;
          if (!distributions.has(dest)) {
            distributions.set(dest, 0);
            receiveTime.set(dest, getCloseTime(tx));
          }
          distributions.set(dest, distributions.get(dest) + val);
        }
      }
    }
  }

  // ── Mirror wallet detection (accounts receiving similar amounts) ──────────
  const distEntries = [...distributions.entries()]
    .sort((a, b) => b[1] - a[1]);

  const mirrorGroups = [];
  if (distEntries.length >= 3) {
    // Bucket by order-of-magnitude + nearest 10%
    const buckets = new Map();
    for (const [a2, amt] of distEntries) {
      if (amt <= 0) continue;
      const mag   = Math.pow(10, Math.floor(Math.log10(amt)));
      const bucket = Math.round(amt / mag / 0.1) * 0.1 * mag;
      const key   = bucket.toPrecision(2);
      if (!buckets.has(key)) buckets.set(key, []);
      buckets.get(key).push({ addr: a2, amt });
    }
    for (const [, group] of buckets.entries()) {
      if (group.length >= 3) {
        const approxAmt = group.reduce((s, g) => s + g.amt, 0) / group.length;
        mirrorGroups.push({ approxAmt, accounts: group });
        signals.push({
          sev: 'warn',
          label: `${group.length} accounts each received ~${fmt(approxAmt, 0)} tokens`,
          detail: 'Highly similar token amounts suggest coordinated wallets, pre-arranged airdrop clusters, or sybil accounts.',
        });
      }
    }
  }

  // ── Rapid simultaneous distribution ──────────────────────────────────────
  const ts = [...receiveTime.values()].sort();
  if (ts.length >= 5) {
    const span = ts[ts.length - 1] - ts[0];
    if (span < 3600 && ts.length >= 10) {
      signals.push({
        sev: 'warn',
        label: `${ts.length} accounts funded within ${Math.ceil(span / 60)} minutes`,
        detail: 'Rapid token distribution to many wallets in a narrow time window. Matches pre-sale airdrop or coordinated distribution for wash trading.',
      });
    }
  }

  // ── Account creation chains ───────────────────────────────────────────────
  if (createdAccts.size > 0) {
    signals.push({
      sev: createdAccts.size > 10 ? 'warn' : 'info',
      label: `${createdAccts.size} account(s) created by this address`,
      detail: 'This issuer funded the activation of these accounts. They may be controlled by the same entity.',
    });
  }

  // ── Token supply concentration (from trustlines) ──────────────────────────
  // IMPORTANT: account_lines returns at most 400 trustlines. For tokens with many
  // holders, this is a partial sample. All percentages are relative to the visible
  // sample unless gateway_balances provided the true total. We always caveat this.
  const issuedLines = lines.filter(l => Number(l.balance) < 0);

  // True total from gateway_balances if available; fall back to sample sum
  const trueTotal   = _gatewayTotal; // injected below from gatewayBalances
  const sampleTotal = issuedLines.reduce((s, l) => s + Math.abs(Number(l.balance)), 0);
  const totalIssued = trueTotal != null ? trueTotal : sampleTotal;
  const isSampleOnly = trueTotal == null && issuedLines.length > 0;
  const sampleCaveat = isSampleOnly
    ? ` (based on ${issuedLines.length} visible trustlines — actual total supply may be higher if there are more holders)`
    : '';

  const topHolders = issuedLines
    .map(l => ({ addr: l.account, balance: Math.abs(Number(l.balance)), currency: hexToAscii(l.currency) }))
    .sort((a, b) => b.balance - a.balance)
    .slice(0, 10);

  // Only flag concentration if we have a reliable denominator.
  // When sampleOnly, the top holders trivially sum near 100% of the sample —
  // that's an artifact of limited data, not evidence of concentration.
  const denominator = trueTotal != null ? trueTotal : sampleTotal;
  const canAssessConcentration = denominator > 0 && (trueTotal != null || issuedLines.length >= 50);

  if (topHolders.length >= 2 && canAssessConcentration) {
    const top1Pct = topHolders[0].balance / denominator * 100;
    const sourceNote = trueTotal != null ? '' : ' (of visible sample)';
    if (top1Pct > 50) {
      signals.push({ sev: 'critical',
        label: `Top holder controls ${top1Pct.toFixed(0)}%${sourceNote} of supply`,
        detail: `${shortAddr(topHolders[0].addr)} holds ${fmt(topHolders[0].balance, 0)} of ${fmt(denominator, 0)} total${sampleCaveat}. ` +
                (trueTotal != null ? 'Extreme dump risk — one wallet could sell everything.' : 'Check gateway_balances or a block explorer to confirm the full supply picture.') });
    } else if (top1Pct > 25) {
      signals.push({ sev: 'warn',
        label: `Top holder controls ${top1Pct.toFixed(0)}%${sourceNote} of supply`,
        detail: `Large single-holder concentration${sampleCaveat}. Monitor for coordinated sell events.` });
    }

    const top5     = topHolders.slice(0, 5).reduce((s, h) => s + h.balance, 0);
    const top5Pct  = top5 / denominator * 100;
    if (top5Pct > 75) {
      signals.push({ sev: 'warn',
        label: `Top 5 holders own ${top5Pct.toFixed(0)}%${sourceNote} of supply`,
        detail: `Supply heavily concentrated in a few wallets${sampleCaveat}. ` +
                'This pattern is common in pre-launch setups or tokens with limited real distribution.' });
    }
  } else if (issuedLines.length > 0 && !canAssessConcentration) {
    // We have some holders but not enough data to compute meaningful percentages
    signals.push({ sev: 'info',
      label: `${issuedLines.length} trustline holder(s) visible — supply data limited`,
      detail: `Only ${issuedLines.length} trustlines returned by account_lines. ` +
              `The true holder count and total supply cannot be determined from this data alone. ` +
              `Use a block explorer (XRPScan, Bithomp) for a complete holder distribution.` });
  }

  if (signals.length === 0 && totalIssued === 0) {
    signals.push({ sev: 'info', label: 'No token issuance detected', detail: 'This account does not appear to be an active token issuer.' });
  }

  return {
    signals,
    totalIssued,
    holderCount: issuedLines.length,
    topHolders,
    mirrorGroups,
    createdAccts: [...createdAccts],
    distributions: distEntries.slice(0, 10),
    isSampleOnly,
  };
}

/* ─────────────────────────────
   Blackhole / Issuer Safety Helpers
   Prevent false positives for intentionally blackholed issuers
──────────────────────────────── */

// Known XRPL blackhole / provably unusable addresses commonly used for issuer lockout
const KNOWN_BLACKHOLE_ADDRESSES = new Set([
  'rrrrrrrrrrrrrrrrrrrrrhoLvTp',
  'rrrrrrrrrrrrrrrrrrrrBZbvji',
  'rrrrrrrrrrrrrrrrrNAMEtxvNvQ',
  'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh', // Genesis / well-known blackhole reference in some contexts
  'r9cZA1mLK5R5Am25ArfXFmqgNwjZgnfk59', // included because your registry already marks it specially
]);

function isKnownBlackholeAddress(addr) {
  return !!addr && KNOWN_BLACKHOLE_ADDRESSES.has(addr);
}

/**
 * Heuristic: determine whether this account looks intentionally blackholed,
 * which is common for token issuers that permanently disable control.
 *
 * Signals:
 * - master key disabled
 * - regular key points to known blackhole address
 * - no signer list retained
 *
 * This should NOT be treated as a drain pattern by default.
 */
function isIntentionalBlackhole(acct, flags, signerLists = [], txList = []) {
  const masterDisabled = !!(flags & FLAGS.lsfDisableMaster);
  const regularKey     = acct?.RegularKey || '';
  const hasSignerList  = Array.isArray(signerLists) && signerLists.length > 0;
  const knownBlackhole = isKnownBlackholeAddress(regularKey);

  if (masterDisabled && knownBlackhole && !hasSignerList) return true;

  return false;
}

/**
 * Heuristic: determine whether this account behaves like an issuer.
 * Used so we can raise caution wording about sending tokens back to a
 * blackholed issuer without mislabeling it as compromised.
 */
function looksLikeIssuer(acct, flags, txList = []) {
  const defaultRipple = !!(flags & FLAGS.lsfDefaultRipple);
  const requireAuth   = !!(flags & FLAGS.lsfRequireAuth);
  const globalFreeze  = !!(flags & FLAGS.lsfGlobalFreeze);
  const noFreeze      = !!(flags & FLAGS.lsfNoFreeze);

  const trustSetCount = txList.filter(({ tx }) => tx.TransactionType === 'TrustSet').length;
  const paymentTokenCount = txList.filter(({ tx }) =>
    tx.TransactionType === 'Payment' &&
    typeof tx.Amount === 'object' &&
    tx.Amount?.currency
  ).length;

  return defaultRipple || requireAuth || globalFreeze || noFreeze || trustSetCount >= 3 || paymentTokenCount >= 5;
}

/* ═══════════════════════════════════════════════════
   ANALYSIS PASSES
═══════════════════════════════════════════════════ */

/* ── Security Posture ────────────────────────────── */
function analyseSecurityPosture(acct, flags, signerLists, txList) {
  const findings = [];
  let score = 100; // start perfect, deduct

  const masterDisabled = !!(flags & FLAGS.lsfDisableMaster);
  const hasRegularKey  = !!acct.RegularKey;
  const hasSignerList  = signerLists.length > 0;
  const blackholed     = isIntentionalBlackhole(acct, flags, signerLists, txList);
  const issuerLike     = looksLikeIssuer(acct, flags, txList);

  // 1. Master key disabled without regular key = locked out risk
  if (masterDisabled && !hasRegularKey && !hasSignerList) {
    findings.push({
      sev: 'critical',
      label: 'Master key disabled — no fallback',
      detail: 'Account cannot sign transactions. Funds are inaccessible.'
    });
    score -= 40;

  } else if (blackholed) {
    findings.push({
      sev: 'info',
      label: 'Intentional blackhole pattern detected',
      detail: `Master key is disabled and regular key ${acct.RegularKey} is a known blackhole address. This usually indicates the account was intentionally locked, not compromised.`
    });

    if (issuerLike) {
      findings.push({
        sev: 'warn',
        label: 'Blackholed issuer caution',
        detail: 'This account appears issuer-like and intentionally blackholed. Sending issued tokens back here may make them unrecoverable or effectively burn them.'
      });
    }

  } else if (masterDisabled) {
    findings.push({
      sev: 'info',
      label: 'Master key disabled',
      detail: 'Signing via regular key or multisig only.'
    });
  }

  // 2. Regular key set — check if it changed recently
  if (hasRegularKey) {
    const setKeyTx = txList.find(({ tx }) => tx.TransactionType === 'SetRegularKey');
    const recentChange = setKeyTx &&
      (Date.now() / 1000 - getCloseTime(setKeyTx.tx)) < 86400 * 30;

    if (blackholed) {
      findings.push({
        sev: 'info',
        label: 'Regular key points to blackhole address',
        detail: acct.RegularKey
      });

    } else if (recentChange) {
      findings.push({
        sev: 'warn',
        label: 'Regular key set recently',
        detail: `Key: ${acct.RegularKey} — changed within 30 days. Verify you intended this.`
      });
      score -= 15;

    } else {
      findings.push({
        sev: 'info',
        label: 'Regular key active',
        detail: acct.RegularKey
      });
    }
  }

  // 3. Signer list analysis
  signerLists.forEach(sl => {
    const entries = sl.SignerEntries || [];
    const quorum  = sl.SignerQuorum || 1;
    findings.push({
      sev: 'info',
      label: `Multisig: ${entries.length} signers, quorum ${quorum}`,
      detail: entries.map(e => shortAddr(e.SignerEntry?.Account || '')).join(', ')
    });
  });

  // 4. Global freeze
  if (flags & FLAGS.lsfGlobalFreeze) {
    findings.push({
      sev: 'warn',
      label: 'Global Freeze active',
      detail: 'This issuer has frozen all token balances.'
    });
    score -= 10;
  }

  // 5. Deposit auth
  if (flags & FLAGS.lsfDepositAuth) {
    findings.push({
      sev: 'ok',
      label: 'Deposit Authorization enabled',
      detail: 'Only pre-authorized senders can deposit.'
    });
  }

  // 6. Default ripple
  if (flags & FLAGS.lsfDefaultRipple) {
    findings.push({
      sev: 'info',
      label: 'Default Ripple enabled',
      detail: 'Balances can ripple through this account (issuer behaviour).'
    });
  }

  // 7. AccountDelete attempts
  const deleteTxs = txList.filter(({ tx }) => tx.TransactionType === 'AccountDelete');
  if (deleteTxs.length) {
    findings.push({
      sev: 'warn',
      label: `${deleteTxs.length} AccountDelete attempt(s)`,
      detail: 'Account deletion was attempted.'
    });
    score -= 5;
  }

  return { findings, score: Math.max(0, score) };
}

/* ── Drain Risk ──────────────────────────────────── */
function analyseDrainRisk(acct, flags, signerLists, txList, paychans, escrows) {
  const signals = [];
  let riskLevel = 'low'; // low | medium | high | critical

  const masterOff  = !!(flags & FLAGS.lsfDisableMaster);
  const blackholed = isIntentionalBlackhole(acct, flags, signerLists, txList);
  const issuerLike = looksLikeIssuer(acct, flags, txList);

  // 1. Master disabled + regular key
  if (blackholed) {
    signals.push({
      sev: 'info',
      label: 'Intentional blackhole detected',
      detail: `Master key is disabled and regular key ${acct.RegularKey} is a known blackhole address. This is typical for a permanently locked issuer/account, not a classic drain setup.`
    });

    if (issuerLike) {
      signals.push({
        sev: 'warn',
        label: 'Caution: sending assets back may burn them',
        detail: 'Because this account appears to be an intentionally blackholed issuer, sending issued tokens back to it may strand or effectively burn those tokens.'
      });
    }

  } else if (masterOff && acct.RegularKey) {
    signals.push({
      sev: 'critical',
      label: 'Classic drain setup detected',
      detail: `Master key disabled. Regular key ${acct.RegularKey} controls the account. If this key was set by an attacker, funds are at risk.`
    });
    riskLevel = 'critical';
  }

  // 2. Recent SetRegularKey from a DIFFERENT sender (3rd party set the key)
  const keyChanges = txList.filter(({ tx }) =>
    tx.TransactionType === 'SetRegularKey' && tx.Account !== acct.Account
  );

  if (!blackholed && keyChanges.length) {
    signals.push({
      sev: 'critical',
      label: 'Regular key set by external account',
      detail: `${keyChanges.length} key change(s) where sender ≠ account owner. This is unusual.`
    });
    riskLevel = 'critical';
  }

  // 3. Large outflows shortly after suspicious auth changes
  const suspiciousAuthTxs = txList.filter(({ tx }) =>
    ['SetRegularKey', 'SignerListSet'].includes(tx.TransactionType)
  );

  if (!blackholed && suspiciousAuthTxs.length > 0) {
    const authTime = getCloseTime(suspiciousAuthTxs[0].tx);

    const drainPayments = txList.filter(({ tx }) => {
      if (tx.TransactionType !== 'Payment') return false;
      if (tx.Account !== acct.Account) return false; // only outbound
      const txTime = getCloseTime(tx);
      return txTime > authTime && txTime < authTime + 3600 * 48; // within 48h
    });

    if (drainPayments.length > 0) {
      const totalDrained = drainPayments.reduce((acc, { tx }) => {
        const amt = tx.Amount;
        if (typeof amt === 'string') return acc + Number(amt) / 1e6;
        return acc;
      }, 0);

      if (totalDrained > 10) {
        signals.push({
          sev: 'critical',
          label: `${fmt(totalDrained, 2)} XRP sent within 48h of auth change`,
          detail: `${drainPayments.length} payment(s) shortly after key/signer modification. Pattern matches drain attack.`
        });
        riskLevel = 'critical';
      }
    }
  }

  // 4. Open payment channels
  if (paychans.length) {
    const totalLocked = paychans.reduce((acc, p) => acc + Number(p.Amount || 0) / 1e6, 0);
    signals.push({
      sev: 'warn',
      label: `${paychans.length} open payment channel(s) — ${fmt(totalLocked, 2)} XRP locked`,
      detail: `Destination(s): ${paychans.map(p => shortAddr(p.Destination)).join(', ')}`
    });
    if (riskLevel === 'low') riskLevel = 'medium';
  }

  // 5. Open escrows
  if (escrows.length) {
    const totalEscrowed = escrows.reduce((acc, e) => acc + Number(e.Amount || 0) / 1e6, 0);
    signals.push({
      sev: 'info',
      label: `${escrows.length} open escrow(s) — ${fmt(totalEscrowed, 2)} XRP escrowed`,
      detail: `Escrow(s): ${escrows.map(e => e.Destination ? shortAddr(e.Destination) : 'self-escrow').join(', ')}`
    });
  }

  // 6. DepositPreauth grants
  const authGrants = txList.filter(({ tx }) =>
    tx.TransactionType === 'DepositPreauth' && tx.Authorize
  );
  if (authGrants.length > 5) {
    signals.push({
      sev: 'warn',
      label: `${authGrants.length} DepositPreauth grants issued`,
      detail: 'Account pre-authorized many senders. Review if all are trusted.'
    });
    if (riskLevel === 'low') riskLevel = 'medium';
  }

  if (signals.length === 0) {
    signals.push({
      sev: 'ok',
      label: 'No drain patterns detected',
      detail: 'Auth structure looks intact.'
    });
  }

  return { signals, riskLevel };
}
/* ── NFT Risk ────────────────────────────────────── */
function analyseNftRisk(nfts, txList, addr) {
  const flags   = [];
  const nftMap  = new Map(nfts.map(n => [n.NFTokenID, n]));

  // 1. Suspicious NFT offers created by this account with Amount=0 or very low
  const nftOfferCreates = txList.filter(({ tx }) =>
    tx.TransactionType === 'NFTokenCreateOffer' && tx.Account === addr
  );
  const zeroAmtOffers = nftOfferCreates.filter(({ tx }) => {
    const amt = tx.Amount;
    if (!amt) return true; // no amount = free transfer offer
    if (typeof amt === 'string') return Number(amt) < 1000000; // < 1 XRP
    return false;
  });
  if (zeroAmtOffers.length) {
    flags.push({ sev: 'critical', label: `${zeroAmtOffers.length} NFT offer(s) created for ≤1 XRP`,
      detail: 'You created sell offers at near-zero price. This is a common NFT drain vector — attackers trick victims into listing their NFTs for free.' });
  }

  // 2. NFTs accepted from unknown sources (NFTokenAcceptOffer)
  const nftAccepts = txList.filter(({ tx }) =>
    tx.TransactionType === 'NFTokenAcceptOffer' && tx.Account === addr
  );
  if (nftAccepts.length) {
    flags.push({ sev: 'warn', label: `${nftAccepts.length} NFT offer(s) accepted`,
      detail: 'Review these transactions to confirm they were intentional sales/purchases.' });
  }

  // 3. NFTs received that were immediately burned or transferred out
  const nftBurns = txList.filter(({ tx }) =>
    tx.TransactionType === 'NFTokenBurn' && tx.Account === addr
  );
  if (nftBurns.length) {
    flags.push({ sev: 'warn', label: `${nftBurns.length} NFT(s) burned`,
      detail: 'Burned NFTs cannot be recovered. Confirm these were intentional.' });
  }

  // 4. NFT mint then rapid transfer (< 10 ledgers)
  const mints    = txList.filter(({ tx }) => tx.TransactionType === 'NFTokenMint' && tx.Account === addr);
  const transfers = txList.filter(({ tx }) =>
    tx.TransactionType === 'NFTokenCreateOffer' || tx.TransactionType === 'NFTokenAcceptOffer'
  );
  if (mints.length > 0 && transfers.length > 0) {
    flags.push({ sev: 'info', label: `${mints.length} NFT(s) minted · ${transfers.length} transfer event(s)`,
      detail: 'This account has minting activity.' });
  }

  // 5. NFTs with TransferFee (royalty check)
  const royaltyNfts = nfts.filter(n => n.TransferFee && n.TransferFee > 0);
  if (royaltyNfts.length) {
    const avgFee = royaltyNfts.reduce((a, n) => a + n.TransferFee, 0) / royaltyNfts.length;
    flags.push({ sev: 'info', label: `${royaltyNfts.length} NFT(s) carry transfer fees (avg ${(avgFee / 1000).toFixed(1)}%)`,
      detail: 'These NFTs pay royalties on each transfer.' });
  }

  // 6. NFTs from suspicious issuers (non-standard URI or empty)
  const noUriNfts = nfts.filter(n => !n.URI);
  if (noUriNfts.length > 2) {
    flags.push({ sev: 'warn', label: `${noUriNfts.length} NFT(s) have no URI / metadata`,
      detail: 'NFTs without a URI may be spam or placeholder tokens used in scams.' });
  }

  if (flags.length === 0 && nfts.length === 0) {
    flags.push({ sev: 'ok', label: 'No NFT activity detected', detail: 'This account holds no NFTs.' });
  } else if (flags.length === 0) {
    flags.push({ sev: 'ok', label: `${nfts.length} NFT(s) held — no risk signals`, detail: 'NFT posture looks normal.' });
  }

  return { flags, nftCount: nfts.length, mintCount: mints.length };
}

/* ── Wash Trading ────────────────────────────────── */
function analyseWashTrading(txList, addr, lines) {
  const signals = [];
  let   score   = 0; // 0=clean, 100=certain wash

  const creates = txList.filter(({ tx }) => tx.TransactionType === 'OfferCreate');
  const cancels = txList.filter(({ tx }) => tx.TransactionType === 'OfferCancel');
  const fills   = creates.filter(({ meta }) => {
    // Filled offers have AffectedNodes with DeletedNode OfferDirectory
    return meta?.AffectedNodes?.some?.(n => n.DeletedNode?.LedgerEntryType === 'Offer');
  });
  const payments = txList.filter(({ tx }) => tx.TransactionType === 'Payment');

  // 1. Cancel ratio
  const cancelRatio = creates.length > 0 ? cancels.length / creates.length : 0;
  if (creates.length >= WASH_MIN_TX && cancelRatio > WASH_CANCEL_RATIO) {
    signals.push({ sev: 'warn', label: `High cancel ratio: ${(cancelRatio * 100).toFixed(1)}%`,
      detail: `${cancels.length} cancels vs ${creates.length} creates. Threshold: ${(WASH_CANCEL_RATIO * 100).toFixed(0)}%. May indicate layering / spoofing.` });
    score += 25;
  }

  // 2. Round-trip payments (pays someone who pays back)
  const outboundRecipients = new Set(
    payments.filter(({ tx }) => tx.Account === addr && tx.Destination).map(({ tx }) => tx.Destination)
  );
  const inboundSenders = new Set(
    payments.filter(({ tx }) => tx.Destination === addr && tx.Account).map(({ tx }) => tx.Account)
  );
  const roundTrip = [...outboundRecipients].filter(a => inboundSenders.has(a));
  if (roundTrip.length > 0 && payments.length >= WASH_MIN_TX) {
    const rtRatio = roundTrip.length / outboundRecipients.size;
    if (rtRatio > WASH_SELF_RATIO) {
      signals.push({ sev: 'warn', label: `${roundTrip.length} round-trip counterpart(s) detected`,
        detail: `${(rtRatio * 100).toFixed(1)}% of payment recipients also sent back to this account. Possible wash-trade cycle.` });
      score += 20;
    }
  }

  // 3. Same-pair repeated offers (currency A/B traded back and forth many times)
  const pairCounts = new Map();
  creates.forEach(({ tx }) => {
    if (!tx.TakerPays || !tx.TakerGets) return;
    const getCurr = o => typeof o === 'string' ? 'XRP' : `${o.currency}.${shortAddr(o.issuer || '')}`;
    const pair = [getCurr(tx.TakerPays), getCurr(tx.TakerGets)].sort().join('↔');
    pairCounts.set(pair, (pairCounts.get(pair) || 0) + 1);
  });
  const dominantPair = [...pairCounts.entries()].sort((a, b) => b[1] - a[1])[0];
  if (dominantPair && creates.length >= WASH_MIN_TX) {
    const pairConcentration = dominantPair[1] / creates.length;
    if (pairConcentration > 0.70) {
      signals.push({ sev: 'warn', label: `${(pairConcentration * 100).toFixed(0)}% of offers on single pair: ${dominantPair[0]}`,
        detail: `${dominantPair[1]} of ${creates.length} offers on one pair. High concentration is a wash trading signal.` });
      score += 20;
    }
  }

  // 4. Low fill rate (creates offers but rarely lets them fill)
  const fillRate = creates.length > 0 ? fills.length / creates.length : 0;
  if (creates.length >= WASH_MIN_TX && fillRate < 0.05) {
    signals.push({ sev: 'warn', label: `Very low fill rate: ${(fillRate * 100).toFixed(1)}%`,
      detail: `Only ${fills.length} of ${creates.length} offers filled. Placing orders never intended to execute.` });
    score += 15;
  }

  // 5. Burst activity (many trades in short window)
  if (creates.length >= 5) {
    // Check for bursts of ≥5 creates in any 30-second window
    const times = creates.map(({ tx }) => getCloseTime(tx)).sort();
    let maxBurst = 1;
    for (let i = 0; i < times.length; i++) {
      let burst = 1;
      for (let j = i + 1; j < times.length && times[j] - times[i] <= 30; j++) burst++;
      maxBurst = Math.max(maxBurst, burst);
    }
    if (maxBurst >= 8) {
      signals.push({ sev: 'warn', label: `Burst activity: ${maxBurst} offers within 30 seconds`,
        detail: 'Rapid automated trading pattern detected.' });
      score += 10;
    }
  }

  // ── 6. Self-trade: same wallet is both sender and receiver ─────────
  const selfTrades = payments.filter(({ tx }) =>
    tx.Account === addr && tx.Destination === addr
  );
  if (selfTrades.length > 0) {
    signals.push({ sev: 'critical',
      label: `${selfTrades.length} self-trade(s): sender = receiver`,
      detail: 'Payments where origin and destination are the same address. ' +
              'Classic wash-trading indicator — creates artificial volume with zero economic transfer.' });
    score += 30;
  }

  // ── 7. Large-order spoofing: cancel ratio of big-size orders ─────
  // Flag if ≥10 large offers and ≥95% are cancelled without fill
  if (creates.length >= 10) {
    const xrpAmounts = creates.map(({ tx }) => {
      const g = tx.TakerGets;
      return typeof g === 'string' ? Number(g) / 1e6 : null;
    }).filter(v => v != null);
    const p95 = xrpAmounts.sort((a,b) => b-a)[Math.floor(xrpAmounts.length * 0.05)] || 0;
    const largeOrders = creates.filter(({ tx }) => {
      const g = tx.TakerGets;
      return typeof g === 'string' && Number(g) / 1e6 >= p95;
    });
    const largeCancelled = largeOrders.filter(({ meta }) =>
      !meta?.AffectedNodes?.some?.(n => n.DeletedNode?.LedgerEntryType === 'Offer')
    );
    const spoof = largeOrders.length >= 5 ? largeCancelled.length / largeOrders.length : 0;
    if (spoof >= 0.95) {
      signals.push({ sev: 'critical',
        label: `Spoofing pattern: ${(spoof * 100).toFixed(0)}% of large orders cancelled`,
        detail: `${largeCancelled.length} of ${largeOrders.length} top-5% size orders were cancelled without execution. ` +
                '≥95% cancel rate on large orders strongly implies fake order book depth (spoofing).' });
      score += 30;
    } else if (spoof >= 0.80) {
      signals.push({ sev: 'warn',
        label: `Elevated large-order cancel rate: ${(spoof * 100).toFixed(0)}%`,
        detail: `${largeCancelled.length}/${largeOrders.length} large orders cancelled. Watch for spoofing behaviour.` });
      score += 15;
    }
  }

  // ── 8. Trade-size uniformity (CV) ───────────────────────────────
  if (creates.length >= WASH_MIN_TX) {
    const sizes = creates.map(({ tx }) => {
      const g = tx.TakerGets;
      return typeof g === 'string' ? Number(g) / 1e6
           : (g?.value ? Number(g.value) : null);
    }).filter(v => v != null && v > 0);
    if (sizes.length >= WASH_MIN_TX) {
      const mu  = sizes.reduce((a, b) => a + b, 0) / sizes.length;
      const sig = Math.sqrt(sizes.reduce((a, v) => a + (v - mu) ** 2, 0) / sizes.length);
      const cv  = mu > 0 ? sig / mu : null;
      if (cv !== null && cv < 0.05) {
        signals.push({ sev: 'critical',
          label: `Robotic trade uniformity (CV ${cv.toFixed(3)})`,
          detail: `${(cv * 100).toFixed(1)}% coefficient of variation across ${sizes.length} offer sizes. ` +
                  'Near-identical sizes indicate bot-generated fake volume (natural markets show CV ≥ 0.5).' });
        score += 25;
      } else if (cv !== null && cv < 0.20) {
        signals.push({ sev: 'warn',
          label: `Unusually uniform trade sizes (CV ${cv.toFixed(3)})`,
          detail: `Only ${(cv * 100).toFixed(1)}% variation in offer sizes — suspiciously low for organic activity.` });
        score += 10;
      }
    }
  }

  // ── 9. Roundness of transaction values ───────────────────────────
  const allAmts = [...creates, ...payments].map(({ tx }) => {
    const a = tx.TakerGets || tx.Amount;
    return typeof a === 'string' ? Number(a) / 1e6
         : (a?.value ? Number(a.value) : null);
  }).filter(v => v != null && v > 0 && Number.isFinite(v));
  if (allAmts.length >= 10) {
    const roundMagn = [100, 1_000, 10_000, 100_000];
    const roundCount = allAmts.filter(v => roundMagn.some(m => Math.abs(v % m) < 1e-6 && v / m >= 1)).length;
    const roundPct   = roundCount / allAmts.length;
    if (roundPct > 0.45) {
      signals.push({ sev: 'warn',
        label: `Round-number bias: ${(roundPct * 100).toFixed(0)}% of amounts at exact multiples`,
        detail: `${roundCount}/${allAmts.length} trade / payment amounts are exact multiples of 100, 1,000, or 10,000. ` +
                'Statistical excess of round numbers is a signature of bot-generated activity.' });
      score += 12;
    }
  }

  // ── 10. Enhanced burst: >100 offers within 1 hour ────────────────
  if (creates.length >= 5) {
    const times = creates.map(({ tx }) => getCloseTime(tx)).sort((a, b) => a - b);
    let maxHourly = 0;
    for (let i = 0; i < times.length; i++) {
      let cnt = 1;
      for (let j = i + 1; j < times.length && times[j] - times[i] <= 3600; j++) cnt++;
      if (cnt > maxHourly) maxHourly = cnt;
    }
    if (maxHourly > 100) {
      signals.push({ sev: 'critical',
        label: `Hourly burst: ${maxHourly} offers within 60 minutes`,
        detail: `>100 OfferCreate txs in a single hour is a strong bot-pump indicator, ` +
                'especially in typically illiquid token markets.' });
      score += 20;
    } else if (maxHourly >= 8) {
      // Existing 30-second style burst note — add only if not already covered
      const times30 = times;
      let maxBurst30 = 1;
      for (let i = 0; i < times30.length; i++) {
        let b = 1;
        for (let j = i + 1; j < times30.length && times30[j] - times30[i] <= 30; j++) b++;
        if (b > maxBurst30) maxBurst30 = b;
      }
      if (maxBurst30 >= 8) {
        signals.push({ sev: 'warn',
          label: `Rapid burst: ${maxBurst30} offers within 30 seconds`,
          detail: 'Automated trading pattern — bursts at this speed exceed human capability.' });
        score += 10;
      }
    }
  }

  const verdict = score === 0      ? 'clean'
    : score <  25 ? 'low-risk'
    : score <  50 ? 'suspicious'
    : 'high-risk';

  if (signals.length === 0) {
    signals.push({ sev: 'ok', label: 'No wash trading signals',
      detail: `${creates.length} offers · ${cancels.length} cancels · ${selfTrades.length} self-trades — patterns look normal.` });
  }

  return {
    signals, score, verdict,
    stats: {
      creates: creates.length, cancels: cancels.length, fills: fills.length,
      payments: payments.length, roundTrip: roundTrip.length, selfTrades: selfTrades.length,
    },
  };
}

/* ── Benford's Law Analysis ─────────────────────────
   Tests first digits of all monetary amounts.
   Natural data follows log10(1 + 1/d) distribution.
   Large chi-squared = fabricated / bot data.
──────────────────────────────────────────────────── */
function analyseBenfordsLaw(txList) {
  const amounts = [];
  for (const { tx } of txList) {
    const candidates = [tx.Amount, tx.TakerGets, tx.TakerPays, tx.SendMax, tx.DeliverMin];
    for (const c of candidates) {
      const v = typeof c === 'string' ? Number(c) / 1e6
              : (c?.value ? Number(c.value) : null);
      if (v != null && v > 0 && Number.isFinite(v)) amounts.push(v);
    }
  }

  if (amounts.length < 50) {
    return {
      signals: [{ sev: 'info', label: "Insufficient data for Benford's Law",
        detail: `Need ≥50 monetary amounts, found ${amounts.length}.` }],
      chiSq: null, verdict: 'insufficient', digitBreakdown: [], sampleSize: amounts.length,
    };
  }

  // Expected Benford probabilities (digits 1–9)
  const BENFORD = [0, 0.301, 0.176, 0.125, 0.097, 0.079, 0.067, 0.058, 0.051, 0.046];
  const observed = new Array(10).fill(0);
  for (const v of amounts) {
    const s = v.toFixed(6).replace(/^0+\.?0*/, '');
    const d = parseInt(s[0], 10);
    if (d >= 1 && d <= 9) observed[d]++;
  }

  const n = amounts.length;
  let chiSq = 0;
  const digitBreakdown = [];
  for (let d = 1; d <= 9; d++) {
    const obs = observed[d] / n;
    const exp = BENFORD[d];
    chiSq += n * Math.pow(obs - exp, 2) / exp;
    digitBreakdown.push({ digit: d, obs: (obs * 100).toFixed(1), exp: (exp * 100).toFixed(1),
                          delta: ((obs - exp) * 100).toFixed(1) });
  }

  // Chi-square critical values (8 df): p=0.05 → 15.51,  p=0.01 → 20.09
  const signals = [];
  let verdict;
  if (chiSq > 20.09) {
    verdict = 'high-deviation';
    signals.push({ sev: 'warn',
      label: `Benford's Law: significant deviation (χ²=${chiSq.toFixed(1)})`,
      detail: `First-digit distribution deviates significantly from natural patterns (p<0.01, n=${n}). ` +
              'This is a statistical signature of fabricated or algorithmically generated transaction amounts.' });
  } else if (chiSq > 15.51) {
    verdict = 'moderate-deviation';
    signals.push({ sev: 'info',
      label: `Benford's Law: moderate deviation (χ²=${chiSq.toFixed(1)})`,
      detail: `Some deviation from expected natural distribution (p<0.05, n=${n}). Worth monitoring alongside other signals.` });
  } else {
    verdict = 'normal';
    signals.push({ sev: 'ok',
      label: `Benford's Law: normal distribution (χ²=${chiSq.toFixed(1)})`,
      detail: `First-digit distribution is consistent with organic transaction patterns (n=${n}).` });
  }

  return { signals, chiSq, verdict, digitBreakdown, sampleSize: n };
}

/* ═══════════════════════════════════════════════════
   FORENSIC ANALYTICS SUITE
   Four independent quantitative engines that complement
   Benford's Law to form a 5-pillar fraud detection framework.
   Each engine produces signals, a numeric score, and a
   layman verdict. All five feed the combined Forensic Report.
═══════════════════════════════════════════════════ */

/* ── [1] Shannon's Entropy ────────────────────────────
   Measures information randomness in transaction amounts,
   counterparty diversity, time-of-day spread, and tx types.

   THEORY: Organic financial activity has medium entropy —
   not too uniform (bots repeat amounts) and not maximally
   random (artificially shuffled data). Entropy outside the
   natural band is a structural signal of non-organic behavior.

   H = −Σ p(x) · log₂(p(x))

   Organic range for XRPL wallets: ~2.4–3.8 bits (amount bins)
   Bot-generated: < 1.8 (repeating) or > 4.2 (pure random)
──────────────────────────────────────────────────── */
function analyseShannonsEntropy(txList, addr) {
  const MIN_TX = 30;
  const signals = [];

  // ── 1. Amount magnitude entropy ──────────────────
  const amounts = [];
  for (const { tx } of txList) {
    const candidates = [tx.Amount, tx.TakerGets, tx.TakerPays];
    for (const c of candidates) {
      const v = typeof c === 'string' ? Number(c) / 1e6
              : (c?.value ? Number(c.value) : null);
      if (v && v > 0 && Number.isFinite(v)) amounts.push(v);
    }
  }

  const amountEntropy = amounts.length >= MIN_TX ? (() => {
    // Bucket into 12 magnitude bins (log scale)
    const bins = new Array(12).fill(0);
    for (const v of amounts) {
      const bin = Math.min(11, Math.max(0, Math.floor(Math.log10(v + 1) * 2)));
      bins[bin]++;
    }
    return _shannonH(bins);
  })() : null;

  // ── 2. Counterparty address entropy ───────────────
  const cpCounts = {};
  for (const { tx } of txList) {
    const cp = tx.Account === addr ? tx.Destination : tx.Account;
    if (cp && cp !== addr) cpCounts[cp] = (cpCounts[cp] || 0) + 1;
  }
  const cpFreqs = Object.values(cpCounts);
  const counterpartyEntropy = cpFreqs.length >= 3 ? _shannonH(cpFreqs) : null;

  // ── 3. Time-of-day distribution entropy ──────────
  const hourBins = new Array(24).fill(0);
  let hasTimes = false;
  for (const { tx } of txList) {
    if (tx.date) {
      const rippleEpoch = 946684800; // Ripple epoch offset from Unix
      const hour = new Date((tx.date + rippleEpoch) * 1000).getUTCHours();
      hourBins[hour]++;
      hasTimes = true;
    }
  }
  const timeEntropy = hasTimes && txList.length >= MIN_TX ? _shannonH(hourBins) : null;

  // ── 4. Transaction type entropy ───────────────────
  const typeCounts = {};
  for (const { tx } of txList) {
    typeCounts[tx.TransactionType] = (typeCounts[tx.TransactionType] || 0) + 1;
  }
  const typeEntropy = _shannonH(Object.values(typeCounts));

  // ── 5. Verdict construction ───────────────────────
  let verdict = 'normal';
  let riskPenalty = 0;

  // Low amount entropy: bot repeating the same amounts
  if (amountEntropy !== null) {
    if (amountEntropy < 1.5) {
      verdict = 'low-entropy';
      riskPenalty += 18;
      signals.push({ sev: 'warn',
        label: `Amount entropy critically low (H=${amountEntropy.toFixed(2)} bits)`,
        detail: `Transaction amounts are highly repetitive. A bot or scripted actor tends to reuse the same values. Organic wallets show entropy ≥2.4 bits across amount magnitudes.` });
    } else if (amountEntropy < 2.2) {
      riskPenalty += 8;
      signals.push({ sev: 'info',
        label: `Amount entropy below natural range (H=${amountEntropy.toFixed(2)} bits)`,
        detail: `Some amount repetition detected. Could indicate automated activity mixed with organic transactions.` });
    } else if (amountEntropy > 4.5) {
      riskPenalty += 10;
      signals.push({ sev: 'info',
        label: `Amount entropy abnormally high (H=${amountEntropy.toFixed(2)} bits)`,
        detail: `Transaction amounts are maximally varied — more than organic activity typically shows. This can indicate amounts were artificially randomized to evade Benford detection.` });
    } else {
      signals.push({ sev: 'ok',
        label: `Amount entropy normal (H=${amountEntropy.toFixed(2)} bits)`,
        detail: `Transaction amount diversity is consistent with organic financial activity.` });
    }
  }

  // Low counterparty entropy: concentrated interactions (wash ring signal)
  if (counterpartyEntropy !== null) {
    if (counterpartyEntropy < 1.0 && cpFreqs.length < 4) {
      riskPenalty += 14;
      signals.push({ sev: 'warn',
        label: `Counterparty entropy very low (H=${counterpartyEntropy.toFixed(2)} bits)`,
        detail: `This wallet transacts with very few unique addresses and with high repetition — a structural signature of round-trip wash trading rings.` });
    } else if (counterpartyEntropy < 2.0) {
      riskPenalty += 5;
      signals.push({ sev: 'info',
        label: `Counterparty entropy low (H=${counterpartyEntropy.toFixed(2)} bits)`,
        detail: `Most interactions are concentrated among a small set of counterparties.` });
    } else {
      signals.push({ sev: 'ok',
        label: `Counterparty diversity healthy (H=${counterpartyEntropy.toFixed(2)} bits)`,
        detail: `Counterparty distribution reflects diverse interaction patterns.` });
    }
  }

  // Time-of-day concentration: bot at exact hours
  if (timeEntropy !== null) {
    const maxPossible = Math.log2(24);
    const relEntropy = timeEntropy / maxPossible;
    if (relEntropy < 0.45) {
      riskPenalty += 10;
      signals.push({ sev: 'warn',
        label: `Time-of-day entropy low (H=${timeEntropy.toFixed(2)} bits, ${(relEntropy*100).toFixed(0)}% of max)`,
        detail: `Transactions cluster heavily in a few hours of the day. Bots typically run at fixed UTC hours; organic users spread activity across the day.` });
    } else {
      signals.push({ sev: 'ok',
        label: `Time-of-day distribution natural (H=${timeEntropy.toFixed(2)} bits)`,
        detail: `Transaction timing is distributed across hours in a pattern consistent with human activity.` });
    }
  }

  if (!signals.length) {
    signals.push({ sev: 'info', label: 'Insufficient data for entropy analysis',
      detail: `Need ≥${MIN_TX} transactions. Found ${txList.length}.` });
  }

  if (riskPenalty >= 18) verdict = 'anomalous';
  else if (riskPenalty >= 8)  verdict = 'elevated';

  return {
    signals, verdict, riskPenalty,
    amountEntropy, counterpartyEntropy, timeEntropy, typeEntropy,
    uniqueCounterparties: cpFreqs.length, sampleSize: txList.length,
  };
}

function _shannonH(counts) {
  const total = counts.reduce((a, b) => a + b, 0);
  if (!total) return 0;
  return -counts.reduce((h, c) => {
    if (!c) return h;
    const p = c / total;
    return h + p * Math.log2(p);
  }, 0);
}

/* ── [2] Zipf's Law Analysis ──────────────────────────
   THEORY: In natural systems — language, city populations,
   internet traffic, organic financial networks — the nth
   most frequent item has frequency ∝ 1/nˢ where s ≈ 1.

   For XRPL: rank counterparties by interaction frequency.
   Organic wallets follow Zipf (s ≈ 0.8–1.3).
   Wash-trading rings show flat distributions (s < 0.4)
   or hyper-concentrated (s > 2.2).

   Method: OLS regression of log(rank) vs log(frequency).
   The slope is the Zipf exponent.
──────────────────────────────────────────────────── */
function analyseZipfsLaw(txList, addr) {
  const MIN_CP = 8; // need enough counterparties
  const signals = [];

  // Build counterparty frequency map
  const cpMap = {};
  for (const { tx } of txList) {
    const cp = tx.Account === addr ? tx.Destination : tx.Account;
    if (cp && cp !== addr) cpMap[cp] = (cpMap[cp] || 0) + 1;
  }
  const freqs = Object.values(cpMap).sort((a, b) => b - a);

  if (freqs.length < MIN_CP) {
    return {
      signals: [{ sev: 'info',
        label: `Insufficient counterparties for Zipf's Law (need ≥${MIN_CP}, found ${freqs.length})`,
        detail: 'Zipf analysis becomes meaningful with a broader counterparty network.' }],
      verdict: 'insufficient', zipfExponent: null, riskPenalty: 0,
      freqTable: [], uniqueCounterparties: freqs.length,
    };
  }

  // OLS regression: log(rank) vs log(frequency)
  const n = freqs.length;
  let sumX = 0, sumY = 0, sumXY = 0, sumX2 = 0;
  const logPairs = freqs.map((f, i) => ({ rank: i + 1, freq: f,
    lx: Math.log(i + 1), ly: Math.log(f) }));

  for (const { lx, ly } of logPairs) {
    sumX += lx; sumY += ly; sumXY += lx * ly; sumX2 += lx * lx;
  }
  const denom = n * sumX2 - sumX * sumX;
  const slope = denom !== 0 ? (n * sumXY - sumX * sumY) / denom : null;
  const zipfExponent = slope !== null ? Math.abs(slope) : null;

  // R² for fit quality
  const meanY = sumY / n;
  let ssTot = 0, ssRes = 0;
  const b = (sumY - slope * sumX) / n;
  for (const { lx, ly } of logPairs) {
    ssTot += Math.pow(ly - meanY, 2);
    ssRes += Math.pow(ly - (slope * lx + b), 2);
  }
  const rSquared = ssTot > 0 ? 1 - ssRes / ssTot : 0;

  let verdict = 'normal';
  let riskPenalty = 0;

  if (zipfExponent !== null) {
    if (rSquared < 0.55) {
      // Poor Zipf fit — artificial structure
      riskPenalty += 12;
      signals.push({ sev: 'warn',
        label: `Counterparty distribution doesn't follow Zipf's Law (R²=${rSquared.toFixed(2)})`,
        detail: `Natural networks follow a power-law rank-frequency relationship. This wallet's counterparty network has poor Zipf fit (R²=${rSquared.toFixed(2)}), suggesting artificial or script-driven interaction structure.` });
      verdict = 'anomalous';
    } else if (zipfExponent < 0.4) {
      // Too flat: unusually uniform usage of counterparties (wash ring)
      riskPenalty += 15;
      signals.push({ sev: 'warn',
        label: `Zipf exponent too flat (s=${zipfExponent.toFixed(2)}, expected 0.8–1.3)`,
        detail: `A very flat Zipf exponent means counterparties are used with surprisingly equal frequency. In organic networks, you transact far more often with a few key addresses. Flat distribution is consistent with round-trip wash trading rings.` });
      verdict = 'anomalous';
    } else if (zipfExponent > 2.2) {
      // Too steep: hyper-concentration
      riskPenalty += 10;
      signals.push({ sev: 'warn',
        label: `Zipf exponent hyper-concentrated (s=${zipfExponent.toFixed(2)}, expected 0.8–1.3)`,
        detail: `Extreme concentration on one or two counterparties with steep dropoff. While not unusual for simple wallets, combined with other signals this suggests coordinated narrow-ring activity.` });
      verdict = 'elevated';
    } else {
      signals.push({ sev: 'ok',
        label: `Counterparty network follows Zipf's Law (s=${zipfExponent.toFixed(2)}, R²=${rSquared.toFixed(2)})`,
        detail: `The rank-frequency distribution of counterparties follows the expected natural power-law pattern. This is consistent with organic wallet activity.` });
    }
  }

  // Also check amount Zipf (round-number concentration)
  const amtBins = {};
  for (const { tx } of txList) {
    const v = typeof tx.Amount === 'string' ? Math.round(Number(tx.Amount) / 1e4) * 10 : null;
    if (v && v > 0) amtBins[v] = (amtBins[v] || 0) + 1;
  }
  const amtFreqs = Object.values(amtBins).sort((a, b) => b - a);
  const topAmtShare = amtFreqs.length ? amtFreqs[0] / amtFreqs.reduce((a,b)=>a+b,0) : 0;
  if (topAmtShare > 0.45) {
    riskPenalty += 8;
    signals.push({ sev: 'warn',
      label: `Single amount dominates ${(topAmtShare*100).toFixed(0)}% of transactions`,
      detail: `One transaction amount value accounts for nearly half of all payments. Round-number dominance is a hallmark of scripted or wash-trading activity.` });
  }

  if (!signals.length) {
    signals.push({ sev: 'info', label: 'Zipf analysis: no anomalies detected', detail: 'Counterparty distribution consistent with natural activity.' });
  }

  return {
    signals, verdict, riskPenalty,
    zipfExponent, rSquared, freqTable: freqs.slice(0, 12),
    uniqueCounterparties: freqs.length,
  };
}

/* ── [3] Time Series Analysis ─────────────────────────
   THEORY: Human financial activity is irregular and
   bursty. Bots are periodic and mechanically spaced.

   We measure:
   1. Inter-transaction interval CV (coefficient of variation)
      Bot CV ≈ 0–0.3 (too regular)
      Human CV ≈ 0.8–3.0 (irregular)
   2. Autocorrelation at lag-1 and lag-7 days (periodicity)
   3. Volume burst score (sudden spikes vs baseline)
   4. Day-of-week entropy (bots often skip weekends or run 24/7)
──────────────────────────────────────────────────── */
function analyseTimeSeries(txList) {
  const MIN_TX = 20;
  const signals = [];
  const RIPPLE_EPOCH = 946684800;

  if (txList.length < MIN_TX) {
    return {
      signals: [{ sev: 'info',
        label: `Insufficient transactions for time series analysis (need ≥${MIN_TX}, found ${txList.length})`,
        detail: 'Time series analysis requires a longer transaction history.' }],
      verdict: 'insufficient', riskPenalty: 0, intervalCV: null,
      autocorrelation: null, burstScore: null, periodicityScore: null,
    };
  }

  // ── 1. Collect timestamps ───────────────────────
  const timestamps = txList
    .filter(({ tx }) => tx.date != null)
    .map(({ tx }) => (tx.date + RIPPLE_EPOCH) * 1000)
    .sort((a, b) => a - b);

  if (timestamps.length < MIN_TX) {
    return { signals: [{ sev: 'info', label: 'No timestamp data available', detail: 'Time series requires date-stamped transactions.' }],
      verdict: 'insufficient', riskPenalty: 0, intervalCV: null, autocorrelation: null, burstScore: null, periodicityScore: null };
  }

  // ── 2. Inter-transaction intervals ──────────────
  const intervals = [];
  for (let i = 1; i < timestamps.length; i++) {
    const d = (timestamps[i] - timestamps[i-1]) / 1000; // seconds
    if (d > 0 && d < 86400 * 30) intervals.push(d); // exclude gaps > 30 days
  }

  let intervalCV = null;
  if (intervals.length >= 5) {
    const mean = intervals.reduce((a,b) => a+b, 0) / intervals.length;
    const std = Math.sqrt(intervals.reduce((s, v) => s + Math.pow(v - mean, 2), 0) / intervals.length);
    intervalCV = mean > 0 ? std / mean : null;
  }

  // ── 3. Daily volume buckets ──────────────────────
  const dayBuckets = {};
  for (const t of timestamps) {
    const day = new Date(t).toISOString().slice(0, 10);
    dayBuckets[day] = (dayBuckets[day] || 0) + 1;
  }
  const dailyVols = Object.values(dayBuckets);

  // ── 4. Burst score ───────────────────────────────
  let burstScore = 0;
  if (dailyVols.length >= 4) {
    const mean = dailyVols.reduce((a,b)=>a+b,0)/dailyVols.length;
    const std  = Math.sqrt(dailyVols.reduce((s,v)=>s+Math.pow(v-mean,2),0)/dailyVols.length);
    const maxVol = Math.max(...dailyVols);
    burstScore = std > 0 ? (maxVol - mean) / std : 0; // z-score of peak day
  }

  // ── 5. Lag-1 autocorrelation ─────────────────────
  let autocorrelation = null;
  if (dailyVols.length >= 6) {
    const mean = dailyVols.reduce((a,b)=>a+b,0)/dailyVols.length;
    const centered = dailyVols.map(v => v - mean);
    const denom = centered.reduce((s,v)=>s+v*v,0);
    if (denom > 0) {
      const lag1 = centered.slice(0,-1).reduce((s,v,i)=>s+v*centered[i+1],0) / denom;
      autocorrelation = lag1;
    }
  }

  // ── 6. Day-of-week entropy ───────────────────────
  const dowBins = new Array(7).fill(0);
  for (const t of timestamps) dowBins[new Date(t).getUTCDay()]++;
  const dowEntropy = _shannonH(dowBins);
  const maxDowH = Math.log2(7);

  // ── 7. Periodicity detection (FFT-lite: look for dominant period) ────
  let periodicityScore = 0;
  if (intervals.length >= 10) {
    // Count how many intervals are within ±20% of the median
    const sorted = [...intervals].sort((a,b)=>a-b);
    const median = sorted[Math.floor(sorted.length/2)];
    const nearMedian = intervals.filter(v => Math.abs(v - median) / median < 0.2).length;
    periodicityScore = nearMedian / intervals.length;
  }

  // ── 8. Signals ───────────────────────────────────
  let verdict = 'normal';
  let riskPenalty = 0;

  if (intervalCV !== null) {
    if (intervalCV < 0.25) {
      riskPenalty += 20;
      verdict = 'bot-pattern';
      signals.push({ sev: 'warn',
        label: `Transaction intervals mechanically regular (CV=${intervalCV.toFixed(2)})`,
        detail: `The time gaps between transactions are too regular for human behavior (CV < 0.25). Organic wallets show irregular timing (CV 0.8–3.0). This pattern is a strong bot signature.` });
    } else if (intervalCV < 0.5) {
      riskPenalty += 8;
      signals.push({ sev: 'info',
        label: `Transaction timing somewhat regular (CV=${intervalCV.toFixed(2)})`,
        detail: `Interval regularity is below typical human variance. Could indicate scheduled automation.` });
    } else {
      signals.push({ sev: 'ok',
        label: `Transaction timing is irregular (CV=${intervalCV.toFixed(2)})`,
        detail: `Inter-transaction intervals show natural human-like variance.` });
    }
  }

  if (periodicityScore > 0.55) {
    riskPenalty += 12;
    signals.push({ sev: 'warn',
      label: `Strong periodicity detected (${(periodicityScore*100).toFixed(0)}% of intervals near median)`,
      detail: `More than half of transaction intervals cluster around the same duration. This mechanical repetition is consistent with an automated script executing on a fixed schedule.` });
  }

  if (burstScore > 3.5) {
    signals.push({ sev: 'info',
      label: `Activity burst detected (peak day z-score=${burstScore.toFixed(1)})`,
      detail: `One or more days had extreme transaction volume compared to baseline. Could indicate a coordinated pump event or account recovery sweep.` });
  }

  if (autocorrelation !== null && autocorrelation > 0.6) {
    riskPenalty += 6;
    signals.push({ sev: 'info',
      label: `High day-to-day volume autocorrelation (ρ=${autocorrelation.toFixed(2)})`,
      detail: `Transaction volume is strongly self-correlated — today's activity predicts tomorrow's. This is consistent with an automated routine that maintains a constant pace.` });
  }

  const dowRel = dowEntropy / maxDowH;
  if (dowRel < 0.7 && timestamps.length > 30) {
    riskPenalty += 6;
    signals.push({ sev: 'info',
      label: `Day-of-week distribution concentrated (${(dowRel*100).toFixed(0)}% of max entropy)`,
      detail: `Transactions cluster heavily on specific days. Automated systems often run every day (maximally flat) or skip weekends — both deviate from natural human patterns.` });
  }

  if (!signals.length) {
    signals.push({ sev: 'ok', label: 'No temporal anomalies detected',
      detail: 'Transaction timing patterns are consistent with organic human activity.' });
  }
  if (riskPenalty >= 20) verdict = 'bot-pattern';
  else if (riskPenalty >= 8) verdict = 'elevated';

  const span = timestamps.length >= 2
    ? Math.round((timestamps[timestamps.length-1] - timestamps[0]) / 86400000)
    : null;

  return {
    signals, verdict, riskPenalty, intervalCV, autocorrelation,
    burstScore, periodicityScore, dowEntropy, dowBins,
    dailyVolume: Object.entries(dayBuckets).slice(-30),
    activeSpanDays: span, totalTimestamped: timestamps.length,
  };
}

/* ── [4] Granger Causality (Simplified Cross-Correlation) ─
   THEORY: Granger Causality tests whether knowing the
   history of time series X improves prediction of Y.
   If X Granger-causes Y, X leads Y with significant
   cross-correlation at positive lags.

   XRPL applications:
   A. Offer-creation → Cancellation causality
      (wash trading: same actor creates then cancels)
   B. Inflow → Outflow causality
      (self-trading: inflow immediately causes outflow)
   C. NFT listing → offer acceptance causality
      (trap offers: listing followed quickly by zero-price accept)

   Method: Pearson cross-correlation at lags 0..5 ledgers.
   Leading significant correlation = causal signal.
──────────────────────────────────────────────────── */
function analyseGrangerCausality(txList, addr) {
  const MIN_TX = 20;
  const signals = [];
  const RIPPLE_EPOCH = 946684800;

  if (txList.length < MIN_TX) {
    return {
      signals: [{ sev: 'info',
        label: `Insufficient data for Granger causality analysis (need ≥${MIN_TX}, found ${txList.length})`,
        detail: 'Granger causality requires enough temporal observations to test lead-lag relationships.' }],
      verdict: 'insufficient', riskPenalty: 0,
      offerCancelCausality: null, inflowOutflowCausality: null,
    };
  }

  // ── Bucket transactions into 12-hour windows ──────
  const WINDOW_MS = 12 * 3600 * 1000;
  const bucketOf = tx => {
    if (!tx.date) return null;
    return Math.floor(((tx.date + RIPPLE_EPOCH) * 1000) / WINDOW_MS);
  };

  const buckets = {};
  const ensureBucket = b => {
    if (!buckets[b]) buckets[b] = { offerCreate: 0, offerCancel: 0, inflow: 0, outflow: 0, nftList: 0, nftAccept: 0 };
  };

  for (const { tx, meta } of txList) {
    const b = bucketOf(tx);
    if (b === null) continue;
    ensureBucket(b);
    const d = buckets[b];
    const t = tx.TransactionType;

    if (t === 'OfferCreate') d.offerCreate++;
    else if (t === 'OfferCancel') d.offerCancel++;

    if (t === 'NFTokenCreateOffer') d.nftList++;
    else if (t === 'NFTokenAcceptOffer') d.nftAccept++;

    // Inflow/outflow
    const delivered = meta?.delivered_amount || tx.Amount;
    const xrpAmt = typeof delivered === 'string' ? Number(delivered) / 1e6 : 0;
    if (xrpAmt > 0) {
      if (tx.Destination === addr) d.inflow += xrpAmt;
      else if (tx.Account === addr) d.outflow += xrpAmt;
    }
  }

  const sortedKeys = Object.keys(buckets).map(Number).sort((a,b)=>a-b);
  if (sortedKeys.length < 6) {
    return {
      signals: [{ sev: 'info', label: 'Insufficient temporal windows for Granger test',
        detail: 'Need activity spread across multiple time windows.' }],
      verdict: 'insufficient', riskPenalty: 0,
      offerCancelCausality: null, inflowOutflowCausality: null,
    };
  }

  const seriesX = (key) => sortedKeys.map(k => buckets[k][key] || 0);

  // Cross-correlation at lags 0..4 windows
  const crossCorr = (X, Y, maxLag = 4) => {
    const n = X.length;
    const mx = X.reduce((a,b)=>a+b,0)/n, my = Y.reduce((a,b)=>a+b,0)/n;
    const Xc = X.map(x=>x-mx), Yc = Y.map(y=>y-my);
    const sdX = Math.sqrt(Xc.reduce((s,x)=>s+x*x,0)/n);
    const sdY = Math.sqrt(Yc.reduce((s,y)=>s+y*y,0)/n);
    if (!sdX || !sdY) return Array(maxLag+1).fill(0);
    return Array.from({ length: maxLag+1 }, (_, lag) => {
      let sum = 0, cnt = 0;
      for (let i = 0; i + lag < n; i++) { sum += Xc[i] * Yc[i+lag]; cnt++; }
      return cnt > 0 ? sum / (cnt * sdX * sdY) : 0;
    });
  };

  let verdict = 'normal';
  let riskPenalty = 0;

  // ── A. OfferCreate → OfferCancel causality ────────
  const ocSeries  = seriesX('offerCreate');
  const canSeries = seriesX('offerCancel');
  const ocCCF     = crossCorr(ocSeries, canSeries);
  const maxOCLag  = ocCCF.indexOf(Math.max(...ocCCF));
  const maxOCCorr = Math.max(...ocCCF);
  const offerCancelCausality = { ccf: ocCCF, maxCorr: maxOCCorr, maxLag: maxOCLag };

  if (maxOCCorr > 0.55 && maxOCLag <= 2) {
    riskPenalty += 18;
    verdict = 'causal-signal';
    signals.push({ sev: 'warn',
      label: `OfferCreate → OfferCancel Granger signal (ρ=${maxOCCorr.toFixed(2)}, lag=${maxOCLag} window${maxOCLag===1?'':'s'})`,
      detail: `Offer creation strongly predicts subsequent cancellation at lag ${maxOCLag} (${maxOCLag * 12}h). This causal pattern is the mechanical signature of wash trading: create offers to inflate visible book activity, then cancel them. A leading correlation this strong at such short lag is unlikely in organic market-making.` });
  } else if (maxOCCorr > 0.35) {
    riskPenalty += 6;
    signals.push({ sev: 'info',
      label: `Mild offer-cancel lead relationship (ρ=${maxOCCorr.toFixed(2)}, lag=${maxOCLag})`,
      detail: `Some temporal link between creating and cancelling offers. Worth monitoring alongside other signals.` });
  } else {
    signals.push({ sev: 'ok',
      label: `No Granger signal between offer creation and cancellation`,
      detail: `Offer creation and cancellation timing appear independent — no evidence of systematic cancel-to-create cycles.` });
  }

  // ── B. Inflow → Outflow causality ─────────────────
  const inSeries  = seriesX('inflow');
  const outSeries = seriesX('outflow');
  const ioCCF     = crossCorr(inSeries, outSeries);
  const maxIOLag  = ioCCF.indexOf(Math.max(...ioCCF));
  const maxIOCorr = Math.max(...ioCCF);
  const inflowOutflowCausality = { ccf: ioCCF, maxCorr: maxIOCorr, maxLag: maxIOLag };

  if (maxIOCorr > 0.65 && maxIOLag === 0) {
    riskPenalty += 12;
    signals.push({ sev: 'warn',
      label: `Inflow and outflow move in perfect lockstep (ρ=${maxIOCorr.toFixed(2)} at lag 0)`,
      detail: `Funds entering and leaving the wallet in the same time window with high correlation at zero lag is consistent with pass-through or round-trip self-trading: money comes in and immediately goes back out.` });
  } else if (maxIOCorr > 0.55 && maxIOLag <= 1) {
    riskPenalty += 8;
    signals.push({ sev: 'info',
      label: `Inflow leads outflow (ρ=${maxIOCorr.toFixed(2)}, lag=${maxIOLag})`,
      detail: `Incoming funds reliably precede outgoing funds at short lag. Could indicate legitimate management, but in conjunction with other signals suggests fund cycling.` });
  } else {
    signals.push({ sev: 'ok',
      label: `No suspicious inflow→outflow Granger pattern`,
      detail: `Inflow and outflow timing are not predictably linked, consistent with independent organic transaction activity.` });
  }

  // ── C. NFT listing → acceptance causality ─────────
  const nftL = seriesX('nftList');
  const nftA = seriesX('nftAccept');
  const totalNftList = nftL.reduce((a,b)=>a+b,0);
  const totalNftAccept = nftA.reduce((a,b)=>a+b,0);
  if (totalNftList > 3 && totalNftAccept > 3) {
    const nftCCF = crossCorr(nftL, nftA);
    const maxNFTCorr = Math.max(...nftCCF);
    const maxNFTLag  = nftCCF.indexOf(maxNFTCorr);
    if (maxNFTCorr > 0.6 && maxNFTLag <= 1) {
      riskPenalty += 8;
      signals.push({ sev: 'warn',
        label: `NFT listing causes rapid acceptance (ρ=${maxNFTCorr.toFixed(2)}, lag=${maxNFTLag})`,
        detail: `NFT sell offer creation is closely followed by acceptance. Combined with the NFT trap detection module, this timing pattern can indicate coordinated offer traps with a controlled accepting address.` });
    }
  }

  if (!signals.some(s => s.sev === 'warn' || s.sev === 'critical')) {
    if (!signals.length) signals.push({ sev: 'ok', label: 'No Granger causality anomalies detected',
      detail: 'Temporal relationships between transaction types show no suspicious lead-lag patterns.' });
  }

  if (riskPenalty >= 18) verdict = 'causal-signal';
  else if (riskPenalty >= 8) verdict = 'elevated';

  return {
    signals, verdict, riskPenalty,
    offerCancelCausality, inflowOutflowCausality,
    windowCount: sortedKeys.length,
  };
}

/* ── Volume Concentration (token-focused) ────────────
   Measures how many unique accounts are generating
   volume for each IOU/token. <5 unique actors is
   a strong wash-trading signal.
──────────────────────────────────────────────────── */
function analyseVolumeConcentration(txList, addr) {
  // Aggregate unique senders + volume per currency
  const tokenData = new Map(); // currency → { senders: Set, vol: number, trades: number }

  for (const { tx } of txList) {
    // Check both TakerGets (offer) and Amount (payment)
    const candidates = [tx.TakerGets, tx.Amount];
    for (const amt of candidates) {
      if (!amt || typeof amt !== 'object') continue; // skip XRP strings
      const currency = amt.currency;
      const value    = Number(amt.value || 0);
      const sender   = tx.Account;
      if (!currency || !sender || value <= 0 || !Number.isFinite(value)) continue;

      if (!tokenData.has(currency)) tokenData.set(currency, { senders: new Set(), vol: 0, trades: 0 });
      const d = tokenData.get(currency);
      d.senders.add(sender);
      d.vol    += value;
      d.trades++;
    }
  }

  const signals = [];
  const concentrations = [];

  for (const [currency, d] of tokenData.entries()) {
    if (d.trades < 8) continue; // too few trades to be meaningful
    const uniqueActors = d.senders.size;
    concentrations.push({ currency, uniqueActors, vol: d.vol, trades: d.trades });

    if (uniqueActors < 5) {
      signals.push({ sev: 'critical',
        label: `${currency}: ${uniqueActors} wallet(s) driving all volume`,
        detail: `${d.trades} trades totalling ${d.vol.toFixed(2)} ${currency} from only ${uniqueActors} address(es). ` +
                'Fewer than 5 unique actors generating most volume is a wash trading red flag.' });
    } else if (uniqueActors < 10) {
      signals.push({ sev: 'warn',
        label: `${currency}: low actor diversity (${uniqueActors} wallets, ${d.trades} trades)`,
        detail: `Volume concentrated among only ${uniqueActors} addresses. Organic markets typically have broader participation.` });
    }
  }

  if (!concentrations.length) {
    signals.push({ sev: 'info', label: 'No IOU/token volume data',
      detail: 'No token-denominated transactions found in history (XRP-only activity).' });
  } else if (!signals.length) {
    signals.push({ sev: 'ok', label: 'Volume concentration normal',
      detail: `${concentrations.length} token(s) analysed — all have ≥10 unique trading participants.` });
  }

  return { signals, concentrations };
}

/* ── Token Issuer Analysis ───────────────────────── */
function analyseTokenIssuer(acct, lines, flags, txList) {
  const signals = [];
  const isIssuer = !!(flags & FLAGS.lsfDefaultRipple) || lines.some(l => l.account === acct.Account);

  // Obligations: lines where account is the "account" field = they issued those tokens
  const obligations = lines.filter(l => Number(l.balance) < 0); // negative = we owe to holders
  const totalObligated = obligations.reduce((a, l) => a + Math.abs(Number(l.balance)), 0);

  if (obligations.length > 0) {
    signals.push({ sev: 'info', label: `Token issuer: ${obligations.length} outstanding currency lines`,
      detail: `Total outstanding: ${fmt(totalObligated, 2)} across ${obligations.length} holder(s).` });
  }

  // Freeze checks
  const frozenLines = lines.filter(l => l.freeze);
  const frozenByIssuer = lines.filter(l => l.freeze_peer);
  if (frozenLines.length) {
    signals.push({ sev: 'warn', label: `${frozenLines.length} trustline(s) frozen by this account`,
      detail: 'This account has frozen specific trustlines.' });
  }
  if (frozenByIssuer.length) {
    signals.push({ sev: 'critical', label: `${frozenByIssuer.length} of your trustline(s) frozen by issuer`,
      detail: `Frozen currencies: ${frozenByIssuer.map(l => l.currency).join(', ')}. You cannot transfer these tokens.` });
  }

  // Global freeze
  if (flags & FLAGS.lsfGlobalFreeze) {
    signals.push({ sev: 'critical', label: 'Global Freeze — all token transfers suspended',
      detail: 'No holders can transfer tokens issued by this account.' });
  }

  // No-freeze flag (cannot freeze in future — good for holders)
  if (flags & FLAGS.lsfNoFreeze) {
    signals.push({ sev: 'ok', label: 'NoFreeze flag set — issuer cannot freeze balances',
      detail: 'Token holders are protected against future freeze actions.' });
  }

  // Black hole check (issuer account deleted / no access = stranded tokens)
  const acctBalance = Number(acct.Balance || 0) / 1e6;
  const reserve = 10 + Number(acct.OwnerCount || 0) * 2;
  if (obligations.length > 0 && acctBalance < reserve + 1) {
    signals.push({ sev: 'warn', label: 'Issuer balance near reserve — possible black hole',
      detail: 'Issuer with outstanding tokens has almost no XRP above reserve. Tokens may be stranded.' });
  }

  // Note: detailed supply concentration analysis is in the Issuer Connections panel,
  // which correctly accounts for sample size and uses gateway_balances when available.

  if (signals.length === 0) {
    signals.push({ sev: 'ok', label: 'No token issuer flags', detail: 'This account does not appear to be a token issuer.' });
  }

  return { signals, isIssuer, obligationCount: obligations.length };
}

/* ── AMM Positions ───────────────────────────────── */
function analyseAmmPositions(lines, txList, objects, ammInfoMap = new Map()) {
  const signals  = [];
  const positions = [];

  // LP tokens are trustlines with currency = 03... (LP token discriminator on XRPL)
  const lpLines = lines.filter(l =>
    l.currency && (l.currency.startsWith('03') || l.currency.length === 40)
  );

  // AMM transactions
  const ammDeposits  = txList.filter(({ tx }) => tx.TransactionType === 'AMMDeposit');
  const ammWithdraws = txList.filter(({ tx }) => tx.TransactionType === 'AMMWithdraw');
  const ammCreates   = txList.filter(({ tx }) => tx.TransactionType === 'AMMCreate');
  const ammVotes     = txList.filter(({ tx }) => tx.TransactionType === 'AMMVote');
  const ammBids      = txList.filter(({ tx }) => tx.TransactionType === 'AMMBid');

  lpLines.forEach(l => {
    const balance = Number(l.balance);
    const limit   = Number(l.limit);
    positions.push({
      currency: l.currency,
      issuer:   l.account,
      balance:  balance,
      limit:    limit,
    });
  });

  if (positions.length) {
    signals.push({ sev: 'info', label: `${positions.length} LP token position(s)`,
      detail: `Active liquidity provider in ${positions.length} AMM pool(s).` });
    // Enrich with amm_info data if available
    for (const p of positions) {
      const ammData = ammInfoMap.get(p.currency);
      if (ammData) {
        p.tvl     = ammData.amount  ? Number(ammData.amount) / 1e6     : null;
        p.tvl2    = ammData.amount2?.value ? Number(ammData.amount2.value) : null;
        p.feeRate = ammData.trading_fee != null ? ammData.trading_fee / 1000 : null; // basis points → %
        p.lpSupply = ammData.lp_token?.value ? Number(ammData.lp_token.value) : null;
        // Ownership share: our LP balance / total LP supply
        if (p.lpSupply && p.balance) {
          const ownerPct = (Math.abs(p.balance) / p.lpSupply) * 100;
          p.ownerPct = ownerPct;
          if (ownerPct > 50) {
            signals.push({ sev: 'warn',
              label: `Dominant AMM position: ${ownerPct.toFixed(0)}% of pool`,
              detail: `This account controls ${ownerPct.toFixed(0)}% of the LP token supply for pool ${shortAddr(p.currency)}. ` +
                      `Withdrawing all at once would severely impact pool liquidity and anyone currently trading in it.` });
          }
        }
        if (p.tvl != null) {
          signals.push({ sev: 'info',
            label: `Pool TVL: ${fmt(p.tvl, 2)} XRP${p.tvl2 ? ` + ${fmt(p.tvl2, 2)} tokens` : ''} · Fee: ${p.feeRate?.toFixed(2) ?? '?'}%`,
            detail: `Actual pool context from amm_info. Your LP position represents ${ p.ownerPct != null ? p.ownerPct.toFixed(1) + '% of the pool.' : 'an unknown share of the pool.'}` });
        }
      }
    }
  }

  if (ammCreates.length) {
    signals.push({ sev: 'info', label: `Created ${ammCreates.length} AMM pool(s)`,
      detail: 'This account bootstrapped one or more liquidity pools.' });
  }

  if (ammDeposits.length || ammWithdraws.length) {
    signals.push({ sev: 'info', label: `${ammDeposits.length} deposit(s) · ${ammWithdraws.length} withdrawal(s)`,
      detail: 'LP activity history.' });
  }

  if (ammVotes.length) {
    signals.push({ sev: 'info', label: `${ammVotes.length} AMM fee vote(s)`,
      detail: 'This account has voted on AMM trading fee parameters.' });
  }

  if (ammBids.length) {
    signals.push({ sev: 'info', label: `${ammBids.length} continuous auction bid(s)`,
      detail: 'Bid for the AMM auction slot (reduced fee trading window).' });
  }

  // Impermanent loss warning if large LP position
  const largePositions = positions.filter(p => Math.abs(p.balance) > 1000);
  if (largePositions.length) {
    signals.push({ sev: 'warn', label: 'Large LP positions — impermanent loss risk',
      detail: 'Significant liquidity positions carry exposure to price divergence between pool assets.' });
  }

  if (signals.length === 0) {
    signals.push({ sev: 'ok', label: 'No AMM positions', detail: 'This account is not a liquidity provider.' });
  }

  return { signals, positions, deposits: ammDeposits.length, withdrawals: ammWithdraws.length };
}


/* ── Fee Spike Detection ────────────────────────────────────────────────────
   Detects elevated fees that often accompany coordinated manipulation events.
   When bots pay 10-100x the base fee to ensure same-ledger execution, a
   distinct spike pattern emerges that organic wallets rarely produce.
────────────────────────────────────────────────────────────────────────── */
function analyseFeeSpikePattern(txList) {
  const signals = [];
  const BASE_FEE_DROPS = 12;
  const feeTxs = txList.filter(({tx}) => tx.Fee && Number(tx.Fee) > 0);

  if (feeTxs.length < 10) {
    return { signals: [], verdict: 'insufficient', riskPenalty: 0,
             avgFeeMultiplier: null, spikeCount: 0, topFeeHashes: [] };
  }

  const multipliers = feeTxs.map(({tx}) => Number(tx.Fee) / BASE_FEE_DROPS);
  const avgMult = multipliers.reduce((a,b) => a+b, 0) / multipliers.length;
  const highFeeTxs = feeTxs.filter(({tx}) => Number(tx.Fee) / BASE_FEE_DROPS > 100);
  const spikeCount = highFeeTxs.length;
  const spikeRate  = spikeCount / feeTxs.length;

  let riskPenalty = 0;
  let verdict = 'normal';

  // Collect top-3 high-fee hashes for the report
  const topFeeHashes = [...feeTxs]
    .sort((a,b) => Number(b.tx.Fee) - Number(a.tx.Fee))
    .slice(0, 5)
    .map(({tx}) => ({ hash: tx.hash, mult: (Number(tx.Fee) / BASE_FEE_DROPS).toFixed(0), fee: Number(tx.Fee) }));

  if (spikeRate > 0.15 && spikeCount >= 5) {
    riskPenalty = 10;
    verdict = 'elevated';
    signals.push({ sev: 'warn',
      label: `Fee spike pattern: ${spikeCount} txs paid >100x base fee (${(spikeRate*100).toFixed(0)}% of history)`,
      detail: `Average fee multiplier: ${avgMult.toFixed(0)}x. In XRPL, bots often pay elevated fees to guarantee ` +
              `same-ledger execution as a counterparty — a technique used in coordinated wash trading and sandwich attacks. ` +
              `Organic users rarely pay more than 2–5x the base fee. Top hashes: ${topFeeHashes.slice(0,3).map(h => shortAddr(h.hash)).join(', ')}.`,
      hashes: topFeeHashes.map(h => h.hash),
    });
  } else if (avgMult > 20) {
    riskPenalty = 4;
    signals.push({ sev: 'info',
      label: `Elevated average fee (${avgMult.toFixed(0)}x base fee)`,
      detail: `This wallet consistently pays above-average fees. Could indicate priority execution requirements or automated trading.` });
  } else {
    signals.push({ sev: 'ok',
      label: `Fee levels normal (avg ${avgMult.toFixed(1)}x base fee)`,
      detail: `Transaction fees are within typical organic ranges.` });
  }

  return { signals, verdict, riskPenalty, avgFeeMultiplier: +avgMult.toFixed(2), spikeCount, topFeeHashes };
}

/* ── Destination Tag Analysis ───────────────────────────────────────────────
   DestinationTag identifies the recipient sub-account at an exchange or service.
   The same tag repeating across many payments = one account being funded repeatedly.
   Wildly diverse tags to one exchange = a service (or wash ring) using many accounts.
   This is computed entirely from existing txList — no new API calls needed.
────────────────────────────────────────────────────────────────────────── */
function analyseDestTagPatterns(txList, addr) {
  const signals   = [];
  const tagsByDest = new Map(); // dest → Set of tags used

  for (const { tx } of txList) {
    if (tx.TransactionType !== 'Payment') continue;
    if (tx.Account !== addr) continue;  // outbound only
    const dest = tx.Destination;
    const tag  = tx.DestinationTag;
    if (!dest) continue;
    if (!tagsByDest.has(dest)) tagsByDest.set(dest, new Set());
    if (tag != null) tagsByDest.get(dest).add(tag);
  }

  const exchangeDests = [...tagsByDest.entries()].filter(([d]) => {
    const ent = getEntity(d);
    return ent?.type === 'exchange';
  });

  let riskPenalty = 0;
  const tagProfiles = [];

  for (const [dest, tags] of tagsByDest.entries()) {
    const ent  = getEntity(dest);
    const name = ent?.name || shortAddr(dest);
    const uniqueTags = tags.size;
    const txCount = txList.filter(({tx}) => tx.Account === addr && tx.Destination === dest).length;

    tagProfiles.push({ dest, name, uniqueTags, txCount, tags: [...tags].slice(0, 10) });

    // Single tag used many times = probably the same person's exchange account
    if (uniqueTags === 1 && txCount >= 5 && ent?.type === 'exchange') {
      signals.push({ sev: 'info',
        label: `${name}: ${txCount} payments all using tag ${[...tags][0]}`,
        detail: `Single destination tag used across all ${txCount} payments to ${name}. ` +
                `This is the normal pattern for one person funding their own exchange account.` });
    }
    // Many different tags = possibly funding many different accounts
    else if (uniqueTags > 10 && ent?.type === 'exchange') {
      riskPenalty = Math.max(riskPenalty, 8);
      signals.push({ sev: 'warn',
        label: `${name}: ${uniqueTags} different destination tags used`,
        detail: `${txCount} payments to ${name} used ${uniqueTags} different tags — ` +
                `each tag typically identifies a different customer account. Funding many exchange ` +
                `sub-accounts can indicate either a service (legitimate) or coordinated deposit layering ` +
                `where funds are spread across many exchange wallets to avoid detection.` });
    }
    // Zero tags to exchange = may not reach intended recipient
    else if (uniqueTags === 0 && txCount >= 2 && ent?.type === 'exchange') {
      signals.push({ sev: 'warn',
        label: `${name}: ${txCount} payments with no destination tag`,
        detail: `Payments to exchange addresses without a destination tag may not be credited. ` +
                `Most exchanges require a tag to identify which customer account receives the funds.` });
    }
  }

  if (signals.length === 0 && tagsByDest.size > 0) {
    signals.push({ sev: 'ok',
      label: 'Destination tag patterns normal',
      detail: `Payment routing tags are consistent with regular outbound payments.` });
  } else if (tagsByDest.size === 0) {
    signals.push({ sev: 'info',
      label: 'No outbound payments to analyse for destination tags',
      detail: 'No outbound Payment transactions found in history.' });
  }

  return { signals, riskPenalty, tagProfiles };
}

/* ── Path Payment Depth Analysis ────────────────────────────────────────────
   Deep analysis of path payments: suspicious patterns include:
   - XRP→IOU→XRP round-trips (circular routing for wash volume)
   - Hops through obscure/illiquid issuers (obfuscation)
   - Same source and destination after multi-hop path (value round-trip)
   This uses tx.Paths already in txList — no new API calls.
────────────────────────────────────────────────────────────────────────── */
function analysePathPaymentDepth(txList, addr) {
  const signals = [];
  const pathPayments = txList.filter(({tx}) =>
    tx.TransactionType === 'Payment' && tx.Account === addr &&
    (Array.isArray(tx.Paths) && tx.Paths.length > 0 || tx.SendMax != null)
  );

  if (pathPayments.length === 0) {
    return { signals: [], riskPenalty: 0, roundTripCount: 0, deepHopCount: 0, selfRoutedCount: 0, noData: true };
  }

  // Show what we found even with small counts — just caveat statistical power
  const lowSampleNote = pathPayments.length < 5 ? ` (small sample: ${pathPayments.length} path payments found — patterns may not be statistically significant)` : '';

  // Detect XRP→IOU→XRP round-trips (SendMax in XRP drops, Amount in XRP drops)
  const xrpRoundTrips = pathPayments.filter(({tx}) => {
    const amtIsXrp    = typeof tx.Amount  === 'string';
    const smaxIsXrp   = typeof tx.SendMax === 'string';
    return amtIsXrp && smaxIsXrp;  // paying XRP to receive XRP = routing through IOU pairs
  });

  // Detect hops ≥ 3 (deep chains often used to obscure fund origin)
  const deepHops = pathPayments.filter(({tx}) => {
    if (!Array.isArray(tx.Paths)) return false;
    return tx.Paths.some(path => Array.isArray(path) && path.length >= 3);
  });

  // Detect self-routing (dest === source, fund goes out and comes back)
  const selfRouted = pathPayments.filter(({tx}) =>
    tx.Destination === addr
  );

  let riskPenalty = 0;

  if (xrpRoundTrips.length >= 1) {  // flag even 1 confirmed round-trip
    riskPenalty += 12;
    signals.push({ sev: 'warn',
      label: `${xrpRoundTrips.length} XRP→IOU→XRP round-trip path payments`,
      detail: `Sending XRP and receiving XRP via intermediate token pairs means the payment ` +
              `routes through the DEX and creates trading volume without changing economic position. ` +
              `${xrpRoundTrips.length} occurrences suggests this is deliberate. ` +
              `This is the classic cross-currency wash-trading arb pattern on XRPL. ` +
              `Example hash: ${xrpRoundTrips[0]?.tx?.hash ? shortAddr(xrpRoundTrips[0].tx.hash) : 'N/A'}.`,
      hashes: xrpRoundTrips.slice(0,5).map(({tx}) => tx.hash).filter(Boolean),
    });
  }

  if (deepHops.length >= 1) {  // flag even single deep-hop payment
    riskPenalty += 6;
    signals.push({ sev: 'info',
      label: `${deepHops.length} path payments with ≥3 intermediate hops`,
      detail: `Deep routing chains (3+ hops) can indicate: legitimate arbitrage, ` +
              `liquidity optimization, or deliberate obfuscation of fund origin. ` +
              `Check each transaction for the intermediate issuers in the path.` });
  }

  if (selfRouted.length > 0) {
    riskPenalty += 15;
    signals.push({ sev: 'critical',
      label: `${selfRouted.length} path payment(s) where sender = destination`,
      detail: `Money sent to your own address via a multi-hop path creates DEX trading volume ` +
              `with no net change in balance. This is a direct wash-trading technique: ` +
              `the path through the order book generates artificial volume on every intermediate pair. ` +
              `Hashes: ${selfRouted.slice(0,3).map(({tx}) => shortAddr(tx.hash||'')).join(', ')}.`,
      hashes: selfRouted.slice(0,5).map(({tx}) => tx.hash).filter(Boolean),
    });
  }

  if (signals.length === 0) {
    signals.push({ sev: 'ok',
      label: `${pathPayments.length} path payment(s) — no suspicious routing patterns${lowSampleNote}`,
      detail: `No circular routing (XRP→IOU→XRP), self-routing, or unusual deep hop chains detected.` });
  }

  return { signals, riskPenalty, roundTripCount: xrpRoundTrips.length,
           deepHopCount: deepHops.length, selfRoutedCount: selfRouted.length };
}


/* ── Inbound Flow Analysis ───────────────────────────────────────────────────
   Mirrors analyseFundFlow but for incoming payments. Answers:
   who funded this wallet, from how many sources, from known exchanges,
   and whether funding looks structured (many small equal payments).
────────────────────────────────────────────────────────────────────────── */
function analyseInboundFlow(txList, addr) {
  const sources    = new Map();
  const inboundSeq = [];

  for (const { tx, meta } of txList) {
    if (tx.TransactionType !== 'Payment') continue;
    if (tx.Destination !== addr) continue;  // inbound only
    const src = tx.Account;
    if (!src || src === addr) continue;

    let amtXrp   = 0;
    let amtToken = null;
    const delivered = meta?.delivered_amount || tx.Amount;
    if (typeof delivered === 'string') amtXrp = Number(delivered) / 1e6;
    else if (delivered?.value) amtToken = { value: Number(delivered.value), currency: hexToAscii(delivered.currency), issuer: delivered.issuer };

    const ts = getCloseTime(tx);
    inboundSeq.push({ src, amtXrp, amtToken, ts, hash: tx.hash || '', destTag: tx.DestinationTag });

    if (!sources.has(src)) {
      sources.set(src, { addr: src, totalXrp: 0, txCount: 0, firstSeen: ts, lastSeen: ts, entity: getEntity(src) || null });
    }
    const s = sources.get(src);
    s.totalXrp += amtXrp;
    s.txCount++;
    s.lastSeen  = Math.max(s.lastSeen,  ts);
    s.firstSeen = Math.min(s.firstSeen, ts);
  }

  const topSources = [...sources.values()]
    .sort((a,b) => b.totalXrp - a.totalXrp || b.txCount - a.txCount)
    .slice(0, 10);

  const totalIn      = topSources.reduce((s,d) => s + d.totalXrp, 0);
  const exchangeSrcs = topSources.filter(s => s.entity?.type === 'exchange');

  // Structured funding: many payments of near-equal amounts from different sources
  const amtBuckets = {};
  for (const r of inboundSeq) {
    if (r.amtXrp <= 0) continue;
    const bucket = Math.round(r.amtXrp / 10) * 10;  // group to nearest 10 XRP
    amtBuckets[bucket] = (amtBuckets[bucket] || 0) + 1;
  }
  const topBucket = Object.entries(amtBuckets).sort((a,b) => b[1]-a[1])[0];
  const structuredFlag = topBucket && topBucket[1] >= 5 && topBucket[1] / inboundSeq.length > 0.4;

  const signals = [];
  if (exchangeSrcs.length) {
    const names = [...new Set(exchangeSrcs.map(s => s.entity.name))].join(', ');
    signals.push({ sev: 'info',
      label: `Funding from ${exchangeSrcs.length} known exchange(s): ${names}`,
      detail: `${fmt(exchangeSrcs.reduce((s,d)=>s+d.totalXrp,0),2)} XRP received from exchange withdrawals — typical for a personal trading wallet.` });
  }
  if (structuredFlag) {
    signals.push({ sev: 'warn',
      label: `Structured inbound pattern: ${topBucket[1]} payments near ~${topBucket[0]} XRP`,
      detail: `Over 40% of inbound payments cluster around the same amount (~${topBucket[0]} XRP). Structured deposits can indicate layering — deliberately splitting large amounts into smaller equal transfers to avoid detection.` });
  }
  if (sources.size === 1 && inboundSeq.length >= 5) {
    const sole = topSources[0];
    signals.push({ sev: 'info',
      label: `Single funding source: all ${inboundSeq.length} inbound payments from one address`,
      detail: `${sole.entity?.name || shortAddr(sole.addr)} is the sole funding source. This is normal for a personal wallet but notable for a wallet claiming broad community usage.` });
  }
  if (!signals.length && inboundSeq.length > 0) {
    signals.push({ sev: 'ok', label: `${inboundSeq.length} inbound payment(s) from ${sources.size} source(s)`, detail: `Total received: ${fmt(totalIn,2)} XRP. No unusual inbound patterns.` });
  }
  if (inboundSeq.length === 0) {
    signals.push({ sev: 'info', label: 'No inbound payments found in analysed history', detail: 'Wallet may be funded via DEX activity or in ledgers outside the analysed range.' });
  }

  return { signals, topSources, totalIn, uniqueSources: sources.size, timeline: inboundSeq.slice(-20).reverse(), exchangeSrcs, structuredFlag: !!structuredFlag };
}

/* ── Memo Analysis ────────────────────────────────────────────────────────────
   Scans all Memo fields in the transaction history.
   Memos can contain: exchange deposit references, scam coordination text,
   payout codes, hex-encoded data, or repeated pattern signals.
────────────────────────────────────────────────────────────────────────── */
function analyseMemos(txList, addr) {
  const signals  = [];
  const allMemos = [];

  // Known scam / suspicious memo patterns
  const SCAM_PATTERNS = [
    /airdrop/i, /claim.*reward/i, /free.*xrp/i, /verify.*wallet/i,
    /support.*team/i, /urgent/i, /suspended/i, /confirm.*seed/i,
    /your.*account.*hold/i, /unlock/i,
  ];

  for (const { tx } of txList) {
    if (!tx.Memos?.length) continue;
    for (const m of tx.Memos) {
      const raw = m.Memo?.MemoData || '';
      if (!raw) continue;
      let text = '';
      try { text = decodeURIComponent(raw.replace(/../g, h => '%' + h)); } catch { text = raw; }
      // Also try plain hex→ASCII
      if (!text || text === raw) {
        try {
          let ascii = '';
          for (let i = 0; i < raw.length; i += 2) {
            const c = parseInt(raw.slice(i,i+2), 16);
            if (c >= 32 && c < 127) ascii += String.fromCharCode(c);
          }
          if (ascii.length > 4) text = ascii;
        } catch {}
      }
      allMemos.push({ tx: tx.hash || '', type: tx.TransactionType, sender: tx.Account, text: text.slice(0, 200), raw });
    }
  }

  if (allMemos.length === 0) {
    return { signals: [], allMemos: [], scamMemos: [], repeatedMemos: [] };
  }

  // Check for scam patterns
  const scamMemos = allMemos.filter(m => SCAM_PATTERNS.some(p => p.test(m.text)));
  if (scamMemos.length) {
    signals.push({ sev: 'critical',
      label: `${scamMemos.length} memo(s) match known scam patterns`,
      detail: `Memos containing phrases like "airdrop", "claim reward", "verify wallet", or "urgent" are used in social engineering attacks. These payments were likely sent to trick the recipient into taking action. Examples: ${scamMemos.slice(0,2).map(m => '"'+m.text.slice(0,40)+'"').join(', ')}` });
  }

  // Check for repeated memo text (coordination signal)
  const memoFreq = {};
  for (const m of allMemos) {
    const key = m.text.slice(0,50).trim().toLowerCase();
    if (key.length > 3) memoFreq[key] = (memoFreq[key] || 0) + 1;
  }
  const repeatedMemos = Object.entries(memoFreq).filter(([,c]) => c >= 3).sort((a,b)=>b[1]-a[1]);
  if (repeatedMemos.length) {
    signals.push({ sev: 'warn',
      label: `${repeatedMemos.length} memo text(s) repeated ≥3 times`,
      detail: `Identical memo text across multiple transactions suggests scripted or automated activity. Most repeated: "${repeatedMemos[0][0]}" (${repeatedMemos[0][1]}×)` });
  }

  if (!signals.length) {
    signals.push({ sev: 'ok',
      label: `${allMemos.length} memo(s) found — no suspicious patterns`,
      detail: `Memo content looks normal.` });
  }

  return { signals, allMemos, scamMemos, repeatedMemos: repeatedMemos.slice(0,5) };
}

/* ── Escrow Depth Analysis ────────────────────────────────────────────────────
   Goes beyond counting escrows to understand who created them, when they mature,
   and whether third-party escrows (created by external accounts) are present.
────────────────────────────────────────────────────────────────────────── */
function analyseEscrowDepth(objects, txList, addr) {
  const escrows = objects.filter(o => o.LedgerEntryType === 'Escrow');
  if (!escrows.length) return { signals: [], escrows: [], hasThirdParty: false };

  const signals   = [];
  const now       = Math.floor(Date.now() / 1000);
  const RIPPLE_EPOCH = 946684800;

  const details = escrows.map(e => {
    const creator     = e.Account || null;
    const dest        = e.Destination || null;
    const amtXrp      = Number(e.Amount || 0) / 1e6;
    const finishAfter = e.FinishAfter ? e.FinishAfter + RIPPLE_EPOCH : null;
    const cancelAfter = e.CancelAfter ? e.CancelAfter + RIPPLE_EPOCH : null;
    const isThirdParty = creator && creator !== addr && dest === addr;
    const isSelfEscrow = creator === addr && dest === addr;
    const daysToFinish = finishAfter ? Math.ceil((finishAfter - now) / 86400) : null;
    return { creator, dest, amtXrp, finishAfter, cancelAfter, isThirdParty, isSelfEscrow, daysToFinish, conditional: !!e.Condition };
  });

  const thirdParty = details.filter(e => e.isThirdParty);
  const totalLocked = details.reduce((s,e) => s+e.amtXrp, 0);

  if (thirdParty.length) {
    signals.push({ sev: 'warn',
      label: `${thirdParty.length} escrow(s) created by external account(s) — funds locked to this address`,
      detail: `${fmt(thirdParty.reduce((s,e)=>s+e.amtXrp,0),2)} XRP in escrows that an outside party controls. The creator sets the conditions. ` +
              `Escrows created by attackers just before a drain attempt have been observed in some compromise patterns — verify who created these.` });
  }

  // Look for escrows maturing soon (within 7 days)
  const soonMature = details.filter(e => e.daysToFinish != null && e.daysToFinish >= 0 && e.daysToFinish <= 7);
  if (soonMature.length) {
    signals.push({ sev: 'info',
      label: `${soonMature.length} escrow(s) mature within 7 days`,
      detail: `${fmt(soonMature.reduce((s,e)=>s+e.amtXrp,0),2)} XRP will become claimable soon. ` +
              `If these are third-party escrows, the creator can claim funds once the condition is met.` });
  }

  if (!signals.length) {
    signals.push({ sev: 'ok',
      label: `${escrows.length} self-escrow(s) — ${fmt(totalLocked,2)} XRP locked`,
      detail: `All escrows appear to be self-controlled time-locks. No third-party escrow risk.` });
  }

  return { signals, escrows: details, hasThirdParty: thirdParty.length > 0, totalLocked };
}

/* ── Check Object Analysis ────────────────────────────────────────────────────
   XRPL Checks are deferred payments — like a paper check, must be cashed by recipient.
   An uncashed check for a large amount sitting open for months is unusual.
────────────────────────────────────────────────────────────────────────── */
function analyseChecks(objects) {
  const checks = objects.filter(o => o.LedgerEntryType === 'Check');
  if (!checks.length) return { signals: [], checks: [] };

  const signals = [];
  const RIPPLE_EPOCH = 946684800;
  const now     = Math.floor(Date.now() / 1000);

  const details = checks.map(c => {
    const amtXrp   = typeof c.SendMax === 'string' ? Number(c.SendMax) / 1e6 : null;
    const amtToken = typeof c.SendMax === 'object' ? c.SendMax : null;
    const expiry   = c.Expiration ? c.Expiration + RIPPLE_EPOCH : null;
    const agesDays = c.ledger_index ? null : null;  // would need ledger close time to compute
    const expired  = expiry && expiry < now;
    return { sender: c.Account, dest: c.Destination, amtXrp, amtToken, expiry, expired, id: c.index || '' };
  });

  const largeChecks = details.filter(c => c.amtXrp && c.amtXrp > 100);
  const expiredChecks = details.filter(c => c.expired);

  if (largeChecks.length) {
    signals.push({ sev: 'info',
      label: `${largeChecks.length} large uncashed check(s) — ${fmt(largeChecks.reduce((s,c)=>s+(c.amtXrp||0),0),2)} XRP pending`,
      detail: `Open checks can be cashed by the recipient at any time before expiry. Large uncashed checks represent a future outflow commitment.` });
  }
  if (expiredChecks.length) {
    signals.push({ sev: 'info',
      label: `${expiredChecks.length} expired check(s) — should be cancelled to reclaim reserve`,
      detail: `Expired checks still occupy owner reserve slots (2 XRP each). Cancelling them returns the reserved XRP.` });
  }
  if (!signals.length) {
    signals.push({ sev: 'ok',
      label: `${checks.length} check(s) found — no unusual patterns`,
      detail: `Check amounts are within normal range.` });
  }

  return { signals, checks: details };
}

/* ── Live Order Book Analysis ─────────────────────────────────────────────────
   Fetches the current live order book for the wallet's most-traded pair.
   Looks for: wall orders (very large single orders dominating depth),
   suspicious size patterns (orders too uniform in size — bot-placed),
   and whether this wallet's open offers match the book.
────────────────────────────────────────────────────────────────────────── */
function analyseLiveOrderBook(liveOrderBook, addr) {
  if (!liveOrderBook || !liveOrderBook.offers?.length) {
    return { signals: [], hasData: false };
  }

  const { pair, offers } = liveOrderBook;
  const signals = [];

  // Total book depth by account
  const accountDepth = new Map();
  for (const o of offers) {
    const acct = o.Account;
    const gets = typeof o.TakerGets === 'string' ? Number(o.TakerGets)/1e6 : Number(o.TakerGets?.value||0);
    accountDepth.set(acct, (accountDepth.get(acct)||0) + gets);
  }
  const totalDepth = [...accountDepth.values()].reduce((s,v)=>s+v,0);

  // Our wallet's share of the book
  const ourDepth = accountDepth.get(addr) || 0;
  const ourShare = totalDepth > 0 ? ourDepth / totalDepth : 0;

  // Wall detection: top order is >40% of total book depth
  const sortedBySize = [...offers].sort((a,b) => {
    const ga = typeof a.TakerGets === 'string' ? Number(a.TakerGets)/1e6 : Number(a.TakerGets?.value||0);
    const gb = typeof b.TakerGets === 'string' ? Number(b.TakerGets)/1e6 : Number(b.TakerGets?.value||0);
    return gb - ga;
  });
  const topOffer = sortedBySize[0];
  const topGets  = typeof topOffer?.TakerGets === 'string' ? Number(topOffer.TakerGets)/1e6 : Number(topOffer?.TakerGets?.value||0);
  const wallShare = totalDepth > 0 ? topGets / totalDepth : 0;

  if (wallShare > 0.4 && topOffer?.Account === addr) {
    signals.push({ sev: 'critical',
      label: `Active wall order: this wallet controls ${(wallShare*100).toFixed(0)}% of current book depth`,
      detail: `A single order from this address represents ${(wallShare*100).toFixed(0)}% of the visible order book depth on pair ${pair}. ` +
              `Large orders placed to make a market look deeper than it is — without intent to fill — is spoofing. ` +
              `This order is live right now.` });
  } else if (wallShare > 0.4) {
    signals.push({ sev: 'warn',
      label: `Wall order present: ${(wallShare*100).toFixed(0)}% of book depth in one order`,
      detail: `A single address controls ${(wallShare*100).toFixed(0)}% of the current order book for pair ${pair}. ` +
              `Wall orders dominate book depth and can be removed instantly — they create false liquidity signals.` });
  }

  if (ourShare > 0.25) {
    signals.push({ sev: 'info',
      label: `This wallet controls ${(ourShare*100).toFixed(0)}% of current order book depth`,
      detail: `${fmt(ourDepth,2)} of ${fmt(totalDepth,2)} total book volume on pair ${pair}.` });
  }

  if (!signals.length) {
    signals.push({ sev: 'ok',
      label: `Live order book looks normal (${offers.length} orders, pair: ${pair.split('↔').map(p=>p.split('+')[0]).join('↔')})`,
      detail: `No wall orders or unusual depth concentration detected in the current order book.` });
  }

  return { signals, hasData: true, pair, offerCount: offers.length, ourShare, wallShare };
}

/* ── Risk Score Breakdown ─────────────────────────────────────────────────────
   Returns a structured breakdown of what drove the overall score.
   Used by the visual breakdown bar in the header.
────────────────────────────────────────────────────────────────────────── */
function buildRiskBreakdown(riskScore, security, drain, nft, wash, benfords, volConc,
    entropy, zipf, timeSeries, granger, fee, inbound, memo) {
  const components = [
    { label: 'Security',       pts: Math.round((100 - security.score) * 0.4),   max: 40,  color: '#ff5555', icon: '🔐' },
    { label: 'Drain Risk',     pts: { low:0, medium:10, high:25, critical:35 }[drain.riskLevel] || 0, max: 35, color: '#ff5555', icon: '⚠️' },
    { label: 'Wash Trading',   pts: Math.min(15, Math.round((wash.score||0) * 0.15)), max: 15, color: '#ffb86c', icon: '📊' },
    { label: 'NFT Risk',       pts: Math.min(15, (nft.flags.filter(f=>f.sev==='critical').length)*8 + (nft.flags.filter(f=>f.sev==='warn').length)*3), max: 15, color: '#bd93f9', icon: '🎨' },
    { label: "Benford's",      pts: benfords?.chiSq > 20.09 ? 10 : benfords?.chiSq > 15.51 ? 5 : 0, max: 10, color: '#f1fa8c', icon: '📐' },
    { label: 'Forensic Suite', pts: Math.min(20,
        Math.min(8,Math.round((entropy?.riskPenalty||0)*0.35)) +
        Math.min(8,Math.round((zipf?.riskPenalty||0)*0.4)) +
        Math.min(8,Math.round((timeSeries?.riskPenalty||0)*0.35)) +
        Math.min(8,Math.round((granger?.riskPenalty||0)*0.35))), max: 20, color: '#00d4ff', icon: '🧬' },
    { label: 'Vol Conc',       pts: Math.min(10, (volConc?.signals?.filter(s=>s.sev==='critical').length||0)*6 + (volConc?.signals?.filter(s=>s.sev==='warn').length||0)*3), max: 10, color: '#ffb86c', icon: '🫧' },
    { label: 'Fee Spikes',     pts: Math.min(5, fee?.riskPenalty||0), max: 5, color: '#ffb86c', icon: '💸' },
  ].filter(c => c.pts > 0);
  return components;
}

/* ─────────────────────────────
   Overall Risk Score
──────────────────────────────── */
function computeOverallRisk(security, drain, nft, wash, benfords, volConc, entropy, zipf, timeSeries, granger, fee = null) {
  let score = 0;

  // Security posture (0–40 pts)
  score += Math.round((100 - security.score) * 0.4);

  // Drain risk (0–35 pts)
  const drainPts = { low: 0, medium: 10, high: 25, critical: 35 };
  score += drainPts[drain.riskLevel] || 0;

  // NFT (0–15 pts)
  const criticalNft = nft.flags.filter(f => f.sev === 'critical').length;
  const warnNft     = nft.flags.filter(f => f.sev === 'warn').length;
  score += Math.min(15, criticalNft * 8 + warnNft * 3);

  // Wash trading (0–15 pts)
  score += Math.min(15, Math.round(wash.score * 0.15));

  // Benford's Law deviation (0–10 pts)
  if (benfords?.chiSq != null) {
    if (benfords.chiSq > 20.09) score += 10;
    else if (benfords.chiSq > 15.51) score += 5;
  }

  // Volume concentration (0–10 pts)
  if (volConc?.signals) {
    const crit = volConc.signals.filter(s => s.sev === 'critical').length;
    const warn = volConc.signals.filter(s => s.sev === 'warn').length;
    score += Math.min(10, crit * 6 + warn * 3);
  }

  // ── Forensic Suite (capped at 20 pts total, scaled) ──
  // Shannon Entropy penalty (0–8)
  if (entropy?.riskPenalty) score += Math.min(8, Math.round(entropy.riskPenalty * 0.35));
  // Zipf's Law penalty (0–8)
  if (zipf?.riskPenalty) score += Math.min(8, Math.round(zipf.riskPenalty * 0.4));
  // Time Series penalty (0–8)
  if (timeSeries?.riskPenalty) score += Math.min(8, Math.round(timeSeries.riskPenalty * 0.35));
  // Granger Causality penalty (0–8)
  if (granger?.riskPenalty) score += Math.min(8, Math.round(granger.riskPenalty * 0.35));

  // Fee spike penalty (coordinated fee elevation = possible orchestrated activity)
  if (fee?.riskPenalty) score += Math.min(5, fee.riskPenalty);

  return Math.min(100, score);
}

/* ═══════════════════════════════════════════════════
   RENDER SECTIONS
═══════════════════════════════════════════════════ */

/* ── Benford's Law Panel ────────────────────────── */
function renderBenfordsPanel(analysis) {
  const body = document.getElementById('inspect-benfords-body');
  if (!body) return;

  const clsBySev = { critical:'sev-critical', warn:'sev-warn', info:'sev-info', ok:'sev-ok' };

  const sigRows = analysis.signals.map(s => `
    <div class="finding finding--${s.sev}">
      <span class="finding-sev ${clsBySev[s.sev] || ''}">${s.sev.toUpperCase()}</span>
      <div class="finding-body">
        <div class="finding-label">${escHtml(s.label)}</div>
        <div class="finding-detail">${escHtml(s.detail)}</div>
      </div>
    </div>`).join('');

  // Digit bar chart (show expected vs observed)
  const bars = analysis.digitBreakdown?.length ? `
    <div class="benford-grid">
      <div class="benford-grid-h">Digit</div>
      <div class="benford-grid-h">Observed</div>
      <div class="benford-grid-h">Expected</div>
      <div class="benford-grid-h">Bar</div>
      ${analysis.digitBreakdown.map(d => {
        const obsN = parseFloat(d.obs), expN = parseFloat(d.exp);
        const delta = obsN - expN;
        const color = Math.abs(delta) > 5 ? '#ff5555' : Math.abs(delta) > 2.5 ? '#ffb86c' : '#50fa7b';
        const bar = `<div style="height:6px;border-radius:3px;background:rgba(255,255,255,.08);overflow:hidden">
          <div style="height:100%;width:${Math.min(100, obsN * 3.3).toFixed(0)}%;background:${color};border-radius:3px"></div>
        </div>`;
        return `<div class="mono" style="text-align:center">${d.digit}</div>
                <div class="mono" style="color:${color}">${d.obs}%</div>
                <div class="mono" style="opacity:.6">${d.exp}%</div>
                <div>${bar}</div>`;
      }).join('')}
    </div>` : '';

  const meta = analysis.chiSq != null
    ? `<div class="wash-stat-row" style="margin-top:8px">
        <span>Sample size</span><span class="mono">${analysis.sampleSize}</span>
       </div>
       <div class="wash-stat-row">
        <span>Chi-squared (χ²)</span>
        <span class="mono ${analysis.chiSq > 20.09 ? 'risk-text-high' : analysis.chiSq > 15.51 ? 'risk-text-med' : ''}">${analysis.chiSq.toFixed(2)}</span>
       </div>
       <div class="wash-stat-row">
        <span>Critical values</span><span class="mono" style="opacity:.6">p&lt;0.05: 15.51 · p&lt;0.01: 20.09</span>
       </div>`
    : '';

  // ── Layman explainer block (always shown) ───────────────────────────────
  const verdict      = analysis.verdict;
  const chiSq        = analysis.chiSq;
  const sampleSize   = analysis.sampleSize;

  let explainIcon  = '📊';
  let explainTitle = "What is Benford\u2019s Law?";
  let explainIntro = "In nature — population sizes, river lengths, stock prices, real financial transactions — the leading (first) digit of numbers is NOT random. The number 1 appears as the first digit about 30% of the time. The number 9 appears only 4.6% of the time. This predictable pattern is Benford's Law.";
  let explainResult = '';
  let explainColor  = 'rgba(255,255,255,.08)';
  let explainBorderColor = 'rgba(255,255,255,.10)';

  if (verdict === 'insufficient') {
    explainResult = `<p class="benford-explain-result">Not enough data yet — we need at least 50 transaction amounts to run this test. This account has ${sampleSize} so far. The more activity, the more reliable the analysis.</p>`;
  } else if (verdict === 'high-deviation') {
    explainIcon  = '🚨';
    explainColor = 'rgba(255,85,85,.06)';
    explainBorderColor = 'rgba(255,85,85,.22)';
    explainResult = `<p class="benford-explain-result">
      <strong style="color:#ff5555">What this means for this account:</strong>
      The transaction amounts here deviate strongly from what you'd expect in real organic activity
      (χ²&nbsp;=&nbsp;${chiSq?.toFixed(1)}, which is above the suspicious threshold of 20.09 at 99% confidence).
    </p>
    <p class="benford-explain-result">
      In plain terms: the mix of numbers being used feels <em>too calculated</em>.
      Real human spending is messy — you buy things for $7.43, $312.50, $1,200 — and the leading digits
      naturally follow Benford's pattern. When a bot or script generates amounts, it tends to use
      suspiciously round numbers, repeat the same values, or avoid certain digits — and that breaks
      the pattern.
    </p>
    <p class="benford-explain-result" style="color:#ffb86c">
      This is a supporting signal, not proof of fraud on its own. Cross-reference with the Wash Trading
      and Volume Concentration sections for a fuller picture.
    </p>`;
  } else if (verdict === 'moderate-deviation') {
    explainIcon  = '⚠';
    explainColor = 'rgba(255,184,108,.05)';
    explainBorderColor = 'rgba(255,184,108,.20)';
    explainResult = `<p class="benford-explain-result">
      <strong style="color:#ffb86c">What this means for this account:</strong>
      There's a moderate mismatch from natural patterns (χ²&nbsp;=&nbsp;${chiSq?.toFixed(1)}).
      This could mean some automated or repeated transactions are mixed in with genuine activity.
      It isn't alarming on its own but is worth watching — especially if other sections also show signals.
    </p>`;
  } else if (verdict === 'normal') {
    explainIcon  = '✅';
    explainColor = 'rgba(80,250,123,.04)';
    explainBorderColor = 'rgba(80,250,123,.15)';
    explainResult = `<p class="benford-explain-result">
      <strong style="color:#50fa7b">What this means for this account:</strong>
      The transaction amounts follow the natural Benford's pattern closely (χ²&nbsp;=&nbsp;${chiSq?.toFixed(1)}).
      This is what you'd expect from organic, real-world financial activity.
      No statistical red flags here.
    </p>`;
  }

  const explainerBlock = `
    <div class="benford-explainer" style="background:${explainColor};border-color:${explainBorderColor}">
      <div class="benford-explainer-head">
        <span class="benford-explainer-icon">${explainIcon}</span>
        <span class="benford-explainer-title">${explainTitle}</span>
      </div>
      <p class="benford-explain-text">
        ${explainIntro}
      </p>
      <div class="benford-explain-visual">
        <div class="benford-visual-row">
          <span class="benford-digit-ex">Digit 1</span>
          <div class="benford-visual-bar" style="width:30.1%;background:rgba(80,250,123,.55)"></div>
          <span class="benford-visual-pct">30.1%</span>
          <span class="benford-visual-note">most common</span>
        </div>
        <div class="benford-visual-row">
          <span class="benford-digit-ex">Digit 5</span>
          <div class="benford-visual-bar" style="width:7.9%;background:rgba(255,184,108,.55)"></div>
          <span class="benford-visual-pct">7.9%</span>
          <span class="benford-visual-note"></span>
        </div>
        <div class="benford-visual-row">
          <span class="benford-digit-ex">Digit 9</span>
          <div class="benford-visual-bar" style="width:4.6%;background:rgba(255,85,85,.55)"></div>
          <span class="benford-visual-pct">4.6%</span>
          <span class="benford-visual-note">least common</span>
        </div>
      </div>
      <p class="benford-explain-text" style="margin-top:6px;opacity:.75">
        When real money moves — payments, trades, escrows — these proportions hold up remarkably well.
        When amounts are <em>generated by a script</em> or deliberately faked, they don't.
        That's why forensic accountants use Benford's Law to detect fraud in financial records.
      </p>
      ${explainResult}
    </div>
  `;

  body.innerHTML = sigRows + meta + bars + explainerBlock;
}

/* ── Volume Concentration Panel ──────────────────── */
function renderVolConcPanel(analysis) {
  const body = document.getElementById('inspect-volconc-body');
  if (!body) return;

  const clsBySev = { critical:'sev-critical', warn:'sev-warn', info:'sev-info', ok:'sev-ok' };

  const sigRows = analysis.signals.map(s => `
    <div class="finding finding--${s.sev}">
      <span class="finding-sev ${clsBySev[s.sev] || ''}">${s.sev.toUpperCase()}</span>
      <div class="finding-body">
        <div class="finding-label">${escHtml(s.label)}</div>
        <div class="finding-detail">${escHtml(s.detail)}</div>
      </div>
    </div>`).join('');

  const table = analysis.concentrations?.length ? `
    <table class="benford-grid" style="margin-top:10px;width:100%">
      <tr style="opacity:.5;font-size:10px">
        <th style="text-align:left">Currency</th>
        <th>Unique actors</th>
        <th>Trades</th>
        <th>Indicator</th>
      </tr>
      ${analysis.concentrations.map(c => {
        const color = c.uniqueActors < 5 ? '#ff5555' : c.uniqueActors < 10 ? '#ffb86c' : '#50fa7b';
        const flag  = c.uniqueActors < 5 ? '🚨 Wash risk' : c.uniqueActors < 10 ? '⚠ Low diversity' : '✓ OK';
        return `<tr>
          <td class="mono" style="padding:3px 0">${escHtml(c.currency.slice(0,10))}</td>
          <td class="mono" style="text-align:center;color:${color}">${c.uniqueActors}</td>
          <td class="mono" style="text-align:center;opacity:.7">${c.trades}</td>
          <td style="font-size:11px;color:${color}">${flag}</td>
        </tr>`;
      }).join('')}
    </table>` : '';

  body.innerHTML = sigRows + table;
}

/* ═══════════════════════════════════════════════════
   FORENSIC ANALYTICS SUITE — INDIVIDUAL PANELS
═══════════════════════════════════════════════════ */

function _renderForensicPanel(bodyId, analysis, metaRows) {
  const body = document.getElementById(bodyId);
  if (!body) return;
  const clsBySev = { critical:'sev-critical', warn:'sev-warn', info:'sev-info', ok:'sev-ok' };
  const sigRows = analysis.signals.map(s => `
    <div class="finding finding--${s.sev}">
      <span class="finding-sev ${clsBySev[s.sev] || ''}">${s.sev.toUpperCase()}</span>
      <div class="finding-body">
        <div class="finding-label">${escHtml(s.label)}</div>
        <div class="finding-detail">${escHtml(s.detail)}</div>
      </div>
    </div>`).join('');
  body.innerHTML = sigRows + (metaRows || '');
}

function _forensicMeta(rows) {
  return `<div class="wash-stat-row" style="margin-top:10px;opacity:.5;font-size:.78rem">
    ${rows.map(([k,v,cls]) => `<span>${k}</span><span class="mono ${cls||''}">${v}</span>`).join('')}
  </div>` + rows.map(([k,v,cls]) => `
    <div class="wash-stat-row">
      <span>${k}</span><span class="mono ${cls||''}">${v}</span>
    </div>`).join('');
}

function renderEntropyPanel(a) {
  const rows = [
    ['Sample size', a.sampleSize],
    ['Amount entropy', a.amountEntropy != null ? a.amountEntropy.toFixed(2) + ' bits' : '—',
      a.amountEntropy != null && a.amountEntropy < 2.0 ? 'risk-text-high' : ''],
    ['Counterparty entropy', a.counterpartyEntropy != null ? a.counterpartyEntropy.toFixed(2) + ' bits' : '—'],
    ['Time-of-day entropy', a.timeEntropy != null ? a.timeEntropy.toFixed(2) + ' bits' : '—'],
    ['Unique counterparties', a.uniqueCounterparties],
    ['Verdict', a.verdict,
      a.verdict === 'anomalous' ? 'risk-text-high' : a.verdict === 'elevated' ? 'risk-text-med' : ''],
  ];
  _renderForensicPanel('inspect-entropy-body', a,
    `<div class="wash-stat-row" style="margin-top:10px"><span>Metric</span><span class="mono" style="opacity:.45">Value</span></div>` +
    rows.map(([k,v,cls]) => `<div class="wash-stat-row"><span>${k}</span><span class="mono ${cls||''}">${v}</span></div>`).join(''));
}

function renderZipfPanel(a) {
  const rows = [
    ['Unique counterparties', a.uniqueCounterparties],
    ['Zipf exponent (s)', a.zipfExponent != null ? a.zipfExponent.toFixed(3) : '—',
      a.zipfExponent != null && (a.zipfExponent < 0.4 || a.zipfExponent > 2.2) ? 'risk-text-high' : ''],
    ['Fit quality (R²)', a.rSquared != null ? a.rSquared.toFixed(3) : '—',
      a.rSquared != null && a.rSquared < 0.55 ? 'risk-text-high' : ''],
    ['Natural range', 's ≈ 0.8–1.3, R² > 0.55'],
    ['Verdict', a.verdict,
      a.verdict === 'anomalous' ? 'risk-text-high' : a.verdict === 'elevated' ? 'risk-text-med' : ''],
  ];

  // Rank-frequency mini chart
  const chartRows = a.freqTable?.slice(0, 10).map((f, i) => {
    const maxF = a.freqTable[0] || 1;
    const pct  = (f / maxF * 100).toFixed(0);
    const zipfExpected = a.freqTable[0] ? (a.freqTable[0] / Math.pow(i+1, a.zipfExponent||1)).toFixed(1) : 0;
    return `<div class="wash-stat-row">
      <span class="mono" style="min-width:28px">Rank ${i+1}</span>
      <div style="flex:1;height:6px;background:rgba(255,255,255,.06);border-radius:3px;overflow:hidden;margin:0 8px">
        <div style="height:100%;width:${pct}%;background:var(--accent);border-radius:3px"></div>
      </div>
      <span class="mono" style="opacity:.6">${f}</span>
    </div>`;
  }).join('') || '';

  _renderForensicPanel('inspect-zipf-body', a,
    rows.map(([k,v,cls]) => `<div class="wash-stat-row" style="margin-top:${k==='Unique counterparties'?10:0}px"><span>${k}</span><span class="mono ${cls||''}">${v}</span></div>`).join('') +
    (chartRows ? `<div style="margin-top:14px;opacity:.75;font-size:.72rem;letter-spacing:.08em;color:rgba(255,255,255,.45);margin-bottom:6px">COUNTERPARTY RANK–FREQUENCY</div>${chartRows}` : ''));
}

function renderTimeSeriesPanel(a) {
  const rows = [
    ['Transactions timed', a.totalTimestamped || '—'],
    ['Active span', a.activeSpanDays != null ? a.activeSpanDays + ' days' : '—'],
    ['Interval CV', a.intervalCV != null ? a.intervalCV.toFixed(3) : '—',
      a.intervalCV != null && a.intervalCV < 0.5 ? 'risk-text-high' : ''],
    ['Periodicity score', a.periodicityScore != null ? (a.periodicityScore*100).toFixed(0)+'%' : '—',
      a.periodicityScore > 0.55 ? 'risk-text-high' : ''],
    ['Burst score (z)', a.burstScore != null ? a.burstScore.toFixed(2) : '—'],
    ['Lag-1 autocorrelation', a.autocorrelation != null ? a.autocorrelation.toFixed(3) : '—',
      a.autocorrelation > 0.6 ? 'risk-text-med' : ''],
    ['Day-of-week entropy', a.dowEntropy != null ? a.dowEntropy.toFixed(2)+' bits' : '—'],
    ['Verdict', a.verdict,
      a.verdict === 'bot-pattern' ? 'risk-text-high' : a.verdict === 'elevated' ? 'risk-text-med' : ''],
  ];

  // Day-of-week mini chart
  const days = ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'];
  const maxDow = a.dowBins ? Math.max(...a.dowBins, 1) : 1;
  const dowChart = a.dowBins ? `
    <div style="margin-top:14px;opacity:.75;font-size:.72rem;letter-spacing:.08em;color:rgba(255,255,255,.45);margin-bottom:6px">DAY-OF-WEEK DISTRIBUTION</div>
    <div style="display:flex;gap:5px;align-items:flex-end;height:42px">
      ${a.dowBins.map((v, i) => `
        <div style="flex:1;display:flex;flex-direction:column;align-items:center;gap:3px">
          <div style="width:100%;height:${(v/maxDow*36).toFixed(0)}px;background:rgba(0,212,255,.35);border-radius:2px 2px 0 0;min-height:2px"></div>
          <div style="font-size:.6rem;opacity:.5">${days[i]}</div>
        </div>`).join('')}
    </div>` : '';

  _renderForensicPanel('inspect-timeseries-body', a,
    rows.map(([k,v,cls]) => `<div class="wash-stat-row" style="margin-top:${k==='Transactions timed'?10:0}px"><span>${k}</span><span class="mono ${cls||''}">${v}</span></div>`).join('') +
    dowChart);
}

function renderGrangerPanel(a) {
  const oc = a.offerCancelCausality;
  const io = a.inflowOutflowCausality;

  const ccfBars = (ccf, label) => {
    if (!ccf?.length) return '';
    const maxV = Math.max(0.01, ...ccf.map(Math.abs));
    return `<div style="margin-top:12px;opacity:.75;font-size:.72rem;letter-spacing:.08em;color:rgba(255,255,255,.45);margin-bottom:6px">${label}</div>
    <div style="display:flex;gap:4px;align-items:flex-end;height:40px">
      ${ccf.map((v, lag) => {
        const h = (Math.abs(v)/maxV*36).toFixed(0);
        const c = v > 0.5 ? 'rgba(255,85,85,.7)' : v > 0.3 ? 'rgba(255,184,108,.6)' : 'rgba(0,212,255,.3)';
        return `<div style="flex:1;display:flex;flex-direction:column;align-items:center;gap:3px">
          <div style="width:100%;height:${h}px;background:${c};border-radius:2px 2px 0 0;min-height:2px"></div>
          <div style="font-size:.6rem;opacity:.5">L${lag}</div>
        </div>`;
      }).join('')}
    </div>`;
  };

  const rows = [
    ['Time windows', a.windowCount || '—'],
    ['OfferCreate→Cancel ρ', oc ? oc.maxCorr.toFixed(3) : '—', oc && oc.maxCorr > 0.55 ? 'risk-text-high' : ''],
    ['OC lag', oc ? `${oc.maxLag} window${oc.maxLag===1?'':'s'} (${oc.maxLag*12}h)` : '—'],
    ['Inflow→Outflow ρ', io ? io.maxCorr.toFixed(3) : '—', io && io.maxCorr > 0.65 ? 'risk-text-high' : ''],
    ['IO lag', io ? `${io.maxLag} window${io.maxLag===1?'':'s'}` : '—'],
    ['Verdict', a.verdict, a.verdict === 'causal-signal' ? 'risk-text-high' : a.verdict === 'elevated' ? 'risk-text-med' : ''],
  ];

  _renderForensicPanel('inspect-granger-body', a,
    rows.map(([k,v,cls]) => `<div class="wash-stat-row" style="margin-top:${k==='Time windows'?10:0}px"><span>${k}</span><span class="mono ${cls||''}">${v}</span></div>`).join('') +
    ccfBars(oc?.ccf, 'OFFER-CREATE → CANCEL CROSS-CORRELATION') +
    ccfBars(io?.ccf, 'INFLOW → OUTFLOW CROSS-CORRELATION'));
}

/* ── Forensic Analytics Suite — Combined Report ──── */
function renderForensicSuitePanel(benfords, entropy, zipf, timeSeries, granger) {
  const body = document.getElementById('inspect-forensic-suite-body');
  if (!body) return;

  const score = (a, max = 25) => {
    if (!a || a.verdict === 'insufficient') return null;
    // normalize riskPenalty (or chiSq for Benford) to 0-max
    if (a.chiSq != null) {
      // Benford
      if (a.verdict === 'high-deviation') return { val: max, cls: 'risk-text-high', label: 'HIGH DEVIATION' };
      if (a.verdict === 'moderate-deviation') return { val: Math.round(max * 0.5), cls: 'risk-text-med', label: 'MODERATE' };
      return { val: 0, cls: '', label: 'NORMAL' };
    }
    const v = a.riskPenalty || 0;
    if (v >= 18) return { val: max, cls: 'risk-text-high', label: 'ANOMALOUS' };
    if (v >= 8)  return { val: Math.round(max * 0.5), cls: 'risk-text-med', label: 'ELEVATED' };
    return { val: 0, cls: '', label: 'NORMAL' };
  };

  const engines = [
    { name: "Benford's Law",     icon: '📐', desc: 'First-digit digit distribution vs log-uniform expected',                      s: score(benfords)      },
    { name: "Shannon's Entropy", icon: '🔀', desc: 'Randomness of amounts, counterparties, time-of-day, tx types',               s: score(entropy)       },
    { name: "Zipf's Law",        icon: '📈', desc: 'Counterparty rank-frequency power-law fit',                                   s: score(zipf)          },
    { name: "Time Series",       icon: '🕐', desc: 'Interval regularity, periodicity, burst detection, autocorrelation',          s: score(timeSeries)    },
    { name: "Granger Causality", icon: '🔗', desc: 'Lead-lag temporal causality: create→cancel, inflow→outflow',                 s: score(granger)       },
  ];

  const anySignal   = engines.some(e => e.s && e.s.val > 0);
  const highCount   = engines.filter(e => e.s?.cls === 'risk-text-high').length;
  const medCount    = engines.filter(e => e.s?.cls === 'risk-text-med').length;
  const missingData = engines.filter(e => !e.s).length;

  // ── Overall verdict ────────────────────────────────
  let suiteVerdict, suiteColor, suiteIcon;
  if (highCount >= 3) {
    suiteVerdict = 'STRONG MANIPULATION SIGNALS — Multiple independent engines converging on anomalous patterns.';
    suiteColor = '#ff5555'; suiteIcon = '🚨';
  } else if (highCount >= 2 || (highCount >= 1 && medCount >= 2)) {
    suiteVerdict = 'SIGNIFICANT ANOMALIES — At least two engines detect non-organic behavior. Cross-reference with Wash Trading and Drain Risk.';
    suiteColor = '#ff5555'; suiteIcon = '⚠️';
  } else if (highCount >= 1 || medCount >= 2) {
    suiteVerdict = 'ELEVATED RISK — One or more engines flag behavioral anomalies. Investigate the specific modules for detail.';
    suiteColor = '#ffb86c'; suiteIcon = '⚠️';
  } else if (!anySignal && missingData < 3) {
    suiteVerdict = 'NO ANOMALIES — All five engines return results consistent with organic financial activity.';
    suiteColor = '#50fa7b'; suiteIcon = '✅';
  } else {
    suiteVerdict = 'INSUFFICIENT DATA — More transaction history needed for a reliable multi-engine assessment.';
    suiteColor = 'rgba(255,255,255,.4)'; suiteIcon = '📊';
  }

  // ── Engine score cards ─────────────────────────────
  const engineCards = engines.map(e => {
    const noData = !e.s;
    const color  = noData ? 'rgba(255,255,255,.25)' : e.s.val === 0 ? '#50fa7b' : e.s.cls === 'risk-text-high' ? '#ff5555' : '#ffb86c';
    const label  = noData ? 'NO DATA' : e.s.label;
    const barPct = noData ? 0 : e.s.val === 0 ? 4 : e.s.cls === 'risk-text-high' ? 100 : 55;
    return `<div style="background:rgba(255,255,255,.025);border:1px solid rgba(255,255,255,.07);border-radius:12px;padding:14px 14px 12px">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
        <span style="font-size:1.05rem">${e.icon}</span>
        <div style="flex:1">
          <div style="font-size:.82rem;font-weight:700;color:rgba(255,255,255,.85)">${e.name}</div>
          <div style="font-size:.7rem;color:rgba(255,255,255,.35);margin-top:1px;line-height:1.4">${e.desc}</div>
        </div>
      </div>
      <div style="display:flex;align-items:center;gap:8px">
        <div style="flex:1;height:5px;background:rgba(255,255,255,.08);border-radius:3px;overflow:hidden">
          <div style="height:100%;width:${barPct}%;background:${color};border-radius:3px;transition:width .6s ease"></div>
        </div>
        <span style="font-size:.65rem;font-weight:800;color:${color};min-width:80px;text-align:right;letter-spacing:.06em">${label}</span>
      </div>
    </div>`;
  }).join('');

  // ── Convergence narrative ──────────────────────────
  const convergingEngines = engines.filter(e => e.s && e.s.val > 0);
  let narrative = '';
  if (convergingEngines.length >= 2) {
    narrative = `<div style="background:rgba(255,184,108,.05);border:1px solid rgba(255,184,108,.2);border-radius:12px;padding:14px 16px;margin-top:14px">
      <div style="font-size:.68rem;font-weight:900;color:#ffb86c;letter-spacing:.12em;text-transform:uppercase;margin-bottom:8px">⚡ Convergence Analysis</div>
      <p style="font-size:.84rem;color:rgba(255,255,255,.65);line-height:1.7;margin:0">
        ${convergingEngines.map(e => e.name).join(' and ')} are all flagging behavioral anomalies.
        When multiple independent statistical methods converge on the same conclusion — each using
        different mathematical principles — the combined signal is substantially stronger than any
        single engine alone. This convergence reduces the probability that the findings are false positives
        from sample-specific artifacts or edge cases.
        ${highCount >= 2 ? ' The strength and breadth of these signals warrants serious investigation.' : ' Monitor alongside the Wash Trading and Security modules for a complete picture.'}
      </p>
    </div>`;
  } else if (anySignal) {
    narrative = `<div style="background:rgba(0,212,255,.04);border:1px solid rgba(0,212,255,.12);border-radius:12px;padding:14px 16px;margin-top:14px">
      <p style="font-size:.84rem;color:rgba(255,255,255,.55);line-height:1.7;margin:0">
        Only one engine is currently flagging anomalies. A single-engine signal is a hypothesis, not a conclusion.
        Cross-reference with Wash Trading, Benford's Law, and Drain Risk modules to determine whether
        the pattern is isolated or part of a broader behavioral signature.
      </p>
    </div>`;
  } else {
    narrative = `<div style="background:rgba(80,250,123,.04);border:1px solid rgba(80,250,123,.12);border-radius:12px;padding:14px 16px;margin-top:14px">
      <p style="font-size:.84rem;color:rgba(255,255,255,.55);line-height:1.7;margin:0">
        No engine in the forensic suite has flagged this account.
        The five methods use independent mathematical frameworks —
        digit distribution (Benford), information theory (entropy), power laws (Zipf),
        temporal statistics (time series), and causal inference (Granger).
        Agreement across all five is a strong indicator of organic activity.
      </p>
    </div>`;
  }

  body.innerHTML = `
    <div style="background:rgba(${suiteColor==='#ff5555'?'255,85,85':'255,255,255'},.04);border:1px solid rgba(${suiteColor==='#ff5555'?'255,85,85':'255,255,255'},.15);border-radius:12px;padding:14px 16px;margin-bottom:14px;display:flex;align-items:flex-start;gap:12px">
      <span style="font-size:1.4rem;flex-shrink:0;margin-top:2px">${suiteIcon}</span>
      <div>
        <div style="font-size:.68rem;font-weight:900;letter-spacing:.12em;text-transform:uppercase;color:${suiteColor};margin-bottom:5px">FORENSIC SUITE VERDICT</div>
        <p style="font-size:.88rem;color:rgba(255,255,255,.7);line-height:1.65;margin:0">${suiteVerdict}</p>
      </div>
    </div>
    <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:10px">
      ${engineCards}
    </div>
    ${narrative}
    <div style="margin-top:16px;padding:12px 14px;background:rgba(255,255,255,.02);border-radius:10px;border:1px solid rgba(255,255,255,.05)">
      <div style="font-size:.68rem;font-weight:900;letter-spacing:.12em;color:rgba(255,255,255,.3);text-transform:uppercase;margin-bottom:6px">How to read this suite</div>
      <p style="font-size:.78rem;color:rgba(255,255,255,.4);line-height:1.7;margin:0">
        Each engine is mathematically independent. A single flag could be a false positive from small samples or edge-case data.
        Two or more flags converging is a meaningful signal. Three or more is strong evidence of non-organic behavior.
        None of these engines constitute legal proof — they are forensic intelligence to guide further investigation.
      </p>
    </div>`;
}

/* ── Header / Overview ───────────────────────────── */
function renderHeader(addr, acct, balXrp, reserve, ownerCnt, sequence, riskScore, walletAgeDays = null, walletCreatedTs = null) {
  // Address badge: display shortened, full addr in title + dataset for copy
  const badge = $('inspect-addr-badge');
  if (badge) {
    badge.textContent = addr.length > 20 ? addr.slice(0,10) + '…' + addr.slice(-8) : addr;
    badge.title = addr;
    badge.dataset.fullAddr = addr;
  }

  // Risk score
  const scoreEl = $('inspect-risk-score');
  if (scoreEl) {
    scoreEl.textContent = riskScore;
    scoreEl.className = 'irb-score-val ' + riskScoreClass(riskScore);
  }
  const scoreLabelEl = $('inspect-risk-label');
  if (scoreLabelEl) {
    scoreLabelEl.textContent = riskScore < 20 ? 'Low Risk'
      : riskScore < 45 ? 'Moderate'
      : riskScore < 70 ? 'High Risk'
      : 'Critical';
    scoreLabelEl.className = 'irb-score-label ' + riskScoreClass(riskScore);
  }

  // Account grid
  const grid = $('inspect-acct-grid');
  if (!grid) return;

  const spendable = Math.max(0, balXrp - reserve);
  const flags = Number(acct.Flags || 0);

  // Wallet age string
  const ageStr = walletAgeDays != null
    ? walletAgeDays === 0 ? 'Created today'
    : walletAgeDays === 1 ? '1 day old'
    : walletAgeDays < 30  ? `${walletAgeDays} days old`
    : walletAgeDays < 365 ? `${Math.floor(walletAgeDays / 30)} months old`
    : `${(walletAgeDays / 365).toFixed(1)} years old`
    : '—';

  const createdStr = walletCreatedTs
    ? new Date(walletCreatedTs).toLocaleDateString('en-US', { year:'numeric', month:'short', day:'numeric' })
    : null;

  const usdBalance   = _usd(balXrp);
  const usdSpendable = _usd(spendable);

  const cells = [
    { label: 'XRP Balance',  value: `${fmt(balXrp, 6)} XRP${usdBalance}`,   mono: true },
    { label: 'Spendable',    value: `${fmt(spendable, 6)} XRP${usdSpendable}`, mono: true, note: `${reserve} XRP reserved` },
    { label: 'Wallet Age',   value: ageStr,
      note: createdStr ? `Created ${createdStr}` : null,
      highlight: walletAgeDays != null && walletAgeDays < 7 ? 'new' : null },
    { label: 'Owner Count',  value: ownerCnt,                                  note: `${ownerCnt * 2} XRP tied up` },
    { label: 'Sequence',     value: sequence,                                  mono: true },
    { label: 'Regular Key',  value: acct.RegularKey ? shortAddr(acct.RegularKey) : 'None',
      warn: !!acct.RegularKey, mono: true },
    { label: 'Master Key',   value: (flags & FLAGS.lsfDisableMaster) ? 'Disabled' : 'Active',
      warn: !!(flags & FLAGS.lsfDisableMaster) },
  ];

  grid.innerHTML = cells.map(c => `
    <div class="acct-cell ${c.warn ? 'acct-cell--warn' : ''} ${c.highlight === 'new' ? 'acct-cell--new' : ''}">
      <div class="acct-cell-label">${escHtml(c.label)}</div>
      <div class="acct-cell-value ${c.mono ? 'mono' : ''}">${escHtml(String(c.value))}</div>
      ${c.note ? `<div class="acct-cell-note">${escHtml(c.note)}</div>` : ''}
      ${c.highlight === 'new' ? '<div class="acct-cell-new-badge">⚠ New wallet</div>' : ''}
    </div>`).join('');
}

/* ── Security Audit ──────────────────────────────── */
function renderSecurityAudit(audit, acct, flags, signerLists, depositAuths) {
  const el = $('inspect-security-body');
  if (!el) return;

  const decodedFlags = Object.entries(FLAGS)
    .filter(([, bit]) => flags & bit)
    .map(([name]) => name.replace('lsf', ''));

  el.innerHTML = `
    <div class="audit-items">
      ${audit.findings.map(f => auditRow(f)).join('')}
    </div>
    ${decodedFlags.length ? `
    <div class="audit-flags">
      <div class="audit-flags-label">Active Flags</div>
      <div class="audit-flags-pills">
        ${decodedFlags.map(f => `<span class="flag-pill">${escHtml(f)}</span>`).join('')}
      </div>
    </div>` : ''}
    ${signerLists.length ? `
    <div class="signer-list-block">
      <div class="signer-list-title">Signer List (Multisig)</div>
      ${signerLists.map(sl => `
        <div class="signer-entries">
          ${(sl.SignerEntries || []).map(e => `
            <div class="signer-entry">
              <span class="signer-addr mono">${escHtml(e.SignerEntry?.Account || '—')}</span>
              <span class="signer-weight">weight ${e.SignerEntry?.SignerWeight || 1}</span>
            </div>`).join('')}
          <div class="signer-quorum">Quorum: ${sl.SignerQuorum}</div>
        </div>`).join('')}
    </div>` : ''}
    ${depositAuths.length ? `
    <div class="audit-note">
      <span class="audit-note-label">DepositPreauth grants:</span>
      ${depositAuths.slice(0, 8).map(d => `<span class="mono">${shortAddr(d.Authorize || '')}</span>`).join(', ')}
      ${depositAuths.length > 8 ? `+${depositAuths.length - 8} more` : ''}
    </div>` : ''}
  `;
  _setBadge('badge-security', audit.findings);
}

/* ── Drain Analysis ──────────────────────────────── */
function renderDrainAnalysis(drain, paychans, escrows, checks) {
  const el = $('inspect-drain-body');
  if (!el) return;

  const levelColors = { low: '#50fa7b', medium: '#ffb86c', high: '#ff8c42', critical: '#ff5555' };
  const levelIcons  = { low: '✓', medium: '⚠', high: '⚠', critical: '⛔' };

  el.innerHTML = `
    <div class="drain-level drain-level--${drain.riskLevel}">
      <span class="drain-level-icon">${levelIcons[drain.riskLevel]}</span>
      <span class="drain-level-text">Drain Risk: <strong>${drain.riskLevel.toUpperCase()}</strong></span>
    </div>
    <div class="audit-items">
      ${drain.signals.map(s => auditRow(s)).join('')}
    </div>
    ${paychans.length ? `
    <div class="drain-sub-section">
      <div class="drain-sub-title">Open Payment Channels</div>
      ${paychans.map(p => `
        <div class="drain-channel-row">
          <span class="mono">${shortAddr(p.Destination)}</span>
          <span>${fmt(Number(p.Amount || 0) / 1e6, 2)} XRP allocated</span>
          <span>${fmt(Number(p.Balance || 0) / 1e6, 2)} XRP claimed</span>
        </div>`).join('')}
    </div>` : ''}
    ${escrows.length ? `
    <div class="drain-sub-section">
      <div class="drain-sub-title">Open Escrows</div>
      ${escrows.slice(0, 5).map(e => `
        <div class="drain-channel-row">
          <span>${e.Destination ? shortAddr(e.Destination) : 'self'}</span>
          <span>${fmt(Number(e.Amount || 0) / 1e6, 2)} XRP</span>
          <span class="mono">${e.Condition ? 'conditional' : e.FinishAfter ? 'time-locked' : ''}</span>
        </div>`).join('')}
    </div>` : ''}
  `;
  _setBadgeDrainLevel('badge-drain', drain.riskLevel);
}

/* ── NFT Panel ───────────────────────────────────── */
function renderNftPanel(nftAnalysis, nfts) {
  const el = $('inspect-nft-body');
  if (!el) return;

  el.innerHTML = `
    <div class="audit-items">
      ${nftAnalysis.flags.map(f => auditRow(f)).join('')}
    </div>
    ${nfts.length ? `
    <div class="nft-grid">
      ${nfts.slice(0, 12).map(n => nftCard(n)).join('')}
    </div>
    ${nfts.length > 12 ? `<div class="nft-more">+${nfts.length - 12} more NFTs</div>` : ''}
    ` : ''}
  `;
  _setBadge('badge-nft', nftAnalysis.flags);
}

function nftCard(n) {
  const flags = Number(n.Flags || 0);
  const transferable = !!(flags & NFT_FLAGS.lsfTransferable);
  const burnable     = !!(flags & NFT_FLAGS.lsfBurnable);
  const taxon = n.NFTokenTaxon || 0;
  const fee   = n.TransferFee  ? `${(n.TransferFee / 1000).toFixed(1)}%` : '0%';
  return `
    <div class="nft-card">
      <div class="nft-id mono">${n.NFTokenID ? shortAddr(n.NFTokenID) : '—'}</div>
      <div class="nft-meta">
        <span class="nft-badge ${transferable ? 'nft-badge--ok' : 'nft-badge--warn'}">
          ${transferable ? 'Transferable' : 'Non-transferable'}
        </span>
        ${burnable ? '<span class="nft-badge nft-badge--info">Burnable</span>' : ''}
      </div>
      <div class="nft-details">
        <span>Taxon: ${taxon}</span>
        <span>Fee: ${fee}</span>
      </div>
      ${n.Issuer && n.Issuer !== n.Account ? `<div class="nft-issuer mono">Issuer: ${shortAddr(n.Issuer)}</div>` : ''}
    </div>`;
}

/* ── Wash Trading Panel ──────────────────────────── */
function renderWashPanel(wash) {
  const el = $('inspect-wash-body');
  if (!el) return;

  const verdictColor = wash.verdict === 'clean'    ? '#50fa7b'
    : wash.verdict === 'low-risk'   ? '#50fa7b'
    : wash.verdict === 'suspicious' ? '#ffb86c'
    : '#ff5555';

  el.innerHTML = `
    <div class="wash-header">
      <div class="wash-score-wrap">
        <div class="wash-score-bar">
          <div class="wash-score-fill" style="width:${wash.score}%;background:${verdictColor}"></div>
        </div>
        <div class="wash-score-labels">
          <span>Clean</span>
          <span style="color:${verdictColor};font-weight:900">${wash.verdict.replace('-', ' ').toUpperCase()} (${wash.score}/100)</span>
          <span>Certain</span>
        </div>
      </div>
    </div>
    <div class="wash-stats">
      ${washStat('Offer Creates', wash.stats.creates)}
      ${washStat('Offer Cancels', wash.stats.cancels)}
      ${washStat('Filled Offers', wash.stats.fills)}
      ${washStat('Payments', wash.stats.payments)}
      ${washStat('Round-trip Counterparties', wash.stats.roundTrip)}
    </div>
    <div class="audit-items">
      ${wash.signals.map(s => auditRow(s)).join('')}
    </div>
  `;
  const wb = $('badge-wash');
  if (wb) { const vc2 = wash.verdict==='clean'||wash.verdict==='low-risk' ? 'ok' : wash.verdict==='suspicious' ? 'warn' : 'crit'; wb.textContent=wash.verdict.replace('-',' '); wb.className='section-badge section-badge--'+vc2; }
}

function washStat(label, val) {
  return `<div class="wash-stat"><span class="wash-stat-label">${escHtml(label)}</span><span class="wash-stat-val">${val}</span></div>`;
}

/* ── Token Issuer Panel ──────────────────────────── */
function renderIssuerPanel(issuer, lines) {
  const el = $('inspect-issuer-body');
  if (!el) return;

  const tokenLines = lines.filter(l => l.currency && (l.currency.length === 3 || l.currency.length === 40));

  el.innerHTML = `
    <div class="audit-items">
      ${issuer.signals.map(s => auditRow(s)).join('')}
    </div>
    ${tokenLines.length ? `
    <div class="trustline-list">
      ${tokenLines.slice(0, 10).map(l => `
        <div class="trustline-row">
          <span class="trustline-currency">${escHtml(hexToAscii(l.currency))}</span>
          <span class="trustline-issuer mono">${shortAddr(l.account)}</span>
          <span class="trustline-balance ${Number(l.balance) < 0 ? 'trustline-owed' : ''} mono">
            ${Number(l.balance) < 0 ? '▼ ' : ''}${fmt(Math.abs(Number(l.balance)), 2)}
            ${l.freeze ? '<span class="trustline-frozen">FROZEN</span>' : ''}
            ${l.freeze_peer ? '<span class="trustline-frozen trustline-frozen--peer">FROZEN BY ISSUER</span>' : ''}
          </span>
        </div>`).join('')}
      ${tokenLines.length > 10 ? `<div class="trustline-more">+${tokenLines.length - 10} more trustlines</div>` : ''}
    </div>` : ''}
  `;
  _setBadge('badge-issuer', issuer.signals);
}

/* ── AMM Panel ───────────────────────────────────── */
function renderAmmPanel(amm, lines) {
  const el = $('inspect-amm-body');
  if (!el) return;

  el.innerHTML = `
    <div class="audit-items">
      ${amm.signals.map(s => auditRow(s)).join('')}
    </div>
    ${amm.positions.length ? `
    <div class="amm-positions">
      ${amm.positions.map(p => `
        <div class="amm-position-card">
          <div class="amm-position-currency mono">${shortAddr(p.currency)}</div>
          <div class="amm-position-meta">
            <span>Pool: ${shortAddr(p.issuer)}</span>
            <span class="amm-position-balance">${fmt(Math.abs(p.balance), 4)} LP tokens</span>
          </div>
        </div>`).join('')}
    </div>` : ''}
  `;
  _setBadge('badge-amm', amm.signals);
}

/* ── Trustlines ──────────────────────────────────── */
function renderTrustlines(lines) {
  const badge = $('trust-count-badge');
  if (badge) badge.textContent = lines.length;

  const tbody = $('inspect-trust-body');
  if (!tbody) return;

  tbody.innerHTML = lines.length
    ? lines.map(l => {
        const frozen   = l.freeze        ? '<span class="trustline-frozen">Frozen</span>' : '';
        const peerFrz  = l.freeze_peer   ? '<span class="trustline-frozen trustline-frozen--peer">Issuer Frozen</span>' : '';
        const noRipple = l.no_ripple     ? '<span class="trustline-norip">NoRipple</span>' : '';
        return `
          <div class="trustline-row">
            <span class="trustline-currency">${escHtml(hexToAscii(l.currency))}</span>
            <span class="trustline-issuer mono">${shortAddr(l.account)}</span>
            <span class="trustline-balance mono">${escHtml(l.balance)} / ${escHtml(l.limit)}</span>
            <span class="trustline-flags">${frozen}${peerFrz}${noRipple}</span>
          </div>`;
      }).join('')
    : `<div class="inspect-empty-note">No trustlines found.</div>`;
}

/* ── Transaction Timeline ────────────────────────── */
function renderTxTimeline(txList, addr) {
  const el = $('inspect-tx-timeline');
  if (!el) return;

  const SHOW = 60;
  const items = txList.slice(0, SHOW);

  const txBadgeEl = $('badge-tx'); if (txBadgeEl) { txBadgeEl.textContent = txList.length + ' tx'; txBadgeEl.className = 'section-badge section-badge--neutral'; }
  el.innerHTML = items.length
    ? items.map(({ tx, meta }) => {
        const type    = tx.TransactionType || 'Unknown';
        const success = meta?.TransactionResult === 'tesSUCCESS';
        const risk    = txRiskLevel(tx, meta, addr);
        const ts      = getCloseTime(tx);
        const timeStr = ts ? new Date(ts * 1000).toLocaleString() : '—';
        const brief   = txBrief(tx, addr);

        const hashShort = tx.hash ? tx.hash.slice(0, 8) + '…' + tx.hash.slice(-4) : '';
        const explorerUrl = tx.hash ? `https://livenet.xrpl.org/transactions/${tx.hash}` : null;
        const xrpscanUrl  = tx.hash ? `https://xrpscan.com/tx/${tx.hash}` : null;
        return `
          <div class="tx-row tx-row--${risk}">
            <span class="tx-type-badge tx-type-badge--${typeBadgeClass(type)}">${escHtml(type)}</span>
            <span class="tx-brief">${brief}</span>
            <span class="tx-result ${success ? 'tx-ok' : 'tx-fail'}">${success ? '✓' : '✗'}</span>
            <span class="tx-time">${timeStr}</span>
            ${explorerUrl ? `<span class="tx-links">
              <a href="${explorerUrl}" target="_blank" rel="noopener" class="tx-explorer-link" title="View on XRPL Livenet">🔗</a>
              <a href="${xrpscanUrl}" target="_blank" rel="noopener" class="tx-explorer-link" title="View on XRPScan">🔍</a>
            </span>` : ''}
          </div>`;
      }).join('')
    : `<div class="inspect-empty-note">No transactions found.</div>`;

  if (txList.length > SHOW) {
    el.innerHTML += `<div class="tx-more">Showing ${SHOW} of ${txList.length} transactions</div>`;
  }
}


/* ── Fund Flow Panel ─────────────────────────────── */
function renderFundFlowPanel(flow) {
  const el = $('inspect-fundflow-body');
  if (!el) return;

  const badge = $('badge-fundflow');

  if (!flow.timeline.length && !flow.destinations.length) {
    el.innerHTML = `<div class="audit-row audit-row--ok"><span class="audit-icon">✓</span><div class="audit-text"><div class="audit-label">No outbound payments found in analysed transaction history</div></div></div>`;
    if (badge) { badge.textContent = 'Clear'; badge.className = 'section-badge section-badge--ok'; }
    return;
  }

  const exchangeAlert = flow.exchangeDests.length
    ? `<div class="flow-alert flow-alert--exchange">💱 Funds reached ${flow.exchangeDests.length} known exchange(s): ${flow.exchangeDests.map(d => d.entity.name).join(', ')}</div>`
    : '';
  const blackholeAlert = flow.blackHoleDests.length
    ? `<div class="flow-alert flow-alert--blackhole">🕳 Funds sent to black hole address — irrecoverable!</div>`
    : '';
  const newWalletAlert = flow.newWalletDests?.length
    ? `<div class="flow-alert" style="background:rgba(255,85,85,.06);border:1px solid rgba(255,85,85,.25);color:#ff5555;border-radius:8px;padding:10px 14px;margin-bottom:8px">
        ⚠️ <strong>${flow.newWalletDests.length} destination(s) are brand-new wallets</strong> (Sequence &lt; 10) receiving large XRP amounts.
        New wallets receiving large transfers shortly after creation are a common pattern in drain attacks — the attacker creates a disposable wallet and drains funds there.
       </div>`
    : '';

  el.innerHTML = `
    ${newWalletAlert}${exchangeAlert}${blackholeAlert}
    <div class="flow-summary">
      <div class="flow-stat"><span>Unique destinations</span><b>${flow.uniqueDests}</b></div>
      <div class="flow-stat"><span>Total XRP out</span><b class="mono">${fmt(flow.totalOut, 2)}</b></div>
      <div class="flow-stat"><span>Path payments</span><b>${flow.totalPathPay}</b></div>
      <div class="flow-stat"><span>Exchange dests</span><b>${flow.exchangeDests.length}</b></div>
    </div>

    <div class="flow-section-h">📍 Top Destinations</div>
    <div class="flow-dest-list">
      ${flow.destinations.map((d, i) => {
        const pct = flow.totalOut > 0 ? (d.totalXrp / flow.totalOut * 100) : 0;
        const entityBadge = d.entity
          ? `<span class="flow-entity-badge flow-entity--${d.entity.type}">${escHtml(d.entity.name)}</span>`
          : '';
        const pathBadge = d.pathCount > 0
          ? `<span class="flow-path-badge">${d.maxHops}-hop path ×${d.pathCount}</span>`
          : '';
        const tokenChips = d.tokens.slice(0,2).map(t => `<span class="flow-token-chip">${escHtml(t.k.split('.')[0])}</span>`).join('');
        return `
          <div class="flow-dest-row">
            <div class="flow-dest-rank ${d.entity?.type === 'exchange' ? 'flow-rank--exchange' : d.entity?.type === 'blackhole' ? 'flow-rank--blackhole' : ''}">${i+1}</div>
            <div class="flow-dest-info">
              <div class="flow-dest-top">
                <button class="addr-link mono cut flow-dest-addr" data-addr="${escHtml(d.addr)}" title="${escHtml(d.addr)}">${escHtml(shortAddr(d.addr))}</button>
                <a href="https://xrpscan.com/account/${escHtml(d.addr)}" target="_blank" rel="noopener" class="tx-explorer-link" title="View on XRPScan">🔍</a>
                ${entityBadge}${pathBadge}${tokenChips}
              </div>
              <div class="flow-bar-row">
                <div class="flow-dest-bar"><div class="flow-dest-fill" style="width:${Math.min(100,pct).toFixed(1)}%;background:${d.entity?.type === 'exchange' ? '#00d4ff' : d.entity?.type === 'blackhole' ? '#ff5555' : 'rgba(80,250,123,.7)'}"></div></div>
                <span class="mono flow-dest-pct">${pct.toFixed(0)}%</span>
              </div>
              <div class="flow-dest-meta">
                <span class="mono">${fmt(d.totalXrp, 2)} XRP</span>
                <span class="flow-dest-cnt">${d.txCount} tx</span>
                ${d.txCount > 1 ? `<span class="flow-dest-span">${_fmtDateRange(d.firstSeen, d.lastSeen)}</span>` : ''}
              </div>
            </div>
          </div>`;
      }).join('')}
    </div>

    <div class="flow-section-h" style="margin-top:18px">⏱ Outflow Timeline</div>
    <div class="flow-timeline">
      ${flow.timeline.map(o => {
        const date  = new Date((o.ts) * 1000).toLocaleDateString();
        const time  = new Date((o.ts) * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        const amt   = o.amtXrp > 0 ? `${fmt(o.amtXrp, 2)} XRP` : (o.amtToken ? `${fmt(o.amtToken.value, 2)} ${o.amtToken.currency}` : '—');
        const ent   = getEntity(o.dest);
        const entityTag = ent ? `<span class="flow-entity-badge flow-entity--${ent.type}" style="font-size:.65rem">${escHtml(ent.name)}</span>` : '';
        return `
          <div class="flow-tx-row">
            <span class="flow-tx-date">${date} ${time}</span>
            <button class="addr-link mono cut flow-tx-dest" data-addr="${escHtml(o.dest)}" title="${escHtml(o.dest)}">${escHtml(shortAddr(o.dest))}</button>
            ${entityTag}
            <span class="flow-tx-amt mono">${amt}</span>
            ${o.isPathPay ? `<span class="flow-path-tag">${o.hopCount}-hop</span>` : ''}
          </div>`;
      }).join('')}
    </div>
  `;

  if (badge) {
    const hasCritical = flow.blackHoleDests.length || flow.exchangeDests.length > 2;
    badge.textContent = `${flow.uniqueDests} dests`;
    badge.className = `section-badge section-badge--${hasCritical ? 'crit' : flow.uniqueDests > 0 ? 'warn' : 'ok'}`;
  }
}

function _fmtDateRange(firstTs, lastTs) {
  if (!firstTs || !lastTs) return '';
  const d1 = new Date(firstTs * 1000).toLocaleDateString();
  const d2 = new Date(lastTs * 1000).toLocaleDateString();
  return d1 === d2 ? d1 : `${d1} – ${d2}`;
}

/* ── Issuer Connections Panel ────────────────────── */
function renderIssuerConnectionsPanel(data, lines) {
  const el = $('inspect-issuer-connections-body');
  if (!el) return;

  const totalIssued = data.totalIssued;
  const badge = $('badge-issuer-connections');

  el.innerHTML = `
    <div class="audit-items">
      ${data.signals.map(s => auditRow(s)).join('')}
    </div>

    ${totalIssued > 0 ? `
    <div class="conn-stats">
      <div class="conn-stat"><span>Total Supply</span><b class="mono">${fmt(totalIssued, 0)}</b></div>
      <div class="conn-stat"><span>Trustline Holders</span><b>${data.holderCount}</b></div>
      <div class="conn-stat"><span>Accts Created</span><b>${data.createdAccts.length}</b></div>
      <div class="conn-stat"><span>Distribution txs</span><b>${data.distributions.length}</b></div>
    </div>

    ${data.topHolders.length ? `
    <div class="conn-section-h">🏆 Supply Distribution — Top Holders</div>
    <div class="conn-holders">
      ${data.topHolders.map((h, i) => {
        const pct = totalIssued > 0 ? h.balance / totalIssued * 100 : 0;
        const fillColor = pct > 50 ? '#ff5555' : pct > 25 ? '#ffb86c' : pct > 10 ? '#f1fa8c' : '#50fa7b';
        return `
          <div class="conn-holder-row">
            <span class="conn-holder-rank">${i+1}</span>
            <button class="addr-link mono cut conn-holder-addr" data-addr="${escHtml(h.addr)}" title="${escHtml(h.addr)}">${escHtml(shortAddr(h.addr))}</button>
            <div class="conn-holder-bar-wrap">
              <div class="conn-holder-bar">
                <div class="conn-holder-fill" style="width:${Math.min(100, pct).toFixed(1)}%;background:${fillColor}"></div>
              </div>
              <span class="mono conn-holder-pct">${pct.toFixed(1)}%</span>
            </div>
            <span class="mono conn-holder-amt">${fmt(h.balance, 0)} ${escHtml(h.currency.slice(0,8))}</span>
          </div>`;
      }).join('')}
    </div>` : ''}

    ${data.createdAccts.length ? `
    <div class="conn-section-h">🆕 Accounts Created by This Issuer</div>
    <div class="conn-created-list">
      ${data.createdAccts.slice(0, 12).map(a => `
        <button class="addr-chip mono" data-addr="${escHtml(a)}" title="${escHtml(a)}">${escHtml(shortAddr(a))}</button>
      `).join('')}
      ${data.createdAccts.length > 12 ? `<span style="opacity:.65;font-size:.78rem">+${data.createdAccts.length - 12} more</span>` : ''}
    </div>` : ''}

    ` : ''}

    ${data.mirrorGroups.length ? `
    <div class="conn-section-h">🔁 Mirror Wallet Clusters</div>
    <div class="conn-mirror-list">
      ${data.mirrorGroups.map(g => `
        <div class="conn-mirror-group">
          <div class="conn-mirror-h">~${fmt(g.approxAmt, 0)} tokens · ${g.accounts.length} wallets</div>
          <div class="conn-mirror-addrs">
            ${g.accounts.slice(0, 8).map(a => `
              <button class="addr-chip mono" data-addr="${escHtml(a.addr)}" title="${escHtml(a.addr)}">${escHtml(shortAddr(a.addr))}</button>
            `).join('')}
            ${g.accounts.length > 8 ? `<span class="conn-mirror-more">+${g.accounts.length - 8} more</span>` : ''}
          </div>
        </div>
      `).join('')}
    </div>` : ''}
  `;

  if (badge) {
    const sev = data.signals.some(s => s.sev === 'critical') ? 'crit'
      : data.signals.some(s => s.sev === 'warn') ? 'warn'
      : data.signals.some(s => s.sev === 'info') ? 'neutral'
      : 'ok';
    badge.className = `section-badge section-badge--${sev}`;
    badge.textContent = totalIssued > 0 ? `${data.holderCount} holders` : 'No issuance';
  }
}


/* ── Fee Analysis Panel ──────────────────────────── */
function renderFeeAnalysisPanel(a) {
  const body = document.getElementById('inspect-fee-analysis-body');
  if (!body || !a) return;
  const clsBySev = { critical:'sev-critical', warn:'sev-warn', info:'sev-info', ok:'sev-ok' };
  const sigs = (a.signals || []).map(s => `
    <div class="finding finding--${s.sev}">
      <span class="finding-sev ${clsBySev[s.sev] || ''}">${s.sev.toUpperCase()}</span>
      <div class="finding-body">
        <div class="finding-label">${escHtml(s.label)}</div>
        <div class="finding-detail">${escHtml(s.detail)}</div>
      </div>
    </div>`).join('');
  const stats = a.avgFeeMultiplier != null ? `
    <div class="wash-stat-row" style="margin-top:10px">
      <span>Average fee multiplier</span><span class="mono">${a.avgFeeMultiplier}x base (12 drops)</span>
    </div>
    <div class="wash-stat-row">
      <span>High-fee transactions (>100x)</span><span class="mono ${a.spikeCount > 5 ? 'risk-text-high' : ''}">${a.spikeCount}</span>
    </div>` : '';
  // Top fee table
  const topTable = a.topFeeHashes?.length ? `
    <div style="margin-top:12px;font-size:.72rem;color:rgba(255,255,255,.4);text-transform:uppercase;letter-spacing:.08em;margin-bottom:6px">TOP FEE TRANSACTIONS</div>
    ${a.topFeeHashes.map(h => `
      <div class="wash-stat-row">
        <a href="https://livenet.xrpl.org/transactions/${escHtml(h.hash)}" target="_blank" rel="noopener"
           class="mono" style="font-size:.75rem;color:var(--accent);text-decoration:none">${shortAddr(h.hash)}</a>
        <span class="mono" style="color:#ffb86c">${h.mult}x base fee</span>
      </div>`).join('')}` : '';
  const section = document.getElementById('section-fee-analysis');
  const hasWarn = (a.signals||[]).some(s => s.sev === 'warn' || s.sev === 'critical');
  // Hide the section if fees are completely normal — no need to show "looks fine"
  if (!hasWarn) { if (section) section.style.display = 'none'; return; }
  if (section) section.style.display = '';
  body.innerHTML = sigs + stats + topTable;
  const badge = document.getElementById('badge-fee-analysis');
  if (badge) {
    badge.textContent = 'Elevated';
    badge.className = 'section-badge section-badge--warn';
  }
}

/* ── Destination Tag Panel ───────────────────────── */
function renderDestTagPanel(a) {
  const body = document.getElementById('inspect-desttag-body');
  if (!body || !a) return;
  const clsBySev = { critical:'sev-critical', warn:'sev-warn', info:'sev-info', ok:'sev-ok' };
  const sigs = (a.signals || []).map(s => `
    <div class="finding finding--${s.sev}">
      <span class="finding-sev ${clsBySev[s.sev] || ''}">${s.sev.toUpperCase()}</span>
      <div class="finding-body">
        <div class="finding-label">${escHtml(s.label)}</div>
        <div class="finding-detail">${escHtml(s.detail)}</div>
      </div>
    </div>`).join('');
  const profileTable = a.tagProfiles?.length ? `
    <div style="margin-top:12px;font-size:.72rem;color:rgba(255,255,255,.4);text-transform:uppercase;letter-spacing:.08em;margin-bottom:6px">DESTINATION TAG SUMMARY</div>
    ${a.tagProfiles.slice(0,8).map(p => `
      <div class="wash-stat-row">
        <span>${escHtml(p.name)}</span>
        <span class="mono" style="opacity:.65">${p.txCount} tx · ${p.uniqueTags} unique tag${p.uniqueTags!==1?'s':''}</span>
      </div>`).join('')}` : '';
  const section = document.getElementById('section-desttag');
  const hasWarn = (a.signals||[]).some(s => s.sev === 'warn' || s.sev === 'critical');
  // Hide if no exchange payments or nothing unusual
  const hasProfiles = a.tagProfiles?.length > 0;
  if (!hasWarn && !hasProfiles) { if (section) section.style.display = 'none'; return; }
  if (section) section.style.display = '';
  body.innerHTML = sigs + profileTable;
  const badge = document.getElementById('badge-desttag');
  if (badge) {
    badge.textContent = hasWarn ? 'Check' : 'Normal';
    badge.className = `section-badge section-badge--${hasWarn ? 'warn' : 'ok'}`;
  }
}

/* ── Path Payment Depth Panel ────────────────────── */
function renderPathDepthPanel(a) {
  const section = document.getElementById('section-pathdepth');
  const body    = document.getElementById('inspect-pathdepth-body');
  const badge   = document.getElementById('badge-pathdepth');

  // No path payments at all — collapse the section so it doesn't clutter the UI
  if (!a || a.noData || !a.signals?.length) {
    if (section) section.style.display = 'none';
    return;
  }

  if (section) section.style.display = '';
  if (!body) return;

  const clsBySev = { critical:'sev-critical', warn:'sev-warn', info:'sev-info', ok:'sev-ok' };
  const sigs = a.signals.map(s => `
    <div class="finding finding--${s.sev}">
      <span class="finding-sev ${clsBySev[s.sev] || ''}">${s.sev.toUpperCase()}</span>
      <div class="finding-body">
        <div class="finding-label">${escHtml(s.label)}</div>
        <div class="finding-detail">${escHtml(s.detail)}</div>
      </div>
    </div>`).join('');

  // Stats row
  const stats = `
    <div class="wash-stat-row" style="margin-top:10px">
      <span>Total path payments</span><span class="mono">${a.roundTripCount + a.deepHopCount + (a.selfRoutedCount||0) + (a.signals.filter(s=>s.sev==='ok').length > 0 ? 1 : 0)}</span>
    </div>
    ${a.roundTripCount ? `<div class="wash-stat-row"><span>XRP→IOU→XRP round-trips</span><span class="mono ${a.roundTripCount >= 3 ? 'risk-text-high' : 'risk-text-med'}">${a.roundTripCount}</span></div>` : ''}
    ${a.deepHopCount   ? `<div class="wash-stat-row"><span>Deep hop chains (≥3 hops)</span><span class="mono">${a.deepHopCount}</span></div>` : ''}
    ${a.selfRoutedCount? `<div class="wash-stat-row"><span>Self-routed payments</span><span class="mono risk-text-high">${a.selfRoutedCount}</span></div>` : ''}`;

  body.innerHTML = sigs + stats;

  if (badge) {
    const hasCrit = a.signals.some(s => s.sev === 'critical');
    const hasWarn = a.signals.some(s => s.sev === 'warn');
    badge.textContent = hasCrit ? 'Critical' : hasWarn ? 'Check' : 'Normal';
    badge.className = `section-badge section-badge--${hasCrit ? 'crit' : hasWarn ? 'warn' : 'ok'}`;
  }
}


/* ── Inbound Flow Panel ──────────────────────────── */
function renderInboundFlowPanel(flow) {
  const el = $('inspect-inbound-body');
  if (!el) return;
  const clsBySev = { critical:'sev-critical', warn:'sev-warn', info:'sev-info', ok:'sev-ok' };

  const sigs = (flow.signals||[]).map(s => `
    <div class="finding finding--${s.sev}">
      <span class="finding-sev ${clsBySev[s.sev]||''}">${s.sev.toUpperCase()}</span>
      <div class="finding-body"><div class="finding-label">${escHtml(s.label)}</div>
      <div class="finding-detail">${escHtml(s.detail)}</div></div>
    </div>`).join('');

  const stats = `
    <div class="flow-summary" style="margin-top:10px">
      <div class="flow-stat"><span>Inbound payments</span><b>${flow.timeline?.length || 0}</b></div>
      <div class="flow-stat"><span>Unique sources</span><b>${flow.uniqueSources}</b></div>
      <div class="flow-stat"><span>Total XRP received</span><b class="mono">${fmt(flow.totalIn,2)}</b></div>
      <div class="flow-stat"><span>Exchange sources</span><b>${flow.exchangeSrcs?.length||0}</b></div>
    </div>`;

  const topList = flow.topSources?.length ? `
    <div class="flow-section-h" style="margin-top:14px">📥 Top Funding Sources</div>
    <div class="flow-dest-list">
      ${flow.topSources.map((s,i) => {
        const pct = flow.totalIn > 0 ? (s.totalXrp/flow.totalIn*100).toFixed(0) : 0;
        const ent = s.entity;
        const badge = ent ? `<span class="flow-entity-badge flow-entity--${ent.type}">${escHtml(ent.name)}</span>` : '';
        return `<div class="flow-dest-row">
          <div class="flow-dest-rank">${i+1}</div>
          <div class="flow-dest-info">
            <div class="flow-dest-top">
              <a href="https://xrpscan.com/account/${escHtml(s.addr)}" target="_blank" rel="noopener" class="addr-link mono cut">${escHtml(shortAddr(s.addr))}</a>
              ${badge}
            </div>
            <div class="flow-bar-row">
              <div class="flow-dest-bar"><div class="flow-dest-fill" style="width:${Math.min(100,pct)}%;background:${ent?.type==='exchange'?'#00d4ff':'rgba(80,250,123,.7)'}"></div></div>
              <span class="mono flow-dest-pct">${pct}%</span>
            </div>
            <div class="flow-dest-meta">
              <span class="mono">${fmt(s.totalXrp,2)} XRP${_usd(s.totalXrp)}</span>
              <span class="flow-dest-cnt">${s.txCount} tx</span>
            </div>
          </div>
        </div>`;
      }).join('')}
    </div>` : '';

  el.innerHTML = sigs + stats + topList;
  const badge = $('badge-inbound');
  if (badge) {
    const hasWarn = (flow.signals||[]).some(s=>s.sev==='warn'||s.sev==='critical');
    badge.textContent = `${flow.uniqueSources} src${flow.uniqueSources!==1?'s':''}`;
    badge.className = `section-badge section-badge--${hasWarn?'warn':'neutral'}`;
  }
}

/* ── Memo Analysis Panel ─────────────────────────── */
function renderMemoPanel(a) {
  const section = $('section-memos');
  const body    = $('inspect-memos-body');
  if (!a || !a.allMemos?.length) { if (section) section.style.display = 'none'; return; }
  if (section) section.style.display = '';
  if (!body) return;
  const clsBySev = { critical:'sev-critical', warn:'sev-warn', info:'sev-info', ok:'sev-ok' };
  const sigs = (a.signals||[]).map(s => `
    <div class="finding finding--${s.sev}">
      <span class="finding-sev ${clsBySev[s.sev]||''}">${s.sev.toUpperCase()}</span>
      <div class="finding-body"><div class="finding-label">${escHtml(s.label)}</div>
      <div class="finding-detail">${escHtml(s.detail)}</div></div>
    </div>`).join('');
  const memoList = a.allMemos.slice(0,10).map(m => `
    <div class="wash-stat-row" style="flex-direction:column;align-items:flex-start;gap:2px;padding:6px 0;border-bottom:1px solid rgba(255,255,255,.05)">
      <div style="font-size:.72rem;color:rgba(255,255,255,.35)">${escHtml(m.type)} · <a href="https://livenet.xrpl.org/transactions/${escHtml(m.tx)}" target="_blank" rel="noopener" style="color:var(--accent);text-decoration:none">${shortAddr(m.tx)}</a></div>
      <div style="font-size:.82rem;word-break:break-all;color:rgba(255,255,255,.75)">${escHtml(m.text.slice(0,120))}${m.text.length>120?'…':''}</div>
    </div>`).join('');
  body.innerHTML = sigs + `<div style="margin-top:10px;font-size:.72rem;color:rgba(255,255,255,.4);text-transform:uppercase;letter-spacing:.08em;margin-bottom:4px">MEMO CONTENTS (${a.allMemos.length} found)</div>` + memoList;
  const badge = $('badge-memos');
  if (badge) {
    const hasCrit = (a.signals||[]).some(s=>s.sev==='critical');
    const hasWarn = (a.signals||[]).some(s=>s.sev==='warn');
    badge.textContent = hasCrit?'Scam text':hasWarn?'Patterns':'Normal';
    badge.className = `section-badge section-badge--${hasCrit?'crit':hasWarn?'warn':'ok'}`;
  }
}

/* ── Escrow Depth Panel ──────────────────────────── */
function renderEscrowDepthPanel(a) {
  const section = $('section-escrow-depth');
  const body    = $('inspect-escrow-depth-body');
  if (!a || !a.escrows?.length) { if (section) section.style.display = 'none'; return; }
  if (section) section.style.display = '';
  if (!body) return;
  const clsBySev = { critical:'sev-critical', warn:'sev-warn', info:'sev-info', ok:'sev-ok' };
  const sigs = (a.signals||[]).map(s => `
    <div class="finding finding--${s.sev}">
      <span class="finding-sev ${clsBySev[s.sev]||''}">${s.sev.toUpperCase()}</span>
      <div class="finding-body"><div class="finding-label">${escHtml(s.label)}</div>
      <div class="finding-detail">${escHtml(s.detail)}</div></div>
    </div>`).join('');
  const EPOCH = 946684800;
  const rows = a.escrows.map(e => `
    <div class="wash-stat-row">
      <span>${e.isSelfEscrow?'Self-escrow':e.isThirdParty?'<span style="color:#ff5555">Third-party →</span>':shortAddr(e.dest||'')}</span>
      <span class="mono">${fmt(e.amtXrp,2)} XRP${_usd(e.amtXrp)}</span>
      <span style="font-size:.72rem;opacity:.55">${e.daysToFinish!=null?(e.daysToFinish<0?'matured':e.daysToFinish+'d'):e.conditional?'conditional':'—'}</span>
    </div>`).join('');
  body.innerHTML = sigs + `<div style="margin-top:10px">${rows}</div>`;
  const badge = $('badge-escrow-depth');
  if (badge) {
    const hasWarn = a.hasThirdParty;
    badge.textContent = `${a.escrows.length} escrow${a.escrows.length!==1?'s':''}`;
    badge.className = `section-badge section-badge--${hasWarn?'warn':'neutral'}`;
  }
}

/* ── Check Panel ─────────────────────────────────── */
function renderCheckPanel(a) {
  const section = $('section-checks');
  const body    = $('inspect-checks-body');
  if (!a || !a.checks?.length) { if (section) section.style.display = 'none'; return; }
  if (section) section.style.display = '';
  if (!body) return;
  const clsBySev = { critical:'sev-critical', warn:'sev-warn', info:'sev-info', ok:'sev-ok' };
  const sigs = (a.signals||[]).map(s => `
    <div class="finding finding--${s.sev}">
      <span class="finding-sev ${clsBySev[s.sev]||''}">${s.sev.toUpperCase()}</span>
      <div class="finding-body"><div class="finding-label">${escHtml(s.label)}</div>
      <div class="finding-detail">${escHtml(s.detail)}</div></div>
    </div>`).join('');
  const rows = a.checks.map(c => `
    <div class="wash-stat-row">
      <span class="mono">${shortAddr(c.sender)} → ${shortAddr(c.dest||'')}</span>
      <span class="mono">${c.amtXrp!=null?fmt(c.amtXrp,2)+' XRP'+_usd(c.amtXrp):(c.amtToken?.value||'?')+' '+c.amtToken?.currency}</span>
      <span style="font-size:.72rem;${c.expired?'color:#ff5555':'opacity:.55'}">${c.expired?'Expired':'Open'}</span>
    </div>`).join('');
  body.innerHTML = sigs + `<div style="margin-top:10px">${rows}</div>`;
  const badge = $('badge-checks');
  if (badge) {
    badge.textContent = `${a.checks.length} check${a.checks.length!==1?'s':''}`;
    badge.className = 'section-badge section-badge--neutral';
  }
}

/* ── Live Order Book Panel ───────────────────────── */
function renderLiveBookPanel(a) {
  const section = $('section-livebook');
  const body    = $('inspect-livebook-body');
  if (!a?.hasData) { if (section) section.style.display = 'none'; return; }
  if (section) section.style.display = '';
  if (!body) return;
  const clsBySev = { critical:'sev-critical', warn:'sev-warn', info:'sev-info', ok:'sev-ok' };
  const sigs = (a.signals||[]).map(s => `
    <div class="finding finding--${s.sev}">
      <span class="finding-sev ${clsBySev[s.sev]||''}">${s.sev.toUpperCase()}</span>
      <div class="finding-body"><div class="finding-label">${escHtml(s.label)}</div>
      <div class="finding-detail">${escHtml(s.detail)}</div></div>
    </div>`).join('');
  const stats = `
    <div class="wash-stat-row" style="margin-top:10px">
      <span>Pair</span><span class="mono">${escHtml(a.pair.split('↔').map(p=>p.split('+')[0]).join(' ↔ '))}</span>
    </div>
    <div class="wash-stat-row">
      <span>Live orders in book</span><span class="mono">${a.offerCount}</span>
    </div>
    ${a.ourShare>0?`<div class="wash-stat-row"><span>This wallet's book share</span><span class="mono ${a.ourShare>0.25?'risk-text-high':''}">${(a.ourShare*100).toFixed(1)}%</span></div>`:''}
    ${a.wallShare>0.3?`<div class="wash-stat-row"><span>Largest single order share</span><span class="mono ${a.wallShare>0.4?'risk-text-high':'risk-text-med'}">${(a.wallShare*100).toFixed(1)}%</span></div>`:''}`;
  body.innerHTML = sigs + stats;
  const badge = $('badge-livebook');
  if (badge) {
    const hasCrit = (a.signals||[]).some(s=>s.sev==='critical');
    const hasWarn = (a.signals||[]).some(s=>s.sev==='warn');
    badge.textContent = hasCrit?'Wall order':hasWarn?'Check':'Normal';
    badge.className = `section-badge section-badge--${hasCrit?'crit':hasWarn?'warn':'ok'}`;
  }
}

/* ── Risk Score Breakdown Bar ────────────────────── */
function renderRiskBreakdown(riskScore, ...analysisArgs) {
  const body = $('inspect-risk-breakdown');
  if (!body) return;
  const components = buildRiskBreakdown(riskScore, ...analysisArgs);
  if (!components.length) { body.innerHTML = ''; return; }
  const total = Math.max(1, components.reduce((s,c)=>s+c.pts,0));
  body.innerHTML = `
    <div style="margin-top:8px">
      <div style="font-size:.65rem;color:rgba(255,255,255,.35);text-transform:uppercase;letter-spacing:.1em;margin-bottom:5px">Score Breakdown</div>
      <div style="display:flex;height:8px;border-radius:4px;overflow:hidden;gap:1px">
        ${components.map(c=>`<div style="flex:${c.pts};background:${c.color};opacity:.85" title="${escHtml(c.label)}: ${c.pts} pts"></div>`).join('')}
      </div>
      <div style="display:flex;flex-wrap:wrap;gap:6px;margin-top:6px">
        ${components.map(c=>`<span style="font-size:.67rem;color:${c.color};opacity:.8">${c.icon} ${escHtml(c.label)} ${c.pts}pts</span>`).join('')}
      </div>
    </div>`;
}

/* ═══════════════════════════════════════════════════
   HELPERS
═══════════════════════════════════════════════════ */

function auditRow({ sev, label, detail }) {
  const icons = { ok: '✓', info: 'ℹ', warn: '⚠', critical: '⛔' };
  return `
    <div class="audit-row audit-row--${sev}">
      <span class="audit-icon">${icons[sev] || 'ℹ'}</span>
      <div class="audit-text">
        <div class="audit-label">${escHtml(label)}</div>
        ${detail ? `<div class="audit-detail">${escHtml(detail)}</div>` : ''}
      </div>
    </div>`;
}

function riskScoreClass(score) {
  return score < 20 ? 'risk-ok' : score < 45 ? 'risk-medium' : score < 70 ? 'risk-high' : 'risk-critical';
}

function txRiskLevel(tx, meta, addr) {
  if (DRAIN_TX_TYPES.has(tx.TransactionType)) return 'warn';
  if (tx.TransactionType === 'NFTokenCreateOffer') {
    const amt = tx.Amount;
    if (!amt || (typeof amt === 'string' && Number(amt) < 1000000)) return 'critical';
  }
  if (meta?.TransactionResult && meta.TransactionResult !== 'tesSUCCESS') return 'fail';
  return 'normal';
}

function txBrief(tx, addr) {
  const type = tx.TransactionType;
  if (type === 'Payment') {
    const dir = tx.Account === addr ? `→ ${shortAddr(tx.Destination)}` : `← ${shortAddr(tx.Account)}`;
    const amt = typeof tx.Amount === 'string'
      ? `${fmt(Number(tx.Amount) / 1e6, 2)} XRP`
      : (tx.Amount?.value ? `${fmt(Number(tx.Amount.value), 2)} ${tx.Amount.currency}` : '');
    return escHtml(`${amt} ${dir}`);
  }
  if (type === 'OfferCreate') {
    const pays = typeof tx.TakerPays === 'string'
      ? `${fmt(Number(tx.TakerPays) / 1e6, 2)} XRP`
      : `${fmt(Number(tx.TakerPays?.value), 2)} ${tx.TakerPays?.currency}`;
    const gets = typeof tx.TakerGets === 'string'
      ? `${fmt(Number(tx.TakerGets) / 1e6, 2)} XRP`
      : `${fmt(Number(tx.TakerGets?.value), 2)} ${tx.TakerGets?.currency}`;
    return escHtml(`${pays} for ${gets}`);
  }
  if (type === 'SetRegularKey')   return escHtml(`Key: ${tx.RegularKey ? shortAddr(tx.RegularKey) : 'REMOVED'}`);
  if (type === 'NFTokenMint')     return escHtml(`Taxon: ${tx.NFTokenTaxon ?? '—'}`);
  if (type === 'NFTokenBurn')     return escHtml(`Token: ${tx.NFTokenID ? shortAddr(tx.NFTokenID) : '—'}`);
  if (type === 'AMMDeposit')      return escHtml(`Pool deposit`);
  if (type === 'AMMWithdraw')     return escHtml(`LP withdrawal`);
  if (type === 'EscrowCreate')    return escHtml(`${fmt(Number(tx.Amount || 0) / 1e6, 2)} XRP → ${shortAddr(tx.Destination)}`);
  return '';
}

function typeBadgeClass(type) {
  const map = {
    Payment: 'payment', OfferCreate: 'offer', OfferCancel: 'offer',
    NFTokenMint: 'nft', NFTokenBurn: 'nft', NFTokenCreateOffer: 'nft', NFTokenAcceptOffer: 'nft',
    SetRegularKey: 'auth', SignerListSet: 'auth', AccountSet: 'auth', AccountDelete: 'auth',
    TrustSet: 'trust',
    AMMCreate: 'amm', AMMDeposit: 'amm', AMMWithdraw: 'amm', AMMVote: 'amm', AMMBid: 'amm',
    EscrowCreate: 'escrow', EscrowFinish: 'escrow', EscrowCancel: 'escrow',
    PaymentChannelCreate: 'channel', PaymentChannelFund: 'channel', PaymentChannelClaim: 'channel',
  };
  return map[type] || 'other';
}

function getCloseTime(tx) {
  const t = tx?.date || tx?.close_time || tx?.ledger_close_time;
  if (!t) return 0;
  return Number(t) + XRPL_EPOCH;
}

function hexToAscii(hex) {
  if (!hex || hex.length !== 40) return hex || '';
  // Try to decode as ASCII currency code
  try {
    let str = '';
    for (let i = 0; i < hex.length; i += 2) {
      const code = parseInt(hex.slice(i, i + 2), 16);
      if (code === 0) continue;
      if (code < 32 || code > 126) return hex; // not printable ASCII
      str += String.fromCharCode(code);
    }
    return str || hex;
  } catch {
    return hex;
  }
}


/* ═══════════════════════════════════════════════════
   FULL INVESTIGATION REPORT
═══════════════════════════════════════════════════ */

function generateFullReport(addr, acct, balXrp, riskScore,
  securityAudit, drainAnalysis, nftAnalysis, washAnalysis,
  benfordsAnalysis, volConcAnalysis, issuerAnalysis,
  ammAnalysis, fundFlowAnalysis, issuerConnAnalysis, txList,
  entropyAnalysis, zipfAnalysis, timeSeriesAnalysis, grangerAnalysis,
  extra = {}) {

  const {
    feeAnalysis = null, destTagAnalysis = null, pathDepthAnalysis = null, gatewayBalances = null,
    inboundFlowAnalysis = null, memoAnalysis = null, escrowDepthAnalysis = null,
    checkAnalysis = null, liveBookAnalysis = null, walletAgeDays = null, walletCreatedTs = null,
  } = extra;
  const RIPPLE_EPOCH = 946684800;

  const ts        = new Date().toLocaleString();
  const addrShort = addr.slice(0, 10) + '…' + addr.slice(-8);
  const riskWord  = riskScore < 20 ? 'LOW' : riskScore < 45 ? 'MODERATE' : riskScore < 70 ? 'HIGH' : 'CRITICAL';
  const riskColor = riskScore < 20 ? '#50fa7b' : riskScore < 45 ? '#ffb86c' : riskScore < 70 ? '#ff8c42' : '#ff5555';

  // ── Data coverage ────────────────────────────────────────────────────────
  const datedTxs = txList.filter(({tx}) => tx.date != null);
  let coverageStr = `${txList.length} transactions`;
  let coverageDateStr = '';
  let coverageSpanDays = 0;
  if (datedTxs.length >= 2) {
    const oldest = datedTxs[0].tx.date + RIPPLE_EPOCH;
    const newest = datedTxs[datedTxs.length - 1].tx.date + RIPPLE_EPOCH;
    coverageSpanDays = Math.round((newest - oldest) / 86400);
    const oldD = new Date(oldest * 1000).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
    const newD = new Date(newest * 1000).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
    coverageDateStr = `${oldD} – ${newD} (${coverageSpanDays} days)`;
    coverageStr = `${txList.length} transactions from ${coverageDateStr}`;
  }

  // ── Collect all findings ─────────────────────────────────────────────────
  const allFindings = [];
  const push = (module, sev, headline, detail, hashes) =>
    allFindings.push({ module, sev, headline, detail: detail || '', hashes: hashes || [] });

  for (const f of securityAudit.findings || []) push('Security', f.sev, f.label, f.detail);
  push('Drain Risk',
    drainAnalysis.riskLevel === 'low' ? 'ok' : drainAnalysis.riskLevel === 'medium' ? 'warn' : 'critical',
    'Drain Risk Level: ' + drainAnalysis.riskLevel.toUpperCase(), null);
  for (const s of drainAnalysis.signals  || []) if (s.sev !== 'ok') push('Drain Risk',          s.sev, s.label, s.detail, s.hashes);
  for (const f of nftAnalysis.flags      || []) if (f.sev !== 'ok') push('NFT',                  f.sev, f.label, f.detail, f.hashes);
  if (washAnalysis.verdict && !['clean','low-risk'].includes(washAnalysis.verdict))
    push('Wash Trading', washAnalysis.score >= 60 ? 'critical' : 'warn',
      `Wash score ${washAnalysis.score}/100 — ${washAnalysis.verdict.replace('-',' ')}`, null);
  for (const s of washAnalysis.signals   || []) if (s.sev !== 'ok') push('Wash Trading',         s.sev, s.label, s.detail);
  for (const s of benfordsAnalysis.signals||[]) if (s.sev !== 'ok') push("Benford's Law",         s.sev, s.label, s.detail);
  for (const s of volConcAnalysis.signals|| []) if (s.sev !== 'ok') push('Volume Concentration',  s.sev, s.label, s.detail);
  for (const s of entropyAnalysis?.signals  || []) if (s.sev !== 'ok') push("Shannon's Entropy",  s.sev, s.label, s.detail);
  for (const s of zipfAnalysis?.signals     || []) if (s.sev !== 'ok') push("Zipf's Law",         s.sev, s.label, s.detail);
  for (const s of timeSeriesAnalysis?.signals||[]) if (s.sev !== 'ok') push('Time Series',        s.sev, s.label, s.detail);
  for (const s of grangerAnalysis?.signals  || []) if (s.sev !== 'ok') push('Granger Causality',  s.sev, s.label, s.detail);
  for (const s of issuerAnalysis.signals || []) if (s.sev !== 'ok') push('Token Issuer',          s.sev, s.label, s.detail);
  for (const s of ammAnalysis.signals    || []) if (s.sev !== 'ok') push('AMM',                   s.sev, s.label, s.detail);
  if (fundFlowAnalysis.blackHoleDests?.length)
    push('Fund Flow', 'critical', `Funds sent to ${fundFlowAnalysis.blackHoleDests.length} black hole address(es)`, 'These funds are permanently irrecoverable.');
  if (fundFlowAnalysis.exchangeDests?.length)
    push('Fund Flow', 'warn', `${fundFlowAnalysis.exchangeDests.length} known exchange(s) received funds`, fundFlowAnalysis.exchangeDests.map(d => d.entity.name).join(', '));
  if (fundFlowAnalysis.newWalletDests?.length)
    push('Fund Flow', 'critical', `${fundFlowAnalysis.newWalletDests.length} brand-new wallet(s) received large XRP transfers`, 'New wallets (Sequence < 10) receiving large amounts are a classic drain-mule pattern.');
  for (const s of issuerConnAnalysis.signals||[]) if (s.sev !== 'ok') push('Issuer Connections',  s.sev, s.label, s.detail);
  for (const s of feeAnalysis?.signals      ||[]) if (s.sev !== 'ok') push('Fee Spikes',          s.sev, s.label, s.detail, s.hashes);
  for (const s of destTagAnalysis?.signals  ||[]) if (s.sev !== 'ok') push('Destination Tags',    s.sev, s.label, s.detail);
  for (const s of pathDepthAnalysis?.signals||[])   if (s.sev !== 'ok') push('Path Payments',    s.sev, s.label, s.detail, s.hashes);
  for (const s of inboundFlowAnalysis?.signals||[]) if (s.sev !== 'ok') push('Inbound Flow',     s.sev, s.label, s.detail);
  for (const s of memoAnalysis?.signals||[])         if (s.sev !== 'ok') push('Memo Analysis',   s.sev, s.label, s.detail);
  for (const s of escrowDepthAnalysis?.signals||[])  if (s.sev !== 'ok') push('Escrow Depth',    s.sev, s.label, s.detail);
  for (const s of liveBookAnalysis?.signals||[])     if (s.sev !== 'ok') push('Live Order Book', s.sev, s.label, s.detail);

  const criticals = allFindings.filter(f => f.sev === 'critical');
  const warnings  = allFindings.filter(f => f.sev === 'warn');

  // ── Helper: severity badge ────────────────────────────────────────────────
  const sevBadge = sev => {
    const map = {
      critical: 'background:rgba(255,85,85,.15);border:1px solid rgba(255,85,85,.35);color:#ff5555',
      warn:     'background:rgba(255,184,108,.10);border:1px solid rgba(255,184,108,.30);color:#ffb86c',
      info:     'background:rgba(120,180,255,.08);border:1px solid rgba(120,180,255,.18);color:rgba(120,180,255,.9)',
      ok:       'background:rgba(80,250,123,.08);border:1px solid rgba(80,250,123,.22);color:#50fa7b',
    };
    return `<span style="padding:2px 8px;border-radius:999px;font-size:.68rem;font-weight:900;letter-spacing:.3px;text-transform:uppercase;${map[sev]||map.info}">${sev.toUpperCase()}</span>`;
  };

  // ── Plain-English narrative ──────────────────────────────────────────────
  function buildNarrative() {
    const parts = [];

    // Opening — always includes actual data coverage
    parts.push(
      `<strong>Address ${addrShort}</strong> was inspected on ${ts}. ` +
      `The account holds <strong>${fmt(balXrp, 4)} XRP</strong>. ` +
      `This report analyzed <strong>${coverageStr}</strong>, ` +
      `plus all open on-chain objects (escrows, payment channels, trustlines, NFTs, AMM positions). ` +
      `The overall risk score is <strong style="color:${riskColor}">${riskScore}/100 — ${riskWord}</strong>. ` +
      `<em style="opacity:.7">Risk scores reflect statistical patterns — not legal proof. ` +
      `A high score means unusual patterns were detected. Always verify before drawing conclusions.</em>`
    );

    if (criticals.length) {
      parts.push(`⚠️ The scan found <strong>${criticals.length} critical issue${criticals.length > 1 ? 's' : ''}</strong> and <strong>${warnings.length} warning${warnings.length !== 1 ? 's' : ''}</strong> — explained in plain English below.`);
    }

    // ── Drain / Security ──────────────────────────────────────────────────
    if (drainAnalysis.riskLevel === 'critical') {
      parts.push(
        `<span style="color:#ff5555"><strong>🚨 WALLET DRAIN RISK — CRITICAL</strong></span><br>` +
        `<strong>What was found:</strong> The account's security structure matches a known attack pattern — ` +
        `the master signing key has been disabled and replaced with a different key.<br>` +
        `<strong>What it means in plain English:</strong> If you did not personally do this, your wallet may have been taken over. ` +
        `An attacker who controls the replacement key can drain every XRP and token from the account.<br>` +
        `<strong>What to do right now:</strong> Stop sending any funds to this address. If it's your wallet, contact a security professional immediately.`
      );
    } else if (drainAnalysis.riskLevel === 'high') {
      parts.push(`<strong>⚠️ Elevated Drain Risk:</strong> Unusual security patterns found — possibly a key change followed by large outflows. See the Drain Risk section for exact transactions.`);
    }

    // ── New wallet alert ──────────────────────────────────────────────────
    if (fundFlowAnalysis.newWalletDests?.length) {
      parts.push(
        `<strong>🆕 Brand-New Receiving Wallets:</strong> ` +
        `${fundFlowAnalysis.newWalletDests.length} of the top destinations are freshly-created wallets (fewer than 10 lifetime transactions) that received significant XRP. ` +
        `Creating a new disposable wallet to receive drained funds — then disappearing — is the most common drain attack pattern on XRPL.`
      );
    }

    // ── Fund flow ─────────────────────────────────────────────────────────
    if (fundFlowAnalysis.blackHoleDests?.length) {
      parts.push(`<span style="color:#ff5555"><strong>🕳 Funds Sent to Uncontrolled Address:</strong></span> Some XRP reached a "black hole" — an address nobody controls. <strong>These funds cannot be recovered by anyone.</strong>`);
    }
    if (fundFlowAnalysis.exchangeDests?.length) {
      const exchNames = [...new Set(fundFlowAnalysis.exchangeDests.map(d => d.entity.name))].join(', ');
      parts.push(
        `<strong>💱 Exchange Activity:</strong> Funds reached known exchange(s): <strong>${exchNames}</strong>. ` +
        `Total outflow tracked: ${fmt(fundFlowAnalysis.totalOut, 2)} XRP to ${fundFlowAnalysis.uniqueDests} destination(s). ` +
        `This is often normal — people cash out to exchanges. It becomes a concern when combined with the security or timing signals above.`
      );
    } else if (fundFlowAnalysis.totalOut > 0) {
      parts.push(`<strong>Outbound payments:</strong> ${fmt(fundFlowAnalysis.totalOut, 2)} XRP sent to ${fundFlowAnalysis.uniqueDests} destination(s). None matched known exchange addresses.`);
    }

    // ── Wash trading ──────────────────────────────────────────────────────
    if (washAnalysis.score >= 60) {
      const s = washAnalysis.stats;
      const cancelRate = s.creates > 0 ? ((s.cancels / s.creates) * 100).toFixed(0) : 0;
      parts.push(
        `<strong>📊 Wash Trading Signals (Score: ${washAnalysis.score}/100 — ${washAnalysis.verdict.replace('-',' ').toUpperCase()}):</strong><br>` +
        `<strong>What was found:</strong> Out of ${s.creates} DEX offers placed, ${s.cancels} (${cancelRate}%) were cancelled before filling. ` +
        `Only ${s.fills} actually filled.` +
        (s.selfTrades > 0 ? ` ${s.selfTrades} payment(s) were sent from and back to the same address.` : '') + `<br>` +
        `<strong>What it means:</strong> Placing orders and cancelling them before they fill inflates a token's visible trading activity without any real buying or selling. ` +
        `It makes a thin market look active to attract other traders.<br>` +
        `<strong>Caveat:</strong> Legitimate market makers do cancel many orders as prices move. ` +
        `This finding is strongest when combined with the self-trade and fee-spike signals.`
      );
    } else if (washAnalysis.score >= 30) {
      parts.push(`<strong>Moderate trading signals</strong> (score ${washAnalysis.score}/100): Some DEX patterns look unusual but not conclusive alone. See Wash Trading section for specifics.`);
    } else {
      parts.push(`<strong>✅ DEX activity looks normal</strong> (wash score ${washAnalysis.score}/100). Cancel ratios, fill rates, and trade sizes are within organic ranges.`);
    }

    // ── Path payments ─────────────────────────────────────────────────────
    if (pathDepthAnalysis?.selfRoutedCount > 0) {
      parts.push(
        `<strong>🔄 Self-Routing Path Payments:</strong> ${pathDepthAnalysis.selfRoutedCount} payment(s) where the sender and destination are the same address. ` +
        `Routing XRP through the DEX back to yourself creates trading volume on every intermediate pair with no net economic transfer — ` +
        `a DEX-specific wash trading technique that's harder to detect than simple self-trades.`
      );
    }
    if (pathDepthAnalysis?.roundTripCount >= 3) {
      parts.push(`<strong>XRP→IOU→XRP round-trips:</strong> ${pathDepthAnalysis.roundTripCount} path payments paid and received XRP through intermediate token pairs — generating DEX volume without changing economic position.`);
    }

    // ── Fee spikes ────────────────────────────────────────────────────────
    if (feeAnalysis?.verdict === 'elevated') {
      parts.push(
        `<strong>💸 Fee Spike Pattern:</strong> ${feeAnalysis.spikeCount} transaction(s) paid more than 100× the normal fee. ` +
        `Bots often overpay fees to guarantee same-ledger execution alongside a counterparty — ` +
        `a coordination technique used in wash trading and front-running. Organic users almost never need fees this high.`
      );
    }

    // ── Statistical forensics ─────────────────────────────────────────────
    const forensicFlags = [
      benfordsAnalysis.verdict === 'high-deviation',
      entropyAnalysis?.verdict === 'anomalous',
      zipfAnalysis?.verdict === 'anomalous' || zipfAnalysis?.verdict === 'elevated',
      timeSeriesAnalysis?.verdict === 'bot-pattern',
      grangerAnalysis?.verdict === 'causal-signal',
    ].filter(Boolean).length;

    if (forensicFlags >= 3) {
      parts.push(
        `<strong>🔬 Statistical Analysis — Multiple Engines Agree:</strong><br>` +
        `${forensicFlags} out of 5 independent mathematical tests found patterns inconsistent with human organic activity. ` +
        `These tests each use different mathematical approaches (number patterns, information theory, power laws, timing, causality) ` +
        `so they can't all be false alarms from the same data artifact.<br>` +
        `<strong>What it means:</strong> When unrelated statistical methods all flag the same account, ` +
        `the probability that all findings are coincidental false positives drops dramatically. ` +
        `This strongly suggests automated or coordinated activity, though it's not proof of fraud.`
      );
    } else if (forensicFlags >= 2) {
      parts.push(`<strong>Statistical analysis:</strong> ${forensicFlags}/5 tests flagged unusual patterns. Multiple independent tests agreeing is a meaningful signal — see the Forensic Suite section.`);
    } else if (forensicFlags === 1) {
      parts.push(`<strong>Statistical analysis:</strong> 1/5 tests flagged an unusual pattern. A single flag is a hypothesis to investigate further, not a conclusion.`);
    } else if (txList.length >= 30) {
      parts.push(`<strong>✅ All statistical tests normal:</strong> Benford's Law, entropy, Zipf's Law, time series, and Granger causality all returned results consistent with organic activity across ${txList.length} transactions.`);
    }

    // ── Benford detail ────────────────────────────────────────────────────
    if (benfordsAnalysis.verdict === 'high-deviation' && benfordsAnalysis.chiSq != null) {
      parts.push(
        `<strong>Benford's Law detail (χ²=${benfordsAnalysis.chiSq.toFixed(1)}):</strong> ` +
        `In real financial data, "1" appears as the first digit ~30% of the time and "9" only ~4.6%. ` +
        `Computer-generated amounts break this pattern. This wallet's amounts deviate significantly ` +
        `(χ²=${benfordsAnalysis.chiSq.toFixed(1)} exceeds the 99% confidence threshold of 20.09).`
      );
    }

    // ── Token issuance ────────────────────────────────────────────────────
    if (issuerConnAnalysis.totalIssued > 0) {
      const top    = issuerConnAnalysis.topHolders?.[0];
      const topPct = top ? (top.balance / issuerConnAnalysis.totalIssued * 100).toFixed(0) : null;
      // Use gateway_balances for a more accurate supply figure if available
      const trueSupply = gatewayBalances?.result?.obligations
        ? Object.values(gatewayBalances.result.obligations).reduce((s, v) => s + Number(v), 0)
        : null;
      const supplyNote = trueSupply ? ` (verified via gateway_balances: ${fmt(trueSupply, 0)} total obligations)` : '';
      parts.push(
        `<strong>🪙 Token Issuance:</strong> This account has issued tokens — ` +
        `<strong>${fmt(issuerConnAnalysis.totalIssued, 0)} outstanding</strong> across ${issuerConnAnalysis.holderCount} holder(s)${supplyNote}. ` +
        (topPct ? `The largest single holder controls <strong>${topPct}% of supply</strong>. ` : '') +
        (topPct && Number(topPct) > 50 ? `Holding more than half the supply means one wallet could dump and collapse the token price. ` : '') +
        (issuerConnAnalysis.mirrorGroups?.length ? `<strong>${issuerConnAnalysis.mirrorGroups.length} cluster(s)</strong> of wallets each received identical token amounts — possible coordinated/insider wallets. ` : '') +
        (issuerConnAnalysis.createdAccts?.length ? `This issuer also created ${issuerConnAnalysis.createdAccts.length} wallet(s) — they may be controlled by the same entity. ` : '')
      );
    }

    // ── NFT ───────────────────────────────────────────────────────────────
    const critNft = (nftAnalysis.flags || []).filter(f => f.sev === 'critical');
    if (critNft.length) {
      parts.push(
        `<strong>🎨 NFT Risk:</strong> ${critNft.length} critical NFT issue(s) — most commonly a zero-price sell offer. ` +
        `The most common XRPL NFT scam: a malicious dApp tricks the wallet owner into signing a transaction ` +
        `that creates a sell offer for 0 XRP, making the NFT free for anyone to take.`
      );
    }

    // ── Inbound flow narrative ───────────────────────────────────────────
    if (inboundFlowAnalysis?.structuredFlag) {
      parts.push(
        `<strong>📥 Structured Inbound Pattern:</strong> ` +
        `${inboundFlowAnalysis.uniqueSources} source(s) funded this wallet — many payments arrive at near-identical amounts. ` +
        `Structured deposits deliberately break large transfers into smaller equal amounts to reduce traceability.`
      );
    } else if (inboundFlowAnalysis?.exchangeSrcs?.length) {
      const names = [...new Set(inboundFlowAnalysis.exchangeSrcs.map(s=>s.entity.name))].join(', ');
      parts.push(`<strong>📥 Funding Sources:</strong> Wallet received funds from ${inboundFlowAnalysis.uniqueSources} source(s) — ${names} among them. Total inbound: ${fmt(inboundFlowAnalysis.totalIn,2)} XRP.`);
    }

    // ── Memo narrative ────────────────────────────────────────────────────
    if (memoAnalysis?.scamMemos?.length) {
      parts.push(
        `<strong>📝 Scam Memo Content Detected:</strong> ` +
        `${memoAnalysis.scamMemos.length} transaction memo(s) contain text matching known scam patterns ` +
        `(airdrop claims, wallet verification requests, urgency language). ` +
        `These payments were likely sent by attackers attempting social engineering.`
      );
    }

    // ── Live book narrative ───────────────────────────────────────────────
    if (liveBookAnalysis?.signals?.some(s=>s.sev==='critical')) {
      parts.push(
        `<strong>📖 Active Spoofing Detected Right Now:</strong> ` +
        `This wallet currently has an order that controls over 40% of the visible order book depth. ` +
        `Large orders placed without intent to fill — then quickly cancelled when approached — is spoofing. ` +
        `This is happening in the live order book at time of inspection.`
      );
    }

    // ── Dest tag anomalies ────────────────────────────────────────────────
    if (destTagAnalysis?.riskPenalty > 0) {
      parts.push(`<strong>🏷 Destination Tag Pattern:</strong> Payments to exchanges used an unusually wide variety of destination tags — each tag identifies a different customer account. This can indicate a service routing payments to many accounts, or deliberate spread of deposits across exchange accounts to reduce traceability.`);
    }

    // ── Clean bill ────────────────────────────────────────────────────────
    if (criticals.length === 0 && warnings.length === 0) {
      parts.push(
        `<span style="color:#50fa7b"><strong>✅ No Elevated Signals Found</strong></span><br>` +
        `All checks returned results within normal ranges across ${coverageStr}. ` +
        `This does not guarantee the account is trustworthy — it means no identifiable red flags were found ` +
        `in the data analyzed.`
      );
    }

    // ── Coverage caveat ───────────────────────────────────────────────────
    parts.push(
      `<em style="opacity:.6;font-size:.86em">` +
      `Data coverage: ${coverageStr}. ` +
      (txList.length < 100 ? `Note: fewer than 100 transactions means some statistical tests may not reach reliable conclusions. ` : '') +
      `All findings are pattern-based. Legitimate market makers, automated services, and bots can trigger individual flags. ` +
      `None of these findings constitute legal proof of wrongdoing.</em>`
    );

    return parts;
  }

  // ── Module groups ────────────────────────────────────────────────────────
  const MODULE_META = {
    'Security':             { icon: '🔐', desc: 'Keys, flags, multisig, auth changes' },
    'Drain Risk':           { icon: '⚠️', desc: 'Auth changes → large outflows, external key injection' },
    'Fund Flow':            { icon: '🌊', desc: 'Exchange flows, black holes, new-wallet recipients, path routing' },
    'NFT':                  { icon: '🎨', desc: 'Zero-value offers, no-metadata tokens, burns' },
    'Wash Trading':         { icon: '📊', desc: 'Cancel ratios, self-trades, order uniformity, burst patterns' },
    "Benford's Law":        { icon: '📐', desc: 'First-digit natural distribution test on all amounts' },
    'Volume Concentration': { icon: '🫧', desc: 'How many wallets drive token trading volume' },
    "Shannon's Entropy":    { icon: '🔀', desc: 'Randomness of amounts, counterparties, timing, tx types' },
    "Zipf's Law":           { icon: '📈', desc: 'Counterparty frequency power-law distribution' },
    'Time Series':          { icon: '🕐', desc: 'Interval regularity, periodicity — bot vs human timing' },
    'Granger Causality':    { icon: '🔗', desc: 'Create→cancel cycles, inflow→outflow cycling' },
    'Token Issuer':         { icon: '🪙', desc: 'Supply, freeze state, concentration' },
    'AMM':                  { icon: '💧', desc: 'LP positions, pool TVL, ownership share' },
    'Issuer Connections':   { icon: '🕸', desc: 'Distribution patterns, mirror wallets, account creation chains' },
    'Fee Spikes':           { icon: '💸', desc: 'Elevated fee transactions — coordination signal' },
    'Destination Tags':     { icon: '🏷', desc: 'Exchange sub-account routing patterns' },
    'Path Payments':        { icon: '🔄', desc: 'Circular routing, self-routing, deep-hop obfuscation' },
    'Inbound Flow':         { icon: '📥', desc: 'Funding sources, exchange deposits, structured inbound patterns' },
    'Memo Analysis':        { icon: '📝', desc: 'Scam patterns, coordination text, hex-decoded memo data' },
    'Escrow Depth':         { icon: '🔒', desc: 'Third-party escrows, maturity dates, conditional locks' },
    'Live Order Book':      { icon: '📖', desc: 'Current spoofing detection — wall orders, book depth concentration' },
  };

  const moduleOrder = ['Security','Drain Risk','Fund Flow','NFT','Wash Trading',
    "Benford's Law",'Volume Concentration',"Shannon's Entropy","Zipf's Law",
    'Time Series','Granger Causality','Token Issuer','AMM','Issuer Connections',
    'Fee Spikes','Destination Tags','Path Payments'];

  const byModule = {};
  for (const m of moduleOrder)
    byModule[m] = allFindings.filter(f => f.module === m && f.sev !== 'ok' && f.sev !== 'info');

  const findingRows = moduleOrder
    .filter(m => byModule[m].length > 0)
    .map(m => {
      const meta = MODULE_META[m] || { icon: '📋', desc: '' };
      const rows = byModule[m].map(f => {
        // Build clickable hash links for findings that include transaction hashes
        const hashLinks = f.hashes?.length ? `
          <div style="margin-top:6px;display:flex;flex-wrap:wrap;gap:6px">
            ${f.hashes.slice(0,5).map(h => `
              <a href="https://livenet.xrpl.org/transactions/${escHtml(h)}" target="_blank" rel="noopener"
                 style="font-size:.7rem;font-family:monospace;color:var(--accent);text-decoration:none;
                        background:rgba(0,212,255,.06);border:1px solid rgba(0,212,255,.2);
                        border-radius:4px;padding:2px 6px" title="${escHtml(h)}">
                ${h.slice(0,8)}…${h.slice(-4)} 🔗
              </a>`).join('')}
          </div>` : '';
        return `
          <div class="report-finding-row">
            <div class="report-finding-top">
              ${sevBadge(f.sev)}
              <span class="report-finding-headline">${escHtml(f.headline)}</span>
            </div>
            ${f.detail ? `<div class="report-finding-detail">${escHtml(f.detail)}</div>` : ''}
            ${hashLinks}
          </div>`;
      }).join('');
      return `
        <div class="report-module">
          <div class="report-module-h">
            <span style="margin-right:6px">${meta.icon}</span>${escHtml(m)}
            <span style="font-size:.72rem;font-weight:400;opacity:.45;margin-left:8px">${escHtml(meta.desc)}</span>
          </div>
          ${rows}
        </div>`;
    }).join('');

  // ── Stats table ──────────────────────────────────────────────────────────
  const statRows = [
    { k: 'Address',                          v: addr,                                        mono: true },
    { k: 'Balance',                          v: fmt(balXrp, 4) + ' XRP' + _usd(balXrp),     mono: true },
    { k: 'Wallet Age',                       v: walletAgeDays != null ? (walletAgeDays < 1 ? 'Created today' : walletAgeDays + ' days') + (walletCreatedTs ? ' — created ' + new Date(walletCreatedTs).toLocaleDateString('en-US',{year:'numeric',month:'short',day:'numeric'}) : '') : '—' },
    { k: 'Risk Score',                       v: riskScore + '/100 — ' + riskWord,             color: riskColor },
    { k: 'Transactions Analyzed',            v: txList.length + (coverageDateStr ? ' · ' + coverageDateStr : '') },
    { k: 'Activity Span',                    v: coverageSpanDays > 0 ? coverageSpanDays + ' days' : 'unknown' },
    { k: 'Outbound Destinations',            v: fundFlowAnalysis.uniqueDests + ' addresses received funds' },
    { k: 'Total XRP Sent Out',               v: fmt(fundFlowAnalysis.totalOut, 2) + ' XRP',  mono: true },
    { k: 'New-Wallet Recipients',            v: (fundFlowAnalysis.newWalletDests?.length || 0) + (fundFlowAnalysis.newWalletDests?.length ? ' ⚠' : ' — none'), color: fundFlowAnalysis.newWalletDests?.length ? '#ff5555' : null },
    { k: 'Wash Trading Score',               v: (washAnalysis.score||0) + '/100 — ' + (washAnalysis.verdict||'—').replace('-',' ') + (washAnalysis.score < 25 ? ' ✓' : washAnalysis.score < 50 ? ' ⚠ moderate' : ' 🚨 elevated') },
    { k: 'Fee Spike Count (>100× base)',     v: (feeAnalysis?.spikeCount ?? 'N/A') + (feeAnalysis?.spikeCount > 5 ? ' ⚠' : ''), mono: true },
    { k: "Benford χ² (normal ≤ 15.5)",       v: benfordsAnalysis.chiSq != null ? benfordsAnalysis.chiSq.toFixed(2) + ' — ' + benfordsAnalysis.verdict.replace('-',' ') : 'insufficient data', mono: true },
    { k: 'Amount Entropy (natural 2.4–4.2)', v: entropyAnalysis?.amountEntropy != null ? entropyAnalysis.amountEntropy.toFixed(2) + ' bits' : 'N/A', mono: true },
    { k: 'Zipf Exponent (natural 0.8–1.3)',  v: zipfAnalysis?.zipfExponent != null ? zipfAnalysis.zipfExponent.toFixed(3) + '  R²=' + zipfAnalysis.rSquared?.toFixed(2) : 'N/A', mono: true },
    { k: 'Timing Regularity CV (bot < 0.25)',v: timeSeriesAnalysis?.intervalCV != null ? timeSeriesAnalysis.intervalCV.toFixed(3) + (timeSeriesAnalysis.intervalCV < 0.25 ? ' ⚠ bot-level' : ' ✓') : 'N/A', mono: true },
    { k: 'Granger OC Correlation',           v: grangerAnalysis?.offerCancelCausality?.maxCorr != null ? grangerAnalysis.offerCancelCausality.maxCorr.toFixed(3) + (grangerAnalysis.offerCancelCausality.maxCorr > 0.55 ? ' ⚠' : ' ✓') : 'N/A', mono: true },
    { k: 'XRP→IOU→XRP Round-Trips',         v: (pathDepthAnalysis?.roundTripCount ?? 0) + (pathDepthAnalysis?.roundTripCount >= 3 ? ' ⚠' : ''), mono: true },
    { k: 'Token Holders',                    v: issuerConnAnalysis.holderCount > 0 ? issuerConnAnalysis.holderCount + ' wallets hold tokens from this issuer' : 'Not a token issuer' },
    { k: 'Critical Findings',               v: criticals.length + (criticals.length === 0 ? ' — none' : ''), color: criticals.length > 0 ? '#ff5555' : '#50fa7b' },
    { k: 'Warnings',                         v: warnings.length  + (warnings.length  === 0 ? ' — none' : ''), color: warnings.length  > 0 ? '#ffb86c' : '#50fa7b' },
  ].map(r => `
    <div class="report-stat-row">
      <span class="report-stat-k">${escHtml(r.k)}</span>
      <span class="report-stat-v ${r.mono ? 'mono' : ''}" style="${r.color ? 'color:' + r.color : ''}">${escHtml(String(r.v))}</span>
    </div>`).join('');

  // ── Recommendations ──────────────────────────────────────────────────────
  const recColors   = { critical:'rgba(255,85,85,.08)',  warn:'rgba(255,184,108,.06)', info:'rgba(120,180,255,.05)', ok:'rgba(80,250,123,.05)' };
  const recBorders  = { critical:'rgba(255,85,85,.25)',  warn:'rgba(255,184,108,.20)', info:'rgba(120,180,255,.15)', ok:'rgba(80,250,123,.15)' };

  const recs = [];
  if (drainAnalysis.riskLevel === 'critical' || drainAnalysis.riskLevel === 'high')
    recs.push({ icon:'🔴', sev:'critical', text: 'If this is your wallet: stop sending funds here immediately. The account\'s security keys match a known drain attack pattern. Contact a security professional or the XRPL community before taking any action.' });
  if (fundFlowAnalysis.newWalletDests?.length)
    recs.push({ icon:'⚠️', sev:'critical', text: `${fundFlowAnalysis.newWalletDests.length} brand-new wallet(s) received large XRP transfers. This is a classic drain pattern. If this was unexpected, the funds have likely already been moved further down the chain.` });
  if (fundFlowAnalysis.blackHoleDests?.length)
    recs.push({ icon:'⛔', sev:'critical', text: 'Funds sent to black hole addresses are gone permanently. No exchange, no support team, and no legal action can retrieve them.' });
  if (fundFlowAnalysis.exchangeDests?.length)
    recs.push({ icon:'💱', sev:'warn', text: `If this was a drain: contact ${[...new Set(fundFlowAnalysis.exchangeDests.map(d => d.entity.name))].join(', ')} exchange support immediately with the transaction hashes from the Fund Flow section. Act within hours — exchanges can sometimes freeze funds quickly but not after they've been withdrawn.` });
  if (washAnalysis.score >= 60)
    recs.push({ icon:'📊', sev:'warn', text: 'Significant wash trading signals detected. If you\'re a market maker: high cancel ratios are normal for your role — review the self-trade and self-routing signals specifically. If you\'re a token holder or researcher: this pattern suggests the token\'s apparent volume may be artificial.' });
  if (pathDepthAnalysis?.selfRoutedCount > 0)
    recs.push({ icon:'🔄', sev:'warn', text: `${pathDepthAnalysis.selfRoutedCount} path payment(s) routed XRP from and back to the same address through the DEX. This creates artificial trading volume on every intermediate pair. Check the Path Payments section for specific transaction hashes.` });
  if (issuerConnAnalysis.mirrorGroups?.length)
    recs.push({ icon:'🕸', sev:'warn', text: 'Mirror wallet clusters found. If you are the issuer, determine whether these are genuine holders or insider accounts used to create the appearance of broader distribution. These wallets could coordinate a sell-off.' });
  if (nftAnalysis.flags?.some(f => f.sev === 'critical'))
    recs.push({ icon:'🎨', sev:'critical', text: 'Zero-value NFT offer detected. If you didn\'t intentionally list your NFT for free: identify what website or app you used around the time this transaction was signed, and revoke any approvals it has.' });
  if (feeAnalysis?.verdict === 'elevated')
    recs.push({ icon:'💸', sev:'info', text: `${feeAnalysis.spikeCount} transactions paid >100× normal fees. Check the Fee Spikes section to see if these align with moments of concentrated trading — elevated fees often mark coordinated activity windows.` });
  if (recs.length === 0)
    recs.push({ icon:'✅', sev:'ok', text: 'No immediate actions required. The account shows no identifiable red flags. Continue monitoring as activity grows — some patterns only become statistically significant with more data.' });

  const recsHtml = recs.map(r => `
    <div style="background:${recColors[r.sev]||recColors.info};border:1px solid ${recBorders[r.sev]||recBorders.info};border-radius:10px;padding:12px 14px;margin-bottom:8px;display:flex;gap:12px;align-items:flex-start">
      <span style="font-size:1.15rem;flex-shrink:0;margin-top:1px">${r.icon}</span>
      <span style="font-size:.85rem;line-height:1.65;color:rgba(255,255,255,.78)">${r.text}</span>
    </div>`).join('');

  // ── Glossary ─────────────────────────────────────────────────────────────
  const glossaryTerms = [
    ["Benford's Law",      "In organic financial data, amounts starting with '1' appear ~30% of the time. Computer-generated amounts often break this law."],
    ["Shannon's Entropy",  "Measures how 'predictable' transaction amounts and partners are. Bots repeat the same amounts; humans don't."],
    ["Zipf's Law",         "Natural networks have a few heavy relationships and many light ones. Wash rings show unnaturally equal relationships."],
    ["Time Series CV",     "Coefficient of Variation of gaps between transactions. Humans: >0.8 (irregular). Bots: <0.3 (clock-like)."],
    ["Granger Causality",  "Tests if one event type systematically causes another — e.g., every offer creation is followed by a cancellation at a predictable lag."],
    ["Interval CV",        "The regularity of timing between transactions. Very low = mechanical/automated. Very high = erratic/bursty."],
    ["Gateway Balances",   "The XRPL API command that returns the true outstanding obligations of a token issuer — more accurate than just reading trustlines."],
    ["Destination Tag",    "A number attached to a payment that identifies the recipient sub-account at an exchange. Like a bank account reference number."],
    ["Path Payment",       "An XRPL payment that routes through intermediate DEX pairs. Can create trading volume on pairs the sender never intended to trade."],
    ["XRP Round-Trip",     "A path payment that starts and ends in XRP, routed through IOU pairs. Creates DEX volume with no net economic transfer."],
    ["Fee Multiplier",     "XRPL's base transaction fee is 12 drops (~$0.000001). Paying 100× means paying 1,200 drops — bots do this for guaranteed same-ledger execution."],
  ];

  const glossaryHtml = `
    <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:8px;margin-top:10px">
      ${glossaryTerms.map(([term, def]) => `
        <div style="background:rgba(255,255,255,.03);border-radius:8px;padding:10px 12px;border:1px solid rgba(255,255,255,.05)">
          <div style="font-size:.78rem;font-weight:700;color:rgba(255,255,255,.75);margin-bottom:4px">${escHtml(term)}</div>
          <div style="font-size:.74rem;color:rgba(255,255,255,.42);line-height:1.5">${escHtml(def)}</div>
        </div>`).join('')}
    </div>`;

  const narrativeParts = buildNarrative();

  return `
    <div class="report-wrap">

      <!-- ── Cover ── -->
      <div class="report-cover">
        <div class="report-cover-left">
          <div class="report-logo">⚡ NaluXRP</div>
          <h2 class="report-title">Account Investigation Report</h2>
          <div class="report-addr mono">${escHtml(addr)}</div>
          <div class="report-ts">Generated ${ts}</div>
          <div style="font-size:.75rem;color:rgba(255,255,255,.38);margin-top:4px">Coverage: ${escHtml(coverageStr)}</div>
        </div>
        <div class="report-score-circle" style="--score-color:${riskColor}">
          <div class="report-score-num" style="color:${riskColor}">${riskScore}</div>
          <div class="report-score-den">/100</div>
          <div class="report-score-word" style="color:${riskColor}">${riskWord}</div>
        </div>
      </div>

      <!-- ── Executive Summary ── -->
      <div class="report-section">
        <h3 class="report-section-h">📋 Executive Summary</h3>
        <div class="report-narrative">
          ${narrativeParts.map(p => `<p style="margin-bottom:12px;line-height:1.7">${p}</p>`).join('')}
        </div>
      </div>

      <!-- ── Stats Snapshot ── -->
      <div class="report-section">
        <h3 class="report-section-h">📐 Account Snapshot
          <button onclick="exportTxCSV(window._lastTxList)" title="Export all transactions to CSV"
            style="margin-left:12px;background:rgba(0,212,255,.10);border:1px solid rgba(0,212,255,.25);
                   color:var(--accent);border-radius:6px;padding:3px 10px;font-size:.7rem;cursor:pointer">
            ⬇ Export CSV
          </button>
        </h3>
        <div class="report-stats-grid">${statRows}</div>
      </div>

      <!-- ── Findings by Module ── -->
      ${findingRows ? `
      <div class="report-section">
        <h3 class="report-section-h">🔬 Findings by Module
          <span class="report-counts">
            <span class="report-count report-count--crit">${criticals.length} Critical</span>
            <span class="report-count report-count--warn">${warnings.length} Warnings</span>
          </span>
        </h3>
        <p style="font-size:.8rem;color:rgba(255,255,255,.4);margin-bottom:14px;line-height:1.6">
          Each module below used a different method to analyse the account.
          Findings include clickable transaction hash links so you can verify everything on-chain.
        </p>
        <div class="report-findings">${findingRows}</div>
      </div>` : `
      <div class="report-section">
        <h3 class="report-section-h">🔬 Findings</h3>
        <div class="report-clean-note">✅ No elevated findings across all ${moduleOrder.length} analysis modules.</div>
      </div>`}

      <!-- ── Recommendations ── -->
      <div class="report-section">
        <h3 class="report-section-h">💡 Recommended Actions</h3>
        ${recsHtml}
      </div>

      <!-- ── Glossary ── -->
      <div class="report-section">
        <h3 class="report-section-h">📖 Understanding This Report</h3>
        <p style="font-size:.82rem;color:rgba(255,255,255,.45);line-height:1.65;margin-bottom:10px">
          Plain-English definitions for every technical term used in this report.
        </p>
        ${glossaryHtml}
      </div>

      <!-- ── Disclaimer ── -->
      <div class="report-disclaimer">
        <strong>Important:</strong> This report is generated automatically from public on-chain data using
        statistical pattern analysis. Signals are not proof. Legitimate market makers, bots, and active
        users can trigger individual flags. Always cross-reference with additional evidence before making
        legal, financial, or reputational decisions. NaluXRP Inspector is a transparency and research tool —
        not a legal or forensic authority.
      </div>

    </div>
  `;
}

function renderFullReport(container, ...args) {
  container.innerHTML = generateFullReport(...args);
}

/* ═══════════════════════════════════════════════════
   HTML SELF-MOUNT
═══════════════════════════════════════════════════ */
function _mountInspectorHTML() {
  const panel = document.getElementById('tab-inspector');
  // Force-replace whenever our version marker is absent
  if (!panel) return;
  if (panel.querySelector('[data-inspector-v2]')) return;

  panel.innerHTML = `
    <div class="inspector-wrap" data-inspector-v2="1">

      <div class="inspector-page-header">
        <div class="inspector-title-row">
          <h1 class="inspector-page-title">🔍 Account Inspector</h1>
          <button class="inspector-howto-btn" onclick="showInspectorHowTo()">
            <span>?</span> How to use
          </button>
        </div>
        <p class="inspector-sub">
          Deep-dive any XRPL address — security posture, drain risk, NFT exposure,
          wash-trading signals, token issuer status and AMM liquidity positions.
        </p>
      </div>

      <div class="search-row">
        <input id="inspect-addr" class="xrpl-input" type="text"
          placeholder="rXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
          autocomplete="off" spellcheck="false"
          aria-label="XRPL address to inspect" />
        <button class="xrpl-btn btn-inspect" onclick="runInspect()">Inspect →</button>
      </div>

      <div id="inspect-warn"    class="alert-warn"    style="display:none">⚡ Not connected — connect to an XRPL node first.</div>
      <div id="inspect-err"     class="alert-err"     style="display:none"></div>
      <div id="inspect-loading" class="inspect-loading-state" style="display:none">
        <div class="inspect-spinner"></div>
        <span id="inspect-loading-msg">Analyzing…</span>
      </div>

      <!-- ══ Initial State Dashboard ══ -->
      <div id="inspect-empty">

        <!-- ── Network health strip ── -->
        <div class="isd-net-strip">

          <!-- Status pill -->
          <div class="isd-conn-pill" id="isd-conn-pill">
            <span class="isd-conn-dot" id="isd-conn-dot"></span>
            <span id="isd-conn-label">Connecting…</span>
          </div>

          <!-- Live metrics -->
          <div class="isd-metrics-row">

            <div class="isd-metric-card">
              <div class="isd-metric-label">Ledger</div>
              <div class="isd-metric-val mono" id="isd-ledger-idx">—</div>
              <div class="isd-metric-sub" id="isd-ledger-age">—</div>
            </div>

            <div class="isd-metric-card">
              <div class="isd-metric-label">TPS</div>
              <div class="isd-metric-val" id="isd-tps">—</div>
              <div class="isd-metric-sub" id="isd-tps-trend">waiting…</div>
            </div>

            <div class="isd-metric-card">
              <div class="isd-metric-label">Avg Fee</div>
              <div class="isd-metric-val mono" id="isd-fee">—</div>
              <div class="isd-metric-sub" id="isd-fee-level">—</div>
            </div>

            <div class="isd-metric-card">
              <div class="isd-metric-label">Close Time</div>
              <div class="isd-metric-val" id="isd-close-time">—</div>
              <div class="isd-metric-sub">secs / ledger</div>
            </div>

            <div class="isd-metric-card">
              <div class="isd-metric-label">Reserve</div>
              <div class="isd-metric-val mono" id="isd-reserve">10 XRP</div>
              <div class="isd-metric-sub">+2 per object</div>
            </div>

            <div class="isd-metric-card">
              <div class="isd-metric-label">Dominant TX</div>
              <div class="isd-metric-val" id="isd-dom-tx">—</div>
              <div class="isd-metric-sub" id="isd-dom-pct">—</div>
            </div>

          </div>

          <!-- Fee pressure bar -->
          <div class="isd-fee-bar-wrap">
            <span class="isd-fee-bar-label">Fee Pressure</span>
            <div class="isd-fee-bar-track">
              <div class="isd-fee-bar-fill" id="isd-fee-bar"></div>
            </div>
            <span class="isd-fee-bar-level" id="isd-fee-bar-label">Low</span>
          </div>

        </div>

        <!-- ── My Wallets ── -->
        <div class="isd-section" id="isd-wallets-section" style="display:none">
          <div class="isd-section-hdr">
            <div class="isd-section-left">
              <span class="isd-section-icon">💼</span>
              <span class="isd-section-title">My Wallets</span>
            </div>
            <span class="isd-section-hint">tap to inspect</span>
          </div>
          <div class="isd-wallet-grid" id="isd-wallet-list"></div>
        </div>

        <!-- ── Recent Inspections ── -->
        <div class="isd-section" id="isd-recent-section" style="display:none">
          <div class="isd-section-hdr">
            <div class="isd-section-left">
              <span class="isd-section-icon">🕐</span>
              <span class="isd-section-title">Recent Inspections</span>
            </div>
            <button class="isd-text-btn" onclick="inspectorClearHistory()">Clear all</button>
          </div>
          <div class="isd-recent-list" id="isd-recent-list"></div>
        </div>

        <!-- ── Notable Addresses ── -->
        <div class="isd-section">
          <div class="isd-section-hdr">
            <div class="isd-section-left">
              <span class="isd-section-icon">🌐</span>
              <span class="isd-section-title">Notable XRPL Addresses</span>
            </div>
            <span class="isd-section-hint">tap to explore</span>
          </div>
          <div class="isd-notable-grid" id="isd-notable-grid"></div>
        </div>

        <!-- ── What We Detect ── -->
        <div class="isd-section">
          <div class="isd-section-hdr">
            <div class="isd-section-left">
              <span class="isd-section-icon">🛡</span>
              <span class="isd-section-title">What The Inspector Detects</span>
            </div>
          </div>
          <div class="isd-cap-grid" id="isd-cap-grid"></div>
        </div>

      </div>

      <div id="inspect-result" style="display:none">

        <div class="inspect-risk-banner">
          <div class="irb-left">
            <button class="irb-back-btn" onclick="inspectorGoBack()" title="Back to search">← Back</button>
            <div class="irb-addr-group">
              <span class="irb-addr mono" id="inspect-addr-badge">—</span>
              <button class="irb-copy-btn" onclick="inspectorCopyAddr()" title="Copy address">📋</button>
            </div>
          </div>
          <div class="irb-score-group">
            <div class="irb-score-val" id="inspect-risk-score">—</div>
            <div class="irb-score-label" id="inspect-risk-label">Risk Score</div>
          </div>
        </div>

        <section class="widget-card inspector-section" id="section-overview">
          <header class="widget-header section-header">
            <span class="widget-title">📊 Account Overview</span>
            <span class="section-chevron">▾</span>
          </header>
          <div class="section-body account-grid" id="inspect-acct-grid"></div>
          <div id="inspect-risk-breakdown" style="padding:0 12px 12px"></div>
        </section>

        <section class="widget-card inspector-section" id="section-security">
          <header class="widget-header section-header">
            <span class="widget-title">🔐 Security Audit</span>
            <span class="section-badge" id="badge-security"></span>
            <span class="section-chevron">▾</span>
          </header>
          <div class="section-body" id="inspect-security-body"></div>
        </section>

        <section class="widget-card inspector-section" id="section-drain">
          <header class="widget-header section-header">
            <span class="widget-title">⚠ Drain Risk</span>
            <span class="section-badge" id="badge-drain"></span>
            <span class="section-chevron">▾</span>
          </header>
          <div class="section-body" id="inspect-drain-body"></div>
        </section>

        <section class="widget-card inspector-section" id="section-fundflow">
          <header class="widget-header section-header">
            <span class="widget-title">🌊 Fund Flow Tracer</span>
            <span class="section-badge" id="badge-fundflow"></span>
            <span class="section-chevron">▾</span>
          </header>
          <div class="section-body" id="inspect-fundflow-body">
            <p class="widget-help" style="opacity:.6;font-size:.84rem">
              Traces every outbound payment — shows where funds went, which exchanges they reached,
              multi-hop path payment routes, and a chronological drain timeline.
            </p>
          </div>
        </section>

        <section class="widget-card inspector-section" id="section-inbound">
          <header class="widget-header section-header">
            <span class="widget-title">📥 Inbound Flow Analysis</span>
            <span class="section-badge" id="badge-inbound"></span>
            <span class="section-chevron">▾</span>
          </header>
          <div class="section-body" id="inspect-inbound-body">
            <p class="widget-help" style="opacity:.55;font-size:.84rem">
              Who funded this wallet — top sources, exchange withdrawals, structured deposit patterns,
              and single-source concentration. Pairs with Fund Flow for a complete in/out picture.
            </p>
          </div>
        </section>

        <section class="widget-card inspector-section" id="section-nft">
          <header class="widget-header section-header">
            <span class="widget-title">🎨 NFT Analysis</span>
            <span class="section-badge" id="badge-nft"></span>
            <span class="section-chevron">▾</span>
          </header>
          <div class="section-body" id="inspect-nft-body"></div>
        </section>

        <section class="widget-card inspector-section" id="section-wash">
          <header class="widget-header section-header">
            <span class="widget-title">📊 Wash Trading</span>
            <span class="section-badge" id="badge-wash"></span>
            <span class="section-chevron">▾</span>
          </header>
          <div class="section-body" id="inspect-wash-body"></div>
        </section>

        <section class="widget-card inspector-section" id="section-benfords">
          <header class="widget-header section-header">
            <span class="widget-title">📐 Benford's Law</span>
            <span class="section-badge" id="badge-benfords"></span>
            <span class="section-chevron">▾</span>
          </header>
          <div class="section-body" id="inspect-benfords-body"></div>
        </section>

        <section class="widget-card inspector-section" id="section-entropy">
          <header class="widget-header section-header">
            <span class="widget-title">🔀 Shannon's Entropy</span>
            <span class="section-badge" id="badge-entropy"></span>
            <span class="section-chevron">▾</span>
          </header>
          <div class="section-body" id="inspect-entropy-body">
            <p class="widget-help" style="opacity:.55;font-size:.84rem">
              Measures information randomness across transaction amounts, counterparty diversity,
              time-of-day distribution, and transaction type mix. Low entropy = bot repetition.
              High entropy = artificial randomization to evade Benford detection.
            </p>
          </div>
        </section>

        <section class="widget-card inspector-section" id="section-zipf">
          <header class="widget-header section-header">
            <span class="widget-title">📈 Zipf's Law</span>
            <span class="section-badge" id="badge-zipf"></span>
            <span class="section-chevron">▾</span>
          </header>
          <div class="section-body" id="inspect-zipf-body">
            <p class="widget-help" style="opacity:.55;font-size:.84rem">
              Tests whether counterparty frequency follows the natural power-law rank distribution.
              Flat distribution (Zipf exponent &lt; 0.4) signals wash-trading ring structure.
              Poor R² fit signals artificially constructed interaction patterns.
            </p>
          </div>
        </section>

        <section class="widget-card inspector-section" id="section-timeseries">
          <header class="widget-header section-header">
            <span class="widget-title">🕐 Time Series Analysis</span>
            <span class="section-badge" id="badge-timeseries"></span>
            <span class="section-chevron">▾</span>
          </header>
          <div class="section-body" id="inspect-timeseries-body">
            <p class="widget-help" style="opacity:.55;font-size:.84rem">
              Interval CV, periodicity score, burst detection, day-of-week entropy, and lag-1
              autocorrelation. Bots transact mechanically (CV &lt; 0.25). Humans are irregular and bursty.
            </p>
          </div>
        </section>

        <section class="widget-card inspector-section" id="section-granger">
          <header class="widget-header section-header">
            <span class="widget-title">🔗 Granger Causality</span>
            <span class="section-badge" id="badge-granger"></span>
            <span class="section-chevron">▾</span>
          </header>
          <div class="section-body" id="inspect-granger-body">
            <p class="widget-help" style="opacity:.55;font-size:.84rem">
              Cross-correlation lag analysis: does offer creation cause cancellation?
              Does inflow cause outflow? Strong lead-lag correlation at short windows
              is the temporal signature of wash trading and fund cycling.
            </p>
          </div>
        </section>

        <section class="widget-card inspector-section" id="section-forensic-suite" style="border-color:rgba(0,212,255,.2)">
          <header class="widget-header section-header" style="background:rgba(0,212,255,.03)">
            <span class="widget-title">🧬 Forensic Analytics Suite — Combined Report</span>
            <span class="section-badge" id="badge-forensic-suite" style="background:rgba(0,212,255,.12);color:var(--accent);border-color:rgba(0,212,255,.3)">5 Engines</span>
            <span class="section-chevron">▾</span>
          </header>
          <div class="section-body" id="inspect-forensic-suite-body">
            <p class="widget-help" style="opacity:.55;font-size:.84rem">
              Synthesizes Benford's Law, Shannon's Entropy, Zipf's Law, Time Series, and Granger Causality
              into a single convergence verdict. Multiple engines flagging simultaneously is substantially
              stronger evidence than any single engine alone.
            </p>
          </div>
        </section>

        <section class="widget-card inspector-section" id="section-volconc">
          <header class="widget-header section-header">
            <span class="widget-title">🫧 Volume Concentration</span>
            <span class="section-badge" id="badge-volconc"></span>
            <span class="section-chevron">▾</span>
          </header>
          <div class="section-body" id="inspect-volconc-body"></div>
        </section>

        <section class="widget-card inspector-section" id="section-issuer">
          <header class="widget-header section-header">
            <span class="widget-title">🪙 Token Issuer</span>
            <span class="section-badge" id="badge-issuer"></span>
            <span class="section-chevron">▾</span>
          </header>
          <div class="section-body" id="inspect-issuer-body"></div>
        </section>

        <section class="widget-card inspector-section" id="section-issuer-connections">
          <header class="widget-header section-header">
            <span class="widget-title">🕸 Issuer Connection Graph</span>
            <span class="section-badge" id="badge-issuer-connections"></span>
            <span class="section-chevron">▾</span>
          </header>
          <div class="section-body" id="inspect-issuer-connections-body">
            <p class="widget-help" style="opacity:.6;font-size:.84rem">
              Token supply distribution, holder concentration, accounts created by this issuer,
              and mirror-wallet clusters (accounts receiving identical amounts — possible sybil rings).
            </p>
          </div>
        </section>

        <section class="widget-card inspector-section" id="section-amm">
          <header class="widget-header section-header">
            <span class="widget-title">💧 AMM / Liquidity</span>
            <span class="section-badge" id="badge-amm"></span>
            <span class="section-chevron">▾</span>
          </header>
          <div class="section-body" id="inspect-amm-body"></div>
        </section>

        <section class="widget-card inspector-section" id="section-fee-analysis">
          <header class="widget-header section-header">
            <span class="widget-title">💸 Fee Spike Analysis</span>
            <span class="section-badge" id="badge-fee-analysis"></span>
            <span class="section-chevron">▾</span>
          </header>
          <div class="section-body" id="inspect-fee-analysis-body">
            <p class="widget-help" style="opacity:.55;font-size:.84rem">
              Detects transactions where fees were paid at 100× or more above the base rate.
              Bots overpay fees to guarantee same-ledger execution alongside a counterparty —
              a coordination technique used in wash trading and front-running.
            </p>
          </div>
        </section>

        <section class="widget-card inspector-section" id="section-desttag">
          <header class="widget-header section-header">
            <span class="widget-title">🏷 Destination Tag Patterns</span>
            <span class="section-badge" id="badge-desttag"></span>
            <span class="section-chevron">▾</span>
          </header>
          <div class="section-body" id="inspect-desttag-body">
            <p class="widget-help" style="opacity:.55;font-size:.84rem">
              Analyses destination tags used in exchange payments. The same tag repeated = one person's exchange account.
              Many different tags = a service routing to many accounts, or deliberate deposit spreading.
            </p>
          </div>
        </section>

        <section class="widget-card inspector-section" id="section-pathdepth">
          <header class="widget-header section-header">
            <span class="widget-title">🔄 Path Payment Depth</span>
            <span class="section-badge" id="badge-pathdepth"></span>
            <span class="section-chevron">▾</span>
          </header>
          <div class="section-body" id="inspect-pathdepth-body">
            <p class="widget-help" style="opacity:.55;font-size:.84rem">
              Analyses multi-hop path payments for circular routing (XRP→IOU→XRP round-trips),
              self-routing (paying yourself through the DEX to generate artificial volume),
              and deep hop chains that may obscure fund origin.
            </p>
          </div>
        </section>

        <section class="widget-card inspector-section" id="section-memos" style="display:none">
          <header class="widget-header section-header">
            <span class="widget-title">📝 Memo Analysis</span>
            <span class="section-badge" id="badge-memos"></span>
            <span class="section-chevron">▾</span>
          </header>
          <div class="section-body" id="inspect-memos-body">
            <p class="widget-help" style="opacity:.55;font-size:.84rem">
              Scans all memo fields for scam patterns, repeated coordination text, and hex-encoded data.
              Memos are a vector for social engineering — attackers embed instructions inside payments.
            </p>
          </div>
        </section>

        <section class="widget-card inspector-section" id="section-escrow-depth" style="display:none">
          <header class="widget-header section-header">
            <span class="widget-title">🔒 Escrow Depth</span>
            <span class="section-badge" id="badge-escrow-depth"></span>
            <span class="section-chevron">▾</span>
          </header>
          <div class="section-body" id="inspect-escrow-depth-body">
            <p class="widget-help" style="opacity:.55;font-size:.84rem">
              Identifies third-party escrows (created by external accounts), maturity dates,
              and conditional escrows. Third-party escrows can lock funds with conditions the wallet owner didn't set.
            </p>
          </div>
        </section>

        <section class="widget-card inspector-section" id="section-checks" style="display:none">
          <header class="widget-header section-header">
            <span class="widget-title">🧾 Open Checks</span>
            <span class="section-badge" id="badge-checks"></span>
            <span class="section-chevron">▾</span>
          </header>
          <div class="section-body" id="inspect-checks-body">
            <p class="widget-help" style="opacity:.55;font-size:.84rem">
              XRPL Checks are deferred payments — like a paper check, the recipient can cash them at any time.
              Open checks represent future outflow commitments. Expired checks waste reserve slots.
            </p>
          </div>
        </section>

        <section class="widget-card inspector-section" id="section-livebook" style="display:none">
          <header class="widget-header section-header">
            <span class="widget-title">📖 Live Order Book</span>
            <span class="section-badge" id="badge-livebook"></span>
            <span class="section-chevron">▾</span>
          </header>
          <div class="section-body" id="inspect-livebook-body">
            <p class="widget-help" style="opacity:.55;font-size:.84rem">
              Current live order book for this wallet's most-traded pair.
              Detects wall orders (one address dominating book depth), uniform bot-placed sizes,
              and whether this wallet's open offers make up an unusual share of visible liquidity.
            </p>
          </div>
        </section>

        <section class="widget-card inspector-section" id="section-trustlines">
          <header class="widget-header section-header">
            <span class="widget-title">🔗 Trustlines</span>
            <span class="section-badge section-badge--neutral" id="trust-count-badge">0</span>
            <span class="section-chevron">▾</span>
          </header>
          <div class="section-body" id="inspect-trust-body"></div>
        </section>

        <section class="widget-card inspector-section" id="section-tx">
          <header class="widget-header section-header">
            <span class="widget-title">📜 Transaction History</span>
            <span class="section-badge section-badge--neutral" id="badge-tx">—</span>
            <span class="section-chevron">▾</span>
          </header>
          <div class="section-body" id="inspect-tx-timeline"></div>
        </section>

        <section class="widget-card inspector-section report-card" id="section-report">
          <header class="widget-header section-header">
            <span class="widget-title">📄 Full Investigation Report</span>
            <span class="section-badge section-badge--neutral" id="badge-report">Auto-generated</span>
            <button class="report-export-btn" id="report-export-btn" onclick="exportInspectorReport()" title="Copy report to clipboard">📋 Copy</button>
            <button class="report-export-btn" onclick="printInspectorReport()" title="Print or save as PDF" style="margin-left:4px">🖨 Print / PDF</button>
            <span class="section-chevron">▾</span>
          </header>
          <div class="section-body" id="inspect-report-body">
            <p class="widget-help" style="opacity:.55;font-size:.84rem">
              A plain-English summary of every finding, recommended actions, and a full data snapshot.
              Generates automatically after each inspection.
            </p>
          </div>
        </section>

      </div>
    </div>
  `;
}

/* ═══════════════════════════════════════════════════
   BOTTOM NAV
═══════════════════════════════════════════════════ */
function _mountInspectorNav() {
  if (document.getElementById('inspector-nav')) return;

  const nav = document.createElement('nav');
  nav.id = 'inspector-nav';
  nav.setAttribute('aria-label', 'Inspector navigation');
  nav.innerHTML = `
    <div class="inspector-nav-track">

      <div class="nav-group nav-group--security">
        <div class="nav-group-label">Security</div>
        <div class="nav-group-btns">
          <button class="in-btn" data-jump="security"><span class="in-icon">🔐</span><span class="in-label">Security</span></button>
          <button class="in-btn" data-jump="drain"><span class="in-icon">⚠️</span><span class="in-label">Drain</span></button>
          <button class="in-btn" data-jump="fundflow"><span class="in-icon">🌊</span><span class="in-label">Flow</span></button>
          <button class="in-btn" data-jump="inbound"><span class="in-icon">📥</span><span class="in-label">Inbound</span></button>
          <button class="in-btn" data-jump="nft"><span class="in-icon">🎨</span><span class="in-label">NFT</span></button>
        </div>
      </div>

      <div class="nav-group-divider"></div>

      <div class="nav-group nav-group--analytics">
        <div class="nav-group-label">Analytics</div>
        <div class="nav-group-btns">
          <button class="in-btn" data-jump="wash"><span class="in-icon">📊</span><span class="in-label">Wash</span></button>
          <button class="in-btn" data-jump="benfords"><span class="in-icon">📐</span><span class="in-label">Benford</span></button>
          <button class="in-btn" data-jump="entropy"><span class="in-icon">🔀</span><span class="in-label">Entropy</span></button>
          <button class="in-btn" data-jump="zipf"><span class="in-icon">📈</span><span class="in-label">Zipf</span></button>
          <button class="in-btn" data-jump="timeseries"><span class="in-icon">🕐</span><span class="in-label">Time Series</span></button>
          <button class="in-btn" data-jump="granger"><span class="in-icon">🔗</span><span class="in-label">Granger</span></button>
          <button class="in-btn in-btn--suite" data-jump="forensic-suite"><span class="in-icon">🧬</span><span class="in-label">Suite</span></button>
        </div>
      </div>

      <div class="nav-group-divider"></div>

      <div class="nav-group nav-group--account">
        <div class="nav-group-label">Account</div>
        <div class="nav-group-btns">
          <button class="in-btn" data-jump="volconc"><span class="in-icon">🫧</span><span class="in-label">Vol</span></button>
          <button class="in-btn" data-jump="issuer"><span class="in-icon">🪙</span><span class="in-label">Issuer</span></button>
          <button class="in-btn" data-jump="issuer-connections"><span class="in-icon">🕸</span><span class="in-label">Network</span></button>
          <button class="in-btn" data-jump="amm"><span class="in-icon">💧</span><span class="in-label">AMM</span></button>
        </div>
      </div>

      <div class="nav-group-divider"></div>

      <div class="nav-group nav-group--data">
        <div class="nav-group-label">Data</div>
        <div class="nav-group-btns">
          <button class="in-btn" data-jump="fee-analysis"><span class="in-icon">💸</span><span class="in-label">Fees</span></button>
          <button class="in-btn" data-jump="desttag"><span class="in-icon">🏷</span><span class="in-label">Tags</span></button>
          <button class="in-btn" data-jump="pathdepth"><span class="in-icon">🔄</span><span class="in-label">Paths</span></button>
          <button class="in-btn" data-jump="memos"><span class="in-icon">📝</span><span class="in-label">Memos</span></button>
          <button class="in-btn" data-jump="escrow-depth"><span class="in-icon">🔒</span><span class="in-label">Escrow</span></button>
          <button class="in-btn" data-jump="checks"><span class="in-icon">🧾</span><span class="in-label">Checks</span></button>
          <button class="in-btn" data-jump="livebook"><span class="in-icon">📖</span><span class="in-label">Book</span></button>
          <button class="in-btn" data-jump="trustlines"><span class="in-icon">🔗</span><span class="in-label">Lines</span></button>
          <button class="in-btn" data-jump="tx"><span class="in-icon">📜</span><span class="in-label">History</span></button>
          <button class="in-btn in-btn--report" data-jump="report"><span class="in-icon">📄</span><span class="in-label">Report</span></button>
          <button class="in-btn in-btn--guide" onclick="showInspectorHowTo()"><span class="in-icon">?</span><span class="in-label">Guide</span></button>
        </div>
      </div>

    </div>
  `;

  const panel = document.getElementById('tab-inspector');
  if (panel) panel.appendChild(nav);
}

/* ═══════════════════════════════════════════════════
   HOW-TO OVERLAY
═══════════════════════════════════════════════════ */
function _mountHowToOverlay() {
  if (document.getElementById('inspector-howto')) return;

  const overlay = document.createElement('div');
  overlay.id = 'inspector-howto';
  overlay.className = 'howto-overlay';
  overlay.style.display = 'none';
  overlay.innerHTML = `
    <div class="howto-modal">
      <button class="howto-close" onclick="hideInspectorHowTo()">✕</button>

      <div class="howto-head">
        <div class="howto-head-icon">🔍</div>
        <h2 class="howto-title">Inspector Guide</h2>
        <p class="howto-subtitle">What each section tells you and what to watch for</p>
      </div>

      <div class="howto-items">

        <div class="howto-item">
          <div class="howto-item-icon">🔐</div>
          <div class="howto-item-body">
            <div class="howto-item-title">Security Audit</div>
            <div class="howto-item-desc">Decodes every account flag, checks master key status, regular key age, and multisig signer lists.
              <strong class="howto-red">Red flag:</strong> master key disabled with no regular key and no signer list = funds permanently inaccessible.</div>
          </div>
        </div>

        <div class="howto-item howto-item--warn">
          <div class="howto-item-icon">⚠</div>
          <div class="howto-item-body">
            <div class="howto-item-title">Drain Risk</div>
            <div class="howto-item-desc">Detects classic wallet-drain patterns. A drained account typically has master key disabled and a new regular key set by the attacker.
              We also detect large outflows within 48h of an auth change, open payment channels, and external key injections (a 3rd party setting your key).</div>
          </div>
        </div>

        <div class="howto-item">
          <div class="howto-item-icon">🎨</div>
          <div class="howto-item-body">
            <div class="howto-item-title">NFT Analysis</div>
            <div class="howto-item-desc">Catches the most common NFT scam: creating a sell offer for 0 XRP or ≤1 XRP — the victim thinks they're signing something else but listed their NFT for free.
              Also flags NFTs with no metadata URI (common in fake-offer scams) and unexpected burns.</div>
          </div>
        </div>

        <div class="howto-item">
          <div class="howto-item-icon">📊</div>
          <div class="howto-item-body">
            <div class="howto-item-title">Wash Trading</div>
            <div class="howto-item-desc">Scores 0–100 across five signals: cancel ratio &gt;55%, round-trip counterparties, single-pair concentration &gt;70%, fill rate &lt;5%, and 8+ offers in 30 seconds.
              Score above 50 warrants review — market makers may score moderately without manipulation intent.</div>
          </div>
        </div>

        <div class="howto-item">
          <div class="howto-item-icon">🪙</div>
          <div class="howto-item-body">
            <div class="howto-item-title">Token Issuer</div>
            <div class="howto-item-desc">Shows outstanding token obligations (negative balances = tokens issued). Checks individual line freezes, global freeze, and the NoFreeze flag —
              the most important trust signal for token holders since it permanently prevents issuer freeze actions.</div>
          </div>
        </div>

        <div class="howto-item">
          <div class="howto-item-icon">💧</div>
          <div class="howto-item-body">
            <div class="howto-item-title">AMM / Liquidity</div>
            <div class="howto-item-desc">Detects LP token positions (03… currency prefix), deposit/withdrawal history, fee votes, and auction slot bids.
              Large positions carry impermanent loss risk when pool asset prices diverge.</div>
          </div>
        </div>

        <div class="howto-item">
          <div class="howto-item-icon">🔗</div>
          <div class="howto-item-body">
            <div class="howto-item-title">Trustlines</div>
            <div class="howto-item-desc"><span class="howto-red">Frozen by issuer</span> = you cannot transfer that token.
              NoRipple is normal and protective. Negative balance = this account owes that amount to the counterparty.
              Limit=0 with negative balance is common for DEX issuers.</div>
          </div>
        </div>

        <div class="howto-item">
          <div class="howto-item-icon">📜</div>
          <div class="howto-item-body">
            <div class="howto-item-title">Transaction History</div>
            <div class="howto-item-desc">Up to 1,300 transactions fetched across three passes — color-coded by risk.
              <span class="howto-amber">Amber border</span> = auth-changing tx (key changes, signer lists).
              <span class="howto-red">Red border</span> = high risk (free NFT offers). Faded = failed tx.
              Click the 🔗 or 🔍 icon on any row to open it on XRPL Livenet or XRPScan.</div>
          </div>
        </div>

        <div class="howto-item">
          <div class="howto-item-icon">💸</div>
          <div class="howto-item-body">
            <div class="howto-item-title">Fee Spike Analysis</div>
            <div class="howto-item-desc">Bots often pay 100–500× the normal fee to guarantee their transaction lands in the same ledger as a counterparty's.
              Organic users almost never pay more than 2–5×.
              This section flags bursts of elevated fees and links the specific transaction hashes.</div>
          </div>
        </div>

        <div class="howto-item">
          <div class="howto-item-icon">🏷</div>
          <div class="howto-item-body">
            <div class="howto-item-title">Destination Tag Patterns</div>
            <div class="howto-item-desc">Exchanges use destination tags to identify which customer account receives a deposit — like a bank reference number.
              One tag used repeatedly = the same person's exchange account. Many different tags to one exchange = a service routing to multiple customer accounts, or deliberate deposit spreading.</div>
          </div>
        </div>

        <div class="howto-item">
          <div class="howto-item-icon">🔄</div>
          <div class="howto-item-body">
            <div class="howto-item-title">Path Payment Depth</div>
            <div class="howto-item-desc">Path payments route through intermediate DEX pairs.
              <strong class="howto-red">XRP→IOU→XRP round-trips</strong> pay and receive XRP via token pairs — generating DEX volume with no economic transfer.
              <strong class="howto-red">Self-routing</strong> (destination = source) is pure wash volume.
              Deep hop chains (3+ intermediaries) can obscure fund origin.</div>
          </div>
        </div>

        <div class="howto-item">
          <div class="howto-item-icon">🕸</div>
          <div class="howto-item-body">
            <div class="howto-item-title">Issuer Connection Graph</div>
            <div class="howto-item-desc">Shows token supply distribution across holders, accounts the issuer funded/created, and mirror-wallet clusters —
              groups of wallets that all received nearly identical token amounts. Mirror clusters often indicate sybil rings or insider pre-allocations.
              <strong>Note:</strong> supply percentages are only reliable when gateway_balances data is available; otherwise a "visible sample" caveat is shown.</div>
          </div>
        </div>

        <div class="howto-tip">
          <span class="howto-tip-icon">💡</span>
          <span><strong>Pro tips:</strong> Connect your wallet in Profile to auto-populate your address here.
            Click any address in the live stream to inspect it instantly.
            Paste an address — inspection runs automatically.
            Use the ⬇ Export CSV button in the report to take transaction data into Excel or Python.</span>
        </div>

      </div>
    </div>
  `;

  overlay.addEventListener('click', e => { if (e.target === overlay) _hideHowTo(); });
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape' && overlay.style.display !== 'none') _hideHowTo();
  });
  document.body.appendChild(overlay);
}

/* ═══════════════════════════════════════════════════
   NAV + BADGE + UX HELPERS
═══════════════════════════════════════════════════ */
function _navSetActive(section) {
  $$('#inspector-nav .in-btn[data-jump]').forEach(b =>
    b.classList.toggle('in-btn--active', b.dataset.jump === section)
  );
}

function _navOnScroll() {
  // Skip if inspector tab not active or results not showing
  if (!document.body.classList.contains('inspector')) return;
  if ($('inspect-result')?.style.display === 'none') return;
  const secs = ['security','drain','nft','wash','issuer','amm','trustlines','tx'];
  let active = null;
  for (const id of secs) {
    const el = document.getElementById('section-' + id);
    if (el && el.getBoundingClientRect().top <= 150) active = id;
  }
  if (active) _navSetActive(active);
}

function _setBadge(id, findings) {
  const el = $(id);
  if (!el) return;
  const crits = findings.filter(f => f.sev === 'critical').length;
  const warns  = findings.filter(f => f.sev === 'warn').length;
  if (crits)  { el.textContent = crits + ' critical'; el.className = 'section-badge section-badge--crit'; }
  else if (warns) { el.textContent = warns + ' warn'; el.className = 'section-badge section-badge--warn'; }
  else        { el.textContent = 'OK';                el.className = 'section-badge section-badge--ok';   }
}

function _setBadgeDrainLevel(id, level) {
  const el = $(id);
  if (!el) return;
  const map = { low:'ok', medium:'warn', high:'warn', critical:'crit' };
  el.textContent = level;
  el.className = 'section-badge section-badge--' + (map[level] || 'ok');
}

function _copyAddr() {
  const badge = $('inspect-addr-badge');
  const addr  = badge?.dataset?.fullAddr || badge?.textContent;
  if (!addr || addr === '—') return;
  navigator.clipboard?.writeText(addr).then(() => {
    const btn = document.querySelector('.irb-copy-btn');
    if (btn) { btn.textContent = '✓'; setTimeout(() => (btn.textContent = '📋'), 1500); }
  });
}

window.inspectorGoBack = function() {
  const resEl   = $('inspect-result');
  const emptyEl = $('inspect-empty');
  const errEl   = $('inspect-err');
  const inp     = $('inspect-addr');
  if (resEl)   resEl.style.display   = 'none';
  if (errEl)   errEl.style.display   = 'none';
  if (emptyEl) emptyEl.style.display = '';
  if (inp)     inp.value = '';
  _loadWallets();
  _loadRecentHistory();
  window.scrollTo({ top: 0, behavior: 'smooth' });
  setTimeout(() => inp?.focus(), 300);
};

function _showHowTo() {
  const el = document.getElementById('inspector-howto');
  if (el) { el.style.display = ''; requestAnimationFrame(() => el.classList.add('howto-visible')); }
}

function _hideHowTo() {
  const el = document.getElementById('inspector-howto');
  if (!el) return;
  el.classList.remove('howto-visible');
  setTimeout(() => { if (!el.classList.contains('howto-visible')) el.style.display = 'none'; }, 260);
}

/* ═══════════════════════════════════════════════════
   INITIAL STATE DASHBOARD
═══════════════════════════════════════════════════ */

const LS_INSPECT_HISTORY = 'nalulf_inspect_history';
const LS_WALLETS         = 'nalulf_wallets';

/* ── Curated notable addresses ── */
const NOTABLE_ADDRESSES = [
  {
    label: 'SOLO Issuer',
    addr:  'rsoLo2S1kiGeCcn6hCUXVrCpGMWLrRrLZz',
    tag:   'Token Issuer',
    icon:  '🪙',
    note:  '200 trustlines · master disabled · liquidity provider',
    color: '#ffb86c',
  },
  {
    label: 'Ripple Genesis',
    addr:  'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh',
    tag:   'Genesis',
    icon:  '🌐',
    note:  'Original genesis wallet · 100 billion XRP issued',
    color: '#50fa7b',
  },
  {
    label: 'Bitstamp Hot',
    addr:  'rvYAfWj5gh67oV6fW32ZzP3Aw4Eubs59B',
    tag:   'Exchange',
    icon:  '🏦',
    note:  'Major exchange hot wallet · high payment volume',
    color: '#8be9fd',
  },
  {
    label: 'GateHub Hot',
    addr:  'rhub8VRN55s94qWKDv6jmDy1pUykJzF3wq',
    tag:   'Exchange',
    icon:  '🏦',
    note:  'GateHub gateway · multi-currency issuance',
    color: '#8be9fd',
  },
  {
    label: 'XAMAN Wallet',
    addr:  'rPEPPER7kfTD9w2To4CQk6UCfuHM9c6GDY',
    tag:   'Wallet App',
    icon:  '📱',
    note:  'XAMAN (XUMM) custodial wallet address',
    color: '#bd93f9',
  },
  {
    label: 'DEX Market Maker',
    addr:  'r9cZA1mLK5R5Am25ArfXFmqgNwjZgnfk59',
    tag:   'Market Maker',
    icon:  '📊',
    note:  'High-volume DEX activity · offer patterns',
    color: '#ff79c6',
  },
];

/* ── Capabilities shown on empty state ── */
const CAPABILITIES = [
  {
    icon: '🔐',
    title: 'Security Audit',
    desc: 'Decodes all account flags, checks master key status, regular key age, multisig signer lists, and suspicious auth changes.',
    color: '#50fa7b',
  },
  {
    icon: '⚠',
    title: 'Drain Detection',
    desc: 'Classic drain setup, external key injection (3rd party sets your key), large outflows within 48h of auth change, open payment channels.',
    color: '#ff5555',
  },
  {
    icon: '🎨',
    title: 'NFT Risk',
    desc: 'Zero-value sell offers (free NFT drain vector), no-URI spam tokens, unexpected burns, transfer fee exposure.',
    color: '#bd93f9',
  },
  {
    icon: '📊',
    title: 'Wash Trading',
    desc: 'Five-signal scoring: cancel ratio, round-trip counterparties, single-pair concentration, fill rate, burst activity.',
    color: '#ffb86c',
  },
  {
    icon: '🪙',
    title: 'Token Issuer',
    desc: 'Outstanding obligations, individual line freezes, global freeze, NoFreeze protection, black hole risk detection.',
    color: '#f1fa8c',
  },
  {
    icon: '💧',
    title: 'AMM & Liquidity',
    desc: 'LP token positions, deposit/withdrawal history, fee votes, auction slot bids, impermanent loss warnings.',
    color: '#8be9fd',
  },
  {
    icon: '🌊',
    title: 'Fund Flow Tracer',
    desc: 'Traces every outbound payment from a wallet — where funds went, which exchanges they reached, multi-hop path payment routes, and a full chronological drain timeline.',
    color: '#00d4ff',
  },
  {
    icon: '🕸',
    title: 'Issuer Connection Graph',
    desc: 'Token supply concentration, top holder %, accounts the issuer created/funded, and mirror-wallet clusters — groups of wallets receiving identical token amounts (sybil detection).',
    color: '#bd93f9',
  },
];

/* ─────────────────────────────
   Main init (called from initInspector)
──────────────────────────────── */
function initInspectorDashboard() {
  _renderNotableAddresses();
  _renderCapabilities();
  _loadWallets();
  _loadRecentHistory();
  _startNetworkPulse();
}

/* ─────────────────────────────
   Notable addresses
──────────────────────────────── */
function _renderNotableAddresses() {
  const grid = document.getElementById('isd-notable-grid');
  if (!grid) return;

  grid.innerHTML = NOTABLE_ADDRESSES.map(n => `
    <button class="isd-notable-card" onclick="inspectorLoadAddr('${n.addr}')" type="button">
      <div class="isd-notable-top">
        <span class="isd-notable-icon" style="color:${n.color}">${n.icon}</span>
        <span class="isd-notable-tag" style="border-color:${n.color}40;color:${n.color}">${escHtml(n.tag)}</span>
      </div>
      <div class="isd-notable-label">${escHtml(n.label)}</div>
      <div class="isd-notable-addr mono">${n.addr.slice(0,8)}…${n.addr.slice(-6)}</div>
      <div class="isd-notable-note">${escHtml(n.note)}</div>
    </button>
  `).join('');
}

/* ─────────────────────────────
   Capability grid
──────────────────────────────── */
function _renderCapabilities() {
  const grid = document.getElementById('isd-cap-grid');
  if (!grid) return;

  grid.innerHTML = CAPABILITIES.map(c => `
    <div class="isd-cap" style="--cap-color:${c.color}">
      <div class="isd-cap-icon-wrap"><span class="isd-cap-icon">${c.icon}</span></div>
      <div class="isd-cap-body">
        <div class="isd-cap-title">${escHtml(c.title)}</div>
        <div class="isd-cap-desc">${escHtml(c.desc)}</div>
      </div>
    </div>
  `).join('');
}

/* ─────────────────────────────
   My Wallets (from localStorage)
──────────────────────────────── */
function _loadWallets() {
  const section = document.getElementById('isd-wallets-section');
  const list    = document.getElementById('isd-wallet-list');
  if (!section || !list) return;

  const wallets = safeJson(safeGet(LS_WALLETS)) || [];

  if (!wallets.length) { section.style.display = 'none'; return; }

  section.style.display = '';
  list.innerHTML = wallets.map(w => {
    const color  = w.color  || '#50fa7b';
    const emoji  = w.emoji  || '💎';
    const label  = w.label  || 'Wallet';
    const addr   = w.address || '';
    const short  = addr ? addr.slice(0,8) + '…' + addr.slice(-6) : '—';
    const isTest = w.testnet ? '<span class="isd-wallet-testnet">TESTNET</span>' : '';
    return `
      <button class="isd-wallet-card" onclick="inspectorLoadAddr('${escHtml(addr)}')" type="button">
        <div class="isd-wallet-avatar" style="background:${color}20;border-color:${color}50">${emoji}</div>
        <div class="isd-wallet-info">
          <div class="isd-wallet-name">${escHtml(label)} ${isTest}</div>
          <div class="isd-wallet-addr mono">${short}</div>
        </div>
        <div class="isd-wallet-inspect">Inspect →</div>
      </button>
    `;
  }).join('');
}

/* ─────────────────────────────
   Recent history
──────────────────────────────── */
function _loadRecentHistory() {
  const section = document.getElementById('isd-recent-section');
  const list    = document.getElementById('isd-recent-list');
  if (!section || !list) return;

  const history = _getHistory();
  if (!history.length) { section.style.display = 'none'; return; }

  section.style.display = '';
  list.innerHTML = history.map((item, i) => {
    const shortA  = item.addr ? item.addr.slice(0,10) + '…' + item.addr.slice(-8) : '—';
    const scoreEl = item.riskScore != null
      ? `<span class="isd-risk-pill isd-risk-pill--${_riskBucket(item.riskScore)}">${item.riskScore}</span>`
      : '';
    return `
      <button class="isd-recent-row" onclick="inspectorLoadAddr('${escHtml(item.addr)}')" type="button">
        <span class="isd-recent-n">${i + 1}</span>
        <span class="isd-recent-addr mono">${shortA}</span>
        <div class="isd-recent-right">
          ${scoreEl}
          <span class="isd-recent-time">${_relativeTime(item.ts)}</span>
        </div>
      </button>
    `;
  }).join('');
}

/* ─────────────────────────────
   Network pulse — runs every 2s
──────────────────────────────── */
function _startNetworkPulse() {
  // Event-driven: update immediately and on every new ledger (no polling needed)
  _updatePulse();
  window.addEventListener('xrpl-ledger', _onLedgerForPulse);
  // Also update on connection state changes
  window.addEventListener('xrpl-connection', _updatePulse);
}

function _onLedgerForPulse(e) {
  _updatePulse(e.detail);
}

// Pulse DOM refs - cached once, reset when dashboard re-mounts
let _p = null;
function _getPulseDOM() {
  if (_p) return _p;
  return (_p = {
    idx:     document.getElementById('isd-ledger-idx'),
    age:     document.getElementById('isd-ledger-age'),
    tps:     document.getElementById('isd-tps'),
    tpsTrnd: document.getElementById('isd-tps-trend'),
    fee:     document.getElementById('isd-fee'),
    feeLv:   document.getElementById('isd-fee-level'),
    close:   document.getElementById('isd-close-time'),
    dot:     document.getElementById('isd-conn-dot'),
    connLbl: document.getElementById('isd-conn-label'),
    pill:    document.getElementById('isd-conn-pill'),
    domTx:   document.getElementById('isd-dom-tx'),
    domPct:  document.getElementById('isd-dom-pct'),
    bar:     document.getElementById('isd-fee-bar'),
    barLbl:  document.getElementById('isd-fee-bar-label'),
  });
}

function _updatePulse() {
  const {
    idx: ledgerIdxEl, age: ledgerAgeEl,
    tps: tpsEl,       tpsTrnd: tpsTrendEl,
    fee: feeEl,       feeLv: feeLevelEl,
    close: closeTimeEl,
    dot: dotEl, connLbl: connLabelEl, pill: connPillEl,
    domTx: domTxEl,   domPct: domPctEl,
    bar: feeBarEl,    barLbl: feeBarLabelEl,
  } = _getPulseDOM();

  /* Connection status */
  const cs = state.connectionState || 'disconnected';
  const connMap = {
    connected:    { label: 'Connected',     cls: 'conn--live' },
    connecting:   { label: 'Connecting…',   cls: 'conn--warn' },
    disconnected: { label: 'Disconnected',  cls: 'conn--dead' },
  };
  const cm = connMap[cs] || connMap.disconnected;
  if (dotEl)        dotEl.className        = 'isd-conn-dot'; // color inherits from parent pill via currentColor
  if (connLabelEl)  connLabelEl.textContent = cm.label;
  if (connPillEl)   connPillEl.className    = `isd-conn-pill ${cm.cls}`;

  /* Ledger index + age */
  const log = state.ledgerLog || [];
  if (log.length && ledgerIdxEl) {
    const last = log[0];
    ledgerIdxEl.textContent = Number(last.ledgerIndex || 0).toLocaleString();
    if (ledgerAgeEl) ledgerAgeEl.textContent = last.closeTimeSec !== '—'
      ? last.closeTimeSec + 's close'
      : '—';
    if (closeTimeEl) {
      const ct = parseFloat(last.closeTimeSec);
      closeTimeEl.textContent = isNaN(ct) ? '—' : ct.toFixed(1);
    }
  }

  /* TPS */
  const tpsHist = state.tpsHistory || [];
  if (tpsHist.length && tpsEl) {
    const recent = tpsHist.slice(-5);
    const avg    = recent.reduce((a, b) => a + b, 0) / recent.length;
    tpsEl.textContent = avg.toFixed(1);

    if (tpsTrendEl && tpsHist.length >= 6) {
      const prev = tpsHist.slice(-10, -5);
      const prevAvg = prev.reduce((a, b) => a + b, 0) / prev.length;
      const delta = avg - prevAvg;
      tpsTrendEl.textContent = delta > 0.5 ? '↑ rising' : delta < -0.5 ? '↓ falling' : '→ stable';
      tpsTrendEl.className = `isd-metric-sub ${delta > 0.5 ? 'isd-up' : delta < -0.5 ? 'isd-down' : ''}`;
    }
  }

  /* Fee — stored as drops (integers), convert to XRP */
  const feeHist = state.feeHistory || [];
  if (feeHist.length && feeEl) {
    const recent  = feeHist.slice(-5);
    const avgDrop = recent.reduce((a, b) => a + b, 0) / recent.length;
    const avgXrp  = avgDrop / 1e6;

    // Display: if < 0.001 XRP show drops, else XRP
    feeEl.textContent = avgDrop < 5000
      ? avgDrop.toFixed(0) + ' drops'
      : avgXrp.toFixed(5) + ' XRP';

    // Fee level: base is ~12 drops. Elevated ≥100, High ≥500, Congested ≥2000
    const level = avgDrop < 20 ? { lbl: 'Low',       cls: 'fee-low',     pct: 10 }
      : avgDrop < 100         ? { lbl: 'Normal',     cls: 'fee-normal',  pct: 28 }
      : avgDrop < 500         ? { lbl: 'Elevated',   cls: 'fee-elevated',pct: 60 }
      : avgDrop < 2000        ? { lbl: 'High',       cls: 'fee-high',    pct: 82 }
      :                         { lbl: 'Congested',  cls: 'fee-congest', pct: 100 };

    if (feeLevelEl)    { feeLevelEl.textContent = level.lbl; feeLevelEl.className = `isd-metric-sub ${level.cls}`; }
    if (feeBarEl)      { feeBarEl.style.width = level.pct + '%'; feeBarEl.className = `isd-fee-bar-fill ${level.cls}`; }
    if (feeBarLabelEl) { feeBarLabelEl.textContent = level.lbl; feeBarLabelEl.className = `isd-fee-bar-level ${level.cls}`; }
  }

  /* Dominant TX type */
  const mix = state.txMixAccum || {};
  const entries = Object.entries(mix).filter(([,v]) => v > 0).sort(([,a],[,b]) => b - a);
  if (entries.length && domTxEl) {
    const total = entries.reduce((s, [,v]) => s + v, 0);
    const [topType, topCount] = entries[0];
    domTxEl.textContent = topType;
    if (domPctEl) domPctEl.textContent = ((topCount / total) * 100).toFixed(0) + '% of traffic';
  }
}

/* ─────────────────────────────
   Exposed globals
──────────────────────────────── */

/* ─────────────────────────────
   Export to CSV
──────────────────────────────── */
window.exportTxCSV = function(txList) {
  if (!txList || !txList.length) {
    alert('No transaction data to export. Run an inspection first.');
    return;
  }
  const RIPPLE_EPOCH = 946684800;
  const rows = [
    ['Hash', 'Date', 'Type', 'Account', 'Destination', 'Amount_XRP', 'Amount_Token',
     'Currency', 'Fee_Drops', 'DestinationTag', 'Result', 'LedgerIndex'],
    ...txList.map(({tx, meta}) => {
      const ts = tx.date ? new Date((tx.date + RIPPLE_EPOCH) * 1000).toISOString() : '';
      const amtXrp   = typeof tx.Amount === 'string' ? (Number(tx.Amount) / 1e6).toFixed(6) : '';
      const amtToken = tx.Amount?.value ? tx.Amount.value : '';
      const currency = tx.Amount?.currency || (typeof tx.Amount === 'string' ? 'XRP' : '');
      const result   = meta?.TransactionResult || '';
      return [
        tx.hash || '',
        ts,
        tx.TransactionType || '',
        tx.Account || '',
        tx.Destination || '',
        amtXrp,
        amtToken,
        currency,
        tx.Fee || '',
        tx.DestinationTag ?? '',
        result,
        tx.ledger_index || '',
      ];
    })
  ];

  const csvContent = rows.map(row =>
    row.map(cell => {
      const s = String(cell);
      return s.includes(',') || s.includes('"') || s.includes('\n')
        ? '"' + s.replace(/"/g, '""') + '"'
        : s;
    }).join(',')
  ).join('\n');

  const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  const addr = document.getElementById('inspect-addr-badge')?.dataset?.fullAddr || 'wallet';
  a.href     = url;
  a.download = `naluxrp_${addr.slice(0,10)}_${new Date().toISOString().slice(0,10)}.csv`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
};

/* ─────────────────────────────
   Risk score diff tracking
──────────────────────────────── */
function _getRiskScoreDiff(addr, newScore) {
  const history = _getHistory();
  const prev = history.find(h => h.addr === addr);
  if (!prev || prev.riskScore == null || newScore == null) return null;
  const diff = newScore - prev.riskScore;
  return { prev: prev.riskScore, curr: newScore, diff, ts: prev.ts };
}

function _renderRiskScoreDiff(addr, riskScore) {
  const diff = _getRiskScoreDiff(addr, riskScore);
  if (!diff || Math.abs(diff.diff) < 2) return; // ignore trivial changes
  const scoreEl = document.getElementById('inspect-risk-score');
  if (!scoreEl) return;
  const diffStr = diff.diff > 0
    ? `<span style="color:#ff5555;font-size:.7rem;font-weight:700"> ↑${diff.diff}</span>`
    : `<span style="color:#50fa7b;font-size:.7rem;font-weight:700"> ↓${Math.abs(diff.diff)}</span>`;
  const ago = _relativeTime(diff.ts);
  scoreEl.insertAdjacentHTML('afterend',
    `<span class="risk-score-diff" title="Changed from ${diff.prev} → ${diff.curr} since ${ago}">${diffStr} vs ${ago}</span>`
  );
}

window.inspectorLoadAddr = function(addr) {
  const inp = $('inspect-addr');
  if (inp) inp.value = addr;
  runInspect();
};

// Alias for profile.js inspectWalletAddr calls
window.inspectWalletAddr = function(addr) {
  window.inspectorLoadAddr(addr);
  // Switch to inspector tab if not already there
  const tabBtn = document.querySelector('[data-tab="inspector"]');
  if (tabBtn) window.switchTab?.(tabBtn, 'inspector');
  window.showDashboard?.();
};

window.printInspectorReport = function() {
  const body = document.getElementById('inspect-report-body');
  if (!body) return;
  const addr = document.getElementById('inspect-addr-badge')?.dataset?.fullAddr || 'wallet';
  const w = window.open('', '_blank', 'width=900,height=700');
  w.document.write(`<!DOCTYPE html><html><head>
    <title>NaluXRP Report — ${addr}</title>
    <style>
      body { font-family: -apple-system, system-ui, sans-serif; background:#fff; color:#111; margin:40px; line-height:1.6; }
      .report-cover { display:flex; justify-content:space-between; align-items:flex-start; border-bottom:2px solid #111; padding-bottom:20px; margin-bottom:24px; }
      .report-section { margin-bottom:28px; }
      .report-section-h { font-size:1.05rem; font-weight:800; border-bottom:1px solid #ddd; padding-bottom:6px; margin-bottom:12px; }
      .report-stat-row { display:flex; gap:12px; padding:4px 0; border-bottom:1px solid #f0f0f0; font-size:.88rem; }
      .report-stat-k { color:#555; min-width:220px; flex-shrink:0; }
      .report-finding-row { margin-bottom:10px; padding:8px; border-left:3px solid #ddd; }
      .report-module-h { font-weight:700; font-size:.9rem; margin:16px 0 6px; color:#333; }
      .report-rec { display:flex; gap:10px; margin-bottom:8px; font-size:.88rem; }
      @media print { body { margin:20px; } button { display:none; } }
    </style>
  </head><body>
    <button onclick="window.print()" style="margin-bottom:20px;padding:8px 16px;cursor:pointer">🖨 Print / Save as PDF</button>
    ${body.innerHTML}
  </body></html>`);
  w.document.close();
};

window.exportInspectorReport = function() {
  const body = document.getElementById('inspect-report-body');
  if (!body) return;
  // Copy as plain text
  const text = body.innerText || body.textContent || '';
  navigator.clipboard?.writeText(text).then(() => {
    const btn = document.getElementById('report-export-btn');
    if (btn) { btn.textContent = '✓ Copied!'; setTimeout(() => { btn.textContent = '📋 Copy Report'; }, 2000); }
  }).catch(() => {
    // Fallback: select all text in the section
    const range = document.createRange();
    range.selectNodeContents(body);
    const sel = window.getSelection();
    sel.removeAllRanges();
    sel.addRange(range);
  });
};

window.inspectorClearHistory = function() {
  safeRemove(LS_INSPECT_HISTORY);
  const section = document.getElementById('isd-recent-section');
  if (section) section.style.display = 'none';
};

/* ─────────────────────────────
   History helpers
──────────────────────────────── */
function _getHistory() {
  return safeJson(safeGet(LS_INSPECT_HISTORY)) || [];
}

function addInspectHistory(addr, riskScore) {
  let history = _getHistory();
  history = history.filter(h => h.addr !== addr);
  history.unshift({ addr, riskScore, ts: Date.now() });
  history = history.slice(0, 8);
  safeSet(LS_INSPECT_HISTORY, JSON.stringify(history));
}

function _relativeTime(ts) {
  const diff = Date.now() - ts;
  if (diff < 60000)    return 'just now';
  if (diff < 3600000)  return Math.floor(diff / 60000) + 'm ago';
  if (diff < 86400000) return Math.floor(diff / 3600000) + 'h ago';
  return Math.floor(diff / 86400000) + 'd ago';
}

function _riskBucket(score) {
  // Maps to isd-risk-pill--ok/medium/high/critical suffix
  const c = riskScoreClass(score); // 'risk-ok' | 'risk-medium' | 'risk-high' | 'risk-critical'
  return c.replace('risk-', '');   // 'ok' | 'medium' | 'high' | 'critical'
}

/* ─────────────────────────────
   Cleanup (called on page/tab leave)
──────────────────────────────── */
export function destroyInspector() {
  if (_pulseInterval) { clearInterval(_pulseInterval); _pulseInterval = null; }
  _inspectAbort = true;
  _dom = null;
  _p   = null; // release all cached DOM refs
}