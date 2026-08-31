/* =====================================================
   shared-analysis.js — Shared account/entity intelligence
   =====================================================
   Small utilities used by BOTH the forensic engine (inspector.js) and the
   wallet (profile.js). Extracted out of inspector.js rather than having
   profile.js import from inspector.js directly, because inspector.js
   already imports copyToClipboard from profile.js — a direct
   profile.js -> inspector.js import would create a circular module
   dependency between the two largest files in the app. This file only
   imports from utils.js, a zero-dependency leaf module, so both can depend
   on it safely in one direction.
   ===================================================== */
import { safeGet, safeSet, safeRemove, safeJson } from './utils.js';

/* ─────────────────────────────
   Known Exchange / Entity Registry
──────────────────────────────── */
export const KNOWN_ENTITIES = new Map([
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
  // rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh is the real XRPL genesis account (the
  // account that originally held all 100 billion XRP) — corroborated by
  // KNOWN_BLACKHOLE_ADDRESSES below and the "Ripple Genesis" watchlist entry
  // elsewhere in inspector.js.
  ['rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh', { name: 'Genesis (Black Hole)', type: 'blackhole' }],
  ['r9cZA1mLK5R5Am25ArfXFmqgNwjZgnfk59', { name: 'Black Hole #2',        type: 'blackhole' }],

  // ── Known Wallet Apps & Infrastructure ──────────────────────────────────
  ['rPEPPER7kfTD9w2To4CQk6UCfuHM9c6GDY', { name: 'XAMAN (XUMM)', type: 'wallet' }],
  ['rBj4eVRWn6mCELVTNkVFDfGNByE9VFTM3R', { name: 'XAMAN',        type: 'wallet' }],

  // ── Notable Token Issuers ────────────────────────────────────────────────
  ['rsoLo2S1kiGeCcn6hCUXVrCpGMWLrRrLZz', { name: 'SOLO Issuer',     type: 'issuer' }],
  ['rcoreNywaoz2ZCVt2sc3JiEi7G7MpZxZgm', { name: 'CORE Token',      type: 'issuer' }],
  ['rhXo4TcWbLY4GqTSmscMpgZ1KMXFBi9V55', { name: 'XRPL DeFi Pool',  type: 'issuer' }],
]);

/** Look up a known entity by address. Returns null when unknown — absence
 *  of a match is not itself a risk signal, most legitimate addresses are
 *  simply not in this curated registry. */
export function getEntity(addr) {
  return KNOWN_ENTITIES.get(addr) || null;
}

/* ─────────────────────────────
   Blackhole / Issuer Safety Helpers
   Prevent false positives for intentionally blackholed issuers
──────────────────────────────── */

// Known XRPL blackhole / provably unusable addresses commonly used for issuer lockout
export const KNOWN_BLACKHOLE_ADDRESSES = new Set([
  'rrrrrrrrrrrrrrrrrrrrrhoLvTp',
  'rrrrrrrrrrrrrrrrrrrrBZbvji',
  'rrrrrrrrrrrrrrrrrNAMEtxvNvQ',
  'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh', // Genesis / well-known blackhole reference in some contexts
  'r9cZA1mLK5R5Am25ArfXFmqgNwjZgnfk59', // included because the entity registry already marks it specially
]);

export function isKnownBlackholeAddress(addr) {
  return !!addr && KNOWN_BLACKHOLE_ADDRESSES.has(addr);
}

/* ─────────────────────────────
   Account Size Baseline
──────────────────────────────── */

// Below this many historical outbound payments, "typical size for this
// account" isn't statistically meaningful — a wallet with 2-3 prior
// payments can show a spurious 5x+ swing from ordinary variance alone.
// Callers must check `.applicable` before treating a baseline comparison
// as evidence rather than noise (same discipline as Benford's applicability
// gate and Volume Concentration's sample-size severity cap).
export const BASELINE_MIN_SAMPLE = 8;

/** This account's own historical outbound-Payment size profile — median,
 *  95th percentile, and sample size — optionally excluding a date range
 *  (e.g. the episode window being evaluated, so its own transfers don't
 *  inflate what "typical" means for it) and/or a specific destination (so
 *  the very payment(s) being judged for size-anomaly against a destination
 *  can't self-launder their own comparison baseline).
 *
 *  `txList` accepts either the {tx, meta} pairs inspector.js works with,
 *  or a flat array of tx objects (profile.js's txCache shape) — only `.tx`
 *  is ever read, so a flat array works if callers map it as
 *  `txns.map(tx => ({ tx }))` first. Shared by Drain Risk (per-episode
 *  transfer-size anomaly), Fund Flow (per-destination transfer-size
 *  anomaly), and the wallet's pre-send Destination Intelligence check,
 *  rather than each computing its own ad hoc median. */
export function computeAccountBaseline(txList, addr, { excludeFrom = null, excludeTo = null, excludeDest = null } = {}) {
  const excludingRange = excludeFrom != null && excludeTo != null;
  const sizes = txList
    .filter(({ tx }) => tx.TransactionType === 'Payment' && tx.Account === addr && typeof tx.Amount === 'string'
      && !(excludingRange && tx.date >= excludeFrom && tx.date <= excludeTo)
      && !(excludeDest != null && tx.Destination === excludeDest))
    .map(({ tx }) => Number(tx.Amount) / 1e6)
    .filter(v => v > 0)
    .sort((a, b) => a - b);
  const sampleSize = sizes.length;
  const pct = p => sampleSize ? sizes[Math.min(sampleSize - 1, Math.floor(p * sampleSize))] : null;
  return { sampleSize, medianXrp: pct(0.5), p95Xrp: pct(0.95), applicable: sampleSize >= BASELINE_MIN_SAMPLE };
}

/* ─────────────────────────────
   Unified Watchlist
   ─────────────────────────────
   Previously two disconnected localStorage stores: inspector.js's
   'nalulf_watchlist' (address objects with a running risk-score history)
   and profile.js's 'naluxrp_token_watchlist' (a flat array of token keys).
   Same underlying idea — "things this user wants to keep an eye on" — with
   no shared representation, so a future feature (e.g. flagging that a
   watched token's issuer is also a watched address) had nowhere to hook in.
   One entry shape now covers both: { type, key, label, addedAt, lastScore,
   lastTs }. `lastScore`/`lastTs` are address-specific (risk score at last
   inspection) and simply stay null for token entries — token watchlist
   entries intentionally carry no cached metadata of their own; the token's
   live price/name is resolved from the current Discovery snapshot at
   render time, exactly as before. */
const WATCHLIST_KEY = 'naluxrp_watchlist';
const WATCHLIST_MAX = 200;
const LEGACY_ADDR_WATCHLIST_KEY  = 'nalulf_watchlist';
const LEGACY_TOKEN_WATCHLIST_KEY = 'naluxrp_token_watchlist';

let _watchlistMigrated = false;
function _ensureWatchlistMigrated() {
  if (_watchlistMigrated) return;
  _watchlistMigrated = true;
  if (safeGet(WATCHLIST_KEY) != null) return; // already migrated (or a fresh, deliberately-empty list)

  const merged = [];
  const legacyAddrs = safeJson(safeGet(LEGACY_ADDR_WATCHLIST_KEY)) || [];
  for (const w of legacyAddrs) {
    if (!w?.addr) continue;
    merged.push({ type: 'address', key: w.addr, label: w.label || null, addedAt: w.addedTs || Date.now(), lastScore: w.lastScore ?? null, lastTs: w.lastTs ?? null });
  }
  const legacyTokens = safeJson(safeGet(LEGACY_TOKEN_WATCHLIST_KEY)) || [];
  for (const key of legacyTokens) {
    if (!key) continue;
    merged.push({ type: 'token', key, label: null, addedAt: Date.now(), lastScore: null, lastTs: null });
  }
  safeSet(WATCHLIST_KEY, JSON.stringify(merged));
  if (legacyAddrs.length)  safeRemove(LEGACY_ADDR_WATCHLIST_KEY);
  if (legacyTokens.length) safeRemove(LEGACY_TOKEN_WATCHLIST_KEY);
}

function _readWatchlist() {
  _ensureWatchlistMigrated();
  return safeJson(safeGet(WATCHLIST_KEY)) || [];
}
function _writeWatchlist(list) {
  safeSet(WATCHLIST_KEY, JSON.stringify(list.slice(0, WATCHLIST_MAX)));
}

/** All watchlist entries, optionally filtered to one type ('address' | 'token'). */
export function getWatchlist(type) {
  const list = _readWatchlist();
  return type ? list.filter(w => w.type === type) : list;
}
export function addToWatchlist(type, key, extra = {}) {
  key = String(key || '').trim();
  if (!key) return;
  const list = _readWatchlist().filter(w => !(w.type === type && w.key === key));
  list.unshift({ type, key, label: extra.label ?? null, addedAt: Date.now(), lastScore: extra.lastScore ?? null, lastTs: extra.lastTs ?? null });
  _writeWatchlist(list);
}
export function removeFromWatchlist(type, key) {
  _writeWatchlist(_readWatchlist().filter(w => !(w.type === type && w.key === key)));
}
export function isWatched(type, key) {
  return _readWatchlist().some(w => w.type === type && w.key === key);
}
export function updateWatchlistEntry(type, key, patch) {
  _writeWatchlist(_readWatchlist().map(w => (w.type === type && w.key === key) ? { ...w, ...patch } : w));
}
export function clearWatchlist(type) {
  _writeWatchlist(type ? _readWatchlist().filter(w => w.type !== type) : []);
}
