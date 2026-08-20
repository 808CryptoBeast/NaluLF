/* =====================================================
   project-intel.js — XRPL Project Intelligence
   =====================================================
   Token/project-level analysis, as distinct from inspector.js (which
   analyses one ACCOUNT's behavior). Given a {symbol, issuer} pair, computes:
     - AMM liquidity state (reserves, fee, LP supply, auction slot, votes)
     - DEX order-book depth: how much XRP can be traded before price moves
       1/2/5/10/25% — the "is there real exit liquidity" question a bare
       TVL/market-cap number can't answer
     - Issuer risk flags (freeze, clawback, require-auth, blackhole state)
     - Holder concentration (top1/top5/top10 share of supply)
     - LP token concentration (who actually controls the pool)
     - A composite Project Strength score — every sub-score carries its raw
       inputs so the UI can show exactly why it landed where it did; see
       computeProjectStrength()'s doc comment for what this score is and
       isn't a claim about.

   Deliberately standalone — no import from profile.js, even though that's
   where the UI lives and where an equivalent xrplPost() already exists.
   Importing it back would make profile.js and this file circularly
   dependent (profile.js already needs to import functions from here to
   render them). This mirrors an existing pattern in the codebase: xrpl.js's
   wsSend() and profile.js's own xrplPost() are already two independent
   implementations of "send an XRPL RPC command" living in different files —
   adding a third small one here is consistent with that, not a new
   inconsistency.
   ===================================================== */
import { wsSend } from './xrpl.js';
import { state } from './state.js';

const RPC_HTTP = 'https://xrplcluster.com/';
const RPC_HTTP_BACKUP = 'https://s2.ripple.com:51234/';

async function _rpc(method, params) {
  try {
    if (state.wsConn?.readyState === 1) {
      const msg = await wsSend({ command: method, ...params });
      if (msg?.status === 'error') throw new Error(msg.error_message || msg.error || 'XRPL RPC error');
      return msg?.result || null;
    }
  } catch {
    // Fall through to HTTPS JSON-RPC.
  }
  const body = JSON.stringify({ method, params: [params] });
  const tryFetch = async (url) => {
    const r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body, mode: 'cors' });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return (await r.json()).result;
  };
  try { return await tryFetch(RPC_HTTP); }
  catch { return await tryFetch(RPC_HTTP_BACKUP); }
}

/** Raw numeric value of an XRPL Amount — a plain drops string for XRP, or
 *  {currency,issuer,value} for issued currencies. Unlike profile.js's
 *  _parseXrplAmount, this returns numbers for computation, not display strings. */
function _amt(amount) {
  if (typeof amount === 'string') return { value: Number(amount) / 1e6, isXrp: true, currency: 'XRP' };
  if (amount && typeof amount === 'object') {
    return { value: Number(amount.value || 0), isXrp: false, currency: amount.currency, issuer: amount.issuer };
  }
  return { value: 0, isXrp: true, currency: 'XRP' };
}

/** XRPL currency fields in amm_info/account_lines/book_offers requests must
 *  be either a standard 3-character ISO code or the exact 160-bit hex form
 *  (ASCII bytes, zero-padded to 20 bytes) — a plain 4+ letter symbol like
 *  "SOLO" matches neither and silently returns no results (not an error,
 *  just an empty/not-found response), which is exactly what happened when
 *  this was missing: account_info (no currency param) worked fine while
 *  amm_info/account_lines/book_offers all quietly came back empty. Applied
 *  once at fetchProjectIntel's entry point rather than trusting every
 *  caller to have already encoded it correctly. */
function _normalizeCurrencyCode(code) {
  const c = String(code || '').trim().toUpperCase();
  if (c === 'XRP') return c;
  if (/^[A-Z0-9?!@#$%^&*(){}[\]|]{3}$/i.test(c)) return c;
  if (/^[0-9A-F]{40}$/.test(c)) return c;
  const bytes = new TextEncoder().encode(c).slice(0, 20);
  const padded = new Uint8Array(20);
  padded.set(bytes);
  return Array.from(padded).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

// AccountRoot ledger flag bits touching issuer risk. Values cross-checked
// against xrpl.org's AccountRoot flag reference (and — except clawback,
// which nothing in this codebase checked before — against inspector.js's
// existing FLAGS constant, so a mismatch would have already surfaced there).
const ACCOUNT_FLAGS = {
  lsfRequireAuth:            0x00040000,
  lsfDisableMaster:          0x00100000,
  lsfNoFreeze:               0x00200000,
  lsfGlobalFreeze:           0x00400000,
  lsfDefaultRipple:          0x00800000,
  lsfAllowTrustLineClawback: 0x80000000,
};

/* ── AMM state for a token/XRP pair ──────────────────────────────────── */
export async function fetchAmmSnapshot(currency, issuer) {
  try {
    const r = await _rpc('amm_info', {
      asset: { currency: 'XRP' },
      asset2: { currency, issuer },
    });
    const amm = r?.amm;
    if (!amm) return { exists: false };

    const xrpReserve = _amt(amm.amount).value;
    const tokenReserve = _amt(amm.amount2).value;
    const lpSupply = _amt(amm.lp_token || amm.lp_token_balance).value;
    const lpCurrency = (amm.lp_token || amm.lp_token_balance)?.currency || null;

    return {
      exists: true,
      account: amm.account,
      xrpReserve,
      tokenReserve,
      lpSupply,
      lpCurrency,
      tradingFeePct: Number(amm.trading_fee || 0) / 1000, // trading_fee is in units of 1/100,000; /1000 → %
      // amm_info exposes auction-slot and vote-slot data (per XRPL docs) that
      // nothing in this codebase previously parsed — surfaced here since
      // auction discounts and fee-vote weighting both affect LP economics.
      auctionSlot: amm.auction_slot ? {
        account: amm.auction_slot.account,
        discountedFeePct: Number(amm.auction_slot.discounted_fee || 0) / 1000,
        priceXrp: _amt(amm.auction_slot.price).value,
        expiration: amm.auction_slot.expiration || null,
      } : null,
      voteSlots: Array.isArray(amm.vote_slots) ? amm.vote_slots.map(v => ({
        account: v.account,
        tradingFeePct: Number(v.trading_fee || 0) / 1000,
        voteWeight: Number(v.vote_weight || 0) / 1000, // vote_weight is also in 1/100,000ths (proportional to LP-token share)
      })) : [],
    };
  } catch {
    return { exists: false, error: true };
  }
}

/* ── Issuer risk flags ───────────────────────────────────────────────── */
export async function fetchIssuerRisk(issuerAddr) {
  try {
    const r = await _rpc('account_info', { account: issuerAddr, ledger_index: 'validated' });
    const acct = r?.account_data;
    if (!acct) return { exists: false };
    const flags = Number(acct.Flags || 0);
    const has = (bit) => (flags & bit) === bit;

    return {
      exists: true,
      requireAuth:     has(ACCOUNT_FLAGS.lsfRequireAuth),
      globalFreeze:    has(ACCOUNT_FLAGS.lsfGlobalFreeze),
      noFreeze:        has(ACCOUNT_FLAGS.lsfNoFreeze),        // individual-freeze permanently disabled (a positive signal — the issuer gave up that power)
      freezeCapable:   !has(ACCOUNT_FLAGS.lsfNoFreeze),        // issuer retains the ability to freeze individual trustlines
      defaultRipple:   has(ACCOUNT_FLAGS.lsfDefaultRipple),
      clawbackEnabled: has(ACCOUNT_FLAGS.lsfAllowTrustLineClawback),
      blackholed:      has(ACCOUNT_FLAGS.lsfDisableMaster) && !acct.RegularKey,
      masterDisabled:  has(ACCOUNT_FLAGS.lsfDisableMaster),
      hasRegularKey:   !!acct.RegularKey,
    };
  } catch {
    return { exists: false, error: true };
  }
}

/** Shared by fetchHolderConcentration and fetchLpConcentration — trustlines
 *  connect symmetrically, so paginating account_lines on the issuing account
 *  (rather than a holder's account) lists every holder of that issuer's
 *  currencies, XRPL has no dedicated "list holders" method. Capped at 8
 *  pages (~3,200 lines) — enough for concentration math on all but the
 *  largest tokens, and unbounded pagination on a popular issuer could mean
 *  dozens of round trips for a dashboard meant to load in a few seconds. */
async function _paginateHolderLines(issuerAddr, currency, maxPages = 8) {
  const holders = [];
  let marker;
  for (let page = 0; page < maxPages; page++) {
    const r = await _rpc('account_lines', {
      account: issuerAddr,
      ledger_index: 'validated',
      limit: 400,
      ...(marker ? { marker } : {}),
    });
    for (const l of (r?.lines || [])) {
      if (l.currency !== currency) continue;
      // account_lines reports balances from the issuer's own point of view:
      // a holder's positive balance to them is issuer debt, so the true
      // holder balance is the negation of what's reported here.
      const bal = -Number(l.balance || 0);
      if (bal > 0) holders.push({ address: l.account, balance: bal });
    }
    marker = r?.marker;
    if (!marker) break;
  }
  return holders;
}

function _concentrationFrom(holders) {
  const sorted = [...holders].sort((a, b) => b.balance - a.balance);
  const total = sorted.reduce((s, h) => s + h.balance, 0);
  const pctOfTop = (n) => total > 0 ? sorted.slice(0, n).reduce((s, h) => s + h.balance, 0) / total * 100 : 0;
  return {
    holderCount: sorted.length,
    totalSampled: total,
    top1Pct: pctOfTop(1),
    top5Pct: pctOfTop(5),
    top10Pct: pctOfTop(10),
    topHolders: sorted.slice(0, 10),
  };
}

/* ── Token holder concentration ──────────────────────────────────────── */
export async function fetchHolderConcentration(issuerAddr, currency) {
  try {
    const holders = await _paginateHolderLines(issuerAddr, currency);
    if (!holders.length) return { exists: false };
    return { exists: true, ...(_concentrationFrom(holders)),
      // Sample-only caveat: gateway_balances gives the true circulating
      // total (issued minus what the issuer itself still holds), but
      // account_lines pagination above is capped — on a widely-held token
      // the sample may not be every holder, only the largest reachable set.
      sampleOnly: true };
  } catch {
    return { exists: false, error: true };
  }
}

/* ── LP token concentration (who controls the pool) ─────────────────── */
export async function fetchLpConcentration(ammAccount, lpCurrency) {
  if (!ammAccount || !lpCurrency) return { exists: false };
  try {
    const holders = await _paginateHolderLines(ammAccount, lpCurrency);
    if (!holders.length) return { exists: false };
    return { exists: true, ...(_concentrationFrom(holders)) };
  } catch {
    return { exists: false, error: true };
  }
}

/* ── DEX order-book depth / price-impact walk ────────────────────────
   "quality" on a book_offers response is taker_pays ÷ taker_gets — cost per
   unit received, from the requesting taker's perspective, in BOTH
   directions (buying or selling). Lower quality is always better for the
   taker, so both sides sort ascending and use the same walk. */
const DEPTH_THRESHOLDS_PCT = [1, 2, 5, 10, 25];

async function _fetchBookSide(currency, issuer, direction) {
  // direction 'buy'  → taker wants the TOKEN, pays XRP  (buy-side depth: exit liquidity for someone entering)
  // direction 'sell' → taker wants XRP, pays the TOKEN   (sell-side depth: exit liquidity for someone leaving)
  const takerGets = direction === 'buy' ? { currency, issuer } : { currency: 'XRP' };
  const takerPays = direction === 'buy' ? { currency: 'XRP' } : { currency, issuer };
  const r = await _rpc('book_offers', {
    taker_gets: takerGets, taker_pays: takerPays,
    limit: 200, ledger_index: 'validated',
  });
  const offers = (r?.offers || []).map(o => {
    // Funded amounts (what the offer creator can actually deliver right
    // now) override the offer's nominal face amount when present — an
    // under-collateralized offer's stated size overstates real depth.
    const gets = _amt(o.taker_gets_funded ?? o.TakerGets).value;
    const pays = _amt(o.taker_pays_funded ?? o.TakerPays).value;
    if (gets <= 0 || pays <= 0) return null;
    return { gets, pays, quality: pays / gets };
  }).filter(Boolean).sort((a, b) => a.quality - b.quality);
  return offers;
}

/** Walks a sorted offer book, returning cumulative XRP/token traded at each
 *  price-impact threshold in DEPTH_THRESHOLDS_PCT. Threshold pct is applied
 *  in the book's own quality units — on the sell side that's TOKEN/XRP, not
 *  the inverted XRP/TOKEN "price" callers see elsewhere in this file, so a
 *  25%-labeled sell-side level is a ~20% move once inverted back to price
 *  terms. Both sides are still walked correctly (each stops on its own
 *  offers' real exchange rate, XRPL's own quality field), this only affects
 *  how precisely the numeric label matches an inverted-price percentage at
 *  the largest thresholds. `book_exhausted: true` on a level means the
 *  whole visible book (200 offers) was consumed before price moved that
 *  far — real depth may be deeper, or the book may genuinely be that thin;
 *  this is reported as-is rather than guessed at. */
function _walkDepth(offers) {
  if (!offers.length) return { bestPrice: null, levels: [] };
  const bestPrice = offers[0].quality;
  const levels = DEPTH_THRESHOLDS_PCT.map(pct => {
    const limitPrice = bestPrice * (1 + pct / 100);
    let xrpAtOffer = 0, tokenAtOffer = 0, exhausted = true;
    for (const o of offers) {
      if (o.quality > limitPrice) { exhausted = false; break; }
      // direction-agnostic: whichever side is XRP contributes to xrpAtOffer,
      // the other to tokenAtOffer — offers here are already one-directional
      // (all buy-side or all sell-side), so gets/pays consistently map to
      // XRP-vs-token across the whole array.
      xrpAtOffer += o.pays; // taker_pays for buy = XRP spent; for sell, taker_gets is XRP — see caller
      tokenAtOffer += o.gets;
    }
    return { pct, xrpAtOffer, tokenAtOffer, bookExhausted: exhausted };
  });
  return { bestPrice, levels };
}

export async function fetchOrderBookDepth(currency, issuer) {
  try {
    const [buyOffers, sellOffers] = await Promise.all([
      _fetchBookSide(currency, issuer, 'buy'),
      _fetchBookSide(currency, issuer, 'sell'),
    ]);
    if (!buyOffers.length && !sellOffers.length) return { exists: false };

    // On the sell side (taker_gets=XRP, taker_pays=TOKEN), `pays` IS the
    // token amount and `gets` IS the XRP received — _walkDepth's xrpAtOffer
    // accumulator (built for the buy side, where pays=XRP) needs the two
    // swapped here so "xrpAtOffer" always means XRP regardless of direction.
    const sellWalk = _walkDepth(sellOffers.map(o => ({ ...o, gets: o.pays, pays: o.gets })));
    const buyWalk = _walkDepth(buyOffers);

    // sellWalk.bestPrice/quality is TOKEN-per-XRP (it's whatever the sell
    // side's book_offers request computed quality as: taker_pays÷taker_gets
    // = TOKEN÷XRP there, vs. XRP÷TOKEN on the buy side) — a different unit
    // than buyWalk.bestPrice. Both need to be in XRP-per-token before
    // they're comparable as a bid/ask spread, so invert the sell side.
    const sellPriceXrp = sellWalk.bestPrice ? 1 / sellWalk.bestPrice : null;
    const spreadPct = (buyWalk.bestPrice && sellPriceXrp)
      ? ((buyWalk.bestPrice - sellPriceXrp) / sellPriceXrp) * 100
      : null;

    return {
      exists: true,
      buySideOfferCount: buyOffers.length,
      sellSideOfferCount: sellOffers.length,
      buyPriceXrp: buyWalk.bestPrice, // price to BUY 1 token (XRP per token)
      sellPriceXrp,                  // price received SELLING 1 token (XRP per token)
      spreadPct,
      buyDepth: buyWalk.levels,   // XRP required to buy through each % price-impact threshold
      sellDepth: sellWalk.levels, // XRP received selling through each % price-impact threshold
    };
  } catch {
    return { exists: false, error: true };
  }
}

/* ── Composite Project Strength score ────────────────────────────────
   This is NOT the full 8-dimension index from the original spec (Network
   Activity, Treasury Health, and Project Transparency all need historical
   transaction scanning and wallet-identity heuristics beyond what a single
   live snapshot can provide — see the architecture note this feature
   shipped with). It scores the 5 dimensions computable from one live XRPL
   query burst: Liquidity, Holder Distribution, Market Quality, LP
   Stability, Issuer Risk. Weights are the original spec's weights for
   these 5 dimensions, renormalized to sum to 100 (25/15/15/15/10 → scaled
   up by ÷0.8). Every sub-score returns the raw numbers it was computed
   from — this function's whole point is that nothing here is opaque. */
const STRENGTH_WEIGHTS = {
  liquidity:    31.25, // was 25% of the full 8-dim index
  distribution: 18.75, // was 15%
  marketQuality:18.75, // was 15%
  lpStability:  18.75, // was 15%
  issuerRisk:   12.5,  // was 10%
};

function _clamp0to100(n) { return Math.max(0, Math.min(100, n)); }
function _scaleLinear(value, lo, hi) { // lo→0, hi→100, clamped
  if (hi === lo) return 0;
  return _clamp0to100(((value - lo) / (hi - lo)) * 100);
}

export function computeProjectStrength({ amm, orderBook, holders, lp, issuer }) {
  const subScores = {};

  // Liquidity: combined AMM TVL (in XRP-equivalent, reserves doubled since
  // it's a balanced pool) and buy-side depth-to-2%-impact. Thresholds below
  // are a starting calibration (100 at 100K XRP TVL / 20K XRP depth-to-2%),
  // not a claim about what "good" objectively is — meant to be tuned as
  // real project data comes through the dashboard.
  const tvlXrp = amm?.exists ? amm.xrpReserve * 2 : 0;
  const depth2 = orderBook?.exists ? (orderBook.buyDepth.find(l => l.pct === 2)?.xrpAtOffer || 0) : 0;
  subScores.liquidity = {
    score: Math.round((_scaleLinear(tvlXrp, 0, 100000) + _scaleLinear(depth2, 0, 20000)) / 2),
    inputs: { ammTvlXrp: tvlXrp, depthTo2PctXrp: depth2, ammExists: !!amm?.exists, orderBookExists: !!orderBook?.exists },
  };

  // Distribution: inverse of top-10 holder concentration.
  subScores.distribution = {
    score: holders?.exists ? Math.round(_scaleLinear(holders.top10Pct, 90, 20)) : 0,
    inputs: { top1Pct: holders?.top1Pct ?? null, top5Pct: holders?.top5Pct ?? null, top10Pct: holders?.top10Pct ?? null, holderCount: holders?.holderCount ?? 0, sampleOnly: holders?.sampleOnly ?? true },
  };

  // Market quality: presence of two-sided depth + tightness of the buy/sell spread.
  const spread = orderBook?.exists ? Math.abs(orderBook.spreadPct ?? 100) : 100;
  subScores.marketQuality = {
    score: orderBook?.exists ? Math.round(_scaleLinear(spread, 15, 0)) : 0,
    inputs: { spreadPct: orderBook?.spreadPct ?? null, buySideOfferCount: orderBook?.buySideOfferCount ?? 0, sellSideOfferCount: orderBook?.sellSideOfferCount ?? 0 },
  };

  // LP stability: inverse of top-1 LP holder concentration + a mild bonus
  // for a broader LP holder base.
  subScores.lpStability = {
    score: lp?.exists ? Math.round((_scaleLinear(lp.top1Pct, 100, 20) + _scaleLinear(lp.holderCount, 1, 25)) / 2) : 0,
    inputs: { top1Pct: lp?.top1Pct ?? null, top5Pct: lp?.top5Pct ?? null, holderCount: lp?.holderCount ?? 0 },
  };

  // Issuer risk: start clean, subtract for each capability that increases
  // counterparty risk. Clawback and global freeze are weighted heaviest —
  // both let the issuer unilaterally alter holder balances/access.
  let riskScore = 100;
  const riskInputs = { clawbackEnabled: false, globalFreeze: false, freezeCapable: false, requireAuth: false, blackholed: false };
  if (issuer?.exists) {
    riskInputs.clawbackEnabled = issuer.clawbackEnabled;
    riskInputs.globalFreeze = issuer.globalFreeze;
    riskInputs.freezeCapable = issuer.freezeCapable;
    riskInputs.requireAuth = issuer.requireAuth;
    riskInputs.blackholed = issuer.blackholed;
    if (issuer.clawbackEnabled) riskScore -= 30;
    if (issuer.globalFreeze) riskScore -= 25;
    if (issuer.freezeCapable) riskScore -= 10; // common and not inherently malicious — smaller penalty
    if (issuer.requireAuth) riskScore -= 10;
    // Blackholed (master key disabled, no regular key) is the opposite of
    // risky — it means the issuer has permanently given up account control.
    if (issuer.blackholed) riskScore += 15;
  } else {
    riskScore = 0; // no data — score as unknown, not as safe
  }
  subScores.issuerRisk = { score: _clamp0to100(Math.round(riskScore)), inputs: riskInputs };

  const overall = Object.entries(STRENGTH_WEIGHTS).reduce(
    (sum, [key, weight]) => sum + (subScores[key].score * weight / 100), 0
  );

  return {
    overall: Math.round(overall),
    subScores,
    weights: STRENGTH_WEIGHTS,
    dimensionsLive: Object.keys(STRENGTH_WEIGHTS),
    dimensionsDeferred: ['networkActivity', 'treasuryHealth', 'transparency'],
  };
}

/* ── Orchestrator ─────────────────────────────────────────────────────
   One entry point the UI calls with a {symbol, issuer} token record (the
   same shape Token Discovery already produces). Fetches everything in
   parallel — independent RPC calls, no reason to serialize them. */
export async function fetchProjectIntel(token) {
  const currency = _normalizeCurrencyCode(token.currency || token.symbol);
  const issuer = token.issuer;
  if (!issuer) throw new Error('This token has no issuer address — Project Intelligence only applies to issued tokens, not XRP itself.');

  const [amm, issuerRisk, holders, orderBook] = await Promise.all([
    fetchAmmSnapshot(currency, issuer),
    fetchIssuerRisk(issuer),
    fetchHolderConcentration(issuer, currency),
    fetchOrderBookDepth(currency, issuer),
  ]);

  const lp = (amm.exists && amm.account && amm.lpCurrency)
    ? await fetchLpConcentration(amm.account, amm.lpCurrency)
    : { exists: false };

  const strength = computeProjectStrength({ amm, orderBook, holders, lp, issuer: issuerRisk });

  return { token: { symbol: token.symbol, name: token.name, issuer, currency }, amm, issuerRisk, holders, lp, orderBook, strength, fetchedAt: Date.now() };
}

/* ── Project Intelligence Graph — proven layer ───────────────────────────
   Reshapes fetchProjectIntel's already-fetched result into a node/edge
   graph: Project → Token → Issuer / AMM → Whales / LPs. Every node and edge
   here is backed by a specific on-ledger fact already present on `intel` —
   this function issues zero new RPC calls. Every edge carries `proven: true`
   and a `factLabel` naming exactly what ledger data backs it, so nothing
   here reads as an inference. A later, separate "Deep Analysis" pass may
   add `proven: false, confidence` edges (wallet clustering, market-maker
   classification) onto this same node/edge shape — not built in this pass,
   since it needs full transaction-history pagination per graphed holder,
   a materially different RPC cost than the rest of this file. */
const PI_GRAPH_HOLDER_CAP = 10; // matches _concentrationFrom's existing topHolders cap — no new truncation introduced here

export function buildProjectGraph(intel) {
  const nodes = [];
  const edges = [];
  const addNode = (n) => { nodes.push(n); return n.id; };
  const addEdge = (from, to, type, factLabel, extra = {}) =>
    edges.push({ from, to, type, proven: true, factLabel, ...extra });

  const { token, amm, issuerRisk, holders, lp } = intel;

  const projectId = addNode({ id: 'project', type: 'project', label: token.name || token.symbol });
  const tokenId = addNode({ id: 'token', type: 'token', label: token.symbol, meta: { currency: token.currency, issuer: token.issuer } });
  addEdge(projectId, tokenId, 'contains', 'Token record looked up for this project.');

  const issuerId = addNode({
    id: 'issuer', type: 'issuer', label: 'Issuer', address: token.issuer,
    meta: issuerRisk?.exists ? { ...issuerRisk } : { exists: false },
  });
  addEdge(tokenId, issuerId, 'issued-by', `account_info: ${token.issuer} is the issuing account of currency ${token.currency}.`);

  let ammId = null;
  if (amm?.exists) {
    ammId = addNode({
      id: 'amm', type: 'amm', label: 'AMM Pool', address: amm.account,
      meta: { xrpReserve: amm.xrpReserve, tokenReserve: amm.tokenReserve, tradingFeePct: amm.tradingFeePct, lpSupply: amm.lpSupply },
    });
    addEdge(tokenId, ammId, 'pooled-in', `amm_info: XRP/${token.symbol} pool exists at account ${amm.account}.`);

    if (amm.auctionSlot?.account) {
      const auctionId = addNode({
        id: 'auction', type: 'auction', label: 'Auction Slot Holder', address: amm.auctionSlot.account,
        meta: { discountedFeePct: amm.auctionSlot.discountedFeePct, expiration: amm.auctionSlot.expiration },
      });
      addEdge(auctionId, ammId, 'auction-slot-holder', `amm_info: auction_slot.account holds the discounted-fee slot on this pool.`);
    }
    (amm.voteSlots || []).forEach((v, i) => {
      if (!v.account) return;
      const voteId = addNode({
        id: `vote_${i}`, type: 'vote', label: 'Fee Voter', address: v.account,
        meta: { tradingFeePct: v.tradingFeePct, voteWeight: v.voteWeight },
      });
      addEdge(voteId, ammId, 'fee-voter', `amm_info: vote_slots[${i}].account cast a trading-fee vote weighted by its LP-token share.`);
    });
  }

  (holders?.topHolders || []).slice(0, PI_GRAPH_HOLDER_CAP).forEach((h, i) => {
    const pct = holders.totalSampled > 0 ? (h.balance / holders.totalSampled) * 100 : 0;
    const whaleId = addNode({
      id: `whale_${i}`, type: 'whale', label: `Holder #${i + 1}`, address: h.address,
      meta: { balance: h.balance, pctOfSampled: pct },
    });
    addEdge(whaleId, tokenId, 'holds', `account_lines: trustline balance of ${h.balance} (${pct.toFixed(2)}% of the ${holders.holderCount}-holder sample).`);
  });

  if (ammId) {
    (lp?.topHolders || []).slice(0, PI_GRAPH_HOLDER_CAP).forEach((h, i) => {
      const pct = lp.totalSampled > 0 ? (h.balance / lp.totalSampled) * 100 : 0;
      const lpId = addNode({
        id: `lp_${i}`, type: 'lp', label: `LP Holder #${i + 1}`, address: h.address,
        meta: { balance: h.balance, pctOfSampled: pct },
      });
      addEdge(lpId, ammId, 'provides-liquidity', `account_lines (on the AMM account): LP-token balance of ${h.balance} (${pct.toFixed(2)}% of sampled LP supply).`);
    });
  }

  return { nodes, edges };
}
