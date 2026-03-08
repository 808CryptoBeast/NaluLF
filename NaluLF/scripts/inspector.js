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
  // Exchanges
  ['rPVMhWBsfF9iMXYj3aAzJVkPDTFNSyWdKy', { name: 'Bitstamp', type: 'exchange' }],
  ['rrpNnNLKrartuEqfJGpqyDwPj1BBN1ih7', { name: 'Bitstamp', type: 'exchange' }],
  ['rN7n3473SaZBCG4dFL83w7PB9judJ7qdDo', { name: 'Binance', type: 'exchange' }],
  ['rEb8TK3gBgk5auZkwc6sHnwrGVJH8DuaLh', { name: 'Binance', type: 'exchange' }],
  ['rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh', { name: 'Genesis (Black Hole)', type: 'blackhole' }],
  ['r9cZA1mLK5R5Am25ArfXFmqgNwjZgnfk59', { name: 'Black Hole #2', type: 'blackhole' }],
  ['rBKPS4oLSaV2KVVuHH8EpQqMGgGefGFQs7', { name: 'Bitso', type: 'exchange' }],
  ['rfk5bwaKCoNU84fTzdqWQowqnNaZorDmiV',  { name: 'Gate.io', type: 'exchange' }],
  ['rwYHCs2EYBMBvRXFmxDrCUSorPsuqCck7t', { name: 'Kraken', type: 'exchange' }],
  ['rLHzPsX6oXkzU2qL12kHCH8G8cnZv1rBJh', { name: 'Kraken', type: 'exchange' }],
  ['ra5nK24KXen9AHvsdFTKHSANinZseWnPcX', { name: 'Uphold', type: 'exchange' }],
  ['rGWrZyax5eXbi5gs49MRZKkE9eKNL9p4B',  { name: 'Bittrex', type: 'exchange' }],
  ['rDsbeomae4FXwgQTJp9Rs64Qg9vDiTCdBv', { name: 'Coinone', type: 'exchange' }],
  ['rHsMUQFzBb7S6GnQFVgNirqvHRcLpAn5dU', { name: 'Bithumb', type: 'exchange' }],
  ['rMQ98K56yXJbDGv49ZSmW51sLn94Xe1mu1', { name: 'Huobi', type: 'exchange' }],
]);



/* ─────────────────────────────
   State
──────────────────────────────── */
let _currentAddr  = null;
let _inspectAbort = false;
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
    _setMsg('Fetching transaction history…');

    // ── Phase 2: Transaction history (up to 200 tx) ─────────────────────────
    const txRes = await wsSend({
      command: 'account_tx', account: addr,
      limit: 200, ledger_index_min: -1, ledger_index_max: -1,
    }).catch(() => null);

    if (_inspectAbort) return;
    if (d.loading) d.loading.style.display = 'none';

    const acct    = infoRes?.result?.account_data || {};
    const lines   = linesRes?.result?.lines       || [];
    const offers  = offersRes?.result?.offers      || [];
    const nfts    = nftRes?.result?.account_nfts   || [];
    const objects = objRes?.result?.account_objects || [];
    const txList  = normaliseTxList(txRes?.result?.transactions || []);

    // ── Phase 3: Render ─────────────────────────────────────────────────────
    renderAll(addr, acct, lines, offers, nfts, objects, txList);

    if (d.result) d.result.style.display = '';

    // Save to history
    const riskVal = d.score ? Number(d.score.textContent) : null;
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
  return raw.map(item => {
    const tx   = item.tx   || item.transaction   || {};
    const meta = item.meta || item.metadata       || {};
    return { tx, meta };
  });
}

/* ─────────────────────────────
   Master render
──────────────────────────────── */
function renderAll(addr, acct, lines, offers, nfts, objects, txList) {
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
  const ammAnalysis        = analyseAmmPositions(lines, txList, objects);
  const benfordsAnalysis   = analyseBenfordsLaw(txList);
  const volConcAnalysis    = analyseVolumeConcentration(txList, addr);

  // ── New deep analysis ────────────────────────────────────────────────────
  const fundFlowAnalysis      = analyseFundFlow(txList, addr);
  const issuerConnAnalysis    = analyseIssuerConnections(txList, addr, lines);

  // Overall risk score (0–100)
  const riskScore = computeOverallRisk(securityAudit, drainAnalysis, nftAnalysis, washAnalysis, benfordsAnalysis, volConcAnalysis);

  // ── Render sections ──────────────────────────────────────────────────────
  renderHeader(addr, acct, balXrp, reserve, ownerCnt, sequence, riskScore);
  renderSecurityAudit(securityAudit, acct, flags, signerLists, depositAuths);
  renderDrainAnalysis(drainAnalysis, paychans, escrows, checks);
  renderFundFlowPanel(fundFlowAnalysis);
  renderNftPanel(nftAnalysis, nfts);
  renderWashPanel(washAnalysis);
  renderBenfordsPanel(benfordsAnalysis);
  renderVolConcPanel(volConcAnalysis);
  renderIssuerPanel(issuerAnalysis, lines);
  renderIssuerConnectionsPanel(issuerConnAnalysis, lines);
  renderAmmPanel(ammAnalysis, lines);
  renderTrustlines(lines);
  renderTxTimeline(txList, addr);

  // ── Full Report section (always rendered last) ───────────────────────────
  const reportContainer = $('inspect-report-body');
  if (reportContainer) {
    renderFullReport(
      reportContainer,
      addr, acct, balXrp, riskScore,
      securityAudit, drainAnalysis, nftAnalysis, washAnalysis,
      benfordsAnalysis, volConcAnalysis, issuerAnalysis,
      ammAnalysis, fundFlowAnalysis, issuerConnAnalysis, txList
    );
  }
}


/* ── Fund Flow Tracer ────────────────────────────── */
function analyseFundFlow(txList, addr) {
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
        entity:    KNOWN_ENTITIES.get(dest) || null,
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
  };
}

/* ── Issuer Connection Analysis ──────────────────── */
function analyseIssuerConnections(txList, addr, lines) {
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
  const issuedLines = lines.filter(l => Number(l.balance) < 0);
  const totalIssued = issuedLines.reduce((s, l) => s + Math.abs(Number(l.balance)), 0);
  const topHolders  = issuedLines
    .map(l => ({ addr: l.account, balance: Math.abs(Number(l.balance)), currency: hexToAscii(l.currency) }))
    .sort((a, b) => b.balance - a.balance)
    .slice(0, 10);

  if (topHolders.length >= 2 && totalIssued > 0) {
    const top1Pct = topHolders[0].balance / totalIssued * 100;
    if (top1Pct > 50) {
      signals.push({ sev: 'critical', label: `Top holder controls ${top1Pct.toFixed(0)}% of supply`,
        detail: `${shortAddr(topHolders[0].addr)} holds ${fmt(topHolders[0].balance, 0)} of ${fmt(totalIssued, 0)} total. Extreme dump risk.` });
    } else if (top1Pct > 25) {
      signals.push({ sev: 'warn', label: `Top holder controls ${top1Pct.toFixed(0)}% of supply`,
        detail: 'Large single holder concentration. Monitor for coordinated sell events.' });
    }

    // Top-5 concentration
    const top5 = topHolders.slice(0, 5).reduce((s, h) => s + h.balance, 0);
    const top5Pct = top5 / totalIssued * 100;
    if (top5Pct > 75) {
      signals.push({ sev: 'warn', label: `Top 5 holders own ${top5Pct.toFixed(0)}% of supply`,
        detail: 'Supply heavily concentrated in a few wallets — common in pre-launch manipulation setups.' });
    }
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
  };
}

/* ═══════════════════════════════════════════════════
   ANALYSIS PASSES
═══════════════════════════════════════════════════ */

/* ── Security Posture ────────────────────────────── */
function analyseSecurityPosture(acct, flags, signerLists, txList) {
  const findings = [];
  let score = 100; // start perfect, deduct

  // 1. Master key disabled without regular key = locked out risk
  const masterDisabled = !!(flags & FLAGS.lsfDisableMaster);
  const hasRegularKey  = !!acct.RegularKey;
  const hasSignerList  = signerLists.length > 0;

  if (masterDisabled && !hasRegularKey && !hasSignerList) {
    findings.push({ sev: 'critical', label: 'Master key disabled — no fallback', detail: 'Account cannot sign transactions. Funds are inaccessible.' });
    score -= 40;
  } else if (masterDisabled) {
    findings.push({ sev: 'info', label: 'Master key disabled', detail: 'Signing via regular key or multisig only.' });
  }

  // 2. Regular key set — check if it changed recently
  if (hasRegularKey) {
    const setKeyTx = txList.find(({ tx }) => tx.TransactionType === 'SetRegularKey');
    const recentChange = setKeyTx &&
      (Date.now() / 1000 - getCloseTime(setKeyTx.tx)) < 86400 * 30;
    if (recentChange) {
      findings.push({ sev: 'warn', label: `Regular key set recently`, detail: `Key: ${acct.RegularKey} — changed within 30 days. Verify you intended this.` });
      score -= 15;
    } else {
      findings.push({ sev: 'info', label: 'Regular key active', detail: acct.RegularKey });
    }
  }

  // 3. Signer list analysis
  signerLists.forEach(sl => {
    const entries = sl.SignerEntries || [];
    const quorum  = sl.SignerQuorum || 1;
    findings.push({ sev: 'info', label: `Multisig: ${entries.length} signers, quorum ${quorum}`,
      detail: entries.map(e => shortAddr(e.SignerEntry?.Account || '')).join(', ') });
  });

  // 4. Global freeze (issuer froze all balances)
  if (flags & FLAGS.lsfGlobalFreeze) {
    findings.push({ sev: 'warn', label: 'Global Freeze active', detail: 'This issuer has frozen all token balances.' });
    score -= 10;
  }

  // 5. Deposit auth (good practice actually)
  if (flags & FLAGS.lsfDepositAuth) {
    findings.push({ sev: 'ok', label: 'Deposit Authorization enabled', detail: 'Only pre-authorized senders can deposit.' });
  }

  // 6. Default ripple (issuer flag — rippling enabled)
  if (flags & FLAGS.lsfDefaultRipple) {
    findings.push({ sev: 'info', label: 'Default Ripple enabled', detail: 'Balances can ripple through this account (issuer behaviour).' });
  }

  // 7. AccountDelete attempts
  const deleteTxs = txList.filter(({ tx }) => tx.TransactionType === 'AccountDelete');
  if (deleteTxs.length) {
    findings.push({ sev: 'warn', label: `${deleteTxs.length} AccountDelete attempt(s)`, detail: 'Account deletion was attempted.' });
    score -= 5;
  }

  return { findings, score: Math.max(0, score) };
}

/* ── Drain Risk ──────────────────────────────────── */
function analyseDrainRisk(acct, flags, signerLists, txList, paychans, escrows) {
  const signals  = [];
  let   riskLevel = 'low'; // low | medium | high | critical

  // 1. Regular key changed + master disabled = classic drain setup
  const masterOff = !!(flags & FLAGS.lsfDisableMaster);
  if (masterOff && acct.RegularKey) {
    signals.push({ sev: 'critical', label: 'Classic drain setup detected',
      detail: `Master key disabled. Regular key ${acct.RegularKey} controls the account. If this key was set by an attacker, funds are at risk.` });
    riskLevel = 'critical';
  }

  // 2. Recent SetRegularKey from a DIFFERENT sender (3rd party set the key)
  const keyChanges = txList.filter(({ tx }) =>
    tx.TransactionType === 'SetRegularKey' && tx.Account !== acct.Account
  );
  if (keyChanges.length) {
    signals.push({ sev: 'critical', label: `Regular key set by external account`,
      detail: `${keyChanges.length} key change(s) where sender ≠ account owner. This is unusual.` });
    riskLevel = 'critical';
  }

  // 3. Large outflows shortly after suspicious auth changes
  const suspiciousAuthTxs = txList.filter(({ tx }) =>
    ['SetRegularKey', 'SignerListSet'].includes(tx.TransactionType)
  );
  if (suspiciousAuthTxs.length > 0) {
    const authTime = getCloseTime(suspiciousAuthTxs[0].tx);
    const drainPayments = txList.filter(({ tx, meta }) => {
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
        signals.push({ sev: 'critical', label: `${fmt(totalDrained, 2)} XRP sent within 48h of auth change`,
          detail: `${drainPayments.length} payment(s) shortly after key/signer modification. Pattern matches drain attack.` });
        riskLevel = 'critical';
      }
    }
  }

  // 4. Open payment channels (funds locked for potential drain)
  if (paychans.length) {
    const totalLocked = paychans.reduce((acc, p) => acc + Number(p.Amount || 0) / 1e6, 0);
    signals.push({ sev: 'warn', label: `${paychans.length} open payment channel(s) — ${fmt(totalLocked, 2)} XRP locked`,
      detail: `Destination(s): ${paychans.map(p => shortAddr(p.Destination)).join(', ')}` });
    if (riskLevel === 'low') riskLevel = 'medium';
  }

  // 5. Open escrows
  if (escrows.length) {
    const totalEscrowed = escrows.reduce((acc, e) => acc + Number(e.Amount || 0) / 1e6, 0);
    signals.push({ sev: 'info', label: `${escrows.length} open escrow(s) — ${fmt(totalEscrowed, 2)} XRP escrowed`,
      detail: `Escrow(s): ${escrows.map(e => e.Destination ? shortAddr(e.Destination) : 'self-escrow').join(', ')}` });
  }

  // 6. DepositPreauth grants (who is authorized to send to this wallet)
  // This is actually protective — just flag who is authorized
  const authGrants = txList.filter(({ tx }) => tx.TransactionType === 'DepositPreauth' && tx.Authorize);
  if (authGrants.length > 5) {
    signals.push({ sev: 'warn', label: `${authGrants.length} DepositPreauth grants issued`,
      detail: 'Account pre-authorized many senders. Review if all are trusted.' });
    if (riskLevel === 'low') riskLevel = 'medium';
  }

  if (signals.length === 0) {
    signals.push({ sev: 'ok', label: 'No drain patterns detected', detail: 'Auth structure looks intact.' });
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

  // Supply concentration: top-holder dominance (bubble map proxy)
  if (obligations.length >= 3) {
    // Sort holders by absolute obligation (how much we "owe" them)
    const holderBals = obligations
      .map(l => ({ holder: l.account, bal: Math.abs(Number(l.balance)) }))
      .sort((a, b) => b.bal - a.bal);
    const totalBal = holderBals.reduce((s, h) => s + h.bal, 0);
    const top3Bal  = holderBals.slice(0, 3).reduce((s, h) => s + h.bal, 0);
    const top3Pct  = totalBal > 0 ? (top3Bal / totalBal) * 100 : 0;
    const topHolder = holderBals[0];
    const top1Pct   = totalBal > 0 ? (topHolder.bal / totalBal) * 100 : 0;

    if (top1Pct >= 80) {
      signals.push({ sev: 'critical',
        label: `Supply concentration: 1 wallet holds ${top1Pct.toFixed(0)}% of supply`,
        detail: `A single address (${shortAddr(topHolder.holder)}) controls the vast majority of circulating tokens. ` +
                '"Heavy bubble" — this wallet can easily dump on holders with zero warning.' });
    } else if (top3Pct >= 80) {
      signals.push({ sev: 'warn',
        label: `Supply concentration: top 3 wallets hold ${top3Pct.toFixed(0)}%`,
        detail: `Top 3 holders control most of circulating supply. Coordinated selling could collapse token price.` });
    } else if (top3Pct >= 60) {
      signals.push({ sev: 'info',
        label: `Moderate supply concentration: top 3 hold ${top3Pct.toFixed(0)}%`,
        detail: `Top 3 holders hold a majority but not a dominant share. Monitor for accumulation changes.` });
    }
  }

  if (signals.length === 0) {
    signals.push({ sev: 'ok', label: 'No token issuer flags', detail: 'This account does not appear to be a token issuer.' });
  }

  return { signals, isIssuer, obligationCount: obligations.length };
}

/* ── AMM Positions ───────────────────────────────── */
function analyseAmmPositions(lines, txList, objects) {
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

/* ─────────────────────────────
   Overall Risk Score
──────────────────────────────── */
function computeOverallRisk(security, drain, nft, wash, benfords, volConc) {
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

  // Wash trading (0–15 pts — bumped because we now have more checks)
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
  let explainTitle = 'What is Benfords Law?';
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

/* ── Header / Overview ───────────────────────────── */
function renderHeader(addr, acct, balXrp, reserve, ownerCnt, sequence, riskScore) {
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

  const cells = [
    { label: 'XRP Balance',     value: `${fmt(balXrp, 6)} XRP`,      mono: true },
    { label: 'Spendable',       value: `${fmt(spendable, 6)} XRP`,    mono: true, note: `${reserve} XRP reserved` },
    { label: 'Owner Count',     value: ownerCnt,                       note: `${ownerCnt * 2} XRP tied up` },
    { label: 'Sequence',        value: sequence,                       mono: true },
    { label: 'Regular Key',     value: acct.RegularKey ? shortAddr(acct.RegularKey) : 'None',
      warn: !!acct.RegularKey, mono: true },
    { label: 'Master Key',      value: (flags & FLAGS.lsfDisableMaster) ? 'Disabled' : 'Active',
      warn: !!(flags & FLAGS.lsfDisableMaster) },
  ];

  grid.innerHTML = cells.map(c => `
    <div class="acct-cell ${c.warn ? 'acct-cell--warn' : ''}">
      <div class="acct-cell-label">${escHtml(c.label)}</div>
      <div class="acct-cell-value ${c.mono ? 'mono' : ''}">${escHtml(String(c.value))}</div>
      ${c.note ? `<div class="acct-cell-note">${escHtml(c.note)}</div>` : ''}
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

        return `
          <div class="tx-row tx-row--${risk}">
            <span class="tx-type-badge tx-type-badge--${typeBadgeClass(type)}">${escHtml(type)}</span>
            <span class="tx-brief">${brief}</span>
            <span class="tx-result ${success ? 'tx-ok' : 'tx-fail'}">${success ? '✓' : '✗'}</span>
            <span class="tx-time">${timeStr}</span>
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
    el.innerHTML = `<div class="audit-row audit-row--ok"><span class="audit-icon">✓</span><div class="audit-text"><div class="audit-label">No outbound payments found in last 200 tx</div></div></div>`;
    if (badge) { badge.textContent = 'Clear'; badge.className = 'section-badge section-badge--ok'; }
    return;
  }

  const exchangeAlert = flow.exchangeDests.length
    ? `<div class="flow-alert flow-alert--exchange">💱 Funds reached ${flow.exchangeDests.length} known exchange(s): ${flow.exchangeDests.map(d => d.entity.name).join(', ')}</div>`
    : '';
  const blackholeAlert = flow.blackHoleDests.length
    ? `<div class="flow-alert flow-alert--blackhole">🕳 Funds sent to black hole address — irrecoverable!</div>`
    : '';

  el.innerHTML = `
    ${exchangeAlert}${blackholeAlert}
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
        const ent   = KNOWN_ENTITIES.get(o.dest);
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
  ammAnalysis, fundFlowAnalysis, issuerConnAnalysis, txList) {

  const ts     = new Date().toLocaleString();
  const addrShort = addr.slice(0,10) + '…' + addr.slice(-8);
  const riskCls   = riskScoreClass(riskScore);
  const riskWord  = riskScore < 20 ? 'LOW' : riskScore < 45 ? 'MODERATE' : riskScore < 70 ? 'HIGH' : 'CRITICAL';
  const riskColor = riskScore < 20 ? '#50fa7b' : riskScore < 45 ? '#ffb86c' : riskScore < 70 ? '#ff8c42' : '#ff5555';

  // ── Collect all findings across modules ─────────────────────────────────
  const allFindings = [];

  const push = (module, sev, headline, detail) =>
    allFindings.push({ module, sev, headline, detail });

  // Security
  for (const f of securityAudit.findings || []) push('Security', f.sev, f.label, f.detail);
  // Drain
  push('Drain Risk', drainAnalysis.riskLevel === 'low' ? 'ok' : drainAnalysis.riskLevel === 'medium' ? 'warn' : 'critical',
    'Drain Risk Level: ' + drainAnalysis.riskLevel.toUpperCase(), null);
  for (const s of drainAnalysis.signals || []) if (s.sev !== 'ok') push('Drain Risk', s.sev, s.label, s.detail);
  // NFT
  for (const f of nftAnalysis.flags || []) if (f.sev !== 'ok') push('NFT', f.sev, f.label, f.detail);
  // Wash
  if (washAnalysis.verdict && washAnalysis.verdict !== 'clean' && washAnalysis.verdict !== 'low-risk') {
    push('Wash Trading', washAnalysis.score >= 60 ? 'critical' : 'warn',
      `Wash score ${washAnalysis.score}/100 — ${washAnalysis.verdict.replace('-',' ')}`, null);
  }
  for (const s of washAnalysis.signals || []) if (s.sev !== 'ok') push('Wash Trading', s.sev, s.label, s.detail);
  // Benford
  for (const s of benfordsAnalysis.signals || []) if (s.sev !== 'ok') push("Benford's Law", s.sev, s.label, s.detail);
  // Vol conc
  for (const s of volConcAnalysis.signals || []) if (s.sev !== 'ok') push('Volume Concentration', s.sev, s.label, s.detail);
  // Issuer
  for (const s of issuerAnalysis.signals || []) if (s.sev !== 'ok') push('Token Issuer', s.sev, s.label, s.detail);
  // AMM
  for (const s of ammAnalysis.signals || []) if (s.sev !== 'ok') push('AMM', s.sev, s.label, s.detail);
  // Fund flow
  if (fundFlowAnalysis.blackHoleDests?.length)
    push('Fund Flow', 'critical', `Funds sent to ${fundFlowAnalysis.blackHoleDests.length} black hole address(es)`, 'These funds are permanently irrecoverable.');
  if (fundFlowAnalysis.exchangeDests?.length)
    push('Fund Flow', 'warn', `${fundFlowAnalysis.exchangeDests.length} known exchange(s) received funds`, fundFlowAnalysis.exchangeDests.map(d => d.entity.name).join(', '));
  // Issuer connections
  for (const s of issuerConnAnalysis.signals || []) if (s.sev !== 'ok') push('Issuer Connections', s.sev, s.label, s.detail);

  const criticals = allFindings.filter(f => f.sev === 'critical');
  const warnings  = allFindings.filter(f => f.sev === 'warn');
  const infos     = allFindings.filter(f => f.sev === 'info');

  // ── Narrative summary ────────────────────────────────────────────────────
  function buildNarrative() {
    const parts = [];
    parts.push(`<strong>Address ${addrShort}</strong> was inspected on ${ts}. `
      + `The account holds <strong>${fmt(balXrp, 4)} XRP</strong> and has a computed risk score of `
      + `<strong style="color:${riskColor}">${riskScore}/100 (${riskWord})</strong>. `
      + `The analysis covered the last 200 transactions and all on-chain account objects.`);

    if (criticals.length) {
      parts.push(`The scan identified <strong>${criticals.length} critical finding${criticals.length > 1 ? 's' : ''}</strong> that require immediate attention.`);
    }

    // Drain narrative
    if (drainAnalysis.riskLevel === 'critical') {
      parts.push(`<span style="color:#ff5555"><strong>Wallet drain indicators are present.</strong></span> The account's authentication structure matches the classic drain setup — master key disabled with a recently-set regular key, or key changes made by an external account. If this is your wallet, assume it is compromised and move funds immediately if the account can still sign.`);
    } else if (drainAnalysis.riskLevel === 'high') {
      parts.push(`Elevated drain risk signals were found. Review the Drain Risk section for details on auth changes and outflow patterns.`);
    }

    // Fund flow narrative
    if (fundFlowAnalysis.blackHoleDests?.length) {
      parts.push(`<span style="color:#ff5555">Funds were sent to one or more black hole addresses and <strong>cannot be recovered</strong>.</span>`);
    }
    if (fundFlowAnalysis.exchangeDests?.length) {
      const exchNames = [...new Set(fundFlowAnalysis.exchangeDests.map(d => d.entity.name))].join(', ');
      parts.push(`Outbound funds reached <strong>${fundFlowAnalysis.exchangeDests.length} known exchange(s): ${exchNames}</strong>. Total tracked outflow: ${fmt(fundFlowAnalysis.totalOut, 2)} XRP across ${fundFlowAnalysis.uniqueDests} destination(s).`);
    } else if (fundFlowAnalysis.totalOut > 0) {
      parts.push(`Total outbound XRP: <strong>${fmt(fundFlowAnalysis.totalOut, 2)} XRP</strong> across ${fundFlowAnalysis.uniqueDests} destination(s). None matched known exchange addresses.`);
    }

    // Wash trading narrative
    if (washAnalysis.score >= 60) {
      parts.push(`<strong>Significant wash trading indicators</strong> were detected (score ${washAnalysis.score}/100). The account shows patterns — high cancel ratios, round-trip counterparties, or near-identical trade sizes — that are statistically inconsistent with genuine market activity.`);
    } else if (washAnalysis.score >= 30) {
      parts.push(`Moderate wash trading signals (score ${washAnalysis.score}/100). Some DEX behavior is suspicious but not conclusive on its own.`);
    }

    // Benford narrative
    if (benfordsAnalysis.verdict === 'high-deviation') {
      parts.push(`Benford's Law analysis found <strong>statistically significant deviation</strong> (χ²=${benfordsAnalysis.chiSq?.toFixed(1)}) in the distribution of transaction amount first digits. This pattern is consistent with algorithmically generated or manipulated transaction values.`);
    }

    // Issuer narrative
    if (issuerConnAnalysis.totalIssued > 0) {
      const top = issuerConnAnalysis.topHolders?.[0];
      const topPct = top && issuerConnAnalysis.totalIssued > 0
        ? (top.balance / issuerConnAnalysis.totalIssued * 100).toFixed(0) : null;
      parts.push(`This account has issued tokens with a total outstanding supply of <strong>${fmt(issuerConnAnalysis.totalIssued, 0)}</strong> across ${issuerConnAnalysis.holderCount} trustline holder(s).`
        + (topPct ? ` The largest holder controls <strong>${topPct}%</strong> of supply.` : ''));
      if (issuerConnAnalysis.mirrorGroups?.length) {
        parts.push(`<strong>${issuerConnAnalysis.mirrorGroups.length} mirror-wallet cluster(s)</strong> detected — groups of accounts that received nearly identical token amounts. This is a strong indicator of coordinated wallets or sybil rings.`);
      }
      if (issuerConnAnalysis.createdAccts?.length > 0) {
        parts.push(`This issuer created or activated <strong>${issuerConnAnalysis.createdAccts.length} account(s)</strong>. These accounts were funded from this address and may be controlled by the same entity.`);
      }
    }

    // NFT narrative
    const critNft = (nftAnalysis.flags || []).filter(f => f.sev === 'critical');
    if (critNft.length) {
      parts.push(`NFT analysis flagged <strong>${critNft.length} critical issue(s)</strong>, including possible zero-value sell offers — a common NFT drain vector where victims inadvertently list assets for free.`);
    }

    // Clean bill
    if (criticals.length === 0 && warnings.length === 0) {
      parts.push(`<span style="color:#50fa7b"><strong>No elevated signals were found.</strong></span> The account's security posture, transaction patterns, and on-chain objects all appear within normal parameters.`);
    }

    return parts;
  }

  const narrativeParts = buildNarrative();

  // ── Severity badge helper ─────────────────────────────────────────────────
  const sevBadge = (sev) => {
    const map = {
      critical: 'background:rgba(255,85,85,.15);border:1px solid rgba(255,85,85,.35);color:#ff5555',
      warn:     'background:rgba(255,184,108,.10);border:1px solid rgba(255,184,108,.30);color:#ffb86c',
      info:     'background:rgba(120,180,255,.08);border:1px solid rgba(120,180,255,.18);color:rgba(120,180,255,.9)',
      ok:       'background:rgba(80,250,123,.08);border:1px solid rgba(80,250,123,.22);color:#50fa7b',
    };
    return `<span style="padding:2px 8px;border-radius:999px;font-size:.68rem;font-weight:900;letter-spacing:.3px;text-transform:uppercase;${map[sev] || map.info}">${sev.toUpperCase()}</span>`;
  };

  // ── Module grouping ───────────────────────────────────────────────────────
  const moduleOrder = ['Security','Drain Risk','Fund Flow','NFT','Wash Trading',"Benford's Law",'Volume Concentration','Token Issuer','AMM','Issuer Connections'];
  const byModule = {};
  for (const m of moduleOrder) byModule[m] = allFindings.filter(f => f.module === m && f.sev !== 'ok' && f.sev !== 'info');

  const findingRows = moduleOrder
    .filter(m => byModule[m].length > 0)
    .map(m => {
      const rows = byModule[m].map(f => `
        <div class="report-finding-row">
          <div class="report-finding-top">
            ${sevBadge(f.sev)}
            <span class="report-finding-headline">${escHtml(f.headline)}</span>
          </div>
          ${f.detail ? `<div class="report-finding-detail">${escHtml(f.detail)}</div>` : ''}
        </div>`).join('');
      return `
        <div class="report-module">
          <div class="report-module-h">${escHtml(m)}</div>
          ${rows}
        </div>`;
    }).join('');

  // ── Stats snapshot ────────────────────────────────────────────────────────
  const statRows = [
    { k: 'Address',           v: addr, mono: true },
    { k: 'Balance',           v: fmt(balXrp, 4) + ' XRP', mono: true },
    { k: 'Risk Score',        v: riskScore + '/100 — ' + riskWord, color: riskColor },
    { k: 'Transactions',      v: txList.length + ' analysed' },
    { k: 'Outbound destinations', v: fundFlowAnalysis.uniqueDests },
    { k: 'Total XRP out',     v: fmt(fundFlowAnalysis.totalOut, 2) + ' XRP', mono: true },
    { k: 'Wash score',        v: (washAnalysis.score || 0) + '/100 — ' + (washAnalysis.verdict || '—').replace('-',' ') },
    { k: "Benford's χ²",      v: benfordsAnalysis.chiSq != null ? benfordsAnalysis.chiSq.toFixed(2) + ' (' + benfordsAnalysis.verdict + ')' : 'insufficient data', mono: true },
    { k: 'Trustline holders', v: issuerConnAnalysis.holderCount || 0 },
    { k: 'Critical findings', v: criticals.length, color: criticals.length > 0 ? '#ff5555' : '#50fa7b' },
    { k: 'Warnings',          v: warnings.length, color: warnings.length > 0 ? '#ffb86c' : '#50fa7b' },
  ].map(r => `
    <div class="report-stat-row">
      <span class="report-stat-k">${escHtml(r.k)}</span>
      <span class="report-stat-v ${r.mono ? 'mono' : ''}" style="${r.color ? 'color:' + r.color : ''}">${escHtml(String(r.v))}</span>
    </div>`).join('');

  // ── Recommendations ───────────────────────────────────────────────────────
  const recs = [];
  if (drainAnalysis.riskLevel === 'critical' || drainAnalysis.riskLevel === 'high')
    recs.push({ icon: '🔴', text: 'If this is your wallet: do not send further funds to this address. Investigate the auth change history immediately and consider the account compromised.' });
  if (fundFlowAnalysis.blackHoleDests?.length)
    recs.push({ icon: '⛔', text: 'Funds sent to black hole addresses are irrecoverable. No further action will reverse these transactions.' });
  if (fundFlowAnalysis.exchangeDests?.length)
    recs.push({ icon: '💱', text: `Contact ${[...new Set(fundFlowAnalysis.exchangeDests.map(d => d.entity.name))].join(', ')} exchange support with the transaction hashes from the Fund Flow section. Exchanges may be able to freeze accounts if contacted quickly after a drain.` });
  if (washAnalysis.score >= 50)
    recs.push({ icon: '📊', text: 'DEX activity shows wash trading signals. If you are a market maker, high cancel ratios can be normal — review the specific patterns flagged against your trading strategy.' });
  if (issuerConnAnalysis.mirrorGroups?.length)
    recs.push({ icon: '🕸', text: 'Mirror wallet clusters found. If you are the issuer, review whether these coordinated wallets represent insider accounts that could create artificial trading volume or coordinated dumps.' });
  if (nftAnalysis.flags?.some(f => f.sev === 'critical'))
    recs.push({ icon: '🎨', text: 'NFT zero-value offer detected. Check whether you intentionally created sell offers at this price, or whether a malicious dApp tricked you into signing a disguised transaction.' });
  if (recs.length === 0)
    recs.push({ icon: '✅', text: 'No immediate actions required. Continue monitoring this address as activity increases for emerging signals.' });

  const recsHtml = recs.map(r => `
    <div class="report-rec">
      <span class="report-rec-icon">${r.icon}</span>
      <span class="report-rec-text">${r.text}</span>
    </div>`).join('');

  return `
    <div class="report-wrap">

      <!-- ── Cover ── -->
      <div class="report-cover">
        <div class="report-cover-left">
          <div class="report-logo">⚡ NaluXRP</div>
          <h2 class="report-title">Account Investigation Report</h2>
          <div class="report-addr mono">${escHtml(addr)}</div>
          <div class="report-ts">Generated ${ts}</div>
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
          ${narrativeParts.map(p => `<p>${p}</p>`).join('')}
        </div>
      </div>

      <!-- ── Stats Snapshot ── -->
      <div class="report-section">
        <h3 class="report-section-h">📐 Account Snapshot</h3>
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
        <div class="report-findings">${findingRows}</div>
      </div>` : `
      <div class="report-section">
        <h3 class="report-section-h">🔬 Findings</h3>
        <div class="report-clean-note">✅ No elevated findings across all modules.</div>
      </div>`}

      <!-- ── Recommendations ── -->
      <div class="report-section">
        <h3 class="report-section-h">💡 Recommended Actions</h3>
        <div class="report-recs">${recsHtml}</div>
      </div>

      <!-- ── Disclaimer ── -->
      <div class="report-disclaimer">
        This report is generated from on-chain public data and heuristic analysis only.
        Signals are not proof. Always verify findings manually before taking legal or financial action.
        NaluXRP Inspector is a transparency tool — not a legal or forensic authority.
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
            <button class="report-export-btn" id="report-export-btn" onclick="exportInspectorReport()" title="Copy report to clipboard">📋 Copy Report</button>
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
      <button class="in-btn" data-jump="security"><span class="in-icon">🔐</span><span class="in-label">Security</span></button>
      <button class="in-btn" data-jump="drain"><span class="in-icon">⚠</span><span class="in-label">Drain</span></button>
      <button class="in-btn in-btn--flow" data-jump="fundflow"><span class="in-icon">🌊</span><span class="in-label">Flow</span></button>
      <button class="in-btn" data-jump="nft"><span class="in-icon">🎨</span><span class="in-label">NFT</span></button>
      <button class="in-btn" data-jump="wash"><span class="in-icon">📊</span><span class="in-label">Wash</span></button>
      <button class="in-btn" data-jump="benfords"><span class="in-icon">📐</span><span class="in-label">Benford</span></button>
      <button class="in-btn" data-jump="volconc"><span class="in-icon">🫧</span><span class="in-label">Vol.Conc</span></button>
      <button class="in-btn" data-jump="issuer"><span class="in-icon">🪙</span><span class="in-label">Issuer</span></button>
      <button class="in-btn in-btn--conn" data-jump="issuer-connections"><span class="in-icon">🕸</span><span class="in-label">Connections</span></button>
      <button class="in-btn" data-jump="amm"><span class="in-icon">💧</span><span class="in-label">AMM</span></button>
      <button class="in-btn" data-jump="trustlines"><span class="in-icon">🔗</span><span class="in-label">Lines</span></button>
      <button class="in-btn" data-jump="tx"><span class="in-icon">📜</span><span class="in-label">History</span></button>
      <button class="in-btn in-btn--report" data-jump="report"><span class="in-icon">📄</span><span class="in-label">Report</span></button>
      <button class="in-btn in-btn--guide" onclick="showInspectorHowTo()"><span class="in-icon">?</span><span class="in-label">Guide</span></button>
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
            <div class="howto-item-desc">Last 200 txs color-coded by risk.
              <span class="howto-amber">Amber border</span> = auth-changing tx (key changes, signer lists).
              <span class="howto-red">Red border</span> = high risk (free NFT offers). Faded = failed tx.</div>
          </div>
        </div>

        <div class="howto-tip">
          <span class="howto-tip-icon">💡</span>
          <span><strong>Pro tips:</strong> Connect your wallet in Profile to auto-populate your address here.
            Click any address in the live stream to inspect it instantly.
            Paste an address — inspection runs automatically.</span>
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