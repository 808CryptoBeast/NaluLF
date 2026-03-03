/* =====================================================
   network.js — Deep-State XRPL Health & Security Suite
   NaluLF v3.1

   Verified rippled API field paths.
   New in v3.1:
     - Interactive world map (SVG, hover tooltips)
     - Amendment detail modal with full documentation
     - System Health Dashboard (11 checks, 3 groups)
     - Health check summary strip in banner
   ===================================================== */

import { $, escHtml, toastWarn } from './utils.js';
import { state }                  from './state.js';
import { wsSend }                 from './xrpl.js';
import { ENDPOINTS_BY_NETWORK }   from './config.js';

const POLL_MS             = 60_000;
const MIN_GAP_MS          = 10_000;
const BACKOFF_MS          = 120_000;
const LATENCY_TIMEOUT_MS  = 8_000;
const LATENCY_COOLDOWN_MS = 120_000;
const LATENCY_GAP_MS      = 300;
const BASELINE_KEY        = 'nalulf_net_baseline_v2';
const BASELINE_LEN        = 80;
const ALERT_WEIGHT        = 5;

/* ─── Adversarial signal registry ─── */
const SIG = {
  quorumTight:   { w:3, label:'Quorum within 3 validators of failure threshold'           },
  nUnlActive:    { w:2, label:'Negative UNL active — validators currently being ignored'  },
  amendVeto:     { w:1, label:'Amendment veto clustering — protocol governance dispute'   },
  feeSpike:      { w:2, label:'Open ledger fee 10× minimum — DDoS / spam attack likely'  },
  burnAnomaly:   { w:2, label:'XRP burn rate z-score > 3σ — resource exhaustion pattern' },
  peerSaturate:  { w:2, label:'Inbound peers > 80% of connections — Eclipse Attack risk' },
  eclipseRisk:   { w:3, label:'Peer count < 6 — node highly vulnerable to isolation'     },
  dexSpike:      { w:1, label:'DEX volume > 3× AMM baseline — unusual event-driven flow' },
  reserveSpike:  { w:1, label:'New account rate > 3× baseline — possible bot creation'   },
  slowConverge:  { w:2, label:'Consensus convergence > 6s — network agreement degraded'  },
  lowProposers:  { w:2, label:'Proposer count below quorum — validator participation low' },
  queuePressure: { w:2, label:'TX queue > 80% full — fee surge imminent'                 },
  spamLedger:    { w:1, label:'Ledger > 2× expected size — ledger spam in progress'      },
  ioStressed:    { w:1, label:'Node IO latency > 5ms — storage or network I/O stress'   },
  peerChurn:     { w:1, label:'Elevated peer disconnect rate — DDoS or instability'      },
  staleLedger:   { w:3, label:'Ledger age > 10s — validation appears stalled'            },
};

/* ─── Amendment documentation ─── */
const AMENDMENT_DOCS = {
  MultiSign:            { purpose:'Multi-signature authorization',                    intro:'rippled 0.31',  desc:'Lets multiple keys jointly authorize one transaction. Essential for institutional custody and hardware-wallet setups.',                         impact:'New transaction: SignerListSet. All signers submit their signature; the last one broadcasts.' },
  MultiSignReserve:     { purpose:'Cheaper signer-list reserve',                      intro:'rippled 1.2',   desc:'Cuts the owner reserve for SignerList objects from 5 owner-items (10 XRP) down to 1 owner-item (2 XRP).',                                     impact:'Existing SignerLists do not gain the reduction automatically; delete and re-create the list.' },
  DepositAuth:          { purpose:'Block unsolicited incoming payments',               intro:'rippled 0.90',  desc:'An account can set lsfDepositAuth so it only receives payments explicitly pre-authorized via DepositPreauth.',                                 impact:'Senders to un-authorized accounts receive tecNO_PERMISSION.' },
  DeletableAccounts:    { purpose:'Permanent account deletion + reserve reclaim',      intro:'rippled 1.4',   desc:'An account with no objects and sequence ≥ (current ledger − 256) can permanently delete itself and recover the base reserve.',                 impact:'New transaction: AccountDelete. Sends all XRP minus fees to a destination.' },
  NegativeUNL:          { purpose:'Fault-tolerant consensus during outages',           intro:'rippled 1.6',   desc:'When validators are persistently offline, the network may add them to the Negative UNL so they do not count against quorum.',                   impact:'Enables the network to survive planned outages of up to 20% of trusted validators.' },
  Checks:               { purpose:'Deferred, cancellable payments',                    intro:'rippled 1.0',   desc:'The sender creates a Check; the recipient can later cash it up to the authorized amount or let it expire. The sender can cancel at any time.',  impact:'New transactions: CheckCreate, CheckCash, CheckCancel. Each open Check uses one owner-reserve slot.' },
  AMM:                  { purpose:'Native Automated Market Maker DEX',                 intro:'rippled 1.12',  desc:'Adds a Constant-Product (x*y=k) AMM directly in the ledger. Anyone can deposit two assets to earn LP tokens and a share of swap fees.',         impact:'New transactions: AMMCreate, AMMDeposit, AMMWithdraw, AMMVote, AMMBid, AMMDelete.' },
  XChainBridge:         { purpose:'Cross-chain bridge protocol',                       intro:'rippled 2.0',   desc:'Lets assets move between XRPL Mainnet, sidechains, and EVM chains via a locking/minting bridge secured by Witness servers.',                   impact:'New ledger objects: Bridge, XChainOwnedCreateAccountClaimID, etc. Requires Witness infrastructure.' },
  Clawback:             { purpose:'Token-issuer recovery',                             intro:'rippled 1.12',  desc:'Issuers who set lsfAllowTrustLineClawback before issuing tokens can claw back tokens from any holder.',                                         impact:'Must be enabled on a fresh account before any trust lines are created.' },
  NonFungibleTokensV1:  { purpose:'Native NFT support',                                intro:'rippled 1.9',   desc:'Adds NFTokenMint, NFTokenBurn, and offer-based transfer mechanics for non-fungible tokens stored in NFTokenPage objects.',                       impact:'Each NFTokenPage holds up to 32 tokens and costs one owner-reserve slot. Royalties up to 50%.' },
  'NonFungibleTokensV1_1': { purpose:'NFT V1 corrections',                             intro:'rippled 1.10',  desc:'Fixes pagination bugs, transfer-fee edge cases, and minting with the URI field that were present in V1.',                                        impact:'Breaking fix for some V1 edge cases. Wallets built for V1 should test V1_1 compatibility.' },
  PayChan:              { purpose:'Payment channels for streaming micropayments',       intro:'rippled 0.33',  desc:'Sender deposits XRP into a channel, then issues signed claims off-ledger. Recipient submits the highest claim at any time to settle on-ledger.',impact:'New transactions: PaymentChannelCreate, PaymentChannelFund, PaymentChannelClaim.' },
  Escrow:               { purpose:'Time-locked and condition-based XRP transfers',      intro:'rippled 0.60',  desc:'Lock XRP until a future time OR a cryptographic fulfillment (PREIMAGE-SHA-256) is revealed, enabling vesting schedules and atomic swaps.',      impact:'New transactions: EscrowCreate, EscrowFinish, EscrowCancel. Locked XRP counts against reserves.' },
  DisallowIncoming:     { purpose:'Block unsolicited ledger-object creation',           intro:'rippled 1.10',  desc:'New account flags let you individually block incoming Trust Lines, Check objects, NFToken offers, and Payment Channels.',                        impact:'Four new AccountSet flags; existing incoming objects are unaffected.' },
  ExpandedSignerList:   { purpose:'Larger multi-sig signer lists',                     intro:'rippled 1.9.1', desc:'Increases the maximum signers per SignerList from 8 to 32, enabling more complex institutional multi-sig and DAO governance.',                    impact:'Reserve cost scales with signer count. Requires MultiSignReserve to be cost-effective.' },
  OwnerPaysFee:         { purpose:'Correct fee payer in PayChan',                      intro:'rippled 0.33',  desc:'Fixes a spec inconsistency where the channel owner correctly pays the transaction fee when closing or expiring channels.',                        impact:'Purely a fee-accounting fix; no user-visible behavior changes.' },
  fixMasterKeyAsRegularKey: { purpose:'Master-key mis-use bug fix',                    intro:'rippled 0.90',  desc:'Prevents accounts from setting their master key as their regular key — an operation that could create an unusable account state.',                impact:'No application changes needed; existing accounts are not affected.' },
  TrustSetAuth:         { purpose:'Authorized trust lines',                            intro:'rippled 0.30',  desc:'Issuers can require explicit authorization before anyone can hold their token — a prerequisite for regulatory-grade stablecoins.',                impact:'New flow: issuer sends TrustSet with tfSetfAuth to approve each holder.' },
};

/* ─── Known UNL validator registry ─── */
const KNOWN_VALIDATORS = {
  'nHB8QMKGt9VB4Vg71VszjBVQnDW3v3QudM4436zXRZgiuUBBSWJe': { label:'Ripple 1',       p:'Ripple'     },
  'nHUon2tpyJEHHYGmxqNd3h3oGNQwNyX8PNS3aHe3bNpCrNXZlHo': { label:'Ripple 2',       p:'Ripple'     },
  'nHUpwrafS45zmi6eT72XS5ijpkW5JwfL5mLdPhEibrqUvtRcMAjU': { label:'Ripple 3',       p:'Ripple'     },
  'nHUkp7WhouVMobBUKGrV5FNqjsdD9zKP5jpGnnLfQXCMNe4dkDqo': { label:'Ripple 4',       p:'Ripple'     },
  'nHUryiyDqEtyWVtFG24AAhaYjMf9FRLietZGBWYwUTojmugMsx3o': { label:'Ripple 5',       p:'Ripple'     },
  'nHUpcmNsxAw47yt2ADDoNoQrzLyTJPgnyq16u6Qx2kRPA17oUNHz': { label:'Ripple 6',       p:'Ripple'     },
  'nHUnhRJK3csknycNK5SXRFi8jvDp3sKoWvS9wKWLq1ATBBGgPBjp': { label:'Ripple 7',       p:'Ripple'     },
  'nHUq9tJvk5QTDkwurB7EzbzkZ2uuoHjS3GKjP6pZiU3DJGnobNYK': { label:'Coil',           p:'AWS'        },
  'nHUvcCcmoH1FJMMC6NtF9KKA4LpCWhjsxk2reCQidsp5AHQ7QY9H': { label:'Gatehub',        p:'Hetzner'    },
  'nHDH7bQJpVfDhVSqdui3Z8GPvKEBQpo6AKHcnXe21zoD4nABA6xj': { label:'XRPL Labs',      p:'GCP'        },
  'nHUED59jjpQ5QbNtesAbB6Es3uUPv3c9Ri5MNNgfMv5t5Lhb5ndW': { label:'Bitso',          p:'AWS'        },
  'nHBidG3pZK11zqjeVos6hFxTDPGYuqfRFZ5gu9b7tQFdB8nPZujG': { label:'Digital Garage', p:'NTT'        },
  'nHDB2PAPYqF86j9j3c6w1F1ZqwvQfiWcFShZ9Pokg9q4ohNDSkAz': { label:'Arrington XRP',  p:'Azure'      },
  'nHUdphn3LXa31w5sLd39MQdPEKQNrNYL3DQFByijVXiNQ3G6BYBZ': { label:'Tokenize',       p:'AWS'        },
  'nHUFCyRCrUjvtZmKiLeF8ReopzKuSkVzdl1VsMCqm75aqyohLYEg': { label:'XRPL Commons',   p:'OVH'        },
  'nHULqGBkJtWeNFjhTzYeAsHA3qKKS7HoBh8CV3BAGTGMZuepEhWC': { label:'Blockchain LLC', p:'Equinix'    },
  'nHBdXSF6YHAHSZUk7rvox6jwbvvyqBnsWGcewBtq8x1XuH6KXKXr': { label:'XRP Scan',       p:'Cloudflare' },
};

/* ─── Validator geographic coordinates ─── */
const VALIDATOR_GEO = {
  'nHB8QMKGt9VB4Vg71VszjBVQnDW3v3QudM4436zXRZgiuUBBSWJe': { lat:37.77, lng:-122.42, city:'San Francisco', org:'Ripple'             },
  'nHUon2tpyJEHHYGmxqNd3h3oGNQwNyX8PNS3aHe3bNpCrNXZlHo': { lat:37.77, lng:-122.41, city:'San Francisco', org:'Ripple'             },
  'nHUpwrafS45zmi6eT72XS5ijpkW5JwfL5mLdPhEibrqUvtRcMAjU': { lat:37.78, lng:-122.40, city:'San Francisco', org:'Ripple'             },
  'nHUkp7WhouVMobBUKGrV5FNqjsdD9zKP5jpGnnLfQXCMNe4dkDqo': { lat:37.76, lng:-122.43, city:'San Francisco', org:'Ripple'             },
  'nHUryiyDqEtyWVtFG24AAhaYjMf9FRLietZGBWYwUTojmugMsx3o': { lat:37.79, lng:-122.38, city:'San Francisco', org:'Ripple'             },
  'nHUpcmNsxAw47yt2ADDoNoQrzLyTJPgnyq16u6Qx2kRPA17oUNHz': { lat:37.80, lng:-122.39, city:'San Francisco', org:'Ripple'             },
  'nHUnhRJK3csknycNK5SXRFi8jvDp3sKoWvS9wKWLq1ATBBGgPBjp': { lat:37.75, lng:-122.44, city:'San Francisco', org:'Ripple'             },
  'nHUq9tJvk5QTDkwurB7EzbzkZ2uuoHjS3GKjP6pZiU3DJGnobNYK': { lat:39.04, lng:-77.49,  city:'Ashburn, VA',   org:'AWS (Coil)'         },
  'nHUvcCcmoH1FJMMC6NtF9KKA4LpCWhjsxk2reCQidsp5AHQ7QY9H': { lat:49.45, lng:11.08,   city:'Nuremberg',     org:'Hetzner (Gatehub)'  },
  'nHDH7bQJpVfDhVSqdui3Z8GPvKEBQpo6AKHcnXe21zoD4nABA6xj': { lat:52.37, lng:4.90,    city:'Amsterdam',     org:'GCP (XRPL Labs)'    },
  'nHUED59jjpQ5QbNtesAbB6Es3uUPv3c9Ri5MNNgfMv5t5Lhb5ndW': { lat:19.43, lng:-99.13,  city:'Mexico City',   org:'AWS (Bitso)'        },
  'nHBidG3pZK11zqjeVos6hFxTDPGYuqfRFZ5gu9b7tQFdB8nPZujG': { lat:35.69, lng:139.69,  city:'Tokyo',         org:'NTT (Digital Garage)'},
  'nHDB2PAPYqF86j9j3c6w1F1ZqwvQfiWcFShZ9Pokg9q4ohNDSkAz': { lat:47.61, lng:-122.33, city:'Seattle, WA',   org:'Azure (Arrington)'  },
  'nHUdphn3LXa31w5sLd39MQdPEKQNrNYL3DQFByijVXiNQ3G6BYBZ': { lat:1.35,  lng:103.82,  city:'Singapore',     org:'AWS (Tokenize)'     },
  'nHUFCyRCrUjvtZmKiLeF8ReopzKuSkVzdl1VsMCqm75aqyohLYEg': { lat:48.86, lng:2.35,    city:'Paris',         org:'OVH (XRPL Commons)' },
  'nHULqGBkJtWeNFjhTzYeAsHA3qKKS7HoBh8CV3BAGTGMZuepEhWC': { lat:40.71, lng:-74.01,  city:'New York',      org:'Equinix (Blockchain LLC)'},
  'nHBdXSF6YHAHSZUk7rvox6jwbvvyqBnsWGcewBtq8x1XuH6KXKXr': { lat:37.79, lng:-122.40, city:'San Francisco', org:'Cloudflare (XRP Scan)'},
};

const PUBLIC_NODES = [
  { lat:37.34, lng:-121.89, label:'s1.ripple.com',   city:'San Jose, CA', org:'Ripple'  },
  { lat:37.34, lng:-121.87, label:'s2.ripple.com',   city:'San Jose, CA', org:'Ripple'  },
  { lat:52.37, lng:4.91,   label:'xrplcluster.com', city:'Amsterdam',    org:'Cluster' },
  { lat:52.36, lng:4.89,   label:'xrpl.ws',          city:'Amsterdam',    org:'Cluster' },
];

const MAP_W = 800, MAP_H = 380;
const CONTINENTS = [
  [[-168,72],[-135,60],[-130,50],[-124,38],[-117,32],[-88,16],[-77,8],[-60,14],[-55,48],[-66,44],[-68,47],[-60,47],[-60,60],[-72,73],[-100,76],[-130,72],[-168,72]],
  [[-80,12],[-65,10],[-52,4],[-38,-4],[-36,-8],[-48,-28],[-52,-36],[-58,-44],[-66,-52],[-74,-48],[-76,-32],[-78,-8],[-80,2],[-80,12]],
  [[-10,70],[20,76],[30,70],[38,66],[28,62],[25,55],[22,44],[30,40],[28,36],[15,36],[5,40],[-6,44],[-10,44],[-10,52],[-10,70]],
  [[-18,16],[-14,10],[-16,4],[-10,4],[10,4],[30,2],[42,12],[52,12],[44,-8],[40,-12],[36,-18],[30,-30],[20,-36],[16,-34],[0,-22],[-18,14],[-18,16]],
  [[26,72],[50,76],[80,74],[110,74],[140,72],[150,62],[143,50],[135,34],[130,28],[122,22],[112,4],[104,0],[98,6],[80,10],[68,22],[62,26],[60,34],[46,38],[36,46],[28,56],[26,62],[26,72]],
  [[114,-22],[122,-18],[128,-14],[134,-12],[142,-10],[154,-24],[152,-26],[154,-32],[152,-40],[148,-44],[144,-40],[136,-36],[130,-34],[116,-34],[114,-22]],
  [[-48,84],[-16,78],[-18,70],[-24,65],[-44,60],[-58,64],[-70,72],[-48,84]],
  [[-5,50],[2,51],[2,55],[-2,58],[-6,58],[-5,52],[-5,50]],
  [[130,32],[132,34],[134,36],[138,38],[140,42],[140,44],[138,42],[136,34],[132,34],[130,32]],
  [[100,6],[108,2],[116,0],[120,-4],[118,-8],[108,-8],[104,-2],[100,6]],
  [[172,-34],[174,-36],[176,-37],[178,-38],[174,-44],[170,-44],[172,-34]],
  [[-24,64],[-14,66],[-12,66],[-14,64],[-20,63],[-24,64]],
  [[44,-12],[50,-14],[50,-26],[44,-25],[44,-12]],
];

/* ─── Module state ─── */
let _poll=null, _inited=false, _busy=false, _lastAt=0, _backoff=0, _latAt=0, _latRun=0;
let _info=null, _fee=null, _vals=null, _peers=null, _sigs={};
let _prevDiscon=null, _amendmentData={};
let _leafletMap=null, _mapMarkers=[], _mapNetId=null, _keyToMarker={};

let _bl = {
  fees:[], burnDrops:[], dexOffers:[], ammSwaps:[],
  newAccounts:[], converge:[], proposers:[], peerCounts:[], peerDiscon:[],
};

/* ═══════════════════════════════════════════════════
   INIT
═══════════════════════════════════════════════════ */
export function initNetwork() {
  if (_inited) return;
  _inited = true;
  _loadBL();

  window.addEventListener('xrpl-connected',    () => { _syncPoll(); if (_vis()) { _refresh({force:true}); measureLatency({force:false}); } });
  window.addEventListener('xrpl-disconnected', () => { _stopPoll(); _banner(null); });
  window.addEventListener('xrpl-ledger',       e  => { _accumulate(e.detail); if (_vis()) _liveCells(e.detail); });

  $('btn-network-refresh')?.addEventListener('click', () => { _refresh({force:true}); measureLatency({force:true}); });
  document.querySelector('.dash-tab[data-tab="network"]')?.addEventListener('click', () => {
    _syncPoll(); _refresh({force:true}); measureLatency({force:false});
  });

  const t = $('tab-network');
  if (t) new MutationObserver(_syncPoll).observe(t, { attributes:true, attributeFilter:['style','class'] });
}

function _vis()      { const t=$('tab-network'); return t ? t.style.display!=='none' : false; }
function _syncPoll() { if (_vis()) _startPoll(); else _stopPoll(); }
function _startPoll() {
  if (_poll) return;
  _refresh({force:false});
  _poll = setInterval(() => { if (_vis()) _refresh({force:false}); }, POLL_MS);
}
function _stopPoll() { clearInterval(_poll); _poll = null; }

/* ═══════════════════════════════════════════════════
   REFRESH ORCHESTRATOR
═══════════════════════════════════════════════════ */
async function _refresh({force=false}={}) {
  if (!_vis() && !force) return;
  const now = Date.now();
  if (!force && (now-_lastAt<MIN_GAP_MS || _busy || now<_backoff)) return;
  _busy=true; _lastAt=now; _sigs={}; _spin(true);
  try {
    await Promise.allSettled([_doInfo(), _doFee(), _doVals(), _doPeers(), _doAmend()]);
    _m1(); _m2(); _m3(); _alert(); _banner({info:_info, fee:_fee, vals:_vals});
    _saveBL();
  } catch(e) {
    const msg = String(e?.message ?? '');
    if (msg.toLowerCase().includes('too much load')) {
      _backoff = Date.now()+BACKOFF_MS;
      toastWarn?.('Rate-limited — backing off 2 min.');
    }
  } finally { _spin(false); _busy=false; }
}
function _spin(on) { $('btn-network-refresh')?.classList.toggle('spinning', on); }

/* ═══════════════════════════════════════════════════
   FETCH — verified rippled field paths
═══════════════════════════════════════════════════ */
async function _doInfo() {
  const r = await wsSend({command:'server_info'});
  _info = r?.result?.info ?? null;
  if (!_info) return;
  _bpush('converge',   Number(_info.last_close?.converge_time_s ?? 0));
  _bpush('proposers',  Number(_info.last_close?.proposers ?? 0));
  _bpush('peerCounts', Number(_info.peers ?? 0));
  const d = Number(_info.peer_disconnects_resources ?? 0);
  if (_prevDiscon !== null && d > _prevDiscon) _bpush('peerDiscon', d - _prevDiscon);
  _prevDiscon = d;
}

async function _doFee() {
  const r = await wsSend({command:'fee'});
  _fee = r?.result ?? null;
  if (_fee?.drops?.open_ledger_fee != null)
    _bpush('fees', Number(_fee.drops.open_ledger_fee));
}

async function _doVals() {
  try { const r=await wsSend({command:'validators'}); _vals=r?.result??null; }
  catch { _vals=null; }
}

async function _doPeers() {
  try { const r=await wsSend({command:'peers'}); _peers=Array.isArray(r?.result?.peers)?r.result.peers:null; }
  catch { _peers=null; }
}

async function _doAmend() {
  try {
    const r = await wsSend({command:'feature'});
    if (r?.result?.features) {
      _cacheAmendmentData(r.result.features);
      _renderAmend(r.result.features);
    }
  } catch {}
}

/* ═══════════════════════════════════════════════════
   MODULE 1 — CONSENSUS & GOVERNANCE
═══════════════════════════════════════════════════ */
function _m1() {
  const info=_info, vals=_vals;

  const keys    = vals?.trusted_validator_keys ?? [];
  const quorum  = Number(vals?.validation_quorum ?? info?.validation_quorum ?? 0);
  const active  = keys.length;
  const margin  = active - quorum;
  const qPct    = active > 0 ? (quorum/active)*100 : 0;
  const known   = keys.filter(k=>KNOWN_VALIDATORS[k]).length;
  const overlap = active > 0 ? Math.round((known/active)*100) : 0;

  const cvg     = Number(info?.last_close?.converge_time_s ?? 0);
  const prop    = Number(info?.last_close?.proposers ?? 0);
  const prtcpPct= quorum > 0 ? Math.round((prop/quorum)*100) : 0;

  const nUnl    = Array.isArray(info?.negative_unl) ? info.negative_unl : [];

  const valsAvail = !!_vals;   // false when validators command is unsupported by endpoint

  if (margin>=0 && margin<=3)            _sigs.quorumTight  = true;
  if (nUnl.length>0)                     _sigs.nUnlActive   = true;
  if (cvg>6)                             _sigs.slowConverge = true;
  if (prop>0 && quorum>0 && prop<quorum) _sigs.lowProposers = true;

  // Use '—' only when data is genuinely absent, never for 0
  _t('m1-active',      valsAvail ? active : '—');
  _t('m1-quorum',      quorum > 0 ? quorum : '—');
  _t('m1-margin',      valsAvail ? (margin >= 0 ? margin : `−${Math.abs(margin)}`) : '—');
  _t('m1-overlap',     valsAvail ? `${overlap}%` : '—');
  _t('m1-known',       valsAvail ? `${known} / ${active} identified` : '— (validators cmd unavailable)');
  _t('m1-proposers',   info?.last_close?.proposers != null ? prop : '—');
  _t('m1-particip',    quorum>0 && info?.last_close?.proposers != null ? `${prtcpPct}%` : '—');
  _t('m1-converge',    info?.last_close?.converge_time_s != null ? `${cvg.toFixed(2)}s` : '—');
  _t('m1-converge-avg',_bavg('converge')>0 ? `avg ${_bavg('converge').toFixed(2)}s` : '—');

  _bar('m1-qbar',    qPct,      qPct>90?'bar-danger':qPct>80?'bar-warn':'bar-ok');
  _bar('m1-obar',    overlap,   overlap<40?'bar-danger':overlap<70?'bar-warn':'bar-ok');
  _bar('m1-pbar',    prtcpPct,  prtcpPct<80?'bar-danger':prtcpPct<95?'bar-warn':'bar-ok');
  _bar('m1-cvgbar',  Math.min(100,(cvg/10)*100), cvg>6?'bar-danger':cvg>4?'bar-warn':'bar-ok');

  const pub = vals?.publisher_lists?.[0];
  if (pub) {
    _t('m1-vl-uri', pub.uri ?? '—');
    _t('m1-vl-seq', pub.seq ?? '—');
    const expEl = $('m1-vl-expiry');
    if (expEl && pub.expiration) {
      const days = Math.floor((new Date(pub.expiration)-Date.now())/86400000);
      expEl.textContent = days>0 ? `Expires ${days}d` : '⚠ EXPIRED';
      expEl.className   = `expiry-pill ${days>30?'pill-ok':days>7?'pill-warn':'pill-bad'}`;
      expEl.style.display = '';
    }
  }

  const nUnlEl = $('m1-nunl-list');
  _t('m1-nunl-count', nUnl.length || '0');
  if (nUnlEl) {
    if (!nUnl.length) {
      nUnlEl.innerHTML = '<div class="nunl-empty">✓ No validators on Negative UNL</div>';
    } else {
      const provTally = {};
      nUnlEl.innerHTML = nUnl.map(key => {
        const kv = KNOWN_VALIDATORS[key];
        if (kv?.p) provTally[kv.p] = (provTally[kv.p]||0)+1;
        return `<div class="nunl-entry">
          <span class="nunl-dot"></span>
          <div class="nunl-info">
            <span class="nunl-label">${escHtml(kv?.label ?? key.slice(0,12)+'...')}</span>
            ${kv?.p ? `<span class="nunl-prov">${escHtml(kv.p)}</span>` : ''}
          </div>
          <span class="nunl-key" onclick="navigator.clipboard?.writeText('${escHtml(key)}')">${key.slice(0,8)}...</span>
        </div>`;
      }).join('');
      const top = Object.entries(provTally).sort((a,b)=>b[1]-a[1])[0];
      if (top?.[1] > 1)
        nUnlEl.innerHTML += `<div class="nunl-alert">⚠ ${top[1]} offline validators share <b>${escHtml(top[0])}</b> — likely provider outage</div>`;
    }
  }

  _valGrid(keys, quorum, nUnl);

  // Use live keys if available, else fall back to full known-operator list for the map
  const mapKeys   = valsAvail ? keys : Object.keys(KNOWN_VALIDATORS);
  const infoPeers = Number(_info?.peers ?? 0);
  _t('wm-stat-val',   valsAvail ? `${active} validators` : `${mapKeys.length} known`);
  _t('wm-stat-nunl',  `${nUnl.length} on nUNL`);
  _t('wm-stat-peers', `${_peers ? _peers.length : infoPeers} peers`);
  _renderWorldMap(mapKeys, nUnl, _peers, !valsAvail);
}

function _valGrid(keys, quorum, nUnl) {
  const grid = $('m1-val-grid');
  if (!grid) return;

  const liveAvail = keys.length > 0;
  const displayKeys = liveAvail ? keys : Object.keys(KNOWN_VALIDATORS);
  const nSet = new Set(nUnl);

  if (!liveAvail) {
    grid.innerHTML = `<div class="vg-notice">⚠ Live validator list unavailable — showing known UNL operators · click any to locate on map</div>`;
  } else {
    grid.innerHTML = '';
  }

  grid.innerHTML += displayKeys.map(key => {
    const kv   = KNOWN_VALIDATORS[key];
    const onN  = nSet.has(key);
    const label = kv?.label ?? `${key.slice(0,8)}...${key.slice(-4)}`;
    const hasGeo = !!VALIDATOR_GEO[key];
    const refMode = !liveAvail;
    return `<div class="vpill ${onN?'vp-nunl':kv?'vp-known':''} ${refMode?'vp-ref':''} ${hasGeo?'vp-locatable':''}"
                 title="${escHtml(key)}"
                 onclick="window.focusValidator('${escHtml(key)}')"
                 data-key="${escHtml(key)}">
      <span class="vpdot"></span>
      <div class="vptext">
        <span class="vplabel">${escHtml(label)}</span>
        ${kv?.p ? `<span class="vpprov">${escHtml(kv.p)}</span>` : ''}
      </div>
      <div class="vpactions">
        ${hasGeo ? '<span class="vp-locate-icon" title="Show on map">📍</span>' : ''}
        ${refMode ? '<span class="vntag vntag-ref">ref</span>' : ''}
        ${onN ? '<span class="vntag">nUNL</span>' : ''}
      </div>
    </div>`;
  }).join('');

  const identifiedCount = displayKeys.filter(k=>KNOWN_VALIDATORS[k]).length;
  if (liveAvail) {
    _t('m1-val-summary', `${keys.length} trusted · quorum ${quorum} · ${nUnl.length} on nUNL · ${identifiedCount} identified`);
  } else {
    _t('m1-val-summary', `${displayKeys.length} known operators · click to locate on map`);
  }
}

/* ── focusValidator: fly map to a validator and open its popup ── */
window.focusValidator = function(key) {
  const geo = VALIDATOR_GEO[key];
  const kv  = KNOWN_VALIDATORS[key];

  // Highlight the pill
  document.querySelectorAll('.vpill').forEach(el => el.classList.remove('vp-active'));
  const pill = document.querySelector(`.vpill[data-key="${CSS.escape(key)}"]`);
  if (pill) {
    pill.classList.add('vp-active');
    pill.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  // If no geo, just show a toast-style notice in the map area
  if (!geo) {
    const container = $('world-map-container');
    if (container) {
      const old = container.querySelector('.wm-no-geo');
      if (old) old.remove();
      const notice = document.createElement('div');
      notice.className = 'wm-no-geo';
      notice.textContent = `📍 ${kv?.label || key.slice(0,16)+'...'} — geographic location unknown`;
      container.appendChild(notice);
      setTimeout(() => notice.remove(), 3500);
    }
    return;
  }

  // Scroll map into view
  const mapSection = $('world-map-container');
  if (mapSection) mapSection.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

  // Fly to location and open popup
  if (_leafletMap) {
    _leafletMap.flyTo([geo.lat, geo.lng], 6, { duration: 1.2 });
    // After fly, open the marker popup
    setTimeout(() => {
      const m = _keyToMarker[key];
      if (m) { m.openPopup(); }
    }, 1300);
  }
};

/* ═══════════════════════════════════════════════════
   MODULE 2 — INFRASTRUCTURE & CYBER-DEFENSE
═══════════════════════════════════════════════════ */
function _m2() {
  const info=_info;

  const nodeState  = info?.server_state     ?? 'unknown';
  const version    = info?.build_version    ?? '—';
  const uptime     = Number(info?.uptime    ?? 0);
  const netId      = info?.network_id;
  const ioMs       = Number(info?.io_latency_ms ?? 0);
  const jqOverflow = String(info?.jq_trans_overflow ?? '0');
  const peerDiscon = Number(info?.peer_disconnects_resources ?? 0);
  const loadFactor = Number(info?.load_factor        ?? 1);
  const loadNet    = Number(info?.load_factor_net    ?? 1);
  const loadLocal  = Number(info?.load_factor_server ?? info?.load_factor_local ?? 1);
  const ledgerAge  = Number(info?.validated_ledger?.age ?? 0);
  const ledgerSeq  = info?.validated_ledger?.seq;
  const complete   = info?.complete_ledgers ?? '';
  const stateAcct  = info?.state_accounting ?? null;

  if (ledgerAge>10)          _sigs.staleLedger = true;
  if (ioMs>5)                _sigs.ioStressed  = true;
  if (_bavg('peerDiscon')>5) _sigs.peerChurn   = true;

  const stEl = $('m2-state');
  if (stEl) {
    stEl.textContent = nodeState;
    const ok   = ['full','proposing','validating'].includes(nodeState);
    const warn = ['syncing','tracking','connected'].includes(nodeState);
    stEl.className = `state-pill state-${ok?'ok':warn?'warn':'bad'}`;
  }

  _t('m2-version',    version);
  _t('m2-uptime',     _fmtUp(uptime));
  _t('m2-netid',      netId===0?'0 (Mainnet)':netId===1?'1 (Testnet)':netId??'—');
  _t('m2-ledger-seq', ledgerSeq!=null ? Number(ledgerSeq).toLocaleString() : '—');
  _t('m2-ledger-age', ledgerAge>0?`${ledgerAge}s`:'< 1s');
  _t('m2-io-ms',      ioMs>0?`${ioMs}ms`:'< 1ms');
  _t('m2-jq',         jqOverflow==='0' ? '0 (clean)' : `⚠ ${jqOverflow}`);
  _t('m2-discon',     peerDiscon.toLocaleString());

  const ageEl = $('m2-ledger-age');
  if (ageEl) ageEl.className = `kv-v ${ledgerAge>10?'text-danger':ledgerAge>5?'text-warn':''}`;

  const lpct = Math.min(100, ((loadFactor-1)/49)*100);
  _bar('m2-load-bar', lpct, loadFactor>5?'bar-danger':loadFactor>2?'bar-warn':'bar-ok');
  _t('m2-load-total', `${loadFactor.toFixed(2)}×`);
  _t('m2-load-net',   `${loadNet.toFixed(2)}×`);
  _t('m2-load-local', `${loadLocal.toFixed(2)}×`);
  const src = loadLocal>loadNet*1.5?'Local node stressed':loadNet>loadLocal*1.5?'Network-wide stress':loadFactor>1.2?'Distributed':'Normal';
  _t('m2-load-src', src);

  const tps = state.tpsHistory.length ? state.tpsHistory[state.tpsHistory.length-1] : null;
  _t('m2-tps',    tps!=null ? tps.toFixed(1) : '—');
  _t('m2-txcount', state.ledgerLog[0]?.txCount ?? '—');

  const isFull = complete==='entire ledger' || complete.startsWith('32570');
  const hScore = isFull ? 100 : _histScore(complete);
  _t('m2-ledger-range', complete||'—');
  _t('m2-hist-type',    isFull?'Full History Node':'Pruned / Partial');
  _t('m2-hist-score',   `${hScore}%`);
  _bar('m2-hist-bar', hScore, hScore<30?'bar-danger':hScore<70?'bar-warn':'bar-ok');

  if (stateAcct) {
    const saEl = $('m2-state-acct');
    if (saEl) {
      const states=['full','syncing','tracking','connected','disconnected'];
      let total=0;
      const dur={};
      states.forEach(s => { dur[s]=Number(stateAcct[s]?.duration_us??0); total+=dur[s]; });
      saEl.innerHTML = total>0 ? states.map(s => {
        const pct=Math.round((dur[s]/total)*100); if (!pct) return '';
        const bc=s==='full'?'bar-ok':s==='syncing'?'bar-warn':'bar-danger';
        return `<div class="sa-row"><span class="sa-lbl">${s}</span>
          <div class="bar-track sa-bar"><div class="bar-fill ${bc}" style="width:${pct}%"></div></div>
          <span class="sa-pct">${pct}%</span></div>`;
      }).join('') : '<span class="dim">No data</span>';
    }
  }

  // peerCount from server_info (always available); _peers from peers command (may be restricted)
  const peerCount = info?.peers != null ? Number(info.peers) : null;
  const peerKnown = peerCount != null;  // do we have ANY peer count at all?
  let ib=0, ob=0, peersDetailed=false;
  if (_peers) {
    _peers.forEach(p => { if (p.inbound===true) ib++; else ob++; });
    peersDetailed = true;
  }
  // Infer inbound/outbound from detailed list if available, else show total only
  const ibPct = peersDetailed && (ib+ob)>0 ? Math.round((ib/(ib+ob))*100) : 0;
  const effectivePeers = peersDetailed ? _peers.length : (peerCount ?? 0);
  const eclRisk = effectivePeers<6?'HIGH':effectivePeers<15?'MEDIUM':'LOW';

  if (effectivePeers<6)  _sigs.eclipseRisk  = true;
  if (ibPct>80)          _sigs.peerSaturate = true;

  _t('m2-peers',    peerKnown ? effectivePeers : '—');
  _t('m2-inbound',  peersDetailed ? ib : peerKnown ? '— (cmd restricted)' : '—');
  _t('m2-outbound', peersDetailed ? ob : peerKnown ? '— (cmd restricted)' : '—');
  _t('m2-ib-pct',   peersDetailed ? `${ibPct}%` : '—');
  _bar('m2-peer-bar', Math.min(100,(effectivePeers/21)*100),
    effectivePeers>18?'bar-danger':effectivePeers>15?'bar-warn':'bar-ok');
  _bar('m2-ib-bar', ibPct, ibPct>80?'bar-danger':ibPct>60?'bar-warn':'bar-ok');

  const eclEl=$('m2-eclipse');
  if (eclEl) { eclEl.textContent=eclRisk; eclEl.className=`risk-badge risk-${eclRisk.toLowerCase()}`; }
}

/* ═══════════════════════════════════════════════════
   MODULE 3 — CRYPTOGRAPHIC & ECONOMIC SECURITY
═══════════════════════════════════════════════════ */
function _m3() {
  const fee=_fee;

  const baseFee = Number(fee?.drops?.base_fee         ?? 10);
  const minFee  = Number(fee?.drops?.minimum_fee      ?? 10);
  const openFee = Number(fee?.drops?.open_ledger_fee  ?? 10);
  const medFee  = Number(fee?.drops?.median_fee       ?? 10);
  const openLvl = Number(fee?.levels?.open_ledger_level ?? 256);
  const refLvl  = Number(fee?.levels?.reference_level   ?? 256);
  const escRatio= refLvl>0 ? (openLvl/refLvl) : 1;

  const curSz   = Number(fee?.current_ledger_size  ?? 0);
  const expSz   = Number(fee?.expected_ledger_size  ?? 1);
  const curQ    = Number(fee?.current_queue_size    ?? 0);
  const maxQ    = Number(fee?.max_queue_size         ?? 1);
  const qPct    = maxQ>0 ? Math.round((curQ/maxQ)*100) : 0;
  const szRatio = expSz>0 ? curSz/expSz : 1;

  const avgFee  = _bavg('fees');
  const devPct  = avgFee>0 ? Math.round(((openFee-avgFee)/avgFee)*100) : 0;
  const spamIdx = Math.min(100, Math.round(Math.log2(Math.max(1,openFee/10))*14));

  if (openFee > minFee*10) _sigs.feeSpike      = true;
  if (qPct > 80)           _sigs.queuePressure = true;
  if (szRatio > 2)         _sigs.spamLedger    = true;

  const pressure = openFee>5000?'Severe':openFee>500?'High':openFee>100?'Elevated':openFee>20?'Normal':'Minimal';
  const prEl=$('m3-pressure');
  if (prEl) { prEl.textContent=pressure; prEl.className=`pressure-badge p-${pressure.toLowerCase()}`; }

  _t('m3-base',    `${baseFee} drops`);
  _t('m3-min',     `${minFee} drops`);
  _t('m3-open',    `${openFee} drops`);
  _t('m3-med',     `${medFee} drops`);
  _t('m3-escrat',  `${escRatio.toFixed(1)}x`);
  _t('m3-devpct',  `${devPct>0?'+':''}${devPct}%`);
  _t('m3-spam',    `${spamIdx}/100`);
  _t('m3-qsize',   `${curQ} / ${maxQ}`);
  _t('m3-qpct',    `${qPct}%`);
  _t('m3-szratio', `${szRatio.toFixed(2)}x`);
  _t('m3-curledger',`${curSz} txs`);
  _t('m3-expledger',`${expSz} expected`);

  _bar('m3-spam-bar', spamIdx,  spamIdx>70?'bar-danger':spamIdx>40?'bar-warn':'bar-ok');
  _bar('m3-q-bar',    qPct,     qPct>80?'bar-danger':qPct>50?'bar-warn':'bar-ok');
  _bar('m3-sz-bar',   Math.min(100,szRatio*50), szRatio>2?'bar-danger':szRatio>1.5?'bar-warn':'bar-ok');

  _frow('frow-base', baseFee, openFee);
  _frow('frow-min',  minFee,  openFee);
  _frow('frow-open', openFee, openFee);
  _frow('frow-med',  medFee,  openFee);

  const rb   = _bl.burnDrops.slice(-10);
  const avgB = rb.length ? rb.reduce((a,b)=>a+b,0)/rb.length : 0;
  const sdB  = _stddev(_bl.burnDrops);
  const meanB= _bavg('burnDrops');
  const zB   = sdB>0&&_bl.burnDrops.length>5 ? ((avgB-meanB)/sdB).toFixed(2) : '0.00';
  const anomB= Math.min(100, Math.abs(Number(zB))*20);
  if (Math.abs(Number(zB))>3) _sigs.burnAnomaly=true;
  _t('m3-burn',    avgB>0 ? `${(avgB/1e6).toFixed(4)} XRP/ledger` : '—');
  _t('m3-burnz',   `z = ${zB}`);
  _t('m3-burnanom',`${anomB.toFixed(0)}%`);
  _bar('m3-burn-bar', anomB, anomB>60?'bar-danger':anomB>30?'bar-warn':'bar-ok');

  const dex10=_bsum('dexOffers',10), amm10=_bsum('ammSwaps',10);
  const tot  =dex10+amm10;
  const dPct =tot>0 ? Math.round((dex10/tot)*100) : 50;
  const bRat =_bavg('ammSwaps')>0 ? _bavg('dexOffers')/_bavg('ammSwaps') : null;
  const cRat =amm10>0 ? dex10/amm10 : null;
  const spk  =bRat!=null&&cRat!=null&&cRat>bRat*3;
  if (spk) _sigs.dexSpike=true;
  _t('m3-dex',     dex10.toLocaleString());
  _t('m3-amm',     amm10.toLocaleString());
  _t('m3-dexratio',amm10>0 ? `${(dex10/amm10).toFixed(1)}:1 CLOB/AMM` : 'CLOB only');
  _t('m3-dexspike',spk ? '⚠ Spike Detected' : 'Normal');
  _bar('m3-dex-bar', dPct,     'bar-info');
  _bar('m3-amm-bar', 100-dPct, 'bar-purple');

  const vl    = _info?.validated_ledger ?? {};
  const baseR = vl.reserve_base_xrp ?? (vl.reserve_base ? vl.reserve_base/1e6 : 10);
  const ownerR= vl.reserve_inc_xrp  ?? (vl.reserve_inc  ? vl.reserve_inc/1e6  :  2);
  const bR=Number(baseR), oR=Number(ownerR);

  _t('m3-base-res',  `${bR.toFixed(0)} XRP`);
  _t('m3-owner-res', `${oR.toFixed(0)} XRP`);
  _t('m3-formula',   `${bR} + ${oR} x objects`);
  _t('m3-ex1',       `${(bR+oR*1).toFixed(0)} XRP`);
  _t('m3-ex5',       `${(bR+oR*5).toFixed(0)} XRP`);
  _t('m3-ex10',      `${(bR+oR*10).toFixed(0)} XRP`);
  _t('m3-ex25',      `${(bR+oR*25).toFixed(0)} XRP`);

  const totAcc =_bl.newAccounts.reduce((a,b)=>a+b,0);
  const bAcc   =_bavg('newAccounts');
  const rAcc   =_bl.newAccounts.slice(-1)[0]??0;
  const spkAcc =rAcc>bAcc*3;
  if (spkAcc) _sigs.reserveSpike=true;
  _t('m3-new-acc', totAcc.toLocaleString());
  _t('m3-acc-rate',spkAcc ? 'Elevated — Bot Risk?' : 'Normal');
  _t('m3-locked',  totAcc>0 ? `~${(totAcc*bR).toLocaleString()} XRP` : '—');
}

function _frow(id, drops, ref) {
  const row=$(id); if (!row) return;
  const n=Number(drops);
  const v=row.querySelector('.fr-v'), b=row.querySelector('.fr-fill');
  if (v) v.textContent=n>=1_000_000 ? `${(n/1e6).toFixed(4)} XRP` : `${n} drops`;
  if (b) b.style.width=`${Math.min(100,(n/Math.max(ref,2000))*100)}%`;
}

/* ═══════════════════════════════════════════════════
   AMENDMENT PIPELINE
═══════════════════════════════════════════════════ */
function _renderAmend(features) {
  const el=$('amendment-list'); if (!el) return;
  const list=Object.entries(features)
    .map(([hash,f])=>({hash,...f}))
    .sort((a,b)=>{ if(a.enabled!==b.enabled) return a.enabled?1:-1; return (b.count??0)-(a.count??0); })
    .slice(0,25);
  if (!list.length) { el.innerHTML='<div class="amend-empty">No data</div>'; return; }

  const pending=list.filter(f=>!f.enabled&&!f.vetoed);
  if (pending.some(f=>(f.count??0)<(f.threshold??28)*0.5)) _sigs.amendVeto=true;

  el.innerHTML=list.map(f=>{
    const c=f.count??0, th=f.threshold??28;
    const pct=Math.min(100,Math.round((c/th)*100));
    const name=f.name ?? `${f.hash.slice(0,10)}...`;
    const en=!!f.enabled, vt=!!f.vetoed, maj=!!f.majority;
    const bc=en?'bar-ok':vt?'bar-danger':maj?'bar-warn':'bar-info';
    return `<div class="arow amend-clickable ${en?'ar-en':''} ${vt?'ar-vt':''}"
                 onclick="window.showAmendDetail('${escHtml(f.hash)}')">
      <div class="ar-top">
        <span class="ar-name" title="${escHtml(f.hash)}">${escHtml(name)}</span>
        <div class="ar-tags">
          ${en  ? '<span class="atag atag-en">Active</span>'      : ''}
          ${vt  ? '<span class="atag atag-vt">Vetoed</span>'      : ''}
          ${maj&&!en ? '<span class="atag atag-near">Threshold</span>' : ''}
          ${!en&&!vt&&pct>=80&&!maj ? '<span class="atag atag-near">Near</span>' : ''}
        </div>
        ${!en ? `<span class="ar-votes">${c}/${th}</span>` : ''}
      </div>
      ${!en ? `<div class="ar-btrack"><div class="ar-bfill ${bc}" style="width:${pct}%"></div></div>` : ''}
    </div>`;
  }).join('');
}

/* ─── Amendment data cache ─── */
function _cacheAmendmentData(features) {
  _amendmentData = {};
  Object.entries(features).forEach(([hash, f]) => { _amendmentData[hash]={hash,...f}; });
}

/* ─── Amendment detail modal ─── */
window.showAmendDetail = function(hash) {
  const f = _amendmentData[hash]; if (!f) return;
  const name      = f.name || `${hash.slice(0,16)}...`;
  const docs      = AMENDMENT_DOCS[name] || {};
  const count     = f.count    ?? 0;
  const thresh    = f.threshold ?? 28;
  const pct       = Math.min(100, Math.round((count/thresh)*100));
  const statusTxt = f.enabled  ? 'Active on Ledger'
    : f.vetoed   ? 'Vetoed'
    : f.majority ? 'Majority Reached'
    : 'Voting in Progress';
  const statusCls = f.enabled  ? 'adm-s-ok'
    : f.vetoed   ? 'adm-s-bad'
    : f.majority ? 'adm-s-warn'
    : 'adm-s-info';
  const barCls    = f.enabled  ? 'bar-ok'
    : f.vetoed   ? 'bar-danger'
    : f.majority ? 'bar-warn'
    : 'bar-info';

  const majNote = (f.majority && !f.enabled) ? `
    <div class="adm-note adm-note-warn">
      Majority reached. If maintained for 2 weeks this amendment will auto-activate.
      Majority since: ${escHtml(String(f.majority))}
    </div>` : '';

  const overlay=$('amend-modal-overlay'), body=$('amend-modal-body');
  if (!overlay||!body) return;

  body.innerHTML=`
    <div class="adm-header">
      <div class="adm-title-row">
        <h2 class="adm-title">${escHtml(name)}</h2>
        <span class="adm-status ${statusCls}">${escHtml(statusTxt)}</span>
      </div>
      <div class="adm-hash mono">${escHtml(hash)}</div>
    </div>
    ${docs.purpose ? `<div class="adm-purpose-row"><span class="adm-purpose-tag">Purpose</span>${escHtml(docs.purpose)}</div>` : ''}
    ${docs.desc    ? `<div class="adm-section"><div class="adm-slbl">What it does</div><div class="adm-sdesc">${escHtml(docs.desc)}</div></div>` : ''}
    ${docs.impact  ? `<div class="adm-section"><div class="adm-slbl">Technical Impact</div><div class="adm-sdesc">${escHtml(docs.impact)}</div></div>` : ''}
    <div class="adm-section">
      <div class="adm-slbl">Validator Votes</div>
      ${!f.enabled ? `
        <div class="adm-vote-wrap">
          <div class="adm-vote-track">
            <div class="bar-fill ${barCls} adm-vote-fill" style="width:${pct}%"></div>
            <div class="adm-vote-line" style="left:80%" title="80% threshold"></div>
          </div>
          <div class="adm-vote-lbl">
            <span class="adm-vote-n">${count} / ${thresh} validators</span>
            <span>${pct}% — need 80%</span>
          </div>
        </div>
        ${majNote}` : '<div class="adm-ratified">Fully ratified — running on all ledgers</div>'}
    </div>
    <div class="adm-meta">
      <div class="adm-mi"><span class="adm-mk">Node supports</span><span class="adm-mv ${f.supported?'adm-ok':'adm-bad'}">${f.supported?'Yes':'No — upgrade required'}</span></div>
      <div class="adm-mi"><span class="adm-mk">Vetoed by node</span><span class="adm-mv ${f.vetoed?'adm-bad':''}">${f.vetoed?'Yes':'No'}</span></div>
      ${docs.intro ? `<div class="adm-mi"><span class="adm-mk">First available</span><span class="adm-mv">${escHtml(docs.intro)}</span></div>` : ''}
    </div>
    <div class="adm-footer">
      <a class="adm-link" href="https://xrpl.org/known-amendments.html" target="_blank" rel="noopener noreferrer">Amendment Reference</a>
      <a class="adm-link" href="https://xrpl.org/consensus.html" target="_blank" rel="noopener noreferrer">Consensus Docs</a>
    </div>`;

  overlay.style.display='flex';
  overlay.addEventListener('click', e => { if (e.target===overlay) window.closeAmendModal(); }, {once:true});
};

window.closeAmendModal = function() {
  const o=$('amend-modal-overlay'); if (o) o.style.display='none';
};

/* ═══════════════════════════════════════════════════
   WORLD MAP — Leaflet.js interactive
═══════════════════════════════════════════════════ */

/* Dynamically load Leaflet CSS+JS if not already present */
function _ensureLeaflet(cb) {
  if (window.L) { cb(); return; }
  // CSS
  if (!document.querySelector('#leaflet-css')) {
    const lnk = document.createElement('link');
    lnk.id   = 'leaflet-css';
    lnk.rel  = 'stylesheet';
    lnk.href = 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.css';
    document.head.appendChild(lnk);
  }
  // JS
  const scr = document.createElement('script');
  scr.src = 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.js';
  scr.onload = cb;
  document.head.appendChild(scr);
}

function _renderWorldMap(trustedKeys, nUnl, peers, refMode=false) {
  const container = $('world-map-container');
  if (!container) return;

  _ensureLeaflet(() => _buildLeafletMap(trustedKeys, nUnl, peers, refMode));
}

function _buildLeafletMap(trustedKeys, nUnl, peers, refMode=false) {
  const container = $('world-map-container');
  if (!container) return;

  const nUnlSet  = new Set(nUnl || []);
  const networkId = state.currentNetwork || 'xrpl-mainnet';

  // On network change, destroy old map instance
  if (_leafletMap && _mapNetId !== networkId) {
    _leafletMap.remove();
    _leafletMap = null;
    _mapMarkers = [];
    _mapNetId   = null;
  }

  // Build map container once
  if (!_leafletMap) {
    container.innerHTML = '';
    const mapDiv = document.createElement('div');
    mapDiv.id    = 'wm-leaflet';
    mapDiv.style.cssText = 'width:100%;height:440px;';
    container.appendChild(mapDiv);

    _leafletMap = L.map('wm-leaflet', {
      center: [25, 5], zoom: 2, minZoom: 1, maxZoom: 12,
      zoomControl: true, attributionControl: true,
      worldCopyJump: true,
    });

    // Dark CartoDB tiles
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
      attribution: '&copy; <a href="https://carto.com">CARTO</a> &copy; <a href="https://openstreetmap.org">OSM</a>',
      subdomains: 'abcd', maxZoom: 19,
    }).addTo(_leafletMap);

    _mapNetId = networkId;
  }

  // Remove old markers
  _mapMarkers.forEach(m => m.remove());
  _mapMarkers = [];

  // ── Validator clusters ──
  _keyToMarker = {};   // reset index
  const clusterMap = {};
  (trustedKeys || []).forEach(key => {
    const geo = VALIDATOR_GEO[key]; if (!geo) return;
    // Snap to 0.5° grid for clustering (looser = fewer micro-clusters)
    const ck = `${(Math.round(geo.lat*2)/2).toFixed(1)},${(Math.round(geo.lng*2)/2).toFixed(1)}`;
    if (!clusterMap[ck]) clusterMap[ck] = { lat:geo.lat, lng:geo.lng, keys:[], city:geo.city, org:geo.org };
    clusterMap[ck].keys.push(key);
  });

  Object.values(clusterMap).forEach(cl => {
    const hasNunl = cl.keys.some(k => nUnlSet.has(k));
    const count   = cl.keys.length;
    const color   = hasNunl ? '#ff5555' : '#00fff0';
    const glow    = hasNunl ? 'rgba(255,85,85,.4)' : 'rgba(0,255,240,.35)';
    const r       = count > 5 ? 13 : count > 2 ? 10 : 7;
    const isRef   = refMode;

    const icon = L.divIcon({
      html: `<div class="wm-lmarker wm-lmarker-val ${hasNunl?'wm-lmarker-nunl':''} ${isRef?'wm-lmarker-ref':''}"
                  style="--mc:${color};--mg:${glow};" title="${cl.keys.map(k=>KNOWN_VALIDATORS[k]?.label||k.slice(0,8)).join(', ')}">
        <div class="wm-lring"></div>
        <div class="wm-ldot" style="width:${r*2}px;height:${r*2}px;">${count>1?`<span>${count}</span>`:''}</div>
      </div>`,
      className: '', iconSize: [(r+8)*2, (r+8)*2], iconAnchor: [r+8, r+8],
    });

    const marker = L.marker([cl.lat, cl.lng], { icon })
      .bindPopup(_valPopupHtml(cl.keys, cl.city, cl.org, hasNunl, nUnlSet, isRef), {
        maxWidth: 340, className: 'wm-popup-wrap',
      })
      .addTo(_leafletMap);

    // Index every key in this cluster to the same marker
    cl.keys.forEach(k => { _keyToMarker[k] = marker; });
    _mapMarkers.push(marker);
  });

  // If refMode, show a subtle banner inside the map
  if (refMode) {
    const refBanner = L.control({ position: 'bottomleft' });
    refBanner.onAdd = () => {
      const d = L.DomUtil.create('div', 'wm-ref-banner');
      d.innerHTML = '📡 Reference positions · live validator list unavailable from endpoint';
      return d;
    };
    refBanner.addTo(_leafletMap);
    _mapMarkers.push(refBanner);
  }

  // ── Unknown validators notice ──
  const unknownKeys = (trustedKeys||[]).filter(k => !VALIDATOR_GEO[k]);
  if (unknownKeys.length) {
    const notice = L.control({ position: 'bottomright' });
    notice.onAdd = () => {
      const d = L.DomUtil.create('div', 'wm-unknown-ctrl');
      d.innerHTML = `+ ${unknownKeys.length} validators · location unknown`;
      return d;
    };
    notice.addTo(_leafletMap);
    _mapMarkers.push(notice);
  }

  // ── Public nodes ──
  PUBLIC_NODES.forEach(n => {
    const icon = L.divIcon({
      html: `<div class="wm-lmarker wm-lmarker-pub">
        <div class="wm-lring"></div>
        <div class="wm-ldot" style="width:10px;height:10px;"></div>
      </div>`,
      className: '', iconSize: [20, 20], iconAnchor: [10, 10],
    });
    const m = L.marker([n.lat, n.lng], { icon })
      .bindPopup(`
        <div class="wm-popup-inner">
          <div class="wm-popup-badge wm-popup-badge-pub">Public Node</div>
          <div class="wm-popup-name">${escHtml(n.label)}</div>
          <div class="wm-popup-row"><span class="wm-popup-key">Location</span><span>📍 ${escHtml(n.city)}</span></div>
          <div class="wm-popup-row"><span class="wm-popup-key">Operator</span><span>${escHtml(n.org)}</span></div>
          <div class="wm-popup-row"><span class="wm-popup-key">Type</span><span>Full history node</span></div>
        </div>`, { maxWidth: 260, className: 'wm-popup-wrap' })
      .addTo(_leafletMap);
    _mapMarkers.push(m);
  });

  // ── Legend control ──
  const peersArr = Array.isArray(peers) ? peers : [];
  const ib = peersArr.filter(p=>p.inbound===true).length;
  const ob = peersArr.length - ib;
  const peerTxt = peersArr.length > 0 ? `${peersArr.length} peers (${ib}↓ ${ob}↑)` : `${Number(_info?.peers??0)} peers`;

  const legend = L.control({ position: 'topleft' });
  legend.onAdd = () => {
    const d = L.DomUtil.create('div', 'wm-legend-ctrl');
    d.innerHTML = `
      <div class="wm-leg-row"><span class="wm-leg-dot" style="background:#00fff0;box-shadow:0 0 5px rgba(0,255,240,.8)"></span>UNL Validator</div>
      <div class="wm-leg-row"><span class="wm-leg-dot" style="background:#ff5555;box-shadow:0 0 5px rgba(255,85,85,.8)"></span>Negative UNL</div>
      <div class="wm-leg-row"><span class="wm-leg-dot" style="background:#50fa7b;box-shadow:0 0 5px rgba(80,250,123,.7)"></span>Public Node</div>
      <div class="wm-leg-row wm-leg-peers"><span class="wm-leg-dot" style="background:#ffb86c"></span>${peerTxt}</div>`;
    return d;
  };
  legend.addTo(_leafletMap);
  _mapMarkers.push(legend);

  // Fit bounds to validators
  if (_mapMarkers.filter(m => m.getLatLng).length > 0) {
    const pts = _mapMarkers.filter(m => m.getLatLng).map(m => m.getLatLng());
    if (pts.length > 1) {
      _leafletMap.fitBounds(L.latLngBounds(pts).pad(0.15), { maxZoom: 6 });
    }
  }
}

function _valPopupHtml(keys, city, org, hasNunl, nUnlSet, isRef=false) {
  const isCluster = keys.length > 1;
  const rows = keys.map(key => {
    const kv    = KNOWN_VALIDATORS[key];
    const onN   = nUnlSet.has(key);
    const label = kv?.label || `${key.slice(0,12)}...`;
    const shortKey = key.slice(0,20) + '...';
    return `<div class="wm-popup-val-row ${onN?'wm-popup-val-nunl':''}">
      <span class="wm-popup-val-dot" style="background:${onN?'#ff5555':'#00fff0'};box-shadow:0 0 6px ${onN?'rgba(255,85,85,.6)':'rgba(0,255,240,.6)'}"></span>
      <div class="wm-popup-val-info">
        <span class="wm-popup-val-name">${escHtml(label)}</span>
        <span class="wm-popup-val-key"
              onclick="navigator.clipboard?.writeText('${escHtml(key)}');this.textContent='✓ Copied!';setTimeout(()=>this.textContent='${escHtml(shortKey)}',1400)"
              title="Click to copy full key">${escHtml(shortKey)}</span>
        <div class="wm-popup-val-tags">
          ${onN  ? '<span class="wm-popup-nunl-tag">⚠ Negative UNL</span>' : '<span class="wm-popup-ok-tag">✓ Active</span>'}
          ${kv?.p ? `<span class="wm-popup-prov">${escHtml(kv.p)}</span>` : ''}
        </div>
      </div>
    </div>`;
  }).join('');

  // Build org lines — unique across cluster
  const orgs = [...new Set(keys.map(k => VALIDATOR_GEO[k]?.org).filter(Boolean))];

  return `<div class="wm-popup-inner">
    <div class="wm-popup-loc-row">
      <span class="wm-popup-loc-icon">📍</span>
      <div>
        <div class="wm-popup-name">${escHtml(city || 'Unknown Location')}</div>
        ${orgs.map(o=>`<div class="wm-popup-org">${escHtml(o)}</div>`).join('')}
      </div>
    </div>
    <div class="wm-popup-badges">
      ${isCluster ? `<div class="wm-popup-badge wm-popup-badge-cluster">${keys.length} Validators at this location</div>` : ''}
      ${hasNunl   ? '<div class="wm-popup-badge wm-popup-badge-nunl">⚠ On Negative UNL</div>' : ''}
      ${isRef     ? '<div class="wm-popup-badge wm-popup-badge-ref">Reference data</div>' : ''}
    </div>
    <div class="wm-popup-divider"></div>
    <div class="wm-popup-vals">${rows}</div>
  </div>`;
}

/* ═══════════════════════════════════════════════════
   ADVERSARIAL ALERT ENGINE
═══════════════════════════════════════════════════ */
function _alert() {
  const keys=Object.keys(_sigs);
  const wt  =keys.reduce((s,k)=>s+(SIG[k]?.w??1),0);
  const hot =wt>=ALERT_WEIGHT;

  const alertEl=$('adversarial-alert');
  if (alertEl) { alertEl.classList.toggle('adv-active',hot); alertEl.classList.toggle('adv-inactive',!hot); }

  const scoreEl=$('adversarial-score');
  if (scoreEl) { scoreEl.textContent=`Threat Score: ${wt}`; scoreEl.className=`adv-score ${hot?'adv-hot':'adv-cool'}`; }

  const listEl=$('adversarial-signals');
  if (!listEl) return;
  if (!keys.length) {
    listEl.innerHTML='<span class="adv-clear">✓ All systems nominal — no adversarial signals active</span>';
  } else {
    keys.sort((a,b)=>(SIG[b]?.w??1)-(SIG[a]?.w??1));
    listEl.innerHTML=keys.map(k=>
      `<div class="adv-sig"><span class="adv-dot"></span>
       <span class="adv-txt">${escHtml(SIG[k]?.label??k)}</span>
       <span class="adv-wt">x${SIG[k]?.w??1}</span></div>`
    ).join('');
  }
}

/* ═══════════════════════════════════════════════════
   HEALTH BANNER
═══════════════════════════════════════════════════ */
function _banner(data) {
  const el=$('nh-banner'); if (!el) return;
  if (!data || state.connectionState!=='connected') {
    _t('nh-score','—'); _t('nh-grade','Disconnected'); _t('nh-sub','Connect to begin');
    el.className='nh-banner nh-dead'; _vitals({}); _renderHealthChecks(null); return;
  }
  const {info,fee,vals}=data;
  let sc=100;
  const st=info?.server_state??'unknown';
  if (!['full','proposing','validating'].includes(st)) sc-=(st==='syncing'?20:40);
  const lf=Number(info?.load_factor??1);
  if(lf>2)sc-=10; if(lf>5)sc-=15; if(lf>20)sc-=20;
  const pc=Number(info?.peers??0);
  if(pc<6)sc-=30; else if(pc<15)sc-=10;
  const cvg=Number(info?.last_close?.converge_time_s??0);
  if(cvg>6)sc-=10; if(cvg>10)sc-=15;
  const age=Number(info?.validated_ledger?.age??0);
  if(age>5)sc-=5; if(age>10)sc-=15;
  const of=Number(fee?.drops?.open_ledger_fee??10);
  if(of>500)sc-=5; if(of>2000)sc-=10;
  const tc=vals?.trusted_validator_keys?.length??0, q=vals?.validation_quorum??0;
  if(q>0&&tc<q)sc-=30;
  const nc=(info?.negative_unl??[]).length; sc-=Math.min(20,nc*4);
  const sw=Object.keys(_sigs).reduce((s,k)=>s+(SIG[k]?.w??1),0); sc-=Math.min(25,sw*3);
  sc=Math.max(0,Math.min(100,Math.round(sc)));

  const {grade,cls}=_grade(sc);
  const sigN=Object.keys(_sigs).length;
  _t('nh-score',sc); _t('nh-grade',grade);
  _t('nh-sub',`${new Date().toLocaleTimeString()} · ${sigN} signal${sigN!==1?'s':''} active`);
  el.className=`nh-banner nh-${cls}`;

  const ring=$('nh-ring');
  if (ring) {
    const c=2*Math.PI*28;
    ring.style.strokeDasharray =c;
    ring.style.strokeDashoffset=c*(1-sc/100);
    ring.style.stroke=cls==='great'?'#00fff0':cls==='good'?'#50fa7b':cls==='fair'?'#ffb86c':'#ff5555';
  }
  _vitals({st,pc,q,tc,lf,cvg,age,nc});
  _renderHealthChecks({info,fee,vals});
}

function _grade(s) {
  return s>=90?{grade:'Excellent',cls:'great'}:s>=70?{grade:'Good',cls:'good'}:s>=50?{grade:'Fair',cls:'fair'}:{grade:'Degraded',cls:'bad'};
}

function _vitals(v) {
  _vit('nh-v-state',['full','proposing','validating'].includes(v.st)?'ok':v.st==='syncing'?'warn':'bad', v.st??'—');
  _vit('nh-v-peers',(v.pc??0)>=15?'ok':(v.pc??0)>=6?'warn':'bad', v.pc??'—');
  _vit('nh-v-cvg',  (v.cvg??0)<4?'ok':(v.cvg??0)<7?'warn':'bad',  v.cvg!=null?`${Number(v.cvg).toFixed(1)}s`:'—');
  _vit('nh-v-age',  (v.age??0)<3?'ok':(v.age??0)<8?'warn':'bad',   v.age!=null?`${Number(v.age)}s`:'—');
  _vit('nh-v-load', (v.lf??1)<2?'ok':(v.lf??1)<5?'warn':'bad',     v.lf!=null?`${Number(v.lf).toFixed(1)}x`:'—');
  _vit('nh-v-nunl', (v.nc??0)===0?'ok':(v.nc??0)<=2?'warn':'bad',  v.nc!=null?(v.nc===0?'None':v.nc):'—');
}
function _vit(id, cls, txt) { const e=$(id); if(e){e.textContent=txt; e.className=`nh-vval nh-vval--${cls}`;} }

/* ═══════════════════════════════════════════════════
   SYSTEM HEALTH DASHBOARD
═══════════════════════════════════════════════════ */
function _renderHealthChecks(data) {
  const el=$('nh-health-checks'); if (!el) return;
  if (!data) {
    el.innerHTML='<div class="hc-disconnected">Connect to an XRPL node to see system health</div>';
    return;
  }
  const {info,fee,vals}=data;

  const checks=[
    { label:'Node State',    group:'consensus', check:()=>{
        const s=info?.server_state||'unknown';
        const ok=['full','proposing','validating'].includes(s);
        return {pass:ok, warn:s==='syncing', fail:!ok&&s!=='syncing', detail:s};
    }},
    { label:'Quorum',        group:'consensus', check:()=>{
        const tk=vals?.trusted_validator_keys?.length??0, q=vals?.validation_quorum??0;
        const m=tk-q;
        if (!q) return {pass:false,warn:true,fail:false,detail:'No quorum data'};
        return {pass:m>3, warn:m>0&&m<=3, fail:m<=0, detail:`${tk} validators, quorum ${q}, margin ${m}`};
    }},
    { label:'Negative UNL',  group:'consensus', check:()=>{
        const n=(info?.negative_unl||[]).length;
        return {pass:n===0, warn:n>0&&n<=2, fail:n>2, detail:n===0?'None':`${n} offline`};
    }},
    { label:'Ledger Age',    group:'consensus', check:()=>{
        const age=Number(info?.validated_ledger?.age??0);
        return {pass:age<5, warn:age>=5&&age<10, fail:age>=10, detail:`${age}s`};
    }},
    { label:'Convergence',   group:'consensus', check:()=>{
        const cvg=Number(info?.last_close?.converge_time_s??0);
        return {pass:cvg<4, warn:cvg>=4&&cvg<7, fail:cvg>=7, detail:cvg>0?`${cvg.toFixed(1)}s`:'< 1s'};
    }},
    { label:'Peer Count',    group:'infra', check:()=>{
        const p=Number(info?.peers??0);
        return {pass:p>=15, warn:p>=6&&p<15, fail:p<6, detail:`${p} connected`};
    }},
    { label:'Eclipse Risk',  group:'infra', check:()=>{
        const p=Number(info?.peers??0);
        return {pass:p>=15, warn:p>=6, fail:p<6, detail:p<6?'HIGH RISK':p<15?'Medium':'Low'};
    }},
    { label:'Load Factor',   group:'infra', check:()=>{
        const lf=Number(info?.load_factor??1);
        return {pass:lf<2, warn:lf>=2&&lf<5, fail:lf>=5, detail:`${lf.toFixed(2)}x`};
    }},
    { label:'IO Latency',    group:'infra', check:()=>{
        const ms=Number(info?.io_latency_ms??0);
        return {pass:ms<2, warn:ms>=2&&ms<10, fail:ms>=10, detail:ms>0?`${ms}ms`:'< 1ms'};
    }},
    { label:'Job Queue',     group:'infra', check:()=>{
        const jq=Number(info?.jq_trans_overflow??0);
        return {pass:jq===0, warn:false, fail:jq>0, detail:jq===0?'Clean':`${jq} overflows`};
    }},
    { label:'Fee Pressure',  group:'economic', check:()=>{
        const f=Number(fee?.drops?.open_ledger_fee??10);
        return {pass:f<100, warn:f>=100&&f<500, fail:f>=500, detail:`${f} drops`};
    }},
    { label:'TX Queue',      group:'economic', check:()=>{
        const q=Number(fee?.current_queue_size??0), m=Number(fee?.max_queue_size??1);
        const p=m>0?Math.round((q/m)*100):0;
        return {pass:p<50, warn:p>=50&&p<80, fail:p>=80, detail:`${p}% full`};
    }},
  ];

  const results  =checks.map(c=>({...c,result:c.check()}));
  const passCount=results.filter(r=>r.result.pass).length;
  const warnCount=results.filter(r=>r.result.warn).length;
  const failCount=results.filter(r=>r.result.fail).length;

  const sumEl=$('nh-health-summary');
  if (sumEl) {
    sumEl.innerHTML=`
      <span class="hcs-count hcs-pass">${passCount}</span><span class="hcs-lbl">healthy</span>
      <span class="hcs-sep">·</span>
      <span class="hcs-count hcs-warn">${warnCount}</span><span class="hcs-lbl">warning</span>
      <span class="hcs-sep">·</span>
      <span class="hcs-count hcs-fail">${failCount}</span><span class="hcs-lbl">degraded</span>
      <span class="hcs-total">of ${results.length} checks</span>`;
  }

  const groups={consensus:'Consensus',infra:'Infrastructure',economic:'Economic'};
  el.innerHTML=Object.entries(groups).map(([gid,gname])=>{
    const gc=results.filter(r=>r.group===gid);
    const items=gc.map(r=>{
      const cls=r.result.pass?'hc-ok':r.result.warn?'hc-warn':'hc-fail';
      const ico=r.result.pass?'✓':r.result.warn?'⚠':'✗';
      return `<div class="hc-item ${cls}">
        <span class="hc-icon">${ico}</span>
        <div class="hc-text">
          <span class="hc-label">${escHtml(r.label)}</span>
          <span class="hc-detail">${escHtml(r.result.detail)}</span>
        </div>
      </div>`;
    }).join('');
    const gPass=gc.filter(r=>r.result.pass).length;
    const gCls =gPass===gc.length?'hcg-all-ok':gPass===0?'hcg-all-fail':'hcg-mixed';
    return `<div class="hc-group ${gCls}">
      <div class="hc-group-title">${escHtml(gname)}</div>
      <div class="hc-group-items">${items}</div>
    </div>`;
  }).join('');
}

/* ─── Ledger accumulator ─── */
function _accumulate(d) {
  if (!d) return;
  _bpush('burnDrops',  (d.avgFee||0)*1e6*(d.txPerLedger??0));
  _bpush('dexOffers',  d.txTypes?.OfferCreate??0);
  _bpush('ammSwaps',   (d.txTypes?.AMMDeposit??0)+(d.txTypes?.AMMWithdraw??0)+(d.txTypes?.AMMBid??0));
  _bpush('newAccounts',d.txTypes?.AccountSet??0);
}
function _liveCells(d) {
  const tps=state.tpsHistory.length?state.tpsHistory[state.tpsHistory.length-1]:null;
  _t('m2-tps',    tps!=null?tps.toFixed(1):'—');
  _t('m2-txcount',d.txPerLedger??'—');
  if (d.successRate!=null) _t('m2-success',`${d.successRate.toFixed(0)}%`);
}

/* ═══════════════════════════════════════════════════
   ENDPOINT LATENCY
═══════════════════════════════════════════════════ */
export async function measureLatency({force=false}={}) {
  if (!_vis() && !force) return;
  const now=Date.now();
  if (!force&&now-_latAt<LATENCY_COOLDOWN_MS) return;
  _latAt=now;
  const listEl=$('latency-list'); if (!listEl) return;
  const eps=ENDPOINTS_BY_NETWORK[state.currentNetwork]??[];
  const run=++_latRun;
  listEl.innerHTML=eps.map((ep,i)=>`
    <div class="latency-row" id="lat-row-${i}">
      <div class="lat-ep">
        <span class="lat-name">${escHtml(ep.name)}</span>
        <span class="lat-url">${escHtml(ep.url)}</span>
      </div>
      <div class="lat-bwrap"><div class="lat-bfill" id="lat-bar-${i}" style="width:0%"></div></div>
      <span class="lat-val" id="lat-val-${i}">—</span>
    </div>`).join('');
  for (let i=0; i<eps.length; i++) {
    if (run!==_latRun) return;
    await _ping(eps[i],i);
    await _delay(LATENCY_GAP_MS);
  }
}

async function _ping(ep,idx) {
  const ve=$(`lat-val-${idx}`), be=$(`lat-bar-${idx}`), re=$(`lat-row-${idx}`);
  if (ve) ve.textContent='...';
  const t0=performance.now();
  try {
    const ws=new WebSocket(ep.url);
    await new Promise((res,rej)=>{
      const t=setTimeout(()=>rej(),LATENCY_TIMEOUT_MS);
      ws.onopen=()=>{clearTimeout(t);res();}; ws.onerror=()=>{clearTimeout(t);rej();};
    });
    const ms=Math.round(performance.now()-t0); try{ws.close();}catch{}
    const cls=ms<100?'lat-fast':ms<300?'lat-med':'lat-slow';
    if (ve){ve.textContent=`${ms}ms`; ve.className=`lat-val ${cls}`;}
    if (be) be.style.width=`${Math.min(100,(ms/600)*100)}%`;
    re?.classList.toggle('lat-active',state.wsConn?.url===ep.url);
  } catch {
    if (ve){ve.textContent='timeout'; ve.className='lat-val lat-slow';}
  }
}

/* ─── Helpers ─── */
function _bpush(k,v)  { if(!_bl[k])_bl[k]=[]; _bl[k].push(Number(v)); if(_bl[k].length>BASELINE_LEN)_bl[k].shift(); }
function _bavg(k)     { const a=_bl[k]??[]; return a.length?a.reduce((s,v)=>s+v,0)/a.length:0; }
function _bsum(k,n)   { return(_bl[k]??[]).slice(-n).reduce((s,v)=>s+v,0); }
function _stddev(arr) { if(arr.length<2)return 0; const m=arr.reduce((s,v)=>s+v,0)/arr.length; return Math.sqrt(arr.reduce((s,v)=>s+(v-m)**2,0)/arr.length); }
function _loadBL()    { try{const r=localStorage.getItem(BASELINE_KEY); if(!r)return; const p=JSON.parse(r); Object.keys(_bl).forEach(k=>{if(Array.isArray(p[k]))_bl[k]=p[k];});}catch{} }
function _saveBL()    { try{localStorage.setItem(BASELINE_KEY,JSON.stringify(_bl));}catch{} }
function _t(id,v)     { const e=$(id); if(e)e.textContent=v??'—'; }
function _bar(id,pct,cls) { const e=$(id); if(!e)return; e.style.width=`${Math.min(100,Math.max(0,Number(pct)||0))}%`; e.className=`bar-fill ${cls??''}`; }
function _histScore(cl) { if(!cl)return 0; const m=cl.match(/(\d+)-(\d+)/); if(!m)return 10; const r=Number(m[2])-Number(m[1]); return r>10_000_000?95:r>1_000_000?70:r>100_000?40:15; }
function _fmtUp(s)    { if(!s)return'—'; const d=Math.floor(s/86400),h=Math.floor((s%86400)/3600),m=Math.floor((s%3600)/60); return d>0?`${d}d ${h}h`:h>0?`${h}h ${m}m`:`${m}m`; }
function _delay(ms)   { return new Promise(r=>setTimeout(r,ms)); }