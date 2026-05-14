/* =====================================================
   network.js — Deep-State XRPL Health & Security Suite
   NaluLF v3.3

   Verified rippled API field paths.
   New in v3.3:
     - Live validator registry via GET /api/v1/validatorregistry
       * Fetches Ripple UNL, XRPL Foundation dUNL, xrplmeta enrichment
       * Merges label / domain / provider / geo dynamically
       * Falls back to FALLBACK_VALIDATORS if endpoint unreachable
     - Validator grid tabs: UNL · dUNL · Others · All (unchanged)
     - Map markers colour-coded per category (unchanged)
     - Global Atlas section removed (unchanged)
   ===================================================== */

import { $, escHtml, toastWarn } from './utils.js';
import { state }                from './state.js';
import { wsSend }               from './xrpl.js';
import { ENDPOINTS_BY_NETWORK } from './config.js';

const POLL_MS             = 60_000;
const MIN_GAP_MS          = 10_000;
const BACKOFF_MS          = 120_000;
const LATENCY_TIMEOUT_MS  = 8_000;
const LATENCY_COOLDOWN_MS = 120_000;
const LATENCY_GAP_MS      = 300;

const BASELINE_KEY        = 'nalulf_net_baseline_v2';
const BASELINE_LEN        = 80;
const ALERT_WEIGHT        = 5;

/* ── Registry endpoint ─────────────────────────────── */
const REGISTRY_URL         = '/api/v1/validatorregistry';
const VALIDATOR_URL        = '/api/v1/validator';   // + /:key  or /:key/reports
const NODE_URL             = '/api/v1/node';         // + /:key
const REGISTRY_CACHE_MS    = 5  * 60 * 1000;
const DETAIL_CACHE_MS      = 10 * 60 * 1000;
const REGISTRY_TIMEOUT_MS  = 10_000;
const DETAIL_TIMEOUT_MS    = 8_000;

/* Client-side caches for detail fetches */
const _detailCache     = new Map();   // key → { data, cachedAt }
const _reportsCache    = new Map();   // key → { data, cachedAt }
const _nodeDetailCache = new Map();   // key → { data, cachedAt }

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

/* ═══════════════════════════════════════════════════
   AUTHORITATIVE UNL / CHAIN CLASSIFICATION
   Source of truth derived from XRPScan data.
   UNL_DOMAINS = the 35 starred validators on main UNL.
   TESTNET_KEYS = keys whose chain = 'test'.
   These override whatever the API returns for unl/chain.
═══════════════════════════════════════════════════ */

/** Rows 1–35 from XRPScan: starred UNL validators on mainnet */
const UNL_DOMAINS = new Set([
  'xrpscan.com', 'xrpl.aesthetes.art', 'xrpkuwait.com', 'xrpgoat.com',
  'xrp.vet', 'xrp.unic.ac.cy', 'xrp-validator.interledger.org', 'xpmarket.com',
  'verum.eminence.im', 'validator.xrpl.robertswarthout.com', 'validator.xrpl-labs.com',
  'validator.poli.usp.br', 'validator.gatehub.net', 'validator.aspired.nz',
  'v2.xrpl-commons.org', 'tequ.dev', 'squidrouter.com', 'ripple.ittc.ku.edu',
  'ripple.com', 'peersyst.cloud', 'onxrp.com', 'katczynski.net', 'jon-nilsen.no',
  'ekiserrepe.es', 'cabbit.tech', 'bithomp.com', 'aureusox.com',
  'arrington-xrp-capital.blockdaemon.com', 'anodos.finance', 'bitso.com',
  'ripple.kenan-flagler.unc.edu', 'ripplevalidator.uwaterloo.ca',
  'shadow.haas.berkeley.edu', 'www.bitrue.com', 'xrp-col.anu.edu.au',
]);

/** Rows 128–176: testnet validator keys (no domain on testnet rows) */
const TESTNET_KEYS = new Set([
  'nHBu3iuq1SQ9Z686pYwWYVKpScSMDWfpUJHdNEQRxn5XyETui7Db',
  'nHDwBbubxJswoweWQKEgWLNRJv2hNRCTR4GGApJmbtCcbtYNSpdB',
  'nHU2FpRbPrvVcyQQpkqrAUDJDTRHZpjij8DpKeSC481PYY9ikYkb',
  'nHUbmg8QNzEGjHzgnt99e9YE2scU3DZGH7FsF6MCcK5eiPt3AtaH',
  'nHUxBD1UPb383SdWgJx62GGQ7W2WKvgpUtUXLjiGGRRcPb3nbSXd',
  'nHUP6rfQfgzg6tKga3k9ziEvtjwn1PB32gcr5dLcamqzmitszYv2',
  'nHBT58yHyDdPdJ6gzaBMT7gqwTMpj5ERji1s9SvfKKtfoZUS89WX',
  'nHBxsUzx3Bbf6J4yJ3fLQ3VizPtdREVwTJ6mdqkuDTjLcVbggVbk',
  'nHUeUNSn3zce2xQZWNghQvd9WRH6FWEnCBKYVJu2vAizMxnXegfJ',
  'nHUCAdca6VoWWYVdBH1bwCUQggEX2e5acQSqxM3DwyuhsFknxmh3',
  'nHDDiwQBqXhEL1CFoRHdMXD33x9K7rpYJfniXxL7kFavpPd21EGe',
  'nHBipbbREjNEiCs4hpy3K2489dRf27MPnxdivTTWKSd8ZUhfRvn8',
  'nHDDe5uAdiv6RA59MA1oM4JLDtVSYKNShgjEqq1KsdJXZiR47CQT',
  'nHBbiP5ua5dUqCTz5i5vd3ia9jg3KJthohDjgKxnc7LxtmnauW7Z',
  'nHBQ3CT3EWYZ4uzbnL3k6TRf9bBPhWRFVcK1F5NjtwCBksMEt5yy',
  'nHU16DF2kq7TmbR1Y5z8yKNXiLEf3oHT19HVpVXv7unFLfxa17nT',
  'nHUC23NnutZyYeQxQbAbPUpKoVGj5aisBxf2zzcZzJ43fcw5rc9z',
  'nHUgdMvuchx7AWG4ATMQdNNuMryo1SFoNptLCEVt2Dn7wEc625mF',
  'nHUhQVE93dajM3srxubsEj1mK1gzRwJob14QSrJefY1FdLs6r7WJ',
  'nHUU8xBczYzW6kZ6Ei9DsggzTJXRFkN3wE3FP5H4SLYzhbodeYcG',
  'nHUGqooyfGqFkyH6uskbaEi6y2MjXjdA7QdbmyZ6p9etL5isRKLT',
  'nHDp1ZXxEn7eo5YaUtiagaxSLwXudnKZDx68C96p4tdVLGLLLUFn',
  'nHBcLEB4S6moQGrhMjJo1jbp58WL5psHY9EMDWNAtdqykUYiA1rF',
  'nHUAECq1v1cKwn3NsYVyD7v6BNbfqyXmNVSF3e4XCVxPgBHRWkvv',
  'nHUif4sukXu9pJGyyBaeVMwmE8L1fJ5KJj4X4ksgTKhgjG6k96s2',
  'nHUVJR7SeT3nn6JPTz46JHqYRf7vX2if1sdTxnceywmSBWa167pt',
  'nHUEYz4TtTv7yebjhY3aDib5KYPHnKjnY5mPYK5y4QuKdocwS5tD',
  'nHUN5n2S3nQ8bzKm7bqeFMiQeDijh1LMgEocyNyQbb4mREazVdZ5',
  'nHUgchANqM3giYSSvY5HsafFW6qxmG5jJ3CvPiv7n8gjNQuNm8Uz',
  'nHDUqGoM7KR1pgbdYBRgKpGKdFLhpnMzVbECs8RE73RGZm3Va6MJ',
  'nHUVxTi8XfXjaaJppw7mLSrYDRpkDpf8H9ypzgVKxfSXShcWwAoK',
  'nHBveTxA1NaBj5AayRAU91f6YopuFWt9rmxfGaEh77a32Q6ZzzHc',
]);

/** Testnet domains (rows 160–176) */
const TESTNET_DOMAINS = new Set([
  'validator.pftperry.com','rip973.com','preaware.org','postfiat.org',
  'pftmeech.xyz','pft.xbtseal.com','pft.wizbubba.xyz','pft.permanentupperclass.com',
  'pft.g.money','pft.akirax.xyz','jollydinger.com','auri0x.io','app.w.ai',
]);

/**
 * Authoritative classification — overrides whatever the API returns.
 * domain is normalised (lowercase, www. stripped) before checking.
 */
function _classifyValidator(key, domain) {
  const d = (domain || '').toLowerCase().replace(/^www\./, '');
  if (TESTNET_KEYS.has(key) || TESTNET_DOMAINS.has(d)) return { chain:'test', isUnl:false };
  if (UNL_DOMAINS.has(d) || UNL_DOMAINS.has('www.' + d))   return { chain:'main', isUnl:true  };
  return { chain:'main', isUnl:false };
}

/* ─── Static fallback registry — all 127 mainnet validators + testnet ─── */
const FALLBACK_VALIDATORS = {
  /* UNL mainnet (rows 1–35) */
  'xrpscan.com':                           { label:'XRP Scan',             domain:'xrpscan.com',                           chain:'main', category:'unl'  },
  'xrpl.aesthetes.art':                    { label:'Aesthetes',             domain:'xrpl.aesthetes.art',                    chain:'main', category:'unl'  },
  'xrpkuwait.com':                         { label:'XRP Kuwait',            domain:'xrpkuwait.com',                         chain:'main', category:'unl'  },
  'xrpgoat.com':                           { label:'XRP Goat',              domain:'xrpgoat.com',                           chain:'main', category:'unl'  },
  'xrp.vet':                               { label:'XRP Vet',               domain:'xrp.vet',                               chain:'main', category:'unl'  },
  'xrp.unic.ac.cy':                        { label:'Univ. of Nicosia',      domain:'xrp.unic.ac.cy',                        chain:'main', category:'unl'  },
  'xrp-validator.interledger.org':         { label:'Interledger',           domain:'xrp-validator.interledger.org',         chain:'main', category:'unl'  },
  'xpmarket.com':                          { label:'XPMarket',              domain:'xpmarket.com',                          chain:'main', category:'unl'  },
  'verum.eminence.im':                     { label:'Eminence',              domain:'verum.eminence.im',                     chain:'main', category:'unl'  },
  'validator.xrpl.robertswarthout.com':    { label:'R. Swarthout',          domain:'validator.xrpl.robertswarthout.com',    chain:'main', category:'unl'  },
  'validator.xrpl-labs.com':               { label:'XRPL Labs',             domain:'validator.xrpl-labs.com',               chain:'main', category:'unl'  },
  'validator.poli.usp.br':                 { label:'USP',                   domain:'validator.poli.usp.br',                 chain:'main', category:'unl'  },
  'validator.gatehub.net':                 { label:'Gatehub',               domain:'validator.gatehub.net',                 chain:'main', category:'unl'  },
  'validator.aspired.nz':                  { label:'Aspired NZ',            domain:'validator.aspired.nz',                  chain:'main', category:'unl'  },
  'v2.xrpl-commons.org':                   { label:'XRPL Commons',          domain:'v2.xrpl-commons.org',                   chain:'main', category:'unl'  },
  'tequ.dev':                              { label:'Tequ',                  domain:'tequ.dev',                              chain:'main', category:'unl'  },
  'squidrouter.com':                       { label:'Squid Router',          domain:'squidrouter.com',                       chain:'main', category:'unl'  },
  'ripple.ittc.ku.edu':                    { label:'Univ. of Kansas',       domain:'ripple.ittc.ku.edu',                    chain:'main', category:'unl'  },
  'ripple.com':                            { label:'Ripple',                domain:'ripple.com',                            chain:'main', category:'unl'  },
  'peersyst.cloud':                        { label:'Peersyst',              domain:'peersyst.cloud',                        chain:'main', category:'unl'  },
  'onxrp.com':                             { label:'OnXRP',                 domain:'onxrp.com',                             chain:'main', category:'unl'  },
  'katczynski.net':                        { label:'Katczynski',            domain:'katczynski.net',                        chain:'main', category:'unl'  },
  'jon-nilsen.no':                         { label:'Jon Nilsen',            domain:'jon-nilsen.no',                         chain:'main', category:'unl'  },
  'ekiserrepe.es':                         { label:'Ekiserrepe',            domain:'ekiserrepe.es',                         chain:'main', category:'unl'  },
  'cabbit.tech':                           { label:'Cabbit',                domain:'cabbit.tech',                           chain:'main', category:'unl'  },
  'bithomp.com':                           { label:'Bithomp',               domain:'bithomp.com',                           chain:'main', category:'unl'  },
  'aureusox.com':                          { label:'Aureus Ox',             domain:'aureusox.com',                          chain:'main', category:'unl'  },
  'arrington-xrp-capital.blockdaemon.com': { label:'Arrington / Blockdaemon',domain:'arrington-xrp-capital.blockdaemon.com',chain:'main', category:'unl'  },
  'anodos.finance':                        { label:'Anodos Finance',        domain:'anodos.finance',                        chain:'main', category:'unl'  },
  'bitso.com':                             { label:'Bitso',                 domain:'bitso.com',                             chain:'main', category:'unl'  },
  'ripple.kenan-flagler.unc.edu':          { label:'UNC Kenan-Flagler',     domain:'ripple.kenan-flagler.unc.edu',          chain:'main', category:'unl'  },
  'ripplevalidator.uwaterloo.ca':          { label:'Univ. of Waterloo',     domain:'ripplevalidator.uwaterloo.ca',          chain:'main', category:'unl'  },
  'shadow.haas.berkeley.edu':              { label:'UC Berkeley Haas',      domain:'shadow.haas.berkeley.edu',              chain:'main', category:'unl'  },
  'www.bitrue.com':                        { label:'Bitrue',                domain:'www.bitrue.com',                        chain:'main', category:'unl'  },
  'xrp-col.anu.edu.au':                    { label:'ANU',                   domain:'xrp-col.anu.edu.au',                    chain:'main', category:'unl'  },
  /* Other mainnet (rows 68–127, domain-known) */
  'xrpval.rawsec.de':                      { label:'Rawsec',                domain:'xrpval.rawsec.de',                      chain:'main', category:'other' },
  'xrplvl.carbonvibe.com':                 { label:'Carbon Vibe',           domain:'xrplvl.carbonvibe.com',                 chain:'main', category:'other' },
  'xrplvalidator.alloy.ee':                { label:'Alloy',                 domain:'xrplvalidator.alloy.ee',                chain:'main', category:'other' },
  'xrpl.uni.lu':                           { label:'Univ. of Luxembourg',   domain:'xrpl.uni.lu',                           chain:'main', category:'other' },
  'xrpl.to':                               { label:'XRPL.to',               domain:'xrpl.to',                               chain:'main', category:'other' },
  'xrpl.su':                               { label:'XRPL.su',               domain:'xrpl.su',                               chain:'main', category:'other' },
  'xrpl.sbivc.co.jp':                      { label:'SBI VC Trade',          domain:'xrpl.sbivc.co.jp',                      chain:'main', category:'other' },
  'xrpl-verification.flare.network':       { label:'Flare Network',         domain:'xrpl-verification.flare.network',       chain:'main', category:'other' },
  'xrpl-validator.7rev.dev':               { label:'7Rev',                  domain:'xrpl-validator.7rev.dev',               chain:'main', category:'other' },
  'xrp.teacopula.com':                     { label:'Teacopula',             domain:'xrp.teacopula.com',                     chain:'main', category:'other' },
  'xrp.moneymindedapes.com':               { label:'MoneyMindedApes',       domain:'xrp.moneymindedapes.com',               chain:'main', category:'other' },
  'xrp.hazza-systems.de':                  { label:'Hazza Systems',         domain:'xrp.hazza-systems.de',                  chain:'main', category:'other' },
  'xrp.cs.uoregon.edu':                    { label:'Univ. of Oregon',       domain:'xrp.cs.uoregon.edu',                    chain:'main', category:'other' },
  'xrp.bpsqn.com':                         { label:'BPSQN',                 domain:'xrp.bpsqn.com',                         chain:'main', category:'other' },
  'xrp-validator.grapedrop.xyz':           { label:'Grapedrop',             domain:'xrp-validator.grapedrop.xyz',           chain:'main', category:'other' },
  'xaodao.io':                             { label:'XaoDAO',                domain:'xaodao.io',                             chain:'main', category:'other' },
  'vl.xrpsalute.com':                      { label:'XRP Salute',            domain:'vl.xrpsalute.com',                      chain:'main', category:'other' },
  'validator.xrpl.app':                    { label:'XRPL App',              domain:'validator.xrpl.app',                    chain:'main', category:'other' },
  'validator.ukcbt.org':                   { label:'UKCBT',                 domain:'validator.ukcbt.org',                   chain:'main', category:'other' },
  'validator.sugarxrpl.com':               { label:'SugarXRPL',             domain:'validator.sugarxrpl.com',               chain:'main', category:'other' },
  'validator.boscaern.digital':            { label:'Boscaern',              domain:'validator.boscaern.digital',            chain:'main', category:'other' },
  'trimaera.tech':                         { label:'Trimaera',              domain:'trimaera.tech',                         chain:'main', category:'other' },
  'textrp.io':                             { label:'TextRP',                domain:'textrp.io',                             chain:'main', category:'other' },
  'tesbert.com':                           { label:'Tesbert',               domain:'tesbert.com',                           chain:'main', category:'other' },
  'tachyon-xrpl-validator.github.io':      { label:'Tachyon',               domain:'tachyon-xrpl-validator.github.io',      chain:'main', category:'other' },
  'solonation.io':                         { label:'SoloNation',            domain:'solonation.io',                         chain:'main', category:'other' },
  'smokydrip.com':                         { label:'SmokyDrip',             domain:'smokydrip.com',                         chain:'main', category:'other' },
  'rippled-validator.us':                  { label:'rippled-validator.us',  domain:'rippled-validator.us',                  chain:'main', category:'other' },
  'rippleat.snt.uni.lu':                   { label:'Univ. Luxembourg (SNT)',domain:'rippleat.snt.uni.lu',                   chain:'main', category:'other' },
  'ripple.uni.lu':                         { label:'Univ. Luxembourg',      domain:'ripple.uni.lu',                         chain:'main', category:'other' },
  'ripple.j2b.com':                        { label:'J2B',                   domain:'ripple.j2b.com',                        chain:'main', category:'other' },
  'rich-list.info':                        { label:'Rich List',             domain:'rich-list.info',                        chain:'main', category:'other' },
  'proptoexchange.com':                    { label:'ProPtoExchange',        domain:'proptoexchange.com',                    chain:'main', category:'other' },
  'printscierge.com':                      { label:'Printscierge',          domain:'printscierge.com',                      chain:'main', category:'other' },
  'opulencex.io':                          { label:'OpulenceX',             domain:'opulencex.io',                          chain:'main', category:'other' },
  'onledger.net':                          { label:'OnLedger',              domain:'onledger.net',                          chain:'main', category:'other' },
  'oclost.art':                            { label:'Oclost',                domain:'oclost.art',                            chain:'main', category:'other' },
  'managednetwork.us':                     { label:'ManagedNetwork',        domain:'managednetwork.us',                     chain:'main', category:'other' },
  'joshuahamsa.com':                       { label:'Joshua Hamsa',          domain:'joshuahamsa.com',                       chain:'main', category:'other' },
  'grimmsxrpflow.jwscott.net':             { label:'Grimm XRP Flow',        domain:'grimmsxrpflow.jwscott.net',             chain:'main', category:'other' },
  'getlol.xyz':                            { label:'GetLol',                domain:'getlol.xyz',                            chain:'main', category:'other' },
  'gen3labs.xyz':                          { label:'Gen3 Labs',             domain:'gen3labs.xyz',                          chain:'main', category:'other' },
  'garveyvalid.com':                       { label:'Garvey',                domain:'garveyvalid.com',                       chain:'main', category:'other' },
  'easynpl.kr':                            { label:'EasyNPL',               domain:'easynpl.kr',                            chain:'main', category:'other' },
  'diseb.ewi.tudelft.nl':                  { label:'TU Delft',              domain:'diseb.ewi.tudelft.nl',                  chain:'main', category:'other' },
  'datamossa.com':                         { label:'DataMossa',             domain:'datamossa.com',                         chain:'main', category:'other' },
  'crypto.unibe.ch':                       { label:'Univ. of Bern',         domain:'crypto.unibe.ch',                       chain:'main', category:'other' },
  'commonprefix.com':                      { label:'Common Prefix',         domain:'commonprefix.com',                      chain:'main', category:'other' },
  'catalyze-research.com':                 { label:'Catalyze Research',     domain:'catalyze-research.com',                 chain:'main', category:'other' },
  'catalog.org':                           { label:'Catalog',               domain:'catalog.org',                           chain:'main', category:'other' },
  'blockchain.korea.ac.kr':                { label:'Korea Univ.',           domain:'blockchain.korea.ac.kr',                chain:'main', category:'other' },
  'astatiumprotocol.com':                  { label:'Astatium Protocol',     domain:'astatiumprotocol.com',                  chain:'main', category:'other' },
  'ladykxrpl.mywire.org':                  { label:'LadyK XRPL',            domain:'LadyKXRPL.mywire.org',                  chain:'main', category:'other' },
  'eelap-p1201-xrp.abudhabi.nyu.edu':      { label:'NYU Abu Dhabi',         domain:'EELAP-P1201-XRP.ABUDHABI.NYU.EDU',      chain:'main', category:'other' },
  '589.clouds.hspeed.ch':                  { label:'HSpeed',                domain:'589.clouds.hspeed.ch',                  chain:'main', category:'other' },
  /* Testnet (rows 128–176, domain-known) */
  'validator.pftperry.com':                { label:'PFT Perry',             domain:'validator.pftperry.com',                chain:'test', category:'other' },
  'rip973.com':                            { label:'rip973',                domain:'rip973.com',                            chain:'test', category:'other' },
  'preaware.org':                          { label:'Preaware',              domain:'preaware.org',                          chain:'test', category:'other' },
  'postfiat.org':                          { label:'PostFiat',              domain:'postfiat.org',                          chain:'test', category:'other' },
  'pftmeech.xyz':                          { label:'PFT Meech',             domain:'pftmeech.xyz',                          chain:'test', category:'other' },
  'pft.xbtseal.com':                       { label:'PFT XBT Seal',          domain:'pft.xbtseal.com',                       chain:'test', category:'other' },
  'pft.wizbubba.xyz':                      { label:'PFT Wizbubba',          domain:'pft.wizbubba.xyz',                      chain:'test', category:'other' },
  'pft.permanentupperclass.com':           { label:'PFT Perm Upper Class',  domain:'pft.permanentupperclass.com',           chain:'test', category:'other' },
  'pft.g.money':                           { label:'PFT G.Money',           domain:'pft.g.money',                           chain:'test', category:'other' },
  'pft.akirax.xyz':                        { label:'PFT Akirax',            domain:'pft.akirax.xyz',                        chain:'test', category:'other' },
  'jollydinger.com':                       { label:'Jollydinger',           domain:'jollydinger.com',                       chain:'test', category:'other' },
  'auri0x.io':                             { label:'Auri0x',                domain:'auri0x.io',                             chain:'test', category:'other' },
  'app.w.ai':                              { label:'W.ai',                  domain:'app.w.ai',                              chain:'test', category:'other' },
};

/* ─── Validator geographic coordinates by public key ─── */
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

/* ─── Domain → geo lookup (covers all 127 mainnet validators from XRPScan data) ───
   Used as a third-tier geo fallback when key-based lookup fails.
   Coordinates are city-level approximations.
─── */
const DOMAIN_GEO = {
  /* ── UNL validators (rows 1–35) ── */
  'xrpscan.com':                               { lat:51.51,  lng:-0.13,   city:'London',           org:'XRPScan'               },
  'xrpl.aesthetes.art':                        { lat:52.37,  lng:4.90,    city:'Amsterdam',         org:'Aesthetes'             },
  'xrpkuwait.com':                             { lat:29.37,  lng:47.98,   city:'Kuwait City',       org:'XRP Kuwait'            },
  'xrpgoat.com':                               { lat:39.04,  lng:-77.49,  city:'Ashburn, VA',       org:'XRP Goat'              },
  'xrp.vet':                                   { lat:48.86,  lng:2.35,    city:'Paris',             org:'XRP Vet'               },
  'xrp.unic.ac.cy':                            { lat:35.17,  lng:33.37,   city:'Nicosia',           org:'Univ. of Nicosia'      },
  'xrp-validator.interledger.org':             { lat:40.71,  lng:-74.01,  city:'New York',          org:'Interledger Foundation'},
  'xpmarket.com':                              { lat:52.37,  lng:4.90,    city:'Amsterdam',         org:'XPMarket'              },
  'verum.eminence.im':                         { lat:51.51,  lng:-0.13,   city:'London',            org:'Eminence'              },
  'validator.xrpl.robertswarthout.com':        { lat:52.37,  lng:4.90,    city:'Amsterdam',         org:'R. Swarthout'          },
  'validator.xrpl-labs.com':                   { lat:52.37,  lng:4.90,    city:'Amsterdam',         org:'XRPL Labs'             },
  'validator.xrpl.app':                        { lat:52.37,  lng:4.90,    city:'Amsterdam',         org:'XRPL App'              },
  'validator.poli.usp.br':                     { lat:-23.55, lng:-46.63,  city:'São Paulo',         org:'USP'                   },
  'validator.gatehub.net':                     { lat:46.05,  lng:14.51,   city:'Ljubljana',         org:'Gatehub'               },
  'validator.aspired.nz':                      { lat:-36.86, lng:174.76,  city:'Auckland',          org:'Aspired NZ'            },
  'v2.xrpl-commons.org':                       { lat:48.86,  lng:2.35,    city:'Paris',             org:'XRPL Commons'          },
  'tequ.dev':                                  { lat:60.17,  lng:24.94,   city:'Helsinki',          org:'Tequ'                  },
  'squidrouter.com':                           { lat:37.77,  lng:-122.42, city:'San Francisco',     org:'Squid Router'          },
  'ripple.ittc.ku.edu':                        { lat:38.97,  lng:-95.24,  city:'Lawrence, KS',      org:'Univ. of Kansas'       },
  'ripple.com':                                { lat:37.77,  lng:-122.42, city:'San Francisco',     org:'Ripple'                },
  'peersyst.cloud':                            { lat:41.39,  lng:2.15,    city:'Barcelona',         org:'Peersyst'              },
  'onxrp.com':                                 { lat:51.51,  lng:-0.13,   city:'London',            org:'OnXRP'                 },
  'katczynski.net':                            { lat:52.23,  lng:21.01,   city:'Warsaw',            org:'Katczynski'            },
  'jon-nilsen.no':                             { lat:59.91,  lng:10.75,   city:'Oslo',              org:'Jon Nilsen'            },
  'ekiserrepe.es':                             { lat:40.42,  lng:-3.70,   city:'Madrid',            org:'Ekiserrepe'            },
  'cabbit.tech':                               { lat:51.51,  lng:-0.13,   city:'London',            org:'Cabbit'                },
  'bithomp.com':                               { lat:59.33,  lng:18.07,   city:'Stockholm',         org:'Bithomp'               },
  'aureusox.com':                              { lat:40.71,  lng:-74.01,  city:'New York',          org:'Aureus Ox'             },
  'arrington-xrp-capital.blockdaemon.com':     { lat:40.71,  lng:-74.01,  city:'New York',          org:'Blockdaemon'           },
  'anodos.finance':                            { lat:37.98,  lng:23.73,   city:'Athens',            org:'Anodos Finance'        },
  'bitso.com':                                 { lat:19.43,  lng:-99.13,  city:'Mexico City',       org:'Bitso'                 },
  'ripple.kenan-flagler.unc.edu':              { lat:35.90,  lng:-79.05,  city:'Chapel Hill, NC',   org:'UNC Kenan-Flagler'     },
  'ripplevalidator.uwaterloo.ca':              { lat:43.47,  lng:-80.54,  city:'Waterloo, ON',      org:'Univ. of Waterloo'     },
  'shadow.haas.berkeley.edu':                  { lat:37.87,  lng:-122.26, city:'Berkeley, CA',      org:'UC Berkeley Haas'      },
  'www.bitrue.com':                            { lat:1.35,   lng:103.82,  city:'Singapore',         org:'Bitrue'                },
  'xrp-col.anu.edu.au':                        { lat:-35.28, lng:149.13,  city:'Canberra',          org:'ANU'                   },

  /* ── Other mainnet validators (rows 68–127) ── */
  'xrpval.rawsec.de':                          { lat:51.17,  lng:10.45,   city:'Germany',           org:'Rawsec'                },
  'xrplvl.carbonvibe.com':                     { lat:51.51,  lng:-0.13,   city:'London',            org:'Carbon Vibe'           },
  'xrplvalidator.alloy.ee':                    { lat:59.44,  lng:24.75,   city:'Tallinn',           org:'Alloy'                 },
  'xrpl.uni.lu':                               { lat:49.61,  lng:6.13,    city:'Luxembourg',        org:'Univ. of Luxembourg'   },
  'xrpl.to':                                   { lat:48.86,  lng:2.35,    city:'Paris',             org:'XRPL.to'               },
  'xrpl.su':                                   { lat:55.75,  lng:37.62,   city:'Moscow',            org:'XRPL.su'               },
  'xrpl.sbivc.co.jp':                          { lat:35.69,  lng:139.69,  city:'Tokyo',             org:'SBI VC Trade'          },
  'xrpl-verification.flare.network':           { lat:51.51,  lng:-0.13,   city:'London',            org:'Flare Network'         },
  'xrpl-validator.7rev.dev':                   { lat:52.52,  lng:13.40,   city:'Berlin',            org:'7Rev'                  },
  'xrp.teacopula.com':                         { lat:39.04,  lng:-77.49,  city:'Ashburn, VA',       org:'Teacopula'             },
  'xrp.moneymindedapes.com':                   { lat:39.04,  lng:-77.49,  city:'Ashburn, VA',       org:'MoneyMindedApes'       },
  'xrp.hazza-systems.de':                      { lat:52.52,  lng:13.40,   city:'Berlin',            org:'Hazza Systems'         },
  'xrp.cs.uoregon.edu':                        { lat:44.05,  lng:-123.08, city:'Eugene, OR',        org:'Univ. of Oregon'       },
  'xrp.bpsqn.com':                             { lat:37.77,  lng:-122.42, city:'San Francisco',     org:'BPSQN'                 },
  'xrp-validator.grapedrop.xyz':               { lat:52.37,  lng:4.90,    city:'Amsterdam',         org:'Grapedrop'             },
  'xaodao.io':                                 { lat:1.35,   lng:103.82,  city:'Singapore',         org:'XaoDAO'                },
  'vl.xrpsalute.com':                          { lat:40.71,  lng:-74.01,  city:'New York',          org:'XRP Salute'            },
  'validator.ukcbt.org':                       { lat:51.51,  lng:-0.13,   city:'London',            org:'UKCBT'                 },
  'validator.sugarxrpl.com':                   { lat:37.77,  lng:-122.42, city:'San Francisco',     org:'SugarXRPL'             },
  'validator.boscaern.digital':                { lat:53.33,  lng:-6.25,   city:'Dublin',            org:'Boscaern'              },
  'trimaera.tech':                             { lat:48.86,  lng:2.35,    city:'Paris',             org:'Trimaera'              },
  'textrp.io':                                 { lat:1.35,   lng:103.82,  city:'Singapore',         org:'TextRP'                },
  'tesbert.com':                               { lat:39.04,  lng:-77.49,  city:'Ashburn, VA',       org:'Tesbert'               },
  'tachyon-xrpl-validator.github.io':          { lat:37.77,  lng:-122.42, city:'San Francisco',     org:'Tachyon'               },
  'solonation.io':                             { lat:1.35,   lng:103.82,  city:'Singapore',         org:'SoloNation'            },
  'smokydrip.com':                             { lat:39.04,  lng:-77.49,  city:'Ashburn, VA',       org:'SmokyDrip'             },
  'rippled-validator.us':                      { lat:39.04,  lng:-77.49,  city:'Ashburn, VA',       org:'rippled-validator.us'  },
  'rippleat.snt.uni.lu':                       { lat:49.61,  lng:6.13,    city:'Luxembourg',        org:'Univ. of Luxembourg'   },
  'ripple.uni.lu':                             { lat:49.61,  lng:6.13,    city:'Luxembourg',        org:'Univ. of Luxembourg'   },
  'ripple.j2b.com':                            { lat:37.77,  lng:-122.42, city:'San Francisco',     org:'J2B'                   },
  'rich-list.info':                            { lat:51.51,  lng:-0.13,   city:'London',            org:'Rich List'             },
  'proptoexchange.com':                        { lat:39.04,  lng:-77.49,  city:'Ashburn, VA',       org:'ProPtoExchange'        },
  'printscierge.com':                          { lat:39.04,  lng:-77.49,  city:'Ashburn, VA',       org:'Printscierge'          },
  'opulencex.io':                              { lat:1.35,   lng:103.82,  city:'Singapore',         org:'OpulenceX'             },
  'onledger.net':                              { lat:52.37,  lng:4.90,    city:'Amsterdam',         org:'OnLedger'              },
  'oclost.art':                                { lat:48.86,  lng:2.35,    city:'Paris',             org:'Oclost'                },
  'managednetwork.us':                         { lat:39.04,  lng:-77.49,  city:'Ashburn, VA',       org:'ManagedNetwork'        },
  'joshuahamsa.com':                           { lat:37.77,  lng:-122.42, city:'San Francisco',     org:'Joshua Hamsa'          },
  'grimmsxrpflow.jwscott.net':                 { lat:39.04,  lng:-77.49,  city:'Ashburn, VA',       org:'Grimm XRP Flow'        },
  'getlol.xyz':                                { lat:39.04,  lng:-77.49,  city:'Ashburn, VA',       org:'GetLol'                },
  'gen3labs.xyz':                              { lat:37.77,  lng:-122.42, city:'San Francisco',     org:'Gen3 Labs'             },
  'garveyvalid.com':                           { lat:40.71,  lng:-74.01,  city:'New York',          org:'Garvey'                },
  'easynpl.kr':                                { lat:37.57,  lng:126.98,  city:'Seoul',             org:'EasyNPL'               },
  'diseb.ewi.tudelft.nl':                      { lat:52.00,  lng:4.36,    city:'Delft',             org:'TU Delft'              },
  'datamossa.com':                             { lat:48.86,  lng:2.35,    city:'Paris',             org:'DataMossa'             },
  'crypto.unibe.ch':                           { lat:46.95,  lng:7.45,    city:'Bern',              org:'Univ. of Bern'         },
  'commonprefix.com':                          { lat:37.98,  lng:23.73,   city:'Athens',            org:'Common Prefix'         },
  'catalyze-research.com':                     { lat:51.51,  lng:-0.13,   city:'London',            org:'Catalyze Research'     },
  'catalog.org':                               { lat:37.77,  lng:-122.42, city:'San Francisco',     org:'Catalog'               },
  'blockchain.korea.ac.kr':                    { lat:37.57,  lng:126.98,  city:'Seoul',             org:'Korea Univ.'           },
  'astatiumprotocol.com':                      { lat:1.35,   lng:103.82,  city:'Singapore',         org:'Astatium Protocol'     },
  'ladykxrpl.mywire.org':                      { lat:39.04,  lng:-77.49,  city:'Ashburn, VA',       org:'LadyK XRPL'            },
  'eelap-p1201-xrp.abudhabi.nyu.edu':          { lat:24.47,  lng:54.37,   city:'Abu Dhabi',         org:'NYU Abu Dhabi'         },
  '589.clouds.hspeed.ch':                      { lat:47.38,  lng:8.54,    city:'Zurich',            org:'HSpeed'                },
  'xrp-validator.grapedrop.xyz':               { lat:52.37,  lng:4.90,    city:'Amsterdam',         org:'Grapedrop'             },
  'www.payonline.financial':                   { lat:55.75,  lng:37.62,   city:'Moscow',            org:'PayOnline'             },
};

/** Look up geo by domain name (case-insensitive, strips www.) */
function _geoByDomain(domain) {
  if (!domain) return null;
  const d = domain.toLowerCase().replace(/^www\./, '');
  return DOMAIN_GEO[d] ?? DOMAIN_GEO['www.' + d] ?? null;
}

const PUBLIC_NODES = [
  { lat:37.34, lng:-121.89, label:'s1.ripple.com',   city:'San Jose, CA', org:'Ripple'  },
  { lat:37.34, lng:-121.87, label:'s2.ripple.com',   city:'San Jose, CA', org:'Ripple'  },
  { lat:52.37, lng:4.91,    label:'xrplcluster.com', city:'Amsterdam',    org:'Cluster' },
  { lat:52.36, lng:4.89,    label:'xrpl.ws',         city:'Amsterdam',    org:'Cluster' },
];

/* ─── Validator category colours ─── */
const VAL_COLOR = {
  nunl:  { hex:'#ff5555', glow:'rgba(255,85,85,.4)',   label:'Negative UNL' },
  both:  { hex:'#50fa7b', glow:'rgba(80,250,123,.4)',  label:'UNL + dUNL'   },
  unl:   { hex:'#00fff0', glow:'rgba(0,255,240,.35)',  label:'UNL'          },
  dunl:  { hex:'#bd93f9', glow:'rgba(189,147,249,.4)', label:'dUNL only'    },
  other: { hex:'#ffb86c', glow:'rgba(255,184,108,.4)', label:'Other'        },
  pub:   { hex:'#50fa7b', glow:'rgba(80,250,123,.4)',  label:'Public Node'  },
};

/* ═══════════════════════════════════════════════════
   LIVE VALIDATOR REGISTRY
   Three-tier resolution, tried in order:
     1. Your backend proxy  → /api/v1/validatorregistry
     2. XRPScan direct      → api.xrpscan.com (CORS permitting)
     3. Hardcoded fallback  → FALLBACK_VALIDATORS (17 known)
═══════════════════════════════════════════════════ */

const XRPSCAN_DIRECT = 'https://api.xrpscan.com/api/v1/validatorregistry';

/** Live registry: Map<key → {label, domain, provider, lists, category, geo, meta}> */
let _registry       = new Map();
let _registryLists  = {};
let _registryAt     = 0;
let _registryOk     = false;
let _registrySource = 'fallback'; // 'proxy' | 'xrpscan' | 'fallback'

/**
 * Seed _registry from FALLBACK_VALIDATORS when the API is unreachable.
 * FALLBACK_VALIDATORS is keyed by domain; we create synthetic entries with
 * domain-as-key so the grid is populated. _classifyValidator drives category/chain.
 */
function _seedFallback() {
  if (_registryOk) return; // don't overwrite live data
  _registry.clear();
  for (const [domainKey, v] of Object.entries(FALLBACK_VALIDATORS)) {
    const domain = v.domain ?? domainKey;
    const clf    = _classifyValidator('', domain);
    const geo    = _geoByDomain(domain) ?? null;
    _registry.set(domainKey, {
      key:      domainKey,  // synthetic — domain as stand-in until real key known
      label:    v.label,
      domain,
      domainVerified: false,
      provider: v.provider ?? geo?.org ?? null,
      lists:    v.lists ?? [],
      category: clf.isUnl  ? 'unl'  : 'other',
      chain:    clf.chain,
      unl:      clf.isUnl,
      dunl:     false,
      geo,
      meta:     {},
      agreement: { '1h': null, '24h': null, '30d': null },
    });
  }
  _registrySource = 'fallback';
  _updateRegistryBadge({ ok: false, source: 'fallback', error: 'using hardcoded data — mount /api/v1 router' });
  const unlCount = [..._registry.values()].filter(v => v.category === 'unl').length;
  console.log(`[registry] fallback seeded — ${_registry.size} entries, ${unlCount} UNL`);
}

/* Cooldown — stop hammering a broken endpoint */
let _registryFailAt = 0;
const REGISTRY_FAIL_COOLDOWN_MS = 5 * 60 * 1000;

/**
 * _applyRegistryData — normalises both proxy + direct XRPScan responses.
 * ALWAYS calls _classifyValidator(key, domain) as the authoritative source of
 * truth for chain and UNL membership — never trusts the API's unl field.
 */
function _applyRegistryData(raw, source) {
  const items = Array.isArray(raw)
    ? raw
    : (raw.validators ?? raw.data ?? []);

  if (!items.length) throw new Error('Empty validators array');

  _registry.clear();
  for (const v of items) {
    const key = v.key
      ?? v.validation_public_key
      ?? v.master_key
      ?? v.signing_key
      ?? null;
    if (!key) continue;

    // Raw domain from API (may have mixed case or www prefix)
    const rawDomain = v.domain ?? null;
    const domain    = rawDomain ? rawDomain.toLowerCase().replace(/^www\./, '') : null;

    // ── Classification: API unl boolean is primary; domain lookup is secondary fallback ──
    const apiIsUnl = v.unl === true || v.unl === 1 || v.unl === 'true';
    const clf      = _classifyValidator(key, domain);
    const isUnl    = apiIsUnl || clf.isUnl;
    const chain    = clf.chain;   // 'main' | 'test'
    const category = isUnl ? 'unl' : 'other';

    // Best human-readable label
    const fb = Object.values(FALLBACK_VALIDATORS).find(f =>
      f.domain && f.domain.toLowerCase().replace(/^www\./, '') === domain
    );
    const label = fb?.label
      ?? v.label
      ?? v.account_name
      ?? v.name
      ?? (domain ?? null)
      ?? `${key.slice(0,8)}…${key.slice(-6)}`;

    const staticGeo = VALIDATOR_GEO[key] ?? _geoByDomain(domain) ?? null;
    const liveGeo   = v.geo?.lat != null && v.geo?.lng != null ? v.geo : null;
    const geo       = liveGeo ?? staticGeo;

    _registry.set(key, {
      key,
      label,
      domain:         rawDomain ?? null,
      domainVerified: !!(v.domainVerified ?? v.domain_verified),
      provider:       v.provider ?? geo?.org ?? fb?.provider ?? null,
      lists:          Array.isArray(v.lists) ? v.lists : [],
      category,
      chain,
      unl:            isUnl,
      dunl:           false,
      geo,
      version:        v.version ?? v.build_version ?? null,
      baseFee:        v.base_fee_xrp ?? v.base_fee ?? null,
      ownerReserve:   v.reserve_inc_xrp ?? v.owner_reserve ?? null,
      meta:           v.meta ?? {},
      agreement: v.agreement ?? {
        '1h':  _agr(v.agreement_1h  ?? v.agr_1h),
        '24h': _agr(v.agreement_24h ?? v.agr_24h),
        '30d': _agr(v.agreement_30d ?? v.agr_30d),
      },
    });
  }

  _registryLists  = raw.lists ?? {};
  _registryAt     = Date.now();
  _registryOk     = true;
  _registrySource = source;
  _registryFailAt = 0;

  const unlCount  = [..._registry.values()].filter(v => v.category === 'unl').length;
  const testCount = [..._registry.values()].filter(v => v.chain === 'test').length;
  console.log(`[registry] loaded ${_registry.size} validators from ${source} — ${unlCount} UNL, ${testCount} testnet`);
  _updateRegistryBadge({ ok: true, count: _registry.size, lists: _registryLists, source });
}

function _agr(block) {
  if (!block) return null;
  const total  = Number(block.total  ?? block.ledgers ?? 0);
  const missed = Number(block.missed ?? 0);
  const hit    = total - missed;
  const pct    = total > 0 ? ((hit / total) * 100).toFixed(1) : null;
  return { total, missed, hit, score: pct ? `${pct}%` : null, scoreRaw: block.score ?? null };
}

/** Fetch from /api/v1/validatorregistry; returns true on success */
async function _fetchRegistry(force = false) {
  const now = Date.now();

  if (!force && _registryOk && now - _registryAt < REGISTRY_CACHE_MS) return true;
  if (!force && !_registryOk && now - _registryFailAt < REGISTRY_FAIL_COOLDOWN_MS) return false;

  /* ── Tier 1: your backend proxy ── */
  console.log('[registry] trying tier 1 →', REGISTRY_URL);
  try {
    const ctrl = new AbortController();
    const tid  = setTimeout(() => ctrl.abort(), REGISTRY_TIMEOUT_MS);
    const res  = await fetch(REGISTRY_URL, { signal: ctrl.signal, headers: { Accept: 'application/json' } });
    clearTimeout(tid);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    _applyRegistryData(data, 'proxy');
    return true;
  } catch (proxyErr) {
    console.warn('[registry] tier 1 (proxy) failed:', proxyErr.message);
  }

  /* ── Tier 2: XRPScan direct ── */
  console.log('[registry] trying tier 2 →', XRPSCAN_DIRECT);
  try {
    const ctrl = new AbortController();
    const tid  = setTimeout(() => ctrl.abort(), REGISTRY_TIMEOUT_MS);
    const res  = await fetch(XRPSCAN_DIRECT, { signal: ctrl.signal });
    clearTimeout(tid);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const text = await res.text();
    console.log('[registry] tier 2 raw response (first 200):', text.slice(0, 200));
    const data = JSON.parse(text);
    const count = Array.isArray(data) ? data.length : (data.validators?.length ?? '?');
    console.log('[registry] tier 2 parsed — item count:', count);
    _applyRegistryData(data, 'xrpscan');
    return true;
  } catch (directErr) {
    console.warn('[registry] tier 2 (xrpscan direct) failed:', directErr.message);
    if (directErr.message.includes('Failed to fetch') || directErr.message.includes('CORS')) {
      console.warn('[registry] CORS blocked — mount the backend proxy route (see validatorregistry.js)');
    }
  }

  /* ── Tier 3: hardcoded fallback (17 known validators) ── */
  console.warn('[registry] all sources failed — showing', Object.keys(FALLBACK_VALIDATORS).length, 'hardcoded validators');
  _registryFailAt = Date.now();
  if (!_registryOk) _seedFallback();
  _updateRegistryBadge({ ok: false, source: 'fallback', error: 'all sources failed — mount /api/v1 router' });
  return false;
}

/* ── Browser console helper: window.debugRegistry() ── */
window.debugRegistry = async function() {
  console.group('🔍 Registry debug');
  console.log('Current source:', _registrySource);
  console.log('Validators loaded:', _registry.size);
  console.log('Registry ok:', _registryOk);
  console.log('Last fetch:', _registryAt ? new Date(_registryAt).toLocaleTimeString() : 'never');
  console.log('');
  console.log('Testing proxy →', REGISTRY_URL);
  try {
    const r = await fetch(REGISTRY_URL);
    const t = await r.text();
    console.log('  Status:', r.status, '— body preview:', t.slice(0, 300));
  } catch(e) { console.warn('  Failed:', e.message); }
  console.log('');
  console.log('Testing XRPScan direct →', XRPSCAN_DIRECT);
  try {
    const r = await fetch(XRPSCAN_DIRECT);
    const t = await r.text();
    console.log('  Status:', r.status, '— body preview:', t.slice(0, 300));
  } catch(e) { console.warn('  Failed:', e.message); }
  console.groupEnd();
  return { source: _registrySource, size: _registry.size, ok: _registryOk };
};

/** Registry lookup — returns entry or synthetic fallback object */
function _reg(key) {
  return _registry.get(key) ?? {
    key,
    label:    `${key.slice(0,10)}…${key.slice(-6)}`,
    domain:   null,
    provider: null,
    lists:    [],
    category: 'other',
    geo:      VALIDATOR_GEO[key] ?? null,
    meta:     {},
  };
}

/** Resolve geo for any registry entry — key lookup → domain lookup */
function _resolveGeo(entry) {
  if (!entry) return null;
  if (entry.geo?.lat != null) return entry.geo;
  const byKey = VALIDATOR_GEO[entry.key];
  if (byKey) return byKey;
  return _geoByDomain(entry.domain);
}

/** Computed key sets from live registry */
function _unlKeys()   { return [..._registry.values()].filter(v => (v.category === 'unl'  || v.category === 'both') && v.chain !== 'test').map(v => v.key); }
function _dunlKeys()  { return [..._registry.values()].filter(v => (v.category === 'dunl' || v.category === 'both') && v.chain !== 'test').map(v => v.key); }
function _otherKeys() { return [..._registry.values()].filter(v => v.category === 'other' && v.chain !== 'test').map(v => v.key); }
function _testKeys()  { return [..._registry.values()].filter(v => v.chain === 'test').map(v => v.key); }

/** Update the small registry status badge near the validator grid header */
function _updateRegistryBadge({ ok, count, lists, source, error }) {
  const el = $('m1-registry-badge');
  if (!el) return;
  if (ok) {
    const unlCount  = [..._registry.values()].filter(v => v.category === 'unl').length;
    const testCount = [..._registry.values()].filter(v => v.chain === 'test').length;
    const mainCount = count - testCount;
    el.textContent  = `${mainCount} mainnet · ${unlCount} UNL · ${testCount} testnet · live`;
    el.className    = 'registry-badge registry-badge--ok';
  } else {
    el.textContent  = source === 'fallback'
      ? `Fallback data · ${_registry.size} known · ${error ?? 'endpoint unreachable'}`
      : 'Refreshing…';
    el.className = 'registry-badge registry-badge--warn';
  }
}

/* ─── Module state ─── */
let _poll=null, _inited=false, _busy=false, _lastAt=0, _backoff=0, _latAt=0, _latRun=0;
let _info=null, _fee=null, _vals=null, _peers=null, _sigs={};
let _prevDiscon=null, _amendmentData={};
let _leafletMap=null, _mapMarkers=[], _mapNetId=null, _keyToMarker={};

/* ─── Validator grid tab state ─── */
let _valGridTab = 'unl'; // 'unl' | 'dunl' | 'others' | 'all'

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
  _seedFallback();              // Always available immediately
  _fetchRegistry(true);         // Kick off live fetch in background

  _injectValGridStyles();
  _injectNetworkMetricsPanels();

  window.addEventListener('xrpl-connected',    () => {
    _syncPoll();
    if (_vis()) {
      _refresh({force:true});
      measureLatency({force:false});
    }
  });

  window.addEventListener('xrpl-disconnected', () => {
    _stopPoll();
    _banner(null);
  });

  window.addEventListener('xrpl-ledger', e => {
    _accumulate(e.detail);
    if (_vis()) _liveCells(e.detail);
  });

  $('btn-network-refresh')?.addEventListener('click', () => {
    _refresh({force:true});
    _fetchRegistry(true);
    measureLatency({force:true});
  });

  document.querySelector('.dash-tab[data-tab="network"]')?.addEventListener('click', () => {
    _syncPoll();
    _refresh({force:true});
    _fetchRegistry(false);
    measureLatency({force:false});
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
    // Registry and XRPL data in parallel — registry won't block the rest
    await Promise.allSettled([
      _fetchRegistry(false),
      _doInfo(), _doFee(), _doVals(), _doPeers(), _doAmend(),
    ]);
    _m1(); _m2(); _m3(); _m4(); _alert(); _banner({info:_info, fee:_fee, vals:_vals});
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

  // Live trusted keys come from the rippled validators command
  const liveUnlKeys = vals?.trusted_validator_keys ?? [];

  // Registry-derived key sets (from /api/v1/validatorregistry)
  const regUnlKeys  = _unlKeys();
  const regDunlKeys = _dunlKeys();

  // Use live rippled keys as the authoritative UNL when available;
  // fall back to registry unl keys.
  const unlKeys  = liveUnlKeys.length ? liveUnlKeys : regUnlKeys;
  const dunlKeys = regDunlKeys;

  const quorum  = Number(vals?.validation_quorum ?? info?.validation_quorum ?? 0);
  const active  = unlKeys.length;
  const margin  = active - quorum;
  const qPct    = active > 0 ? (quorum/active)*100 : 0;

  // "Identified" = keys found in registry with a label/domain
  const identified = unlKeys.filter(k => _registry.has(k)).length;
  const overlap    = active > 0 ? Math.round((identified/active)*100) : 0;

  const cvg     = Number(info?.last_close?.converge_time_s ?? 0);
  const prop    = Number(info?.last_close?.proposers ?? 0);
  const prtcpPct= quorum > 0 ? Math.round((prop/quorum)*100) : 0;

  const nUnl    = Array.isArray(info?.negative_unl) ? info.negative_unl : [];

  const valsAvail = !!_vals;

  if (margin>=0 && margin<=3)            _sigs.quorumTight  = true;
  if (nUnl.length>0)                     _sigs.nUnlActive   = true;
  if (cvg>6)                             _sigs.slowConverge = true;
  if (prop>0 && quorum>0 && prop<quorum) _sigs.lowProposers = true;

  _t('m1-active',      valsAvail ? active : '—');
  _t('m1-quorum',      quorum > 0 ? quorum : '—');
  _t('m1-margin',      valsAvail ? (margin >= 0 ? margin : `−${Math.abs(margin)}`) : '—');
  _t('m1-overlap',     valsAvail ? `${overlap}%` : '—');
  _t('m1-known',       valsAvail ? `${identified} / ${active} identified` : '— (validators cmd unavailable)');
  _t('m1-proposers',   info?.last_close?.proposers != null ? prop : '—');
  _t('m1-particip',    quorum>0 && info?.last_close?.proposers != null ? `${prtcpPct}%` : '—');
  _t('m1-converge',    info?.last_close?.converge_time_s != null ? `${cvg.toFixed(2)}s` : '—');
  _t('m1-converge-avg',_bavg('converge')>0 ? `avg ${_bavg('converge').toFixed(2)}s` : '—');

  _bar('m1-qbar',    qPct,      qPct>90?'bar-danger':qPct>80?'bar-warn':'bar-ok');
  _bar('m1-obar',    overlap,   overlap<40?'bar-danger':overlap<70?'bar-warn':'bar-ok');
  _bar('m1-pbar',    prtcpPct,  prtcpPct<80?'bar-danger':prtcpPct<95?'bar-warn':'bar-ok');
  _bar('m1-cvgbar',  Math.min(100,(cvg/10)*100), cvg>6?'bar-danger':cvg>4?'bar-warn':'bar-ok');

  // ── Quorum ring visualisation ──
  _renderQuorumRing({ active, quorum, margin, nUnl, valsAvail });

  // Publisher list metadata (from live rippled response, enriched by registry)
  const pub = vals?.publisher_lists?.[0];
  const regList = _registryLists?.ripple ?? _registryLists?.xrplf ?? null;
  const listUri = pub?.uri ?? regList?.uri ?? '—';
  const listSeq = pub?.seq ?? regList?.seq ?? '—';
  _t('m1-vl-uri', listUri);
  _t('m1-vl-seq', listSeq);

  if (pub?.expiration || regList?.expiration) {
    const expEl = $('m1-vl-expiry');
    if (expEl) {
      const expDate = pub?.expiration ?? regList?.expiration;
      const days = Math.floor((new Date(expDate)-Date.now())/86400000);
      expEl.textContent = days>0 ? `Expires ${days}d` : '⚠ EXPIRED';
      expEl.className   = `expiry-pill ${days>30?'pill-ok':days>7?'pill-warn':'pill-bad'}`;
      expEl.style.display = '';
    }
  }

  // Negative UNL list (annotated with registry labels)
  const nUnlEl = $('m1-nunl-list');
  _t('m1-nunl-count', nUnl.length || '0');
  if (nUnlEl) {
    if (!nUnl.length) {
      nUnlEl.innerHTML = '<div class="nunl-empty">✓ No validators on Negative UNL</div>';
    } else {
      const provTally = {};
      nUnlEl.innerHTML = nUnl.map(key => {
        const rv = _reg(key);
        if (rv.provider) provTally[rv.provider] = (provTally[rv.provider]||0)+1;
        return `<div class="nunl-entry">
          <span class="nunl-dot"></span>
          <div class="nunl-info">
            <span class="nunl-label">${escHtml(rv.label)}</span>
            ${rv.domain ? `<span class="nunl-prov">${escHtml(rv.domain)}</span>` : ''}
          </div>
          <span class="nunl-key" onclick="navigator.clipboard?.writeText('${escHtml(key)}')">${key.slice(0,8)}...</span>
        </div>`;
      }).join('');
      const top = Object.entries(provTally).sort((a,b)=>b[1]-a[1])[0];
      if (top?.[1] > 1)
        nUnlEl.innerHTML += `<div class="nunl-alert">⚠ ${top[1]} offline validators share <b>${escHtml(top[0])}</b> — likely provider outage</div>`;
    }
  }

  _valGrid(unlKeys, dunlKeys, quorum, nUnl, valsAvail);

  // Map stats line
  const infoPeers = Number(_info?.peers ?? 0);
  _t('wm-stat-val',   valsAvail ? `${active} validators` : `${_registry.size} in registry`);
  _t('wm-stat-nunl',  `${nUnl.length} on nUNL`);
  _t('wm-stat-peers', `${_peers ? _peers.length : infoPeers} peers`);

  // All keys that have geo → show on map (UNL + dUNL + others with geo)
  const mapKeys = [..._registry.keys()];
  _renderWorldMap(unlKeys, dunlKeys, nUnl, _peers, !valsAvail);
}

/* ═══════════════════════════════════════════════════
   VALIDATOR GRID — tabbed (UNL / dUNL / Others / All)
═══════════════════════════════════════════════════ */
function _valGrid(unlKeys, dunlKeys, quorum, nUnl, valsAvail) {
  const grid = $('m1-val-grid');
  if (!grid) return;

  const unlSet  = new Set(unlKeys);
  const dunlSet = new Set(dunlKeys);
  const nSet    = new Set(nUnl);

  // Derive all groups directly from registry — don't rely solely on passed unlKeys
  // Registry categories (set by _classifyValidator) are the authoritative source
  const regUnlKeys  = _unlKeys();   // category === 'unl', chain !== 'test'
  const regTestKeys = _testKeys();  // chain === 'test'
  const regOtherKeys= _otherKeys(); // category === 'other', chain !== 'test'

  // For the UNL tab: prefer passed live keys (from rippled validators cmd) if available,
  // otherwise use registry-classified keys
  const effectiveUnl = unlKeys.length ? unlKeys : regUnlKeys;

  const allKeys     = [..._registry.keys()];
  const mainKeys    = allKeys.filter(k => (_registry.get(k)?.chain ?? 'main') === 'main');
  const testKeys    = regTestKeys;
  const otherKeys   = regOtherKeys;
  const namedUnl    = effectiveUnl.filter(k => !!(_reg(k).domain));
  const anonUnl     = effectiveUnl.filter(k => !(_reg(k).domain));
  const namedOther  = otherKeys.filter(k => !!(_reg(k).domain));
  const anonOther   = otherKeys.filter(k => !(_reg(k).domain));
  const withGeo     = allKeys.filter(k => !!_resolveGeo(_reg(k)));

  /* ── Tab strip ── */
  const tabs = [
    { id:'unl',    label:'UNL',     count: effectiveUnl.length, dot: 'unl'   },
    { id:'others', label:'Others',  count: otherKeys.length,    dot: 'other' },
    { id:'all',    label:'All',     count: mainKeys.length,     dot: null    },
    { id:'test',   label:'Testnet', count: testKeys.length,     dot: null    },
  ];

  const colMap = { unl:'#00fff0', dunl:'#bd93f9', both:'#50fa7b', nunl:'#ff5555', other:'#ffb86c' };

  const tabHtml = `<div class="vg-tabs" role="tablist">` +
    tabs.map(t =>
      `<button class="vg-tab ${_valGridTab===t.id?'vg-tab--active':''}" data-vgtab="${t.id}">
        ${t.dot ? `<span class="vg-tab-dot" style="background:${colMap[t.dot]}"></span>` : ''}
        ${escHtml(t.label)}
        <span class="vg-tab-count">${t.count}</span>
      </button>`
    ).join('') +
    `</div>`;

  /* ── Key list and section groups for active tab ── */
  let sections = [];
  let summaryTxt = '';

  if (_valGridTab === 'unl') {
    const nUnlKeys   = effectiveUnl.filter(k => nSet.has(k));
    const cleanNamed = namedUnl.filter(k => !nSet.has(k));
    const cleanAnon  = anonUnl.filter(k => !nSet.has(k));
    if (nUnlKeys.length) sections.push({ title: `⚠ Negative UNL (${nUnlKeys.length})`, keys: nUnlKeys, cls:'vgs-warn' });
    sections.push({ title: `Named UNL validators · ${cleanNamed.length}`, keys: cleanNamed });
    if (cleanAnon.length) sections.push({ title: `Key-only UNL validators · ${cleanAnon.length}`, keys: cleanAnon, collapsed: true });
    if (!effectiveUnl.length) sections.push({ title:'No UNL data', keys:[], notice:'Registry not loaded yet' });
    const src = valsAvail ? 'live rippled' : `registry (${_registrySource})`;
    summaryTxt = `${effectiveUnl.length} trusted · quorum ${quorum} · ${nUnl.length} on nUNL · source: ${src}`;

  } else if (_valGridTab === 'others') {
    sections.push({ title: `Named mainnet (non-UNL) · ${namedOther.length}`, keys: namedOther });
    if (anonOther.length) sections.push({ title: `Key-only mainnet · ${anonOther.length}`, keys: anonOther, collapsed: true });
    summaryTxt = `${otherKeys.length} mainnet validators not on UNL · source: ${_registrySource}`;

  } else if (_valGridTab === 'test') {
    const testNamed = testKeys.filter(k => !!_reg(k).domain);
    const testAnon  = testKeys.filter(k => !_reg(k).domain);
    if (testNamed.length) sections.push({ title: `Named testnet · ${testNamed.length}`, keys: testNamed });
    if (testAnon.length)  sections.push({ title: `Key-only testnet · ${testAnon.length}`, keys: testAnon, collapsed: true });
    summaryTxt = `${testKeys.length} testnet validators`;

  } else { // all mainnet + testnet
    sections.push({ title: `⭐ UNL · ${effectiveUnl.length}`, keys: effectiveUnl });
    sections.push({ title: `Other mainnet · ${otherKeys.length}`, keys: otherKeys, collapsed: true });
    if (testKeys.length) sections.push({ title: `Testnet · ${testKeys.length}`, keys: testKeys, collapsed: true });
    summaryTxt = `${mainKeys.length} mainnet · ${testKeys.length} testnet · ${withGeo.length} geo-located · source: ${_registrySource}`;
  }

  /* ── Render a single validator pill ── */
  function renderPill(key, idx) {
    const rv     = _reg(key);
    const onN    = nSet.has(key);
    const inUnl  = unlSet.has(key);
    const inDunl = dunlSet.has(key);
    const isTest = rv.chain === 'test';

    let catClass, catTag, catColor;
    if (onN)                   { catClass='vp-nunl';  catTag='nUNL';     catColor=colMap.nunl; }
    else if (inUnl && inDunl)  { catClass='vp-both';  catTag='UNL+dUNL'; catColor=colMap.both; }
    else if (inUnl)            { catClass='vp-unl';   catTag='UNL';      catColor=colMap.unl;  }
    else if (inDunl)           { catClass='vp-dunl';  catTag='dUNL';     catColor=colMap.dunl; }
    else                       { catClass='vp-other'; catTag='Other';    catColor=colMap.other;}

    const geo      = _resolveGeo(rv);
    const hasGeo   = !!geo;
    const locStr   = geo ? `📍 ${geo.city ?? ''}` : '';
    const domainLbl = rv.domain
      ? rv.domain.replace(/^www\./, '').replace(/^validator\./, '').replace(/^xrp\./, '')
      : null;
    const shortKey = `${key.slice(0,8)}…${key.slice(-6)}`;
    const numBadge = (inUnl && idx != null) ? `<span class="vg-num">${idx+1}</span>` : '';
    const agr = rv.agreement?.['24h'];
    const agrBadge = agr?.score
      ? `<span class="vg-agr" style="color:${parseFloat(agr.score)>=99?'#50fa7b':parseFloat(agr.score)>=95?'#ffb86c':'#ff5555'}" title="24h agreement">${agr.score}</span>`
      : '';

    return `<div class="vpill ${catClass} ${hasGeo?'vp-locatable':''}"
                 title="${escHtml([rv.label, rv.domain, geo?.city, key].filter(Boolean).join(' · '))}"
                 onclick="window.focusValidator('${escHtml(key)}')"
                 data-key="${escHtml(key)}">
      ${numBadge}
      <span class="vpdot" style="background:${catColor};box-shadow:0 0 5px ${catColor}55"></span>
      <div class="vptext">
        <span class="vplabel">${escHtml(domainLbl ?? rv.label ?? shortKey)}</span>
        ${locStr ? `<span class="vpprov vp-geo">${escHtml(locStr)}</span>` : ''}
      </div>
      <div class="vpactions">
        ${agrBadge}
        <span class="vntag vntag-cat" style="border-color:${catColor}44;color:${catColor}">${catTag}</span>
        ${isTest ? '<span class="vntag" style="opacity:.5">test</span>' : ''}
      </div>
    </div>`;
  }

  /* ── Render sections ── */
  let bodyHtml = '';
  sections.forEach(sec => {
    if (!sec.keys.length) return;
    const isUnlSection = sec.keys.some(k => unlSet.has(k));
    const pillsHtml = sec.keys.map((k, i) => renderPill(k, isUnlSection ? i : null)).join('');
    const collapseId = `vgs-${Math.random().toString(36).slice(2,8)}`;
    const startOpen  = !sec.collapsed;
    bodyHtml += `
      <div class="vg-section ${sec.cls ?? ''}">
        <button class="vg-section-hdr" onclick="
          const c=document.getElementById('${collapseId}');
          const open=c.style.display!=='none';
          c.style.display=open?'none':'';
          this.querySelector('.vg-chevron').textContent=open?'▶':'▼';
        ">
          <span class="vg-chevron">${startOpen ? '▼' : '▶'}</span>
          <span class="vg-sec-title">${escHtml(sec.title)}</span>
        </button>
        <div id="${collapseId}" class="vg-section-body" style="display:${startOpen?'':'none'}">
          ${pillsHtml}
        </div>
      </div>`;
  });

  if (!bodyHtml) bodyHtml = '<div class="nunl-empty">No validators in this view.</div>';

  grid.innerHTML = tabHtml + bodyHtml;
  _t('m1-val-summary', summaryTxt);

  /* ── Tab click handler ── */
  grid.querySelectorAll('.vg-tab').forEach(btn => {
    btn.addEventListener('click', e => {
      e.stopPropagation();
      const tab = btn.getAttribute('data-vgtab');
      if (tab) { _valGridTab = tab; _valGrid(unlKeys, dunlKeys, quorum, nUnl, valsAvail); }
    });
  });
}

/* ── focusValidator: fly map to validator + open popup ── */
/* ─── Client-side detail fetchers ─────────────────── */

async function _fetchValidatorDetail(key) {
  const hit = _detailCache.get(key);
  if (hit && Date.now() - hit.cachedAt < DETAIL_CACHE_MS) return hit.data;
  try {
    const ctrl = new AbortController();
    const tid  = setTimeout(() => ctrl.abort(), DETAIL_TIMEOUT_MS);
    const res  = await fetch(`${VALIDATOR_URL}/${encodeURIComponent(key)}`, { signal: ctrl.signal });
    clearTimeout(tid);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    _detailCache.set(key, { data, cachedAt: Date.now() });
    return data;
  } catch { return null; }
}

async function _fetchValidatorReports(key) {
  const hit = _reportsCache.get(key);
  if (hit && Date.now() - hit.cachedAt < DETAIL_CACHE_MS) return hit.data;
  try {
    const ctrl = new AbortController();
    const tid  = setTimeout(() => ctrl.abort(), DETAIL_TIMEOUT_MS);
    const res  = await fetch(`${VALIDATOR_URL}/${encodeURIComponent(key)}/reports`, { signal: ctrl.signal });
    clearTimeout(tid);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    const reports = data.reports ?? data ?? [];
    _reportsCache.set(key, { data: reports, cachedAt: Date.now() });
    return reports;
  } catch { return []; }
}

async function _fetchNodeDetail(key) {
  const hit = _nodeDetailCache.get(key);
  if (hit && Date.now() - hit.cachedAt < DETAIL_CACHE_MS) return hit.data;
  try {
    const ctrl = new AbortController();
    const tid  = setTimeout(() => ctrl.abort(), DETAIL_TIMEOUT_MS);
    const res  = await fetch(`${NODE_URL}/${encodeURIComponent(key)}`, { signal: ctrl.signal });
    clearTimeout(tid);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    _nodeDetailCache.set(key, { data, cachedAt: Date.now() });
    return data;
  } catch { return null; }
}

/* ── focusValidator: fly map + fetch live detail ── */
window.focusValidator = async function(key) {
  const rv  = _reg(key);
  const geo = _resolveGeo(rv);

  // Highlight pill
  document.querySelectorAll('.vpill').forEach(el => el.classList.remove('vp-active'));
  const pill = document.querySelector(`.vpill[data-key="${CSS.escape(key)}"]`);
  if (pill) {
    pill.classList.add('vp-active');
    pill.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  // Open detail drawer immediately (with what we have), then enrich async
  _openValidatorDrawer(key, rv, null);

  // Kick off detail + reports fetch in parallel (non-blocking)
  _fetchValidatorDetail(key).then(detail => {
    if (detail) _openValidatorDrawer(key, rv, detail);
  });

  // Fly map
  if (!geo) {
    const container = $('world-map-container');
    if (container) {
      const old = container.querySelector('.wm-no-geo');
      if (old) old.remove();
      const notice = document.createElement('div');
      notice.className = 'wm-no-geo';
      notice.textContent = `📍 ${rv.label} — geographic location unknown`;
      container.appendChild(notice);
      setTimeout(() => notice.remove(), 3500);
    }
    return;
  }

  const mapSection = $('world-map-container');
  if (mapSection) mapSection.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

  if (_leafletMap) {
    _leafletMap.flyTo([geo.lat, geo.lng], 6, { duration: 1.2 });
    setTimeout(() => {
      const m = _keyToMarker[key];
      if (m) m.openPopup();
    }, 1300);
  }
};

/* ── Validator detail drawer ── */
function _openValidatorDrawer(key, rv, detail) {
  const overlay = $('amend-modal-overlay');
  const body    = $('amend-modal-body');
  if (!overlay || !body) return;

  // Merge registry data + API detail — registry is always more trusted for category/chain
  const d       = detail ?? {};
  const label   = rv.label   ?? d.label   ?? d.account_name ?? key.slice(0,16) + '…';
  const domain  = rv.domain  ?? d.domain  ?? null;
  const chain   = rv.chain   ?? d.chain   ?? 'main';
  const category= rv.category ?? 'other';
  const col     = VAL_COLOR[category] ?? VAL_COLOR.other;
  const geo     = _resolveGeo(rv);
  const isUnl   = rv.unl   || category === 'unl'  || category === 'both';
  const isDunl  = rv.dunl  || category === 'dunl' || category === 'both';
  const verified = (rv.domainVerified || d.domain_verified) ? '✓ Verified' : (domain ? 'Unverified' : '—');

  // Agreement — prefer registry data (from API parse), fall back to detail
  const agr = rv.agreement ?? d.agreement ?? {};

  const loading = !detail && !rv.agreement?.['24h'];

  function agrRow(lbl, block) {
    if (!block || !block.total) return `<div class="adm-mi"><span class="adm-mk">${lbl}</span><span class="adm-mv" style="opacity:.5">—</span></div>`;
    const score = parseFloat(block.score) || 0;
    const cls   = score >= 99 ? 'color:#50fa7b' : score >= 95 ? 'color:#ffb86c' : 'color:#ff5555';
    return `<div class="adm-mi">
      <span class="adm-mk">${lbl}</span>
      <span class="adm-mv mono" style="${cls}">${block.score ?? '—'}
        <span style="opacity:.55;font-size:10px;font-weight:400"> · ${block.missed ?? 0} missed / ${block.total ?? 0}</span>
      </span>
    </div>`;
  }

  function infoRow(k, v, mono=false) {
    if (!v && v !== 0) return '';
    return `<div class="adm-mi"><span class="adm-mk">${k}</span><span class="adm-mv ${mono?'mono':''}">${escHtml(String(v))}</span></div>`;
  }

  // Reports mini-chart
  const reportsHit = _reportsCache.get(key);
  const reports    = reportsHit?.data?.slice(-14) ?? [];
  const miniChart  = reports.length
    ? `<div class="adm-section">
        <div class="adm-slbl">Ledger agreement — last ${reports.length} days</div>
        <div style="display:flex;gap:2px;align-items:flex-end;height:32px;margin-top:6px;">
          ${reports.map(r => {
            const missed = Number(r.missed ?? r.miss ?? 0);
            const total  = Number(r.total ?? r.ledgers ?? 1);
            const pct    = total > 0 ? ((total-missed)/total)*100 : 100;
            const h      = Math.round(4 + (pct/100)*28);
            const c      = pct >= 99 ? '#50fa7b' : pct >= 95 ? '#ffb86c' : '#ff5555';
            return `<div title="${r.date ?? ''} · ${pct.toFixed(1)}% (${missed} missed)" style="flex:1;height:${h}px;background:${c};border-radius:2px 2px 0 0;opacity:.85;transition:opacity .15s" onmouseover="this.style.opacity=1" onmouseout="this.style.opacity=.85"></div>`;
          }).join('')}
        </div>
      </div>` : '';

  // Category badge styling
  const catLabel = category === 'unl' ? '⭐ UNL' : category === 'both' ? '⭐ UNL + dUNL' : category === 'nunl' ? '⚠ Neg-UNL' : category === 'dunl' ? 'dUNL' : 'Non-UNL';
  const catStyle = category === 'unl' || category === 'both' ? 'background:rgba(0,255,240,.15);color:#00fff0;border-color:#00fff044'
    : category === 'nunl' ? 'background:rgba(255,85,85,.15);color:#ff5555;border-color:#ff555544'
    : 'background:rgba(255,184,108,.1);color:#ffb86c;border-color:#ffb86c44';

  const xrpscanUrl = domain
    ? `https://xrpscan.com/validator/${encodeURIComponent(domain)}`
    : `https://xrpscan.com/validator/${encodeURIComponent(key)}`;

  body.innerHTML = `
    <div class="adm-header" style="border-bottom:1px solid rgba(255,255,255,.08);padding-bottom:12px;margin-bottom:12px;">
      <div class="adm-title-row" style="display:flex;align-items:flex-start;gap:10px;margin-bottom:6px;">
        <div style="flex:1">
          <h2 class="adm-title" style="color:${col.hex};margin:0;font-size:17px;font-weight:700">${escHtml(label)}</h2>
          ${domain ? `<div style="font-size:12px;opacity:.65;margin-top:2px">${escHtml(domain)} <span style="opacity:.6">${escHtml(verified)}</span></div>` : ''}
        </div>
        <span style="font-size:11px;padding:3px 8px;border-radius:10px;border:1px solid;flex-shrink:0;font-weight:600;${catStyle}">${catLabel}</span>
      </div>
      <div style="font-family:monospace;font-size:10px;opacity:.45;word-break:break-all;cursor:pointer" title="Click to copy" onclick="navigator.clipboard?.writeText('${escHtml(key)}');this.style.opacity=.8;setTimeout(()=>this.style.opacity=.45,800)">${escHtml(key)}</div>
    </div>

    <div class="adm-section">
      <div class="adm-slbl">Identity &amp; Status</div>
      ${infoRow('Chain',   chain === 'main' ? '🌐 Mainnet' : '🧪 Testnet')}
      ${infoRow('UNL',     isUnl  ? '⭐ Yes — Ripple UNL' : 'No')}
      ${infoRow('dUNL',    isDunl ? '✓ Yes — XRPL Foundation UNL' : 'No')}
      ${geo ? infoRow('Location', [geo.city, geo.country].filter(Boolean).join(', ') || '—') : ''}
      ${geo?.org ? infoRow('Provider', geo.org) : ''}
      ${infoRow('Version',    rv.version  ?? d.version  ?? d.build_version ?? null)}
      ${infoRow('Base fee',   rv.baseFee  ?? d.base_fee_xrp ?? d.baseFee ?? null)}
      ${infoRow('Ledger',     d.currentIndex ? Number(d.currentIndex).toLocaleString() : null, true)}
    </div>

    <div class="adm-section">
      <div class="adm-slbl">Ledger Agreement ${loading ? '<span style="opacity:.4;font-size:10px;margin-left:6px">loading…</span>' : ''}</div>
      ${agrRow('1-hour',  agr['1h']  ?? d.agreement?.['1h'])}
      ${agrRow('24-hour', agr['24h'] ?? d.agreement?.['24h'])}
      ${agrRow('30-day',  agr['30d'] ?? d.agreement?.['30d'])}
    </div>

    ${miniChart}

    <div class="adm-footer" style="display:flex;gap:10px;margin-top:12px;padding-top:10px;border-top:1px solid rgba(255,255,255,.07)">
      <a class="adm-link" href="${xrpscanUrl}" target="_blank" rel="noopener noreferrer">↗ XRPScan</a>
      <button class="adm-link" style="background:none;border:none;cursor:pointer;color:inherit;padding:0" onclick="window._loadValidatorReports('${escHtml(key)}')">📊 Load reports</button>
      ${geo?.lat != null ? `<button class="adm-link" style="background:none;border:none;cursor:pointer;color:inherit;padding:0" onclick="window.closeAmendModal();setTimeout(()=>window.focusValidator('${escHtml(key)}'),200)">📍 Show on map</button>` : ''}
    </div>`;

  overlay.style.display = 'flex';
  overlay.addEventListener('click', e => { if (e.target === overlay) window.closeAmendModal(); }, { once: true });
}

window._loadValidatorReports = async function(key) {
  const rv = _reg(key);
  await _fetchValidatorReports(key);
  _openValidatorDrawer(key, rv, _detailCache.get(key)?.data ?? null);
};

/* ─── Quorum Ring visualiser ─── */
function _renderQuorumRing({active, quorum, margin, nUnl, valsAvail}) {
  const el = $('m1-quorum-ring'); if (!el) return;
  if (!valsAvail || !quorum || !active) {
    el.innerHTML = '<div style="opacity:.4;font-size:12px;text-align:center;padding:16px">Connect to view quorum</div>';
    return;
  }

  const radius   = 44;
  const circumf  = 2 * Math.PI * radius;
  const nUnlSet  = new Set(nUnl);
  const online   = active - nUnl.length;
  const offline  = nUnl.length;
  const spare    = Math.max(0, active - quorum);
  const needed   = quorum;
  const marginColor = margin <= 0 ? '#ff5555' : margin <= 3 ? '#ffb86c' : '#50fa7b';

  // Arc fractions
  const onlinePct  = active > 0 ? online  / active : 0;
  const offlinePct = active > 0 ? offline / active : 0;

  // Build SVG ring — three arcs: quorum zone, margin zone, offline zone
  const qPct    = active > 0 ? quorum / active : 0;
  const mPct    = active > 0 ? Math.max(0, margin) / active : 0;
  const nPct    = active > 0 ? offline / active : 0;

  function arc(startFrac, lenFrac, color, width=8) {
    if (lenFrac <= 0) return '';
    const start = startFrac * circumf;
    const len   = lenFrac * circumf;
    return `<circle r="${radius}" cx="50" cy="50" fill="none"
      stroke="${color}" stroke-width="${width}" opacity=".85"
      stroke-dasharray="${len} ${circumf - len}"
      stroke-dashoffset="${circumf - start}"
      stroke-linecap="round"
      style="transform-origin:50px 50px;transform:rotate(-90deg)"/>`;
  }

  el.innerHTML = `
    <div class="qr-wrap">
      <svg viewBox="0 0 100 100" width="100" height="100" style="overflow:visible">
        <!-- Background ring -->
        <circle r="${radius}" cx="50" cy="50" fill="none" stroke="rgba(255,255,255,.06)" stroke-width="9"/>
        <!-- Quorum zone (required validators) -->
        ${arc(0, qPct, 'rgba(0,255,240,.25)', 9)}
        <!-- Margin zone (extra validators) -->
        ${arc(qPct, mPct, '#50fa7b', 9)}
        <!-- Negative UNL (offline) -->
        ${nPct > 0 ? arc(qPct+mPct, nPct, '#ff5555', 9) : ''}
        <!-- Centre text -->
        <text x="50" y="45" text-anchor="middle" fill="${marginColor}" font-size="18" font-weight="700" font-family="monospace">${active}</text>
        <text x="50" y="57" text-anchor="middle" fill="rgba(255,255,255,.45)" font-size="9">validators</text>
      </svg>
      <div class="qr-legend">
        <div class="qr-leg-row"><span class="qr-dot" style="background:rgba(0,255,240,.5)"></span>Required for quorum <strong>${quorum}</strong></div>
        <div class="qr-leg-row"><span class="qr-dot" style="background:#50fa7b"></span>Margin <strong style="color:${marginColor}">${Math.max(0,margin)}</strong></div>
        ${offline > 0 ? `<div class="qr-leg-row"><span class="qr-dot" style="background:#ff5555"></span>Offline (nUNL) <strong style="color:#ff5555">${offline}</strong></div>` : ''}
        <div class="qr-leg-row" style="margin-top:6px;border-top:1px solid rgba(255,255,255,.06);padding-top:6px">
          <span style="opacity:.5;font-size:10px">Need ${quorum} · have ${active} · ${margin > 0 ? margin+' can fail safely' : '⚠ AT QUORUM LIMIT'}</span>
        </div>
      </div>
    </div>`;
}

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
      let total=0; const dur={};
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

  const peerCount = info?.peers != null ? Number(info.peers) : null;
  const peerKnown = peerCount != null;
  let ib=0, ob=0, peersDetailed=false;
  if (_peers) {
    _peers.forEach(p => { if (p.inbound===true) ib++; else ob++; });
    peersDetailed = true;
  }

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
   MODULE 3 — NETWORK CONGESTION & SPAM DEFENSE
   Tracks fee pressure, TX queue health, ledger bloat,
   and burn-rate anomalies as network-health indicators.
═══════════════════════════════════════════════════ */
function _m3() {
  const fee = _fee;

  const minFee  = Number(fee?.drops?.minimum_fee     ?? 10);
  const openFee = Number(fee?.drops?.open_ledger_fee ?? 10);
  const medFee  = Number(fee?.drops?.median_fee      ?? 10);
  const baseFee = Number(fee?.drops?.base_fee        ?? 10);

  const curSz   = Number(fee?.current_ledger_size  ?? 0);
  const expSz   = Number(fee?.expected_ledger_size ?? 1);
  const curQ    = Number(fee?.current_queue_size   ?? 0);
  const maxQ    = Number(fee?.max_queue_size        ?? 1);
  const qPct    = maxQ > 0 ? Math.round((curQ / maxQ) * 100) : 0;
  const szRatio = expSz > 0 ? curSz / expSz : 1;

  const avgFee  = _bavg('fees');
  const devPct  = avgFee > 0 ? Math.round(((openFee - avgFee) / avgFee) * 100) : 0;
  // Spam index: logarithmic scale — 10 drops = 0, 10k drops ≈ 100
  const spamIdx = Math.min(100, Math.round(Math.log2(Math.max(1, openFee / 10)) * 14));

  // Raise adversarial signals
  if (openFee > minFee * 10) _sigs.feeSpike      = true;
  if (qPct > 80)             _sigs.queuePressure = true;
  if (szRatio > 2)           _sigs.spamLedger    = true;

  // Burn-rate anomaly (z-score on rolling window)
  const rb    = _bl.burnDrops.slice(-10);
  const avgB  = rb.length ? rb.reduce((a, b) => a + b, 0) / rb.length : 0;
  const sdB   = _stddev(_bl.burnDrops);
  const meanB = _bavg('burnDrops');
  const zB    = sdB > 0 && _bl.burnDrops.length > 5
    ? ((avgB - meanB) / sdB).toFixed(2) : '0.00';
  const anomB = Math.min(100, Math.abs(Number(zB)) * 20);
  if (Math.abs(Number(zB)) > 3) _sigs.burnAnomaly = true;

  // ── Pressure badge ──
  const pressure = openFee > 5000 ? 'Severe'
    : openFee > 500  ? 'High'
    : openFee > 100  ? 'Elevated'
    : openFee > 20   ? 'Normal' : 'Minimal';
  const pressCols = { Severe:'#ff5555', High:'#ff9955', Elevated:'#ffb86c', Normal:'#50fa7b', Minimal:'#6272a4' };
  const pressCol  = pressCols[pressure] ?? '#50fa7b';

  const prEl = $('m3-pressure');
  if (prEl) { prEl.textContent = pressure; prEl.className = `pressure-badge p-${pressure.toLowerCase()}`; }

  // ── Fee levels ──
  _t('m3-open',    `${openFee} drops`);
  _t('m3-med',     `${medFee} drops`);
  _t('m3-base',    `${baseFee} drops`);
  _t('m3-devpct',  `${devPct > 0 ? '+' : ''}${devPct}% vs baseline`);

  // ── Congestion indicators ──
  _t('m3-spam',      `${spamIdx} / 100`);
  _t('m3-qsize',     `${curQ} / ${maxQ}`);
  _t('m3-qpct',      `${qPct}%`);
  _t('m3-szratio',   `${szRatio.toFixed(2)}×`);
  _t('m3-curledger', `${curSz} txs`);
  _t('m3-expledger', `${expSz} expected`);
  _t('m3-burn',      avgB > 0 ? `${(avgB / 1e6).toFixed(4)} XRP / ledger` : '—');
  _t('m3-burnz',     `z = ${zB}`);

  // ── Progress bars ──
  _bar('m3-spam-bar', spamIdx, spamIdx > 70 ? 'bar-danger' : spamIdx > 40 ? 'bar-warn' : 'bar-ok');
  _bar('m3-q-bar',    qPct,    qPct > 80 ? 'bar-danger' : qPct > 50 ? 'bar-warn' : 'bar-ok');
  _bar('m3-sz-bar',   Math.min(100, szRatio * 50),
       szRatio > 2 ? 'bar-danger' : szRatio > 1.5 ? 'bar-warn' : 'bar-ok');
  _bar('m3-burn-bar', anomB, anomB > 60 ? 'bar-danger' : anomB > 30 ? 'bar-warn' : 'bar-ok');

  // ── Contextual congestion summary card ──
  const congEl = $('m3-congestion-summary');
  if (congEl) {
    const lines = [];
    if (szRatio > 2)  lines.push({ icon:'🚨', txt:`Ledger ${szRatio.toFixed(1)}× normal size — possible spam burst`, col:'#ff5555' });
    if (qPct > 80)    lines.push({ icon:'⚠',  txt:`TX queue ${qPct}% full — fee surge imminent`, col:'#ffb86c' });
    if (spamIdx > 70) lines.push({ icon:'⚠',  txt:`Spam index ${spamIdx}/100 — elevated DDoS risk`, col:'#ffb86c' });
    if (Math.abs(Number(zB)) > 3) lines.push({ icon:'📉', txt:`Burn rate z=${zB} — resource exhaustion pattern`, col:'#ff9955' });
    if (devPct > 200) lines.push({ icon:'💸', txt:`Open fee ${devPct}% above baseline — network stress`, col:'#ffb86c' });
    congEl.innerHTML = lines.length
      ? lines.map(l => `<div class="cong-line"><span>${l.icon}</span><span style="color:${l.col}">${escHtml(l.txt)}</span></div>`).join('')
      : `<div class="cong-clear"><span style="color:#50fa7b">✓</span> No congestion signals — network traffic is normal</div>`;
  }
}

function _frow(id, drops, ref) {
  const row=$(id); if (!row) return;
  const n=Number(drops);
  const v=row.querySelector('.fr-v'), b=row.querySelector('.fr-fill');
  if (v) v.textContent=n>=1_000_000 ? `${(n/1e6).toFixed(4)} XRP` : `${n} drops`;
  if (b) b.style.width=`${Math.min(100,(n/Math.max(ref,2000))*100)}%`;
}

/* ═══════════════════════════════════════════════════
   MODULE 4 — DECENTRALIZATION & VERSION DISTRIBUTION
═══════════════════════════════════════════════════ */
function _m4() {
  // ── Version distribution from registry ──
  const versionMap = {};
  let versionTotal = 0;
  for (const rv of _registry.values()) {
    if (rv.chain === 'test') continue;
    const v = rv.version ?? 'unknown';
    versionMap[v] = (versionMap[v] ?? 0) + 1;
    versionTotal++;
  }
  // Also fold in peer versions
  const peerVersionMap = {};
  let peerTotal = 0;
  if (Array.isArray(_peers)) {
    for (const p of _peers) {
      const v = (p.version ?? 'unknown').replace(/rippled-/i,'').split(' ')[0];
      peerVersionMap[v] = (peerVersionMap[v] ?? 0) + 1;
      peerTotal++;
    }
  }

  const vdEl = $('m4-version-dist');
  if (vdEl && versionTotal > 0) {
    const sorted = Object.entries(versionMap).sort((a,b) => b[1]-a[1]);
    const latest = sorted[0]?.[0] ?? '?';
    const latestPct = versionTotal > 0 ? Math.round((sorted[0]?.[1] ?? 0) / versionTotal * 100) : 0;
    const vColors = ['#00fff0','#50fa7b','#ffb86c','#bd93f9','#ff5555','#8be9fd'];
    vdEl.innerHTML = sorted.slice(0, 6).map(([ver, n], i) => {
      const pct = Math.round(n/versionTotal*100);
      const c = vColors[i % vColors.length];
      const isBeta = ver.includes('beta') || ver.includes('rc') || ver.includes('RC');
      return `<div class="vd-row">
        <div class="vd-ver-label">
          <span style="color:${c};font-weight:600">${escHtml(ver)}</span>
          ${isBeta ? '<span class="vd-beta-tag">beta</span>' : ''}
        </div>
        <div class="vd-bar-wrap">
          <div class="vd-bar-fill" style="width:${pct}%;background:${c};opacity:.75"></div>
        </div>
        <span class="vd-count">${n} <span style="opacity:.5">(${pct}%)</span></span>
      </div>`;
    }).join('') + `<div class="vd-summary">${versionTotal} validators · ${sorted.length} versions · ${latestPct}% on latest (${escHtml(latest)})</div>`;
  }

  // ── Geographic distribution ──
  const regionMap = { 'North America':0, 'Europe':0, 'Asia Pacific':0, 'Middle East':0, 'South America':0, 'Other':0 };
  function _latToRegion(lat, lng) {
    if (lat > 15 && lng < -30)  return 'North America';
    if (lat > -60 && lng < -30) return 'South America';
    if (lat > 35 && lng > -30 && lng < 60)  return 'Europe';
    if (lat > 10 && lng >= 60 && lng < 150) return 'Asia Pacific';
    if (lat >= -40 && lng >= 110)            return 'Asia Pacific';
    if (lat > 10 && lat < 40 && lng >= 30 && lng < 70) return 'Middle East';
    return 'Other';
  }
  let geoTotal = 0;
  for (const rv of _registry.values()) {
    if (rv.chain === 'test') continue;
    const geo = _resolveGeo(rv);
    if (!geo?.lat) continue;
    const region = _latToRegion(geo.lat, geo.lng);
    regionMap[region] = (regionMap[region] ?? 0) + 1;
    geoTotal++;
  }
  const geoEl = $('m4-geo-dist');
  if (geoEl && geoTotal > 0) {
    const rColors = { 'North America':'#00fff0','Europe':'#50fa7b','Asia Pacific':'#bd93f9','Middle East':'#ffb86c','South America':'#8be9fd','Other':'#6272a4' };
    const sorted = Object.entries(regionMap).filter(([,n])=>n>0).sort((a,b)=>b[1]-a[1]);
    const hhi = sorted.reduce((s,[,n]) => s + (n/geoTotal)**2, 0); // Herfindahl index
    const concentration = hhi > 0.4 ? 'Concentrated' : hhi > 0.25 ? 'Moderate' : 'Distributed';
    const concColor = hhi > 0.4 ? '#ff5555' : hhi > 0.25 ? '#ffb86c' : '#50fa7b';
    geoEl.innerHTML = sorted.map(([region, n]) => {
      const pct = Math.round(n/geoTotal*100);
      const c = rColors[region] ?? '#6272a4';
      return `<div class="vd-row">
        <span class="vd-ver-label" style="color:${c};font-weight:600">${escHtml(region)}</span>
        <div class="vd-bar-wrap">
          <div class="vd-bar-fill" style="width:${pct}%;background:${c};opacity:.65"></div>
        </div>
        <span class="vd-count">${n} <span style="opacity:.5">(${pct}%)</span></span>
      </div>`;
    }).join('') + `<div class="vd-summary">${geoTotal} geo-located · <span style="color:${concColor}">${concentration}</span> (HHI ${hhi.toFixed(2)})</div>`;
  }

  // ── Provider concentration ──
  const provMap = {};
  for (const rv of _registry.values()) {
    if (rv.chain === 'test') continue;
    const geo = _resolveGeo(rv);
    const prov = rv.provider ?? geo?.org ?? 'Unknown';
    // Normalise to infrastructure provider
    const infra = prov.match(/AWS|Amazon/i) ? 'AWS' : prov.match(/Azure|Microsoft/i) ? 'Azure'
      : prov.match(/GCP|Google/i) ? 'GCP' : prov.match(/Hetzner/i) ? 'Hetzner'
      : prov.match(/OVH/i) ? 'OVH' : prov.match(/Cloudflare/i) ? 'Cloudflare'
      : prov.match(/Equinix/i) ? 'Equinix' : prov.match(/NTT/i) ? 'NTT'
      : prov.match(/Ripple/i) ? 'Ripple' : 'Other';
    provMap[infra] = (provMap[infra] ?? 0) + 1;
  }
  const provEl = $('m4-provider-dist');
  if (provEl) {
    const provTotal = Object.values(provMap).reduce((a,b)=>a+b, 0);
    if (provTotal > 0) {
      const sorted = Object.entries(provMap).sort((a,b)=>b[1]-a[1]);
      const pColors = ['#ff5555','#ffb86c','#50fa7b','#00fff0','#bd93f9','#8be9fd','#6272a4'];
      provEl.innerHTML = sorted.slice(0,7).map(([p,n],i) => {
        const pct = Math.round(n/provTotal*100);
        const c = pColors[i % pColors.length];
        const warn = pct > 33 ? '⚠ ' : '';
        return `<div class="vd-row">
          <span class="vd-ver-label" style="color:${c};font-weight:600">${warn}${escHtml(p)}</span>
          <div class="vd-bar-wrap">
            <div class="vd-bar-fill" style="width:${pct}%;background:${c};opacity:.7;${pct>33?'box-shadow:0 0 6px '+c+'88':''}"></div>
          </div>
          <span class="vd-count">${n} <span style="opacity:.5">(${pct}%)</span></span>
        </div>`;
      }).join('');
    }
  }
}

/* ═══════════════════════════════════════════════════
   AMENDMENT PIPELINE
═══════════════════════════════════════════════════ */
/* Amendment pipeline tab state */
let _amendTab = 'pending'; // 'pending' | 'active' | 'vetoed' | 'all'

function _renderAmend(features) {
  const el=$('amendment-list'); if (!el) return;
  const hdr=$('amend-pipeline-header');

  const all = Object.entries(features).map(([hash,f])=>({hash,...f}));
  const active  = all.filter(f=>f.enabled);
  const pending = all.filter(f=>!f.enabled&&!f.vetoed).sort((a,b)=>(b.count??0)-(a.count??0));
  const vetoed  = all.filter(f=>f.vetoed);
  const majority= pending.filter(f=>f.majority);
  const nearThresh = pending.filter(f=>!f.majority && (f.count??0)>=(f.threshold??28)*0.8);

  if (pending.some(f=>(f.count??0)<(f.threshold??28)*0.5)) _sigs.amendVeto=true;

  // Build tab strip
  if (hdr) {
    const tabs=[
      {id:'pending', label:'Voting', count:pending.length,   color:'#8be9fd'},
      {id:'active',  label:'Active', count:active.length,    color:'#50fa7b'},
      {id:'vetoed',  label:'Vetoed', count:vetoed.length,    color:'#ff5555'},
      {id:'all',     label:'All',    count:all.length,       color:null},
    ];
    hdr.innerHTML = `
      <div class="ap-tabs">
        ${tabs.map(t=>`
          <button class="ap-tab ${_amendTab===t.id?'ap-tab--active':''}" data-aptab="${t.id}">
            ${t.color?`<span style="display:inline-block;width:7px;height:7px;border-radius:50%;background:${t.color};margin-right:5px;vertical-align:middle"></span>`:''}
            ${t.label}
            <span class="ap-tab-count">${t.count}</span>
          </button>`).join('')}
      </div>
      ${majority.length ? `<div class="ap-alert-bar">⏳ ${majority.length} amendment${majority.length>1?'s':''} reached validator majority — activates in ~14 days if maintained</div>` : ''}
      ${nearThresh.length ? `<div class="ap-near-bar">📈 ${nearThresh.length} amendment${nearThresh.length>1?'s':''} approaching 80% threshold</div>` : ''}`;

    hdr.querySelectorAll('.ap-tab').forEach(btn => {
      btn.onclick = () => { _amendTab = btn.dataset.aptab; _renderAmend(features); };
    });
  }

  const view = _amendTab==='active' ? active
    : _amendTab==='vetoed' ? vetoed
    : _amendTab==='all'    ? all.sort((a,b)=>{ if(a.enabled!==b.enabled) return a.enabled?1:-1; if(a.vetoed!==b.vetoed) return a.vetoed?1:-1; return (b.count??0)-(a.count??0); })
    : pending;

  if (!view.length) {
    el.innerHTML=`<div class="amend-empty">${_amendTab==='vetoed'?'No vetoed amendments':'No data'}</div>`;
    return;
  }

  el.innerHTML = view.map(f=>{
    const c=f.count??0, th=f.threshold??28;
    const pct=Math.min(100,Math.round((c/th)*100));
    const name=f.name ?? `${f.hash.slice(0,10)}...`;
    const en=!!f.enabled, vt=!!f.vetoed, maj=!!f.majority;
    const docs=AMENDMENT_DOCS[name]??{};
    const momentum = _bl.amendMomentum?.[f.hash];

    // Compute days-to-activation estimate for majority amendments
    let countdownHtml='';
    if (maj && !en && f.majority) {
      const sinceMs = Date.now() - new Date(f.majority).getTime();
      const daysIn  = sinceMs>0 ? Math.floor(sinceMs/86400000) : 0;
      const daysLeft= Math.max(0, 14-daysIn);
      const prog    = Math.min(100,Math.round((daysIn/14)*100));
      countdownHtml = `<div class="ap-countdown">
        <span class="ap-countdown-lbl">Majority held ${daysIn}d · activates in ~${daysLeft}d</span>
        <div class="ap-countdown-track"><div class="ap-countdown-fill" style="width:${prog}%"></div></div>
      </div>`;
    }

    const statusColor = en?'#50fa7b':vt?'#ff5555':maj?'#ffb86c':pct>=80?'#8be9fd':'rgba(255,255,255,.3)';
    const statusLabel = en?'Active':vt?'Vetoed':maj?'Majority':pct>=80?'Near':'Voting';

    return `<div class="ap-row" onclick="window.showAmendDetail('${escHtml(f.hash)}')">
      <div class="ap-row-main">
        <div class="ap-row-top">
          <span class="ap-name">${escHtml(name)}</span>
          <span class="ap-status-tag" style="border-color:${statusColor}44;color:${statusColor}">${statusLabel}</span>
        </div>
        ${docs.purpose ? `<div class="ap-purpose">${escHtml(docs.purpose)}</div>` : ''}
        ${!en ? `<div class="ap-vote-row">
          <div class="ap-vote-track">
            <div class="ap-vote-fill" style="width:${pct}%;background:${statusColor};opacity:${en?1:.75}"></div>
            <div class="ap-vote-thresh" title="80% threshold"></div>
          </div>
          <span class="ap-vote-label">${c}/${th} <span style="opacity:.5">(${pct}%)</span></span>
        </div>` : `<div class="ap-active-note">✓ Running on all ledgers${docs.intro?' · since '+docs.intro:''}</div>`}
        ${countdownHtml}
      </div>
    </div>`;
  }).join('');
}

function _cacheAmendmentData(features) {
  _amendmentData = {};
  Object.entries(features).forEach(([hash, f]) => { _amendmentData[hash]={hash,...f}; });
}

window.showAmendDetail = function(hash) {
  const f = _amendmentData[hash]; if (!f) return;
  const name      = f.name || `${hash.slice(0,16)}...`;
  const docs      = AMENDMENT_DOCS[name] || {};
  const count     = f.count    ?? 0;
  const thresh    = f.threshold ?? 28;
  const pct       = Math.min(100, Math.round((count/thresh)*100));

  const statusTxt = f.enabled ? 'Active on Ledger'
    : f.vetoed    ? 'Vetoed'
    : f.majority  ? 'Majority Reached'
    : 'Voting in Progress';

  const statusCls = f.enabled ? 'adm-s-ok'
    : f.vetoed    ? 'adm-s-bad'
    : f.majority  ? 'adm-s-warn'
    : 'adm-s-info';

  const barCls    = f.enabled ? 'bar-ok'
    : f.vetoed    ? 'bar-danger'
    : f.majority  ? 'bar-warn'
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
function _ensureLeaflet(cb) {
  if (window.L) { cb(); return; }
  if (!document.querySelector('#leaflet-css')) {
    const lnk = document.createElement('link');
    lnk.id   = 'leaflet-css';
    lnk.rel  = 'stylesheet';
    lnk.href = 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.css';
    document.head.appendChild(lnk);
  }
  const scr = document.createElement('script');
  scr.src = 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.js';
  scr.onload = cb;
  document.head.appendChild(scr);
}

function _renderWorldMap(unlKeys, dunlKeys, nUnl, peers, refMode=false) {
  const container = $('world-map-container');
  if (!container) return;
  _ensureLeaflet(() => _buildLeafletMap(unlKeys, dunlKeys, nUnl, peers, refMode));
}

function _buildLeafletMap(unlKeys, dunlKeys, nUnl, peers, refMode=false) {
  const container = $('world-map-container');
  if (!container) return;

  const nUnlSet  = new Set(nUnl     || []);
  const unlSet   = new Set(unlKeys  || []);
  const dunlSet  = new Set(dunlKeys || []);
  const networkId = state.currentNetwork || 'xrpl-mainnet';

  if (_leafletMap && _mapNetId !== networkId) {
    _leafletMap.remove();
    _leafletMap = null;
    _mapMarkers = [];
    _mapNetId   = null;
  }

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

    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
      attribution: '&copy; <a href="https://carto.com">CARTO</a> &copy; <a href="https://openstreetmap.org">OSM</a>',
      subdomains: 'abcd', maxZoom: 19,
    }).addTo(_leafletMap);

    _mapNetId = networkId;
  }

  _mapMarkers.forEach(m => { try { m.remove(); } catch {} });
  _mapMarkers = [];

  /* ── Category helper ── */
  function _keyCategory(key) {
    if (nUnlSet.has(key))                        return 'nunl';
    if (unlSet.has(key) && dunlSet.has(key))     return 'both';
    if (unlSet.has(key))                         return 'unl';
    if (dunlSet.has(key))                        return 'dunl';
    return 'other';
  }

  /* ── All keys with known geo from registry ── */
  _keyToMarker = {};
  const clusterMap = {};

  for (const [key, entry] of _registry) {
    const geo = _resolveGeo(entry);
    if (!geo?.lat || !geo?.lng) continue;
    const ck = `${(Math.round(geo.lat*2)/2).toFixed(1)},${(Math.round(geo.lng*2)/2).toFixed(1)}`;
    if (!clusterMap[ck]) clusterMap[ck] = { lat:geo.lat, lng:geo.lng, keys:[], city:geo.city, org:geo.org };
    clusterMap[ck].keys.push(key);
  }

  Object.values(clusterMap).forEach(cl => {
    const count = cl.keys.length;
    const cats  = cl.keys.map(_keyCategory);
    const dom   = ['nunl','both','unl','dunl','other'].find(c => cats.includes(c)) || 'other';
    const col   = VAL_COLOR[dom];
    const r     = count > 5 ? 13 : count > 2 ? 10 : 7;

    const icon = L.divIcon({
      html: `<div class="wm-lmarker wm-lmarker-val ${dom==='nunl'?'wm-lmarker-nunl':''} ${refMode?'wm-lmarker-ref':''}"
                  style="--mc:${col.hex};--mg:${col.glow};"
                  title="${cl.keys.map(k=>_reg(k).label).join(', ')}">
        <div class="wm-lring"></div>
        <div class="wm-ldot" style="width:${r*2}px;height:${r*2}px;">${count>1?`<span>${count}</span>`:''}</div>
      </div>`,
      className: '', iconSize: [(r+8)*2, (r+8)*2], iconAnchor: [r+8, r+8],
    });

    const marker = L.marker([cl.lat, cl.lng], { icon })
      .bindPopup(_valPopupHtml(cl.keys, cl.city, cl.org, nUnlSet, unlSet, dunlSet, refMode), {
        maxWidth: 380, className: 'wm-popup-wrap',
      })
      .addTo(_leafletMap);

    cl.keys.forEach(k => { _keyToMarker[k] = marker; });
    _mapMarkers.push(marker);
  });

  /* ── refMode banner ── */
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

  /* ── Unknown geo notice ── */
  const knownGeoCount = [..._registry.keys()].filter(k => {
    const e = _registry.get(k);
    return e.geo?.lat != null || VALIDATOR_GEO[k];
  }).length;
  const unknownCount = _registry.size - knownGeoCount;

  if (unknownCount > 0) {
    const notice = L.control({ position: 'bottomright' });
    notice.onAdd = () => {
      const d = L.DomUtil.create('div', 'wm-unknown-ctrl');
      d.innerHTML = `+ ${unknownCount} validators · location unknown`;
      return d;
    };
    notice.addTo(_leafletMap);
    _mapMarkers.push(notice);
  }

  /* ── Public nodes ── */
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

  /* ── Legend ── */
  const peersArr = Array.isArray(peers) ? peers : [];
  const ib = peersArr.filter(p=>p.inbound===true).length;
  const ob = peersArr.length - ib;
  const peerTxt = peersArr.length > 0 ? `${peersArr.length} peers (${ib}↓ ${ob}↑)` : `${Number(_info?.peers??0)} peers`;

  const legend = L.control({ position: 'topleft' });
  legend.onAdd = () => {
    const d = L.DomUtil.create('div', 'wm-legend-ctrl');
    d.innerHTML = `
      <div class="wm-leg-row"><span class="wm-leg-dot" style="background:${VAL_COLOR.unl.hex};box-shadow:0 0 5px ${VAL_COLOR.unl.glow}"></span>UNL Validator</div>
      <div class="wm-leg-row"><span class="wm-leg-dot" style="background:${VAL_COLOR.dunl.hex};box-shadow:0 0 5px ${VAL_COLOR.dunl.glow}"></span>dUNL only</div>
      <div class="wm-leg-row"><span class="wm-leg-dot" style="background:${VAL_COLOR.both.hex};box-shadow:0 0 5px ${VAL_COLOR.both.glow}"></span>UNL + dUNL</div>
      <div class="wm-leg-row"><span class="wm-leg-dot" style="background:${VAL_COLOR.other.hex};box-shadow:0 0 5px ${VAL_COLOR.other.glow}"></span>Other validator</div>
      <div class="wm-leg-row"><span class="wm-leg-dot" style="background:${VAL_COLOR.nunl.hex};box-shadow:0 0 5px ${VAL_COLOR.nunl.glow}"></span>Negative UNL</div>
      <div class="wm-leg-row"><span class="wm-leg-dot" style="background:${VAL_COLOR.pub.hex};box-shadow:0 0 5px ${VAL_COLOR.pub.glow}"></span>Public Node</div>
      <div class="wm-leg-row wm-leg-peers"><span class="wm-leg-dot" style="background:#8be9fd"></span>${peerTxt}</div>
      <div class="wm-leg-src" style="opacity:.55;font-size:10px;margin-top:4px;">
        Registry: ${_registrySource === 'live' ? '🟢 live' : '🟡 fallback'}
      </div>`;
    return d;
  };
  legend.addTo(_leafletMap);
  _mapMarkers.push(legend);

  const pointMarkers = _mapMarkers.filter(m => m && typeof m.getLatLng === 'function');
  if (pointMarkers.length >= 2) {
    try {
      const bounds = L.latLngBounds(pointMarkers.map(m => m.getLatLng()));
      if (bounds.isValid()) {
        _leafletMap.fitBounds(bounds.pad(0.15), { maxZoom: 6 });
      }
    } catch (e) {
      // fitBounds can still throw on degenerate single-point bounds — ignore
    }
  }

  try {
    window.dispatchEvent(new CustomEvent('nalulf-network-map', {
      detail: { map: _leafletMap, networkId: _mapNetId }
    }));
  } catch {}
}

function _valPopupHtml(keys, city, org, nUnlSet, unlSet, dunlSet, isRef=false) {
  const isCluster = keys.length > 1;

  const rows = keys.map(key => {
    const rv    = _reg(key);
    const onN   = nUnlSet.has(key);
    const inUnl = unlSet.has(key);
    const inDun = dunlSet.has(key);
    const shortKey = key.slice(0,20) + '...';

    let catColor, catLabel;
    if (onN)              { catColor = VAL_COLOR.nunl.hex;  catLabel = 'Negative UNL'; }
    else if (inUnl&&inDun){ catColor = VAL_COLOR.both.hex;  catLabel = 'UNL + dUNL'; }
    else if (inUnl)       { catColor = VAL_COLOR.unl.hex;   catLabel = 'UNL'; }
    else if (inDun)       { catColor = VAL_COLOR.dunl.hex;  catLabel = 'dUNL'; }
    else                  { catColor = VAL_COLOR.other.hex; catLabel = 'Other'; }

    return `<div class="wm-popup-val-row">
      <span class="wm-popup-val-dot" style="background:${catColor};box-shadow:0 0 6px ${catColor}66"></span>
      <div class="wm-popup-val-info">
        <span class="wm-popup-val-name">${escHtml(rv.label)}</span>
        ${rv.domain ? `<span class="wm-popup-val-domain">${escHtml(rv.domain)}</span>` : ''}
        <span class="wm-popup-val-key"
              onclick="navigator.clipboard?.writeText('${escHtml(key)}');this.textContent='✓ Copied!';setTimeout(()=>this.textContent='${escHtml(shortKey)}',1400)"
              title="Click to copy full key">${escHtml(shortKey)}</span>
        <div class="wm-popup-val-tags">
          <span class="wm-popup-ok-tag" style="border-color:${catColor}66;color:${catColor}">${catLabel}</span>
          ${rv.provider ? `<span class="wm-popup-prov">${escHtml(rv.provider)}</span>` : ''}
        </div>
      </div>
    </div>`;
  }).join('');

  const orgs = [...new Set(keys.map(k => {
    const rv = _reg(k);
    return rv.provider ?? _resolveGeo(rv)?.org ?? null;
  }).filter(Boolean))];

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
      ${isRef     ? '<div class="wm-popup-badge wm-popup-badge-ref">Reference data</div>' : ''}
    </div>
    <div class="wm-popup-divider"></div>
    <div class="wm-popup-vals">${rows}</div>
  </div>`;
}

/* ═══════════════════════════════════════════════════
   ADVERSARIAL SIGNAL MONITOR
═══════════════════════════════════════════════════ */
const _sigHistory = []; // { key, label, ts, weight }

function _alert() {
  const keys=Object.keys(_sigs);
  const wt  =keys.reduce((s,k)=>s+(SIG[k]?.w??1),0);
  const hot =wt>=ALERT_WEIGHT;

  // Record new signals with timestamp
  keys.forEach(k => {
    if (!_sigHistory.find(h=>h.key===k&&Date.now()-h.ts<300_000)) {
      _sigHistory.push({key:k, label:SIG[k]?.label??k, ts:Date.now(), weight:SIG[k]?.w??1});
    }
  });
  // Trim history to last 20
  while (_sigHistory.length>20) _sigHistory.shift();

  const alertEl=$('adversarial-alert');
  if (alertEl) {
    alertEl.classList.toggle('adv-active',hot);
    alertEl.classList.toggle('adv-inactive',!hot);
  }

  // Update threat level badge
  const scoreEl=$('adversarial-score');
  if (scoreEl) {
    const level = wt===0?'All Clear':wt<3?'Monitor':wt<5?'Elevated':wt<10?'High':'Critical';
    const lvlColor = wt===0?'#50fa7b':wt<3?'#8be9fd':wt<5?'#ffb86c':wt<10?'#ff9955':'#ff5555';
    scoreEl.innerHTML=`<span style="color:${lvlColor};font-weight:700">${level}</span>
      <span style="opacity:.5;font-size:11px;margin-left:8px">threat score ${wt}</span>`;
    scoreEl.className='adv-score';
  }

  const listEl=$('adversarial-signals');
  if (!listEl) return;

  if (!keys.length) {
    listEl.innerHTML=`<div class="adv-clear-card">
      <span class="adv-clear-icon">✓</span>
      <div>
        <div class="adv-clear-title">No Active Signals</div>
        <div class="adv-clear-sub">All ${Object.keys(SIG).length} threat indicators are nominal</div>
      </div>
    </div>`;
  } else {
    // Group by severity
    const critical = keys.filter(k=>(SIG[k]?.w??1)>=3);
    const elevated  = keys.filter(k=>(SIG[k]?.w??1)===2);
    const monitor  = keys.filter(k=>(SIG[k]?.w??1)===1);
    const renderGroup = (title, ks, col) => ks.length===0?'' : `
      <div class="adv-group-title" style="color:${col}">${title} (${ks.length})</div>
      ${ks.map(k=>{
        const sig=SIG[k]??{w:1,label:k};
        // Split label into short title + detail
        const parts=sig.label.split(' — ');
        const shortTitle=parts[0], detail=parts[1]||'';
        return `<div class="adv-sig-card adv-sig-${sig.w>=3?'critical':sig.w>=2?'elevated':'monitor'}">
          <div class="adv-sig-top">
            <span class="adv-sig-dot" style="background:${col}"></span>
            <span class="adv-sig-title">${escHtml(shortTitle)}</span>
            <span class="adv-sig-badge" style="border-color:${col}44;color:${col}">W${sig.w}</span>
          </div>
          ${detail?`<div class="adv-sig-detail">${escHtml(detail)}</div>`:''}
        </div>`;
      }).join('')}`;

    listEl.innerHTML=
      renderGroup('Critical', critical, '#ff5555') +
      renderGroup('Elevated', elevated, '#ffb86c') +
      renderGroup('Monitor',  monitor,  '#8be9fd');
  }

  // Recent signal history
  const histEl=$('adversarial-history');
  if (histEl && _sigHistory.length) {
    const now=Date.now();
    histEl.innerHTML=_sigHistory.slice(-8).reverse().map(h=>{
      const ago=Math.round((now-h.ts)/60000);
      const isActive=keys.includes(h.key);
      return `<div class="adv-hist-row ${isActive?'adv-hist-active':'adv-hist-resolved'}">
        <span class="adv-hist-dot"></span>
        <span class="adv-hist-lbl">${escHtml((h.label.split(' — ')[0]).substring(0,40))}</span>
        <span class="adv-hist-time">${ago<1?'now':`${ago}m ago`} ${isActive?'<span class="adv-hist-tag-active">active</span>':'<span class="adv-hist-tag-res">resolved</span>'}</span>
      </div>`;
    }).join('');
  }
}

/* ═══════════════════════════════════════════════════
   HEALTH BANNER
═══════════════════════════════════════════════════ */
function _banner(data) {
  const el=$('nh-banner'); if (!el) return;

  if (!data || state.connectionState!=='connected') {
    _t('nh-score','—'); _t('nh-grade','Disconnected'); _t('nh-sub','Connect to begin');
    el.className='nh-banner nh-dead';
    _vitals({});
    _renderHealthChecks(null);
    return;
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

  const nc=(info?.negative_unl??[]).length;
  sc-=Math.min(20,nc*4);

  const sw=Object.keys(_sigs).reduce((s,k)=>s+(SIG[k]?.w??1),0);
  sc-=Math.min(25,sw*3);

  sc=Math.max(0,Math.min(100,Math.round(sc)));

  const sigN=Object.keys(_sigs).length;

  const {grade, status, cls} = _grade(sc);
  _t('nh-score',  status);      // show STATUS word, not raw number
  _t('nh-grade',  grade);
  _t('nh-sub',    `${new Date().toLocaleTimeString()} · ${sigN > 0 ? sigN+' signal'+(sigN!==1?'s':'')+' active' : 'All signals clear'}`);
  el.className=`nh-banner nh-${cls}`;

  const ring=$('nh-ring');
  if (ring) {
    const c=2*Math.PI*28;
    ring.style.strokeDasharray =c;
    ring.style.strokeDashoffset=c*(1-sc/100);
    const ringColor = cls==='great'?'#00fff0':cls==='good'?'#50fa7b':cls==='fair'?'#ffb86c':cls==='warn'?'#ff9955':'#ff5555';
    ring.style.stroke = ringColor;
  }

  _vitals({st,pc,q,tc,lf,cvg,age,nc});
  _renderHealthChecks({info,fee,vals});
}

function _grade(s) {
  return s>=90?{grade:'All Systems Nominal', status:'Optimal',  cls:'great'}
    :s>=70?{grade:'Operating Normally',   status:'Good',     cls:'good'}
    :s>=50?{grade:'Minor Issues Detected',status:'Watch',    cls:'fair'}
    :s>=30?{grade:'Attention Required',   status:'Warning',  cls:'warn'}
    :      {grade:'Critical Issues',       status:'Critical', cls:'bad'};
}

function _vitals(v) {
  _vit('nh-v-state',['full','proposing','validating'].includes(v.st)?'ok':v.st==='syncing'?'warn':'bad', v.st??'—');
  _vit('nh-v-peers',(v.pc??0)>=15?'ok':(v.pc??0)>=6?'warn':'bad',
       v.pc!=null?`${v.pc} peers`:'—');
  _vit('nh-v-cvg',  (v.cvg??0)<4?'ok':(v.cvg??0)<7?'warn':'bad',
       v.cvg!=null?`${Number(v.cvg).toFixed(1)}s`:'—');
  _vit('nh-v-age',  (v.age??0)<3?'ok':(v.age??0)<8?'warn':'bad',
       v.age!=null?`${Number(v.age)}s ago`:'—');
  _vit('nh-v-load', (v.lf??1)<2?'ok':(v.lf??1)<5?'warn':'bad',
       v.lf!=null?`${Number(v.lf).toFixed(2)}× load`:'—');
  _vit('nh-v-nunl', (v.nc??0)===0?'ok':(v.nc??0)<=2?'warn':'bad',
       v.nc!=null?(v.nc===0?'None offline':`${v.nc} offline`):'—');
  // Quorum vitals
  const ql = v.q??0, tl = v.tc??0, mg = tl-ql;
  _vit('nh-v-quorum', mg>3?'ok':mg>0?'warn':'bad',
       ql>0?`${ql} required · margin ${mg}`:'—');
}
function _vit(id, cls, txt) {
  const e=$(id); if(e){e.textContent=txt; e.className=`nh-vval nh-vval--${cls}`;}
}

/* ═══════════════════════════════════════════════════
   SYSTEM HEALTH DASHBOARD
═══════════════════════════════════════════════════ */
function _renderHealthChecks(data) {
  const el=$('nh-health-checks'); if (!el) return;

  if (!data) {
    el.innerHTML='<div class="hc-disconnected">Connect to an XRPL node to run health checks</div>';
    return;
  }

  const {info,fee,vals}=data;

  // Each check returns { value, status:'ok'|'watch'|'alert', note }
  const checks=[
    { label:'Node State',      group:'consensus', icon:'⬡',
      check:()=>{
        const s=info?.server_state||'unknown';
        const ok=['full','proposing','validating'].includes(s);
        const watch=s==='syncing'||s==='tracking';
        return { value:s, status:ok?'ok':watch?'watch':'alert',
                 note:ok?'Participating in consensus':watch?'Catching up to network':'Not participating' };
    }},
    { label:'Quorum Margin',   group:'consensus', icon:'⚖',
      check:()=>{
        const tk=vals?.trusted_validator_keys?.length??0, q=vals?.validation_quorum??0;
        const m=tk-q;
        if (!q) return { value:'—', status:'watch', note:'Validator data not available' };
        return { value:`${m} spare`, status:m>3?'ok':m>0?'watch':'alert',
                 note:m>3?`${q} of ${tk} needed — ${m} can go offline safely`
                   :m>0?`Only ${m} validator(s) above quorum — very tight`
                   :'Below quorum — consensus may stall' };
    }},
    { label:'Negative UNL',    group:'consensus', icon:'⛔',
      check:()=>{
        const n=(info?.negative_unl||[]).length;
        return { value:n===0?'None':`${n} listed`, status:n===0?'ok':n<=2?'watch':'alert',
                 note:n===0?'All UNL validators are online'
                   :`${n} validator(s) temporarily excluded from consensus counting` };
    }},
    { label:'Ledger Age',      group:'consensus', icon:'⏱',
      check:()=>{
        const age=Number(info?.validated_ledger?.age??0);
        return { value:age<2?'< 1s':`${age}s`, status:age<5?'ok':age<10?'watch':'alert',
                 note:age<5?'Ledger closing on schedule (3–4s target)'
                   :age<10?'Slightly delayed — network may be busy'
                   :'Ledger stalled — consensus issue likely' };
    }},
    { label:'Convergence Time',group:'consensus', icon:'🔄',
      check:()=>{
        const cvg=Number(info?.last_close?.converge_time_s??0);
        return { value:cvg>0?`${cvg.toFixed(1)}s`:'—', status:cvg<4?'ok':cvg<7?'watch':'alert',
                 note:cvg<4?'Validators agreeing quickly'
                   :cvg<7?'Slightly slow — check for network latency'
                   :'Slow convergence — validator disagreement or network partition' };
    }},
    { label:'Peer Count',      group:'infra', icon:'🔗',
      check:()=>{
        const p=Number(info?.peers??0);
        return { value:`${p} peers`, status:p>=15?'ok':p>=6?'watch':'alert',
                 note:p>=15?'Well-connected to the network'
                   :p>=6?'Below recommended (15+) — consider adding peers'
                   :'Critically low — eclipse attack risk is high' };
    }},
    { label:'Load Factor',     group:'infra', icon:'⚡',
      check:()=>{
        const lf=Number(info?.load_factor??1);
        return { value:`${lf.toFixed(2)}×`, status:lf<2?'ok':lf<5?'watch':'alert',
                 note:lf<2?'Normal load — node processing freely'
                   :lf<5?'Elevated load — fees increasing'
                   :'High load — this node is throttling transactions' };
    }},
    { label:'IO Latency',      group:'infra', icon:'💾',
      check:()=>{
        const ms=Number(info?.io_latency_ms??0);
        return { value:ms>0?`${ms}ms`:'< 1ms', status:ms<2?'ok':ms<10?'watch':'alert',
                 note:ms<2?'Storage and network I/O responding well'
                   :ms<10?'Moderate I/O latency — monitor disk/network'
                   :'High I/O latency — storage or network bottleneck' };
    }},
    { label:'Job Queue',       group:'infra', icon:'📋',
      check:()=>{
        const jq=Number(info?.jq_trans_overflow??0);
        return { value:jq===0?'Clear':`${jq} overflow`, status:jq===0?'ok':'alert',
                 note:jq===0?'No transaction job queue overflows'
                   :'Queue overflowing — node is overwhelmed, upgrade resources' };
    }},
    { label:'Fee Pressure',    group:'ledger', icon:'💸',
      check:()=>{
        const f=Number(fee?.drops?.open_ledger_fee??10);
        const label=f<100?'Minimal':f<500?'Elevated':f<5000?'High':'Severe';
        return { value:`${f} drops`, status:f<100?'ok':f<500?'watch':'alert',
                 note:f<100?'Normal transaction fees — network not congested'
                   :f<500?'Fees rising — moderate network congestion'
                   :'High fees — significant congestion or spam attack' };
    }},
    { label:'TX Queue Fill',   group:'ledger', icon:'🗂',
      check:()=>{
        const q=Number(fee?.current_queue_size??0), m=Number(fee?.max_queue_size??1);
        const p=m>0?Math.round((q/m)*100):0;
        return { value:`${p}% (${q}/${m})`, status:p<50?'ok':p<80?'watch':'alert',
                 note:p<50?`Queue at ${p}% — plenty of headroom`
                   :p<80?`Queue ${p}% full — fee spike likely soon`
                   :'Queue nearly full — transactions being dropped' };
    }},
  ];

  const results=checks.map(c=>({...c,result:c.check()}));
  const okCount=results.filter(r=>r.result.status==='ok').length;
  const watchCount=results.filter(r=>r.result.status==='watch').length;
  const alertCount=results.filter(r=>r.result.status==='alert').length;

  const sumEl=$('nh-health-summary');
  if (sumEl) {
    sumEl.innerHTML=`
      <span class="hcs-count hcs-pass">${okCount}</span><span class="hcs-lbl">nominal</span>
      <span class="hcs-sep">·</span>
      <span class="hcs-count hcs-warn">${watchCount}</span><span class="hcs-lbl">watch</span>
      <span class="hcs-sep">·</span>
      <span class="hcs-count hcs-fail">${alertCount}</span><span class="hcs-lbl">alert</span>
      <span class="hcs-total">of ${results.length} checks</span>`;
  }

  const groups={consensus:'Consensus Health',infra:'Node Infrastructure',ledger:'Ledger & Fees'};
  el.innerHTML=Object.entries(groups).map(([gid,gname])=>{
    const gc=results.filter(r=>r.group===gid);
    const items=gc.map(r=>{
      const s=r.result.status;
      const cls=s==='ok'?'hc-ok':s==='watch'?'hc-warn':'hc-fail';
      const ico=s==='ok'?'●':s==='watch'?'●':'●';
      const dotCol=s==='ok'?'#50fa7b':s==='watch'?'#ffb86c':'#ff5555';
      return `<div class="hc-item ${cls}">
        <div class="hc-item-top">
          <span class="hc-dot" style="background:${dotCol}"></span>
          <span class="hc-label">${escHtml(r.icon)} ${escHtml(r.label)}</span>
          <span class="hc-value">${escHtml(r.result.value)}</span>
        </div>
        <div class="hc-note">${escHtml(r.result.note)}</div>
      </div>`;
    }).join('');
    const gOk=gc.filter(r=>r.result.status==='ok').length;
    const gAlert=gc.filter(r=>r.result.status==='alert').length;
    const gCls=gAlert>0?'hcg-alert':gOk===gc.length?'hcg-ok':'hcg-watch';
    return `<div class="hc-group ${gCls}">
      <div class="hc-group-title">${escHtml(gname)}
        <span class="hcg-badge">${gOk}/${gc.length}</span>
      </div>
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
  // Extended tx type tracking for pulse panel
  _bpush('txPayment',  d.txTypes?.Payment??0);
  _bpush('txNFT',      (d.txTypes?.NFTokenMint??0)+(d.txTypes?.NFTokenBurn??0)+(d.txTypes?.NFTokenCreateOffer??0)+(d.txTypes?.NFTokenAcceptOffer??0));
  _bpush('txLedger',   d.txPerLedger??0);
  _bpush('tps',        d.tps ?? (d.txPerLedger ?? 0) / 3.5);
  _bpush('closeTime',  d.closeTime ?? 3.5);
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
      ws.onopen=()=>{clearTimeout(t);res();};
      ws.onerror=()=>{clearTimeout(t);rej();};
    });
    const ms=Math.round(performance.now()-t0);
    try{ws.close();}catch{}

    const cls=ms<100?'lat-fast':ms<300?'lat-med':'lat-slow';
    if (ve){ve.textContent=`${ms}ms`; ve.className=`lat-val ${cls}`;}
    if (be) be.style.width=`${Math.min(100,(ms/600)*100)}%`;
    re?.classList.toggle('lat-active',state.wsConn?.url===ep.url);
  } catch {
    if (ve){ve.textContent='timeout'; ve.className='lat-val lat-slow';}
  }
}

/* ═══════════════════════════════════════════════════
   INJECTED STYLES — validator grid tabs
═══════════════════════════════════════════════════ */
function _injectValGridStyles() {
  if (document.getElementById('vg-tab-styles')) return;
  const s = document.createElement('style');
  s.id = 'vg-tab-styles';
  s.textContent = `
    /* ── Validator grid layout ── */
    .vg-tabs { display:flex; gap:4px; flex-wrap:wrap; margin-bottom:10px; padding-bottom:8px; border-bottom:1px solid rgba(255,255,255,.07); }
    .vg-tab {
      padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: 600;
      cursor: pointer; background: transparent;
      border: 1px solid rgba(255,255,255,.18); color: rgba(255,255,255,.6);
      transition: background .15s, color .15s, border-color .15s; white-space: nowrap;
    }
    .vg-tab:hover  { background: rgba(255,255,255,.06); color: #fff; }
    .vg-tab--active { background: rgba(0,255,240,.12); border-color: rgba(0,255,240,.5); color: #00fff0; }

    .vpill.vp-both  .vpdot { background: #50fa7b; box-shadow: 0 0 6px rgba(80,250,123,.6); }
    .vpill.vp-dunl  .vpdot { background: #bd93f9; box-shadow: 0 0 6px rgba(189,147,249,.6); }
    .vpill.vp-other .vpdot { background: #ffb86c; box-shadow: 0 0 6px rgba(255,184,108,.6); }

    .vntag-cat {
      font-size: 10px; padding: 1px 6px; border-radius: 10px;
      border: 1px solid rgba(255,255,255,.2); color: rgba(255,255,255,.6);
      background: rgba(255,255,255,.04);
    }
    .vp-both  .vntag-cat { border-color: rgba(80,250,123,.4);  color: #50fa7b; }
    .vp-dunl  .vntag-cat { border-color: rgba(189,147,249,.4); color: #bd93f9; }
    .vp-nunl  .vntag-cat { border-color: rgba(255,85,85,.4);   color: #ff5555; }
    .vp-other .vntag-cat { border-color: rgba(255,184,108,.4); color: #ffb86c; }
    .vp-unl   .vntag-cat { border-color: rgba(0,255,240,.4);   color: #00fff0; }

    /* ── Validator grid sections ── */
    .vg-section { margin-bottom: 6px; border: 1px solid rgba(255,255,255,.07); border-radius: 8px; overflow: hidden; }
    .vg-section.vgs-warn { border-color: rgba(255,85,85,.3); }
    .vg-section-hdr {
      width:100%; display:flex; align-items:center; gap:8px;
      padding:7px 10px; background:rgba(255,255,255,.03);
      border:none; cursor:pointer; color:rgba(255,255,255,.75);
      font-size:11px; font-weight:600; text-align:left;
      transition: background .15s;
    }
    .vg-section-hdr:hover { background:rgba(255,255,255,.06); }
    .vg-chevron { font-size:9px; opacity:.5; min-width:10px; }
    .vg-sec-title { flex:1; }
    .vg-section-body { display:flex; flex-wrap:wrap; gap:5px; padding:8px; }
    .vg-num {
      font-size:10px; font-weight:700; min-width:18px; text-align:center;
      color:rgba(255,255,255,.35); flex-shrink:0;
    }
    .vg-agr { font-size:10px; font-weight:700; }
    .vg-tab-dot { display:inline-block; width:7px; height:7px; border-radius:50%; margin-right:3px; vertical-align:middle; }
    .vg-tab-count {
      background:rgba(255,255,255,.1); border-radius:10px;
      font-size:10px; padding:0px 5px; margin-left:3px;
    }
    .vg-tab--active .vg-tab-count { background:rgba(0,255,240,.15); }
    .vp-geo { font-size:10px; opacity:.7; }

    /* ── Congestion summary card ── */
    .cong-line  { display:flex; align-items:flex-start; gap:8px; font-size:12px; padding:4px 0; border-bottom:1px solid rgba(255,255,255,.04); }
    .cong-clear { font-size:12px; padding:6px 0; }
    /* Pressure badge colours */
    .p-severe   { background:rgba(255,85,85,.15);   color:#ff5555; border-color:rgba(255,85,85,.3)   !important; }
    .p-high     { background:rgba(255,153,85,.12);  color:#ff9955; border-color:rgba(255,153,85,.3)  !important; }
    .p-elevated { background:rgba(255,184,108,.10); color:#ffb86c; border-color:rgba(255,184,108,.3) !important; }
    .p-normal   { background:rgba(80,250,123,.08);  color:#50fa7b; border-color:rgba(80,250,123,.25) !important; }
    .p-minimal  { background:rgba(98,114,164,.10);  color:#6272a4; border-color:rgba(98,114,164,.2)  !important; }

    /* ── Health banner grade variants ── */
    .nh-banner.nh-warn .nh-score-num { color:#ff9955; }

        /* Registry status badge */
    .registry-badge {
      display: inline-block; font-size: 11px; padding: 2px 8px; border-radius: 10px;
      margin-left: 8px; vertical-align: middle;
    }
    .registry-badge--ok   { background: rgba(80,250,123,.12); border: 1px solid rgba(80,250,123,.3); color: #50fa7b; }
    .registry-badge--warn { background: rgba(255,184,108,.10); border: 1px solid rgba(255,184,108,.3); color: #ffb86c; }

    /* ── Quorum Ring ── */
    .qr-wrap    { display:flex; align-items:center; gap:16px; padding:8px 0; }
    .qr-legend  { display:flex; flex-direction:column; gap:5px; flex:1; }
    .qr-leg-row { display:flex; align-items:center; gap:7px; font-size:11px; }
    .qr-dot     { width:9px; height:9px; border-radius:50%; flex-shrink:0; }

    /* ── Amendment Pipeline tabs ── */
    .ap-tabs { display:flex; gap:4px; flex-wrap:wrap; margin-bottom:8px; }
    .ap-tab {
      padding:3px 10px; border-radius:16px; font-size:11px; font-weight:600;
      cursor:pointer; background:transparent; border:1px solid rgba(255,255,255,.15);
      color:rgba(255,255,255,.5); transition:all .15s;
    }
    .ap-tab:hover { background:rgba(255,255,255,.05); color:#fff; }
    .ap-tab--active { background:rgba(0,255,240,.1); border-color:rgba(0,255,240,.4); color:#00fff0; }
    .ap-tab-count { font-size:9px; padding:1px 5px; border-radius:8px; background:rgba(255,255,255,.08); margin-left:3px; }
    .ap-alert-bar { font-size:11px; color:#ffb86c; background:rgba(255,184,108,.08); border:1px solid rgba(255,184,108,.2); border-radius:6px; padding:5px 10px; margin-bottom:6px; }
    .ap-near-bar  { font-size:11px; color:#8be9fd; background:rgba(139,233,253,.06); border:1px solid rgba(139,233,253,.2); border-radius:6px; padding:5px 10px; margin-bottom:6px; }
    .ap-row {
      padding:9px 12px; border-radius:7px; cursor:pointer;
      border:1px solid rgba(255,255,255,.06); margin-bottom:5px;
      background:rgba(255,255,255,.02); transition:background .15s;
    }
    .ap-row:hover { background:rgba(255,255,255,.05); }
    .ap-row-top { display:flex; align-items:center; gap:8px; margin-bottom:3px; }
    .ap-name { font-size:13px; font-weight:600; flex:1; color:rgba(255,255,255,.9); }
    .ap-status-tag { font-size:10px; padding:2px 7px; border-radius:10px; border:1px solid; flex-shrink:0; }
    .ap-purpose { font-size:11px; opacity:.55; margin-bottom:6px; }
    .ap-active-note { font-size:11px; color:#50fa7b; opacity:.8; }
    .ap-vote-row { display:flex; align-items:center; gap:8px; margin-top:5px; }
    .ap-vote-track { flex:1; height:5px; background:rgba(255,255,255,.07); border-radius:3px; overflow:visible; position:relative; }
    .ap-vote-fill { height:100%; border-radius:3px; transition:width .4s; }
    .ap-vote-thresh { position:absolute; left:80%; top:-3px; bottom:-3px; width:2px; background:rgba(255,255,255,.3); border-radius:1px; }
    .ap-vote-label { font-size:11px; opacity:.6; white-space:nowrap; }
    .ap-countdown { margin-top:6px; }
    .ap-countdown-lbl { font-size:10px; color:#ffb86c; display:block; margin-bottom:3px; }
    .ap-countdown-track { height:3px; background:rgba(255,255,255,.07); border-radius:2px; overflow:hidden; }
    .ap-countdown-fill  { height:100%; background:#ffb86c; border-radius:2px; transition:width .5s; }

    /* ── Health check matrix ── */
    .hc-item { padding:8px 10px; border-radius:6px; margin-bottom:4px; background:rgba(255,255,255,.02); border:1px solid rgba(255,255,255,.05); }
    .hc-item-top { display:flex; align-items:center; gap:8px; margin-bottom:3px; }
    .hc-dot  { width:8px; height:8px; border-radius:50%; flex-shrink:0; }
    .hc-label { font-size:12px; font-weight:600; flex:1; }
    .hc-value { font-size:11px; font-weight:700; font-family:monospace; opacity:.85; }
    .hc-note  { font-size:10px; opacity:.5; padding-left:16px; line-height:1.4; }
    .hc-ok   { border-color:rgba(80,250,123,.15); }
    .hc-warn { border-color:rgba(255,184,108,.15); }
    .hc-fail { border-color:rgba(255,85,85,.2); }
    .hc-group { margin-bottom:12px; }
    .hc-group-title { font-size:10px; font-weight:700; text-transform:uppercase; letter-spacing:.08em; opacity:.5; margin-bottom:6px; display:flex; align-items:center; gap:8px; }
    .hcg-badge { background:rgba(255,255,255,.08); border-radius:8px; padding:1px 6px; font-size:9px; font-weight:600; }
    .hcg-ok    .hcg-badge { background:rgba(80,250,123,.15); color:#50fa7b; }
    .hcg-alert .hcg-badge { background:rgba(255,85,85,.15);  color:#ff5555; }
    .hcg-watch .hcg-badge { background:rgba(255,184,108,.15);color:#ffb86c; }
    .hc-disconnected { opacity:.4; font-size:12px; padding:16px; text-align:center; }

    /* ── Adversarial Signal Monitor ── */
    .adv-clear-card { display:flex; align-items:center; gap:12px; padding:14px; border-radius:8px; background:rgba(80,250,123,.05); border:1px solid rgba(80,250,123,.15); }
    .adv-clear-icon { font-size:22px; color:#50fa7b; }
    .adv-clear-title { font-size:14px; font-weight:700; color:#50fa7b; }
    .adv-clear-sub   { font-size:11px; opacity:.6; margin-top:2px; }
    .adv-group-title { font-size:10px; font-weight:700; text-transform:uppercase; letter-spacing:.07em; margin:10px 0 5px; }
    .adv-sig-card { padding:8px 10px; border-radius:6px; margin-bottom:4px; border:1px solid; }
    .adv-sig-critical { border-color:rgba(255,85,85,.25);  background:rgba(255,85,85,.04); }
    .adv-sig-elevated  { border-color:rgba(255,184,108,.2); background:rgba(255,184,108,.04); }
    .adv-sig-monitor  { border-color:rgba(139,233,253,.15); background:rgba(139,233,253,.03); }
    .adv-sig-top   { display:flex; align-items:center; gap:8px; }
    .adv-sig-dot   { width:7px; height:7px; border-radius:50%; flex-shrink:0; }
    .adv-sig-title { font-size:12px; font-weight:600; flex:1; }
    .adv-sig-badge { font-size:9px; padding:1px 5px; border-radius:8px; border:1px solid; }
    .adv-sig-detail { font-size:10px; opacity:.55; margin-top:4px; padding-left:15px; line-height:1.4; }
    .adv-hist-row { display:flex; align-items:center; gap:8px; padding:4px 0; border-bottom:1px solid rgba(255,255,255,.04); font-size:11px; }
    .adv-hist-active   .adv-hist-dot { background:#ffb86c; }
    .adv-hist-resolved .adv-hist-dot { background:rgba(255,255,255,.2); }
    .adv-hist-dot { width:6px; height:6px; border-radius:50%; flex-shrink:0; }
    .adv-hist-lbl  { flex:1; opacity:.7; }
    .adv-hist-time { font-size:10px; opacity:.5; white-space:nowrap; }
    .adv-hist-tag-active   { background:rgba(255,184,108,.15); color:#ffb86c; border-radius:6px; padding:1px 5px; font-size:9px; margin-left:4px; }
    .adv-hist-tag-res      { background:rgba(80,250,123,.1);   color:#50fa7b; border-radius:6px; padding:1px 5px; font-size:9px; margin-left:4px; }
  `;
  document.head.appendChild(s);
}

/* ═══════════════════════════════════════════════════
   INJECT NETWORK METRICS PANELS
   Creates the Pulse and Decentralization panels dynamically
   so they slot into whatever container wraps the tab-network div.
═══════════════════════════════════════════════════ */
function _injectNetworkMetricsPanels() {
  if (document.getElementById('m4-panel')) return; // already injected

  // Find the best insertion point — look for existing sections to append after
  const targets = [
    () => document.querySelector('[data-section="fee-market"]'),
    () => document.querySelector('[data-section="infrastructure"]'),
    () => document.querySelector('#tab-network .section-grid'),
    () => document.querySelector('#tab-network'),
    () => document.body,
  ];
  let container = null;
  for (const fn of targets) { container = fn(); if (container) break; }
  if (!container) return;

  const panelHtml = `
  <!-- ── Decentralization Panel ── -->
  <div id="m4-panel" class="net-panel" style="margin-top:12px">
    <div class="net-panel-header">
      <span class="net-panel-title">🌐 Decentralization Metrics</span>
      <span class="net-panel-sub">Version distribution · geographic spread · provider concentration</span>
    </div>
    <div class="net-panel-body">
      <div class="m4-grid">

        <div class="m4-col">
          <div class="np-section-title">Validator Versions</div>
          <div id="m4-version-dist" class="vd-list">
            <span style="opacity:.4;font-size:12px">Loading registry…</span>
          </div>
        </div>

        <div class="m4-col">
          <div class="np-section-title">Geographic Distribution</div>
          <div id="m4-geo-dist" class="vd-list">
            <span style="opacity:.4;font-size:12px">Loading…</span>
          </div>
        </div>

        <div class="m4-col">
          <div class="np-section-title">Provider Concentration</div>
          <div class="np-section-sub">⚠ bars &gt; 33% indicate single-provider risk</div>
          <div id="m4-provider-dist" class="vd-list">
            <span style="opacity:.4;font-size:12px">Loading…</span>
          </div>
        </div>

      </div>
    </div>
  </div>`;

  container.insertAdjacentHTML('beforeend', panelHtml);

  // ── Inject CSS for new panels ──
  const s = document.createElement('style');
  s.id = 'net-panel-styles';
  s.textContent = `
    /* ── Network Panels ── */
    .net-panel {
      background: rgba(255,255,255,.025);
      border: 1px solid rgba(255,255,255,.07);
      border-radius: 12px;
      overflow: hidden;
      margin-bottom: 12px;
    }
    .net-panel-header {
      display: flex; align-items: center; gap: 10px;
      padding: 12px 16px;
      border-bottom: 1px solid rgba(255,255,255,.06);
      background: rgba(255,255,255,.02);
    }
    .net-panel-title { font-size: 14px; font-weight: 700; color: rgba(255,255,255,.9); }
    .net-panel-sub   { font-size: 11px; opacity: .5; }
    .net-panel-body  { padding: 16px; }

    /* Section titles */
    .np-section-title { font-size: 11px; font-weight: 600; opacity: .6; text-transform: uppercase; letter-spacing: .07em; margin-bottom: 8px; }
    .np-section-sub   { font-size: 10px; opacity: .45; margin-bottom: 6px; margin-top: -4px; }

    /* TX breakdown */
    .np-tx-list { display: flex; flex-direction: column; gap: 5px; }
    .np-tx-row  { display: grid; grid-template-columns: 80px 1fr 100px; align-items: center; gap: 8px; }
    .np-tx-label { font-size: 12px; font-weight: 600; }
    .np-tx-bar-wrap { height: 6px; background: rgba(255,255,255,.06); border-radius: 3px; overflow: hidden; }
    .np-tx-cnt { font-size: 11px; opacity: .7; text-align: right; }

    /* Supply grid */

    /* Decentralization m4 grid */
    .m4-grid { display: grid; grid-template-columns: repeat(3,1fr); gap: 14px; }
    @media (max-width: 800px) { .m4-grid { grid-template-columns: 1fr 1fr; } }
    @media (max-width: 500px) { .m4-grid { grid-template-columns: 1fr; } }
    .m4-col {}

    /* Version/geo distribution bars */
    .vd-list    { display: flex; flex-direction: column; gap: 6px; }
    .vd-row     { display: grid; grid-template-columns: 110px 1fr 70px; align-items: center; gap: 8px; }
    .vd-ver-label { font-size: 12px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .vd-bar-wrap  { height: 6px; background: rgba(255,255,255,.07); border-radius: 3px; overflow: hidden; }
    .vd-bar-fill  { height: 100%; border-radius: 3px; transition: width .5s; }
    .vd-count     { font-size: 11px; opacity: .65; text-align: right; white-space: nowrap; }
    .vd-summary   { font-size: 10px; opacity: .45; margin-top: 8px; border-top: 1px solid rgba(255,255,255,.05); padding-top: 6px; }
    .vd-beta-tag  { font-size: 9px; padding: 1px 5px; background: rgba(255,184,108,.15); color: #ffb86c; border-radius: 8px; border: 1px solid rgba(255,184,108,.3); margin-left: 4px; }
  `;
  if (!document.getElementById('net-panel-styles')) document.head.appendChild(s);
}

/* ─── Helpers ─── */
function _bpush(k,v)  { if(!_bl[k])_bl[k]=[]; _bl[k].push(Number(v)); if(_bl[k].length>BASELINE_LEN)_bl[k].shift(); }
function _bavg(k)     { const a=_bl[k]??[]; return a.length?a.reduce((s,v)=>s+v,0)/a.length:0; }
function _bsum(k,n)   { return(_bl[k]??[]).slice(-n).reduce((s,v)=>s+v,0); }
function _stddev(arr) { if(arr.length<2)return 0; const m=arr.reduce((s,v)=>s+v,0)/arr.length; return Math.sqrt(arr.reduce((s,v)=>s+(v-m)**2,0)/arr.length); }
function _loadBL()    { try{const r=localStorage.getItem(BASELINE_KEY); if(!r)return; const p=JSON.parse(r); Object.keys(_bl).forEach(k=>{if(Array.isArray(p[k]))_bl[k]=p[k];});}catch{} }
function _saveBL()    { try{localStorage.setItem(BASELINE_KEY,JSON.stringify(_bl));}catch{} }
function _t(id,v)     { const e=$(id); if(e)e.textContent=v??'—'; }
function _bar(id,pct,cls) {
  const e=$(id); if(!e)return;
  e.style.width=`${Math.min(100,Math.max(0,Number(pct)||0))}%`;
  e.className=`bar-fill ${cls??''}`;
}
function _histScore(cl) { if(!cl)return 0; const m=cl.match(/(\d+)-(\d+)/); if(!m)return 10; const r=Number(m[2])-Number(m[1]); return r>10_000_000?95:r>1_000_000?70:r>100_000?40:15; }
function _fmtUp(s) {
  if(!s)return'—';
  const d=Math.floor(s/86400),h=Math.floor((s%86400)/3600),m=Math.floor((s%3600)/60);
  return d>0?`${d}d ${h}h`:h>0?`${h}h ${m}m`:`${m}m`;
}
function _delay(ms) { return new Promise(r=>setTimeout(r,ms)); }