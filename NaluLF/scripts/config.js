/* =====================================================
   config.js — Network Endpoints · Constants · LS Keys
   ===================================================== */

// httpUrl is each endpoint's own plain JSON-RPC address (verified directly,
// not guessed — rippled/Clio nodes don't follow one single port/path
// convention) — used by xrpl.js's wsSendResilient() as an independent,
// one-off fallback when a critical request fails on the currently-connected
// server, WITHOUT touching the shared persistent WS connection or its
// ledger-stream subscription. This is the concrete answer to "never
// fabricate age when history is partial" in the one case that's actually
// the SERVER's fault, not a data gap: s1/s2.ripple.com run Clio, which has
// a documented bug returning "Internal error" for account_info on AMM
// pseudo-accounts specifically — xrpl.ws/xrplcluster.com run native
// rippled and don't share that bug, so falling back to one of them when
// the connected Clio node errors recovers cleanly instead of crashing the
// whole inspection.
export const XRPL_ENDPOINTS = [
  // Prefer Ripple first (fast + stable)
  { name: 'Ripple s1',    url: 'wss://s1.ripple.com',                    httpUrl: 'https://s1.ripple.com:51234/',             network: 'xrpl-mainnet' },
  { name: 'Ripple s2',    url: 'wss://s2.ripple.com',                    httpUrl: 'https://s2.ripple.com:51234/',             network: 'xrpl-mainnet' },
  { name: 'xrpl.ws',      url: 'wss://xrpl.ws',                          httpUrl: 'https://xrpl.ws/',                         network: 'xrpl-mainnet' },
  { name: 'XRPL Cluster', url: 'wss://xrplcluster.com',                  httpUrl: 'https://xrplcluster.com/',                 network: 'xrpl-mainnet' },

  { name: 'Testnet',      url: 'wss://s.altnet.rippletest.net:51233',     httpUrl: 'https://s.altnet.rippletest.net:51234/',   network: 'xrpl-testnet' },
  { name: 'Xahau',        url: 'wss://xahau.network',                    httpUrl: 'https://xahau.network/',                   network: 'xahau-mainnet' },
];

export const ENDPOINTS_BY_NETWORK = {
  'xrpl-mainnet':  XRPL_ENDPOINTS.filter(e => e.network === 'xrpl-mainnet'),
  'xrpl-testnet':  XRPL_ENDPOINTS.filter(e => e.network === 'xrpl-testnet'),
  'xahau-mainnet': XRPL_ENDPOINTS.filter(e => e.network === 'xahau-mainnet'),
};

export const MAX_TX_BUFFER  = 300;
export const CHART_WINDOW   = 32;
export const LEDGER_LOG_MAX = 150;
export const WS_TIMEOUT_MS  = 12000;
export const MAX_RECONNECT_DELAY = 30000;

export const LS_SAVED   = 'naluxrp_saved_addresses';
export const LS_PINNED  = 'naluxrp_pinned_address';
export const LS_THEME   = 'naluxrp_theme';
export const LS_NETWORK = 'naluxrp_network';
export const LS_REDUCE_MOTION = 'naluxrp_reduce_motion'; // 'system' | 'reduce' | 'full'

// Optional: add exchange deposit hot wallets here to enable "exchange inflow/outflow" metrics.
// Leave empty to disable.
export const KNOWN_EXCHANGE_WALLETS = [
  // 'rEXAMPLE...'
];

export const THEMES = ['gold', 'cosmic', 'starry', 'hawaiian', 'highcontrast'];

export const TX_COLORS = {
  Payment:              '#50fa7b',
  OfferCreate:          '#ffb86c',
  OfferCancel:          '#ff6b6b',
  TrustSet:             '#50a8ff',
  NFTokenMint:          '#bd93f9',
  NFTokenBurn:          '#ff6b6b',
  NFTokenCreateOffer:   '#bd93f9',
  NFTokenCancelOffer:   '#f472b6',
  NFTokenAcceptOffer:   '#8b5cf6',
  AMMCreate:            '#00d4ff',
  AMMDeposit:           '#00ffaa',
  AMMWithdraw:          '#ffd700',
  AMMVote:              '#00fff0',
  AMMBid:               '#ff79c6',
  AMMDelete:            '#ff6b6b',
  EscrowCreate:         '#4ade80',
  EscrowFinish:         '#34d399',
  EscrowCancel:         '#fb923c',
  PaymentChannelCreate: '#60a5fa',
  PaymentChannelFund:   '#38bdf8',
  PaymentChannelClaim:  '#818cf8',
  CheckCreate:          '#a78bfa',
  CheckCash:            '#c084fc',
  CheckCancel:          '#f472b6',
  AccountSet:           '#94a3b8',
  AccountDelete:        '#ef4444',
  SetRegularKey:        '#78716c',
  SignerListSet:        '#71717a',
  Clawback:             '#dc2626',
  Other:                '#6b7280',
};