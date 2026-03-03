/* =====================================================
   config.js — Network Endpoints · Constants · LS Keys
   ===================================================== */

export const XRPL_ENDPOINTS = [
  // Prefer Ripple first (fast + stable)
  { name: 'Ripple s1',    url: 'wss://s1.ripple.com',                    network: 'xrpl-mainnet' },
  { name: 'Ripple s2',    url: 'wss://s2.ripple.com',                    network: 'xrpl-mainnet' },
  { name: 'xrpl.ws',      url: 'wss://xrpl.ws',                          network: 'xrpl-mainnet' },
  { name: 'XRPL Cluster', url: 'wss://xrplcluster.com',                  network: 'xrpl-mainnet' },

  { name: 'Testnet',      url: 'wss://s.altnet.rippletest.net:51233',     network: 'xrpl-testnet' },
  { name: 'Xahau',        url: 'wss://xahau.network',                    network: 'xahau-mainnet' },
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

// Optional: add exchange deposit hot wallets here to enable "exchange inflow/outflow" metrics.
// Leave empty to disable.
export const KNOWN_EXCHANGE_WALLETS = [
  // 'rEXAMPLE...'
];

export const THEMES = ['gold', 'cosmic', 'starry', 'hawaiian'];

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