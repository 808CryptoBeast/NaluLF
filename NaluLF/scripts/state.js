/* =====================================================
   state.js — Shared Mutable Application State
   Import this object in any module that needs to read
   or write shared state. Mutate in-place; don't reassign.
   ===================================================== */

export const state = {
  // Auth
  session: null,        // { name, email } or null

  // Connection
  wsConn:         null,
  wsRetry:        0,
  currentNetwork: 'xrpl-mainnet',
  endpointIdx:    0,
  reconnectTimer: null,
  pendingReqs:    {},   // id → { resolve, reject, timer }
  reqId:          0,
  connectionState: 'disconnected',  // 'disconnected' | 'connecting' | 'connected'

  // Ledger data buffers
  tpsHistory:   [],
  feeHistory:   [],
  ledgerLog:    [],
  txMixAccum:   {},
  lastCloseTs:  null,

  // UI
  currentTheme: 'gold',
  currentPage:  'landing',
  currentTab:   'stream',

  // Saved addresses (mirrors localStorage)
  savedAddresses: [],
  pinnedAddress:  null,
};