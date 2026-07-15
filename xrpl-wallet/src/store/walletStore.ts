import { create } from 'zustand'
import { ECDSA, Wallet } from 'xrpl'
import { decryptSeed, encryptSeed } from '../lib/crypto'
import { logActivity } from '../lib/naluActivity'
import { readDefaultNetwork } from '../lib/naluPreferences'
import type {
  ActivityEvent,
  AggregatedAsset,
  AccountMetrics,
  NetworkType,
  NetworkStats,
  NftAsset,
  SecuritySnapshot,
  StoredWallet,
  TrustlineBalance,
  UiTransaction,
} from '../types/wallet'

/**
 * Wallets live in the SAME localStorage keys NaluLF/scripts/profile.js and
 * inspector.js already read/write (`nalulf_wallets` / `naluxrp_active_wallet`)
 * — this store does not own that data, it's just another reader/writer of it.
 * Deliberately not using zustand's `persist` middleware: secret material
 * (decrypted seeds / xrpl.js Wallet instances) must never touch localStorage,
 * only the already-encrypted `encSeed` blob does, written by createWallet/
 * importWalletFromSeed via the same PBKDF2+AES-GCM scheme as profile.js.
 */
const LS_WALLETS = 'nalulf_wallets'
const LS_ACTIVE_ID = 'naluxrp_active_wallet'

function readWallets(): StoredWallet[] {
  try {
    const raw = localStorage.getItem(LS_WALLETS)
    const parsed = raw ? JSON.parse(raw) : []
    return Array.isArray(parsed) ? parsed : []
  } catch {
    return []
  }
}

function writeWallets(wallets: StoredWallet[]) {
  localStorage.setItem(LS_WALLETS, JSON.stringify(wallets))
}

function readActiveWalletId(wallets: StoredWallet[]): string | null {
  return localStorage.getItem(LS_ACTIVE_ID) || wallets[0]?.id || null
}

function writeActiveWalletId(id: string) {
  localStorage.setItem(LS_ACTIVE_ID, id)
}

const XRP_ADDRESS_RE = /^r[1-9A-HJ-NP-Za-km-z]{24,34}$/

interface PassphraseRequest {
  walletLabel: string
  resolve: (passphrase: string) => void
  reject: (err: Error) => void
}

interface WalletStore {
  network: NetworkType
  wallets: StoredWallet[]
  activeWalletId: string | null
  /** Decrypted xrpl.js Wallet for the active wallet, in-memory only — never persisted. */
  sessionWallet: Wallet | null
  pendingPassphraseRequest: PassphraseRequest | null
  balanceXrp: number
  reserveXrp: number
  trustlines: TrustlineBalance[]
  nfts: NftAsset[]
  transactions: UiTransaction[]
  activity: ActivityEvent[]
  security: SecuritySnapshot
  networkStats: NetworkStats
  aggregatedAssets: AggregatedAsset[]
  metrics: AccountMetrics
  xrpUsdPrice: number
  lastUpdated?: string

  setNetwork: (network: NetworkType) => void
  activeWallet: () => StoredWallet | null
  setActiveWallet: (id: string) => void
  createWallet: (opts: {
    label: string
    algo: 'ed25519' | 'secp256k1'
    emoji: string
    color: string
    testnet: boolean
    passphrase: string
  }) => Promise<{ wallet: StoredWallet; seed: string }>
  importWalletFromSeed: (opts: {
    label: string
    seed: string
    passphrase: string
    testnet: boolean
  }) => Promise<StoredWallet>
  importWatchOnlyWallet: (opts: { label: string; address: string }) => StoredWallet
  deleteWallet: (id: string) => void
  /** Returns a decrypted xrpl.js Wallet for signing, prompting for the wallet's
   *  passphrase via pendingPassphraseRequest if not already unlocked this session. */
  getUnlockedWallet: () => Promise<Wallet>
  requestPassphrase: (walletLabel: string) => Promise<string>
  resolvePassphrase: (passphrase: string) => void
  cancelPassphrase: () => void
  lockWallet: () => void

  setAccountData: (payload: {
    balanceXrp: number
    reserve: number
    trustlines: TrustlineBalance[]
    nftAssets: NftAsset[]
    transactions: UiTransaction[]
    activity: ActivityEvent[]
    security: SecuritySnapshot
    networkStats: NetworkStats
    aggregatedAssets: AggregatedAsset[]
    metrics: AccountMetrics
  }) => void
  setXrpUsdPrice: (price: number) => void
  /** Network-wide state (ledger/fee) — safe to refresh with no wallet at all. */
  setNetworkStats: (stats: NetworkStats) => void
}

const emptyMetrics: AccountMetrics = {
  trustlineCount: 0,
  nftCount: 0,
  xrpReserve: 0,
  recentTxCount: 0,
  lpTokenCount: 0,
}

const emptySecurity: SecuritySnapshot = {
  baseReserveXrp: 10,
  ownerReserveXrp: 0,
  totalReserveXrp: 10,
  accountSequence: 0,
  baseFeeXrp: '0.000012',
  accountFlags: [],
}

const emptyNetworkStats: NetworkStats = {
  ledgerIndex: 0,
  validatedLedgerHash: '-',
  networkLabel: 'Unknown',
}

const emptyAccountData = {
  balanceXrp: 0,
  reserveXrp: 0,
  trustlines: [] as TrustlineBalance[],
  nfts: [] as NftAsset[],
  transactions: [] as UiTransaction[],
  activity: [] as ActivityEvent[],
  security: emptySecurity,
  networkStats: emptyNetworkStats,
  aggregatedAssets: [] as AggregatedAsset[],
  metrics: emptyMetrics,
  xrpUsdPrice: 0,
  lastUpdated: undefined as string | undefined,
}

const initialWallets = readWallets()

export const useWalletStore = create<WalletStore>()((set, get) => ({
  network: readDefaultNetwork(),
  wallets: initialWallets,
  activeWalletId: readActiveWalletId(initialWallets),
  sessionWallet: null,
  pendingPassphraseRequest: null,
  ...emptyAccountData,

  setNetwork: (network) => set({ network }),

  activeWallet: () => {
    const { wallets, activeWalletId } = get()
    return wallets.find((w) => w.id === activeWalletId) || wallets[0] || null
  },

  setActiveWallet: (id) => {
    if (!get().wallets.find((w) => w.id === id)) return
    writeActiveWalletId(id)
    set({ activeWalletId: id, sessionWallet: null, ...emptyAccountData })
  },

  createWallet: async ({ label, algo, emoji, color, testnet, passphrase }) => {
    const generated = Wallet.generate(algo === 'ed25519' ? ECDSA.ed25519 : ECDSA.secp256k1)
    const seed = generated.seed ?? ''
    const encSeed = await encryptSeed(seed, passphrase)
    const wallet: StoredWallet = {
      id: crypto.randomUUID(),
      label,
      address: generated.classicAddress,
      algo,
      emoji,
      color,
      testnet,
      watchOnly: false,
      encSeed,
      createdAt: new Date().toISOString(),
    }

    const wallets = [...get().wallets, wallet]
    writeWallets(wallets)
    const activeWalletId = get().activeWalletId ?? wallet.id
    if (!get().activeWalletId) writeActiveWalletId(wallet.id)
    set({ wallets, activeWalletId, sessionWallet: generated })
    logActivity('wallet_created', wallet.label)
    return { wallet, seed }
  },

  importWalletFromSeed: async ({ label, seed, passphrase, testnet }) => {
    const generated = Wallet.fromSeed(seed)
    const address = generated.classicAddress
    if (get().wallets.find((w) => w.address === address)) {
      throw new Error('This address is already in your vault.')
    }
    const algo: 'ed25519' | 'secp256k1' = generated.publicKey.startsWith('ED')
      ? 'ed25519'
      : 'secp256k1'
    const encSeed = await encryptSeed(seed, passphrase)
    const wallet: StoredWallet = {
      id: `imp_${Date.now()}`,
      label,
      address,
      algo,
      emoji: '🔑',
      color: '#bd93f9',
      testnet,
      watchOnly: false,
      encSeed,
      createdAt: new Date().toISOString(),
    }

    const wallets = [...get().wallets, wallet]
    writeWallets(wallets)
    const activeWalletId = get().activeWalletId ?? wallet.id
    if (!get().activeWalletId) writeActiveWalletId(wallet.id)
    set({ wallets, activeWalletId, sessionWallet: generated })
    logActivity('wallet_imported', `${wallet.label} (${wallet.address.slice(0, 8)}…)`)
    return wallet
  },

  importWatchOnlyWallet: ({ label, address }) => {
    if (!XRP_ADDRESS_RE.test(address)) {
      throw new Error('Enter a valid XRPL address (starts with r…)')
    }
    if (get().wallets.find((w) => w.address === address)) {
      throw new Error('This address is already in your list.')
    }
    const wallet: StoredWallet = {
      id: `watch_${Date.now()}`,
      label: label || 'Watch Wallet',
      address,
      algo: '—',
      emoji: '👁',
      color: '#8be9fd',
      testnet: false,
      watchOnly: true,
      createdAt: new Date().toISOString(),
    }

    const wallets = [...get().wallets, wallet]
    writeWallets(wallets)
    const activeWalletId = get().activeWalletId ?? wallet.id
    if (!get().activeWalletId) writeActiveWalletId(wallet.id)
    set({ wallets, activeWalletId })
    logActivity('watch_added', `${wallet.label} (${wallet.address.slice(0, 8)}…)`)
    return wallet
  },

  deleteWallet: (id) => {
    const removed = get().wallets.find((w) => w.id === id)
    const wallets = get().wallets.filter((w) => w.id !== id)
    writeWallets(wallets)
    const wasActive = get().activeWalletId === id
    if (!wasActive) {
      set({ wallets })
      if (removed) logActivity('wallet_removed', removed.label)
      return
    }
    const nextActiveId = wallets[0]?.id || null
    if (nextActiveId) writeActiveWalletId(nextActiveId)
    set({ wallets, activeWalletId: nextActiveId, sessionWallet: null, ...emptyAccountData })
    if (removed) logActivity('wallet_removed', removed.label)
  },

  requestPassphrase: (walletLabel) =>
    new Promise<string>((resolve, reject) => {
      set({ pendingPassphraseRequest: { walletLabel, resolve, reject } })
    }),

  resolvePassphrase: (passphrase) => {
    const req = get().pendingPassphraseRequest
    set({ pendingPassphraseRequest: null })
    req?.resolve(passphrase)
  },

  cancelPassphrase: () => {
    const req = get().pendingPassphraseRequest
    set({ pendingPassphraseRequest: null })
    req?.reject(new Error('Wallet password entry was cancelled.'))
  },

  getUnlockedWallet: async () => {
    const active = get().activeWallet()
    if (!active) throw new Error('No active wallet selected.')
    if (active.watchOnly || !active.encSeed) {
      throw new Error('This is a watch-only wallet — import its seed to enable signing.')
    }

    const cached = get().sessionWallet
    if (cached && cached.classicAddress === active.address) return cached

    const passphrase = await get().requestPassphrase(active.label)
    let seed: string
    try {
      seed = await decryptSeed(active.encSeed, passphrase)
    } catch {
      throw new Error('Could not decrypt wallet seed. Check your wallet password and try again.')
    }
    const wallet = Wallet.fromSeed(seed)
    set({ sessionWallet: wallet })
    return wallet
  },

  lockWallet: () => set({ sessionWallet: null }),

  setAccountData: ({
    balanceXrp,
    reserve,
    trustlines,
    nftAssets,
    transactions,
    activity,
    security,
    networkStats,
    aggregatedAssets,
    metrics,
  }) => {
    set({
      balanceXrp,
      reserveXrp: reserve,
      trustlines,
      nfts: nftAssets,
      transactions,
      activity,
      security,
      networkStats,
      aggregatedAssets,
      metrics,
      lastUpdated: new Date().toISOString(),
    })
  },

  setXrpUsdPrice: (price) => set({ xrpUsdPrice: price }),
  setNetworkStats: (networkStats) => set({ networkStats }),
}))
