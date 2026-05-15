import { create } from 'zustand'
import { persist } from 'zustand/middleware'
import { Wallet } from 'xrpl'
import { decryptSeed, encryptSeed } from '../lib/crypto'
import type {
  AccountMetrics,
  NetworkType,
  NftAsset,
  StoredWallet,
  TrustlineBalance,
  UiTransaction,
} from '../types/wallet'

interface WalletStore {
  network: NetworkType
  storedWallet: StoredWallet | null
  sessionWallet: Wallet | null
  balanceXrp: number
  reserveXrp: number
  trustlines: TrustlineBalance[]
  nfts: NftAsset[]
  transactions: UiTransaction[]
  metrics: AccountMetrics
  xrpUsdPrice: number
  lastUpdated?: string
  setNetwork: (network: NetworkType) => void
  loginWithWallet: (wallet: Wallet) => void
  lockWallet: () => void
  wipeWallet: () => void
  setAccountData: (payload: {
    balanceXrp: number
    reserve: number
    trustlines: TrustlineBalance[]
    nftAssets: NftAsset[]
    transactions: UiTransaction[]
    metrics: AccountMetrics
  }) => void
  setXrpUsdPrice: (price: number) => void
  exportEncryptedKeystore: (passphrase: string) => Promise<string>
  importEncryptedKeystore: (keystore: string, passphrase: string) => Promise<void>
}

const emptyMetrics: AccountMetrics = {
  trustlineCount: 0,
  nftCount: 0,
  xrpReserve: 0,
  recentTxCount: 0,
}

export const useWalletStore = create<WalletStore>()(
  persist(
    (set, get) => ({
      network: 'testnet',
      storedWallet: null,
      sessionWallet: null,
      balanceXrp: 0,
      reserveXrp: 0,
      trustlines: [],
      nfts: [],
      transactions: [],
      metrics: emptyMetrics,
      xrpUsdPrice: 0,
      setNetwork: (network) => set({ network }),
      loginWithWallet: (wallet) => {
        const seed = wallet.seed ?? ''
        set({
          sessionWallet: wallet,
          storedWallet: {
            address: wallet.classicAddress,
            seed,
            publicKey: wallet.publicKey,
            algorithm: wallet.publicKey.startsWith('ED') ? 'ed25519' : 'secp256k1',
            createdAt: new Date().toISOString(),
          },
        })
      },
      lockWallet: () => {
        set({ sessionWallet: null })
      },
      wipeWallet: () => {
        set({
          storedWallet: null,
          sessionWallet: null,
          balanceXrp: 0,
          reserveXrp: 0,
          trustlines: [],
          nfts: [],
          transactions: [],
          metrics: emptyMetrics,
          xrpUsdPrice: 0,
          lastUpdated: undefined,
        })
      },
      setAccountData: ({ balanceXrp, reserve, trustlines, nftAssets, transactions, metrics }) => {
        set({
          balanceXrp,
          reserveXrp: reserve,
          trustlines,
          nfts: nftAssets,
          transactions,
          metrics,
          lastUpdated: new Date().toISOString(),
        })
      },
      setXrpUsdPrice: (price) => {
        set({ xrpUsdPrice: price })
      },
      exportEncryptedKeystore: async (passphrase: string) => {
        const wallet = get().storedWallet
        if (!wallet?.seed) {
          throw new Error('No wallet seed available for export')
        }

        const encryptedSeed = await encryptSeed(wallet.seed, passphrase)
        return JSON.stringify(
          {
            type: 'xrpl-keystore',
            version: 1,
            address: wallet.address,
            algorithm: wallet.algorithm,
            encryptedSeed,
            createdAt: new Date().toISOString(),
          },
          null,
          2,
        )
      },
      importEncryptedKeystore: async (keystore, passphrase) => {
        const parsed = JSON.parse(keystore) as {
          encryptedSeed: string
        }
        const seed = await decryptSeed(parsed.encryptedSeed, passphrase)
        const wallet = Wallet.fromSeed(seed)
        get().loginWithWallet(wallet)
      },
    }),
    {
      name: 'xrpl-wallet-store',
      partialize: (state) => ({
        network: state.network,
        storedWallet: state.storedWallet,
      }),
    },
  ),
)
