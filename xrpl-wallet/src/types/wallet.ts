import type { Wallet } from 'xrpl'

export type NetworkType = 'mainnet' | 'testnet'

export interface StoredWallet {
  address: string
  seed: string
  publicKey: string
  algorithm: 'ed25519' | 'secp256k1'
  createdAt: string
}

export interface NetworkConfig {
  wsUrl: string
  label: string
  explorerTxBase: string
}

export interface UiTransaction {
  hash: string
  date?: string
  type: string
  result: string
  fee: string
}

export interface WalletSession {
  wallet: Wallet
  network: NetworkType
}

export interface TrustlineBalance {
  currency: string
  issuer: string
  balance: string
  limit: string
}

export interface NftAsset {
  NFTokenID: string
  URI?: string
  Issuer: string
  Flags: number
  TransferFee?: number
}

export interface AccountMetrics {
  trustlineCount: number
  nftCount: number
  xrpReserve: number
  recentTxCount: number
}
