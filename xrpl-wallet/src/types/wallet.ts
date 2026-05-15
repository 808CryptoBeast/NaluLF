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
  amount?: string
  raw?: unknown
}

export interface ActivityEvent {
  id: string
  category: 'payment' | 'trustline' | 'nft' | 'amm' | 'account' | 'other'
  title: string
  detail: string
  txHash?: string
  status: string
  date: string
  raw?: unknown
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
  lpTokenCount: number
}

export interface SecuritySnapshot {
  baseReserveXrp: number
  ownerReserveXrp: number
  totalReserveXrp: number
  accountSequence: number
  baseFeeXrp: string
  accountFlags: string[]
}

export interface NetworkStats {
  ledgerIndex: number
  validatedLedgerHash: string
  networkLabel: string
}

export type PriceConfidence = 'high' | 'medium' | 'low' | 'unknown'

export interface AggregatedAsset {
  type: 'xrp' | 'token' | 'nft' | 'lp'
  name: string
  symbol: string
  quantity: number
  valueXrp: number
  valueUsd: number
  metadata?: string
  priceConfidence?: PriceConfidence
  priceSource?: string
}

export interface AmmPoolSummary {
  id: string
  label: string
  asset1Symbol: string
  asset1Issuer?: string
  asset2Symbol: string
  asset2Issuer?: string
  amount1: number
  amount2: number
  lpTokenSupply: number
  tradingFee: number
  auctionDiscountedFee?: number
  ammAccount?: string
  tvlXrp: number
  tvlUsd: number
  volume24hXrp: number
  volume24hUsd: number
  userLpTokens: number
  userPositionUsd: number
  compositionA: number
  compositionB: number
}
