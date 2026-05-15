import {
  Client,
  Wallet,
  xrpToDrops,
  dropsToXrp,
  type AccountInfoRequest,
  type AccountLinesRequest,
  type AccountNFTsRequest,
  type AccountTxRequest,
  type AMMBid,
  type AMMCreate,
  type AMMDeposit,
  type AMMVote,
  type AMMWithdraw,
  type EscrowCreate,
  type EscrowFinish,
  type NFTokenCreateOffer,
  type Payment,
  type PaymentChannelClaim,
  type PaymentChannelCreate,
  type TrustSet,
} from 'xrpl'
import type {
  AccountMetrics,
  NetworkConfig,
  NetworkType,
  NftAsset,
  TrustlineBalance,
  UiTransaction,
} from '../types/wallet'

export const NETWORKS: Record<NetworkType, NetworkConfig> = {
  mainnet: {
    wsUrl: 'wss://xrplcluster.com',
    label: 'Mainnet',
    explorerTxBase: 'https://livenet.xrpl.org/transactions/',
  },
  testnet: {
    wsUrl: 'wss://s.altnet.rippletest.net:51233',
    label: 'Testnet',
    explorerTxBase: 'https://testnet.xrpl.org/transactions/',
  },
}

const clients = new Map<NetworkType, Client>()

async function getClient(network: NetworkType): Promise<Client> {
  const existing = clients.get(network)
  if (existing?.isConnected()) {
    return existing
  }

  const client = existing ?? new Client(NETWORKS[network].wsUrl)
  if (!client.isConnected()) {
    await client.connect()
  }

  clients.set(network, client)
  return client
}

export function generateWalletEd25519(): Wallet {
  return Wallet.generate()
}

export function importWalletFromSeed(seed: string): Wallet {
  return Wallet.fromSeed(seed)
}

export function importWalletFromSecretNumbers(secretNumbers: string): Wallet {
  const normalized = secretNumbers
    .split(/[,\s]+/)
    .map((chunk) => chunk.trim())
    .filter(Boolean)
  return Wallet.fromSeed(normalized.join(''))
}

export async function fetchAccountState(account: string, network: NetworkType) {
  const client = await getClient(network)

  const info = await client.request({
    command: 'account_info',
    account,
    ledger_index: 'validated',
  } as AccountInfoRequest)

  const lines = await client.request({
    command: 'account_lines',
    account,
    ledger_index: 'validated',
  } as AccountLinesRequest)

  const nfts = await client.request({
    command: 'account_nfts',
    account,
    ledger_index: 'validated',
  } as AccountNFTsRequest)

  const tx = await client.request({
    command: 'account_tx',
    account,
    ledger_index_max: -1,
    ledger_index_min: -1,
    limit: 20,
  } as AccountTxRequest)

  const balanceXrp = Number(dropsToXrp(info.result.account_data.Balance))
  const ownerCount = Number(info.result.account_data.OwnerCount ?? 0)
  const reserve = 10 + ownerCount * 2

  const metrics: AccountMetrics = {
    trustlineCount: lines.result.lines.length,
    nftCount: nfts.result.account_nfts.length,
    xrpReserve: reserve,
    recentTxCount: tx.result.transactions.length,
  }

  const transactions: UiTransaction[] = tx.result.transactions.map((entry) => {
    const txData = typeof entry.tx === 'string' ? null : entry.tx
    return {
      hash: txData?.hash ?? 'Unknown',
      type: txData?.TransactionType ?? 'Unknown',
      result:
        typeof entry.meta === 'object' && entry.meta !== null
          ? String(entry.meta.TransactionResult ?? 'unknown')
          : 'unknown',
      fee: txData?.Fee ?? '0',
      date: txData?.date ? String(txData.date) : undefined,
    }
  })

  const trustlines: TrustlineBalance[] = lines.result.lines.map((line) => ({
    currency: line.currency,
    issuer: line.account,
    balance: line.balance,
    limit: line.limit,
  }))

  const nftAssets: NftAsset[] = nfts.result.account_nfts.map((asset) => ({
    NFTokenID: asset.NFTokenID,
    URI: asset.URI,
    Issuer: asset.Issuer,
    Flags: asset.Flags,
    TransferFee: (asset as unknown as Record<string, unknown>).TransferFee as number,
  }))

  return {
    balanceXrp,
    reserve,
    ownerCount,
    trustlines,
    nftAssets,
    transactions,
    metrics,
    sequence: Number(info.result.account_data.Sequence),
  }
}

async function submitLocallySigned(
  wallet: Wallet,
  network: NetworkType,
  tx: object,
) {
  const client = await getClient(network)
  const prepared = await client.autofill(tx as never)
  const signed = wallet.sign(prepared)
  return client.submitAndWait(signed.tx_blob)
}

export async function estimateFee(network: NetworkType): Promise<string> {
  const client = await getClient(network)
  const fee = (client as unknown as { getFee: () => string }).getFee?.() ?? '0.000012'
  return fee
}

export async function sendXrp(
  wallet: Wallet,
  network: NetworkType,
  destination: string,
  amountXrp: string,
  destinationTag?: number,
) {
  const tx: Payment = {
    TransactionType: 'Payment',
    Account: wallet.classicAddress,
    Destination: destination,
    Amount: xrpToDrops(amountXrp),
    ...(destinationTag ? { DestinationTag: destinationTag } : {}),
  }

  return submitLocallySigned(wallet, network, tx)
}

export async function sendIssuedToken(
  wallet: Wallet,
  network: NetworkType,
  destination: string,
  currency: string,
  issuer: string,
  value: string,
  destinationTag?: number,
) {
  const tx: Payment = {
    TransactionType: 'Payment',
    Account: wallet.classicAddress,
    Destination: destination,
    Amount: {
      currency,
      issuer,
      value,
    },
    ...(destinationTag ? { DestinationTag: destinationTag } : {}),
  }

  return submitLocallySigned(wallet, network, tx)
}

export async function sendNft(
  wallet: Wallet,
  network: NetworkType,
  nftId: string,
  destination: string,
) {
  const tx: NFTokenCreateOffer = {
    TransactionType: 'NFTokenCreateOffer',
    Account: wallet.classicAddress,
    NFTokenID: nftId,
    Destination: destination,
    Amount: '0',
    Flags: 1,
  }

  return submitLocallySigned(wallet, network, tx)
}

export async function createTrustline(
  wallet: Wallet,
  network: NetworkType,
  currency: string,
  issuer: string,
  limit: string,
) {
  const tx: TrustSet = {
    TransactionType: 'TrustSet',
    Account: wallet.classicAddress,
    LimitAmount: {
      currency,
      issuer,
      value: limit,
    },
  }

  return submitLocallySigned(wallet, network, tx)
}

export async function createAmm(
  wallet: Wallet,
  network: NetworkType,
  asset1: AMMCreate['Amount'],
  asset2: AMMCreate['Amount2'],
  tradingFee: number,
) {
  const tx: AMMCreate = {
    TransactionType: 'AMMCreate',
    Account: wallet.classicAddress,
    Amount: asset1,
    Amount2: asset2,
    TradingFee: tradingFee,
  }

  return submitLocallySigned(wallet, network, tx)
}

export function depositAmm(
  wallet: Wallet,
  network: NetworkType,
  asset1: AMMDeposit['Amount'],
  asset2: AMMDeposit['Amount2'],
) {
  const tx: AMMDeposit = {
    TransactionType: 'AMMDeposit',
    Account: wallet.classicAddress,
    Amount: asset1,
    Amount2: asset2,
    Asset: { currency: '', issuer: '' },
    Asset2: { currency: '', issuer: '' },
  }

  return submitLocallySigned(wallet, network, tx)
}

export async function withdrawAmm(
  wallet: Wallet,
  network: NetworkType,
  asset1: AMMWithdraw['Amount'],
  asset2: AMMWithdraw['Amount2'],
) {
  const tx: AMMWithdraw = {
    TransactionType: 'AMMWithdraw',
    Account: wallet.classicAddress,
    Amount: asset1,
    Amount2: asset2,
    Asset: { currency: '', issuer: '' },
    Asset2: { currency: '', issuer: '' },
  }

  return submitLocallySigned(wallet, network, tx)
}

export async function voteAmmFee(
  wallet: Wallet,
  network: NetworkType,
  asset: AMMVote['Asset'],
  asset2: AMMVote['Asset2'],
  tradingFee: number,
) {
  const tx: AMMVote = {
    TransactionType: 'AMMVote',
    Account: wallet.classicAddress,
    Asset: asset,
    Asset2: asset2,
    TradingFee: tradingFee,
  }

  return submitLocallySigned(wallet, network, tx)
}

export async function bidAmmAuction(
  wallet: Wallet,
  network: NetworkType,
  asset: AMMBid['Asset'],
  asset2: AMMBid['Asset2'],
  bidMin: string,
) {
  const tx: AMMBid = {
    TransactionType: 'AMMBid',
    Account: wallet.classicAddress,
    Asset: asset,
    Asset2: asset2,
    BidMin: {
      currency: '03',
      issuer: wallet.classicAddress,
      value: bidMin,
    } as never,
  }

  return submitLocallySigned(wallet, network, tx)
}

export async function createEscrow(
  wallet: Wallet,
  network: NetworkType,
  destination: string,
  amountXrp: string,
  finishAfterUnix: number,
) {
  const tx: EscrowCreate = {
    TransactionType: 'EscrowCreate',
    Account: wallet.classicAddress,
    Destination: destination,
    Amount: xrpToDrops(amountXrp),
    FinishAfter: finishAfterUnix,
  }

  return submitLocallySigned(wallet, network, tx)
}

export async function finishEscrow(
  wallet: Wallet,
  network: NetworkType,
  owner: string,
  offerSequence: number,
) {
  const tx: EscrowFinish = {
    TransactionType: 'EscrowFinish',
    Account: wallet.classicAddress,
    Owner: owner,
    OfferSequence: offerSequence,
  }

  return submitLocallySigned(wallet, network, tx)
}

export async function createPaymentChannel(
  wallet: Wallet,
  network: NetworkType,
  destination: string,
  amountXrp: string,
  settleDelay: number,
) {
  const tx: PaymentChannelCreate = {
    TransactionType: 'PaymentChannelCreate',
    Account: wallet.classicAddress,
    Destination: destination,
    Amount: xrpToDrops(amountXrp),
    SettleDelay: settleDelay,
    PublicKey: wallet.publicKey,
  }

  return submitLocallySigned(wallet, network, tx)
}

export async function claimPaymentChannel(
  wallet: Wallet,
  network: NetworkType,
  channelId: string,
  amountDrops: string,
) {
  const tx: PaymentChannelClaim = {
    TransactionType: 'PaymentChannelClaim',
    Account: wallet.classicAddress,
    Channel: channelId,
    Balance: amountDrops,
  }

  return submitLocallySigned(wallet, network, tx)
}

export async function subscribeAccount(
  network: NetworkType,
  account: string,
  callback: () => void,
): Promise<() => Promise<void>> {
  const client = await getClient(network)
  await client.request({ command: 'subscribe', accounts: [account] })

  const handler = () => callback()
  client.on('transaction', handler)

  return async () => {
    client.off('transaction', handler)
    if (client.isConnected()) {
      await client.request({ command: 'unsubscribe', accounts: [account] })
    }
  }
}

export function getExplorerUrl(network: NetworkType, hash: string): string {
  return `${NETWORKS[network].explorerTxBase}${hash}`
}

export async function disconnectAllClients() {
  for (const [, client] of clients.entries()) {
    if (client.isConnected()) {
      await client.disconnect()
    }
  }
  clients.clear()
}
