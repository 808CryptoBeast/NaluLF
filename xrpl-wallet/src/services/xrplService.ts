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
  type OfferCreate,
  type Payment,
  type PaymentChannelClaim,
  type PaymentChannelCreate,
  type TrustSet,
} from 'xrpl'
import type {
  ActivityEvent,
  AggregatedAsset,
  AccountMetrics,
  AmmPoolSummary,
  NetworkConfig,
  NetworkType,
  NetworkStats,
  NftAsset,
  SecuritySnapshot,
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
const AMM_POOL_CACHE_KEY = 'xrpl-wallet-amm-pools-v1'

const FLAG_MAP: Record<number, string> = {
  0x00010000: 'RequireDestTag',
  0x00020000: 'RequireAuth',
  0x00040000: 'DisallowXRP',
  0x00100000: 'DisableMasterKey',
  0x00200000: 'AccountTxnID',
  0x00400000: 'NoFreeze',
  0x00800000: 'GlobalFreeze',
  0x01000000: 'DefaultRipple',
  0x02000000: 'DepositAuth',
  0x04000000: 'AuthorizedNFTokenMinter',
  0x08000000: 'DisallowIncomingNFTokenOffer',
  0x10000000: 'DisallowIncomingCheck',
  0x20000000: 'DisallowIncomingPayChan',
  0x40000000: 'DisallowIncomingTrustline',
  0x80000000: 'AllowTrustLineClawback',
}

function fromRippleEpoch(epoch?: number): string {
  if (!epoch) {
    return new Date().toISOString()
  }
  return new Date((epoch + 946684800) * 1000).toISOString()
}

function parseFlags(flags: number): string[] {
  return Object.entries(FLAG_MAP)
    .filter(([mask]) => (flags & Number(mask)) !== 0)
    .map(([, label]) => label)
}

function inferActivity(tx: UiTransaction): ActivityEvent {
  const lowered = tx.type.toLowerCase()
  let category: ActivityEvent['category'] = 'other'

  if (lowered.includes('payment')) {
    category = 'payment'
  } else if (lowered.includes('trust')) {
    category = 'trustline'
  } else if (lowered.includes('nft') || lowered.includes('tokenoffer')) {
    category = 'nft'
  } else if (lowered.includes('amm')) {
    category = 'amm'
  } else if (lowered.includes('account')) {
    category = 'account'
  }

  return {
    id: tx.hash,
    category,
    title: tx.type,
    detail: tx.amount ? `Amount: ${tx.amount}` : 'XRPL transaction event',
    txHash: tx.hash,
    status: tx.result,
    date: tx.date ?? new Date().toISOString(),
    raw: tx.raw,
  }
}

function normalizeAmount(value: unknown): number {
  if (typeof value === 'string') {
    return Number(dropsToXrp(value))
  }
  if (typeof value === 'object' && value !== null && 'value' in value) {
    return Number((value as { value: string }).value)
  }
  return 0
}

function amountToAssetRef(amount: unknown): string | null {
  if (typeof amount === 'string') {
    return 'XRP'
  }
  if (typeof amount === 'object' && amount !== null) {
    const rec = amount as { currency?: string; issuer?: string }
    if (rec.currency && rec.issuer) {
      return `${rec.currency}:${rec.issuer}`
    }
  }
  return null
}

function readCachedPoolPairs(): string[] {
  try {
    const raw = localStorage.getItem(AMM_POOL_CACHE_KEY)
    if (!raw) {
      return []
    }
    const parsed = JSON.parse(raw) as string[]
    return Array.isArray(parsed) ? parsed : []
  } catch {
    return []
  }
}

function writeCachedPoolPairs(pairs: string[]) {
  try {
    localStorage.setItem(AMM_POOL_CACHE_KEY, JSON.stringify([...new Set(pairs)].slice(0, 300)))
  } catch {
    // Ignore cache failures in private browsing or restricted storage contexts.
  }
}

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

  const serverInfo = await client.request({ command: 'server_info' })
  const fee = await client.request({ command: 'fee' })

  const balanceXrp = Number(dropsToXrp(info.result.account_data.Balance))
  const ownerCount = Number(info.result.account_data.OwnerCount ?? 0)
  const reserve = 10 + ownerCount * 2

  const metrics: AccountMetrics = {
    trustlineCount: lines.result.lines.length,
    nftCount: nfts.result.account_nfts.length,
    xrpReserve: reserve,
    recentTxCount: tx.result.transactions.length,
    lpTokenCount: lines.result.lines.filter((line) => line.currency.startsWith('03')).length,
  }

  const transactions: UiTransaction[] = tx.result.transactions.map((entry) => {
    const txData = typeof entry.tx === 'string' ? null : entry.tx
    const amountValue = txData && 'Amount' in txData ? (txData as { Amount?: unknown }).Amount : undefined
    return {
      hash: txData?.hash ?? 'Unknown',
      type: txData?.TransactionType ?? 'Unknown',
      result:
        typeof entry.meta === 'object' && entry.meta !== null
          ? String(entry.meta.TransactionResult ?? 'unknown')
          : 'unknown',
      fee: txData?.Fee ?? '0',
      date: fromRippleEpoch(typeof txData?.date === 'number' ? txData.date : undefined),
      amount:
        amountValue !== undefined
          ? typeof amountValue === 'string'
            ? dropsToXrp(amountValue)
            : (amountValue as { value?: string }).value
          : undefined,
      raw: txData,
    }
  })

  const activity: ActivityEvent[] = transactions.map(inferActivity)

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

  const security: SecuritySnapshot = {
    baseReserveXrp: 10,
    ownerReserveXrp: ownerCount * 2,
    totalReserveXrp: reserve,
    accountSequence: Number(info.result.account_data.Sequence),
    baseFeeXrp:
      (fee.result?.drops as { base_fee?: string } | undefined)?.base_fee
        ? dropsToXrp((fee.result.drops as { base_fee: string }).base_fee)
        : '0.000012',
    accountFlags: parseFlags(Number(info.result.account_data.Flags ?? 0)),
  }

  const validated = (serverInfo.result.info as { validated_ledger?: { seq?: number; hash?: string } })
    .validated_ledger
  const networkStats: NetworkStats = {
    ledgerIndex: Number(validated?.seq ?? 0),
    validatedLedgerHash: String(validated?.hash ?? '-'),
    networkLabel: NETWORKS[network].label,
  }

  const aggregatedAssets: AggregatedAsset[] = [
    {
      type: 'xrp',
      name: 'XRP',
      symbol: 'XRP',
      quantity: balanceXrp,
      valueXrp: balanceXrp,
      valueUsd: 0,
      metadata: 'Native XRPL balance',
    },
    ...trustlines.map((line) => ({
      type: (line.currency.startsWith('03') ? 'lp' : 'token') as 'lp' | 'token',
      name: line.currency.startsWith('03') ? `LP ${line.currency.slice(0, 8)}` : line.currency,
      symbol: line.currency,
      quantity: Number(line.balance),
      valueXrp: 0,
      valueUsd: 0,
      metadata: line.issuer,
    })),
    {
      type: 'nft' as const,
      name: 'XRPL NFTs',
      symbol: 'NFT',
      quantity: nftAssets.length,
      valueXrp: 0,
      valueUsd: 0,
      metadata: 'Estimated value requires marketplace pricing',
    },
  ]

  return {
    balanceXrp,
    reserve,
    ownerCount,
    trustlines,
    nftAssets,
    transactions,
    activity,
    security,
    networkStats,
    aggregatedAssets,
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
  const fee = await client.request({ command: 'fee' })
  const baseDrops = (fee.result?.drops as { open_ledger_fee?: string } | undefined)?.open_ledger_fee
  return baseDrops ? dropsToXrp(baseDrops) : '0.000012'
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
  callback: (event?: unknown) => void,
): Promise<() => Promise<void>> {
  const client = await getClient(network)
  await client.request({ command: 'subscribe', accounts: [account] })

  const handler = (event: unknown) => callback(event)
  client.on('transaction', handler)

  return async () => {
    client.off('transaction', handler)
    if (client.isConnected()) {
      await client.request({ command: 'unsubscribe', accounts: [account] })
    }
  }
}

type AssetRef =
  | { currency: string; issuer: string }
  | 'XRP'

function parseAssetRef(input: string): AssetRef {
  if (input.toUpperCase() === 'XRP') {
    return 'XRP'
  }
  const [currency, issuer] = input.split(':')
  return { currency, issuer }
}

export async function fetchAmmPool(
  network: NetworkType,
  assetA: string,
  assetB: string,
  xrpUsdPrice: number,
): Promise<AmmPoolSummary | null> {
  const client = await getClient(network)

  try {
    const req = {
      command: 'amm_info',
      asset: parseAssetRef(assetA),
      asset2: parseAssetRef(assetB),
    }
    const response = (await client.request(req)) as {
      result: {
        amm: {
          account?: string
          amount: unknown
          amount2: unknown
          lp_token?: { value?: string }
          trading_fee?: number
          auction_slot?: { discounted_fee?: number }
        }
      }
    }
    const amm = response.result.amm as {
      account?: string
      amount: unknown
      amount2: unknown
      lp_token?: { value?: string }
      trading_fee?: number
      auction_slot?: { discounted_fee?: number }
    }

    const amount1 = normalizeAmount(amm.amount)
    const amount2 = normalizeAmount(amm.amount2)
    const tvlXrp = amount1 + amount2
    const tvlUsd = tvlXrp * xrpUsdPrice
    const compositionA = tvlXrp > 0 ? (amount1 / tvlXrp) * 100 : 50
    const compositionB = Math.max(0, 100 - compositionA)

    const parsedA = parseAssetRef(assetA)
    const parsedB = parseAssetRef(assetB)

    return {
      id: `${assetA}-${assetB}`,
      label: `${assetA.split(':')[0]}/${assetB.split(':')[0]}`,
      asset1Symbol: assetA.split(':')[0],
      asset1Issuer: parsedA === 'XRP' ? undefined : parsedA.issuer,
      asset2Symbol: assetB.split(':')[0],
      asset2Issuer: parsedB === 'XRP' ? undefined : parsedB.issuer,
      amount1,
      amount2,
      lpTokenSupply: Number(amm.lp_token?.value ?? 0),
      tradingFee: Number(amm.trading_fee ?? 0),
      auctionDiscountedFee: amm.auction_slot?.discounted_fee,
      ammAccount: amm.account,
      tvlXrp,
      tvlUsd,
      volume24hXrp: 0,
      volume24hUsd: 0,
      userLpTokens: 0,
      userPositionUsd: 0,
      compositionA,
      compositionB,
    }
  } catch {
    return null
  }
}

export async function discoverAmmPools(
  network: NetworkType,
  trustlines: TrustlineBalance[],
  xrpUsdPrice: number,
): Promise<AmmPoolSummary[]> {
  const cachedPairs = readCachedPoolPairs()
  const candidates = new Set<string>([
    'USD:rhub8VRN55s94qWKDv6jmDy1pUykJzF3wq',
    'EUR:rhub8VRN55s94qWKDv6jmDy1pUykJzF3wq',
    ...cachedPairs.flatMap((pair) => pair.split('|')),
  ])
  trustlines.slice(0, 15).forEach((line) => {
    candidates.add(`${line.currency}:${line.issuer}`)
  })

  const client = await getClient(network)
  try {
    const info = await client.request({ command: 'server_info' })
    const validated = (info.result.info as { validated_ledger?: { seq?: number } }).validated_ledger
    const latest = Number(validated?.seq ?? 0)
    const discoveredPairs: string[] = []

    for (let seq = latest; seq > Math.max(0, latest - 20); seq -= 1) {
      const ledger = await client.request({
        command: 'ledger',
        ledger_index: seq,
        transactions: true,
        expand: true,
      })
      const txs = (ledger.result.ledger as { transactions?: unknown[] }).transactions ?? []
      txs.forEach((entry) => {
        const tx = entry as { TransactionType?: string; Amount?: unknown; Amount2?: unknown }
        if (tx.TransactionType !== 'AMMCreate') {
          return
        }
        const a = amountToAssetRef(tx.Amount)
        const b = amountToAssetRef(tx.Amount2)
        if (a && b) {
          discoveredPairs.push(`${a}|${b}`)
          candidates.add(a)
          candidates.add(b)
        }
      })
    }

    if (discoveredPairs.length) {
      writeCachedPoolPairs([...readCachedPoolPairs(), ...discoveredPairs])
    }
  } catch {
    // Fallback to cached + trustline candidates when ledger scan is unavailable.
  }

  const pairCandidates = new Set<string>(cachedPairs)
  ;[...candidates].forEach((token) => {
    if (token !== 'XRP') {
      pairCandidates.add(`XRP|${token}`)
    }
  })

  const pools = await Promise.all(
    [...pairCandidates].map((pair) => {
      const [a, b] = pair.split('|')
      return fetchAmmPool(network, a, b, xrpUsdPrice)
    }),
  )

  return pools.filter((pool): pool is AmmPoolSummary => pool !== null)
}

export function enrichPoolSnapshots(
  nextPools: AmmPoolSummary[],
  prevPools: AmmPoolSummary[],
): AmmPoolSummary[] {
  const prevMap = new Map(prevPools.map((p) => [p.id, p]))
  return nextPools.map((pool) => {
    const prev = prevMap.get(pool.id)
    if (!prev) {
      return pool
    }
    const volume24hXrp = Math.max(Math.abs(pool.amount1 - prev.amount1) + Math.abs(pool.amount2 - prev.amount2), 0)
    return {
      ...pool,
      volume24hXrp,
      volume24hUsd: volume24hXrp * (pool.tvlUsd / Math.max(pool.tvlXrp, 0.000001)),
    }
  })
}

export function applyUserLpPositions(
  pools: AmmPoolSummary[],
  trustlines: TrustlineBalance[],
): AmmPoolSummary[] {
  return pools.map((pool) => {
    const line = trustlines.find((t) => t.currency.startsWith('03') && t.issuer === pool.ammAccount)
    const userLpTokens = Number(line?.balance ?? 0)
    const ratio = pool.lpTokenSupply > 0 ? userLpTokens / pool.lpTokenSupply : 0
    return {
      ...pool,
      userLpTokens,
      userPositionUsd: pool.tvlUsd * ratio,
    }
  })
}

export async function subscribeLedger(
  network: NetworkType,
  callback: () => void,
): Promise<() => Promise<void>> {
  const client = await getClient(network)
  await client.request({ command: 'subscribe', streams: ['ledger'] })

  const handler = () => callback()
  client.on('ledgerClosed', handler)

  return async () => {
    client.off('ledgerClosed', handler)
    if (client.isConnected()) {
      await client.request({ command: 'unsubscribe', streams: ['ledger'] })
    }
  }
}

function toSwapAmount(
  asset: { currency: string; issuer?: string },
  amount: string,
): string | { currency: string; issuer: string; value: string } {
  if (asset.currency.toUpperCase() === 'XRP') {
    return xrpToDrops(amount)
  }
  return {
    currency: asset.currency,
    issuer: asset.issuer ?? '',
    value: amount,
  }
}

export async function executeSwapOffer(
  wallet: Wallet,
  network: NetworkType,
  params: {
    from: { currency: string; issuer?: string }
    to: { currency: string; issuer?: string }
    amountIn: string
    expectedOut: string
    slippagePct: number
  },
): Promise<{ txHash?: string; status?: string }> {
  const amountIn = Number(params.amountIn)
  const expectedOut = Number(params.expectedOut)
  const safeSlippage = Math.max(0, Math.min(params.slippagePct, 50))

  if (!Number.isFinite(amountIn) || amountIn <= 0 || !Number.isFinite(expectedOut) || expectedOut <= 0) {
    throw new Error('Invalid swap sizing. Enter a positive amount and quote first.')
  }

  const minOut = expectedOut * (1 - safeSlippage / 100)
  const tx: OfferCreate = {
    TransactionType: 'OfferCreate',
    Account: wallet.classicAddress,
    TakerPays: toSwapAmount(params.from, amountIn.toString()),
    TakerGets: toSwapAmount(params.to, minOut.toString()),
    Flags: 0x00020000,
  }

  const response = (await submitLocallySigned(wallet, network, tx)) as {
    result?: {
      hash?: string
      meta?: { TransactionResult?: string }
      tx_json?: { hash?: string }
    }
  }

  return {
    txHash: response.result?.hash ?? response.result?.tx_json?.hash,
    status: response.result?.meta?.TransactionResult,
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
