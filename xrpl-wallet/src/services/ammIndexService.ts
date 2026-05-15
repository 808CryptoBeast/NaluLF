import type { AmmPoolSummary, NetworkType } from '../types/wallet'

interface IndexedPool {
  pair: string
  amount1: number
  amount2: number
  lpTokenSupply: number
  tradingFee: number
  auctionDiscountedFee?: number
  ammAccount?: string
  asset1Symbol: string
  asset1Issuer?: string
  asset2Symbol: string
  asset2Issuer?: string
}

function deriveTvls(pool: IndexedPool, xrpUsdPrice: number): AmmPoolSummary {
  const tvlXrp = pool.amount1 + pool.amount2
  const tvlUsd = tvlXrp * xrpUsdPrice
  const compositionA = tvlXrp > 0 ? (pool.amount1 / tvlXrp) * 100 : 50

  return {
    id: pool.pair,
    label: `${pool.asset1Symbol}/${pool.asset2Symbol}`,
    asset1Symbol: pool.asset1Symbol,
    asset1Issuer: pool.asset1Issuer,
    asset2Symbol: pool.asset2Symbol,
    asset2Issuer: pool.asset2Issuer,
    amount1: pool.amount1,
    amount2: pool.amount2,
    lpTokenSupply: pool.lpTokenSupply,
    tradingFee: pool.tradingFee,
    auctionDiscountedFee: pool.auctionDiscountedFee,
    ammAccount: pool.ammAccount,
    tvlXrp,
    tvlUsd,
    volume24hXrp: 0,
    volume24hUsd: 0,
    userLpTokens: 0,
    userPositionUsd: 0,
    compositionA,
    compositionB: Math.max(0, 100 - compositionA),
  }
}

export async function fetchIndexedAmmPools(
  network: NetworkType,
  xrpUsdPrice: number,
): Promise<AmmPoolSummary[]> {
  const base = import.meta.env.VITE_AMM_INDEX_URL ?? 'http://localhost:8787'
  const response = await fetch(`${base}/api/amm/pools?network=${network}`, {
    method: 'GET',
    headers: { Accept: 'application/json' },
  })

  if (!response.ok) {
    throw new Error(`AMM index API error: ${response.status}`)
  }

  const payload = (await response.json()) as { pools?: IndexedPool[] }
  return (payload.pools ?? []).map((pool) => deriveTvls(pool, xrpUsdPrice))
}
