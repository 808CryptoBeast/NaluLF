import type { ChartPoint, ChartTimeframe, TradingToken } from '../store/tradingStore'

const SYMBOL_TO_COINGECKO: Record<string, string> = {
  XRP: 'ripple',
  BTC: 'bitcoin',
  ETH: 'ethereum',
  USDC: 'usd-coin',
  USDT: 'tether',
  SOL: 'solana',
  ADA: 'cardano',
}

const TIMEFRAME_POINTS: Record<ChartTimeframe, number> = {
  '1m': 90,
  '5m': 120,
  '15m': 120,
  '30m': 120,
  '1h': 168,
  '4h': 180,
  '1d': 180,
  '1w': 120,
  '1M': 120,
}

function nowUnixSeconds(): number {
  return Math.floor(Date.now() / 1000)
}

function seedFromToken(token: TradingToken): number {
  const source = `${token.symbol}|${token.issuer ?? 'native'}`
  let seed = 0
  for (let i = 0; i < source.length; i += 1) {
    seed = (seed * 31 + source.charCodeAt(i)) % 1_000_003
  }
  return seed
}

function pseudoRandom(seed: number): number {
  const next = (seed * 9301 + 49297) % 233280
  return next / 233280
}

function makeFallbackSeries(token: TradingToken, timeframe: ChartTimeframe): ChartPoint[] {
  const points = TIMEFRAME_POINTS[timeframe]
  const start = nowUnixSeconds() - points * 3600
  const seed = seedFromToken(token)
  let value = token.isXRP ? 2.2 : 0.25 + (seed % 500) / 100

  return Array.from({ length: points }).map((_, index) => {
    const noise = pseudoRandom(seed + index) - 0.5
    value = Math.max(0.0001, value * (1 + noise * 0.03))
    return { time: start + index * 3600, value: Number(value.toFixed(6)) }
  })
}

function normalizePrices(prices: number[][]): ChartPoint[] {
  return prices
    .map((row) => ({
      time: Math.floor(Number(row[0]) / 1000),
      value: Number(row[1]),
    }))
    .filter((point) => Number.isFinite(point.time) && Number.isFinite(point.value))
}

export async function fetchOHLCV(token: TradingToken, timeframe: ChartTimeframe): Promise<ChartPoint[]> {
  const id = SYMBOL_TO_COINGECKO[token.symbol.toUpperCase()]
  if (!id) {
    return makeFallbackSeries(token, timeframe)
  }

  const days = timeframe === '1m' || timeframe === '5m' || timeframe === '15m' || timeframe === '30m'
    ? 2
    : timeframe === '1h'
      ? 7
      : timeframe === '4h'
        ? 30
        : timeframe === '1d'
          ? 120
          : timeframe === '1w'
            ? 365
            : 1460

  try {
    const response = await fetch(
      `https://api.coingecko.com/api/v3/coins/${id}/market_chart?vs_currency=usd&days=${days}`,
      { cache: 'no-store' },
    )
    if (!response.ok) {
      throw new Error(`chart http ${response.status}`)
    }
    const payload = (await response.json()) as { prices?: number[][] }
    const points = normalizePrices(payload.prices ?? [])
    if (!points.length) {
      return makeFallbackSeries(token, timeframe)
    }

    const targetPoints = TIMEFRAME_POINTS[timeframe]
    const stride = Math.max(1, Math.floor(points.length / targetPoints))
    return points.filter((_, idx) => idx % stride === 0).slice(-targetPoints)
  } catch {
    return makeFallbackSeries(token, timeframe)
  }
}
