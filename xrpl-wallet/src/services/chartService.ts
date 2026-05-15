import type { CandlePoint, ChartTimeframe, TradingToken } from '../store/tradingStore'

const SYMBOL_TO_COINGECKO: Record<string, string> = {
  XRP: 'ripple',
  BTC: 'bitcoin',
  ETH: 'ethereum',
  USDC: 'usd-coin',
  USDT: 'tether',
  SOL: 'solana',
  ADA: 'cardano',
}

const SYMBOL_TO_COINBASE_PRODUCT: Record<string, string> = {
  XRP: 'XRP-USD',
  BTC: 'BTC-USD',
  ETH: 'ETH-USD',
  USDC: 'USDC-USD',
  SOL: 'SOL-USD',
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

export function timeframeToSeconds(timeframe: ChartTimeframe): number {
  switch (timeframe) {
    case '1m': return 60
    case '5m': return 300
    case '15m': return 900
    case '30m': return 1800
    case '1h': return 3600
    case '4h': return 14_400
    case '1d': return 86_400
    case '1w': return 604_800
    case '1M': return 2_592_000
    default: return 3600
  }
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

function makeFallbackSeries(token: TradingToken, timeframe: ChartTimeframe): CandlePoint[] {
  const points = TIMEFRAME_POINTS[timeframe]
  const interval = timeframeToSeconds(timeframe)
  const start = nowUnixSeconds() - points * interval
  const seed = seedFromToken(token)
  let close = token.isXRP ? 2.2 : 0.25 + (seed % 500) / 100

  return Array.from({ length: points }).map((_, index) => {
    const noise = pseudoRandom(seed + index) - 0.5
    const open = close
    close = Math.max(0.0001, close * (1 + noise * 0.03))
    const high = Math.max(open, close) * (1 + Math.abs(noise) * 0.02)
    const low = Math.min(open, close) * (1 - Math.abs(noise) * 0.02)
    return {
      time: start + index * interval,
      open: Number(open.toFixed(6)),
      high: Number(high.toFixed(6)),
      low: Number(low.toFixed(6)),
      close: Number(close.toFixed(6)),
    }
  })
}

function bucketToCandles(prices: number[][], timeframe: ChartTimeframe): CandlePoint[] {
  const interval = timeframeToSeconds(timeframe)
  const buckets = new Map<number, CandlePoint>()

  prices.forEach((row) => {
    const rawTs = Math.floor(Number(row[0]) / 1000)
    const value = Number(row[1])
    if (!Number.isFinite(rawTs) || !Number.isFinite(value)) return

    const bucket = Math.floor(rawTs / interval) * interval
    const current = buckets.get(bucket)
    if (!current) {
      buckets.set(bucket, {
        time: bucket,
        open: value,
        high: value,
        low: value,
        close: value,
      })
      return
    }

    current.high = Math.max(current.high, value)
    current.low = Math.min(current.low, value)
    current.close = value
  })

  return [...buckets.values()].sort((a, b) => a.time - b.time)
}

export async function fetchOHLCV(token: TradingToken, timeframe: ChartTimeframe): Promise<CandlePoint[]> {
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
    const points = bucketToCandles(payload.prices ?? [], timeframe)
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

function mergeTickIntoCandles(
  candles: CandlePoint[],
  price: number,
  timestampSec: number,
  timeframe: ChartTimeframe,
): CandlePoint[] {
  const interval = timeframeToSeconds(timeframe)
  const bucket = Math.floor(timestampSec / interval) * interval
  const next = [...candles]
  const last = next.at(-1)

  if (!last || last.time < bucket) {
    next.push({
      time: bucket,
      open: price,
      high: price,
      low: price,
      close: price,
    })
    return next
  }

  if (last.time === bucket) {
    last.high = Math.max(last.high, price)
    last.low = Math.min(last.low, price)
    last.close = price
    return next
  }

  return next
}

export function subscribeLiveCandles(
  token: TradingToken,
  timeframe: ChartTimeframe,
  initialCandles: CandlePoint[],
  onUpdate: (candles: CandlePoint[], source: string) => void,
): () => void {
  const productId = SYMBOL_TO_COINBASE_PRODUCT[token.symbol.toUpperCase()]
  const sourceLabel = productId ? 'Coinbase WebSocket' : 'Synthetic fallback'
  let candles = [...initialCandles]

  if (productId) {
    const ws = new WebSocket('wss://ws-feed.exchange.coinbase.com')
    ws.onopen = () => {
      ws.send(JSON.stringify({
        type: 'subscribe',
        channels: [{ name: 'ticker', product_ids: [productId] }],
      }))
    }
    ws.onmessage = (event) => {
      try {
        const payload = JSON.parse(String(event.data)) as { type?: string; price?: string; time?: string }
        if (payload.type !== 'ticker' || !payload.price) return
        const price = Number(payload.price)
        if (!Number.isFinite(price) || price <= 0) return
        const timestampSec = payload.time ? Math.floor(new Date(payload.time).getTime() / 1000) : nowUnixSeconds()
        candles = mergeTickIntoCandles(candles, price, timestampSec, timeframe)
        onUpdate(candles, sourceLabel)
      } catch {
        // ignore malformed ticks
      }
    }
    return () => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({
          type: 'unsubscribe',
          channels: [{ name: 'ticker', product_ids: [productId] }],
        }))
      }
      ws.close()
    }
  }

  const tick = setInterval(() => {
    const last = candles.at(-1)
    const seed = seedFromToken(token) + nowUnixSeconds()
    const base = last?.close ?? (token.isXRP ? 2.2 : 0.25)
    const drift = (pseudoRandom(seed) - 0.5) * 0.01
    const price = Math.max(0.0001, base * (1 + drift))
    candles = mergeTickIntoCandles(candles, price, nowUnixSeconds(), timeframe)
    onUpdate(candles, sourceLabel)
  }, 2500)

  return () => clearInterval(tick)
}
