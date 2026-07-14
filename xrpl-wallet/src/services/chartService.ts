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

// Same two CORS-relay fallbacks NaluLF/scripts/profile.js uses for public
// APIs that don't send CORS headers (onthedex.live doesn't).
const CORS_GET_PROXIES = [
  (url: string) => `https://corsproxy.io/?${encodeURIComponent(url)}`,
  (url: string) => `https://api.allorigins.win/raw?url=${encodeURIComponent(url)}`,
]

async function fetchJsonWithCorsFallback<T>(url: string, timeoutMs = 10_000): Promise<T> {
  const doFetch = async (target: string): Promise<T> => {
    const signal = typeof AbortSignal.timeout === 'function' ? AbortSignal.timeout(timeoutMs) : undefined
    const res = await fetch(target, { method: 'GET', mode: 'cors', cache: 'no-store', signal })
    if (!res.ok) throw new Error(`HTTP ${res.status}`)
    return (await res.json()) as T
  }

  try {
    return await doFetch(url)
  } catch (firstErr) {
    for (const makeProxyUrl of CORS_GET_PROXIES) {
      try {
        return await doFetch(makeProxyUrl(url))
      } catch {
        // try next proxy
      }
    }
    throw firstErr
  }
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

/** OnTheDex only accepts 5|15|60|240|D|W bar intervals. */
function timeframeToOnTheDexInterval(timeframe: ChartTimeframe): string {
  switch (timeframe) {
    case '1m':
    case '5m':
      return '5'
    case '15m':
      return '15'
    case '30m':
    case '1h':
      return '60'
    case '4h':
      return '240'
    case '1d':
      return 'D'
    case '1w':
    case '1M':
      return 'W'
    default:
      return 'D'
  }
}

interface OnTheDexOhlcRow {
  t: number
  o: number
  h: number
  l: number
  c: number
  vb?: number
}

/** Real XRPL-DEX OHLC (quoted in XRP) for any currency+issuer pair — same
 *  public endpoint NaluLF/scripts/profile.js uses, so any real issued token
 *  gets real trade history instead of the last-resort synthetic series. */
async function fetchOnTheDexBars(
  currency: string,
  issuer: string,
  timeframe: ChartTimeframe,
  bars = 300,
): Promise<CandlePoint[]> {
  const base = `${currency}.${issuer}`
  const interval = timeframeToOnTheDexInterval(timeframe)
  const clampedBars = Math.min(2000, Math.max(20, bars))
  const url = `https://api.onthedex.live/public/v1/ohlc?base=${encodeURIComponent(base)}&quote=XRP&interval=${interval}&bars=${clampedBars}`

  const payload = await fetchJsonWithCorsFallback<{ data?: { ohlc?: OnTheDexOhlcRow[] } }>(url)
  const rows = Array.isArray(payload?.data?.ohlc) ? payload.data.ohlc : []

  return rows
    .map((r) => ({
      time: Number(r.t),
      open: Number(r.o),
      high: Number(r.h),
      low: Number(r.l),
      close: Number(r.c),
    }))
    .filter((c) => [c.time, c.open, c.high, c.low, c.close].every(Number.isFinite))
    .sort((a, b) => a.time - b.time)
}

let cachedXrpUsd: { price: number; fetchedAt: number } | null = null

async function getXrpUsdPrice(): Promise<number> {
  if (cachedXrpUsd && Date.now() - cachedXrpUsd.fetchedAt < 60_000) {
    return cachedXrpUsd.price
  }
  try {
    const response = await fetch('https://api.coingecko.com/api/v3/simple/price?ids=ripple&vs_currencies=usd', {
      cache: 'no-store',
    })
    const payload = (await response.json()) as { ripple?: { usd?: number } }
    const price = Number(payload?.ripple?.usd)
    if (Number.isFinite(price) && price > 0) {
      cachedXrpUsd = { price, fetchedAt: Date.now() }
      return price
    }
  } catch {
    // fall through — caller treats 0 as "leave in XRP terms"
  }
  return cachedXrpUsd?.price ?? 0
}

function toUsdCandles(candles: CandlePoint[], xrpUsd: number): CandlePoint[] {
  if (!(xrpUsd > 0)) return candles
  return candles.map((c) => ({
    time: c.time,
    open: c.open * xrpUsd,
    high: c.high * xrpUsd,
    low: c.low * xrpUsd,
    close: c.close * xrpUsd,
  }))
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

export interface ChartFetchResult {
  candles: CandlePoint[]
  source: string
  /** true only for the last-resort randomized series — never a real quote. */
  synthetic: boolean
}

export async function fetchOHLCV(token: TradingToken, timeframe: ChartTimeframe): Promise<ChartFetchResult> {
  const coingeckoId = SYMBOL_TO_COINGECKO[token.symbol.toUpperCase()]

  if (coingeckoId) {
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
        `https://api.coingecko.com/api/v3/coins/${coingeckoId}/market_chart?vs_currency=usd&days=${days}`,
        { cache: 'no-store' },
      )
      if (!response.ok) throw new Error(`chart http ${response.status}`)
      const payload = (await response.json()) as { prices?: number[][] }
      const points = bucketToCandles(payload.prices ?? [], timeframe)
      if (points.length) {
        const targetPoints = TIMEFRAME_POINTS[timeframe]
        const stride = Math.max(1, Math.floor(points.length / targetPoints))
        const candles = points.filter((_, idx) => idx % stride === 0).slice(-targetPoints)
        return { candles, source: 'CoinGecko historical', synthetic: false }
      }
    } catch {
      // fall through to OnTheDex/synthetic below
    }
  }

  if (token.issuer) {
    try {
      const xrpBars = await fetchOnTheDexBars(token.symbol, token.issuer, timeframe, 300)
      if (xrpBars.length) {
        const xrpUsd = await getXrpUsdPrice()
        const candles = toUsdCandles(xrpBars, xrpUsd)
        return {
          candles,
          source: `OnTheDex XRPL DEX (${token.symbol}/XRP)${xrpUsd > 0 ? ' → USD' : ''}`,
          synthetic: false,
        }
      }
    } catch {
      // no real DEX history yet (new/illiquid token) — fall through to synthetic
    }
  }

  return { candles: makeFallbackSeries(token, timeframe), source: 'Synthetic (no market data available)', synthetic: true }
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

  if (productId) {
    let candles = [...initialCandles]
    const sourceLabel = 'Coinbase WebSocket'
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

  if (token.issuer) {
    // No public XRPL-DEX websocket feed — poll real OnTheDex bars instead of
    // the old fabricated per-tick noise, so live updates stay real data.
    const poll = setInterval(async () => {
      try {
        const xrpBars = await fetchOnTheDexBars(token.symbol, token.issuer!, timeframe, 300)
        if (!xrpBars.length) return
        const xrpUsd = await getXrpUsdPrice()
        onUpdate(toUsdCandles(xrpBars, xrpUsd), `OnTheDex XRPL DEX (${token.symbol}/XRP)${xrpUsd > 0 ? ' → USD' : ''}`)
      } catch {
        // keep showing the last good candles until the next poll succeeds
      }
    }, 45_000)
    return () => clearInterval(poll)
  }

  // No real data source for this token at all — do not fabricate live ticks
  // on top of the synthetic series, that would misrepresent it as active.
  return () => {}
}
