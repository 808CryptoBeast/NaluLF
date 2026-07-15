import axios from 'axios'
import type { PriceConfidence } from '../types/wallet'

export interface PriceQuote {
  usd: number
  confidence: PriceConfidence
  source: string
}

// CoinGecko's public API blocks CORS outright from some browser origins —
// Coinbase Exchange's public REST endpoints send proper CORS headers and are
// already relied on elsewhere in this app (chartService.ts), so major coins
// price off that directly instead.
const SYMBOL_TO_COINBASE_PRODUCT: Record<string, string> = {
  XRP: 'XRP-USD',
  BTC: 'BTC-USD',
  ETH: 'ETH-USD',
  USDC: 'USDC-USD',
  SOL: 'SOL-USD',
}

const STABLE_USD: Record<string, number> = {
  USD: 1,
  USDC: 1,
  USDT: 1,
  DAI: 1,
}

const ISSUER_PRICE_OVERRIDES: Record<string, PriceQuote> = {
  'USD:rhub8VRN55s94qWKDv6jmDy1pUykJzF3wq': { usd: 1, confidence: 'high', source: 'Issuer override' },
  'EUR:rhub8VRN55s94qWKDv6jmDy1pUykJzF3wq': { usd: 1.08, confidence: 'medium', source: 'Issuer override' },
}

function normalizeSymbol(symbol: string): string {
  return symbol.trim().toUpperCase()
}

export async function fetchXrpUsdPrice(): Promise<number> {
  const response = await axios.get<{ price: string }>(
    'https://api.exchange.coinbase.com/products/XRP-USD/ticker',
    { timeout: 8000 },
  )

  return Number(response.data.price)
}

export async function fetchCurrencyUsdMap(symbols: string[]): Promise<Record<string, PriceQuote>> {
  const unique = [...new Set(symbols.map(normalizeSymbol).filter(Boolean))]
  const result: Record<string, PriceQuote> = {}

  unique.forEach((symbol) => {
    if (STABLE_USD[symbol] !== undefined) {
      result[symbol] = { usd: STABLE_USD[symbol], confidence: 'high', source: 'Stablecoin parity' }
    }
  })

  const withProducts = unique
    .map((symbol) => ({ symbol, product: SYMBOL_TO_COINBASE_PRODUCT[symbol] }))
    .filter((entry): entry is { symbol: string; product: string } => Boolean(entry.product))

  await Promise.all(
    withProducts.map(async ({ symbol, product }) => {
      try {
        const response = await axios.get<{ price: string }>(
          `https://api.exchange.coinbase.com/products/${product}/ticker`,
          { timeout: 9000 },
        )
        const usd = Number(response.data.price)
        if (Number.isFinite(usd) && usd > 0) {
          result[symbol] = { usd, confidence: 'high', source: 'Coinbase Exchange' }
        }
      } catch {
        // Keep existing fallback quotes.
      }
    }),
  )

  return result
}

export function resolveIssuerQuote(currency: string, issuer?: string): PriceQuote | undefined {
  if (!issuer) {
    return undefined
  }
  return ISSUER_PRICE_OVERRIDES[`${normalizeSymbol(currency)}:${issuer}`]
}
