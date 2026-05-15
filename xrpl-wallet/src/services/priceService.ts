import axios from 'axios'
import type { PriceConfidence } from '../types/wallet'

export interface PriceQuote {
  usd: number
  confidence: PriceConfidence
  source: string
}

const SYMBOL_TO_COINGECKO: Record<string, string> = {
  XRP: 'ripple',
  BTC: 'bitcoin',
  ETH: 'ethereum',
  USDC: 'usd-coin',
  USDT: 'tether',
  SOL: 'solana',
  ADA: 'cardano',
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
  const response = await axios.get<{ ripple: { usd: number } }>(
    'https://api.coingecko.com/api/v3/simple/price?ids=ripple&vs_currencies=usd',
    {
      timeout: 8000,
    },
  )

  return response.data.ripple.usd
}

export async function fetchCurrencyUsdMap(symbols: string[]): Promise<Record<string, PriceQuote>> {
  const unique = [...new Set(symbols.map(normalizeSymbol).filter(Boolean))]
  const result: Record<string, PriceQuote> = {}

  unique.forEach((symbol) => {
    if (STABLE_USD[symbol] !== undefined) {
      result[symbol] = { usd: STABLE_USD[symbol], confidence: 'high', source: 'Stablecoin parity' }
    }
  })

  const ids = unique
    .map((symbol) => SYMBOL_TO_COINGECKO[symbol])
    .filter((id): id is string => Boolean(id))

  if (ids.length) {
    try {
      const response = await axios.get<Record<string, { usd: number }>>(
        `https://api.coingecko.com/api/v3/simple/price?ids=${ids.join(',')}&vs_currencies=usd`,
        { timeout: 9000 },
      )

      unique.forEach((symbol) => {
        const id = SYMBOL_TO_COINGECKO[symbol]
        if (id && response.data[id]?.usd !== undefined) {
          result[symbol] = { usd: response.data[id].usd, confidence: 'high', source: 'CoinGecko' }
        }
      })
    } catch {
      // Keep existing fallback quotes.
    }
  }

  return result
}

export function resolveIssuerQuote(currency: string, issuer?: string): PriceQuote | undefined {
  if (!issuer) {
    return undefined
  }
  return ISSUER_PRICE_OVERRIDES[`${normalizeSymbol(currency)}:${issuer}`]
}
