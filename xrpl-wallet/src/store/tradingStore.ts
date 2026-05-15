import { create } from 'zustand'
import { persist } from 'zustand/middleware'

export type ChartTimeframe = '1m' | '5m' | '15m' | '30m' | '1h' | '4h' | '1d' | '1w' | '1M'

export interface TradingToken {
  symbol: string
  name: string
  issuer: string | null
  currencyCode: string
  isXRP: boolean
  pairType: string
}

export interface ChartPoint {
  time: number
  value: number
}

export interface CandlePoint {
  time: number
  open: number
  high: number
  low: number
  close: number
}

export interface TrendlineDrawing {
  id: string
  startTime: number
  startPrice: number
  endTime: number
  endPrice: number
}

interface TradingStore {
  selectedToken: TradingToken
  watchlist: TradingToken[]
  chartData: Record<string, CandlePoint[]>
  indicatorSelections: Record<string, string[]>
  drawingsByToken: Record<string, TrendlineDrawing[]>
  is3DEnabled: boolean
  theme: 'light' | 'dark'
  refreshChart: null | (() => void)
  selectToken: (token: TradingToken) => void
  addToWatchlist: (token: TradingToken) => void
  removeFromWatchlist: (symbol: string, issuer?: string | null) => void
  setChartData: (tokenKey: string, data: CandlePoint[]) => void
  addIndicatorForToken: (tokenKey: string, indicatorId: string) => void
  removeIndicatorForToken: (tokenKey: string, indicatorId: string) => void
  addTrendline: (tokenKey: string, line: TrendlineDrawing) => void
  clearTrendlines: (tokenKey: string) => void
  setRefreshChart: (refreshChart: null | (() => void)) => void
  toggle3D: () => void
  toggleTheme: () => void
}

export function toTokenKey(token: Pick<TradingToken, 'symbol' | 'issuer'>): string {
  return `${token.symbol.toUpperCase()}::${token.issuer ?? 'native'}`
}

const defaultToken: TradingToken = {
  symbol: 'XRP',
  name: 'XRP',
  issuer: null,
  currencyCode: 'XRP',
  isXRP: true,
  pairType: 'XRP/USD',
}

export const useTradingStore = create<TradingStore>()(
  persist(
    (set, get) => ({
      selectedToken: defaultToken,
      watchlist: [defaultToken],
      chartData: {},
      indicatorSelections: {},
      drawingsByToken: {},
      is3DEnabled: true,
      theme: 'dark',
      refreshChart: null,
      selectToken: (token) => {
        set({ selectedToken: token })
        const refresh = get().refreshChart
        if (refresh) refresh()
      },
      addToWatchlist: (token) =>
        set((state) => {
          const key = toTokenKey(token)
          if (state.watchlist.some((item) => toTokenKey(item) === key)) {
            return state
          }
          return { watchlist: [...state.watchlist, token] }
        }),
      removeFromWatchlist: (symbol, issuer) =>
        set((state) => ({
          watchlist: state.watchlist.filter(
            (item) => !(item.symbol === symbol && (item.issuer ?? null) === (issuer ?? null)),
          ),
        })),
      setChartData: (tokenKey, data) =>
        set((state) => ({
          chartData: {
            ...state.chartData,
            [tokenKey]: data,
          },
        })),
      addIndicatorForToken: (tokenKey, indicatorId) =>
        set((state) => {
          const current = state.indicatorSelections[tokenKey] ?? []
          if (current.includes(indicatorId)) {
            return state
          }
          return {
            indicatorSelections: {
              ...state.indicatorSelections,
              [tokenKey]: [...current, indicatorId],
            },
          }
        }),
      removeIndicatorForToken: (tokenKey, indicatorId) =>
        set((state) => ({
          indicatorSelections: {
            ...state.indicatorSelections,
            [tokenKey]: (state.indicatorSelections[tokenKey] ?? []).filter((id) => id !== indicatorId),
          },
        })),
      addTrendline: (tokenKey, line) =>
        set((state) => ({
          drawingsByToken: {
            ...state.drawingsByToken,
            [tokenKey]: [...(state.drawingsByToken[tokenKey] ?? []), line],
          },
        })),
      clearTrendlines: (tokenKey) =>
        set((state) => ({
          drawingsByToken: {
            ...state.drawingsByToken,
            [tokenKey]: [],
          },
        })),
      setRefreshChart: (refreshChart) => set({ refreshChart }),
      toggle3D: () => set((state) => ({ is3DEnabled: !state.is3DEnabled })),
      toggleTheme: () => set((state) => ({ theme: state.theme === 'dark' ? 'light' : 'dark' })),
    }),
    {
      name: 'xrpl-trading-store',
      partialize: (state) => ({
        selectedToken: state.selectedToken,
        watchlist: state.watchlist,
        chartData: state.chartData,
        indicatorSelections: state.indicatorSelections,
        drawingsByToken: state.drawingsByToken,
        is3DEnabled: state.is3DEnabled,
        theme: state.theme,
      }),
    },
  ),
)
