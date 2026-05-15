import { useEffect, useMemo, useRef, useState } from 'react'
import type { AggregatedAsset } from '../types/wallet'
import { fetchOHLCV } from '../services/chartService'
import {
  toTokenKey,
  useTradingStore,
  type ChartPoint,
  type ChartTimeframe,
  type TradingToken,
} from '../store/tradingStore'
import { Button, Card, Input, SectionTitle } from './ui'

interface Props {
  aggregatedAssets: AggregatedAsset[]
}

const TIMEFRAMES: ChartTimeframe[] = ['1m', '5m', '15m', '30m', '1h', '4h', '1d', '1w', '1M']

const INDICATOR_LIBRARY = [
  { id: 'SMA', category: 'Trend', purpose: 'Smooths price to identify direction and trend persistence.' },
  { id: 'EMA', category: 'Trend', purpose: 'Weights recent candles more heavily to react faster to changes.' },
  { id: 'MACD', category: 'Trend', purpose: 'Compares fast and slow momentum to detect shifts in direction.' },
  { id: 'RSI', category: 'Momentum', purpose: 'Measures speed of movement to highlight overbought/oversold zones.' },
  { id: 'Stoch', category: 'Momentum', purpose: 'Compares close relative to range and helps spot reversals.' },
  { id: 'OBV', category: 'Volume', purpose: 'Tracks buying and selling pressure through directional volume.' },
  { id: 'ATR', category: 'Volatility', purpose: 'Shows expected movement range for risk sizing.' },
  { id: 'VWAP', category: 'Custom', purpose: 'Volume-weighted average price often used for execution quality.' },
]

const DEFAULT_BIAS_COACHING =
  'Bias guardrail: define entry, invalidation, and position size before execution. Avoid anchoring to prior highs and wait for confirmation from volume or trend context.'

function toDiscoveryToken(asset: AggregatedAsset): TradingToken {
  const symbol = asset.symbol.toUpperCase()
  const issuer = asset.type === 'token' || asset.type === 'lp' ? asset.metadata ?? null : null
  const isXRP = symbol === 'XRP' || asset.type === 'xrp'
  return {
    symbol,
    name: asset.name || symbol,
    issuer,
    currencyCode: symbol,
    isXRP,
    pairType: isXRP ? 'XRP/USD' : `${symbol}/USD`,
  }
}

function miniSparkline(points: ChartPoint[] | undefined): string {
  if (!points || points.length < 2) return ''
  const values = points.map((point) => point.value)
  const min = Math.min(...values)
  const max = Math.max(...values)
  const spread = max - min || 1
  return values
    .map((value, idx) => {
      const x = (idx / (values.length - 1)) * 100
      const y = 24 - ((value - min) / spread) * 24
      return `${x.toFixed(2)},${y.toFixed(2)}`
    })
    .join(' ')
}

function TokenRow({
  token,
  selected,
  inWatchlist,
  onSelect,
  onToggleWatch,
}: {
  token: TradingToken
  selected: boolean
  inWatchlist: boolean
  onSelect: (token: TradingToken) => void
  onToggleWatch: (token: TradingToken, inWatchlist: boolean) => void
}) {
  return (
    <div
      role="button"
      tabIndex={0}
      onClick={() => onSelect(token)}
      onKeyDown={(event) => {
        if (event.key === 'Enter' || event.key === ' ') {
          event.preventDefault()
          onSelect(token)
        }
      }}
      className={`flex items-center justify-between gap-2 rounded-xl border px-3 py-2 text-sm transition ${
        selected
          ? 'border-teal-600 bg-teal-50 text-teal-900'
          : 'border-slate-200 bg-slate-50 text-slate-700 hover:border-slate-300'
      }`}
    >
      <div className="min-w-0">
        <p className="truncate font-semibold">{token.symbol}</p>
        <p className="truncate text-xs opacity-75" title={token.issuer ?? 'Native XRP'}>
          {token.issuer ?? 'Native XRP'}
        </p>
      </div>
      <Button
        variant={inWatchlist ? 'secondary' : 'primary'}
        onClick={(event) => {
          event.stopPropagation()
          onToggleWatch(token, inWatchlist)
        }}
      >
        {inWatchlist ? 'Remove' : 'Watch'}
      </Button>
    </div>
  )
}

export function TradingTerminal({ aggregatedAssets }: Props) {
  const selectedToken = useTradingStore((state) => state.selectedToken)
  const watchlist = useTradingStore((state) => state.watchlist)
  const chartData = useTradingStore((state) => state.chartData)
  const selectToken = useTradingStore((state) => state.selectToken)
  const setChartData = useTradingStore((state) => state.setChartData)
  const addToWatchlist = useTradingStore((state) => state.addToWatchlist)
  const removeFromWatchlist = useTradingStore((state) => state.removeFromWatchlist)
  const setRefreshChart = useTradingStore((state) => state.setRefreshChart)
  const is3DEnabled = useTradingStore((state) => state.is3DEnabled)
  const toggle3D = useTradingStore((state) => state.toggle3D)

  const [timeframe, setTimeframe] = useState<ChartTimeframe>('1h')
  const [isLoading, setIsLoading] = useState(false)
  const [search, setSearch] = useState('')
  const [indicatorSearch, setIndicatorSearch] = useState('')
  const [selectedIndicators, setSelectedIndicators] = useState<string[]>([])
  const [activeIndicator, setActiveIndicator] = useState<string | null>(null)

  const chartContainerRef = useRef<HTMLDivElement | null>(null)

  const discoveryTokens = useMemo(() => {
    const entries = [
      {
        symbol: 'XRP',
        name: 'XRP',
        issuer: null,
        currencyCode: 'XRP',
        isXRP: true,
        pairType: 'XRP/USD',
      } as TradingToken,
      ...aggregatedAssets
        .filter((asset) => asset.type === 'token' || asset.type === 'xrp')
        .map(toDiscoveryToken),
    ]

    const deduped = new Map<string, TradingToken>()
    entries.forEach((token) => {
      deduped.set(toTokenKey(token), token)
    })

    return [...deduped.values()]
  }, [aggregatedAssets])

  const filteredTokens = useMemo(() => {
    const query = search.trim().toLowerCase()
    if (!query) return discoveryTokens
    return discoveryTokens.filter((token) => {
      return (
        token.symbol.toLowerCase().includes(query)
        || token.name.toLowerCase().includes(query)
        || (token.issuer ?? '').toLowerCase().includes(query)
      )
    })
  }, [discoveryTokens, search])

  const availableIndicators = useMemo(() => {
    const query = indicatorSearch.trim().toLowerCase()
    if (!query) return INDICATOR_LIBRARY
    return INDICATOR_LIBRARY.filter((indicator) => {
      return indicator.id.toLowerCase().includes(query) || indicator.category.toLowerCase().includes(query)
    })
  }, [indicatorSearch])

  const selectedKey = toTokenKey(selectedToken)
  const series = chartData[selectedKey] ?? []

  const refreshChartForSelection = async () => {
    setIsLoading(true)
    try {
      const next = await fetchOHLCV(selectedToken, timeframe)
      setChartData(selectedKey, next)
    } finally {
      setIsLoading(false)
    }
  }

  useEffect(() => {
    setRefreshChart(() => {
      void refreshChartForSelection()
    })
    return () => {
      setRefreshChart(null)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedKey, timeframe])

  useEffect(() => {
    void refreshChartForSelection()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedKey, timeframe])

  const onTokenSelect = (token: TradingToken) => {
    selectToken(token)
    chartContainerRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }

  const currentIndicator = INDICATOR_LIBRARY.find((indicator) => indicator.id === activeIndicator)

  return (
    <div className="space-y-5">
      <Card>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <SectionTitle
            title="XRPL Trading Terminal"
            subtitle="Global token selection with immediate chart synchronization."
          />
          <div className="flex gap-2">
            <Button variant="secondary" onClick={toggle3D}>
              3D {is3DEnabled ? 'On' : 'Off'}
            </Button>
          </div>
        </div>
      </Card>

      <div className="grid gap-5 xl:grid-cols-[1.6fr_1fr]">
        <div className="space-y-5">
          <Card>
            <div id="chart-container" ref={chartContainerRef} className="relative overflow-hidden rounded-xl border border-slate-200">
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-200 bg-slate-50 p-3">
                <div>
                  <p className="text-sm font-semibold text-slate-900">{selectedToken.name} Chart</p>
                  <p className="text-xs text-slate-500">Data source: {selectedToken.isXRP ? 'CoinGecko spot' : 'Oracle fallback/market proxy'}</p>
                </div>
                <div className="flex flex-wrap gap-1">
                  {TIMEFRAMES.map((tf) => (
                    <button
                      key={tf}
                      type="button"
                      className={`rounded-md px-2 py-1 text-xs font-semibold ${
                        timeframe === tf ? 'bg-teal-700 text-white' : 'bg-white text-slate-700 border border-slate-300'
                      }`}
                      onClick={() => setTimeframe(tf)}
                    >
                      {tf}
                    </button>
                  ))}
                </div>
              </div>

              {is3DEnabled ? (
                <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_top,_rgba(20,184,166,0.18),_transparent_55%),radial-gradient(ellipse_at_bottom,_rgba(59,130,246,0.16),_transparent_60%)]" />
              ) : null}

              <div className="relative h-[500px] p-3">
                <SimpleLineChart points={series} loading={isLoading} />
              </div>
            </div>
          </Card>

          <Card>
            <SectionTitle title="Indicator Lab" subtitle="Search and select indicators, then review intent and common bias traps." />
            <div className="space-y-3">
              <Input
                value={indicatorSearch}
                onChange={(event) => setIndicatorSearch(event.target.value)}
                placeholder="Search indicators (RSI, MACD, ATR...)"
              />
              <div className="flex flex-wrap gap-2">
                {availableIndicators.map((indicator) => (
                  <button
                    key={indicator.id}
                    type="button"
                    onClick={() => {
                      setActiveIndicator(indicator.id)
                      setSelectedIndicators((current) => {
                        if (current.includes(indicator.id)) return current
                        return [...current, indicator.id]
                      })
                    }}
                    className="rounded-full border border-slate-300 bg-white px-3 py-1 text-xs font-semibold text-slate-700 shadow-sm hover:border-teal-500 hover:text-teal-700"
                    title={indicator.purpose}
                  >
                    {indicator.category} · {indicator.id}
                  </button>
                ))}
              </div>
              <div className="rounded-xl border border-slate-200 bg-slate-50 p-3 text-sm text-slate-700">
                <p className="font-semibold text-slate-900">Educational Panel</p>
                <p className="mt-1">
                  {currentIndicator
                    ? `${currentIndicator.id}: ${currentIndicator.purpose}`
                    : 'Select an indicator to view context and setup guidance.'}
                </p>
                <p className="mt-2 text-xs text-slate-600">{DEFAULT_BIAS_COACHING}</p>
              </div>
              {selectedIndicators.length ? (
                <div className="flex flex-wrap gap-2">
                  {selectedIndicators.map((indicator) => (
                    <span key={indicator} className="max-w-[160px] truncate rounded-full bg-slate-900 px-3 py-1 text-xs font-semibold text-white" title={indicator}>
                      {indicator}
                    </span>
                  ))}
                </div>
              ) : null}
            </div>
          </Card>
        </div>

        <div className="space-y-5">
          <Card>
            <SectionTitle title="Token Discovery" subtitle="Click any token to update chart instantly via shared store." />
            <Input
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Search symbol, name, issuer"
            />
            <div className="mt-3 max-h-[360px] space-y-2 overflow-auto pr-1">
              {filteredTokens.map((token) => {
                const key = toTokenKey(token)
                const inWatchlist = watchlist.some((item) => toTokenKey(item) === key)
                return (
                  <TokenRow
                    key={key}
                    token={token}
                    selected={selectedKey === key}
                    inWatchlist={inWatchlist}
                    onSelect={onTokenSelect}
                    onToggleWatch={(item, isInWatchlist) => {
                      if (isInWatchlist) {
                        removeFromWatchlist(item.symbol, item.issuer)
                      } else {
                        addToWatchlist(item)
                      }
                    }}
                  />
                )
              })}
            </div>
          </Card>

          <Card>
            <SectionTitle title="Watchlist" subtitle="Persisted tokens with quick chart jump and sparkline context." />
            <div className="space-y-2">
              {watchlist.map((token) => {
                const key = toTokenKey(token)
                const spark = miniSparkline(chartData[key])
                return (
                  <button
                    key={key}
                    type="button"
                    onClick={() => onTokenSelect(token)}
                    className={`w-full rounded-xl border px-3 py-2 text-left transition ${
                      selectedKey === key
                        ? 'border-teal-600 bg-teal-50'
                        : 'border-slate-200 bg-slate-50 hover:border-slate-300'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <div className="min-w-0">
                        <p className="truncate text-sm font-semibold text-slate-900">{token.symbol}</p>
                        <p className="truncate text-xs text-slate-500" title={token.issuer ?? 'Native XRP'}>
                          {token.issuer ?? 'Native XRP'}
                        </p>
                      </div>
                      {spark ? (
                        <svg width="100" height="24" viewBox="0 0 100 24" className="shrink-0">
                          <polyline fill="none" stroke="#0f766e" strokeWidth="1.5" points={spark} />
                        </svg>
                      ) : (
                        <span className="text-xs text-slate-400">No sparkline</span>
                      )}
                    </div>
                  </button>
                )
              })}
              {!watchlist.length ? <p className="text-sm text-slate-500">No watchlist tokens yet.</p> : null}
            </div>
          </Card>
        </div>
      </div>
    </div>
  )
}

function SimpleLineChart({ points, loading }: { points: ChartPoint[]; loading: boolean }) {
  if (loading) {
    return <div className="flex h-full items-center justify-center text-sm text-slate-500">Loading chart data…</div>
  }

  if (points.length < 2) {
    return <div className="flex h-full items-center justify-center text-sm text-slate-500">Not enough points for chart.</div>
  }

  const values = points.map((point) => point.value)
  const min = Math.min(...values)
  const max = Math.max(...values)
  const spread = max - min || 1

  const chartPoints = values
    .map((value, idx) => {
      const x = (idx / (values.length - 1)) * 100
      const y = 100 - ((value - min) / spread) * 100
      return `${x.toFixed(2)},${y.toFixed(2)}`
    })
    .join(' ')

  const last = values.at(-1) ?? 0
  const first = values[0] ?? 0
  const deltaPct = first ? ((last - first) / first) * 100 : 0

  return (
    <div className="h-full rounded-xl border border-slate-200 bg-white/80 p-2">
      <div className="mb-1 flex items-center justify-between text-xs text-slate-600">
        <span>Last: ${last.toFixed(4)}</span>
        <span className={deltaPct >= 0 ? 'text-emerald-700' : 'text-rose-700'}>{deltaPct.toFixed(2)}%</span>
      </div>
      <svg viewBox="0 0 100 100" className="h-[calc(100%-1.5rem)] w-full">
        <polyline fill="none" stroke="#0f766e" strokeWidth="1.2" points={chartPoints} />
      </svg>
    </div>
  )
}
