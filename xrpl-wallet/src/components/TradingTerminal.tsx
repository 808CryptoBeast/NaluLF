import { useEffect, useMemo, useRef, useState } from 'react'
import {
  CandlestickSeries,
  createChart,
  type CandlestickData,
  type IChartApi,
  type ISeriesApi,
  type UTCTimestamp,
} from 'lightweight-charts'
import type { AggregatedAsset } from '../types/wallet'
import { fetchOHLCV, subscribeLiveCandles } from '../services/chartService'
import {
  toTokenKey,
  useTradingStore,
  type CandlePoint,
  type ChartTimeframe,
  type TrendlineDrawing,
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

function miniSparkline(points: CandlePoint[] | undefined): string {
  if (!points || points.length < 2) return ''
  const values = points.map((point) => point.close)
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

type DraftPoint = {
  time: number
  price: number
}

type LineCoordinates = TrendlineDrawing & {
  x1: number
  y1: number
  x2: number
  y2: number
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
  const indicatorSelections = useTradingStore((state) => state.indicatorSelections)
  const drawingsByToken = useTradingStore((state) => state.drawingsByToken)
  const selectToken = useTradingStore((state) => state.selectToken)
  const setChartData = useTradingStore((state) => state.setChartData)
  const addIndicatorForToken = useTradingStore((state) => state.addIndicatorForToken)
  const removeIndicatorForToken = useTradingStore((state) => state.removeIndicatorForToken)
  const addTrendline = useTradingStore((state) => state.addTrendline)
  const clearTrendlines = useTradingStore((state) => state.clearTrendlines)
  const addToWatchlist = useTradingStore((state) => state.addToWatchlist)
  const removeFromWatchlist = useTradingStore((state) => state.removeFromWatchlist)
  const setRefreshChart = useTradingStore((state) => state.setRefreshChart)
  const is3DEnabled = useTradingStore((state) => state.is3DEnabled)
  const toggle3D = useTradingStore((state) => state.toggle3D)
  const theme = useTradingStore((state) => state.theme)
  const toggleTheme = useTradingStore((state) => state.toggleTheme)

  const [timeframe, setTimeframe] = useState<ChartTimeframe>('1h')
  const [isLoading, setIsLoading] = useState(false)
  const [search, setSearch] = useState('')
  const [indicatorSearch, setIndicatorSearch] = useState('')
  const [activeIndicator, setActiveIndicator] = useState<string | null>(null)
  const [sourceLabel, setSourceLabel] = useState('Loading…')
  const [drawMode, setDrawMode] = useState(false)
  const [draftPoint, setDraftPoint] = useState<DraftPoint | null>(null)

  const chartContainerRef = useRef<HTMLDivElement | null>(null)
  const chartRootRef = useRef<HTMLDivElement | null>(null)
  const chartApiRef = useRef<IChartApi | null>(null)
  const seriesApiRef = useRef<ISeriesApi<'Candlestick'> | null>(null)

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
  const selectedIndicators = indicatorSelections[selectedKey] ?? []
  const selectedDrawings = drawingsByToken[selectedKey] ?? []

  const lineCoordinates = useMemo(() => {
    if (!chartApiRef.current || !seriesApiRef.current) return [] as LineCoordinates[]
    return selectedDrawings.reduce<LineCoordinates[]>((acc, line) => {
        const x1 = chartApiRef.current?.timeScale().timeToCoordinate(line.startTime as UTCTimestamp)
        const x2 = chartApiRef.current?.timeScale().timeToCoordinate(line.endTime as UTCTimestamp)
        const y1 = seriesApiRef.current?.priceToCoordinate(line.startPrice)
        const y2 = seriesApiRef.current?.priceToCoordinate(line.endPrice)
        if (x1 == null || x2 == null || y1 == null || y2 == null) return acc
        acc.push({ ...line, x1: Number(x1), y1: Number(y1), x2: Number(x2), y2: Number(y2) })
        return acc
      }, [])
  }, [selectedDrawings, series])

  useEffect(() => {
    if (!chartRootRef.current || chartApiRef.current) return

    const chart = createChart(chartRootRef.current, {
      layout: {
        background: { color: theme === 'dark' ? '#0f172a' : '#f8fafc' },
        textColor: theme === 'dark' ? '#cbd5e1' : '#334155',
      },
      grid: {
        vertLines: { color: theme === 'dark' ? 'rgba(148,163,184,0.18)' : 'rgba(148,163,184,0.22)' },
        horzLines: { color: theme === 'dark' ? 'rgba(148,163,184,0.18)' : 'rgba(148,163,184,0.22)' },
      },
      rightPriceScale: { borderColor: 'rgba(148,163,184,0.3)' },
      timeScale: { borderColor: 'rgba(148,163,184,0.3)', timeVisible: true },
      width: chartRootRef.current.clientWidth,
      height: 460,
      autoSize: false,
    })

    const candleSeries = chart.addSeries(CandlestickSeries, {
      upColor: '#16a34a',
      downColor: '#dc2626',
      borderVisible: false,
      wickUpColor: '#16a34a',
      wickDownColor: '#dc2626',
    })

    chartApiRef.current = chart
    seriesApiRef.current = candleSeries

    const observer = new ResizeObserver(() => {
      if (!chartRootRef.current || !chartApiRef.current) return
      chartApiRef.current.applyOptions({ width: chartRootRef.current.clientWidth })
    })
    observer.observe(chartRootRef.current)

    return () => {
      observer.disconnect()
      chart.remove()
      chartApiRef.current = null
      seriesApiRef.current = null
    }
  }, [theme])

  useEffect(() => {
    if (!chartApiRef.current) return
    chartApiRef.current.applyOptions({
      layout: {
        background: { color: theme === 'dark' ? '#0f172a' : '#f8fafc' },
        textColor: theme === 'dark' ? '#cbd5e1' : '#334155',
      },
    })
  }, [theme])

  useEffect(() => {
    if (!seriesApiRef.current) return
    const candles: CandlestickData<UTCTimestamp>[] = series.map((point) => ({
      time: point.time as UTCTimestamp,
      open: point.open,
      high: point.high,
      low: point.low,
      close: point.close,
    }))
    seriesApiRef.current.setData(candles)
    chartApiRef.current?.timeScale().fitContent()
  }, [series])

  const refreshChartForSelection = async () => {
    setIsLoading(true)
    try {
      const next = await fetchOHLCV(selectedToken, timeframe)
      setChartData(selectedKey, next)
      setSourceLabel('CoinGecko historical')
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

  useEffect(() => {
    if (!series.length) return
    const unsubscribe = subscribeLiveCandles(selectedToken, timeframe, series, (nextCandles, source) => {
      setChartData(selectedKey, nextCandles.slice(-320))
      setSourceLabel(source)
    })

    return () => {
      unsubscribe()
    }
  }, [selectedToken, selectedKey, timeframe, series, setChartData])

  const onChartClickCapture = (event: React.MouseEvent<HTMLDivElement>) => {
    if (!drawMode || !chartRootRef.current || !chartApiRef.current || !seriesApiRef.current) return
    const rect = chartRootRef.current.getBoundingClientRect()
    const x = event.clientX - rect.left
    const y = event.clientY - rect.top
    const time = chartApiRef.current.timeScale().coordinateToTime(x)
    const price = seriesApiRef.current.coordinateToPrice(y)
    if (typeof time !== 'number' || price == null) return

    const point = { time, price }
    if (!draftPoint) {
      setDraftPoint(point)
      return
    }

    addTrendline(selectedKey, {
      id: `${selectedKey}-${Date.now()}`,
      startTime: draftPoint.time,
      startPrice: draftPoint.price,
      endTime: point.time,
      endPrice: point.price,
    })
    setDraftPoint(null)
    setDrawMode(false)
  }

  const onTokenSelect = (token: TradingToken) => {
    selectToken(token)
    setDraftPoint(null)
    setDrawMode(false)
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
            <Button variant="secondary" onClick={toggleTheme}>
              Theme: {theme}
            </Button>
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
                  <p className="text-xs text-slate-500">Data source: {sourceLabel}</p>
                </div>
                <div className="flex flex-wrap gap-1 items-center">
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
                  <Button variant={drawMode ? 'primary' : 'secondary'} onClick={() => setDrawMode((prev) => !prev)}>
                    {drawMode ? 'Drawing…' : 'Draw Trendline'}
                  </Button>
                  <Button variant="secondary" onClick={() => clearTrendlines(selectedKey)}>
                    Clear Drawings
                  </Button>
                </div>
              </div>

              {is3DEnabled ? (
                <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_top,_rgba(20,184,166,0.18),_transparent_55%),radial-gradient(ellipse_at_bottom,_rgba(59,130,246,0.16),_transparent_60%)]" />
              ) : null}

              <div className="relative h-[500px] p-3">
                <div
                  className="relative h-full w-full overflow-hidden rounded-xl border border-slate-200 bg-white/80"
                  onClick={onChartClickCapture}
                >
                  <div ref={chartRootRef} className="h-full w-full" />
                  <svg className="pointer-events-none absolute inset-0 h-full w-full">
                    {lineCoordinates.map((line) => (
                      <line
                        key={line.id}
                        x1={line.x1}
                        y1={line.y1}
                        x2={line.x2}
                        y2={line.y2}
                        stroke="#f59e0b"
                        strokeWidth="2"
                        strokeDasharray="4 2"
                      />
                    ))}
                  </svg>
                  {isLoading ? (
                    <div className="pointer-events-none absolute inset-0 flex items-center justify-center bg-slate-900/10 text-sm font-medium text-slate-700">
                      Loading chart data…
                    </div>
                  ) : null}
                  {drawMode ? (
                    <div className="pointer-events-none absolute bottom-2 right-2 rounded-md bg-slate-900/80 px-2 py-1 text-xs text-white">
                      Click two points to place trendline
                    </div>
                  ) : null}
                </div>
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
                      addIndicatorForToken(selectedKey, indicator.id)
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
                    <button
                      key={indicator}
                      type="button"
                      className="max-w-[180px] truncate rounded-full bg-slate-900 px-3 py-1 text-xs font-semibold text-white"
                      title={`${indicator} (click to remove)`}
                      onClick={() => removeIndicatorForToken(selectedKey, indicator)}
                    >
                      {indicator} ×
                    </button>
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
