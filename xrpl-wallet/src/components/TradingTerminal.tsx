import { useEffect, useMemo, useRef, useState } from 'react'
import {
  CandlestickSeries,
  HistogramSeries,
  LineSeries,
  createChart,
  type CandlestickData,
  type HistogramData,
  type IChartApi,
  type ISeriesApi,
  type LineData,
  type UTCTimestamp,
} from 'lightweight-charts'
import type { AggregatedAsset } from '../types/wallet'
import { fetchOHLCV, subscribeLiveCandles } from '../services/chartService'
import { atr, ema, macd, obv, rsi, sma, stochastic, vwap, type IndicatorPoint } from '../lib/indicators'
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

interface IndicatorLine {
  key: string
  color: string
  points: IndicatorPoint[]
}

/** Same math as NaluLF/scripts/profile.js's _sma/_ema/_rsi/etc (see lib/indicators.ts).
 *  'overlay' indicators share the candle price scale; 'oscillator' ones get
 *  their own price scale squeezed into the bottom of the chart. */
function computeIndicatorLines(id: string, candles: CandlePoint[]): { kind: 'overlay' | 'oscillator'; lines: IndicatorLine[] } {
  switch (id) {
    case 'SMA':
      return { kind: 'overlay', lines: [{ key: 'SMA-20', color: '#f59e0b', points: sma(candles, 20) }] }
    case 'EMA':
      return { kind: 'overlay', lines: [{ key: 'EMA-20', color: '#a855f7', points: ema(candles, 20) }] }
    case 'VWAP':
      return { kind: 'overlay', lines: [{ key: 'VWAP', color: '#22d3ee', points: vwap(candles) }] }
    case 'RSI':
      return { kind: 'oscillator', lines: [{ key: 'RSI-14', color: '#a3e635', points: rsi(candles, 14) }] }
    case 'ATR':
      return { kind: 'oscillator', lines: [{ key: 'ATR-14', color: '#fb923c', points: atr(candles, 14) }] }
    case 'OBV':
      return { kind: 'oscillator', lines: [{ key: 'OBV', color: '#67e8f9', points: obv(candles) }] }
    case 'Stoch': {
      const { k, d } = stochastic(candles, 14, 3)
      return {
        kind: 'oscillator',
        lines: [
          { key: 'Stoch-%K', color: '#38bdf8', points: k },
          { key: 'Stoch-%D', color: '#f472b6', points: d },
        ],
      }
    }
    case 'MACD': {
      const { line, signal } = macd(candles, 12, 26, 9)
      return {
        kind: 'oscillator',
        lines: [
          { key: 'MACD', color: '#38bdf8', points: line },
          { key: 'MACD-Signal', color: '#f97316', points: signal },
        ],
      }
    }
    default:
      return { kind: 'overlay', lines: [] }
  }
}

function formatPrice(value: number): string {
  if (!Number.isFinite(value)) return '—'
  const decimals = value >= 100 ? 2 : value >= 1 ? 4 : 6
  return value.toLocaleString('en-US', { minimumFractionDigits: decimals, maximumFractionDigits: decimals })
}

function formatCompactNumber(value: number | undefined): string {
  if (!Number.isFinite(value ?? NaN) || !value) return '—'
  if (value >= 1_000_000_000) return `${(value / 1_000_000_000).toFixed(2)}B`
  if (value >= 1_000_000) return `${(value / 1_000_000).toFixed(2)}M`
  if (value >= 1_000) return `${(value / 1_000).toFixed(2)}K`
  return value.toFixed(2)
}

interface HoverCandle {
  time: number
  open: number
  high: number
  low: number
  close: number
  volume?: number
}

const DEFAULT_BIAS_COACHING =
  'Bias guardrail: define entry, invalidation, and position size before execution. Avoid anchoring to prior highs and wait for confirmation from volume or trend context.'

const XRP_ADDRESS_RE = /^r[1-9A-HJ-NP-Za-km-z]{24,34}$/

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
          : 'border-slate-700 bg-slate-800 text-slate-300 hover:border-slate-600'
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
  const [isSynthetic, setIsSynthetic] = useState(false)
  const [drawMode, setDrawMode] = useState(false)
  const [draftPoint, setDraftPoint] = useState<DraftPoint | null>(null)
  const [lookupCurrency, setLookupCurrency] = useState('')
  const [lookupIssuer, setLookupIssuer] = useState('')
  const [lookupError, setLookupError] = useState<string | null>(null)

  const [hoverCandle, setHoverCandle] = useState<HoverCandle | null>(null)

  const chartContainerRef = useRef<HTMLDivElement | null>(null)
  const chartRootRef = useRef<HTMLDivElement | null>(null)
  const chartApiRef = useRef<IChartApi | null>(null)
  const seriesApiRef = useRef<ISeriesApi<'Candlestick'> | null>(null)
  const volumeSeriesApiRef = useRef<ISeriesApi<'Histogram'> | null>(null)
  const indicatorSeriesRef = useRef<Map<string, ISeriesApi<'Line'>>>(new Map())

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

  const quoteStats = useMemo(() => {
    if (!series.length) return null
    const last = series[series.length - 1]
    const first = series[0]
    const changeAbs = last.close - first.open
    const changePct = first.open ? (changeAbs / first.open) * 100 : 0
    const periodHigh = Math.max(...series.map((c) => c.high))
    const periodLow = Math.min(...series.map((c) => c.low))
    const periodVolume = series.reduce((sum, c) => sum + (c.volume ?? 0), 0)
    return { last: last.close, changeAbs, changePct, periodHigh, periodLow, periodVolume }
  }, [series])

  const indicatorLegend = useMemo(() => {
    return selectedIndicators.flatMap((id) => {
      const { lines } = computeIndicatorLines(id, series)
      return lines
        .filter((line) => line.points.length > 0)
        .map((line) => ({ key: line.key, color: line.color, value: line.points[line.points.length - 1].value }))
    })
  }, [selectedIndicators, series])

  const displayedCandle: HoverCandle | null = hoverCandle ?? (series.length ? series[series.length - 1] : null)

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
      autoSize: true,
    })

    const candleSeries = chart.addSeries(CandlestickSeries, {
      upColor: '#16a34a',
      downColor: '#dc2626',
      borderVisible: false,
      wickUpColor: '#16a34a',
      wickDownColor: '#dc2626',
    })

    // Volume bars share the main pane (standard trading-chart layout) —
    // their own price scale keeps them squeezed into the bottom ~18% so they
    // never compete with candle scaling.
    const volumeSeries = chart.addSeries(HistogramSeries, {
      priceScaleId: 'volume-overlay',
      priceFormat: { type: 'volume' },
      color: '#475569',
    })
    chart.priceScale('volume-overlay').applyOptions({ scaleMargins: { top: 0.85, bottom: 0 } })

    chartApiRef.current = chart
    seriesApiRef.current = candleSeries
    volumeSeriesApiRef.current = volumeSeries

    chart.subscribeCrosshairMove((param) => {
      if (!param.time) {
        setHoverCandle(null)
        return
      }
      const candle = param.seriesData.get(candleSeries) as CandlestickData<UTCTimestamp> | undefined
      if (!candle || !('open' in candle)) {
        setHoverCandle(null)
        return
      }
      const vol = param.seriesData.get(volumeSeries) as HistogramData<UTCTimestamp> | undefined
      setHoverCandle({
        time: Number(param.time),
        open: candle.open,
        high: candle.high,
        low: candle.low,
        close: candle.close,
        volume: vol?.value,
      })
    })

    return () => {
      volumeSeriesApiRef.current = null
      chart.remove()
      chartApiRef.current = null
      seriesApiRef.current = null
      indicatorSeriesRef.current.clear()
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

    if (volumeSeriesApiRef.current) {
      const volumeBars: HistogramData<UTCTimestamp>[] = series.map((point) => ({
        time: point.time as UTCTimestamp,
        value: point.volume ?? 0,
        color: point.close >= point.open ? 'rgba(22,163,74,0.55)' : 'rgba(220,38,38,0.55)',
      }))
      volumeSeriesApiRef.current.setData(volumeBars)
    }

    chartApiRef.current?.timeScale().fitContent()
    setHoverCandle(null)
  }, [series])

  useEffect(() => {
    const chart = chartApiRef.current
    if (!chart) return

    indicatorSeriesRef.current.forEach((s) => {
      try {
        chart.removeSeries(s)
      } catch {
        // already disposed with the chart (e.g. theme change recreated it)
      }
    })
    indicatorSeriesRef.current.clear()

    if (!series.length) return

    const overlayLines: IndicatorLine[] = []
    const oscillatorGroups: { id: string; lines: IndicatorLine[] }[] = []
    selectedIndicators.forEach((id) => {
      const { kind, lines } = computeIndicatorLines(id, series)
      if (!lines.length) return
      if (kind === 'overlay') overlayLines.push(...lines)
      else oscillatorGroups.push({ id, lines })
    })

    overlayLines.forEach((line) => {
      const lineSeries = chart.addSeries(LineSeries, {
        color: line.color,
        lineWidth: 2,
        priceLineVisible: false,
        lastValueVisible: false,
      })
      lineSeries.setData(line.points.map((p) => ({ time: p.time as UTCTimestamp, value: p.value }) as LineData<UTCTimestamp>))
      indicatorSeriesRef.current.set(line.key, lineSeries)
    })

    // Volume always keeps the bottom 15% of the pane. Oscillators (when
    // present) get a 17% band directly above it, and candles take whatever
    // is left at the top — the three never visually overlap.
    const hasOscillators = oscillatorGroups.length > 0
    chart.priceScale('right').applyOptions({
      scaleMargins: hasOscillators ? { top: 0.05, bottom: 0.32 } : { top: 0.05, bottom: 0.15 },
    })

    const oscillatorTop = 0.68
    const oscillatorBandHeight = hasOscillators ? 0.17 / oscillatorGroups.length : 0
    oscillatorGroups.forEach((group, idx) => {
      const scaleId = `osc-${group.id}`
      const top = oscillatorTop + oscillatorBandHeight * idx
      const bottom = Math.max(0, 0.32 - oscillatorBandHeight * (idx + 1))
      group.lines.forEach((line) => {
        const lineSeries = chart.addSeries(LineSeries, {
          color: line.color,
          lineWidth: 1,
          priceScaleId: scaleId,
          priceLineVisible: false,
          lastValueVisible: false,
        })
        lineSeries.setData(line.points.map((p) => ({ time: p.time as UTCTimestamp, value: p.value }) as LineData<UTCTimestamp>))
        indicatorSeriesRef.current.set(line.key, lineSeries)
      })
      chart.priceScale(scaleId).applyOptions({ scaleMargins: { top, bottom } })
    })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedIndicators.join(','), series, theme])

  const refreshChartForSelection = async () => {
    setIsLoading(true)
    try {
      const { candles, source, synthetic } = await fetchOHLCV(selectedToken, timeframe)
      setChartData(selectedKey, candles)
      setSourceLabel(source)
      setIsSynthetic(synthetic)
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
      setIsSynthetic(false)
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

  const submitLookup = () => {
    const currency = lookupCurrency.trim().toUpperCase()
    const issuer = lookupIssuer.trim()
    if (!currency) {
      setLookupError('Enter a currency code first.')
      return
    }
    if (!issuer || !XRP_ADDRESS_RE.test(issuer)) {
      setLookupError('Enter a valid XRPL issuer address.')
      return
    }
    setLookupError(null)
    onTokenSelect({
      symbol: currency,
      name: currency,
      issuer,
      currencyCode: currency,
      isXRP: false,
      pairType: `${currency}/XRP`,
    })
    setLookupCurrency('')
    setLookupIssuer('')
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
            <div id="chart-container" ref={chartContainerRef} className="relative overflow-hidden rounded-xl border border-slate-700">
              <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-700 bg-slate-800 p-3">
                <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
                  <p className="text-sm font-semibold text-white">{selectedToken.name}</p>
                  <span className="text-xs text-slate-500">{selectedToken.pairType}</span>
                  {quoteStats ? (
                    <>
                      <span className="text-xl font-bold tabular-nums text-white">${formatPrice(quoteStats.last)}</span>
                      <span
                        className={`text-sm font-semibold tabular-nums ${
                          quoteStats.changeAbs >= 0 ? 'text-emerald-400' : 'text-rose-400'
                        }`}
                      >
                        {quoteStats.changeAbs >= 0 ? '▲' : '▼'} {formatPrice(Math.abs(quoteStats.changeAbs))} (
                        {quoteStats.changePct >= 0 ? '+' : ''}
                        {quoteStats.changePct.toFixed(2)}%)
                      </span>
                    </>
                  ) : null}
                </div>
                <div className="flex flex-wrap gap-1 items-center">
                  {TIMEFRAMES.map((tf) => (
                    <button
                      key={tf}
                      type="button"
                      className={`rounded-md px-2 py-1 text-xs font-semibold ${
                        timeframe === tf ? 'bg-teal-700 text-white' : 'bg-slate-900 text-slate-300 border border-slate-600'
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

              {quoteStats ? (
                <div className="flex flex-wrap gap-x-5 gap-y-1 border-b border-slate-700 bg-slate-900/60 px-3 py-1.5 text-xs text-slate-400">
                  <span>
                    Period High <span className="text-slate-200">${formatPrice(quoteStats.periodHigh)}</span>
                  </span>
                  <span>
                    Period Low <span className="text-slate-200">${formatPrice(quoteStats.periodLow)}</span>
                  </span>
                  <span>
                    Volume <span className="text-slate-200">{formatCompactNumber(quoteStats.periodVolume)}</span>
                  </span>
                  <span>
                    Data source: {sourceLabel}
                    {isSynthetic ? (
                      <span className="ml-2 rounded-full border border-amber-700 bg-amber-950 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-amber-300">
                        No real market data — placeholder
                      </span>
                    ) : null}
                  </span>
                </div>
              ) : null}

              {is3DEnabled ? (
                <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_top,_rgba(20,184,166,0.18),_transparent_55%),radial-gradient(ellipse_at_bottom,_rgba(59,130,246,0.16),_transparent_60%)]" />
              ) : null}

              <div className="relative h-[600px] p-3">
                <div
                  className="relative h-full w-full overflow-hidden rounded-xl border border-slate-700 bg-slate-900/80"
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

                  {displayedCandle ? (
                    <div className="pointer-events-none absolute left-2 top-2 flex flex-wrap items-center gap-x-3 gap-y-1 rounded-lg bg-slate-900/80 px-2.5 py-1.5 text-[11px] font-medium tabular-nums text-slate-300 backdrop-blur-sm">
                      <span>
                        O <span className="text-slate-100">{formatPrice(displayedCandle.open)}</span>
                      </span>
                      <span>
                        H <span className="text-slate-100">{formatPrice(displayedCandle.high)}</span>
                      </span>
                      <span>
                        L <span className="text-slate-100">{formatPrice(displayedCandle.low)}</span>
                      </span>
                      <span className={displayedCandle.close >= displayedCandle.open ? 'text-emerald-400' : 'text-rose-400'}>
                        C <span>{formatPrice(displayedCandle.close)}</span>
                      </span>
                      {displayedCandle.volume ? (
                        <span>
                          Vol <span className="text-slate-100">{formatCompactNumber(displayedCandle.volume)}</span>
                        </span>
                      ) : null}
                      {indicatorLegend.map((item) => (
                        <span key={item.key} style={{ color: item.color }}>
                          {item.key} {formatPrice(item.value)}
                        </span>
                      ))}
                    </div>
                  ) : null}

                  {isLoading ? (
                    <div className="pointer-events-none absolute inset-0 flex items-center justify-center bg-slate-900/60 text-sm font-medium text-slate-300">
                      Loading chart data…
                    </div>
                  ) : null}
                  {drawMode ? (
                    <div className="pointer-events-none absolute bottom-2 right-2 rounded-md bg-slate-700/90 px-2 py-1 text-xs text-white">
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
                    className="rounded-full border border-slate-600 bg-slate-900 px-3 py-1 text-xs font-semibold text-slate-300 shadow-sm hover:border-teal-500 hover:text-teal-700"
                    title={indicator.purpose}
                  >
                    {indicator.category} · {indicator.id}
                  </button>
                ))}
              </div>
              <div className="rounded-xl border border-slate-700 bg-slate-800 p-3 text-sm text-slate-300">
                <p className="font-semibold text-white">Educational Panel</p>
                <p className="mt-1">
                  {currentIndicator
                    ? `${currentIndicator.id}: ${currentIndicator.purpose}`
                    : 'Select an indicator to view context and setup guidance.'}
                </p>
                <p className="mt-2 text-xs text-slate-400">{DEFAULT_BIAS_COACHING}</p>
              </div>
              {selectedIndicators.length ? (
                <div className="flex flex-wrap gap-2">
                  {selectedIndicators.map((indicator) => (
                    <button
                      key={indicator}
                      type="button"
                      className="max-w-[180px] truncate rounded-full bg-teal-700 px-3 py-1 text-xs font-semibold text-white"
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
            <SectionTitle
              title="Look Up Any Token"
              subtitle="Chart any issued XRPL asset by currency + issuer, even if it's not in the list above."
            />
            <div className="space-y-2">
              <Input
                value={lookupCurrency}
                onChange={(event) => setLookupCurrency(event.target.value)}
                placeholder="Currency code (e.g. USD, FOO)"
              />
              <Input
                value={lookupIssuer}
                onChange={(event) => setLookupIssuer(event.target.value)}
                placeholder="Issuer address (r...)"
              />
              {lookupError ? <p className="text-sm text-rose-400">{lookupError}</p> : null}
              <Button onClick={submitLookup}>🔎 Load Chart</Button>
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
                        : 'border-slate-700 bg-slate-800 hover:border-slate-600'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <div className="min-w-0">
                        <p className="truncate text-sm font-semibold text-white">{token.symbol}</p>
                        <p className="truncate text-xs text-slate-400" title={token.issuer ?? 'Native XRP'}>
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
              {!watchlist.length ? <p className="text-sm text-slate-400">No watchlist tokens yet.</p> : null}
            </div>
          </Card>
        </div>
      </div>
    </div>
  )
}
