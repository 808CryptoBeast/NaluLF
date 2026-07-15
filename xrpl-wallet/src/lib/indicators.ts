import type { CandlePoint } from '../store/tradingStore'

/**
 * Ported faithfully from NaluLF/scripts/profile.js's _sma/_ema/_rsi/_atr/
 * _macd/_stochastic/_vwap/_volumeOscillators (same formulas, same defaults)
 * so indicator values here match what the legacy chart already computed.
 */

export interface IndicatorPoint {
  time: number
  value: number
}

export function sma(data: CandlePoint[], len: number): IndicatorPoint[] {
  const out: IndicatorPoint[] = []
  let sum = 0
  for (let i = 0; i < data.length; i += 1) {
    sum += data[i].close
    if (i >= len) sum -= data[i - len].close
    if (i >= len - 1) out.push({ time: data[i].time, value: sum / len })
  }
  return out
}

export function ema(data: CandlePoint[], len: number): IndicatorPoint[] {
  const out: IndicatorPoint[] = []
  if (!data.length) return out
  const k = 2 / (len + 1)
  let value = data[0].close
  for (let i = 0; i < data.length; i += 1) {
    value = i === 0 ? data[i].close : data[i].close * k + value * (1 - k)
    if (i >= len - 1) out.push({ time: data[i].time, value })
  }
  return out
}

export function vwap(data: CandlePoint[]): IndicatorPoint[] {
  const out: IndicatorPoint[] = []
  let pv = 0
  let vol = 0
  for (const c of data) {
    const typical = (c.high + c.low + c.close) / 3
    pv += typical * (c.volume || 0)
    vol += c.volume || 0
    if (vol > 0) out.push({ time: c.time, value: pv / vol })
  }
  return out
}

export function rsi(data: CandlePoint[], len = 14): IndicatorPoint[] {
  const out: IndicatorPoint[] = []
  if (data.length <= len) return out
  let gain = 0
  let loss = 0
  for (let i = 1; i <= len; i += 1) {
    const d = data[i].close - data[i - 1].close
    gain += d > 0 ? d : 0
    loss += d < 0 ? -d : 0
  }
  let avgGain = gain / len
  let avgLoss = loss / len
  for (let i = len + 1; i < data.length; i += 1) {
    const d = data[i].close - data[i - 1].close
    avgGain = (avgGain * (len - 1) + (d > 0 ? d : 0)) / len
    avgLoss = (avgLoss * (len - 1) + (d < 0 ? -d : 0)) / len
    const rs = avgLoss > 0 ? avgGain / avgLoss : 100
    out.push({ time: data[i].time, value: 100 - 100 / (1 + rs) })
  }
  return out
}

export function atr(data: CandlePoint[], len = 14): IndicatorPoint[] {
  const tr: number[] = []
  for (let i = 0; i < data.length; i += 1) {
    const prevClose = i > 0 ? data[i - 1].close : data[i].close
    tr.push(Math.max(data[i].high - data[i].low, Math.abs(data[i].high - prevClose), Math.abs(data[i].low - prevClose)))
  }
  const out: IndicatorPoint[] = []
  let prev = tr.slice(0, len).reduce((s, v) => s + v, 0) / Math.max(1, len)
  for (let i = len; i < data.length; i += 1) {
    prev = (prev * (len - 1) + tr[i]) / len
    out.push({ time: data[i].time, value: prev })
  }
  return out
}

export interface StochasticResult {
  k: IndicatorPoint[]
  d: IndicatorPoint[]
}

export function stochastic(data: CandlePoint[], len = 14, smooth = 3): StochasticResult {
  const k: IndicatorPoint[] = []
  for (let i = len - 1; i < data.length; i += 1) {
    const slice = data.slice(i - len + 1, i + 1)
    const hh = Math.max(...slice.map((c) => c.high))
    const ll = Math.min(...slice.map((c) => c.low))
    const v = hh !== ll ? ((data[i].close - ll) / (hh - ll)) * 100 : 50
    k.push({ time: data[i].time, value: v })
  }
  const d: IndicatorPoint[] = []
  for (let i = smooth - 1; i < k.length; i += 1) {
    const s = k.slice(i - smooth + 1, i + 1).reduce((a, b) => a + b.value, 0) / smooth
    d.push({ time: k[i].time, value: s })
  }
  return { k, d }
}

export interface MacdResult {
  line: IndicatorPoint[]
  signal: IndicatorPoint[]
  hist: IndicatorPoint[]
}

export function macd(data: CandlePoint[], fast = 12, slow = 26, signalLen = 9): MacdResult {
  const fastEma = ema(data, fast)
  const slowEma = ema(data, slow)
  const slowMap = new Map(slowEma.map((v) => [v.time, v.value]))
  const line = fastEma
    .filter((v) => slowMap.has(v.time))
    .map((v) => ({ time: v.time, value: v.value - slowMap.get(v.time)! }))

  const signal: IndicatorPoint[] = []
  if (line.length) {
    const k = 2 / (signalLen + 1)
    let value = line[0].value
    for (let i = 0; i < line.length; i += 1) {
      value = i === 0 ? line[i].value : line[i].value * k + value * (1 - k)
      if (i >= signalLen - 1) signal.push({ time: line[i].time, value })
    }
  }

  const sigMap = new Map(signal.map((v) => [v.time, v.value]))
  const hist = line.filter((v) => sigMap.has(v.time)).map((v) => ({ time: v.time, value: v.value - sigMap.get(v.time)! }))
  return { line, signal, hist }
}

export function obv(data: CandlePoint[]): IndicatorPoint[] {
  const out: IndicatorPoint[] = []
  let value = 0
  for (let i = 0; i < data.length; i += 1) {
    if (i > 0) {
      const prev = data[i - 1]
      if (data[i].close > prev.close) value += data[i].volume || 0
      if (data[i].close < prev.close) value -= data[i].volume || 0
    }
    out.push({ time: data[i].time, value })
  }
  return out
}
