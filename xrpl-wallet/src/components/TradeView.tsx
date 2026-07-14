import { TradingTerminal } from './TradingTerminal'
import type { AggregatedAsset } from '../types/wallet'
import { SectionTitle } from './ui'

interface Props {
  aggregatedAssets: AggregatedAsset[]
}

/**
 * The chart used to live embedded inside Dashboard alongside ~9 other cards
 * (account health, portfolio metrics, activity feed, receive, network
 * stats...) — a dense single-page kitchen sink. It gets its own top-level
 * tab now: a dedicated trading screen, not one card among many.
 */
export function TradeView({ aggregatedAssets }: Props) {
  return (
    <div className="space-y-5">
      <SectionTitle
        title="Trade"
        subtitle="Chart, indicators, and token discovery for the XRPL DEX."
      />
      <TradingTerminal aggregatedAssets={aggregatedAssets} />
    </div>
  )
}
