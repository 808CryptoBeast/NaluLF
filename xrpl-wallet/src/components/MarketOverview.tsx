import type { NetworkStats } from '../types/wallet'
import { formatCurrency, shortAddress } from '../lib/format'
import { Card, Row, SectionTitle, Stat } from './ui'

interface Props {
  xrpUsdPrice: number
  networkStats: NetworkStats
  baseFeeXrp: string
}

/**
 * What the Dashboard shows before a wallet exists — general XRPL market and
 * network state, not personal account data (there isn't any yet). Once a
 * wallet is created, the Dashboard tab switches to the real per-account view.
 */
export function MarketOverview({ xrpUsdPrice, networkStats, baseFeeXrp }: Props) {
  return (
    <div className="space-y-5">
      <Card>
        <SectionTitle title="Market Overview" subtitle="General XRPL market data — add a wallet to see your own account here." />
        <div className="grid gap-4 md:grid-cols-2">
          <Stat label="XRP / USD" value={xrpUsdPrice > 0 ? formatCurrency(xrpUsdPrice, 'USD') : '—'} />
          <Stat label="Network" value={networkStats.networkLabel} />
        </div>
      </Card>

      <Card>
        <SectionTitle title="Network Stats" />
        <div className="space-y-2 text-sm text-slate-300">
          <Row label="Ledger Index" value={String(networkStats.ledgerIndex || '—')} />
          <Row label="Ledger Hash" value={shortAddress(networkStats.validatedLedgerHash)} />
          <Row label="Base Fee" value={`${baseFeeXrp} XRP`} />
        </div>
      </Card>
    </div>
  )
}
