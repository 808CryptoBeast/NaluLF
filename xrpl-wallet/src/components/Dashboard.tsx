import dayjs from 'dayjs'
import { Copy, RefreshCw } from 'lucide-react'
import { QRCodeSVG } from 'qrcode.react'
import type { ActivityEvent, NetworkStats, SecuritySnapshot } from '../types/wallet'
import { formatCurrency, shortAddress } from '../lib/format'
import { Button, Card, Row, SectionTitle, Stat } from './ui'

interface Props {
  address: string
  balanceXrp: number
  reserveXrp: number
  activity: ActivityEvent[]
  security: SecuritySnapshot
  networkStats: NetworkStats
  onRefresh: () => Promise<void>
}

/**
 * A genuinely light "at a glance" landing view — balance health, a short
 * activity preview, and receive/network info. Everything else that used to
 * live here (the chart, full portfolio breakdown, full transaction history,
 * security/compliance details) now has its own dedicated tab, since cramming
 * all of it onto one screen was the exact problem this rebuild set out to fix.
 */
export function Dashboard({
  address,
  balanceXrp,
  reserveXrp,
  activity,
  security,
  networkStats,
  onRefresh,
}: Props) {
  const liquidXrp = Math.max(balanceXrp - reserveXrp, 0)
  const spendableXrp = Math.max(balanceXrp - security.totalReserveXrp, 0)

  return (
    <div className="space-y-5">
      <Card>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <SectionTitle title="Overview" subtitle="Account health at a glance." />
          <Button variant="secondary" onClick={onRefresh}>
            <RefreshCw className="mr-2 h-4 w-4" /> Refresh
          </Button>
        </div>
        <div className="grid gap-4 md:grid-cols-3">
          <Stat label="Liquid XRP" value={formatCurrency(liquidXrp, 'XRP')} />
          <Stat label="XRP Reserve" value={formatCurrency(security.totalReserveXrp, 'XRP')} />
          <Stat label="Net Spendable XRP" value={formatCurrency(spendableXrp, 'XRP')} />
        </div>
      </Card>

      <div className="grid gap-5 xl:grid-cols-[1.7fr_1fr]">
        <Card>
          <SectionTitle title="Recent Activity" subtitle="See the Portfolio tab for full transaction history." />
          <div className="space-y-2">
            {activity.slice(0, 5).map((event) => (
              <div key={event.id} className="rounded-xl border border-slate-700 bg-slate-800 p-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <p className="text-sm font-semibold text-white">{event.title}</p>
                  <span className="rounded-full bg-slate-900 px-2 py-0.5 text-xs font-medium text-slate-400">
                    {event.category}
                  </span>
                </div>
                <p className="mt-1 text-sm text-slate-300">{event.detail}</p>
                <p className="mt-1 text-xs text-slate-400">
                  {dayjs(event.date).format('YYYY-MM-DD HH:mm:ss')} | {event.status}
                </p>
              </div>
            ))}
            {!activity.length ? <p className="text-sm text-slate-400">No activity yet.</p> : null}
          </div>
        </Card>

        <div className="space-y-5">
          <Card className="text-center">
            <SectionTitle title="Receive" subtitle="Share your XRPL address." />
            <div className="mx-auto mb-3 w-fit rounded-xl border border-slate-700 bg-slate-900 p-3">
              <QRCodeSVG value={address} size={156} bgColor="#ffffff" fgColor="#0f172a" />
            </div>
            <p className="mb-3 break-all text-sm text-slate-300">{address}</p>
            <Button
              variant="secondary"
              onClick={() => {
                navigator.clipboard.writeText(address)
              }}
            >
              <Copy className="mr-2 h-4 w-4" /> Copy Address
            </Button>
          </Card>

          <Card>
            <SectionTitle title="Network Stats" />
            <div className="space-y-2 text-sm text-slate-300">
              <Row label="Network" value={networkStats.networkLabel} />
              <Row label="Ledger Index" value={String(networkStats.ledgerIndex)} />
              <Row label="Ledger Hash" value={shortAddress(networkStats.validatedLedgerHash)} />
              <Row label="Base Fee" value={`${security.baseFeeXrp} XRP`} />
            </div>
          </Card>
        </div>
      </div>
    </div>
  )
}
