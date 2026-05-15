import dayjs from 'dayjs'
import { Copy, RefreshCw } from 'lucide-react'
import { QRCodeSVG } from 'qrcode.react'
import type { UiTransaction } from '../types/wallet'
import { formatCurrency, shortAddress } from '../lib/format'
import { Button, Card, SectionTitle } from './ui'

interface Props {
  address: string
  balanceXrp: number
  reserveXrp: number
  xrpUsdPrice: number
  transactions: UiTransaction[]
  onRefresh: () => Promise<void>
}

export function Dashboard({
  address,
  balanceXrp,
  reserveXrp,
  xrpUsdPrice,
  transactions,
  onRefresh,
}: Props) {
  const liquidXrp = Math.max(balanceXrp - reserveXrp, 0)
  const usdValue = balanceXrp * xrpUsdPrice

  return (
    <div className="grid gap-5 xl:grid-cols-[1.6fr_1fr]">
      <div className="space-y-5">
        <Card>
          <SectionTitle
            title="Portfolio Overview"
            subtitle="Live XRPL account value and reserve-aware spendable balance."
          />
          <div className="grid gap-4 md:grid-cols-3">
            <Stat label="Total XRP" value={formatCurrency(balanceXrp, 'XRP')} />
            <Stat label="Portfolio (USD)" value={formatCurrency(usdValue, 'USD')} />
            <Stat label="Liquid XRP" value={formatCurrency(liquidXrp, 'XRP')} />
          </div>
        </Card>

        <Card>
          <div className="mb-3 flex items-center justify-between gap-3">
            <SectionTitle title="Recent Transactions" subtitle="Latest validated activity from account_tx." />
            <Button variant="secondary" onClick={onRefresh}>
              <RefreshCw className="mr-2 h-4 w-4" /> Refresh
            </Button>
          </div>

          <div className="overflow-auto">
            <table className="min-w-full text-left text-sm">
              <thead className="border-b border-slate-200 text-xs uppercase tracking-wide text-slate-500">
                <tr>
                  <th className="py-2 pr-3">Type</th>
                  <th className="py-2 pr-3">Result</th>
                  <th className="py-2 pr-3">Fee</th>
                  <th className="py-2 pr-3">Hash</th>
                  <th className="py-2">Observed</th>
                </tr>
              </thead>
              <tbody>
                {transactions.slice(0, 10).map((tx) => (
                  <tr className="border-b border-slate-100 text-slate-700" key={tx.hash}>
                    <td className="py-2 pr-3">{tx.type}</td>
                    <td className="py-2 pr-3">{tx.result}</td>
                    <td className="py-2 pr-3">{tx.fee}</td>
                    <td className="py-2 pr-3 font-medium text-slate-900">{shortAddress(tx.hash)}</td>
                    <td className="py-2 text-slate-500">{tx.date ? dayjs(tx.date).format('YYYY-MM-DD') : '-'}</td>
                  </tr>
                ))}
                {!transactions.length ? (
                  <tr>
                    <td className="py-3 text-slate-500" colSpan={5}>
                      No transactions found yet.
                    </td>
                  </tr>
                ) : null}
              </tbody>
            </table>
          </div>
        </Card>
      </div>

      <div className="space-y-5">
        <Card className="text-center">
          <SectionTitle title="Receive XRP & Tokens" subtitle="Share this XRPL classic address." />
          <div className="mx-auto mb-3 w-fit rounded-xl border border-slate-200 bg-white p-3">
            <QRCodeSVG value={address} size={156} bgColor="#ffffff" fgColor="#0f172a" />
          </div>
          <p className="mb-3 break-all text-sm text-slate-700">{address}</p>
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
          <SectionTitle title="XRP Balance Split" />
          <div className="space-y-2 text-sm text-slate-700">
            <Row label="Total XRP" value={formatCurrency(balanceXrp, 'XRP')} />
            <Row label="Reserve XRP" value={formatCurrency(reserveXrp, 'XRP')} />
            <Row label="Liquid XRP" value={formatCurrency(liquidXrp, 'XRP')} />
          </div>
        </Card>
      </div>
    </div>
  )
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-xl border border-slate-200 bg-slate-50/70 p-3">
      <p className="text-xs uppercase tracking-wide text-slate-500">{label}</p>
      <p className="mt-1 text-lg font-semibold text-slate-900">{value}</p>
    </div>
  )
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between border-b border-slate-100 py-2 last:border-0">
      <span>{label}</span>
      <strong className="text-slate-900">{value}</strong>
    </div>
  )
}
