import { useMemo, useState } from 'react'
import dayjs from 'dayjs'
import { Copy, RefreshCw } from 'lucide-react'
import { QRCodeSVG } from 'qrcode.react'
import { TradingTerminal } from './TradingTerminal'
import type {
  ActivityEvent,
  AggregatedAsset,
  NetworkStats,
  SecuritySnapshot,
  UiTransaction,
} from '../types/wallet'
import { formatCurrency, shortAddress } from '../lib/format'
import { Button, Card, Notice, SectionTitle } from './ui'

type ProfileView = 'dashboard' | 'portfolio' | 'activity' | 'security'

interface Props {
  address: string
  balanceXrp: number
  reserveXrp: number
  xrpUsdPrice: number
  transactions: UiTransaction[]
  activity: ActivityEvent[]
  security: SecuritySnapshot
  networkStats: NetworkStats
  aggregatedAssets: AggregatedAsset[]
  trustlineCount: number
  nftCount: number
  lpTokenCount: number
  onRefresh: () => Promise<void>
}

export function Dashboard({
  address,
  balanceXrp,
  reserveXrp,
  xrpUsdPrice,
  transactions,
  activity,
  security,
  networkStats,
  aggregatedAssets,
  trustlineCount,
  nftCount,
  lpTokenCount,
  onRefresh,
}: Props) {
  const [view, setView] = useState<ProfileView>('dashboard')
  const [selectedTx, setSelectedTx] = useState<UiTransaction | null>(null)

  const liquidXrp = Math.max(balanceXrp - reserveXrp, 0)
  const spendableXrp = Math.max(balanceXrp - security.totalReserveXrp, 0)
  const portfolioUsd = balanceXrp * xrpUsdPrice

  const assetsByType = useMemo(() => {
    const groups = {
      xrp: [] as AggregatedAsset[],
      token: [] as AggregatedAsset[],
      nft: [] as AggregatedAsset[],
      lp: [] as AggregatedAsset[],
    }
    aggregatedAssets.forEach((asset) => {
      groups[asset.type].push(asset)
    })
    return groups
  }, [aggregatedAssets])

  return (
    <div className="space-y-5">
      <Card>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <SectionTitle
            title="Mission Control"
            subtitle="Real-time account health, portfolio intelligence, and security posture."
          />
          <Button variant="secondary" onClick={onRefresh}>
            <RefreshCw className="mr-2 h-4 w-4" /> Refresh
          </Button>
        </div>

        <div className="mt-2 flex flex-wrap gap-2">
          <TabButton label="Dashboard" active={view === 'dashboard'} onClick={() => setView('dashboard')} />
          <TabButton label="Portfolio" active={view === 'portfolio'} onClick={() => setView('portfolio')} />
          <TabButton label="Activity" active={view === 'activity'} onClick={() => setView('activity')} />
          <TabButton label="Security & Settings" active={view === 'security'} onClick={() => setView('security')} />
        </div>
      </Card>

      {view === 'dashboard' ? (
        <div className="grid gap-5 xl:grid-cols-[1.7fr_1fr]">
          <div className="space-y-5">
            <TradingTerminal aggregatedAssets={aggregatedAssets} />

            <Card>
              <SectionTitle title="Account Health" subtitle="Liquid, reserve, and spendable XRP." />
              <div className="grid gap-4 md:grid-cols-3">
                <Stat label="Liquid XRP" value={formatCurrency(liquidXrp, 'XRP')} />
                <Stat label="XRP Reserve" value={formatCurrency(security.totalReserveXrp, 'XRP')} />
                <Stat label="Net Spendable XRP" value={formatCurrency(spendableXrp, 'XRP')} />
              </div>
            </Card>

            <Card>
              <SectionTitle title="Portfolio Metrics" subtitle="Asset and holdings footprint across XRPL." />
              <div className="grid gap-4 md:grid-cols-4">
                <Stat label="Total Value" value={formatCurrency(portfolioUsd, 'USD')} />
                <Stat label="Trustlines" value={String(trustlineCount)} />
                <Stat label="NFTs" value={String(nftCount)} />
                <Stat label="LP Tokens Held" value={String(lpTokenCount)} />
              </div>
            </Card>

            <Card>
              <SectionTitle title="Live Activity Stream" subtitle="Incoming/outgoing activity, trustline and NFT events." />
              <div className="space-y-2">
                {activity.slice(0, 12).map((event) => (
                  <div key={event.id} className="rounded-xl border border-slate-200 bg-slate-50 p-3">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <p className="text-sm font-semibold text-slate-900">{event.title}</p>
                      <span className="rounded-full bg-white px-2 py-0.5 text-xs font-medium text-slate-600">
                        {event.category}
                      </span>
                    </div>
                    <p className="mt-1 text-sm text-slate-700">{event.detail}</p>
                    <p className="mt-1 text-xs text-slate-500">
                      {dayjs(event.date).format('YYYY-MM-DD HH:mm:ss')} | {event.status}
                    </p>
                  </div>
                ))}
                {!activity.length ? <p className="text-sm text-slate-500">No activity yet.</p> : null}
              </div>
            </Card>
          </div>

          <div className="space-y-5">
            <Card className="text-center">
              <SectionTitle title="Receive" subtitle="Share your XRPL address." />
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
              <SectionTitle title="Network Stats" />
              <div className="space-y-2 text-sm text-slate-700">
                <Row label="Network" value={networkStats.networkLabel} />
                <Row label="Ledger Index" value={String(networkStats.ledgerIndex)} />
                <Row label="Ledger Hash" value={shortAddress(networkStats.validatedLedgerHash)} />
                <Row label="Base Fee" value={`${security.baseFeeXrp} XRP`} />
              </div>
            </Card>
          </div>
        </div>
      ) : null}

      {view === 'portfolio' ? (
        <div className="grid gap-5 lg:grid-cols-2">
          <AssetGroup title="XRP" assets={assetsByType.xrp} xrpUsdPrice={xrpUsdPrice} />
          <AssetGroup title="Tokens" assets={assetsByType.token} xrpUsdPrice={xrpUsdPrice} />
          <AssetGroup title="NFTs" assets={assetsByType.nft} xrpUsdPrice={xrpUsdPrice} />
          <AssetGroup title="LP Tokens" assets={assetsByType.lp} xrpUsdPrice={xrpUsdPrice} />
        </div>
      ) : null}

      {view === 'activity' ? (
        <Card>
          <SectionTitle
            title="Recent Activity"
            subtitle="Detailed transaction history with advanced technical view."
          />
          <div className="overflow-auto">
            <table className="min-w-full text-left text-sm">
              <thead className="border-b border-slate-200 text-xs uppercase tracking-wide text-slate-500">
                <tr>
                  <th className="py-2 pr-3">Type</th>
                  <th className="py-2 pr-3">Amount</th>
                  <th className="py-2 pr-3">Status</th>
                  <th className="py-2 pr-3">Date</th>
                  <th className="py-2 pr-3">Hash</th>
                  <th className="py-2">Details</th>
                </tr>
              </thead>
              <tbody>
                {transactions.map((tx) => (
                  <tr key={tx.hash} className="border-b border-slate-100 text-slate-700">
                    <td className="py-2 pr-3">{tx.type}</td>
                    <td className="py-2 pr-3">{tx.amount ?? '-'}</td>
                    <td className="py-2 pr-3">{tx.result}</td>
                    <td className="py-2 pr-3">{dayjs(tx.date).format('YYYY-MM-DD HH:mm')}</td>
                    <td className="py-2 pr-3 font-medium text-slate-900">{shortAddress(tx.hash)}</td>
                    <td className="py-2">
                      <Button variant="secondary" onClick={() => setSelectedTx(tx)}>
                        Advanced
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {selectedTx ? (
            <div className="mt-4 rounded-xl border border-slate-200 bg-slate-50 p-3">
              <p className="text-sm font-semibold text-slate-900">Advanced Details - {selectedTx.hash}</p>
              <pre className="mt-2 overflow-auto whitespace-pre-wrap text-xs text-slate-700">
                {JSON.stringify(selectedTx.raw, null, 2)}
              </pre>
            </div>
          ) : null}
        </Card>
      ) : null}

      {view === 'security' ? (
        <div className="grid gap-5 xl:grid-cols-2">
          <Card>
            <SectionTitle title="Security & Compliance Hub" subtitle="Reserve model, fee posture, account flags." />
            <div className="space-y-2 text-sm text-slate-700">
              <Row label="Base Reserve" value={formatCurrency(security.baseReserveXrp, 'XRP')} />
              <Row label="Owner Reserve" value={formatCurrency(security.ownerReserveXrp, 'XRP')} />
              <Row label="Total Reserve" value={formatCurrency(security.totalReserveXrp, 'XRP')} />
              <Row label="Account Sequence" value={String(security.accountSequence)} />
              <Row label="Base Fee" value={`${security.baseFeeXrp} XRP`} />
            </div>
            <div className="mt-4">
              <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">Active Account Flags</p>
              <div className="flex flex-wrap gap-2">
                {security.accountFlags.length
                  ? security.accountFlags.map((flag) => (
                      <span key={flag} className="rounded-full border border-slate-300 bg-white px-2 py-1 text-xs text-slate-700">
                        {flag}
                      </span>
                    ))
                  : <span className="text-sm text-slate-500">No active special flags</span>}
              </div>
            </div>
          </Card>

          <Card>
            <SectionTitle title="Safety Guidance" />
            <Notice tone="warning">
              Transactions that create objects (trustlines, escrow entries, offers) increase owner reserve. Ensure spendable XRP stays above network reserve requirements.
            </Notice>
            <Notice tone="info" className="mt-3">
              Keep your seed offline, export encrypted keystore backups, and lock this session when idle.
            </Notice>
          </Card>
        </div>
      ) : null}
    </div>
  )
}

function TabButton({
  label,
  active,
  onClick,
}: {
  label: string
  active: boolean
  onClick: () => void
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`rounded-lg px-3 py-1.5 text-sm font-semibold transition ${
        active ? 'bg-teal-700 text-white' : 'bg-slate-100 text-slate-700 hover:bg-slate-200'
      }`}
    >
      {label}
    </button>
  )
}

function AssetGroup({
  title,
  assets,
  xrpUsdPrice,
}: {
  title: string
  assets: AggregatedAsset[]
  xrpUsdPrice: number
}) {
  return (
    <Card>
      <SectionTitle title={title} />
      <div className="space-y-2">
        {assets.map((asset) => {
          const valueXrp = asset.valueXrp || (asset.valueUsd && xrpUsdPrice > 0 ? asset.valueUsd / xrpUsdPrice : 0)
          const valueUsd = asset.valueUsd || valueXrp * xrpUsdPrice
          return (
            <div key={`${asset.type}-${asset.symbol}-${asset.metadata ?? ''}`} className="rounded-xl border border-slate-200 bg-slate-50 p-3">
              <div className="flex items-center justify-between gap-2">
                <p className="text-sm font-semibold text-slate-900">{asset.name}</p>
                <p className="text-sm text-slate-700">Qty: {asset.quantity}</p>
              </div>
              <div className="mt-1 flex flex-wrap items-center gap-2 text-xs">
                <span className="text-slate-600">{asset.metadata}</span>
                <span className={`rounded-full px-2 py-0.5 font-semibold ${
                  asset.priceConfidence === 'high'
                    ? 'bg-emerald-100 text-emerald-700'
                    : asset.priceConfidence === 'medium'
                      ? 'bg-amber-100 text-amber-700'
                      : asset.priceConfidence === 'low'
                        ? 'bg-rose-100 text-rose-700'
                        : 'bg-slate-200 text-slate-700'
                }`}>
                  {asset.priceConfidence ?? 'unknown'} confidence
                </span>
                {asset.priceSource ? <span className="text-slate-500">{asset.priceSource}</span> : null}
              </div>
              <p className="mt-2 text-sm text-slate-700">
                {formatCurrency(valueXrp, 'XRP')} | {formatCurrency(valueUsd, 'USD')}
              </p>
            </div>
          )
        })}
        {!assets.length ? <p className="text-sm text-slate-500">No assets in this group.</p> : null}
      </div>
    </Card>
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
      <strong className="max-w-[58%] truncate text-right text-slate-900">{value}</strong>
    </div>
  )
}
