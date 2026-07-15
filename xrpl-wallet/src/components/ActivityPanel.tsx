import { ACTIVITY_ICONS, relativeTime, useActivityLog } from '../lib/naluActivity'
import type { UiTransaction } from '../types/wallet'
import { ActivityHeatmap } from './ActivityHeatmap'
import { Button, Card, SectionTitle } from './ui'

interface Props {
  activeWalletLabel?: string
  activeWalletAddress?: string
  transactions: UiTransaction[]
}

/**
 * Mirrors profile.js's renderActivityPanel(): an in-app "movements" feed
 * (wallet lifecycle, sends, trustlines, etc. — sourced from the SAME
 * nalulf_activity_log localStorage key the legacy page writes to), a 26-week
 * on-chain activity heatmap, plus a redirect card into Inspector for full
 * forensic history.
 */
export function ActivityPanel({ activeWalletLabel, activeWalletAddress, transactions }: Props) {
  const log = useActivityLog()

  return (
    <div className="space-y-5">
      {activeWalletAddress ? (
        <Card>
          <SectionTitle title="Activity Heatmap" subtitle="On-chain transactions over the last 26 weeks" />
          <ActivityHeatmap transactions={transactions} />
        </Card>
      ) : null}

      <div className="grid gap-5 lg:grid-cols-2">
        <Card>
          <SectionTitle title="In-App Activity" subtitle="Your recent actions across Nalu LF" />
          {log.length === 0 ? (
            <p className="text-sm text-slate-400">No activity yet.</p>
          ) : (
            <div className="space-y-3">
              {log.slice(0, 20).map((entry, i) => (
                <div key={`${entry.ts}-${i}`} className="flex items-start gap-3">
                  <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-slate-800 text-base">
                    {ACTIVITY_ICONS[entry.type] || '●'}
                  </div>
                  <div className="min-w-0 flex-1">
                    <p className="truncate text-sm text-slate-200">{entry.detail}</p>
                    <p className="text-xs text-slate-500">{relativeTime(entry.ts)}</p>
                  </div>
                </div>
              ))}
            </div>
          )}
        </Card>

        <Card>
          <SectionTitle title="On-Chain Activity" subtitle="Full forensic analysis via Inspector" />
          {activeWalletAddress ? (
            <div className="rounded-xl border border-slate-700 bg-slate-800/60 p-4">
              <p className="text-sm font-semibold text-white">{activeWalletLabel}</p>
              <p className="mt-1 text-sm text-slate-400">
                Transaction history, wash-trading signals, fund-flow tracing, and a full investigation report.
              </p>
              <Button
                className="mt-3"
                onClick={() => window.inspectWalletAddr?.(activeWalletAddress)}
              >
                Open Inspector →
              </Button>
            </div>
          ) : (
            <p className="text-sm text-slate-400">Create a wallet to inspect on-chain activity.</p>
          )}
        </Card>
      </div>
    </div>
  )
}
