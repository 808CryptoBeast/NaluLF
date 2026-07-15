import { useMemo } from 'react'
import type { UiTransaction } from '../types/wallet'

interface Props {
  transactions: UiTransaction[]
}

const WEEKS = 26
const CELL = 12
const GAP = 2

function heatColor(fraction: number): string {
  if (fraction === 0) return 'rgba(255,255,255,.07)'
  return `rgb(0,${Math.round(85 + fraction * 170)},${Math.round(119 + fraction * 121)})`
}

/** Same 26-week grid NaluLF/scripts/profile.js's _buildHeatmap() renders,
 *  just driven by UiTransaction[] (already ISO date strings) instead of
 *  raw ripple-epoch tx rows. */
export function ActivityHeatmap({ transactions }: Props) {
  const { days, cells, maxCount, monthLabels } = useMemo(() => {
    const cellCounts = new Map<string, number>()
    transactions.forEach((tx) => {
      if (!tx.date) return
      const key = tx.date.slice(0, 10)
      cellCounts.set(key, (cellCounts.get(key) || 0) + 1)
    })

    const now = new Date()
    const allDays = Array.from({ length: WEEKS * 7 }, (_, i) => {
      const d = new Date(now)
      d.setDate(d.getDate() - (WEEKS * 7 - 1 - i))
      return d
    })
    const byWeek = Array.from({ length: WEEKS }, (_, w) => allDays.slice(w * 7, w * 7 + 7))
    const max = Math.max(1, ...cellCounts.values())

    const labels: { weekIndex: number; label: string }[] = []
    let lastMonth = -1
    byWeek.forEach((week, weekIndex) => {
      const month = week[0]?.getMonth()
      if (month !== lastMonth) {
        lastMonth = month
        labels.push({ weekIndex, label: week[0].toLocaleDateString('en-US', { month: 'short' }) })
      }
    })

    return { days: byWeek, cells: cellCounts, maxCount: max, monthLabels: labels }
  }, [transactions])

  const width = WEEKS * (CELL + GAP) + 30
  const height = 7 * (CELL + GAP) + 28
  const activeDays = cells.size
  const dayLabels = ['', 'Mon', '', 'Wed', '', 'Fri', '']

  return (
    <div>
      <div className="mb-2 flex flex-wrap items-center justify-between gap-2 text-xs text-slate-400">
        <span>
          {transactions.length} tx · {activeDays} active days
        </span>
        <div className="flex items-center gap-1.5">
          <span>Less</span>
          {[0, 0.25, 0.5, 0.75, 1].map((f) => (
            <div key={f} className="h-2.5 w-2.5 rounded-sm" style={{ background: heatColor(f) }} />
          ))}
          <span>More</span>
        </div>
      </div>
      <div className="overflow-x-auto">
        <svg viewBox={`0 0 ${width} ${height}`} width={width} height={height}>
          {monthLabels.map(({ weekIndex, label }) => (
            <text
              key={weekIndex}
              x={26 + weekIndex * (CELL + GAP)}
              y={10}
              fontSize={9}
              fill="rgba(255,255,255,.38)"
            >
              {label}
            </text>
          ))}
          {dayLabels.map((label, dayIndex) =>
            label ? (
              <text
                key={dayIndex}
                x={0}
                y={16 + dayIndex * (CELL + GAP) + CELL / 2 + 3}
                fontSize={9}
                fill="rgba(255,255,255,.3)"
              >
                {label}
              </text>
            ) : null,
          )}
          {days.map((week, weekIndex) =>
            week.map((day, dayIndex) => {
              const key = day.toISOString().slice(0, 10)
              const count = cells.get(key) || 0
              return (
                <rect
                  key={`${weekIndex}-${dayIndex}`}
                  x={26 + weekIndex * (CELL + GAP)}
                  y={16 + dayIndex * (CELL + GAP)}
                  width={CELL}
                  height={CELL}
                  rx={2}
                  fill={heatColor(count / maxCount)}
                  opacity={count > 0 ? 0.9 : 0.25}
                >
                  <title>
                    {key}: {count} tx
                  </title>
                </rect>
              )
            }),
          )}
        </svg>
      </div>
    </div>
  )
}
