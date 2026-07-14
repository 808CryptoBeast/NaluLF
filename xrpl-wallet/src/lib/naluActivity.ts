import { useEffect, useState } from 'react'

/**
 * Mirrors NaluLF/scripts/profile.js's in-app activity log exactly (same
 * localStorage key, same entry shape, same cap) so entries logged by the
 * legacy vanilla-JS page and this React page show up in one shared feed
 * regardless of which one is currently mounted.
 */
const LS_ACTIVITY = 'nalulf_activity_log'
const ACTIVITY_MAX = 60
const ACTIVITY_CHANGED_EVENT = 'nalulf:activity-log-changed'

export interface ActivityLogEntry {
  type: string
  detail: string
  ts: number
}

export const ACTIVITY_ICONS: Record<string, string> = {
  wallet_created: '💎',
  wallet_removed: '🗑',
  social_connected: '🔗',
  social_removed: '✕',
  profile_saved: '✏️',
  trustline_added: '🔗',
  sent: '⬆',
  received: '⬇',
  vault_created: '🔐',
  backup_exported: '📂',
  theme_changed: '🎨',
  wallet_imported: '🔑',
  watch_added: '👁',
}

function readActivityLog(): ActivityLogEntry[] {
  try {
    const raw = localStorage.getItem(LS_ACTIVITY)
    const parsed = raw ? JSON.parse(raw) : []
    return Array.isArray(parsed) ? parsed : []
  } catch {
    return []
  }
}

export function logActivity(type: string, detail: string) {
  const log = readActivityLog()
  log.unshift({ type, detail, ts: Date.now() })
  if (log.length > ACTIVITY_MAX) log.length = ACTIVITY_MAX
  localStorage.setItem(LS_ACTIVITY, JSON.stringify(log))
  window.dispatchEvent(new CustomEvent(ACTIVITY_CHANGED_EVENT))
}

export function relativeTime(ts: number): string {
  const s = (Date.now() - ts) / 1000
  if (s < 60) return 'just now'
  if (s < 3600) return `${Math.floor(s / 60)}m ago`
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`
  return `${Math.floor(s / 86400)}d ago`
}

export function useActivityLog(): ActivityLogEntry[] {
  const [log, setLog] = useState<ActivityLogEntry[]>(() => readActivityLog())

  useEffect(() => {
    const sync = () => setLog(readActivityLog())
    window.addEventListener(ACTIVITY_CHANGED_EVENT, sync)
    window.addEventListener('storage', sync)
    return () => {
      window.removeEventListener(ACTIVITY_CHANGED_EVENT, sync)
      window.removeEventListener('storage', sync)
    }
  }, [])

  return log
}
