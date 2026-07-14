import { useEffect, useState } from 'react'

/**
 * NaluLF's app-wide theme system (NaluLF/scripts/theme.js) toggles a
 * `theme-<id>` class on <body> and writes CSS custom properties
 * (--accent-primary, --bg-primary, etc. — see NaluLF/css/base.css). Since the
 * React root is a normal DOM descendant of <body> (no Shadow DOM), those
 * variables already cascade in for free — this hook just mirrors which theme
 * is active so the Profile tab can show a picker, calling the existing
 * window.setTheme() rather than reimplementing theme switching.
 */
export const APP_THEMES = [
  { id: 'gold', label: 'Gold', swatch: '#d4af37' },
  { id: 'cosmic', label: 'Cosmic', swatch: '#b580ff' },
  { id: 'starry', label: 'Starry', swatch: '#00d4ff' },
  { id: 'hawaiian', label: 'Hawaiian', swatch: '#FF6B35' },
] as const

export type AppThemeId = (typeof APP_THEMES)[number]['id']

declare global {
  interface Window {
    setTheme?: (theme: AppThemeId) => void
  }
}

function readActiveTheme(): AppThemeId {
  const match = APP_THEMES.find((t) => document.body.classList.contains(`theme-${t.id}`))
  return match?.id ?? 'gold'
}

export function useAppTheme() {
  const [theme, setThemeState] = useState<AppThemeId>(() => readActiveTheme())

  useEffect(() => {
    const observer = new MutationObserver(() => setThemeState(readActiveTheme()))
    observer.observe(document.body, { attributes: true, attributeFilter: ['class'] })
    return () => observer.disconnect()
  }, [])

  const setAppTheme = (id: AppThemeId) => {
    window.setTheme?.(id)
    setThemeState(id)
  }

  return { theme, setAppTheme }
}
