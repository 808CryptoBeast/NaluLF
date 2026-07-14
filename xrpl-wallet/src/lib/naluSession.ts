import { useEffect, useState } from 'react'

/**
 * NaluLF's own sign-in system (NaluLF/scripts/auth.js's CryptoVault) is a
 * vanilla-JS, email+password, client-side-encrypted identity layer that
 * already gates/personalizes the rest of the app — it is NOT being rebuilt
 * here. main.js exposes it read-only via `window.NaluLF = { state }`
 * (state.session is `{ name, email, domain } | null`) and fires
 * `naluxrp:vault-ready` / `naluxrp:vault-locked` on sign-in/lock. This hook
 * just mirrors that into React so the Profile page can show who's signed in
 * instead of looking like a bare wallet creator.
 */
export interface NaluSession {
  name: string
  email: string
  domain?: string
}

declare global {
  interface Window {
    NaluLF?: { state?: { session?: NaluSession | null } }
    openAuth?: (mode?: 'login' | 'signup' | 'forgot' | 'welcome') => void
    inspectWalletAddr?: (address: string) => void
  }
}

function readSession(): NaluSession | null {
  return window.NaluLF?.state?.session ?? null
}

export function useNaluSession(): NaluSession | null {
  const [session, setSession] = useState<NaluSession | null>(() => readSession())

  useEffect(() => {
    const sync = () => setSession(readSession())
    window.addEventListener('naluxrp:vault-ready', sync)
    window.addEventListener('naluxrp:vault-locked', sync)
    // The bridge can populate slightly after this component mounts on first
    // load (main.js runs restoreSession() during boot) — a couple of cheap
    // re-checks covers that without needing a polling loop.
    const t1 = setTimeout(sync, 300)
    const t2 = setTimeout(sync, 1200)
    return () => {
      window.removeEventListener('naluxrp:vault-ready', sync)
      window.removeEventListener('naluxrp:vault-locked', sync)
      clearTimeout(t1)
      clearTimeout(t2)
    }
  }, [])

  return session
}
