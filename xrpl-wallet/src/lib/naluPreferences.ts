import { useEffect, useState } from 'react'

/**
 * Same preference keys NaluLF/scripts/profile.js's Settings tab reads/writes
 * (nalulf_pref_currency / nalulf_pref_network / nalulf_pref_autolock) — kept
 * separate from the app-wide theme (naluTheme.ts) since those already have
 * their own dedicated system via window.setTheme.
 */
const LS_CURRENCY = 'nalulf_pref_currency'
const LS_NETWORK = 'nalulf_pref_network'
const LS_AUTOLOCK = 'nalulf_pref_autolock'
const PREFS_CHANGED_EVENT = 'nalulf:preferences-changed'

export type DisplayCurrency = 'XRP' | 'USD'
export type DefaultNetwork = 'mainnet' | 'testnet'
export type AutoLockMinutes = '15' | '30' | '60'

export function readDisplayCurrency(): DisplayCurrency {
  return localStorage.getItem(LS_CURRENCY) === 'USD' ? 'USD' : 'XRP'
}

export function readDefaultNetwork(): DefaultNetwork {
  return localStorage.getItem(LS_NETWORK) === 'testnet' ? 'testnet' : 'mainnet'
}

export function readAutoLockMinutes(): AutoLockMinutes {
  const v = localStorage.getItem(LS_AUTOLOCK)
  return v === '15' || v === '60' ? v : '30'
}

export function setDisplayCurrency(value: DisplayCurrency) {
  localStorage.setItem(LS_CURRENCY, value)
  window.dispatchEvent(new CustomEvent(PREFS_CHANGED_EVENT))
}

export function setDefaultNetwork(value: DefaultNetwork) {
  localStorage.setItem(LS_NETWORK, value)
  window.dispatchEvent(new CustomEvent(PREFS_CHANGED_EVENT))
}

export function setAutoLockMinutes(value: AutoLockMinutes) {
  localStorage.setItem(LS_AUTOLOCK, value)
  window.dispatchEvent(new CustomEvent(PREFS_CHANGED_EVENT))
}

export function usePreferences() {
  const [currency, setCurrencyState] = useState<DisplayCurrency>(() => readDisplayCurrency())
  const [network, setNetworkState] = useState<DefaultNetwork>(() => readDefaultNetwork())
  const [autoLock, setAutoLockState] = useState<AutoLockMinutes>(() => readAutoLockMinutes())

  useEffect(() => {
    const sync = () => {
      setCurrencyState(readDisplayCurrency())
      setNetworkState(readDefaultNetwork())
      setAutoLockState(readAutoLockMinutes())
    }
    window.addEventListener(PREFS_CHANGED_EVENT, sync)
    window.addEventListener('storage', sync)
    return () => {
      window.removeEventListener(PREFS_CHANGED_EVENT, sync)
      window.removeEventListener('storage', sync)
    }
  }, [])

  return { currency, network, autoLock }
}
