import { useState, type FormEvent } from 'react'
import { useWalletStore } from '../store/walletStore'
import { Button, Input, Label } from './ui'

/**
 * Mirrors profile.js's _resolveSeedForSigning(): the wallet's seed is only
 * ever decrypted in-memory, on demand, right before a signature — never
 * persisted. Rendered once at the app root; walletStore.getUnlockedWallet()
 * opens a request here and awaits the result.
 */
export function PassphraseModal() {
  const request = useWalletStore((s) => s.pendingPassphraseRequest)
  const resolvePassphrase = useWalletStore((s) => s.resolvePassphrase)
  const cancelPassphrase = useWalletStore((s) => s.cancelPassphrase)
  const [passphrase, setPassphrase] = useState('')

  if (!request) return null

  const submit = (e: FormEvent) => {
    e.preventDefault()
    const value = passphrase
    setPassphrase('')
    resolvePassphrase(value)
  }

  const cancel = () => {
    setPassphrase('')
    cancelPassphrase()
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <form
        onSubmit={submit}
        className="w-full max-w-sm rounded-2xl border border-slate-700 bg-slate-900 p-5 shadow-xl"
      >
        <h2 className="text-lg font-semibold text-white">Unlock Wallet</h2>
        <p className="mt-1 text-sm text-slate-400">
          Enter the password for <span className="font-medium text-slate-200">{request.walletLabel}</span> to
          decrypt its seed and sign this transaction. It stays in this browser tab only.
        </p>
        <div className="mt-4">
          <Label>Wallet Password</Label>
          <Input
            type="password"
            autoFocus
            value={passphrase}
            onChange={(e) => setPassphrase(e.target.value)}
          />
        </div>
        <div className="mt-4 flex gap-3">
          <Button type="submit" disabled={!passphrase}>
            Unlock
          </Button>
          <Button type="button" variant="secondary" onClick={cancel}>
            Cancel
          </Button>
        </div>
      </form>
    </div>
  )
}
