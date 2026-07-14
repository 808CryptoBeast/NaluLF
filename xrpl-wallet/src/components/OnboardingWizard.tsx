import { useMemo, useState } from 'react'
import { explainXrplError } from '../lib/errors'
import { useWalletStore } from '../store/walletStore'
import { Button, Card, Input, Label, Notice, SectionTitle } from './ui'

type Mode = 'choose' | 'create-setup' | 'create-backup' | 'import-seed' | 'import-watch'

const WALLET_COLORS = ['#8be9fd', '#50fa7b', '#bd93f9', '#ff79c6', '#f1fa8c', '#ffb86c']
const WALLET_EMOJIS = ['🌊', '🐚', '🌴', '🔥', '⚡', '💎', '🚀', '🦈']

export function OnboardingWizard({ onClose }: { onClose?: () => void }) {
  const createWallet = useWalletStore((s) => s.createWallet)
  const importWalletFromSeed = useWalletStore((s) => s.importWalletFromSeed)
  const importWatchOnlyWallet = useWalletStore((s) => s.importWatchOnlyWallet)
  const canCancel = Boolean(onClose)

  const [mode, setMode] = useState<Mode>('choose')
  const [label, setLabel] = useState('')
  const [algo, setAlgo] = useState<'ed25519' | 'secp256k1'>('ed25519')
  const [emoji, setEmoji] = useState(WALLET_EMOJIS[0])
  const [color, setColor] = useState(WALLET_COLORS[0])
  const [testnet, setTestnet] = useState(true)
  const [passphrase, setPassphrase] = useState('')
  const [passphraseConfirm, setPassphraseConfirm] = useState('')
  const [seedInput, setSeedInput] = useState('')
  const [addressInput, setAddressInput] = useState('')
  const [revealedSeed, setRevealedSeed] = useState('')
  const [checks, setChecks] = useState({
    wroteSeedOffline: false,
    understoodReserve: false,
    understandNoCustody: false,
  })
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  const checklistComplete = useMemo(() => Object.values(checks).every(Boolean), [checks])

  const resetToChoose = () => {
    setMode('choose')
    setLabel('')
    setPassphrase('')
    setPassphraseConfirm('')
    setSeedInput('')
    setAddressInput('')
    setRevealedSeed('')
    setChecks({ wroteSeedOffline: false, understoodReserve: false, understandNoCustody: false })
    setError(null)
  }

  const submitCreate = async () => {
    setError(null)
    if (passphrase.length < 10) return setError('Use a wallet password with at least 10 characters.')
    if (passphrase !== passphraseConfirm) return setError('Wallet password confirmation does not match.')

    try {
      setLoading(true)
      const { seed } = await createWallet({
        label: label.trim() || 'New XRPL Wallet',
        algo,
        emoji,
        color,
        testnet,
        passphrase,
      })
      setRevealedSeed(seed)
      setMode('create-backup')
    } catch (err) {
      setError(explainXrplError(err))
    } finally {
      setLoading(false)
    }
  }

  const submitImportSeed = async () => {
    setError(null)
    if (!seedInput.trim()) return setError('Enter your seed phrase.')
    if (passphrase.length < 10) return setError('Use a wallet password with at least 10 characters.')
    if (passphrase !== passphraseConfirm) return setError('Wallet password confirmation does not match.')

    try {
      setLoading(true)
      await importWalletFromSeed({
        label: label.trim() || 'Imported Wallet',
        seed: seedInput.trim(),
        passphrase,
        testnet,
      })
      resetToChoose()
      onClose?.()
    } catch (err) {
      setError(explainXrplError(err))
    } finally {
      setLoading(false)
    }
  }

  const submitImportWatch = () => {
    setError(null)
    try {
      importWatchOnlyWallet({ label: label.trim() || 'Watch Wallet', address: addressInput.trim() })
      onClose?.()
    } catch (err) {
      setError(explainXrplError(err))
    }
  }

  return (
    <div className="grid gap-6 lg:grid-cols-[1.25fr_1fr]">
      <Card>
        <div className="flex items-start justify-between gap-3">
          <SectionTitle
            title="Add a Wallet to Your Profile"
            subtitle="Optional — track and manage an XRPL wallet from your profile. Create a new one or import an existing account; all key handling happens locally in this browser."
          />
          {canCancel ? (
            <Button variant="secondary" onClick={onClose}>
              Cancel
            </Button>
          ) : null}
        </div>

        {mode === 'choose' ? (
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
            <Button onClick={() => setMode('create-setup')}>Create New Wallet</Button>
            <Button variant="secondary" onClick={() => setMode('import-seed')}>
              Import From Seed
            </Button>
            <Button variant="secondary" onClick={() => setMode('import-watch')}>
              Watch an Address
            </Button>
          </div>
        ) : null}

        {mode === 'create-setup' ? (
          <div className="space-y-4">
            <div>
              <Label>Wallet Name</Label>
              <Input value={label} onChange={(e) => setLabel(e.target.value)} placeholder="My XRPL Wallet" />
            </div>

            <div>
              <Label>Key Type</Label>
              <div className="flex gap-2">
                {(['ed25519', 'secp256k1'] as const).map((value) => (
                  <Button
                    key={value}
                    type="button"
                    variant={algo === value ? 'primary' : 'secondary'}
                    onClick={() => setAlgo(value)}
                  >
                    {value}
                  </Button>
                ))}
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <Label>Emoji</Label>
                <div className="flex flex-wrap gap-2">
                  {WALLET_EMOJIS.map((e) => (
                    <button
                      key={e}
                      type="button"
                      onClick={() => setEmoji(e)}
                      className={`h-9 w-9 rounded-lg border text-lg ${emoji === e ? 'border-teal-600 bg-teal-950' : 'border-slate-700 bg-slate-800'}`}
                    >
                      {e}
                    </button>
                  ))}
                </div>
              </div>
              <div>
                <Label>Color</Label>
                <div className="flex flex-wrap gap-2">
                  {WALLET_COLORS.map((c) => (
                    <button
                      key={c}
                      type="button"
                      onClick={() => setColor(c)}
                      style={{ background: c }}
                      className={`h-9 w-9 rounded-lg border-2 ${color === c ? 'border-white' : 'border-transparent'}`}
                    />
                  ))}
                </div>
              </div>
            </div>

            <label className="flex items-center gap-2 text-sm text-slate-300">
              <input type="checkbox" checked={testnet} onChange={(e) => setTestnet(e.target.checked)} />
              This is a testnet wallet
            </label>

            <Notice tone="info">
              Choose a wallet password now. It encrypts your seed on this device (PBKDF2 + AES-256-GCM) —
              you'll need it any time you sign a transaction. It is never sent anywhere or stored in plaintext.
            </Notice>

            <div className="grid gap-3 sm:grid-cols-2">
              <div>
                <Label>Wallet Password</Label>
                <Input type="password" value={passphrase} onChange={(e) => setPassphrase(e.target.value)} />
              </div>
              <div>
                <Label>Confirm Password</Label>
                <Input
                  type="password"
                  value={passphraseConfirm}
                  onChange={(e) => setPassphraseConfirm(e.target.value)}
                />
              </div>
            </div>

            <div className="flex gap-3">
              <Button onClick={submitCreate} disabled={loading}>
                Generate Wallet
              </Button>
              <Button variant="secondary" onClick={resetToChoose}>
                Back
              </Button>
            </div>
          </div>
        ) : null}

        {mode === 'create-backup' ? (
          <div className="space-y-4">
            <Notice tone="warning">
              This seed unlocks your funds. Write it down and store it offline — it will not be shown again.
              Anyone with this seed controls this wallet.
            </Notice>

            <div className="rounded-xl border border-slate-700 bg-slate-800 p-3">
              <Label>Seed Phrase</Label>
              <code className="break-all text-sm text-white">{revealedSeed}</code>
            </div>

            <div className="grid gap-2">
              <label className="flex items-start gap-2 text-sm text-slate-300">
                <input
                  type="checkbox"
                  checked={checks.wroteSeedOffline}
                  onChange={(e) => setChecks((prev) => ({ ...prev, wroteSeedOffline: e.target.checked }))}
                />
                I wrote my seed down in secure offline storage.
              </label>
              <label className="flex items-start gap-2 text-sm text-slate-300">
                <input
                  type="checkbox"
                  checked={checks.understoodReserve}
                  onChange={(e) => setChecks((prev) => ({ ...prev, understoodReserve: e.target.checked }))}
                />
                I understand XRPL reserve: base 10 XRP plus ~2 XRP per owned object.
              </label>
              <label className="flex items-start gap-2 text-sm text-slate-300">
                <input
                  type="checkbox"
                  checked={checks.understandNoCustody}
                  onChange={(e) => setChecks((prev) => ({ ...prev, understandNoCustody: e.target.checked }))}
                />
                I understand this wallet is non-custodial and recovery is only possible with my seed backup.
              </label>
            </div>

            <Button
              disabled={!checklistComplete}
              onClick={() => {
                resetToChoose()
                onClose?.()
              }}
            >
              Done — Go to Dashboard
            </Button>
          </div>
        ) : null}

        {mode === 'import-seed' ? (
          <div className="space-y-4">
            <div>
              <Label>Wallet Name</Label>
              <Input value={label} onChange={(e) => setLabel(e.target.value)} placeholder="Imported Wallet" />
            </div>
            <div>
              <Label>Seed</Label>
              <Input value={seedInput} onChange={(e) => setSeedInput(e.target.value)} placeholder="sEd... / sn..." />
            </div>
            <div className="grid gap-3 sm:grid-cols-2">
              <div>
                <Label>Wallet Password</Label>
                <Input type="password" value={passphrase} onChange={(e) => setPassphrase(e.target.value)} />
              </div>
              <div>
                <Label>Confirm Password</Label>
                <Input
                  type="password"
                  value={passphraseConfirm}
                  onChange={(e) => setPassphraseConfirm(e.target.value)}
                />
              </div>
            </div>
            <label className="flex items-center gap-2 text-sm text-slate-300">
              <input type="checkbox" checked={testnet} onChange={(e) => setTestnet(e.target.checked)} />
              This is a testnet wallet
            </label>
            <div className="flex gap-3">
              <Button onClick={submitImportSeed} disabled={loading}>
                Import Wallet
              </Button>
              <Button variant="secondary" onClick={resetToChoose}>
                Back
              </Button>
            </div>
          </div>
        ) : null}

        {mode === 'import-watch' ? (
          <div className="space-y-4">
            <Notice tone="info">
              Watch-only wallets can view balances and activity but cannot sign or send transactions.
            </Notice>
            <div>
              <Label>Label</Label>
              <Input value={label} onChange={(e) => setLabel(e.target.value)} placeholder="Watch Wallet" />
            </div>
            <div>
              <Label>XRPL Address</Label>
              <Input value={addressInput} onChange={(e) => setAddressInput(e.target.value)} placeholder="r..." />
            </div>
            <div className="flex gap-3">
              <Button onClick={submitImportWatch}>Add Watch-Only Wallet</Button>
              <Button variant="secondary" onClick={resetToChoose}>
                Back
              </Button>
            </div>
          </div>
        ) : null}

        {error ? <p className="mt-4 text-sm font-medium text-rose-400">{error}</p> : null}
      </Card>

      <Card className="h-fit">
        <SectionTitle title="Why This Is Secure" />
        <ul className="space-y-3 text-sm text-slate-300">
          <li>All transaction signing happens locally in your browser using xrpl.js wallet signing.</li>
          <li>Seeds are never sent to a server — only encrypted at rest with your wallet password.</li>
          <li>Wallets created here are visible from the rest of Nalu LF (Inspector, legacy Profile) and vice versa.</li>
          <li>You can add multiple wallets and switch between them at any time.</li>
        </ul>
      </Card>
    </div>
  )
}
