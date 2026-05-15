import { useMemo, useState } from 'react'
import { Wallet } from 'xrpl'
import { explainXrplError } from '../lib/errors'
import { Button, Card, Input, Label, Notice, SectionTitle } from './ui'
import {
  generateWalletEd25519,
  importWalletFromSecretNumbers,
  importWalletFromSeed,
} from '../services/xrplService'

type ImportMethod = 'seed' | 'secretNumbers' | 'keystore'

interface Props {
  onAuthenticated: (wallet: Wallet) => Promise<void> | void
  onImportKeystore: (keystoreText: string, passphrase: string) => Promise<void>
}

export function OnboardingWizard({ onAuthenticated, onImportKeystore }: Props) {
  const [step, setStep] = useState(1)
  const [wallet, setWallet] = useState<Wallet | null>(null)
  const [seedInput, setSeedInput] = useState('')
  const [secretNumbersInput, setSecretNumbersInput] = useState('')
  const [keystoreInput, setKeystoreInput] = useState('')
  const [keystorePass, setKeystorePass] = useState('')
  const [importMethod, setImportMethod] = useState<ImportMethod>('seed')
  const [checks, setChecks] = useState({
    wroteSeedOffline: false,
    understoodReserve: false,
    understandNoCustody: false,
  })
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  const checklistComplete = useMemo(
    () => Object.values(checks).every(Boolean),
    [checks],
  )

  const buildNewWallet = () => {
    try {
      const generated = generateWalletEd25519()
      setWallet(generated)
      setStep(2)
      setError(null)
    } catch (err) {
      setError(explainXrplError(err))
    }
  }

  const submitImport = async () => {
    try {
      setLoading(true)
      setError(null)

      if (importMethod === 'seed') {
        const imported = importWalletFromSeed(seedInput.trim())
        await onAuthenticated(imported)
        return
      }

      if (importMethod === 'secretNumbers') {
        const imported = importWalletFromSecretNumbers(secretNumbersInput.trim())
        await onAuthenticated(imported)
        return
      }

      await onImportKeystore(keystoreInput, keystorePass)
    } catch (err) {
      setError(explainXrplError(err))
    } finally {
      setLoading(false)
    }
  }

  const finishCreateFlow = async () => {
    if (!wallet) {
      return
    }

    try {
      setLoading(true)
      setError(null)
      await onAuthenticated(wallet)
    } catch (err) {
      setError(explainXrplError(err))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="grid gap-6 lg:grid-cols-[1.25fr_1fr]">
      <Card>
        <SectionTitle
          title="Secure XRPL Wallet Setup"
          subtitle="Create an Ed25519 wallet or import an existing account with local key handling only."
        />

        <div className="mb-4 grid grid-cols-2 gap-3">
          <Button variant={step < 3 ? 'primary' : 'secondary'} onClick={buildNewWallet}>
            Create New Wallet
          </Button>
          <Button variant={step === 3 ? 'primary' : 'secondary'} onClick={() => setStep(3)}>
            Import Existing Wallet
          </Button>
        </div>

        {step === 2 && wallet ? (
          <div className="space-y-4">
            <Notice tone="warning">
              This seed unlocks your funds. Store it offline and never share it. Anyone with this seed controls your XRP and assets.
            </Notice>

            <div className="rounded-xl border border-slate-200 bg-slate-50 p-3">
              <Label>Seed Phrase</Label>
              <code className="break-all text-sm text-slate-800">{wallet.seed}</code>
            </div>

            <div className="grid gap-2">
              <label className="flex items-start gap-2 text-sm text-slate-700">
                <input
                  type="checkbox"
                  checked={checks.wroteSeedOffline}
                  onChange={(e) =>
                    setChecks((prev) => ({ ...prev, wroteSeedOffline: e.target.checked }))
                  }
                />
                I wrote my seed down in secure offline storage.
              </label>
              <label className="flex items-start gap-2 text-sm text-slate-700">
                <input
                  type="checkbox"
                  checked={checks.understoodReserve}
                  onChange={(e) =>
                    setChecks((prev) => ({ ...prev, understoodReserve: e.target.checked }))
                  }
                />
                I understand XRPL reserve: base 10 XRP plus ~2 XRP per owned object (trustline, NFT offer, etc.).
              </label>
              <label className="flex items-start gap-2 text-sm text-slate-700">
                <input
                  type="checkbox"
                  checked={checks.understandNoCustody}
                  onChange={(e) =>
                    setChecks((prev) => ({ ...prev, understandNoCustody: e.target.checked }))
                  }
                />
                I understand this wallet is non-custodial and recovery is only possible with my seed backup.
              </label>
            </div>

            <div className="flex gap-3">
              <Button onClick={finishCreateFlow} disabled={!checklistComplete || loading}>
                Continue to Dashboard
              </Button>
              <Button variant="secondary" onClick={() => setStep(1)}>
                Start Over
              </Button>
            </div>
          </div>
        ) : null}

        {step === 3 ? (
          <div className="space-y-4">
            <div className="flex flex-wrap gap-2">
              <Button
                variant={importMethod === 'seed' ? 'primary' : 'secondary'}
                onClick={() => setImportMethod('seed')}
              >
                Seed
              </Button>
              <Button
                variant={importMethod === 'secretNumbers' ? 'primary' : 'secondary'}
                onClick={() => setImportMethod('secretNumbers')}
              >
                Secret Numbers
              </Button>
              <Button
                variant={importMethod === 'keystore' ? 'primary' : 'secondary'}
                onClick={() => setImportMethod('keystore')}
              >
                Keystore JSON
              </Button>
            </div>

            {importMethod === 'seed' ? (
              <div>
                <Label>Seed</Label>
                <Input
                  value={seedInput}
                  onChange={(e) => setSeedInput(e.target.value)}
                  placeholder="sEd..."
                />
              </div>
            ) : null}

            {importMethod === 'secretNumbers' ? (
              <div>
                <Label>Secret Numbers</Label>
                <Input
                  value={secretNumbersInput}
                  onChange={(e) => setSecretNumbersInput(e.target.value)}
                  placeholder="Comma-separated secret numbers"
                />
              </div>
            ) : null}

            {importMethod === 'keystore' ? (
              <>
                <div>
                  <Label>Keystore JSON</Label>
                  <textarea
                    className="h-40 w-full rounded-xl border border-slate-300 bg-white px-3 py-2 text-sm text-slate-900 outline-none ring-teal-500/30 transition focus:border-teal-600 focus:ring-4"
                    value={keystoreInput}
                    onChange={(e) => setKeystoreInput(e.target.value)}
                    placeholder="Paste your encrypted keystore JSON"
                  />
                </div>
                <div>
                  <Label>Keystore Passphrase</Label>
                  <Input
                    type="password"
                    value={keystorePass}
                    onChange={(e) => setKeystorePass(e.target.value)}
                    placeholder="Enter passphrase"
                  />
                </div>
              </>
            ) : null}

            <Button onClick={submitImport} disabled={loading}>
              Unlock Wallet
            </Button>
          </div>
        ) : null}

        {error ? <p className="mt-4 text-sm font-medium text-rose-700">{error}</p> : null}
      </Card>

      <Card className="h-fit">
        <SectionTitle title="Why This Is Secure" />
        <ul className="space-y-3 text-sm text-slate-700">
          <li>All transaction signing happens locally in your browser using xrpl.js wallet signing.</li>
          <li>Seeds are never sent to a server. RPC calls only include public account and signed blobs.</li>
          <li>You can export an encrypted keystore and wipe browser storage at any time.</li>
          <li>Before reserve-changing actions, the UI shows plain-English XRP reserve impact warnings.</li>
        </ul>
      </Card>
    </div>
  )
}
