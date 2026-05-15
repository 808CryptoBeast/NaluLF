import { useEffect, useMemo, useState, type ReactNode } from 'react'
import { Download, Lock, LogOut, ShieldCheck, Trash2, Wallet2 } from 'lucide-react'
import type { Wallet } from 'xrpl'
import { Dashboard } from './components/Dashboard'
import { OnboardingWizard } from './components/OnboardingWizard'
import { AssetManager } from './components/AssetManager'
import { SendPanel } from './components/SendPanel'
import { DefiPanel } from './components/DefiPanel'
import { AdvancedPanel } from './components/AdvancedPanel'
import { Button, Card, Input, Notice } from './components/ui'
import { explainXrplError } from './lib/errors'
import { formatCurrency } from './lib/format'
import { fetchXrpUsdPrice } from './services/priceService'
import {
  bidAmmAuction,
  claimPaymentChannel,
  createAmm,
  createEscrow,
  createPaymentChannel,
  createTrustline,
  depositAmm,
  disconnectAllClients,
  estimateFee,
  fetchAccountState,
  finishEscrow,
  getExplorerUrl,
  sendIssuedToken,
  sendNft,
  sendXrp,
  subscribeAccount,
  voteAmmFee,
  withdrawAmm,
  NETWORKS,
} from './services/xrplService'
import { useWalletStore } from './store/walletStore'

type Tab = 'dashboard' | 'assets' | 'send' | 'defi' | 'advanced'

function App() {
  const [tab, setTab] = useState<Tab>('dashboard')
  const [statusMessage, setStatusMessage] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [feeXrp, setFeeXrp] = useState('0.000012')
  const [keystorePassphrase, setKeystorePassphrase] = useState('')
  const [keystorePreview, setKeystorePreview] = useState('')

  const {
    network,
    setNetwork,
    storedWallet,
    sessionWallet,
    loginWithWallet,
    lockWallet,
    wipeWallet,
    setAccountData,
    trustlines,
    nfts,
    transactions,
    balanceXrp,
    reserveXrp,
    xrpUsdPrice,
    metrics,
    setXrpUsdPrice,
    exportEncryptedKeystore,
    importEncryptedKeystore,
  } = useWalletStore()

  const currentWallet = sessionWallet
  const connectedAddress = storedWallet?.address

  const totalUsd = useMemo(() => balanceXrp * xrpUsdPrice, [balanceXrp, xrpUsdPrice])

  const refreshAccount = async () => {
    if (!connectedAddress) {
      return
    }

    try {
      const [state, price, fee] = await Promise.all([
        fetchAccountState(connectedAddress, network),
        fetchXrpUsdPrice(),
        estimateFee(network),
      ])
      setAccountData(state)
      setXrpUsdPrice(price)
      setFeeXrp(fee)
      setError(null)
    } catch (err) {
      setError(explainXrplError(err))
    }
  }

  useEffect(() => {
    void refreshAccount()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [connectedAddress, network])

  useEffect(() => {
    let unsubscribe: (() => Promise<void>) | null = null

    async function run() {
      if (!connectedAddress) {
        return
      }
      unsubscribe = await subscribeAccount(network, connectedAddress, async () => {
        await refreshAccount()
        setStatusMessage('Live update received from XRPL.')
      })
    }

    void run()

    return () => {
      if (unsubscribe) {
        void unsubscribe()
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [connectedAddress, network])

  useEffect(() => {
    return () => {
      void disconnectAllClients()
    }
  }, [])

  const submitAction = async (fn: () => Promise<void>) => {
    try {
      setError(null)
      setStatusMessage(null)
      await fn()
      await refreshAccount()
    } catch (err) {
      setError(explainXrplError(err))
    }
  }

  const toAmmAmount = (asset: {
    kind: 'xrp' | 'token'
    amount: string
    currency?: string
    issuer?: string
  }) => {
    if (asset.kind === 'xrp') {
      return String(Math.trunc(Number(asset.amount) * 1_000_000))
    }

    return {
      currency: asset.currency ?? '',
      issuer: asset.issuer ?? '',
      value: asset.amount,
    }
  }

  const toAmmAsset = (currency: string, issuer: string) => ({ currency, issuer })

  const onAuthenticated = async (wallet: Wallet) => {
    loginWithWallet(wallet)
    setStatusMessage('Wallet unlocked locally. No private keys were sent anywhere.')
  }

  const onImportKeystore = async (keystoreText: string, passphrase: string) => {
    await importEncryptedKeystore(keystoreText, passphrase)
    setStatusMessage('Encrypted keystore imported and unlocked locally.')
  }

  if (!currentWallet && !storedWallet) {
    return (
      <AppShell network={network} setNetwork={setNetwork}>
        <OnboardingWizard
          onAuthenticated={onAuthenticated}
          onImportKeystore={onImportKeystore}
        />
      </AppShell>
    )
  }

  if (!currentWallet && storedWallet) {
    return (
      <AppShell network={network} setNetwork={setNetwork}>
        <Card className="mx-auto max-w-xl">
          <h2 className="text-xl font-semibold text-slate-900">Wallet Locked</h2>
          <p className="mt-2 text-sm text-slate-600">
            For security, your session key was cleared. Re-import from seed, secret numbers, or encrypted keystore.
          </p>
          <div className="mt-4">
            <OnboardingWizard
              onAuthenticated={onAuthenticated}
              onImportKeystore={onImportKeystore}
            />
          </div>
        </Card>
      </AppShell>
    )
  }

  const activeWallet = currentWallet!

  return (
    <AppShell network={network} setNetwork={setNetwork}>
      <div className="grid gap-5 xl:grid-cols-[220px_1fr]">
        <aside className="space-y-4">
          <Card>
            <div className="mb-4 flex items-center gap-2 text-slate-900">
              <Wallet2 className="h-5 w-5 text-teal-700" />
              <h1 className="text-lg font-semibold">Nalu XRPL Wallet</h1>
            </div>

            <nav className="space-y-2">
              {([
                ['dashboard', 'Dashboard'],
                ['assets', 'Assets'],
                ['send', 'Send'],
                ['defi', 'DeFi / AMM'],
                ['advanced', 'Advanced'],
              ] as const).map(([value, label]) => (
                <button
                  type="button"
                  key={value}
                  onClick={() => setTab(value)}
                  className={`w-full rounded-xl px-3 py-2 text-left text-sm font-medium transition ${
                    tab === value
                      ? 'bg-teal-700 text-white'
                      : 'bg-slate-100 text-slate-700 hover:bg-slate-200'
                  }`}
                >
                  {label}
                </button>
              ))}
            </nav>

            <div className="mt-4 space-y-2 border-t border-slate-200 pt-4">
              <Button variant="secondary" className="w-full" onClick={lockWallet}>
                <Lock className="mr-2 h-4 w-4" /> Lock Session
              </Button>
              <Button
                variant="danger"
                className="w-full"
                onClick={() => {
                  wipeWallet()
                  setStatusMessage('Wallet wiped from browser storage.')
                }}
              >
                <Trash2 className="mr-2 h-4 w-4" /> Wipe Wallet
              </Button>
            </div>
          </Card>

          <Card>
            <h3 className="text-sm font-semibold text-slate-900">Metrics Snapshot</h3>
            <div className="mt-3 space-y-2 text-sm text-slate-700">
              <MetricRow label="Trustlines" value={String(metrics.trustlineCount)} />
              <MetricRow label="NFTs" value={String(metrics.nftCount)} />
              <MetricRow label="Reserve" value={formatCurrency(metrics.xrpReserve, 'XRP')} />
              <MetricRow label="Recent TX" value={String(metrics.recentTxCount)} />
            </div>
          </Card>
        </aside>

        <main className="space-y-5">
          <Card>
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <p className="text-xs uppercase tracking-wide text-slate-500">Active Account</p>
                <p className="text-sm font-semibold text-slate-900">{activeWallet.classicAddress}</p>
                <p className="text-xs text-slate-500">
                  Total Value: {formatCurrency(totalUsd, 'USD')} ({formatCurrency(balanceXrp, 'XRP')})
                </p>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <Button
                  variant="secondary"
                  onClick={async () => {
                    try {
                      const fee = await estimateFee(network)
                      setFeeXrp(fee)
                    } catch (err) {
                      setError(explainXrplError(err))
                    }
                  }}
                >
                  Network Fee: {feeXrp} XRP
                </Button>
                <Button
                  variant="secondary"
                  onClick={async () => {
                    if (!keystorePassphrase) {
                      setError('Enter a passphrase first to export encrypted keystore.')
                      return
                    }
                    const json = await exportEncryptedKeystore(keystorePassphrase)
                    setKeystorePreview(json)
                    setStatusMessage('Encrypted keystore generated locally.')
                  }}
                >
                  <Download className="mr-2 h-4 w-4" /> Export Keystore
                </Button>
                <Button variant="secondary" onClick={() => void refreshAccount()}>
                  <ShieldCheck className="mr-2 h-4 w-4" /> Refresh Account
                </Button>
                {transactions[0]?.hash ? (
                  <a
                    href={getExplorerUrl(network, transactions[0].hash)}
                    target="_blank"
                    rel="noreferrer"
                    className="inline-flex items-center rounded-xl border border-slate-300 bg-white px-4 py-2 text-sm font-semibold text-slate-700 hover:bg-slate-100"
                  >
                    <LogOut className="mr-2 h-4 w-4" /> Latest TX
                  </a>
                ) : null}
              </div>
            </div>

            <div className="mt-4 grid gap-3 md:grid-cols-[1fr_2fr]">
              <div>
                <label className="mb-1 block text-xs font-semibold uppercase tracking-wide text-slate-500">
                  Keystore Export Passphrase
                </label>
                <Input
                  type="password"
                  value={keystorePassphrase}
                  onChange={(e) => setKeystorePassphrase(e.target.value)}
                  placeholder="Use a long unique passphrase"
                />
              </div>
              <div>
                <label className="mb-1 block text-xs font-semibold uppercase tracking-wide text-slate-500">
                  Keystore Preview
                </label>
                <textarea
                  className="h-24 w-full rounded-xl border border-slate-300 bg-white px-3 py-2 text-xs text-slate-800"
                  value={keystorePreview}
                  readOnly
                  placeholder="Encrypted keystore JSON appears here after export"
                />
              </div>
            </div>
          </Card>

          {tab === 'dashboard' ? (
            <Dashboard
              address={activeWallet.classicAddress}
              balanceXrp={balanceXrp}
              reserveXrp={reserveXrp}
              xrpUsdPrice={xrpUsdPrice}
              transactions={transactions}
              onRefresh={refreshAccount}
            />
          ) : null}

          {tab === 'assets' ? (
            <AssetManager
              trustlines={trustlines}
              nfts={nfts}
              onCreateTrustline={async (currency, issuer, limit) => {
                await submitAction(async () => {
                  await createTrustline(activeWallet, network, currency, issuer, limit)
                  setStatusMessage(
                    'Trustline submitted. This may consume ~2 XRP reserve while active.',
                  )
                })
              }}
              onSendToken={async ({ destination, amount, currency, issuer, destinationTag }) => {
                await submitAction(async () => {
                  await sendIssuedToken(
                    activeWallet,
                    network,
                    destination,
                    currency,
                    issuer,
                    amount,
                    destinationTag,
                  )
                  setStatusMessage('Issued token payment submitted and awaiting validation.')
                })
              }}
              onSendNft={async (nftId, destination) => {
                await submitAction(async () => {
                  await sendNft(activeWallet, network, nftId, destination)
                  setStatusMessage('NFT transfer offer submitted.')
                })
              }}
            />
          ) : null}

          {tab === 'send' ? (
            <SendPanel
              feeXrp={feeXrp}
              trustlines={trustlines}
              nfts={nfts}
              onSendXrp={async ({ destination, amount, destinationTag }) => {
                await submitAction(async () => {
                  await sendXrp(activeWallet, network, destination, amount, destinationTag)
                  setStatusMessage('XRP payment submitted.')
                })
              }}
              onSendToken={async ({ destination, amount, currency, issuer, destinationTag }) => {
                await submitAction(async () => {
                  await sendIssuedToken(
                    activeWallet,
                    network,
                    destination,
                    currency,
                    issuer,
                    amount,
                    destinationTag,
                  )
                  setStatusMessage('Token payment submitted.')
                })
              }}
              onSendNft={async (nftId, destination) => {
                await submitAction(async () => {
                  await sendNft(activeWallet, network, nftId, destination)
                  setStatusMessage('NFT send offer submitted.')
                })
              }}
            />
          ) : null}

          {tab === 'defi' ? (
            <DefiPanel
              onCreateAmm={async (a1, a2, tradingFee) => {
                await submitAction(async () => {
                  await createAmm(
                    activeWallet,
                    network,
                    toAmmAmount(a1) as never,
                    toAmmAmount(a2) as never,
                    tradingFee,
                  )
                  setStatusMessage('AMM pool creation submitted.')
                })
              }}
              onDepositAmm={async (a1, a2) => {
                await submitAction(async () => {
                  await depositAmm(
                    activeWallet,
                    network,
                    toAmmAmount(a1) as never,
                    toAmmAmount(a2) as never,
                  )
                  setStatusMessage('AMM liquidity deposit submitted.')
                })
              }}
              onWithdrawAmm={async (a1, a2) => {
                await submitAction(async () => {
                  await withdrawAmm(
                    activeWallet,
                    network,
                    toAmmAmount(a1) as never,
                    toAmmAmount(a2) as never,
                  )
                  setStatusMessage('AMM liquidity withdrawal submitted.')
                })
              }}
              onVoteAmmFee={async (c1, i1, c2, i2, fee) => {
                await submitAction(async () => {
                  await voteAmmFee(
                    activeWallet,
                    network,
                    toAmmAsset(c1, i1),
                    toAmmAsset(c2, i2),
                    fee,
                  )
                  setStatusMessage('AMM fee vote submitted.')
                })
              }}
              onBidAuction={async (c1, i1, c2, i2, bidMin) => {
                await submitAction(async () => {
                  await bidAmmAuction(
                    activeWallet,
                    network,
                    toAmmAsset(c1, i1),
                    toAmmAsset(c2, i2),
                    bidMin,
                  )
                  setStatusMessage('AMM auction bid submitted.')
                })
              }}
            />
          ) : null}

          {tab === 'advanced' ? (
            <AdvancedPanel
              onCreateEscrow={async (destination, amount, finishAfter) => {
                await submitAction(async () => {
                  await createEscrow(activeWallet, network, destination, amount, finishAfter)
                  setStatusMessage('EscrowCreate transaction submitted.')
                })
              }}
              onFinishEscrow={async (owner, offerSequence) => {
                await submitAction(async () => {
                  await finishEscrow(activeWallet, network, owner, offerSequence)
                  setStatusMessage('EscrowFinish transaction submitted.')
                })
              }}
              onCreateChannel={async (destination, amount, settleDelay) => {
                await submitAction(async () => {
                  await createPaymentChannel(
                    activeWallet,
                    network,
                    destination,
                    amount,
                    settleDelay,
                  )
                  setStatusMessage('PaymentChannelCreate submitted.')
                })
              }}
              onClaimChannel={async (channel, amountDrops) => {
                await submitAction(async () => {
                  await claimPaymentChannel(activeWallet, network, channel, amountDrops)
                  setStatusMessage('PaymentChannelClaim submitted.')
                })
              }}
            />
          ) : null}

          {statusMessage ? <Notice tone="success">{statusMessage}</Notice> : null}
          {error ? <Notice tone="danger">{error}</Notice> : null}
        </main>
      </div>
    </AppShell>
  )
}

function AppShell({
  children,
  network,
  setNetwork,
}: {
  children: ReactNode
  network: 'mainnet' | 'testnet'
  setNetwork: (network: 'mainnet' | 'testnet') => void
}) {
  return (
    <div className="min-h-screen bg-app pb-10">
      <div className="mx-auto max-w-[1300px] px-4 py-5 lg:px-8 lg:py-8">
        <header className="mb-5 flex flex-wrap items-center justify-between gap-4 rounded-2xl border border-white/60 bg-white/70 p-4 shadow-[0_10px_40px_-24px_rgba(15,23,42,0.45)] backdrop-blur-sm">
          <div>
            <p className="text-xs uppercase tracking-[0.2em] text-teal-800">Professional XRPL Wallet</p>
            <p className="text-sm text-slate-700">
              Full-featured local-signing wallet for XRP, tokens, NFTs, DeFi, and advanced XRPL flows.
            </p>
          </div>
          <div className="inline-flex rounded-xl border border-slate-200 bg-white p-1">
            {(['testnet', 'mainnet'] as const).map((value) => (
              <button
                type="button"
                key={value}
                onClick={() => setNetwork(value)}
                className={`rounded-lg px-4 py-1.5 text-sm font-semibold transition ${
                  network === value
                    ? 'bg-teal-700 text-white'
                    : 'text-slate-600 hover:bg-slate-100'
                }`}
              >
                {NETWORKS[value].label}
              </button>
            ))}
          </div>
        </header>

        {children}
      </div>
    </div>
  )
}

function MetricRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between">
      <span>{label}</span>
      <strong className="text-slate-900">{value}</strong>
    </div>
  )
}

export default App
