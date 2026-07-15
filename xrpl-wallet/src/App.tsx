import { useEffect, useMemo, useState, type CSSProperties, type ReactNode } from 'react'
import { Lock, LogOut, Plus, ShieldCheck, Trash2, Wallet2 } from 'lucide-react'
import type { Wallet } from 'xrpl'
import { Dashboard } from './components/Dashboard'
import { MarketOverview } from './components/MarketOverview'
import { OnboardingWizard } from './components/OnboardingWizard'
import { PassphraseModal } from './components/PassphraseModal'
import { ProfileIdentityBar } from './components/ProfileIdentityBar'
import { TradingTerminal } from './components/TradingTerminal'
import { AssetManager } from './components/AssetManager'
import { SendPanel } from './components/SendPanel'
import { DefiPanel } from './components/DefiPanel'
import { AdvancedPanel } from './components/AdvancedPanel'
import { ActivityPanel } from './components/ActivityPanel'
import { ProfileTab } from './components/ProfileTab'
import { Button, Card, Notice } from './components/ui'
import { explainXrplError } from './lib/errors'
import { formatCurrency } from './lib/format'
import { logActivity } from './lib/naluActivity'
import { useProfileAppearance } from './lib/naluAppearance'
import { usePreferences } from './lib/naluPreferences'
import {
  fetchCurrencyUsdMap,
  fetchXrpUsdPrice,
  resolveIssuerQuote,
} from './services/priceService'
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
  executeSwapOffer,
  fetchAccountState,
  fetchNetworkOverview,
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

type Tab = 'profile' | 'dashboard' | 'assets' | 'send' | 'activity' | 'defi' | 'advanced'

function App() {
  const [tab, setTab] = useState<Tab>('profile')
  const [statusMessage, setStatusMessage] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [feeXrp, setFeeXrp] = useState('0.000012')
  const { autoLock: autoLockMinutes } = usePreferences()

  const {
    network,
    setNetwork,
    wallets,
    activeWalletId,
    setActiveWallet,
    deleteWallet,
    getUnlockedWallet,
    lockWallet,
    setAccountData,
    trustlines,
    nfts,
    transactions,
    activity,
    security,
    networkStats,
    aggregatedAssets,
    balanceXrp,
    reserveXrp,
    xrpUsdPrice,
    metrics,
    setXrpUsdPrice,
    setNetworkStats,
  } = useWalletStore()

  const activeWallet = useMemo(
    () => wallets.find((w) => w.id === activeWalletId) || wallets[0] || null,
    [wallets, activeWalletId],
  )
  const connectedAddress = activeWallet?.address

  // Wallets are entirely optional — a signed-in user can use Profile/Activity
  // without ever creating one. This just controls whether the add/import
  // wizard overlay is showing; it never gates the rest of the app.
  const [onboardingActive, setOnboardingActive] = useState(false)
  const [marketBaseFee, setMarketBaseFee] = useState('0.000012')
  const walletDependentTabs: Tab[] = ['assets', 'send', 'defi', 'advanced']

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

      const symbols = state.aggregatedAssets.map((asset) => asset.symbol)
      const symbolUsdMap = await fetchCurrencyUsdMap(symbols)
      const repricedAssets = state.aggregatedAssets.map((asset) => {
        const symbol = asset.symbol.toUpperCase()
        if (asset.type === 'xrp') {
          return {
            ...asset,
            valueUsd: asset.quantity * price,
            valueXrp: asset.quantity,
            priceConfidence: 'high' as const,
            priceSource: 'Coinbase XRP/USD',
          }
        }

        if (asset.type === 'nft') {
          return {
            ...asset,
            priceConfidence: 'unknown' as const,
            priceSource: 'No floor oracle configured',
          }
        }

        const issuer = asset.metadata
        const issuerQuote = resolveIssuerQuote(symbol, issuer)
        const quote = issuerQuote ?? symbolUsdMap[symbol]
        const usdRate = quote?.usd ?? 0
        const valueUsd = asset.quantity * usdRate
        return {
          ...asset,
          valueUsd,
          valueXrp: price > 0 ? valueUsd / price : 0,
          priceConfidence: quote?.confidence ?? 'low',
          priceSource: quote?.source ?? 'Unpriced estimate',
        }
      })

      setAccountData({
        ...state,
        aggregatedAssets: repricedAssets,
      })
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

  // XRP/USD price and network ledger/fee state need no account at all —
  // refresh them regardless of whether the user has a wallet yet, so the
  // Dashboard shows real market data by default instead of staying at zero
  // until a wallet exists.
  useEffect(() => {
    let cancelled = false
    async function run() {
      try {
        const [price, overview] = await Promise.all([fetchXrpUsdPrice(), fetchNetworkOverview(network)])
        if (cancelled) return
        setXrpUsdPrice(price)
        setNetworkStats(overview.networkStats)
        setMarketBaseFee(overview.baseFeeXrp)
      } catch {
        // keep showing the last known values if this fails
      }
    }
    void run()
    const interval = setInterval(run, 30_000)
    return () => {
      cancelled = true
      clearInterval(interval)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [network])

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

  // Auto-lock the decrypted signing key after the configured idle period
  // (nalulf_pref_autolock — same preference profile.js's Settings tab writes).
  useEffect(() => {
    const minutes = Number(autoLockMinutes)
    let timer: ReturnType<typeof setTimeout> | null = null

    const reset = () => {
      if (timer) clearTimeout(timer)
      timer = setTimeout(() => lockWallet(), minutes * 60_000)
    }

    const events = ['mousemove', 'keydown', 'click', 'touchstart'] as const
    events.forEach((evt) => window.addEventListener(evt, reset))
    reset()

    return () => {
      if (timer) clearTimeout(timer)
      events.forEach((evt) => window.removeEventListener(evt, reset))
    }
  }, [autoLockMinutes, lockWallet])

  const submitAction = async (fn: (wallet: Wallet) => Promise<void>) => {
    try {
      setError(null)
      setStatusMessage(null)
      const wallet = await getUnlockedWallet()
      await fn(wallet)
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

  return (
    <AppShell network={network} setNetwork={setNetwork}>
      <PassphraseModal />
      {onboardingActive ? (
        <div className="fixed inset-0 z-40 flex items-start justify-center overflow-y-auto bg-black/60 p-4 py-10">
          <div className="w-full max-w-4xl">
            <OnboardingWizard onClose={() => setOnboardingActive(false)} />
          </div>
        </div>
      ) : null}
      <div className="grid gap-5 xl:grid-cols-[240px_1fr]">
        <aside className="space-y-4">
          <Card>
            <div className="mb-4 flex items-center gap-2 text-white">
              <Wallet2 className="h-5 w-5 text-teal-700" />
              <h1 className="text-lg font-semibold">Nalu XRPL Wallet</h1>
            </div>

            <div className="mb-4 space-y-1.5">
              {wallets.length === 0 ? (
                <p className="rounded-xl border border-dashed border-slate-700 p-3 text-xs text-slate-400">
                  No wallets yet — completely optional. Add one below whenever you're ready.
                </p>
              ) : null}
              {wallets.map((w) => (
                <div
                  key={w.id}
                  className={`flex items-center gap-2 rounded-xl border px-2 py-1.5 ${
                    w.id === activeWallet?.id
                      ? 'border-teal-700 bg-teal-950/60'
                      : 'border-slate-700 bg-slate-800/60'
                  }`}
                >
                  <button
                    type="button"
                    onClick={() => setActiveWallet(w.id)}
                    className="flex min-w-0 flex-1 items-center gap-2 text-left"
                  >
                    <span aria-hidden>{w.emoji}</span>
                    <span className="min-w-0 flex-1">
                      <span className="block truncate text-sm font-medium text-white">{w.label}</span>
                      <span className="block truncate text-xs text-slate-400">
                        {w.address.slice(0, 8)}…{w.address.slice(-5)}
                        {w.watchOnly ? ' · watch-only' : ''}
                      </span>
                    </span>
                  </button>
                  <button
                    type="button"
                    title="Remove wallet"
                    onClick={() => {
                      if (confirm(`Remove "${w.label}" from this browser? This does not affect the account on-ledger.`)) {
                        deleteWallet(w.id)
                      }
                    }}
                    className="shrink-0 rounded-lg p-1 text-slate-500 hover:bg-slate-700 hover:text-rose-400"
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </button>
                </div>
              ))}
            </div>

            <Button variant="secondary" className="w-full" onClick={() => setOnboardingActive(true)}>
              <Plus className="mr-2 h-4 w-4" /> Add Wallet
            </Button>

            <nav className="mt-4 space-y-2 border-t border-slate-700 pt-4">
              {([
                ['profile', 'Profile'],
                ['dashboard', 'Dashboard'],
                ['assets', 'Portfolio'],
                ['send', 'Send & Receive'],
                ['activity', 'Activity'],
                ['defi', 'AMM Explorer'],
                ['advanced', 'Advanced'],
              ] as const).map(([value, label]) => (
                <button
                  type="button"
                  key={value}
                  onClick={() => setTab(value)}
                  className={`w-full rounded-xl px-3 py-2 text-left text-sm font-medium transition ${
                    tab === value
                      ? 'bg-[var(--profile-accent,var(--accent-primary,#0f766e))] text-white'
                      : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
                  }`}
                >
                  {label}
                </button>
              ))}
            </nav>

            <div className="mt-4 space-y-2 border-t border-slate-700 pt-4">
              <Button variant="secondary" className="w-full" onClick={lockWallet}>
                <Lock className="mr-2 h-4 w-4" /> Lock Signing Key
              </Button>
            </div>
          </Card>

          {connectedAddress ? (
            <Card>
              <h3 className="text-sm font-semibold text-white">Metrics Snapshot</h3>
              <div className="mt-3 space-y-2 text-sm text-slate-300">
                <MetricRow label="Trustlines" value={String(metrics.trustlineCount)} />
                <MetricRow label="NFTs" value={String(metrics.nftCount)} />
                <MetricRow label="Reserve" value={formatCurrency(metrics.xrpReserve, 'XRP')} />
                <MetricRow label="Recent TX" value={String(metrics.recentTxCount)} />
              </div>
            </Card>
          ) : (
            <Card>
              <h3 className="text-sm font-semibold text-white">Market Snapshot</h3>
              <div className="mt-3 space-y-2 text-sm text-slate-300">
                <MetricRow label="XRP / USD" value={xrpUsdPrice > 0 ? formatCurrency(xrpUsdPrice, 'USD') : '—'} />
                <MetricRow label="Network" value={networkStats.networkLabel} />
                <MetricRow label="Ledger Index" value={String(networkStats.ledgerIndex || '—')} />
              </div>
            </Card>
          )}
        </aside>

        <main className="space-y-5">
          {connectedAddress && tab !== 'profile' ? (
            <Card>
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div>
                  <p className="text-xs uppercase tracking-wide text-slate-400">Active Account</p>
                  <p className="text-sm font-semibold text-white">{connectedAddress}</p>
                  <p className="text-xs text-slate-400">
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
                  <Button variant="secondary" onClick={() => void refreshAccount()}>
                    <ShieldCheck className="mr-2 h-4 w-4" /> Refresh Account
                  </Button>
                  {transactions[0]?.hash ? (
                    <a
                      href={getExplorerUrl(network, transactions[0].hash)}
                      target="_blank"
                      rel="noreferrer"
                      className="inline-flex items-center rounded-xl border border-slate-600 bg-slate-900 px-4 py-2 text-sm font-semibold text-slate-300 hover:bg-slate-800"
                    >
                      <LogOut className="mr-2 h-4 w-4" /> Latest TX
                    </a>
                  ) : null}
                </div>
              </div>
            </Card>
          ) : null}

          {tab === 'profile' ? <ProfileTab onAddWallet={() => setOnboardingActive(true)} /> : null}

          {walletDependentTabs.includes(tab) && !connectedAddress ? (
            <Card>
              <p className="text-sm font-semibold text-white">No wallet on this tab yet</p>
              <p className="mt-1 text-sm text-slate-400">
                Wallets are optional. Add one from your profile to use Trade, Portfolio, Send, AMM, and Advanced.
              </p>
              <Button className="mt-3" onClick={() => setOnboardingActive(true)}>
                <Plus className="mr-2 h-4 w-4" /> Add a Wallet
              </Button>
            </Card>
          ) : null}

          {tab === 'dashboard' ? (
            <div className="space-y-5">
              <TradingTerminal aggregatedAssets={aggregatedAssets} />
              {connectedAddress ? (
                <Dashboard
                  address={connectedAddress}
                  balanceXrp={balanceXrp}
                  reserveXrp={reserveXrp}
                  activity={activity}
                  security={security}
                  networkStats={networkStats}
                  onRefresh={refreshAccount}
                />
              ) : (
                <MarketOverview xrpUsdPrice={xrpUsdPrice} networkStats={networkStats} baseFeeXrp={marketBaseFee} />
              )}
            </div>
          ) : null}

          {tab === 'assets' && connectedAddress ? (
            <AssetManager
              trustlines={trustlines}
              nfts={nfts}
              aggregatedAssets={aggregatedAssets}
              xrpUsdPrice={xrpUsdPrice}
              portfolioUsd={totalUsd}
              lpTokenCount={metrics.lpTokenCount}
              transactions={transactions}
              onCreateTrustline={async (currency, issuer, limit) => {
                await submitAction(async (wallet) => {
                  await createTrustline(wallet, network, currency, issuer, limit)
                  setStatusMessage(
                    'Trustline submitted. This may consume ~2 XRP reserve while active.',
                  )
                  logActivity('trustline_added', `${currency} (${issuer.slice(0, 10)}…)`)
                })
              }}
              onSendToken={async ({ destination, amount, currency, issuer, destinationTag }) => {
                await submitAction(async (wallet) => {
                  await sendIssuedToken(
                    wallet,
                    network,
                    destination,
                    currency,
                    issuer,
                    amount,
                    destinationTag,
                  )
                  setStatusMessage('Issued token payment submitted and awaiting validation.')
                  logActivity('sent', `${amount} ${currency} → ${destination.slice(0, 10)}…`)
                })
              }}
              onSendNft={async (nftId, destination) => {
                await submitAction(async (wallet) => {
                  await sendNft(wallet, network, nftId, destination)
                  setStatusMessage('NFT transfer offer submitted.')
                })
              }}
            />
          ) : null}

          {tab === 'send' && connectedAddress ? (
            <SendPanel
              feeXrp={feeXrp}
              trustlines={trustlines}
              nfts={nfts}
              onSendXrp={async ({ destination, amount, destinationTag }) => {
                await submitAction(async (wallet) => {
                  await sendXrp(wallet, network, destination, amount, destinationTag)
                  setStatusMessage('XRP payment submitted.')
                  logActivity('sent', `${amount} XRP → ${destination.slice(0, 10)}…`)
                })
              }}
              onSendToken={async ({ destination, amount, currency, issuer, destinationTag }) => {
                await submitAction(async (wallet) => {
                  await sendIssuedToken(
                    wallet,
                    network,
                    destination,
                    currency,
                    issuer,
                    amount,
                    destinationTag,
                  )
                  setStatusMessage('Token payment submitted.')
                  logActivity('sent', `${amount} ${currency} → ${destination.slice(0, 10)}…`)
                })
              }}
              onSendNft={async (nftId, destination) => {
                await submitAction(async (wallet) => {
                  await sendNft(wallet, network, nftId, destination)
                  setStatusMessage('NFT send offer submitted.')
                })
              }}
            />
          ) : null}

          {tab === 'activity' ? (
            <ActivityPanel
              activeWalletLabel={activeWallet?.label}
              activeWalletAddress={connectedAddress}
              transactions={transactions}
            />
          ) : null}

          {tab === 'defi' && connectedAddress ? (
            <DefiPanel
              network={network}
              trustlines={trustlines}
              xrpUsdPrice={xrpUsdPrice}
              onCreateAmm={async (a1, a2, tradingFee) => {
                await submitAction(async (wallet) => {
                  await createAmm(
                    wallet,
                    network,
                    toAmmAmount(a1) as never,
                    toAmmAmount(a2) as never,
                    tradingFee,
                  )
                  setStatusMessage('AMM pool creation submitted.')
                })
              }}
              onDepositAmm={async (a1, a2) => {
                await submitAction(async (wallet) => {
                  await depositAmm(
                    wallet,
                    network,
                    toAmmAmount(a1) as never,
                    toAmmAmount(a2) as never,
                  )
                  setStatusMessage('AMM liquidity deposit submitted.')
                })
              }}
              onWithdrawAmm={async (a1, a2) => {
                await submitAction(async (wallet) => {
                  await withdrawAmm(
                    wallet,
                    network,
                    toAmmAmount(a1) as never,
                    toAmmAmount(a2) as never,
                  )
                  setStatusMessage('AMM liquidity withdrawal submitted.')
                })
              }}
              onExecuteSwap={async ({ from, to, amountIn, expectedOut, slippagePct }) => {
                let swapMeta: { txHash?: string; status?: string } = {}
                await submitAction(async (wallet) => {
                  swapMeta = await executeSwapOffer(wallet, network, {
                    from,
                    to,
                    amountIn,
                    expectedOut,
                    slippagePct,
                  })
                  setStatusMessage('Swap offer submitted with slippage protection.')
                })
                return swapMeta
              }}
              onVoteAmmFee={async (c1, i1, c2, i2, fee) => {
                await submitAction(async (wallet) => {
                  await voteAmmFee(
                    wallet,
                    network,
                    toAmmAsset(c1, i1),
                    toAmmAsset(c2, i2),
                    fee,
                  )
                  setStatusMessage('AMM fee vote submitted.')
                })
              }}
              onBidAuction={async (c1, i1, c2, i2, bidMin) => {
                await submitAction(async (wallet) => {
                  await bidAmmAuction(
                    wallet,
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

          {tab === 'advanced' && connectedAddress ? (
            <AdvancedPanel
              security={security}
              onCreateEscrow={async (destination, amount, finishAfter) => {
                await submitAction(async (wallet) => {
                  await createEscrow(wallet, network, destination, amount, finishAfter)
                  setStatusMessage('EscrowCreate transaction submitted.')
                })
              }}
              onFinishEscrow={async (owner, offerSequence) => {
                await submitAction(async (wallet) => {
                  await finishEscrow(wallet, network, owner, offerSequence)
                  setStatusMessage('EscrowFinish transaction submitted.')
                })
              }}
              onCreateChannel={async (destination, amount, settleDelay) => {
                await submitAction(async (wallet) => {
                  await createPaymentChannel(
                    wallet,
                    network,
                    destination,
                    amount,
                    settleDelay,
                  )
                  setStatusMessage('PaymentChannelCreate submitted.')
                })
              }}
              onClaimChannel={async (channel, amountDrops) => {
                await submitAction(async (wallet) => {
                  await claimPaymentChannel(wallet, network, channel, amountDrops)
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
  const { accent, bgPreset, bgImage } = useProfileAppearance()

  const rootStyle: CSSProperties & Record<string, string> = {}
  if (accent) rootStyle['--profile-accent'] = accent
  if (bgImage) {
    rootStyle.backgroundImage = `url(${bgImage})`
    rootStyle.backgroundSize = 'cover'
    rootStyle.backgroundPosition = 'center'
    rootStyle.backgroundAttachment = 'fixed'
  }

  return (
    <div className={`min-h-screen pb-10 ${bgImage ? '' : bgPreset || 'bg-app'}`} style={rootStyle}>
      <div className="w-full px-4 py-5 lg:px-8 lg:py-8">
        <header className="mb-5 flex flex-wrap items-center justify-between gap-4 rounded-2xl border border-slate-900/60 bg-slate-900/70 p-4 shadow-[0_10px_40px_-24px_rgba(15,23,42,0.45)] backdrop-blur-sm">
          <div>
            <p className="text-xs uppercase tracking-[0.2em] text-[var(--profile-accent,var(--accent-primary,#0f766e))]">Nalu Profile</p>
            <p className="text-sm text-slate-300">
              Your identity, activity, and XRPL wallets — wallets are optional and local-signing only.
            </p>
          </div>
          <div className="inline-flex rounded-xl border border-slate-700 bg-slate-900 p-1">
            {(['testnet', 'mainnet'] as const).map((value) => (
              <button
                type="button"
                key={value}
                onClick={() => setNetwork(value)}
                className={`rounded-lg px-4 py-1.5 text-sm font-semibold transition ${
                  network === value
                    ? 'bg-[var(--profile-accent,var(--accent-primary,#0f766e))] text-white'
                    : 'text-slate-400 hover:bg-slate-800'
                }`}
              >
                {NETWORKS[value].label}
              </button>
            ))}
          </div>
        </header>

        <ProfileIdentityBar />

        {children}
      </div>
    </div>
  )
}

function MetricRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between">
      <span>{label}</span>
      <strong className="text-white">{value}</strong>
    </div>
  )
}

export default App
