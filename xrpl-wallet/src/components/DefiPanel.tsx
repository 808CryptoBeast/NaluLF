import { useEffect, useMemo, useState } from 'react'
import { explainXrplError } from '../lib/errors'
import { formatCurrency } from '../lib/format'
import {
  applyUserLpPositions,
  discoverAmmPools,
  enrichPoolSnapshots,
  subscribeLedger,
} from '../services/xrplService'
import { fetchIndexedAmmPools } from '../services/ammIndexService'
import type { AmmPoolSummary, NetworkType, TrustlineBalance } from '../types/wallet'
import { Button, Card, Input, Label, Notice, SectionTitle } from './ui'

type AssetPayload = {
  kind: 'xrp' | 'token'
  amount: string
  currency?: string
  issuer?: string
}

type DefiView = 'swap' | 'pools' | 'liquidity' | 'explorer'

interface Props {
  network: NetworkType
  trustlines: TrustlineBalance[]
  xrpUsdPrice: number
  onCreateAmm: (a1: AssetPayload, a2: AssetPayload, tradingFee: number) => Promise<void>
  onDepositAmm: (a1: AssetPayload, a2: AssetPayload) => Promise<void>
  onWithdrawAmm: (a1: AssetPayload, a2: AssetPayload) => Promise<void>
  onExecuteSwap: (payload: {
    from: { currency: string; issuer?: string }
    to: { currency: string; issuer?: string }
    amountIn: string
    expectedOut: string
    slippagePct: number
  }) => Promise<{ txHash?: string; status?: string }>
  onVoteAmmFee: (currency: string, issuer: string, currency2: string, issuer2: string, fee: number) => Promise<void>
  onBidAuction: (currency: string, issuer: string, currency2: string, issuer2: string, bidMin: string) => Promise<void>
}

export function DefiPanel({
  network,
  trustlines,
  xrpUsdPrice,
  onCreateAmm,
  onDepositAmm,
  onWithdrawAmm,
  onExecuteSwap,
  onVoteAmmFee,
  onBidAuction,
}: Props) {
  const [view, setView] = useState<DefiView>('swap')
  const [asset1, setAsset1] = useState<AssetPayload>({ kind: 'xrp', amount: '' })
  const [asset2, setAsset2] = useState<AssetPayload>({ kind: 'token', amount: '', currency: '', issuer: '' })
  const [fee, setFee] = useState('500')
  const [vote, setVote] = useState({ c1: '', i1: '', c2: '', i2: '', fee: '500' })
  const [bid, setBid] = useState({ c1: '', i1: '', c2: '', i2: '', bidMin: '' })
  const [swapFrom, setSwapFrom] = useState('XRP')
  const [swapTo, setSwapTo] = useState('USD')
  const [swapAmount, setSwapAmount] = useState('10')
  const [slippagePct, setSlippagePct] = useState('1')
  const [lastSwap, setLastSwap] = useState<{
    txHash?: string
    status?: string
    from: string
    to: string
    amountIn: number
    expectedOut: number
    minOut: number
    submittedAt: string
  } | null>(null)
  const [poolList, setPoolList] = useState<AmmPoolSummary[]>([])
  const [selectedPoolId, setSelectedPoolId] = useState<string | null>(null)
  const [message, setMessage] = useState<string | null>(null)

  const selectedPool = useMemo(
    () => poolList.find((pool) => pool.id === selectedPoolId) ?? poolList[0],
    [poolList, selectedPoolId],
  )

  const userPools = useMemo(
    () => poolList.filter((pool) => pool.userLpTokens > 0),
    [poolList],
  )

  const totalUserLiquidityUsd = useMemo(
    () => userPools.reduce((sum, pool) => sum + pool.userPositionUsd, 0),
    [userPools],
  )

  const estimatedFeesUsd = useMemo(
    () => userPools.reduce((sum, pool) => sum + (pool.volume24hUsd * pool.tradingFee) / 100000, 0),
    [userPools],
  )

  const swapQuote = useMemo(() => {
    const pool = poolList.find((p) => p.asset1Symbol === swapFrom && p.asset2Symbol === swapTo)
      ?? poolList.find((p) => p.asset1Symbol === swapTo && p.asset2Symbol === swapFrom)

    if (!pool) {
      return null
    }

    const amountIn = Number(swapAmount)
    const slippage = Number(slippagePct)
    if (!Number.isFinite(amountIn) || amountIn <= 0 || !Number.isFinite(slippage)) {
      return null
    }

    const direct = pool.asset1Symbol === swapFrom
    const reserveIn = direct ? pool.amount1 : pool.amount2
    const reserveOut = direct ? pool.amount2 : pool.amount1
    const feeFactor = 1 - pool.tradingFee / 100000
    const amountInAfterFee = amountIn * feeFactor

    const k = reserveIn * reserveOut
    const newReserveIn = reserveIn + amountInAfterFee
    const newReserveOut = k / Math.max(newReserveIn, 0.000001)
    const out = Math.max(reserveOut - newReserveOut, 0)

    const midRate = reserveOut / Math.max(reserveIn, 0.000001)
    const executionRate = out / Math.max(amountIn, 0.000001)
    const priceImpactPct = Math.max(((midRate - executionRate) / Math.max(midRate, 0.000001)) * 100, 0)
    const minOut = out * (1 - Math.max(slippage, 0) / 100)

    return {
      rate: executionRate,
      output: out,
      tradingFee: pool.tradingFee,
      estimatedFee: amountIn - amountInAfterFee,
      priceImpactPct,
      minOut,
      routePreview: `Direct AMM path: ${swapFrom} -> ${swapTo} via ${pool.label}`,
      pool,
    }
  }, [poolList, slippagePct, swapAmount, swapFrom, swapTo])

  const loadPools = async () => {
    try {
      let discovered: AmmPoolSummary[] = []
      try {
        discovered = await fetchIndexedAmmPools(network, xrpUsdPrice)
      } catch {
        discovered = await discoverAmmPools(network, trustlines, xrpUsdPrice)
      }
      const withVolume = enrichPoolSnapshots(discovered, poolList)
      const withUser = applyUserLpPositions(withVolume, trustlines)
      setPoolList(withUser)
      if (!selectedPoolId && withUser[0]) {
        setSelectedPoolId(withUser[0].id)
      }
    } catch (err) {
      setMessage(explainXrplError(err))
    }
  }

  useEffect(() => {
    void loadPools()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [network, trustlines.length, xrpUsdPrice])

  useEffect(() => {
    let unsubscribe: (() => Promise<void>) | null = null

    async function connect() {
      unsubscribe = await subscribeLedger(network, async () => {
        await loadPools()
      })
    }

    void connect()

    return () => {
      if (unsubscribe) {
        void unsubscribe()
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [network])

  const submitCreate = async () => {
    try {
      await onCreateAmm(asset1, asset2, Number(fee))
      setMessage('AMMCreate transaction submitted.')
    } catch (err) {
      setMessage(explainXrplError(err))
    }
  }

  const submitDeposit = async () => {
    try {
      await onDepositAmm(asset1, asset2)
      setMessage('AMMDeposit transaction submitted.')
    } catch (err) {
      setMessage(explainXrplError(err))
    }
  }

  const submitWithdraw = async () => {
    try {
      await onWithdrawAmm(asset1, asset2)
      setMessage('AMMWithdraw transaction submitted.')
    } catch (err) {
      setMessage(explainXrplError(err))
    }
  }

  return (
    <div className="space-y-5">
      <Card>
        <SectionTitle
          title="DeFi Control Room"
          subtitle="AMM discovery, swap intelligence, and liquidity provider operations."
        />
        <div className="flex flex-wrap gap-2">
          <DefiTab label="Swap" active={view === 'swap'} onClick={() => setView('swap')} />
          <DefiTab label="Pools" active={view === 'pools'} onClick={() => setView('pools')} />
          <DefiTab label="My Liquidity" active={view === 'liquidity'} onClick={() => setView('liquidity')} />
          <DefiTab label="AMM Explorer" active={view === 'explorer'} onClick={() => setView('explorer')} />
          <Button variant="secondary" onClick={() => void loadPools()}>
            Refresh Pools
          </Button>
        </div>
      </Card>

      {view === 'swap' ? (
        <Card>
          <SectionTitle title="DEX Swap Widget" subtitle="Quote trades from live AMM pool data." />
          <div className="grid gap-4 md:grid-cols-3">
            <div>
              <Label>From Asset</Label>
              <Input value={swapFrom} onChange={(e) => setSwapFrom(e.target.value.toUpperCase())} placeholder="XRP" />
            </div>
            <div>
              <Label>To Asset</Label>
              <Input value={swapTo} onChange={(e) => setSwapTo(e.target.value.toUpperCase())} placeholder="USD" />
            </div>
            <div>
              <Label>Amount</Label>
              <Input value={swapAmount} onChange={(e) => setSwapAmount(e.target.value)} placeholder="10" />
            </div>
            <div>
              <Label>Slippage %</Label>
              <Input value={slippagePct} onChange={(e) => setSlippagePct(e.target.value)} placeholder="1" />
            </div>
          </div>

          {swapQuote ? (
            <div className="mt-4 rounded-xl border border-slate-200 bg-slate-50 p-3 text-sm text-slate-700">
              <p>Pool: {swapQuote.pool.label}</p>
              <p>Exchange Rate: 1 {swapFrom} = {swapQuote.rate.toFixed(6)} {swapTo}</p>
              <p>Estimated Output: {swapQuote.output.toFixed(6)} {swapTo}</p>
              <p>Trading Fee: {swapQuote.tradingFee} ({swapQuote.estimatedFee.toFixed(6)} {swapFrom})</p>
              <p>Price Impact: {swapQuote.priceImpactPct.toFixed(2)}%</p>
              <p>Route: {swapQuote.routePreview}</p>
              <p>Min Receive (slippage): {swapQuote.minOut.toFixed(6)} {swapTo}</p>
              {swapQuote.priceImpactPct > 3 ? (
                <Notice tone="warning" className="mt-3">
                  High price impact detected. Consider a smaller trade or deeper pool.
                </Notice>
              ) : null}
              <div className="mt-3">
                <Button
                  onClick={async () => {
                    try {
                      const response = await onExecuteSwap({
                        from: {
                          currency: swapQuote.pool.asset1Symbol === swapFrom ? swapQuote.pool.asset1Symbol : swapQuote.pool.asset2Symbol,
                          issuer: swapQuote.pool.asset1Symbol === swapFrom ? swapQuote.pool.asset1Issuer : swapQuote.pool.asset2Issuer,
                        },
                        to: {
                          currency: swapQuote.pool.asset1Symbol === swapTo ? swapQuote.pool.asset1Symbol : swapQuote.pool.asset2Symbol,
                          issuer: swapQuote.pool.asset1Symbol === swapTo ? swapQuote.pool.asset1Issuer : swapQuote.pool.asset2Issuer,
                        },
                        amountIn: swapAmount,
                        expectedOut: swapQuote.output.toString(),
                        slippagePct: Number(slippagePct || '1'),
                      })
                      setLastSwap({
                        txHash: response.txHash,
                        status: response.status,
                        from: swapFrom,
                        to: swapTo,
                        amountIn: Number(swapAmount),
                        expectedOut: swapQuote.output,
                        minOut: swapQuote.minOut,
                        submittedAt: new Date().toISOString(),
                      })
                      setMessage('Swap offer submitted (IOC) with slippage protection.')
                    } catch (err) {
                      setMessage(explainXrplError(err))
                    }
                  }}
                >
                  Execute Swap
                </Button>
              </div>
            </div>
          ) : (
            <Notice tone="warning" className="mt-4">No matching AMM pool found for this pair yet.</Notice>
          )}

          {lastSwap ? (
            <div className="mt-4 rounded-xl border border-emerald-200 bg-emerald-50 p-3 text-sm text-emerald-900">
              <p className="font-semibold">Post-Trade Reconciliation</p>
              <p>Pair: {lastSwap.from}/{lastSwap.to}</p>
              <p>Input: {lastSwap.amountIn.toFixed(6)} {lastSwap.from}</p>
              <p>Expected Out: {lastSwap.expectedOut.toFixed(6)} {lastSwap.to}</p>
              <p>Min Out: {lastSwap.minOut.toFixed(6)} {lastSwap.to}</p>
              <p>Status: {lastSwap.status ?? 'submitted'}</p>
              <p>TX: {lastSwap.txHash ?? 'pending hash'}</p>
              <p>Submitted: {new Date(lastSwap.submittedAt).toLocaleString()}</p>
            </div>
          ) : null}
        </Card>
      ) : null}

      {view === 'pools' ? (
        <Card>
          <SectionTitle title="Live Pool Listings" subtitle="Asset balances, LP supply, fee, and auction slot insights." />
          <div className="overflow-auto">
            <table className="min-w-full text-left text-sm">
              <thead className="border-b border-slate-200 text-xs uppercase tracking-wide text-slate-500">
                <tr>
                  <th className="py-2 pr-3">Pool</th>
                  <th className="py-2 pr-3">Asset 1</th>
                  <th className="py-2 pr-3">Asset 2</th>
                  <th className="py-2 pr-3">LP Supply</th>
                  <th className="py-2 pr-3">Fee</th>
                  <th className="py-2 pr-3">TVL</th>
                  <th className="py-2">24h Vol</th>
                </tr>
              </thead>
              <tbody>
                {poolList.map((pool) => (
                  <tr
                    key={pool.id}
                    className={`cursor-pointer border-b border-slate-100 text-slate-700 ${
                      selectedPool?.id === pool.id ? 'bg-teal-50' : ''
                    }`}
                    onClick={() => setSelectedPoolId(pool.id)}
                  >
                    <td className="py-2 pr-3 font-semibold text-slate-900">{pool.label}</td>
                    <td className="py-2 pr-3">{pool.amount1.toFixed(2)} {pool.asset1Symbol}</td>
                    <td className="py-2 pr-3">{pool.amount2.toFixed(2)} {pool.asset2Symbol}</td>
                    <td className="py-2 pr-3">{pool.lpTokenSupply.toFixed(2)}</td>
                    <td className="py-2 pr-3">{pool.tradingFee}</td>
                    <td className="py-2 pr-3">{formatCurrency(pool.tvlUsd, 'USD')}</td>
                    <td className="py-2">{formatCurrency(pool.volume24hUsd, 'USD')}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      ) : null}

      {view === 'liquidity' ? (
        <div className="space-y-5">
          <Card>
            <SectionTitle title="User AMM Metrics" subtitle="Your positions, estimated fees, and LP inventory." />
            <div className="grid gap-4 md:grid-cols-3">
              <Kpi label="Total Value Locked" value={formatCurrency(totalUserLiquidityUsd, 'USD')} />
              <Kpi label="Estimated 24h Fees" value={formatCurrency(estimatedFeesUsd, 'USD')} />
              <Kpi label="Owned LP Tokens" value={String(userPools.reduce((sum, p) => sum + p.userLpTokens, 0).toFixed(2))} />
            </div>
          </Card>

          <Card>
            <SectionTitle title="My Liquidity Positions" />
            <div className="space-y-3">
              {userPools.map((pool) => (
                <div key={pool.id} className="rounded-xl border border-slate-200 bg-slate-50 p-3">
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <p className="text-sm font-semibold text-slate-900">{pool.label}</p>
                    <p className="text-sm text-slate-700">LP: {pool.userLpTokens.toFixed(4)}</p>
                  </div>
                  <p className="mt-1 text-sm text-slate-600">Position Value: {formatCurrency(pool.userPositionUsd, 'USD')}</p>
                </div>
              ))}
              {!userPools.length ? <p className="text-sm text-slate-500">No LP positions found yet.</p> : null}
            </div>
          </Card>

          <Card>
            <SectionTitle title="Liquidity Provider Interface" subtitle="Add or remove liquidity from AMM pools." />
            <div className="grid gap-4 lg:grid-cols-2">
              <AssetEditor title="Asset 1" value={asset1} onChange={setAsset1} />
              <AssetEditor title="Asset 2" value={asset2} onChange={setAsset2} />
            </div>
            <div className="mt-4 grid gap-3 md:grid-cols-[1fr_auto_auto_auto]">
              <div>
                <Label>Trading Fee (for AMMCreate)</Label>
                <Input value={fee} onChange={(e) => setFee(e.target.value)} placeholder="500" />
              </div>
              <div className="flex items-end">
                <Button onClick={submitCreate}>Create Pool</Button>
              </div>
              <div className="flex items-end">
                <Button variant="secondary" onClick={submitDeposit}>Deposit</Button>
              </div>
              <div className="flex items-end">
                <Button variant="secondary" onClick={submitWithdraw}>Withdraw</Button>
              </div>
            </div>
          </Card>
        </div>
      ) : null}

      {view === 'explorer' ? (
        <div className="grid gap-5 xl:grid-cols-[1.5fr_1fr]">
          <Card>
            <SectionTitle title="Visual Pool Details" subtitle="Composition, liquidity depth, and auction status." />
            {selectedPool ? (
              <>
                <p className="text-sm font-semibold text-slate-900">{selectedPool.label}</p>
                <p className="mt-1 text-sm text-slate-700">
                  TVL: {formatCurrency(selectedPool.tvlUsd, 'USD')} | 24h Volume: {formatCurrency(selectedPool.volume24hUsd, 'USD')}
                </p>
                <div className="mt-4 space-y-3">
                  <Gauge label={`${selectedPool.asset1Symbol} Composition`} value={selectedPool.compositionA} />
                  <Gauge label={`${selectedPool.asset2Symbol} Composition`} value={selectedPool.compositionB} />
                </div>
                <div className="mt-4 rounded-xl border border-slate-200 bg-slate-50 p-3 text-sm text-slate-700">
                  <p>Trading Fee: {selectedPool.tradingFee}</p>
                  <p>Auction Discounted Fee: {selectedPool.auctionDiscountedFee ?? 'N/A'}</p>
                  <p>AMM Account: {selectedPool.ammAccount ?? 'Unknown'}</p>
                </div>
              </>
            ) : <p className="text-sm text-slate-500">Select a pool from the Pools view.</p>}
          </Card>

          <Card>
            <SectionTitle title="Advanced AMM Ops" subtitle="Fee voting and auction bidding." />
            <TokenPairInputs
              c1={vote.c1}
              i1={vote.i1}
              c2={vote.c2}
              i2={vote.i2}
              onChange={(key, value) => setVote((prev) => ({ ...prev, [key]: value }))}
            />
            <div className="mt-3">
              <Label>Proposed Fee</Label>
              <Input value={vote.fee} onChange={(e) => setVote((p) => ({ ...p, fee: e.target.value }))} placeholder="500" />
            </div>
            <Button className="mt-3" onClick={async () => {
              try {
                await onVoteAmmFee(vote.c1, vote.i1, vote.c2, vote.i2, Number(vote.fee))
                setMessage('AMMVote submitted.')
              } catch (err) {
                setMessage(explainXrplError(err))
              }
            }}>
              Submit AMMVote
            </Button>

            <div className="mt-5 border-t border-slate-200 pt-4">
              <TokenPairInputs
                c1={bid.c1}
                i1={bid.i1}
                c2={bid.c2}
                i2={bid.i2}
                onChange={(key, value) => setBid((prev) => ({ ...prev, [key]: value }))}
              />
              <div className="mt-3">
                <Label>Bid Min (LP Tokens)</Label>
                <Input value={bid.bidMin} onChange={(e) => setBid((p) => ({ ...p, bidMin: e.target.value }))} placeholder="100" />
              </div>
              <Button className="mt-3" onClick={async () => {
                try {
                  await onBidAuction(bid.c1, bid.i1, bid.c2, bid.i2, bid.bidMin)
                  setMessage('AMMBid submitted.')
                } catch (err) {
                  setMessage(explainXrplError(err))
                }
              }}>
                Submit AMMBid
              </Button>
            </div>
          </Card>
        </div>
      ) : null}

      {message ? <Notice tone="info">{message}</Notice> : null}
    </div>
  )
}

function DefiTab({ label, active, onClick }: { label: string; active: boolean; onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`rounded-lg px-3 py-1.5 text-sm font-semibold transition ${
        active ? 'bg-teal-700 text-white' : 'bg-slate-100 text-slate-700 hover:bg-slate-200'
      }`}
    >
      {label}
    </button>
  )
}

function Gauge({ label, value }: { label: string; value: number }) {
  const safe = Math.max(0, Math.min(100, value))
  return (
    <div>
      <div className="mb-1 flex items-center justify-between text-xs text-slate-600">
        <span>{label}</span>
        <span>{safe.toFixed(1)}%</span>
      </div>
      <div className="h-2 rounded-full bg-slate-200">
        <div className="h-2 rounded-full bg-teal-600 transition-all" style={{ width: `${safe}%` }} />
      </div>
    </div>
  )
}

function Kpi({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-xl border border-slate-200 bg-slate-50 p-3">
      <p className="text-xs uppercase tracking-wide text-slate-500">{label}</p>
      <p className="mt-1 text-lg font-semibold text-slate-900">{value}</p>
    </div>
  )
}

function AssetEditor({ title, value, onChange }: { title: string; value: AssetPayload; onChange: (value: AssetPayload) => void }) {
  return (
    <div className="rounded-xl border border-slate-200 bg-slate-50/60 p-3">
      <p className="mb-2 text-sm font-semibold text-slate-800">{title}</p>
      <div className="space-y-2">
        <div>
          <Label>Type</Label>
          <select
            className="w-full rounded-xl border border-slate-300 bg-white px-3 py-2 text-sm"
            value={value.kind}
            onChange={(e) => onChange({ ...value, kind: e.target.value as 'xrp' | 'token' })}
          >
            <option value="xrp">XRP</option>
            <option value="token">Issued Token / MPT</option>
          </select>
        </div>
        <div>
          <Label>Amount</Label>
          <Input value={value.amount} onChange={(e) => onChange({ ...value, amount: e.target.value })} placeholder="100" />
        </div>
        {value.kind === 'token' ? (
          <>
            <div>
              <Label>Currency</Label>
              <Input value={value.currency ?? ''} onChange={(e) => onChange({ ...value, currency: e.target.value })} placeholder="USD" />
            </div>
            <div>
              <Label>Issuer</Label>
              <Input value={value.issuer ?? ''} onChange={(e) => onChange({ ...value, issuer: e.target.value })} placeholder="r..." />
            </div>
          </>
        ) : null}
      </div>
    </div>
  )
}

function TokenPairInputs({
  c1,
  i1,
  c2,
  i2,
  onChange,
}: {
  c1: string
  i1: string
  c2: string
  i2: string
  onChange: (key: 'c1' | 'i1' | 'c2' | 'i2', value: string) => void
}) {
  return (
    <div className="grid gap-3">
      <div>
        <Label>Token 1 Currency</Label>
        <Input value={c1} onChange={(e) => onChange('c1', e.target.value)} placeholder="USD" />
      </div>
      <div>
        <Label>Token 1 Issuer</Label>
        <Input value={i1} onChange={(e) => onChange('i1', e.target.value)} placeholder="r..." />
      </div>
      <div>
        <Label>Token 2 Currency</Label>
        <Input value={c2} onChange={(e) => onChange('c2', e.target.value)} placeholder="EUR" />
      </div>
      <div>
        <Label>Token 2 Issuer</Label>
        <Input value={i2} onChange={(e) => onChange('i2', e.target.value)} placeholder="r..." />
      </div>
    </div>
  )
}
