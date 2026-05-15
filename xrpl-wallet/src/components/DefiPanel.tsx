import { useState } from 'react'
import { explainXrplError } from '../lib/errors'
import { Button, Card, Input, Label, Notice, SectionTitle } from './ui'

interface AssetPayload {
  kind: 'xrp' | 'token'
  amount: string
  currency?: string
  issuer?: string
}

interface Props {
  onCreateAmm: (a1: AssetPayload, a2: AssetPayload, tradingFee: number) => Promise<void>
  onDepositAmm: (a1: AssetPayload, a2: AssetPayload) => Promise<void>
  onWithdrawAmm: (a1: AssetPayload, a2: AssetPayload) => Promise<void>
  onVoteAmmFee: (currency: string, issuer: string, currency2: string, issuer2: string, fee: number) => Promise<void>
  onBidAuction: (currency: string, issuer: string, currency2: string, issuer2: string, bidMin: string) => Promise<void>
}

export function DefiPanel({
  onCreateAmm,
  onDepositAmm,
  onWithdrawAmm,
  onVoteAmmFee,
  onBidAuction,
}: Props) {
  const [asset1, setAsset1] = useState<AssetPayload>({ kind: 'xrp', amount: '' })
  const [asset2, setAsset2] = useState<AssetPayload>({ kind: 'token', amount: '', currency: '', issuer: '' })
  const [fee, setFee] = useState('500')
  const [vote, setVote] = useState({ c1: '', i1: '', c2: '', i2: '', fee: '500' })
  const [bid, setBid] = useState({ c1: '', i1: '', c2: '', i2: '', bidMin: '' })
  const [message, setMessage] = useState<string | null>(null)

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

  const submitVote = async () => {
    try {
      await onVoteAmmFee(vote.c1, vote.i1, vote.c2, vote.i2, Number(vote.fee))
      setMessage('AMMVote submitted.')
    } catch (err) {
      setMessage(explainXrplError(err))
    }
  }

  const submitBid = async () => {
    try {
      await onBidAuction(bid.c1, bid.i1, bid.c2, bid.i2, bid.bidMin)
      setMessage('AMMBid submitted.')
    } catch (err) {
      setMessage(explainXrplError(err))
    }
  }

  return (
    <div className="space-y-5">
      <Card>
        <SectionTitle
          title="AMM Pool Management"
          subtitle="Create pools and manage liquidity with AMMCreate / AMMDeposit / AMMWithdraw."
        />

        <div className="grid gap-4 lg:grid-cols-2">
          <AssetEditor title="Asset 1" value={asset1} onChange={setAsset1} />
          <AssetEditor title="Asset 2" value={asset2} onChange={setAsset2} />
        </div>

        <div className="mt-4 grid gap-4 md:grid-cols-[1fr_auto_auto_auto]">
          <div>
            <Label>Trading Fee (1/100000)</Label>
            <Input value={fee} onChange={(e) => setFee(e.target.value)} placeholder="500" />
          </div>
          <div className="flex items-end">
            <Button onClick={submitCreate}>Create Pool</Button>
          </div>
          <div className="flex items-end">
            <Button variant="secondary" onClick={submitDeposit}>
              Deposit Liquidity
            </Button>
          </div>
          <div className="flex items-end">
            <Button variant="secondary" onClick={submitWithdraw}>
              Withdraw Liquidity
            </Button>
          </div>
        </div>

        <Notice tone="warning" className="mt-4">
          AMM operations can fail when liquidity is insufficient or assets are malformed. Validate issuer/currency carefully.
        </Notice>
      </Card>

      <div className="grid gap-5 lg:grid-cols-2">
        <Card>
          <SectionTitle title="Advanced AMM Voting" subtitle="Vote pool fee using AMMVote." />
          <TokenPairInputs
            c1={vote.c1}
            i1={vote.i1}
            c2={vote.c2}
            i2={vote.i2}
            onChange={(key, value) => setVote((prev) => ({ ...prev, [key]: value }))}
          />
          <div className="mt-3">
            <Label>Proposed Fee</Label>
            <Input
              value={vote.fee}
              onChange={(e) => setVote((prev) => ({ ...prev, fee: e.target.value }))}
              placeholder="500"
            />
          </div>
          <Button className="mt-4" onClick={submitVote}>
            Submit AMMVote
          </Button>
        </Card>

        <Card>
          <SectionTitle title="Auction Slot Bid" subtitle="Bid for reduced fees using AMMBid." />
          <TokenPairInputs
            c1={bid.c1}
            i1={bid.i1}
            c2={bid.c2}
            i2={bid.i2}
            onChange={(key, value) => setBid((prev) => ({ ...prev, [key]: value }))}
          />
          <div className="mt-3">
            <Label>Bid Min (LP Tokens)</Label>
            <Input
              value={bid.bidMin}
              onChange={(e) => setBid((prev) => ({ ...prev, bidMin: e.target.value }))}
              placeholder="100"
            />
          </div>
          <Button className="mt-4" onClick={submitBid}>
            Submit AMMBid
          </Button>
        </Card>
      </div>

      {message ? <Notice tone="info">{message}</Notice> : null}
    </div>
  )
}

function AssetEditor({
  title,
  value,
  onChange,
}: {
  title: string
  value: AssetPayload
  onChange: (value: AssetPayload) => void
}) {
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
          <Input
            value={value.amount}
            onChange={(e) => onChange({ ...value, amount: e.target.value })}
            placeholder="100"
          />
        </div>
        {value.kind === 'token' ? (
          <>
            <div>
              <Label>Currency</Label>
              <Input
                value={value.currency ?? ''}
                onChange={(e) => onChange({ ...value, currency: e.target.value })}
                placeholder="USD"
              />
            </div>
            <div>
              <Label>Issuer</Label>
              <Input
                value={value.issuer ?? ''}
                onChange={(e) => onChange({ ...value, issuer: e.target.value })}
                placeholder="r..."
              />
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
