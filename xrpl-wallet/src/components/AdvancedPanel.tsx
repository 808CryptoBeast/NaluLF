import { useState } from 'react'
import { explainXrplError } from '../lib/errors'
import { Button, Card, Input, Label, Notice, SectionTitle } from './ui'

interface Props {
  onCreateEscrow: (destination: string, amount: string, finishAfter: number) => Promise<void>
  onFinishEscrow: (owner: string, offerSequence: number) => Promise<void>
  onCreateChannel: (destination: string, amount: string, settleDelay: number) => Promise<void>
  onClaimChannel: (channel: string, amountDrops: string) => Promise<void>
}

export function AdvancedPanel({
  onCreateEscrow,
  onFinishEscrow,
  onCreateChannel,
  onClaimChannel,
}: Props) {
  const [escrow, setEscrow] = useState({ destination: '', amount: '', finishAfter: '' })
  const [escrowFinish, setEscrowFinish] = useState({ owner: '', offerSequence: '' })
  const [channelCreate, setChannelCreate] = useState({ destination: '', amount: '', settleDelay: '3600' })
  const [channelClaim, setChannelClaim] = useState({ channel: '', amountDrops: '' })
  const [message, setMessage] = useState<string | null>(null)

  const submitEscrow = async () => {
    try {
      await onCreateEscrow(escrow.destination, escrow.amount, Number(escrow.finishAfter))
      setMessage('EscrowCreate submitted.')
    } catch (err) {
      setMessage(explainXrplError(err))
    }
  }

  const submitEscrowFinish = async () => {
    try {
      await onFinishEscrow(escrowFinish.owner, Number(escrowFinish.offerSequence))
      setMessage('EscrowFinish submitted.')
    } catch (err) {
      setMessage(explainXrplError(err))
    }
  }

  const submitChannelCreate = async () => {
    try {
      await onCreateChannel(
        channelCreate.destination,
        channelCreate.amount,
        Number(channelCreate.settleDelay),
      )
      setMessage('PaymentChannelCreate submitted.')
    } catch (err) {
      setMessage(explainXrplError(err))
    }
  }

  const submitChannelClaim = async () => {
    try {
      await onClaimChannel(channelClaim.channel, channelClaim.amountDrops)
      setMessage('PaymentChannelClaim submitted.')
    } catch (err) {
      setMessage(explainXrplError(err))
    }
  }

  return (
    <div className="space-y-5">
      <div className="grid gap-5 lg:grid-cols-2">
        <Card>
          <SectionTitle title="Escrow Timelocks" subtitle="Create and finish conditional XRP escrow payments." />
          <div className="space-y-3">
            <div>
              <Label>Destination</Label>
              <Input
                value={escrow.destination}
                onChange={(e) => setEscrow((p) => ({ ...p, destination: e.target.value }))}
                placeholder="r..."
              />
            </div>
            <div>
              <Label>Amount XRP</Label>
              <Input
                value={escrow.amount}
                onChange={(e) => setEscrow((p) => ({ ...p, amount: e.target.value }))}
                placeholder="100"
              />
            </div>
            <div>
              <Label>Finish After (Ripple Epoch Seconds)</Label>
              <Input
                value={escrow.finishAfter}
                onChange={(e) => setEscrow((p) => ({ ...p, finishAfter: e.target.value }))}
                placeholder="760000000"
              />
            </div>
            <Button onClick={submitEscrow}>Create Escrow</Button>
          </div>

          <div className="mt-4 border-t border-slate-200 pt-4">
            <Label>Escrow Owner</Label>
            <Input
              value={escrowFinish.owner}
              onChange={(e) => setEscrowFinish((p) => ({ ...p, owner: e.target.value }))}
              placeholder="r..."
            />
            <Label>Offer Sequence</Label>
            <Input
              value={escrowFinish.offerSequence}
              onChange={(e) => setEscrowFinish((p) => ({ ...p, offerSequence: e.target.value }))}
              placeholder="123"
            />
            <Button className="mt-3" variant="secondary" onClick={submitEscrowFinish}>
              Finish Escrow
            </Button>
          </div>
        </Card>

        <Card>
          <SectionTitle
            title="Payment Channels"
            subtitle="Open and claim micropayment channels for high-throughput flows."
          />

          <div className="space-y-3">
            <div>
              <Label>Destination</Label>
              <Input
                value={channelCreate.destination}
                onChange={(e) => setChannelCreate((p) => ({ ...p, destination: e.target.value }))}
                placeholder="r..."
              />
            </div>
            <div>
              <Label>Amount XRP</Label>
              <Input
                value={channelCreate.amount}
                onChange={(e) => setChannelCreate((p) => ({ ...p, amount: e.target.value }))}
                placeholder="500"
              />
            </div>
            <div>
              <Label>Settle Delay (seconds)</Label>
              <Input
                value={channelCreate.settleDelay}
                onChange={(e) => setChannelCreate((p) => ({ ...p, settleDelay: e.target.value }))}
                placeholder="3600"
              />
            </div>
            <Button onClick={submitChannelCreate}>Create Channel</Button>
          </div>

          <div className="mt-4 border-t border-slate-200 pt-4">
            <Label>Channel ID</Label>
            <Input
              value={channelClaim.channel}
              onChange={(e) => setChannelClaim((p) => ({ ...p, channel: e.target.value }))}
              placeholder="ABC..."
            />
            <Label>Claim Balance (drops)</Label>
            <Input
              value={channelClaim.amountDrops}
              onChange={(e) => setChannelClaim((p) => ({ ...p, amountDrops: e.target.value }))}
              placeholder="1000000"
            />
            <Button className="mt-3" variant="secondary" onClick={submitChannelClaim}>
              Claim Channel
            </Button>
          </div>
        </Card>
      </div>

      <Card>
        <SectionTitle
          title="Compliance & Permissioning"
          subtitle="Institutional mode for Permissioned Domains (XLS-80) and gated trading."
        />
        <Notice tone="info">
          This wallet includes a dedicated module placeholder for Permissioned Domains and gated DEX routes. XLS-80 endpoints vary by server support and amendment status, so production deployment should enable this based on your rippled configuration and compliance policy.
        </Notice>
      </Card>

      {message ? <Notice tone="success">{message}</Notice> : null}
    </div>
  )
}
