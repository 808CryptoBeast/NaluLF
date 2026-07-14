import { useMemo, useState } from 'react'
import type { NftAsset, TrustlineBalance } from '../types/wallet'
import { explainXrplError } from '../lib/errors'
import { Button, Card, Input, Label, Notice, SectionTitle } from './ui'

type AssetType = 'xrp' | 'token' | 'nft'

interface Props {
  feeXrp: string
  trustlines: TrustlineBalance[]
  nfts: NftAsset[]
  onSendXrp: (payload: {
    destination: string
    amount: string
    destinationTag?: number
  }) => Promise<void>
  onSendToken: (payload: {
    destination: string
    amount: string
    currency: string
    issuer: string
    destinationTag?: number
  }) => Promise<void>
  onSendNft: (nftId: string, destination: string) => Promise<void>
}

export function SendPanel({
  feeXrp,
  trustlines,
  nfts,
  onSendToken,
  onSendXrp,
  onSendNft,
}: Props) {
  const [assetType, setAssetType] = useState<AssetType>('xrp')
  const [destination, setDestination] = useState('')
  const [amount, setAmount] = useState('')
  const [destinationTag, setDestinationTag] = useState('')
  const [selectedToken, setSelectedToken] = useState('')
  const [selectedNft, setSelectedNft] = useState('')
  const [message, setMessage] = useState<string | null>(null)

  const reserveWarning = useMemo(() => {
    if (assetType === 'token') {
      return 'Token payments require an existing trustline on destination account.'
    }

    if (assetType === 'nft') {
      return 'NFT send creates an NFToken offer transaction. Recipient acceptance may be required.'
    }

    return 'XRP payments draw from liquid XRP only. Keep enough XRP for base + owner reserve.'
  }, [assetType])

  const submit = async () => {
    try {
      setMessage(null)

      if (assetType === 'xrp') {
        await onSendXrp({
          destination,
          amount,
          destinationTag: destinationTag ? Number(destinationTag) : undefined,
        })
        setMessage('XRP payment submitted.')
        return
      }

      if (assetType === 'token') {
        const [currency, issuer] = selectedToken.split('|')
        await onSendToken({
          destination,
          amount,
          currency,
          issuer,
          destinationTag: destinationTag ? Number(destinationTag) : undefined,
        })
        setMessage('Token payment submitted.')
        return
      }

      await onSendNft(selectedNft, destination)
      setMessage('NFT offer submitted.')
    } catch (err) {
      setMessage(explainXrplError(err))
    }
  }

  return (
    <Card>
      <SectionTitle
        title="Send Payment"
        subtitle="Unified XRPL sending flow for XRP, issued tokens, and NFTs."
      />

      <div className="grid gap-4 lg:grid-cols-2">
        <div>
          <Label>Asset Type</Label>
          <select
            value={assetType}
            onChange={(e) => setAssetType(e.target.value as AssetType)}
            className="w-full rounded-xl border border-slate-600 bg-slate-900 px-3 py-2 text-sm"
          >
            <option value="xrp">XRP</option>
            <option value="token">Issued Token / MPT</option>
            <option value="nft">NFT</option>
          </select>
        </div>

        <div>
          <Label>Estimated Fee</Label>
          <Input value={`${feeXrp} XRP`} readOnly />
        </div>
      </div>

      <div className="mt-4 grid gap-4 lg:grid-cols-2">
        <div>
          <Label>Destination Address</Label>
          <Input value={destination} onChange={(e) => setDestination(e.target.value)} placeholder="r..." />
        </div>
        {assetType !== 'nft' ? (
          <div>
            <Label>Amount</Label>
            <Input value={amount} onChange={(e) => setAmount(e.target.value)} placeholder="10" />
          </div>
        ) : null}
      </div>

      {assetType !== 'nft' ? (
        <div className="mt-4">
          <Label>Destination Tag (Optional)</Label>
          <Input
            value={destinationTag}
            onChange={(e) => setDestinationTag(e.target.value)}
            placeholder="12345"
          />
        </div>
      ) : null}

      {assetType === 'token' ? (
        <div className="mt-4">
          <Label>Select Token</Label>
          <select
            className="w-full rounded-xl border border-slate-600 bg-slate-900 px-3 py-2 text-sm"
            value={selectedToken}
            onChange={(e) => setSelectedToken(e.target.value)}
          >
            <option value="">Select token...</option>
            {trustlines.map((line) => (
              <option key={`${line.currency}-${line.issuer}`} value={`${line.currency}|${line.issuer}`}>
                {line.currency} - {line.issuer}
              </option>
            ))}
          </select>
        </div>
      ) : null}

      {assetType === 'nft' ? (
        <div className="mt-4">
          <Label>Select NFT</Label>
          <select
            className="w-full rounded-xl border border-slate-600 bg-slate-900 px-3 py-2 text-sm"
            value={selectedNft}
            onChange={(e) => setSelectedNft(e.target.value)}
          >
            <option value="">Select NFT...</option>
            {nfts.map((nft) => (
              <option key={nft.NFTokenID} value={nft.NFTokenID}>
                {nft.NFTokenID}
              </option>
            ))}
          </select>
        </div>
      ) : null}

      <div className="mt-4 space-y-3">
        <Notice tone="warning">{reserveWarning}</Notice>
        <Button onClick={submit}>Submit Transaction</Button>
      </div>

      {message ? <p className="mt-3 text-sm text-slate-300">{message}</p> : null}
    </Card>
  )
}
