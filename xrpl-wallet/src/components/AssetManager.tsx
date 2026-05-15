import { useState } from 'react'
import { explainXrplError } from '../lib/errors'
import type { NftAsset, TrustlineBalance } from '../types/wallet'
import { Button, Card, Input, Label, Notice, SectionTitle } from './ui'

interface Props {
  trustlines: TrustlineBalance[]
  nfts: NftAsset[]
  onCreateTrustline: (currency: string, issuer: string, limit: string) => Promise<void>
  onSendToken: (payload: {
    destination: string
    amount: string
    currency: string
    issuer: string
    destinationTag?: number
  }) => Promise<void>
  onSendNft: (nftId: string, destination: string) => Promise<void>
}

export function AssetManager({
  trustlines,
  nfts,
  onCreateTrustline,
  onSendToken,
  onSendNft,
}: Props) {
  const [trustlineCurrency, setTrustlineCurrency] = useState('')
  const [trustlineIssuer, setTrustlineIssuer] = useState('')
  const [trustlineLimit, setTrustlineLimit] = useState('1000000')
  const [tokenDestination, setTokenDestination] = useState('')
  const [tokenAmount, setTokenAmount] = useState('')
  const [selectedToken, setSelectedToken] = useState<string>('')
  const [tokenTag, setTokenTag] = useState('')
  const [nftDestination, setNftDestination] = useState('')
  const [selectedNft, setSelectedNft] = useState<string>('')
  const [message, setMessage] = useState<string | null>(null)

  const sendToken = async () => {
    try {
      const [currency, issuer] = selectedToken.split('|')
      await onSendToken({
        destination: tokenDestination,
        amount: tokenAmount,
        currency,
        issuer,
        destinationTag: tokenTag ? Number(tokenTag) : undefined,
      })
      setMessage('Token payment submitted successfully.')
    } catch (err) {
      setMessage(explainXrplError(err))
    }
  }

  const createTrustlineAction = async () => {
    try {
      await onCreateTrustline(trustlineCurrency, trustlineIssuer, trustlineLimit)
      setMessage('Trustline transaction submitted.')
    } catch (err) {
      setMessage(explainXrplError(err))
    }
  }

  const sendNftAction = async () => {
    try {
      await onSendNft(selectedNft, nftDestination)
      setMessage('NFT transfer offer created.')
    } catch (err) {
      setMessage(explainXrplError(err))
    }
  }

  return (
    <div className="space-y-5">
      <Card>
        <SectionTitle
          title="XRPL Tokens"
          subtitle="Trustlines from account_lines including issued tokens and MPT balances where supported."
        />

        <div className="overflow-auto">
          <table className="min-w-full text-left text-sm">
            <thead className="border-b border-slate-200 text-xs uppercase tracking-wide text-slate-500">
              <tr>
                <th className="py-2 pr-3">Currency</th>
                <th className="py-2 pr-3">Issuer</th>
                <th className="py-2 pr-3">Balance</th>
                <th className="py-2">Limit</th>
              </tr>
            </thead>
            <tbody>
              {trustlines.map((line) => (
                <tr key={`${line.currency}-${line.issuer}`} className="border-b border-slate-100 text-slate-700">
                  <td className="py-2 pr-3 font-medium text-slate-900">{line.currency}</td>
                  <td className="py-2 pr-3">{line.issuer}</td>
                  <td className="py-2 pr-3">{line.balance}</td>
                  <td className="py-2">{line.limit}</td>
                </tr>
              ))}
              {!trustlines.length ? (
                <tr>
                  <td colSpan={4} className="py-3 text-slate-500">
                    No trustlines yet.
                  </td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>
      </Card>

      <div className="grid gap-5 lg:grid-cols-2">
        <Card>
          <SectionTitle title="Create Trustline" subtitle="Warning: trustlines consume owner reserve (~2 XRP)." />
          <div className="space-y-3">
            <div>
              <Label>Currency Code</Label>
              <Input value={trustlineCurrency} onChange={(e) => setTrustlineCurrency(e.target.value)} placeholder="USD" />
            </div>
            <div>
              <Label>Issuer Address</Label>
              <Input value={trustlineIssuer} onChange={(e) => setTrustlineIssuer(e.target.value)} placeholder="r..." />
            </div>
            <div>
              <Label>Limit</Label>
              <Input value={trustlineLimit} onChange={(e) => setTrustlineLimit(e.target.value)} placeholder="1000000" />
            </div>
            <Notice tone="warning">This action may lock 2 XRP reserve until the trustline is removed.</Notice>
            <Button onClick={createTrustlineAction}>Create Trustline</Button>
          </div>
        </Card>

        <Card>
          <SectionTitle title="Send Issued Token" subtitle="Send any token from your trustline list." />
          <div className="space-y-3">
            <div>
              <Label>Select Token</Label>
              <select
                className="w-full rounded-xl border border-slate-300 bg-white px-3 py-2 text-sm"
                value={selectedToken}
                onChange={(e) => setSelectedToken(e.target.value)}
              >
                <option value="">Select token...</option>
                {trustlines.map((line) => (
                  <option value={`${line.currency}|${line.issuer}`} key={`${line.currency}-${line.issuer}`}>
                    {line.currency} - {line.issuer}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <Label>Destination</Label>
              <Input value={tokenDestination} onChange={(e) => setTokenDestination(e.target.value)} placeholder="r..." />
            </div>
            <div>
              <Label>Amount</Label>
              <Input value={tokenAmount} onChange={(e) => setTokenAmount(e.target.value)} placeholder="25" />
            </div>
            <div>
              <Label>Destination Tag (Optional)</Label>
              <Input value={tokenTag} onChange={(e) => setTokenTag(e.target.value)} placeholder="12345" />
            </div>
            <Button onClick={sendToken} disabled={!selectedToken}>
              Send Token
            </Button>
          </div>
        </Card>
      </div>

      <Card>
        <SectionTitle title="NFT Gallery" subtitle="Owned NFTs fetched with account_nfts." />
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
          {nfts.map((nft) => (
            <button
              key={nft.NFTokenID}
              type="button"
              onClick={() => setSelectedNft(nft.NFTokenID)}
              className={`rounded-xl border p-3 text-left transition ${
                selectedNft === nft.NFTokenID
                  ? 'border-teal-600 bg-teal-50'
                  : 'border-slate-200 bg-slate-50 hover:border-slate-300'
              }`}
            >
              <p className="text-xs uppercase tracking-wide text-slate-500">NFTokenID</p>
              <p className="mt-1 break-all text-sm font-medium text-slate-900">{nft.NFTokenID}</p>
              <p className="mt-2 text-xs text-slate-600">Issuer: {nft.Issuer}</p>
            </button>
          ))}
          {!nfts.length ? <p className="text-sm text-slate-500">No NFTs in this account.</p> : null}
        </div>

        <div className="mt-4 grid gap-3 md:grid-cols-[2fr_1fr]">
          <div>
            <Label>Destination Address</Label>
            <Input value={nftDestination} onChange={(e) => setNftDestination(e.target.value)} placeholder="r..." />
          </div>
          <div className="flex items-end">
            <Button onClick={sendNftAction} disabled={!selectedNft} className="w-full">
              Send Selected NFT
            </Button>
          </div>
        </div>
      </Card>

      {message ? <Notice tone="info">{message}</Notice> : null}
    </div>
  )
}
