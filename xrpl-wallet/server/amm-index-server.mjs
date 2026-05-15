import express from 'express'
import cors from 'cors'
import { Client, dropsToXrp } from 'xrpl'

const app = express()
app.use(cors())
app.use(express.json())

const PORT = Number(process.env.AMM_INDEX_PORT ?? 8787)
const NETWORKS = {
  mainnet: 'wss://xrplcluster.com',
  testnet: 'wss://s.altnet.rippletest.net:51233',
}

const clients = new Map()
const cache = new Map()

async function getClient(network) {
  const existing = clients.get(network)
  if (existing?.isConnected()) {
    return existing
  }

  const client = existing ?? new Client(NETWORKS[network] ?? NETWORKS.testnet)
  if (!client.isConnected()) {
    await client.connect()
  }

  clients.set(network, client)
  return client
}

function assetRef(value) {
  if (typeof value === 'string') {
    return { symbol: 'XRP' }
  }
  if (value && typeof value === 'object') {
    return {
      symbol: value.currency ?? 'UNK',
      issuer: value.issuer,
    }
  }
  return { symbol: 'UNK' }
}

function amountNumber(value) {
  if (typeof value === 'string') {
    return Number(dropsToXrp(value))
  }
  if (value && typeof value === 'object' && value.value) {
    return Number(value.value)
  }
  return 0
}

async function scanAmmPairs(client, depth = 30) {
  const info = await client.request({ command: 'server_info' })
  const latest = Number(info.result.info?.validated_ledger?.seq ?? 0)
  const pairs = new Set()

  for (let seq = latest; seq > Math.max(0, latest - depth); seq -= 1) {
    const ledger = await client.request({
      command: 'ledger',
      ledger_index: seq,
      transactions: true,
      expand: true,
    })
    const txs = ledger.result.ledger?.transactions ?? []

    txs.forEach((entry) => {
      if (entry.TransactionType !== 'AMMCreate') {
        return
      }
      const a = assetRef(entry.Amount)
      const b = assetRef(entry.Amount2)
      const keyA = a.issuer ? `${a.symbol}:${a.issuer}` : a.symbol
      const keyB = b.issuer ? `${b.symbol}:${b.issuer}` : b.symbol
      pairs.add(`${keyA}|${keyB}`)
    })
  }

  return [...pairs]
}

function parseAsset(value) {
  if (value === 'XRP') {
    return 'XRP'
  }
  const [currency, issuer] = value.split(':')
  return { currency, issuer }
}

async function buildPools(client, pairKeys) {
  const pools = []

  for (const pair of pairKeys) {
    const [aRaw, bRaw] = pair.split('|')
    try {
      const response = await client.request({
        command: 'amm_info',
        asset: parseAsset(aRaw),
        asset2: parseAsset(bRaw),
      })
      const amm = response.result.amm
      const a = assetRef(amm.amount)
      const b = assetRef(amm.amount2)

      pools.push({
        pair,
        amount1: amountNumber(amm.amount),
        amount2: amountNumber(amm.amount2),
        lpTokenSupply: Number(amm.lp_token?.value ?? 0),
        tradingFee: Number(amm.trading_fee ?? 0),
        auctionDiscountedFee: amm.auction_slot?.discounted_fee,
        ammAccount: amm.account,
        asset1Symbol: a.symbol,
        asset1Issuer: a.issuer,
        asset2Symbol: b.symbol,
        asset2Issuer: b.issuer,
      })
    } catch {
      // Pool might not exist on this network or pair.
    }
  }

  return pools
}

async function getIndexedPools(network) {
  const cached = cache.get(network)
  const now = Date.now()
  if (cached && now - cached.updatedAt < 30_000) {
    return cached.pools
  }

  const client = await getClient(network)
  const pairs = await scanAmmPairs(client, 30)
  const pools = await buildPools(client, pairs)
  cache.set(network, { updatedAt: now, pools })
  return pools
}

app.get('/health', (_req, res) => {
  res.json({ ok: true, service: 'amm-index-server' })
})

app.get('/api/amm/pools', async (req, res) => {
  const network = String(req.query.network ?? 'testnet')
  try {
    const pools = await getIndexedPools(network)
    res.json({ network, pools, count: pools.length, indexedAt: new Date().toISOString() })
  } catch (error) {
    res.status(500).json({
      error: error instanceof Error ? error.message : 'Indexing error',
    })
  }
})

app.listen(PORT, () => {
  console.log(`AMM index server listening on http://localhost:${PORT}`)
})
