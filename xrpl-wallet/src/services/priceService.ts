import axios from 'axios'

export async function fetchXrpUsdPrice(): Promise<number> {
  const response = await axios.get<{ ripple: { usd: number } }>(
    'https://api.coingecko.com/api/v3/simple/price?ids=ripple&vs_currencies=usd',
    {
      timeout: 8000,
    },
  )

  return response.data.ripple.usd
}
