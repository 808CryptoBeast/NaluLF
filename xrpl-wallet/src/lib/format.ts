export function formatXrp(drops: string | number): string {
  const xrp = Number(drops) / 1_000_000
  return Number.isFinite(xrp)
    ? new Intl.NumberFormat('en-US', { maximumFractionDigits: 6 }).format(xrp)
    : '0'
}

export function formatCurrency(value: number, code: 'USD' | 'XRP' = 'USD'): string {
  if (!Number.isFinite(value)) {
    return code === 'USD' ? '$0.00' : '0 XRP'
  }

  if (code === 'USD') {
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: 'USD',
      maximumFractionDigits: 2,
    }).format(value)
  }

  return `${new Intl.NumberFormat('en-US', { maximumFractionDigits: 6 }).format(value)} XRP`
}

export function shortAddress(address: string): string {
  if (address.length < 12) {
    return address
  }
  return `${address.slice(0, 6)}...${address.slice(-6)}`
}
