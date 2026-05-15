export function explainXrplError(error: unknown): string {
  if (!error) {
    return 'Unknown XRPL error.'
  }

  const text =
    typeof error === 'string'
      ? error
      : error instanceof Error
        ? error.message
        : JSON.stringify(error)

  const normalized = text.toLowerCase()

  if (normalized.includes('tecfail') || normalized.includes('insuf')) {
    return 'Insufficient XRP for the transaction fee or reserve. Fund your wallet and try again.'
  }
  if (normalized.includes('tembadamount')) {
    return 'Invalid amount format. Check decimals and currency precision.'
  }
  if (normalized.includes('tecno_line')) {
    return 'Trustline is missing. Create a trustline before sending this token.'
  }
  if (normalized.includes('tecpath_dry')) {
    return 'No liquidity path found for this trade. Try a smaller amount or another route.'
  }
  if (normalized.includes('telinsuf_fee_p')) {
    return 'Network is currently congested. Increase fee and resubmit.'
  }
  if (normalized.includes('malformed address')) {
    return 'Destination address is invalid.'
  }
  if (normalized.includes('disconnected') || normalized.includes('not connected')) {
    return 'Network connection lost. Reconnect to XRPL and retry.'
  }

  return text
}
