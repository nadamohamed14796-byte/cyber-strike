export type BrokerTurnText = {
  messageID: string
  text: string
}

/**
 * Assign each persistent Proxy Broker user turn to its captured request.
 * Ordinary follow-ups inherit the previous request; a panel follow-up can
 * explicitly switch back to an older request with a trusted Current request
 * identity block.
 */
export function requestIDsByBrokerTurn(turns: readonly BrokerTurnText[]) {
  let activeRequestID: string | undefined
  return turns.map((turn) => {
    let inIdentitySection = false
    for (const line of turn.text.split(/\r?\n/)) {
      if (/^## (?:Request Task Identity|Current request)\s*$/.test(line)) {
        inIdentitySection = true
        continue
      }
      if (/^## /.test(line)) {
        if (inIdentitySection) break
        continue
      }
      if (!inIdentitySection) continue
      const match = line.match(/^\s*-\s*(?:Request ID|request_id):\s*([^\r\n]+)\s*$/i)
      if (match?.[1]) {
        activeRequestID = match[1].trim()
        break
      }
    }
    return { messageID: turn.messageID, requestID: activeRequestID }
  })
}
