/**
 * Bound captured HTTP material injected directly into the persistent Proxy Agent
 * prompt. The canonical Request row remains complete and can be fetched on demand.
 */
export function capCapturedRequestField(input: {
  value: string
  label: "request" | "response"
  requestID: string
  maxBytes: number
}): string {
  const source = Buffer.from(input.value, "utf8")
  if (source.byteLength <= input.maxBytes) return input.value

  const marker = [
    "",
    "",
    `[TRUNCATED ${input.label.toUpperCase()}: ${source.byteLength} bytes total; prompt budget ${input.maxBytes} bytes.]`,
    `[The complete capture is preserved. Call web_get_request_detail with request_id "${input.requestID}" and inspect the full ${input.label} before drawing conclusions.]`,
  ].join("\n")
  const markerBytes = Buffer.byteLength(marker, "utf8")
  const budget = Math.max(0, input.maxBytes - markerBytes)
  const headBytes = Math.floor(budget * 0.7)
  const tailBytes = budget - headBytes
  const head = source.subarray(0, headBytes).toString("utf8")
  const tail = tailBytes > 0 ? source.subarray(source.byteLength - tailBytes).toString("utf8") : ""
  return head + marker + (tail ? "\n[END OF CAPTURE TAIL]\n" + tail : "")
}
