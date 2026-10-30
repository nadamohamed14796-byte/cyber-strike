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
  if (markerBytes >= input.maxBytes) {
    return Buffer.from(marker, "utf8").subarray(0, input.maxBytes).toString("utf8")
  }

  const budget = input.maxBytes - markerBytes
  const headBytes = Math.floor(budget * 0.7)
  const tailBytes = budget - headBytes
  let head = source.subarray(0, headBytes).toString("utf8")
  let tail = tailBytes > 0 ? source.subarray(source.byteLength - tailBytes).toString("utf8") : ""
  const compose = () => head + marker + (tail ? "\n[END OF CAPTURE TAIL]\n" + tail : "")
  let result = compose()

  // UTF-8 boundary replacement can add a few bytes after decoding slices.
  // Keep the promised byte ceiling exact, including for multilingual responses.
  while (Buffer.byteLength(result, "utf8") > input.maxBytes) {
    if (head.length > 0) head = head.slice(0, -1)
    else if (tail.length > 0) tail = tail.slice(1)
    else break
    result = compose()
  }
  return result
}
