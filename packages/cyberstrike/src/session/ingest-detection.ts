/**
 * Distinguish a malformed captured HTTP request from ordinary text sent to
 * the ingest endpoint. A failed HTTP parse must never fall through into the
 * parent chat transcript, where it could steal the active text window.
 */
export function looksLikeHTTPRequest(rawText: string, hasHTTPMetadata = false): boolean {
  if (hasHTTPMetadata) return true

  const lines = rawText.split(/\r?\n/)
  const requestLine = (lines[0] ?? "").trim()
  if (!requestLine) return false

  const validRequestLine = /^[A-Z][A-Z0-9!#$%&'*+.^_`|~-]{0,31}\s+\S+\s+HTTP\/\d(?:\.\d)?$/i
  if (validRequestLine.test(requestLine)) return true

  // Still classify common damaged/truncated captures as HTTP when the first
  // line resembles "GET /path" and following lines contain HTTP headers.
  const partialRequestLine = /^[A-Z][A-Z0-9!#$%&'*+.^_`|~-]{0,31}\s+\S+$/i
  const headerLine = /^(?:host|user-agent|accept|content-type|content-length|authorization|cookie|origin|referer|connection|transfer-encoding)\s*:/i
  return partialRequestLine.test(requestLine) && lines.slice(1).some((line) => headerLine.test(line.trim()))
}
