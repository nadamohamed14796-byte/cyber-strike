/**
 * Deterministic, evidence-preserving preflight for captured HTTP requests.
 *
 * This module never removes a request row. It only identifies cases where a
 * confirmed empty HTML document has no useful attack surface for an LLM turn.
 */
export interface EmptyStaticResponseInput {
  method: string
  responseStatus?: number
  responseContentType?: string
  responseSize?: number
  contentLength?: string
  htmlSource?: string
  rawRequest?: string
  bodyHash?: string
  queryHash?: string
  protocol?: string
  operation?: string
  triggerElement?: string
  elementRoles?: string[]
  uiContext?: Record<string, unknown>
}

function requestHasQueryOrBody(rawRequest: string | undefined): boolean {
  if (!rawRequest) return true
  const normalized = rawRequest.replace(/\r\n/g, "\n")
  const split = normalized.indexOf("\n\n")
  const head = split < 0 ? normalized : normalized.slice(0, split)
  const body = split < 0 ? "" : normalized.slice(split + 2)
  const requestLine = head.split("\n", 1)[0] ?? ""
  const target = requestLine.trim().split(/\s+/)[1] ?? ""
  if (target.includes("?")) return true
  return body.trim().length > 0
}

/**
 * True only when the complete original response is a 2xx HTML document whose
 * remaining content is just an empty document shell and inert metadata.
 * Unknown/truncated/summarized HTML is deliberately not treated as empty.
 */
export function isConfirmedEmptyStaticHTML(input: EmptyStaticResponseInput): boolean {
  if (input.method !== "GET" && input.method !== "HEAD") return false
  if (input.responseStatus === undefined || input.responseStatus < 200 || input.responseStatus >= 300) return false
  if (!input.responseContentType?.toLowerCase().includes("text/html")) return false
  if (input.htmlSource === undefined || input.responseSize === undefined) return false
  if (Buffer.byteLength(input.htmlSource, "utf8") !== input.responseSize) return false
  if (input.contentLength !== undefined) {
    const declaredLength = Number.parseInt(input.contentLength, 10)
    if (!Number.isFinite(declaredLength) || declaredLength !== input.responseSize) return false
  }
  if (input.bodyHash || input.queryHash || input.protocol || input.operation) return false
  if (requestHasQueryOrBody(input.rawRequest)) return false
  if (input.triggerElement || input.elementRoles?.length) return false
  if (input.uiContext && Object.keys(input.uiContext).length > 0) return false

  let remaining = input.htmlSource
    .replace(/^\uFEFF/, "")
    .replace(/<!--[\s\S]*?-->/g, "")
    .replace(/<!doctype\b[^>]*>/gi, "")

  // Scriptable, interactive, navigational, embedded, or externally loaded
  // elements make this a real document even when its visible body is empty.
  if (/<\s*(?:script|form|input|button|select|option|textarea|a|iframe|frame|object|embed|img|picture|video|audio|canvas|svg|link|style|base|template|noscript)\b/i.test(remaining)) {
    return false
  }
  if (/\bon[a-z]+\s*=|\b(?:src|href|action|formaction|srcdoc|background|poster|data|srcset|manifest|style)\s*=/i.test(remaining)) return false
  if (/\bhttp-equiv\s*=\s*["']?refresh\b/i.test(remaining)) return false

  remaining = remaining
    .replace(/<title\b[^>]*>[\s\S]*?<\/title\s*>/gi, "")
    .replace(/<meta\b[^>]*\/?>/gi, "")
    .replace(/<\/?(?:html|head|body)\b[^>]*>/gi, "")

  return remaining.trim().length === 0
}
