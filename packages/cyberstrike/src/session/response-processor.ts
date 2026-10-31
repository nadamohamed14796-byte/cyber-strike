// Response Processing for HTTP Responses
// Handles truncation, HTML summarization, and binary detection

const MAX_RESPONSE_SIZE = 100 * 1024 // 100 KB

// Headers useful for application analysis
const USEFUL_HEADERS = [
  "content-type",
  "content-length",
  "location",
  "x-powered-by",
  "server",
  "x-request-id",
  "x-correlation-id",
  "www-authenticate",
  "allow",
  "x-ratelimit-limit",
  "x-ratelimit-remaining",
  "retry-after",
]

export interface ResponseInput {
  status: number
  headers: Record<string, string>
  body: string
  /** Optional observed URL/path, used to recognize script responses with incorrect/missing MIME types. */
  url?: string
}

export interface ProcessedResponse {
  status: number
  headers: Record<string, string>
  contentType: string
  originalSize: number
  content: string
  /** Full JavaScript or source-map body for static analysis/correlation; separate from the bounded response preview. */
  javascriptSource?: string
  /** Full HTML body for deterministic preflight; never copied into the LLM preview. */
  htmlSource?: string
  /** Executable inline script bodies extracted from HTML as inert source text. */
  inlineJavaScriptSources?: string[]
}

export function processResponse(input: ResponseInput): ProcessedResponse {
  // 1. Filter headers
  const filteredHeaders = filterHeaders(input.headers)

  // 2. Determine content type
  const contentType = getContentType(input.headers)
  const originalSize = Buffer.byteLength(input.body, "utf-8")

  // 3. Build metadata line
  const metadata = `[Status: ${input.status}, Type: ${contentType}, Size: ${formatSize(originalSize)}]`

  // 4. Process based on content type
  let content: string

  if (isBinary(contentType)) {
    content = `${metadata}\nBinary content: ${contentType}`
  } else if (isHtml(contentType)) {
    content = `${metadata}\nThis is an HTML response`
  } else if (isJson(contentType) || isText(contentType)) {
    if (originalSize > MAX_RESPONSE_SIZE) {
      const truncated = input.body.slice(0, MAX_RESPONSE_SIZE)
      content = `${metadata}\n${truncated}\n[TRUNCATED - showing first 100KB of ${formatSize(originalSize)}]`
    } else {
      content = `${metadata}\n${input.body}`
    }
  } else {
    // Unknown type - treat as text with truncation
    if (originalSize > MAX_RESPONSE_SIZE) {
      const truncated = input.body.slice(0, MAX_RESPONSE_SIZE)
      content = `${metadata}\n${truncated}\n[TRUNCATED - showing first 100KB of ${formatSize(originalSize)}]`
    } else {
      content = `${metadata}\n${input.body}`
    }
  }

  return {
    status: input.status,
    headers: filteredHeaders,
    contentType,
    originalSize,
    content,
    ...(isJavaScriptOrSourceMap(contentType, input.url) ? { javascriptSource: input.body } : {}),
    ...(isHtml(contentType) ? { htmlSource: input.body, inlineJavaScriptSources: extractInlineJavaScriptSources(input.body) } : {}),
  }
}

function filterHeaders(headers: Record<string, string>): Record<string, string> {
  const filtered: Record<string, string> = {}
  for (const [key, value] of Object.entries(headers)) {
    if (USEFUL_HEADERS.includes(key.toLowerCase())) {
      filtered[key.toLowerCase()] = value
    }
  }
  return filtered
}

function getContentType(headers: Record<string, string>): string {
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === "content-type") {
      // Extract main type, ignore charset etc
      return value.split(";")[0].trim()
    }
  }
  return "unknown"
}

function isBinary(contentType: string): boolean {
  const ct = contentType.toLowerCase()
  return (
    ct.startsWith("image/") ||
    ct.startsWith("video/") ||
    ct.startsWith("audio/") ||
    ct.includes("application/octet-stream") ||
    ct.includes("application/pdf") ||
    ct.includes("application/zip") ||
    ct.includes("application/gzip")
  )
}

function isHtml(contentType: string): boolean {
  const type = contentType.toLowerCase()
  return type.includes("text/html") || type.includes("application/xhtml+xml")
}

/** Extract inline executable scripts; JSON-LD, import maps, and data blocks are not JavaScript. */
export function extractInlineJavaScriptSources(html: string): string[] {
  const output: string[] = []
  const pattern = /<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi
  for (const match of html.matchAll(pattern)) {
    const attributes = match[1] ?? ""
    const type = /\btype\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i.exec(attributes)
    const mime = (type?.[1] ?? type?.[2] ?? type?.[3] ?? "").split(";", 1)[0]!.trim().toLowerCase()
    if (mime && ![
      "module",
      "text/javascript",
      "application/javascript",
      "text/ecmascript",
      "application/ecmascript",
      "application/x-javascript",
    ].includes(mime)) continue
    const source = (match[2] ?? "").trim()
    if (source) output.push(source)
  }
  return output
}

function isJson(contentType: string): boolean {
  const ct = contentType.toLowerCase()
  return ct.includes("application/json") || ct.includes("+json")
}

function isJavaScriptOrSourceMap(contentType: string, url?: string): boolean {
  const ct = contentType.toLowerCase()
  const scriptMimeType = ct.includes("javascript") || ct.includes("ecmascript") || ct === "text/jscript"
  const sourceMapMimeType = /(?:application\/(?:x-)?source-map\+json|text\/x-source-map)/i.test(ct)
  const pathname = (url ?? "").split(/[?#]/, 1)[0] ?? ""
  return scriptMimeType || sourceMapMimeType || /\.(?:m?js|cjs|map)$/i.test(pathname)
}

function isText(contentType: string): boolean {
  const ct = contentType.toLowerCase()
  return ct.startsWith("text/") || ct.includes("xml") || ct.includes("javascript")
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} bytes`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}
