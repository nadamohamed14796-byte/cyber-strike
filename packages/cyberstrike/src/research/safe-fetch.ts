import type { ResearchSource } from "./sources"

const MAX_DOCUMENT_BYTES = 1_500_000
const MAX_REDIRECTS = 5
const REQUEST_TIMEOUT_MS = 20_000
const MAX_RETRIES = 2

class NonRetryableResearchError extends Error {}

function hostAllowed(url: URL, source: ResearchSource) {
  return (
    url.protocol === "https:" &&
    !url.username &&
    !url.password &&
    source.hosts.some((host) => url.hostname === host || url.hostname.endsWith("." + host))
  )
}

async function readBoundedText(body: ReadableStream<Uint8Array> | null) {
  if (!body) return ""

  const reader = body.getReader()
  const chunks: Uint8Array[] = []
  let size = 0
  try {
    while (true) {
      const next = await reader.read()
      if (next.done) break
      size += next.value.byteLength
      if (size > MAX_DOCUMENT_BYTES) {
        await reader.cancel().catch(() => undefined)
        throw new NonRetryableResearchError("research document too large")
      }
      chunks.push(next.value)
    }
  } finally {
    reader.releaseLock()
  }

  const bytes = new Uint8Array(size)
  let offset = 0
  for (const chunk of chunks) {
    bytes.set(chunk, offset)
    offset += chunk.byteLength
  }
  return new TextDecoder("utf-8").decode(bytes)
}

/**
 * Fetch public research only from explicitly allowed HTTPS hosts.
 *
 * Redirects are followed manually so a trusted source cannot redirect the
 * crawler to an unrelated host, a plaintext endpoint, or a local service.
 * Response bodies are size-limited while streaming, before they can consume
 * unbounded memory.
 */
export async function fetchResearchText(url: string, source: ResearchSource) {
  const initial = new URL(url)
  if (!hostAllowed(initial, source)) {
    throw new NonRetryableResearchError("blocked research host: " + initial.hostname)
  }

  let lastError: unknown
  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    let current = new URL(url)
    try {
      for (let redirects = 0; ; redirects++) {
        if (!hostAllowed(current, source)) {
          throw new NonRetryableResearchError("blocked research host: " + current.hostname)
        }

        const controller = new AbortController()
        const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS)
        try {
          const response = await fetch(current, {
            signal: controller.signal,
            redirect: "manual",
            headers: {
              accept: "text/html,application/xhtml+xml,text/plain,application/xml;q=0.9,*/*;q=0.8",
              "user-agent": "CyberStrike-Research/2.0 (+public-security-research)",
            },
          })

          if (response.status >= 300 && response.status < 400) {
            const location = response.headers.get("location")
            await response.body?.cancel().catch(() => undefined)
            if (!location) throw new NonRetryableResearchError("research redirect missing Location header")
            if (redirects >= MAX_REDIRECTS) {
              throw new NonRetryableResearchError("too many research redirects")
            }
            const next = new URL(location, current)
            if (!hostAllowed(next, source)) {
              throw new NonRetryableResearchError("blocked research redirect: " + next.hostname)
            }
            current = next
            continue
          }

          if (response.status === 429 || response.status >= 500) {
            await response.body?.cancel().catch(() => undefined)
            throw new Error("HTTP " + response.status)
          }
          if (!response.ok) {
            await response.body?.cancel().catch(() => undefined)
            // Retry throttling and server failures, but do not waste attempts
            // on terminal client errors such as 400/401/403/404.
            throw new NonRetryableResearchError("HTTP " + response.status)
          }

          const contentType = response.headers.get("content-type") ?? ""
          if (!/^(?:text\/html|application\/xhtml\+xml|text\/plain|application\/xml)(?:\s*;|$)/i.test(contentType)) {
            await response.body?.cancel().catch(() => undefined)
            throw new NonRetryableResearchError("unsupported content type: " + contentType)
          }
          const length = Number(response.headers.get("content-length") ?? 0)
          if (length > MAX_DOCUMENT_BYTES) {
            await response.body?.cancel().catch(() => undefined)
            throw new NonRetryableResearchError("research document too large")
          }

          return await readBoundedText(response.body)
        } finally {
          clearTimeout(timer)
        }
      }
    } catch (error) {
      lastError = error
      if (error instanceof NonRetryableResearchError) throw error
      if (attempt < MAX_RETRIES) await Bun.sleep(500 * 2 ** attempt)
    }
  }

  throw lastError instanceof Error ? lastError : new Error(String(lastError))
}
