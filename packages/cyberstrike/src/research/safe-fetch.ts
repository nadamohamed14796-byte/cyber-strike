import { researchSourceHostAllowed, researchSourcePathAllowed, type ResearchSource } from "./sources"
import { Database, and, desc, eq, inArray, isNotNull, like, or, sql } from "../storage/db"
import { RequestTable, WebCredentialTable } from "../session/session.sql"
import { lookup } from "node:dns/promises"
import { isIP } from "node:net"

const MAX_DOCUMENT_BYTES = 1_500_000
const MAX_REDIRECTS = 5
const REQUEST_TIMEOUT_MS = 20_000
const MAX_TOTAL_FETCH_MS = 120_000
const MAX_RETRIES = 2

class NonRetryableResearchError extends Error {}

export function isNonRetryableResearchError(error: unknown): boolean {
  return error instanceof NonRetryableResearchError
}

type ResearchCredentialSource = Pick<ResearchSource, "id"> & Partial<Pick<ResearchSource, "hosts" | "exactHosts">>

function safeCookieValue(value: unknown) {
  if (typeof value !== "string") return undefined
  const cookie = value.trim()
  return cookie && cookie.length <= 16_384 && !/[\r\n\0]/.test(cookie) ? cookie : undefined
}

function cookieFromHeaders(headers: Record<string, string> | null | undefined) {
  if (!headers) return undefined
  const entry = Object.entries(headers).find(([name]) => name.toLowerCase() === "cookie")
  return safeCookieValue(entry?.[1])
}

/** Extract only the Cookie header from a captured request; never return or log the raw request. */
function cookieFromRawRequest(rawRequest: string | null | undefined) {
  if (!rawRequest) return undefined
  const headerBlock = rawRequest.split(/\r?\n\r?\n/, 1)[0] ?? ""
  const lines = headerBlock.split(/\r?\n/)
  for (const line of lines.slice(1)) {
    const separator = line.indexOf(":")
    if (separator < 1 || line.slice(0, separator).trim().toLowerCase() !== "cookie") continue
    const cookie = safeCookieValue(line.slice(separator + 1))
    if (cookie) return cookie
  }
  return undefined
}

function capturedSessionRequests(sessionIDs: readonly string[], hostname?: string) {
  const ids = [...new Set(sessionIDs.map((id) => id.trim()).filter(Boolean))]
  if (!ids.length) return []
  const sessionPredicate = inArray(RequestTable.session_id, ids)
  const cookiePredicate = or(
    isNotNull(RequestTable.credential_id),
    like(RequestTable.raw_request, "%cookie:%"),
  )!
  return Database.use((db) => db
    .select({
      host: RequestTable.host,
      rawRequest: RequestTable.raw_request,
      credentialHeaders: WebCredentialTable.headers,
    })
    .from(RequestTable)
    .leftJoin(WebCredentialTable, and(
      eq(WebCredentialTable.id, RequestTable.credential_id),
      eq(WebCredentialTable.session_id, RequestTable.session_id),
    ))
    .where(hostname
      ? and(sessionPredicate, sql`lower(${RequestTable.host}) = ${hostname.toLowerCase()}`, cookiePredicate)
      : and(sessionPredicate, cookiePredicate))
    .orderBy(desc(RequestTable.time_updated))
    .all())
}

/**
 * Reuse a cookie already captured by CyberStrike only for requests to the exact
 * hostname on which it was observed. The secret remains in memory and is never
 * copied to research queue rows, prompts, logs, or knowledge records.
 */
export function researchSessionCookieForHost(sessionIDs: readonly string[], hostname: string) {
  const normalizedHost = hostname.trim().toLowerCase().replace(/\.$/, "")
  if (!normalizedHost || /[^a-z0-9.:-]/i.test(normalizedHost)) return undefined
  const rows = capturedSessionRequests(sessionIDs, normalizedHost)
  for (const row of rows) {
    if (!row.host || row.host.toLowerCase().replace(/\.$/, "") !== normalizedHost) continue
    const cookie = cookieFromHeaders(row.credentialHeaders) ?? cookieFromRawRequest(row.rawRequest)
    if (cookie) return cookie
  }
  return undefined
}

/** Hostnames only; useful for status output without ever disclosing a cookie value. */
export function researchSessionCookieHosts(sessionIDs: readonly string[]) {
  const rows = capturedSessionRequests(sessionIDs)
  const hosts = new Set<string>()
  for (const row of rows) {
    const hostname = row.host?.trim().toLowerCase().replace(/\.$/, "")
    if (!hostname) continue
    if (cookieFromHeaders(row.credentialHeaders) || cookieFromRawRequest(row.rawRequest)) hosts.add(hostname)
  }
  return [...hosts]
}

export function researchSourceHasCredentials(source: ResearchCredentialSource, sessionIDs: readonly string[] = []): boolean {
  const suffix = source.id.toUpperCase().replace(/[^A-Z0-9]+/g, "_")
  if (
    process.env["CYBERSTRIKE_RESEARCH_COOKIE_" + suffix]?.trim() ||
    process.env["CYBERSTRIKE_RESEARCH_AUTHORIZATION_" + suffix]?.trim()
  ) return true
  if (!source.hosts?.length || !sessionIDs.length) return false
  return researchSessionCookieHosts(sessionIDs).some((hostname) =>
    researchSourceHostAllowed("https://" + hostname, {
      hosts: source.hosts!,
      exactHosts: source.exactHosts,
    }),
  )
}

export type ResearchLookup = (hostname: string) => Promise<Array<{ address: string; family: number }>>

const systemRanges: Array<[string, number]> = [
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10],
  ["127.0.0.0", 8],
  ["169.254.0.0", 16],
  ["172.16.0.0", 12],
  ["192.0.0.0", 24],
  ["192.0.2.0", 24],
  ["192.88.99.0", 24],
  ["192.168.0.0", 16],
  ["198.18.0.0", 15],
  ["198.51.100.0", 24],
  ["203.0.113.0", 24],
  ["224.0.0.0", 4],
  ["240.0.0.0", 4],
]

function ipv4Number(value: string): number | undefined {
  const parts = value.split(".")
  if (parts.length !== 4 || parts.some((part) => !/^\d{1,3}$/.test(part))) return undefined
  const octets = parts.map(Number)
  if (octets.some((octet) => octet < 0 || octet > 255)) return undefined
  return (((octets[0] * 256 + octets[1]) * 256 + octets[2]) * 256 + octets[3])
}

function ipv6Number(value: string): bigint | undefined {
  let address = value.toLowerCase().split("%")[0] ?? ""
  // Expand an embedded IPv4 tail into its two hexadecimal groups.
  if (address.includes(".")) {
    const separator = address.lastIndexOf(":")
    if (separator < 0) return undefined
    const ipv4 = ipv4Number(address.slice(separator + 1))
    if (ipv4 === undefined) return undefined
    const high = Math.floor(ipv4 / 65_536).toString(16)
    const low = (ipv4 % 65_536).toString(16)
    address = address.slice(0, separator + 1) + high + ":" + low
  }

  const sections = address.split("::")
  if (sections.length > 2) return undefined
  const left = sections[0] ? sections[0].split(":") : []
  const right = sections.length === 2 && sections[1] ? sections[1].split(":") : []
  const missing = 8 - left.length - right.length
  if ((sections.length === 1 && missing !== 0) || (sections.length === 2 && missing < 1)) return undefined
  const groups = [...left, ...Array(missing).fill("0"), ...right]
  if (groups.length !== 8 || groups.some((group) => !/^[0-9a-f]{1,4}$/i.test(group))) return undefined
  return groups.reduce((result, group) => (result << 16n) | BigInt(Number.parseInt(group, 16)), 0n)
}

function ipv6InRange(address: string, base: string, prefix: number): boolean {
  const value = ipv6Number(address)
  const network = ipv6Number(base)
  if (value === undefined || network === undefined || prefix < 0 || prefix > 128) return false
  const shift = BigInt(128 - prefix)
  return (value >> shift) === (network >> shift)
}

/** Public unicast addresses only; reject reserved, local, documentation and transition ranges. */
export function isPublicResearchAddress(address: string): boolean {
  const family = isIP(address)
  if (family === 4) {
    const value = ipv4Number(address)
    if (value === undefined) return false
    return !systemRanges.some(([baseText, prefix]) => {
      const base = ipv4Number(baseText)!
      const width = 2 ** (32 - prefix)
      return Math.floor(value / width) === Math.floor(base / width)
    })
  }
  if (family !== 6) return false

  const normalized = address.toLowerCase().split("%")[0]
  if (normalized.startsWith("::ffff:")) {
    const mapped = normalized.slice("::ffff:".length)
    if (mapped.includes(".")) return isPublicResearchAddress(mapped)
    const hex = mapped.split(":").filter(Boolean)
    if (hex.length === 2) {
      const hi = Number.parseInt(hex[0], 16)
      const lo = Number.parseInt(hex[1], 16)
      if (!Number.isFinite(hi) || !Number.isFinite(lo)) return false
      return isPublicResearchAddress([
        (hi >> 8) & 255, hi & 255, (lo >> 8) & 255, lo & 255,
      ].join("."))
    }
    return false
  }

  // Only currently allocated global-unicast 2000::/3 is eligible. Parse the full
  // address so expanded IPv6 spellings cannot bypass the special-purpose deny list.
  if (ipv6Number(normalized) === undefined || !ipv6InRange(normalized, "2000::", 3)) return false

  // Deny IANA special-purpose allocations, documentation space, and 6to4.
  if (
    ipv6InRange(normalized, "2001::", 23) ||
    ipv6InRange(normalized, "2001:db8::", 32) ||
    ipv6InRange(normalized, "2002::", 16) ||
    ipv6InRange(normalized, "3fff::", 20)
  ) return false
  return true
}

async function defaultResearchLookup(hostname: string) {
  return lookup(hostname, { all: true, verbatim: true })
}

async function assertPublicDestination(url: URL, resolveHost: ResearchLookup) {
  const hostname = url.hostname.replace(/^\[|\]$/g, "").replace(/\.$/, "").toLowerCase()
  const literalFamily = isIP(hostname)
  if (literalFamily) {
    if (!isPublicResearchAddress(hostname)) {
      throw new NonRetryableResearchError("blocked non-public research destination: " + hostname)
    }
    return
  }

  const addresses = await resolveHost(hostname)
  if (!addresses.length || addresses.some((entry) => !isPublicResearchAddress(entry.address))) {
    throw new NonRetryableResearchError("blocked research host resolving to a non-public address: " + hostname)
  }
}

function hostAllowed(url: URL, source: ResearchSource) {
  return (
    url.protocol === "https:" &&
    // Research adapters should fetch normal web pages, not arbitrary HTTPS services
    // exposed on alternate ports by a source hostname.
    (!url.port || url.port === "443") &&
    !url.username &&
    !url.password &&
    researchSourceHostAllowed(url, source) &&
    researchSourcePathAllowed(url, source)
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
export async function fetchResearchText(url: string, source: ResearchSource, resolveHost: ResearchLookup = defaultResearchLookup, sessionIDs: readonly string[] = []) {
  const initial = new URL(url)
  if (!hostAllowed(initial, source)) {
    throw new NonRetryableResearchError("blocked research host: " + initial.hostname)
  }

  // Resolve captured session cookies once per exact initial host. A redirect to a
  // different allowlisted hostname must not inherit these credentials.
  const capturedCookie = researchSessionCookieForHost(sessionIDs, initial.hostname)

  // Bound a whole document fetch, including redirects and retries, so a
  // worker cannot hold a queue lease indefinitely on a slow trusted host.
  const deadline = Date.now() + MAX_TOTAL_FETCH_MS
  let lastError: unknown
  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    let current = new URL(url)
    try {
      for (let redirects = 0; ; redirects++) {
        if (!hostAllowed(current, source)) {
          throw new NonRetryableResearchError("blocked research host: " + current.hostname)
        }
        // DNS checks are repeated after every redirect. Never request a source URL
        // that resolves to loopback, private, link-local, multicast, or reserved space.
        await assertPublicDestination(current, resolveHost)

        const remainingMs = deadline - Date.now()
        if (remainingMs <= 0) {
          throw new NonRetryableResearchError("research fetch exceeded total time budget")
        }
        const controller = new AbortController()
        const timer = setTimeout(() => controller.abort(), Math.min(REQUEST_TIMEOUT_MS, remainingMs))
        try {
          const sourceSuffix = source.id.toUpperCase().replace(/[^A-Z0-9]+/g, "_")
          const headers: Record<string, string> = {
            accept: "text/html,application/xhtml+xml,text/plain,application/xml;q=0.9,*/*;q=0.8",
            "user-agent": "CyberStrike-Research/2.0 (+public-security-research)",
          }
          // Optional source-scoped operator credentials are never persisted. Do not auto-register or bypass MFA/CAPTCHA.
          const cookie = process.env["CYBERSTRIKE_RESEARCH_COOKIE_" + sourceSuffix]
          const authorization = process.env["CYBERSTRIKE_RESEARCH_AUTHORIZATION_" + sourceSuffix]
          // Source-scoped operator credentials and captured cookies are sent only to
          // the exact initial hostname, never across a redirect to another host.
          if (current.hostname === initial.hostname) {
            const selectedCookie = safeCookieValue(cookie) ?? capturedCookie
            if (selectedCookie) headers.cookie = selectedCookie
            if (authorization?.trim()) headers.authorization = authorization.trim()
          }
          const response = await fetch(current, { signal: controller.signal, redirect: "manual", headers })

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
