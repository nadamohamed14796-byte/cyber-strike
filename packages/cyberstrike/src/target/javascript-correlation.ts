import { createHash } from "node:crypto"
import fs from "node:fs/promises"
import path from "node:path"
import { and, desc, eq, inArray } from "../storage/db"
import { Database } from "../storage/db"
import { Instance } from "../project/instance"
import { Session } from "../session"
import { SessionTable, RequestTable, RequestJavaScriptCaptureTable, RequestObservationTable, WebFunctionTable, VulnerabilityTable } from "../session/session.sql"
import { IntelEntryTable } from "../methodology/methodology.sql"
import { TargetMemory } from "./index"
import { analyzeJavaScriptSource, normalizeJavaScriptEndpointPath, type JavaScriptSourceAnalysis, type JavaScriptRequestCandidate, type JavaScriptFunctionCandidate, type JavaScriptSecretCandidate, type JavaScriptRoleHint, type JavaScriptRiskSignal, type JavaScriptApplicationHint, type JavaScriptWorkflowSignal } from "./javascript-analysis"
import { createJavaScriptScenarioCandidates, type JavaScriptScenarioCandidate } from "./javascript-scenarios"

/**
 * SQLite builds have a finite bind-parameter budget. Split IN lists into safe
 * query batches, then combine and sort the complete result; this is not a result cap.
 */
const SQLITE_IN_BATCH_SIZE = 500
function chunkForSQLiteIn<T>(values: readonly T[], size = SQLITE_IN_BATCH_SIZE): T[][] {
  const output: T[][] = []
  for (let offset = 0; offset < values.length; offset += size) {
    output.push(values.slice(offset, offset + size))
  }
  return output
}
function newestFirst<T extends { time_updated: number }>(rows: T[]): T[] {
  return rows.sort((a, b) => b.time_updated - a.time_updated)
}

function safeURL(input?: string | null): URL | undefined {
  if (!input?.trim()) return undefined
  try {
    const value = input.trim()
    // Request.host is stored as a bare hostname in legacy captures; normalize that
    // form here without treating relative paths as URLs.
    const candidate = /^[a-z][a-z\d+.-]*:\/\//i.test(value) ? value : value.includes("/") || value.includes("?") || value.includes("#") ? "" : "https://" + value
    if (!candidate) return undefined
    const url = new URL(candidate)
    if (url.protocol !== "http:" && url.protocol !== "https:") return undefined
    if (url.username || url.password) return undefined
    return url
  } catch {
    return undefined
  }
}

/** Resolve the actual request origin without mistaking the page that triggered it for the request host. */
export function isSourceMapResponse(contentType?: string | null, pathValue?: string | null): boolean {
  return /(?:application\/(?:x-)?source-map\+json|text\/x-source-map)/i.test(contentType ?? "") ||
    /\.map(?:[?#]|$)/i.test(pathValue ?? "")
}

export function isJavaScriptOrSourceMapResponse(contentType?: string | null, pathValue?: string | null): boolean {
  return isSourceMapResponse(contentType, pathValue) ||
    /(?:java|ecma)script|x-javascript/i.test(contentType ?? "") ||
    /\.(?:m?js|cjs)(?:[?#]|$)/i.test(pathValue ?? "")
}

function observedRequestBaseURL(input: {
  origin?: string | null
  scheme?: string | null
  host?: string | null
  port?: number | null
  pageURL?: string | null
}): URL | undefined {
  const explicitOrigin = safeURL(input.origin)
  if (explicitOrigin) return explicitOrigin
  const pageURL = safeURL(input.pageURL)
  const host = input.host?.trim()
  if (host) {
    if (/^https?:\/\//i.test(host)) return safeURL(host)
    const hostAlreadyHasPort = /(?:\]:\d+|:\d+)$/.test(host)
    const portPart = input.port && !hostAlreadyHasPort ? ":" + input.port : ""
    const scheme = input.scheme || pageURL?.protocol.replace(/:$/, "") || "https"
    const fromHost = safeURL(scheme + "://" + host + portPart)
    if (fromHost) return fromHost
  }
  return pageURL
}

/** Match a captured request to one explicit JavaScript asset by exact origin and path. */
export function matchesCapturedJavaScriptAsset(input: {
  origin?: string | null
  pageURL?: string | null
  host?: string | null
  scheme?: string | null
  port?: number | null
  normalizedPath?: string | null
}, target: string | URL): boolean {
  const targetURL = target instanceof URL ? target : safeURL(target)
  if (!targetURL) return false
  const base = observedRequestBaseURL(input)
  if (!base || !input.normalizedPath?.trim()) return false
  let observed: URL
  try {
    observed = new URL(input.normalizedPath, base)
  } catch {
    return false
  }
  return observed.origin === targetURL.origin && observed.pathname === targetURL.pathname
}

function javascriptAssetURL(input: { type?: string | null; title?: string | null; detail?: string | null; asset?: string | null; tags?: string[] | null }): URL | undefined {
  const base = safeURL(input.asset)
  if (base && /\.(?:m?js|cjs|map)$/i.test(base.pathname)) return base

  // Intel's asset field is usually a target host, not a JavaScript file URL.
  // Resolve an actual script path from title/detail instead of labeling the host as a JS asset.
  const text = [input.title, input.detail].filter(Boolean).join("\n")
  const absolute = /https?:\/\/[^\s"'<>),\x60]+\.(?:m?js|cjs|map)(?:\?[^\s"'<>)]*)?/gi
  for (const match of text.matchAll(absolute)) {
    const url = safeURL(match[0].replace(/[.,;]+$/, ""))
    if (url && /\.(?:m?js|cjs|map)$/i.test(url.pathname)) return url
  }

  const relative = /(?:^|[\s"'(\x60=:])((?:\/|\.{1,2}\/)?[A-Za-z0-9_@.%+/-]+\.(?:m?js|cjs|map)(?:\?[^\s"'<>)]*)?)/gi
  for (const match of text.matchAll(relative)) {
    const candidate = match[1]
    const direct = safeURL(candidate)
    if (direct && /\.(?:m?js|cjs|map)$/i.test(direct.pathname)) return direct
    if (base) {
      try {
        const resolved = new URL(candidate, base)
        if ((resolved.protocol === "http:" || resolved.protocol === "https:") && /\.(?:m?js|cjs|map)$/i.test(resolved.pathname)) return resolved
      } catch {}
    }
  }

  const signal = [input.type, input.title, ...(input.tags ?? [])].filter(Boolean).join(" ").toLowerCase()
  if (!/\bjavascript\b|\bjavascript[-_ ]?file\b|\bjs[-_ ]?asset\b|\bscript[-_ ]?asset\b/.test(signal)) return undefined
  const titlePath = input.title?.trim()
  if (base && titlePath && /\.(?:m?js|cjs|map)(?:$|[?#])/i.test(titlePath) && !/https?:\/\//i.test(titlePath)) {
    try {
      const resolved = new URL(titlePath, base)
      if (resolved.protocol === "http:" || resolved.protocol === "https:") return resolved
    } catch {}
  }
  return undefined
}

function redact(value?: string | null, max = 320): string | null {
  if (!value) return null
  return value
    // Redact complete quoted values (including whitespace and escaped quotes) before generic assignments.
    .replace(/(["']?(?:authorization|proxy-authorization|x-auth-token|x-access-token|x-csrf-token|cookie|set-cookie|x-api-key|api[_-]?(?:key|secret)|access[_-]?token|refresh[_-]?token|id[_-]?token|auth[_-]?token|token|jwt|client[_-]?secret|webhook[_-]?secret|signing[_-]?key|encryption[_-]?key|private[_-]?key|secret[_-]?key|password|passwd|pwd|secret|session(?:[_-]?id)?|csrf(?:[_-]?token)?)["']?\s*:\s*)(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^,\s;}]+)/gi, "$1[REDACTED]")
    .replace(/\b(authorization|proxy-authorization|x-auth-token|x-access-token|x-csrf-token|cookie|set-cookie|x-api-key|api[_-]?(?:key|secret)|access[_-]?token|refresh[_-]?token|id[_-]?token|auth[_-]?token|token|jwt|client[_-]?secret|webhook[_-]?secret|signing[_-]?key|encryption[_-]?key|private[_-]?key|secret[_-]?key|password|passwd|pwd|secret|session(?:[_-]?id)?|csrf(?:[_-]?token)?)\s*[:=]\s*[^\r\n,;]+/gi, "$1: [REDACTED]")
    .replace(/\bBearer\s+[A-Za-z0-9._~+/=-]+/gi, "Bearer [REDACTED]")
    .replace(/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, "[JWT REDACTED]")
    .replace(/[\r\n]/g, " ")
    .slice(0, max)
}

/** Never store JavaScript source previews in the attack-surface graph or target notes. */
export function safeCorrelationResponsePreview(input: {
  id: string
  normalizedPath?: string | null
  responseContentType?: string | null
  processedResponse?: string | null
}, max = 320): string | null {
  if (!input.processedResponse) return null
  if (isJavaScriptOrSourceMapResponse(input.responseContentType, input.normalizedPath)) {
    return "[JavaScript/source-map response preview omitted; inspect captured request ID " + input.id + " on demand]"
  }
  return redact(input.processedResponse, max)
}

function sameHost(left: string | null | undefined, right: string | null | undefined) {
  const a = safeURL(left)
  const b = safeURL(right)
  return Boolean(a && b && a.hostname.toLowerCase() === b.hostname.toLowerCase())
}

function pathWithinScope(candidate: string | null | undefined, scopedPath: string): boolean {
  const value = candidate?.split(/[?#]/, 1)[0]
  if (!value) return false
  const base = scopedPath.replace(/\/$/, "") || "/"
  if (base === "/") return true
  return value === base || value.startsWith(base + "/")
}

/** Local correlation boundary only; this does not replace the existing scope engine. */
/** Keep in-scope hostnames as candidates until the authoritative scope engine decides. */
export function selectJavaScriptAssetsForCorrelation<T extends { url: URL }>(
  candidates: readonly T[],
  explicitURL?: URL,
): T[] {
  if (!explicitURL) return [...candidates]
  return candidates.filter((item) =>
    item.url.origin === explicitURL.origin && item.url.pathname === explicitURL.pathname,
  )
}

export function isJavaScriptAssetAllowed(input: {
  targetURL: string
  javascriptURL: string
  alreadyObserved?: boolean
}): boolean {
  const target = safeURL(input.targetURL)
  const script = safeURL(input.javascriptURL)
  if (!target || !script) return false
  const hostMatches = script.hostname === target.hostname || script.hostname.endsWith("." + target.hostname)
  const targetPath = target.pathname.replace(/\/$/, "") || "/"
  const pathMatches =
    targetPath === "/" ||
    script.hostname !== target.hostname ||
    pathWithinScope(script.pathname, targetPath)
  return (hostMatches && pathMatches) || input.alreadyObserved === true
}

function normalizeEndpointLiteral(value: string): string | undefined {
  const trimmed = value.trim()
  if (!trimmed) return undefined
  const absolute = safeURL(trimmed)
  if (absolute) {
    if (/\.map$/i.test(absolute.pathname)) return undefined
    const normalizedPath = normalizeJavaScriptEndpointPath(absolute.pathname).path
    return absolute.origin + normalizedPath
  }
  if (!trimmed.startsWith("/")) return undefined
  const noQuery = trimmed.split(/[?#]/, 1)[0]
  const normalized = noQuery
    .replace(/\$\{[^}]+\}/g, "{param}")
    .replace(/:[A-Za-z_$][\w$]*/g, "{param}")
    .replace(/\/{2,}/g, "/")
  return normalized.length > 1 ? normalizeJavaScriptEndpointPath(normalized).path : undefined
}

function skipJavaScriptQuotedLiteral(input: string, start: number): number {
  const quote = input[start]
  let escaped = false
  for (let index = start + 1; index < input.length; index++) {
    const char = input[index]!
    if (escaped) {
      escaped = false
      continue
    }
    if (char === "\\") {
      escaped = true
      continue
    }
    if (char === quote) return index + 1
  }
  return input.length
}

function skipJavaScriptComment(input: string, start: number): number | undefined {
  if (input[start] !== "/") return undefined
  if (input[start + 1] === "/") {
    const end = input.indexOf("\n", start + 2)
    return end < 0 ? input.length : end + 1
  }
  if (input[start + 1] === "*") {
    const end = input.indexOf("*/", start + 2)
    return end < 0 ? input.length : end + 2
  }
  return undefined
}

/** Find a call's matching close-paren while ignoring strings, templates, and comments. */
function findCallEnd(input: string, start: number): number {
  let round = 0
  let curly = 0
  let square = 0
  for (let index = start; index < input.length; index++) {
    const char = input[index]!
    if (char === "'" || char === '"' || char === "\x60") {
      index = skipJavaScriptQuotedLiteral(input, index) - 1
      continue
    }
    const commentEnd = skipJavaScriptComment(input, index)
    if (commentEnd !== undefined) {
      index = commentEnd - 1
      continue
    }
    if (char === "(") round++
    else if (char === ")") {
      round--
      if (round === 0) return index
      if (round < 0) return -1
    } else if (char === "{") curly++
    else if (char === "}") curly = Math.max(0, curly - 1)
    else if (char === "[") square++
    else if (char === "]") square = Math.max(0, square - 1)
  }
  return -1
}

/** Split function arguments without splitting nested object/array/call expressions. */
function splitTopLevelArguments(input: string): string[] {
  const output: string[] = []
  let start = 0
  let round = 0
  let curly = 0
  let square = 0
  for (let index = 0; index < input.length; index++) {
    const char = input[index]!
    if (char === "'" || char === '"' || char === "\x60") {
      index = skipJavaScriptQuotedLiteral(input, index) - 1
      continue
    }
    const commentEnd = skipJavaScriptComment(input, index)
    if (commentEnd !== undefined) {
      index = commentEnd - 1
      continue
    }
    if (char === "(") round++
    else if (char === ")") round = Math.max(0, round - 1)
    else if (char === "{") curly++
    else if (char === "}") curly = Math.max(0, curly - 1)
    else if (char === "[") square++
    else if (char === "]") square = Math.max(0, square - 1)
    else if (char === "," && round === 0 && curly === 0 && square === 0) {
      output.push(input.slice(start, index).trim())
      start = index + 1
    }
  }
  const finalArgument = input.slice(start).trim()
  if (finalArgument || output.length) output.push(finalArgument)
  return output
}

export function extractStaticJavaScriptEndpoints(content: string): string[] {
  const found = new Set<string>()
  // Absolute URLs count only when they are the first argument of a recognizable
  // network call. Arbitrary strings include docs, namespaces, assets and examples.
  const calls = /\b(?:fetch|axios\.(?:get|post|put|patch|delete|head|options|request)|[A-Za-z_$][\w$]*\.(?:get|post|put|patch|delete|head|options|request|open))\s*\(/gi
  for (const call of content.matchAll(calls)) {
    const start = (call.index ?? 0) + call[0].length
    const tail = content.slice(start)
    const callText = "(" + tail
    const close = findCallEnd(callText, 0)
    if (close < 0) continue
    const args = splitTopLevelArguments(callText.slice(1, close))
    const first = call[0].toLowerCase().endsWith(".open(") ? args[1] : args[0]
    const literal = first?.match(/^\s*['"\x60]([^'"\x60]+)['\x60]/)?.[1]
    if (!literal) continue
    const normalized = normalizeEndpointLiteral(literal)
    if (normalized) found.add(normalized)
  }

  // A conservative direct-literal fallback protects absolute API URLs from
  // being lost when a complex/minified call expression defeats the balanced
  // argument scanner. Only recognized request-call first arguments qualify;
  // arbitrary absolute links are still excluded.
  const absoluteRequestCalls = /\b(?:fetch|axios\.(?:get|post|put|patch|delete|head|options|request)|[A-Za-z_$][\w$]*\.(?:get|post|put|patch|delete|head|options|request))\s*\(\s*(["'\x60])(https?:\/\/[^"'\x60\s<>]+)\1/gi
  for (const match of content.matchAll(absoluteRequestCalls)) {
    const normalized = normalizeEndpointLiteral(match[2]!)
    if (normalized) found.add(normalized)
  }

  // XHR's open(method, url) keeps the URL in its second argument.
  const absoluteXHROpenCalls = /\b[A-Za-z_$][\w$]*\.open\s*\(\s*["'](?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE)["']\s*,\s*(["'])(https?:\/\/[^"'\s<>]+)\1/gi
  for (const match of content.matchAll(absoluteXHROpenCalls)) {
    const normalized = normalizeEndpointLiteral(match[2]!)
    if (normalized) found.add(normalized)
  }

  // Retain conventional API-like relative routes as candidates, without turning
  // arbitrary URLs, framework namespaces, or static assets into endpoints.
  const routes = /["'\x60](\/(?:api|graphql|rest|rpc|v\d+|oauth|auth|admin|internal)(?:\/[^"'\x60\s]*)?)["'\x60]/gi
  for (const match of content.matchAll(routes)) {
    const normalized = normalizeEndpointLiteral(match[1]!)
    if (normalized) found.add(normalized)
  }
  return [...found]
}

export interface JavaScriptSourceFile {
  relativePath: string
  basename: string
  sha256: string
  bytes: number
  endpointLiterals: string[]
  /** Canonical source URL without query/fragment; provides the correct origin for relative routes. */
  sourceURL?: string
  /** Canonical, query-free URL of the source map associated with this artifact. */
  sourceMapURL?: string
  /** Original sources[] path/name; embedded source contents are not persisted. */
  sourceMapSource?: string
  sourceMapVersion?: number | null
  sourceMapStatus?: "analyzed" | "no-sources-content" | "partial-sources-content" | "invalid-json" | "unsupported" | "truncated"
  sourceMapSourcesContentAvailable?: boolean
  sourceMapSourceCount?: number
  sourceMapEmbeddedSourceCount?: number
  sourceMapInline?: boolean
  /** External sourceMappingURL references found in this JavaScript response. */
  sourceMapURLs?: string[]
  /** True when upstream response capture marked this body as truncated. */
  captureTruncated?: boolean
  /** First request ID is retained for backward-compatible artifact references. */
  sourceRequestID?: string
  /** All request IDs whose response contained this canonical URL/content version. */
  sourceRequestIDs?: string[]
  /** First persistent JavaScript-capture row for this content version. */
  sourceCaptureID?: string
  /** Persistent capture-row IDs for this canonical URL/content version. */
  sourceCaptureIDs?: string[]
  /** Static-analysis metadata; secret-like matches retain only fingerprints, never raw values. */
  analysis?: JavaScriptSourceAnalysis
}

const LEGACY_RAW_SECRET_NOTE =
  "Exact candidate values are available for target-local evidence; a static match remains unverified until independently validated."

/** Remove legacy raw-value fields before old graph caches or new files can persist them. */
function sanitizeJavaScriptSourceAnalysisForPersistence(analysis: JavaScriptSourceAnalysis): JavaScriptSourceAnalysis {
  return {
    ...analysis,
    secretCandidates: analysis.secretCandidates.map((candidate) => ({
      kind: candidate.kind,
      line: candidate.line,
      functionName: candidate.functionName ?? null,
      fingerprint: candidate.fingerprint,
      confidence: candidate.confidence,
    })),
    notes: analysis.notes.map((note) => note === LEGACY_RAW_SECRET_NOTE
      ? "Secret-like values are never retained in derived analysis output; only fingerprints, source locations, and candidate status are emitted."
      : note),
  }
}

/** Return a URL identity without query/fragment values that may contain signatures or tokens. */
function canonicalSourceURLIdentity(value?: string | null): string {
  if (!value) return ""
  const url = safeURL(value)
  return url ? url.origin + url.pathname : value.split(/[?#]/, 1)[0]!
}

/**
 * Link virtual sourcesContent records to the real, query-free source-map URL.
 * The original local:// URL is read from the map record itself, not reconstructed
 * from its generated virtual filename (which is intentionally different).
 */
export function linkLocalSourceMapSources(
  sourceFiles: JavaScriptSourceFile[],
  mapRecord: JavaScriptSourceFile,
  canonicalMapURL: string,
): void {
  const localMapURL = mapRecord.sourceMapURL
  mapRecord.sourceMapURL = canonicalMapURL
  mapRecord.sourceURL = canonicalMapURL
  if (!localMapURL) return
  for (const source of sourceFiles) {
    if (source === mapRecord || source.sourceMapURL !== localMapURL) continue
    source.sourceMapURL = canonicalMapURL
    source.sourceURL = canonicalMapURL
  }
}

/**
 * Prefer request-linked capture records when the same source bytes/URL were
 * already present in the local asset inventory. The path is not part of the
 * identity because ingestion and capture persistence deliberately use separate
 * directories. Keep distinct source-map sources and distinct origins intact.
 */
export function mergeCapturedAndLocalJavaScriptSources(
  localFiles: JavaScriptSourceFile[],
  capturedFiles: JavaScriptSourceFile[],
): JavaScriptSourceFile[] {
  const identity = (file: JavaScriptSourceFile) => [
    file.sha256,
    canonicalSourceURLIdentity(file.sourceURL),
    canonicalSourceURLIdentity(file.sourceMapURL),
    file.sourceMapSource ?? "",
  ].join("\\0")
  const capturedIdentities = new Set(capturedFiles.map(identity))
  return [
    ...localFiles.filter((file) => !capturedIdentities.has(identity(file))),
    ...capturedFiles,
  ]
}

/** Persist summaries and fingerprints only; never save source-map source text or raw secret-like values. */
export function sanitizeJavaScriptSourceFileForPersistence(file: JavaScriptSourceFile): JavaScriptSourceFile {
  if (!file.analysis) return file
  return {
    ...file,
    analysis: sanitizeJavaScriptSourceAnalysisForPersistence(file.analysis),
  }
}

/**
 * Unwrap the bounded LLM-facing response preview while preserving whether the
 * upstream processor explicitly truncated it; complete capture-table bodies are preferred.
 */
function unwrapProcessedResponseBody(value: string): { body: string; truncated: boolean } {
  const metadata = /^\[Status:\s*\d+,\s*Type:\s*[^,\]\r\n]+,\s*Size:\s*[^\]\r\n]+\]\r?\n/
  const truncated = /\r?\n\[TRUNCATED - showing first 100KB of [^\]]+\]$/.test(value)
  return {
    body: value.replace(metadata, "").replace(/\r?\n\[TRUNCATED - showing first 100KB of [^\]]+\]$/, ""),
    truncated,
  }
}

export function extractJavaScriptSourceMapReferences(source: string, sourceURL: string): string[] {
  const references = new Set<string>()
  const pattern = /(?:\/\/[#@]\s*sourceMappingURL\s*=\s*([^\s*]+)|\/\*[#@]\s*sourceMappingURL\s*=\s*([^*\s]+)\s*\*\/)/g
  for (const match of source.matchAll(pattern)) {
    const candidate = (match[1] ?? match[2] ?? "").trim()
    if (!candidate || /^data:/i.test(candidate)) continue
    try {
      const resolved = new URL(candidate, sourceURL)
      if ((resolved.protocol === "http:" || resolved.protocol === "https:") && !resolved.username && !resolved.password) {
        references.add(resolved.origin + resolved.pathname)
      }
    } catch {
      // Invalid sourceMappingURL comments are not usable retrieval targets.
    }
  }
  return [...references]
}

/**
 * In explicit-asset mode, include maps referenced by that exact observed bundle.
 * This accepts both versioned capture rows and legacy RequestTable snapshots.
 */
export function collectExplicitJavaScriptSourceMapURLs(
  explicitAssetURL: string | URL,
  inputs: Array<{ url?: string | null; responseBody?: string | null }>,
): string[] {
  const selected = safeURL(explicitAssetURL instanceof URL ? explicitAssetURL.href : explicitAssetURL)
  if (!selected) return []
  const references = new Set<string>()
  for (const input of inputs) {
    if (!input.responseBody) continue
    const observedURL = safeURL(input.url)
    if (!observedURL || observedURL.origin !== selected.origin || observedURL.pathname !== selected.pathname) continue
    const body = unwrapProcessedResponseBody(input.responseBody).body
    for (const mapURL of extractJavaScriptSourceMapReferences(body, observedURL.origin + observedURL.pathname)) {
      references.add(mapURL)
    }
  }
  return [...references]
}

function emptyJavaScriptSourceAnalysis(notes: string[]): JavaScriptSourceAnalysis {
  return { functions: [], requests: [], secretCandidates: [], roleHints: [], riskSignals: [], applicationHints: [], notes }
}

function sourceMapSourceBasename(sourceName: string, index: number): string {
  const base = sourceName.replace(/\\/g, "/").split("/").filter(Boolean).pop() || "source-" + (index + 1) + ".js"
  return base.replace(/[^a-z0-9._-]/gi, "_").slice(0, 80) || "source-" + (index + 1) + ".js"
}

function sourceMapFilesFromContent(input: {
  content: string
  mapURL: string
  basename: string
  digest: string
  bytes: number
  requestID?: string
  captureID?: string
  truncated: boolean
  inline?: boolean
  analysisCache?: Map<string, JavaScriptSourceAnalysis>
}): JavaScriptSourceFile[] {
  const mapURL = safeURL(input.mapURL)
  const canonicalMapURL = mapURL ? mapURL.origin + mapURL.pathname : input.mapURL
  const host = mapURL?.hostname.toLowerCase() ?? "local"
  const mapDirectory = "source-maps/" + host + "/" + input.digest.slice(0, 12)
  let parsed: { version?: unknown; sources?: unknown; sourcesContent?: unknown } | undefined
  let parseError = false
  try {
    const candidate = JSON.parse(input.content)
    if (candidate && typeof candidate === "object" && !Array.isArray(candidate)) parsed = candidate
    else parseError = true
  } catch {
    parseError = true
  }
  const sources = Array.isArray(parsed?.sources) ? parsed!.sources as unknown[] : []
  const embedded = Array.isArray(parsed?.sourcesContent) ? parsed!.sourcesContent as unknown[] : []
  // Count only content aligned to an actual sources[] entry; stray extra array items
  // must not make an incomplete source map look fully analyzed.
  const embeddedCount = sources.reduce<number>((count, _source, index) =>
    count + (typeof embedded[index] === "string" && (embedded[index] as string).length > 0 ? 1 : 0), 0)
  let status: NonNullable<JavaScriptSourceFile["sourceMapStatus"]>
  const notes: string[] = []
  if (input.truncated) {
    status = "truncated"
    notes.push("SOURCE MAP INCOMPLETE: captured response was marked truncated; available embedded source entries are partial evidence only.")
  } else if (parseError) {
    status = "invalid-json"
    notes.push("SOURCE MAP UNPARSED: response is not valid JSON; recapture the complete .map response before considering its sources analyzed.")
  } else if (parsed?.version !== 3 || !Array.isArray(parsed.sources)) {
    status = "unsupported"
    notes.push("SOURCE MAP UNSUPPORTED: expected a version 3 source-map object with a sources array.")
  } else if (embeddedCount === 0) {
    status = "no-sources-content"
    notes.push("SOURCE MAP INCOMPLETE: no non-empty sourcesContent entries are embedded; referenced source files were not fetched or executed.")
  } else if (embeddedCount < sources.length) {
    status = "partial-sources-content"
    notes.push("SOURCE MAP PARTIAL: " + embeddedCount + " of " + sources.length + " source entries contain embedded source text; available entries were analyzed, missing entries remain unresolved.")
  } else {
    status = "analyzed"
    notes.push("SOURCE MAP ANALYZED: version 3 metadata parsed; " + embeddedCount + " embedded source file(s) are analyzed as separate virtual source records without persisting source code.")
  }
  const requestFields = {
    ...(input.requestID ? { sourceRequestID: input.requestID, sourceRequestIDs: [input.requestID] } : {}),
    ...(input.captureID ? { sourceCaptureID: input.captureID, sourceCaptureIDs: [input.captureID] } : {}),
  }
  const mapRecord: JavaScriptSourceFile = {
    relativePath: mapDirectory + "/" + input.basename.replace(/[^a-z0-9._-]/gi, "_").slice(0, 100),
    basename: input.basename,
    sha256: input.digest,
    bytes: input.bytes,
    endpointLiterals: [],
    sourceURL: canonicalMapURL,
    sourceMapURL: canonicalMapURL,
    sourceMapVersion: typeof parsed?.version === "number" ? parsed.version : null,
    sourceMapStatus: status,
    sourceMapSourcesContentAvailable: embeddedCount > 0,
    sourceMapSourceCount: sources.length,
    sourceMapEmbeddedSourceCount: embeddedCount,
    ...(input.inline ? { sourceMapInline: true } : {}),
    captureTruncated: input.truncated,
    ...requestFields,
    analysis: emptyJavaScriptSourceAnalysis(notes),
  }
  const output: JavaScriptSourceFile[] = [mapRecord]
  if (parseError || parsed?.version !== 3 || !Array.isArray(parsed.sources)) return output
  for (let index = 0; index < sources.length; index++) {
    const sourceName = typeof sources[index] === "string" ? sources[index] as string : "source-" + (index + 1) + ".js"
    const sourceContent = embedded[index]
    if (typeof sourceContent !== "string" || sourceContent.length === 0) continue
    const sourceDigest = createHash("sha256").update(sourceContent).digest("hex")
    let analysis = input.analysisCache?.get(sourceDigest)
    if (!analysis) {
      analysis = analyzeJavaScriptSource(sourceContent)
      input.analysisCache?.set(sourceDigest, analysis)
    }
    const sourceBasename = sourceMapSourceBasename(sourceName, index)
    output.push({
      relativePath: mapDirectory + "/sources/" + String(index + 1).padStart(4, "0") + "-" + sourceBasename + "-" + sourceDigest.slice(0, 8),
      basename: sourceBasename,
      sha256: sourceDigest,
      bytes: Buffer.byteLength(sourceContent, "utf-8"),
      endpointLiterals: extractStaticJavaScriptEndpoints(sourceContent),
      sourceURL: canonicalMapURL,
      sourceMapURL: canonicalMapURL,
      sourceMapSource: sourceName,
      sourceMapVersion: 3,
      sourceMapStatus: status,
      sourceMapSourcesContentAvailable: true,
      captureTruncated: input.truncated,
      ...requestFields,
      analysis,
    })
  }
  return output
}

function extractInlineSourceMapContent(source: string): string | undefined {
  const match = /sourceMappingURL\s*=\s*(data:application\/json(?:;[^,\s*]*)?,[^\s*]+)/i.exec(source)
  const dataURL = match?.[1]
  if (!dataURL) return undefined
  const comma = dataURL.indexOf(",")
  if (comma < 0) return undefined
  const metadata = dataURL.slice(0, comma)
  const payload = dataURL.slice(comma + 1)
  try {
    return (/;base64/i.test(metadata) ? Buffer.from(payload, "base64").toString("utf-8") : decodeURIComponent(payload)).trim() || undefined
  } catch {
    return undefined
  }
}

/** Extract executable inline script blocks from captured/local HTML as inert source text. */
function extractInlineHTMLScripts(html: string): string[] {
  const output: string[] = []
  const pattern = /<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi
  for (const match of html.matchAll(pattern)) {
    const attributes = match[1] ?? ""
    const type = /\btype\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i.exec(attributes)
    const mime = (type?.[1] ?? type?.[2] ?? type?.[3] ?? "").split(";", 1)[0]!.trim().toLowerCase()
    // JSON-LD, import maps, and framework data blobs are not executable JavaScript.
    if (mime && !["module", "text/javascript", "application/javascript", "text/ecmascript", "application/ecmascript", "application/x-javascript"].includes(mime)) continue
    const body = (match[2] ?? "").trim()
    if (body) output.push(body)
  }
  return output
}

export function extractCapturedJavaScriptSources(
  requests: Array<{
    id: string
    requestID?: string
    captureID?: string
    url?: string | null
    origin?: string | null
    pageURL?: string | null
    host?: string | null
    scheme?: string | null
    port?: number | null
    normalizedPath?: string | null
    responseContentType?: string | null
    responseBody?: string | null
  }>,
  analysisCache?: Map<string, JavaScriptSourceAnalysis>,
): JavaScriptSourceFile[] {
  const output: JavaScriptSourceFile[] = []
  const sourceIndexByURLAndHash = new Map<string, number>()
  for (const request of requests) {
    let url = safeURL(request.url)
    const base = observedRequestBaseURL(request)
    if (!url && base && request.normalizedPath) {
      try {
        url = new URL(request.normalizedPath, base)
      } catch {
        url = undefined
      }
    }
    url ??= base
    const storedBody = request.responseBody
    if (!url || !storedBody) continue
    // RequestTable stores the response-processor's metadata prefix and truncation marker;
    // strip them so source line numbers and content hashes refer to the captured JS itself.
    const unwrapped = unwrapProcessedResponseBody(storedBody)
    const body = unwrapped.body
    const isSourceMap = isSourceMapResponse(request.responseContentType, url.pathname)
    const isJavaScript =
      /(?:java|ecma)script|x-javascript/i.test(request.responseContentType ?? "") ||
      /\.(?:m?js|cjs)$/i.test(url.pathname)
    const isHTML =
      /(?:text\/html|application\/xhtml\+xml)/i.test(request.responseContentType ?? "") ||
      /\.x?html?$/i.test(url.pathname)
    if (isHTML) {
      const inlineScripts = extractInlineHTMLScripts(body)
      inlineScripts.forEach((script, index) => {
        const bytes = Buffer.byteLength(script, "utf-8")
        if (bytes < 1) return
        const digest = createHash("sha256").update(script).digest("hex")
        const canonicalSourceURL = url!.origin + url!.pathname
        const basename = (url!.pathname.split("/").filter(Boolean).pop() || "captured.html").replace(/[^a-z0-9._-]/gi, "_").slice(0, 80)
          + ".inline-" + (index + 1) + ".js"
        const analysis = analysisCache?.get(digest) ?? analyzeJavaScriptSource(script)
        analysisCache?.set(digest, analysis)
        output.push({
          relativePath: "captured-html/" + basename,
          basename,
          sha256: digest,
          bytes,
          endpointLiterals: extractStaticJavaScriptEndpoints(script),
          sourceURL: canonicalSourceURL,
          sourceRequestID: request.requestID ?? request.id,
          sourceRequestIDs: [request.requestID ?? request.id],
          ...(request.captureID ? { sourceCaptureID: request.captureID, sourceCaptureIDs: [request.captureID] } : {}),
          captureTruncated: unwrapped.truncated,
          analysis,
        })
      })
      continue
    }
    if (!isJavaScript && !isSourceMap) continue
    const bytes = Buffer.byteLength(body, "utf-8")
    if (bytes < 1) continue
    const digest = createHash("sha256").update(body).digest("hex")
    const canonicalSourceURL = url.origin + url.pathname
    const identity = canonicalSourceURL + "\0" + digest
    const previousIndex = sourceIndexByURLAndHash.get(identity)
    if (previousIndex !== undefined) {
      const previous = output[previousIndex]!
      const requestID = request.requestID ?? request.id
      previous.sourceRequestIDs = [...new Set([...(previous.sourceRequestIDs ?? [previous.sourceRequestID].filter((id): id is string => Boolean(id))), requestID])]
      if (request.captureID) {
        previous.sourceCaptureIDs = [...new Set([...(previous.sourceCaptureIDs ?? [previous.sourceCaptureID].filter((id): id is string => Boolean(id))), request.captureID])]
      }
      continue
    }
    const basename = (url.pathname.split("/").filter(Boolean).pop() || (isSourceMap ? "captured.map" : "captured.js")).replace(/[^a-z0-9._-]/gi, "_").slice(0, 100)
    if (isSourceMap) {
      sourceIndexByURLAndHash.set(identity, output.length)
      output.push(...sourceMapFilesFromContent({
        content: body,
        mapURL: canonicalSourceURL,
        basename,
        digest,
        bytes,
        requestID: request.requestID ?? request.id,
        ...(request.captureID ? { captureID: request.captureID } : {}),
        truncated: unwrapped.truncated,
        analysisCache,
      }))
      continue
    }
    let analysis = analysisCache?.get(digest)
    if (!analysis) {
      analysis = analyzeJavaScriptSource(body)
      analysisCache?.set(digest, analysis)
    }
    if (unwrapped.truncated && !analysis.notes.some((note) => note.startsWith("PARTIAL SOURCE:"))) {
      analysis = {
        ...analysis,
        notes: [...analysis.notes, "PARTIAL SOURCE: captured response was explicitly truncated by the upstream response processor at 100KB; routes, parameters, functions, and sinks in the omitted tail were not analyzed. Retrieve the full response through the request-detail/capture pipeline before treating this inventory as complete."],
      }
    }
    const inlineMapContent = extractInlineSourceMapContent(body)
    const inlineMapReference = /sourceMappingURL\s*=\s*data:application\/json/i.test(body)
    if (inlineMapReference && !inlineMapContent) {
      analysis = { ...analysis, notes: [...analysis.notes, "INLINE SOURCE MAP UNPARSED: a data-URL source map was present but could not be decoded from the captured body."] }
    }
    sourceIndexByURLAndHash.set(identity, output.length)
    const sourceURLKey = createHash("sha256").update(canonicalSourceURL).digest("hex").slice(0, 8)
    output.push({
      relativePath: "captured/" + url.hostname.toLowerCase() + "/" + sourceURLKey + "/" + basename + "-" + digest.slice(0, 8),
      basename,
      sha256: digest,
      bytes,
      endpointLiterals: extractStaticJavaScriptEndpoints(body),
      sourceURL: canonicalSourceURL,
      sourceMapURLs: extractJavaScriptSourceMapReferences(body, canonicalSourceURL),
      captureTruncated: unwrapped.truncated,
      sourceRequestID: request.requestID ?? request.id,
      sourceRequestIDs: [request.requestID ?? request.id],
      ...(request.captureID ? { sourceCaptureID: request.captureID, sourceCaptureIDs: [request.captureID] } : {}),
      analysis,
    })
    if (inlineMapContent) {
      const inlineDigest = createHash("sha256").update(inlineMapContent).digest("hex")
      output.push(...sourceMapFilesFromContent({
        content: inlineMapContent,
        mapURL: canonicalSourceURL,
        basename: "inline-source-map.map",
        digest: inlineDigest,
        bytes: Buffer.byteLength(inlineMapContent, "utf-8"),
        requestID: request.requestID ?? request.id,
        ...(request.captureID ? { captureID: request.captureID } : {}),
        truncated: false,
        inline: true,
        analysisCache,
      }))
    }
  }
  return output
}


export interface JavaScriptEndpointCandidate {
  id: string
  literal: string
  host: string | null
  origin: string | null
  path: string
  /** Null means no reliable evidence established the HTTP method. */
  method?: string | null
  /** Where the method itself was established; do not infer JavaScript support from traffic-only methods. */
  methodEvidenceSources?: Array<"javascript" | "traffic">
  pathParameters?: string[]
  queryParameters?: string[]
  bodyParameters?: string[]
  headerNames?: string[]
  contentTypes?: string[]
  authSignals?: string[]
  cookieSignals?: string[]
  sourceFiles: string[]
  observedRequestIDs: string[]
  observedInTraffic: boolean
  confidence: "candidate" | "observed"
}

/**
 * Correlates statically extracted route literals with captured traffic.
 * A matching path is evidence the route was observed, not proof that this
 * particular JavaScript file executed the request.
 */
export function matchesEndpointPathTemplate(template: string, observedPath: string): boolean {
  const normalize = (value: string) => {
    const path = value.split(/[?#]/, 1)[0]!.replace(/\/{2,}/g, "/")
    return path.length > 1 ? path.replace(/\/+$/, "") : "/"
  }
  const expected = normalize(template).split("/").filter(Boolean)
  const observed = normalize(observedPath).split("/").filter(Boolean)
  if (expected.length !== observed.length) return false
  return expected.every((segment, index) =>
    /^\{[^}]+\}$/.test(segment) ? Boolean(observed[index]) : segment === observed[index],
  )
}


function normalizedTemplateShape(inputPath: string): string {
  return inputPath.split(/[?#]/, 1)[0]!.replace(/\/{2,}/g, "/").split("/").map((segment) =>
    /^\{[^}]+\}$/.test(segment) ? "{}" : segment,
  ).join("/").replace(/\/+$/, "") || "/"
}

/** Merge structured request calls into endpoint inventory, including uncommon client/config forms. */
export function mergeStructuredJavaScriptEndpoints(
  staticEndpoints: JavaScriptEndpointCandidate[],
  requests: Array<JavaScriptRequestCandidate & { sourceFile: string; observedRequestIDs: string[] }>,
  _capturedRequests: Array<{ id: string; method: string }> = [],
): JavaScriptEndpointCandidate[] {
  const byKey = new Map<string, JavaScriptEndpointCandidate>()
  const routeKeyOf = (origin: string | null, route: string) =>
    (origin?.toLowerCase() ?? "*") + "\0" + normalizedTemplateShape(route)
  const normalizeMethod = (method?: string | null) => method?.trim().toUpperCase() || null
  const keyOf = (origin: string | null, route: string, method?: string | null) =>
    routeKeyOf(origin, route) + "\\0method:" + (normalizeMethod(method) ?? "*")
  const unique = (values: string[]) => [...new Set(values.filter(Boolean))]

  function mergeEndpointEvidence(target: JavaScriptEndpointCandidate, source: JavaScriptEndpointCandidate) {
    target.sourceFiles = unique([...target.sourceFiles, ...source.sourceFiles])
    target.pathParameters = unique([...(target.pathParameters ?? []), ...(source.pathParameters ?? [])])
    target.queryParameters = unique([...(target.queryParameters ?? []), ...(source.queryParameters ?? [])])
    target.bodyParameters = unique([...(target.bodyParameters ?? []), ...(source.bodyParameters ?? [])])
    target.headerNames = unique([...(target.headerNames ?? []), ...(source.headerNames ?? [])])
    target.contentTypes = unique([...(target.contentTypes ?? []), ...(source.contentTypes ?? [])])
    target.authSignals = unique([...(target.authSignals ?? []), ...(source.authSignals ?? [])])
    target.cookieSignals = unique([...(target.cookieSignals ?? []), ...(source.cookieSignals ?? [])])
    target.observedRequestIDs = unique([...target.observedRequestIDs, ...source.observedRequestIDs])
    target.methodEvidenceSources = unique([
      ...(target.methodEvidenceSources ?? []),
      ...(source.methodEvidenceSources ?? []),
    ]) as Array<"javascript" | "traffic">
    if (target.observedRequestIDs.length) {
      target.observedInTraffic = true
      target.confidence = "observed"
    }
  }

  function mergeStaticEndpoint(source: JavaScriptEndpointCandidate) {
    const method = normalizeMethod(source.method)
    const key = keyOf(source.origin, source.path, method)
    let endpoint = byKey.get(key)
    if (!endpoint) {
      endpoint = {
        ...source,
        id: "endpoint-operation:" + createHash("sha256").update(key).digest("hex").slice(0, 16),
        method,
        sourceFiles: [],
        observedRequestIDs: [],
        pathParameters: [],
        queryParameters: [],
        bodyParameters: [],
        headerNames: [],
        contentTypes: [],
        authSignals: [],
        cookieSignals: [],
        methodEvidenceSources: [],
        observedInTraffic: false,
        confidence: "candidate",
      }
      byKey.set(key, endpoint)
    }
    mergeEndpointEvidence(endpoint, source)
  }

  // Keep method-unknown route clues as endpoint-level evidence. Never copy their
  // parameters, headers, or auth hints into every known method merely because the
  // paths match; that would incorrectly turn a route clue into an operation contract.
  for (const source of staticEndpoints) mergeStaticEndpoint(source)

  for (const request of requests) {
    const url = safeURL(request.urlTemplate)
    const origin = request.origin ?? url?.origin ?? null
    const host = url?.host ?? request.host ?? null
    const method = normalizeMethod(request.method)
    const key = keyOf(origin, request.path, method)
    const requestEvidence: JavaScriptEndpointCandidate = {
      id: "endpoint-operation:" + createHash("sha256").update(key).digest("hex").slice(0, 16),
      literal: request.urlTemplate,
      host,
      origin,
      path: request.path,
      method,
      methodEvidenceSources: method
        ? ["javascript", ...(request.observedRequestIDs.length ? ["traffic" as const] : [])]
        : [],
      sourceFiles: [request.sourceFile],
      observedRequestIDs: [...request.observedRequestIDs],
      pathParameters: [...request.pathParameters],
      queryParameters: [...request.queryParameters],
      bodyParameters: [...request.bodyParameters],
      headerNames: [...request.headerNames],
      contentTypes: [...(request.contentTypes ?? [])],
      authSignals: [...request.authSignals],
      cookieSignals: [...request.cookieSignals],
      observedInTraffic: request.observedRequestIDs.length > 0,
      confidence: request.observedRequestIDs.length > 0 ? "observed" : "candidate",
    }
    const existing = byKey.get(key)
    if (existing) mergeEndpointEvidence(existing, requestEvidence)
    else byKey.set(key, requestEvidence)
  }

  return [...byKey.values()]
}


export function correlateStaticJavaScriptEndpoints(
  sourceFiles: JavaScriptSourceFile[],
  requests: Array<{ id: string; method: string; host: string | null; url: string | null; normalizedPath: string; responseStatus: number | null }>,
  targetHost: string,
  targetOrigin?: string,
): JavaScriptEndpointCandidate[] {
  const candidates = new Map<string, JavaScriptEndpointCandidate>()
  for (const file of sourceFiles) {
    for (const literal of file.endpointLiterals) {
      const endpointURL = safeURL(literal)
      const endpointPath = (endpointURL?.pathname ?? literal.split(/[?#]/, 1)[0]).replace(/\/{2,}/g, "/")
      if (!endpointPath.startsWith("/")) continue
      const explicitOrigin = endpointURL?.origin.toLowerCase() ?? null
      const matchingRequests = requests.flatMap((request) => {
        const requestURL = safeURL(request.url) ?? safeURL(request.host)
        if (!requestURL) return []
        if (explicitOrigin && requestURL.origin.toLowerCase() !== explicitOrigin) return []
        const observedPath = request.normalizedPath.split(/[?#]/, 1)[0]
        return matchesEndpointPathTemplate(endpointPath, observedPath) ? [{ request, url: requestURL }] : []
      })

      // Relative routes are not bound to the JavaScript bundle's host: browsers
      // resolve them against the document/API base. Use captured matching traffic to
      // discover the actual origin(s); if none are observed, leave origin unknown.
      const origins = new Map<string, { origin: string | null; host: string | null; matching: typeof matchingRequests }>()
      if (explicitOrigin && endpointURL) {
        origins.set(explicitOrigin, {
          origin: explicitOrigin,
          host: endpointURL.host.toLowerCase(),
          matching: matchingRequests.filter((item) => item.url.origin.toLowerCase() === explicitOrigin),
        })
      } else if (matchingRequests.length) {
        for (const item of matchingRequests) {
          const origin = item.url.origin.toLowerCase()
          const existing = origins.get(origin)
          if (existing) existing.matching.push(item)
          else origins.set(origin, { origin, host: item.url.host.toLowerCase(), matching: [item] })
        }
      } else {
        origins.set("*", { origin: null, host: null, matching: [] })
      }

      for (const variant of origins.values()) {
        // A path match proves traffic was observed at the route, not that this JS
        // asset declared or issued the observed method. Preserve each captured method
        // as its own traffic-sourced operation, including methods absent from JS.
        const byMethod = new Map<string, typeof variant.matching>()
        for (const item of variant.matching) {
          const method = item.request.method.trim().toUpperCase()
          if (!method) continue
          const group = byMethod.get(method) ?? []
          group.push(item)
          byMethod.set(method, group)
        }
        const methodVariants: Array<{ method: string | null; matching: typeof variant.matching }> =
          byMethod.size
            ? [...byMethod.entries()].map(([method, matching]) => ({ method, matching }))
            : [{ method: null, matching: [] }]

        for (const methodVariant of methodVariants) {
          const method = methodVariant.method
          const key = (variant.origin ?? "*") + "\0" + normalizedTemplateShape(endpointPath) + "\0" + (method ?? "UNKNOWN")
          let candidate = candidates.get(key)
          if (!candidate) {
            candidate = {
              id: "endpoint-operation:" + createHash("sha256").update(key).digest("hex").slice(0, 16),
              literal,
              host: variant.host,
              origin: variant.origin,
              path: endpointPath,
              ...(method ? { method, methodEvidenceSources: ["traffic" as const] } : {}),
              sourceFiles: [],
              observedRequestIDs: [],
              observedInTraffic: false,
              confidence: "candidate",
            }
            candidates.set(key, candidate)
          }
          if (!candidate.sourceFiles.includes(file.relativePath)) candidate.sourceFiles.push(file.relativePath)
          for (const item of methodVariant.matching) {
            if (!candidate.observedRequestIDs.includes(item.request.id)) candidate.observedRequestIDs.push(item.request.id)
          }
          if (candidate.observedRequestIDs.length) {
            candidate.observedInTraffic = true
            candidate.confidence = "observed"
          }
        }
      }
    }
  }
  return [...candidates.values()]
}


export interface JavaScriptInventoryIssue {
  relativePath: string
  stage: "directory-read" | "file-processing"
  code: string
}

/** Inventory local JavaScript and source-map files; never follow symlinks or execute their contents. */
export async function inventoryJavaScriptFiles(
  root: string,
  analysisCache?: Map<string, JavaScriptSourceAnalysis>,
  sourceBaseURL?: string,
  issues: JavaScriptInventoryIssue[] = [],
): Promise<JavaScriptSourceFile[]> {
  const output: JavaScriptSourceFile[] = []
  let rootInfo
  try {
    rootInfo = await fs.lstat(root)
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return output
    throw error
  }
  if (rootInfo.isSymbolicLink() || !rootInfo.isDirectory()) {
    throw new Error("Refusing to inventory JavaScript from a symbolic link or non-directory root.")
  }
  const resolvedRoot = path.resolve(root)
  const realRoot = await fs.realpath(root)
  if (realRoot !== resolvedRoot) {
    throw new Error("Refusing to inventory JavaScript from a root that resolves outside its canonical workspace path.")
  }
  const pendingDirectories = [root]
  while (pendingDirectories.length) {
    const directory = pendingDirectories.pop()!
    let entries
    try {
      entries = await fs.readdir(directory, { withFileTypes: true })
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code ?? "UNKNOWN"
      issues.push({
        relativePath: path.relative(path.dirname(root), directory).split(path.sep).join("/") || ".",
        stage: "directory-read",
        code: String(code),
      })
      // Continue with sibling directories instead of losing all other discovered sources.
      continue
    }
    for (const entry of entries) {
      const fullPath = path.join(directory, entry.name)
      // Dirent checks intentionally avoid following symlinks outside the workspace.
      if (entry.isDirectory()) {
        pendingDirectories.push(fullPath)
        continue
      }
      if (!entry.isFile() || !/\.(?:m?js|cjs|m?ts|cts|tsx|jsx|map|html?|xhtml)$/i.test(entry.name)) continue
      const workspaceRelativePath = path.relative(path.dirname(root), fullPath).split(path.sep).join("/")

      try {
        const content = await fs.readFile(fullPath, "utf-8")
        const digest = createHash("sha256").update(content).digest("hex")
        const sourceBytes = Buffer.byteLength(content, "utf-8")
      if (/\.(?:html?|xhtml)$/i.test(entry.name)) {
        const inlineScripts = extractInlineHTMLScripts(content)
        inlineScripts.forEach((script, index) => {
          const scriptDigest = createHash("sha256").update(script).digest("hex")
          let analysis = analysisCache?.get(scriptDigest)
          if (!analysis) {
            analysis = analyzeJavaScriptSource(script)
            analysisCache?.set(scriptDigest, analysis)
          }
          const basename = entry.name.replace(/\.(?:html?|xhtml)$/i, "") + ".inline-" + (index + 1) + ".js"
          output.push({
            relativePath: workspaceRelativePath + "#inline-" + (index + 1),
            basename,
            sha256: scriptDigest,
            bytes: Buffer.byteLength(script, "utf-8"),
            endpointLiterals: extractStaticJavaScriptEndpoints(script),
            sourceURL: sourceBaseURL ? safeURL(sourceBaseURL)?.origin : undefined,
            analysis,
          })
        })
        continue
      }
      if (/\.map$/i.test(entry.name)) {
        output.push(...sourceMapFilesFromContent({
          content,
          mapURL: "local://" + workspaceRelativePath,
          basename: entry.name,
          digest,
          bytes: sourceBytes,
          truncated: false,
          analysisCache,
        }))
        continue
      }
      let analysis = analysisCache?.get(digest)
      if (!analysis) {
        analysis = analyzeJavaScriptSource(content)
        analysisCache?.set(digest, analysis)
      }
      const inlineMapContent = extractInlineSourceMapContent(content)
      const hasInlineMapReference = /sourceMappingURL\s*=\s*data:application\/json/i.test(content)
      if (hasInlineMapReference && !inlineMapContent) {
        analysis = { ...analysis, notes: [...analysis.notes, "INLINE SOURCE MAP UNPARSED: a data-URL source map was present but could not be decoded from the local source file."] }
      }
      output.push({
        relativePath: workspaceRelativePath,
        basename: entry.name,
        sha256: digest,
        bytes: sourceBytes,
        endpointLiterals: extractStaticJavaScriptEndpoints(content),
        sourceURL: sourceBaseURL ? safeURL(sourceBaseURL)?.origin : undefined,
        analysis,
      })
      if (inlineMapContent) {
        const inlineDigest = createHash("sha256").update(inlineMapContent).digest("hex")
        output.push(...sourceMapFilesFromContent({
          content: inlineMapContent,
          mapURL: "local://" + workspaceRelativePath,
          basename: "inline-source-map.map",
          digest: inlineDigest,
          bytes: Buffer.byteLength(inlineMapContent, "utf-8"),
          truncated: false,
          inline: true,
          analysisCache,
        }))
      }
      } catch (error) {
        const code = (error as NodeJS.ErrnoException).code ?? "UNKNOWN"
        issues.push({
          relativePath: workspaceRelativePath,
          stage: "file-processing",
          code: String(code),
        })
        // An unreadable or malformed asset is an explicit coverage gap, not a reason
        // to discard all successfully analyzed siblings in a large JavaScript batch.
      }
    }
  }
  return output
}

export interface JavaScriptCorrelationGraph {
  schemaVersion: 2
  createdAt: string
  targetURL: string
  sessionID: string
  javascriptAssets: Array<{
    intelEntryID: string | null
    url: string
    title: string
    discoveredBy: string | null
    confidence: string | null
    tags: string[]
  }>
  sourceFiles: JavaScriptSourceFile[]
  sourceMapReferences?: Array<{
    url: string
    sourceFiles: string[]
    status: "analyzed" | "no-sources-content" | "invalid-json" | "unsupported" | "truncated" | "partial-sources-content" | "referenced-not-captured" | "out-of-scope"
    note: string
  }>
  /** Static JS review leads, kept separate from verified findings. */
  javascriptAnalysis: {
    functions: Array<JavaScriptFunctionCandidate & { sourceFile: string }>
    requestCandidates: Array<JavaScriptRequestCandidate & { sourceFile: string; observedRequestIDs: string[]; recommendedChecks: string[] }>
    secretCandidates: Array<JavaScriptSecretCandidate & { sourceFile: string }>
    roleHints: Array<JavaScriptRoleHint & { sourceFile: string }>
    riskSignals: Array<JavaScriptRiskSignal & { sourceFile: string }>
    applicationHints?: Array<JavaScriptApplicationHint & { sourceFile: string }>
    workflowSignals?: Array<JavaScriptWorkflowSignal & { sourceFile: string }>
    dataExposureSignals?: Array<import("./javascript-analysis").JavaScriptDataExposureSignal & { sourceFile: string }>
  }
  endpointCandidates: JavaScriptEndpointCandidate[]
  /** Source-linked review scenarios from workflow, application, role, risk, and secret clues. */
  additionalScenarios?: JavaScriptScenarioCandidate[]
  evidence: Array<{
    id: string
    requestID: string
    kind: "captured-response"
    responseStatus: number | null
    contentType: string | null
    responseSize: number | null
    redactedPreview: string | null
  }>
  requests: Array<{
    id: string
    method: string
    host: string | null
    url: string | null
    normalizedPath: string
    responseStatus: number | null
    responseContentType: string | null
    responseSize: number | null
    responsePreview: string | null
    hasRawRequest: boolean
  }>
  webFunctions: Array<{
    id: string
    name: string
    actionType: string
    requestID: string
    roleID: string | null
    objects: string[]
  }>
  observations: Array<{
    id: string
    requestID: string | null
    credentialID: string | null
    operationGroupHash: string
    slots: Array<{ location: string; name: string; retained?: boolean }>
  }>
  findings: Array<{
    id: string
    title: string
    severity: string
    status: string
    endpoint: string | null
    targetID: string | null
  }>
  edges: Array<{ from: string; to: string; relation: string; confidence: "direct" | "candidate"; evidence: string }>
  notes: string[]
}



const JAVASCRIPT_ANALYSIS_BEGIN = "<!-- BEGIN CYBERSTRIKE JAVASCRIPT ANALYSIS -->"
const JAVASCRIPT_ANALYSIS_END = "<!-- END CYBERSTRIKE JAVASCRIPT ANALYSIS -->"
const JAVASCRIPT_ENDPOINTS_BEGIN = "# BEGIN CYBERSTRIKE JAVASCRIPT ENDPOINTS"
const JAVASCRIPT_ENDPOINTS_END = "# END CYBERSTRIKE JAVASCRIPT ENDPOINTS"

function uniqueValues<T>(values: T[], key: (value: T) => string): T[] {
  const output = new Map<string, T>()
  for (const value of values) output.set(key(value), value)
  return [...output.values()]
}

function normalizeEndpointOrigin(value?: string | null): string {
  if (!value) return "*"
  try { return new URL(value).origin.toLowerCase() } catch { return value.toLowerCase().replace(/\/+$/, "") }
}

export function mergeCanonicalJavaScriptEndpoints(
  graphs: Array<{
    endpointCandidates: JavaScriptEndpointCandidate[]
    requests: Array<{ id: string; method: string }>
  }>,
): JavaScriptEndpointCandidate[] {
  const byKey = new Map<string, JavaScriptEndpointCandidate>()
  const routeKey = (endpoint: JavaScriptEndpointCandidate) =>
    normalizeEndpointOrigin(endpoint.origin) + "\0" + normalizedTemplateShape(endpoint.path)
  const keyOf = (endpoint: JavaScriptEndpointCandidate) =>
    routeKey(endpoint) + "\0" + (endpoint.method?.trim().toUpperCase() || "UNKNOWN")
  const uniqueStrings = (values: string[]) => [...new Set(values.filter(Boolean))]

  for (const endpoint of graphs.flatMap((graph) => graph.endpointCandidates ?? [])) {
    const key = keyOf(endpoint)
    const existing = byKey.get(key)
    if (!existing) {
      byKey.set(key, {
        ...endpoint,
        id: "endpoint-operation:" + createHash("sha256").update(key).digest("hex").slice(0, 16),
        sourceFiles: uniqueStrings(endpoint.sourceFiles ?? []),
        observedRequestIDs: uniqueStrings(endpoint.observedRequestIDs ?? []),
        pathParameters: uniqueStrings(endpoint.pathParameters ?? []),
        queryParameters: uniqueStrings(endpoint.queryParameters ?? []),
        bodyParameters: uniqueStrings(endpoint.bodyParameters ?? []),
        headerNames: uniqueStrings(endpoint.headerNames ?? []),
        contentTypes: uniqueStrings(endpoint.contentTypes ?? []),
        authSignals: uniqueStrings(endpoint.authSignals ?? []),
        cookieSignals: uniqueStrings(endpoint.cookieSignals ?? []),
        methodEvidenceSources: uniqueStrings(endpoint.methodEvidenceSources ?? []) as Array<"javascript" | "traffic">,
      })
      continue
    }
    existing.sourceFiles = uniqueStrings([...existing.sourceFiles, ...endpoint.sourceFiles])
    existing.observedRequestIDs = uniqueStrings([...existing.observedRequestIDs, ...endpoint.observedRequestIDs])
    existing.pathParameters = uniqueStrings([...(existing.pathParameters ?? []), ...(endpoint.pathParameters ?? [])])
    existing.queryParameters = uniqueStrings([...(existing.queryParameters ?? []), ...(endpoint.queryParameters ?? [])])
    existing.bodyParameters = uniqueStrings([...(existing.bodyParameters ?? []), ...(endpoint.bodyParameters ?? [])])
    existing.headerNames = uniqueStrings([...(existing.headerNames ?? []), ...(endpoint.headerNames ?? [])])
    existing.contentTypes = uniqueStrings([...(existing.contentTypes ?? []), ...(endpoint.contentTypes ?? [])])
    existing.authSignals = uniqueStrings([...(existing.authSignals ?? []), ...(endpoint.authSignals ?? [])])
    existing.cookieSignals = uniqueStrings([...(existing.cookieSignals ?? []), ...(endpoint.cookieSignals ?? [])])
    existing.methodEvidenceSources = uniqueStrings([
      ...(existing.methodEvidenceSources ?? []),
      ...(endpoint.methodEvidenceSources ?? []),
    ]) as Array<"javascript" | "traffic">
    existing.observedInTraffic ||= endpoint.observedInTraffic
    if (existing.observedInTraffic) existing.confidence = "observed"
  }

  return [...byKey.values()].sort((a, b) =>
    normalizeEndpointOrigin(a.origin).localeCompare(normalizeEndpointOrigin(b.origin)) ||
    normalizedTemplateShape(a.path).localeCompare(normalizedTemplateShape(b.path)) ||
    (a.method ?? "UNKNOWN").localeCompare(b.method ?? "UNKNOWN"),
  )
}

export interface CanonicalJavaScriptEndpointRecord {
  id: string
  literal: string
  host: string | null
  origin: string | null
  path: string
  sourceFiles: string[]
  operations: JavaScriptEndpointCandidate[]
  unattributed: {
    sourceFiles: string[]
    pathParameters: string[]
    queryParameters: string[]
    bodyParameters: string[]
    headerNames: string[]
    contentTypes: string[]
    authSignals: string[]
    cookieSignals: string[]
    observedRequestIDs: string[]
  }
}

/**
 * Group method-specific operations beneath one endpoint identity (origin + route
 * template). Unknown-method clues stay endpoint-level; captured methods absent
 * from JavaScript become traffic-only operations and are never relabeled as JS.
 */
export function groupCanonicalJavaScriptEndpoints(
  graphs: Array<{
    endpointCandidates: JavaScriptEndpointCandidate[]
    requests: Array<{ id: string; method: string }>
  }>,
): CanonicalJavaScriptEndpointRecord[] {
  const operations = mergeCanonicalJavaScriptEndpoints(graphs)
  const capturedMethodByID = new Map(
    graphs.flatMap((graph) => graph.requests).map((request) => [request.id, request.method.trim().toUpperCase()] as const),
  )
  const records = new Map<string, CanonicalJavaScriptEndpointRecord>()
  const unique = (values: string[]) => [...new Set(values.filter(Boolean))]
  const routeIdentity = (endpoint: Pick<JavaScriptEndpointCandidate, "origin" | "path">) =>
    normalizeEndpointOrigin(endpoint.origin) + "\0" + normalizedTemplateShape(endpoint.path)

  function getRecord(endpoint: JavaScriptEndpointCandidate): CanonicalJavaScriptEndpointRecord {
    const key = routeIdentity(endpoint)
    let record = records.get(key)
    if (!record) {
      const origin = endpoint.origin
      const pathValue = endpoint.path.split(/[?#]/, 1)[0]!.replace(/\/{2,}/g, "/").replace(/\/+$/, "") || "/"
      record = {
        id: "endpoint:" + createHash("sha256").update(key).digest("hex").slice(0, 16),
        literal: endpoint.literal,
        host: endpoint.host,
        origin,
        path: pathValue,
        sourceFiles: [],
        operations: [],
        unattributed: {
          sourceFiles: [],
          pathParameters: [],
          queryParameters: [],
          bodyParameters: [],
          headerNames: [],
          contentTypes: [],
          authSignals: [],
          cookieSignals: [],
          observedRequestIDs: [],
        },
      }
      records.set(key, record)
    }
    return record
  }

  function mergeOperation(record: CanonicalJavaScriptEndpointRecord, incoming: JavaScriptEndpointCandidate) {
    const method = incoming.method?.trim().toUpperCase()
    if (!method) return
    let operation = record.operations.find((item) => item.method?.trim().toUpperCase() === method)
    if (!operation) {
      operation = {
        ...incoming,
        method,
        sourceFiles: [],
        observedRequestIDs: [],
        pathParameters: [],
        queryParameters: [],
        bodyParameters: [],
        headerNames: [],
        contentTypes: [],
        authSignals: [],
        cookieSignals: [],
        methodEvidenceSources: [],
      }
      record.operations.push(operation)
    }
    const methodSourceFiles = (incoming.methodEvidenceSources ?? []).includes("javascript")
      ? incoming.sourceFiles
      : []
    operation.sourceFiles = unique([...operation.sourceFiles, ...methodSourceFiles])
    operation.observedRequestIDs = unique([...operation.observedRequestIDs, ...incoming.observedRequestIDs])
    operation.pathParameters = unique([...(operation.pathParameters ?? []), ...(incoming.pathParameters ?? [])])
    operation.queryParameters = unique([...(operation.queryParameters ?? []), ...(incoming.queryParameters ?? [])])
    operation.bodyParameters = unique([...(operation.bodyParameters ?? []), ...(incoming.bodyParameters ?? [])])
    operation.headerNames = unique([...(operation.headerNames ?? []), ...(incoming.headerNames ?? [])])
    operation.contentTypes = unique([...(operation.contentTypes ?? []), ...(incoming.contentTypes ?? [])])
    operation.authSignals = unique([...(operation.authSignals ?? []), ...(incoming.authSignals ?? [])])
    operation.cookieSignals = unique([...(operation.cookieSignals ?? []), ...(incoming.cookieSignals ?? [])])
    operation.methodEvidenceSources = unique([
      ...(operation.methodEvidenceSources ?? []),
      ...(incoming.methodEvidenceSources ?? []),
    ]) as Array<"javascript" | "traffic">
    if (operation.observedRequestIDs.length) {
      operation.observedInTraffic = true
      operation.confidence = "observed"
    }
  }

  for (const item of operations) {
    const record = getRecord(item)
    record.sourceFiles = unique([...record.sourceFiles, ...item.sourceFiles])
    if (item.method?.trim()) {
      mergeOperation(record, item)
      continue
    }

    const unassigned = record.unattributed
    unassigned.sourceFiles = unique([...unassigned.sourceFiles, ...item.sourceFiles])
    unassigned.pathParameters = unique([...unassigned.pathParameters, ...(item.pathParameters ?? [])])
    unassigned.queryParameters = unique([...unassigned.queryParameters, ...(item.queryParameters ?? [])])
    unassigned.bodyParameters = unique([...unassigned.bodyParameters, ...(item.bodyParameters ?? [])])
    unassigned.headerNames = unique([...unassigned.headerNames, ...(item.headerNames ?? [])])
    unassigned.contentTypes = unique([...unassigned.contentTypes, ...(item.contentTypes ?? [])])
    unassigned.authSignals = unique([...unassigned.authSignals, ...(item.authSignals ?? [])])
    unassigned.cookieSignals = unique([...unassigned.cookieSignals, ...(item.cookieSignals ?? [])])

    for (const requestID of item.observedRequestIDs) {
      const method = capturedMethodByID.get(requestID)
      if (method) {
        const trafficOperation: JavaScriptEndpointCandidate = {
          id: "endpoint-operation:" + createHash("sha256").update(routeIdentity(item) + "\0" + method).digest("hex").slice(0, 16),
          literal: item.literal,
          host: item.host,
          origin: item.origin,
          path: item.path,
          method,
          methodEvidenceSources: ["traffic"],
          sourceFiles: [],
          observedRequestIDs: [requestID],
          pathParameters: [],
          queryParameters: [],
          bodyParameters: [],
          headerNames: [],
          contentTypes: [],
          authSignals: [],
          cookieSignals: [],
          observedInTraffic: true,
          confidence: "observed",
        }
        mergeOperation(record, trafficOperation)
      } else {
        unassigned.observedRequestIDs = unique([...unassigned.observedRequestIDs, requestID])
      }
    }
  }

  return [...records.values()]
    .map((record) => {
      record.operations.sort((a, b) => (a.method ?? "").localeCompare(b.method ?? ""))
      record.sourceFiles = unique(record.sourceFiles)
      return record
    })
    .sort((a, b) =>
      normalizeEndpointOrigin(a.origin).localeCompare(normalizeEndpointOrigin(b.origin)) ||
      normalizedTemplateShape(a.path).localeCompare(normalizedTemplateShape(b.path)),
    )
}


function safeSummaryURL(input: string): string {
  try {
    const url = new URL(input)
    const keys = [...new Set([...url.searchParams.keys()])]
    // Keep the endpoint and parameter names, never signed/token-bearing query values.
    return url.origin + url.pathname + (keys.length ? "?" + keys.map((key) => encodeURIComponent(key) + "=[value omitted]").join("&") : "")
  } catch {
    return input.replace(/[\r\n]/g, " ").slice(0, 500)
  }
}

function safeSummaryText(input: string): string {
  const withoutURLValues = input.replace(/https?:\/\/[^\s"'<>]+/gi, (candidate) => {
    let end = candidate.length
    while (end > 0 && /[),.;\]]/.test(candidate[end - 1]!)) end--
    return safeSummaryURL(candidate.slice(0, end)) + candidate.slice(end)
  })
  return withoutURLValues
    .replace(/Bearer\s+[-A-Za-z0-9._~+\/]+=*/gi, "Bearer [REDACTED]")
    .replace(/((?:token|secret|password|passwd|api[_-]?key|client[_-]?secret|authorization|signature|session[_-]?id)\s*[:=]\s*)["']?[^\s,;"']+/gi, "$1[REDACTED]")
    .replace(/[\r\n]/g, " ")
}

async function readSafeWorkspaceText(workspacePath: string, relativePath: string): Promise<string> {
  const root = path.resolve(workspacePath)
  const candidate = path.resolve(root, relativePath)
  const relative = path.relative(root, candidate)
  if (!relative || relative.startsWith("..") || path.isAbsolute(relative)) {
    throw new Error("Refusing to read an artifact outside the canonical target workspace.")
  }
  let info
  try {
    info = await fs.lstat(candidate)
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return ""
    throw error
  }
  if (info.isSymbolicLink() || !info.isFile()) {
    throw new Error("Refusing to read a non-regular or symlinked workspace artifact: " + relativePath)
  }
  const rootReal = await fs.realpath(root)
  const fileReal = await fs.realpath(candidate)
  if (!fileReal.startsWith(rootReal + path.sep)) {
    throw new Error("Refusing to read a workspace artifact that resolves outside the canonical target workspace: " + relativePath)
  }
  return await fs.readFile(candidate, "utf8")
}

function replaceManagedSection(existing: string, begin: string, end: string, generated: string): string {
  const lines = existing.split(/\r?\n/)
  const preserved: string[] = []
  let inside = false
  let sawBegin = false
  let sawEnd = false
  for (const line of lines) {
    if (line === begin) {
      if (inside) throw new Error("Existing generated artifact section is nested and cannot be safely updated.")
      inside = true
      sawBegin = true
      continue
    }
    if (line === end) {
      if (!inside) throw new Error("Existing generated artifact section has an unmatched end marker.")
      inside = false
      sawEnd = true
      continue
    }
    if (!inside) preserved.push(line)
  }
  if (inside || sawBegin !== sawEnd) {
    throw new Error("Existing generated artifact section is incomplete; refusing to overwrite the target artifact.")
  }
  const prefix = preserved.join("\n").trimEnd()
  return (prefix ? prefix + "\n\n" : "") + generated.trimEnd() + "\n"
}

type CanonicalAssetManifest = {
  schemaVersion?: number
  assets?: Array<{
    url: string
    finalURL?: string
    source?: string
    status?: string
    contentHash?: string
    bytes?: number
    error?: string
    localPath?: string
  }>
  pendingURLs?: string[]
}

function readCorrelationGraph(value: unknown, targetURL: string): value is JavaScriptCorrelationGraph {
  if (!value || typeof value !== "object") return false
  const graph = value as Partial<JavaScriptCorrelationGraph>
  return graph.schemaVersion === 2 &&
    graph.targetURL === targetURL &&
    typeof graph.createdAt === "string" &&
    Array.isArray(graph.javascriptAssets) &&
    Array.isArray(graph.sourceFiles) &&
    Array.isArray(graph.endpointCandidates) &&
    Boolean(graph.javascriptAnalysis) &&
    Array.isArray(graph.javascriptAnalysis?.functions)
}

async function collectCorrelationGraphs(
  workspacePath: string,
  targetURL: string,
  currentGraph: JavaScriptCorrelationGraph,
  currentGraphFilename: string,
): Promise<JavaScriptCorrelationGraph[]> {
  const directory = path.join(workspacePath, "javascript")
  let entries
  try {
    entries = await fs.readdir(directory, { withFileTypes: true })
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return [currentGraph]
    throw error
  }
  const found: JavaScriptCorrelationGraph[] = []
  for (const entry of entries) {
    if (!entry.isFile() || entry.name === currentGraphFilename || !entry.name.toLowerCase().endsWith(".json")) continue
    try {
      const raw = await readSafeWorkspaceText(workspacePath, path.posix.join("javascript", entry.name))
      if (!raw) continue
      const parsed: unknown = JSON.parse(raw)
      if (readCorrelationGraph(parsed, targetURL)) found.push(parsed)
    } catch {
      // Non-correlation JSON and damaged old snapshots are ignored as sources;
      // the current snapshot will still be included and canonical output reports its own gaps.
    }
  }
  found.push(currentGraph)
  return found.sort((a, b) => Date.parse(a.createdAt) - Date.parse(b.createdAt))
}

function mergeGraphSnapshots(graphs: JavaScriptCorrelationGraph[]): JavaScriptCorrelationGraph {
  if (!graphs.length) throw new Error("No JavaScript correlation graph was available to summarize.")
  const latest = graphs[graphs.length - 1]!
  const assets = new Map<string, JavaScriptCorrelationGraph["javascriptAssets"][number]>()
  const sourceFiles = new Map<string, JavaScriptCorrelationGraph["sourceFiles"][number]>()
  const sourceMaps = new Map<string, NonNullable<JavaScriptCorrelationGraph["sourceMapReferences"]>[number]>()
  for (const graph of graphs) {
    for (const asset of graph.javascriptAssets) {
      const previous = assets.get(asset.url)
      assets.set(asset.url, previous
        ? { ...previous, ...asset, tags: [...new Set([...previous.tags, ...asset.tags])] }
        : { ...asset, tags: [...asset.tags] })
    }
    for (const file of graph.sourceFiles) {
      const key = file.relativePath + "\0" + file.sha256
      const previous = sourceFiles.get(key)
      sourceFiles.set(key, previous ? {
        ...previous,
        ...file,
        sourceRequestIDs: [...new Set([...(previous.sourceRequestIDs ?? []), ...(file.sourceRequestIDs ?? [])])],
        sourceCaptureIDs: [...new Set([...(previous.sourceCaptureIDs ?? []), ...(file.sourceCaptureIDs ?? [])])],
        sourceMapURLs: [...new Set([...(previous.sourceMapURLs ?? []), ...(file.sourceMapURLs ?? [])])],
      } : { ...file })
    }
    for (const reference of graph.sourceMapReferences ?? []) {
      const previous = sourceMaps.get(reference.url)
      sourceMaps.set(reference.url, previous ? {
        ...previous,
        ...reference,
        sourceFiles: [...new Set([...previous.sourceFiles, ...reference.sourceFiles])],
      } : { ...reference, sourceFiles: [...reference.sourceFiles] })
    }
  }
  const mergeRecords = <T>(lists: T[][], key: (item: T) => string): T[] => uniqueValues(lists.flat(), key)
  const functions = mergeRecords(graphs.map((g) => g.javascriptAnalysis.functions), (item) => [item.sourceFile, item.line, item.name].join("\0"))
    .map((fn) => ({
      ...fn,
      callSites: uniqueValues(
        graphs.flatMap((graph) => graph.javascriptAnalysis.functions
          .filter((candidate) => candidate.sourceFile === fn.sourceFile && candidate.line === fn.line && candidate.name === fn.name)
          .flatMap((candidate) => candidate.callSites ?? [])),
        (site) => site.line + "\0" + site.kind,
      ).sort((a, b) => a.line - b.line || a.kind.localeCompare(b.kind)),
    }))
  const requestCandidates = mergeRecords(graphs.map((g) => g.javascriptAnalysis.requestCandidates), (item) => [item.sourceFile, item.sourceLine, item.method ?? "", item.urlTemplate].join("\0"))
  const secrets = mergeRecords(graphs.map((g) => g.javascriptAnalysis.secretCandidates), (item) => [item.sourceFile, item.line, item.kind, item.fingerprint, item.functionName ?? ""].join("\0"))
  const roles = mergeRecords(graphs.map((g) => g.javascriptAnalysis.roleHints), (item) => [item.sourceFile, item.line, item.kind, item.value].join("\0"))
  const risks = mergeRecords(graphs.map((g) => g.javascriptAnalysis.riskSignals), (item) => [item.sourceFile, item.line, item.kind, item.functionName ?? ""].join("\0"))
  const applicationHints = mergeRecords(graphs.map((g) => g.javascriptAnalysis.applicationHints ?? []), (item) => [item.sourceFile, item.line, item.kind, item.value].join("\0"))
  const workflowSignals = mergeRecords(graphs.map((g) => g.javascriptAnalysis.workflowSignals ?? []), (item) =>
    [item.sourceFile, item.line, item.kind, item.value, item.functionName ?? ""].join("\0"),
  )
  const dataExposureSignals = mergeRecords(graphs.map((g) => g.javascriptAnalysis.dataExposureSignals ?? []), (item) =>
    [item.sourceFile, item.line, item.kind, item.field ?? "", item.functionName ?? ""].join("\0"),
  )
  const scenarioMap = new Map<string, JavaScriptScenarioCandidate>()
  for (const graph of graphs) {
    for (const scenario of graph.additionalScenarios ?? []) {
      const previous = scenarioMap.get(scenario.id)
      scenarioMap.set(scenario.id, previous ? {
        ...previous,
        ...scenario,
        sourceLines: [...new Set([...previous.sourceLines, ...scenario.sourceLines])].sort((a, b) => a - b),
        signals: uniqueValues([...previous.signals, ...scenario.signals], (item) =>
          [item.evidenceType, item.kind, item.value, item.line, item.sourceFunction ?? ""].join("\0"),
        ),
        relatedEndpointIDs: [...new Set([...previous.relatedEndpointIDs, ...scenario.relatedEndpointIDs])],
        relatedRequestCandidateIDs: [...new Set([...previous.relatedRequestCandidateIDs, ...scenario.relatedRequestCandidateIDs])],
        observedRequestIDs: [...new Set([...previous.observedRequestIDs, ...scenario.observedRequestIDs])],
        riskSignalIDs: [...new Set([...previous.riskSignalIDs, ...scenario.riskSignalIDs])],
        prerequisites: [...new Set([...previous.prerequisites, ...scenario.prerequisites])],
        recommendedChecks: [...new Set([...previous.recommendedChecks, ...scenario.recommendedChecks])],
      } : { ...scenario })
    }
  }
  const uniqueObjects = <T>(items: T[], key: (item: T) => string) => uniqueValues(items, key)
  return {
    ...latest,
    javascriptAssets: [...assets.values()].sort((a, b) => a.url.localeCompare(b.url)),
    sourceFiles: [...sourceFiles.values()].sort((a, b) => a.relativePath.localeCompare(b.relativePath) || a.sha256.localeCompare(b.sha256)),
    sourceMapReferences: [...sourceMaps.values()].sort((a, b) => a.url.localeCompare(b.url)),
    javascriptAnalysis: { ...latest.javascriptAnalysis, functions, requestCandidates, secretCandidates: secrets, roleHints: roles, riskSignals: risks, applicationHints, workflowSignals, dataExposureSignals },
    endpointCandidates: mergeCanonicalJavaScriptEndpoints(graphs),
    additionalScenarios: [...scenarioMap.values()].sort((a, b) => a.sourceFile.localeCompare(b.sourceFile) || a.category.localeCompare(b.category) || a.id.localeCompare(b.id)),
    evidence: uniqueObjects(graphs.flatMap((g) => g.evidence), (x) => x.id),
    requests: uniqueObjects(graphs.flatMap((g) => g.requests), (x) => x.id),
    webFunctions: uniqueObjects(graphs.flatMap((g) => g.webFunctions), (x) => x.id),
    observations: uniqueObjects(graphs.flatMap((g) => g.observations), (x) => x.id),
    findings: uniqueObjects(graphs.flatMap((g) => g.findings), (x) => x.id),
    edges: uniqueObjects(graphs.flatMap((g) => g.edges), (x) => [x.from, x.to, x.relation, x.evidence].join("\0")),
    notes: [...new Set(graphs.flatMap((g) => g.notes))],
  }
}

function renderJavaScriptWorkflowTrace(graph: JavaScriptCorrelationGraph): string[] {
  const signals = [...(graph.javascriptAnalysis.workflowSignals ?? [])].sort((a, b) =>
    a.sourceFile.localeCompare(b.sourceFile) || a.line - b.line || a.kind.localeCompare(b.kind),
  )
  const functions = graph.javascriptAnalysis.functions
  const requests = graph.javascriptAnalysis.requestCandidates
  const sourceFiles = graph.sourceFiles
  const byFunction = new Map<string, {
    sourceFile: string
    functionName: string | null
    declaration?: JavaScriptCorrelationGraph["javascriptAnalysis"]["functions"][number]
    signals: typeof signals
  }>()
  for (const signal of signals) {
    const key = signal.sourceFile + "\\0" + (signal.functionName ?? "(top-level)")
    const current = byFunction.get(key) ?? {
      sourceFile: signal.sourceFile,
      functionName: signal.functionName,
      declaration: signal.functionName
        ? functions.find((fn) => fn.sourceFile === signal.sourceFile && fn.name === signal.functionName)
        : undefined,
      signals: [],
    }
    current.signals.push(signal)
    byFunction.set(key, current)
  }
  if (!byFunction.size) return ["- No email-verification, recovery, token, SQL-statement, or data-layer-operation markers matched current static rules."]
  return [...byFunction.values()].map((group) => {
    const functionRequests = group.functionName
      ? requests.filter((request) => request.sourceFile === group.sourceFile && request.sourceFunction === group.functionName)
      : []
    const callSites = group.declaration?.callSites ?? []
    const signalText = group.signals.map((signal) =>
      safeSummaryText(signal.kind) + ":" + safeSummaryText(signal.value) + "@" + signal.line,
    ).join(", ")
    const parameterText = group.declaration
      ? group.declaration.parameters.map(safeSummaryText).join(", ")
      : ""
    const definition = group.declaration
      ? group.declaration.name + "(" + parameterText + ")@" + group.sourceFile + ":" + group.declaration.line
      : "(no enclosing function identified)"
    const calls = functionRequests.length
      ? functionRequests.map((request) =>
          (request.method ?? "UNKNOWN") + " " + safeSummaryText(request.urlTemplate) +
          " [path:" + request.pathParameters.join(",") +
          "; query:" + request.queryParameters.join(",") +
          "; body:" + request.bodyParameters.join(",") +
          "; headers:" + request.headerNames.join(",") +
          "; captured request IDs:" + (request.observedRequestIDs.join(",") || "not matched") + "]",
        ).join(" | ")
      : "no request call attributed to this function"
    const entries = callSites.length
      ? callSites.map((site) => site.kind + "@" + site.line + (site.callerFunctionName ? " in " + safeSummaryText(site.callerFunctionName) : " at module/component scope")).join(", ")
      : "no UI/event/callback reference matched"
    const sourceRecord = sourceFiles.find((file) => file.relativePath === group.sourceFile)
    const sourceLocation = sourceRecord?.sourceURL
      ? safeSummaryURL(sourceRecord.sourceURL) + " → " + safeSummaryText(group.sourceFile)
      : safeSummaryText(group.sourceFile)
    const mappedSource = sourceRecord?.sourceMapSource ? " — original source: " + safeSummaryText(sourceRecord.sourceMapSource) : ""
    const sourceRequests = sourceRecord?.sourceRequestIDs ?? (sourceRecord?.sourceRequestID ? [sourceRecord.sourceRequestID] : [])
    return "- " + sourceLocation + mappedSource + (sourceRequests.length ? " — asset captured in request(s): " + sourceRequests.join(", ") : "") +
      " — signals: " + signalText +
      " — function: " + definition +
      " — call/reference sites: " + entries +
      " — same-function requests: " + calls +
      " — confidence: candidate; a static handler reference is a navigation clue, not proof of a user click or successful server operation."
  })
}

function renderCanonicalJavaScriptAnalysis(
  graph: JavaScriptCorrelationGraph,
  manifest?: CanonicalAssetManifest,
  manifestWarning?: string,
  graphCount = 1,
): string {
  const manifestAssets = (manifest?.assets ?? []).filter((item) => typeof item.url === "string")
  const endpointRecords = groupCanonicalJavaScriptEndpoints([graph])
  const operationCount = endpointRecords.reduce((sum, endpoint) => sum + endpoint.operations.length, 0)
  const trafficOperationCount = endpointRecords.reduce(
    (sum, endpoint) => sum + endpoint.operations.filter((operation) => operation.observedInTraffic).length,
    0,
  )
  const manifestByURL = new Map(manifestAssets.map((asset) => [asset.url, asset]))
  const assets = new Map<string, JavaScriptCorrelationGraph["javascriptAssets"][number]>()
  for (const asset of graph.javascriptAssets) assets.set(asset.url, asset)
  for (const record of manifestAssets) {
    if (!assets.has(record.url)) {
      assets.set(record.url, {
        intelEntryID: null,
        url: record.url,
        title: "Downloaded JavaScript/source-map asset",
        discoveredBy: record.source ?? null,
        confidence: "observed",
        tags: [record.status ?? "asset-manifest"],
      })
    }
  }
  const sourceMapReferences = graph.sourceMapReferences ?? []
  const incompleteMaps = sourceMapReferences.filter((item) => item.status !== "analyzed")
  const downloadedAssets = manifestAssets.filter((item) => item.status === "downloaded")
  const reusedAssets = manifestAssets.filter((item) => item.status === "reused")
  const failedAssets = manifestAssets.filter((item) => item.status === "failed")
  const skippedAssets = manifestAssets.filter((item) => item.status === "skipped")
  const pendingAssets = manifestAssets.filter((item) => item.status === "pending")
  const inventoryGaps = graph.notes.filter((note) => note.startsWith("JAVASCRIPT INVENTORY GAP:"))
  const localFiles = graph.sourceFiles
  const bySourceLine = <T extends { sourceFile: string; line: number }>(a: T, b: T) =>
    a.sourceFile.localeCompare(b.sourceFile) || a.line - b.line
  const functions = [...graph.javascriptAnalysis.functions].sort((a, b) =>
    bySourceLine(a, b) || a.name.localeCompare(b.name),
  )
  const requestCandidates = [...graph.javascriptAnalysis.requestCandidates].sort((a, b) =>
    a.sourceFile.localeCompare(b.sourceFile) || a.sourceLine - b.sourceLine ||
    (a.method ?? "UNKNOWN").localeCompare(b.method ?? "UNKNOWN") || a.urlTemplate.localeCompare(b.urlTemplate),
  )
  const roleHints = [...graph.javascriptAnalysis.roleHints].sort((a, b) =>
    a.kind.localeCompare(b.kind) || bySourceLine(a, b) || a.value.localeCompare(b.value),
  )
  const applicationHints = [...(graph.javascriptAnalysis.applicationHints ?? [])].sort((a, b) =>
    a.kind.localeCompare(b.kind) || bySourceLine(a, b) || a.value.localeCompare(b.value),
  )
  const riskSignals = [...graph.javascriptAnalysis.riskSignals].sort((a, b) =>
    a.kind.localeCompare(b.kind) || a.sourceFile.localeCompare(b.sourceFile) || a.line - b.line ||
    (a.functionName ?? "").localeCompare(b.functionName ?? ""),
  )
  const secretCandidates = [...graph.javascriptAnalysis.secretCandidates].sort((a, b) =>
    a.kind.localeCompare(b.kind) || a.sourceFile.localeCompare(b.sourceFile) || a.line - b.line,
  )
  const hasRecordedGaps = inventoryGaps.length > 0 || Boolean(manifest?.pendingURLs?.length) ||
    pendingAssets.length > 0 || failedAssets.length > 0 || skippedAssets.length > 0 ||
    incompleteMaps.length > 0 || Boolean(manifestWarning)
  const lines = [
    JAVASCRIPT_ANALYSIS_BEGIN,
    "# JavaScript Analysis Summary",
    "",
    "- Target: " + safeSummaryURL(graph.targetURL),
    "- Generated: " + graph.createdAt,
    "- Coverage assessment: " + (hasRecordedGaps
      ? "INCOMPLETE / REVIEW REQUIRED — see the explicit gap sections below"
      : "No known gaps recorded; verify collection_complete=true and analysis_complete=true in the ingestion result"),
    "- Correlation snapshots combined: " + graphCount,
    "- Unique JavaScript/source-map URLs: " + assets.size,
    "- Asset statuses: downloaded=" + downloadedAssets.length + ", reused/cache-hit=" + reusedAssets.length +
      ", failed=" + failedAssets.length + ", skipped=" + skippedAssets.length + ", pending=" + pendingAssets.length,
    "- Local source files/content versions: " + localFiles.length,
    "- Local JavaScript inventory gaps: " + inventoryGaps.length,
    "- Source-map references: " + sourceMapReferences.length,
    "- Source maps analyzed completely: " + sourceMapReferences.filter((item) => item.status === "analyzed").length,
    "- Source maps unresolved/incomplete: " + incompleteMaps.length,
    "- Embedded source entries analyzed: " + localFiles.filter((file) => Boolean(file.sourceMapSource)).length,
    "- Canonical endpoint records: " + endpointRecords.length,
    "- Method-specific endpoint operations: " + operationCount,
    "- Operations overlapping captured traffic: " + trafficOperationCount,
    "- JavaScript function candidates: " + functions.length,
    "- Structured request candidates: " + requestCandidates.length,
    "- Secret-like assignments (fingerprints only): " + secretCandidates.length,
    "- Role/feature hints: " + roleHints.length,
    "- Application/integration hints: " + applicationHints.length,
    "- Static risk-sink candidates: " + riskSignals.length,
    "- Business/token/data-operation flow signals: " + (graph.javascriptAnalysis.workflowSignals ?? []).length,
    "- Additional review scenarios (candidate only): " + (graph.additionalScenarios ?? []).length,
    "- Sensitive-data field/literal candidates (not verified leaks): " + (graph.javascriptAnalysis.dataExposureSignals ?? []).length,
    "- Captured requests correlated: " + graph.requests.length,
    "- Response evidence records: " + graph.evidence.length,
    "- Failed asset fetches: " + failedAssets.length,
    "- Skipped asset fetches: " + skippedAssets.length,
    "- Pending URLs: " + (manifest?.pendingURLs?.length ?? 0),
    ...(manifestWarning ? ["- Asset-manifest warning: " + safeSummaryText(manifestWarning)] : []),
    "",
    "## JavaScript/source-map URLs and hashes",
    ...([...assets.values()].sort((a, b) => a.url.localeCompare(b.url)).map((asset) => {
      const record = manifestByURL.get(asset.url)
      return "- " + safeSummaryURL(asset.url) +
        " — SHA-256: " + (record?.contentHash ?? "not recorded in asset manifest") +
        " — status: " + (record?.status ?? "captured/indexed") +
        " — source: " + safeSummaryText(record?.source ?? asset.discoveredBy ?? "unknown")
    })),
    ...(assets.size ? [] : ["- No JavaScript/source-map URL was recorded."]),
    "",
    "## Local source files/content versions",
    ...(localFiles.length ? localFiles.map((file) =>
      "- " + file.relativePath +
      (file.sourceMapSource ? " — mapped source: " + safeSummaryText(file.sourceMapSource) : "") +
      " — SHA-256: " + file.sha256 + " — " + file.bytes +
      " bytes — endpoint literals: " + file.endpointLiterals.length +
      (file.sourceURL ? " — asset URL: " + safeSummaryURL(file.sourceURL) : "") +
      (file.sourceRequestIDs?.length ? " — captured request IDs: " + file.sourceRequestIDs.join(", ") : "") +
      (file.sourceMapStatus ? " — source-map status: " + file.sourceMapStatus : ""),
    ) : ["- No local source files were analyzed."]),
    "",
    "## Source-map status",
    ...(sourceMapReferences.length ? sourceMapReferences.map((item) =>
      "- " + safeSummaryURL(item.url) + " — " + item.status +
      " — source files: " + item.sourceFiles.join(", ") +
      " — " + safeSummaryText(item.note),
    ) : ["- No external source-mapping references were found in the combined snapshots."]),
    ...(manifest?.pendingURLs?.length ? ["", "## Pending URLs", ...manifest.pendingURLs.map((url) => "- " + safeSummaryURL(url))] : []),
    ...(failedAssets.length ? ["", "## Failed asset fetches", ...failedAssets.map((asset) => "- " + safeSummaryURL(asset.url) + " — failed; inspect the manifest error field locally.")] : []),
    ...(skippedAssets.length ? ["", "## Skipped asset fetches", ...skippedAssets.map((asset) => "- " + safeSummaryURL(asset.url) + " — skipped; inspect the manifest status/error locally.")] : []),
    "",
        "## Function and call-site inventory",
        ...(functions.length ? functions.map((fn) => {
          const sourceAsset = localFiles.find((file) => file.relativePath === fn.sourceFile)
          const callSites = fn.callSites ?? []
          return "- " + safeSummaryText(fn.name) + "(" + fn.parameters.map(safeSummaryText).join(", ") + ") — " +
            safeSummaryText(fn.sourceFile) + ":" + fn.line +
            (sourceAsset?.sourceMapSource ? " — mapped source: " + safeSummaryText(sourceAsset.sourceMapSource) : "") +
            (sourceAsset?.sourceURL ? " — asset URL: " + safeSummaryURL(sourceAsset.sourceURL) : "") +
            (callSites.length ? " — candidate references: " + callSites.map((site) => site.kind + "@" + site.line + (site.callerFunctionName ? " in " + safeSummaryText(site.callerFunctionName) : " at module/component scope")).join(", ") : " — no UI/event/callback references matched")
        }) : ["- No named function candidates were extracted."]),
        "",
    "## API and request intelligence",
    ...(requestCandidates.length ? requestCandidates.map((item) =>
      "- " + (item.method ?? "UNKNOWN") + " " + safeSummaryText(item.urlTemplate) +
      " — function: " + (item.sourceFunction ?? "unknown") +
      " — source: " + item.sourceFile + ":" + item.sourceLine +
      " — parameters: path=[" + item.pathParameters.join(", ") + "]; query=[" + item.queryParameters.join(", ") +
      "]; body=[" + item.bodyParameters.join(", ") + "]; headers=[" + item.headerNames.join(", ") + "]" +
      " — content types: [" + (item.contentTypes ?? []).join(", ") + "]" +
      " — auth signals: [" + item.authSignals.join(", ") + "] — cookies: [" + item.cookieSignals.join(", ") + "]" +
      " — captured request IDs: [" + item.observedRequestIDs.join(", ") + "]",
    ) : ["- No structured request-call candidates were extracted."]),
    "",

    "## Feature and behavior trace (static candidates; use these to locate code and correlate UI actions)",
    ...renderJavaScriptWorkflowTrace(graph),
    "",
    "## Sensitive data indicators (candidate only; raw values omitted)",
    ...((graph.javascriptAnalysis.dataExposureSignals ?? []).length ? (graph.javascriptAnalysis.dataExposureSignals ?? []).map((item) =>
      "- " + item.kind + (item.field ? " — field: " + item.field : " — embedded contact literal; value omitted") + " — " + safeSummaryText(item.sourceFile) + ":" + item.line + (item.functionName ? " — function: " + safeSummaryText(item.functionName) : "")
    ) : ["- No sensitive data-field or embedded email indicators matched."]),
    "",
    "## Additional hypothesis scenarios (candidate only; not automatically tested)",
    ...((graph.additionalScenarios ?? []).length ? (graph.additionalScenarios ?? []).map((scenario) =>
      "- " + scenario.title + " [" + scenario.category + "] — " + safeSummaryText(scenario.sourceFile) + ":" + scenario.sourceLines.join(",") +
      (scenario.sourceFunction ? " — function: " + safeSummaryText(scenario.sourceFunction) : "") +
      " — SHA-256: " + scenario.sourceSHA256 +
      " — signals: " + scenario.signals.map((signal) => signal.kind + "@" + signal.line).join(", ") +
      " — endpoints: " + (scenario.relatedEndpointIDs.join(", ") || "none linked") +
      " — request IDs: " + (scenario.observedRequestIDs.join(", ") || "none linked") +
      " — next checks: " + scenario.recommendedChecks.join("; ")
    ) : ["- No additional scenario candidates were generated from current static signals."]),
    "",
    "## Roles, permissions, tenants and feature flags",
    ...(roleHints.length ? roleHints.map((item) =>
      "- " + safeSummaryText(item.kind) + " — " + safeSummaryText(item.value) + " — " + safeSummaryText(item.sourceFile) + ":" + item.line,
    ) : ["- No role/feature hints matched the static heuristics."]),
    "",
    "## Application features and integrations (candidate intelligence)",
    ...(applicationHints.length
      ? applicationHints.map((item) =>
          "- " + safeSummaryText(item.kind) + " — " + safeSummaryText(item.value) + " — " +
          safeSummaryText(item.sourceFile) + ":" + item.line + " — candidate only",
        )
      : ["- No application/integration hints matched the current static rules."]),
    "",
    "## Security review leads (not confirmed findings)",
    ...(riskSignals.length ? riskSignals.map((item) =>
      "- " + safeSummaryText(item.kind) + " — " + safeSummaryText(item.sourceFile) + ":" + item.line + " — function: " +
      safeSummaryText(item.functionName ?? "unknown") + " — candidate only",
    ) : ["- No configured static risk patterns matched."]),
    "",
    "## Secret-like candidates (fingerprints only; never raw values)",
    ...(secretCandidates.length ? secretCandidates.map((item) =>
      "- " + safeSummaryText(item.kind) + " — " + safeSummaryText(item.sourceFile) + ":" + item.line +
      " — fingerprint sha256:" + item.fingerprint + " — candidate only",
    ) : ["- No secret-like assignments matched the static heuristics."]),
    "",
    ...(riskSignals.length ? riskSignals.map((item) =>
      "- " + item.kind + " — " + item.sourceFile + ":" + item.line + " — function: " +
      (item.functionName ?? "unknown") + " — candidate only",
    ) : ["- No configured static sink patterns matched."]),
    "",
    "## Coverage gaps and correlation notes",
    ...(incompleteMaps.length ? incompleteMaps.map((item) => "- SOURCE MAP GAP: " + safeSummaryURL(item.url) + " — " + item.status + " — " + safeSummaryText(item.note)) : []),
    ...(graph.notes.length ? graph.notes.map((note) => "- " + safeSummaryText(note)) : ["- No additional correlation notes."]),
    ...(inventoryGaps.length ? ["- NOT COMPLETE: one or more local JavaScript files/directories could not be fully read or analyzed; the exact gaps are listed above."] : []),
    ...(manifest?.pendingURLs?.length || pendingAssets.length ? ["- NOT COMPLETE: pending URL ingestion must be resumed."] : []),
    ...(failedAssets.length ? ["- NOT COMPLETE: one or more asset URLs failed to fetch."] : []),
    ...(skippedAssets.length ? ["- REVIEW REQUIRED: one or more URLs were skipped; inspect their recorded content type/status before calling coverage complete."] : []),
    ...(incompleteMaps.length ? ["- REVIEW REQUIRED: one or more referenced source maps remain unresolved or incomplete."] : []),
    ...(!inventoryGaps.length && !manifest?.pendingURLs?.length && !pendingAssets.length && !failedAssets.length && !skippedAssets.length && !incompleteMaps.length && !manifestWarning
      ? ["- No known gaps are recorded in the current saved artifacts. Confirm collection_complete=true and analysis_complete=true in the ingestion result before claiming exhaustive coverage."]
      : []),
    "",
    "Static candidates are leads, not findings. URL strings and same-host matches do not prove runtime calls or authorization defects.",
    JAVASCRIPT_ANALYSIS_END,
  ]
  return lines.join("\n") + "\n"
}

function renderCanonicalJavaScriptEndpointInventory(graph: JavaScriptCorrelationGraph): string {
  const endpoints = groupCanonicalJavaScriptEndpoints([graph])
  const lines = [
    JAVASCRIPT_ENDPOINTS_BEGIN,
    "# Canonical identity: normalized origin + path template. Each HTTP method is a separate operation nested under its endpoint.",
    "# Operation parameters, headers, auth/cookie clues, and captured request IDs remain method-specific. Traffic-only methods are not attributed to JavaScript.",
    ...endpoints.flatMap((endpoint) => {
      const inline = (value: string) => safeSummaryText(value).replace(/[|]/g, "/")
      const origin = normalizeEndpointOrigin(endpoint.origin)
      const endpointLine = "Endpoint: " + origin + endpoint.path + " — id=" + endpoint.id
      const sourceLine = "  endpoint_sources=[" + endpoint.sourceFiles.map(inline).join(", ") + "]"
      const operationLines = endpoint.operations.flatMap((operation) => {
        const method = operation.method?.trim().toUpperCase() || "UNKNOWN"
        const methodSources = (operation.methodEvidenceSources ?? []).join("+") || "unspecified"
        return [
          "  Operation: " + method + " — method_source=" + methodSources +
            " — traffic=" + (operation.observedInTraffic ? "observed" : "not-yet-observed") +
            " — confidence=" + operation.confidence,
          "    path_params=[" + (operation.pathParameters ?? []).map(inline).join(", ") + "]" +
            " — query_params=[" + (operation.queryParameters ?? []).map(inline).join(", ") + "]" +
            " — body_params=[" + (operation.bodyParameters ?? []).map(inline).join(", ") + "]",
          "    headers=[" + (operation.headerNames ?? []).map(inline).join(", ") + "]" +
            " — content_types=[" + (operation.contentTypes ?? []).map(inline).join(", ") + "]" +
            " — auth=[" + (operation.authSignals ?? []).map(inline).join(", ") + "]" +
            " — cookies=[" + (operation.cookieSignals ?? []).map(inline).join(", ") + "]",
          "    sources=[" + operation.sourceFiles.map(inline).join(", ") + "]" +
            " — request_ids=[" + operation.observedRequestIDs.join(", ") + "]",
        ]
      })
      const unassigned = endpoint.unattributed
      const hasUnassigned = unassigned.sourceFiles.length || unassigned.pathParameters.length ||
        unassigned.queryParameters.length || unassigned.bodyParameters.length ||
        unassigned.headerNames.length || unassigned.contentTypes.length || unassigned.authSignals.length ||
        unassigned.cookieSignals.length || unassigned.observedRequestIDs.length
      const unassignedLines = hasUnassigned ? [
        "  Method-unattributed endpoint evidence (not copied into any operation):",
        "    path_params=[" + unassigned.pathParameters.map(inline).join(", ") + "]" +
          " — query_params=[" + unassigned.queryParameters.map(inline).join(", ") + "]" +
          " — body_params=[" + unassigned.bodyParameters.map(inline).join(", ") + "]",
        "    headers=[" + unassigned.headerNames.map(inline).join(", ") + "]" +
          " — content_types=[" + unassigned.contentTypes.map(inline).join(", ") + "]" +
          " — auth=[" + unassigned.authSignals.map(inline).join(", ") + "]" +
          " — cookies=[" + unassigned.cookieSignals.map(inline).join(", ") + "]",
        "    sources=[" + unassigned.sourceFiles.map(inline).join(", ") + "]" +
          " — request_ids_without_method=[" + unassigned.observedRequestIDs.join(", ") + "]",
      ] : []
      return [endpointLine, sourceLine, ...operationLines, ...unassignedLines, ""]
    }),
    JAVASCRIPT_ENDPOINTS_END,
  ]
  return lines.join("\n") + "\n"
}


async function persistCanonicalJavaScriptArtifacts(
  workspace: Parameters<typeof TargetMemory.writeWorkspaceFile>[0],
  graph: JavaScriptCorrelationGraph,
  currentGraphFilename: string,
): Promise<{ analysisSummaryPath: string; endpointInventoryPath: string }> {
  const graphs = await collectCorrelationGraphs(workspace.workspacePath, workspace.targetURL, graph, currentGraphFilename)
  const combined = mergeGraphSnapshots(graphs)
  let manifest: CanonicalAssetManifest | undefined
  let manifestWarning: string | undefined
  try {
    const rawManifest = await readSafeWorkspaceText(workspace.workspacePath, path.posix.join("javascript", "asset-manifest.json"))
    if (rawManifest) {
      const parsed: unknown = JSON.parse(rawManifest)
      if (!parsed || typeof parsed !== "object" || (parsed as { schemaVersion?: unknown }).schemaVersion !== 1 ||
          !Array.isArray((parsed as { assets?: unknown }).assets)) {
        manifestWarning = "existing asset manifest has an unsupported schema and was not used to infer coverage"
      } else {
        manifest = parsed as CanonicalAssetManifest
      }
    }
  } catch (error) {
    manifestWarning = error instanceof Error ? error.message : String(error)
  }

  const summaryPath = "javascript-analysis.md"
  const endpointPath = "endpoints.txt"
  const existingSummary = await readSafeWorkspaceText(workspace.workspacePath, summaryPath)
  const existingEndpoints = await readSafeWorkspaceText(workspace.workspacePath, endpointPath)
  const summary = replaceManagedSection(
    existingSummary,
    JAVASCRIPT_ANALYSIS_BEGIN,
    JAVASCRIPT_ANALYSIS_END,
    renderCanonicalJavaScriptAnalysis(combined, manifest, manifestWarning, graphs.length),
  )
  const endpoints = replaceManagedSection(
    existingEndpoints,
    JAVASCRIPT_ENDPOINTS_BEGIN,
    JAVASCRIPT_ENDPOINTS_END,
    renderCanonicalJavaScriptEndpointInventory(combined),
  )
  const analysisSummaryPath = await TargetMemory.writeWorkspaceFile(workspace, summaryPath, summary)
  const endpointInventoryPath = await TargetMemory.writeWorkspaceFile(workspace, endpointPath, endpoints)
  return { analysisSummaryPath, endpointInventoryPath }
}




export type JavaScriptTesterCheckStatus = "planned" | "in_progress" | "completed" | "blocked" | "not_applicable"
export type JavaScriptTesterCaseStatus = "planned" | "in_progress" | "completed" | "blocked" | "stale"

export interface JavaScriptTesterCheck {
  id: string
  kind: string
  title: string
  status: JavaScriptTesterCheckStatus
  result?: string
  evidenceRequestIDs: string[]
}
export interface JavaScriptTesterCase {
  id: string
  candidateID: string
  method: string | null
  urlTemplate: string
  host: string | null
  path: string
  sourceFile: string
  sourceFunction: string | null
  sourceLine: number
  pathParameters: string[]
  queryParameters: string[]
  bodyParameters: string[]
  headerNames: string[]
  authSignals: string[]
  cookieSignals: string[]
  observedRequestIDs: string[]
  status: JavaScriptTesterCaseStatus
  stale: boolean
  checks: JavaScriptTesterCheck[]
}
const SURVEY_CHECK_STATUSES = new Set<JavaScriptTesterCheckStatus>(["planned", "in_progress", "completed", "blocked", "not_applicable"])
const SURVEY_CASE_STATUSES = new Set<JavaScriptTesterCaseStatus>(["planned", "in_progress", "completed", "blocked", "stale"])
function surveyKey(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 64) || "review"
}
function surveyRouteKey(host: string | null, path: string): string {
  const normalized = path.replace(/\/{2,}/g, "/").replace(/\/+$/, "") || "/"
  const shape = normalized.split("/").map((part) => /^\{[^}]+\}$/.test(part) ? "{}" : part).join("/")
  return (host?.toLowerCase() ?? "*") + shape
}

/** Generate a review plan only; it never sends a request or assumes a vulnerability. */
export function createJavaScriptTesterCases(
  requests: Array<JavaScriptRequestCandidate & { sourceFile: string; observedRequestIDs: string[]; recommendedChecks: string[] }>,
  endpoints: JavaScriptEndpointCandidate[],
  previousCases: JavaScriptTesterCase[] = [],
): JavaScriptTesterCase[] {
  const previous = new Map(previousCases.filter((item) => item && typeof item.id === "string" && Array.isArray(item.checks)).map((item) => [item.id, item]))
  const cases: JavaScriptTesterCase[] = []
  const structuredRoutes = new Set<string>()
  const buildCase = (input: {
    candidateID: string; method: string | null; urlTemplate: string; host: string | null; path: string;
    sourceFile: string; sourceFunction: string | null; sourceLine: number; pathParameters: string[];
    queryParameters: string[]; bodyParameters: string[]; headerNames: string[]; authSignals: string[];
    cookieSignals: string[]; observedRequestIDs: string[]; recommendedChecks: string[]
  }): JavaScriptTesterCase => {
    // Keep case identity stable when a new analysis adds/removes parameter/header hints.
    const id = "tester-case:" + createHash("sha256").update(JSON.stringify([
      input.sourceFile, input.sourceLine, input.method, input.host?.toLowerCase() ?? null, normalizedTemplateShape(input.path),
    ])).digest("hex").slice(0, 20)
    const old = previous.get(id)
    const titles = [
      "Capture or inspect the baseline request and response",
      ...(input.pathParameters.length ? ["Vary one path parameter using controlled test data"] : []),
      ...(input.queryParameters.length ? ["Compare omitted and altered query parameters one at a time"] : []),
      ...(input.bodyParameters.length ? ["Compare body fields, requiredness, and accepted data types"] : []),
      ...(input.headerNames.length ? ["Vary one non-secret header at a time and record response differences"] : ["Record relevant headers from a captured baseline"]),
      "Compare authenticated and unauthenticated behavior using authorized test accounts",
      "Compare session-cookie behavior one cookie at a time using authorized test sessions",
      "Check authorization with objects owned by controlled test accounts",
      "Review response fields for unintended sensitive-data exposure",
      "Confirm server-side input validation; static source alone is not a finding",
      ...input.recommendedChecks,
    ]
    const checks: JavaScriptTesterCheck[] = [...new Set(titles)].map((title) => {
      const kind = surveyKey(title)
      const checkID = "tester-check:" + createHash("sha256").update(id + "\0" + kind).digest("hex").slice(0, 16)
      const oldCheck = old?.checks?.find((item) => item && item.id === checkID)
      return {
        id: checkID, kind, title,
        status: oldCheck && SURVEY_CHECK_STATUSES.has(oldCheck.status) ? oldCheck.status : "planned",
        ...(oldCheck?.result ? { result: oldCheck.result } : {}),
        evidenceRequestIDs: [...new Set([...(oldCheck?.evidenceRequestIDs ?? []), ...input.observedRequestIDs]) ],
      }
    })
    return {
      id, candidateID: input.candidateID, method: input.method, urlTemplate: input.urlTemplate, host: input.host, path: input.path,
      sourceFile: input.sourceFile, sourceFunction: input.sourceFunction, sourceLine: input.sourceLine,
      pathParameters: [...new Set(input.pathParameters)], queryParameters: [...new Set(input.queryParameters)],
      bodyParameters: [...new Set(input.bodyParameters)], headerNames: [...new Set(input.headerNames)],
      authSignals: [...new Set(input.authSignals)], cookieSignals: [...new Set(input.cookieSignals)],
      observedRequestIDs: [...new Set([...(old?.observedRequestIDs ?? []), ...input.observedRequestIDs]) ],
      status: old && SURVEY_CASE_STATUSES.has(old.status) ? old.status : "planned", stale: false, checks,
    }
  }
  for (const request of requests) {
    structuredRoutes.add(surveyRouteKey(request.host, request.path))
    cases.push(buildCase({
      candidateID: request.id, method: request.method, urlTemplate: request.urlTemplate, host: request.host, path: request.path,
      sourceFile: request.sourceFile, sourceFunction: request.sourceFunction, sourceLine: request.sourceLine,
      pathParameters: request.pathParameters, queryParameters: request.queryParameters, bodyParameters: request.bodyParameters,
      headerNames: request.headerNames, authSignals: request.authSignals, cookieSignals: request.cookieSignals,
      observedRequestIDs: request.observedRequestIDs, recommendedChecks: request.recommendedChecks,
    }))
  }
  // Literal-only routes remain visible, but are marked as lacking method/shape evidence.
  for (const endpoint of endpoints) {
    if (structuredRoutes.has(surveyRouteKey(endpoint.host, endpoint.path))) continue
    for (const sourceFile of endpoint.sourceFiles.length ? endpoint.sourceFiles : ["(static route literal)"]) {
      cases.push(buildCase({
        candidateID: endpoint.id + ":" + sourceFile, method: null, urlTemplate: endpoint.literal,
        host: endpoint.host, path: endpoint.path, sourceFile, sourceFunction: null, sourceLine: 0,
        pathParameters: Array.from(endpoint.path.matchAll(/\{([^}]+)\}/g), (match) => match[1]!),
        queryParameters: [], bodyParameters: [], headerNames: [], authSignals: [], cookieSignals: [],
        observedRequestIDs: endpoint.observedRequestIDs,
        recommendedChecks: ["Determine HTTP method and request shape from an authorized captured request"],
      }))
    }
  }
  const currentIDs = new Set(cases.map((item) => item.id))
  for (const old of previous.values()) {
    if (currentIDs.has(old.id)) continue
    cases.push({...old, status: old.status === "completed" ? "completed" : "stale", stale: true,
      checks: old.checks.map((item) => ({...item, evidenceRequestIDs: [...item.evidenceRequestIDs]}))})
  }
  return cases.sort((a, b) => a.sourceFile.localeCompare(b.sourceFile) || a.sourceLine - b.sourceLine || a.path.localeCompare(b.path))
}

/**
 * Correlates JavaScript asset observations with already-recorded target requests,
 * response metadata, web-function models, request observations and findings. It
 * performs no HTTP requests and stores only redacted, size-limited response previews.
 */
export namespace JavaScriptCorrelation {
  export type BuildResult = {
    graph: JavaScriptCorrelationGraph
    workspacePath: string
    graphPath: string
    endpointPath: string
    testerSurveyPath: string
    analysisSummaryPath: string
    endpointInventoryPath: string
    noteID: string
    capturedAssetCount: number
  }

  const buildQueues = new Map<string, Promise<BuildResult>>()
  // Different asset selectors may be analyzed concurrently for the same target.
  // Serialize the read/merge/write cycle for the two canonical root artifacts so
  // one finished run cannot overwrite another run's newly merged endpoint rows.
  const canonicalArtifactQueues = new Map<string, Promise<unknown>>()

  async function serializeCanonicalArtifacts<T>(workspaceID: string, operation: () => Promise<T>): Promise<T> {
    const previous = canonicalArtifactQueues.get(workspaceID)
    const current = (previous ? previous.catch(() => undefined) : Promise.resolve()).then(operation)
    canonicalArtifactQueues.set(workspaceID, current)
    try {
      return await current
    } finally {
      if (canonicalArtifactQueues.get(workspaceID) === current) canonicalArtifactQueues.delete(workspaceID)
    }
  }

  export async function build(input: {
    sessionID: string
    targetURL: string
    javascriptURL?: string
    /** Permit workspace-local static analysis when no target request exists in this session tree. */
    localOnly?: boolean
  }): Promise<BuildResult> {
    const rootSessionID = Session.root(input.sessionID)
    const targetURL = TargetMemory.normalize(input.targetURL).targetURL
    // Serialize selectors per target/session because captured-index and canonical endpoint artifacts are shared.
    const key = rootSessionID + "\0" + targetURL
    const previous = buildQueues.get(key)
    const current = (previous ? previous.catch(() => undefined) : Promise.resolve(undefined)).then(() =>
      buildInternal(input),
    )
    buildQueues.set(key, current)
    try {
      return await current
    } finally {
      if (buildQueues.get(key) === current) buildQueues.delete(key)
    }
  }

  async function buildInternal(input: {
    sessionID: string
    targetURL: string
    javascriptURL?: string
    localOnly?: boolean
  }): Promise<BuildResult> {
    const rootSessionID = Session.root(input.sessionID)
    const normalizedTarget = TargetMemory.normalize(input.targetURL)
    const explicitJS = input.javascriptURL ? safeURL(input.javascriptURL) : undefined
    if (input.javascriptURL && !explicitJS) throw new Error("javascriptURL must be a valid HTTP(S) URL without embedded credentials.")
    const workspaceDecision = await TargetMemory.checkURLScope(input.targetURL)
    // A concrete authorized subdomain resolves to the same canonical root used
    // by ingestion. A root workspace may also be a policy container whose own
    // URL is not included; permit only that exact root identity when no scope
    // exclusion applies. Never fall back to an unconfigured child workspace.
    const exactRootContainer = Boolean(
      workspaceDecision.workspace &&
      workspaceDecision.workspace.parentTargetID === null &&
      workspaceDecision.workspace.targetKey === normalizedTarget.targetKey &&
      workspaceDecision.excludeMatches.length === 0,
    )
    const workspace = workspaceDecision.allowed && workspaceDecision.workspace
      ? workspaceDecision.workspace
      : exactRootContainer
        ? workspaceDecision.workspace
        : null
    if (!workspace) {
      throw new Error("No authorized target workspace matches this target: " + workspaceDecision.reason)
    }
    const sessionAssociated = TargetMemory.isObservedOrAncestorInSession(rootSessionID, workspace.targetURL)
    if (!sessionAssociated && !input.localOnly) {
      throw new Error("The target or one of its registered descendant workspaces was not observed in this session tree. Refusing to correlate unrelated target data.")
    }

    // Scope decisions are cached by origin/path because authorization can depend on
    // path prefixes as well as host, scheme, port, exclusions, and ancestor scopes.
    const scopeDecisionCache = new Map<string, Awaited<ReturnType<typeof TargetMemory.checkURLScope>>>()
    const scopeDecisionFor = async (value: string) => {
      const parsed = safeURL(value)
      const key = parsed ? parsed.origin + parsed.pathname : value
      const cached = scopeDecisionCache.get(key)
      if (cached) return cached
      const decision = await TargetMemory.checkURLScope(key)
      scopeDecisionCache.set(key, decision)
      return decision
    }
    // The canonical workspace may be a program/policy container whose URL is not
    // itself in scope. Require its persisted authorization manifest, then enforce
    // scope on every concrete script, response, and endpoint below.
    const rootScope = await TargetMemory.getScope(workspace.targetURL)
    if (!rootScope || rootScope.status !== "configured" || rootScope.scopeItems.length === 0) {
      throw new Error("Target workspace has no configured, non-empty persisted scope manifest.")
    }

    // Correlation may include the selected workspace and its descendants only.
    const relatedTargetIDs = new Set<string>([workspace.id])
    const targetFrontier = [workspace.id]
    while (targetFrontier.length > 0) {
      const parentID = targetFrontier.pop()!
      for (const child of TargetMemory.children(parentID)) {
        if (relatedTargetIDs.has(child.id)) continue
        relatedTargetIDs.add(child.id)
        targetFrontier.push(child.id)
      }
    }

    const filenameHost = (explicitJS?.hostname ?? new URL(workspace.targetURL).hostname).replace(/[^a-z0-9.-]/gi, "-").slice(0, 50)
    const snapshotSelector = explicitJS ? explicitJS.origin + explicitJS.pathname : "all-assets"
    const digest = createHash("sha256").update(JSON.stringify([workspace.targetURL, snapshotSelector])).digest("hex").slice(0, 12)
    const graphFilename = filenameHost + "-" + digest + ".json"
    const endpointFilename = filenameHost + "-" + digest + "-endpoints.json"
    const testerSurveyRelativePath = path.posix.join("findings", "tester-survey-" + digest + ".json")
    const legacyTesterSurveyRelativePath = path.posix.join("testing", "tester-survey-" + digest + ".json")
    const analysisCache = new Map<string, JavaScriptSourceAnalysis>()
    type IngestedAssetRecord = {
      url: string
      finalURL?: string
      source?: string
      status?: string
      contentHash?: string
      bytes?: number
      localPath?: string
      contentType?: string
      assetKind?: "javascript" | "html" | "source-map" | "non-js"
    }
    const ingestedAssetRecords: IngestedAssetRecord[] = []
    let ingestedManifestWarning: string | undefined
    try {
      const rawManifest = await readSafeWorkspaceText(workspace.workspacePath, "javascript/asset-manifest.json")
      if (rawManifest) {
        const parsed: unknown = JSON.parse(rawManifest)
        if (!parsed || typeof parsed !== "object" || (parsed as { schemaVersion?: unknown }).schemaVersion !== 1 ||
            !Array.isArray((parsed as { assets?: unknown }).assets)) {
          ingestedManifestWarning = "JavaScript asset manifest has an unsupported schema; URL-to-file relationships could not be reconstructed."
        } else {
          for (const item of (parsed as { assets: unknown[] }).assets) {
            if (!item || typeof item !== "object") continue
            const record = item as IngestedAssetRecord
            if (typeof record.url === "string" && (record.status === "downloaded" || record.status === "reused")) {
              ingestedAssetRecords.push(record)
            }
          }
        }
      }
    } catch (error) {
      ingestedManifestWarning = "JavaScript asset manifest could not be read: " + (error instanceof Error ? error.message : String(error))
    }
    const previousGraphPath = path.join(workspace.workspacePath, "javascript", graphFilename)
    try {
      const info = await fs.lstat(previousGraphPath)
      if (info.isFile() && !info.isSymbolicLink()) {
        const previous = JSON.parse(await fs.readFile(previousGraphPath, "utf-8")) as JavaScriptCorrelationGraph
        if (previous.schemaVersion === 2 && previous.targetURL === workspace.targetURL) {
          for (const source of previous.sourceFiles ?? []) {
            if (source.sha256 && source.analysis) {
              analysisCache.set(source.sha256, sanitizeJavaScriptSourceAnalysisForPersistence(source.analysis))
            }
          }
        }
      }
    } catch {
      // A missing/invalid old graph only disables the optimization; current evidence is still analyzed.
    }

    // An explicit asset URL must narrow source analysis, and must have been observed
    // and pass the same persisted scope/hierarchy gate as captured traffic.
    const inventoryIssues: JavaScriptInventoryIssue[] = []
    const sourceFiles = explicitJS
      ? []
      : await inventoryJavaScriptFiles(
          path.join(workspace.workspacePath, "javascript"),
          analysisCache,
          normalizedTarget.targetURL,
          inventoryIssues,
        )
    for (const file of sourceFiles) {
      const absoluteFile = path.resolve(workspace.workspacePath, file.relativePath)
      let matchingRecord = ingestedAssetRecords.find((record) =>
        record.localPath &&
        record.contentHash === file.sha256 &&
        path.resolve(record.localPath) === absoluteFile,
      )
      // Local inline scripts use a synthetic "#inline-N" path and their hash is
      // the script body, not the containing HTML response. Recover provenance
      // from the exact parent HTML asset so they deduplicate with captured inline
      // scripts and retain the real page URL.
      if (!matchingRecord) {
        const inlineMarker = file.relativePath.lastIndexOf("#inline-")
        if (inlineMarker > 0) {
          const parentPath = path.resolve(workspace.workspacePath, file.relativePath.slice(0, inlineMarker))
          matchingRecord = ingestedAssetRecords.find((record) =>
            record.localPath &&
            path.resolve(record.localPath) === parentPath &&
            (record.assetKind === "html" || /text\\/html|application\\/xhtml\\+xml/i.test(record.contentType ?? "")),
          )
        }
      }
      if (!matchingRecord) continue
      const sourceURL = safeURL(matchingRecord.finalURL ?? matchingRecord.url)
      if (!sourceURL) continue
      file.sourceURL = sourceURL.origin + sourceURL.pathname
      // Local source-map inventory creates virtual source records with a local:// map URL.
      // Restore the exact manifest-backed URL so the original JS sourceMappingURL can match it,
      // including signed query parameters without exposing those values in the rendered summary.
      if (file.sourceMapStatus) {
        linkLocalSourceMapSources(
          sourceFiles,
          file,
          sourceURL.origin + sourceURL.pathname,
        )
      }
    }

    const projectID = Instance.project.id
    // Static-only fallback must not import unrelated requests, credentials, or findings.
    const sessionIDsSet = new Set<string>(sessionAssociated ? [rootSessionID] : [])
    let frontier = sessionAssociated ? [rootSessionID] : []
    while (frontier.length > 0) {
      const children = Database.use((db) =>
        chunkForSQLiteIn(frontier).flatMap((parentIDs) =>
          db
            .select({ id: SessionTable.id })
            .from(SessionTable)
            .where(and(eq(SessionTable.project_id, projectID), inArray(SessionTable.parent_id, parentIDs)))
            .all()
            .map((row) => row.id),
        ).filter((id) => !sessionIDsSet.has(id)),
      )
      for (const child of children) sessionIDsSet.add(child)
      frontier = children
    }
    const sessionIDs = [...sessionIDsSet]

    const intel = Database.use((db) =>
      newestFirst(chunkForSQLiteIn(sessionIDs).flatMap((ids) =>
        db.select().from(IntelEntryTable).where(inArray(IntelEntryTable.session_id, ids)).all(),
      )),
    )
    const jsCandidates = intel
      .map((row) => ({
        row,
        url: javascriptAssetURL({
          type: row.type,
          title: row.title,
          detail: row.detail,
          asset: row.asset,
          tags: row.tags as string[] | null,
        }),
      }))
      .filter((item): item is { row: typeof intel[number]; url: URL } => Boolean(item.url))

    for (const record of ingestedAssetRecords) {
      if (!record.localPath || !record.contentHash) continue
      const localPath = path.resolve(record.localPath)
      const relativeLocalPath = path.relative(workspace.workspacePath, localPath)
      if (!relativeLocalPath || relativeLocalPath.startsWith("..") || path.isAbsolute(relativeLocalPath)) continue
      try {
        const localInfo = await fs.lstat(localPath)
        if (!localInfo.isFile() || localInfo.isSymbolicLink()) continue
      } catch {
        continue
      }
      const url = safeURL(record.finalURL ?? record.url)
      if (!url) continue
      const htmlRecord = record.assetKind === "html" ||
        /text\/html|application\/xhtml\+xml/i.test(record.contentType ?? "")
      const codeRecord = record.assetKind === "javascript" || record.assetKind === "source-map" ||
        /\.(?:m?js|cjs|map)(?:\.gz)?$/i.test(url.pathname) ||
        /javascript|ecmascript|source-map/i.test(record.contentType ?? "")
      if (htmlRecord || !codeRecord) continue
      const assetKey = url.origin + url.pathname
      if (jsCandidates.some((candidate) => candidate.url.origin + candidate.url.pathname === assetKey)) continue
      jsCandidates.push({
        row: {
          id: null as unknown as string,
          type: "javascript_file",
          title: url.pathname.split("/").pop() || "downloaded-javascript-asset",
          asset: url.href,
          source: record.source ?? "persisted JavaScript asset manifest",
          confidence_level: "observed",
          tags: ["javascript", "ingested", record.status ?? "downloaded", "sha256:" + record.contentHash],
        } as typeof intel[number],
        url,
      })
    }

    const targetURL = new URL(normalizedTarget.targetURL)
    const targetPath = targetURL.pathname.replace(/\/$/, "") || "/"
    if (explicitJS) {
      const explicitKey = explicitJS.origin + explicitJS.pathname
      const alreadyInIntel = jsCandidates.some((item) => item.url.origin + item.url.pathname === explicitKey)
      const observedInSession = alreadyInIntel || TargetMemory.isObservedInSession(rootSessionID, explicitJS.href)
      const explicitScope = await scopeDecisionFor(explicitJS.href)
      if (
        !observedInSession ||
        !explicitScope.allowed ||
        !explicitScope.workspace ||
        !relatedTargetIDs.has(explicitScope.workspace.id) ||
        !isJavaScriptAssetAllowed({
          targetURL: normalizedTarget.targetURL,
          javascriptURL: explicitJS.href,
          alreadyObserved: observedInSession,
        })
      ) {
        throw new Error("JavaScript asset must be observed in this session and pass the target's persisted scope/hierarchy gate.")
      }
      if (!alreadyInIntel) {
        jsCandidates.unshift({
          row: {
            id: null as unknown as string,
            type: "javascript_file",
            title: explicitJS.pathname.split("/").pop() || explicitJS.href,
            asset: explicitJS.href,
            source: "explicit analyst input",
            confidence_level: "unverified",
            tags: ["javascript", "explicit-input"],
          } as typeof intel[number],
          url: explicitJS,
        })
      }
    }
    // Do not pre-filter by hostname or pathname here: program scope can explicitly
    // allow a CDN or separate asset domain. The persisted scope gate below is authoritative.
    const filteredAssets = selectJavaScriptAssetsForCorrelation(jsCandidates, explicitJS)
    const seenAssets = new Set<string>()
    const assets: typeof filteredAssets = []
    for (const item of filteredAssets) {
      const key = item.url.origin + item.url.pathname
      if (seenAssets.has(key)) continue
      seenAssets.add(key)
      const decision = await scopeDecisionFor(item.url.href)
      if (!decision.allowed || !decision.workspace || !relatedTargetIDs.has(decision.workspace.id)) continue
      assets.push(item)
    }

    const requests = Database.use((db) =>
      newestFirst(chunkForSQLiteIn(sessionIDs).flatMap((ids) =>
        db.select().from(RequestTable).where(inArray(RequestTable.session_id, ids)).all(),
      )),
    )
    // HTML responses may own separately persisted inline-script captures. Include
    // their parent request even when the page host differs from the canonical target
    // host; the exact request URL still passes the persisted scope gate below.
    const capturedJavaScriptRequestIDs = new Set(
      Database.use((db) =>
        chunkForSQLiteIn(sessionIDs).flatMap((ids) =>
          db.select({ request_id: RequestJavaScriptCaptureTable.request_id })
            .from(RequestJavaScriptCaptureTable)
            .where(inArray(RequestJavaScriptCaptureTable.session_id, ids))
            .all()
            .map((row) => row.request_id),
        ),
      ),
    )
    const candidateRequests = requests.filter((request) => {
      const hostURL = safeURL(request.origin) ?? safeURL(request.page_url) ?? safeURL(request.host)
      if (!hostURL) return false
      const host = hostURL.hostname.toLowerCase()
      const isTargetHost = host === targetURL.hostname || host.endsWith("." + targetURL.hostname)
      const hasCapturedJavaScriptSource = capturedJavaScriptRequestIDs.has(request.id)
      // Keep already-captured script/map/inline-source parent requests even on a
      // different host or path. The authoritative persisted scope gate below decides
      // whether each exact response URL is eligible; a hostname match alone never does.
      const capturedScriptOrMap = isJavaScriptOrSourceMapResponse(
        request.response_content_type,
        request.normalized_path,
      ) || hasCapturedJavaScriptSource
      if (isTargetHost) {
        if (host === targetURL.hostname && targetPath !== "/" && !capturedScriptOrMap) {
          const pageURL = safeURL(request.page_url)
          const requestPathMatches = pathWithinScope(request.normalized_path, targetPath)
          const pagePathMatches = pageURL?.hostname === targetURL.hostname && pathWithinScope(pageURL.pathname, targetPath)
          if (!requestPathMatches && !pagePathMatches) return false
        }
        return true
      }
      return capturedScriptOrMap || assets.some((asset) => asset.url.hostname.toLowerCase() === host)
    })
    const relevantRequests: typeof candidateRequests = []
    const requestTargetWorkspaceIDs = new Map<string, string>()
    for (const request of candidateRequests) {
      const base = safeURL(request.origin) ?? safeURL(request.page_url) ?? safeURL(request.host)
      if (!base) continue
      let observedURL: string
      try { observedURL = new URL(request.normalized_path, base).href } catch { continue }
      const decision = await scopeDecisionFor(observedURL)
      if (!decision.allowed || !decision.workspace || !relatedTargetIDs.has(decision.workspace.id)) continue
      relevantRequests.push(request)
      requestTargetWorkspaceIDs.set(request.id, decision.workspace.id)
    }
    // Analyze bodies that were already captured as JavaScript, but never save the
    // source body to disk or the graph. The graph retains only hashes and route literals.
    const relevantRequestIDs = relevantRequests.map((request) => request.id)
    const relevantRequestByID = new Map(relevantRequests.map((request) => [request.id, request]))
    // Versioned captures are queried only through request rows that already passed
    // session-tree and persisted-scope checks. This preserves source history without
    // allowing a capture row to bypass the target boundary.
    const sourceCaptureRows = relevantRequestIDs.length
      ? Database.use((db) =>
          chunkForSQLiteIn(relevantRequestIDs).flatMap((ids) =>
            db.select().from(RequestJavaScriptCaptureTable)
              .where(inArray(RequestJavaScriptCaptureTable.request_id, ids))
              .all(),
          ),
        )
      : []
    const requestURL = (request: typeof requests[number]): URL | undefined => {
      const base = safeURL(request.origin) ?? safeURL(request.page_url) ?? safeURL(request.host)
      if (!base) return undefined
      try { return new URL(request.normalized_path, base) } catch { return undefined }
    }
    // Include direct links from both versioned captures and older RequestTable snapshots.
    const explicitSourceMapURLs = new Set<string>(
      explicitJS ? collectExplicitJavaScriptSourceMapURLs(explicitJS, [
        ...sourceCaptureRows.map((capture) => ({
          url: capture.source_url,
          responseBody: capture.source_content,
        })),
        ...relevantRequests.map((request) => ({
          url: requestURL(request)?.href,
          responseBody: request.javascript_source ?? request.processed_response,
        })),
      ]) : [],
    )
    const isExplicitAssetOrLinkedMap = (url: URL | undefined): boolean => {
      if (!url || !explicitJS) return false
      const key = url.origin + url.pathname
      return key === explicitJS.origin + explicitJS.pathname || explicitSourceMapURLs.has(key)
    }
    const versionedSourceInputs = sourceCaptureRows.flatMap((capture) => {
      const request = relevantRequestByID.get(capture.request_id)
      if (!request) return []
      if (explicitJS) {
        const capturedURL = safeURL(capture.source_url) ?? requestURL(request)
        if (!isExplicitAssetOrLinkedMap(capturedURL)) return []
      }
      return [{
        id: capture.id,
        requestID: capture.request_id,
        captureID: capture.id,
        url: capture.source_url ?? requestURL(request)?.href,
        origin: request.origin,
        pageURL: request.page_url,
        host: request.host,
        scheme: request.scheme,
        port: request.port,
        normalizedPath: request.normalized_path,
        responseContentType: capture.content_type ?? request.response_content_type,
        responseBody: capture.source_content,
      }]
    })
    // Older installations have only the RequestTable snapshot; include it even when
    // newer version rows exist so migration-era first captures are not lost. Content
    // URL/hash dedup merges identical rows and analyzes their bytes only once.
    const legacySourceRequests = explicitJS
      ? relevantRequests.filter((request) => {
          const observedURL = requestURL(request)
          return Boolean(observedURL && isExplicitAssetOrLinkedMap(observedURL))
        })
      : relevantRequests
    const legacySourceInputs = legacySourceRequests.map((request) => ({
      id: request.id,
      requestID: request.id,
      captureID: undefined,
      url: (request.origin ?? "") + request.normalized_path,
      origin: request.origin,
      pageURL: request.page_url,
      host: request.host,
      scheme: request.scheme,
      port: request.port,
      normalizedPath: request.normalized_path,
      responseContentType: request.response_content_type,
      responseBody: request.javascript_source ?? request.processed_response,
    }))
    // Preserve the actual in-scope JavaScript and source-map response bodies in the
    // target workspace. The graph stays redacted, while analysts can inspect the
    // original assets locally and resume analysis without depending on transient DB rows.
    // These inputs have already passed the persisted target-scope and session-tree checks.
    const capturedAssetInputs = [...versionedSourceInputs, ...legacySourceInputs]
    const capturedAssetIndexPath = "javascript/captured-index.json"
    type CapturedAssetIndexEntry = {
      url: string
      requestID: string
      captureID?: string
      contentType: string | null
      sha256: string
      bytes: number
      file: string
    }
    let capturedAssetIndex: CapturedAssetIndexEntry[] = []
    try {
      const indexInfo = await fs.lstat(path.join(workspace.workspacePath, capturedAssetIndexPath))
      if (!indexInfo.isFile() || indexInfo.isSymbolicLink()) {
        throw new Error("Captured JavaScript index is not a regular file; refusing to overwrite it.")
      }
      const previousIndex = JSON.parse(await fs.readFile(path.join(workspace.workspacePath, capturedAssetIndexPath), "utf-8"))
      if (
        previousIndex?.schemaVersion !== 1 ||
        previousIndex?.targetURL !== workspace.targetURL ||
        !Array.isArray(previousIndex.assets) ||
        !previousIndex.assets.every((asset: CapturedAssetIndexEntry) =>
          typeof asset?.file === "string" &&
          typeof asset.url === "string" &&
          typeof asset.requestID === "string" &&
          typeof asset.sha256 === "string" &&
          typeof asset.bytes === "number"
        )
      ) {
        throw new Error("Captured JavaScript index has an invalid schema, asset record, or target identity; refusing to overwrite it.")
      }
      capturedAssetIndex = previousIndex.assets
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error
    }
    const capturedAssetByFile = new Map(capturedAssetIndex.map((asset) => [asset.file, asset]))
    for (const item of capturedAssetInputs) {
      const sourceURL = safeURL(item.url) ?? safeURL(item.origin)
      if (!sourceURL || !isJavaScriptOrSourceMapResponse(item.responseContentType, sourceURL.pathname)) continue
      const body = unwrapProcessedResponseBody(item.responseBody ?? "").body
      if (!body.trim()) continue
      const sha256 = createHash("sha256").update(body, "utf-8").digest("hex")
      const extension = isSourceMapResponse(item.responseContentType, sourceURL.pathname) ? ".map" : ".js"
      const relativeFile = "javascript/captured/" +
        sha256.slice(0, 16) + "-" +
        createHash("sha256").update(sourceURL.origin + sourceURL.pathname).digest("hex").slice(0, 8) +
        extension
      await TargetMemory.writeWorkspaceFile(workspace, relativeFile, body)
      capturedAssetByFile.set(relativeFile, {
        url: sourceURL.href,
        requestID: item.requestID,
        ...(item.captureID ? { captureID: item.captureID } : {}),
        contentType: item.responseContentType ?? null,
        sha256,
        bytes: Buffer.byteLength(body, "utf-8"),
        file: relativeFile,
      })
    }
    capturedAssetIndex = [...capturedAssetByFile.values()].sort((left, right) => left.file.localeCompare(right.file))
    await TargetMemory.writeWorkspaceFile(workspace, capturedAssetIndexPath, JSON.stringify({
      schemaVersion: 1,
      targetURL: workspace.targetURL,
      updatedAt: new Date().toISOString(),
      assetCount: capturedAssetIndex.length,
      assets: capturedAssetIndex,
      note: "Raw assets are retained only for responses that passed the persisted target scope/session checks. Treat source contents as sensitive local evidence; never publish raw values in reports.",
    }, null, 2) + "\n")

    const capturedSources = extractCapturedJavaScriptSources(
      capturedAssetInputs,
      analysisCache,
    )
    // Keep every distinct source location/URL for provenance. analysisCache is keyed by
    // content hash, so identical bytes are analyzed once but may produce multiple origin-aware
    // source records; this matters when the same bundle is served from different hosts.
    // Merge by content and canonical source identity, not the storage directory:
    // ingestion writes javascript/assets/, while request captures write javascript/captured/.
    const mergedSourceFiles = mergeCapturedAndLocalJavaScriptSources(sourceFiles, capturedSources)
    const sourceMapIdentity = (value: string) => {
      const url = safeURL(value)
      return url ? url.origin + url.pathname : value.split(/[?#]/, 1)[0]!
    }
    const sourceMapRecordsByURL = new Map<string, JavaScriptSourceFile[]>()
    for (const file of mergedSourceFiles) {
      if (!file.sourceMapURL || file.sourceMapSource || file.sourceMapInline) continue
      const identity = sourceMapIdentity(file.sourceMapURL)
      const records = sourceMapRecordsByURL.get(identity) ?? []
      records.push(file)
      sourceMapRecordsByURL.set(identity, records)
    }
    const sourceMapReferenceInputs = new Map<string, Set<string>>()
    for (const file of mergedSourceFiles) {
      for (const sourceMapURL of file.sourceMapURLs ?? []) {
        const files = sourceMapReferenceInputs.get(sourceMapURL) ?? new Set<string>()
        files.add(file.relativePath)
        sourceMapReferenceInputs.set(sourceMapURL, files)
      }
    }
    const sourceMapReferences: NonNullable<JavaScriptCorrelationGraph["sourceMapReferences"]> = []
    for (const [url, sources] of sourceMapReferenceInputs) {
      const decision = await scopeDecisionFor(url)
      const scopeAllowed = decision.allowed && Boolean(decision.workspace) && relatedTargetIDs.has(decision.workspace!.id)
      const capturedMaps = sourceMapRecordsByURL.get(sourceMapIdentity(url)) ?? []
      let status: NonNullable<JavaScriptCorrelationGraph["sourceMapReferences"]>[number]["status"]
      let note: string
      if (!scopeAllowed) {
        status = "out-of-scope"
        note = "Reference was recorded from in-scope source, but the source-map URL does not pass the persisted target-scope/hierarchy gate; do not retrieve it."
      } else if (capturedMaps.length > 0 && capturedMaps.every((file) => file.sourceMapStatus === "analyzed")) {
        status = "analyzed"
        note = "Captured source map was parsed and embedded source contents were analyzed as separate virtual source records."
      } else if (capturedMaps.length) {
        const preference: Array<NonNullable<JavaScriptSourceFile["sourceMapStatus"]>> = ["truncated", "invalid-json", "unsupported", "no-sources-content", "partial-sources-content"]
        status = preference.find((candidate) => capturedMaps.some((file) => file.sourceMapStatus === candidate)) ?? "unsupported"
        note = capturedMaps.flatMap((file) => file.analysis?.notes ?? []).filter((item) => item.startsWith("SOURCE MAP")).join(" ") || "Map response was captured but no embedded source content was analyzed."
      } else {
        status = "referenced-not-captured"
        note = "Source map is referenced by JavaScript but was not present in the current captured responses. Retrieve it only through the normal scope-enforced recon/browser workflow, then rerun correlation."
      }
      sourceMapReferences.push({ url, sourceFiles: [...sources].sort(), status, note })
    }
    // Analysis artifacts keep hashes, source locations, fingerprints, and summaries only—never raw secret values or embedded source code.
    const persistedSourceFiles = mergedSourceFiles.map(sanitizeJavaScriptSourceFileForPersistence)
    const requestIDs = relevantRequests.map((request) => request.id)
    const requestIDSet = new Set(requestIDs)
    const webFunctions = requestIDs.length
      ? Database.use((db) =>
          newestFirst(chunkForSQLiteIn(requestIDs).flatMap((ids) =>
            db.select().from(WebFunctionTable).where(inArray(WebFunctionTable.request_id, ids)).all(),
          )),
        )
      : []
    const observations = requestIDs.length
      ? Database.use((db) =>
          newestFirst(
            chunkForSQLiteIn(requestIDs)
              .flatMap((ids) =>
                db.select().from(RequestObservationTable)
                  .where(inArray(RequestObservationTable.request_id, ids))
                  .all(),
              )
              // request IDs were selected only after this session-tree and target-scope
              // gate; retain the session check as a defense against inconsistent rows.
              .filter((row) => sessionIDsSet.has(row.session_id)),
          ),
        )
      : []
    const findingRows = Database.use((db) =>
      newestFirst(chunkForSQLiteIn(sessionIDs).flatMap((ids) =>
        db.select().from(VulnerabilityTable).where(inArray(VulnerabilityTable.session_id, ids)).all(),
      )),
    )
    const findings: typeof findingRows = []
    for (const finding of findingRows) {
      if (!finding.endpoint) continue
      if (finding.target_id && !relatedTargetIDs.has(finding.target_id)) continue
      const endpoint = finding.endpoint.trim()
      const endpointURL = safeURL(endpoint)
      if (endpoint.startsWith("http://") || endpoint.startsWith("https://")) {
        if (!endpointURL) continue
        const decision = await scopeDecisionFor(endpointURL.href)
        if (!decision.allowed || !decision.workspace || !relatedTargetIDs.has(decision.workspace.id)) continue
        if (finding.target_id && finding.target_id !== decision.workspace.id) continue
        findings.push(finding)
        continue
      }

      // Legacy path-only findings without a target foreign key are ambiguous across
      // multi-host sessions. Do not attach them to whichever target happens to share a path.
      if (!finding.target_id) continue
      const endpointValue = endpoint.replace(/^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE)\s+/i, "")
      const pathEndpointURL = safeURL(endpointValue)
      const endpointPath = (pathEndpointURL?.pathname ?? endpointValue).split(/[?#]/, 1)[0]!
      const matchesAttributedRequest = relevantRequests.some((request) => {
        if (requestTargetWorkspaceIDs.get(request.id) !== finding.target_id) return false
        const requestURL = observedRequestBaseURL(request)
        if (pathEndpointURL && requestURL?.origin !== pathEndpointURL.origin) return false
        return matchesEndpointPathTemplate(endpointPath, request.normalized_path)
      })
      if (matchesAttributedRequest) findings.push(finding)
    }

    const graph: JavaScriptCorrelationGraph = {
      schemaVersion: 2,
      createdAt: new Date().toISOString(),
      targetURL: normalizedTarget.targetURL,
      sessionID: rootSessionID,
      javascriptAssets: [
        ...assets.map((item) => ({
          intelEntryID: item.row.id ?? null,
          url: item.url.origin + item.url.pathname,
          title: item.row.title,
          discoveredBy: item.row.source ?? null,
          confidence: item.row.confidence_level ?? null,
          tags: (item.row.tags as string[] | null) ?? [],
        })),
        // A captured JavaScript response is direct evidence of an asset even when
        // no IntelEntry was created for its observed descendant workspace. Keep
        // it in the graph so policy-root correlation doesn't silently lose scripts.
        ...capturedSources
          .filter((file) => file.sourceURL && /\.(?:m?js|cjs)(?:[?#]|$)/i.test(file.sourceURL))
          .filter((file) => !assets.some((asset) => asset.url.origin + asset.url.pathname === file.sourceURL!.split(/[?#]/, 1)[0]))
          .map((file) => ({
            intelEntryID: null,
            url: file.sourceURL!.split(/[?#]/, 1)[0]!,
            title: file.basename,
            discoveredBy: "captured JavaScript response",
            confidence: "observed",
            tags: ["javascript", "observed", "captured-response"],
          })),
        ...sourceMapReferences
          .filter((item) => item.status !== "out-of-scope")
          .filter((item) => !assets.some((asset) => asset.url.origin + asset.url.pathname === item.url))
          .map((item) => ({
            intelEntryID: null,
            url: item.url,
            title: item.url.split("/").pop() || "source-map.map",
            discoveredBy: "sourceMappingURL reference in " + item.sourceFiles.join(", "),
            confidence: item.status === "analyzed" ? "observed" : "candidate",
            tags: ["javascript", "source-map", item.status],
          })),
      ],
      sourceFiles: persistedSourceFiles,
      sourceMapReferences,
      javascriptAnalysis: {
        functions: mergedSourceFiles.flatMap((file) => (file.analysis?.functions ?? []).map((item) => ({ ...item, sourceFile: file.relativePath }))),
        requestCandidates: mergedSourceFiles.flatMap((file) => (file.analysis?.requests ?? []).flatMap((item) => {
          const itemURL = safeURL(item.urlTemplate)
          const explicitOrigin = item.origin ?? itemURL?.origin ?? null
          const explicitHost = item.host ?? itemURL?.host ?? null
          const matchingRequests = relevantRequests.flatMap((request) => {
            const requestURL = observedRequestBaseURL(request)
            if (!requestURL) return []
            if (explicitOrigin && requestURL.origin.toLowerCase() !== explicitOrigin.toLowerCase()) return []
            if (explicitHost && requestURL.host.toLowerCase() !== explicitHost.toLowerCase()) return []
            if (item.method && request.method.toUpperCase() !== item.method.toUpperCase()) return []
            return matchesEndpointPathTemplate(item.path, request.normalized_path) ? [{ request, url: requestURL }] : []
          })
          const variants = new Map<string, { origin: string | null; host: string | null; matching: typeof matchingRequests }>()
          if (explicitOrigin) {
            variants.set(explicitOrigin.toLowerCase(), {
              origin: explicitOrigin.toLowerCase(),
              host: explicitHost?.toLowerCase() ?? safeURL(explicitOrigin)?.host.toLowerCase() ?? null,
              matching: matchingRequests.filter((entry) => entry.url.origin.toLowerCase() === explicitOrigin.toLowerCase()),
            })
          } else if (matchingRequests.length) {
            // Relative routes may be used against several authorized origins (for example,
            // a shared bundle used by both app.example and api.example). Keep those endpoint
            // identities separate rather than guessing from where the JS file was hosted.
            for (const entry of matchingRequests) {
              const origin = entry.url.origin.toLowerCase()
              const existing = variants.get(origin)
              if (existing) existing.matching.push(entry)
              else variants.set(origin, { origin, host: entry.url.host.toLowerCase(), matching: [entry] })
            }
          } else {
            variants.set("*", { origin: null, host: explicitHost?.toLowerCase() ?? null, matching: [] })
          }
          const relatedRiskSignals = (file.analysis?.riskSignals ?? []).filter((signal) =>
            Boolean(item.sourceFunction) && signal.functionName === item.sourceFunction,
          )
          const riskSpecificChecks = relatedRiskSignals.map((signal) => {
            const functionLabel = item.sourceFunction ?? "the associated function"
            switch (signal.kind) {
              case "dom-html-sink":
              case "html-fragment-insertion":
              case "document-write-sink":
                return "DOM-XSS review: trace attacker-controlled input to the HTML sink in " + functionLabel + "; verify contextual escaping/sanitization and use only a harmless marker in an authorized test account."
              case "dynamic-code-execution":
              case "string-timer-execution":
                return "Dynamic-code review: trace whether attacker-controlled data reaches code evaluation in " + functionLabel + "; the sink marker alone does not prove code injection."
              case "navigation-or-redirect-sink":
                return "Navigation/open-redirect review: trace the URL source in " + functionLabel + " and confirm allowlisting with a controlled destination."
              case "cross-window-message":
              case "wildcard-postmessage-origin":
              case "message-event-handler":
                return "postMessage trust-boundary review: verify source-origin checks, message schema, and sensitive actions in " + functionLabel + "; a wildcard/source marker alone is not a confirmed issue."
              case "client-side-token-storage":
                return "Client-storage review: determine whether the stored value is a private credential and whether a demonstrated script-injection path can read it; public client identifiers are not secrets."
              case "document-cookie-write":
                return "Cookie/session review: trace the cookie value and purpose, then verify server-side session protections; a JavaScript cookie write alone does not establish session compromise."
              case "dynamic-regexp":
                return "Regular-expression review: establish whether untrusted input controls the pattern or input length, then use bounded, low-impact validation."
              case "prototype-mutation":
                return "Prototype-pollution review: trace attacker-controlled keys into the mutation and validate only with a benign property on test-owned data."
              case "csrf-review-state-changing-cookie-request":
                return "CSRF review: this state-changing credentialed request has static cookie clues; verify server-side token/origin/Fetch Metadata enforcement with an authorized baseline and negative control."
              default:
                return "Review static risk signal " + signal.kind + " in " + functionLabel + "; trace data flow and prove behavior before classifying a vulnerability."
            }
          })
          const recommendedChecks = [
            "Baseline replay and response capture",
            ...(item.pathParameters.length ? ["Compare path parameter type/boundary values using controlled test data"] : []),
            ...(item.queryParameters.length ? ["Compare omitted and altered query parameters"] : []),
            ...(item.bodyParameters.length ? ["Compare required/optional body fields and expected types"] : []),
            ...(["POST", "PUT", "PATCH", "DELETE"].includes(item.method?.toUpperCase() ?? "") &&
              item.cookieSignals.some((signal) => [
                "credentialed-request-may-send-cookies",
                "cookie-header-signal",
                "document-cookie-access",
              ].includes(signal))
              ? ["Review CSRF defenses for this state-changing credentialed request: verify server-side token/origin/Fetch Metadata validation with an authorized browser baseline; token/header presence alone is not proof."]
              : []),
            ...((file.sourceRequestIDs?.length ?? (file.sourceRequestID ? 1 : 0)) > 0
              ? ["Inspect the original captured JavaScript response(s) via request-detail tooling using request ID(s) " + (file.sourceRequestIDs ?? [file.sourceRequestID]).filter(Boolean).join(", ")]
              : []),
            ...riskSpecificChecks,
            ...(relatedRiskSignals.length ? ["Confirm source-to-sink data flow for each linked risk signal; static links remain candidates, not findings."] : []),
            ...(item.authSignals.length || item.cookieSignals.length ? ["Compare authenticated and unauthenticated/session-cookie behavior using controlled accounts"] : ["Determine authentication requirements from captured requests and controlled account tests"]),
            "Check authorization with accounts that own only their own test data",
            "Manually confirm server-side validation; static JavaScript alone is not proof",
          ]
          return [...variants.values()].map((variant) => ({
            ...item,
            host: variant.host,
            origin: variant.origin,
            urlTemplate: variant.origin ? variant.origin + item.path : item.urlTemplate,
            sourceFile: file.relativePath,
            observedRequestIDs: [...new Set(variant.matching.map((entry) => entry.request.id))],
            recommendedChecks,
          }))
        })),
        secretCandidates: persistedSourceFiles.flatMap((file) => (file.analysis?.secretCandidates ?? []).map((item) => ({ ...item, sourceFile: file.relativePath }))),
        roleHints: mergedSourceFiles.flatMap((file) => (file.analysis?.roleHints ?? []).map((item) => ({ ...item, sourceFile: file.relativePath }))),
        riskSignals: mergedSourceFiles.flatMap((file) => (file.analysis?.riskSignals ?? []).map((item) => ({ ...item, sourceFile: file.relativePath }))),
        applicationHints: mergedSourceFiles.flatMap((file) => (file.analysis?.applicationHints ?? []).map((item) => ({ ...item, sourceFile: file.relativePath }))),
        workflowSignals: mergedSourceFiles.flatMap((file) => (file.analysis?.workflowSignals ?? []).map((item) => ({ ...item, sourceFile: file.relativePath }))),
        dataExposureSignals: mergedSourceFiles.flatMap((file) => (file.analysis?.dataExposureSignals ?? []).map((item) => ({ ...item, sourceFile: file.relativePath }))),
      },
      endpointCandidates: [],
      evidence: relevantRequests
        .filter((request) => request.response_status !== null || Boolean(request.processed_response))
        .map((request) => ({
          id: "response:" + request.id,
          requestID: request.id,
          kind: "captured-response" as const,
          responseStatus: request.response_status ?? null,
          contentType: request.response_content_type ?? null,
          responseSize: request.response_size ?? null,
          redactedPreview: safeCorrelationResponsePreview({
            id: request.id,
            normalizedPath: request.normalized_path,
            responseContentType: request.response_content_type,
            processedResponse: request.processed_response,
          }),
        })),
      requests: relevantRequests.map((request) => {
        // Older captures may have host/page_url but no normalized origin. Build
        // a URL only from an observed base; never invent a host for path-only rows.
        const base = observedRequestBaseURL(request)
        let observedURL: string | null = null
        if (base) {
          try {
            observedURL = new URL(request.normalized_path, base).href
          } catch {
            observedURL = null
          }
        }
        return {
          id: request.id,
          method: request.method,
          host: request.host ?? base?.host ?? null,
          url: observedURL,
          normalizedPath: request.normalized_path,
          responseStatus: request.response_status ?? null,
          responseContentType: request.response_content_type ?? null,
          responseSize: request.response_size ?? null,
          responsePreview: safeCorrelationResponsePreview({
            id: request.id,
            normalizedPath: request.normalized_path,
            responseContentType: request.response_content_type,
            processedResponse: request.processed_response,
          }),
          hasRawRequest: Boolean(request.raw_request),
        }
      }),
      webFunctions: webFunctions.map((fn) => ({
        id: fn.id,
        name: fn.name,
        actionType: fn.action_type,
        requestID: fn.request_id,
        roleID: fn.role_id ?? null,
        objects: (fn.objects as string[] | null) ?? [],
      })),
      observations: observations.map((row) => ({
        id: row.id,
        requestID: row.request_id ?? null,
        credentialID: row.credential_id ?? null,
        operationGroupHash: row.op_group_hash,
        slots: ((row.slots as Array<{loc:string;name:string;value?:string;retained?:boolean}> | null) ?? []).map((slot) => ({
          location: slot.loc,
          name: slot.name,
          retained: slot.retained,
        })),
      })),
      findings: findings.map((finding) => ({
        id: finding.id,
        title: finding.title,
        severity: finding.severity,
        status: finding.status,
        endpoint: finding.endpoint ?? null,
        targetID: finding.target_id ?? null,
      })),
      edges: [],
      notes: [
        ...inventoryIssues.map((issue) =>
          `JAVASCRIPT INVENTORY GAP: ${issue.relativePath} — ${issue.stage} failed (error ${issue.code}); this item was not completely analyzed. Fix the file/directory access and rerun JavaScript correlation.`,
        ),
        ...(ingestedManifestWarning ? [ingestedManifestWarning] : []),
        ...(!sessionAssociated ? [
          "LOCAL-ONLY CORRELATION: the persisted scope manifest authorized workspace asset ingestion, but this target was not observed in the current session tree. Static local source files were analyzed without importing session requests, credentials, observations, or findings.",
        ] : []),
      ],
    }

    const assetBasenames = new Map(graph.javascriptAssets.map((asset) => [path.posix.basename(new URL(asset.url).pathname).toLowerCase(), asset.url]))
    for (const file of graph.sourceFiles) {
      const matchedURL = assetBasenames.get(file.basename.toLowerCase())
      if (matchedURL) {
        graph.edges.push({
          from: "javascript-file:" + file.relativePath,
          to: "javascript:" + matchedURL,
          relation: "basename-match",
          confidence: "candidate",
          evidence: "Local file and observed asset share a basename; verify the content/hash before treating them as identical.",
        })
      }
    }
    for (const file of graph.sourceFiles) {
      const absoluteFile = path.resolve(workspace.workspacePath, file.relativePath)
      for (const record of ingestedAssetRecords) {
        if (!record.localPath || record.contentHash !== file.sha256 || path.resolve(record.localPath) !== absoluteFile) continue
        const sourceURL = safeURL(record.finalURL ?? record.url)
        if (!sourceURL) continue
        const assetURL = sourceURL.origin + sourceURL.pathname
        if (!graph.javascriptAssets.some((asset) => asset.url === assetURL)) continue
        graph.edges.push({
          from: "javascript-file:" + file.relativePath,
          to: "javascript:" + assetURL,
          relation: "content-hash-match",
          confidence: "direct",
          evidence: "The local asset manifest maps this exact SHA-256 content hash to the recorded, scope-checked asset URL.",
        })
      }
    }

    graph.endpointCandidates = mergeStructuredJavaScriptEndpoints(
      correlateStaticJavaScriptEndpoints(graph.sourceFiles, graph.requests, targetURL.hostname, targetURL.origin),
      graph.javascriptAnalysis.requestCandidates,
      graph.requests,
    )
    const scenarioEndpointRecords = groupCanonicalJavaScriptEndpoints([{
      endpointCandidates: graph.endpointCandidates,
      requests: graph.requests,
    }])
    const scenarioEndpoints = scenarioEndpointRecords.map((endpoint) => ({
      id: endpoint.id,
      path: endpoint.path,
      method: null,
      sourceFiles: endpoint.sourceFiles,
      observedRequestIDs: [...new Set([
        ...endpoint.unattributed.observedRequestIDs,
        ...endpoint.operations.flatMap((operation) => operation.observedRequestIDs),
      ])],
    }))
    graph.additionalScenarios = createJavaScriptScenarioCandidates({
      sourceFiles: graph.sourceFiles,
      requestCandidates: graph.javascriptAnalysis.requestCandidates,
      endpoints: scenarioEndpoints,
      workflowSignals: graph.javascriptAnalysis.workflowSignals ?? [],
      applicationHints: graph.javascriptAnalysis.applicationHints ?? [],
      roleHints: graph.javascriptAnalysis.roleHints,
      riskSignals: graph.javascriptAnalysis.riskSignals,
      secretCandidates: graph.javascriptAnalysis.secretCandidates,
      dataExposureSignals: graph.javascriptAnalysis.dataExposureSignals ?? [],
    })
    for (const endpoint of graph.endpointCandidates) {
      for (const sourceFile of endpoint.sourceFiles) {
        graph.edges.push({
          from: "javascript-file:" + sourceFile,
          to: endpoint.id,
          relation: "contains-static-endpoint",
          confidence: "candidate",
          evidence: "Static route literal was extracted from this local JavaScript file; runtime execution is not proven.",
        })
      }
      for (const requestID of endpoint.observedRequestIDs) {
        graph.edges.push({
          from: endpoint.id,
          to: "request:" + requestID,
          relation: "static-endpoint-path-overlap",
          confidence: "candidate",
          evidence: "The route pattern overlaps a captured request path. This confirms traffic observation only, not that this source file issued the request.",
        })
      }
    }
    for (const candidate of graph.javascriptAnalysis.requestCandidates) {
      const matchingFunctions = candidate.sourceFunction
        ? graph.javascriptAnalysis.functions
            .filter((fn) => fn.sourceFile === candidate.sourceFile && fn.name === candidate.sourceFunction && fn.line <= candidate.sourceLine)
            .sort((a, b) => b.line - a.line)
        : []
      const fn = matchingFunctions[0]
      const requestNode = "javascript-request-candidate:" + createHash("sha256")
        .update([candidate.sourceFile, candidate.sourceLine, candidate.method ?? "", candidate.urlTemplate].join("\\0"))
        .digest("hex").slice(0, 16)
      if (fn) {
        graph.edges.push({
          from: "javascript-function:" + candidate.sourceFile + ":" + fn.line + ":" + fn.name,
          to: requestNode,
          relation: "function-contains-request-candidate",
          confidence: "candidate",
          evidence: "Static lexical function attribution links this request call to the nearest matching function declaration; review minified or complex syntax manually.",
        })
      }
      for (const endpoint of scenarioEndpointRecords) {
        if (!endpoint.sourceFiles.includes(candidate.sourceFile)) continue
        if (normalizedTemplateShape(endpoint.path) !== normalizedTemplateShape(candidate.path)) continue
        const sameSourceOperation = candidate.method
          ? endpoint.operations.some((operation) =>
              operation.method?.toUpperCase() === candidate.method?.toUpperCase() &&
              operation.sourceFiles.includes(candidate.sourceFile),
            )
          : endpoint.unattributed.sourceFiles.includes(candidate.sourceFile)
        if (!sameSourceOperation) continue
        graph.edges.push({
          from: requestNode,
          to: endpoint.id,
          relation: "request-candidate-maps-to-endpoint",
          confidence: "candidate",
          evidence: "The structured request call maps to one canonical origin/path endpoint; its method-specific operation retains the source file and contract. Static source evidence does not prove runtime execution.",
        })
      }
    }

    for (const scenario of graph.additionalScenarios ?? []) {
      const scenarioNode = "javascript-scenario:" + scenario.id
      graph.edges.push({
        from: "javascript-file:" + scenario.sourceFile,
        to: scenarioNode,
        relation: "source-supports-scenario-candidate",
        confidence: "candidate",
        evidence: "Static workflow/application/role/risk/secret markers at source lines " + scenario.sourceLines.join(", ") + " motivate this review scenario; they do not establish a vulnerability.",
      })
      for (const endpointID of scenario.relatedEndpointIDs) {
        graph.edges.push({
          from: scenarioNode,
          to: endpointID,
          relation: "scenario-reviews-endpoint-candidate",
          confidence: "candidate",
          evidence: "The scenario and endpoint share source-linked JavaScript evidence; test relevance and server behavior remain unverified.",
        })
      }
      for (const candidateID of scenario.relatedRequestCandidateIDs) {
        const candidate = graph.javascriptAnalysis.requestCandidates.find((item) => item.id === candidateID)
        if (!candidate) continue
        const requestNode = "javascript-request-candidate:" + createHash("sha256")
          .update([candidate.sourceFile, candidate.sourceLine, candidate.method ?? "", candidate.urlTemplate].join("\\0"))
          .digest("hex").slice(0, 16)
        graph.edges.push({
          from: scenarioNode,
          to: requestNode,
          relation: "scenario-reviews-request-candidate",
          confidence: "candidate",
          evidence: "The scenario and structured request candidate share source/function context; the candidate may be static-only and is not proof of a transmitted request.",
        })
      }
      for (const requestID of scenario.observedRequestIDs) {
        graph.edges.push({
          from: scenarioNode,
          to: "request:" + requestID,
          relation: "scenario-correlates-observed-request",
          confidence: "candidate",
          evidence: "A request ID is associated with a same-source request/endpoint candidate; verify the exact operation, identity, and response before testing.",
        })
      }
      for (const riskID of scenario.riskSignalIDs) {
        graph.edges.push({
          from: scenarioNode,
          to: "javascript-risk:" + riskID,
          relation: "scenario-reviews-risk-signal",
          confidence: "candidate",
          evidence: "A static risk signal contributed to this review scenario; source-to-sink reachability and impact are not confirmed.",
        })
      }
    }

    for (const risk of graph.javascriptAnalysis.riskSignals) {
      const riskNode = "javascript-risk:" + risk.id
      graph.edges.push({
        from: "javascript-file:" + risk.sourceFile,
        to: riskNode,
        relation: "file-contains-risk-signal",
        confidence: "candidate",
        evidence: "Static risk pattern at source line " + risk.line + "; source-to-sink data flow and exploitability remain unverified.",
      })
      const matchingFunctions = risk.functionName
        ? graph.javascriptAnalysis.functions
            .filter((fn) => fn.sourceFile === risk.sourceFile && fn.name === risk.functionName && fn.line <= risk.line)
            .sort((a, b) => b.line - a.line)
        : []
      const fn = matchingFunctions[0]
      if (fn) {
        graph.edges.push({
          from: "javascript-function:" + risk.sourceFile + ":" + fn.line + ":" + fn.name,
          to: riskNode,
          relation: "function-contains-risk-signal",
          confidence: "candidate",
          evidence: "The static risk signal was attributed to this function by lexical source ranges; confirm attribution in minified/complex code.",
        })
      }
      for (const candidate of graph.javascriptAnalysis.requestCandidates) {
        if (!risk.functionName || candidate.sourceFile !== risk.sourceFile || candidate.sourceFunction !== risk.functionName) continue
        const requestNode = "javascript-request-candidate:" + createHash("sha256")
          .update([candidate.sourceFile, candidate.sourceLine, candidate.method ?? "", candidate.urlTemplate].join("\\0"))
          .digest("hex").slice(0, 16)
        graph.edges.push({
          from: riskNode,
          to: requestNode,
          relation: "risk-signal-shares-function",
          confidence: "candidate",
          evidence: "The risk signal and request candidate share a statically inferred function; this suggests a review path but does not prove tainted data reaches the endpoint or sink.",
        })
      }
    }

    for (const response of graph.evidence) {
      graph.edges.push({
        from: "request:" + response.requestID,
        to: "evidence:" + response.id,
        relation: "captured-response-evidence",
        confidence: "direct",
        evidence: "Response status/content metadata is linked to the request record in SQLite.",
      })
    }

    for (const asset of graph.javascriptAssets) {
      for (const request of graph.requests) {
        const reqHost = safeURL(request.url)?.hostname
        const assetHost = safeURL(asset.url)?.hostname
        if (reqHost && assetHost && reqHost === assetHost) {
          graph.edges.push({
            from: "javascript:" + asset.url,
            to: "request:" + request.id,
            relation: "same-host-observation",
            confidence: "candidate",
            evidence: "Host match only; this does not prove the JavaScript file issued the request.",
          })
        }
      }
    }
    for (const fn of graph.webFunctions) {
      if (requestIDSet.has(fn.requestID)) {
        graph.edges.push({
          from: "request:" + fn.requestID,
          to: "web-function:" + fn.id,
          relation: "request-backs-web-function",
          confidence: "direct",
          evidence: "web_function.request_id foreign-key relationship",
        })
      }
    }
    for (const observation of graph.observations) {
      if (observation.requestID && requestIDSet.has(observation.requestID)) {
        graph.edges.push({
          from: "request:" + observation.requestID,
          to: "observation:" + observation.id,
          relation: "request-has-observation",
          confidence: "direct",
          evidence: "request_observation.request_id foreign-key relationship",
        })
      }
    }
    for (const finding of graph.findings) {
      const rawEndpoint = (finding.endpoint ?? "").trim()
      const endpointURL = safeURL(rawEndpoint)
      const endpointPath = (endpointURL?.pathname ?? rawEndpoint.replace(/^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE)\s+/i, "")).split(/[?#]/, 1)[0]!
      const matching = graph.requests.filter((request) => {
        if (finding.targetID && requestTargetWorkspaceIDs.get(request.id) !== finding.targetID) return false
        const requestURL = safeURL(request.url)
        if (endpointURL && requestURL?.origin !== endpointURL.origin) return false
        return matchesEndpointPathTemplate(endpointPath, request.normalizedPath)
      })
      for (const request of matching) {
        graph.edges.push({
          from: "request:" + request.id,
          to: "finding:" + finding.id,
          relation: "endpoint-pattern-match",
          confidence: "candidate",
          evidence: "Finding endpoint string matched normalized request path; manually verify the match.",
        })
      }
    }
    graph.notes.push("Local JavaScript files are hashed and scanned only for static URL/path literals; source code is never copied into the graph.")
    graph.notes.push("Static endpoint candidates and source correlations are recorded alongside recon support artifacts; observedInTraffic means a path overlap was seen, not that a specific script executed it.")
    graph.notes.push("No JavaScript source was downloaded or executed by this correlation operation.")
    graph.notes.push("Additional scenario candidates preserve source file/hash/line and linked endpoint/request IDs; they are review plans only and are never dispatched or tested automatically.")
    graph.notes.push("Host-only JavaScript-to-request edges are candidate relationships, not proof the script caused or called the endpoint.")
    graph.notes.push("Response previews are length-limited and redacted heuristically; derived JavaScript artifacts retain secret fingerprints and source locations only, never raw candidate values. Captured request/source bodies remain in the existing private capture store for on-demand evidence inspection.")
    graph.notes.push("This graph only correlates observations already stored in the current session tree; missing edges do not prove that a relationship does not exist.")

    let previousTesterCases: JavaScriptTesterCase[] = []
    for (const surveyRelativePath of [testerSurveyRelativePath, legacyTesterSurveyRelativePath]) {
      const surveyAbsolutePath = path.join(workspace.workspacePath, surveyRelativePath)
      try {
        const info = await fs.lstat(surveyAbsolutePath)
        if (!info.isFile() || info.isSymbolicLink()) continue
        const oldSurvey = JSON.parse(await fs.readFile(surveyAbsolutePath, "utf-8"))
        if (oldSurvey?.schemaVersion === 1 && oldSurvey.targetURL === workspace.targetURL && Array.isArray(oldSurvey.cases)) {
          previousTesterCases = oldSurvey.cases as JavaScriptTesterCase[]
          break
        }
      } catch {
        // Missing or invalid prior survey only disables state reuse; try a legacy path,
        // then create the current survey from the available evidence.
      }
    }
    const testerCases = createJavaScriptTesterCases(graph.javascriptAnalysis.requestCandidates, graph.endpointCandidates, previousTesterCases)
    const testerSurvey = {
      schemaVersion: 1,
      generatedAt: graph.createdAt,
      targetURL: graph.targetURL,
      sessionID: graph.sessionID,
      sourceGraph: path.posix.join("javascript", graphFilename),
      sourceEndpointInventory: path.posix.join("recon", endpointFilename),
      cases: testerCases,
      additionalScenarios: graph.additionalScenarios ?? [],
      notes: [
        "Review plan only; generating this artifact sends no HTTP requests.",
        "Before replay, re-check the persisted scope and use captured baselines; change one input at a time.",
        "Completed statuses and prior evidence links persist for stable case IDs; vanished cases remain as stale history.",
      ],
    }
    const urlList = graph.javascriptAssets.map((asset) => asset.url).join("\n")
    const endpointRecords = groupCanonicalJavaScriptEndpoints([graph])
    const operationCount = endpointRecords.reduce((sum, endpoint) => sum + endpoint.operations.length, 0)
    const trafficOperationCount = endpointRecords.reduce(
      (sum, endpoint) => sum + endpoint.operations.filter((operation) => operation.observedInTraffic).length,
      0,
    )
    const content = [
      "# JavaScript Correlation Snapshot",
      "",
      "- Target: " + workspace.targetURL,
      "- Session: " + rootSessionID,
      "- JavaScript asset URLs: " + graph.javascriptAssets.length,
      "- Captured JS/source-map files persisted: " + capturedAssetIndex.length,
      "- Captured asset index: " + capturedAssetIndexPath,
      "- JavaScript/source-map records indexed: " + graph.sourceFiles.length,
      "- Static endpoint literals extracted: " + graph.sourceFiles.reduce((sum, file) => sum + file.endpointLiterals.length, 0),
      "- Source-map references: " + (graph.sourceMapReferences ?? []).length,
      "- Source maps awaiting capture: " + (graph.sourceMapReferences ?? []).filter((item) => item.status === "referenced-not-captured").length,
      "- Embedded source entries analyzed: " + graph.sourceFiles.filter((file) => Boolean(file.sourceMapSource)).length,
      "- JavaScript function candidates: " + graph.javascriptAnalysis.functions.length,
      "- Structured request candidates: " + graph.javascriptAnalysis.requestCandidates.length,
      "- Secret-like assignments (fingerprints only; candidate only): " + graph.javascriptAnalysis.secretCandidates.length,
      "- Role/feature hints: " + graph.javascriptAnalysis.roleHints.length,
      "- Static JavaScript sink candidates (not confirmed findings): " + graph.javascriptAnalysis.riskSignals.length,
      "- Canonical endpoint records: " + endpointRecords.length,
      "- Distinct method operations: " + operationCount,
      "- Operations observed in captured traffic: " + trafficOperationCount,
      "- Captured response evidence nodes: " + graph.evidence.length,
      "- Related captured requests: " + graph.requests.length,
      "- Web functions: " + graph.webFunctions.length,
      "- Request observations: " + graph.observations.length,
      "- Candidate findings: " + graph.findings.length,
      "- Recorded graph edges: " + graph.edges.length,
      "- Tester survey cases: " + testerCases.length,
      "- Additional scenario candidates: " + (graph.additionalScenarios ?? []).length,
      "- Tester survey artifact: " + testerSurveyRelativePath,
      "",
      "## Captured asset evidence (raw local files; treat as sensitive)",
      ...(capturedAssetIndex.length ? capturedAssetIndex.map((asset) => "- " + asset.url + " — " + asset.file + " — SHA-256 " + asset.sha256 + " — " + asset.bytes + " bytes — request " + asset.requestID) : ["No captured JavaScript/source-map response bodies were persisted. Collection is incomplete unless local source files were independently supplied."]),
      "",
      "## Local JavaScript files",
      ...(graph.sourceFiles.length ? graph.sourceFiles.map((file) => "- " + file.relativePath + " — SHA-256 " + file.sha256 + " — " + file.bytes + " bytes — " + file.endpointLiterals.length + " static endpoint literal(s)" + (file.sourceMapStatus ? " — source-map status: " + file.sourceMapStatus : "")) : ["No local JavaScript/source-map source files found in the target workspace."]),
      "",
      "## Function candidates",
      ...(graph.javascriptAnalysis.functions.length ? graph.javascriptAnalysis.functions.map((fn) => "- " + fn.name + "(" + fn.parameters.join(", ") + ") — " + fn.sourceFile + ":" + fn.line) : ["No named function candidates extracted."]),
      "",
      "## Structured request candidates",
      ...(graph.javascriptAnalysis.requestCandidates.length ? graph.javascriptAnalysis.requestCandidates.map((request) => "- " + (request.method ?? "UNKNOWN") + " " + request.urlTemplate + " — function: " + (request.sourceFunction ?? "unknown") + " — source: " + request.sourceFile + ":" + request.sourceLine + (mergedSourceFiles.find((file) => file.relativePath === request.sourceFile)?.sourceRequestID ? " — source request: " + mergedSourceFiles.find((file) => file.relativePath === request.sourceFile)!.sourceRequestID : "") + " — path[" + request.pathParameters.join(", ") + "], query[" + request.queryParameters.join(", ") + "], body[" + request.bodyParameters.join(", ") + "] — headers[" + request.headerNames.join(", ") + "] — content types[" + (request.contentTypes ?? []).join(", ") + "] — auth[" + request.authSignals.join(", ") + "] — cookies[" + request.cookieSignals.join(", ") + "] — captured requests[" + request.observedRequestIDs.join(", ") + "] — review plan (not run): " + request.recommendedChecks.join("; ")) : ["No structured request candidates extracted."]),
      "",
      "## Secret-like assignments (fingerprints only; candidates, not verified)",
      ...(graph.javascriptAnalysis.secretCandidates.length ? graph.javascriptAnalysis.secretCandidates.map((item) => "- " + item.kind + " — raw value omitted — source: " + item.sourceFile + ":" + item.line + " — fingerprint sha256:" + item.fingerprint + " — status: candidate (verify independently)") : ["No secret-like assignments matched the static heuristics."]),
      "",
      "## Static JavaScript risk-sink candidates (not confirmed findings)",
      ...(graph.javascriptAnalysis.riskSignals.length ? graph.javascriptAnalysis.riskSignals.map((item) => "- " + item.kind + " — " + item.sourceFile + ":" + item.line + " — function: " + (item.functionName ?? "unknown") + " — candidate only") : ["No configured static sink patterns matched."]),
      "",
      "## Role and hidden-feature hints",
      ...(graph.javascriptAnalysis.roleHints.length ? graph.javascriptAnalysis.roleHints.map((item) => "- " + item.kind + " — " + item.value + " — " + item.sourceFile + ":" + item.line) : ["No role/feature hints matched the static heuristics."]),
      "",
      "## Application and integration intelligence (candidate hints, not vulnerability verdicts)",
      ...((graph.javascriptAnalysis.applicationHints ?? []).length ? (graph.javascriptAnalysis.applicationHints ?? []).map((item) => "- " + item.kind + " — " + item.value + " — " + item.sourceFile + ":" + item.line + " — candidate only") : ["No application-intelligence hints matched the current static rules."]),
      "",
      "## JavaScript assets",
      ...(urlList ? [urlList] : ["No JavaScript asset matched the current stored Intel. Provide --javascript-url or record an asset with add_intel first."]),
      "",
      "## Source-map references",
      ...((graph.sourceMapReferences ?? []).length
        ? (graph.sourceMapReferences ?? []).map((item) => "- " + item.url + " — " + item.status + " — source: " + item.sourceFiles.join(", ") + " — " + item.note)
        : ["No external sourceMappingURL references were extracted from the analyzed JavaScript."]),
      "",
      "## Canonical endpoint candidates",
      ...(endpointRecords.length ? endpointRecords.map((endpoint) =>
        "- " + (endpoint.host ?? "(relative)") + endpoint.path +
        " — operations=[" + endpoint.operations.map((operation) =>
          (operation.method ?? "UNKNOWN") + ":" + ((operation.methodEvidenceSources ?? []).join("+") || "unspecified"),
        ).join(", ") + "]" +
        " — traffic_operations=[" + endpoint.operations.filter((operation) => operation.observedInTraffic).map((operation) => operation.method).join(", ") + "]" +
        " — source_files=[" + endpoint.sourceFiles.join(", ") + "]",
      ) : ["No static endpoint literals extracted."]),
      "",
      "## Notes about relationship confidence",
      ...graph.notes.map((note) => "- " + note),
      "",
      "## Findings matched by endpoint pattern",
      ...graph.findings.map((finding) => "- " + finding.id + " [" + finding.status + "/" + finding.severity + "] " + finding.title + " — " + (finding.endpoint ?? "no endpoint")),
    ].join("\n")
    const note = await TargetMemory.addNote(workspace.targetURL, {
      kind: "javascript",
      title: "JavaScript correlation snapshot" + (explicitJS ? " - " + explicitJS.pathname : " - all assets"),
      content,
      source: "javascript-correlation:" + workspace.id + ":" + snapshotSelector,
      sourceURL: explicitJS?.href,
      status: "observed",
      tags: ["javascript", "correlation", "request-response", "finding"],
      upsertByIdentity: true,
    })

    // Refresh stable per-target/session outputs atomically, refusing symlink
    // parents or files that could redirect writes outside the workspace.
    const graphPath = await TargetMemory.writeWorkspaceFile(
      workspace,
      path.posix.join("javascript", graphFilename),
      JSON.stringify(graph, null, 2) + "\n",
    )
    const endpointPath = await TargetMemory.writeWorkspaceFile(
      workspace,
      path.posix.join("recon", endpointFilename),
      JSON.stringify({
        schemaVersion: 2,
        generatedAt: graph.createdAt,
        targetURL: graph.targetURL,
        sessionID: graph.sessionID,
        note: "Canonical endpoint records group HTTP methods as independent operations. Static candidates are leads, not proof of reachability or vulnerability; traffic-only methods remain labeled as traffic evidence.",
        endpoints: groupCanonicalJavaScriptEndpoints([graph]),
        additionalScenarios: graph.additionalScenarios ?? [],
        javascriptAnalysis: graph.javascriptAnalysis,
        sourceMapReferences: graph.sourceMapReferences ?? [],
        testerSurvey: testerSurveyRelativePath,
      }, null, 2) + "\n",
    )

    const testerSurveyPath = await TargetMemory.writeWorkspaceFile(
      workspace,
      testerSurveyRelativePath,
      JSON.stringify(testerSurvey, null, 2) + "\n",
    )

    // One canonical note per origin + route template. HTTP methods are nested
    // operations; method-specific fields never leak into sibling operations.
    for (const endpoint of groupCanonicalJavaScriptEndpoints([graph])) {
      await TargetMemory.mergeCanonicalEndpointRecord({
        targetURL: workspace.targetURL,
        origin: endpoint.origin,
        path: endpoint.path,
        sourceFiles: endpoint.sourceFiles,
        operations: endpoint.operations.map((operation) => ({
          method: operation.method ?? "UNKNOWN",
          methodEvidenceSources: operation.methodEvidenceSources ?? [],
          pathParameters: operation.pathParameters ?? [],
          queryParameters: operation.queryParameters ?? [],
          bodyParameters: operation.bodyParameters ?? [],
          headerNames: operation.headerNames ?? [],
          contentTypes: operation.contentTypes ?? [],
          authSignals: operation.authSignals ?? [],
          cookieSignals: operation.cookieSignals ?? [],
          sourceFiles: operation.sourceFiles ?? [],
          requestIDs: operation.observedRequestIDs ?? [],
          observedInTraffic: operation.observedInTraffic,
          confidence: operation.confidence,
          evidence: operation.methodEvidenceSources?.length ? [
            ...(operation.methodEvidenceSources.includes("javascript") ? [{
              source: "javascript" as const,
              pathParameters: operation.pathParameters ?? [],
              queryParameters: operation.queryParameters ?? [],
              bodyParameters: operation.bodyParameters ?? [],
              headerNames: operation.headerNames ?? [],
              contentTypes: operation.contentTypes ?? [],
              authSignals: operation.authSignals ?? [],
              cookieSignals: operation.cookieSignals ?? [],
              sourceFiles: operation.sourceFiles ?? [],
              confidence: operation.confidence,
            }] : []),
            ...(operation.methodEvidenceSources.includes("traffic") ? [{
              source: "traffic" as const,
              requestIDs: operation.observedRequestIDs ?? [],
              confidence: operation.observedInTraffic ? "observed" as const : "candidate" as const,
            }] : []),
          ] : undefined,
        })),
        unattributed: endpoint.unattributed,
      })
    }
    const canonicalArtifacts = await serializeCanonicalArtifacts(
      workspace.id,
      () => persistCanonicalJavaScriptArtifacts(workspace, graph, graphFilename),
    )
    return {
      graph,
      workspacePath: workspace.workspacePath,
      graphPath,
      endpointPath,
      testerSurveyPath,
      analysisSummaryPath: canonicalArtifacts.analysisSummaryPath,
      endpointInventoryPath: canonicalArtifacts.endpointInventoryPath,
      capturedAssetCount: capturedAssetIndex.length,
      noteID: note.note.id,
    }
  }
}
