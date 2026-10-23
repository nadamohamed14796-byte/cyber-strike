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
import { analyzeJavaScriptSource, normalizeJavaScriptEndpointPath, type JavaScriptSourceAnalysis, type JavaScriptRequestCandidate, type JavaScriptFunctionCandidate, type JavaScriptSecretCandidate, type JavaScriptRoleHint, type JavaScriptRiskSignal } from "./javascript-analysis"

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
    .replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, "[EMAIL REDACTED]")
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

export function extractStaticJavaScriptEndpoints(content: string): string[] {
  const found = new Set<string>()
  const callArgument = /(?:fetch|axios\.(?:get|post|put|patch|delete)|\.open)\s*\(\s*["'\`]([^"'\`]+)["'\`]/gi
  const routeString = /["'\`]((?:https?:\/\/)[^"'\`\s]+|\/(?:api|graphql|rest|rpc|v\d+|auth|admin|users|account|orders|cart|checkout|upload|download|search|profile)(?:\/[^"'\`\s]*)?)["'\`]/gi
  for (const pattern of [callArgument, routeString]) {
    for (const match of content.matchAll(pattern)) {
      const normalized = normalizeEndpointLiteral(match[1])
      if (normalized) found.add(normalized)
    }
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
      fingerprint: candidate.fingerprint,
      confidence: candidate.confidence,
    })),
    notes: analysis.notes.map((note) => note === LEGACY_RAW_SECRET_NOTE
      ? "Secret-like values are never retained in derived analysis output; only fingerprints, source locations, and candidate status are emitted."
      : note),
  }
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

function emptyJavaScriptSourceAnalysis(notes: string[]): JavaScriptSourceAnalysis {
  return { functions: [], requests: [], secretCandidates: [], roleHints: [], riskSignals: [], notes }
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
  const embeddedCount = embedded.filter((value): value is string => typeof value === "string" && value.length > 0).length
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
    if (!isJavaScript && !isSourceMap) continue
    const bytes = Buffer.byteLength(body, "utf-8")
    if (bytes < 1) continue
    const digest = createHash("sha256").update(body).digest("hex")
    const canonicalSourceURL = url.origin + url.pathname
    const identity = canonicalSourceURL + "\\0" + digest
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
  /** Null means static evidence did not establish the HTTP method. */
  method?: string | null
  pathParameters?: string[]
  queryParameters?: string[]
  bodyParameters?: string[]
  headerNames?: string[]
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
  capturedRequests: Array<{ id: string; method: string }> = [],
): JavaScriptEndpointCandidate[] {
  const byKey = new Map<string, JavaScriptEndpointCandidate>()
  const routeKeyOf = (origin: string | null, route: string) =>
    (origin?.toLowerCase() ?? "*") + "\\0" + normalizedTemplateShape(route)
  const normalizeMethod = (method?: string | null) => method?.trim().toUpperCase() || null
  const keyOf = (origin: string | null, route: string, method?: string | null) =>
    routeKeyOf(origin, route) + "\\0method:" + (normalizeMethod(method) ?? "*")
  const capturedMethodByID = new Map(capturedRequests.map((request) => [request.id, normalizeMethod(request.method)]))
  const requestVariants = new Map<string, Map<string | null, typeof requests>>()
  const unique = (values: string[]) => [...new Set(values)]

  for (const request of requests) {
    const url = safeURL(request.urlTemplate)
    const origin = request.origin ?? url?.origin ?? null
    const method = normalizeMethod(request.method)
    const routeKey = routeKeyOf(origin, request.path)
    let byMethod = requestVariants.get(routeKey)
    if (!byMethod) {
      byMethod = new Map()
      requestVariants.set(routeKey, byMethod)
    }
    const items = byMethod.get(method) ?? []
    items.push(request)
    byMethod.set(method, items)
  }

  function mergeStaticEndpoint(source: JavaScriptEndpointCandidate, method: string | null) {
    const key = keyOf(source.origin, source.path, method)
    let endpoint = byKey.get(key)
    const sourceObservedIDs = method && capturedRequests.length
      ? source.observedRequestIDs.filter((id) => capturedMethodByID.get(id) === method)
      : source.observedRequestIDs
    if (!endpoint) {
      endpoint = {
        ...source,
        id: "endpoint:" + createHash("sha256").update(key).digest("hex").slice(0, 16),
        method,
        sourceFiles: [],
        observedRequestIDs: [],
        pathParameters: [],
        queryParameters: [],
        bodyParameters: [],
        headerNames: [],
        authSignals: [],
        cookieSignals: [],
        observedInTraffic: false,
        confidence: "candidate",
      }
      byKey.set(key, endpoint)
    }
    endpoint.sourceFiles = unique([...endpoint.sourceFiles, ...source.sourceFiles])
    endpoint.pathParameters = unique([...(endpoint.pathParameters ?? []), ...(source.pathParameters ?? [])])
    endpoint.queryParameters = unique([...(endpoint.queryParameters ?? []), ...(source.queryParameters ?? [])])
    endpoint.bodyParameters = unique([...(endpoint.bodyParameters ?? []), ...(source.bodyParameters ?? [])])
    endpoint.headerNames = unique([...(endpoint.headerNames ?? []), ...(source.headerNames ?? [])])
    endpoint.authSignals = unique([...(endpoint.authSignals ?? []), ...(source.authSignals ?? [])])
    endpoint.cookieSignals = unique([...(endpoint.cookieSignals ?? []), ...(source.cookieSignals ?? [])])
    endpoint.observedRequestIDs = unique([...endpoint.observedRequestIDs, ...sourceObservedIDs])
    if (endpoint.observedRequestIDs.length) {
      endpoint.observedInTraffic = true
      endpoint.confidence = "observed"
    }
  }

  // A generic route literal may correspond to more than one HTTP method. Once the
  // source reveals those methods, materialize one stable endpoint per method rather
  // than mixing GET/POST evidence and parameter sets into a single route record.
  for (const source of staticEndpoints) {
    const routeKey = routeKeyOf(source.origin, source.path)
    const variants = requestVariants.get(routeKey)
    if (normalizeMethod(source.method)) {
      mergeStaticEndpoint(source, normalizeMethod(source.method))
      continue
    }
    const methods = variants ? [...variants.keys()] : []
    if (methods.some((method) => method !== null)) {
      for (const method of methods) mergeStaticEndpoint(source, method)
    } else {
      mergeStaticEndpoint(source, null)
    }
  }

  for (const request of requests) {
    const url = safeURL(request.urlTemplate)
    const origin = request.origin ?? url?.origin ?? null
    const host = url?.host ?? request.host ?? null
    const method = normalizeMethod(request.method)
    const key = keyOf(origin, request.path, method)
    let endpoint = byKey.get(key)
    if (!endpoint) {
      endpoint = {
        id: "endpoint:" + createHash("sha256").update(key).digest("hex").slice(0, 16),
        literal: request.urlTemplate,
        host,
        origin,
        path: request.path,
        method,
        sourceFiles: [],
        observedRequestIDs: [],
        pathParameters: [],
        queryParameters: [],
        bodyParameters: [],
        headerNames: [],
        authSignals: [],
        cookieSignals: [],
        observedInTraffic: false,
        confidence: "candidate",
      }
      byKey.set(key, endpoint)
    }
    if (!endpoint.sourceFiles.includes(request.sourceFile)) endpoint.sourceFiles.push(request.sourceFile)
    endpoint.pathParameters = unique([...(endpoint.pathParameters ?? []), ...request.pathParameters])
    endpoint.queryParameters = unique([...(endpoint.queryParameters ?? []), ...request.queryParameters])
    endpoint.bodyParameters = unique([...(endpoint.bodyParameters ?? []), ...request.bodyParameters])
    endpoint.headerNames = unique([...(endpoint.headerNames ?? []), ...request.headerNames])
    endpoint.authSignals = unique([...(endpoint.authSignals ?? []), ...request.authSignals])
    endpoint.cookieSignals = unique([...(endpoint.cookieSignals ?? []), ...request.cookieSignals])
    endpoint.observedRequestIDs = unique([...endpoint.observedRequestIDs, ...request.observedRequestIDs])
    if (endpoint.observedRequestIDs.length) {
      endpoint.observedInTraffic = true
      endpoint.confidence = "observed"
    }
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
      const variants = new Map<string, { origin: string | null; host: string | null; matching: typeof matchingRequests }>()
      if (explicitOrigin && endpointURL) {
        variants.set(explicitOrigin, {
          origin: explicitOrigin,
          host: endpointURL.host.toLowerCase(),
          matching: matchingRequests.filter((item) => item.url.origin.toLowerCase() === explicitOrigin),
        })
      } else if (matchingRequests.length) {
        for (const item of matchingRequests) {
          const origin = item.url.origin.toLowerCase()
          const existing = variants.get(origin)
          if (existing) existing.matching.push(item)
          else variants.set(origin, { origin, host: item.url.host.toLowerCase(), matching: [item] })
        }
      } else {
        variants.set("*", { origin: null, host: null, matching: [] })
      }

      for (const variant of variants.values()) {
        const key = (variant.origin ?? "*") + "\\0" + normalizedTemplateShape(endpointPath)
        let candidate = candidates.get(key)
        if (!candidate) {
          candidate = {
            id: "endpoint:" + createHash("sha256").update(key).digest("hex").slice(0, 16),
            literal,
            host: variant.host,
            origin: variant.origin,
            path: endpointPath,
            sourceFiles: [],
            observedRequestIDs: [],
            observedInTraffic: false,
            confidence: "candidate",
          }
          candidates.set(key, candidate)
        }
        if (!candidate.sourceFiles.includes(file.relativePath)) candidate.sourceFiles.push(file.relativePath)
        for (const item of variant.matching) {
          if (!candidate.observedRequestIDs.includes(item.request.id)) candidate.observedRequestIDs.push(item.request.id)
        }
        if (candidate.observedRequestIDs.length) {
          candidate.observedInTraffic = true
          candidate.confidence = "observed"
        }
      }
    }
  }
  return [...candidates.values()]
}

/** Inventory local JavaScript and source-map files; never follow symlinks or execute their contents. */
export async function inventoryJavaScriptFiles(root: string, analysisCache?: Map<string, JavaScriptSourceAnalysis>, sourceBaseURL?: string): Promise<JavaScriptSourceFile[]> {
  const output: JavaScriptSourceFile[] = []
  const pendingDirectories = [root]
  while (pendingDirectories.length) {
    const directory = pendingDirectories.pop()!
    let entries
    try {
      entries = await fs.readdir(directory, { withFileTypes: true })
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") continue
      throw error
    }
    for (const entry of entries) {
      const fullPath = path.join(directory, entry.name)
      // Dirent checks intentionally avoid following symlinks outside the workspace.
      if (entry.isDirectory()) {
        pendingDirectories.push(fullPath)
        continue
      }
      if (!entry.isFile() || !/\.(?:m?js|cjs|map)$/i.test(entry.name)) continue
      const content = await fs.readFile(fullPath, "utf-8")
      const digest = createHash("sha256").update(content).digest("hex")
      const sourceBytes = Buffer.byteLength(content, "utf-8")
      const workspaceRelativePath = path.relative(path.dirname(root), fullPath).split(path.sep).join("/")
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
  }
  endpointCandidates: JavaScriptEndpointCandidate[]
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
    noteID: string
  }

  const buildQueues = new Map<string, Promise<BuildResult>>()

  export async function build(input: {
    sessionID: string
    targetURL: string
    javascriptURL?: string
  }): Promise<BuildResult> {
    const rootSessionID = Session.root(input.sessionID)
    const targetURL = TargetMemory.normalize(input.targetURL).targetURL
    const selectorURL = input.javascriptURL ? safeURL(input.javascriptURL) : undefined
    const selector = selectorURL ? selectorURL.origin + selectorURL.pathname : "all-assets"
    const key = rootSessionID + "\\0" + targetURL + "\\0" + selector
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
  }): Promise<BuildResult> {
    const rootSessionID = Session.root(input.sessionID)
    const normalizedTarget = TargetMemory.normalize(input.targetURL)
    const explicitJS = input.javascriptURL ? safeURL(input.javascriptURL) : undefined
    if (input.javascriptURL && !explicitJS) throw new Error("javascriptURL must be a valid HTTP(S) URL without embedded credentials.")
    const workspace = await TargetMemory.get(input.targetURL)
    if (!workspace) {
      throw new Error("No existing target workspace matches this target. Initialize it with target_workspace first.")
    }
    if (!TargetMemory.isObservedInSession(rootSessionID, workspace.targetURL)) {
      throw new Error("The target was not observed in this session tree. Refusing to correlate unrelated target data.")
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
    const targetScopeDecision = await scopeDecisionFor(workspace.targetURL)
    if (!targetScopeDecision.allowed || targetScopeDecision.workspace?.id !== workspace.id) {
      throw new Error("Target workspace does not pass its persisted active-scope gate: " + targetScopeDecision.reason)
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
    const endpointFilename = graphFilename
    const testerSurveyRelativePath = path.posix.join("testing", "tester-survey-" + digest + ".json")
    const analysisCache = new Map<string, JavaScriptSourceAnalysis>()
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
    const sourceFiles = explicitJS ? [] : await inventoryJavaScriptFiles(path.join(workspace.workspacePath, "javascript"), analysisCache, normalizedTarget.targetURL)

    const projectID = Instance.project.id
    const sessionIDsSet = new Set<string>([rootSessionID])
    let frontier = [rootSessionID]
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
    const filteredAssets = explicitJS
      ? jsCandidates.filter((item) => item.url.origin + item.url.pathname === explicitJS.origin + explicitJS.pathname)
      : jsCandidates.filter((item) => {
          const hostMatches = item.url.hostname === targetURL.hostname || item.url.hostname.endsWith("." + targetURL.hostname)
          if (!hostMatches) return false
          // For a path-scoped application, ignore scripts from sibling applications
          // mounted on the same hostname.
          if (item.url.hostname === targetURL.hostname && targetPath !== "/" && !pathWithinScope(item.url.pathname, targetPath)) return false
          return true
        })
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
    const candidateRequests = requests.filter((request) => {
      const hostURL = safeURL(request.origin) ?? safeURL(request.page_url) ?? safeURL(request.host)
      if (!hostURL) return false
      const host = hostURL.hostname.toLowerCase()
      const isTargetHost = host === targetURL.hostname || host.endsWith("." + targetURL.hostname)
      // Keep already-captured script/map responses in the candidate set even on a
      // different host or path. The authoritative persisted scope gate below decides
      // whether each exact response URL is eligible; a hostname match alone never does.
      const capturedScriptOrMap = isJavaScriptOrSourceMapResponse(
        request.response_content_type,
        request.normalized_path,
      )
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
    // Narrow explicit-asset runs to the selected bundle plus only its directly
    // referenced external maps. Canonicalization drops query/fragment secrets.
    const explicitSourceMapURLs = new Set<string>()
    if (explicitJS) {
      for (const capture of sourceCaptureRows) {
        const capturedURL = safeURL(capture.source_url)
        if (!capturedURL || capturedURL.origin !== explicitJS.origin || capturedURL.pathname !== explicitJS.pathname) continue
        const capturedBody = unwrapProcessedResponseBody(capture.source_content).body
        for (const mapURL of extractJavaScriptSourceMapReferences(capturedBody, capturedURL.origin + capturedURL.pathname)) {
          explicitSourceMapURLs.add(mapURL)
        }
      }
    }
    const isExplicitAssetOrLinkedMap = (url: URL | undefined): boolean => {
      if (!url || !explicitJS) return false
      const key = url.origin + url.pathname
      return key === explicitJS.origin + explicitJS.pathname || explicitSourceMapURLs.has(key)
    }
    const requestURL = (request: typeof requests[number]): URL | undefined => {
      const base = safeURL(request.origin) ?? safeURL(request.page_url) ?? safeURL(request.host)
      if (!base) return undefined
      try { return new URL(request.normalized_path, base) } catch { return undefined }
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
        url: capture.source_url,
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
    const capturedSources = extractCapturedJavaScriptSources(
      [...versionedSourceInputs, ...legacySourceInputs],
      analysisCache,
    )
    // Keep every distinct source location/URL for provenance. analysisCache is keyed by
    // content hash, so identical bytes are analyzed once but may produce multiple origin-aware
    // source records; this matters when the same bundle is served from different hosts.
    const mergedSourceFiles = [...sourceFiles, ...capturedSources]
    const sourceMapRecordsByURL = new Map<string, JavaScriptSourceFile[]>()
    for (const file of mergedSourceFiles) {
      if (!file.sourceMapURL || file.sourceMapSource || file.sourceMapInline) continue
      const records = sourceMapRecordsByURL.get(file.sourceMapURL) ?? []
      records.push(file)
      sourceMapRecordsByURL.set(file.sourceMapURL, records)
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
      const capturedMaps = sourceMapRecordsByURL.get(url) ?? []
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
          const recommendedChecks = [
            "Baseline replay and response capture",
            ...(item.pathParameters.length ? ["Compare path parameter type/boundary values using controlled test data"] : []),
            ...(item.queryParameters.length ? ["Compare omitted and altered query parameters"] : []),
            ...(item.bodyParameters.length ? ["Compare required/optional body fields and expected types"] : []),
            ...((file.sourceRequestIDs?.length ?? (file.sourceRequestID ? 1 : 0)) > 0
              ? ["Inspect the original captured JavaScript response(s) via request-detail tooling using request ID(s) " + (file.sourceRequestIDs ?? [file.sourceRequestID]).filter(Boolean).join(", ")]
              : []),
            ...(file.analysis?.riskSignals?.some((signal) => signal.functionName === item.sourceFunction) ? ["Manually review static sink candidates in the associated function and confirm source-to-sink data flow"] : []),
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
      notes: [],
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
    graph.endpointCandidates = mergeStructuredJavaScriptEndpoints(
      correlateStaticJavaScriptEndpoints(graph.sourceFiles, graph.requests, targetURL.hostname, targetURL.origin),
      graph.javascriptAnalysis.requestCandidates,
      graph.requests,
    )
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
    graph.notes.push("Static endpoint candidates are saved separately under endpoints/; observedInTraffic means a path overlap was seen, not that a specific script executed it.")
    graph.notes.push("No JavaScript source was downloaded or executed by this correlation operation.")
    graph.notes.push("Host-only JavaScript-to-request edges are candidate relationships, not proof the script caused or called the endpoint.")
    graph.notes.push("Response previews are length-limited and redacted heuristically; derived JavaScript artifacts retain secret fingerprints and source locations only, never raw candidate values. Captured request/source bodies remain in the existing private capture store for on-demand evidence inspection.")
    graph.notes.push("This graph only correlates observations already stored in the current session tree; missing edges do not prove that a relationship does not exist.")

    const testerSurveyAbsolutePath = path.join(workspace.workspacePath, testerSurveyRelativePath)
    let previousTesterCases: JavaScriptTesterCase[] = []
    try {
      const info = await fs.lstat(testerSurveyAbsolutePath)
      if (info.isFile() && !info.isSymbolicLink()) {
        const oldSurvey = JSON.parse(await fs.readFile(testerSurveyAbsolutePath, "utf-8"))
        if (oldSurvey?.schemaVersion === 1 && oldSurvey.targetURL === workspace.targetURL && Array.isArray(oldSurvey.cases)) {
          previousTesterCases = oldSurvey.cases as JavaScriptTesterCase[]
        }
      }
    } catch {
      // Missing or invalid prior survey only disables state reuse; fresh analysis still proceeds.
    }
    const testerCases = createJavaScriptTesterCases(graph.javascriptAnalysis.requestCandidates, graph.endpointCandidates, previousTesterCases)
    const testerSurvey = {
      schemaVersion: 1,
      generatedAt: graph.createdAt,
      targetURL: graph.targetURL,
      sessionID: graph.sessionID,
      sourceGraph: path.posix.join("javascript", graphFilename),
      sourceEndpointInventory: path.posix.join("endpoints", endpointFilename),
      cases: testerCases,
      notes: [
        "Review plan only; generating this artifact sends no HTTP requests.",
        "Before replay, re-check the persisted scope and use captured baselines; change one input at a time.",
        "Completed statuses and prior evidence links persist for stable case IDs; vanished cases remain as stale history.",
      ],
    }
    const urlList = graph.javascriptAssets.map((asset) => asset.url).join("\n")
    const content = [
      "# JavaScript Correlation Snapshot",
      "",
      "- Target: " + workspace.targetURL,
      "- Session: " + rootSessionID,
      "- JavaScript asset URLs: " + graph.javascriptAssets.length,
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
      "- Unique endpoint candidates: " + graph.endpointCandidates.length,
      "- Endpoint candidates overlapping captured traffic: " + graph.endpointCandidates.filter((endpoint) => endpoint.observedInTraffic).length,
      "- Captured response evidence nodes: " + graph.evidence.length,
      "- Related captured requests: " + graph.requests.length,
      "- Web functions: " + graph.webFunctions.length,
      "- Request observations: " + graph.observations.length,
      "- Candidate findings: " + graph.findings.length,
      "- Recorded graph edges: " + graph.edges.length,
      "- Tester survey cases: " + testerCases.length,
      "- Tester survey artifact: " + testerSurveyRelativePath,
      "",
      "## Local JavaScript files",
      ...(graph.sourceFiles.length ? graph.sourceFiles.map((file) => "- " + file.relativePath + " — SHA-256 " + file.sha256 + " — " + file.bytes + " bytes — " + file.endpointLiterals.length + " static endpoint literal(s)" + (file.sourceMapStatus ? " — source-map status: " + file.sourceMapStatus : "")) : ["No local JavaScript/source-map source files found in the target workspace."]),
      "",
      "## Function candidates",
      ...(graph.javascriptAnalysis.functions.length ? graph.javascriptAnalysis.functions.map((fn) => "- " + fn.name + "(" + fn.parameters.join(", ") + ") — " + fn.sourceFile + ":" + fn.line) : ["No named function candidates extracted."]),
      "",
      "## Structured request candidates",
      ...(graph.javascriptAnalysis.requestCandidates.length ? graph.javascriptAnalysis.requestCandidates.map((request) => "- " + (request.method ?? "UNKNOWN") + " " + request.urlTemplate + " — source: " + request.sourceFile + ":" + request.sourceLine + (mergedSourceFiles.find((file) => file.relativePath === request.sourceFile)?.sourceRequestID ? " — source request: " + mergedSourceFiles.find((file) => file.relativePath === request.sourceFile)!.sourceRequestID : "") + " — path[" + request.pathParameters.join(", ") + "], query[" + request.queryParameters.join(", ") + "], body[" + request.bodyParameters.join(", ") + "] — headers[" + request.headerNames.join(", ") + "] — auth: " + request.authAssessment + (request.observedRequestIDs.length ? " — captured requests: " + request.observedRequestIDs.join(", ") : " — no matching captured request") + " — review plan (not run): " + request.recommendedChecks.join("; ")) : ["No structured request candidates extracted."]),
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
      "## JavaScript assets",
      ...(urlList ? [urlList] : ["No JavaScript asset matched the current stored Intel. Provide --javascript-url or record an asset with add_intel first."]),
      "",
      "## Source-map references",
      ...((graph.sourceMapReferences ?? []).length
        ? (graph.sourceMapReferences ?? []).map((item) => "- " + item.url + " — " + item.status + " — source: " + item.sourceFiles.join(", ") + " — " + item.note)
        : ["No external sourceMappingURL references were extracted from the analyzed JavaScript."]),
      "",
      "## Static endpoint candidates",
      ...(graph.endpointCandidates.length ? graph.endpointCandidates.map((endpoint) => "- " + (endpoint.host ? endpoint.host : "(relative)") + endpoint.path + " — " + (endpoint.observedInTraffic ? "path overlap observed" : "not yet observed in captured traffic") + " — source: " + endpoint.sourceFiles.join(", ") + (endpoint.observedRequestIDs.length ? " — requests: " + endpoint.observedRequestIDs.join(", ") : "")) : ["No static endpoint literals extracted."]),
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
      path.posix.join("endpoints", endpointFilename),
      JSON.stringify({
        schemaVersion: 2,
        generatedAt: graph.createdAt,
        targetURL: graph.targetURL,
        sessionID: graph.sessionID,
        note: "Static endpoint candidates are leads, not proof of reachability or vulnerability. observedInTraffic only records path overlap with captured requests.",
        endpoints: graph.endpointCandidates,
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

    // Create one stable, readable note per endpoint candidate so future request
    // ingestion can update/reuse the same evidence record instead of rediscovering it.
    for (const endpoint of graph.endpointCandidates) {
      const relatedRequests = graph.requests.filter((request) => endpoint.observedRequestIDs.includes(request.id))
      const requestLines = relatedRequests.length
        ? relatedRequests.map((request) => "- " + request.id + ": " + request.method + " " + (request.url ?? request.normalizedPath) + " — status " + (request.responseStatus ?? "unknown"))
        : ["- No matching captured request yet."]
      const endpointOrigin = endpoint.origin?.toLowerCase() ?? "*"
      const relatedCandidates = graph.javascriptAnalysis.requestCandidates.filter((candidate) => {
        const candidateURL = safeURL(candidate.urlTemplate)
        const candidateOrigin = (candidate.origin ?? candidateURL?.origin ?? null)?.toLowerCase() ?? "*"
        return candidateOrigin === endpointOrigin &&
          normalizedTemplateShape(candidate.path) === normalizedTemplateShape(endpoint.path) &&
          (endpoint.method ? candidate.method?.toUpperCase() === endpoint.method : !candidate.method)
      })
      const parameterLines = [
        "- Path parameters: " + ((endpoint.pathParameters ?? []).join(", ") || "none statically identified"),
        "- Query parameters: " + ((endpoint.queryParameters ?? []).join(", ") || "none statically identified"),
        "- Body parameters: " + ((endpoint.bodyParameters ?? []).join(", ") || "none statically identified"),
        "- Header names: " + ((endpoint.headerNames ?? []).join(", ") || "none statically identified"),
        "- Authentication signals: " + ((endpoint.authSignals ?? []).join(", ") || "none statically identified"),
        "- Cookie/session signals: " + ((endpoint.cookieSignals ?? []).join(", ") || "none statically identified"),
      ]
      const sourceCallLines = relatedCandidates.length
        ? relatedCandidates.map((candidate) => {
            const parameterEvidence = [
              ...candidate.pathParameters.map((name) => name + " [path; type unknown unless independently inferred]"),
              ...candidate.queryParameters.map((name) => name + " [query; type unknown unless independently inferred]"),
              ...candidate.bodyParameters.map((name) => name + " [body; type unknown unless independently inferred]"),
              ...candidate.headerNames.map((name) => name + " [header; value/type not captured by this static hint]"),
            ]
            const sourceRecord = graph.sourceFiles.find((file) => file.relativePath === candidate.sourceFile)
            const sourceRequestIDs = sourceRecord?.sourceRequestIDs ?? (sourceRecord?.sourceRequestID ? [sourceRecord.sourceRequestID] : [])
            const sourceCaptureIDs = sourceRecord?.sourceCaptureIDs ?? (sourceRecord?.sourceCaptureID ? [sourceRecord.sourceCaptureID] : [])
            const sourceReference = sourceRequestIDs.length
              ? "captured JS response " + (sourceRecord?.sourceURL ?? "(URL unavailable)") +
                (sourceCaptureIDs.length ? " (source capture version IDs: " + sourceCaptureIDs.join(", ") + ")" : "") +
                " via request IDs " + sourceRequestIDs.join(", ") + " (full body remains in request storage, not in the graph file)"
              : "workspace file " + candidate.sourceFile
            return "- " + (candidate.method ?? "UNKNOWN") + " " + candidate.urlTemplate +
              " — source: " + sourceReference + ":" + candidate.sourceLine +
              (candidate.sourceFunction ? " in " + candidate.sourceFunction : "") +
              " — parameters: [" + (parameterEvidence.join(", ") || "none statically identified") + "]" +
              " — confidence: " + candidate.confidence +
              " — auth assessment: " + candidate.authAssessment +
              " — auth signals: [" + candidate.authSignals.join(", ") + "]" +
              " — cookie/session signals: [" + candidate.cookieSignals.join(", ") + "]" +
              " — captured request IDs: [" + (candidate.observedRequestIDs.join(", ") || "none") + "]"
          })
        : ["- No structured request-call candidate associated with this method-specific route."]
      const endpointNoteContent = [
        "# Endpoint Evidence",
        "",
        "- Candidate ID: " + endpoint.id,
        "- Target: " + workspace.targetURL,
        "- Origin: " + (endpoint.origin ?? "(relative or same-origin route)"),
        "- Host: " + (endpoint.host ?? "(relative or same-origin route)"),
        "- Method: " + (endpoint.method ?? "not statically known"),
        "- Path/template: " + endpoint.path,
        "- Observation status: " + (endpoint.observedInTraffic ? "path overlap observed in captured traffic" : "static JavaScript candidate; not yet observed in captured traffic"),
        "- Confidence: " + endpoint.confidence,
        "- Source JavaScript files: " + (endpoint.sourceFiles.length ? endpoint.sourceFiles.join(", ") : "none recorded"),
        "- Related captured request IDs: " + (endpoint.observedRequestIDs.length ? endpoint.observedRequestIDs.join(", ") : "none"),
        "",
        "## Merged parameter inventory (kept separate by location)",
        ...parameterLines,
        "",
        "## Request-call provenance",
        ...sourceCallLines,
        "",
        "## Related captured request evidence",
        ...requestLines,
        "",
        "## Artifact links",
        "- JavaScript correlation graph: " + path.relative(workspace.workspacePath, graphPath).split(path.sep).join("/"),
        "- Endpoint inventory: " + path.relative(workspace.workspacePath, endpointPath).split(path.sep).join("/"),
        "",
        "## Interpretation",
        "This is an endpoint candidate, not a vulnerability finding. Path overlap does not prove the listed JavaScript file executed the request. Verify the exact origin, method, authentication/role context, parameter locations, response behavior, and authorization before testing.",
      ].join("\n")
      await TargetMemory.addNote(workspace.targetURL, {
        kind: "endpoint",
        title: ("Endpoint " + (endpoint.method ? endpoint.method + " " : "") + (endpoint.host ?? "relative") + endpoint.path).slice(0, 180),
        content: endpointNoteContent,
        source: "javascript-correlation:" + endpoint.id,
        sourceURL: endpoint.origin ? endpoint.origin + endpoint.path : undefined,
        status: endpoint.observedInTraffic ? "observed" : "unverified",
        tags: ["endpoint", "javascript", endpoint.observedInTraffic ? "traffic-observed" : "static-candidate"],
        upsertByIdentity: true,
      })
    }
    return { graph, workspacePath: workspace.workspacePath, graphPath, endpointPath, testerSurveyPath, noteID: note.note.id }
  }
}
