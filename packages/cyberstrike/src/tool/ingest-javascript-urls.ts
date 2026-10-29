import { createHash } from "node:crypto"
import fs from "node:fs/promises"
import path from "node:path"
import z from "zod"
import { gunzipSync } from "node:zlib"
import { TargetMemory } from "../target"
import { JavaScriptCorrelation, extractJavaScriptSourceMapReferences } from "../target/javascript-correlation"
import { Tool } from "./tool"

// Bound work per invocation for reliable checkpoints; the total queue is never capped.
const MAX_ASSETS_PER_INVOCATION = 25

// Redirects are bounded to prevent unending redirect loops; URL/worklist count
// and asset body size are intentionally not capped.
const MAX_REDIRECTS = 5

const Parameters = z.object({
  target_url: z.string().min(1).describe("Existing canonical root target URL whose saved scope governs every fetch."),
  urls: z.array(z.string().trim().min(1)).default([])
    .describe("Optional JavaScript asset or HTML page URLs from the URL collector, crawler, HTML links, source-map references, URL inventory, or user input. HTML pages are parsed for inline scripts and external script src URLs. Pass actual HTTP(S) URLs, not local file paths. Leave empty to resume pending/retryable URLs saved in the existing target manifest."),
  source: z.string().trim().min(1).default("unspecified")
    .describe("Provenance for this batch, e.g. collector, crawler, user-supplied, HTML, source-map, or urls.txt."),
  force_refresh: z.boolean().default(false)
    .describe("False reuses an already downloaded URL and its content hash. True re-fetches existing URLs to check for changed content."),
})

type AssetRecord = {
  url: string
  finalURL?: string
  source: string
  sources?: string[]
  status: "pending" | "downloaded" | "reused" | "skipped" | "failed"
  pendingRefresh?: boolean
  retryable?: boolean
  contentHash?: string
  localPath?: string
  contentType?: string
  bytes?: number
  fetchedAt?: string
  error?: string
  /** Network/HTTP/body-read attempts for this URL; force_refresh starts a new series. */
  attempts?: number
  assetKind?: "javascript" | "html" | "source-map" | "non-js"
  skipReason?: "non-javascript-resource" | "error-document"
}

type Manifest = {
  schemaVersion: 1
  updatedAt: string
  assets: AssetRecord[]
}

function normalizeURL(input: string): string | undefined {
  try {
    const url = new URL(input.trim())
    if ((url.protocol !== "http:" && url.protocol !== "https:") || url.username || url.password) return undefined
    url.hash = ""
    return url.toString()
  } catch {
    return undefined
  }
}

export function mergeAssetSources(...values: Array<string | string[] | undefined>): string[] {
  const merged = new Set<string>()
  for (const value of values) {
    const items = Array.isArray(value) ? value : typeof value === "string" ? value.split(" | ") : []
    for (const item of items) {
      const source = item.trim()
      if (source) merged.add(source)
    }
  }
  return [...merged].sort()
}

// Keep complete provenance in the display label as well as sources[]; never
// truncate the metadata that explains where a source asset was discovered.
export function mergeAssetSourceLabel(sources: string[]): string {
  return [...new Set(sources.map((source) => source.trim()).filter(Boolean))].sort().join(" | ") || "unspecified"
}

export function parseAssetManifest(input: string): Manifest {
  const parsed: unknown = JSON.parse(input)
  if (
    !parsed ||
    typeof parsed !== "object" ||
    (parsed as Partial<Manifest>).schemaVersion !== 1 ||
    typeof (parsed as Partial<Manifest>).updatedAt !== "string" ||
    !Array.isArray((parsed as Partial<Manifest>).assets)
  ) {
    throw new Error("Unsupported or malformed JavaScript asset manifest")
  }
  const manifest = parsed as Manifest
  const statuses = new Set<AssetRecord["status"]>(["pending", "downloaded", "reused", "skipped", "failed"])
  if (manifest.assets.some((item) =>
    !item ||
    typeof item !== "object" ||
    typeof item.url !== "string" ||
    !normalizeURL(item.url) ||
    typeof item.source !== "string" ||
    !statuses.has(item.status),
  )) {
    throw new Error("Malformed JavaScript asset manifest entries")
  }
  return manifest
}

export function shouldResumeAsset(record: { status: AssetRecord["status"]; retryable?: boolean }): boolean {
  return record.status === "pending" || record.retryable === true
}

export function shouldFetchAsset(
  record: { status: AssetRecord["status"]; retryable?: boolean } | undefined,
  forceRefresh = false,
): boolean {
  if (forceRefresh || !record) return true
  return record.status !== "skipped" && (record.status !== "failed" || record.retryable === true)
}

/** Retry transient collection failures once per run; permanent statuses never loop. */
export function shouldRetryJavaScriptAsset(input:
  | { kind: "network"; attempt: number }
  | { kind: "http"; attempt: number; status: number }
  | { kind: "read"; attempt: number },
): boolean {
  if (input.attempt >= 2) return false
  if (input.kind === "network") return true
  if (input.kind === "http") return input.status === 408 || input.status === 429 || input.status >= 500
  return true
}

function displayURL(input: string): string {
  try {
    const url = new URL(input)
    return url.origin + url.pathname + (url.search ? "?[query redacted]" : "")
  } catch {
    return "[invalid URL]"
  }
}

function redactURLs(input: string): string {
  return input.replace(/https?:\/\/[^\s"'<>]+/gi, (url) => displayURL(url))
}

function extensionFor(url: string, contentType: string): string {
  const pathname = new URL(url).pathname.toLowerCase()
  if (/text\/html|application\/xhtml\+xml/.test(contentType) || /\.x?html?$/.test(pathname)) return ".html"
  if (/\.map(?:\.gz)?$/.test(pathname) || /source-map\+json|x-source-map/.test(contentType)) return ".map"
  if (/\.m?js\.gz$/.test(pathname)) return pathname.endsWith(".mjs.gz") ? ".mjs" : ".js"
  if (pathname.endsWith(".mjs")) return ".mjs"
  if (pathname.endsWith(".cjs")) return ".cjs"
  return ".js"
}

function isHTMLResponse(body: string, contentType: string, url: string): boolean {
  return /text\/html|application\/xhtml\+xml/i.test(contentType) ||
    /\.x?html?$/i.test(new URL(url).pathname) && /^\s*(?:<!doctype\s+html|<html\b|<head\b|<body\b)/i.test(body.slice(0, 4096))
}

/** Detect reusable local JavaScript evidence without following symlinks. */
async function hasLocalJavaScriptInputs(root: string): Promise<boolean> {
  const pending = [root]
  const visited = new Set<string>()
  while (pending.length > 0) {
    const directory = pending.pop()!
    if (visited.has(directory)) continue
    visited.add(directory)
    let entries: import("node:fs").Dirent[]
    try {
      entries = await fs.readdir(directory, { withFileTypes: true })
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") continue
      throw error
    }
    for (const entry of entries) {
      // Do not follow symlinked directories or files outside the target workspace.
      if (entry.isSymbolicLink()) continue
      const fullPath = path.join(directory, entry.name)
      if (entry.isDirectory()) {
        pending.push(fullPath)
        continue
      }
      if (entry.isFile() && /\.(?:js|mjs|cjs|map|html?|xhtml)$/i.test(entry.name)) return true
    }
  }
  return false
}

export function extractJavaScriptImportURLs(body: string, assetURL: string): string[] {
  const output = new Set<string>()
  const patterns = [
    /\bimport\s+(?:(?:[\w$*{},\s]+?)\s+from\s*)?["']([^"'\\\r\n]+)["']/g,
    /\bexport\s+(?:[\w$*{},\s]+?)\s+from\s*["']([^"'\\\r\n]+)["']/g,
    /\bimport\s*\(\s*["']([^"'\\\r\n]+)["']\s*\)/g,
  ]
  for (const pattern of patterns) {
    for (const match of body.matchAll(pattern)) {
      const specifier = (match[1] ?? "").trim()
      if (!/^(?:\.{1,2}\/|\/|https?:\/\/|\/\/)/i.test(specifier)) continue
      try {
        const resolved = normalizeURL(new URL(specifier, assetURL).toString())
        if (resolved) output.add(resolved)
      } catch { /* Ignore non-URL or malformed module specifiers. */ }
    }
  }
  return [...output]
}

export function extractHTMLScriptURLs(body: string, pageURL: string): string[] {
  const output = new Set<string>()
  const baseMatch = /<base\b[^>]*\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i.exec(body)
  let baseURL = pageURL
  const baseValue = baseMatch?.[1] ?? baseMatch?.[2] ?? baseMatch?.[3]
  if (baseValue) {
    try { baseURL = new URL(baseValue, pageURL).toString() } catch { /* Keep the page URL as the base. */ }
  }
  const pattern = /<script\b([^>]*)>/gi
  for (const match of body.matchAll(pattern)) {
    const attributes = match[1] ?? ""
    const srcMatch = /\bsrc\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i.exec(attributes)
    const src = (srcMatch?.[1] ?? srcMatch?.[2] ?? srcMatch?.[3] ?? "").trim()
    if (!src || /^(?:data:|blob:|javascript:)/i.test(src)) continue
    try {
      const resolved = normalizeURL(new URL(src, baseURL).toString())
      if (resolved) output.add(resolved)
    } catch { /* Ignore malformed script src values. */ }
  }
  return [...output]
}

function isLikelyScriptErrorDocument(body: string, contentType: string, url: string): boolean {
  const pathname = new URL(url).pathname
  if (!/\.(?:m?js|cjs)(?:\.gz)?$/i.test(pathname)) return false
  const sample = body.trimStart()
  if (/^(?:Cannot GET\b|Not Found\b|404 Not Found\b|Bad Gateway\b)/i.test(sample)) return true
  if (/^<!doctype\s+html|^<html\b/i.test(sample) && !/<script\b/i.test(sample)) return true
  if (/application\/(?:json|problem\+json)/i.test(contentType) &&
      /^\s*\{/.test(sample) && /"(?:error|message|status)"\s*:/i.test(sample)) return true
  return false
}

function looksLikeJavaScript(body: string, contentType: string, url: string): boolean {
  if (/text\/html|application\/xhtml\+xml/i.test(contentType)) return false
  if (/javascript|ecmascript|x-javascript|source-map\+json|x-source-map/i.test(contentType)) return true
  if (/\.map(?:\.gz)?$/i.test(new URL(url).pathname)) {
    try {
      const parsed = JSON.parse(body) as { version?: unknown; sources?: unknown; mappings?: unknown }
      return parsed.version === 3 && Array.isArray(parsed.sources) && typeof parsed.mappings === "string"
    } catch { return false }
  }
  // Some CDNs omit or mislabel Content-Type. Inspect the full response so syntax
  // after a large license banner or generated comment is not silently ignored.
  const sample = body.trimStart()
  if (/^(?:<!doctype\s+html|<html\b)/i.test(sample)) return false
  // A script extension remains a strong asset hint even when a CDN serves it as
  // text/plain or a minified bundle does not match the lightweight syntax sniff.
  if (/\.(?:m?js|cjs)(?:\.gz)?$/i.test(new URL(url).pathname)) return true
  return /(?:\b(?:function|const|let|var|import|export|class|return|throw|async|await)\b|\b(?:fetch|axios|window|document|globalThis|self|define|require|exports|module)\s*[.(=]|=>|!function\s*\(|sourceMappingURL)/.test(sample)
}

async function readCompleteResponse(response: Response): Promise<Uint8Array> {
  if (!response.body) return new Uint8Array()
  const reader = response.body.getReader()
  const chunks: Uint8Array[] = []
  let size = 0
  try {
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      size += value.byteLength
      chunks.push(value)
    }
  } finally {
    reader.releaseLock()
  }
  const output = new Uint8Array(size)
  let offset = 0
  for (const chunk of chunks) { output.set(chunk, offset); offset += chunk.byteLength }
  return output
}

async function fetchScoped(inputURL: string, abort: AbortSignal): Promise<{ response: Response; finalURL: string } | { error: string; aborted?: boolean }> {
  let current = inputURL
  for (let redirects = 0; redirects <= MAX_REDIRECTS; redirects++) {
    if (abort.aborted) return { error: "fetch cancelled; URL remains pending for resume", aborted: true }
    const scope = await TargetMemory.checkURLScope(current)
    if (abort.aborted) return { error: "fetch cancelled; URL remains pending for resume", aborted: true }
    if (!scope.allowed) return { error: "scope denied for " + displayURL(current) + ": " + redactURLs(scope.reason) }
    let response: Response
    try {
      response = await fetch(current, {
        method: "GET",
        redirect: "manual",
        signal: AbortSignal.any([abort, AbortSignal.timeout(20_000)]),
        headers: { Accept: "application/javascript, text/javascript, application/ecmascript, text/ecmascript, application/json;q=0.8, */*;q=0.1" },
      })
    } catch (error) {
      if (abort.aborted) return { error: "fetch cancelled; URL remains pending for resume", aborted: true }
      return { error: "fetch failed: " + redactURLs(error instanceof Error ? error.message : String(error)) }
    }
    if (![301, 302, 303, 307, 308].includes(response.status)) return { response, finalURL: current }
    const location = response.headers.get("location")
    if (!location) return { error: "redirect response has no Location header" }
    if (redirects === MAX_REDIRECTS) return { error: "redirect limit exceeded" }
    const next = normalizeURL(new URL(location, current).toString())
    if (!next) return { error: "redirect destination is not a credential-free HTTP(S) URL" }
    current = next
  }
  return { error: "redirect limit exceeded" }
}

export const IngestJavaScriptURLsTool = Tool.define<typeof Parameters, Tool.Metadata>("ingest_javascript_urls", {
  description: [
    "Fetch, save, deduplicate, and analyze JavaScript asset URLs supplied by any source.",
    "Input may come from the URL collector, crawlers, HTML page URLs, extracted script src links, relative/absolute ES module imports, dynamic imports, source-map references, urls.txt, another tool, or links manually supplied by the user. HTML pages are saved as inert local artifacts, inline scripts are analyzed, and external script src URLs are added to this same queue. Pass new URLs when available; `urls: []` resumes eligible pending/retryable work from the existing asset manifest without requiring the original URL list.",
    "Each URL is checked against the persisted target scope before fetching, and every redirect is checked again. Requests are GET-only, do not execute downloaded JavaScript, and never send credentials from the current browser/session. The complete response body is downloaded and processed regardless of URL-list length or file size; no URL-count, batch, aggregate-byte, per-file-byte, URL-string-length, or provenance-string-length cap is imposed. The invocation processes the full dynamic worklist (including discovered imports and source maps), writing progress and manifest updates as it goes. Cancellation leaves unfinished URLs pending for resume.",
    "Downloads are stored under the existing target workspace's javascript/assets directory. JavaScript, source maps, and HTML containers are stored as inert files; local correlation extracts inline scripts from HTML and analyzes them without execution. javascript/asset-manifest.json records URL provenance, final URL, status, SHA-256, local path, content type, size, and errors. Pending URLs are persisted before processing and automatically resumed on the next call for the same target after interruption. Relative/absolute ES module and dynamic imports plus source-map references are discovered from each downloaded bundle and added to the same queue. Each asset result is checkpointed in small batches; newly discovered script, module, and source-map URLs are persisted immediately. The tool updates its existing progress metadata for the currently active asset and correlation stage without generating a separate chat message for every queued URL. Repeated URLs reuse the existing local artifact by default; identical content from different URLs shares one content-addressed file while preserving each URL/source record. Use force_refresh when intentionally refreshing cached assets or retrying a permanent failure/skip after confirming the target or response has changed; it never overrides scope checks.",
    "After downloading, invoke the existing JavaScript correlation pipeline so local files are analyzed along with captured response bodies. Analysis extracts endpoint, parameter, auth/header/cookie, role/feature, secret-fingerprint, source-map, and risky-sink candidates. It does not execute code or automatically run vulnerability probes.",
    "Only already initialized target workspaces with a valid configured scope can fetch. URLs outside scope or redirects outside scope are rejected; a user-supplied URL is input, not authorization.",
  ].join("\n"),
  parameters: Parameters,
  async execute(params, ctx) {
    const workspace = await TargetMemory.get(params.target_url)
    if (!workspace) {
      return { title: "JavaScript URL ingestion stopped", output: "No existing target workspace matches target_url. Initialize the canonical target workspace first.", metadata: { error: "workspace_missing" } }
    }

    const scope = await TargetMemory.getScope(params.target_url)
    if (!scope || scope.status !== "configured") {
      return { title: "JavaScript URL ingestion stopped", output: "The target workspace has no valid configured scope. No URLs were fetched.", metadata: { error: "scope_unconfigured" } }
    }

    const root = path.join(workspace.workspacePath, "javascript")
    const assetsDir = path.join(root, "assets")
    const manifestPath = path.join(root, "asset-manifest.json")
    await fs.mkdir(assetsDir, { recursive: true })

    let manifest: Manifest = { schemaVersion: 1, updatedAt: new Date().toISOString(), assets: [] }
    try {
      const rawManifest = await fs.readFile(manifestPath, "utf8")
      try {
        manifest = parseAssetManifest(rawManifest)
      } catch (error) {
        return {
          title: "JavaScript ingestion stopped — manifest needs repair",
          output: [
            "The existing JavaScript asset manifest is invalid or uses an unsupported schema.",
            "No URLs were fetched and the existing manifest was left untouched to protect pending work and provenance.",
            "Manifest: " + manifestPath,
            "Parser error: " + (error instanceof Error ? error.message : String(error)),
          ].join("\n"),
          metadata: { error: "manifest_invalid", manifest_path: manifestPath },
        }
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
        return {
          title: "JavaScript ingestion stopped — manifest unreadable",
          output: "Could not read the existing JavaScript asset manifest. No URLs were fetched. Manifest: " + manifestPath,
          metadata: { error: "manifest_unreadable", manifest_path: manifestPath },
        }
      }
    }

    const byURL = new Map(manifest.assets.map((item) => [normalizeURL(item.url) ?? item.url, item]))
    const byHash = new Map<string, AssetRecord>()
    for (const item of manifest.assets) {
      if (item.contentHash && item.localPath && await Bun.file(item.localPath).exists()) byHash.set(item.contentHash, item)
    }

    const saveManifest = async () => {
      manifest = {
        schemaVersion: 1,
        updatedAt: new Date().toISOString(),
        assets: [...byURL.values()].sort((a, b) => a.url.localeCompare(b.url)),
      }
      const temporaryManifest = manifestPath + ".tmp"
      await fs.writeFile(temporaryManifest, JSON.stringify(manifest, null, 2) + "\n", "utf8")
      await fs.rename(temporaryManifest, manifestPath)
    }

    let unsavedProgress = 0
    const saveProgress = async (force = false) => {
      unsavedProgress++
      if (force || unsavedProgress >= 10) {
        await saveManifest()
        unsavedProgress = 0
      }
    }

    const invalidCount = params.urls.filter((url) => !normalizeURL(url)).length
    const inputURLs = [...new Set(params.urls.map(normalizeURL).filter((value): value is string => Boolean(value)))]
    const localJavaScriptInputsAtStart = inputURLs.length === 0 ? await hasLocalJavaScriptInputs(root) : false
    const queuedURLs = new Set(inputURLs)
    const sourceByURL = new Map<string, Set<string>>()
    const addSource = (url: string, source: string) => {
      const values = sourceByURL.get(url) ?? new Set(mergeAssetSources(byURL.get(url)?.sources, byURL.get(url)?.source))
      const before = values.size
      for (const item of mergeAssetSources(source)) values.add(item)
      sourceByURL.set(url, values)
      const prior = byURL.get(url)
      if (prior) {
        const sources = [...values].sort()
        byURL.set(url, { ...prior, source: mergeAssetSourceLabel(sources), sources })
      }
      return values.size > before
    }
    const markPending = (url: string, forceRefresh = false) => {
      const prior = byURL.get(url)
      const sources = mergeAssetSources(prior?.sources, prior?.source, [...(sourceByURL.get(url) ?? [])])
      if (forceRefresh || !prior || prior.status === "pending" || prior.retryable === true) {
        byURL.set(url, {
          ...prior,
          url,
          retryable: undefined,
          attempts: forceRefresh ? 0 : (prior?.attempts ?? 0),
          source: mergeAssetSourceLabel(sources),
          sources,
          status: "pending",
          ...(forceRefresh || prior?.pendingRefresh ? { pendingRefresh: true } : {}),
        })
      }
    }
    const enqueueURL = (url: string, source: string) => {
      const sourceChanged = addSource(url, source)
      if (queuedURLs.has(url)) return sourceChanged
      queuedURLs.add(url)
      inputURLs.push(url)
      markPending(url, params.force_refresh)
      return true
    }
    for (const url of inputURLs) addSource(url, params.source)
    for (const item of manifest.assets) {
      if (!shouldResumeAsset(item)) continue
      const url = normalizeURL(item.url)
      if (!url) continue
      for (const source of mergeAssetSources(item.sources, item.source)) addSource(url, source)
      if (!queuedURLs.has(url)) {
        queuedURLs.add(url)
        inputURLs.push(url)
      }
    }
    if (inputURLs.length === 0 && !localJavaScriptInputsAtStart) {
      const downloadedExisting = manifest.assets.filter((record) => record.status === "downloaded").length
      const reusedExisting = manifest.assets.filter((record) => record.status === "reused").length
      const failedExisting = manifest.assets.filter((record) => record.status === "failed").length
      const skippedExisting = manifest.assets.filter((record) => record.status === "skipped").length
      const pendingExisting = manifest.assets.filter((record) => record.status === "pending").length
      const retryableExisting = manifest.assets.filter((record) => record.status === "failed" && record.retryable === true).length
      const existingCoverageComplete =
        manifest.assets.length > 0 &&
        invalidCount === 0 &&
        manifest.assets.every((record) => record.status === "downloaded" || record.status === "reused")
      return {
        title: existingCoverageComplete
          ? "JavaScript manifest is settled — no new URLs to fetch"
          : "JavaScript ingestion has no resumable work — existing coverage gaps remain",
        output: [
          invalidCount
            ? "No valid HTTP(S) URLs were supplied, and the target manifest has no pending or retryable assets to resume."
            : "No URLs were supplied and the target manifest has no pending or retryable assets to resume.",
          "Manifest: " + manifestPath,
          "Existing manifest entries: " + manifest.assets.length,
          "Downloaded: " + downloadedExisting,
          "Reused: " + reusedExisting,
          "Failed: " + failedExisting,
          "Skipped: " + skippedExisting,
          "Pending: " + pendingExisting,
          "Retryable failures: " + retryableExisting,
          "Collection coverage: " + (existingCoverageComplete ? "complete" : "incomplete — inspect failed/skipped/invalid statuses before reporting full coverage"),
        ].join("\n"),
        metadata: {
          error: "no_urls_or_pending_queue",
          manifest_path: manifestPath,
          workspace: workspace.workspacePath,
          invalid_urls: invalidCount,
          queued_urls: 0,
          worklist_settled: 0,
          worklist_available: 0,
          worklist_pending: pendingExisting,
          worklist_retryable_failures: retryableExisting,
          worklist_missing_manifest_records: 0,
          manifest_reconciled: pendingExisting === 0 && retryableExisting === 0,
          collection_complete: existingCoverageComplete,
          correlation_saved: false,
          analysis_complete: false,
          downloaded: 0,
          reused: 0,
          failed: 0,
          skipped: 0,
          pending_assets: pendingExisting,
          retryable_failures: retryableExisting,
        },
      }
    }
    for (const url of inputURLs) markPending(url, params.force_refresh)
    await saveProgress(true)
    const records: AssetRecord[] = []
    let downloadedBytes = 0
    let receivedBytes = 0
    let reused = 0
    let downloaded = 0
    let skipped = 0
    let failed = 0
    let terminalNotRetried = 0
    const automaticRetryScheduled = new Set<string>()

    let processedThisInvocation = 0
    for (let index = 0; index < inputURLs.length && processedThisInvocation < MAX_ASSETS_PER_INVOCATION; index++) {
      processedThisInvocation++
      if (ctx.abort.aborted) {
        await saveProgress(true)
        break
      }
      const url = inputURLs[index]!
      const parsedURL = new URL(url)
      const activeAsset = parsedURL.origin + parsedURL.pathname
      ctx.metadata({
        title: "JavaScript analysis — " + activeAsset,
        metadata: {
          stage: "checking_cache",
          active_asset: activeAsset,
          processed: index,
          queued: queuedURLs.size,
          target_url: displayURL(params.target_url),
        },
      })
      const assetSource = mergeAssetSourceLabel([...(sourceByURL.get(url) ?? new Set([params.source]))])
      const prior = byURL.get(url)
      const forceRefresh = params.force_refresh || prior?.pendingRefresh === true
      if (!shouldFetchAsset(prior, forceRefresh)) {
        terminalNotRetried++
        continue
      }
      if (!forceRefresh && prior?.contentHash && prior.localPath && await Bun.file(prior.localPath).exists()) {
        ctx.metadata({
          title: "Reusing JavaScript asset — " + activeAsset,
          metadata: { stage: "cache_hit", active_asset: activeAsset, processed: index, queued: queuedURLs.size, target_url: displayURL(params.target_url) },
        })
        const sources = mergeAssetSources(prior.sources, prior.source, [...(sourceByURL.get(url) ?? new Set([params.source]))])
        const record: AssetRecord = { ...prior, source: mergeAssetSourceLabel(sources), sources, status: "reused" }
        records.push(record)
        byURL.set(url, record)
        reused++
        await saveProgress()
        continue
      }
      ctx.metadata({
        title: "Fetching JavaScript asset — " + activeAsset,
        metadata: { stage: "fetching", active_asset: activeAsset, processed: index, queued: queuedURLs.size, target_url: displayURL(params.target_url) },
      })
      const result = await fetchScoped(url, ctx.abort)
      if ("error" in result) {
        if (result.aborted || ctx.abort.aborted) {
          const prior = byURL.get(url)
          const sources = mergeAssetSources(prior?.sources, prior?.source, [...(sourceByURL.get(url) ?? new Set([params.source]))])
          const record: AssetRecord = {
            ...prior,
            url,
            source: mergeAssetSourceLabel(sources),
            sources,
            status: "pending",
            ...(forceRefresh || prior?.pendingRefresh ? { pendingRefresh: true } : {}),
            error: result.error,
          }
          records.push(record)
          byURL.set(url, record)
          await saveProgress(true)
          break
        }
        const prior = byURL.get(url)
        const sources = mergeAssetSources(prior?.sources, prior?.source, [...(sourceByURL.get(url) ?? new Set([params.source]))])
        const attempts = (prior?.attempts ?? 0) + 1
        const retryable = result.error.startsWith("fetch failed:") &&
          shouldRetryJavaScriptAsset({ kind: "network", attempt: attempts })
        const record: AssetRecord = {
          ...prior,
          url,
          source: mergeAssetSourceLabel(sources),
          sources,
          status: "failed",
          retryable,
          attempts,
          pendingRefresh: retryable && prior?.pendingRefresh ? true : undefined,
          error: result.error,
          fetchedAt: new Date().toISOString(),
        }
        records.push(record); byURL.set(url, record); failed++
        if (retryable && !automaticRetryScheduled.has(url)) {
          automaticRetryScheduled.add(url)
          inputURLs.push(url)
        }
        await saveProgress()
        continue
      }
      const { response, finalURL } = result
      if (!response.ok) {
        await response.body?.cancel().catch(() => {})
        const prior = byURL.get(url)
        const sources = mergeAssetSources(prior?.sources, prior?.source, [...(sourceByURL.get(url) ?? new Set([params.source]))])
        const attempts = (prior?.attempts ?? 0) + 1
        const retryable = shouldRetryJavaScriptAsset({ kind: "http", status: response.status, attempt: attempts })
        const record: AssetRecord = {
          ...prior,
          url,
          finalURL,
          source: mergeAssetSourceLabel(sources),
          sources,
          status: "failed",
          retryable,
          attempts,
          pendingRefresh: retryable && prior?.pendingRefresh ? true : undefined,
          error: "HTTP " + response.status,
          fetchedAt: new Date().toISOString(),
        }
        records.push(record); byURL.set(url, record); failed++
        if (retryable && !automaticRetryScheduled.has(url)) {
          automaticRetryScheduled.add(url)
          inputURLs.push(url)
        }
        await saveProgress()
        continue
      }
      const contentType = (response.headers.get("content-type") ?? "").split(";")[0]!.trim().toLowerCase()
      let bytes: Uint8Array
      ctx.metadata({
        title: "Reading JavaScript response — " + activeAsset,
        metadata: { stage: "reading_response", active_asset: activeAsset, processed: index, queued: queuedURLs.size, content_type: contentType },
      })
      try { bytes = await readCompleteResponse(response) }
      catch (error) {
        if (ctx.abort.aborted) {
          const prior = byURL.get(url)
          const sources = mergeAssetSources(prior?.sources, prior?.source, [...(sourceByURL.get(url) ?? new Set([params.source]))])
          const record: AssetRecord = {
            ...prior,
            url,
            finalURL,
            source: mergeAssetSourceLabel(sources),
            sources,
            status: "pending",
            ...(forceRefresh || prior?.pendingRefresh ? { pendingRefresh: true } : {}),
            error: "response body read cancelled; pending for resume",
          }
          records.push(record)
          byURL.set(url, record)
          await saveProgress(true)
          break
        }
        const readError = redactURLs(error instanceof Error ? error.message : String(error))
        const prior = byURL.get(url)
        const sources = mergeAssetSources(prior?.sources, prior?.source, [...(sourceByURL.get(url) ?? new Set([params.source]))])
        const attempts = (prior?.attempts ?? 0) + 1
        const retryable = shouldRetryJavaScriptAsset({ kind: "read", attempt: attempts })
        const record: AssetRecord = {
          ...prior,
          url,
          finalURL,
          source: mergeAssetSourceLabel(sources),
          sources,
          status: "failed",
          retryable,
          attempts,
          pendingRefresh: retryable && prior?.pendingRefresh ? true : undefined,
          contentType,
          error: readError,
          fetchedAt: new Date().toISOString(),
        }
        records.push(record); byURL.set(url, record); failed++
        if (retryable && !automaticRetryScheduled.has(url)) {
          automaticRetryScheduled.add(url)
          inputURLs.push(url)
        }
        await saveProgress()
        continue
      }
      const receivedResponseBytes = bytes.byteLength
      receivedBytes += receivedResponseBytes
      const responsePath = new URL(finalURL).pathname
      if (/\.gz$/i.test(responsePath) && bytes.byteLength >= 2 && bytes[0] === 0x1f && bytes[1] === 0x8b) {
        try {
          // Some CDNs serve gzip payloads as files (.js.gz) rather than HTTP content-encoding.
          // Hash/save the decoded source so identical plain and gzip-delivered bundles deduplicate.
          bytes = new Uint8Array(gunzipSync(bytes))
        } catch (error) {
          const prior = byURL.get(url)
          const sources = mergeAssetSources(prior?.sources, prior?.source, [...(sourceByURL.get(url) ?? new Set([params.source]))])
          const record: AssetRecord = {
            ...prior, url, finalURL, source: mergeAssetSourceLabel(sources), sources,
            status: "failed", retryable: false, attempts: (prior?.attempts ?? 0) + 1,
            assetKind: /\.map\.gz$/i.test(responsePath) ? "source-map" : "javascript",
            contentType, bytes: receivedResponseBytes,
            error: "gzip asset could not be decompressed: " + redactURLs(error instanceof Error ? error.message : String(error)),
            fetchedAt: new Date().toISOString(),
          }
          records.push(record); byURL.set(url, record); failed++
          await saveProgress()
          continue
        }
      }
      const body = new TextDecoder("utf-8", { fatal: false }).decode(bytes)
      const isHTML = isHTMLResponse(body, contentType, finalURL)
      const finalPathname = new URL(finalURL).pathname
      const expectedSourceMap = /\.map(?:\.gz)?$/i.test(finalPathname) || /source-map\+json|x-source-map/i.test(contentType)
      const expectedJavaScript = /\.(?:m?js|cjs)(?:\.gz)?$/i.test(finalPathname) || /(?:java|ecma)script|x-javascript/i.test(contentType)
      if (expectedJavaScript && isLikelyScriptErrorDocument(body, contentType, finalURL)) {
        const prior = byURL.get(url)
        const sources = mergeAssetSources(prior?.sources, prior?.source, [...(sourceByURL.get(url) ?? new Set([params.source]))])
        const record: AssetRecord = {
          ...prior, url, finalURL, source: mergeAssetSourceLabel(sources), sources,
          status: "failed", retryable: false, attempts: (prior?.attempts ?? 0) + 1,
          assetKind: "javascript", skipReason: "error-document", contentType, bytes: bytes.byteLength,
          error: "HTTP " + response.status + " returned an error document instead of a JavaScript asset",
          fetchedAt: new Date().toISOString(),
        }
        records.push(record); byURL.set(url, record); failed++
        await saveProgress()
        continue
      }
      if (!isHTML && !expectedSourceMap && !looksLikeJavaScript(body, contentType, finalURL)) {
        const prior = byURL.get(url)
        const sources = mergeAssetSources(prior?.sources, prior?.source, [...(sourceByURL.get(url) ?? new Set([params.source]))])
        const record: AssetRecord = {
          ...prior, url, finalURL, source: mergeAssetSourceLabel(sources), sources,
          status: "skipped", retryable: undefined, pendingRefresh: undefined,
          assetKind: "non-js", skipReason: "non-javascript-resource", contentType,
          bytes: bytes.byteLength,
          error: "response is not a JavaScript asset, HTML container, or source map; excluded from JavaScript coverage",
          fetchedAt: new Date().toISOString(),
        }
        records.push(record); byURL.set(url, record); skipped++
        await saveProgress()
        continue
      }
      let queueChanged = false
      if (isHTML) {
        // Treat HTML as an inert container: local analysis extracts inline scripts,
        // while external script URLs re-enter this same scope-enforced fetch queue.
        for (const scriptURL of extractHTMLScriptURLs(body, finalURL)) {
          if (enqueueURL(scriptURL, "script src from " + displayURL(url))) queueChanged = true
        }
      } else {
        // Discover module chunks and source maps as inert text, then route every
        // candidate through the same scope-enforced queue.
        for (const importURL of extractJavaScriptImportURLs(body, finalURL)) {
          if (enqueueURL(importURL, "module import from " + displayURL(url))) queueChanged = true
        }
        for (const mapURL of extractJavaScriptSourceMapReferences(body, finalURL)) {
          const normalizedMapURL = normalizeURL(mapURL)
          if (!normalizedMapURL) continue
          if (enqueueURL(normalizedMapURL, "sourceMappingURL from " + displayURL(url))) queueChanged = true
        }
      }
      if (queueChanged) await saveProgress(true)
      const contentHash = createHash("sha256").update(bytes).digest("hex")
      const existingContent = byHash.get(contentHash)
      let localPath = existingContent?.localPath
      if (!localPath || !await Bun.file(localPath).exists()) {
        const extension = extensionFor(finalURL, contentType)
        localPath = path.join(assetsDir, contentHash + extension)
        await fs.writeFile(localPath, bytes, { flag: "wx" }).catch(async (error: NodeJS.ErrnoException) => {
          if (error.code !== "EEXIST") throw error
        })
        byHash.set(contentHash, { url, finalURL, source: assetSource, status: "downloaded", contentHash, localPath, contentType, bytes: bytes.byteLength, fetchedAt: new Date().toISOString() })
      }
      const sources = mergeAssetSources(byURL.get(url)?.sources, byURL.get(url)?.source, [...(sourceByURL.get(url) ?? new Set([params.source]))])
      const record: AssetRecord = { url, finalURL, source: mergeAssetSourceLabel(sources), sources, status: existingContent ? "reused" : "downloaded", contentHash, localPath, contentType, bytes: bytes.byteLength, fetchedAt: new Date().toISOString() }
      records.push(record)
      byURL.set(url, record)
      if (existingContent) reused++
      else { downloaded++; downloadedBytes += bytes.byteLength }
      await saveProgress()
    }

    await saveProgress(true)

    let analysisSummary = ctx.abort.aborted ? "Correlation not run because ingestion was interrupted; pending assets are saved for resume." : "Analysis not run."
    let analysisError: string | undefined
    let analyzedSourceRecords = 0
    let analysisCoverageGaps = 0
    const localJavaScriptInputs = await hasLocalJavaScriptInputs(root)
    const hasUnfinishedQueue = [...byURL.values()].some((record) =>
      record.status === "pending" || (record.status === "failed" && record.retryable === true),
    )
    // Avoid rebuilding the full graph after every bounded slice; once pending work drains,
    // correlate the complete local corpus exactly once.
    const shouldRunCorrelation = !ctx.abort.aborted && !hasUnfinishedQueue && (downloaded + reused > 0 || localJavaScriptInputs)
    if (shouldRunCorrelation) {
      ctx.metadata({
        title: "Correlating JavaScript and captured requests",
        metadata: {
          stage: "correlation",
          processed: inputURLs.length,
          queued: queuedURLs.size,
          target_url: displayURL(params.target_url),
        },
      })
      try {
        const result = await JavaScriptCorrelation.build({ sessionID: ctx.sessionID, targetURL: params.target_url, localOnly: true })
        analyzedSourceRecords = result.graph.sourceFiles.length
        analysisCoverageGaps =
          result.graph.notes.filter((note) => note.startsWith("JAVASCRIPT INVENTORY GAP:")).length +
          result.graph.sourceFiles.filter((file) => Boolean(file.sourceMapStatus && file.sourceMapStatus !== "analyzed")).length +
          (result.graph.sourceMapReferences ?? []).filter((item) => !["analyzed", "out-of-scope"].includes(item.status)).length
        analysisSummary = [
          "JavaScript correlation snapshot: " + result.graphPath,
          "Endpoint inventory: " + result.endpointPath,
          "Unique endpoint candidates: " + result.graph.endpointCandidates.length,
          "Unique source records: " + analyzedSourceRecords,
          "Source-map references: " + (result.graph.sourceMapReferences ?? []).length,
          "Unresolved source/inventory gaps: " + analysisCoverageGaps,
        ].join("\n")
      } catch (error) {
        analysisError = error instanceof Error ? error.message : String(error)
        analysisSummary = "Download succeeded, but correlation failed: " + analysisError
      }
    }

    const finalManifestAssets = [...byURL.values()]
    const allQueuedURLs = [...queuedURLs]
    const worklistRecords = allQueuedURLs.map((url) => byURL.get(url))
    const worklistMissingRecords = worklistRecords.filter((record) => !record).length
    const worklistPending = worklistRecords.filter((record) => record?.status === "pending").length
    const worklistRetryable = worklistRecords.filter((record) => record?.status === "failed" && record.retryable === true).length
    const worklistSettled = allQueuedURLs.length - worklistMissingRecords - worklistPending - worklistRetryable
    const worklistAvailable = worklistRecords.filter((record) => record?.status === "downloaded" || record?.status === "reused").length
    const isNonJavaScriptSkip = (record: AssetRecord | undefined) => {
      if (record?.status !== "skipped") return false
      if (record.skipReason === "non-javascript-resource" && record.assetKind === "non-js") return true
      // Legacy manifests predate typed exclusions. Do not hide an old failed JS/source-map
      // response merely because it used the previous generic "does not look like JS" message.
      const pathname = (() => { try { return new URL(record.url).pathname } catch { return "" } })()
      const looksLikeCodeAsset = /\.(?:m?js|cjs|map)(?:\.gz)?$/i.test(pathname) ||
        /(?:java|ecma)script|source-map/i.test(record.contentType ?? "")
      return record.error === "response does not look like JavaScript, HTML with script elements, or a version-3 source map" &&
        !looksLikeCodeAsset
    }
    const worklistNonJavaScript = worklistRecords.filter((record) => isNonJavaScriptSkip(record)).length
    const worklistAccounted = worklistAvailable + worklistNonJavaScript
    const globalPending = finalManifestAssets.filter((record) => record.status === "pending").length
    const globalRetryable = finalManifestAssets.filter((record) => record.status === "failed" && record.retryable === true).length
    const manifestReconciled = worklistMissingRecords === 0 && worklistPending === 0 && worklistRetryable === 0
    const collectionComplete =
      !ctx.abort.aborted &&
      (manifest.assets.length > 0 || allQueuedURLs.length > 0) &&
      manifestReconciled &&
      invalidCount === 0 &&
      globalPending === 0 &&
      globalRetryable === 0 &&
      worklistAccounted === allQueuedURLs.length &&
      finalManifestAssets.every((record) =>
        record.status === "downloaded" || record.status === "reused" || isNonJavaScriptSkip(record),
      )
    const correlationSaved = shouldRunCorrelation && !ctx.abort.aborted && !analysisError
    const completeAnalysis = collectionComplete && correlationSaved && analyzedSourceRecords > 0 && analysisCoverageGaps === 0
    const resultTitle = ctx.abort.aborted
      ? "JavaScript ingestion interrupted — pending work saved"
      : analysisError || !manifestReconciled || globalPending > 0 || globalRetryable > 0
        ? "JavaScript ingestion incomplete — resumable work remains"
        : !collectionComplete
          ? "JavaScript ingestion finished with asset gaps"
          : !completeAnalysis
            ? analyzedSourceRecords > 0
              ? "JavaScript evidence saved — source/inventory coverage gaps remain"
              : "JavaScript evidence saved — no analyzable source records confirmed"
            : "JavaScript URL ingestion complete"

    return {
      title: resultTitle,
      output: [
        "Workspace: " + workspace.workspacePath,
        "Input URL rows: " + params.urls.length,
        "Unique valid URLs supplied: " + new Set(params.urls.map(normalizeURL).filter(Boolean)).size,
        "Unique URLs in complete worklist (supplied, resumed, and discovered): " + allQueuedURLs.length,
        "Worklist records settled with an explicit terminal status: " + worklistSettled + "/" + allQueuedURLs.length,
        "Worklist records with downloaded/reused content: " + worklistAvailable + "/" + allQueuedURLs.length,
        "Explicitly excluded non-JavaScript resources: " + worklistNonJavaScript,
        "URLs processed in this invocation: " + processedThisInvocation + " (per-invocation slice: " + MAX_ASSETS_PER_INVOCATION + "; no total URL cap)",
        "Worklist records still pending: " + worklistPending,
        "Worklist retryable failures: " + worklistRetryable,
        "Worklist URLs without manifest records: " + worklistMissingRecords,
        "Manifest reconciliation: " + (manifestReconciled ? "all queued URLs have recorded statuses; no pending/retryable work in this invocation" : "INCOMPLETE — inspect pending/retryable/missing counts and resume automatically"),
        "Collection coverage: " + (collectionComplete ? "COMPLETE — every listed asset has downloaded/reused content and no manifest gaps" : "INCOMPLETE — inspect invalid, failed, skipped, pending, retryable, or missing records"),
        "Invalid URLs rejected: " + invalidCount,
        "Downloaded new content versions in this invocation: " + downloaded,
        "Reused URL/content records in this invocation: " + reused,
        "Skipped responses in this invocation: " + skipped,
        "Failed fetch attempts in this invocation: " + failed,
        "Permanent failures/skips not retried in this invocation: " + terminalNotRetried,
        "Newly downloaded bytes: " + downloadedBytes,
        "Total response bytes received: " + receivedBytes,
        "Manifest: " + manifestPath,
        "Correlation status: " + (analysisError ? "FAILED — " + analysisError : ctx.abort.aborted ? "not run because the tool was interrupted" : correlationSaved ? (completeAnalysis ? "ran and saved a full-coverage snapshot" : !collectionComplete ? "ran and saved a partial snapshot; collection still has coverage gaps" : analyzedSourceRecords > 0 ? "ran and saved source records, but unresolved source/inventory gaps remain" : "ran but no analyzable source records were confirmed") : "deferred until the persisted queue has no pending/retryable items"),
        "Analyzed source records: " + analyzedSourceRecords,
        analysisSummary,
        ...records.filter((record) => record.status === "failed" || (record.status === "skipped" && !isNonJavaScriptSkip(record))).map((record) => displayURL(record.url) + " — " + record.status + ": " + redactURLs(record.error ?? "")),
      ].join("\n"),
      metadata: {
        manifest_path: manifestPath,
        workspace: workspace.workspacePath,
        input_urls: params.urls.length,
        valid_unique_urls: new Set(params.urls.map(normalizeURL).filter(Boolean)).size,
        queued_urls: allQueuedURLs.length,
        worklist_settled: worklistSettled,
        worklist_available: worklistAvailable,
        worklist_non_javascript: worklistNonJavaScript,
        processed_this_invocation: processedThisInvocation,
        per_invocation_limit: MAX_ASSETS_PER_INVOCATION,
        invocation_limit_reached: !ctx.abort.aborted && processedThisInvocation >= MAX_ASSETS_PER_INVOCATION &&
          [...byURL.values()].some((record) => record.status === "pending" || (record.status === "failed" && record.retryable === true)),
        worklist_pending: worklistPending,
        worklist_retryable_failures: worklistRetryable,
        worklist_missing_manifest_records: worklistMissingRecords,
        manifest_reconciled: manifestReconciled,
        collection_complete: collectionComplete,
        correlation_saved: correlationSaved,
        pending_assets: globalPending,
        retryable_failures: globalRetryable,
        permanent_failures_not_retried: terminalNotRetried,
        invalid_urls: invalidCount,
        downloaded,
        reused,
        skipped,
        failed,
        downloaded_bytes: downloadedBytes,
        received_bytes: receivedBytes,
        analysis_error: analysisError,
        analysis_coverage_gaps: analysisCoverageGaps,
        analyzed_source_records: analyzedSourceRecords,
        analysis_complete: completeAnalysis,
        interrupted: ctx.abort.aborted,
      },
    }
  },
})
