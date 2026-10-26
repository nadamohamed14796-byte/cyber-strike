import { createHash } from "node:crypto"
import fs from "node:fs/promises"
import path from "node:path"
import z from "zod"
import { TargetMemory } from "../target"
import { JavaScriptCorrelation, extractJavaScriptSourceMapReferences } from "../target/javascript-correlation"
import { Tool } from "./tool"

const MAX_ASSET_BYTES = 32 * 1024 * 1024
const MAX_REDIRECTS = 5

const Parameters = z.object({
  target_url: z.string().min(1).describe("Existing canonical root target URL whose saved scope governs every fetch."),
  urls: z.array(z.string().trim().min(1).max(8192)).min(1)
    .describe("JavaScript asset URLs OR HTML page URLs from ANY source: URL collector, crawler, HTML links, source-map references, URL inventory, or user input. HTML pages are parsed for inline scripts and external script src URLs. Pass actual HTTP(S) URLs, not local file paths."),
  source: z.string().trim().min(1).max(120).default("unspecified")
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
  if (pathname.endsWith(".map") || /source-map\+json|x-source-map/.test(contentType)) return ".map"
  if (pathname.endsWith(".mjs")) return ".mjs"
  if (pathname.endsWith(".cjs")) return ".cjs"
  return ".js"
}

function isHTMLResponse(body: string, contentType: string, url: string): boolean {
  return /text\/html|application\/xhtml\+xml/i.test(contentType) ||
    /\.x?html?$/i.test(new URL(url).pathname) && /^\s*(?:<!doctype\s+html|<html\b|<head\b|<body\b)/i.test(body.slice(0, 4096))
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

function looksLikeJavaScript(body: string, contentType: string, url: string): boolean {
  if (/text\/html|application\/xhtml\+xml/i.test(contentType)) return false
  if (/javascript|ecmascript|x-javascript|source-map\+json|x-source-map/i.test(contentType)) return true
  if (new URL(url).pathname.toLowerCase().endsWith(".map")) {
    try {
      const parsed = JSON.parse(body) as { version?: unknown; sources?: unknown; mappings?: unknown }
      return parsed.version === 3 && Array.isArray(parsed.sources) && typeof parsed.mappings === "string"
    } catch { return false }
  }
  // Some CDNs omit or mislabel Content-Type. Accept text only when the response
  // has clear JavaScript syntax and does not look like an HTML error page.
  const sample = body.slice(0, 4096).trimStart()
  if (/^(?:<!doctype\s+html|<html\b)/i.test(sample)) return false
  return /(?:\b(?:function|const|let|var|import|export|class)\b|\b(?:fetch|axios)\s*\(|=>|sourceMappingURL)/.test(sample)
}

async function readBounded(response: Response, limit: number): Promise<Uint8Array> {
  if (!response.body) return new Uint8Array()
  const reader = response.body.getReader()
  const chunks: Uint8Array[] = []
  let size = 0
  try {
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      size += value.byteLength
      if (size > limit) {
        await reader.cancel("JavaScript asset exceeded the configured size limit")
        throw new Error("response exceeds the " + limit + " byte asset limit")
      }
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
    "Input may come from the URL collector, crawlers, HTML page URLs, extracted script src links, relative/absolute ES module imports, dynamic imports, source-map references, urls.txt, another tool, or links manually supplied by the user. HTML pages are saved as inert local artifacts, inline scripts are analyzed, and external script src URLs are added to this same queue. Always pass all available URLs in the urls array and identify their provenance in source.",
    "Each URL is checked against the persisted target scope before fetching, and every redirect is checked again. Requests are bounded, GET-only, do not execute downloaded JavaScript, and never send credentials from the current browser/session.",
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
      const parsed = JSON.parse(await fs.readFile(manifestPath, "utf8")) as Partial<Manifest>
      if (parsed.schemaVersion === 1 && Array.isArray(parsed.assets)) manifest = parsed as Manifest
    } catch { /* First run or unreadable prior manifest: begin a new manifest. */ }

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

    const inputURLs = [...new Set(params.urls.map(normalizeURL).filter((value): value is string => Boolean(value)))]
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
        byURL.set(url, { ...prior, source: sources.join(" | "), sources })
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
          source: sources.join(" | "),
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
    for (const url of inputURLs) markPending(url, params.force_refresh)
    await saveProgress(true)
    const invalidCount = params.urls.filter((url) => !normalizeURL(url)).length
    const records: AssetRecord[] = []
    let downloadedBytes = 0
    let receivedBytes = 0
    let reused = 0
    let downloaded = 0
    let skipped = 0
    let failed = 0
    let terminalNotRetried = 0

    for (let index = 0; index < inputURLs.length; index++) {
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
          queued: inputURLs.length,
          target_url: displayURL(params.target_url),
        },
      })
      const assetSource = [...(sourceByURL.get(url) ?? new Set([params.source]))].sort().join(" | ")
      const prior = byURL.get(url)
      const forceRefresh = params.force_refresh || prior?.pendingRefresh === true
      if (!shouldFetchAsset(prior, forceRefresh)) {
        terminalNotRetried++
        continue
      }
      if (!forceRefresh && prior?.contentHash && prior.localPath && await Bun.file(prior.localPath).exists()) {
        ctx.metadata({
          title: "Reusing JavaScript asset — " + activeAsset,
          metadata: { stage: "cache_hit", active_asset: activeAsset, processed: index, queued: inputURLs.length, target_url: displayURL(params.target_url) },
        })
        const sources = mergeAssetSources(prior.sources, prior.source, [...(sourceByURL.get(url) ?? new Set([params.source]))])
        const record: AssetRecord = { ...prior, source: sources.join(" | "), sources, status: "reused" }
        records.push(record)
        byURL.set(url, record)
        reused++
        await saveProgress()
        continue
      }
      ctx.metadata({
        title: "Fetching JavaScript asset — " + activeAsset,
        metadata: { stage: "fetching", active_asset: activeAsset, processed: index, queued: inputURLs.length, target_url: displayURL(params.target_url) },
      })
      const result = await fetchScoped(url, ctx.abort)
      if ("error" in result) {
        if (result.aborted || ctx.abort.aborted) {
          const prior = byURL.get(url)
          const sources = mergeAssetSources(prior?.sources, prior?.source, [...(sourceByURL.get(url) ?? new Set([params.source]))])
          const record: AssetRecord = {
            ...prior,
            url,
            source: sources.join(" | "),
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
        const retryable = result.error.startsWith("fetch failed:")
        const record: AssetRecord = {
          ...prior,
          url,
          source: sources.join(" | "),
          sources,
          status: "failed",
          retryable,
          pendingRefresh: retryable && prior?.pendingRefresh ? true : undefined,
          error: result.error,
          fetchedAt: new Date().toISOString(),
        }
        records.push(record); byURL.set(url, record); failed++
        await saveProgress()
        continue
      }
      const { response, finalURL } = result
      if (!response.ok) {
        const prior = byURL.get(url)
        const sources = mergeAssetSources(prior?.sources, prior?.source, [...(sourceByURL.get(url) ?? new Set([params.source]))])
        const retryable = response.status === 408 || response.status === 429 || response.status >= 500
        const record: AssetRecord = {
          ...prior,
          url,
          finalURL,
          source: sources.join(" | "),
          sources,
          status: "failed",
          retryable,
          pendingRefresh: retryable && prior?.pendingRefresh ? true : undefined,
          error: "HTTP " + response.status,
          fetchedAt: new Date().toISOString(),
        }
        records.push(record); byURL.set(url, record); failed++
        await saveProgress()
        continue
      }
      const contentType = (response.headers.get("content-type") ?? "").split(";")[0]!.trim().toLowerCase()
      const declaredLength = Number(response.headers.get("content-length") ?? "0")
      if (Number.isFinite(declaredLength) && declaredLength > MAX_ASSET_BYTES) {
        const prior = byURL.get(url)
        const sources = mergeAssetSources(prior?.sources, prior?.source, [...(sourceByURL.get(url) ?? new Set([params.source]))])
        const record: AssetRecord = {
          ...prior,
          url,
          finalURL,
          source: sources.join(" | "),
          sources,
          status: "skipped",
          retryable: undefined,
          pendingRefresh: undefined,
          contentType,
          error: "declared response size exceeds the asset limit",
          fetchedAt: new Date().toISOString(),
        }
        records.push(record); byURL.set(url, record); skipped++
        await saveProgress()
        continue
      }
      let bytes: Uint8Array
      ctx.metadata({
        title: "Reading JavaScript response — " + activeAsset,
        metadata: { stage: "reading_response", active_asset: activeAsset, processed: index, queued: inputURLs.length, content_type: contentType },
      })
      try { bytes = await readBounded(response, MAX_ASSET_BYTES) }
      catch (error) {
        if (ctx.abort.aborted) {
          const prior = byURL.get(url)
          const sources = mergeAssetSources(prior?.sources, prior?.source, [...(sourceByURL.get(url) ?? new Set([params.source]))])
          const record: AssetRecord = {
            ...prior,
            url,
            finalURL,
            source: sources.join(" | "),
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
        const retryable = !readError.includes("response exceeds the " + MAX_ASSET_BYTES + " byte asset limit")
        const record: AssetRecord = {
          ...prior,
          url,
          finalURL,
          source: sources.join(" | "),
          sources,
          status: "failed",
          retryable,
          pendingRefresh: retryable && prior?.pendingRefresh ? true : undefined,
          contentType,
          error: readError,
          fetchedAt: new Date().toISOString(),
        }
        records.push(record); byURL.set(url, record); failed++
        await saveProgress()
        continue
      }
      receivedBytes += bytes.byteLength
      const body = new TextDecoder("utf-8", { fatal: false }).decode(bytes)
      const isHTML = isHTMLResponse(body, contentType, finalURL)
      if (!isHTML && !looksLikeJavaScript(body, contentType, finalURL)) {
        const prior = byURL.get(url)
        const sources = mergeAssetSources(prior?.sources, prior?.source, [...(sourceByURL.get(url) ?? new Set([params.source]))])
        const record: AssetRecord = {
          ...prior,
          url,
          finalURL,
          source: sources.join(" | "),
          sources,
          status: "skipped",
          retryable: undefined,
          pendingRefresh: undefined,
          contentType,
          bytes: bytes.byteLength,
          error: "response does not look like JavaScript, HTML with script elements, or a version-3 source map",
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
      const record: AssetRecord = { url, finalURL, source: sources.join(" | "), sources, status: existingContent ? "reused" : "downloaded", contentHash, localPath, contentType, bytes: bytes.byteLength, fetchedAt: new Date().toISOString() }
      records.push(record)
      byURL.set(url, record)
      if (existingContent) reused++
      else { downloaded++; downloadedBytes += bytes.byteLength }
      await saveProgress()
    }

    await saveProgress(true)

    let analysisSummary = ctx.abort.aborted ? "Correlation not run because ingestion was interrupted; pending assets are saved for resume." : "Analysis not run."
    let analysisError: string | undefined
    if (!ctx.abort.aborted && downloaded + reused > 0) {
      ctx.metadata({
        title: "Correlating JavaScript and captured requests",
        metadata: {
          stage: "correlation",
          processed: inputURLs.length,
          queued: inputURLs.length,
          target_url: displayURL(params.target_url),
        },
      })
      try {
        const result = await JavaScriptCorrelation.build({ sessionID: ctx.sessionID, targetURL: params.target_url })
        analysisSummary = [
          "JavaScript correlation snapshot: " + result.graphPath,
          "Endpoint inventory: " + result.endpointPath,
          "Unique endpoint candidates: " + result.graph.endpointCandidates.length,
          "Unique source records: " + result.graph.sourceFiles.length,
          "Source-map references: " + (result.graph.sourceMapReferences ?? []).length,
        ].join("\n")
      } catch (error) {
        analysisError = error instanceof Error ? error.message : String(error)
        analysisSummary = "Download succeeded, but correlation failed: " + analysisError
      }
    }

    return {
      title: ctx.abort.aborted ? "JavaScript ingestion interrupted — pending work saved" : "JavaScript URL ingestion complete",
      output: [
        "Workspace: " + workspace.workspacePath,
        "Input URLs: " + params.urls.length,
        "Unique URLs handled (supplied, resumed, and discovered): " + inputURLs.length,
        "Pending assets left for resume: " + [...byURL.values()].filter((record) => record.status === "pending").length,
        "Retryable failures retained for the next run: " + [...byURL.values()].filter((record) => record.retryable === true).length,
        "Permanent failures/skips not retried: " + terminalNotRetried,
        "Invalid URLs rejected: " + invalidCount,
        "Downloaded new content versions: " + downloaded,
        "Reused URL/content records: " + reused,
        "Skipped responses: " + skipped,
        "Failed URLs: " + failed,
        "Newly downloaded bytes: " + downloadedBytes,
        "Total response bytes received: " + receivedBytes,
        "Manifest: " + manifestPath,
        analysisSummary,
        ...records.filter((record) => record.status === "failed" || record.status === "skipped").map((record) => displayURL(record.url) + " — " + record.status + ": " + redactURLs(record.error ?? "")),
      ].join("\n"),
      metadata: {
        manifest_path: manifestPath,
        workspace: workspace.workspacePath,
        input_urls: params.urls.length,
        valid_unique_urls: inputURLs.length,
        queued_urls: inputURLs.length,
        pending_assets: [...byURL.values()].filter((record) => record.status === "pending").length,
        retryable_failures: [...byURL.values()].filter((record) => record.retryable === true).length,
        permanent_failures_not_retried: terminalNotRetried,
        invalid_urls: invalidCount,
        downloaded,
        reused,
        skipped,
        failed,
        downloaded_bytes: downloadedBytes,
        received_bytes: receivedBytes,
        analysis_error: analysisError,
        interrupted: ctx.abort.aborted,
      },
    }
  },
})
