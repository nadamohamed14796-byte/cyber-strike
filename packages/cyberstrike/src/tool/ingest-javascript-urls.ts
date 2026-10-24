import { createHash, randomUUID } from "node:crypto"
import fs from "node:fs/promises"
import path from "node:path"
import z from "zod"
import { TargetMemory } from "../target"
import { JavaScriptCorrelation, extractJavaScriptSourceMapReferences } from "../target/javascript-correlation"
import { Tool } from "./tool"

const MAX_URLS = 500 // Per invocation; continue remaining URLs in subsequent calls.
const MAX_ASSET_BYTES = 8 * 1024 * 1024
const MAX_BATCH_BYTES = 64 * 1024 * 1024 // Per invocation only; never a lifetime collection cap.
const MAX_REDIRECTS = 5

const Parameters = z.object({
  target_url: z.string().min(1).describe("Existing canonical root target URL whose saved scope governs every fetch."),
  urls: z.array(z.string().trim().min(1).max(8192)).max(MAX_URLS).default([])
    .describe("Optional JavaScript asset URLs from the URL collector, crawler/HTML, source-map references, a URL inventory, or the user. Pass actual URLs, not local file paths. Leave empty to resume the pending URL queue saved in the target manifest."),
  source: z.string().trim().min(1).max(120).default("unspecified")
    .describe("Fallback provenance for this batch, e.g. collector, crawler, user-supplied, HTML, source-map, or urls.txt."),
  url_sources: z.array(z.object({
    url: z.string().trim().min(1).max(8192),
    source: z.string().trim().min(1).max(120),
  })).max(MAX_URLS).default([])
    .describe("Optional per-URL provenance overrides for resuming a mixed-source batch. Entries apply only to URLs also present in urls."),
  force_refresh: z.boolean().default(false)
    .describe("False reuses an already downloaded URL and its content hash. True re-fetches existing URLs to check for changed content."),
})

type AssetRecord = {
  url: string
  finalURL?: string
  source: string
  sources?: string[]
  status: "downloaded" | "reused" | "skipped" | "failed"
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
  pendingURLs?: string[]
  pendingSources?: Array<{ url: string; source: string }>
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

function mergeProvenance(...values: Array<string | undefined>): string {
  const tokens = [...new Set(values.flatMap((value) => (value ?? "").split(" | ").map((item) => item.trim()).filter(Boolean)))]
  const accepted: string[] = []
  for (const token of tokens) {
    if ([...accepted, token].join(" | ").length > 120) continue
    accepted.push(token)
  }
  return accepted.join(" | ") || "unspecified"
}

function extensionFor(url: string, contentType: string): string {
  const pathname = new URL(url).pathname.toLowerCase()
  if (pathname.endsWith(".map") || /source-map\+json|x-source-map/.test(contentType)) return ".map"
  if (pathname.endsWith(".mjs")) return ".mjs"
  if (pathname.endsWith(".cjs")) return ".cjs"
  return ".js"
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

async function isSavedAssetPath(candidatePath: string, assetsDir: string): Promise<boolean> {
  try {
    const lexicalRoot = path.resolve(assetsDir)
    const candidate = path.resolve(candidatePath)
    if (!candidate.startsWith(lexicalRoot + path.sep)) return false
    const assetsRoot = await fs.realpath(assetsDir)
    const realCandidate = await fs.realpath(candidate)
    return realCandidate.startsWith(assetsRoot + path.sep)
  } catch {
    return false
  }
}

async function savedAssetMatchesHash(candidatePath: string, expectedHash: string): Promise<boolean> {
  try {
    const digest = createHash("sha256").update(await fs.readFile(candidatePath)).digest("hex")
    return digest === expectedHash
  } catch {
    return false
  }
}

async function writeManifestAtomically(manifestPath: string, manifest: Manifest): Promise<void> {
  const temporaryPath = manifestPath + "." + randomUUID() + ".tmp"
  try {
    await fs.writeFile(temporaryPath, JSON.stringify(manifest, null, 2) + "\n", {
      encoding: "utf8",
      flag: "wx",
      mode: 0o600,
    })
    await fs.rename(temporaryPath, manifestPath)
  } catch (error) {
    await fs.rm(temporaryPath, { force: true }).catch(() => {})
    throw error
  }
}

async function writeAssetAtomically(localPath: string, bytes: Uint8Array): Promise<void> {
  const temporaryPath = localPath + "." + randomUUID() + ".tmp"
  try {
    await fs.writeFile(temporaryPath, bytes, { flag: "wx", mode: 0o600 })
    await fs.rename(temporaryPath, localPath)
  } catch (error) {
    await fs.rm(temporaryPath, { force: true }).catch(() => {})
    throw error
  }
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

async function fetchScoped(inputURL: string): Promise<{ response: Response; finalURL: string } | { error: string }> {
  let current = inputURL
  for (let redirects = 0; redirects <= MAX_REDIRECTS; redirects++) {
    const scope = await TargetMemory.checkURLScope(current)
    if (!scope.allowed) return { error: "scope denied for " + current + ": " + scope.reason }
    let response: Response
    try {
      response = await fetch(current, {
        method: "GET",
        redirect: "manual",
        signal: AbortSignal.timeout(20_000),
        headers: { Accept: "application/javascript, text/javascript, application/ecmascript, text/ecmascript, application/json;q=0.8, */*;q=0.1" },
      })
    } catch (error) {
      return { error: "fetch failed: " + (error instanceof Error ? error.message : String(error)) }
    }
    if (![301, 302, 303, 307, 308].includes(response.status)) return { response, finalURL: current }
    const location = response.headers.get("location")
    if (!location) return { error: "redirect response has no Location header" }
    if (redirects === MAX_REDIRECTS) return { error: "redirect limit exceeded" }
    let next: string | undefined
    try {
      next = normalizeURL(new URL(location, current).toString())
    } catch {
      return { error: "redirect destination is invalid" }
    }
    if (!next) return { error: "redirect destination is not a credential-free HTTP(S) URL" }
    current = next
  }
  return { error: "redirect limit exceeded" }
}

export const IngestJavaScriptURLsTool = Tool.define<typeof Parameters, Tool.Metadata>("ingest_javascript_urls", {
  description: [
    "Fetch, save, deduplicate, and analyze JavaScript asset URLs supplied by any source.",
    "Input may come from the URL collector, crawlers, extracted HTML, source-map references, urls.txt, another tool, or links manually supplied by the user. Pass URLs in batches of at most 500; leaving urls empty resumes the pending queue saved in the manifest. Use source as fallback provenance and url_sources to retain per-URL origins in mixed batches. If metadata.pending_urls is nonempty, continue with those URLs in batches of at most 500 and pass matching metadata.pending_sources as url_sources until no pending URLs remain. The pending queue is persisted; the 64 MiB byte budget is per invocation, not a total-work cap.",
    "Each URL is checked against the persisted target scope before fetching, and every redirect is checked again. Requests are bounded, GET-only, do not execute downloaded JavaScript, and never send credentials from the current browser/session.",
    "Downloads are stored under the existing target workspace's javascript/assets directory. javascript/asset-manifest.json records URL provenance, final URL, status, SHA-256, local path, content type, size, errors, and a persistent pending queue so interrupted batches can resume on the next invocation. Repeated URLs reuse the existing local artifact by default; identical content from different URLs shares one content-addressed file while preserving each URL/source record. Use force_refresh only when checking whether a previously fetched URL changed.",
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
    try {
      const workspaceRealPath = await fs.realpath(workspace.workspacePath)
      await fs.mkdir(root, { recursive: true })
      const rootInfo = await fs.lstat(root)
      const rootRealPath = await fs.realpath(root)
      if (rootInfo.isSymbolicLink() || !rootInfo.isDirectory() || rootRealPath !== path.join(workspaceRealPath, "javascript")) {
        throw new Error("javascript directory is not a real directory inside the canonical target workspace")
      }
      await fs.mkdir(assetsDir, { recursive: true })
      const assetsInfo = await fs.lstat(assetsDir)
      const assetsRealPath = await fs.realpath(assetsDir)
      if (assetsInfo.isSymbolicLink() || !assetsInfo.isDirectory() || assetsRealPath !== path.join(rootRealPath, "assets")) {
        throw new Error("javascript/assets is not a real directory inside the target JavaScript workspace")
      }
    } catch (error) {
      return {
        title: "JavaScript URL ingestion stopped",
        output: "Refusing to read or write JavaScript artifacts outside the canonical target workspace: " + (error instanceof Error ? error.message : String(error)),
        metadata: { error: "unsafe_asset_directory", workspace: workspace.workspacePath, manifest_path: manifestPath },
      }
    }

    let manifest: Manifest = { schemaVersion: 1, updatedAt: new Date().toISOString(), assets: [] }
    try {
      const manifestInfo = await fs.lstat(manifestPath)
      if (manifestInfo.isSymbolicLink() || !manifestInfo.isFile()) {
        return {
          title: "JavaScript URL ingestion stopped",
          output: "The existing asset manifest is not a regular file inside the target workspace. It was preserved without reading or overwriting: " + manifestPath,
          metadata: { error: "manifest_unsafe_path", manifest_path: manifestPath, workspace: workspace.workspacePath },
        }
      }
      const rawManifest = await fs.readFile(manifestPath, "utf8")
      let parsed: unknown
      try {
        parsed = JSON.parse(rawManifest)
      } catch {
        return {
          title: "JavaScript URL ingestion stopped",
          output: "The existing asset manifest is invalid JSON. It was preserved without overwrite; repair or back it up before retrying: " + manifestPath,
          metadata: { error: "manifest_invalid_json", manifest_path: manifestPath, workspace: workspace.workspacePath },
        }
      }
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
        return {
          title: "JavaScript URL ingestion stopped",
          output: "The existing asset manifest has an invalid top-level value. It was preserved without overwrite: " + manifestPath,
          metadata: { error: "manifest_invalid_schema", manifest_path: manifestPath, workspace: workspace.workspacePath },
        }
      }
      const candidate = parsed as Partial<Manifest>
      const validAssets = Array.isArray(candidate.assets) && candidate.assets.every((item) => {
        if (!item || typeof item !== "object") return false
        const asset = item as Partial<AssetRecord>
        return typeof asset.url === "string" &&
          typeof asset.source === "string" &&
          ["downloaded", "reused", "skipped", "failed"].includes(asset.status as string) &&
          (asset.finalURL === undefined || typeof asset.finalURL === "string") &&
          (asset.contentHash === undefined || typeof asset.contentHash === "string") &&
          (asset.localPath === undefined || typeof asset.localPath === "string") &&
          (asset.contentType === undefined || typeof asset.contentType === "string") &&
          (asset.bytes === undefined || typeof asset.bytes === "number") &&
          (asset.fetchedAt === undefined || typeof asset.fetchedAt === "string") &&
          (asset.error === undefined || typeof asset.error === "string") &&
          (asset.sources === undefined || (Array.isArray(asset.sources) && asset.sources.every((source) => typeof source === "string")))
      })
      const validPendingURLs = candidate.pendingURLs === undefined ||
        (Array.isArray(candidate.pendingURLs) && candidate.pendingURLs.every((url) => typeof url === "string" && Boolean(normalizeURL(url))))
      const validPendingSources = candidate.pendingSources === undefined ||
        (Array.isArray(candidate.pendingSources) && candidate.pendingSources.every((item) =>
          !!item && typeof item === "object" &&
          typeof item.url === "string" && Boolean(normalizeURL(item.url)) &&
          typeof item.source === "string" && item.source.length > 0 && item.source.length <= 120
        ))
      if (candidate.schemaVersion !== 1 || !validAssets || !validPendingURLs || !validPendingSources) {
        return {
          title: "JavaScript URL ingestion stopped",
          output: "The existing asset manifest has an unsupported schema or invalid asset record. It was preserved without overwrite: " + manifestPath,
          metadata: { error: "manifest_invalid_schema", manifest_path: manifestPath, workspace: workspace.workspacePath },
        }
      }
      manifest = candidate as Manifest
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
        return {
          title: "JavaScript URL ingestion stopped",
          output: "The existing asset manifest could not be read and was preserved: " + (error instanceof Error ? error.message : String(error)),
          metadata: { error: "manifest_read_failed", manifest_path: manifestPath, workspace: workspace.workspacePath },
        }
      }
    }

    const byURL = new Map(manifest.assets.map((item) => [normalizeURL(item.url) ?? item.url, item]))
    const byHash = new Map<string, AssetRecord>()
    for (const item of manifest.assets) {
      if (item.contentHash && item.localPath && await isSavedAssetPath(item.localPath, assetsDir)) {
        byHash.set(item.contentHash, item)
      }
    }

    // Resume any deferred URLs from the manifest before adding new caller inputs.
    const inputURLs = [...new Set([...(manifest.pendingURLs ?? []), ...params.urls]
      .map(normalizeURL)
      .filter((value): value is string => Boolean(value)))]
    const queuedURLs = new Set(inputURLs)
    const sourceByURL = new Map<string, string>()
    for (const item of manifest.pendingSources ?? []) {
      const sourceURL = normalizeURL(item.url)
      if (sourceURL && queuedURLs.has(sourceURL)) {
        sourceByURL.set(sourceURL, mergeProvenance(sourceByURL.get(sourceURL), item.source))
      }
    }
    for (const item of params.url_sources) {
      const sourceURL = normalizeURL(item.url)
      if (sourceURL && queuedURLs.has(sourceURL)) {
        sourceByURL.set(sourceURL, mergeProvenance(sourceByURL.get(sourceURL), item.source))
      }
    }
    for (const rawURL of params.urls) {
      const normalized = normalizeURL(rawURL)
      if (normalized && queuedURLs.has(normalized) && !sourceByURL.has(normalized)) {
        sourceByURL.set(normalized, params.source)
      }
    }
    for (const url of inputURLs) {
      if (!sourceByURL.has(url)) sourceByURL.set(url, params.source)
    }
    if (!inputURLs.length) {
      return {
        title: "JavaScript URL ingestion stopped",
        output: "No input URLs were supplied and the target manifest has no pending URLs to resume.",
        metadata: { error: "no_urls_or_pending_queue", manifest_path: manifestPath, workspace: workspace.workspacePath },
      }
    }
    const invalidCount = params.urls.filter((url) => !normalizeURL(url)).length
    const records: AssetRecord[] = []
    let downloadedBytes = 0
    let receivedBytes = 0
    let reused = 0
    let downloaded = 0
    let skipped = 0
    let failed = 0
    let budgetDeferredURL: string | undefined

    // Persist both the completed asset records and remaining work after each URL.
    // A stopped process resumes from the first unfinished URL without re-fetching
    // successful assets or losing source-map discoveries.
    const persistProgress = async (pendingURLs: string[]) => {
      manifest = {
        ...manifest,
        updatedAt: new Date().toISOString(),
        assets: [...byURL.values()].sort((a, b) => a.url.localeCompare(b.url)),
        pendingURLs,
        pendingSources: pendingURLs.map((pendingURL) => ({
          url: pendingURL,
          source: sourceByURL.get(pendingURL) ?? params.source,
        })),
      }
      await writeManifestAtomically(manifestPath, manifest)
    }
    await persistProgress(inputURLs)

    for (let urlIndex = 0; urlIndex < inputURLs.length; urlIndex++) {
      const url = inputURLs[urlIndex]!
      const assetSource = sourceByURL.get(url) ?? params.source
      const prior = byURL.get(url)
      if (
        !params.force_refresh &&
        prior?.contentHash &&
        prior.localPath &&
        await isSavedAssetPath(prior.localPath, assetsDir) &&
        await savedAssetMatchesHash(prior.localPath, prior.contentHash)
      ) {
        const currentScope = await TargetMemory.checkURLScope(url)
        const finalScope = prior.finalURL ? await TargetMemory.checkURLScope(prior.finalURL) : currentScope
        if (!currentScope.allowed || !finalScope.allowed) {
          const reason = !currentScope.allowed
            ? "cached asset is no longer in persisted scope: " + currentScope.reason
            : "cached redirect destination is no longer in persisted scope: " + finalScope.reason
          const record: AssetRecord = { ...prior, source: assetSource, status: "skipped", error: reason }
          records.push(record)
          byURL.set(url, record)
          skipped++
          await persistProgress(inputURLs.slice(urlIndex + 1))
          continue
        }
        const sources = [...new Set([...(prior.sources ?? prior.source.split(" | ")), ...assetSource.split(" | ")])].filter(Boolean).sort()
        const record: AssetRecord = { ...prior, source: mergeProvenance(...sources), sources, status: "reused", error: undefined }
        records.push(record)
        byURL.set(url, record)
        reused++
        await persistProgress(inputURLs.slice(urlIndex + 1))
        continue
      }
      const result = await fetchScoped(url)
      if ("error" in result) {
        const record: AssetRecord = { url, source: assetSource, status: "failed", error: result.error, fetchedAt: new Date().toISOString() }
        records.push(record); byURL.set(url, record); failed++
        await persistProgress(inputURLs.slice(urlIndex + 1))
        continue
      }
      const { response, finalURL } = result
      if (!response.ok) {
        const record: AssetRecord = { url, finalURL, source: assetSource, status: "failed", error: "HTTP " + response.status, fetchedAt: new Date().toISOString() }
        records.push(record); byURL.set(url, record); failed++
        await persistProgress(inputURLs.slice(urlIndex + 1))
        continue
      }
      const contentType = (response.headers.get("content-type") ?? "").split(";")[0]!.trim().toLowerCase()
      const declaredLength = Number(response.headers.get("content-length") ?? "0")
      if (Number.isFinite(declaredLength) && declaredLength > MAX_ASSET_BYTES) {
        const record: AssetRecord = { url, finalURL, source: assetSource, status: "skipped", contentType, error: "declared response size exceeds the asset limit", fetchedAt: new Date().toISOString() }
        records.push(record); byURL.set(url, record); skipped++
        await persistProgress(inputURLs.slice(urlIndex + 1))
        continue
      }
      let bytes: Uint8Array
      try { bytes = await readBounded(response, MAX_ASSET_BYTES) }
      catch (error) {
        const record: AssetRecord = { url, finalURL, source: assetSource, status: "failed", contentType, error: error instanceof Error ? error.message : String(error), fetchedAt: new Date().toISOString() }
        records.push(record); byURL.set(url, record); failed++
        await persistProgress(inputURLs.slice(urlIndex + 1))
        continue
      }
      receivedBytes += bytes.byteLength
      if (receivedBytes > MAX_BATCH_BYTES) {
        const record: AssetRecord = { url, finalURL, source: assetSource, status: "skipped", contentType, bytes: bytes.byteLength, error: "per-invocation byte budget reached; retry this URL in a subsequent batch", fetchedAt: new Date().toISOString() }
        records.push(record); byURL.set(url, record); skipped++
        budgetDeferredURL = url
        await persistProgress(inputURLs.slice(urlIndex))
        break
      }
      const body = new TextDecoder("utf-8", { fatal: false }).decode(bytes)
      if (!looksLikeJavaScript(body, contentType, finalURL)) {
        const record: AssetRecord = { url, finalURL, source: assetSource, status: "skipped", contentType, bytes: bytes.byteLength, error: "response does not look like JavaScript or a version-3 source map", fetchedAt: new Date().toISOString() }
        records.push(record); byURL.set(url, record); skipped++
        await persistProgress(inputURLs.slice(urlIndex + 1))
        continue
      }
      // Feed external source-map links discovered inside each bundle into this same queue.
      // Every map goes through the same persisted-scope and redirect checks as any other URL.
      const queueLengthBeforeMaps = inputURLs.length
      for (const mapURL of extractJavaScriptSourceMapReferences(body, finalURL)) {
        const normalizedMapURL = normalizeURL(mapURL)
        if (!normalizedMapURL || queuedURLs.has(normalizedMapURL)) continue
        queuedURLs.add(normalizedMapURL)
        inputURLs.push(normalizedMapURL)
        sourceByURL.set(normalizedMapURL, ("sourceMappingURL from " + url).slice(0, 120))
      }
      // Persist newly discovered maps immediately after parsing each bundle. If the
      // process stops before the end-of-batch save, these URLs still remain resumable.
      if (inputURLs.length > queueLengthBeforeMaps) {
        await persistProgress(inputURLs.slice(urlIndex))
      }
      const contentHash = createHash("sha256").update(bytes).digest("hex")
      const existingContent = byHash.get(contentHash)
      let localPath: string
      let reusedExistingContent = false
      if (
        existingContent?.localPath &&
        await isSavedAssetPath(existingContent.localPath, assetsDir) &&
        await savedAssetMatchesHash(existingContent.localPath, contentHash)
      ) {
        localPath = existingContent.localPath
        reusedExistingContent = true
      } else {
        const extension = extensionFor(finalURL, contentType)
        localPath = path.join(assetsDir, contentHash + extension)
        // A content-addressed file is always written completely before it becomes
        // visible under its final name; orphaned partial files are never reused.
        await writeAssetAtomically(localPath, bytes)
        byHash.set(contentHash, { url, finalURL, source: assetSource, status: "downloaded", contentHash, localPath, contentType, bytes: bytes.byteLength, fetchedAt: new Date().toISOString() })
      }
      const priorSources = byURL.get(url)?.sources ?? (byURL.get(url)?.source ? [byURL.get(url)!.source] : [])
      const sources = [...new Set([...priorSources.flatMap((value) => value.split(" | ")), ...assetSource.split(" | ")])].filter(Boolean).sort()
      const record: AssetRecord = { url, finalURL, source: mergeProvenance(...sources), sources, status: reusedExistingContent ? "reused" : "downloaded", contentHash, localPath, contentType, bytes: bytes.byteLength, fetchedAt: new Date().toISOString() }
      records.push(record)
      byURL.set(url, record)
      if (reusedExistingContent) reused++
      else { downloaded++; downloadedBytes += bytes.byteLength }
      await persistProgress(inputURLs.slice(urlIndex + 1))
    }

    const pendingURLs = budgetDeferredURL ? inputURLs.slice(inputURLs.indexOf(budgetDeferredURL)) : []
    const pendingSources = pendingURLs.map((url) => ({ url, source: sourceByURL.get(url) ?? params.source }))
    manifest = {
      schemaVersion: 1,
      updatedAt: new Date().toISOString(),
      assets: [...byURL.values()].sort((a, b) => a.url.localeCompare(b.url)),
      pendingURLs,
      pendingSources,
    }
    await writeManifestAtomically(manifestPath, manifest)
    let analysisSummary = "Analysis not run."
    let analysisError: string | undefined
    if (downloaded + reused > 0) {
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
      title: pendingURLs.length
        ? "JavaScript URL ingestion paused — continue pending URLs"
        : analysisError
          ? "JavaScript assets fetched; correlation failed"
          : "JavaScript URL ingestion complete",
      output: [
        "Workspace: " + workspace.workspacePath,
        "Input URLs: " + params.urls.length,
        "Valid unique URLs queued (including discovered source maps): " + inputURLs.length,
        "Pending URLs for subsequent batches: " + pendingURLs.length,
        "Invalid URLs rejected: " + invalidCount,
        "Downloaded new content versions: " + downloaded,
        "Reused URL/content records: " + reused,
        "Skipped responses: " + skipped,
        "Failed URLs: " + failed,
        "Newly downloaded bytes: " + downloadedBytes,
        "Total response bytes received: " + receivedBytes,
        "Manifest: " + manifestPath,
        analysisSummary,
        ...(pendingURLs.length ? [
          "Continue by passing metadata.pending_urls to ingest_javascript_urls in batches of at most " + MAX_URLS + " URLs, plus matching metadata.pending_sources as url_sources to preserve provenance. The byte budget applies per invocation, not to the total run.",
        ] : []),
        ...records.filter((record) => record.status === "failed" || record.status === "skipped").map((record) => record.url + " — " + record.status + ": " + record.error),
      ].join("\n"),
      metadata: {
        manifest_path: manifestPath,
        workspace: workspace.workspacePath,
        input_urls: params.urls.length,
        valid_unique_urls: inputURLs.length,
        invalid_urls: invalidCount,
        downloaded,
        reused,
        skipped,
        failed,
        downloaded_bytes: downloadedBytes,
        received_bytes: receivedBytes,
        analysis_error: analysisError,
        pending_urls: pendingURLs,
        pending_sources: pendingSources,
        byte_budget_reached: pendingURLs.length > 0,
      },
    }
  },
})
