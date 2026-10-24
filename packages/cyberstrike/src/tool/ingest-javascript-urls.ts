import { createHash } from "node:crypto"
import fs from "node:fs/promises"
import path from "node:path"
import z from "zod"
import { TargetMemory } from "../target"
import { JavaScriptCorrelation, extractJavaScriptSourceMapReferences } from "../target/javascript-correlation"
import { Tool } from "./tool"

const MAX_URLS = 500
const MAX_ASSET_BYTES = 8 * 1024 * 1024
const MAX_TOTAL_BYTES = 64 * 1024 * 1024
const MAX_REDIRECTS = 5

const Parameters = z.object({
  target_url: z.string().min(1).describe("Existing canonical root target URL whose saved scope governs every fetch."),
  urls: z.array(z.string().trim().min(1).max(8192)).min(1).max(MAX_URLS)
    .describe("JavaScript asset URLs from ANY source: the URL collector, crawler/HTML, source-map references, a URL inventory, or URLs manually supplied by the user. Pass the actual URLs, not local file paths."),
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
    const next = normalizeURL(new URL(location, current).toString())
    if (!next) return { error: "redirect destination is not a credential-free HTTP(S) URL" }
    current = next
  }
  return { error: "redirect limit exceeded" }
}

export const IngestJavaScriptURLsTool = Tool.define<typeof Parameters, Tool.Metadata>("ingest_javascript_urls", {
  description: [
    "Fetch, save, deduplicate, and analyze JavaScript asset URLs supplied by any source.",
    "Input may come from the URL collector, crawlers, extracted HTML, source-map references, urls.txt, another tool, or links manually supplied by the user. Always pass all available URLs in the urls array and identify their provenance in source.",
    "Each URL is checked against the persisted target scope before fetching, and every redirect is checked again. Requests are bounded, GET-only, do not execute downloaded JavaScript, and never send credentials from the current browser/session.",
    "Downloads are stored under the existing target workspace's javascript/assets directory. javascript/asset-manifest.json records URL provenance, final URL, status, SHA-256, local path, content type, size, and errors. Repeated URLs reuse the existing local artifact by default; identical content from different URLs shares one content-addressed file while preserving each URL/source record. Use force_refresh only when checking whether a previously fetched URL changed.",
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

    const inputURLs = [...new Set(params.urls.map(normalizeURL).filter((value): value is string => Boolean(value)))]
    const queuedURLs = new Set(inputURLs)
    const sourceByURL = new Map<string, string>(inputURLs.map((url) => [url, params.source] as const))
    const invalidCount = params.urls.filter((url) => !normalizeURL(url)).length
    const records: AssetRecord[] = []
    let downloadedBytes = 0
    let receivedBytes = 0
    let reused = 0
    let downloaded = 0
    let skipped = 0
    let failed = 0

    for (const url of inputURLs) {
      const assetSource = sourceByURL.get(url) ?? params.source
      const prior = byURL.get(url)
      if (!params.force_refresh && prior?.contentHash && prior.localPath && await Bun.file(prior.localPath).exists()) {
        const sources = [...new Set([...(prior.sources ?? prior.source.split(" | ")), assetSource])].filter(Boolean).sort()
        const record: AssetRecord = { ...prior, source: sources.join(" | "), sources, status: "reused" }
        records.push(record)
        byURL.set(url, record)
        reused++
        continue
      }
      const result = await fetchScoped(url)
      if ("error" in result) {
        const record: AssetRecord = { url, source: assetSource, status: "failed", error: result.error, fetchedAt: new Date().toISOString() }
        records.push(record); byURL.set(url, record); failed++
        continue
      }
      const { response, finalURL } = result
      if (!response.ok) {
        const record: AssetRecord = { url, finalURL, source: assetSource, status: "failed", error: "HTTP " + response.status, fetchedAt: new Date().toISOString() }
        records.push(record); byURL.set(url, record); failed++
        continue
      }
      const contentType = (response.headers.get("content-type") ?? "").split(";")[0]!.trim().toLowerCase()
      const declaredLength = Number(response.headers.get("content-length") ?? "0")
      if (Number.isFinite(declaredLength) && declaredLength > MAX_ASSET_BYTES) {
        const record: AssetRecord = { url, finalURL, source: assetSource, status: "skipped", contentType, error: "declared response size exceeds the asset limit", fetchedAt: new Date().toISOString() }
        records.push(record); byURL.set(url, record); skipped++
        continue
      }
      let bytes: Uint8Array
      try { bytes = await readBounded(response, MAX_ASSET_BYTES) }
      catch (error) {
        const record: AssetRecord = { url, finalURL, source: assetSource, status: "failed", contentType, error: error instanceof Error ? error.message : String(error), fetchedAt: new Date().toISOString() }
        records.push(record); byURL.set(url, record); failed++
        continue
      }
      receivedBytes += bytes.byteLength
      if (receivedBytes > MAX_TOTAL_BYTES) {
        const record: AssetRecord = { url, finalURL, source: assetSource, status: "skipped", contentType, bytes: bytes.byteLength, error: "batch download budget exceeded", fetchedAt: new Date().toISOString() }
        records.push(record); byURL.set(url, record); skipped++
        continue
      }
      const body = new TextDecoder("utf-8", { fatal: false }).decode(bytes)
      if (!looksLikeJavaScript(body, contentType, finalURL)) {
        const record: AssetRecord = { url, finalURL, source: assetSource, status: "skipped", contentType, bytes: bytes.byteLength, error: "response does not look like JavaScript or a version-3 source map", fetchedAt: new Date().toISOString() }
        records.push(record); byURL.set(url, record); skipped++
        continue
      }
      // Feed external source-map links discovered inside each bundle into this same queue.
      // Every map goes through the same persisted-scope and redirect checks as any other URL.
      for (const mapURL of extractJavaScriptSourceMapReferences(body, finalURL)) {
        const normalizedMapURL = normalizeURL(mapURL)
        if (!normalizedMapURL || queuedURLs.has(normalizedMapURL) || queuedURLs.size >= MAX_URLS) continue
        queuedURLs.add(normalizedMapURL)
        inputURLs.push(normalizedMapURL)
        sourceByURL.set(normalizedMapURL, "sourceMappingURL from " + url)
      }
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
      const priorSources = byURL.get(url)?.sources ?? (byURL.get(url)?.source ? [byURL.get(url)!.source] : [])
      const sources = [...new Set([...priorSources.flatMap((value) => value.split(" | ")), params.source])].filter(Boolean).sort()
      const record: AssetRecord = { url, finalURL, source: sources.join(" | "), sources, status: existingContent ? "reused" : "downloaded", contentHash, localPath, contentType, bytes: bytes.byteLength, fetchedAt: new Date().toISOString() }
      records.push(record)
      byURL.set(url, record)
      if (existingContent) reused++
      else { downloaded++; downloadedBytes += bytes.byteLength }
    }

    manifest = {
      schemaVersion: 1,
      updatedAt: new Date().toISOString(),
      assets: [...byURL.values()].sort((a, b) => a.url.localeCompare(b.url)),
    }
    const temporaryManifest = manifestPath + ".tmp"
    await fs.writeFile(temporaryManifest, JSON.stringify(manifest, null, 2) + "\n", "utf8")
    await fs.rename(temporaryManifest, manifestPath)

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
      title: "JavaScript URL ingestion complete",
      output: [
        "Workspace: " + workspace.workspacePath,
        "Input URLs: " + params.urls.length,
        "Valid unique URLs: " + inputURLs.length,
        "Invalid URLs rejected: " + invalidCount,
        "Downloaded new content versions: " + downloaded,
        "Reused URL/content records: " + reused,
        "Skipped responses: " + skipped,
        "Failed URLs: " + failed,
        "Newly downloaded bytes: " + downloadedBytes,
        "Total response bytes received: " + receivedBytes,
        "Manifest: " + manifestPath,
        analysisSummary,
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
      },
    }
  },
})
