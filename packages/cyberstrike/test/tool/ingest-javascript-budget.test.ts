import { expect, test } from "bun:test"
import { createHash } from "node:crypto"
import fs from "node:fs/promises"
import path from "node:path"
import { gzipSync } from "node:zlib"
import { Instance } from "../../src/project/instance"
import { Session } from "../../src/session"
import { Request } from "../../src/session/request"
import { TargetMemory } from "../../src/target"
import { IngestJavaScriptURLsTool } from "../../src/tool/ingest-javascript-urls"
import { tmpdir } from "../fixture/fixture"

const MiB = 1024 * 1024
const ASSET_SIZE = 22 * MiB
const FORMER_AGGREGATE_LIMIT = 64 * MiB

function fixedSizeBody(size: number) {
  let remaining = size
  return new ReadableStream<Uint8Array>({
    pull(controller) {
      if (remaining <= 0) {
        controller.close()
        return
      }
      const count = Math.min(64 * 1024, remaining)
      controller.enqueue(new Uint8Array(count).fill(0x78))
      remaining -= count
    },
  })
}

function toolContext(sessionID: string) {
  return {
    sessionID,
    messageID: "msg_ingest_javascript_budget_test",
    agent: "test",
    abort: new AbortController().signal,
    messages: [],
    metadata: () => undefined,
    ask: async () => {},
  } as never
}

test("processes the complete JavaScript worklist beyond the former 64 MiB aggregate budget", async () => {
  await using tmp = await tmpdir()
  const requested: string[] = []
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    fetch(request) {
      const pathname = new URL(request.url).pathname
      requested.push(pathname)
      if (["/assets/one.js", "/assets/two.js", "/assets/three.js"].includes(pathname)) {
        return new Response(fixedSizeBody(ASSET_SIZE), {
          status: 200,
          headers: { "content-type": "application/javascript" },
        })
      }
      return new Response("not found", { status: 404, headers: { "content-type": "text/plain" } })
    },
  })

  try {
    await Instance.provide({
      directory: tmp.path,
      async fn() {
        const target = "http://127.0.0.1:" + server.port
        const configured = await TargetMemory.configureScope(target, {
          include: [target],
          authorizationSource: "Local JavaScript ingestion budget test fixture",
          authorizationReference: "https://example.test/security-policy",
        })
        const canonicalTarget = configured.workspace.targetURL
        const session = await Session.create({})
        Request.add({
          sessionID: session.id,
          method: "GET",
          normalizedPath: "/",
          keyHash: "ingest-javascript-budget-session-root",
          origin: canonicalTarget,
          scheme: "http",
          host: "127.0.0.1",
          pageUrl: canonicalTarget + "/",
          response: {
            status: 200,
            headers: { "content-type": "text/html" },
            body: "<html><body>local test fixture</body></html>",
          },
        })

        const workspace = configured.workspace
        const manifestPath = path.join(workspace.workspacePath, "javascript", "asset-manifest.json")
        const urls = ["/assets/one.js", "/assets/two.js", "/assets/three.js"].map((route) => canonicalTarget + route)
        const tool = await IngestJavaScriptURLsTool.init()
        const result = await tool.execute({
          target_url: canonicalTarget,
          urls,
          source: "unit-test",
          force_refresh: false,
        }, toolContext(session.id))

        expect(ASSET_SIZE * 3).toBeGreaterThan(FORMER_AGGREGATE_LIMIT)
        expect(requested).toEqual(["/assets/one.js", "/assets/two.js", "/assets/three.js"])
        const metadata = result.metadata as Record<string, unknown>
        expect(metadata.received_bytes).toBe(ASSET_SIZE * 3)
        expect(metadata.queued_urls).toBe(3)
        expect(metadata.worklist_settled).toBe(3)
        expect(metadata.worklist_available).toBe(3)
        expect(metadata.worklist_pending).toBe(0)
        expect(metadata.worklist_retryable_failures).toBe(0)
        expect(metadata.worklist_missing_manifest_records).toBe(0)
        expect(metadata.manifest_reconciled).toBe(true)
        expect(metadata.collection_complete).toBe(true)

        const manifest = JSON.parse(await fs.readFile(manifestPath, "utf8")) as {
          assets: Array<{ url: string; status: string; error?: string }>
        }
        const statusFor = (url: string) => manifest.assets.find((item) => item.url === url)
        expect(statusFor(urls[0])?.status).toBe("downloaded")
        expect(statusFor(urls[1])?.status).toBe("reused")
        expect(statusFor(urls[2])?.status).toBe("reused")
      },
    })
  } finally {
    server.stop(true)
  }
}, 60_000)


test("automatically retries one transient JavaScript HTTP failure in the same invocation", async () => {
  await using tmp = await tmpdir()
  let attempts = 0
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    fetch() {
      attempts++
      if (attempts === 1) return new Response("temporarily unavailable", { status: 503 })
      return new Response('function loadProfile() { return fetch("/api/profile") }', {
        status: 200,
        headers: { "content-type": "application/javascript" },
      })
    },
  })

  try {
    await Instance.provide({
      directory: tmp.path,
      async fn() {
        const target = "http://127.0.0.1:" + server.port
        const configured = await TargetMemory.configureScope(target, {
          include: [target],
          authorizationSource: "Local transient JavaScript retry fixture",
          authorizationReference: "https://example.test/security-policy",
        })
        const session = await Session.create({})
        Request.add({
          sessionID: session.id,
          method: "GET",
          normalizedPath: "/",
          keyHash: "ingest-javascript-transient-retry-root",
          origin: configured.workspace.targetURL,
          scheme: "http",
          host: "127.0.0.1",
          pageUrl: configured.workspace.targetURL + "/",
          response: {
            status: 200,
            headers: { "content-type": "text/html" },
            body: "<html><body>local retry fixture</body></html>",
          },
        })

        const tool = await IngestJavaScriptURLsTool.init()
        const url = configured.workspace.targetURL + "/flaky.js"
        const result = await tool.execute({
          target_url: configured.workspace.targetURL,
          urls: [url],
          source: "unit-test-transient-retry",
          force_refresh: false,
        }, toolContext(session.id))

        expect(attempts).toBe(2)
        const metadata = result.metadata as Record<string, unknown>
        expect(metadata.downloaded).toBe(1)
        expect(metadata.worklist_settled).toBe(1)
        expect(metadata.worklist_available).toBe(1)
        expect(metadata.worklist_pending).toBe(0)
        expect(metadata.worklist_retryable_failures).toBe(0)
        expect(metadata.collection_complete).toBe(true)
        const manifestPath = path.join(configured.workspace.workspacePath, "javascript", "asset-manifest.json")
        const manifest = JSON.parse(await fs.readFile(manifestPath, "utf8")) as {
          assets: Array<{ url: string; status: string; retryable?: boolean }>
        }
        expect(manifest.assets.find((asset) => asset.url === url)?.status).toBe("downloaded")
        expect(manifest.assets.find((asset) => asset.url === url)?.retryable).toBeUndefined()
        await Session.remove(session.id)
      },
    })
  } finally {
    server.stop(true)
  }
}, 30_000)


test("retains every source-map provenance label from every bundle without truncation", async () => {
  await using tmp = await tmpdir()
  const requests: string[] = []
  const javascript = 'const route = "/api/profile";\nfetch(route);\n//# sourceMappingURL=/shared.js.map\n'
  const sourceMap = JSON.stringify({ version: 3, sources: ["src/profile.ts"], names: [], mappings: "AAAA" })
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    fetch(request) {
      const pathname = new URL(request.url).pathname
      requests.push(pathname)
      if (pathname === "/shared.js.map") {
        return new Response(sourceMap, { status: 200, headers: { "content-type": "application/json" } })
      }
      if (["/app-one.js", "/app-two.js", "/app-three.js", "/app-four.js"].includes(pathname)) {
        return new Response(javascript, { status: 200, headers: { "content-type": "application/javascript" } })
      }
      return new Response("not found", { status: 404 })
    },
  })

  try {
    await Instance.provide({
      directory: tmp.path,
      async fn() {
        const target = "http://127.0.0.1:" + server.port
        const configured = await TargetMemory.configureScope(target, {
          include: [target],
          authorizationSource: "Local shared source-map provenance fixture",
          authorizationReference: "https://example.test/security-policy",
        })
        const canonicalTarget = configured.workspace.targetURL
        const session = await Session.create({})
        Request.add({
          sessionID: session.id,
          method: "GET",
          normalizedPath: "/",
          keyHash: "ingest-javascript-shared-map-root",
          origin: canonicalTarget,
          scheme: "http",
          host: "127.0.0.1",
          pageUrl: canonicalTarget + "/",
          response: {
            status: 200,
            headers: { "content-type": "text/html" },
            body: '<script src="/app-one.js"></script><script src="/app-two.js"></script><script src="/app-three.js"></script><script src="/app-four.js"></script>',
          },
        })

        const tool = await IngestJavaScriptURLsTool.init()
        const result = await tool.execute({
          target_url: canonicalTarget,
          urls: ["/app-one.js", "/app-two.js", "/app-three.js", "/app-four.js"].map((route) => canonicalTarget + route),
          source: "collector",
          force_refresh: false,
        }, toolContext(session.id))

        expect(requests.filter((pathname) => pathname === "/shared.js.map")).toHaveLength(1)
        expect((result.metadata as Record<string, unknown>).pending_assets).toBe(0)
        const manifestPath = path.join(configured.workspace.workspacePath, "javascript", "asset-manifest.json")
        const savedManifest = JSON.parse(await fs.readFile(manifestPath, "utf8")) as {
          assets: Array<{ url: string; source: string; sources?: string[] }>
        }
        const mapRecord = savedManifest.assets.find((asset) => asset.url === canonicalTarget + "/shared.js.map")
        expect(mapRecord).toBeDefined()
        for (const name of ["app-one.js", "app-two.js", "app-three.js", "app-four.js"]) {
          expect(mapRecord?.sources).toContain("sourceMappingURL from " + canonicalTarget + "/" + name)
        }
        expect(mapRecord?.sources).toHaveLength(4)
        expect(mapRecord?.source.split(" | ").sort()).toEqual([...mapRecord!.sources!].sort())
        expect(mapRecord?.source.length).toBeGreaterThan(120)
      },
    })
  } finally {
    server.stop(true)
  }
}, 30_000)


test("does not overwrite a malformed JavaScript asset manifest", async () => {
  await using tmp = await tmpdir()
  let networkRequests = 0
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    fetch() {
      networkRequests++
      return new Response("unexpected request", { status: 200 })
    },
  })

  try {
    await Instance.provide({
      directory: tmp.path,
      async fn() {
        const target = "http://127.0.0.1:" + server.port
        const configured = await TargetMemory.configureScope(target, {
          include: [target],
          authorizationSource: "Local invalid-manifest test fixture",
          authorizationReference: "https://example.test/security-policy",
        })
        const javascriptRoot = path.join(configured.workspace.workspacePath, "javascript")
        await fs.mkdir(path.join(javascriptRoot, "assets"), { recursive: true })
        const manifestPath = path.join(javascriptRoot, "asset-manifest.json")
        const original = '{"schemaVersion":1, this is intentionally invalid'
        await fs.writeFile(manifestPath, original)

        const tool = await IngestJavaScriptURLsTool.init()
        const result = await tool.execute({
          target_url: configured.workspace.targetURL,
          urls: [configured.workspace.targetURL + "/assets/app.js"],
          source: "test",
          force_refresh: false,
        }, toolContext("ses_invalid_javascript_manifest"))

        expect((result.metadata as Record<string, unknown>).error).toBe("manifest_invalid")
        expect(networkRequests).toBe(0)
        expect(await fs.readFile(manifestPath, "utf8")).toBe(original)
      },
    })
  } finally {
    server.stop(true)
  }
}, 10_000)

test("processes 10,000 distinct JavaScript URLs without a fixed worklist cap", async () => {
  await using tmp = await tmpdir()
  const requested: string[] = []
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    fetch(request) {
      const pathname = new URL(request.url).pathname
      requested.push(pathname)
      if (/^\/assets\/bundle-\d+\.js$/.test(pathname)) {
        const assetIndex = Number(pathname.match(/bundle-(\d+)\.js$/)?.[1] ?? 0)
        const contentIndex = assetIndex % 1_000
        // Every 10 URLs share one source body, producing 1,000 distinct
        // JavaScript contents across 10,000 distinct asset URLs.
        const body =
          'function loadBundle' + contentIndex + '() { return fetch("/api/v' + (contentIndex % 10) + '/profile"); }\n' +
          'const featureFlag = "feature_' + contentIndex + '";'
        const contentType = assetIndex === 9_999 ? "text/plain" : "application/javascript"
        return new Response(body, { status: 200, headers: { "content-type": contentType } })
      }
      return new Response("not found", { status: 404 })
    },
  })

  try {
    await Instance.provide({
      directory: tmp.path,
      async fn() {
        const target = "http://127.0.0.1:" + server.port
        const configured = await TargetMemory.configureScope(target, {
          include: [target],
          authorizationSource: "Local JavaScript worklist-size test fixture",
          authorizationReference: "https://example.test/security-policy",
        })
        const canonicalTarget = configured.workspace.targetURL
        const session = await Session.create({})
        Request.add({
          sessionID: session.id,
          method: "GET",
          normalizedPath: "/",
          keyHash: "ingest-javascript-worklist-size-root",
          origin: canonicalTarget,
          scheme: "http",
          host: "127.0.0.1",
          pageUrl: canonicalTarget + "/",
          response: {
            status: 200,
            headers: { "content-type": "text/html" },
            body: "<html><body>local test fixture</body></html>",
          },
        })

        const urls = Array.from({ length: 10_000 }, (_, index) =>
          canonicalTarget + "/assets/bundle-" + index + ".js",
        )
        const tool = await IngestJavaScriptURLsTool.init()
        const result = await tool.execute({
          target_url: canonicalTarget,
          urls,
          source: "unit-test-worklist-size",
          force_refresh: false,
        }, toolContext(session.id))

        const metadata = result.metadata as Record<string, unknown>
        expect(requested).toHaveLength(urls.length)
        expect(new Set(requested).size).toBe(urls.length)
        expect(metadata.queued_urls).toBe(urls.length)
        expect(metadata.worklist_settled).toBe(urls.length)
        expect(metadata.worklist_available).toBe(urls.length)
        expect(metadata.worklist_pending).toBe(0)
        expect(metadata.worklist_retryable_failures).toBe(0)
        expect(metadata.worklist_missing_manifest_records).toBe(0)
        expect(metadata.manifest_reconciled).toBe(true)
        expect(metadata.collection_complete).toBe(true)
        expect(metadata.analysis_complete).toBe(true)

        const manifestPath = path.join(configured.workspace.workspacePath, "javascript", "asset-manifest.json")
        const manifest = JSON.parse(await fs.readFile(manifestPath, "utf8")) as {
          assets: Array<{ url: string; status: string; contentHash?: string; assetKind?: string }>
        }
        expect(manifest.assets).toHaveLength(urls.length)
        expect(manifest.assets.every((asset) => asset.status === "downloaded" || asset.status === "reused")).toBe(true)

        // URL coverage and source-content coverage are deliberately measured
        // separately: 10,000 URLs must resolve to exactly 1,000 unique bodies.
        const uniqueContentHashes = new Set(manifest.assets.map((asset) => asset.contentHash).filter(Boolean))
        expect(uniqueContentHashes.size).toBe(1_000)
        expect(metadata.downloaded).toBe(1_000)
        expect(metadata.reused).toBe(9_000)
        expect(metadata.analyzed_source_records).toBe(1_000)
        expect(metadata.analysis_complete).toBe(true)

        // The final asset is valid JavaScript despite its misleading MIME type;
        // it shares the expected content hash with bundle-999.js.
        const mislabeledAsset = manifest.assets.find((asset) => asset.url === urls[9_999])
        expect(mislabeledAsset?.assetKind).toBe("javascript")
        expect(mislabeledAsset?.contentHash).toBe(
          manifest.assets.find((asset) => asset.url === urls[999])?.contentHash,
        )

        const graphDigest = createHash("sha256")
          .update(JSON.stringify([canonicalTarget, "all-assets"]))
          .digest("hex")
          .slice(0, 12)
        const graphPath = path.join(
          configured.workspace.workspacePath,
          "javascript",
          "127.0.0.1-" + graphDigest + ".json",
        )
        const graph = JSON.parse(await fs.readFile(graphPath, "utf8")) as {
          sourceFiles: unknown[]
          endpointCandidates: unknown[]
          javascriptAnalysis: {
            functions: Array<{ name: string; sourceFile: string }>
            requestCandidates: Array<{ sourceFunction: string | null; sourceFile: string }>
          }
          edges: Array<{ relation: string }>
        }
        expect(graph.sourceFiles).toHaveLength(1_000)
        expect(graph.javascriptAnalysis.functions).toHaveLength(1_000)
        expect(graph.javascriptAnalysis.requestCandidates).toHaveLength(1_000)
        expect(graph.endpointCandidates).toHaveLength(10)
        expect(graph.edges.filter((edge) => edge.relation === "function-contains-request-candidate")).toHaveLength(1_000)
        expect(graph.edges.filter((edge) => edge.relation === "request-candidate-maps-to-endpoint")).toHaveLength(1_000)
        await Session.remove(session.id)
      },
    })
  } finally {
    server.stop(true)
  }
}, 240_000)



test("reruns JavaScript correlation from saved local assets when the URL queue is empty", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    async fn() {
      const target = "https://resume-js.example.test"
      const configured = await TargetMemory.configureScope(target, {
        include: ["resume-js.example.test"],
        authorizationSource: "Local JavaScript resume regression fixture",
        authorizationReference: "https://example.test/security-policy",
      })
      const canonicalTarget = configured.workspace.targetURL
      const session = await Session.create({})
      Request.add({
        sessionID: session.id,
        method: "GET",
        normalizedPath: "/",
        keyHash: "ingest-javascript-resume-root",
        origin: canonicalTarget,
        scheme: "https",
        host: "resume-js.example.test",
        pageUrl: canonicalTarget + "/",
        response: {
          status: 200,
          headers: { "content-type": "text/html" },
          body: '<html><script src="/assets/cached.js"></script></html>',
        },
      })

      const javascriptRoot = path.join(configured.workspace.workspacePath, "javascript")
      const assetsDir = path.join(javascriptRoot, "assets")
      await fs.mkdir(assetsDir, { recursive: true })
      const url = canonicalTarget + "/assets/cached.js"
      const body = 'export async function loadProfile(profileId) { return fetch("/api/profiles/" + profileId) }'
      const contentHash = createHash("sha256").update(body).digest("hex")
      const localPath = path.join(assetsDir, contentHash + ".js")
      await fs.writeFile(localPath, body, "utf8")
      const manifestPath = path.join(javascriptRoot, "asset-manifest.json")
      await fs.writeFile(manifestPath, JSON.stringify({
        schemaVersion: 1,
        updatedAt: new Date().toISOString(),
        assets: [{
          url,
          finalURL: url,
          source: "unit-test",
          sources: ["unit-test"],
          status: "downloaded",
          contentHash,
          localPath,
          contentType: "application/javascript",
          bytes: Buffer.byteLength(body),
          fetchedAt: new Date().toISOString(),
        }],
      }, null, 2) + "\n", "utf8")

      const tool = await IngestJavaScriptURLsTool.init()
      const result = await tool.execute({
        target_url: canonicalTarget,
        urls: [],
        source: "unit-test-resume",
        force_refresh: false,
      }, toolContext(session.id))

      const metadata = result.metadata as Record<string, unknown>
      expect(metadata.queued_urls).toBe(0)
      expect(metadata.collection_complete).toBe(true)
      expect(metadata.correlation_saved).toBe(true)
      expect(metadata.analyzed_source_records).toBeGreaterThan(0)
      expect(metadata.analysis_complete).toBe(true)
      expect(result.output).toContain("JavaScript correlation snapshot:")
      expect(result.output).toContain("Analyzed source records:")
      const summary = await fs.readFile(path.join(configured.workspace.workspacePath, "javascript-analysis.md"), "utf8")
      expect(summary).toContain("/api/profiles/")

      await Session.remove(session.id)
    },
  })
}, 30_000)


test("processes the complete JavaScript worklist without a file-count cap, decompresses gzip, and accounts for non-JS URLs", async () => {
  await using tmp = await tmpdir()
  const requested: string[] = []
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    fetch(request) {
      const pathname = new URL(request.url).pathname
      requested.push(pathname)
      const jsMatch = pathname.match(/^\/assets\/(\d+)\.js$/)
      if (jsMatch) {
        const index = Number(jsMatch[1])
        return new Response(
          'export function loadAsset' + index + '() { return fetch("/api/items/' + index + '") }',
          { status: 200, headers: { "content-type": "application/javascript" } },
        )
      }
      if (pathname === "/assets/compressed.js.gz") {
        return new Response(new Uint8Array(gzipSync('export function loadCompressed() { return fetch("/api/compressed") }')), {
          status: 200,
          headers: { "content-type": "application/gzip" },
        })
      }
      if (pathname === "/assets/font.woff2") {
        return new Response(new Uint8Array([0, 1, 2, 3]), {
          status: 200,
          headers: { "content-type": "font/woff2" },
        })
      }
      if (pathname === "/page.html") {
        return new Response(
          '<html><head><script src="/assets/0.js"></script></head><body><script>function inlineBootstrap() { return fetch("/api/inline") }</script></body></html>',
          { status: 200, headers: { "content-type": "text/html" } },
        )
      }
      return new Response("not found", { status: 404, headers: { "content-type": "text/plain" } })
    },
  })

  try {
    await Instance.provide({
      directory: tmp.path,
      async fn() {
        const target = "http://127.0.0.1:" + server.port
        const configured = await TargetMemory.configureScope(target, {
          include: [target],
          authorizationSource: "Local JavaScript queue-resume regression fixture",
          authorizationReference: "https://example.test/security-policy",
        })
        const canonicalTarget = configured.workspace.targetURL
        const session = await Session.create({})
        Request.add({
          sessionID: session.id,
          method: "GET",
          normalizedPath: "/",
          keyHash: "ingest-javascript-bounded-resume-root",
          origin: canonicalTarget,
          scheme: "http",
          host: "127.0.0.1",
          pageUrl: canonicalTarget + "/",
          response: {
            status: 200,
            headers: { "content-type": "text/html" },
            body: "<html><body>local resume fixture</body></html>",
          },
        })

        const urls = [
          ...Array.from({ length: 30 }, (_, index) => canonicalTarget + "/assets/" + index + ".js"),
          canonicalTarget + "/assets/compressed.js.gz",
          canonicalTarget + "/assets/font.woff2",
          canonicalTarget + "/page.html",
        ]
        const tool = await IngestJavaScriptURLsTool.init()
        const result = await tool.execute({
          target_url: canonicalTarget,
          urls,
          source: "unit-test-no-file-count-cap",
          force_refresh: false,
        }, toolContext(session.id))
        const metadata = result.metadata as Record<string, unknown>
        expect(metadata.queued_urls).toBe(33)
        expect(metadata.worklist_pending).toBe(0)
        expect(metadata.worklist_retryable_failures).toBe(0)
        expect(metadata.worklist_missing_manifest_records).toBe(0)
        expect(metadata.collection_complete).toBe(true)
        expect(metadata.correlation_saved).toBe(true)
        expect(metadata.analysis_complete).toBe(true)
        expect(metadata.worklist_non_javascript).toBe(1)
        expect(result.output).toContain("Analyzed source records:")
        expect(requested.filter((pathname) => pathname.startsWith("/assets/"))).toHaveLength(32)
        expect(new Set(requested.filter((pathname) => pathname.startsWith("/assets/"))).size).toBe(32)

        const manifest = JSON.parse(await fs.readFile(
          path.join(configured.workspace.workspacePath, "javascript", "asset-manifest.json"),
          "utf8",
        )) as { assets: Array<{ url: string; status: string; localPath?: string; contentHash?: string }> }
        const gzipURL = canonicalTarget + "/assets/compressed.js.gz"
        const gzipRecord = manifest.assets.find((asset) => asset.url === gzipURL)
        expect(gzipRecord?.status).toBe("downloaded")
        expect(gzipRecord?.localPath).toBeTruthy()
        expect(await fs.readFile(gzipRecord!.localPath!, "utf8")).toContain("loadCompressed")
        const fontRecord = manifest.assets.find((asset) => asset.url === canonicalTarget + "/assets/font.woff2")
        expect(fontRecord?.status).toBe("skipped")
        const htmlRecord = manifest.assets.find((asset) => asset.url === canonicalTarget + "/page.html") as
          | { status?: string; assetKind?: string }
          | undefined
        expect(htmlRecord?.status).toBe("downloaded")
        expect(htmlRecord?.assetKind).toBe("html")
        const analysisSummary = await fs.readFile(
          path.join(configured.workspace.workspacePath, "javascript-analysis.md"),
          "utf8",
        )
        expect(analysisSummary).toContain("/api/inline")

        await Session.remove(session.id)
      },
    })
  } finally {
    server.stop(true)
  }
}, 60_000)
