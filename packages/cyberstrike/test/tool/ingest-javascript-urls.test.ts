import { expect, test } from "bun:test"
import fs from "node:fs/promises"
import path from "node:path"
import { Instance } from "../../src/project/instance"
import { Session } from "../../src/session"
import { Request } from "../../src/session/request"
import { TargetMemory } from "../../src/target"
import { IngestJavaScriptURLsTool } from "../../src/tool/ingest-javascript-urls"
import { tmpdir } from "../fixture/fixture"

function toolContext(sessionID: string) {
  return {
    sessionID,
    messageID: "msg_ingest_javascript_urls_test",
    agent: "test",
    abort: new AbortController().signal,
    messages: [],
    metadata: () => undefined,
    ask: async () => {},
  } as never
}

test("resumes a persisted JavaScript queue with an empty input list and preserves source provenance", async () => {
  await using tmp = await tmpdir()
  const paths: string[] = []
  const javascript = 'const profilePath = "/api/profile";\nfetch(profilePath);\n'
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    fetch(request) {
      paths.push(new URL(request.url).pathname)
      return new Response(javascript, {
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
          authorizationSource: "Local JavaScript ingestion test fixture",
          authorizationReference: "https://example.test/security-policy",
        })
        const canonicalTarget = configured.workspace.targetURL
        const session = await Session.create({})
        Request.add({
          sessionID: session.id,
          method: "GET",
          normalizedPath: "/",
          keyHash: "ingest-javascript-session-root",
          origin: canonicalTarget,
          scheme: "http",
          host: "127.0.0.1",
          pageUrl: canonicalTarget + "/",
          response: {
            status: 200,
            headers: { "content-type": "text/html" },
            body: '<script src="/assets/app.js"></script>',
          },
        })

        const workspace = configured.workspace
        const javascriptRoot = path.join(workspace.workspacePath, "javascript")
        const assetsDirectory = path.join(javascriptRoot, "assets")
        const manifestPath = path.join(javascriptRoot, "asset-manifest.json")
        await fs.mkdir(assetsDirectory, { recursive: true })
        const assetURL = canonicalTarget + "/assets/app.js"
        await fs.writeFile(manifestPath, JSON.stringify({
          schemaVersion: 1,
          updatedAt: new Date().toISOString(),
          assets: [],
          pendingURLs: [assetURL],
          pendingSources: [{ url: assetURL, source: "crawler" }],
        }, null, 2) + "\n")

        const tool = await IngestJavaScriptURLsTool.init()
        const result = await tool.execute({
          target_url: canonicalTarget,
          urls: [],
          source: "resume-test",
          url_sources: [],
          force_refresh: false,
        }, toolContext(session.id))

        expect(paths).toEqual(["/assets/app.js"])
        expect(result.metadata.downloaded).toBe(1)
        expect(result.metadata.pending_urls).toEqual([])
        expect(result.metadata.pending_sources).toEqual([])

        const savedManifest = JSON.parse(await fs.readFile(manifestPath, "utf8"))
        expect(savedManifest.pendingURLs).toEqual([])
        expect(savedManifest.assets).toHaveLength(1)
        expect(savedManifest.assets[0].source).toContain("crawler")
        expect(savedManifest.assets[0].sources).toContain("crawler")
        expect(await fs.readFile(savedManifest.assets[0].localPath, "utf8")).toBe(javascript)
      },
    })
  } finally {
    server.stop(true)
  }
})

test("merges provenance when multiple JavaScript bundles reference the same source map", async () => {
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
          urls: [canonicalTarget + "/app-one.js", canonicalTarget + "/app-two.js", canonicalTarget + "/app-three.js", canonicalTarget + "/app-four.js"],
          source: "collector",
          url_sources: [],
          force_refresh: false,
        }, toolContext(session.id))

        expect(requests.filter((pathname) => pathname === "/shared.js.map")).toHaveLength(1)
        expect(result.metadata.pending_urls).toEqual([])
        const manifestPath = path.join(configured.workspace.workspacePath, "javascript", "asset-manifest.json")
        const savedManifest = JSON.parse(await fs.readFile(manifestPath, "utf8"))
        const mapRecord = savedManifest.assets.find((asset: { url: string }) => asset.url === canonicalTarget + "/shared.js.map")
        expect(mapRecord).toBeDefined()
        expect(mapRecord.sources).toContain("sourceMappingURL from " + canonicalTarget + "/app-one.js")
        expect(mapRecord.sources).toContain("sourceMappingURL from " + canonicalTarget + "/app-two.js")
        expect(mapRecord.sources).toContain("sourceMappingURL from " + canonicalTarget + "/app-three.js")
        expect(mapRecord.sources).toContain("sourceMappingURL from " + canonicalTarget + "/app-four.js")
        expect(mapRecord.sources).toHaveLength(4)
        expect(mapRecord.source.length).toBeLessThanOrEqual(120)
      },
    })
  } finally {
    server.stop(true)
  }
})


test("checkpoints completed assets before starting the next URL", async () => {
  await using tmp = await tmpdir()
  let signalSecondStarted!: () => void
  let releaseSecond!: () => void
  const secondStarted = new Promise<void>((resolve) => { signalSecondStarted = resolve })
  const secondRelease = new Promise<void>((resolve) => { releaseSecond = resolve })
  const javascript = 'const route = "/api/items";\nfetch(route);\n'
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    async fetch(request) {
      const pathname = new URL(request.url).pathname
      if (pathname === "/second.js") {
        signalSecondStarted()
        await secondRelease
      }
      return new Response(javascript, {
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
          authorizationSource: "Local JavaScript progress-checkpoint fixture",
          authorizationReference: "https://example.test/security-policy",
        })
        const canonicalTarget = configured.workspace.targetURL
        const session = await Session.create({})
        Request.add({
          sessionID: session.id,
          method: "GET",
          normalizedPath: "/",
          keyHash: "ingest-javascript-progress-root",
          origin: canonicalTarget,
          scheme: "http",
          host: "127.0.0.1",
          pageUrl: canonicalTarget + "/",
          response: {
            status: 200,
            headers: { "content-type": "text/html" },
            body: '<script src="/first.js"></script><script src="/second.js"></script>',
          },
        })
        const firstURL = canonicalTarget + "/first.js"
        const secondURL = canonicalTarget + "/second.js"
        const manifestPath = path.join(configured.workspace.workspacePath, "javascript", "asset-manifest.json")
        const tool = await IngestJavaScriptURLsTool.init()
        const execution = tool.execute({
          target_url: canonicalTarget,
          urls: [firstURL, secondURL],
          source: "collector",
          url_sources: [],
          force_refresh: false,
        }, toolContext(session.id))

        await secondStarted
        const progress = JSON.parse(await fs.readFile(manifestPath, "utf8"))
        expect(progress.pendingURLs).toEqual([secondURL])
        expect(progress.assets.map((asset: { url: string }) => asset.url)).toContain(firstURL)
        expect(progress.assets.find((asset: { url: string }) => asset.url === firstURL)?.status).toBe("downloaded")

        releaseSecond()
        const result = await execution
        expect(result.metadata.pending_urls).toEqual([])
      },
    })
  } finally {
    releaseSecond()
    server.stop(true)
  }
})


test("does not overwrite a malformed JavaScript asset manifest", async () => {
  await using tmp = await tmpdir()
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    fetch() {
      throw new Error("The network must not be contacted when the manifest is invalid.")
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
        const workspace = configured.workspace
        const javascriptRoot = path.join(workspace.workspacePath, "javascript")
        await fs.mkdir(path.join(javascriptRoot, "assets"), { recursive: true })
        const manifestPath = path.join(javascriptRoot, "asset-manifest.json")
        const original = '{"schemaVersion":1, this is intentionally invalid'
        await fs.writeFile(manifestPath, original)

        const tool = await IngestJavaScriptURLsTool.init()
        const result = await tool.execute({
          target_url: workspace.targetURL,
          urls: [workspace.targetURL + "/assets/app.js"],
          source: "test",
          url_sources: [],
          force_refresh: false,
        }, toolContext("ses_invalid_javascript_manifest"))

        expect(result.metadata.error).toBe("manifest_invalid_json")
        expect(await fs.readFile(manifestPath, "utf8")).toBe(original)
      },
    })
  } finally {
    server.stop(true)
  }
})
