import { expect, test } from "bun:test"
import fs from "node:fs/promises"
import path from "node:path"
import { Instance } from "../../src/project/instance"
import { Session } from "../../src/session"
import { Request } from "../../src/session/request"
import { TargetMemory } from "../../src/target"
import { IngestJavaScriptURLsTool } from "../../src/tool/ingest-javascript-urls"
import { tmpdir } from "../fixture/fixture"

const MiB = 1024 * 1024
const ASSET_LIMIT = 32 * MiB
const INVOCATION_LIMIT = 64 * MiB

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

test("enforces the aggregate response-body budget while streaming and preserves remaining URLs as pending", async () => {
  await using tmp = await tmpdir()
  const requested: string[] = []
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    fetch(request) {
      const pathname = new URL(request.url).pathname
      requested.push(pathname)
      if (pathname === "/assets/one.js" || pathname === "/assets/two.js") {
        return new Response(fixedSizeBody(ASSET_LIMIT), {
          status: 200,
          headers: { "content-type": "text/plain" },
        })
      }
      return new Response("should not be fetched", { status: 200, headers: { "content-type": "text/plain" } })
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

        expect(INVOCATION_LIMIT).toBe(ASSET_LIMIT * 2)
        expect(requested).toEqual(["/assets/one.js", "/assets/two.js"])
        expect((result.metadata as Record<string, unknown>).received_bytes).toBe(INVOCATION_LIMIT)

        const manifest = JSON.parse(await fs.readFile(manifestPath, "utf8")) as {
          assets: Array<{ url: string; status: string; error?: string }>
        }
        const statusFor = (url: string) => manifest.assets.find((item) => item.url === url)
        expect(statusFor(urls[0])?.status).toBe("skipped")
        expect(statusFor(urls[1])?.status).toBe("skipped")
        expect(statusFor(urls[2])?.status).toBe("pending")

        // The next invocation can resume the persisted pending URL without re-supplying
        // the original list. Completed/skipped assets must not be fetched again.
        const resumed = await tool.execute({
          target_url: canonicalTarget,
          urls: [],
          source: "unit-test-resume",
          force_refresh: false,
        }, toolContext(session.id))
        expect((resumed.metadata as Record<string, unknown>).pending_assets).toBe(0)
        expect(requested).toEqual(["/assets/one.js", "/assets/two.js", "/assets/three.js"])
        const resumedManifest = JSON.parse(await fs.readFile(manifestPath, "utf8")) as {
          assets: Array<{ url: string; status: string }>
        }
        expect(resumedManifest.assets.find((item) => item.url === urls[2])?.status).toBe("skipped")
      },
    })
  } finally {
    server.stop(true)
  }
}, 60_000)


test("merges source-map provenance from every bundle while keeping the display label bounded", async () => {
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
        expect(mapRecord?.source.length).toBeLessThanOrEqual(120)
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
