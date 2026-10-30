import { expect, test } from "bun:test"
import { Instance } from "../../src/project/instance"
import { Session } from "../../src/session"
import { TargetMemory } from "../../src/target"
import { IngestJavaScriptURLsTool } from "../../src/tool/ingest-javascript-urls"
import { tmpdir } from "../fixture/fixture"

function toolContext(sessionID: string) {
  return {
    sessionID,
    messageID: "msg_ingest_javascript_scope_resolution_test",
    agent: "test",
    abort: new AbortController().signal,
    messages: [],
    metadata: () => undefined,
    ask: async () => {},
  } as never
}

test("JavaScript ingestion correlates an authorized subdomain in its canonical wildcard root", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    async fn() {
      const rootURL = "https://example.test"
      const assetURL = "https://app.example.test"
      const configured = await TargetMemory.configureScope(rootURL, {
        include: ["*.example.test"],
        authorizationSource: "Local canonical JavaScript scope-resolution fixture",
        userConfirmed: true,
      })
      const decision = await TargetMemory.checkURLScope(assetURL + "/assets/app.js")
      expect(decision.allowed).toBe(true)
      expect(decision.workspace?.id).toBe(configured.workspace.id)

      const originalFetch = globalThis.fetch
      const requested: string[] = []
      globalThis.fetch = (async (input: RequestInfo | URL) => {
        const url = String(input)
        requested.push(url)
        if (url !== assetURL + "/assets/app.js") {
          throw new Error("Unexpected URL in local fixture: " + url)
        }
        return new Response(
          'const profileEndpoint = "/api/profile"; fetch(profileEndpoint);',
          { status: 200, headers: { "content-type": "application/javascript" } },
        )
      }) as typeof fetch

      const session = await Session.create({})
      try {
        const tool = await IngestJavaScriptURLsTool.init()
        const result = await tool.execute({
          target_url: assetURL,
          urls: [assetURL + "/assets/app.js"],
          source: "unit-test-canonical-subdomain",
          force_refresh: false,
        }, toolContext(session.id))

        const metadata = result.metadata as Record<string, unknown>
        expect(requested).toEqual([assetURL + "/assets/app.js"])
        expect(metadata.workspace).toBe(configured.workspace.workspacePath)
        expect(metadata.collection_complete).toBe(true)
        expect(metadata.correlation_saved).toBe(true)
        expect(metadata.analysis_error).toBeUndefined()
        expect(Number(metadata.analyzed_source_records)).toBeGreaterThan(0)

        const manifestPath = String(metadata.manifest_path)
        expect(manifestPath).toContain(configured.workspace.workspacePath)
      } finally {
        globalThis.fetch = originalFetch
        await Session.remove(session.id)
      }
    },
  })
})

test("JavaScript ingestion accepts an existing out-of-scope program root as a policy container", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    async fn() {
      const rootURL = "https://www.example.test"
      const assetURL = "https://api.example.net"
      const configured = await TargetMemory.configureScope(rootURL, {
        include: ["api.example.net"],
        authorizationSource: "Local policy-container JavaScript scope fixture",
        userConfirmed: true,
      })
      const rootDecision = await TargetMemory.checkURLScope(rootURL)
      expect(rootDecision.allowed).toBe(false)
      expect(rootDecision.excludeMatches).toHaveLength(0)

      const originalFetch = globalThis.fetch
      const requested: string[] = []
      globalThis.fetch = (async (input: RequestInfo | URL) => {
        const url = String(input)
        requested.push(url)
        if (url !== assetURL + "/assets/app.js") {
          throw new Error("Unexpected URL in local fixture: " + url)
        }
        return new Response(
          'const settingsEndpoint = "/api/settings"; fetch(settingsEndpoint);',
          { status: 200, headers: { "content-type": "application/javascript" } },
        )
      }) as typeof fetch

      const session = await Session.create({})
      try {
        const tool = await IngestJavaScriptURLsTool.init()
        const result = await tool.execute({
          target_url: rootURL,
          urls: [assetURL + "/assets/app.js"],
          source: "unit-test-policy-container",
          force_refresh: false,
        }, toolContext(session.id))

        const metadata = result.metadata as Record<string, unknown>
        expect(requested).toEqual([assetURL + "/assets/app.js"])
        expect(metadata.workspace).toBe(configured.workspace.workspacePath)
        expect(metadata.collection_complete).toBe(true)
        expect(metadata.correlation_saved).toBe(true)
        expect(metadata.analysis_error).toBeUndefined()
        expect(Number(metadata.analyzed_source_records)).toBeGreaterThan(0)
      } finally {
        globalThis.fetch = originalFetch
        await Session.remove(session.id)
      }
    },
  })
})
