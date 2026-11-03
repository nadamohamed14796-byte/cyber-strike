import { expect, test } from "bun:test"
import { Instance } from "../../src/project/instance"
import { Request } from "../../src/session/request"
import { Session } from "../../src/session"
import { TargetMemory } from "../../src/target"
import { initialReconRun, reconRunID, reconScopeFingerprintForWorkspace } from "../../src/target/recon-gate"
import { HttpReplayRawTool, HttpReplayTool } from "../../src/tool/http-replay"
import { tmpdir } from "../fixture/fixture"

test("structured and raw replay are available inside an explicitly running parameter-fuzzing phase", async () => {
  await using tmp = await tmpdir()
  const requests: string[] = []
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    fetch(request) {
      requests.push(new URL(request.url).pathname)
      return new Response("fixture", { status: 200 })
    },
  })

  try {
    await Instance.provide({
      directory: tmp.path,
      async fn() {
        const target = "http://127.0.0.1:" + server.port
        const root = await TargetMemory.configureScope(target, {
          include: [target],
          exclude: [],
          authorizationSource: "Local parameter-fuzzing gate fixture",
          authorizationReference: "https://example.test/security-policy",
        })
        const decision = await TargetMemory.checkURLScope(target)
        expect(decision.allowed).toBe(true)
        expect(decision.workspace?.id).toBe(root.workspace.id)
        const fingerprint = await reconScopeFingerprintForWorkspace(decision.workspace!, root.workspace.id)
        const session = await Session.create({ title: "http-replay-parameter-gate-test" })
        try {
          const run = initialReconRun(root.workspace.targetURL, root.workspace.id, session.id)
          run.phases.scope_validation = {
            status: "complete",
            scopeValidationTarget: target,
            scopeFingerprint: fingerprint,
          }
          for (const phase of [
            "workspace_setup",
            "asset_discovery",
            "live_hosts_ports",
            "url_collection",
            "javascript_analysis",
            "parameter_discovery",
            "directory_fuzzing",
            "endpoint_inventory",
          ] as const) {
            run.phases[phase] = { status: "complete" }
          }
          run.phases.parameter_fuzzing = { status: "running" }
          const manifest = "runs/recon-" + reconRunID(root.workspace.id) + ".json"
          await TargetMemory.writeWorkspaceFile(root.workspace, manifest, JSON.stringify(run, null, 2) + "\n")

          const captured = Request.add({
            sessionID: session.id,
            method: "GET",
            normalizedPath: "/replay?baseline=1",
            rawRequest: "GET /replay?baseline=1 HTTP/1.1\r\nHost: 127.0.0.1:" + server.port + "\r\nConnection: close\r\n\r\n",
            scheme: "http",
            host: "127.0.0.1",
            port: server.port,
            origin: target,
          })
          expect(captured).toBeDefined()
          const ctx = {
            sessionID: session.id,
            messageID: "msg_http_replay_parameter_gate",
            agent: "test",
            abort: new AbortController().signal,
            messages: [],
            ask: async () => {},
            metadata: () => {},
          } as never

          const structured = await (await HttpReplayTool.init()).execute({ request_id: captured!.id }, ctx)
          expect(structured.metadata.testingDenied).toBeUndefined()
          const raw = await (await HttpReplayRawTool.init()).execute({ request_id: captured!.id }, ctx)
          expect(raw.metadata.testingDenied).toBeUndefined()
          expect(requests).toHaveLength(2)
          expect(requests.every((request) => request === "/replay")).toBe(true)
        } finally {
          await Session.remove(session.id)
        }
      },
    })
  } finally {
    server.stop(true)
  }
})

test("structured and raw HTTP replay refuse before network access without an explicit testing checkpoint", async () => {
  await using tmp = await tmpdir()
  const requests: string[] = []
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    fetch(request) {
      requests.push(new URL(request.url).pathname)
      return new Response("fixture", { status: 200 })
    },
  })

  try {
    await Instance.provide({
      directory: tmp.path,
      async fn() {
        const target = "http://127.0.0.1:" + server.port
        await TargetMemory.ensure(target)
        await TargetMemory.configureScope(target, {
          include: [target],
          exclude: [],
          authorizationSource: "Local HTTP replay gate regression fixture",
          authorizationReference: "https://example.test/security-policy",
        })
        const session = await Session.create({ title: "http-replay-active-gate-test" })
        try {
          const captured = Request.add({
            sessionID: session.id,
            method: "GET",
            normalizedPath: "/replay?baseline=1",
            rawRequest: "GET /replay?baseline=1 HTTP/1.1\r\nHost: 127.0.0.1:" + server.port + "\r\nConnection: close\r\n\r\n",
            scheme: "http",
            host: "127.0.0.1",
            port: server.port,
            origin: target,
          })
          expect(captured).toBeDefined()

          const ctx = {
            sessionID: session.id,
            messageID: "msg_http_replay_active_gate",
            agent: "test",
            abort: new AbortController().signal,
            messages: [],
            ask: async () => {},
            metadata: () => {},
          } as never

          const structured = await (await HttpReplayTool.init()).execute({ request_id: captured!.id }, ctx)
          expect(structured.title).toContain("testing checkpoint")
          expect(structured.output).toContain("No replay request was sent.")
          expect(structured.output).toContain("vulnerability_testing")
          expect(structured.metadata).toMatchObject({ testingDenied: true })

          const raw = await (await HttpReplayRawTool.init()).execute({ request_id: captured!.id }, ctx)
          expect(raw.title).toContain("testing checkpoint")
          expect(raw.output).toContain("No byte-exact request was sent.")
          expect(raw.output).toContain("vulnerability_testing")
          expect(raw.metadata).toMatchObject({ testingDenied: true })

          expect(requests).toEqual([])
        } finally {
          await Session.remove(session.id)
        }
      },
    })
  } finally {
    server.stop(true)
  }
})
