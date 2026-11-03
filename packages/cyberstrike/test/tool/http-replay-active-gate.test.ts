import { expect, test } from "bun:test"
import { Instance } from "../../src/project/instance"
import { Request } from "../../src/session/request"
import { Session } from "../../src/session"
import { TargetMemory } from "../../src/target"
import { HttpReplayRawTool, HttpReplayTool } from "../../src/tool/http-replay"
import { tmpdir } from "../fixture/fixture"

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
            rawRequest: "GET /replay?baseline=1 HTTP/1.1\\r\\nHost: 127.0.0.1:" + server.port + "\\r\\nConnection: close\\r\\n\\r\\n",
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
