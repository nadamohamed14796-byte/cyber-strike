import { expect, test } from "bun:test"
import { Instance } from "../../src/project/instance"
import { Request } from "../../src/session/request"
import { Session } from "../../src/session"
import { TargetMemory } from "../../src/target"
import { CsrfExtractTool } from "../../src/tool/csrf-extract"
import { tmpdir } from "../fixture/fixture"

test("CSRF token fetch sends no request before explicit vulnerability-testing handoff", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    async fn() {
      let requests = 0
      const server = Bun.serve({
        hostname: "127.0.0.1",
        port: 0,
        fetch() {
          requests++
          return new Response("csrf_token=fixture")
        },
      })
      const session = await Session.create({})
      try {
        const origin = server.url.origin
        const port = Number(server.url.port)
        await TargetMemory.configureScope(origin, {
          include: [origin],
          authorizationSource: "CSRF checkpoint gate fixture",
          authorizationReference: "https://program.example.test/policy",
        })
        const captured = Request.add({
          id: "req_csrf_gate_fixture",
          sessionID: session.id,
          method: "GET",
          normalizedPath: "/form",
          rawRequest: "GET /form HTTP/1.1\r\nHost: 127.0.0.1:" + port + "\r\n\r\n",
          scheme: "http",
          host: "127.0.0.1",
          port,
          origin,
        })
        expect(captured).toBeTruthy()

        const ctx = {
          sessionID: session.id,
          messageID: "msg_csrf_gate_fixture",
          agent: "cyberstrike",
          abort: new AbortController().signal,
          messages: [],
          metadata: () => undefined,
          ask: async () => {},
        } as never
        const result = await (await CsrfExtractTool.init()).execute({
          request_id: captured!.id,
          extract_from: "body",
          name: "csrf_token=(.*)",
        }, ctx)

        expect(result.metadata.testingDenied).toBe(true)
        expect(result.output).toContain("No CSRF-token fetch was sent.")
        expect(requests).toBe(0)
      } finally {
        await Session.remove(session.id)
        server.stop(true)
      }
    },
  })
})
