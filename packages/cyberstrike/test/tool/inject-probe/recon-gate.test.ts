import { expect, test } from "bun:test"
import { Instance } from "../../../src/project/instance"
import { Request } from "../../../src/session/request"
import { Session } from "../../../src/session"
import { TargetMemory } from "../../../src/target"
import { InjectProbeTool } from "../../../src/tool/inject-probe"
import { tmpdir } from "../../fixture/fixture"

test("inject_probe refuses before sending payloads when vulnerability testing has not been explicitly started", async () => {
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
          authorizationSource: "Local injection-gate regression fixture",
          authorizationReference: "https://example.test/security-policy",
        })
        const session = await Session.create({ title: "inject-probe-recon-gate-test" })
        try {
          const captured = Request.add({
            sessionID: session.id,
            method: "GET",
            normalizedPath: "/search?q=baseline",
            scheme: "http",
            host: "127.0.0.1",
            port: server.port,
            origin: target,
          })
          expect(captured).toBeDefined()
          const tool = await InjectProbeTool.init()
          const result = await tool.execute({
            request_id: captured!.id,
            vuln_type: ["xss"],
            points: [{ location: "query", name: "q" }],
          }, {
            sessionID: session.id,
            messageID: "msg_inject_probe_recon_gate",
            agent: "test",
            abort: new AbortController().signal,
            messages: [],
            ask: async () => {},
            metadata: () => {},
          } as never)

          expect(result.title).toContain("testing checkpoint")
          expect(result.output).toContain("No injection probes were sent.")
          expect(result.output).toContain("vulnerability_testing")
          expect(result.metadata).toMatchObject({ testingDenied: true })
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
