import { expect, test } from "bun:test"
import { Instance } from "../../src/project/instance"
import { TargetMemory } from "../../src/target"
import { WebReconTool } from "../../src/tool/web-recon"
import { tmpdir } from "../fixture/fixture"

test("active web_recon programs are blocked before network access without a running testing checkpoint", async () => {
  await using tmp = await tmpdir()
  const requests: string[] = []
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    fetch(request) {
      requests.push(new URL(request.url).pathname)
      return new Response("fixture", { status: 404 })
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
          authorizationSource: "Local active-testing gate regression fixture",
          authorizationReference: "https://example.test/security-policy",
        })

        const tool = await WebReconTool.init()
        let permissionRequests = 0
        const result = await tool.execute({
          program: "sensitive_files",
          target,
          args: [],
          timeout_seconds: 1,
        }, {
          sessionID: "ses_web_recon_active_gate",
          messageID: "msg_web_recon_active_gate",
          agent: "test",
          abort: new AbortController().signal,
          messages: [],
          ask: async () => { permissionRequests++ },
          metadata: () => {},
        } as never)

        expect(result.output).toContain("vulnerability_testing")
        expect(result.output).toContain("No network probes were sent.")
        expect(result.metadata.artifact_saved).toBe(false)
        expect(permissionRequests).toBe(0)
        expect(requests).toEqual([])
      },
    })
  } finally {
    server.stop(true)
  }
})
