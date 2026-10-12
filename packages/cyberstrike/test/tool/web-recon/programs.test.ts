import { expect, test } from "bun:test"
import { methodCheck } from "../../../src/tool/web-recon/programs"

test("methodCheck is passive and never sends TRACE, PUT, or DELETE", async () => {
  const methods: string[] = []
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    fetch(request) {
      methods.push(request.method)
      return new Response(null, {
        status: 204,
        headers: { Allow: "GET, HEAD, OPTIONS, PUT, DELETE" },
      })
    },
  })

  try {
    const result = await methodCheck(`http://127.0.0.1:${server.port}/resource`, [], 2)
    expect(methods).toEqual(["OPTIONS"])
    expect(result.findings).toEqual([])
    expect(result.output).toContain("PUT is advertised by OPTIONS only")
    expect(result.output).toContain("DELETE is advertised by OPTIONS only")
    expect(result.output).toContain("no mutating request was sent")
    expect(methods.some((method) => ["TRACE", "PUT", "DELETE"].includes(method))).toBe(false)
  } finally {
    server.stop(true)
  }
})
