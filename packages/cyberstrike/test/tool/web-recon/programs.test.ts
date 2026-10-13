import { expect, test } from "bun:test"
import { methodCheck, sitemapScan } from "../../../src/tool/web-recon/programs"

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


test("path-scoped recon passes every requested URL through the persisted scope gate", async () => {
  const requests: string[] = []
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    fetch(request) {
      requests.push(new URL(request.url).pathname)
      return new Response("<urlset></urlset>", { status: 200, headers: { "content-type": "application/xml" } })
    },
  })

  try {
    const target = "http://127.0.0.1:" + server.port + "/portal"
    const result = await sitemapScan(target, [], 2, async (url) => {
      const candidate = new URL(url)
      return candidate.pathname === "/portal" || candidate.pathname.startsWith("/portal/")
    })
    expect(result.output).toContain("No sitemap found")
    expect(requests).toEqual([])
  } finally {
    server.stop(true)
  }
})
