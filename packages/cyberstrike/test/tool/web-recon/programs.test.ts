import { expect, test } from "bun:test"
import { headerAudit, methodCheck, sitemapScan } from "../../../src/tool/web-recon/programs"

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


test("headerAudit treats missing headers as informational leads, not confirmed vulnerabilities", async () => {
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    fetch() {
      return new Response("public page", {
        status: 200,
        headers: { "content-type": "text/html", "content-security-policy": "default-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-eval'" },
      })
    },
  })

  try {
    const result = await headerAudit(`http://127.0.0.1:${server.port}/public`, [], 2)
    const missing = result.findings.filter((finding) => finding.status === "MISSING")
    expect(missing.length).toBeGreaterThan(0)
    expect(missing.every((finding) => finding.severity === "info")).toBe(true)
    expect(missing.every((finding) => finding.details.includes("hardening observation only"))).toBe(true)
    const weakCsp = result.findings.find((finding) => finding.checkId === "WEB-HDR-CSP-WEAK")
    expect(weakCsp?.severity).toBe("low")
    expect(weakCsp?.details).toContain("not proof of an exploitable XSS")
  } finally {
    server.stop(true)
  }
})
