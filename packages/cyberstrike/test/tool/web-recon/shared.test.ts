import { expect, test } from "bun:test"
import { safeFetch } from "../../../src/tool/web-recon/shared"

test("safeFetch rejects non-HTTP URLs and embedded credentials", async () => {
  expect(await safeFetch("file:///etc/passwd")).toBeNull()
  expect(await safeFetch("ftp://example.com/file")).toBeNull()
  expect(await safeFetch("http://user:pass@127.0.0.1:1/")).toBeNull()
})

test("safeFetch does not follow redirects automatically", async () => {
  let destinationHits = 0
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    fetch(request) {
      const url = new URL(request.url)
      if (url.pathname === "/redirect") {
        return new Response(null, { status: 302, headers: { Location: "/destination" } })
      }
      destinationHits++
      return new Response("destination reached")
    },
  })
  try {
    const response = await safeFetch(`http://127.0.0.1:${server.port}/redirect`, { timeout: 2 })
    expect(response?.status).toBe(302)
    expect(response?.headers.get("location")).toBe("/destination")
    expect(destinationHits).toBe(0)
  } finally {
    server.stop(true)
  }
})
