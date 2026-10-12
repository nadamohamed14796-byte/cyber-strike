import { describe, test, expect, beforeAll, afterAll } from "bun:test"
import { HttpMessage } from "../../src/replay/message"
import { BackendFetch } from "../../src/replay/backend-fetch"

const CRLF = "\r\n"
let server: ReturnType<typeof Bun.serve>
let crossServer: ReturnType<typeof Bun.serve>
let origin: string
let crossOrigin: string
let crossOriginHits = 0

// Echo server: reflects method, path, and raw body so we can assert exactly what
// landed on the wire. /slow delays; /big streams a large body.
beforeAll(() => {
  crossServer = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    fetch() {
      crossOriginHits++
      return new Response("cross-origin destination reached")
    },
  })
  crossOrigin = `http://127.0.0.1:${crossServer.port}`
  server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    async fetch(req) {
      const url = new URL(req.url)
      if (url.pathname === "/redirect-same") {
        return new Response(null, { status: 302, headers: { location: "/hello" } })
      }
      if (url.pathname === "/redirect-cross") {
        return new Response(null, { status: 302, headers: { location: `${crossOrigin}/secret` } })
      }
      if (url.pathname === "/slow") {
        await Bun.sleep(300)
        return new Response("late")
      }
      if (url.pathname === "/big") {
        return new Response("x".repeat(100_000))
      }
      const body = await req.text()
      return Response.json({
        method: req.method,
        path: url.pathname + url.search,
        q: url.searchParams.get("q"),
        body,
      })
    },
  })
  origin = `http://127.0.0.1:${server.port}`
})

afterAll(() => {
  server.stop(true)
  crossServer.stop(true)
})

function reqLine(line: string, headers: string[] = [], body = ""): HttpMessage.Request {
  return HttpMessage.parse([line, `Host: 127.0.0.1`, ...headers, ``, body].join(CRLF))
}

describe("BackendFetch.send", () => {
  test("sends a basic GET and returns a parsed response", async () => {
    const r = await BackendFetch.send(reqLine("GET /hello?x=1 HTTP/1.1"), { origin })
    expect(r.error).toBeUndefined()
    expect(r.response?.status).toBe(200)
    const echoed = JSON.parse(new TextDecoder().decode(r.response!.body))
    expect(echoed.method).toBe("GET")
    expect(echoed.path).toBe("/hello?x=1")
    expect(r.timing.totalMs).toBeGreaterThanOrEqual(0)
  })

  test("a shell-hostile payload lands on the wire byte-for-byte", async () => {
    const payload = `{"q":"'\`$(id)\` OR 1=1--","x":42}`
    const r = await BackendFetch.send(reqLine("POST /echo HTTP/1.1", ["Content-Type: application/json"], payload), {
      origin,
    })
    const echoed = JSON.parse(new TextDecoder().decode(r.response!.body))
    // The backtick/$/quote payload arrives intact — no shell ever saw it.
    expect(echoed.body).toBe(payload)
  })

  test("query value round-trips semantically (backend A normalizes encoding)", async () => {
    // fetch URL-encodes the target (space -> %20, ' -> %27); the server decodes
    // back to the same value. Byte-EXACT transmission is the raw-socket backend's
    // job — here we assert the value survives, which is what backend A guarantees.
    const r = await BackendFetch.send(reqLine("GET /p?q=a'b OR 1=1 HTTP/1.1"), { origin })
    const echoed = JSON.parse(new TextDecoder().decode(r.response!.body))
    expect(echoed.q).toBe("a'b OR 1=1")
  })

  test("classifies a connection refused (dead port)", async () => {
    const r = await BackendFetch.send(reqLine("GET / HTTP/1.1"), { origin: "http://127.0.0.1:1" })
    expect(r.response).toBeUndefined()
    expect(r.error?.kind).toBe("conn_refused")
    expect(r.timing.totalMs).toBeGreaterThanOrEqual(0)
  })

  test("a timeout is reported as timeout with elapsed time preserved", async () => {
    const r = await BackendFetch.send(reqLine("GET /slow HTTP/1.1"), { origin, totalTimeoutMs: 50 })
    expect(r.response).toBeUndefined()
    expect(r.error?.kind).toBe("timeout")
    expect(r.timing.totalMs).toBeGreaterThan(0) // elapsed ms survives — time-based signal
  })


  test("follows same-origin redirects when explicitly enabled", async () => {
    const r = await BackendFetch.send(reqLine("GET /redirect-same HTTP/1.1"), {
      origin,
      followRedirects: true,
    })
    expect(r.error).toBeUndefined()
    expect(r.response?.status).toBe(200)
    const echoed = JSON.parse(new TextDecoder().decode(r.response!.body))
    expect(echoed.path).toBe("/hello")
  })

  test("does not follow a redirect to a different origin even when enabled", async () => {
    crossOriginHits = 0
    const r = await BackendFetch.send(reqLine("GET /redirect-cross HTTP/1.1"), {
      origin,
      followRedirects: true,
    })
    expect(r.error).toBeUndefined()
    expect(r.response?.status).toBe(302)
    expect(r.response?.headers.find((h) => h.name.toLowerCase() === "location")?.value).toBe(
      `${crossOrigin}/secret`,
    )
    expect(crossOriginHits).toBe(0)
  })

  test("refuses an absolute-form request target that changes the approved origin", async () => {
    const r = await BackendFetch.send(
      reqLine(`GET ${crossOrigin}/secret HTTP/1.1`),
      { origin },
    )
    expect(r.response).toBeUndefined()
    expect(r.error?.message).toContain("escaped its approved origin")
    expect(crossOriginHits).toBe(0)
  })

  test("caps an oversized response body", async () => {
    const r = await BackendFetch.send(reqLine("GET /big HTTP/1.1"), { origin, bodyCapBytes: 1000 })
    expect(r.response!.body.length).toBeLessThanOrEqual(1000)
  })
})
