import { expect, test } from "bun:test"
import { emitEndpoints } from "../src/discovery/emit.ts"
import type { Endpoint } from "../src/discovery/detector.ts"

test("emits every discovered endpoint beyond the former fixed cap", async () => {
  const endpoints: Endpoint[] = Array.from({ length: 501 }, (_, index) => ({
    method: "GET",
    url: `https://api.example.test/resource/${index}`,
    source: "openapi",
  }))
  const seen = new Set<string>()
  const originalFetch = globalThis.fetch
  let calls = 0

  globalThis.fetch = async () => {
    calls++
    return new Response(JSON.stringify({ sessionID: "ses_test" }), {
      status: 202,
      headers: { "Content-Type": "application/json" },
    })
  }

  try {
    const sent = await emitEndpoints(endpoints, "http://cyberstrike.test", "ses_test", undefined, seen)
    expect(sent).toBe(501)
    expect(calls).toBe(501)
    expect(seen.size).toBe(501)
  } finally {
    globalThis.fetch = originalFetch
  }
})
