import { test, expect } from "bun:test"
import { makeMatcher } from "../src/scope.ts"
import { toScopedPages } from "../src/discovery/url.ts"

const inScope = makeMatcher(["*.example.com"])
const base = "https://app.example.com/dash/#/home"

test("toScopedPages resolves relative paths against the base origin", () => {
  const out = toScopedPages(["/admin", "/users"], base, inScope)
  expect(out).toContain("https://app.example.com/admin")
  expect(out).toContain("https://app.example.com/users")
})

test("toScopedPages drops out-of-scope hosts", () => {
  const out = toScopedPages(["https://evil.com/x", "https://app.example.com/ok"], base, inScope)
  expect(out.some((u) => u.includes("evil.com"))).toBe(false)
  expect(out).toContain("https://app.example.com/ok")
})

test("toScopedPages strips fragments and de-duplicates", () => {
  const out = toScopedPages(["/a#section", "/a", "https://app.example.com/a"], base, inScope)
  expect(out).toEqual(["https://app.example.com/a"])
})

test("toScopedPages skips non-http(s) and malformed values", () => {
  const out = toScopedPages(["mailto:a@b.c", "javascript:void(0)", "", "http://"], base, inScope)
  expect(out).toEqual([])
})


import { emitEndpoints } from "../src/discovery/emit.ts"

 test("failed discovered endpoint delivery is eligible for a later retry", async () => {
  const originalFetch = globalThis.fetch
  const seen = new Set<string>()
  let attempts = 0
  globalThis.fetch = (async () => {
    attempts++
    if (attempts === 1) return new Response("temporary outage", { status: 503 })
    return new Response(JSON.stringify({ sessionID: "session-test" }), {
      status: 202,
      headers: { "Content-Type": "application/json" },
    })
  }) as typeof fetch

  const endpoint = { method: "GET", url: "https://app.example.com/api/profile", source: "test-detector" }
  try {
    expect(await emitEndpoints([endpoint], "http://127.0.0.1:4096", "session-test", undefined, seen)).toBe(0)
    expect(seen.has("GET https://app.example.com/api/profile")).toBe(false)

    expect(await emitEndpoints([endpoint], "http://127.0.0.1:4096", "session-test", undefined, seen)).toBe(1)
    expect(attempts).toBe(2)
    expect(seen.has("GET https://app.example.com/api/profile")).toBe(true)
  } finally {
    globalThis.fetch = originalFetch
  }
})
