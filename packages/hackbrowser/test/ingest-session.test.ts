import { afterEach, expect, test } from "bun:test"
import { initSession } from "../src/ingest.ts"

const originalFetch = globalThis.fetch

afterEach(() => {
  globalThis.fetch = originalFetch
})

test("initSession creates a session without enqueueing a synthetic ingest message", async () => {
  let requestedUrl = ""
  let requestInit: RequestInit | undefined

  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    requestedUrl = String(input)
    requestInit = init
    return new Response(JSON.stringify({ id: "ses_test123" }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    })
  }) as typeof fetch

  const sessionID = await initSession(
    "http://127.0.0.1:4096",
    "https://example.test/dashboard",
    undefined,
  )

  expect(sessionID).toBe("ses_test123")
  expect(requestedUrl).toBe("http://127.0.0.1:4096/session")
  expect(requestInit?.method).toBe("POST")
  expect(requestInit?.headers).toMatchObject({ "Content-Type": "application/json" })

  const payload = JSON.parse(String(requestInit?.body))
  expect(payload).toEqual({ title: "[hackbrowser] example.test" })
  expect(payload.text).toBeUndefined()
});
