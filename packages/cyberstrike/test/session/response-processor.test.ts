import { expect, test } from "bun:test"
import { processResponse } from "../../src/session/response-processor"

test("keeps full JavaScript source while preserving the existing bounded prompt preview", () => {
  const source = 'fetch("/api/full-source");\n' + "x".repeat(110 * 1024)
  const processed = processResponse({
    status: 200,
    headers: { "content-type": "application/javascript; charset=utf-8" },
    body: source,
  })

  expect(processed.originalSize).toBe(Buffer.byteLength(source, "utf-8"))
  expect(processed.content).toContain("[TRUNCATED - showing first 100KB")
  expect(processed.content.length).toBeLessThan(source.length)
  expect(processed.javascriptSource).toBe(source)
})

test("does not duplicate full-source storage for ordinary JSON responses", () => {
  const processed = processResponse({
    status: 200,
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ ok: true }),
  })

  expect(processed.content).toContain('"ok":true')
  expect(processed.javascriptSource).toBeUndefined()
})


test("recognizes JavaScript assets by URL when the response MIME type is wrong", () => {
  const source = 'fetch("/api/mislabelled-source")'
  const processed = processResponse({
    status: 200,
    headers: { "content-type": "text/plain" },
    url: "https://app.example.test/assets/main.js?cache=1",
    body: source,
  })
  expect(processed.javascriptSource).toBe(source)
})
