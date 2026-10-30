import { expect, test } from "bun:test"
import { capCapturedRequestField } from "../../src/session/captured-request-prompt"

test("keeps small captured fields unchanged", () => {
  const value = "GET /health HTTP/1.1"
  expect(capCapturedRequestField({ value, label: "request", requestID: "req-1", maxBytes: 1024 })).toBe(value)
})

test("caps large fields and preserves both head and tail with a retrieval instruction", () => {
  const value = "A".repeat(40_000) + "IMPORTANT_TAIL_MARKER"
  const result = capCapturedRequestField({
    value,
    label: "response",
    requestID: "req-large",
    maxBytes: 4096,
  })
  expect(Buffer.byteLength(result, "utf8")).toBeLessThanOrEqual(4096)
  expect(result).toContain("TRUNCATED RESPONSE")
  expect(result).toContain('web_get_request_detail with request_id "req-large"')
  expect(result).toContain("IMPORTANT_TAIL_MARKER")
  expect(result.startsWith("A")).toBe(true)
})

test("keeps the byte ceiling for multilingual captures", () => {
  const result = capCapturedRequestField({
    value: "محتوى".repeat(10_000),
    label: "response",
    requestID: "req-unicode",
    maxBytes: 4096,
  })
  expect(Buffer.byteLength(result, "utf8")).toBeLessThanOrEqual(4096)
})
