import { describe, expect, test } from "bun:test"
import { normalizeAuthOrigin } from "../src/auth-vault"

describe("normalizeAuthOrigin", () => {
  test("matches only the normalized origin, not a path", () => {
    expect(normalizeAuthOrigin("https://Example.com/login?next=/account")).toBe("https://example.com")
    expect(normalizeAuthOrigin("https://example.com/another/path")).toBe("https://example.com")
  })

  test("preserves non-default ports as part of the origin", () => {
    expect(normalizeAuthOrigin("https://example.com:8443/login")).toBe("https://example.com:8443")
  })

  test("rejects non-http protocols", () => {
    expect(() => normalizeAuthOrigin("file:///tmp/secret")).toThrow("Only http(s) origins")
  })

  test("rejects credentials embedded in a URL", () => {
    expect(() => normalizeAuthOrigin("https://user:pass@example.com")).toThrow("Do not put credentials")
  })
})
