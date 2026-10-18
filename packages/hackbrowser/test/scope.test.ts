import { describe, expect, test } from "bun:test"
import { deriveScope, makeMatcher, normalizeScope } from "../src/scope"

describe("hackbrowser network scope", () => {
  test("defaults to the exact starting hostname, not the registrable domain", () => {
    expect(deriveScope("https://app.example.com/login")).toBe("app.example.com")
    expect(deriveScope("https://example.com")).toBe("example.com")
    expect(deriveScope("http://127.0.0.1:8080/")).toBe("127.0.0.1")
  })

  test("a bare host matches only that host", () => {
    const matches = makeMatcher(["example.com"])
    expect(matches("example.com")).toBe(true)
    expect(matches("www.example.com")).toBe(false)
    expect(matches("notexample.com")).toBe(false)
    expect(matches("EXAMPLE.COM.")).toBe(true)
  })

  test("a wildcard includes the apex and subdomains but rejects lookalikes", () => {
    const matches = makeMatcher(["*.example.com"])
    expect(matches("example.com")).toBe(true)
    expect(matches("api.example.com")).toBe(true)
    expect(matches("deep.api.example.com")).toBe(true)
    expect(matches("notexample.com")).toBe(false)
    expect(matches("example.com.attacker.test")).toBe(false)
  })

  test("explicit entries combine with OR semantics and empty scope fails closed", () => {
    const matches = makeMatcher(["app.example.com", "*.example.net"])
    expect(matches("app.example.com")).toBe(true)
    expect(matches("api.example.com")).toBe(false)
    expect(matches("api.example.net")).toBe(true)
    expect(matches("example.net")).toBe(false)
    expect(makeMatcher([])("example.com")).toBe(false)
  })

  test("normalization preserves wildcard semantics while removing URL details", () => {
    expect(normalizeScope("HTTPS://*.Example.com:443/path?q=1")).toBe("*.example.com")
    expect(normalizeScope("https://app.example.com/path?q=1")).toBe("app.example.com")
  })
})
