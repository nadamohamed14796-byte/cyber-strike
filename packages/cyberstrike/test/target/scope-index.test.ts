import { describe, expect, test } from "bun:test"
import { matchingScopeItems, scopeItemSpecificity } from "../../src/target/scope-index"

describe("scopeItemSpecificity", () => {
  test("prefers an exact host grant over a wildcard family and a path-scoped URL over a bare host", () => {
    expect(scopeItemSpecificity("app.smartsheet.com")).toBeGreaterThan(scopeItemSpecificity("*.smartsheet.com"))
    expect(scopeItemSpecificity("https://app.smartsheet.com/api")).toBeGreaterThan(scopeItemSpecificity("app.smartsheet.com"))
    expect(scopeItemSpecificity("Wildcard: *.smartsheet.com")).toBe(scopeItemSpecificity("*.smartsheet.com"))
  })
})

describe("matchingScopeItems", () => {
  test("trims entries before indexing exact hosts, wildcards, and typed URL scopes", () => {
    const entries = ["  example.com  ", "  *.api.example.com  ", " API: api.example.net/v1 "]
    expect(matchingScopeItems("https://example.com/", entries)).toEqual(["example.com"])
    expect(matchingScopeItems("https://v1.api.example.com/", entries)).toEqual(["*.api.example.com"])
    expect(matchingScopeItems("https://api.example.net/v1/users", entries)).toEqual(["API: api.example.net/v1"])
    expect(matchingScopeItems("https://api.example.net/private", entries)).toEqual([])
  })

  test("matches a listed exact host but does not treat it as a wildcard", () => {
    const entries = ["att.com", "login.att.com"]
    expect(matchingScopeItems("https://att.com/login", entries)).toEqual(["att.com"])
    expect(matchingScopeItems("https://www.att.com/", entries)).toEqual([])
    expect(matchingScopeItems("https://login.att.com/", entries)).toEqual(["login.att.com"])
  })

  test("normalizes case and trailing dots for exact hosts and wildcard domains", () => {
    const entries = ["EXAMPLE.COM.", "*.API.EXAMPLE.COM."]
    expect(matchingScopeItems("https://example.com/", entries)).toEqual(["example.com"])
    expect(matchingScopeItems("https://v1.api.example.com/", entries)).toEqual(["*.api.example.com"])
    expect(matchingScopeItems("https://notexample.com/", entries)).toEqual([])
  })

  test("matches explicit wildcards on the apex and subdomains, including nested wildcard rules", () => {
    const entries = ["*.att.com", "*.api.att.com"]
    expect(matchingScopeItems("https://att.com/", entries)).toEqual(["*.att.com"])
    expect(matchingScopeItems("https://www.att.com/", entries)).toEqual(["*.att.com"])
    expect(matchingScopeItems("https://api.att.com/", entries)).toEqual(["*.api.att.com", "*.att.com"])
    expect(matchingScopeItems("https://v1.api.att.com/", entries)).toEqual(["*.api.att.com", "*.att.com"])
    expect(matchingScopeItems("https://notatt.com/", entries)).toEqual([])
  })

  test("indexes JavaScript files as exact typed entries", () => {
    const entries = ["JavaScript: https://cdn.example.com/app.js"]
    expect(matchingScopeItems("https://cdn.example.com/app.js?v=2", entries)).toEqual(entries)
    expect(matchingScopeItems("https://cdn.example.com/other.js", entries)).toEqual([])
  })

  test("indexes typed HackerOne web assets and keeps non-web assets non-authorizing", () => {
    expect(matchingScopeItems("https://example.com/", ["Wildcard: *.example.com"])).toEqual(["Wildcard: *.example.com"])
    expect(matchingScopeItems("https://example.com/app1/users", ["URL: example.com/app1"])).toEqual(["URL: example.com/app1"])
    expect(matchingScopeItems("https://example.com/", ["Source Code: https://github.com/acme/app"])).toEqual([])
    expect(matchingScopeItems("https://example.com/", ["AWS Cloud Config: 123456789012"])).toEqual([])
  })

  test("indexes every non-web HackerOne type without authorizing HTTP targets", () => {
    const nonWeb = [
      "Android Play Store: com.example.mobile",
      "Android: .apk: com.example.mobile",
      "Hardware/IoT: router-01",
      "Other Asset: internal-system",
      "iOS: App Store: com.example.ios",
      "iOS: Testflight: com.example.ios.beta",
      "Windows: Microsoft Store: 9WZDNCRFHVJL",
    ]
    for (const item of nonWeb) {
      expect(matchingScopeItems("https://example.com/", [item])).toEqual([])
    }
  })

  test("indexes positional wildcard patterns", () => {
    expect(matchingScopeItems("https://www.amazon.com/", ["www.amazon.*"])).toEqual(["www.amazon.*"])
    expect(matchingScopeItems("https://tenant.example.com/", ["{tenant}.example.com"])).toEqual(["{tenant}.example.com"])
    expect(matchingScopeItems("https://a.b.example.com/", ["{tenant}.example.com"])).toEqual([])
  })

  test("matches IPv6 CIDR ranges", () => {
    const entries = ["2001:db8::/32"]
    expect(matchingScopeItems("https://[2001:db8::1]/", entries)).toEqual(["2001:db8::/32"])
    expect(matchingScopeItems("https://[2001:db9::1]/", entries)).toEqual([])
  })

  test("matches explicit URL paths and host ports without losing boundaries", () => {
    const entries = ["https://api.att.com/v2/*", "api.att.com:8443"]
    expect(matchingScopeItems("https://api.att.com/v2/users", entries)).toEqual(["https://api.att.com/v2/*"])
    expect(matchingScopeItems("https://api.att.com/v20/users", entries)).toEqual([])
    expect(matchingScopeItems("https://api.att.com:8443/", entries)).toEqual(["api.att.com:8443"])
    expect(matchingScopeItems("https://api.att.com:9443/", entries)).toEqual([])
  })

  test("indexes bare host/path grants as URL constraints", () => {
    const entries = ["api.example.com/v1"]
    expect(matchingScopeItems("https://api.example.com/v1", entries)).toEqual(entries)
    expect(matchingScopeItems("https://api.example.com/v1/users", entries)).toEqual(entries)
    expect(matchingScopeItems("https://api.example.com/v10/users", entries)).toEqual([])
    expect(matchingScopeItems("https://other.example.com/v1", entries)).toEqual([])
    expect(matchingScopeItems("https://api.example.com/admin", entries)).toEqual([])
  })

  test("matches IPv4 CIDRs and refuses addresses outside the range", () => {
    const entries = ["192.0.2.0/24"]
    expect(matchingScopeItems("https://192.0.2.17/", entries)).toEqual(["192.0.2.0/24"])
    expect(matchingScopeItems("https://192.0.3.17/", entries)).toEqual([])
  })

  test("does not reuse stale authorization when a mutable list changes in place", () => {
    const entries = ["old.example"]
    expect(matchingScopeItems("https://old.example/", entries)).toEqual(["old.example"])
    entries[0] = "new.example"
    expect(matchingScopeItems("https://old.example/", entries)).toEqual([])
    expect(matchingScopeItems("https://new.example/", entries)).toEqual(["new.example"])
  })

  test("recompiles a replacement list rather than reusing an old index", () => {
    const first = ["old.example"]
    expect(matchingScopeItems("https://old.example/", first)).toEqual(["old.example"])
    expect(matchingScopeItems("https://new.example/", first)).toEqual([])
    const replacement = ["new.example"]
    expect(matchingScopeItems("https://new.example/", replacement)).toEqual(["new.example"])
    expect(matchingScopeItems("https://old.example/", replacement)).toEqual([])
  })

  test("supports large lists and reuses the compiled index for repeated checks", () => {
    // Persisted scope manifests are frozen, which permits safe compiled-index reuse.
    const entries = Object.freeze([
      ...Array.from({ length: 100_000 }, (_, index) => "host-" + index + ".att.com"),
      "wanted.att.com",
    ])
    expect(matchingScopeItems("https://wanted.att.com/", entries)).toEqual(["wanted.att.com"])
    expect(matchingScopeItems("https://missing.att.com/", entries)).toEqual([])
  })
})
