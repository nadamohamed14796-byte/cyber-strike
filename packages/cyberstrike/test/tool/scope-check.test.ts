import { describe, expect, test } from "bun:test"
import { checkMatch } from "../../src/tool/scope-check"

describe("scope_check IPv4 CIDR matching", () => {
  test("matches valid in-range IPv4 addresses and URLs", () => {
    expect(checkMatch("10.20.30.40", "10.20.30.0/24").matches).toBe(true)
    expect(checkMatch("https://10.20.30.40:8443/api/users", "10.20.30.0/24").matches).toBe(true)
  })

  test("rejects IPv4-looking substrings in an external hostname", () => {
    expect(checkMatch("https://10.20.30.40.attacker.example/path", "10.20.30.0/24").matches).toBe(false)
    expect(checkMatch("https://attacker.example/?next=10.20.30.40", "10.20.30.0/24").matches).toBe(false)
  })

  test("rejects out-of-range and malformed IPv4 addresses", () => {
    expect(checkMatch("10.20.31.40", "10.20.30.0/24").matches).toBe(false)
    expect(checkMatch("999.20.30.40", "10.20.30.0/24").matches).toBe(false)
    expect(checkMatch("10.20.300.40", "10.20.30.0/24").matches).toBe(false)
  })

  test("rejects malformed network addresses and prefix lengths", () => {
    expect(checkMatch("10.20.30.40", "10.20.300.0/24").matches).toBe(false)
    expect(checkMatch("10.20.30.40", "10.20.30.0/33").matches).toBe(false)
    expect(checkMatch("10.20.30.40", "10.20.30.0/-1").matches).toBe(false)
    expect(checkMatch("10.20.30.40", "10.20.30.0/").matches).toBe(false)
  })

  test("rejects credential-bearing target URLs", () => {
    expect(checkMatch("http://user:pass@10.20.30.40/path", "10.20.30.0/24").matches).toBe(false)
  })

  test("keeps domain and wildcard behavior based on the parsed hostname", () => {
    expect(checkMatch("https://api.example.com/v1", "example.com").matches).toBe(true)
    expect(checkMatch("https://example.com.attacker.test/path", "*.example.com").matches).toBe(false)
    expect(checkMatch("https://api.example.com/path", "*.example.com").matches).toBe(true)
    expect(checkMatch("example.com", "*.example.com").matches).toBe(true)
  })
})
