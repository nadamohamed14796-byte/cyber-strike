import { describe, expect, test } from "bun:test"
import { checkMatch } from "./scope-match"

describe("HackerOne typed scope assets", () => {
  test("wildcard scope includes the apex and nested subdomains but rejects lookalikes", () => {
    expect(checkMatch("https://example.com/", "Wildcard: *.example.com").matches).toBe(true)
    expect(checkMatch("https://api.example.com/", "Wildcard: *.example.com").matches).toBe(true)
    expect(checkMatch("https://a.b.example.com/", "Wildcard: *.example.com").matches).toBe(true)
    expect(checkMatch("https://notexample.com/", "Wildcard: *.example.com").matches).toBe(false)
  })

  test("supports HackerOne wildcard labels in any position", () => {
    expect(checkMatch("https://www.amazon.com/", "www.amazon.*").matches).toBe(true)
    expect(checkMatch("https://www.amazon.com/", "Wildcard: www.amazon.*").matches).toBe(true)
    expect(checkMatch("https://tenant.example.com/", "{tenant}.example.com").matches).toBe(true)
    expect(checkMatch("https://tenant.example.com/", "Wildcard: {tenant}.example.com").matches).toBe(true)
    expect(checkMatch("https://a.b.example.com/", "Wildcard: {tenant}.example.com").matches).toBe(false)
    expect(checkMatch("https://notamazon.com/", "Wildcard: www.amazon.*").matches).toBe(false)
  })

  test("supports wildcard labels after the registered domain suffix", () => {
    expect(checkMatch("https://mercadolibreexperience.com.ar/", "mercadolibreexperience.com.*").matches).toBe(true)
    expect(checkMatch("https://mercadolibreexperience.com.br/", "mercadolibreexperience.com.*").matches).toBe(true)
    expect(checkMatch("https://mercadolibreexperience.com.attacker.test/", "mercadolibreexperience.com.*").matches).toBe(false)
    expect(checkMatch("https://mercadolibreexperience.com/", "mercadolibreexperience.com.*").matches).toBe(false)
  })

  test("matches HackerOne Domain, IP Address, and CIDR identifiers", () => {
    expect(checkMatch("https://example.com/", "Domain: example.com").matches).toBe(true)
    expect(checkMatch("https://sub.example.com/", "Domain: example.com").matches).toBe(false)
    expect(checkMatch("https://192.0.2.17/", "IP Address: 192.0.2.17").matches).toBe(true)
    expect(checkMatch("https://192.0.2.17/", "CIDR: 192.0.2.0/24").matches).toBe(true)
    expect(checkMatch("https://192.0.3.17/", "CIDR: 192.0.2.0/24").matches).toBe(false)
    expect(checkMatch("https://[2001:db8::1]/", "IP Address: 2001:db8::1").matches).toBe(true)
    expect(checkMatch("https://[2001:db8::2]/", "IP Address: 2001:db8::1").matches).toBe(false)
  })

  test("URL assets retain host and path boundaries", () => {
    expect(checkMatch("https://example.com/app1/users", "URL: example.com/app1").matches).toBe(true)
    expect(checkMatch("https://example.com/app10", "URL: example.com/app1").matches).toBe(false)
    expect(checkMatch("https://other.example.com/app1", "URL: example.com/app1").matches).toBe(false)
  })

  test("non-web HackerOne assets never authorize arbitrary HTTP targets", () => {
    for (const scope of [
      "Source Code: https://github.com/acme/app",
      "Executable: app.apk",
      "Hardware: router-01",
      "Android: .apk: com.example.app",
      "AWS Cloud Config: account-123",
      "Azure Cloud Config: subscription-123",
      "Other Asset: internal-system",
    ]) {
      expect(checkMatch("https://example.com/", scope).matches).toBe(false)
    }
  })
})
