import { expect, test } from "bun:test"
import { extractStaticJavaScriptEndpoints } from "../../src/target/javascript-correlation"

test("extracts and deduplicates static endpoint literals from common JavaScript calls", () => {
  const tick = String.fromCharCode(96)
  const source = [
    'const a = fetch("/api/users")',
    "axios.get('/api/users')",
    'client.open("GET", "/v1/profile")',
    'const dynamic = fetch(' + tick + '/api/orders/\${orderId}' + tick + ')',
  ].join("\n")
  const endpoints = extractStaticJavaScriptEndpoints(source)
  expect(endpoints).toContain("/api/users")
  expect(endpoints).toContain("/v1/profile")
  expect(endpoints).toContain("/api/orders/{param}")
  expect(new Set(endpoints).size).toBe(endpoints.length)
})

test("does not treat ordinary labels or non-path relative strings as endpoints", () => {
  const endpoints = extractStaticJavaScriptEndpoints([
    'fetch("not-a-path")',
    'axios.get("hello world")',
    'const label = "administrator"',
  ].join("\n"))
  expect(endpoints).not.toContain("not-a-path")
  expect(endpoints).not.toContain("administrator")
})


test("explicit JavaScript target matching rejects unrelated hosts and sibling paths unless observed", () => {
  const target = new URL("https://app.example.com/portal")
  const insideHost = new URL("https://app.example.com/portal/assets/app.js")
  const outsidePath = new URL("https://app.example.com/other-app/app.js")
  const external = new URL("https://unrelated.example.net/app.js")
  const pathWithin = (candidate: URL, scoped: URL) => {
    const base = scoped.pathname.replace(/\/$/, "") || "/"
    return candidate.pathname === base || candidate.pathname.startsWith(base + "/")
  }
  const matchesHost = (candidate: URL, scoped: URL) =>
    candidate.hostname === scoped.hostname || candidate.hostname.endsWith("." + scoped.hostname)
  const allowed = (candidate: URL, scoped: URL, observed: boolean) =>
    (matchesHost(candidate, scoped) && (scoped.pathname === "/" || candidate.hostname !== scoped.hostname || pathWithin(candidate, scoped))) || observed

  expect(allowed(insideHost, target, false)).toBe(true)
  expect(allowed(outsidePath, target, false)).toBe(false)
  expect(allowed(external, target, false)).toBe(false)
  expect(allowed(external, target, true)).toBe(true)
})
