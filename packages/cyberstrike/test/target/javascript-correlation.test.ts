import { expect, test } from "bun:test"
import { correlateStaticJavaScriptEndpoints, extractStaticJavaScriptEndpoints, isJavaScriptAssetAllowed } from "../../src/target/javascript-correlation"

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
  expect(isJavaScriptAssetAllowed({
    targetURL: "https://app.example.com/portal",
    javascriptURL: "https://app.example.com/portal/assets/app.js",
  })).toBe(true)
  expect(isJavaScriptAssetAllowed({
    targetURL: "https://app.example.com/portal",
    javascriptURL: "https://app.example.com/other-app/app.js",
  })).toBe(false)
  expect(isJavaScriptAssetAllowed({
    targetURL: "https://app.example.com/portal",
    javascriptURL: "https://unrelated.example.net/app.js",
  })).toBe(false)
  expect(isJavaScriptAssetAllowed({
    targetURL: "https://app.example.com/portal",
    javascriptURL: "https://unrelated.example.net/app.js",
    alreadyObserved: true,
  })).toBe(true)
})

test("persists deduplicated endpoint candidates and links only host-compatible captured requests", () => {
  const endpoints = correlateStaticJavaScriptEndpoints(
    [
      { relativePath: "javascript/app.js", basename: "app.js", sha256: "a", bytes: 10, endpointLiterals: ["/api/users", "/api/users", "https://api.example.com/v1/profile"] },
      { relativePath: "javascript/vendor.js", basename: "vendor.js", sha256: "b", bytes: 10, endpointLiterals: ["/api/users"] },
    ],
    [
      { id: "req-1", method: "GET", host: "app.example.com", url: "https://app.example.com/api/users/123", normalizedPath: "/api/users/123", responseStatus: 200 },
      { id: "req-2", method: "GET", host: "other.example.net", url: "https://other.example.net/v1/profile", normalizedPath: "/v1/profile", responseStatus: 200 },
      { id: "req-3", method: "GET", host: "api.example.com", url: "https://api.example.com/v1/profile", normalizedPath: "/v1/profile", responseStatus: 200 },
    ],
  )
  expect(endpoints).toHaveLength(2)
  const users = endpoints.find((endpoint) => endpoint.path === "/api/users")
  expect(users?.sourceFiles).toEqual(["javascript/app.js", "javascript/vendor.js"])
  expect(users?.observedRequestIDs).toContain("req-1")
  expect(users?.observedInTraffic).toBe(true)
  const profile = endpoints.find((endpoint) => endpoint.host === "api.example.com")
  expect(profile?.observedRequestIDs).toEqual(["req-3"])
  expect(profile?.observedRequestIDs).not.toContain("req-2")
})
