import { expect, test } from "bun:test"
import { extractStaticJavaScriptEndpoints, isJavaScriptAssetAllowed } from "../../src/target/javascript-correlation"

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
