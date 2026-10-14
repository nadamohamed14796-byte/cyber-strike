import { expect, test } from "bun:test"
import { correlateStaticJavaScriptEndpoints, extractStaticJavaScriptEndpoints, isJavaScriptAssetAllowed, matchesCapturedJavaScriptAsset, safeCorrelationResponsePreview, sanitizeJavaScriptSourceFileForPersistence } from "../../src/target/javascript-correlation"

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

test("normalizes numeric identifiers from relative and absolute JS endpoint literals", () => {
  const endpoints = extractStaticJavaScriptEndpoints([
    'fetch("/api/users/12345")',
    'fetch("https://api.example.com/v1/accounts/67890")',
  ].join("\n"))
  expect(endpoints).toContain("/api/users/{id}")
  expect(endpoints).toContain("https://api.example.com/v1/accounts/{id}")
  expect(endpoints).not.toContain("/api/users/12345")
  expect(endpoints).not.toContain("https://api.example.com/v1/accounts/67890")
})

test("never persists JavaScript source in correlation response previews", () => {
  const source = [
    "[Status: 200, Type: application/javascript, Size: 1.0 KB]",
    'const api_key = "this-is-a-secret-value-that-must-not-be-saved";',
    'fetch("/api/users")',
  ].join("\n")
  const preview = safeCorrelationResponsePreview({
    id: "request-script-1",
    normalizedPath: "/assets/app.js",
    responseContentType: "application/javascript",
    processedResponse: source,
  })
  expect(preview).toContain("request-script-1")
  expect(preview).not.toContain("this-is-a-secret-value")
  expect(preview).not.toContain("const api_key")

  const jsonPreview = safeCorrelationResponsePreview({
    id: "request-json-1",
    normalizedPath: "/api/profile",
    responseContentType: "application/json",
    processedResponse: '{"api_key":"this-is-a-secret-value-that-must-not-be-saved"}',
  })
  expect(jsonPreview).not.toContain("this-is-a-secret-value")
})

test("redacts detected literal secrets from source-analysis metadata before persistence", async () => {
  const { extractCapturedJavaScriptSources } = await import("../../src/target/javascript-correlation")
  const secret = "private-api-key-value-must-not-be-persisted"
  const [source] = extractCapturedJavaScriptSources([{
    id: "req-secret-js",
    url: "https://app.example.com/assets/secret.js",
    responseContentType: "application/javascript",
    responseBody: 'const api_key = "' + secret + '";',
  }])
  expect(source?.analysis?.secretCandidates[0]?.value).toBe(secret)
  expect(source?.analysis?.secretCandidates[0]?.fingerprint).toBeTruthy()

  const persisted = sanitizeJavaScriptSourceFileForPersistence(source!)
  const serialized = JSON.stringify(persisted)
  expect(serialized).not.toContain(secret)
  expect(persisted.analysis?.secretCandidates[0]?.value).toBe("[REDACTED]")
  expect(persisted.analysis?.secretCandidates[0]?.fingerprint).toBe(source?.analysis?.secretCandidates[0]?.fingerprint)
  expect(serialized).not.toContain("Exact candidate values are available")
  expect(serialized).toContain("redacted from persisted correlation artifacts")
})

test("correlates security sink candidates from captured JavaScript without retaining source", async () => {
  const { extractCapturedJavaScriptSources } = await import("../../src/target/javascript-correlation")
  const sources = extractCapturedJavaScriptSources([{
    id: "req-risk-js",
    url: "https://app.example.com/assets/card.js",
    responseContentType: "application/javascript",
    responseBody: [
      "function renderCard(untrustedHtml) {",
      " document.querySelector('#card').innerHTML = untrustedHtml",
      "}",
      'fetch("/api/cards")',
    ].join("\n"),
  }])
  expect(sources).toHaveLength(1)
  expect(sources[0]?.analysis?.riskSignals.some((signal) => signal.kind === "dom-html-sink")).toBe(true)
  // Parameter names are intentional analysis output; executable source and sink expressions are not.
  expect(sources[0]?.analysis?.functions.find((fn) => fn.name === "renderCard")?.parameters).toContain("untrustedHtml")
  expect(JSON.stringify(sources)).not.toContain("document.querySelector")
  expect(JSON.stringify(sources)).not.toContain("innerHTML = untrustedHtml")
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

test("explicit JavaScript asset filtering matches exact origin and path", () => {
  const target = "https://app.example.com/assets/app.js"
  expect(matchesCapturedJavaScriptAsset({
    origin: "https://app.example.com",
    normalizedPath: "/assets/app.js?cache=1",
    host: "app.example.com",
  }, target)).toBe(true)
  expect(matchesCapturedJavaScriptAsset({
    origin: "https://app.example.com",
    normalizedPath: "/assets/vendor.js",
    host: "app.example.com",
  }, target)).toBe(false)
  expect(matchesCapturedJavaScriptAsset({
    origin: "https://cdn.example.com",
    normalizedPath: "/assets/app.js",
    host: "cdn.example.com",
  }, target)).toBe(false)
  expect(matchesCapturedJavaScriptAsset({
    origin: "https://app.example.com",
    normalizedPath: "/assets/app.js",
    host: "app.example.com",
  }, "javascript:alert(1)")).toBe(false)
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
    "app.example.com",
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


test("strips response processor metadata before analyzing captured JavaScript lines", async () => {
  const { extractCapturedJavaScriptSources } = await import("../../src/target/javascript-correlation")
  const sources = extractCapturedJavaScriptSources([{
    id: "processed-js",
    url: "https://app.example.com/assets/processed.js",
    responseContentType: "application/javascript",
    responseBody: [
      "[Status: 200, Type: application/javascript, Size: 1.2 MB]",
      'fetch("/api/clean-route")',
      "[TRUNCATED - showing first 100KB of 1.2 MB]",
    ].join("\n"),
  }])
  expect(sources).toHaveLength(1)
  expect(sources[0]?.endpointLiterals).toContain("/api/clean-route")
  expect(sources[0]?.analysis?.requests[0]?.sourceLine).toBe(1)
  expect(sources[0]?.sha256).not.toBe("")
})

test("extracts endpoints from already-captured JavaScript responses without retaining source text", async () => {
  const { extractCapturedJavaScriptSources } = await import("../../src/target/javascript-correlation")
  const sources = extractCapturedJavaScriptSources([
    {
      id: "req-js",
      url: "https://app.example.com/assets/app.js",
      responseContentType: "application/javascript",
      responseBody: 'fetch("/api/users"); fetch("/api/orders/\${orderId}"); const key = "secret-value";',
    },
    {
      id: "req-html",
      url: "https://app.example.com/page",
      responseContentType: "text/html",
      responseBody: '<script>fetch("/api/not-js-response")</script>',
    },
  ])
  expect(sources).toHaveLength(1)
  expect(sources[0]?.endpointLiterals).toContain("/api/users")
  expect(sources[0]?.endpointLiterals).toContain("/api/orders/{param}")
  expect(JSON.stringify(sources)).not.toContain("secret-value")
  expect(sources[0]?.relativePath).toContain("captured/app.example.com")
  expect(sources[0]?.sourceRequestID).toBe("req-js")
})
