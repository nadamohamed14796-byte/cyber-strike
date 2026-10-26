import { expect, test } from "bun:test"
import fs from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import { Instance } from "../../src/project/instance"
import { Session } from "../../src/session"
import { Request } from "../../src/session/request"
import { TargetMemory } from "../../src/target"
import { JavaScriptCorrelation } from "../../src/target/javascript-correlation"
import { tmpdir } from "../fixture/fixture"
import { collectExplicitJavaScriptSourceMapURLs, correlateStaticJavaScriptEndpoints, createJavaScriptTesterCases, extractStaticJavaScriptEndpoints, extractJavaScriptSourceMapReferences, inventoryJavaScriptFiles, isJavaScriptOrSourceMapResponse, isSourceMapResponse, isJavaScriptAssetAllowed, matchesCapturedJavaScriptAsset, matchesEndpointPathTemplate, mergeStructuredJavaScriptEndpoints, type JavaScriptEndpointCandidate, type JavaScriptSourceFile, safeCorrelationResponsePreview, sanitizeJavaScriptSourceFileForPersistence, selectJavaScriptAssetsForCorrelation } from "../../src/target/javascript-correlation"

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

test("endpoint correlation requires exact path segments unless a single-segment template is explicit", () => {
  expect(matchesEndpointPathTemplate("/api/users", "/api/users")).toBe(true)
  expect(matchesEndpointPathTemplate("/api/users", "/api/users/123")).toBe(false)
  expect(matchesEndpointPathTemplate("/api/users", "/api/users/123/admin")).toBe(false)
  expect(matchesEndpointPathTemplate("/api/users/{id}", "/api/users/123")).toBe(true)
  expect(matchesEndpointPathTemplate("/api/users/{id}", "/api/users/123/admin")).toBe(false)
  expect(matchesEndpointPathTemplate("/api/users/{id}", "/api/users/")).toBe(false)
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

test("redacts sensitive JSON response preview values across key families and quoted whitespace", () => {
  const secretValues = [
    "two word password must be hidden",
    "client secret must be hidden",
    "private key must be hidden",
    "csrf token must be hidden",
    "generic secret must be hidden",
    "refresh token must be hidden",
    "cookie value must be hidden",
  ]
  const preview = safeCorrelationResponsePreview({
    id: "request-sensitive-json",
    normalizedPath: "/api/config",
    responseContentType: "application/json",
    processedResponse: JSON.stringify({
      password: secretValues[0],
      client_secret: secretValues[1],
      private_key: secretValues[2],
      csrf_token: secretValues[3],
      secret: secretValues[4],
      refresh_token: secretValues[5],
      cookie: secretValues[6],
      secretKey: "secret-key-value-must-be-hidden",
      token: "generic-token-value-must-be-hidden",
      "x-auth-token": "auth-header-token-must-be-hidden",
      authorization: "Bearer multi word credential must be hidden",
    }),
  })
  expect(preview).toContain("[REDACTED]")
  for (const secret of secretValues) expect(preview).not.toContain(secret)
  expect(preview).not.toContain("secret-key-value-must-be-hidden")
  expect(preview).not.toContain("generic-token-value-must-be-hidden")
  expect(preview).not.toContain("auth-header-token-must-be-hidden")
  expect(preview).not.toContain("multi word credential must be hidden")
})

test("persists secret fingerprints and source locations without raw values", async () => {
  const { extractCapturedJavaScriptSources } = await import("../../src/target/javascript-correlation")
  const secret = "private-api-key-value-must-not-be-persisted"
  const [source] = extractCapturedJavaScriptSources([{
    id: "req-secret-js",
    url: "https://app.example.com/assets/secret.js",
    responseContentType: "application/javascript",
    responseBody: 'const api_key = "' + secret + '";',
  }])
  expect(source?.analysis?.secretCandidates[0]?.fingerprint).toMatch(/^[a-f0-9]{20}$/)

  const persisted = sanitizeJavaScriptSourceFileForPersistence(source!)
  const serialized = JSON.stringify(persisted)
  expect(serialized).not.toContain(secret)
  expect(persisted.analysis?.secretCandidates[0]).toMatchObject({
    kind: "api-key",
    line: 1,
    confidence: "candidate",
  })
  expect(serialized).toContain("Secret-like values are never retained")
})

test("accepts JavaScript ingestion batches larger than 500 URLs", async () => {
  const { IngestJavaScriptURLsTool } = await import("../../src/tool/ingest-javascript-urls")
  const tool = await IngestJavaScriptURLsTool.init()
  const urls = Array.from({ length: 501 }, (_, index) => "https://app.example.com/assets/" + index + ".js")
  const parsed = tool.parameters.parse({
    target_url: "https://app.example.com",
    urls,
  })
  expect(parsed.urls).toHaveLength(501)
})

test("resumes pending or explicitly retryable JavaScript asset records only", async () => {
  const { shouldResumeAsset, shouldFetchAsset } = await import("../../src/tool/ingest-javascript-urls")
  expect(shouldResumeAsset({ status: "pending" })).toBe(true)
  expect(shouldResumeAsset({ status: "failed", retryable: true })).toBe(true)
  expect(shouldResumeAsset({ status: "failed", retryable: false })).toBe(false)
  expect(shouldResumeAsset({ status: "skipped" })).toBe(false)
  expect(shouldFetchAsset({ status: "failed", retryable: false })).toBe(false)
  expect(shouldFetchAsset({ status: "skipped" })).toBe(false)
  expect(shouldFetchAsset({ status: "failed", retryable: true })).toBe(true)
  expect(shouldFetchAsset({ status: "failed", retryable: false }, true)).toBe(true)
})

test("merges JavaScript asset provenance across input, HTML, and source-map references", async () => {
  const { mergeAssetSources } = await import("../../src/tool/ingest-javascript-urls")
  expect(mergeAssetSources(
    ["collector", "crawler"],
    ["crawler", "user-supplied"],
    "HTML | collector",
  )).toEqual(["HTML", "collector", "crawler", "user-supplied"])
})

test("resolves external script src URLs from HTML and ignores non-network schemes", async () => {
  const { extractHTMLScriptURLs } = await import("../../src/tool/ingest-javascript-urls")
  const urls = extractHTMLScriptURLs([
    '<base href="/app/">',
    '<script src="../assets/app.js"></script>',
    '<script src="//cdn.example.com/vendor.js"></script>',
    '<script src="data:text/javascript,alert(1)"></script>',
    '<script>fetch("/api/inline")</script>',
  ].join(""), "https://app.example.com/page")
  expect(urls).toContain("https://app.example.com/assets/app.js")
  expect(urls).toContain("https://cdn.example.com/vendor.js")
  expect(urls.some((url) => url.startsWith("data:"))).toBe(false)
  expect(urls).toHaveLength(2)
})

test("extracts inline JavaScript from captured HTML response bodies", async () => {
  const { extractCapturedJavaScriptSources } = await import("../../src/target/javascript-correlation")
  const sources = extractCapturedJavaScriptSources([{
    id: "req-html-inline",
    url: "https://app.example.com/account",
    responseContentType: "text/html; charset=utf-8",
    responseBody: [
      "<html><head><script type=\"application/ld+json\">{\"name\":\"not-code\"}</script></head>",
      "<body><script>fetch('/api/profile');</script>",
      "<script type=\"module\">axios.post('/api/settings', {theme: 'dark'});</script></body></html>",
    ].join(""),
  }])
  expect(sources).toHaveLength(2)
  expect(sources.map((source) => source.endpointLiterals).flat()).toContain("/api/profile")
  expect(sources.map((source) => source.endpointLiterals).flat()).toContain("/api/settings")
  expect(sources.every((source) => source.sourceRequestID === "req-html-inline")).toBe(true)
  expect(JSON.stringify(sources)).not.toContain("application/ld+json")
})

test("inventories inline JavaScript in local HTML files without executing it", async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "cyberstrike-inline-html-"))
  try {
    await fs.writeFile(path.join(root, "page.html"), [
      "<script>fetch('/api/inline-html')</script>",
      "<script type=\"application/json\">{\"not\":\"javascript\"}</script>",
    ].join("\n"), "utf8")
    const sources = await inventoryJavaScriptFiles(root)
    expect(sources).toHaveLength(1)
    expect(sources[0]?.endpointLiterals).toContain("/api/inline-html")
    expect(sources[0]?.relativePath).toContain("page.html#inline-1")
  } finally {
    await fs.rm(root, { recursive: true, force: true })
  }
})

test("reuses analysis for the same JavaScript content hash", async () => {
  const { extractCapturedJavaScriptSources } = await import("../../src/target/javascript-correlation")
  const cache = new Map<string, any>()
  const request = {
    id: "req-cache-js",
    url: "https://app.example.com/assets/app.js",
    responseContentType: "application/javascript",
    responseBody: 'function loadUser(id) { return fetch("/api/users/" + id) }',
  }
  const first = extractCapturedJavaScriptSources([request], cache)[0]
  const second = extractCapturedJavaScriptSources([{ ...request, id: "req-cache-js-2" }], cache)[0]
  expect(first?.sha256).toBe(second?.sha256)
  expect(second?.analysis).toBe(first?.analysis)
  expect(cache.has(first!.sha256)).toBe(true)
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

test("absolute endpoint literals preserve scheme and port during correlation", () => {
  const endpoints = correlateStaticJavaScriptEndpoints(
    [{ relativePath: "javascript/app.js", basename: "app.js", sha256: "a", bytes: 10, endpointLiterals: ["https://api.example.com:8443/v1/profile"] }],
    [
      { id: "req-https", method: "GET", host: "api.example.com", url: "https://api.example.com/v1/profile", normalizedPath: "/v1/profile", responseStatus: 200 },
      { id: "req-port", method: "GET", host: "api.example.com:8443", url: "https://api.example.com:8443/v1/profile", normalizedPath: "/v1/profile", responseStatus: 200 },
      { id: "req-http", method: "GET", host: "api.example.com:8443", url: "http://api.example.com:8443/v1/profile", normalizedPath: "/v1/profile", responseStatus: 200 },
    ],
    "app.example.com",
  )
  expect(endpoints).toHaveLength(1)
  expect(endpoints[0].origin).toBe("https://api.example.com:8443")
  expect(endpoints[0].observedRequestIDs).toEqual(["req-port"])
})

test("persists deduplicated endpoint candidates and links only host-compatible captured requests", () => {
  const endpoints = correlateStaticJavaScriptEndpoints(
    [
      { relativePath: "javascript/app.js", basename: "app.js", sha256: "a", bytes: 10, endpointLiterals: ["/api/users", "/api/users", "/api/users/{id}", "https://api.example.com/v1/profile"] },
      { relativePath: "javascript/vendor.js", basename: "vendor.js", sha256: "b", bytes: 10, endpointLiterals: ["/api/users"] },
    ],
    [
      { id: "req-1", method: "GET", host: "app.example.com", url: "https://app.example.com/api/users", normalizedPath: "/api/users", responseStatus: 200 },
      { id: "req-2", method: "GET", host: "other.example.net", url: "https://other.example.net/v1/profile", normalizedPath: "/v1/profile", responseStatus: 200 },
      { id: "req-3", method: "GET", host: "api.example.com", url: "https://api.example.com/v1/profile", normalizedPath: "/v1/profile", responseStatus: 200 },
      { id: "req-4", method: "GET", host: "app.example.com", url: "https://app.example.com/api/users/123", normalizedPath: "/api/users/123", responseStatus: 200 },
      { id: "req-5", method: "GET", host: "app.example.com", url: "https://app.example.com/api/users/123/admin", normalizedPath: "/api/users/123/admin", responseStatus: 200 },
      { id: "req-6", method: "GET", host: "app.example.com", url: "https://app.example.com/api/user", normalizedPath: "/api/user", responseStatus: 200 },
    ],
    "app.example.com",
  )
  expect(endpoints).toHaveLength(3)
  const users = endpoints.find((endpoint) => endpoint.path === "/api/users")
  expect(users?.sourceFiles).toEqual(["javascript/app.js", "javascript/vendor.js"])
  expect(users?.observedRequestIDs).toEqual(["req-1"])
  expect(users?.observedInTraffic).toBe(true)
  const userByID = endpoints.find((endpoint) => endpoint.path === "/api/users/{id}")
  expect(userByID?.observedRequestIDs).toEqual(["req-4"])
  expect(userByID?.observedRequestIDs).not.toContain("req-5")
  expect(userByID?.observedRequestIDs).not.toContain("req-6")
  const profile = endpoints.find((endpoint) => endpoint.host === "api.example.com")
  expect(profile?.observedRequestIDs).toEqual(["req-3"])
  expect(profile?.observedRequestIDs).not.toContain("req-2")
})


test("merges structured requests into endpoint inventory when literal extraction misses the route", () => {
  const endpoints = mergeStructuredJavaScriptEndpoints([], [{
    id: "js-request:custom-client", sourceFunction: "loadSettings", method: "GET",
    urlTemplate: "http://api.example.com:8080/internal/settings", host: "api.example.com:8080",
    origin: "http://api.example.com:8080", path: "/internal/settings", pathParameters: [],
    queryParameters: ["expand"], bodyParameters: [], headerNames: ["X-Tenant-ID"],
    authSignals: [], cookieSignals: [], authAssessment: "no-static-auth-signal",
    sourceLine: 18, confidence: "candidate", sourceFile: "javascript/settings.js",
    observedRequestIDs: ["request-settings-1"],
  }])
  expect(endpoints).toHaveLength(1)
  expect(endpoints[0]?.origin).toBe("http://api.example.com:8080")
  expect(endpoints[0]?.path).toBe("/internal/settings")
  expect(endpoints[0]?.sourceFiles).toContain("javascript/settings.js")
  expect(endpoints[0]?.observedRequestIDs).toContain("request-settings-1")
  expect(endpoints[0]?.observedInTraffic).toBe(true)
})

test("merges equivalent named route placeholders and unions all source evidence", () => {
  const staticEndpoints = [
    { id: "endpoint:static-a", literal: "/api/users/{param}", host: null, origin: null, path: "/api/users/{param}",
      sourceFiles: ["javascript/routes.js"], observedRequestIDs: ["req-users"], observedInTraffic: true, confidence: "observed" as const },
    { id: "endpoint:static-b", literal: "/api/users/{user}", host: null, origin: null, path: "/api/users/{user}",
      sourceFiles: ["javascript/vendor.js"], observedRequestIDs: [], observedInTraffic: false, confidence: "candidate" as const },
  ]
  const endpoints = mergeStructuredJavaScriptEndpoints(staticEndpoints, [{
    id: "js-request:user", sourceFunction: "loadUser", method: "GET",
    urlTemplate: "/api/users/{userId}", host: null, origin: null, path: "/api/users/{userId}",
    pathParameters: ["userId"], queryParameters: [], bodyParameters: [], headerNames: [],
    authSignals: [], cookieSignals: [], authAssessment: "no-static-auth-signal", sourceLine: 3,
    confidence: "candidate", sourceFile: "javascript/users.js", observedRequestIDs: [],
  }])
  expect(endpoints).toHaveLength(1)
  expect(endpoints[0]?.sourceFiles).toEqual(["javascript/routes.js", "javascript/vendor.js", "javascript/users.js"])
  expect(endpoints[0]?.observedRequestIDs).toContain("req-users")
  expect(endpoints[0]?.observedInTraffic).toBe(true)
})

test("generates an idempotent tester survey with request shape and resumable check progress", () => {
  const candidate = {
    id: "js-request:survey", sourceFunction: "loadUser", method: "GET",
    urlTemplate: "https://app.example.com/api/users/{userId}", host: "app.example.com",
    path: "/api/users/{userId}", pathParameters: ["userId"], queryParameters: ["include"],
    bodyParameters: [], headerNames: ["Authorization", "X-Tenant-ID"],
    authSignals: ["authorization-header"], cookieSignals: ["credentialed-request-may-send-cookies"],
    authAssessment: "signals-present" as const, sourceLine: 42, confidence: "candidate" as const,
    sourceFile: "javascript/app.js", observedRequestIDs: ["req-1"],
    recommendedChecks: ["Manually verify backend validation"],
  }
  const first = createJavaScriptTesterCases([candidate], [], [])
  expect(first).toHaveLength(1)
  expect(first[0]?.pathParameters).toContain("userId")
  expect(first[0]?.queryParameters).toContain("include")
  expect(first[0]?.headerNames).toContain("Authorization")
  expect(first[0]?.observedRequestIDs).toContain("req-1")
  const progressed = {
    ...first[0]!, status: "completed" as const,
    checks: first[0]!.checks.map((check) => check.kind === "capture-or-inspect-the-baseline-request-and-response"
      ? { ...check, status: "completed" as const, result: "Baseline stable" } : check),
  }
  const second = createJavaScriptTesterCases([candidate], [], [progressed])
  expect(second[0]?.id).toBe(first[0]?.id)
  expect(second[0]?.status).toBe("completed")
  expect(second[0]?.checks.find((check) => check.kind === "capture-or-inspect-the-baseline-request-and-response")?.result).toBe("Baseline stable")
})

test("keeps literal-only endpoint candidates in the tester survey", () => {
  const endpoint = {
    id: "endpoint:literal", literal: "/api/admin/reports", host: null, origin: null,
    path: "/api/admin/reports", sourceFiles: ["javascript/admin.js"],
    observedRequestIDs: [], observedInTraffic: false, confidence: "candidate" as const,
  }
  const cases = createJavaScriptTesterCases([], [endpoint], [])
  expect(cases).toHaveLength(1)
  expect(cases[0]?.method).toBe(null)
  expect(cases[0]?.checks.some((check) => check.title.includes("HTTP method"))).toBe(true)
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
  // The JavaScript response and inline script from captured HTML are both analyzed.
  expect(sources).toHaveLength(2)
  expect(sources[0]?.endpointLiterals).toContain("/api/users")
  expect(sources[0]?.endpointLiterals).toContain("/api/orders/{param}")
  expect(sources[1]?.endpointLiterals).toContain("/api/not-js-response")
  expect(sources[1]?.relativePath).toContain("captured-html/")
  expect(JSON.stringify(sources)).not.toContain("secret-value")
  expect(sources[0]?.relativePath).toContain("captured/app.example.com")
  expect(sources[0]?.sourceRequestID).toBe("req-js")
})


test("extracts more than 200 distinct static endpoint literals", () => {
  const source = Array.from({ length: 251 }, (_, index) =>
    'fetch("/api/v1/resource-' + index + '")',
  ).join("\n")
  const endpoints = extractStaticJavaScriptEndpoints(source)
  expect(endpoints).toHaveLength(251)
  expect(endpoints).toContain("/api/v1/resource-250")
})

test("marks captures explicitly truncated by the response processor as partial", async () => {
  const { extractCapturedJavaScriptSources } = await import("../../src/target/javascript-correlation")
  const sources = extractCapturedJavaScriptSources([{
    id: "truncated-js",
    url: "https://app.example.com/assets/truncated.js",
    responseContentType: "application/javascript",
    responseBody: [
      "[Status: 200, Type: application/javascript, Size: 1.2 MB]",
      'fetch("/api/visible-route")',
      "[TRUNCATED - showing first 100KB of 1.2 MB]",
    ].join("\n"),
  }])
  expect(sources[0]?.captureTruncated).toBe(true)
  expect(sources[0]?.analysis?.notes.some((note) => note.startsWith("PARTIAL SOURCE:"))).toBe(true)
})


test("keeps endpoint identity method-specific while merging parameter evidence for the same method", () => {
  const endpoints = mergeStructuredJavaScriptEndpoints(
    [{
      id: "endpoint:static-users",
      literal: "/api/users/{id}",
      host: null,
      origin: null,
      path: "/api/users/{id}",
      sourceFiles: ["javascript/routes.js"],
      observedRequestIDs: ["req-get", "req-post"],
      observedInTraffic: true,
      confidence: "observed",
    }],
    [
      {
        id: "js-request:get-id", sourceFunction: "loadUser", method: "GET",
        urlTemplate: "/api/users/{id}", host: null, origin: null, path: "/api/users/{id}",
        pathParameters: ["id"], queryParameters: ["role"], bodyParameters: [], headerNames: ["Authorization"],
        authSignals: ["authorization-header"], cookieSignals: [], authAssessment: "signals-present",
        sourceLine: 12, confidence: "candidate", sourceFile: "javascript/users.js", observedRequestIDs: ["req-get"],
      },
      {
        id: "js-request:get-expanded", sourceFunction: "loadUser", method: "GET",
        urlTemplate: "/api/users/{userId}", host: null, origin: null, path: "/api/users/{userId}",
        pathParameters: ["userId"], queryParameters: ["include"], bodyParameters: [], headerNames: [],
        authSignals: [], cookieSignals: [], authAssessment: "no-static-auth-signal",
        sourceLine: 39, confidence: "candidate", sourceFile: "javascript/users-expanded.js", observedRequestIDs: [],
      },
      {
        id: "js-request:post-user", sourceFunction: "updateUser", method: "POST",
        urlTemplate: "/api/users/{id}", host: null, origin: null, path: "/api/users/{id}",
        pathParameters: ["id"], queryParameters: [], bodyParameters: ["role"], headerNames: ["X-CSRF-Token"],
        authSignals: ["csrf-or-xsrf-signal"], cookieSignals: ["cookie-header-signal"], authAssessment: "signals-present",
        sourceLine: 61, confidence: "candidate", sourceFile: "javascript/update-user.js", observedRequestIDs: ["req-post"],
      },
    ],
    [
      { id: "req-get", method: "GET" },
      { id: "req-post", method: "POST" },
    ],
  )

  expect(endpoints).toHaveLength(2)
  const getEndpoint = endpoints.find((endpoint) => endpoint.method === "GET")
  const postEndpoint = endpoints.find((endpoint) => endpoint.method === "POST")
  expect(getEndpoint).toBeDefined()
  expect(postEndpoint).toBeDefined()
  expect(getEndpoint?.id).not.toBe(postEndpoint?.id)
  expect(getEndpoint?.sourceFiles).toEqual(["javascript/routes.js", "javascript/users.js", "javascript/users-expanded.js"])
  expect(getEndpoint?.pathParameters).toEqual(["id", "userId"])
  expect(getEndpoint?.queryParameters).toEqual(["role", "include"])
  expect(getEndpoint?.bodyParameters).toEqual([])
  expect(getEndpoint?.observedRequestIDs).toEqual(["req-get"])
  expect(postEndpoint?.sourceFiles).toContain("javascript/update-user.js")
  expect(postEndpoint?.bodyParameters).toEqual(["role"])
  expect(postEndpoint?.queryParameters).toEqual([])
  expect(postEndpoint?.observedRequestIDs).toEqual(["req-post"])
})


test("extracts more than 250 distinct captured JavaScript assets", async () => {
  const { extractCapturedJavaScriptSources } = await import("../../src/target/javascript-correlation")
  const requests = Array.from({ length: 251 }, (_, index) => ({
    id: "captured-js-" + index,
    url: "https://app.example.com/assets/chunk-" + index + ".js",
    responseContentType: "application/javascript",
    responseBody: 'fetch("/api/chunk-' + index + '")',
  }))
  const sources = extractCapturedJavaScriptSources(requests)
  expect(sources).toHaveLength(251)
  expect(sources.some((source) => source.basename === "chunk-250.js")).toBe(true)
})


test("deduplicates analysis by content while preserving each canonical JavaScript source URL", async () => {
  const { extractCapturedJavaScriptSources } = await import("../../src/target/javascript-correlation")
  const body = 'fetch("/api/profile")'
  const cache = new Map<string, any>()
  const sources = extractCapturedJavaScriptSources([
    { id: "req-app", url: "https://app.example.com/assets/shared.js", responseContentType: "application/javascript", responseBody: body },
    { id: "req-api", url: "https://api.example.com/assets/shared.js", responseContentType: "application/javascript", responseBody: body },
    { id: "req-app-2", url: "https://app.example.com/assets/shared.js?cache=refresh", responseContentType: "application/javascript", responseBody: body },
  ], cache)

  expect(sources).toHaveLength(2)
  const appSource = sources.find((source) => source.sourceURL === "https://app.example.com/assets/shared.js")
  const apiSource = sources.find((source) => source.sourceURL === "https://api.example.com/assets/shared.js")
  expect(appSource?.sha256).toBe(apiSource?.sha256)
  expect(appSource?.sourceRequestIDs).toEqual(["req-app", "req-app-2"])
  expect(apiSource?.sourceRequestIDs).toEqual(["req-api"])
  expect(appSource?.relativePath).not.toBe(apiSource?.relativePath)
  expect(appSource?.analysis).toBe(apiSource?.analysis)
  expect(cache.size).toBe(1)
})

test("resolves relative static endpoint candidates to each observed request origin", () => {
  const endpoints = correlateStaticJavaScriptEndpoints(
    [{
      relativePath: "captured/app/shared.js",
      basename: "shared.js",
      sha256: "same-content",
      bytes: 10,
      sourceURL: "https://cdn.example.com/assets/shared.js",
      endpointLiterals: ["/api/profile"],
    }],
    [
      { id: "req-app-profile", method: "GET", host: "app.example.com", url: "https://app.example.com/api/profile", normalizedPath: "/api/profile", responseStatus: 200 },
      { id: "req-api-profile", method: "GET", host: "api.example.com", url: "https://api.example.com/api/profile", normalizedPath: "/api/profile", responseStatus: 200 },
    ],
    "app.example.com",
    "https://app.example.com",
  )

  expect(endpoints).toHaveLength(2)
  expect(endpoints.map((endpoint) => endpoint.origin).sort()).toEqual(["https://api.example.com", "https://app.example.com"])
  expect(endpoints.find((endpoint) => endpoint.origin === "https://app.example.com")?.observedRequestIDs).toEqual(["req-app-profile"])
  expect(endpoints.find((endpoint) => endpoint.origin === "https://api.example.com")?.observedRequestIDs).toEqual(["req-api-profile"])
})


test("merges static parameter variants into one canonical endpoint and unions their evidence", () => {
  const makeCandidate = (input: {
    sourceFile: string
    queryParameters: string[]
    bodyParameters: string[]
    headerNames: string[]
    authSignals: string[]
    cookieSignals: string[]
  }): JavaScriptEndpointCandidate => ({
    id: input.sourceFile,
    literal: "/api/items",
    host: "api.example.com",
    origin: "https://api.example.com",
    path: "/api/items",
    method: "GET",
    pathParameters: [],
    queryParameters: input.queryParameters,
    bodyParameters: input.bodyParameters,
    headerNames: input.headerNames,
    authSignals: input.authSignals,
    cookieSignals: input.cookieSignals,
    sourceFiles: [input.sourceFile],
    observedRequestIDs: [],
    observedInTraffic: false,
    confidence: "candidate",
  })

  const endpoints = mergeStructuredJavaScriptEndpoints([
    makeCandidate({ sourceFile: "bundle-a.js", queryParameters: ["page"], bodyParameters: ["filter"], headerNames: ["x-tenant"], authSignals: ["bearer"], cookieSignals: ["session"] }),
    makeCandidate({ sourceFile: "bundle-b.js", queryParameters: ["sort"], bodyParameters: ["category"], headerNames: ["x-trace"], authSignals: ["api-key"], cookieSignals: ["preference"] }),
  ], [])

  expect(endpoints).toHaveLength(1)
  expect(endpoints[0]?.queryParameters).toEqual(["page", "sort"])
  expect(endpoints[0]?.bodyParameters).toEqual(["filter", "category"])
  expect(endpoints[0]?.headerNames).toEqual(["x-tenant", "x-trace"])
  expect(endpoints[0]?.authSignals).toEqual(["bearer", "api-key"])
  expect(endpoints[0]?.cookieSignals).toEqual(["session", "preference"])
  expect(endpoints[0]?.sourceFiles).toEqual(["bundle-a.js", "bundle-b.js"])
})


test("discovers external sourceMappingURL references, resolves relative paths, strips query data, and deduplicates", () => {
  const source = [
    'fetch("/api/profile")',
    "//# sourceMappingURL=app.js.map?token=must-not-be-forwarded",
    "/*# sourceMappingURL=../maps/shared.js.map */",
    "//@ sourceMappingURL=app.js.map#duplicate",
  ].join("\n")
  expect(extractJavaScriptSourceMapReferences(source, "https://app.example.com/assets/app.js")).toEqual([
    "https://app.example.com/assets/app.js.map",
    "https://app.example.com/maps/shared.js.map",
  ])
  expect(extractStaticJavaScriptEndpoints(source)).not.toContain("https://app.example.com/assets/app.js.map")
})

test("explicit-asset mode follows linked maps from legacy and versioned captures", () => {
  const assetURL = "https://app.example.com/assets/app.js"
  const mapRefs = collectExplicitJavaScriptSourceMapURLs(assetURL, [
    {
      // Legacy RequestTable bodies may include a response-processor metadata prefix.
      url: assetURL + "?cache=1",
      responseBody: "[Status: 200, Type: application/javascript, Size: 2 KB]\n//# sourceMappingURL=../maps/app.js.map?token=hidden",
    },
    {
      // A versioned capture of the same bundle is deduplicated with the legacy row.
      url: assetURL + "#fragment",
      responseBody: "//# sourceMappingURL=https://app.example.com/maps/app.js.map#other",
    },
    {
      url: "https://app.example.com/assets/other.js",
      responseBody: "//# sourceMappingURL=other.js.map",
    },
    {
      url: "https://unrelated.example.net/assets/app.js",
      responseBody: "//# sourceMappingURL=other.js.map",
    },
  ])

  expect(mapRefs).toEqual(["https://app.example.com/maps/app.js.map"])
})

test("parses captured version-3 source maps and analyzes embedded source contents without retaining source text", async () => {
  const { extractCapturedJavaScriptSources } = await import("../../src/target/javascript-correlation")
  const secret = "map-secret-must-not-leak-12345"
  const mapBody = JSON.stringify({
    version: 3,
    file: "app.js",
    sources: ["src/profile.ts", "src/render.ts"],
    sourcesContent: [
      'export async function loadProfile(profileId) { return fetch("/api/profiles/" + profileId) }',
      'function renderUser(value) { document.body.innerHTML = value }\nconst api_key = "' + secret + '";',
    ],
    names: [],
    mappings: "",
  })
  const files = extractCapturedJavaScriptSources([{
    id: "captured-map",
    url: "https://app.example.com/assets/app.js.map",
    responseContentType: "application/json",
    responseBody: mapBody,
  }])
  const map = files.find((file) => file.sourceMapSource === undefined)
  const profileSource = files.find((file) => file.sourceMapSource === "src/profile.ts")
  const renderSource = files.find((file) => file.sourceMapSource === "src/render.ts")
  expect(files).toHaveLength(3)
  expect(map).toMatchObject({
    sourceMapStatus: "analyzed",
    sourceMapVersion: 3,
    sourceMapSourceCount: 2,
    sourceMapEmbeddedSourceCount: 2,
    sourceMapSourcesContentAvailable: true,
  })
  expect(profileSource?.analysis?.requests.some((request) => request.path === "/api/profiles/{profileId}")).toBe(true)
  expect(renderSource?.analysis?.riskSignals.some((signal) => signal.kind === "dom-html-sink")).toBe(true)
  expect(JSON.stringify(files)).toContain("src/profile.ts")
  expect(JSON.stringify(files)).not.toContain(secret)
  expect(JSON.stringify(files)).not.toContain("document.body.innerHTML = value")
})

test("marks maps without embedded sources and malformed or truncated maps as incomplete", async () => {
  const { extractCapturedJavaScriptSources } = await import("../../src/target/javascript-correlation")
  const noContent = extractCapturedJavaScriptSources([{
    id: "map-no-content",
    url: "https://app.example.com/assets/no-content.js.map",
    responseContentType: "application/json",
    responseBody: JSON.stringify({ version: 3, sources: ["src/app.ts"], names: [], mappings: "" }),
  }])
  expect(noContent).toHaveLength(1)
  expect(noContent[0]?.sourceMapStatus).toBe("no-sources-content")
  expect(noContent[0]?.analysis?.notes.some((note) => note.includes("no non-empty sourcesContent"))).toBe(true)

  const partial = extractCapturedJavaScriptSources([{
    id: "map-partial",
    url: "https://app.example.com/assets/partial.js.map",
    responseContentType: "application/json",
    responseBody: JSON.stringify({
      version: 3,
      sources: ["src/missing.ts", "src/available.ts"],
      sourcesContent: [null, 'fetch("/api/available")', 'orphan source content must not count as a matched entry'],
      names: [],
      mappings: "",
    }),
  }])
  expect(partial[0]?.sourceMapStatus).toBe("partial-sources-content")
  expect(partial[0]?.sourceMapEmbeddedSourceCount).toBe(1)
  expect(partial).toHaveLength(2)
  expect(partial[1]?.sourceMapSource).toBe("src/available.ts")
  expect(JSON.stringify(partial)).not.toContain("orphan source content must not count as a matched entry")

  const malformed = extractCapturedJavaScriptSources([{
    id: "map-invalid",
    url: "https://app.example.com/assets/invalid.js.map",
    responseContentType: "application/json",
    responseBody: "{not-json",
  }])
  expect(malformed[0]?.sourceMapStatus).toBe("invalid-json")

  const truncated = extractCapturedJavaScriptSources([{
    id: "map-truncated",
    url: "https://app.example.com/assets/truncated.js.map",
    responseContentType: "application/json",
    responseBody: JSON.stringify({ version: 3, sources: ["src/app.ts"], sourcesContent: ['fetch("/api/from-map")'], names: [], mappings: "" }) + "\n[TRUNCATED - showing first 100KB of 1.2 MB]",
  }])
  expect(truncated[0]?.sourceMapStatus).toBe("truncated")
  expect(truncated[0]?.analysis?.notes.some((note) => note.startsWith("SOURCE MAP INCOMPLETE"))).toBe(true)
})

test("classifies JavaScript and source-map response variants for ingest-triggered correlation", () => {
  expect(isSourceMapResponse("application/json", "/assets/app.js.map")).toBe(true)
  expect(isSourceMapResponse("application/source-map+json", "/assets/app")).toBe(true)
  expect(isSourceMapResponse("text/x-source-map; charset=utf-8", "/assets/generated")).toBe(true)
  expect(isJavaScriptOrSourceMapResponse("application/javascript", "/assets/app")).toBe(true)
  expect(isJavaScriptOrSourceMapResponse("application/json", "/assets/app.js.map?version=2")).toBe(true)
  expect(isJavaScriptOrSourceMapResponse("application/json", "/api/profile")).toBe(false)
})

test("does not persist source-map JSON in generic response previews", () => {
  const preview = safeCorrelationResponsePreview({
    id: "map-preview",
    normalizedPath: "/assets/app.js.map",
    responseContentType: "application/json",
    processedResponse: JSON.stringify({ version: 3, sourcesContent: ["secret-like source payload"] }),
  })
  expect(preview).toContain("source-map response preview omitted")
  expect(preview).not.toContain("secret-like source payload")
})


test("inventories local .map and inline source maps and analyzes embedded sources without persisting source code", async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "cyberstrike-js-inventory-"))
  const javascriptDir = path.join(root, "javascript")
  const secret = "local-source-map-secret-must-not-leak"
  const mappedSource = 'export async function getTeam(teamId) { return fetch("/api/teams/" + teamId) }\nconst api_key = "' + secret + '";'
  const mapBody = JSON.stringify({
    version: 3,
    file: "bundle.js",
    sources: ["src/team.ts"],
    sourcesContent: [mappedSource],
    names: [],
    mappings: "",
  })
  const inlineSource = 'function getBilling() { return fetch("/api/billing") }'
  const inlineMap = JSON.stringify({
    version: 3,
    sources: ["src/inline.ts"],
    sourcesContent: [inlineSource],
    names: [],
    mappings: "",
  })
  const inlineDataUrl = "data:application/json;base64," + Buffer.from(inlineMap).toString("base64")
  try {
    await fs.mkdir(javascriptDir, { recursive: true })
    await fs.writeFile(path.join(javascriptDir, "bundle.js.map"), mapBody)
    await fs.writeFile(path.join(javascriptDir, "inline.js"), "//# sourceMappingURL=" + inlineDataUrl)
    await fs.writeFile(path.join(javascriptDir, "notes.txt"), "fetch('/api/should-not-be-scanned')")
    const files = await inventoryJavaScriptFiles(javascriptDir)
    const externalSource = files.find((file) => file.sourceMapSource === "src/team.ts")
    const embeddedInlineSource = files.find((file) => file.sourceMapSource === "src/inline.ts")
    expect(files.some((file) => file.sourceMapStatus === "analyzed")).toBe(true)
    expect(externalSource?.analysis?.requests.some((request) => request.path === "/api/teams/{teamId}")).toBe(true)
    expect(embeddedInlineSource?.analysis?.requests.some((request) => request.path === "/api/billing")).toBe(true)
    expect(files.some((file) => file.basename === "notes.txt")).toBe(false)
    expect(JSON.stringify(files)).not.toContain(secret)
    expect(JSON.stringify(files)).not.toContain(mappedSource)
    expect(JSON.stringify(files)).not.toContain(inlineSource)
  } finally {
    await fs.rm(root, { recursive: true, force: true })
  }
})


test("redacts legacy raw secret values when sanitizing an old graph artifact", () => {
  const secret = "legacy-cache-secret-value-must-not-survive"
  const legacyFile = {
    relativePath: "captured/app.js",
    basename: "app.js",
    sha256: "legacy-digest",
    bytes: 42,
    endpointLiterals: [],
    analysis: {
      functions: [],
      requests: [],
      secretCandidates: [{
        kind: "api-key",
        line: 1,
        value: secret,
        fingerprint: "0123456789abcdefabcd",
        confidence: "candidate",
      }],
      roleHints: [],
      riskSignals: [],
      notes: ["Exact candidate values are available for target-local evidence; a static match remains unverified until independently validated."],
    },
  } as unknown as JavaScriptSourceFile

  const sanitized = sanitizeJavaScriptSourceFileForPersistence(legacyFile)
  expect(JSON.stringify(sanitized)).not.toContain(secret)
  expect(sanitized.analysis?.secretCandidates[0]).toEqual({
    kind: "api-key",
    line: 1,
    fingerprint: "0123456789abcdefabcd",
    confidence: "candidate",
  })
  expect(JSON.stringify(sanitized)).not.toContain("Exact candidate values are available")
})


test("retains separately hosted JavaScript as a scope-check candidate, while explicit-URL mode stays narrow", () => {
  const candidates = [
    { url: new URL("https://app.example.test/assets/main.js"), tag: "app" },
    { url: new URL("https://static.cdn-example.net/chunks/vendor.js"), tag: "cdn" },
    { url: new URL("https://api.example.test/assets/client.mjs"), tag: "api" },
  ]
  expect(selectJavaScriptAssetsForCorrelation(candidates).map((item) => item.tag)).toEqual(["app", "cdn", "api"])
  expect(selectJavaScriptAssetsForCorrelation(candidates, new URL("https://static.cdn-example.net/chunks/vendor.js?cache=2")).map((item) => item.tag)).toEqual(["cdn"])
})


test("end-to-end correlation persists map-derived endpoints and links them to captured request evidence", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    async fn() {
      try {
        const targetURL = "https://app.example.test"
        await TargetMemory.configureScope(targetURL, {
          include: ["app.example.test"],
          authorizationSource: "JavaScript correlation integration fixture",
          authorizationReference: "https://example.test/security",
        })
        const session = await Session.create({})
        const addCapturedResponse = (input: {
          keyHash: string
          urlPath: string
          contentType: string
          body: string
        }) => Request.add({
          sessionID: session.id,
          method: "GET",
          normalizedPath: input.urlPath,
          keyHash: input.keyHash,
          origin: targetURL,
          scheme: "https",
          host: "app.example.test",
          pageUrl: targetURL + "/",
          response: {
            status: 200,
            headers: { "content-type": input.contentType },
            body: input.body,
          },
        })

        const bundleURL = targetURL + "/assets/app.js"
        const sourceMapURL = targetURL + "/assets/app.js.map"
        const rawSecret = "map-derived-secret-must-not-persist"
        const mapBody = JSON.stringify({
          version: 3,
          file: "app.js",
          sources: ["src/profile.ts", "src/render.ts"],
          sourcesContent: [
            'export async function loadProfile(profileId) { return fetch("/api/profiles/" + profileId) }',
            'export function renderProfile(value) { document.body.innerHTML = value }\nconst api_key = "' + rawSecret + '";',
          ],
          names: [],
          mappings: "",
        })

        expect(addCapturedResponse({
          keyHash: "js-bundle",
          urlPath: "/assets/app.js",
          contentType: "application/javascript",
          body: "//# sourceMappingURL=app.js.map",
        })).toBeDefined()
        expect(addCapturedResponse({
          keyHash: "js-source-map",
          urlPath: "/assets/app.js.map",
          contentType: "application/json",
          body: mapBody,
        })).toBeDefined()
        const apiRequest = addCapturedResponse({
          keyHash: "api-profile",
          urlPath: "/api/profiles/42",
          contentType: "application/json",
          body: JSON.stringify({ id: 42, name: "test-profile" }),
        })
        expect(apiRequest).toBeDefined()

        const result = await JavaScriptCorrelation.build({
          sessionID: session.id,
          targetURL,
          javascriptURL: bundleURL,
        })

        const diskGraph = JSON.parse(await fs.readFile(result.graphPath, "utf-8"))
        const endpointInventory = JSON.parse(await fs.readFile(result.endpointPath, "utf-8"))
        const testerSurvey = JSON.parse(await fs.readFile(result.testerSurveyPath, "utf-8"))
        const mapReference = result.graph.sourceMapReferences?.find((item) => item.url === sourceMapURL)
        const mappedProfile = result.graph.sourceFiles.find((file) => file.sourceMapSource === "src/profile.ts")
        const mappedRender = result.graph.sourceFiles.find((file) => file.sourceMapSource === "src/render.ts")
        const profileCandidate = result.graph.javascriptAnalysis.requestCandidates.find((item) =>
          item.path.startsWith("/api/profiles/") && item.pathParameters.length > 0,
        )
        const observedEndpoint = result.graph.endpointCandidates.find((item) =>
          item.path.startsWith("/api/profiles/") && item.observedRequestIDs.includes(apiRequest!.id),
        )

        expect(result.graph.javascriptAssets.map((asset) => asset.url)).toContain(bundleURL)
        expect(mapReference).toMatchObject({ status: "analyzed", url: sourceMapURL })
        expect(mappedProfile?.analysis?.functions.some((fn) => fn.name === "loadProfile")).toBe(true)
        expect(mappedProfile?.analysis?.requests.some((request) => request.path.startsWith("/api/profiles/") && request.pathParameters.length > 0)).toBe(true)
        expect(mappedRender?.analysis?.riskSignals.some((signal) => signal.kind === "dom-html-sink")).toBe(true)
        expect(profileCandidate?.observedRequestIDs).toContain(apiRequest!.id)
        expect(observedEndpoint?.observedInTraffic).toBe(true)
        expect(result.graph.edges.some((edge) => edge.to === "request:" + apiRequest!.id && edge.relation === "static-endpoint-path-overlap")).toBe(true)
        expect(result.graph.evidence.some((item) => item.requestID === apiRequest!.id)).toBe(true)
        expect(diskGraph.sourceMapReferences.find((item: { url: string }) => item.url === sourceMapURL).status).toBe("analyzed")
        expect(endpointInventory.endpoints.some((item: { path: string }) => item.path.startsWith("/api/profiles/"))).toBe(true)
        expect(testerSurvey.cases.some((item: { path: string }) => item.path.startsWith("/api/profiles/"))).toBe(true)
        for (const artifact of [JSON.stringify(diskGraph), JSON.stringify(endpointInventory), JSON.stringify(testerSurvey)]) {
          expect(artifact).not.toContain(rawSecret)
          expect(artifact).not.toContain("document.body.innerHTML = value")
        }
      } finally {
        await Instance.dispose()
      }
    },
  })
})
