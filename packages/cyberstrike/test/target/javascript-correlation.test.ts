import { expect, test } from "bun:test"
import { correlateStaticJavaScriptEndpoints, createJavaScriptTesterCases, extractStaticJavaScriptEndpoints, isJavaScriptAssetAllowed, matchesCapturedJavaScriptAsset, matchesEndpointPathTemplate, mergeStructuredJavaScriptEndpoints, safeCorrelationResponsePreview, sanitizeJavaScriptSourceFileForPersistence } from "../../src/target/javascript-correlation"

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
    }),
  })
  expect(preview).toContain("[REDACTED]")
  for (const secret of secretValues) expect(preview).not.toContain(secret)
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
  expect(sources).toHaveLength(1)
  expect(sources[0]?.endpointLiterals).toContain("/api/users")
  expect(sources[0]?.endpointLiterals).toContain("/api/orders/{param}")
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
