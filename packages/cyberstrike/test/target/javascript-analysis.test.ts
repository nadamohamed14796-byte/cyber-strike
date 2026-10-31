import { expect, test } from "bun:test"
import { analyzeJavaScriptSource } from "../../src/target/javascript-analysis"

test("flags sensitive data fields and embedded email literals without retaining values", () => {
  const source = [
    'const profile = { email: "private.person@example.test", phoneNumber: "+15555550123", dateOfBirth: "1990-01-01" }',
    'function renderProfile(data) { return data.email + data.phoneNumber }',
  ].join("\n")
  const result = analyzeJavaScriptSource(source)
  expect(result.dataExposureSignals?.map((item) => item.kind)).toContain("sensitive-field")
  expect(result.dataExposureSignals?.some((item) => item.kind === "sensitive-field" && item.field === "dateofbirth")).toBe(true)
  expect(result.dataExposureSignals?.some((item) => item.kind === "embedded-email-address")).toBe(true)
  const serialized = JSON.stringify(result)
  expect(serialized).not.toContain("private.person@example.test")
  expect(serialized).not.toContain("+15555550123")
  expect(serialized).not.toContain("1990-01-01")
})

test("attributes application and authorization hints to their containing functions", () => {
  const source = [
    'function exportReport() {',
    '  const action = "export";',
    '  return fetch("/api/reports/export");',
    '}',
    'function adminDashboard() {',
    '  if (isAdmin) return fetch("/api/admin/dashboard");',
    '}',
  ].join("\n")
  const result = analyzeJavaScriptSource(source)
  expect(result.applicationHints?.find((item) => item.kind === "business-workflow" && item.value === "export")?.functionName).toBe("exportReport")
  expect(result.roleHints.find((item) => item.kind === "admin-role-hint")?.functionName).toBe("adminDashboard")
})

test("attributes secret candidates to their enclosing function and detects known token formats", () => {
  const awsKey = "AKIA1234567890ABCDEF"
  const genericToken = "ghp_" + "A".repeat(36)
  const source = [
    "async function rotateCredential(accountId) {",
    '  const config = { value: "' + awsKey + '" }',
    '  const token = "' + genericToken + '"',
    '  return fetch("/api/accounts/" + accountId + "/rotate", { method: "POST" })',
    "}",
  ].join("\n")
  const result = analyzeJavaScriptSource(source)
  const awsCandidate = result.secretCandidates.find((item) => item.kind === "aws-access-key-id")
  const githubCandidate = result.secretCandidates.find((item) => item.kind === "github-token")
  expect(awsCandidate?.functionName).toBe("rotateCredential")
  expect(githubCandidate?.functionName).toBe("rotateCredential")
  expect(awsCandidate?.fingerprint).toMatch(/^[a-f0-9]{20}$/)
  expect(JSON.stringify(result)).not.toContain(awsKey)
  expect(JSON.stringify(result)).not.toContain(genericToken)
})

test("preserves repeated token occurrences across distinct functions", () => {
  const sharedKey = "AKIA1234567890ABCDEF"
  const source = [
    "function rotateCredential() {",
    '  const config = { value: "' + sharedKey + '" }',
    "}",
    "function refreshCredential() {",
    '  const config = { value: "' + sharedKey + '" }',
    "}",
  ].join("\n")
  const result = analyzeJavaScriptSource(source)
  const occurrences = result.secretCandidates.filter((item) => item.kind === "aws-access-key-id")
  expect(occurrences).toHaveLength(2)
  expect(occurrences.map((item) => ({ line: item.line, functionName: item.functionName }))).toEqual([
    { line: 2, functionName: "rotateCredential" },
    { line: 5, functionName: "refreshCredential" },
  ])
  expect(JSON.stringify(result)).not.toContain(sharedKey)
})

test("extracts named functions and parameters", () => {
  const source = [
    "async function getInvoice(invoiceId, includeItems = false) {",
    ' return fetch("/api/invoices/" + invoiceId)',
    "}",
    "const updateProfile = async (profileId, data) => axios.patch('/api/profile/' + profileId, {",
    ' headers: { Authorization: getToken(), "X-Trace": "test" },',
    " body: JSON.stringify({ displayName: data.name, locale: data.locale })",
    "})",
  ].join("\n")
  const result = analyzeJavaScriptSource(source)
  expect(result.functions.map((item) => item.name)).toContain("getInvoice")
  expect(result.functions.find((item) => item.name === "getInvoice")?.parameters).toEqual(["invoiceId", "includeItems"])
  expect(result.functions.map((item) => item.name)).toContain("updateProfile")
})

test("extracts parameters and auth clues without retaining header values", () => {
  const tick = String.fromCharCode(96)
  const source = [
    "async function loadUser(userId) {",
    ' return fetch(' + tick + "/api/users/$" + "{userId}?view=private&expand=profile" + tick + ', {',
    ' method: "GET",',
    ' headers: { Authorization: "Bearer should-not-persist", "X-API-Key": "not-a-real-key" },',
    ' credentials: "include"',
    " })",
    "}",
  ].join("\n")
  const result = analyzeJavaScriptSource(source)
  const request = result.requests[0]!
  expect(request.method).toBe("GET")
  expect(request.path).toBe("/api/users/{userId}")
  expect(request.pathParameters).toContain("userId")
  expect(request.queryParameters).toEqual(["view", "expand"])
  expect(request.headerNames).toContain("Authorization")
  expect(request.headerNames).toContain("X-API-Key")
  expect(request.authSignals).toContain("authorization-header")
  expect(request.cookieSignals).toContain("credentialed-request-may-send-cookies")
  expect(JSON.stringify(result)).not.toContain("should-not-persist")
  expect(JSON.stringify(result)).not.toContain("not-a-real-key")
})

test("extracts XHR headers and URLSearchParams prepared within the calling function", () => {
  const source = [
    'function loadRecords() {',
    '  const xhr = new XMLHttpRequest()',
    '  const params = new URLSearchParams()',
    '  params.append("page", currentPage)',
    '  params.append("filter", activeFilter)',
    '  xhr.open("GET", "/api/records")',
    '  xhr.setRequestHeader("X-CSRF-Token", csrfToken)',
    '  xhr.setRequestHeader("X-Tenant-ID", tenantId)',
    '  xhr.send()',
    '}',
  ].join("\n")
  const request = analyzeJavaScriptSource(source).requests[0]!
  expect(request.method).toBe("GET")
  expect(request.sourceFunction).toBe("loadRecords")
  expect(request.queryParameters).toContain("page")
  expect(request.queryParameters).toContain("filter")
  expect(request.headerNames).toContain("X-CSRF-Token")
  expect(request.headerNames).toContain("X-Tenant-ID")
  expect(JSON.stringify(request)).not.toContain("csrfToken")
  expect(JSON.stringify(request)).not.toContain("tenantId")
})

test("does not attribute headers or auth signals from a neighboring request", () => {
  const source = [
    'function loadBoth() {',
    '  fetch("/api/private", { headers: { Authorization: privateToken } })',
    '  fetch("/api/public")',
    '}',
  ].join("\n")
  const requests = analyzeJavaScriptSource(source).requests
  const privateRequest = requests.find((item) => item.path === "/api/private")!
  const publicRequest = requests.find((item) => item.path === "/api/public")!
  expect(privateRequest.headerNames).toContain("Authorization")
  expect(privateRequest.authSignals).toContain("authorization-header")
  expect(publicRequest.headerNames).not.toContain("Authorization")
  expect(publicRequest.authSignals).not.toContain("authorization-header")
})

test("extracts XHR headers and query keys from a named URLSearchParams variable", () => {
  const source = [
    'function loadRecords() {',
    '  const xhr = new XMLHttpRequest()',
    '  const params = new URLSearchParams()',
    '  params.append("page", currentPage)',
    '  params.append("filter", activeFilter)',
    '  xhr.open("GET", "/api/records")',
    '  xhr.setRequestHeader("X-CSRF-Token", csrfToken)',
    '  xhr.setRequestHeader("X-Tenant-ID", tenantId)',
    '  xhr.send()',
    '}',
  ].join("\n")
  const request = analyzeJavaScriptSource(source).requests[0]!
  expect(request.method).toBe("GET")
  expect(request.sourceFunction).toBe("loadRecords")
  expect(request.queryParameters).toContain("page")
  expect(request.queryParameters).toContain("filter")
  expect(request.headerNames).toContain("X-CSRF-Token")
  expect(request.headerNames).toContain("X-Tenant-ID")
  expect(JSON.stringify(request)).not.toContain("csrfToken")
  expect(JSON.stringify(request)).not.toContain("tenantId")
})

test("preserves explicit scheme and port in absolute request candidates", () => {
  const request = analyzeJavaScriptSource('fetch("http://api.example.com:8080/v2/profile")').requests[0]!
  expect(request.urlTemplate).toBe("http://api.example.com:8080/v2/profile")
  expect(request.origin).toBe("http://api.example.com:8080")
})

test("extracts axios methods and request body field names", () => {
  const result = analyzeJavaScriptSource('axios.post("/api/items", { title: "demo", visibility: "private" })')
  expect(result.requests[0]?.method).toBe("POST")
  expect(result.requests[0]?.path).toBe("/api/items")
  expect(result.requests[0]?.bodyParameters).toContain("title")
  expect(result.requests[0]?.bodyParameters).toContain("visibility")
})

test("handles custom API clients and concatenated path parameters", () => {
  const source = [
    'async function getInvoice(invoiceId) {',
    ' return api.get("/api/invoices/" + invoiceId + "/items", { headers: { "X-Client": "web" } })',
    '}',
    'const createUser = (userId, input) => client.post("/api/users/" + userId, { displayName: input.name, active: true }, { headers: { "X-Trace": "trace" } })',
  ].join("\n")
  const result = analyzeJavaScriptSource(source)
  const get = result.requests.find((request) => request.method === "GET")
  const post = result.requests.find((request) => request.method === "POST")
  expect(get?.path).toBe("/api/invoices/{invoiceId}/items")
  expect(get?.pathParameters).toContain("invoiceId")
  expect(get?.headerNames).toContain("X-Client")
  expect(post?.path).toBe("/api/users/{userId}")
  expect(post?.pathParameters).toContain("userId")
  expect(post?.bodyParameters).toContain("displayName")
  expect(post?.bodyParameters).toContain("active")
  expect(post?.headerNames).toContain("X-Trace")
})

test("extracts class methods, single-argument arrows, and separates query from path variables", () => {
  const tick = String.fromCharCode(96)
  const source = [
    "class InvoiceService {",
    " async listInvoices(accountId, limit = 20) {",
    '  return this.api.get(' + tick + "/api/accounts/$" + "{accountId}/invoices?limit=$" + "{limit}" + tick + ', { headers: { "X-Client": "web" } })',
    " }",
    "}",
    "const findInvoice = async invoiceId => fetch(" + tick + "/api/invoices/$" + "{invoiceId}" + tick + ")",
  ].join("\n")
  const result = analyzeJavaScriptSource(source)
  expect(result.functions.find((item) => item.name === "listInvoices")?.parameters).toEqual(["accountId", "limit"])
  expect(result.functions.find((item) => item.name === "findInvoice")?.parameters).toEqual(["invoiceId"])
  const request = result.requests.find((item) => item.path.startsWith("/api/accounts/"))
  expect(request?.path).toBe("/api/accounts/{accountId}/invoices")
  expect(request?.pathParameters).toEqual(["accountId"])
  expect(request?.queryParameters).toContain("limit")
})

test("flags dangerous JavaScript sinks for manual review without claiming a vulnerability", () => {
  const source = [
    "function renderCard(userHtml) {",
    " document.querySelector('#card').innerHTML = userHtml",
    "}",
    "function runDynamicCode(input) {",
    " return eval(input)",
    "}",
    "function notifyParent(payload) {",
    " window.parent.postMessage(payload, '*')",
    "}",
  ].join("\n")
  const result = analyzeJavaScriptSource(source)
  expect(result.riskSignals.some((signal) => signal.kind === "dom-html-sink" && signal.functionName === "renderCard")).toBe(true)
  expect(result.riskSignals.some((signal) => signal.kind === "dynamic-code-execution" && signal.functionName === "runDynamicCode")).toBe(true)
  expect(result.riskSignals.some((signal) => signal.kind === "cross-window-message" && signal.functionName === "notifyParent")).toBe(true)
  expect(result.riskSignals.every((signal) => signal.confidence === "candidate")).toBe(true)
  expect(JSON.stringify(result)).not.toContain("document.querySelector")
  expect(JSON.stringify(result)).not.toContain("innerHTML = userHtml")
})

test("keeps concatenated query values out of the inferred path and defaults fetch to GET", () => {
  const source = [
    'const search = (term) => fetch("/api/search?q=" + encodeURIComponent(term))',
    'const byId = (id) => fetch("/api/items/" + id)',
  ].join("\n")
  const result = analyzeJavaScriptSource(source)
  const search = result.requests.find((request) => request.path === "/api/search")
  const item = result.requests.find((request) => request.path === "/api/items/{id}")
  expect(search?.method).toBe("GET")
  expect(search?.pathParameters).toEqual([])
  expect(search?.queryParameters).toContain("q")
  expect(item?.pathParameters).toContain("id")
})

test("does not guess GET when fetch method is dynamic", () => {
  const source = [
    "const method = isWrite ? 'POST' : 'GET'",
    'fetch("/api/items", { method })',
  ].join("\n")
  const request = analyzeJavaScriptSource(source).requests[0]
  expect(request?.method).toBe(null)
})

test("normalizes static numeric and UUID path values to placeholders", () => {
  const source = [
    'fetch("/api/users/12345")',
    'fetch("/api/invoices/550e8400-e29b-41d4-a716-446655440000")',
    'fetch("/api/items/00000000-0000-0000-0000-000000000000")',
  ].join("\n")
  const result = analyzeJavaScriptSource(source)
  expect(result.requests.find((item) => item.path.includes("/api/users/"))?.path).toBe("/api/users/{id}")
  expect(result.requests.find((item) => item.path.includes("/api/invoices/"))?.path).toBe("/api/invoices/{uuid}")
  expect(result.requests.find((item) => item.path.includes("/api/items/"))?.path).toBe("/api/items/{uuid}")
  expect(result.requests.some((item) => item.pathParameters.includes("id"))).toBe(true)
  expect(result.requests.some((item) => item.pathParameters.includes("uuid"))).toBe(true)
  expect(JSON.stringify(result)).not.toContain("12345")
  expect(JSON.stringify(result)).not.toContain("550e8400-e29b-41d4-a716-446655440000")
  expect(JSON.stringify(result)).not.toContain("00000000-0000-0000-0000-000000000000")
})

test("extracts fetch body keys without misclassifying request options", () => {
  const source = [
    'fetch("/api/profile", {',
    ' method: "POST",',
    ' headers: { "Content-Type": "application/json" },',
    ' body: JSON.stringify({ displayName: "Ada", role: "member" })',
    "})",
  ].join("\n")
  const result = analyzeJavaScriptSource(source)
  const request = result.requests[0]!
  expect(request.method).toBe("POST")
  expect(request.bodyParameters).toContain("displayName")
  expect(request.bodyParameters).toContain("role")
  expect(request.bodyParameters).not.toContain("method")
  expect(request.bodyParameters).not.toContain("headers")
  expect(request.bodyParameters).not.toContain("body")
  expect(request.bodyParameters).not.toContain("Content-Type")
  expect(request.contentTypes).toEqual(["application/json"])
})

test("flags browser token storage, cookie writes, and wildcard postMessage as candidates", () => {
  const source = [
    "function persistToken(token) {",
    ' localStorage.setItem("access_token", token)',
    "}",
    "function writeCookie(value) {",
    " document.cookie = value",
    "}",
    "function sendToParent(payload) {",
    ' window.parent.postMessage(payload, "*")',
    "}",
  ].join("\n")
  const result = analyzeJavaScriptSource(source)
  expect(result.riskSignals.some((signal) => signal.kind === "client-side-token-storage")).toBe(true)
  expect(result.riskSignals.some((signal) => signal.kind === "document-cookie-write")).toBe(true)
  expect(result.riskSignals.some((signal) => signal.kind === "wildcard-postmessage-origin")).toBe(true)
  expect(result.riskSignals.every((signal) => signal.confidence === "candidate")).toBe(true)
  expect(JSON.stringify(result)).not.toContain("access_token")
})

test("resolves variable-backed query, headers, and body objects", () => {
  const source = [
    'const query = { page: 2, status: "active" }',
    'const headers = { Authorization: authToken, "X-Tenant-ID": tenantId }',
    'const payload = { displayName: user.name, locale: "en", role: "member" }',
    'client.post("/api/records", payload, { params: query, headers })',
  ].join("\n")
  const request = analyzeJavaScriptSource(source).requests[0]!
  expect(request.queryParameters).toContain("page")
  expect(request.queryParameters).toContain("status")
  expect(request.headerNames).toContain("Authorization")
  expect(request.headerNames).toContain("X-Tenant-ID")
  expect(request.bodyParameters).toContain("displayName")
  expect(request.bodyParameters).toContain("locale")
  expect(request.bodyParameters).toContain("role")
  expect(JSON.stringify(request)).not.toContain("authToken")
  expect(JSON.stringify(request)).not.toContain("tenantId")
  expect(JSON.stringify(request)).not.toContain("member")
})

test("does not assign a top-level request to a function whose body already ended", () => {
  const source = [
    'function first() { fetch("/api/first") }',
    'const outside = fetch("/api/outside")',
    'const second = () => { fetch("/api/second") }',
  ].join("\n")
  const requests = analyzeJavaScriptSource(source).requests
  expect(requests.find((item) => item.path === "/api/first")?.sourceFunction).toBe("first")
  expect(requests.find((item) => item.path === "/api/outside")?.sourceFunction).toBe(null)
  expect(requests.find((item) => item.path === "/api/second")?.sourceFunction).toBe("second")
})

test("retains target-local hard-coded secret evidence with a fingerprint and candidate status", () => {
  const secret = "secret-value-must-never-be-retained"
  const result = analyzeJavaScriptSource('const config = { api_key: "' + secret + '" }')
  expect(result.secretCandidates).toHaveLength(1)
  expect(result.secretCandidates[0]).toMatchObject({
    kind: "api-key",
    confidence: "candidate",
  })
  expect(result.secretCandidates[0]?.fingerprint).toMatch(/^[a-f0-9]{20}$/)
  expect(JSON.stringify(result)).not.toContain(secret)
})

test("records roles and hidden-feature hints as candidates", () => {
  const source = ['if (isAdmin) fetch("/api/admin/reports")', 'if (featureFlag) fetch("/api/beta/exports")', "const debugMode = true"].join("\n")
  const result = analyzeJavaScriptSource(source)
  expect(result.roleHints.some((hint) => hint.kind === "admin-role-hint")).toBe(true)
  expect(result.roleHints.some((hint) => hint.kind === "feature-flag-hint")).toBe(true)
  expect(result.roleHints.some((hint) => hint.kind === "debug-path-hint")).toBe(true)
  expect(result.requests.some((request) => request.path === "/api/admin/reports")).toBe(true)
})

test("retains only a secret fingerprint and source location, never the literal value", () => {
  const secret = "personal-test-token-value-12345";
  const source = 'const api_key = "' + secret + '";';
  const result = analyzeJavaScriptSource(source);
  expect(result.secretCandidates).toHaveLength(1);
  expect(result.secretCandidates[0]).toMatchObject({
    kind: "api-key",
    line: 1,
    confidence: "candidate",
  });
  expect(result.secretCandidates[0]?.fingerprint).toMatch(/^[a-f0-9]{20}$/);
  expect(JSON.stringify(result)).not.toContain(secret);
});


test("does not attribute top-level risk sinks to the previously closed function", () => {
  const source = [
    "function renderCard() {",
    '  document.body.innerHTML = "<p>card</p>"',
    "}",
    'document.body.innerHTML = "<p>top-level</p>"',
  ].join("\n")
  const signals = analyzeJavaScriptSource(source).riskSignals.filter((signal) => signal.kind === "dom-html-sink")
  expect(signals).toHaveLength(2)
  expect(signals.find((signal) => signal.functionName === "renderCard")).toBeDefined()
  expect(signals.find((signal) => signal.functionName === null)).toBeDefined()
})


test("extracts more than 300 JavaScript request candidates", () => {
  const source = Array.from({ length: 350 }, (_, index) =>
    'fetch("/api/v1/resources/item-' + index + '")',
  ).join("\n")
  const result = analyzeJavaScriptSource(source)
  expect(result.requests).toHaveLength(350)
  expect(result.requests.some((request) => request.path === "/api/v1/resources/item-349")).toBe(true)
})


test("analyzes a route found after the former 1 MB source boundary", () => {
  const source = " ".repeat(1_000_050) + 'fetch("/api/v1/after-size-cap")'
  const result = analyzeJavaScriptSource(source)
  expect(result.requests.some((request) => request.path === "/api/v1/after-size-cap")).toBe(true)
})


test("extracts validated request content types from fetch, axios, and config-object calls", () => {
  const source = [
    'fetch("/api/import", { method: "POST", headers: { "Content-Type": "Application/JSON; charset=utf-8" }, body: "{}" })',
    'axios.post("/api/export", payload, { headers: { "content-type": "text/csv; charset=utf-8" } })',
    'client.request({ url: "/api/data", method: "POST", headers: { "Content-Type": "application/vnd.api+json" } })',
  ].join("\n")
  const result = analyzeJavaScriptSource(source)
  expect(result.requests.find((request) => request.path === "/api/import")?.contentTypes).toEqual(["application/json"])
  expect(result.requests.find((request) => request.path === "/api/export")?.contentTypes).toEqual(["text/csv"])
  expect(result.requests.find((request) => request.path === "/api/data")?.contentTypes).toEqual(["application/vnd.api+json"])
  expect(result.requests.every((request) => request.confidence === "candidate")).toBe(true)
})
 
test("extracts request metadata from dollar-prefixed JavaScript identifiers", () => {
  const source = [
    "async function loadItems() {",
    '  const $params = new URLSearchParams()',
    '  $params.append("page", currentPage)',
    '  const $body = { displayName: profileName, active: true }',
    '  return fetch("/api/items", { method: "POST", body: JSON.stringify($body) })',
    "}",
  ].join("\n")
  const request = analyzeJavaScriptSource(source).requests[0]!
  expect(request.queryParameters).toContain("page")
  expect(request.bodyParameters).toContain("displayName")
  expect(request.bodyParameters).toContain("active")
})


test("flags credentialed state-changing requests as CSRF review candidates, not findings", () => {
  const source = [
    "async function updateEmail(email) {",
    '  return fetch("/api/profile/email", {',
    '    method: "POST",',
    '    credentials: "include",',
    '    headers: { "Content-Type": "application/json" },',
    '    body: JSON.stringify({ email })',
    "  })",
    "}",
    'fetch("/api/profile", { credentials: "include" })',
  ].join("\n")
  const result = analyzeJavaScriptSource(source)
  const post = result.requests.find((request) => request.path === "/api/profile/email")
  const get = result.requests.find((request) => request.path === "/api/profile")

  expect(post?.method).toBe("POST")
  expect(post?.sourceFunction).toBe("updateEmail")
  expect(post?.bodyParameters).toContain("email")
  expect(post?.cookieSignals).toContain("credentialed-request-may-send-cookies")
  expect(result.riskSignals.some((signal) =>
    signal.kind === "csrf-review-state-changing-cookie-request" && signal.functionName === "updateEmail",
  )).toBe(true)
  expect(result.riskSignals.some((signal) =>
    signal.kind === "csrf-review-state-changing-cookie-request" && signal.line === get?.sourceLine,
  )).toBe(false)
  expect(result.riskSignals.every((signal) => signal.confidence === "candidate")).toBe(true)
  expect(get?.method).toBe("GET")
  expect(result.notes.some((note) => note.includes("do not prove the server lacks anti-CSRF controls"))).toBe(true)
})

test("considers implicit same-origin cookie context for CSRF review but honors fetch credentials omit", () => {
  const source = [
    'fetch("/api/account/email", { method: "POST", body: JSON.stringify({ email }) })',
    'fetch("/api/account/logout", { method: "POST", credentials: "omit" })',
  ].join("\n")
  const result = analyzeJavaScriptSource(source)
  const update = result.requests.find((request) => request.path === "/api/account/email")
  const logout = result.requests.find((request) => request.path === "/api/account/logout")
  expect(update?.cookieSignals).toContain("relative-route-may-use-same-origin-cookies")
  expect(result.riskSignals.some((signal) =>
    signal.kind === "csrf-review-state-changing-cookie-request" && signal.line === update?.sourceLine,
  )).toBe(true)
  expect(logout?.cookieSignals).not.toContain("relative-route-may-use-same-origin-cookies")
  expect(result.riskSignals.some((signal) =>
    signal.kind === "csrf-review-state-changing-cookie-request" && signal.line === logout?.sourceLine,
  )).toBe(false)
})

test("collects broad application-intelligence hints beyond vulnerability patterns", () => {
  const source = [
    'const operation = "mutation UpdateBillingPlan { updatePlan { id } }"',
    'const apiBase = import.meta.env.VITE_API_BASE',
    'const socket = new WebSocket("wss://events.example.test/socket")',
    'navigator.serviceWorker.register("/service-worker.js")',
    'localStorage.setItem("workspace", currentWorkspace)',
    'const report = Sentry.captureException(error)',
    'async function exportInvoice(invoiceId) { return fetch("/api/invoices/" + invoiceId + "/export") }',
  ].join("\n")
  const result = analyzeJavaScriptSource(source)
  const hints = result.applicationHints ?? []
  expect(hints.some((item) => item.kind === "graphql-operation" && item.value === "UpdateBillingPlan")).toBe(true)
  expect(hints.some((item) => item.kind === "environment-config" && item.value === "VITE_API_BASE")).toBe(true)
  expect(hints.some((item) => item.kind === "websocket-client")).toBe(true)
  expect(hints.some((item) => item.kind === "service-worker")).toBe(true)
  expect(hints.some((item) => item.kind === "browser-persistence")).toBe(true)
  expect(hints.some((item) => item.kind === "telemetry-monitoring-sdk")).toBe(true)
  expect(hints.some((item) => item.kind === "business-workflow" && item.value.toLowerCase() === "export")).toBe(true)
  expect(hints.every((item) => item.confidence === "candidate")).toBe(true)
})

test("builds actionable email-verification, token, and SQL/data-operation traces with call sites", () => {
  const source = [
    'async function sendVerificationEmail(email) {',
    '  return fetch("/api/auth/email/send-verification", { method: "POST", body: JSON.stringify({ email }) })',
    '}',
    'async function verifyEmailToken(token) {',
    '  const claims = decodeJwt(token)',
    '  return fetch("/api/auth/email/verify", { method: "POST", body: JSON.stringify({ token }) })',
    '}',
    'const verifyButton = <button onClick={verifyEmailToken}>Verify</button>',
    'function runEmailVerification(token) {',
    '  return verifyEmailToken(token)',
    '}',
    'function findAccount(accountId) {',
    '  return db.$queryRaw("SELECT id FROM accounts WHERE id = ?")',
    '}',
    'function issueSessionToken(claims) {',
    '  return jwt.sign(claims, signingKey, { expiresIn: "5m" })',
    '}',
    'function validateSessionToken(token) {',
    '  return jwt.verify(token, publicKey)',
    '}',
  ].join("\n")
  const result = analyzeJavaScriptSource(source)
  const signal = (kind: string, functionName: string) => result.workflowSignals?.some((item) =>
    item.kind === kind && item.functionName === functionName,
  )

  expect(signal("email-verification-flow", "verifyEmailToken")).toBe(true)
  expect(signal("token-decode-or-parse", "verifyEmailToken")).toBe(true)
  expect(signal("sql-statement-candidate", "findAccount")).toBe(true)
  expect(signal("data-layer-operation-candidate", "findAccount")).toBe(true)
  expect(signal("token-creation-or-signing", "issueSessionToken")).toBe(true)
  expect(signal("token-expiry-or-lifetime", "issueSessionToken")).toBe(true)
  expect(signal("token-verification-or-validation", "validateSessionToken")).toBe(true)

  const verify = result.functions.find((item) => item.name === "verifyEmailToken")
  expect(verify?.parameters).toContain("token")
  expect(verify?.callSites?.some((item) => item.kind === "ui-event-binding" && item.line === 8)).toBe(true)
  expect(verify?.callSites?.some((item) => item.kind === "direct-call" && item.callerFunctionName === "runEmailVerification")).toBe(true)
  const verifyRequest = result.requests.find((item) => item.sourceFunction === "verifyEmailToken")
  expect(verifyRequest?.method).toBe("POST")
  expect(verifyRequest?.path).toBe("/api/auth/email/verify")
  expect(verifyRequest?.bodyParameters).toContain("token")
})
