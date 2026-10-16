import { expect, test } from "bun:test"
import { analyzeJavaScriptSource } from "../../src/target/javascript-analysis"

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
  ].join("\\n")
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
  ].join("\n")
  const result = analyzeJavaScriptSource(source)
  expect(result.requests.find((item) => item.path.includes("/api/users/"))?.path).toBe("/api/users/{id}")
  expect(result.requests.find((item) => item.path.includes("/api/invoices/"))?.path).toBe("/api/invoices/{uuid}")
  expect(result.requests.some((item) => item.pathParameters.includes("id"))).toBe(true)
  expect(result.requests.some((item) => item.pathParameters.includes("uuid"))).toBe(true)
  expect(JSON.stringify(result)).not.toContain("12345")
  expect(JSON.stringify(result)).not.toContain("550e8400-e29b-41d4-a716-446655440000")
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
    value: secret,
    confidence: "candidate",
  })
  expect(result.secretCandidates[0]?.fingerprint).toMatch(/^[a-f0-9]{20}$/)
})

test("records roles and hidden-feature hints as candidates", () => {
  const source = ['if (isAdmin) fetch("/api/admin/reports")', 'if (featureFlag) fetch("/api/beta/exports")', "const debugMode = true"].join("\n")
  const result = analyzeJavaScriptSource(source)
  expect(result.roleHints.some((hint) => hint.kind === "admin-role-hint")).toBe(true)
  expect(result.roleHints.some((hint) => hint.kind === "feature-flag-hint")).toBe(true)
  expect(result.roleHints.some((hint) => hint.kind === "debug-path-hint")).toBe(true)
  expect(result.requests.some((request) => request.path === "/api/admin/reports")).toBe(true)
})

test("retains exact secret candidate values and keeps them unverified", () => {
  const source = 'const api_key = "personal-test-token-value-12345";';
  const result = analyzeJavaScriptSource(source);
  expect(result.secretCandidates).toHaveLength(1);
  expect(result.secretCandidates[0]).toMatchObject({
    kind: "api-key",
    line: 1,
    value: "personal-test-token-value-12345",
    confidence: "candidate",
  });
  expect(result.secretCandidates[0]?.fingerprint).toMatch(/^[a-f0-9]{20}$/);
});
