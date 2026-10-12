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

test("records hard-coded secret-like assignments as fingerprints only", () => {
  const secret = "secret-value-must-never-be-retained"
  const result = analyzeJavaScriptSource('const config = { api_key: "' + secret + '" }')
  expect(result.secretCandidates).toHaveLength(1)
  expect(result.secretCandidates[0]?.kind).toBe("api-key")
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
