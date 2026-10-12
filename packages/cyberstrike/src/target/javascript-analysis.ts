import { createHash } from "node:crypto"

export interface JavaScriptFunctionCandidate {
  name: string
  line: number
  parameters: string[]
}
export interface JavaScriptRequestCandidate {
  id: string
  sourceFunction: string | null
  method: string | null
  urlTemplate: string
  host: string | null
  path: string
  pathParameters: string[]
  queryParameters: string[]
  bodyParameters: string[]
  headerNames: string[]
  authSignals: string[]
  cookieSignals: string[]
  authAssessment: "signals-present" | "no-static-auth-signal"
  sourceLine: number
  confidence: "candidate"
}
export interface JavaScriptSecretCandidate {
  kind: string
  line: number
  fingerprint: string
  confidence: "candidate"
}
export interface JavaScriptRoleHint { kind: string; value: string; line: number }
export interface JavaScriptSourceAnalysis {
  functions: JavaScriptFunctionCandidate[]
  requests: JavaScriptRequestCandidate[]
  secretCandidates: JavaScriptSecretCandidate[]
  roleHints: JavaScriptRoleHint[]
  notes: string[]
}

const cleanUnique = (values: string[]) => [...new Set(values.map((value) => value.trim()).filter(Boolean))]
const lineNumber = (source: string, index: number) => source.slice(0, index).split("\n").length
const fieldNames = (value: string) => cleanUnique(
  Array.from(value.matchAll(/(?:^|[,{\n])\s*["']?([A-Za-z_$][\w$-]{0,99})["']?\s*:/g), (m) => m[1]!),
).slice(0, 100)

function normalizeEndpoint(value: string) {
  const input = value.trim()
  if (!input || input.length > 2048 || /^(?:data|javascript|file|blob):/i.test(input)) return undefined
  const noFragment = input.split("#", 1)[0]!
  const rawQuery = noFragment.includes("?") ? noFragment.slice(noFragment.indexOf("?") + 1) : ""
  const queryParameters = cleanUnique(rawQuery.split("&").map((part) => part.split("=", 1)[0] ?? "")
    .filter((name) => /^[A-Za-z0-9_.~[\]-]{1,100}$/.test(name))).slice(0, 80)
  const dynamic = [
    ...Array.from(input.matchAll(/\$\{\s*([A-Za-z_$][\w$]*)[^}]*\}/g), (m) => m[1]!),
    ...Array.from(input.matchAll(/:([A-Za-z_$][\w$]*)/g), (m) => m[1]!),
    ...Array.from(input.matchAll(/\{([A-Za-z_$][\w$]*)\}/g), (m) => m[1]!),
  ]
  let path = noFragment.split("?", 1)[0]!
    .replace(/\$\{\s*([A-Za-z_$][\w$]*)[^}]*\}/g, "{$1}")
    .replace(/:([A-Za-z_$][\w$]*)/g, "{$1}")
  let host: string | null = null
  if (/^https?:\/\//i.test(path)) {
    try {
      const url = new URL(path)
      if (url.username || url.password) return undefined
      host = url.host.toLowerCase()
      path = url.pathname || "/"
    } catch { return undefined }
  } else if (!path.startsWith("/")) return undefined
  path = path.replace(/\/{2,}/g, "/")
  const pathParameters = cleanUnique([...dynamic, ...Array.from(path.matchAll(/\{([A-Za-z_$][\w$]*)\}/g), (m) => m[1]!)]).slice(0, 80)
  return { host, path, urlTemplate: (host ? "https://" + host : "") + path, pathParameters, queryParameters }
}

function findCallEnd(source: string, start: number): number {
  let depth = 0, quote = "", escaped = false, lineComment = false, blockComment = false
  for (let i = start; i < source.length; i++) {
    const ch = source[i]!, next = source[i + 1]
    if (lineComment) { if (ch === "\n") lineComment = false; continue }
    if (blockComment) { if (ch === "*" && next === "/") { blockComment = false; i++ }; continue }
    if (quote) { if (escaped) escaped = false; else if (ch === "\\") escaped = true; else if (ch === quote) quote = ""; continue }
    if (ch === "/" && next === "/") { lineComment = true; i++; continue }
    if (ch === "/" && next === "*") { blockComment = true; i++; continue }
    if (ch === "'" || ch === '"' || ch === "\x60") { quote = ch; continue }
    if (ch === "(") depth++
    if (ch === ")" && --depth === 0) return i
  }
  return -1
}
function splitTopLevelArguments(value: string): string[] {
  const out: string[] = []
  let start = 0, quote = "", escaped = false, round = 0, square = 0, curly = 0
  for (let i = 0; i < value.length; i++) {
    const ch = value[i]!
    if (quote) { if (escaped) escaped = false; else if (ch === "\\") escaped = true; else if (ch === quote) quote = ""; continue }
    if (ch === "'" || ch === '"' || ch === "\x60") quote = ch
    else if (ch === "(") round++
    else if (ch === ")") round--
    else if (ch === "[") square++
    else if (ch === "]") square--
    else if (ch === "{") curly++
    else if (ch === "}") curly--
    else if (ch === "," && round === 0 && square === 0 && curly === 0) { out.push(value.slice(start, i).trim()); start = i + 1 }
  }
  if (value.slice(start).trim()) out.push(value.slice(start).trim())
  return out
}

/**
 * Bounded static heuristics only: never evaluates source or returns hard-coded secret values.
 * Results are candidates. Runtime requests and server-side authorization require separate verification.
 */
export function analyzeJavaScriptSource(input: string): JavaScriptSourceAnalysis {
  const source = input.slice(0, 1_000_000)
  const functions: JavaScriptFunctionCandidate[] = []
  const fnPatterns = [
    /\bfunction\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)/g,
    /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?\(([^)]*)\)\s*=>/g,
    /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?function\b\s*\(([^)]*)\)/g,
    /\b([A-Za-z_$][\w$]*)\s*:\s*(?:async\s+)?\(([^)]*)\)\s*=>/g,
  ]
  const fnSeen = new Set<string>()
  for (const pattern of fnPatterns) for (const match of source.matchAll(pattern)) {
    const name = match[1]!, line = lineNumber(source, match.index ?? 0), key = line + ":" + name
    if (fnSeen.has(key)) continue
    fnSeen.add(key)
    const parameters = cleanUnique((match[2] ?? "").split(",").map((p) => p.trim().replace(/^\.\.\./, "").split("=")[0] ?? "")
      .filter((p) => /^[A-Za-z_$][\w$]*$/.test(p))).slice(0, 40)
    functions.push({ name, line, parameters })
    if (functions.length >= 300) break
  }
  functions.sort((a, b) => a.line - b.line)

  const requests: JavaScriptRequestCandidate[] = []
  const callPattern = /\b(fetch|axios\.(?:get|post|put|patch|delete|head|options|request)|[A-Za-z_$][\w$]*\.open)\s*\(/gi
  for (const match of source.matchAll(callPattern)) {
    const index = match.index ?? 0, callee = (match[1] ?? "").toLowerCase()
    const open = index + match[0].lastIndexOf("(")
    const close = findCallEnd(source, open)
    if (close < 0 || close - open > 7000) continue
    const args = splitTopLevelArguments(source.slice(open + 1, close))
    const isXHR = callee.endsWith(".open")
    const axiosMethod = callee.startsWith("axios.") && !callee.endsWith(".request") ? callee.slice(6).toUpperCase() : null
    const urlExpression = isXHR ? args[1] ?? "" : args[0] ?? ""
    const literalMatch = callee === "axios.request"
      ? (args[0] ?? "").match(/\burl\s*:\s*["'\x60]([^"'\x60]{1,2048})["'\x60]/)
      : urlExpression.match(/['"\x60]([^'"\x60]{1,2048})['"\x60]/)
    if (!literalMatch) continue
    const endpoint = normalizeEndpoint(literalMatch[1]!)
    if (!endpoint) continue
    const options = isXHR ? "" : callee === "axios.request" ? args[0] ?? "" : callee.startsWith("axios.") ? args.slice(2).join(",") : args.slice(1).join(",")
    const optionText = options + "\n" + source.slice(index, Math.min(close + 1, index + 7000))
    const methodOption = optionText.match(/\bmethod\s*:\s*["'](GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE)["']/i)
    const method = (axiosMethod ?? methodOption?.[1] ?? (isXHR ? args[0]?.match(/["'](GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE)["']/i)?.[1] : undefined) ?? "").toUpperCase() || null
    const headers = [
      ...Array.from(optionText.matchAll(/\bheaders\s*:\s*\{([\s\S]{0,2500}?)\}/gi), (m) => fieldNames(m[1]!)).flat(),
      ...Array.from(optionText.matchAll(/\.set\s*\(\s*["']([^"']{1,120})["']/g), (m) => m[1]!),
      ...Array.from(optionText.matchAll(/\b(Authorization|Cookie|X-CSRF-Token|X-XSRF-Token|X-API-Key)\b/gi), (m) => m[1]!),
    ]
    const bodyArgs = callee.startsWith("axios.") && !callee.endsWith(".request") ? args[1] ?? "" : options
    const directObject = bodyArgs.trim().startsWith("{") ? bodyArgs.trim().slice(1, bodyArgs.trim().lastIndexOf("}")) : ""
    const bodyParams = [
      ...fieldNames(directObject),
      ...Array.from(bodyArgs.matchAll(/\b(?:body|data)\s*:\s*(?:JSON\.stringify\s*\(\s*)?\{([\s\S]{0,2500}?)\}/gi), (m) => fieldNames(m[1] ?? "")).flat(),
    ]
    const all = optionText + "\n" + bodyArgs
    const authSignals: string[] = [], cookieSignals: string[] = []
    if (/\bAuthorization\b/i.test(all)) authSignals.push("authorization-header")
    if (/\bBearer\b/i.test(all)) authSignals.push("bearer-token")
    if (/\b(?:getToken|readToken|accessToken|access_token|authToken|idToken)\b/i.test(all)) authSignals.push("token-provider-or-token-variable")
    if (/\b(?:csrf|xsrf)[-_]?(?:token)?\b/i.test(all)) authSignals.push("csrf-or-xsrf-signal")
    if (/\b(?:sessionToken|session_id|sessionId)\b/i.test(all)) authSignals.push("session-token-signal")
    if (/\b(?:credentials\s*:\s*["']include["']|withCredentials\s*:\s*true)\b/i.test(all)) {
      authSignals.push("credentialed-request")
      cookieSignals.push("credentialed-request-may-send-cookies")
    }
    if (/\bdocument\.cookie\b/i.test(all)) cookieSignals.push("document-cookie-access")
    if (/\bCookie\b|\bcookie\s*:/i.test(all)) cookieSignals.push("cookie-header-signal")
    if (/\b(?:searchParams|URLSearchParams)\b/i.test(all)) {
      for (const m of all.matchAll(/(?:searchParams|URLSearchParams)(?:\.set|\.append|\.get)?\s*\(\s*["']([^"']{1,100})["']/gi)) endpoint.queryParameters.push(m[1]!)
    }
    const line = lineNumber(source, index)
    const sourceFunction = [...functions].reverse().find((fn) => fn.line <= line)?.name ?? null
    const item: JavaScriptRequestCandidate = {
      id: "js-request:" + createHash("sha256").update(line + ":" + endpoint.urlTemplate + ":" + (method ?? "?")).digest("hex").slice(0, 16),
      sourceFunction, method, urlTemplate: endpoint.urlTemplate, host: endpoint.host, path: endpoint.path,
      pathParameters: endpoint.pathParameters, queryParameters: cleanUnique(endpoint.queryParameters),
      bodyParameters: cleanUnique(bodyParams).slice(0, 100), headerNames: cleanUnique(headers).slice(0, 100),
      authSignals: cleanUnique(authSignals), cookieSignals: cleanUnique(cookieSignals),
      authAssessment: authSignals.length || cookieSignals.length ? "signals-present" : "no-static-auth-signal",
      sourceLine: line, confidence: "candidate",
    }
    if (!requests.some((existing) => existing.id === item.id)) requests.push(item)
    if (requests.length >= 300) break
  }

  const secrets = new Map<string, JavaScriptSecretCandidate>()
  const secretPattern = /\b(api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|secret[_-]?key|password|passwd|private[_-]?key)\b\s*[:=]\s*(['"\x60])([^'"\x60\r\n]{8,500})\2/gi
  for (const match of source.matchAll(secretPattern)) {
    const rawValue = match[3] ?? ""
    if (!rawValue || /^(?:\$\{|\{\{|\$[A-Z_][A-Z0-9_]*|<[^>]+>)/i.test(rawValue.trim())) continue
    const item: JavaScriptSecretCandidate = {
      kind: (match[1] ?? "secret").toLowerCase().replace(/[_-]+/g, "-"), line: lineNumber(source, match.index ?? 0),
      fingerprint: createHash("sha256").update(rawValue).digest("hex").slice(0, 20), confidence: "candidate",
    }
    secrets.set(item.kind + ":" + item.fingerprint, item)
    if (secrets.size >= 100) break
  }

  const roles = new Map<string, JavaScriptRoleHint>()
  const rolePattern = /\b(isAdmin|is_admin|adminOnly|requireAdmin|hasRole|checkPermission|hasPermission|featureFlag|feature_flag|debugMode|debug_mode|internalOnly|superuser|impersonate|impersonation|role|permission)\b/gi
  for (const match of source.matchAll(rolePattern)) {
    const value = match[1]!, lower = value.toLowerCase()
    const kind = /admin|superuser/.test(lower) ? "admin-role-hint" : /role|permission/.test(lower) ? "authorization-hint"
      : /feature.?flag/.test(lower) ? "feature-flag-hint" : /debug/.test(lower) ? "debug-path-hint"
      : /impersonat/.test(lower) ? "impersonation-hint" : "internal-feature-hint"
    const item = { kind, value, line: lineNumber(source, match.index ?? 0) }
    roles.set(kind + ":" + value + ":" + item.line, item)
    if (roles.size >= 100) break
  }
  return {
    functions, requests, secretCandidates: [...secrets.values()], roleHints: [...roles.values()],
    notes: [
      "Bounded static heuristics only; dynamic strings, destructured parameters and minified bundles may be missed.",
      "No static auth/cookie signal does not prove an endpoint is unauthenticated; inspect captured requests and server behavior.",
      "Secret values are never returned or persisted; only type, line number, and one-way fingerprint are retained.",
      "Function attribution is a nearest-preceding-function hint, not a proven runtime call relationship.",
    ],
  }
}
