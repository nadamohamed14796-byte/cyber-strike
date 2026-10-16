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
  /** Explicit HTTP origin, retained so scheme and non-default ports are never guessed. */
  origin?: string | null
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
  /** Exact source value for target-local evidence; never promote a pattern match to verified. */
  value: string
  fingerprint: string
  confidence: "candidate"
}
export interface JavaScriptRoleHint { kind: string; value: string; line: number }
export interface JavaScriptRiskSignal {
  id: string
  kind: string
  line: number
  functionName: string | null
  confidence: "candidate"
}
export interface JavaScriptSourceAnalysis {
  functions: JavaScriptFunctionCandidate[]
  requests: JavaScriptRequestCandidate[]
  secretCandidates: JavaScriptSecretCandidate[]
  roleHints: JavaScriptRoleHint[]
  riskSignals: JavaScriptRiskSignal[]
  notes: string[]
}

const cleanUnique = (values: string[]) => [...new Set(values.map((value) => value.trim()).filter(Boolean))]
function lineNumber(lineStarts: number[], index: number): number {
  let low = 0, high = lineStarts.length
  while (low < high) {
    const middle = (low + high) >>> 1
    if (lineStarts[middle]! <= index) low = middle + 1
    else high = middle
  }
  return low
}

/** Normalize potentially identifying values embedded in route literals without storing query values. */
export function normalizeJavaScriptEndpointPath(inputPath: string): { path: string; pathParameters: string[] } {
  const pathParameters: string[] = []
  const path = inputPath.split("/").map((segment) => {
    if (!segment) return segment
    let decoded = segment
    try { decoded = decodeURIComponent(segment) } catch { /* retain an undecodable segment */ }
    const placeholder = decoded.match(/^\{([A-Za-z_$][\w$]*)\}$/)
    if (placeholder) {
      pathParameters.push(placeholder[1]!)
      return "{" + placeholder[1]! + "}"
    }
    if (/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(decoded)) {
      pathParameters.push("uuid")
      return "{uuid}"
    }
    if (/^\d+$/.test(decoded) || /^[a-f0-9]{24,}$/i.test(decoded)) {
      pathParameters.push("id")
      return "{id}"
    }
    if (/^[^/@\s]+@[^/@\s]+\.[^/@\s]+$/.test(decoded)) {
      pathParameters.push("email")
      return "{email}"
    }
    if (/^eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$/.test(decoded)) {
      pathParameters.push("token")
      return "{token}"
    }
    if (decoded.length >= 48 && /^[A-Za-z0-9_-]+$/.test(decoded)) {
      pathParameters.push("value")
      return "{value}"
    }
    return segment
  }).join("/")
  return { path, pathParameters: cleanUnique(pathParameters).slice(0, 80) }
}
const fieldNames = (value: string) => cleanUnique(
  Array.from(value.matchAll(/(?:^|[,{\n])\s*["']?([A-Za-z_$][\w$-]{0,99})["']?\s*:/g), (m) => m[1]!),
).slice(0, 100)


/** Match a brace-delimited object while ignoring strings and comments. */
function matchingObjectBrace(source: string, open: number, maxLength = 10000): number {
  let depth = 0, quote = "", escaped = false, lineComment = false, blockComment = false
  const limit = Math.min(source.length, open + maxLength)
  for (let i = open; i < limit; i++) {
    const ch = source[i]!, next = source[i + 1]
    if (lineComment) { if (ch === "\n") lineComment = false; continue }
    if (blockComment) { if (ch === "*" && next === "/") { blockComment = false; i++ }; continue }
    if (quote) { if (escaped) escaped = false; else if (ch === "\\") escaped = true; else if (ch === quote) quote = ""; continue }
    if (ch === "/" && next === "/") { lineComment = true; i++; continue }
    if (ch === "/" && next === "*") { blockComment = true; i++; continue }
    if (ch === "'" || ch === '"' || ch === "\x60") { quote = ch; continue }
    if (ch === "{") depth++
    if (ch === "}" && --depth === 0) return i
  }
  return -1
}

function objectPropertyNames(value: string): string[] {
  const names = new Set(fieldNames(value))
  for (const part of splitTopLevelArguments(value)) {
    const match = part.trim().match(/^(?:["']([^"']{1,100})["']|([A-Za-z_$][\w$-]{0,99}))\s*(?:\??:|$)/)
    const name = match?.[1] ?? match?.[2]
    if (name && /^[A-Za-z_$][\w$-]{0,99}$/.test(name)) names.add(name)
  }
  return [...names].slice(0, 100)
}

function objectBindingFields(source: string, name: string, beforeIndex: number): string[] {
  if (!/^[A-Za-z_$][\w$]*$/.test(name)) return []
  const pattern = new RegExp("\\b(?:const|let|var)\\s+" + name + "\\s*=\\s*\\{", "g")
  let match: RegExpExecArray | null
  let bestIndex = -1
  let fields: string[] = []
  while ((match = pattern.exec(source))) {
    const at = match.index ?? 0
    if (at >= beforeIndex) break
    const open = source.indexOf("{", at)
    const close = matchingObjectBrace(source, open)
    if (close < 0 || close >= beforeIndex || at <= bestIndex) continue
    bestIndex = at
    fields = objectPropertyNames(source.slice(open + 1, close))
  }
  return fields
}

function configObjectFields(text: string, property: string, source: string, beforeIndex: number): string[] {
  const fields = new Set<string>()
  const direct = new RegExp("\\b" + property + "\\s*:\\s*\\{", "g")
  let match: RegExpExecArray | null
  while ((match = direct.exec(text))) {
    const open = text.indexOf("{", match.index)
    const close = matchingObjectBrace(text, open)
    if (close >= 0) for (const key of objectPropertyNames(text.slice(open + 1, close))) fields.add(key)
  }
  const reference = new RegExp("\\b" + property + "\\s*:\\s*([A-Za-z_$][\\w$]*)\\b").exec(text)
  if (reference?.[1]) for (const key of objectBindingFields(source, reference[1], beforeIndex)) fields.add(key)
  const shorthand = new RegExp("(?:^|[,{])\\s*" + property + "\\s*(?=,|})").test(text)
  if (shorthand) for (const key of objectBindingFields(source, property, beforeIndex)) fields.add(key)
  return [...fields].slice(0, 100)
}

function bodyVariableNames(text: string): string[] {
  const names = new Set<string>()
  for (const match of text.matchAll(/(?:^|[,{\n])\s*(?:body|data)\s*:\s*(?:JSON\.stringify\s*\(\s*)?([A-Za-z_$][\w$]*)(?:\s*\))?/gi)) {
    const name = match[1]
    if (name && !["true", "false", "null", "undefined", "JSON"].includes(name)) names.add(name)
  }
  return [...names]
}

/** Resolve function body spans, so a later top-level request is not assigned to an earlier function. */
function staticFunctionRanges(source: string, functions: JavaScriptFunctionCandidate[], offsets: Map<string, number>): Array<{ name: string; start: number; end: number }> {
  const ranges: Array<{ name: string; start: number; end: number }> = []
  for (const fn of functions) {
    const offset = offsets.get(fn.line + ":" + fn.name)
    if (offset === undefined) continue
    const view = source.slice(offset, Math.min(source.length, offset + 10000))
    const arrowRel = view.indexOf("=>")
    const parenRel = view.indexOf("(")
    if (arrowRel >= 0 && (parenRel < 0 || arrowRel < view.indexOf("{") || view.indexOf("{") < 0)) {
      const arrow = offset + arrowRel
      let bodyStart = arrow + 2
      while (/\s/.test(source[bodyStart] ?? "")) bodyStart++
      let bodyEnd = -1
      if (source[bodyStart] === "{") bodyEnd = matchingObjectBrace(source, bodyStart)
      else {
        const semicolon = source.indexOf(";", bodyStart)
        const newline = source.indexOf("\n", bodyStart)
        bodyEnd = source.length
        if (semicolon >= 0) bodyEnd = Math.min(bodyEnd, semicolon)
        if (newline >= 0) bodyEnd = Math.min(bodyEnd, newline)
      }
      if (bodyEnd >= bodyStart) ranges.push({ name: fn.name, start: bodyStart, end: bodyEnd })
      continue
    }
    if (parenRel < 0) continue
    const openParen = offset + parenRel
    const closeParen = findCallEnd(source, openParen, 10000)
    if (closeParen < 0) continue
    const openBrace = source.indexOf("{", closeParen + 1)
    if (openBrace < 0 || openBrace - closeParen > 3000) continue
    const semicolon = source.indexOf(";", closeParen + 1)
    const arrow = source.indexOf("=>", closeParen + 1)
    if ((semicolon >= 0 && semicolon < openBrace) || (arrow >= 0 && arrow < openBrace)) continue
    const closeBrace = matchingObjectBrace(source, openBrace)
    if (closeBrace >= openBrace) ranges.push({ name: fn.name, start: openBrace, end: closeBrace })
  }
  return ranges
}

function normalizeEndpoint(value: string) {
  const input = value.trim()
  if (!input || input.length > 2048 || /^(?:data|javascript|file|blob):/i.test(input)) return undefined
  const noFragment = input.split("#", 1)[0]!
  const rawQuery = noFragment.includes("?") ? noFragment.slice(noFragment.indexOf("?") + 1) : ""
  const queryParameters = cleanUnique(rawQuery.split("&").map((part) => part.split("=", 1)[0] ?? "")
    .filter((name) => /^[A-Za-z0-9_.~[\]-]{1,100}$/.test(name))).slice(0, 80)
  const rawPath = noFragment.split("?", 1)[0]!
  const dynamic = [
    ...Array.from(rawPath.matchAll(/\$\{\s*([A-Za-z_$][\w$]*)[^}]*\}/g), (m) => m[1]!),
    ...Array.from(rawPath.matchAll(/:([A-Za-z_$][\w$]*)/g), (m) => m[1]!),
    ...Array.from(rawPath.matchAll(/\{([A-Za-z_$][\w$]*)\}/g), (m) => m[1]!),
  ]
  let path = rawPath
    .replace(/\$\{\s*([A-Za-z_$][\w$]*)[^}]*\}/g, "{$1}")
    .replace(/:([A-Za-z_$][\w$]*)/g, "{$1}")
  let host: string | null = null
  let origin: string | null = null
  if (/^https?:\/\//i.test(path)) {
    try {
      const url = new URL(path)
      if (url.username || url.password) return undefined
      host = url.host.toLowerCase()
      origin = url.origin.toLowerCase()
      path = url.pathname || "/"
    } catch { return undefined }
  } else if (!path.startsWith("/")) return undefined
  path = path.replace(/\/{2,}/g, "/")
  const normalizedPath = normalizeJavaScriptEndpointPath(path)
  path = normalizedPath.path
  const pathParameters = cleanUnique([...dynamic, ...normalizedPath.pathParameters]).slice(0, 80)
  return { host, origin, path, urlTemplate: (origin ?? (host ? "https://" + host : "")) + path, pathParameters, queryParameters }
}

function addConcatenatedPathParameters(
  endpoint: NonNullable<ReturnType<typeof normalizeEndpoint>>,
  expression: string,
): NonNullable<ReturnType<typeof normalizeEndpoint>> {
  const first = expression.match(/(['"\x60])([^'"\x60]{1,2048})\1/)
  if (!first || first.index === undefined) return endpoint
  // A concatenation after ? or # belongs to query/fragment data, not the route path.
  if (first[2]!.includes("?") || first[2]!.includes("#")) return endpoint
  let path = endpoint.path
  let rest = expression.slice(first.index + first[0].length)
  const pathParameters = [...endpoint.pathParameters]
  for (let i = 0; i < 12; i++) {
    const dynamic = rest.match(/^\s*\+\s*(?:(?:encodeURIComponent|String|Number)\s*\(\s*)?([A-Za-z_$][\w$]*)(?:\s*\))?/)
    if (!dynamic) break
    const name = dynamic[1]!
    // Infer a new path segment only when the source explicitly includes its separator.
    if (!path.endsWith("/")) break
    path += "{" + name + "}"
    pathParameters.push(name)
    rest = rest.slice(dynamic[0].length)
    const staticPart = rest.match(/^\s*\+\s*(['"\x60])([^'"\x60]{0,500})\1/)
    if (!staticPart) break
    const suffix = staticPart[2] ?? ""
    if (suffix.includes("?") || suffix.includes("#")) break
    path += suffix
    rest = rest.slice(staticPart[0].length)
  }
  path = path.replace(/\/{2,}/g, "/")
  return {
    ...endpoint,
    path,
    urlTemplate: (endpoint.origin ?? (endpoint.host ? "https://" + endpoint.host : "")) + path,
    pathParameters: cleanUnique(pathParameters).slice(0, 80),
  }
}

function findCallEnd(source: string, start: number, maxLength = 7000): number {
  let depth = 0, quote = "", escaped = false, lineComment = false, blockComment = false
  const limit = Math.min(source.length, start + maxLength)
  for (let i = start; i < limit; i++) {
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
 * Bounded static heuristics only: never evaluates source. Exact candidate values are retained so the
 * private target workspace can record reproducible evidence. Results remain candidates until verified.
 */
export function analyzeJavaScriptSource(input: string): JavaScriptSourceAnalysis {
  const source = input.slice(0, 1_000_000)
  const lineStarts = [0]
  for (let i = 0; i < source.length; i++) if (source.charCodeAt(i) === 10) lineStarts.push(i + 1)
  const functions: JavaScriptFunctionCandidate[] = []
  const functionOffsets = new Map<string, number>()
  const fnPatterns = [
    /\bfunction\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)/g,
    /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?\(([^)]*)\)\s*=>/g,
    /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?([A-Za-z_$][\w$]*)\s*=>/g,
    /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?function\b\s*\(([^)]*)\)/g,
    /\b([A-Za-z_$][\w$]*)\s*:\s*(?:async\s+)?\(([^)]*)\)\s*=>/g,
  ]
  const fnSeen = new Set<string>()
  for (const pattern of fnPatterns) for (const match of source.matchAll(pattern)) {
    const name = match[1]!, line = lineNumber(lineStarts, match.index ?? 0), key = line + ":" + name
    if (fnSeen.has(key)) continue
    fnSeen.add(key)
    const parameters = cleanUnique((match[2] ?? "").split(",").map((p) => (p.trim().replace(/^\.\.\./, "").split("=")[0] ?? "").trim())
      .filter((p) => /^[A-Za-z_$][\w$]*$/.test(p))).slice(0, 40)
    functions.push({ name, line, parameters })
    functionOffsets.set(key, match.index ?? 0)
    if (functions.length >= 300) break
  }
  // Capture class/object shorthand methods and accessors as well as declarations and arrows.
  const reservedMethodNames = new Set(["if", "for", "while", "switch", "catch", "with", "function", "return", "throw", "new", "else", "try", "do"])
  const methodPattern = /(?:^|[;{}]\s*|\n\s*)(?:static\s+|async\s+|public\s+|private\s+|protected\s+|get\s+|set\s+)*([A-Za-z_$][\w$]*)\s*\(([^()]*)\)\s*\{/gm
  for (const match of source.matchAll(methodPattern)) {
    const name = match[1]!
    if (reservedMethodNames.has(name)) continue
    const line = lineNumber(lineStarts, match.index ?? 0), key = line + ":" + name
    if (fnSeen.has(key)) continue
    fnSeen.add(key)
    const parameters = cleanUnique((match[2] ?? "").split(",").map((p) => (p.trim().replace(/^\.\.\./, "").split("=")[0] ?? "").trim())
      .filter((p) => /^[A-Za-z_$][\w$]*$/.test(p))).slice(0, 40)
    functions.push({ name, line, parameters })
    functionOffsets.set(key, match.index ?? 0)
    if (functions.length >= 300) break
  }
  functions.sort((a, b) => a.line - b.line)
  const functionRanges = staticFunctionRanges(source, functions, functionOffsets)

  const requests: JavaScriptRequestCandidate[] = []
  const callPattern = /\b(fetch|axios\.(?:get|post|put|patch|delete|head|options|request)|[A-Za-z_$][\w$]*\.(?:get|post|put|patch|delete|head|options|request|open))\s*\(/gi
  for (const match of source.matchAll(callPattern)) {
    const index = match.index ?? 0, callee = (match[1] ?? "").toLowerCase()
    const open = index + match[0].lastIndexOf("(")
    const close = findCallEnd(source, open)
    if (close < 0 || close - open > 7000) continue
    const args = splitTopLevelArguments(source.slice(open + 1, close))
    const isXHR = callee.endsWith(".open")
    const methodSuffix = /\.(get|post|put|patch|delete|head|options)$/i.exec(callee)?.[1]?.toUpperCase() ?? null
    const axiosMethod = methodSuffix
    const requestConfig = callee.endsWith(".request") && (args[0] ?? "").trim().startsWith("{")
    const urlExpression = isXHR ? args[1] ?? "" : args[0] ?? ""
    const literalMatch = requestConfig
      ? (args[0] ?? "").match(/\burl\s*:\s*["'\x60]([^"'\x60]{1,2048})["'\x60]/)
      : urlExpression.match(/['"\x60]([^'"\x60]{1,2048})['"\x60]/)
    if (!literalMatch) continue
    const normalizedEndpoint = normalizeEndpoint(literalMatch[1]!)
    if (!normalizedEndpoint) continue
    const endpoint = requestConfig ? normalizedEndpoint : addConcatenatedPathParameters(normalizedEndpoint, urlExpression)
    const isFetch = callee === "fetch"
    const isBodyMethod = /\.(?:post|put|patch)$/i.test(callee)
    const options = isXHR ? "" : requestConfig ? args[0] ?? "" : callee.endsWith(".request") ? args.slice(1).join(",")
      : isFetch ? args.slice(1).join(",") : /\.(?:get|head|options|delete)$/i.test(callee) ? args.slice(1).join(",") : args.slice(2).join(",")
    const optionText = options + "\n" + source.slice(index, Math.min(close + 1, index + 7000))
    const methodOption = optionText.match(/\bmethod\s*:\s*["'](GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE)["']/i)
    const hasDynamicMethodOption = isFetch && /\bmethod\b/i.test(optionText) && !methodOption
    const inferredFetchMethod = isFetch && !hasDynamicMethodOption ? "GET" : undefined
    const method = (axiosMethod ?? methodOption?.[1] ?? (isXHR ? args[0]?.match(/["'](GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE)["']/i)?.[1] : inferredFetchMethod) ?? "").toUpperCase() || null
    const headers = [
      ...configObjectFields(optionText, "headers", source, index),
      ...Array.from(optionText.matchAll(/\[\s*\[\s*["']([^"']{1,120})["']/g), (m) => m[1]!),
      ...Array.from(optionText.matchAll(/(?:headers|requestHeaders)\s*\.\s*(?:set|append)\s*\(\s*["']([^"']{1,120})["']/gi), (m) => m[1]!),
      ...Array.from(optionText.matchAll(/\.setRequestHeader\s*\(\s*["']([^"']{1,120})["']/gi), (m) => m[1]!),
      ...Array.from(optionText.matchAll(/\b(Authorization|Cookie|Set-Cookie|X-CSRF-Token|X-XSRF-Token|X-API-Key)\b/gi), (m) => m[1]!),
    ]
    const bodyArgs = requestConfig ? "" : isBodyMethod ? args[1] ?? "" : isFetch ? options : ""
    const directObject = isBodyMethod && bodyArgs.trim().startsWith("{")
      ? bodyArgs.trim().slice(1, bodyArgs.trim().lastIndexOf("}")) : ""
    const bodySource = options + "\n" + bodyArgs + (requestConfig ? "\n" + (args[0] ?? "") : "")
    const bodyParams = [
      ...objectPropertyNames(directObject),
      ...Array.from(bodySource.matchAll(/\b(?:body|data)\s*:\s*\{([\s\S]{0,2500}?)\}/gi), (m) => objectPropertyNames(m[1] ?? "")).flat(),
      ...Array.from(bodySource.matchAll(/JSON\.stringify\s*\(\s*\{([\s\S]{0,2500}?)\}\s*\)/gi), (m) => objectPropertyNames(m[1] ?? "")).flat(),
      ...bodyVariableNames(bodySource).flatMap((name) => objectBindingFields(source, name, index)),
      ...(isBodyMethod && !requestConfig && /^[A-Za-z_$][\w$]*$/.test((args[1] ?? "").trim())
        ? objectBindingFields(source, (args[1] ?? "").trim(), index) : []),
    ]
    const all = optionText + "\n" + bodyArgs
    const authSignals: string[] = [], cookieSignals: string[] = []
    if (/\bAuthorization\b/i.test(all)) authSignals.push("authorization-header")
    if (/\bBearer\b/i.test(all)) authSignals.push("bearer-token")
    if (/\b(?:getToken|readToken|accessToken|access_token|authToken|idToken)\b/i.test(all)) authSignals.push("token-provider-or-token-variable")
    if (/\b(?:csrf|xsrf)[-_]?(?:token)?\b/i.test(all)) authSignals.push("csrf-or-xsrf-signal")
    if (/\b(?:sessionToken|session_id|sessionId)\b/i.test(all)) authSignals.push("session-token-signal")
    if (/(?:\bcredentials\s*:\s*["']include["']|\bwithCredentials\s*:\s*true)/i.test(all)) {
      authSignals.push("credentialed-request")
      cookieSignals.push("credentialed-request-may-send-cookies")
    }
    if (/\bdocument\.cookie\b/i.test(all)) cookieSignals.push("document-cookie-access")
    if (/\bCookie\b|\bcookie\s*:/i.test(all)) cookieSignals.push("cookie-header-signal")
    endpoint.queryParameters.push(
      ...configObjectFields(optionText, "params", source, index),
      ...configObjectFields(optionText, "searchParams", source, index),
      ...Array.from(all.matchAll(/new\s+URLSearchParams\s*\(\s*\{([\s\S]{0,2500}?)\}/gi), (m) => objectPropertyNames(m[1] ?? "")).flat(),
    )
    if (/\b(?:searchParams|URLSearchParams)\b/i.test(all)) {
      for (const m of all.matchAll(/(?:searchParams|URLSearchParams)(?:\.set|\.append|\.get)?\s*\(\s*["']([^"']{1,100})["']/gi)) endpoint.queryParameters.push(m[1]!)
    }
    const line = lineNumber(lineStarts, index)
    const sourceFunction = functionRanges.filter((range) => range.start <= index && index <= range.end).sort((a, b) => (a.end - a.start) - (b.end - b.start))[0]?.name ?? null
    const item: JavaScriptRequestCandidate = {
      id: "js-request:" + createHash("sha256").update(JSON.stringify([line, endpoint.urlTemplate, method, cleanUnique(endpoint.pathParameters), cleanUnique(endpoint.queryParameters), cleanUnique(bodyParams), cleanUnique(headers)])).digest("hex").slice(0, 16),
      sourceFunction, method, urlTemplate: endpoint.urlTemplate, host: endpoint.host, origin: endpoint.origin, path: endpoint.path,
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
      kind: (match[1] ?? "secret").toLowerCase().replace(/[_-]+/g, "-"), line: lineNumber(lineStarts, match.index ?? 0),
      value: rawValue, fingerprint: createHash("sha256").update(rawValue).digest("hex").slice(0, 20), confidence: "candidate",
    }
    secrets.set(item.kind + ":" + item.fingerprint, item)
    if (secrets.size >= 100) break
  }

  const roles = new Map<string, JavaScriptRoleHint>()
  const rolePattern = /\b(isAdmin|is_admin|adminOnly|requireAdmin|hasRole|checkPermission|hasPermission|featureFlag|feature_flag|debugMode|debug_mode|internalOnly|superuser|impersonate|impersonation|role|permission)\b/gi

  // Security-relevant sinks are triage leads only; this deliberately stores rule names,
  // source locations and function hints, never the matched source text or secret values.
  const riskRules: Array<{ kind: string; regex: RegExp }> = [
    { kind: "dom-html-sink", regex: /\b(?:innerHTML|outerHTML)\s*=/gi },
    { kind: "html-fragment-insertion", regex: /\binsertAdjacentHTML\s*\(/gi },
    { kind: "document-write-sink", regex: /\bdocument\.write(?:ln)?\s*\(/gi },
    { kind: "dynamic-code-execution", regex: /\b(?:eval\s*\(|new\s+Function\s*\()/gi },
    { kind: "string-timer-execution", regex: /\b(?:setTimeout|setInterval)\s*\(\s*["'`]/gi },
    { kind: "navigation-or-redirect-sink", regex: /\b(?:window\.)?location(?:\.href)?\s*(?:=|\.assign\s*\(|\.replace\s*\()/gi },
    { kind: "cross-window-message", regex: /\bpostMessage\s*\(/gi },
    { kind: "wildcard-postmessage-origin", regex: /\bpostMessage\s*\([^,]{1,1000},\s*["']\*["']\s*\)/gi },
    { kind: "message-event-handler", regex: /\baddEventListener\s*\(\s*["']message["']/gi },
    { kind: "client-side-token-storage", regex: /\b(?:localStorage|sessionStorage)\.setItem\s*\(\s*["'][^"']{1,120}(?:token|auth|session|secret|key)[^"']*["']/gi },
    { kind: "document-cookie-write", regex: /\bdocument\.cookie\s*=/gi },
    { kind: "dynamic-regexp", regex: /\bnew\s+RegExp\s*\(\s*[A-Za-z_$]/gi },
    { kind: "prototype-mutation", regex: /\b(?:__proto__|prototype)\s*(?:\[|\.)/gi },
  ]
  const riskSignals = new Map<string, JavaScriptRiskSignal>()
  for (const rule of riskRules) for (const match of source.matchAll(rule.regex)) {
    const index = match.index ?? 0, line = lineNumber(lineStarts, index)
    const functionName = [...functions].reverse().find((fn) => fn.line <= line)?.name ?? null
    const id = "js-risk:" + createHash("sha256").update(rule.kind + ":" + line + ":" + (functionName ?? "")).digest("hex").slice(0, 16)
    riskSignals.set(id, { id, kind: rule.kind, line, functionName, confidence: "candidate" })
    if (riskSignals.size >= 300) break
  }
  for (const match of source.matchAll(rolePattern)) {
    const value = match[1]!, lower = value.toLowerCase()
    const kind = /admin|superuser/.test(lower) ? "admin-role-hint" : /role|permission/.test(lower) ? "authorization-hint"
      : /feature.?flag/.test(lower) ? "feature-flag-hint" : /debug/.test(lower) ? "debug-path-hint"
      : /impersonat/.test(lower) ? "impersonation-hint" : "internal-feature-hint"
    const item = { kind, value, line: lineNumber(lineStarts, match.index ?? 0) }
    roles.set(kind + ":" + value + ":" + item.line, item)
    if (roles.size >= 100) break
  }
  return {
    functions, requests, secretCandidates: [...secrets.values()], roleHints: [...roles.values()], riskSignals: [...riskSignals.values()],
    notes: [
      "Bounded static heuristics only; dynamic strings, destructured parameters and minified bundles may be missed.",
      "No static auth/cookie signal does not prove an endpoint is unauthenticated; inspect captured requests and server behavior.",
      "Exact candidate values are available for target-local evidence; a static match remains unverified until independently validated.",
      "Static sink signals are triage candidates, can be false positives in comments/vendor code, and do not prove taint or exploitability.",
      "Function attribution uses bounded lexical body spans; minified or complex TypeScript syntax may remain unattributed.",
      ...(input.length > 1_000_000 ? ["Source was bounded to the first 1 MB for static analysis."] : []),
    ],
  }
}
