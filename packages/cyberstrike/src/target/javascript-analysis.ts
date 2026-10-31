import { createHash } from "node:crypto"

export interface JavaScriptCallSiteCandidate {
  line: number
  kind: "ui-event-binding" | "dom-event-listener" | "callback-reference" | "direct-call"
  /** Enclosing caller when the reference occurs inside a statically identified function. */
  callerFunctionName?: string | null
  confidence: "candidate"
}

export interface JavaScriptFunctionCandidate {
  name: string
  line: number
  parameters: string[]
  /** Candidate locations that call or reference this function; not proof of a browser interaction. */
  callSites?: JavaScriptCallSiteCandidate[]
}
export interface JavaScriptWorkflowSignal {
  kind: string
  value: string
  line: number
  functionName: string | null
  confidence: "candidate"
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
  /** Enclosing statically identified function, when available. */
  functionName?: string | null
  /** SHA-256 fingerprint only; the matched value is never retained in analysis output. */
  fingerprint: string
  confidence: "candidate"
}
export interface JavaScriptDataExposureSignal {
  /** The detected data class, never the matched personal value. */
  kind: "sensitive-field" | "embedded-email-address"
  field: string | null
  line: number
  functionName: string | null
  confidence: "candidate"
}
export interface JavaScriptRoleHint { kind: string; value: string; line: number; functionName?: string | null }
export interface JavaScriptApplicationHint { kind: string; value: string; line: number; functionName?: string | null; confidence: "candidate" }
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
  /** Broad product, protocol, integration, and configuration clues independent of vulnerability classes. */
  applicationHints?: JavaScriptApplicationHint[]
  /** Security-relevant business/token/data-layer flow markers with enclosing-function attribution. */
  workflowSignals?: JavaScriptWorkflowSignal[]
  /** Sensitive field and embedded contact-data indicators; raw values are never retained. */
  dataExposureSignals?: JavaScriptDataExposureSignal[]
  notes: string[]
}

const cleanUnique = (values: string[]) => [...new Set(values.map((value) => value.trim()).filter(Boolean))]
const escapeRegexLiteral = (value: string) => value.replace(/[.*+?^\x24\x7B\x7D()|[\]\\]/g, "\\$&")
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
    if (/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(decoded)) {
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
  return { path, pathParameters: cleanUnique(pathParameters) }
}
const fieldNames = (value: string) => cleanUnique(
  Array.from(value.matchAll(/(?:^|[,{\n])\s*["']?([A-Za-z_$][\w$-]*)["']?\s*:/g), (m) => m[1]!),
 )


/** Match a brace-delimited object while ignoring strings and comments. */
function matchingObjectBrace(source: string, open: number, maxLength = source.length): number {
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
    const match = part.trim().match(/^(?:["']([^"']+)["']|([A-Za-z_$][\w$-]*))\s*(?:\??:|$)/)
    const name = match?.[1] ?? match?.[2]
    if (name && /^[A-Za-z_$][\w$-]*$/.test(name)) names.add(name)
  }
  return [...names]
}

function objectBindingFields(source: string, name: string, beforeIndex: number): string[] {
  if (!/^[A-Za-z_$][\w$]*$/.test(name)) return []
  const pattern = new RegExp("\\b(?:const|let|var)\\s+" + escapeRegexLiteral(name) + "\\s*=\\s*\\{", "g")
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
  const escapedProperty = escapeRegexLiteral(property)
  const direct = new RegExp("\\b" + escapedProperty + "\\s*:\\s*\\{", "g")
  let match: RegExpExecArray | null
  while ((match = direct.exec(text))) {
    const open = text.indexOf("{", match.index)
    const close = matchingObjectBrace(text, open)
    if (close >= 0) for (const key of objectPropertyNames(text.slice(open + 1, close))) fields.add(key)
  }
  const reference = new RegExp("\\b" + escapedProperty + "\\s*:\\s*([A-Za-z_$][\\w$]*)\\b").exec(text)
  if (reference?.[1]) for (const key of objectBindingFields(source, reference[1], beforeIndex)) fields.add(key)
  const shorthand = new RegExp("(?:^|[,{])\\s*" + escapedProperty + "\\s*(?=,|})").test(text)
  if (shorthand) for (const key of objectBindingFields(source, property, beforeIndex)) fields.add(key)
  return [...fields]
}

function urlSearchParamsVariables(text: string): string[] {
  const names = new Set<string>()
  for (const match of text.matchAll(/\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*new\s+URLSearchParams\b/g)) {
    if (match[1]) names.add(match[1])
  }
  return [...names]
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
    const view = source.slice(offset)
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
    const closeParen = findCallEnd(source, openParen)
    if (closeParen < 0) continue
    const openBrace = source.indexOf("{", closeParen + 1)
    if (openBrace < 0) continue
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
  if (!input || /^(?:data|javascript|file|blob):/i.test(input)) return undefined
  const noFragment = input.split("#", 1)[0]!
  const rawQuery = noFragment.includes("?") ? noFragment.slice(noFragment.indexOf("?") + 1) : ""
  const queryParameters = cleanUnique(rawQuery.split("&").map((part) => part.split("=", 1)[0] ?? "")
    .filter((name) => /^[A-Za-z0-9_.~[\]-]+$/.test(name)))
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
  const pathParameters = cleanUnique([...dynamic, ...normalizedPath.pathParameters])
  return { host, origin, path, urlTemplate: (origin ?? (host ? "https://" + host : "")) + path, pathParameters, queryParameters }
}

function addConcatenatedPathParameters(
  endpoint: NonNullable<ReturnType<typeof normalizeEndpoint>>,
  expression: string,
): NonNullable<ReturnType<typeof normalizeEndpoint>> {
  const first = expression.match(/(['"\x60])([^'"\x60]+)\1/)
  if (!first || first.index === undefined) return endpoint
  // A concatenation after ? or # belongs to query/fragment data, not the route path.
  if (first[2]!.includes("?") || first[2]!.includes("#")) return endpoint
  let path = endpoint.path
  let rest = expression.slice(first.index + first[0].length)
  const pathParameters = [...endpoint.pathParameters]
  for (;;) {
    const dynamic = rest.match(/^\s*\+\s*(?:(?:encodeURIComponent|String|Number)\s*\(\s*)?([A-Za-z_$][\w$]*)(?:\s*\))?/)
    if (!dynamic) break
    const name = dynamic[1]!
    // Infer a new path segment only when the source explicitly includes its separator.
    if (!path.endsWith("/")) break
    path += "{" + name + "}"
    pathParameters.push(name)
    rest = rest.slice(dynamic[0].length)
    const staticPart = rest.match(/^\s*\+\s*(['"\x60])([^'"\x60]*)\1/)
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
    pathParameters: cleanUnique(pathParameters),
  }
}

function findCallEnd(source: string, start: number, maxLength = source.length): number {
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
 * Bounded static heuristics only: never evaluates source. Secret-like matches retain only a
 * fingerprint and source line; values are never emitted in analysis output. Results remain candidates
 * until independently verified.
 */
export function analyzeJavaScriptSource(input: string): JavaScriptSourceAnalysis {
  const source = input
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
      .filter((p) => /^[A-Za-z_$][\w$]*$/.test(p)))
    functions.push({ name, line, parameters })
    functionOffsets.set(key, match.index ?? 0)
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
      .filter((p) => /^[A-Za-z_$][\w$]*$/.test(p)))
    functions.push({ name, line, parameters })
    functionOffsets.set(key, match.index ?? 0)
      }
  functions.sort((a, b) => a.line - b.line)
  const functionRanges = staticFunctionRanges(source, functions, functionOffsets)

  // Resolve function references into line-only call-site candidates. Store no source
  // excerpts, and label them as candidates because regex-based analysis is not an AST.
  for (const fn of functions) {
    const pattern = new RegExp("\\b" + escapeRegexLiteral(fn.name) + "\\b", "g")
    const declarationOffset = functionOffsets.get(fn.line + ":" + fn.name)
    const sites = new Map<string, JavaScriptCallSiteCandidate>()
    for (const match of source.matchAll(pattern)) {
      const index = match.index ?? 0
      if (declarationOffset !== undefined && index >= declarationOffset && index <= declarationOffset + fn.name.length + 12) continue
      const left = source.slice(Math.max(0, index - 140), index)
      const right = source.slice(index + fn.name.length, Math.min(source.length, index + fn.name.length + 40))
      let kind: JavaScriptCallSiteCandidate["kind"] | undefined
      if (/\b(?:onClick|onSubmit|onChange|onBlur|onKeyDown|onKeyUp|onPress|onVerify|onComplete|onSuccess)\s*=\s*\{\s*$/i.test(left)) {
        kind = "ui-event-binding"
      } else if (/\b(?:addEventListener|removeEventListener)\s*\(\s*[^,]+,\s*$/i.test(left) && /^\s*[,)]/.test(right)) {
        kind = "dom-event-listener"
      } else if (/\b(?:then|catch|finally|useEffect|useCallback|useMemo|map|filter|forEach|some|every|reduce)\s*\(\s*$/i.test(left) || /^\s*[,)]/.test(right) && /[,({]\s*$/.test(left)) {
        kind = "callback-reference"
      } else if (/^\s*\(/.test(right)) {
        kind = "direct-call"
      }
      if (!kind) {
        // Template event bindings are common in Vue/Angular templates embedded in JS/HTML.
        const lineStart = source.lastIndexOf("\n", index - 1) + 1
        const lineEndIndex = source.indexOf("\n", index)
        const lineText = source.slice(lineStart, lineEndIndex < 0 ? source.length : lineEndIndex)
        const hasTemplateEventAttribute = /(?:@(?:click|submit|change|keyup|keydown)|v-on:(?:click|submit|change)|ng-(?:click|submit))\s*=/.test(lineText)
        const referencesFunction = new RegExp("\\b" + escapeRegexLiteral(fn.name) + "\\b", "i").test(lineText)
        if (hasTemplateEventAttribute && referencesFunction) {
          kind = "ui-event-binding"
        }
      }
      if (!kind) continue
      const line = lineNumber(lineStarts, index)
      const caller = functionRanges
        .filter((range) => range.start <= index && index <= range.end && range.name !== fn.name)
        .sort((a, b) => (a.end - a.start) - (b.end - b.start))[0]
      sites.set(line + ":" + kind, {
        line,
        kind,
        callerFunctionName: caller?.name ?? null,
        confidence: "candidate",
      })
    }
    fn.callSites = [...sites.values()].sort((a, b) => a.line - b.line || a.kind.localeCompare(b.kind))
  }

  const requests: JavaScriptRequestCandidate[] = []
  const callPattern = /\b(fetch|axios\.(?:get|post|put|patch|delete|head|options|request)|[A-Za-z_$][\w$]*\.(?:get|post|put|patch|delete|head|options|request|open))\s*\(/gi
  const requestCallSpans = [...source.matchAll(callPattern)].map((call) => {
    const start = call.index ?? 0
    const open = start + call[0].lastIndexOf("(")
    const end = findCallEnd(source, open)
    return { start, end: end >= 0 ? end + 1 : start + call[0].length }
  }).sort((a, b) => a.start - b.start)
  for (const match of source.matchAll(callPattern)) {
    const index = match.index ?? 0, callee = (match[1] ?? "").toLowerCase()
    const open = index + match[0].lastIndexOf("(")
    const close = findCallEnd(source, open)
    if (close < 0) continue
    const args = splitTopLevelArguments(source.slice(open + 1, close))
    const isXHR = callee.endsWith(".open")
    const methodSuffix = /\.(get|post|put|patch|delete|head|options)$/i.exec(callee)?.[1]?.toUpperCase() ?? null
    const axiosMethod = methodSuffix
    const requestConfig = callee.endsWith(".request") && (args[0] ?? "").trim().startsWith("{")
    const urlExpression = isXHR ? args[1] ?? "" : args[0] ?? ""
    const literalMatch = requestConfig
      ? (args[0] ?? "").match(/\burl\s*:\s*["'\x60]([^"'\x60]+)["'\x60]/)
      : urlExpression.match(/['"\x60]([^'"\x60]+)['"\x60]/)
    if (!literalMatch) continue
    const normalizedEndpoint = normalizeEndpoint(literalMatch[1]!)
    if (!normalizedEndpoint) continue
    const endpoint = requestConfig ? normalizedEndpoint : addConcatenatedPathParameters(normalizedEndpoint, urlExpression)
    const currentFunctionRange = functionRanges.filter((range) => range.start <= index && index <= range.end)
      .sort((a, b) => (a.end - a.start) - (b.end - b.start))[0]
    const previousSpan = [...requestCallSpans].reverse().find((span) => span.end <= index)
    const nextSpan = requestCallSpans.find((span) => span.start > index)
    const lowerBound = Math.max(currentFunctionRange?.start ?? 0, previousSpan?.end ?? 0)
    const upperBound = Math.min(currentFunctionRange?.end ?? source.length - 1, nextSpan?.start ?? source.length)
    const requestContext = source.slice(lowerBound, Math.max(close + 1, upperBound))
    const isFetch = callee === "fetch"
    const isBodyMethod = /\.(?:post|put|patch)$/i.test(callee)
    const options = isXHR ? "" : requestConfig ? args[0] ?? "" : callee.endsWith(".request") ? args.slice(1).join(",")
      : isFetch ? args.slice(1).join(",") : /\.(?:get|head|options|delete)$/i.test(callee) ? args.slice(1).join(",") : args.slice(2).join(",")
    const optionText = options + "\n" + source.slice(index, close + 1)
    const methodOption = optionText.match(/\bmethod\s*:\s*["'](GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE)["']/i)
    const hasDynamicMethodOption = isFetch && /\bmethod\b/i.test(optionText) && !methodOption
    const inferredFetchMethod = isFetch && !hasDynamicMethodOption ? "GET" : undefined
    const method = (axiosMethod ?? methodOption?.[1] ?? (isXHR ? args[0]?.match(/["'](GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE)["']/i)?.[1] : inferredFetchMethod) ?? "").toUpperCase() || null
    const headers = [
      ...configObjectFields(optionText, "headers", source, index),
      ...Array.from(optionText.matchAll(/\[\s*\[\s*["']([^"']+)["']/g), (m) => m[1]!),
      ...Array.from(requestContext.matchAll(/(?:headers|requestHeaders)\s*\.\s*(?:set|append)\s*\(\s*["']([^"']+)["']/gi), (m) => m[1]!),
      ...Array.from(requestContext.matchAll(/\.setRequestHeader\s*\(\s*["']([^"']+)["']/gi), (m) => m[1]!),
      ...Array.from(requestContext.matchAll(/\b(Authorization|Cookie|Set-Cookie|X-CSRF-Token|X-XSRF-Token|X-API-Key)\b/gi), (m) => m[1]!),
    ]
    const bodyArgs = requestConfig ? "" : isBodyMethod ? args[1] ?? "" : isFetch ? options : ""
    const directObject = isBodyMethod && bodyArgs.trim().startsWith("{")
      ? bodyArgs.trim().slice(1, bodyArgs.trim().lastIndexOf("}")) : ""
    const bodySource = options + "\n" + bodyArgs + (requestConfig ? "\n" + (args[0] ?? "") : "")
    const bodyParams = [
      ...objectPropertyNames(directObject),
      ...Array.from(bodySource.matchAll(/\b(?:body|data)\s*:\s*\{([\s\S]*?)\}/gi), (m) => objectPropertyNames(m[1] ?? "")).flat(),
      ...Array.from(bodySource.matchAll(/JSON\.stringify\s*\(\s*\{([\s\S]*?)\}\s*\)/gi), (m) => objectPropertyNames(m[1] ?? "")).flat(),
      ...bodyVariableNames(bodySource).flatMap((name) => objectBindingFields(source, name, index)),
      ...(isBodyMethod && !requestConfig && /^[A-Za-z_$][\w$]*$/.test((args[1] ?? "").trim())
        ? objectBindingFields(source, (args[1] ?? "").trim(), index) : []),
    ]
    const all = optionText + "\n" + bodyArgs + "\n" + requestContext
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
    // Relative HTTP routes are same-origin in browser bundles. Unless the code
    // explicitly opts out of fetch credentials, browser defaults may attach cookies.
    // Keep this as an unconfirmed clue—not proof that a cookie exists or is accepted.
    if (!endpoint.origin && !/\bcredentials\s*:\s*["']omit["']/i.test(all)) {
      cookieSignals.push("relative-route-may-use-same-origin-cookies")
    }
    if (/\bdocument\.cookie\b/i.test(all)) cookieSignals.push("document-cookie-access")
    if (/\bCookie\b|\bcookie\s*:/i.test(all)) cookieSignals.push("cookie-header-signal")
    endpoint.queryParameters.push(
      ...configObjectFields(optionText, "params", source, index),
      ...configObjectFields(optionText, "searchParams", source, index),
      ...Array.from(all.matchAll(/new\s+URLSearchParams\s*\(\s*\{([\s\S]*?)\}/gi), (m) => objectPropertyNames(m[1] ?? "")).flat(),
      ...urlSearchParamsVariables(requestContext).flatMap((name) =>
        Array.from(requestContext.matchAll(new RegExp("(?<![\\w$])" + escapeRegexLiteral(name) + "(?![\\w$])\\s*\\.\\s*(?:set|append|get)\\s*\\(\\s*[\"']([^\"']+)[\"']", "gi")), (m) => m[1]!),
      ),
    )
    if (/\b(?:searchParams|URLSearchParams)\b/i.test(all)) {
      for (const m of all.matchAll(/(?:searchParams|URLSearchParams)(?:\.set|\.append|\.get)?\s*\(\s*["']([^"']+)["']/gi)) endpoint.queryParameters.push(m[1]!)
    }
    const line = lineNumber(lineStarts, index)
    const sourceFunction = currentFunctionRange?.name ?? null
    const item: JavaScriptRequestCandidate = {
      id: "js-request:" + createHash("sha256").update(JSON.stringify([line, endpoint.urlTemplate, method, cleanUnique(endpoint.pathParameters), cleanUnique(endpoint.queryParameters), cleanUnique(bodyParams), cleanUnique(headers)])).digest("hex").slice(0, 16),
      sourceFunction, method, urlTemplate: endpoint.urlTemplate, host: endpoint.host, origin: endpoint.origin, path: endpoint.path,
      pathParameters: endpoint.pathParameters, queryParameters: cleanUnique(endpoint.queryParameters),
      bodyParameters: cleanUnique(bodyParams), headerNames: cleanUnique(headers),
      authSignals: cleanUnique(authSignals), cookieSignals: cleanUnique(cookieSignals),
      authAssessment: authSignals.length || cookieSignals.length ? "signals-present" : "no-static-auth-signal",
      sourceLine: line, confidence: "candidate",
    }
    if (!requests.some((existing) => existing.id === item.id)) requests.push(item)
      }

  const secrets = new Map<string, JavaScriptSecretCandidate>()
  const addSecretCandidate = (kind: string, rawValue: string, index: number) => {
    const value = rawValue.trim()
    if (!value || /^(?:\$\{|\{\{|\$[A-Z_][A-Z0-9_]*|<[^>]+>)/i.test(value)) return
    const containingFunction = functionRanges
      .filter((range) => range.start <= index && index <= range.end)
      .sort((a, b) => (a.end - a.start) - (b.end - a.start))[0]
    const item: JavaScriptSecretCandidate = {
      kind,
      line: lineNumber(lineStarts, index),
      functionName: containingFunction?.name ?? null,
      fingerprint: createHash("sha256").update(value).digest("hex").slice(0, 20),
      confidence: "candidate",
    }
    // Keep every source location. The same token may appear in multiple call paths;
    // collapsing on kind+fingerprint would discard the other function/line evidence.
    secrets.set([item.kind, item.fingerprint, item.line, item.functionName ?? ""].join(":"), item)
  }
  const secretPattern = /\b(api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|secret[_-]?key|password|passwd|private[_-]?key)\b\s*[:=]\s*(['"\x60])([^'"\x60\r\n]{8,})\2/gi
  for (const match of source.matchAll(secretPattern)) {
    addSecretCandidate(
      (match[1] ?? "secret").toLowerCase().replace(/[_-]+/g, "-"),
      match[3] ?? "",
      match.index ?? 0,
    )
  }
  // Recognize common provider token formats even when the variable name is generic.
  // Only a fingerprint and source location are retained, never the matched value.
  const signatureSecretPatterns: Array<{ kind: string; pattern: RegExp }> = [
    { kind: "aws-access-key-id", pattern: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g },
    { kind: "google-api-key", pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g },
    { kind: "github-token", pattern: /\b(?:gh[pousr]_[A-Za-z0-9_]{30,255}|github_pat_[A-Za-z0-9_]{30,255})\b/g },
    { kind: "slack-token", pattern: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g },
    { kind: "stripe-secret-key", pattern: /\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b/g },
    { kind: "jwt-like-token", pattern: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g },
  ]
  for (const rule of signatureSecretPatterns) {
    for (const match of source.matchAll(rule.pattern)) {
      addSecretCandidate(rule.kind, match[0] ?? "", match.index ?? 0)
    }
  }

  // Sensitive-data indicators retain field/class and source location only. Matched values
  // are deliberately discarded; these are static leads, not proof of a data leak.
  const dataExposureSignals = new Map<string, JavaScriptDataExposureSignal>()
  const addDataExposureSignal = (kind: JavaScriptDataExposureSignal["kind"], field: string | null, index: number) => {
    const containingFunction = functionRanges
      .filter((range) => range.start <= index && index <= range.end)
      .sort((a, b) => (a.end - a.start) - (b.end - b.start))[0]
    const item: JavaScriptDataExposureSignal = {
      kind,
      field,
      line: lineNumber(lineStarts, index),
      functionName: containingFunction?.name ?? null,
      confidence: "candidate",
    }
    dataExposureSignals.set([kind, field ?? "", item.line, item.functionName ?? ""].join(":"), item)
  }
  const sensitiveFieldPattern = /\b(email|emailAddress|phone|phoneNumber|mobile|address|postalAddress|dateOfBirth|dob|ssn|socialSecurityNumber|passportNumber|nationalId|taxId|iban|bankAccount|cardNumber|paymentDetails|medicalRecord|accessToken|refreshToken|sessionToken|password|apiKey|clientSecret|privateKey|resetToken)\b["']?\s*:/gi
  for (const match of source.matchAll(sensitiveFieldPattern)) {
    addDataExposureSignal("sensitive-field", (match[1] ?? "").toLowerCase(), match.index ?? 0)
  }
  const embeddedEmailPattern = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi
  for (const match of source.matchAll(embeddedEmailPattern)) {
    addDataExposureSignal("embedded-email-address", null, match.index ?? 0)
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
    { kind: "wildcard-postmessage-origin", regex: /\bpostMessage\s*\([^,]+,\s*["']\*["']\s*\)/gi },
    { kind: "message-event-handler", regex: /\baddEventListener\s*\(\s*["']message["']/gi },
    { kind: "client-side-token-storage", regex: /\b(?:localStorage|sessionStorage)\.setItem\s*\(\s*["'][^"']+(?:token|auth|session|secret|key)[^"']*["']/gi },
    { kind: "document-cookie-write", regex: /\bdocument\.cookie\s*=/gi },
    { kind: "dynamic-regexp", regex: /\bnew\s+RegExp\s*\(\s*[A-Za-z_$]/gi },
    { kind: "prototype-mutation", regex: /\b(?:__proto__|prototype)\s*(?:\[|\.)/gi },
  ]
  const riskSignals = new Map<string, JavaScriptRiskSignal>()
  for (const rule of riskRules) for (const match of source.matchAll(rule.regex)) {
    const index = match.index ?? 0, line = lineNumber(lineStarts, index)
    const containingFunction = functionRanges
      .filter((range) => range.start <= index && index <= range.end)
      .sort((a, b) => (a.end - a.start) - (b.end - b.start))[0]
    const functionName = containingFunction?.name ?? null
    const id = "js-risk:" + createHash("sha256").update(rule.kind + ":" + line + ":" + (functionName ?? "")).digest("hex").slice(0, 16)
    riskSignals.set(id, { id, kind: rule.kind, line, functionName, confidence: "candidate" })
      }
  // A state-changing request with an explicit browser credential/cookie signal
  // deserves CSRF review. This is only a candidate: static code cannot prove the
  // server's cookie policy, token validation, Origin/Referer checks, or impact.
  for (const request of requests) {
    const method = request.method?.toUpperCase()
    if (!method || !["POST", "PUT", "PATCH", "DELETE"].includes(method)) continue
    const mayUseBrowserCredentials = request.cookieSignals.some((signal) =>
      signal === "credentialed-request-may-send-cookies" ||
      signal === "cookie-header-signal" ||
      signal === "document-cookie-access" ||
      signal === "relative-route-may-use-same-origin-cookies",
    )
    if (!mayUseBrowserCredentials) continue
    const kind = "csrf-review-state-changing-cookie-request"
    const id = "js-risk:" + createHash("sha256")
      .update(kind + ":" + request.sourceLine + ":" + (request.sourceFunction ?? "") + ":" + request.urlTemplate)
      .digest("hex")
      .slice(0, 16)
    riskSignals.set(id, {
      id,
      kind,
      line: request.sourceLine,
      functionName: request.sourceFunction,
      confidence: "candidate",
    })
  }

  for (const match of source.matchAll(rolePattern)) {
    const value = match[1]!, lower = value.toLowerCase()
    const kind = /admin|superuser/.test(lower) ? "admin-role-hint" : /role|permission/.test(lower) ? "authorization-hint"
      : /feature.?flag/.test(lower) ? "feature-flag-hint" : /debug/.test(lower) ? "debug-path-hint"
      : /impersonat/.test(lower) ? "impersonation-hint" : "internal-feature-hint"
    const index = match.index ?? 0
    const functionName = functionRanges
      .filter((range) => range.start <= index && index <= range.end)
      .sort((a, b) => (a.end - a.start) - (b.end - b.start))[0]?.name ?? null
    const item = { kind, value, line: lineNumber(lineStarts, index), functionName }
    roles.set(kind + ":" + value + ":" + item.line, item)
      }

  // Broad app intelligence is independent of vulnerability signatures. These
  // hints record useful product flows, protocols and integrations for later review.
  const applicationHints = new Map<string, JavaScriptApplicationHint>()
  const applicationHintRules: Array<{ kind: string; pattern: RegExp; capture?: number }> = [
    { kind: "graphql-operation", pattern: /\b(?:query|mutation|subscription)\s+([A-Za-z_][\w$]*)/g, capture: 1 },
    { kind: "graphql-introspection", pattern: /\b(?:__schema|__type|IntrospectionQuery)\b/g },
    { kind: "websocket-client", pattern: /\bnew\s+WebSocket\s*\(/g },
    { kind: "service-worker", pattern: /\bnavigator\.serviceWorker\.register\s*\(/g },
    { kind: "environment-config", pattern: /\b(?:process\.env|import\.meta\.env)\.([A-Za-z_$][\w$]*)/g, capture: 1 },
    { kind: "frontend-framework", pattern: /\b(?:ReactDOM|React|Vue|Angular|Svelte|Next\.js|Nuxt|Remix|SolidJS|Astro|Webpack|Vite|Rollup|esbuild|Babel|TypeScript)\b/gi },
    { kind: "api-client-or-rpc", pattern: /\b(?:axios|fetch|XMLHttpRequest|superagent|graphql-request|ApolloClient|urql|RelayEnvironment|tRPC|grpc-web|connectrpc|WebSocket|EventSource)\b/gi },
    { kind: "identity-session-flow", pattern: /\b(?:OAuth2?|OIDC|OpenID|SAML|SSO|WebAuthn|passkeys?|MFA|TOTP|passwordReset|forgotPassword|signIn|signOut|logIn|logOut|login|logout|register|refreshToken|accessToken|session)\b/gi },
    { kind: "business-workflow", pattern: /\b(?:upload|download|export|import|payment|billing|checkout|invoice|refund|payout|subscription|wallet|coupon|discount|order|cart|shipment|webhook|integration|invite|invitation|organization|tenant|workspace|impersonation|moderation)\b/gi },
    { kind: "authorization-feature-boundary", pattern: /\b(?:owner|tenant|organization|workspace|role|permission|isAdmin|adminOnly|superuser|impersonate|featureFlag|feature_flag|debugMode|internalOnly)\b/gi },
    { kind: "browser-persistence", pattern: /\b(?:localStorage|sessionStorage|indexedDB|caches|document\.cookie)\b/g },
    { kind: "cross-context-messaging", pattern: /\b(?:postMessage|BroadcastChannel|MessageChannel|SharedWorker|ServiceWorker|serviceWorker)\b/g },
    { kind: "telemetry-monitoring-sdk", pattern: /\b(?:Sentry|Datadog|NewRelic|OpenTelemetry|Mixpanel|Segment|PostHog|Amplitude|LogRocket|FullStory|Bugsnag|Honeycomb)\b/gi },
    { kind: "crypto-token-library", pattern: /\b(?:JWT|jsonwebtoken|jose|decodeJwt|verifyJwt|crypto\.subtle|WebCrypto|createHmac)\b/gi },
  ]
  for (const rule of applicationHintRules) {
    for (const match of source.matchAll(rule.pattern)) {
      const value = (rule.capture ? match[rule.capture] : match[0])?.trim()
      if (!value || value.length > 160) continue
      const index = match.index ?? 0
      const functionName = functionRanges
        .filter((range) => range.start <= index && index <= range.end)
        .sort((a, b) => (a.end - a.start) - (b.end - b.start))[0]?.name ?? null
      const item: JavaScriptApplicationHint = {
        kind: rule.kind,
        value,
        line: lineNumber(lineStarts, index),
        functionName,
        confidence: "candidate",
      }
      applicationHints.set(item.kind + ":" + item.value + ":" + item.line, item)
    }
  }
  // Preserve business/authentication workflows and data-operation vocabulary as
  // structured leads, not findings. Values are rule labels/names only; no source text
  // or token values are retained in this inventory.
  const workflowSignals = new Map<string, JavaScriptWorkflowSignal>()
  const workflowRules: Array<{ kind: string; pattern: RegExp; capture?: number }> = [
    { kind: "email-verification-flow", pattern: /\b(?:verifyEmailToken|verifyEmailAddress|confirmEmailToken|verify_email_token|verifyEmail|verify_email|emailVerification|email_verification|verificationCode|verificationToken|emailToken|confirmEmail|confirm_email|sendVerificationEmail|resendVerification|magicLink|activationToken|emailVerified|email_verified)\b/gi },
    { kind: "account-recovery-flow", pattern: /\b(?:forgotPassword|forgot_password|passwordReset|password_reset|resetPassword|reset_password|recoveryCode|recoveryToken|resetToken)\b/gi },
    { kind: "one-time-code-or-mfa-flow", pattern: /\b(?:\bOTP\b|oneTimePassword|one_time_password|verificationCode|securityCode|TOTP|MFA|WebAuthn|passkeyChallenge)\b/gi },
    { kind: "token-creation-or-signing", pattern: /\b(?:jwt\s*\.\s*sign|signJwt|createJwt|generateJwt|createToken|generateToken|mintToken|issueToken|signToken|createHmac|crypto\s*\.\s*subtle\s*\.\s*sign)\b/gi },
    { kind: "token-decode-or-parse", pattern: /\b(?:jwt\s*\.\s*decode|decodeJwt|decodeToken|parseJwt|atob|base64url|Buffer\s*\.\s*from)\b/gi },
    { kind: "token-verification-or-validation", pattern: /\b(?:jwt\s*\.\s*verify|verifyJwt|verifyToken|validateToken|validateJwt|crypto\s*\.\s*subtle\s*\.\s*verify)\b/gi },
    { kind: "token-expiry-or-lifetime", pattern: /\b(?:expiresIn|expiresAt|expiry|expiration|tokenTtl|tokenTTL|clockTolerance|notBefore|issuedAt|\bexp\b|\bnbf\b|\biat\b)\b/gi },
    { kind: "sql-statement-candidate", pattern: /\b(SELECT|INSERT\s+INTO|UPDATE\s+[A-Za-z_][\w.]*\s+SET|DELETE\s+FROM)\b/gi, capture: 1 },
    { kind: "data-layer-operation-candidate", pattern: /(\$queryRaw|\$executeRaw|\b(?:query|execute|prepare|findUnique|findMany|findFirst|createMany|updateMany|deleteMany|select|insert|update|delete)\b)\s*\(/gi, capture: 1 },
    { kind: "email-delivery-flow", pattern: /\b(?:sendEmail|sendMail|sendVerification|resendVerification|mailer|emailService|emailProvider|emailTemplate)\b/gi },
  ]
  for (const rule of workflowRules) {
    for (const match of source.matchAll(rule.pattern)) {
      const rawValue = (rule.capture ? match[rule.capture] : match[0])?.trim()
      if (!rawValue || rawValue.length > 100) continue
      const index = match.index ?? 0
      const line = lineNumber(lineStarts, index)
      const containingFunction = functionRanges
        .filter((range) => range.start <= index && index <= range.end)
        .sort((a, b) => (a.end - a.start) - (b.end - b.start))[0]
      // A marker may be the function's own name in its declaration header, which is
      // intentionally outside the lexical body span. Attribute that case to the
      // declared function on the same line instead of mislabelling it top-level.
      const declaredFunction = functions.find((fn) => fn.line === line && fn.name === rawValue)
      const item: JavaScriptWorkflowSignal = {
        kind: rule.kind,
        value: rule.kind === "sql-statement-candidate" ? rawValue.toUpperCase().split(/\s+/)[0]!
          : rule.kind === "data-layer-operation-candidate" ? rawValue
          : rawValue,
        line,
        functionName: containingFunction?.name ?? declaredFunction?.name ?? null,
        confidence: "candidate",
      }
      workflowSignals.set(item.kind + ":" + item.value.toLowerCase() + ":" + item.line + ":" + (item.functionName ?? ""), item)
    }
  }

  return {
    functions, requests, secretCandidates: [...secrets.values()], roleHints: [...roles.values()], riskSignals: [...riskSignals.values()],
    applicationHints: [...applicationHints.values()],
    workflowSignals: [...workflowSignals.values()],
    dataExposureSignals: [...dataExposureSignals.values()],
    notes: [
      "Static heuristics only; dynamic strings, destructured parameters and minified bundles may be missed.",
      "No static auth/cookie signal does not prove an endpoint is unauthenticated; inspect captured requests and server behavior.",
      "Secret-like values are never retained; only fingerprints, source locations, and candidate status are emitted.",
      "Static sink signals are triage candidates, can be false positives in comments/vendor code, and do not prove taint or exploitability.",
      "CSRF review candidates require a state-changing request plus a static browser credential/cookie signal; they do not prove the server lacks anti-CSRF controls.",
      "Function attribution uses lexical body spans; minified or complex TypeScript syntax may remain unattributed.",
    ],
  }
}
