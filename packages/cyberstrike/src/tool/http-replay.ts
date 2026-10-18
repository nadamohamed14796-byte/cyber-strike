// http_replay / http_replay_raw — the agent-facing tool surface for the replay
// engine (docs/http-replay-engine-design.md §3.14). Thin CS glue over the
// verified engine in ../replay: resolve a captured request, apply mutations (or
// take raw bytes), send it through a governed backend, and hand back FACTS
// (status, timing, reflection, error signatures, a curl-equivalent) — never a
// verdict. Modeled on tool/inject-probe.ts (request resolution + scope guard).
//
// Payloads travel as request DATA through the engine, never a shell — this is
// the whole point: it replaces the curl-in-bash confirm/weaponize path.

import z from "zod"
import { Tool } from "./tool"
import { Session } from "../session"
import { Request } from "../session/request"
import { WebCredential, COMMON_AUTH_HEADERS } from "../session/web/web-credential"
import { credentialForSession } from "../session/web/credential-scope"
import { HttpMessage } from "../replay/message"
import { Apply } from "../replay/apply"
import { Send } from "../replay/send"
import { Governor } from "../replay/governor"
import { BackendFetch } from "../replay/backend-fetch"
import { BackendSocket } from "../replay/backend-socket"
import { ReplayResponse } from "../replay/response"
import { Observe } from "../replay/observe"
import { Mutate } from "../replay/mutate"
import { Batch } from "../replay/batch"
import { Network } from "../network/network"
import { TargetMemory } from "../target"

// Encode codecs mirrored as a zod enum for the tool schema (kept in sync with
// Encode.Codec in ../replay/encode.ts).
const CODEC = z.enum([
  "url",
  "url-all",
  "url-double",
  "base64",
  "base64url",
  "hex",
  "html-dec",
  "html-hex",
  "unicode",
  "upper",
  "lower",
])

const MUTATION = z.object({
  op: z.enum([
    "set-query",
    "add-query",
    "remove-query",
    "set-header",
    "add-header",
    "remove-header",
    "set-body",
    "set-method",
    "set-target",
    "body-merge",
    "body-set-field",
    "body-remove-field",
    "set-cookie",
    "remove-cookie",
    "set-path-param",
  ]),
  name: z
    .string()
    .optional()
    .describe(
      "param/header/cookie name, JSON field dot-path (body-set-field/body-remove-field), or path segment position as a 0-based string for set-path-param — the position COUNTS the leading empty segment, so in `/rest/products/1/reviews` the id `1` is position 3 (segments: ['', 'rest', 'products', '1', 'reviews']). To rewrite a path id, prefer `set-target` (full request-target) to avoid position miscounts. Required for query/header/cookie/body-field/path-param ops.",
    ),
  value: z
    .string()
    .optional()
    .describe(
      "new value; the method for set-method, the request-target for set-target, JSON string for body-merge, new path segment value for set-path-param",
    ),
  encode: z
    .array(CODEC)
    .optional()
    .describe('encode pipeline applied to value before it is set (e.g. ["url","url"] for double-encode)'),
})

// Compare side — each side of a compare can independently set credential,
// unauthenticated, and mutations.
const COMPARE_SIDE = z.object({
  credential: z.string().optional().describe("Credential ID to use for this side of the comparison"),
  unauthenticated: z.boolean().optional().describe("Strip all auth headers for this side"),
  mutations: z.array(MUTATION).optional().describe("Mutations specific to this side"),
})

function safeURL(u: string): URL | undefined {
  try {
    return new URL(u)
  } catch {
    return undefined
  }
}

function httpOrigin(value: string): string | undefined {
  const url = safeURL(value)
  if (
    !url ||
    (url.protocol !== "http:" && url.protocol !== "https:") ||
    url.username ||
    url.password
  ) return undefined
  return url.origin
}

// Derive and validate the actual HTTP(S) origin from a captured request.
function originOf(request: Request.Info): string | { error: string } {
  if (request.origin) {
    const origin = httpOrigin(request.origin)
    if (origin) return origin
    return { error: "captured request has an invalid or unsupported HTTP origin" }
  }
  const host = request.host
  if (!host) return { error: "request has no host/origin — cannot resolve a sendable origin" }
  const scheme = request.scheme ?? "http"
  const port = request.port ? `:${request.port}` : ""
  const origin = httpOrigin(`${scheme}://${host}${port}`)
  if (!origin) return { error: "captured request has an invalid or unsupported HTTP origin" }
  return origin
}

// Exact-origin allowlisting avoids turning a captured hostname into permission
// to probe arbitrary services on another port or via another scheme.
function inScope(sessionID: string, destination: string): boolean {
  const wanted = httpOrigin(destination)
  if (!wanted) return false
  const allowed = new Set(
    Request.get(sessionID)
      .map((request) => originOf(request))
      .filter((origin): origin is string => typeof origin === "string")
      .map((origin) => httpOrigin(origin))
      .filter((origin): origin is string => Boolean(origin)),
  )
  return allowed.has(wanted)
}

// Build a base message + origin from a constructed target (the FALLBACK source
// when no captured request_id is given). Mirrors what HttpMessage.parse would
// produce for a captured request, so all downstream modes treat it identically.
function buildFromTarget(t: {
  method: string
  url: string
  headers?: Record<string, string>
  body?: string
}): { baseMsg: HttpMessage.Request; origin: string } | { error: string } {
  const url = safeURL(t.url)
  if (!url) return { error: `Invalid target url "${t.url}".` }
  if (
    (url.protocol !== "http:" && url.protocol !== "https:") ||
    url.username ||
    url.password
  ) return { error: "Target URL must be HTTP(S) and must not contain embedded credentials." }
  const headers: HttpMessage.Header[] = [{ name: "Host", value: url.host }]
  if (t.headers) for (const [name, value] of Object.entries(t.headers)) headers.push({ name, value: String(value) })
  const body = t.body != null ? new TextEncoder().encode(t.body) : new Uint8Array(0)
  if (body.length > 0 && !headers.some((h) => h.name.toLowerCase() === "content-length")) {
    headers.push({ name: "Content-Length", value: String(body.length) })
  }
  const baseMsg: HttpMessage.Request = {
    method: t.method.toUpperCase(),
    target: (url.pathname || "/") + url.search,
    version: "HTTP/1.1",
    headers,
    body,
  }
  return { baseMsg, origin: url.origin }
}

const BODY_PREVIEW = 4096
const SECRET_HEADER = /^(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|api-key|x-auth-token|x-access-token|x-session-token|x-csrf-token)$/i

function redactSensitiveText(value: string): string {
  return value
    .replace(/\bBearer\s+[A-Za-z0-9._~+/=-]+/gi, "Bearer [REDACTED]")
    .replace(/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, "[JWT REDACTED]")
    .replace(/([?&](?:access[_-]?token|refresh[_-]?token|token|api[_-]?key|client[_-]?secret|password|session(?:id)?|sid|auth|code)=)[^&#\s]*/gi, "$1[REDACTED]")
    .replace(/([\"']?(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|api[_-]?key|access[_-]?token|refresh[_-]?token|password|client[_-]?secret|session(?:id)?|csrf(?:token)?)[\"']?\s*[:=]\s*)(\"(?:\\\\.|[^\"\\\\])*\"|'(?:\\\\.|[^'\\\\])*'|[^,\\s;}\\r\\n]+)/gi, "$1[REDACTED]")
}

function redactRequestForOutput(msg: HttpMessage.Request): HttpMessage.Request {
  // Query strings can carry credentials too. Sanitize only the agent-facing copy;
  // the original request remains unchanged for the actual send and local evidence.
  const target = redactSensitiveText(msg.target)
  const headers = msg.headers.map((header) => ({
    ...header,
    value: SECRET_HEADER.test(header.name) ? "[REDACTED]" : redactSensitiveText(header.value),
  }))
  let body = msg.body
  try {
    const decoded = new TextDecoder("utf-8", { fatal: true }).decode(msg.body)
    if (!/[\x00-\x08\x0b\x0c\x0e-\x1f]/.test(decoded)) {
      body = new TextEncoder().encode(redactSensitiveText(decoded))
    } else if (msg.body.length > 0) {
      body = new Uint8Array()
    }
  } catch {
    // Do not serialize binary or malformed request bodies into agent output.
    body = new Uint8Array()
  }
  if (body.length === 0) {
    for (let i = headers.length - 1; i >= 0; i--) {
      if (["content-length", "transfer-encoding"].includes(headers[i].name.toLowerCase())) headers.splice(i, 1)
    }
  } else {
    const contentLength = headers.find((header) => header.name.toLowerCase() === "content-length")
    if (contentLength) contentLength.value = String(body.length)
  }
  return { ...msg, target, headers, body }
}

function curlTemplate(msg: HttpMessage.Request, origin: string): string {
  return Apply.toCurl(redactRequestForOutput(msg), origin)
}

function summarize(result: ReplayResponse.Result, marker?: string): Record<string, unknown> {
  if (result.error) {
    return { sent: true, error: result.error, timing: result.timing, attempts: (result as Send.Result).attempts }
  }
  const res = result.response!
  const bodyText = new TextDecoder("latin1").decode(res.body)
  const out: Record<string, unknown> = {
    status: res.status,
    reason: res.reason,
    timing_ms: Math.round(result.timing.totalMs),
    ttfb_ms: result.timing.ttfbMs !== undefined ? Math.round(result.timing.ttfbMs) : undefined,
    response_headers: res.headers.slice(0, 40).map(({ name, value }) => ({
      name,
      value: SECRET_HEADER.test(name) ? "[REDACTED]" : redactSensitiveText(value).slice(0, 2048),
    })),
    body_len: res.body.length,
    body_preview: redactSensitiveText(bodyText).slice(0, BODY_PREVIEW),
    body_truncated: res.body.length > BODY_PREVIEW,
    error_signatures: Observe.errorSignatures(res.body),
    attempts: (result as Send.Result).attempts,
  }
  if (marker) out.reflection = Observe.reflection(res.body, marker)
  return out
}

// ── Auth helpers ──────────────────────────────────────────────────────────────

function stripAuthHeaders(msg: HttpMessage.Request): HttpMessage.Request {
  let out = msg
  for (const h of COMMON_AUTH_HEADERS) {
    out = Mutate.removeHeader(out, h)
  }
  return out
}

function applyCredential(
  msg: HttpMessage.Request,
  credentialID: string,
  sessionID: string,
): HttpMessage.Request | { error: string } {
  const cred = credentialForSession(WebCredential.getById(credentialID), sessionID)
  if (!cred) {
    return { error: `Credential "${credentialID}" not found in this session or belongs to another session.` }
  }
  let out = stripAuthHeaders(msg)
  for (const [name, value] of Object.entries(cred.headers)) {
    out = Mutate.setHeader(out, name, value)
  }
  return out
}

function applyAuthParams(
  msg: HttpMessage.Request,
  opts: { credential?: string; unauthenticated?: boolean },
  sessionID: string,
): HttpMessage.Request | { error: string } {
  if (opts.unauthenticated) return stripAuthHeaders(msg)
  if (opts.credential) return applyCredential(msg, opts.credential, sessionID)
  return msg
}

/**
 * TLS certificate validation is the secure default. Invalid/self-signed
 * certificates may be accepted only when a caller explicitly opts in.
 */
export function shouldRejectUnauthorized(insecureTls?: boolean): boolean {
  return insecureTls !== true
}

// ── Governed send wrapper ─────────────────────────────────────────────────────

async function sendGoverned(
  msg: HttpMessage.Request,
  origin: string,
  opts: {
    insecure_tls?: boolean
    total_timeout_ms?: number
    follow_redirects?: boolean
    signal?: AbortSignal
    redirectScopeCheck?: (url: string) => Promise<boolean>
  },
): Promise<Send.Result> {
  const outbound = await Network.forUrl(origin)
  const budget = new Governor.GlobalBudget()
  const breaker = new Governor.CircuitBreaker()
  return Send.governed(
    () =>
      BackendFetch.send(msg, {
        origin,
        rejectUnauthorized: Network.rejectUnauthorized(opts.insecure_tls, outbound),
        proxy: outbound.proxy,
        ca: outbound.ca,
        clientCertificate: outbound.clientCertificate,
        totalTimeoutMs: opts.total_timeout_ms,
        followRedirects: opts.follow_redirects,
        redirectScopeCheck: opts.redirectScopeCheck,
        signal: opts.signal,
      }),
    msg.method,
    { budget, breaker },
    {},
  )
}

// ── Diff builder ──────────────────────────────────────────────────────────────

function buildDiff(baseline: ReplayResponse.Result, exploit: ReplayResponse.Result): Record<string, unknown> {
  const bs = baseline.response
  const ex = exploit.response

  if (!bs || !ex) {
    return {
      comparable: false,
      baseline_error: baseline.error?.message ?? null,
      exploit_error: exploit.error?.message ?? null,
    }
  }

  const baseBody = new TextDecoder("latin1").decode(bs.body)
  const expBody = new TextDecoder("latin1").decode(ex.body)

  return {
    comparable: true,
    status_match: bs.status === ex.status,
    baseline_status: bs.status,
    exploit_status: ex.status,
    body_length_match: bs.body.length === ex.body.length,
    baseline_body_len: bs.body.length,
    exploit_body_len: ex.body.length,
    body_content_match: baseBody === expBody,
    timing_delta_ms: Math.round((exploit.timing.totalMs ?? 0) - (baseline.timing.totalMs ?? 0)),
  }
}

type ReplayNoteMutation = { op: string; name?: string }
function resultFacts(result: ReplayResponse.Result) {
  return {
    status: result.response?.status ?? null,
    response_bytes: result.response?.body.length ?? null,
    duration_ms: Math.round(result.timing.totalMs ?? 0),
    send_error: result.error ? result.error.kind : null,
  }
}

function redactedDiffFacts(diff: Record<string, unknown>) {
  const allowed = [
    "comparable", "status_match", "baseline_status", "exploit_status",
    "body_length_match", "baseline_body_len", "exploit_body_len",
    "body_content_match", "timing_delta_ms",
  ]
  return Object.fromEntries(allowed
    .filter((key) => typeof diff[key] === "boolean" || (typeof diff[key] === "number" && Number.isFinite(diff[key])))
    .map((key) => [key, diff[key]]))
}
function mutationLabels(mutations?: ReplayNoteMutation[]) {
  return (mutations ?? []).map((mutation) =>
    mutation.op + (mutation.name ? "(" + mutation.name.slice(0, 100) + ")" : ""),
  ).slice(0, 30)
}

function sanitizeEndpointPath(value: string): string {
  return value.split("/").map((segment) => {
    if (!segment) return segment
    let decoded = segment
    try { decoded = decodeURIComponent(segment) } catch { /* retain the encoded segment */ }
    if (/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(decoded)) return "{uuid}"
    if (/^\d+$/.test(decoded)) return "{id}"
    if (/^[^/@\s]+@[^/@\s]+\.[^/@\s]+$/.test(decoded)) return "{email}"
    if (/^eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$/.test(decoded)) return "{token}"
    if (decoded.length >= 48 && /^[A-Za-z0-9_-]+$/.test(decoded)) return "{value}"
    return segment
  }).join("/")
}


/**
 * Keep a redacted per-endpoint history in the existing target workspace.
 * This records observation facts only: never request/response bodies, header values,
 * query values, mutation values, or credential IDs. Out-of-scope/path-unmatched
 * workspaces are not created as a side effect of replay.
 */
async function recordReplayObservation(input: {
  sessionID: string
  origin: string
  method: string
  requestTarget: string
  sourceRequestID?: string
  mode: "single" | "compare" | "sweep"
  mutationLabels: string[]
  summary: Record<string, unknown>
  manualReview: boolean
}): Promise<boolean> {
  try {
    const originURL = safeURL(input.origin)
    if (!originURL) return false
    const requestPath = (input.requestTarget.split("?", 1)[0] ?? "/").split("#", 1)[0] || "/"
    const endpointPath = sanitizeEndpointPath(requestPath)
    const eligible = TargetMemory.list().filter((workspace) => {
      const target = safeURL(workspace.targetURL)
      if (!target || target.origin !== originURL.origin) return false
      const prefix = target.pathname.replace(/\/+$/, "") || "/"
      return prefix === "/" || requestPath === prefix || requestPath.startsWith(prefix + "/")
    }).sort((a, b) => {
      const aPath = safeURL(a.targetURL)?.pathname.replace(/\/+$/, "").length ?? 0
      const bPath = safeURL(b.targetURL)?.pathname.replace(/\/+$/, "").length ?? 0
      return bPath - aPath
    })
    const workspace = eligible[0]
    if (!workspace || !TargetMemory.isObservedInSession(input.sessionID, workspace.targetURL)) return false
    const now = new Date().toISOString()
    const endpoint = input.method.toUpperCase() + " " + endpointPath
    const content = [
      "Test execution time: " + now,
      "Endpoint: " + endpoint,
      "Origin: " + originURL.origin,
      "Mode: " + input.mode,
      "Captured request ID: " + (input.sourceRequestID ?? "constructed request (same captured origin)"),
      "Mutation operations (values deliberately omitted): " + (input.mutationLabels.length ? input.mutationLabels.join(", ") : "none"),
      "Result facts: " + JSON.stringify(input.summary),
      "Assessment: observation only; this record is not a vulnerability verdict or proof the endpoint is safe.",
      "Follow-up: " + (input.manualReview
        ? "Manual review required: compare against the baseline and verify server-side validation/authorization with controlled test accounts."
        : "Review the recorded response facts against a baseline; absence of a difference is not proof of safety."),
    ].join("\n")
    await TargetMemory.addNote(workspace.targetURL, {
      kind: "endpoint",
      title: ("HTTP replay: " + endpoint).slice(0, 180),
      content,
      source: "http-replay:" + input.sessionID,
      status: "observed",
      tags: ["http-replay", "endpoint-test", input.mode, ...(input.manualReview ? ["manual-review"] : [])],
    })
    return true
  } catch {
    // A note-write error must not hide the actual request/response from the caller.
    return false
  }
}

// ── http_replay (structured) ─────────────────────────────────────────────────

const REPLAY_DESC = `Replay a captured request with field-level mutations, sent through the structured (fetch) backend — no shell, so payloads land as request DATA byte-for-byte.

Resolve request_id, apply mutations[] (set/add/remove query & header, set body/method/target, body-merge, body-set-field, body-remove-field, set-cookie, remove-cookie, set-path-param — each value optionally passed through an encode pipeline), then send once (governed: timeout, retry only on transient+idempotent, budget, circuit breaker). Returns FACTS: status, timing, response headers/body preview, error-signature hits, and (if you pass a marker) whether that marker reflected raw vs html-encoded — plus a redacted curl template; sensitive headers, tokens, and binary bodies are omitted. It never decides "vulnerable"; you judge the observations.

Special modes:
- **credential**: Swap auth headers — pass a session credential ID and the engine strips all auth headers from the captured request and injects the credential's headers. Use for cross-credential IDOR testing.
- **unauthenticated**: Strip all auth headers (Cookie, Authorization, etc.) from the request.
- **compare**: Send baseline + exploit in ONE call and get a structured diff (status match, body length, body content, timing delta). Each side independently configures credential/unauthenticated/mutations.
- **sweep**: Test multiple values for one mutation in a single call. Returns an array of results.
- **follow_redirects**: Follow 3xx redirects (default: false — manual redirect for pentest visibility).

Source: usually a captured **request_id** (PRIMARY — carries the real auth, cookies and headers, so prefer it whenever the endpoint was captured). For an endpoint the crawl never captured, pass a constructed **target** {method, url, headers?, body?} instead (FALLBACK) — the same captured-host scope guard applies, so it can reach an un-captured path but not a new host. Give exactly one of request_id / target.

Use for confirm/weaponize instead of building curl in bash. For byte-exact / smuggling / malformed requests use http_replay_raw.`

export const HttpReplayTool = Tool.define("http_replay", {
  description: REPLAY_DESC,
  parameters: z.object({
    request_id: z
      .string()
      .optional()
      .describe(
        "PRIMARY source — ID of a captured request to replay (its real URL, headers, cookies, auth). ALWAYS use this when the endpoint was already captured. Provide EITHER request_id OR target, never both.",
      ),
    target: z
      .object({
        method: z.string().describe("HTTP method, e.g. GET or POST."),
        url: z
          .string()
          .describe(
            "Absolute URL incl. scheme and host, e.g. https://host/api/x?y=1. Host must be one the crawl captured.",
          ),
        headers: z
          .record(z.string(), z.string())
          .optional()
          .describe("Extra request headers (Host is derived from url)."),
        body: z.string().optional().describe("Request body, if any."),
      })
      .optional()
      .describe(
        "FALLBACK source — construct a request from scratch. Use ONLY when the endpoint was NOT captured (e.g. one you inferred by reasoning). NEVER use when a matching captured request_id exists (you would lose the real cookies/headers). mutations/credential/compare/sweep apply to it exactly as to a captured request.",
      ),
    mutations: z
      .array(MUTATION)
      .optional()
      .describe("Ordered field mutations to apply before sending. Omit to replay unchanged."),
    credential: z
      .string()
      .optional()
      .describe(
        "Session credential ID — strips all auth headers from the captured request and injects this credential's headers. Use for cross-credential IDOR testing. Get credential IDs from web_get_session_context.",
      ),
    unauthenticated: z
      .boolean()
      .optional()
      .describe(
        "Strip all auth headers (Cookie, Authorization, x-auth-token, etc.) before sending. Use to test whether endpoints enforce authentication.",
      ),
    compare: z
      .object({
        baseline: COMPARE_SIDE.optional().describe(
          "Baseline request config. Omit to use the captured request with its original auth.",
        ),
        exploit: COMPARE_SIDE.describe("Exploit request config — the modified request to compare against baseline."),
      })
      .optional()
      .describe(
        "Compare mode: sends baseline + exploit and returns both responses with a structured diff. Satisfies the Confirmation Protocol (baseline → exploit → diff) in ONE tool call.",
      ),
    sweep: z
      .object({
        mutation: MUTATION.describe("The mutation to vary — its value is overridden by each sweep value."),
        values: z.array(z.string()).min(1).max(50).describe("Values to test for the mutation."),
      })
      .optional()
      .describe(
        "Sweep mode: test multiple values for one mutation in a single call. Returns an array of {value, status, body_len, ...} for each value.",
      ),
    marker: z
      .string()
      .optional()
      .describe("A unique token you injected via a mutation — reported back as reflected raw / html-encoded / absent."),
    follow_redirects: z
      .boolean()
      .optional()
      .describe("Follow 3xx redirects (default false — manual redirect for pentest visibility)."),
    insecure_tls: z
      .boolean()
      .optional()
      .describe("Accept invalid/self-signed certificates only when explicitly true (default false)."),
    total_timeout_ms: z
      .number()
      .int()
      .positive()
      .optional()
      .describe("Per-send timeout. Raise above your intended SLEEP for time-based tests."),
  }),
  async execute(params, ctx) {
    const sessionID = Session.root(ctx.sessionID)
    const err = (output: string) => ({ title: "http_replay", output, metadata: {} })

    // Resolve the request source: a captured request_id (PRIMARY) or a constructed
    // target (FALLBACK, for endpoints the crawl never captured). Exactly one.
    const hasRid = !!params.request_id
    const hasTarget = !!params.target
    if (hasRid && hasTarget) return err("Provide either request_id or target, not both.")
    if (!hasRid && !hasTarget) return err("Provide request_id (a captured request) or target (a constructed request).")

    let baseMsg: HttpMessage.Request
    let origin: string
    let authorizationURL: string
    if (hasRid) {
      const request = Request.get(sessionID).find((r) => r.id === params.request_id)
      if (!request) return err(`Request "${params.request_id}" not found.`)
      if (!request.raw_request) return err(`Request "${params.request_id}" has no raw_request to replay.`)
      const o = originOf(request)
      if (typeof o !== "string") return err(o.error)
      origin = o
      try {
        baseMsg = HttpMessage.parse(request.raw_request)
        authorizationURL = new URL(request.normalized_path, origin).href
      } catch (e) {
        return err(`Could not parse captured request path: ${e instanceof Error ? e.message : String(e)}`)
      }
    } else {
      const built = buildFromTarget(params.target!)
      if ("error" in built) return err(built.error)
      baseMsg = built.baseMsg
      origin = built.origin
      authorizationURL = params.target!.url
    }

    // Scope guard applies to BOTH sources — a constructed target must resolve to a
    // host the crawl already captured (it can reach an un-captured PATH, not a new host).
    const originHost = safeURL(origin)?.hostname ?? ""
    if (!inScope(sessionID, origin)) {
      return {
        title: "http_replay — refused (out of scope)",
        output: `Refusing origin "${origin}": not among this session's captured in-scope origins.`,
        metadata: {},
      }
    }

    const targetAuthorization = await TargetMemory.checkURLScope(authorizationURL)
    if (!targetAuthorization.allowed) {
      return {
        title: "http_replay — refused (target scope)",
        output: [
          `Refusing URL "${authorizationURL}": ${targetAuthorization.reason}.`,
          "No request was sent.",
          "A configured target workspace and persisted authorization scope are required for active replay.",
        ].join("\n"),
        metadata: { scopeDenied: true, reason: targetAuthorization.reason },
      }
    }

    const originalWorkspaceID = targetAuthorization.workspace?.id
    const sendOpts = {
      insecure_tls: params.insecure_tls,
      total_timeout_ms: params.total_timeout_ms,
      follow_redirects: params.follow_redirects,
      signal: ctx.abort,
      redirectScopeCheck: async (url: string) => {
        if (!originalWorkspaceID) return false
        const redirectDecision = await TargetMemory.checkURLScope(url)
        return redirectDecision.allowed && redirectDecision.workspace?.id === originalWorkspaceID
      },
    }

    // ── Compare mode ──────────────────────────────────────────────────────
    if (params.compare) {
      const { compare } = params

      // Build baseline
      let baselineMsg = baseMsg
      const baseAuth = applyAuthParams(baselineMsg, compare.baseline ?? {}, sessionID)
      if (typeof baseAuth !== "object" || "error" in baseAuth)
        return { title: "http_replay compare", output: (baseAuth as { error: string }).error, metadata: {} }
      baselineMsg = baseAuth
      if (compare.baseline?.mutations)
        baselineMsg = Apply.mutations(baselineMsg, compare.baseline.mutations as Apply.Mutation[])

      // Build exploit
      let exploitMsg = baseMsg
      const expAuth = applyAuthParams(exploitMsg, compare.exploit, sessionID)
      if (typeof expAuth !== "object" || "error" in expAuth)
        return { title: "http_replay compare", output: (expAuth as { error: string }).error, metadata: {} }
      exploitMsg = expAuth
      if (compare.exploit.mutations)
        exploitMsg = Apply.mutations(exploitMsg, compare.exploit.mutations as Apply.Mutation[])

      const [baselineResult, exploitResult] = await Promise.all([
        sendGoverned(baselineMsg, origin, sendOpts),
        sendGoverned(exploitMsg, origin, sendOpts),
      ])

      const diff = buildDiff(baselineResult, exploitResult)
      const behaviorDiffers = diff.comparable === true && (diff.status_match === false || diff.body_length_match === false || diff.body_content_match === false)
      const noteSaved = await recordReplayObservation({
        sessionID, origin, method: exploitMsg.method, requestTarget: exploitMsg.target,
        sourceRequestID: params.request_id, mode: "compare",
        mutationLabels: [
          ...mutationLabels(compare.baseline?.mutations).map((x) => "baseline:" + x),
          ...mutationLabels(compare.exploit.mutations).map((x) => "exploit:" + x),
          ...(compare.baseline?.unauthenticated ? ["baseline:remove-auth-headers"] : []),
          ...(compare.exploit.unauthenticated ? ["exploit:remove-auth-headers"] : []),
          ...(compare.baseline?.credential ? ["baseline:credential-switch"] : []),
          ...(compare.exploit.credential ? ["exploit:credential-switch"] : []),
        ],
        summary: { baseline: resultFacts(baselineResult), exploit: resultFacts(exploitResult), diff: redactedDiffFacts(diff) },
        manualReview: behaviorDiffers || Boolean(baselineResult.error || exploitResult.error
          || compare.baseline?.mutations?.length || compare.exploit.mutations?.length
          || compare.baseline?.unauthenticated || compare.exploit.unauthenticated
          || compare.baseline?.credential || compare.exploit.credential),
      })
      const output = {
        baseline: { ...summarize(baselineResult, params.marker), curl: curlTemplate(baselineMsg, origin) },
        exploit: { ...summarize(exploitResult, params.marker), curl: curlTemplate(exploitMsg, origin) },
        diff,
        observation_note_saved: noteSaved,
      }

      return {
        title: `http_replay compare ${originHost}`,
        output: JSON.stringify(output, null, 2),
        metadata: { observation_note_saved: noteSaved },
      }
    }

    // ── Sweep mode ────────────────────────────────────────────────────────
    if (params.sweep) {
      const { sweep } = params

      // Apply auth + shared mutations to base
      let sharedMsg = baseMsg
      const authResult = applyAuthParams(sharedMsg, params, sessionID)
      if (typeof authResult !== "object" || "error" in authResult)
        return { title: "http_replay sweep", output: (authResult as { error: string }).error, metadata: {} }
      sharedMsg = authResult
      if (params.mutations) sharedMsg = Apply.mutations(sharedMsg, params.mutations as Apply.Mutation[])

      const results = await Batch.run(
        sweep.values,
        async (value) => {
          try {
            const mut = { ...sweep.mutation, value } as Apply.Mutation
            const varMsg = Apply.mutations(sharedMsg, [mut])
            const result = await sendGoverned(varMsg, origin, sendOpts)
            const sensitiveMutation = /(?:authorization|cookie|token|secret|password|api[-_]?key|session|csrf|credential)/i.test(sweep.mutation.name ?? "")
            return { value: sensitiveMutation ? "[REDACTED]" : redactSensitiveText(value), ...summarize(result, params.marker) }
          } catch (e) {
            return { value, error: e instanceof Error ? e.message : String(e) }
          }
        },
        { concurrency: 3 },
      )

      const safeResults = results.filter(Boolean).map((entry) => {
        if (!entry || typeof entry !== "object") return { status: null, body_len: null, error: "unknown" }
        const row = entry as Record<string, unknown>
        return { status: row.status ?? null, body_len: row.body_len ?? null, error: row.error ? "send-error" : null }
      })
      const noteSaved = await recordReplayObservation({
        sessionID, origin, method: sharedMsg.method, requestTarget: sharedMsg.target,
        sourceRequestID: params.request_id, mode: "sweep",
        mutationLabels: mutationLabels([sweep.mutation]),
        summary: { cases: safeResults.length, results: safeResults },
        manualReview: new Set(safeResults.map((result) => JSON.stringify([result.status, result.body_len, result.error]))).size > 1
          || safeResults.some((result) => result.error !== null),
      })
      return {
        title: `http_replay sweep (${sweep.values.length} values) ${originHost}`,
        output: JSON.stringify({ results: results.filter(Boolean), observation_note_saved: noteSaved }, null, 2),
        metadata: { observation_note_saved: noteSaved },
      }
    }

    // ── Single send mode ──────────────────────────────────────────────────
    let msg = baseMsg
    try {
      const authResult = applyAuthParams(msg, params, sessionID)
      if (typeof authResult !== "object" || "error" in authResult)
        return { title: "http_replay", output: (authResult as { error: string }).error, metadata: {} }
      msg = authResult
      if (params.mutations?.length) msg = Apply.mutations(msg, params.mutations as Apply.Mutation[])
    } catch (e) {
      return {
        title: "http_replay",
        output: `Could not build request: ${e instanceof Error ? e.message : String(e)}`,
        metadata: {},
      }
    }

    const result = await sendGoverned(msg, origin, sendOpts)

    const facts = resultFacts(result)
    const noteSaved = await recordReplayObservation({
      sessionID, origin, method: msg.method, requestTarget: msg.target,
      sourceRequestID: params.request_id, mode: "single",
      mutationLabels: [
        ...mutationLabels(params.mutations),
        ...(params.unauthenticated ? ["remove-auth-headers"] : []),
        ...(params.credential ? ["credential-switch"] : []),
      ],
      summary: facts,
      manualReview: Boolean(params.mutations?.length || params.unauthenticated || params.credential || result.error),
    })
    const output = {
      target: { method: msg.method, origin, request_target: redactSensitiveText(msg.target) },
      ...summarize(result, params.marker),
      curl: curlTemplate(msg, origin),
      observation_note_saved: noteSaved,
    }
    return { title: `http_replay ${msg.method} ${originHost}`, output: JSON.stringify(output, null, 2), metadata: { observation_note_saved: noteSaved } }
  },
})

// ── http_replay_raw (byte-exact) ─────────────────────────────────────────────

const RAW_DESC = `Send an EXACT byte sequence over a raw TCP/TLS socket — no normalization. This is the byte-exact backend for request smuggling / desync, intentionally-malformed messages, duplicate/odd-case headers, and Host-header overrides that http_replay (fetch) would normalize away.

Provide request_id (PRIMARY) to derive host/port/TLS from a captured request; by default it sends that request's raw bytes, or pass raw to send bytes you crafted. For an endpoint the crawl never captured, pass target_url (FALLBACK) together with raw instead. Give exactly one of request_id / target_url. Returns the parsed response (status/headers/body) with timing. Host must be one the crawl already captured.`

export const HttpReplayRawTool = Tool.define("http_replay_raw", {
  description: RAW_DESC,
  parameters: z.object({
    request_id: z
      .string()
      .optional()
      .describe(
        "PRIMARY source — a captured request whose host/port/TLS to connect to (and whose bytes to send unless `raw` is given). Provide EITHER request_id OR target_url, never both.",
      ),
    target_url: z
      .string()
      .optional()
      .describe(
        "FALLBACK — connect to this absolute URL's host/port/TLS instead of a captured request. Use ONLY for an endpoint the crawl never captured; requires `raw` (no captured bytes to fall back on). Host must be one the crawl captured.",
      ),
    raw: z
      .string()
      .optional()
      .describe(
        "Exact raw HTTP request bytes to send. Omit to send the captured request's raw bytes unchanged (required when using target_url).",
      ),
    insecure_tls: z.boolean().optional().describe("Accept invalid/self-signed certificates only when explicitly true (default false)."),
    total_timeout_ms: z.number().int().positive().optional(),
  }),
  async execute(params, ctx) {
    const sessionID = Session.root(ctx.sessionID)
    const err = (output: string) => ({ title: "http_replay_raw", output, metadata: {} })

    // Source: a captured request_id (PRIMARY) or a constructed target_url (FALLBACK). Exactly one.
    const hasRid = !!params.request_id
    const hasTarget = !!params.target_url
    if (hasRid && hasTarget) return err("Provide either request_id or target_url, not both.")
    if (!hasRid && !hasTarget) return err("Provide request_id or target_url.")

    let url: URL
    let raw: string | undefined
    let authorizationURL: string
    if (hasRid) {
      const request = Request.get(sessionID).find((r) => r.id === params.request_id)
      if (!request) return err(`Request "${params.request_id}" not found.`)
      const o = originOf(request)
      if (typeof o !== "string") return err(o.error)
      const u = safeURL(o)
      if (!u) return err(`Invalid origin "${o}".`)
      url = u
      authorizationURL = new URL(request.normalized_path, o).href
      raw = params.raw ?? request.raw_request
    } else {
      const u = safeURL(params.target_url!)
      if (!u) return err(`Invalid target_url "${params.target_url}".`)
      url = u
      authorizationURL = params.target_url!
      raw = params.raw
    }

    if (
      (url.protocol !== "http:" && url.protocol !== "https:") ||
      url.username ||
      url.password
    ) return err("target_url must use HTTP(S) and must not contain embedded credentials.")

    // Scope guard applies to BOTH sources and includes exact scheme and port.
    if (!inScope(sessionID, url.origin)) {
      return {
        title: "http_replay_raw — refused (out of scope)",
        output: `Refusing origin "${url.origin}": not among this session's captured in-scope origins.`,
        metadata: {},
      }
    }

    const targetAuthorization = await TargetMemory.checkURLScope(authorizationURL)
    if (!targetAuthorization.allowed) {
      return {
        title: "http_replay_raw — refused (target scope)",
        output: [
          `Refusing URL "${authorizationURL}": ${targetAuthorization.reason}.`,
          "No request was sent.",
          "A configured target workspace and persisted authorization scope are required for active replay.",
        ].join("\n"),
        metadata: { scopeDenied: true, reason: targetAuthorization.reason },
      }
    }

    if (!raw)
      return err(
        hasTarget
          ? "target_url requires raw (the exact bytes to send)."
          : "No raw bytes to send (request has no raw_request and none provided).",
      )

    const useTls = url.protocol === "https:"
    const port = url.port ? Number.parseInt(url.port, 10) : useTls ? 443 : 80
    const outbound = await Network.forUrl(url.toString())
    // Raw byte-exact replay uses a TCP/TLS socket and deliberately refuses to
    // silently bypass a configured proxy, since that would break interception guarantees.
    if (outbound.proxy) return err("http_replay_raw cannot tunnel through network.proxy. Use http_replay for proxy-routed traffic, or add this destination to network.proxy.bypass.")

    const result = await BackendSocket.send(new TextEncoder().encode(raw), {
      host: url.hostname,
      port,
      tls: useTls,
      rejectUnauthorized: Network.rejectUnauthorized(params.insecure_tls, outbound),
      ca: outbound.ca,
      cert: outbound.clientCertificate?.cert,
      key: outbound.clientCertificate?.key,
      passphrase: outbound.clientCertificate?.passphrase,
      totalTimeoutMs: params.total_timeout_ms,
      signal: ctx.abort,
    })

    const output = { target: { host: url.hostname, port, tls: useTls }, ...summarize(result) }
    return {
      title: `http_replay_raw ${url.hostname}:${port}`,
      output: JSON.stringify(output, null, 2),
      metadata: {},
    }
  },
})
