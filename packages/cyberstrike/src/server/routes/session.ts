import { Hono } from "hono"
import { stream } from "hono/streaming"
import { describeRoute, validator, resolver } from "hono-openapi"
import z from "zod"
import { Session } from "../../session"
import { MessageV2 } from "../../session/message-v2"
import { SessionPrompt } from "../../session/prompt"
import { SessionCompaction } from "../../session/compaction"
import { SessionRevert } from "../../session/revert"
import { SessionStatus } from "@/session/status"
import { SessionQueueStatus } from "@/session/queue-status"
import { HackbrowserStatus } from "@/session/hackbrowser-status"
import { SessionSummary } from "@/session/summary"
import { Todo } from "../../session/todo"
import { Vulnerability } from "../../session/vulnerability"
import { Request } from "../../session/request"
import { Observation } from "../../session/observation"
import { CoverageNote } from "../../session/coverage-note"
import { Normalize } from "../../session/normalize"
import { IngestSummary } from "../../session/ingest-summary"
import { IngestQueue } from "../../session/ingest-queue"
import { looksLikeHTTPRequest } from "../../session/ingest-detection"
import { WebCredential } from "../../session/web/web-credential"
import { WebRole } from "../../session/web/web-role"
import { WebObject } from "../../session/web/web-object"
import { WebFunction } from "../../session/web/web-function"
import { WebRetest } from "../../session/web/web-retest"
import { Agent } from "../../agent/agent"
import { Provider } from "../../provider/provider"
import { Snapshot } from "@/snapshot"
import { Log } from "../../util/log"
import { PermissionNext } from "@/permission/next"
import { errors } from "../error"
import { lazy } from "../../util/lazy"
import { TargetMemory } from "../../target"
import { JavaScriptCorrelation, safeCorrelationResponsePreview } from "../../target/javascript-correlation"

const log = Log.create({ service: "server" })

const MAX_REQUEST_SIZE = 16 * 1024 // 16 KB
const MAX_REQUEST_HEADERS = 20 // First N headers
const MAX_REQUEST_BODY = 8 * 1024 // 8 KB

function truncateRawRequest(rawRequest: string): string {
  const originalSize = Buffer.byteLength(rawRequest, "utf-8")

  const lines = rawRequest.split("\n")
  if (lines.length === 0) return rawRequest

  // 1. Keep request line (GET /path HTTP/1.1)
  const requestLine = lines[0]
  const result: string[] = [requestLine]

  // 2. Find blank line separating headers and body
  let blankLineIndex = -1
  for (let i = 1; i < lines.length; i++) {
    if (lines[i].trim() === "") {
      blankLineIndex = i
      break
    }
  }

  // 3. Add headers (up to MAX_REQUEST_HEADERS)
  const headerLines = blankLineIndex === -1 ? lines.slice(1) : lines.slice(1, blankLineIndex)
  const truncatedHeaders = headerLines.slice(0, MAX_REQUEST_HEADERS)
  result.push(...truncatedHeaders)

  const removedHeaderCount = headerLines.length - truncatedHeaders.length
  if (removedHeaderCount > 0) {
    result.push(`[... ${removedHeaderCount} more headers truncated ...]`)
  }

  // 4. Add blank line if there was one
  if (blankLineIndex !== -1) {
    result.push("")

    // 5. Add body (up to MAX_REQUEST_BODY)
    const bodyLines = lines.slice(blankLineIndex + 1)
    const bodyText = bodyLines.join("\n")
    const bodySize = Buffer.byteLength(bodyText, "utf-8")

    if (bodySize > MAX_REQUEST_BODY) {
      const truncatedBody = bodyText.slice(0, MAX_REQUEST_BODY)
      result.push(truncatedBody)
      result.push(
        `\n[... body truncated: showing first ${formatSize(MAX_REQUEST_BODY)} of ${formatSize(bodySize)} ...]`,
      )
    } else {
      result.push(bodyText)
    }
  }

  const finalResult = result.join("\n")
  const finalSize = Buffer.byteLength(finalResult, "utf-8")

  // Log only if truncation occurred
  if (removedHeaderCount > 0 || originalSize !== finalSize) {
    log.debug("truncated raw request", {
      originalSize,
      finalSize,
      removedHeaders: removedHeaderCount,
    })
  }

  return finalResult
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} bytes`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

export interface AccessContextInput {
  triggerElement?: string
  elementRoles?: string[]
  pageUrl?: string
  pageVisitedBy?: string[]
  uiContext?: Record<string, unknown>
}

// Renders the `## Access Context` block when hackbrowser enrichment is
// present. Returns an empty array for requests from sources without UI
// enrichment (e.g., Firefox extension manual browsing). Shared by the ingest
// prompt builder (below) and the subagent-dispatch prompt builder in task.ts,
// so the orchestrator and subagents see the same structured signals.
export function renderAccessContextLines(accessContext: AccessContextInput): string[] {
  const ac = accessContext
  const hasData = ac.triggerElement || ac.pageUrl || ac.uiContext || ac.pageVisitedBy?.length
  if (!hasData) return []
  const lines: string[] = ["", "## Access Context"]
  if (ac.pageUrl) {
    const visitedBy = ac.pageVisitedBy?.length ? ` (visited by: ${ac.pageVisitedBy.join(", ")})` : ""
    lines.push(`Page: ${ac.pageUrl}${visitedBy}`)
  } else if (ac.pageVisitedBy?.length) {
    lines.push(`Visited by: ${ac.pageVisitedBy.join(", ")}`)
  }
  if (ac.triggerElement) {
    const visibleTo = ac.elementRoles?.length ? ` (visible to: ${ac.elementRoles.join(", ")})` : ""
    lines.push(`Trigger: ${ac.triggerElement}${visibleTo}`)
  }
  if (ac.uiContext) {
    const ui = ac.uiContext as {
      formName?: string
      fields?: Array<{
        name: string
        type: string
        isReadOnly?: boolean
        isDisabled?: boolean
        isHidden?: boolean
        validation?: { required?: boolean }
      }>
      hiddenParams?: string[]
    }
    if (ui.formName) lines.push(`Form: ${ui.formName}`)
    if (ui.fields?.length) {
      const fieldsSummary = ui.fields
        .map((f) => {
          const flags: string[] = []
          if (f.validation?.required) flags.push("required")
          if (f.isReadOnly) flags.push("readonly")
          if (f.isDisabled) flags.push("disabled")
          if (f.isHidden) flags.push("hidden")
          return `${f.name}(${f.type}${flags.length ? "," + flags.join(",") : ""})`
        })
        .join(", ")
      lines.push(`Fields: ${fieldsSummary}`)
    }
    if (ui.hiddenParams?.length) {
      lines.push(`Hidden Params: ${ui.hiddenParams.join(", ")}`)
    }
  }
  return lines
}

// Derive visited_by from observed credential attribution (request_observation), merging
// with any capture-time label. This is the Firefox fix: Firefox traffic has no
// page_visited_by at capture time, but request_observation carries per-credential
// reachability for both paths. Merged, distinct, label-resolved.
export function getVisitedByForKeyHash(
  sessionID: string,
  keyHash: string,
  captureVisitedBy?: string[],
): string[] {
  const obs = Observation.listByKeyHash(sessionID, keyHash)
  const ids = [...new Set(obs.map((o) => o.credential_id).filter((id): id is string => !!id))]
  const labels = ids.map((id) => WebCredential.getById(id)?.label ?? id)
  const merged = new Set<string>([...(captureVisitedBy ?? []), ...labels])
  return [...merged]
}

export function resolveVisitedBy(input: {
  sessionID: string
  keyHash?: string
  captureVisitedBy?: string[]
}): string[] | undefined {
  if (!input.keyHash) return input.captureVisitedBy
  const derived = getVisitedByForKeyHash(input.sessionID, input.keyHash, input.captureVisitedBy)
  return derived.length ? derived : input.captureVisitedBy
}

// Renders the `## Observed Values` block: the concrete input values each credential was
// observed using on THIS endpoint shape (deterministic, redaction-aware). RAW FACTS ONLY —
// no interpretation. What the values mean (access-control/IDOR/etc.) is the orchestrator's
// and tester subagent's call, never pre-judged here. Empty when no params carry values.
function renderObservedValuesLines(tree: Observation.EndpointTree): string[] {
  if (tree.params.length === 0) return []
  const lines = [
    "",
    "## Observed Values",
    "Concrete input values captured on this endpoint, per credential (deterministic, redaction-aware).",
  ]
  for (const p of tree.params.slice(0, 12)) {
    const parts = p.byCredential.map((c) => {
      const label = c.credentialID
        ? (WebCredential.getById(c.credentialID)?.label ?? c.credentialID)
        : "unauthenticated"
      if (c.redacted && c.values.length === 0) return `${label}=[redacted]`
      const vals = c.values
        .slice(0, 6)
        .map((v) => JSON.stringify(v))
        .join(", ")
      return `${label}=[${vals}]${c.redacted ? " (+redacted)" : ""}`
    })
    lines.push(`- ${p.name} (${p.loc}): ${parts.join("; ")}`)
  }
  return lines
}

function buildPromptWithCredentialContext(
  rawRequest: string,
  credentialID?: string,
  processedResponse?: string,
  accessContext?: AccessContextInput,
  operationContext?: { protocol: string; operation: string },
  observedValues?: Observation.EndpointTree,
  requestContext?: { requestID: string; method: string; origin?: string; path: string; responseStatus?: number },
): string {
  const lines: string[] = []

  if (requestContext) {
    lines.push("## Request Task Identity")
    lines.push("- Request ID: " + requestContext.requestID)
    lines.push("- Method: " + requestContext.method)
    lines.push("- Origin: " + (requestContext.origin ?? "unknown"))
    lines.push("- Path (query values omitted): " + requestContext.path.split("?")[0])
    lines.push("- Baseline response status: " + (requestContext.responseStatus ?? "unknown"))
    lines.push("")
    lines.push("## Required Evidence-Driven Analysis and Memory")
    lines.push("This is one independent captured-request task. Analyze this request only; do not launch full-target recon or unrelated scans.")
    lines.push("Inspect existing target/session context and relevant endpoint/JavaScript evidence before selecting a test. Reuse prior results and do not repeat tests already resolved.")
    lines.push("Separate observed facts, hypotheses, and confirmed impact. A missing header, scanner signal, unusual status, endpoint existence, or static JavaScript sink is not by itself a confirmed vulnerability.")
    lines.push("For INFO/LOW hardening signals, preserve the observation and investigate whether a concrete, in-scope attack path crosses a real security boundary. Use baseline/negative controls and safe, hypothesis-driven variations; never invent a chain or inflate severity. Raise severity only after demonstrating realistic impact and reproducible evidence. If no impact is demonstrated, keep it INFO/LOW and state why.")
    lines.push("Record meaningful test attempts with verification_attempt using a stable hypothesis key, distinct strategy/variant, rationale, actual observed result, and evidence reference. Use validate_finding for candidate findings when evidence is sufficient; never mark false positive because tests failed or evidence is missing.")
    lines.push("When this request changes target understanding, save or update a concise target_note with Request ID, exact endpoint, relevant role/auth context, evidence/artifact IDs, hypothesis, tests and outcomes, confidence/status, impact if any, unresolved questions, and the next discriminating test. Include useful negative results to prevent repeated work. Do not write generic 'tested X' notes. If a secret-like value is directly relevant to reproduction or validation, preserve its exact value and precise source location only in the private target-local evidence note/artifact; label it as an unverified candidate until validated. Do not copy raw values into global research, shared reports, commits, or external exports. The automatic captured-request note is only an evidence index, not the analysis note.")
    lines.push("If no meaningful security signal or new reusable observation exists, do not create a generic semantic note; finish with a short evidence-grounded conclusion.")
    lines.push("")
  }

  // Protocol/operation banner — this request is a body-dispatched operation
  // (GraphQL/JSON-RPC), not a plain REST endpoint. Route protocol-aware tests
  // (e.g. GraphQL introspection/batching/field-authz; JSON-RPC method enum).
  if (operationContext) {
    lines.push(`## Operation`)
    lines.push(`- protocol: ${operationContext.protocol}`)
    lines.push(`- operation: ${operationContext.operation}`)
    lines.push("")
  }

  lines.push("## Credential Context")

  if (!credentialID) {
    lines.push("UNAUTHENTICATED (no credential provided by browser extension)")
  } else {
    const cred = WebCredential.getById(credentialID)
    if (!cred) {
      lines.push(`- credential_id: ${credentialID} (NOT FOUND in database)`)
    } else {
      lines.push(`- credential_id: ${cred.id}`)
      lines.push(`- label: ${cred.label}`)
      if (cred.container_id) {
        lines.push(`- container_id: ${cred.container_id}`)
      }
      if (Object.keys(cred.headers).length > 0) {
        lines.push("- headers:")
        for (const [key, value] of Object.entries(cred.headers)) {
          const displayValue = value.length > 80 ? value.slice(0, 80) + "..." : value
          lines.push(`  - ${key}: ${displayValue}`)
        }
      }
      if (cred.role_id) {
        lines.push(`- role_id: ${cred.role_id}`)
      }
    }
  }

  if (accessContext) {
    lines.push(...renderAccessContextLines(accessContext))
  }

  if (observedValues) {
    lines.push(...renderObservedValuesLines(observedValues))
  }

  lines.push("")
  lines.push("## Raw HTTP Request")
  lines.push("```")
  lines.push(rawRequest)
  lines.push("```")

  if (processedResponse) {
    lines.push("")
    lines.push("## Response")
    lines.push("```")
    lines.push(processedResponse)
    lines.push("```")
  }

  return lines.join("\n")
}

// Heuristic for ingest payloads that don't carry an explicit scheme. Browser-
// agent supplies it; the legacy Firefox extension does not. We look at the
// request line (absolute-URI form), then fall back to the host port hint, then
// "https" as the safest default — most modern targets are HTTPS and treating
// http traffic as https only inflates the dedup space, never causes data loss.
function inferScheme(rawText: string): "http" | "https" {
  const firstLine = rawText.split(/\r?\n/, 1)[0] ?? ""
  if (/^[A-Z]+\s+https:\/\//.test(firstLine)) return "https"
  if (/^[A-Z]+\s+http:\/\//.test(firstLine)) return "http"
  // Look for a Host header with explicit port 80 (suggests http).
  const hostMatch = rawText.match(/^[Hh]ost:\s*[^\r\n]*?:80\b/m)
  if (hostMatch) return "http"
  return "https"
}

// Bridge between the ingest payload and Normalize.run. Returns null when the
// raw text isn't a parseable HTTP request (the route then falls through to
// the chat-style ingest path that handles plain text).
async function runNormalize(
  body: {
    text: string
    scheme?: "http" | "https"
    model?: { providerID: string; modelID: string }
  },
  sessionID: string,
  dryRun: boolean,
): Promise<Normalize.RunResult | null> {
  const scheme = body.scheme ?? inferScheme(body.text)
  const model = body.model ?? (await SessionPrompt.lastModel(sessionID))

  // Dry-run uses a no-op classifier so Tier 3 never reaches the LLM. Tier 1
  // still resolves the common cases; ambiguous segments fall back to literal.
  const client = dryRun
    ? {
        async classify() {
          return { decisions: [], model: "dry-run" }
        },
      }
    : undefined

  try {
    return await Normalize.run({
      sessionID,
      raw: body.text,
      scheme,
      providerID: model.providerID,
      modelID: model.modelID,
      client,
    })
  } catch (err) {
    // Malformed request line (e.g. plain chat text) — let the caller fall
    // through to the non-HTTP ingest branch.
    log.debug("normalize parse failed", { error: (err as Error).message })
    return null
  }
}

export const SessionRoutes = lazy(() =>
  new Hono()
    .get(
      "/",
      describeRoute({
        summary: "List sessions",
        description: "Get a list of all CyberStrike sessions, sorted by most recently updated.",
        operationId: "session.list",
        responses: {
          200: {
            description: "List of sessions",
            content: {
              "application/json": {
                schema: resolver(Session.Info.array()),
              },
            },
          },
        },
      }),
      validator(
        "query",
        z.object({
          directory: z.string().optional().meta({ description: "Filter sessions by project directory" }),
          roots: z.coerce.boolean().optional().meta({ description: "Only return root sessions (no parentID)" }),
          start: z.coerce
            .number()
            .optional()
            .meta({ description: "Filter sessions updated on or after this timestamp (milliseconds since epoch)" }),
          search: z.string().optional().meta({ description: "Filter sessions by title (case-insensitive)" }),
          limit: z.coerce.number().optional().meta({ description: "Maximum number of sessions to return" }),
        }),
      ),
      async (c) => {
        const query = c.req.valid("query")
        const sessions: Session.Info[] = []
        for await (const session of Session.list({
          directory: query.directory,
          roots: query.roots,
          start: query.start,
          search: query.search,
          limit: query.limit,
        })) {
          sessions.push(session)
        }
        return c.json(sessions)
      },
    )
    .get(
      "/status",
      describeRoute({
        summary: "Get session status",
        description: "Retrieve the current status of all sessions, including active, idle, and completed states.",
        operationId: "session.status",
        responses: {
          200: {
            description: "Get session status",
            content: {
              "application/json": {
                schema: resolver(z.record(z.string(), SessionStatus.Info)),
              },
            },
          },
          ...errors(400),
        },
      }),
      async (c) => {
        const result = SessionStatus.list()
        return c.json(result)
      },
    )
    .get(
      "/queue/status",
      describeRoute({
        summary: "Get ingest queue status",
        description:
          "Retrieve the current ingest-queue state for all sessions (paused flag and pending count). Sessions with no active queue are omitted.",
        operationId: "session.queueStatus",
        responses: {
          200: {
            description: "Queue status map keyed by sessionID",
            content: {
              "application/json": {
                schema: resolver(z.record(z.string(), SessionQueueStatus.Info)),
              },
            },
          },
          ...errors(400),
        },
      }),
      async (c) => {
        const result = SessionQueueStatus.list()
        return c.json(result)
      },
    )
    .post(
      "/:sessionID/hackbrowser/launch",
      describeRoute({
        summary: "Launch a hackbrowser crawl",
        description:
          "Start a hackbrowser crawl for a session from an interactive entry point (TUI slash, CLI subcommand). Same backend as the LLM-callable hackbrowser tool — agent invocation, slash, and CLI all share this surface. Returns a KickOffResult; captures stream into the session asynchronously.",
        operationId: "session.hackbrowserLaunch",
        responses: {
          200: {
            description: "Crawl successfully kicked off; returns sessionID + started flag + status message",
            content: {
              "application/json": {
                schema: resolver(
                  z.object({
                    sessionID: z.string(),
                    started: z.boolean(),
                    message: z.string(),
                  }),
                ),
              },
            },
          },
          ...errors(400, 404),
        },
      }),
      validator(
        "param",
        z.object({
          sessionID: z.string(),
        }),
      ),
      validator(
        "json",
        z.object({
          target: z.string().url(),
          credentials: z.array(z.string()).optional(),
          scope: z.array(z.string()).optional(),
          exclude: z.array(z.string()).optional(),
          steps: z.number().int().min(1).max(200).optional(),
          headless: z.boolean().optional(),
        }),
      ),
      async (c) => {
        const { launchHackbrowser } = await import("@/tool/hackbrowser-launcher")
        const sessionID = c.req.valid("param").sessionID
        const body = c.req.valid("json")
        const result = await launchHackbrowser({
          sessionID,
          target: body.target,
          credentials: body.credentials,
          scope: body.scope,
          exclude: body.exclude,
          steps: body.steps,
          headless: body.headless,
        })
        return c.json(result)
      },
    )
    .post(
      "/:sessionID/hackbrowser/stop",
      describeRoute({
        summary: "Stop the active hackbrowser run for a session",
        description:
          "Cancels an in-flight hackbrowser crawl. The agent finishes the current page's pending tasks (graceful exit), closes the browser, and transitions HackbrowserStatus to completed with whatever was captured so far. Returns false when no hackbrowser run is active for this session.",
        operationId: "session.hackbrowserStop",
        responses: {
          200: {
            description: "true when a run was cancelled, false when no active run",
            content: {
              "application/json": {
                schema: resolver(z.boolean()),
              },
            },
          },
          ...errors(400, 404),
        },
      }),
      validator(
        "param",
        z.object({
          sessionID: z.string(),
        }),
      ),
      async (c) => {
        const { stopHackbrowser } = await import("@/tool/hackbrowser-launcher")
        const stopped = stopHackbrowser(c.req.valid("param").sessionID)
        return c.json(stopped)
      },
    )
    .get(
      "/hackbrowser/status",
      describeRoute({
        summary: "Get hackbrowser status",
        description:
          "Retrieve the current hackbrowser run state for all sessions (phase, page/endpoint counters, errors). Used by the TUI sidebar bootstrap. Sessions with no hackbrowser run are omitted.",
        operationId: "session.hackbrowserStatus",
        responses: {
          200: {
            description: "Hackbrowser status map keyed by sessionID",
            content: {
              "application/json": {
                schema: resolver(z.record(z.string(), HackbrowserStatus.Info)),
              },
            },
          },
          ...errors(400),
        },
      }),
      async (c) => {
        const result = HackbrowserStatus.list()
        return c.json(result)
      },
    )
    .get(
      "/:sessionID",
      describeRoute({
        summary: "Get session",
        description: "Retrieve detailed information about a specific CyberStrike session.",
        tags: ["Session"],
        operationId: "session.get",
        responses: {
          200: {
            description: "Get session",
            content: {
              "application/json": {
                schema: resolver(Session.Info),
              },
            },
          },
          ...errors(400, 404),
        },
      }),
      validator(
        "param",
        z.object({
          sessionID: Session.get.schema,
        }),
      ),
      async (c) => {
        const sessionID = c.req.valid("param").sessionID
        log.info("SEARCH", { url: c.req.url })
        const session = await Session.get(sessionID)
        return c.json(session)
      },
    )
    .get(
      "/:sessionID/children",
      describeRoute({
        summary: "Get session children",
        tags: ["Session"],
        description: "Retrieve all child sessions that were forked from the specified parent session.",
        operationId: "session.children",
        responses: {
          200: {
            description: "List of children",
            content: {
              "application/json": {
                schema: resolver(Session.Info.array()),
              },
            },
          },
          ...errors(400, 404),
        },
      }),
      validator(
        "param",
        z.object({
          sessionID: Session.children.schema,
        }),
      ),
      async (c) => {
        const sessionID = c.req.valid("param").sessionID
        const session = await Session.children(sessionID)
        return c.json(session)
      },
    )
    .get(
      "/:sessionID/usage",
      describeRoute({
        summary: "Get session usage",
        tags: ["Session"],
        description:
          "Aggregate token and cost usage across the session and all its descendant subagents. Resolves the tree root, so the result is the same whether a parent or child session ID is passed.",
        operationId: "session.usage",
        responses: {
          200: {
            description: "Aggregated usage",
            content: {
              "application/json": {
                schema: resolver(
                  z.object({
                    rootID: z.string(),
                    totalCost: z.number(),
                    totalTokens: z.number(),
                    sessionCount: z.number(),
                  }),
                ),
              },
            },
          },
          ...errors(400, 404),
        },
      }),
      validator(
        "param",
        z.object({
          sessionID: Session.usage.schema,
        }),
      ),
      async (c) => {
        const sessionID = c.req.valid("param").sessionID
        return c.json(await Session.usage(sessionID))
      },
    )
    .get(
      "/:sessionID/todo",
      describeRoute({
        summary: "Get session todos",
        description: "Retrieve the todo list associated with a specific session, showing tasks and action items.",
        operationId: "session.todo",
        responses: {
          200: {
            description: "Todo list",
            content: {
              "application/json": {
                schema: resolver(Todo.Info.array()),
              },
            },
          },
          ...errors(400, 404),
        },
      }),
      validator(
        "param",
        z.object({
          sessionID: z.string().meta({ description: "Session ID" }),
        }),
      ),
      async (c) => {
        const sessionID = c.req.valid("param").sessionID
        const todos = await Todo.get(sessionID)
        return c.json(todos)
      },
    )
    .get(
      "/:sessionID/vulnerability",
      describeRoute({
        summary: "Get session vulnerabilities",
        description: "Retrieve the list of vulnerabilities reported for a specific session.",
        operationId: "session.vulnerability",
        responses: {
          200: {
            description: "Vulnerability list",
            content: {
              "application/json": {
                schema: resolver(Vulnerability.Info.array()),
              },
            },
          },
          ...errors(400, 404),
        },
      }),
      validator(
        "param",
        z.object({
          sessionID: z.string().meta({ description: "Session ID" }),
        }),
      ),
      async (c) => {
        const sessionID = c.req.valid("param").sessionID
        const list = Vulnerability.get(sessionID)
        return c.json(list)
      },
    )
    .get(
      "/:sessionID/request",
      describeRoute({
        summary: "Get session requests",
        description: "Retrieve the list of normalized HTTP requests tracked for a specific session.",
        operationId: "session.request",
        responses: {
          200: {
            description: "Request list",
            content: {
              "application/json": {
                schema: resolver(Request.Info.array()),
              },
            },
          },
          ...errors(400, 404),
        },
      }),
      validator(
        "param",
        z.object({
          sessionID: z.string().meta({ description: "Session ID" }),
        }),
      ),
      async (c) => {
        const sessionID = c.req.valid("param").sessionID
        const list = Request.get(sessionID)
        return c.json(list)
      },
    )
    .get(
      "/:sessionID/observations",
      describeRoute({
        summary: "Get observed values for an endpoint",
        description:
          "Per-endpoint observed values (raw facts): which credential used which concrete values for each parameter. " +
          "Pulled on-demand when the UI expands an endpoint. Pass the endpoint's key_hash.",
        operationId: "session.observations",
        responses: {
          200: { description: "Observed-value tree", content: { "application/json": { schema: resolver(z.any()) } } },
          ...errors(400, 404),
        },
      }),
      validator("param", z.object({ sessionID: z.string().meta({ description: "Session ID" }) })),
      validator(
        "query",
        z.object({
          keyHash: z.string().optional().meta({ description: "Endpoint key_hash" }),
          id: z.string().optional().meta({ description: "Request id (alternative to keyHash)" }),
        }),
      ),
      async (c) => {
        const { sessionID } = c.req.valid("param")
        const { keyHash, id } = c.req.valid("query")
        // Resolve the key_hash from a request id when keyHash isn't supplied (the web
        // client's stale SDK schema can strip key_hash from the request list).
        const kh = keyHash ?? (id ? Request.get(sessionID).find((r) => r.id === id)?.key_hash : undefined)
        if (!kh) return c.json({ keyHash: "", credentials: [], params: [] })
        return c.json(Observation.endpointTree(sessionID, kh))
      },
    )
    // Web Proxy Agent Context Endpoints
    .get(
      "/:sessionID/web/credentials",
      describeRoute({
        summary: "Get web credentials",
        description: "Retrieve the list of credentials for web security testing in this session.",
        operationId: "session.webCredentials",
        responses: {
          200: {
            description: "Credential list",
            content: {
              "application/json": {
                schema: resolver(WebCredential.Info.array()),
              },
            },
          },
          ...errors(400, 404),
        },
      }),
      validator(
        "param",
        z.object({
          sessionID: z.string().meta({ description: "Session ID" }),
        }),
      ),
      async (c) => {
        const sessionID = c.req.valid("param").sessionID
        const list = WebCredential.get(sessionID)
        return c.json(list)
      },
    )
    .post(
      "/:sessionID/web/credentials",
      describeRoute({
        summary: "Add web credential",
        description: "Add a new credential for web security testing.",
        operationId: "session.addWebCredential",
        responses: {
          200: {
            description: "Created credential",
            content: {
              "application/json": {
                schema: resolver(WebCredential.Info),
              },
            },
          },
          ...errors(400, 404),
        },
      }),
      validator(
        "param",
        z.object({
          sessionID: z.string().meta({ description: "Session ID" }),
        }),
      ),
      validator(
        "json",
        z.object({
          label: z.string(),
          headers: z.record(z.string(), z.string()).optional(),
          container_id: z.string().optional(),
        }),
      ),
      async (c) => {
        const sessionID = c.req.valid("param").sessionID
        const body = c.req.valid("json")
        const cred = WebCredential.add({
          sessionID,
          label: body.label,
          headers: body.headers,
          containerID: body.container_id,
        })
        return c.json(cred)
      },
    )
    .delete(
      "/:sessionID/web/credentials/:credentialID",
      describeRoute({
        summary: "Delete web credential",
        description: "Delete a credential from the session.",
        operationId: "session.deleteWebCredential",
        responses: {
          200: {
            description: "Successfully deleted",
            content: {
              "application/json": {
                schema: resolver(z.boolean()),
              },
            },
          },
          ...errors(400, 404),
        },
      }),
      validator(
        "param",
        z.object({
          sessionID: z.string().meta({ description: "Session ID" }),
          credentialID: z.string().meta({ description: "Credential ID" }),
        }),
      ),
      async (c) => {
        const params = c.req.valid("param")
        WebCredential.remove(params.credentialID)
        return c.json(true)
      },
    )
    .patch(
      "/:sessionID/web/credentials/:credentialID",
      describeRoute({
        summary: "Update web credential",
        description: "Update a credential's value, label, or role. Used for token refresh.",
        operationId: "session.updateWebCredential",
        responses: {
          200: {
            description: "Updated credential",
            content: {
              "application/json": {
                schema: resolver(WebCredential.Info),
              },
            },
          },
          ...errors(400, 404),
        },
      }),
      validator(
        "param",
        z.object({
          sessionID: z.string().meta({ description: "Session ID" }),
          credentialID: z.string().meta({ description: "Credential ID" }),
        }),
      ),
      validator(
        "json",
        z.object({
          headers: z.record(z.string(), z.string()).optional().meta({ description: "Auth headers" }),
          label: z.string().optional().meta({ description: "New label" }),
          container_id: z.string().optional().meta({ description: "Container ID" }),
          role_id: z.string().optional().meta({ description: "Role ID to link" }),
        }),
      ),
      async (c) => {
        const params = c.req.valid("param")
        const body = c.req.valid("json")
        try {
          const updated = WebCredential.update({
            id: params.credentialID,
            sessionID: params.sessionID,
            headers: body.headers,
            label: body.label,
            containerID: body.container_id,
            roleID: body.role_id,
          })
          if (!updated) {
            c.status(404)
            return c.json({ error: "Credential not found" })
          }
          return c.json(updated)
        } catch (err) {
          c.status(403)
          return c.json({ error: (err as Error).message })
        }
      },
    )
    .get(
      "/:sessionID/web/roles",
      describeRoute({
        summary: "Get web roles",
        description: "Retrieve discovered roles for web security testing.",
        operationId: "session.webRoles",
        responses: {
          200: {
            description: "Role list",
            content: {
              "application/json": {
                schema: resolver(WebRole.Info.array()),
              },
            },
          },
          ...errors(400, 404),
        },
      }),
      validator("param", z.object({ sessionID: z.string() })),
      async (c) => {
        const list = WebRole.get(c.req.valid("param").sessionID)
        return c.json(list)
      },
    )
    .get(
      "/:sessionID/web/objects",
      describeRoute({
        summary: "Get web objects",
        description: "Retrieve discovered data objects for web security testing.",
        operationId: "session.webObjects",
        responses: {
          200: {
            description: "Object list",
            content: {
              "application/json": {
                schema: resolver(WebObject.Info.array()),
              },
            },
          },
          ...errors(400, 404),
        },
      }),
      validator("param", z.object({ sessionID: z.string() })),
      async (c) => {
        const list = WebObject.get(c.req.valid("param").sessionID)
        return c.json(list)
      },
    )
    .get(
      "/:sessionID/web/functions",
      describeRoute({
        summary: "Get web functions",
        description: "Retrieve discovered endpoint functions for web security testing.",
        operationId: "session.webFunctions",
        responses: {
          200: {
            description: "Function list",
            content: {
              "application/json": {
                schema: resolver(WebFunction.Info.array()),
              },
            },
          },
          ...errors(400, 404),
        },
      }),
      validator("param", z.object({ sessionID: z.string() })),
      async (c) => {
        const list = WebFunction.get(c.req.valid("param").sessionID)
        return c.json(list)
      },
    )
    .get(
      "/:sessionID/web/retest-queue",
      describeRoute({
        summary: "Get web retest queue",
        description: "Retrieve pending retests triggered by new discoveries.",
        operationId: "session.webRetestQueue",
        responses: {
          200: {
            description: "Retest queue",
            content: {
              "application/json": {
                schema: resolver(
                  z.object({
                    pending: z.array(WebRetest.Info),
                    counts: z.object({
                      pending: z.number(),
                      processing: z.number(),
                      completed: z.number(),
                    }),
                  }),
                ),
              },
            },
          },
          ...errors(400, 404),
        },
      }),
      validator("param", z.object({ sessionID: z.string() })),
      async (c) => {
        const sessionID = c.req.valid("param").sessionID
        const pending = WebRetest.getPending(sessionID)
        const counts = WebRetest.count(sessionID)
        return c.json({ pending, counts })
      },
    )
    .post(
      "/",
      describeRoute({
        summary: "Create session",
        description: "Create a new CyberStrike session for interacting with AI assistants and managing conversations.",
        operationId: "session.create",
        responses: {
          ...errors(400),
          200: {
            description: "Successfully created session",
            content: {
              "application/json": {
                schema: resolver(Session.Info),
              },
            },
          },
        },
      }),
      validator("json", Session.create.schema.optional()),
      async (c) => {
        const body = c.req.valid("json") ?? {}
        const session = await Session.create(body)
        return c.json(session)
      },
    )
    .post(
      "/ingest",
      describeRoute({
        summary: "Ingest message",
        description:
          "Accept captured HTTP requests or plain-text messages from another port or service. HTTP captures are analyzed in independent child sessions so they do not take over the parent chat window; plain-text messages are processed in the supplied session. Creates a session if sessionID is missing or invalid.",
        operationId: "session.ingest",
        responses: {
          202: {
            description: "Message accepted",
            content: {
              "application/json": {
                schema: resolver(
                  z.object({
                    sessionID: z
                      .string()
                      .meta({ description: "Session id (new or existing); use for follow-up ingest requests" }),
                  }),
                ),
              },
            },
          },
          ...errors(400, 404),
        },
      }),
      validator(
        "json",
        z.object({
          text: z.string().min(1).meta({ description: "Message text (treated as user input)" }),
          sessionID: z
            .string()
            .optional()
            .meta({ description: "Existing session id; omit or leave invalid to create a new session" }),
          agent: z.string().optional().meta({ description: "Agent to use (default if omitted)" }),
          model: z
            .object({
              providerID: z.string(),
              modelID: z.string(),
            })
            .optional()
            .meta({ description: "Model to use (optional)" }),
          credential_id: z.string().optional().meta({ description: "Existing credential ID to use for this request" }),
          credential: z
            .object({
              label: z.string(),
              headers: z.record(z.string(), z.string()).optional(),
              container_id: z.string().optional(),
            })
            .optional()
            .meta({ description: "New credential to register with this request" }),
          response: z
            .object({
              status: z.number().meta({ description: "HTTP status code" }),
              headers: z.record(z.string(), z.string()).meta({ description: "Response headers" }),
              body: z.string().meta({ description: "Response body" }),
            })
            .optional()
            .meta({ description: "HTTP response data" }),
          // Hackbrowser enrichment fields (optional — not sent by Firefox extension)
          trigger_element: z
            .string()
            .optional()
            .meta({ description: "UI element that triggered this request (role:label)" }),
          element_roles: z.array(z.string()).optional().meta({ description: "Roles that can see the trigger element" }),
          ui_context: z
            .record(z.string(), z.unknown())
            .optional()
            .meta({ description: "UI form context at request time" }),
          page_url: z.string().optional().meta({ description: "Page being explored when request was captured" }),
          page_visited_by: z.array(z.string()).optional().meta({ description: "Roles that can visit this page" }),
          scheme: z
            .enum(["http", "https"])
            .optional()
            .meta({ description: "URL scheme of the captured request; inferred from Host header / port when omitted" }),
        }),
      ),
      async (c) => {
        const body = c.req.valid("json")
        let sessionID = body.sessionID
        if (sessionID) {
          try {
            await Session.get(sessionID)
          } catch {
            sessionID = undefined
          }
        }
        if (!sessionID) {
          const session = await Session.create({})
          sessionID = session.id
        }

        const ingestDryRun = process.env.CYBERSTRIKE_INGEST_DRY_RUN === "true"
        const normalized = await runNormalize(body, sessionID, ingestDryRun)

        // Never route a malformed extension capture into the ordinary parent-chat
        // branch. That fallback writes into the active text window and can hijack
        // the user's conversation when request normalization fails.
        if (!normalized && looksLikeHTTPRequest(body.text, Boolean(body.scheme || body.response))) {
          c.status(400)
          return c.json({
            error: "Captured HTTP request could not be normalized; it was not sent to the parent chat session.",
          })
        }

        // Handle credential registration
        let credentialID = body.credential_id
        if (body.credential && !credentialID) {
          const cred = WebCredential.add({
            sessionID,
            label: body.credential.label,
            headers: body.credential.headers,
            containerID: body.credential.container_id,
          })
          credentialID = cred.id
          log.info("credential registered", { sessionID, credentialID, label: body.credential.label })
        }

        // Passive discovery only: attach observed origins when a persisted scope authorizes them.
        // This branch never probes the host and must not block request ingestion on hierarchy errors.
        if (normalized?.origin) {
          const assetType = /^\/(?:api|graphql|v\d+)(?:\/|$)/i.test(normalized.normalizedPath) ||
            /^(api|graphql|gateway)([.-]|$)/i.test(new URL(normalized.origin).hostname)
            ? "api"
            : "subdomain"
          try {
            await TargetMemory.registerObservedAsset(normalized.origin, assetType)
          } catch (error) {
            log.warn("unable to update target hierarchy from captured request", {
              origin: normalized.origin,
              error: error instanceof Error ? error.message : String(error),
            })
          }
        }
        if (body.page_url) {
          try {
            await TargetMemory.registerObservedAsset(body.page_url, "application")
          } catch (error) {
            log.warn("unable to register captured page asset", {
              error: error instanceof Error ? error.message : String(error),
            })
          }
        }

        if (normalized) {
          const isDuplicate = Request.exists({
            sessionID,
            method: normalized.method,
            normalizedPath: normalized.normalizedPath,
            origin: normalized.origin,
            bodyHash: normalized.bodyHash,
            queryHash: normalized.queryKeyHash,
            opKeyHash: normalized.opKeyHash,
            keyHash: normalized.keyHash,
          })

          // Record per-credential observed values on EVERY ingest — including
          // dedup skips, because the whole point is capturing which values which
          // credential used on an already-known endpoint (IDOR/BFLA substrate).
          // Append-only + idempotent, so safe to call on every path.
          const recordObservation = (requestID?: string) =>
            Observation.observe({
              sessionID,
              keyHash: normalized.keyHash,
              opGroupHash: normalized.opGroupHash,
              requestID,
              credentialID,
              valueHash: normalized.valueHash,
              slots: normalized.observedParams,
            })

          const refreshJavaScriptCorrelation = async (
            capture: ReturnType<typeof Request.captureJavaScriptSource>,
            refreshEvenIfAlreadyCaptured = false,
          ) => {
            if (!capture || !normalized.origin || (!capture.captured && !refreshEvenIfAlreadyCaptured)) return
            try {
              const observedURL = new URL(normalized.normalizedPath, normalized.origin).href
              const scopeDecision = await TargetMemory.checkURLScope(observedURL)
              if (!scopeDecision.allowed || !scopeDecision.workspace) {
                log.info("JavaScript source version captured but correlation skipped by persisted scope", {
                  sessionID,
                  requestID: capture.requestID,
                  reason: scopeDecision.reason,
                })
                return
              }
              const correlation = await JavaScriptCorrelation.build({
                sessionID,
                targetURL: scopeDecision.workspace.targetURL,
              })
              log.info("JavaScript source version correlated after request dedup", {
                sessionID,
                requestID: capture.requestID,
                contentHash: capture.contentHash,
                targetID: scopeDecision.workspace.id,
                sourceFiles: correlation.graph.sourceFiles.length,
                endpointCandidates: correlation.graph.endpointCandidates.length,
                graphPath: correlation.graphPath,
              })
            } catch (error) {
              log.warn("automatic correlation of a changed JavaScript source version failed", {
                sessionID,
                requestID: capture.requestID,
                error: error instanceof Error ? error.message : String(error),
              })
            }
          }

          if (isDuplicate) {
            // Do not re-enqueue the duplicate request, but preserve and correlate a
            // changed JavaScript body associated with this same request identity.
            const javascriptCapture = Request.captureJavaScriptSource({
              sessionID,
              method: normalized.method,
              normalizedPath: normalized.normalizedPath,
              response: body.response,
              keyHash: normalized.keyHash,
              bodyHash: normalized.bodyHash,
              queryHash: normalized.queryKeyHash,
              opKeyHash: normalized.opKeyHash,
              origin: normalized.origin,
              scheme: normalized.scheme,
              host: normalized.host,
              port: normalized.port,
              pageUrl: body.page_url,
            })
            recordObservation(javascriptCapture?.requestID)
            await refreshJavaScriptCorrelation(javascriptCapture)
            log.info("duplicate request skipped", {
              sessionID,
              method: normalized.method,
              path: normalized.normalizedPath,
              javascriptSourceVersionCaptured: javascriptCapture?.captured ?? false,
            })
            c.status(202)
            return c.json({
              sessionID,
              skipped: true,
              javascriptSourceVersionCaptured: javascriptCapture?.captured ?? false,
            })
          }
          // Race-duplicate: a concurrent ingest won the atomic key_hash upsert
          // between our exists() check and this insert. Treat exactly like a
          // duplicate — no row was created, so skip the LLM enqueue, but still
          // record the observation (the values are evidence regardless).
          if (!req) {
            const javascriptCapture = Request.captureJavaScriptSource({
              sessionID,
              method: normalized.method,
              normalizedPath: normalized.normalizedPath,
              response: body.response,
              keyHash: normalized.keyHash,
              bodyHash: normalized.bodyHash,
              queryHash: normalized.queryKeyHash,
              opKeyHash: normalized.opKeyHash,
              origin: normalized.origin,
              scheme: normalized.scheme,
              host: normalized.host,
              port: normalized.port,
              pageUrl: body.page_url,
            })
            recordObservation(javascriptCapture?.requestID)
            // Request.add already persisted this capture inside its transaction.
            // Force a read-back correlation even if the helper's insert is now a no-op.
            await refreshJavaScriptCorrelation(javascriptCapture, true)
            c.status(202)
            return c.json({
              sessionID,
              skipped: true,
              javascriptSourceVersionCaptured: javascriptCapture?.captured ?? false,
            })
          }

          // New endpoint shape: record the first observation, linked to the row.
          recordObservation(req.id)

          // Build the prompt as a thunk so the `## Observed Values` block reflects the
          // observation state at SEND time, not at enqueue time. Prompts queue (LLM calls
          // are slow) and other per-credential requests to the SAME endpoint accrue
          // observations while a prompt waits — rendering at dequeue captures them (e.g. a
          // second credential's values land in the prompt instead of being missed).
          const buildPrompt = () => {
            // Prepend app-wide coverage already recorded for this origin so the
            // orchestrator skips re-dispatching deployment-wide testers (JWT/TLS/headers).
            // Rendered at dequeue, so it reflects coverage that accrued while queued.
            const coverage = CoverageNote.wideBlock(sessionID, normalized.origin)
            const visitedBy = resolveVisitedBy({
              sessionID,
              keyHash: normalized.keyHash,
              captureVisitedBy: body.page_visited_by,
            })
            const base = buildPromptWithCredentialContext(
              truncatedRawRequest,
              credentialID,
              req.processed_response,
              {
                triggerElement: body.trigger_element,
                elementRoles: body.element_roles,
                pageUrl: body.page_url,
                pageVisitedBy: visitedBy,
                uiContext: body.ui_context as Record<string, unknown> | undefined,
              },
              normalized.protocol && normalized.operation
                ? { protocol: normalized.protocol, operation: normalized.operation }
                : undefined,
              Observation.endpointTree(sessionID, normalized.keyHash),
              {
                requestID: req.id,
                method: normalized.method,
                origin: normalized.origin ?? undefined,
                path: normalized.normalizedPath,
                responseStatus: req.response_status ?? undefined,
              },
            )
            return coverage ? `${coverage}\n\n${base}` : base
          }

          if (ingestDryRun) {
            // Log the prompt that would be sent to LLM — skip actual LLM call
            log.info("ingest dry-run", {
              sessionID,
              method: normalized.method,
              path: normalized.normalizedPath,
              requestId: req.id,
            })
            log.info("prompt preview:\n" + buildPrompt())
            Request.updateStatus({ id: req.id, status: "processed" })
          } else {
            // Captured HTTP traffic always enters through the proxy orchestrator subagent.
            // Do not let an ingest payload redirect a browser request into the primary chat
            // agent or an unrelated specialist; plain-text ingest retains its explicit agent option.
            const agentName = "proxy-agent"
            const source = `${normalized.method} ${normalized.normalizedPath}`
            // Give every captured request its own child session. The old queue was keyed
            // by the shared parent session, so one slow extension request blocked every
            // later request and changed the parent session active status/model context.
            // Child sessions run independently while session-tree-aware tools continue to
            // read/write shared root request, credential, observation and target memory.
            const childSession = await Session.create({
              parentID: sessionID,
              title: `Captured request - ${normalized.method} ${normalized.normalizedPath.split("?")[0]!.slice(0, 100)}` ,
            })
            const childSessionID = childSession.id
            IngestQueue.enqueue(childSessionID, async () => {
              // A request becomes processed only after agent processing and summary
              // persistence both complete. Failed work stays visible and is not auto-replayed.
              let finalStatus: "processed" | "failed" = "failed"
              try {
                Request.updateStatus({ id: req.id, status: "processing" })
                const before = IngestSummary.snapshot(sessionID)
                // Render at dequeue so Observed Values includes observations accrued while waiting.
                const promptText = buildPrompt()
                const agentResult = await SessionPrompt.prompt({
                  sessionID: childSessionID,
                  agent: agentName,
                  model: body.model,
                  excludeHistory: true,
                  parts: [{ type: "text", text: promptText }],
                })
                // SessionPrompt.prompt can resolve with an assistant message carrying
                // an error, stuck-abort, or step-cap marker instead of throwing.
                // Do not turn those incomplete runs into a successful ingest status.
                const agentInfo = agentResult.info
                const agentError = agentInfo.role === "assistant" ? agentInfo.error : undefined
                const agentStuck = agentInfo.role === "assistant" && Boolean(agentInfo.stuckAborted)
                const agentCapped = agentInfo.role === "assistant" && Boolean(agentInfo.stepCapped)
                const agentIncomplete = Boolean(agentError) || agentStuck || agentCapped
                const model = body.model ?? (await SessionPrompt.lastModel(childSessionID))
                await IngestSummary.write({
                  // Keep completion chatter in the request child session, not the active parent transcript.
                  sessionID: childSessionID,
                  agent: agentName,
                  model,
                  source,
                  before,
                  after: IngestSummary.snapshot(sessionID),
                })

                // Persist a target-local evidence artifact for every captured request.
                // This private artifact preserves the exact captured request for reproduction;
                // shared/exported evidence must be separately redacted before leaving the workspace.
                if (normalized.origin) {
                  try {
                    const observedURL = new URL(normalized.normalizedPath, normalized.origin)
                    const scopeDecision = await TargetMemory.checkURLScope(observedURL.href)
                    if (scopeDecision.allowed && scopeDecision.workspace) {
                      const queryNames = [...new Set([...observedURL.searchParams.keys()])].sort()
                      const requestArtifact = "requests/" + req.id.replace(/[^a-zA-Z0-9_-]/g, "_") + ".json"
                      try {
                        await TargetMemory.writeWorkspaceFile(scopeDecision.workspace, requestArtifact, JSON.stringify({
                          schemaVersion: 1,
                          requestID: req.id,
                          childSessionID,
                          capturedAt: new Date().toISOString(),
                          targetURL: scopeDecision.workspace.targetURL,
                          request: {
                            method: normalized.method,
                            origin: observedURL.origin,
                            path: observedURL.pathname,
                            queryParameterNames: queryNames,
                            rawRequest: truncatedRawRequest,
                          },
                          response: {
                            status: req.response_status ?? null,
                            contentType: req.response_content_type ?? null,
                            size: req.response_size ?? null,
                            redactedPreview: safeCorrelationResponsePreview({
                              id: req.id,
                              normalizedPath: normalized.normalizedPath,
                              responseContentType: req.response_content_type,
                              processedResponse: req.processed_response,
                            }),
                          },
                          evidencePolicy: "Private target-local original preserving exact request values for authorized reproduction. Create a separate redacted copy before sharing, reporting publicly, or sending to an external service.",
                        }, null, 2) + "\n")
                      } catch (error) {
                        log.warn("request artifact persistence failed", {
                          sessionID,
                          childSessionID,
                          requestID: req.id,
                          targetID: scopeDecision.workspace.id,
                          error: error instanceof Error ? error.message : String(error),
                        })
                      }
                      const requestNoteContent = [
                        "# Captured Request Observation",
                        "",
                        "- Request ID: " + req.id,
                        "- Child analysis session: " + childSessionID,
                        "- Method: " + normalized.method,
                        "- Origin: " + observedURL.origin,
                        "- Path: " + observedURL.pathname,
                        "- Query parameter names: " + (queryNames.length ? queryNames.join(", ") : "none"),
                        "- Response status: " + (req.response_status ?? "unknown"),
                        "- Response content type: " + (req.response_content_type ?? "unknown"),
                        "- Response size: " + (req.response_size ?? "unknown"),
                        "",
                        "Interpretation: observed request/response metadata only; this is not a vulnerability finding and does not prove an access-control or input-validation flaw. Unknowns: authorization context, expected behavior, response semantics, and security impact unless the child analysis establishes them.\n" +
                        "Next analysis: inspect the private target-local request artifact (it retains exact captured request values) and canonical request by ID; correlate the exact origin/method/path with the endpoint inventory and JavaScript candidates; compare an authorized baseline/control where appropriate; record concrete evidence and a negative result if behavior is expected. Never infer impact from status code, missing headers, parameter presence, or unusual response alone. Do not share the raw artifact; create a separately redacted copy first.\n" +
                        "The full captured request/response remains in the request store under the Request ID. Private target-local request artifact (contains exact request values): " + requestArtifact + ". The child session contains the per-request analysis and should link relevant endpoint, JavaScript, asset, and prior recon evidence.",
                      ].join("\n")
                      await TargetMemory.addNote(scopeDecision.workspace.targetURL, {
                        kind: "evidence",
                        title: ("Captured request " + normalized.method + " " + normalized.normalizedPath.split("?")[0]).slice(0, 180),
                        content: requestNoteContent,
                        source: "extension-request:" + req.id,
                        sourceURL: observedURL.origin + observedURL.pathname,
                        status: "observed",
                        tags: ["extension-request", "request-observation", normalized.method.toLowerCase()],
                        upsertByIdentity: true,
                      })
                    } else {
                      log.info("request evidence note skipped by persisted scope", {
                        sessionID,
                        childSessionID,
                        requestID: req.id,
                        reason: scopeDecision.reason,
                      })
                    }
                  } catch (error) {
                    // A note failure must not erase the successfully completed request analysis.
                    log.warn("request evidence note persistence failed", {
                      sessionID,
                      childSessionID,
                      requestID: req.id,
                      error: error instanceof Error ? error.message : String(error),
                    })
                  }
                }

                // JavaScript response captures automatically refresh the target's static
                // analysis/correlation graph after the request agent finishes. The builder
                // reads only already-captured, in-scope traffic and persists redacted metadata.
                const isJavaScriptResponse =
                  Boolean(req.processed_response?.trim()) &&
                  (/(?:java|ecma)script|x-javascript/i.test(req.response_content_type ?? "") ||
                    /\.(?:m?js|cjs)(?:[?#]|$)/i.test(normalized.normalizedPath))
                if (isJavaScriptResponse && normalized.origin) {
                  try {
                    const observedURL = new URL(normalized.normalizedPath, normalized.origin).href
                    const scopeDecision = await TargetMemory.checkURLScope(observedURL)
                    if (scopeDecision.allowed && scopeDecision.workspace) {
                      const correlation = await JavaScriptCorrelation.build({
                        sessionID: childSessionID,
                        targetURL: scopeDecision.workspace.targetURL,
                      })
                      log.info("automatic JavaScript correlation completed", {
                        sessionID,
                        childSessionID,
                        requestID: req.id,
                        targetID: scopeDecision.workspace.id,
                        sourceFiles: correlation.graph.sourceFiles.length,
                        endpointCandidates: correlation.graph.endpointCandidates.length,
                        graphPath: correlation.graphPath,
                      })
                    } else {
                      log.info("automatic JavaScript correlation skipped by persisted scope", {
                        sessionID,
                        requestID: req.id,
                        reason: scopeDecision.reason,
                      })
                    }
                  } catch (error) {
                    // Correlation is a follow-up analysis, not the request-agent result.
                    // Preserve the request's successful status and leave a diagnostic log.
                    log.warn("automatic JavaScript correlation failed", {
                      sessionID,
                      requestID: req.id,
                      error: error instanceof Error ? error.message : String(error),
                    })
                  }
                }
                if (agentIncomplete) {
                  log.warn("captured request analysis did not complete cleanly", {
                    sessionID,
                    childSessionID,
                    requestID: req.id,
                    agent: agentName,
                    errorName:
                      agentError && typeof agentError === "object" && "name" in agentError
                        ? String(agentError.name)
                        : agentError
                          ? "error"
                          : undefined,
                    stuckAborted: agentStuck,
                    stepCapped: agentCapped,
                  })
                } else {
                  finalStatus = "processed"
                }
              } finally {
                Request.updateStatus({ id: req.id, status: finalStatus })
              }
            }, sessionID)
          }
        } else {
          // Non-HTTP request (plain text message)
          const promptText = buildPromptWithCredentialContext(body.text, credentialID)
          if (ingestDryRun) {
            log.info("ingest dry-run (text)", { sessionID })
            log.info("prompt preview:\n" + promptText)
          } else {
            const agentName = body.agent ?? "proxy-agent"
            IngestQueue.enqueue(sessionID, async () => {
              const before = IngestSummary.snapshot(sessionID)
              await SessionPrompt.prompt({
                sessionID,
                agent: agentName,
                model: body.model,
                excludeHistory: true,
                parts: [{ type: "text", text: promptText }],
              })
              const model = body.model ?? (await SessionPrompt.lastModel(sessionID))
              await IngestSummary.write({
                sessionID,
                agent: agentName,
                model,
                source: "text ingest",
                before,
                after: IngestSummary.snapshot(sessionID),
              })
            })
          }
        }
        c.status(202)
        return c.json({ sessionID })
      },
    )
    .delete(
      "/:sessionID",
      describeRoute({
        summary: "Delete session",
        description: "Delete a session and permanently remove all associated data, including messages and history.",
        operationId: "session.delete",
        responses: {
          200: {
            description: "Successfully deleted session",
            content: {
              "application/json": {
                schema: resolver(z.boolean()),
              },
            },
          },
          ...errors(400, 404),
        },
      }),
      validator(
        "param",
        z.object({
          sessionID: Session.remove.schema,
        }),
      ),
      async (c) => {
        const sessionID = c.req.valid("param").sessionID
        await Session.remove(sessionID)
        return c.json(true)
      },
    )
    .patch(
      "/:sessionID",
      describeRoute({
        summary: "Update session",
        description: "Update properties of an existing session, such as title or other metadata.",
        operationId: "session.update",
        responses: {
          200: {
            description: "Successfully updated session",
            content: {
              "application/json": {
                schema: resolver(Session.Info),
              },
            },
          },
          ...errors(400, 404),
        },
      }),
      validator(
        "param",
        z.object({
          sessionID: z.string(),
        }),
      ),
      validator(
        "json",
        z.object({
          title: z.string().optional(),
          time: z
            .object({
              archived: z.number().optional(),
            })
            .optional(),
        }),
      ),
      async (c) => {
        const sessionID = c.req.valid("param").sessionID
        const updates = c.req.valid("json")

        let session = await Session.get(sessionID)
        if (updates.title !== undefined) {
          session = await Session.setTitle({ sessionID, title: updates.title })
        }
        if (updates.time?.archived !== undefined) {
          session = await Session.setArchived({ sessionID, time: updates.time.archived })
        }

        return c.json(session)
      },
    )
    .post(
      "/:sessionID/init",
      describeRoute({
        summary: "Initialize session",
        description:
          "Analyze the current application and create an AGENTS.md file with project-specific agent configurations.",
        operationId: "session.init",
        responses: {
          200: {
            description: "200",
            content: {
              "application/json": {
                schema: resolver(z.boolean()),
              },
            },
          },
          ...errors(400, 404),
        },
      }),
      validator(
        "param",
        z.object({
          sessionID: z.string().meta({ description: "Session ID" }),
        }),
      ),
      validator("json", Session.initialize.schema.omit({ sessionID: true })),
      async (c) => {
        const sessionID = c.req.valid("param").sessionID
        const body = c.req.valid("json")
        await Session.initialize({ ...body, sessionID })
        return c.json(true)
      },
    )
    .post(
      "/:sessionID/fork",
      describeRoute({
        summary: "Fork session",
        description: "Create a new session by forking an existing session at a specific message point.",
        operationId: "session.fork",
        responses: {
          200: {
            description: "200",
            content: {
              "application/json": {
                schema: resolver(Session.Info),
              },
            },
          },
        },
      }),
      validator(
        "param",
        z.object({
          sessionID: Session.fork.schema.shape.sessionID,
        }),
      ),
      validator("json", Session.fork.schema.omit({ sessionID: true })),
      async (c) => {
        const sessionID = c.req.valid("param").sessionID
        const body = c.req.valid("json")
        const result = await Session.fork({ ...body, sessionID })
        return c.json(result)
      },
    )
    .post(
      "/:sessionID/abort",
      describeRoute({
        summary: "Abort session",
        description: "Abort an active session and stop any ongoing AI processing or command execution.",
        operationId: "session.abort",
        responses: {
          200: {
            description: "Aborted session",
            content: {
              "application/json": {
                schema: resolver(z.boolean()),
              },
            },
          },
          ...errors(400, 404),
        },
      }),
      validator(
        "param",
        z.object({
          sessionID: z.string(),
        }),
      ),
      async (c) => {
        // Genuine user abort (Esc) — stop the background hackbrowser crawl too.
        SessionPrompt.cancel(c.req.valid("param").sessionID, { stopCrawl: true })
        return c.json(true)
      },
    )
    .post(
      "/:sessionID/queue/pause",
      describeRoute({
        summary: "Pause ingest queue",
        description:
          "Pause the ingest queue for a session. The current in-flight ingest finishes; the next one waits until queue/resume is called. Other flows (chat input, abort) are unaffected.",
        operationId: "session.queuePause",
        responses: {
          200: {
            description: "Paused",
            content: {
              "application/json": {
                schema: resolver(z.boolean()),
              },
            },
          },
          ...errors(400, 404),
        },
      }),
      validator(
        "param",
        z.object({
          sessionID: z.string(),
        }),
      ),
      async (c) => {
        IngestQueue.pause(c.req.valid("param").sessionID)
        return c.json(true)
      },
    )
    .post(
      "/:sessionID/queue/resume",
      describeRoute({
        summary: "Resume ingest queue",
        description:
          "Resume the ingest queue for a session. Tasks queued while paused start processing in original order.",
        operationId: "session.queueResume",
        responses: {
          200: {
            description: "Resumed",
            content: {
              "application/json": {
                schema: resolver(z.boolean()),
              },
            },
          },
          ...errors(400, 404),
        },
      }),
      validator(
        "param",
        z.object({
          sessionID: z.string(),
        }),
      ),
      async (c) => {
        IngestQueue.resume(c.req.valid("param").sessionID)
        return c.json(true)
      },
    )
    .post(
      "/:sessionID/share",
      describeRoute({
        summary: "Share session",
        description: "Create a shareable link for a session, allowing others to view the conversation.",
        operationId: "session.share",
        responses: {
          200: {
            description: "Successfully shared session",
            content: {
              "application/json": {
                schema: resolver(Session.Info),
              },
            },
          },
          ...errors(400, 404),
        },
      }),
      validator(
        "param",
        z.object({
          sessionID: z.string(),
        }),
      ),
      async (c) => {
        const sessionID = c.req.valid("param").sessionID
        await Session.share(sessionID)
        const session = await Session.get(sessionID)
        return c.json(session)
      },
    )
    .get(
      "/:sessionID/diff",
      describeRoute({
        summary: "Get message diff",
        description: "Get the file changes (diff) that resulted from a specific user message in the session.",
        operationId: "session.diff",
        responses: {
          200: {
            description: "Successfully retrieved diff",
            content: {
              "application/json": {
                schema: resolver(Snapshot.FileDiff.array()),
              },
            },
          },
        },
      }),
      validator(
        "param",
        z.object({
          sessionID: SessionSummary.diff.schema.shape.sessionID,
        }),
      ),
      validator(
        "query",
        z.object({
          messageID: SessionSummary.diff.schema.shape.messageID,
        }),
      ),
      async (c) => {
        const query = c.req.valid("query")
        const params = c.req.valid("param")
        const result = await SessionSummary.diff({
          sessionID: params.sessionID,
          messageID: query.messageID,
        })
        return c.json(result)
      },
    )
    .delete(
      "/:sessionID/share",
      describeRoute({
        summary: "Unshare session",
        description: "Remove the shareable link for a session, making it private again.",
        operationId: "session.unshare",
        responses: {
          200: {
            description: "Successfully unshared session",
            content: {
              "application/json": {
                schema: resolver(Session.Info),
              },
            },
          },
          ...errors(400, 404),
        },
      }),
      validator(
        "param",
        z.object({
          sessionID: Session.unshare.schema,
        }),
      ),
      async (c) => {
        const sessionID = c.req.valid("param").sessionID
        await Session.unshare(sessionID)
        const session = await Session.get(sessionID)
        return c.json(session)
      },
    )
    .post(
      "/:sessionID/summarize",
      describeRoute({
        summary: "Summarize session",
        description: "Generate a concise summary of the session using AI compaction to preserve key information.",
        operationId: "session.summarize",
        responses: {
          200: {
            description: "Summarized session",
            content: {
              "application/json": {
                schema: resolver(z.boolean()),
              },
            },
          },
          ...errors(400, 404),
        },
      }),
      validator(
        "param",
        z.object({
          sessionID: z.string().meta({ description: "Session ID" }),
        }),
      ),
      validator(
        "json",
        z.object({
          providerID: z.string(),
          modelID: z.string(),
          auto: z.boolean().optional().default(false),
        }),
      ),
      async (c) => {
        const sessionID = c.req.valid("param").sessionID
        const body = c.req.valid("json")
        const session = await Session.get(sessionID)
        await SessionRevert.cleanup(session)
        const msgs = await Session.messages({ sessionID })
        let currentAgent = await Agent.defaultAgent()
        for (let i = msgs.length - 1; i >= 0; i--) {
          const info = msgs[i].info
          if (info.role === "user") {
            currentAgent = info.agent || (await Agent.defaultAgent())
            break
          }
        }
        await SessionCompaction.create({
          sessionID,
          agent: currentAgent,
          model: {
            providerID: body.providerID,
            modelID: body.modelID,
          },
          auto: body.auto,
        })
        await SessionPrompt.loop({ sessionID }).catch((e) => {
          if (e instanceof Error && e.message === "session prompt cancelled") return
          throw e
        })
        return c.json(true)
      },
    )
    .get(
      "/:sessionID/message",
      describeRoute({
        summary: "Get session messages",
        description: "Retrieve all messages in a session, including user prompts and AI responses.",
        operationId: "session.messages",
        responses: {
          200: {
            description: "List of messages",
            content: {
              "application/json": {
                schema: resolver(MessageV2.WithParts.array()),
              },
            },
          },
          ...errors(400, 404),
        },
      }),
      validator(
        "param",
        z.object({
          sessionID: z.string().meta({ description: "Session ID" }),
        }),
      ),
      validator(
        "query",
        z.object({
          limit: z.coerce.number().optional(),
        }),
      ),
      async (c) => {
        const query = c.req.valid("query")
        const messages = await Session.messages({
          sessionID: c.req.valid("param").sessionID,
          limit: query.limit,
        })
        return c.json(messages)
      },
    )
    .get(
      "/:sessionID/message/:messageID",
      describeRoute({
        summary: "Get message",
        description: "Retrieve a specific message from a session by its message ID.",
        operationId: "session.message",
        responses: {
          200: {
            description: "Message",
            content: {
              "application/json": {
                schema: resolver(
                  z.object({
                    info: MessageV2.Info,
                    parts: MessageV2.Part.array(),
                  }),
                ),
              },
            },
          },
          ...errors(400, 404),
        },
      }),
      validator(
        "param",
        z.object({
          sessionID: z.string().meta({ description: "Session ID" }),
          messageID: z.string().meta({ description: "Message ID" }),
        }),
      ),
      async (c) => {
        const params = c.req.valid("param")
        const message = await MessageV2.get({
          sessionID: params.sessionID,
          messageID: params.messageID,
        })
        return c.json(message)
      },
    )
    .delete(
      "/:sessionID/message/:messageID/part/:partID",
      describeRoute({
        description: "Delete a part from a message",
        operationId: "part.delete",
        responses: {
          200: {
            description: "Successfully deleted part",
            content: {
              "application/json": {
                schema: resolver(z.boolean()),
              },
            },
          },
          ...errors(400, 404),
        },
      }),
      validator(
        "param",
        z.object({
          sessionID: z.string().meta({ description: "Session ID" }),
          messageID: z.string().meta({ description: "Message ID" }),
          partID: z.string().meta({ description: "Part ID" }),
        }),
      ),
      async (c) => {
        const params = c.req.valid("param")
        await Session.removePart({
          sessionID: params.sessionID,
          messageID: params.messageID,
          partID: params.partID,
        })
        return c.json(true)
      },
    )
    .patch(
      "/:sessionID/message/:messageID/part/:partID",
      describeRoute({
        description: "Update a part in a message",
        operationId: "part.update",
        responses: {
          200: {
            description: "Successfully updated part",
            content: {
              "application/json": {
                schema: resolver(MessageV2.Part),
              },
            },
          },
          ...errors(400, 404),
        },
      }),
      validator(
        "param",
        z.object({
          sessionID: z.string().meta({ description: "Session ID" }),
          messageID: z.string().meta({ description: "Message ID" }),
          partID: z.string().meta({ description: "Part ID" }),
        }),
      ),
      validator("json", MessageV2.Part),
      async (c) => {
        const params = c.req.valid("param")
        const body = c.req.valid("json")
        if (body.id !== params.partID || body.messageID !== params.messageID || body.sessionID !== params.sessionID) {
          throw new Error(
            `Part mismatch: body.id='${body.id}' vs partID='${params.partID}', body.messageID='${body.messageID}' vs messageID='${params.messageID}', body.sessionID='${body.sessionID}' vs sessionID='${params.sessionID}'`,
          )
        }
        const part = await Session.updatePart(body)
        return c.json(part)
      },
    )
    .post(
      "/:sessionID/message",
      describeRoute({
        summary: "Send message",
        description: "Create and send a new message to a session, streaming the AI response.",
        operationId: "session.prompt",
        responses: {
          200: {
            description: "Created message",
            content: {
              "application/json": {
                schema: resolver(
                  z.object({
                    info: MessageV2.Assistant,
                    parts: MessageV2.Part.array(),
                  }),
                ),
              },
            },
          },
          ...errors(400, 404),
        },
      }),
      validator(
        "param",
        z.object({
          sessionID: z.string().meta({ description: "Session ID" }),
        }),
      ),
      validator("json", SessionPrompt.PromptInput.omit({ sessionID: true })),
      async (c) => {
        c.status(200)
        c.header("Content-Type", "application/json")
        return stream(c, async (stream) => {
          const sessionID = c.req.valid("param").sessionID
          const body = c.req.valid("json")
          const msg = await SessionPrompt.prompt({ ...body, sessionID }).catch((e) => {
            if (e instanceof Error && e.message === "session prompt cancelled") return
            throw e
          })
          if (msg) stream.write(JSON.stringify(msg))
        })
      },
    )
    .post(
      "/:sessionID/prompt_async",
      describeRoute({
        summary: "Send async message",
        description:
          "Create and send a new message to a session asynchronously, starting the session if needed and returning immediately.",
        operationId: "session.prompt_async",
        responses: {
          204: {
            description: "Prompt accepted",
          },
          ...errors(400, 404),
        },
      }),
      validator(
        "param",
        z.object({
          sessionID: z.string().meta({ description: "Session ID" }),
        }),
      ),
      validator("json", SessionPrompt.PromptInput.omit({ sessionID: true })),
      async (c) => {
        c.status(204)
        c.header("Content-Type", "application/json")
        return stream(c, async () => {
          const sessionID = c.req.valid("param").sessionID
          const body = c.req.valid("json")
          SessionPrompt.prompt({ ...body, sessionID }).catch(() => {})
        })
      },
    )
    .post(
      "/:sessionID/command",
      describeRoute({
        summary: "Send command",
        description: "Send a new command to a session for execution by the AI assistant.",
        operationId: "session.command",
        responses: {
          200: {
            description: "Created message",
            content: {
              "application/json": {
                schema: resolver(
                  z.object({
                    info: MessageV2.Assistant,
                    parts: MessageV2.Part.array(),
                  }),
                ),
              },
            },
          },
          ...errors(400, 404),
        },
      }),
      validator(
        "param",
        z.object({
          sessionID: z.string().meta({ description: "Session ID" }),
        }),
      ),
      validator("json", SessionPrompt.CommandInput.omit({ sessionID: true })),
      async (c) => {
        const sessionID = c.req.valid("param").sessionID
        const body = c.req.valid("json")
        const msg = await SessionPrompt.command({ ...body, sessionID })
        return c.json(msg)
      },
    )
    .post(
      "/:sessionID/shell",
      describeRoute({
        summary: "Run shell command",
        description: "Execute a shell command within the session context and return the AI's response.",
        operationId: "session.shell",
        responses: {
          200: {
            description: "Created message",
            content: {
              "application/json": {
                schema: resolver(MessageV2.Assistant),
              },
            },
          },
          ...errors(400, 404),
        },
      }),
      validator(
        "param",
        z.object({
          sessionID: z.string().meta({ description: "Session ID" }),
        }),
      ),
      validator("json", SessionPrompt.ShellInput.omit({ sessionID: true })),
      async (c) => {
        const sessionID = c.req.valid("param").sessionID
        const body = c.req.valid("json")
        const msg = await SessionPrompt.shell({ ...body, sessionID })
        return c.json(msg)
      },
    )
    .post(
      "/:sessionID/revert",
      describeRoute({
        summary: "Revert message",
        description: "Revert a specific message in a session, undoing its effects and restoring the previous state.",
        operationId: "session.revert",
        responses: {
          200: {
            description: "Updated session",
            content: {
              "application/json": {
                schema: resolver(Session.Info),
              },
            },
          },
          ...errors(400, 404),
        },
      }),
      validator(
        "param",
        z.object({
          sessionID: z.string(),
        }),
      ),
      validator("json", SessionRevert.RevertInput.omit({ sessionID: true })),
      async (c) => {
        const sessionID = c.req.valid("param").sessionID
        log.info("revert", c.req.valid("json"))
        const session = await SessionRevert.revert({
          sessionID,
          ...c.req.valid("json"),
        })
        return c.json(session)
      },
    )
    .post(
      "/:sessionID/unrevert",
      describeRoute({
        summary: "Restore reverted messages",
        description: "Restore all previously reverted messages in a session.",
        operationId: "session.unrevert",
        responses: {
          200: {
            description: "Updated session",
            content: {
              "application/json": {
                schema: resolver(Session.Info),
              },
            },
          },
          ...errors(400, 404),
        },
      }),
      validator(
        "param",
        z.object({
          sessionID: z.string(),
        }),
      ),
      async (c) => {
        const sessionID = c.req.valid("param").sessionID
        const session = await SessionRevert.unrevert({ sessionID })
        return c.json(session)
      },
    )
    .post(
      "/:sessionID/permissions/:permissionID",
      describeRoute({
        summary: "Respond to permission",
        deprecated: true,
        description: "Approve or deny a permission request from the AI assistant.",
        operationId: "permission.respond",
        responses: {
          200: {
            description: "Permission processed successfully",
            content: {
              "application/json": {
                schema: resolver(z.boolean()),
              },
            },
          },
          ...errors(400, 404),
        },
      }),
      validator(
        "param",
        z.object({
          sessionID: z.string(),
          permissionID: z.string(),
        }),
      ),
      validator("json", z.object({ response: PermissionNext.Reply })),
      async (c) => {
        const params = c.req.valid("param")
        PermissionNext.reply({
          requestID: params.permissionID,
          reply: c.req.valid("json").response,
        })
        return c.json(true)
      },
    ),
)
