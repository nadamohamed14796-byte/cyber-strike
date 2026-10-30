import { BusEvent } from "@/bus/bus-event"
import { Bus } from "@/bus"
import z from "zod"
import { Database, eq, and, isNull, asc, or } from "../storage/db"
import { RequestJavaScriptCaptureTable, RequestTable } from "./session.sql"
import { Identifier } from "../id/id"
import { createHash } from "crypto"
import { processResponse, type ResponseInput } from "./response-processor"
import { isConfirmedEmptyStaticHTML } from "./captured-request-triage"

function requestResponseURL(input: {
  normalizedPath: string
  origin?: string
  scheme?: "http" | "https"
  host?: string
  port?: number
}): string {
  let responseURL = input.normalizedPath
  const responseBase = input.origin ?? (
    input.scheme && input.host
      ? input.scheme + "://" + input.host + (input.port && !/(?:\]:\d+|:\d+)$/.test(input.host) ? ":" + input.port : "")
      : undefined
  )
  if (responseBase) {
    try { responseURL = new URL(input.normalizedPath, responseBase).href } catch {}
  }
  return responseURL
}

function canonicalSourceURL(value: string): string {
  try {
    const url = new URL(value)
    url.search = ""
    url.hash = ""
    return url.origin + url.pathname
  } catch {
    return value.split(/[?#]/, 1)[0] || value
  }
}

const Status = z.enum(["queued", "processing", "processed", "failed"])
const Method = z.enum(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
const NormSource = z.enum(["tier1", "tier2", "tier3", "failed"])

export namespace Request {
  export const Info = z
    .object({
      id: z.string(),
      session_id: z.string(),
      credential_id: z.string().optional(),
      method: Method,
      normalized_path: z.string(),
      raw_request: z.string().optional(),
      body_hash: z.string().optional(),
      query_hash: z.string().optional(),
      status: Status,
      // Hackbrowser enrichment (optional — not sent by Firefox extension)
      trigger_element: z.string().optional(),
      element_roles: z.array(z.string()).optional(),
      ui_context: z.record(z.string(), z.unknown()).optional(),
      page_url: z.string().optional(),
      page_visited_by: z.array(z.string()).optional(),
      // normalize-proto enrichment (optional — legacy rows pre-date this).
      scheme: z.enum(["http", "https"]).optional(),
      host: z.string().optional(),
      port: z.number().optional(),
      origin: z.string().optional(),
      site: z.string().optional(),
      canonical_path: z.string().optional(),
      template_id: z.string().optional(),
      norm_source: NormSource.optional(),
      // Protocol/operation enrichment (optional — REST rows leave these unset).
      protocol: z.string().optional(),
      operation: z.string().optional(),
      op_key_hash: z.string().optional(),
      // Unified structural identity (Faz 0). Explicit dedup key; nullable on legacy rows.
      key_hash: z.string().optional(),
      // Response fields
      response_status: z.number().optional(),
      response_headers: z.record(z.string(), z.string()).optional(),
      response_content_type: z.string().optional(),
      response_size: z.number().optional(),
      processed_response: z.string().optional(),
      time: z.object({
        created: z.number(),
        updated: z.number(),
      }),
    })
    .meta({ ref: "Request" })
  export type Info = z.infer<typeof Info>

  export const Event = {
    Updated: BusEvent.define(
      "request.updated",
      z.object({
        sessionID: z.string(),
        requests: z.array(Info),
      }),
    ),
  }

  export function add(input: {
    id?: string
    sessionID: string
    method: z.infer<typeof Method>
    normalizedPath: string
    credentialID?: string
    rawRequest?: string
    bodyHash?: string
    queryHash?: string
    response?: ResponseInput
    // Hackbrowser enrichment (optional — not sent by Firefox extension)
    triggerElement?: string
    elementRoles?: string[]
    uiContext?: Record<string, unknown>
    pageUrl?: string
    pageVisitedBy?: string[]
    // normalize-proto enrichment (optional — supplied by Normalize.run when called from ingest)
    scheme?: "http" | "https"
    host?: string
    port?: number
    origin?: string
    site?: string
    canonicalPath?: string
    templateID?: string
    normSource?: z.infer<typeof NormSource>
    protocol?: string
    operation?: string
    opKeyHash?: string
    keyHash?: string
  }): Info | undefined {
    // Use the ID stamped at intake so asynchronous normalization cannot reverse
    // FIFO recovery order after a restart.
    const id = input.id ?? Identifier.ascending("request")
    const now = Date.now()

    const responseURL = requestResponseURL(input)
    const processed = input.response ? processResponse({ ...input.response, url: responseURL }) : undefined
    const responseBodyHash = input.response
      ? createHash("sha256").update(input.response.body, "utf8").digest("hex")
      : undefined
    const emptyStaticHTML = processed?.htmlSource !== undefined
      ? isConfirmedEmptyStaticHTML({
          method: input.method,
          responseStatus: processed.status,
          responseContentType: processed.contentType,
          responseSize: processed.originalSize,
          contentLength: input.response
            ? Object.entries(input.response.headers).find(([name]) => name.toLowerCase() === "content-length")?.[1]
            : undefined,
          htmlSource: processed.htmlSource,
          rawRequest: input.rawRequest,
          bodyHash: input.bodyHash,
          queryHash: input.queryHash,
          protocol: input.protocol,
          operation: input.operation,
          triggerElement: input.triggerElement,
          elementRoles: input.elementRoles,
          uiContext: input.uiContext,
        })
      : false

    // Every captured HTTP transaction is an independent analysis item. key_hash
    // remains a structural endpoint identity for observation grouping and correlation,
    // not a request-level deduplication key.
    const inserted = Database.transaction((db) => {
      const created = db
        .insert(RequestTable)
        .values({
          id,
          session_id: input.sessionID,
          credential_id: input.credentialID ?? null,
          method: input.method,
          normalized_path: input.normalizedPath,
          raw_request: input.rawRequest ?? null,
          body_hash: input.bodyHash ?? null,
          query_hash: input.queryHash ?? null,
          status: "queued",
          trigger_element: input.triggerElement ?? null,
          element_roles: input.elementRoles ?? null,
          ui_context: input.uiContext ?? null,
          page_url: input.pageUrl ?? null,
          page_visited_by: input.pageVisitedBy ?? null,
          scheme: input.scheme ?? null,
          host: input.host ?? null,
          port: input.port ?? null,
          origin: input.origin ?? null,
          site: input.site ?? null,
          canonical_path: input.canonicalPath ?? null,
          template_id: input.templateID ?? null,
          norm_source: input.normSource ?? null,
          protocol: input.protocol ?? null,
          operation: input.operation ?? null,
          op_key_hash: input.opKeyHash ?? null,
          key_hash: input.keyHash ?? null,
          response_status: processed?.status ?? null,
          response_headers: processed?.headers ?? null,
          response_content_type: processed?.contentType ?? null,
          response_size: processed?.originalSize ?? null,
          response_body_hash: responseBodyHash ?? null,
          processed_response: processed?.content ?? null,
          javascript_source: processed?.javascriptSource ?? null,
          empty_static_html: emptyStaticHTML ? 1 : 0,
          time_created: now,
          time_updated: now,
        })
        .returning({ id: RequestTable.id })
        .all()
      const linkedRequestID = created[0]?.id
      if (processed?.javascriptSource && linkedRequestID) {
        const sourceURL = canonicalSourceURL(responseURL)
        const contentHash = createHash("sha256").update(processed.javascriptSource).digest("hex")
        db.insert(RequestJavaScriptCaptureTable).values({
          id: Identifier.ascending("request_javascript_capture"),
          session_id: input.sessionID,
          request_id: linkedRequestID,
          source_url: sourceURL,
          content_hash: contentHash,
          source_content: processed.javascriptSource,
          content_type: processed.contentType,
          response_size: processed.originalSize,
          time_created: now,
        }).onConflictDoNothing().run()
      }
      return created
    })
    // Race-duplicate: a concurrent ingest already owns this key_hash → caller skips.
    if (inserted.length === 0) return undefined
    const list = get(input.sessionID)
    Bus.publish(Event.Updated, { sessionID: input.sessionID, requests: list })
    return {
      id,
      session_id: input.sessionID,
      credential_id: input.credentialID,
      method: input.method,
      normalized_path: input.normalizedPath,
      raw_request: input.rawRequest,
      body_hash: input.bodyHash,
      query_hash: input.queryHash,
      status: "queued" as const,
      trigger_element: input.triggerElement,
      element_roles: input.elementRoles,
      ui_context: input.uiContext,
      page_url: input.pageUrl,
      page_visited_by: input.pageVisitedBy,
      scheme: input.scheme,
      host: input.host,
      port: input.port,
      origin: input.origin,
      site: input.site,
      canonical_path: input.canonicalPath,
      template_id: input.templateID,
      norm_source: input.normSource,
      protocol: input.protocol,
      operation: input.operation,
      op_key_hash: input.opKeyHash,
      key_hash: input.keyHash,
      response_status: processed?.status,
      response_headers: processed?.headers,
      response_content_type: processed?.contentType,
      response_size: processed?.originalSize,
      processed_response: processed?.content,
      time: { created: now, updated: now },
    }
  }

  /**
   * Save a JavaScript response version for an already-known request without enqueueing
   * another request-analysis job. Used when ingest deduplicates a repeated request shape.
   */
  export function captureJavaScriptSource(input: {
    sessionID: string
    method: z.infer<typeof Method>
    normalizedPath: string
    response?: ResponseInput
    keyHash?: string
    queryHash?: string
    bodyHash?: string
    opKeyHash?: string
    origin?: string
    scheme?: "http" | "https"
    host?: string
    port?: number
    pageUrl?: string
  }): { requestID: string; captured: boolean; contentHash?: string } | undefined {
    if (!input.response) return undefined
    const responseURL = requestResponseURL(input)
    const processed = processResponse({ ...input.response, url: responseURL })
    if (!processed.javascriptSource) return undefined

    const request = Database.use((db) => {
      if (input.keyHash) {
        const match = db.select({ id: RequestTable.id }).from(RequestTable).where(and(
          eq(RequestTable.session_id, input.sessionID),
          eq(RequestTable.key_hash, input.keyHash),
        )).get()
        if (match) return match
      }
      const conditions = [
        eq(RequestTable.session_id, input.sessionID),
        eq(RequestTable.method, input.method),
        eq(RequestTable.normalized_path, input.normalizedPath),
        input.origin ? eq(RequestTable.origin, input.origin) : isNull(RequestTable.origin),
      ]
      if (input.opKeyHash) {
        conditions.push(eq(RequestTable.op_key_hash, input.opKeyHash))
      } else {
        conditions.push(
          input.bodyHash ? eq(RequestTable.body_hash, input.bodyHash) : isNull(RequestTable.body_hash),
          input.queryHash ? eq(RequestTable.query_hash, input.queryHash) : isNull(RequestTable.query_hash),
        )
      }
      return db.select({ id: RequestTable.id }).from(RequestTable).where(and(...conditions)).orderBy(asc(RequestTable.id)).get()
    })
    if (!request) return undefined

    const contentHash = createHash("sha256").update(processed.javascriptSource).digest("hex")
    const inserted = Database.transaction((db) =>
      db.insert(RequestJavaScriptCaptureTable).values({
        id: Identifier.ascending("request_javascript_capture"),
        session_id: input.sessionID,
        request_id: request.id,
        source_url: canonicalSourceURL(responseURL),
        content_hash: contentHash,
        source_content: processed.javascriptSource!,
        content_type: processed.contentType,
        response_size: processed.originalSize,
        time_created: Date.now(),
      }).onConflictDoNothing().returning({ id: RequestJavaScriptCaptureTable.id }).all(),
    )
    return { requestID: request.id, captured: inserted.length > 0, contentHash }
  }

  function rowToInfo(row: typeof RequestTable.$inferSelect): Info {
    return {
      id: row.id,
      session_id: row.session_id,
      credential_id: row.credential_id ?? undefined,
      method: row.method as Info["method"],
      normalized_path: row.normalized_path,
      raw_request: row.raw_request ?? undefined,
      body_hash: row.body_hash ?? undefined,
      query_hash: row.query_hash ?? undefined,
      status: row.status as Info["status"],
      trigger_element: row.trigger_element ?? undefined,
      element_roles: (row.element_roles as string[]) ?? undefined,
      ui_context: (row.ui_context as Record<string, unknown>) ?? undefined,
      page_url: row.page_url ?? undefined,
      page_visited_by: (row.page_visited_by as string[]) ?? undefined,
      scheme: (row.scheme as "http" | "https" | null) ?? undefined,
      host: row.host ?? undefined,
      port: row.port ?? undefined,
      origin: row.origin ?? undefined,
      site: row.site ?? undefined,
      canonical_path: row.canonical_path ?? undefined,
      template_id: row.template_id ?? undefined,
      norm_source: (row.norm_source as Info["norm_source"]) ?? undefined,
      protocol: row.protocol ?? undefined,
      operation: row.operation ?? undefined,
      op_key_hash: row.op_key_hash ?? undefined,
      key_hash: row.key_hash ?? undefined,
      response_status: row.response_status ?? undefined,
      response_headers: (row.response_headers as Record<string, string>) ?? undefined,
      response_content_type: row.response_content_type ?? undefined,
      response_size: row.response_size ?? undefined,
      processed_response: row.processed_response ?? undefined,
      time: { created: row.time_created, updated: row.time_updated },
    }
  }

  export function get(sessionID: string): Info[] {
    const rows = Database.use((db) =>
      // ORDER BY id ASC = ingest order. Keep request order stable for UI consumers.
      db.select().from(RequestTable).where(eq(RequestTable.session_id, sessionID)).orderBy(asc(RequestTable.id)).all(),
    )
    return rows.map(rowToInfo)
  }

  /**
   * Return unfinished requests in their original intake order. Their IDs are stamped
   * before asynchronous normalization so write/completion order cannot reorder recovery.
   */
  export function pending(): Info[] {
    const rows = Database.use((db) =>
      db
        .select()
        .from(RequestTable)
        .where(or(eq(RequestTable.status, "queued"), eq(RequestTable.status, "processing")))
        .orderBy(asc(RequestTable.id))
        .all(),
    )
    return rows.map(rowToInfo)
  }

  /**
   * Two-stage dedup at the TEMPLATE level. Same endpoint shape (normalized
   * template) hit twice — even with different concrete paths like
   * `/users/1` vs `/users/2` — must collapse to one row so proxy-agent only
   * analyzes the template once. The credential who hit it first wins on
   * `request.credential_id`; subsequent hits with different credentials are
   * still recorded by `WebCredential` and matched against the function via
   * cross-cred replay tools.
   *
   * Body/query hashes still discriminate, so PUTs with different bodies
   * (mass-assignment evidence) stay distinct.
   *
   * Stage 1: new identity — (sessionID, method, origin, normalized_path)
   * Stage 2: legacy rows pre-date `origin` — fall back to (normalized_path)
   * limited to rows with origin IS NULL so we don't spuriously match new ones.
   */
  export function exists(input: {
    sessionID: string
    method: string
    normalizedPath: string
    origin?: string
    bodyHash?: string
    queryHash?: string
    opKeyHash?: string
    keyHash?: string
  }): boolean {
    // Primary (Faz 1): key_hash is the unified structural identity. One indexed
    // lookup collapses same-shape requests — including REST mutations whose values
    // differ but whose body key-shape matches. The value-bearing stages below
    // remain as a correctness fallback and for legacy rows (key_hash IS NULL);
    // they can only ever AND-narrow, so they never cause a false collapse.
    const keyHash = input.keyHash
    if (keyHash != null) {
      const hit = Database.use((db) =>
        db
          .select({ id: RequestTable.id })
          .from(RequestTable)
          .where(and(eq(RequestTable.session_id, input.sessionID), eq(RequestTable.key_hash, keyHash)))
          .limit(1)
          .all(),
      )
      if (hit.length > 0) return true
    }
    // For body/header-dispatched protocols (GraphQL/JSON-RPC) the operation key
    // REPLACES body_hash/query_hash as the discriminator — body_hash carries
    // values, so same-operation/different-values calls would never collapse if we
    // also AND'd it in. REST rows have op_key_hash null and use the body/query
    // hashes exactly as before.
    const matches = (rows: { body_hash: string | null; query_hash: string | null; op_key_hash: string | null }[]) =>
      input.opKeyHash != null
        ? rows.some((r) => r.op_key_hash === input.opKeyHash)
        : rows.some(
            (r) =>
              (input.bodyHash ? r.body_hash === input.bodyHash : r.body_hash == null) &&
              (input.queryHash ? r.query_hash === input.queryHash : r.query_hash == null),
          )

    // Stages below are the LEGACY fallback, scoped to rows that pre-date key_hash
    // (key_hash IS NULL). For new rows the key_hash stage above is authoritative —
    // without this scope the value-only query_hash would over-collapse dispatcher
    // variants (e.g. /search?type=user vs ?type=admin) that key_hash correctly splits.
    const origin = input.origin
    if (origin) {
      const newKeyRows = Database.use((db) =>
        db
          .select({
            body_hash: RequestTable.body_hash,
            query_hash: RequestTable.query_hash,
            op_key_hash: RequestTable.op_key_hash,
          })
          .from(RequestTable)
          .where(
            and(
              eq(RequestTable.session_id, input.sessionID),
              eq(RequestTable.method, input.method),
              eq(RequestTable.origin, origin),
              eq(RequestTable.normalized_path, input.normalizedPath),
              isNull(RequestTable.key_hash),
            ),
          )
          .all(),
      )
      if (matches(newKeyRows)) return true
    }

    // Stage 2: legacy fallback. Only matches rows that pre-date origin.
    const legacyRows = Database.use((db) =>
      db
        .select({
          body_hash: RequestTable.body_hash,
          query_hash: RequestTable.query_hash,
          op_key_hash: RequestTable.op_key_hash,
        })
        .from(RequestTable)
        .where(
          and(
            eq(RequestTable.session_id, input.sessionID),
            eq(RequestTable.method, input.method),
            eq(RequestTable.normalized_path, input.normalizedPath),
            isNull(RequestTable.origin),
            isNull(RequestTable.key_hash),
          ),
        )
        .all(),
    )
    return matches(legacyRows)
  }

  /**
   * Find the persisted request owning the current structural dedup key.
   * This is a single indexed lookup and avoids loading all historical requests
   * just to recover the state of a repeated browser capture.
   */
  export function findByKeyHash(sessionID: string, keyHash: string): Info | undefined {
    const row = Database.use((db) =>
      db.select().from(RequestTable)
        .where(and(eq(RequestTable.session_id, sessionID), eq(RequestTable.key_hash, keyHash)))
        .get(),
    )
    return row ? rowToInfo(row) : undefined
  }

  /**
   * Return the preflight classification computed from the complete original HTML
   * body at intake. Only the compact boolean result is persisted.
   */
  export function isConfirmedEmptyStatic(id: string): boolean {
    const row = Database.use((db) =>
      db.select({ empty_static_html: RequestTable.empty_static_html })
        .from(RequestTable)
        .where(eq(RequestTable.id, id))
        .get(),
    )
    return row?.empty_static_html === 1
  }

  /**
   * Find a previously completed, byte-for-byte equivalent capture for the same
   * credential and UI/access context. Different credentials are never folded
   * together: they are essential cross-account and cross-tenant evidence.
   *
   * This is analysis-work reuse only. The current request row and observations
   * remain independent and retain their own Request ID.
   */
  export function findEquivalentProcessed(request: Info): Info | undefined {
    if (!request.id || !request.key_hash || !request.credential_id || !request.raw_request) return undefined

    const current = Database.use((db) =>
      db.select().from(RequestTable)
        .where(and(eq(RequestTable.id, request.id), eq(RequestTable.session_id, request.session_id)))
        .get(),
    )
    if (!current || current.response_status == null || current.response_size == null) return undefined

    // A truncated text preview is not enough to establish exact response equality.
    if (current.response_body_hash == null) return undefined

    const candidates = Database.use((db) =>
      db.select().from(RequestTable).where(and(
        eq(RequestTable.session_id, request.session_id),
        eq(RequestTable.status, "processed"),
        eq(RequestTable.key_hash, request.key_hash!),
        eq(RequestTable.credential_id, request.credential_id!),
        eq(RequestTable.method, request.method),
        eq(RequestTable.normalized_path, request.normalized_path),
        request.origin ? eq(RequestTable.origin, request.origin) : isNull(RequestTable.origin),
        request.body_hash ? eq(RequestTable.body_hash, request.body_hash) : isNull(RequestTable.body_hash),
        request.query_hash ? eq(RequestTable.query_hash, request.query_hash) : isNull(RequestTable.query_hash),
        eq(RequestTable.raw_request, request.raw_request!),
      )).orderBy(asc(RequestTable.id)).all(),
    )

    const sameJSON = (a: unknown, b: unknown) => JSON.stringify(a ?? null) === JSON.stringify(b ?? null)
    const prior = candidates.find((candidate) =>
      candidate.id !== request.id &&
      candidate.response_status === current.response_status &&
      candidate.response_content_type === current.response_content_type &&
      candidate.response_size === current.response_size &&
      candidate.response_body_hash === current.response_body_hash &&
      candidate.processed_response === current.processed_response &&
      candidate.javascript_source === current.javascript_source &&
      sameJSON(candidate.response_headers, current.response_headers) &&
      sameJSON(candidate.element_roles, current.element_roles) &&
      sameJSON(candidate.ui_context, current.ui_context) &&
      candidate.trigger_element === current.trigger_element &&
      candidate.page_url === current.page_url &&
      sameJSON(candidate.page_visited_by, current.page_visited_by),
    )
    if (!prior) return undefined

    return rowToInfo(prior)
  }

  /**
   * Explicitly requeue a failed captured-request analysis.
   *
   * The status check and transition happen in one transaction so duplicate retry
   * requests cannot enqueue the same failed row twice. Successful and in-flight
   * requests remain untouched.
   */
  export function retryFailed(sessionID: string, requestID: string): Info | undefined {
    const row = Database.transaction((db) => {
      const current = db
        .select()
        .from(RequestTable)
        .where(and(eq(RequestTable.id, requestID), eq(RequestTable.session_id, sessionID)))
        .get()
      if (!current || current.status !== "failed") return undefined

      db.update(RequestTable)
        .set({ status: "queued", time_updated: Date.now() })
        .where(
          and(
            eq(RequestTable.id, requestID),
            eq(RequestTable.session_id, sessionID),
            eq(RequestTable.status, "failed"),
          ),
        )
        .run()

      return db
        .select()
        .from(RequestTable)
        .where(and(eq(RequestTable.id, requestID), eq(RequestTable.session_id, sessionID)))
        .get()
    })
    if (!row || row.status !== "queued") return undefined
    Bus.publish(Event.Updated, { sessionID, requests: get(sessionID) })
    return rowToInfo(row)
  }

  export function updateStatus(input: { id: string; status: z.infer<typeof Status> }) {
    const now = Date.now()
    const row = Database.use((db) => {
      db.update(RequestTable)
        .set({ status: input.status, time_updated: now })
        .where(eq(RequestTable.id, input.id))
        .run()
      return db.select().from(RequestTable).where(eq(RequestTable.id, input.id)).get()
    })
    if (row) {
      const list = get(row.session_id)
      Bus.publish(Event.Updated, { sessionID: row.session_id, requests: list })
    }
  }

  export function hash(value: string | undefined): string | undefined {
    if (!value) return undefined
    return createHash("sha256").update(value).digest("hex").slice(0, 16)
  }

  export function hashQueryKeys(query: string | undefined): string | undefined {
    if (!query) return undefined
    const params = new URLSearchParams(query)
    const keys = Array.from(params.keys()).sort()
    if (keys.length === 0) return undefined
    return createHash("sha256").update(keys.join(",")).digest("hex").slice(0, 16)
  }

  // The legacy LLM-only `Request.normalize()` and `Request.parseRawRequest()`
  // were removed in PR-5. Path normalization now flows through
  // `session/normalize/index.ts → Normalize.run()`, which handles parsing,
  // tier-1 regex fast-path, tier-2 cache lookup, and tier-3 LLM fallback in
  // one place. The ingest route invokes it directly.
}
