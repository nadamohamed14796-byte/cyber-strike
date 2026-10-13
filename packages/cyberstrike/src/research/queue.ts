import { and, asc, eq, gt, inArray, isNull, lt, or } from "drizzle-orm"
import { Database } from "../storage/db"
import { ResearchQueueTable } from "./queue.sql"
import { RESEARCH_LEARNING_VERSION, RESEARCH_MODEL_STUDY_VERSION } from "./sources"

export type ResearchQueueStatus = "discovered" | "queued" | "studying" | "learned" | "retry" | "rejected" | "blocked_auth"

const LEASE_MS = 5 * 60_000
const CRAWL_PAGE_TTL_MS = 6 * 60 * 60_000
const MAX_CACHED_DISCOVERY_LINKS = 160
const MAX_CACHED_DISCOVERY_LINK_CHARS = 16_384

function boundedDiscoveryLinks(links: string[] | undefined) {
  if (!links) return undefined
  const unique = new Set<string>()
  const result: string[] = []
  let totalChars = 0
  for (const link of links) {
    if (typeof link !== "string" || link.length > 4096 || unique.has(link)) continue
    if (totalChars + link.length > MAX_CACHED_DISCOVERY_LINK_CHARS) continue
    unique.add(link)
    result.push(link)
    totalChars += link.length
    if (result.length >= MAX_CACHED_DISCOVERY_LINKS) break
  }
  return result
}

function publicID(sequence: number) {
  return "RPT-" + String(sequence).padStart(6, "0")
}

export namespace ResearchQueue {
  export function enqueue(input: {
    sourceID: string
    sourceURL: string
    title?: string
    payload?: Record<string, unknown>
  }) {
    const now = Date.now()
    return Database.transaction((db) => {
      const existing = db
        .select()
        .from(ResearchQueueTable)
        .where(
          and(eq(ResearchQueueTable.source_id, input.sourceID), eq(ResearchQueueTable.source_url, input.sourceURL)),
        )
        .get()
      if (existing) {
        // A URL first seen as an index page may later become a relevant report.
        // Promote it in place rather than letting the crawl cache suppress it forever.
        if (existing.payload?.crawl_page === true) {
          const promoted = db.update(ResearchQueueTable).set({
            title: input.title ?? existing.title,
            payload: input.payload ?? {},
            status: "queued",
            attempts: 0,
            last_error: null,
            lease_owner: null,
            lease_until: null,
            completed_at: null,
            updated_at: now,
          }).where(and(
            eq(ResearchQueueTable.sequence, existing.sequence),
            eq(ResearchQueueTable.status, "discovered"),
          )).returning().get()
          if (promoted) return { id: publicID(promoted.sequence), sequence: promoted.sequence, created: true }
        }
        return { id: publicID(existing.sequence), sequence: existing.sequence, created: false }
      }

      const row = db
        .insert(ResearchQueueTable)
        .values({
          source_id: input.sourceID,
          source_url: input.sourceURL,
          title: input.title ?? null,
          payload: input.payload ?? {},
          status: "queued",
          attempts: 0,
          discovered_at: now,
          updated_at: now,
        })
        .onConflictDoNothing()
        .returning()
        .get()
      if (row) return { id: publicID(row.sequence), sequence: row.sequence, created: true }
      const raced = db
        .select()
        .from(ResearchQueueTable)
        .where(
          and(eq(ResearchQueueTable.source_id, input.sourceID), eq(ResearchQueueTable.source_url, input.sourceURL)),
        )
        .get()
      if (!raced) throw new Error("research queue insert conflicted but the row could not be reloaded")
      return { id: publicID(raced.sequence), sequence: raced.sequence, created: false }
    })
  }

  /**
   * Queue a previously stored public report for the model-led study path using its
   * already sanitized excerpt. This upgrades older heuristic-only knowledge without
   * making another network request.
   */
  export function enqueueForModelStudy(input: {
    sourceID: string
    sourceURL: string
    title: string
    payload: Record<string, unknown>
    modelStudyVersion?: number
  }) {
    const now = Date.now()
    const version = Math.max(1, Math.floor(Number.isFinite(input.modelStudyVersion) ? input.modelStudyVersion ?? RESEARCH_MODEL_STUDY_VERSION : RESEARCH_MODEL_STUDY_VERSION))
    return Database.transaction((db) => {
      const existing = db.select().from(ResearchQueueTable).where(and(
        eq(ResearchQueueTable.source_id, input.sourceID),
        eq(ResearchQueueTable.source_url, input.sourceURL),
      )).get()
      if (!existing) {
        const payload = { ...input.payload, model_study_requested_version: version }
        const row = db.insert(ResearchQueueTable).values({
          source_id: input.sourceID,
          source_url: input.sourceURL,
          title: input.title,
          payload,
          status: "queued",
          attempts: 0,
          discovered_at: now,
          updated_at: now,
        }).onConflictDoNothing().returning().get()
        if (row) return { id: publicID(row.sequence), sequence: row.sequence, queued: true, created: true }
        const raced = db.select().from(ResearchQueueTable).where(and(
          eq(ResearchQueueTable.source_id, input.sourceID),
          eq(ResearchQueueTable.source_url, input.sourceURL),
        )).get()
        return raced
          ? { id: publicID(raced.sequence), sequence: raced.sequence, queued: raced.status === "queued" || raced.status === "retry", created: false }
          : { id: "", sequence: 0, queued: false, created: false }
      }

      if (typeof existing.payload?.model_study_version === "number" && existing.payload.model_study_version >= version) {
        return { id: publicID(existing.sequence), sequence: existing.sequence, queued: false, created: false, reason: "already-model-studied" }
      }
      if (
        existing.status === "studying" &&
        typeof existing.lease_until === "number" &&
        existing.lease_until > now
      ) {
        return { id: publicID(existing.sequence), sequence: existing.sequence, queued: false, created: false, reason: "currently-claimed" }
      }

      const {
        crawl_page: _crawlPage,
        crawl_error: _crawlError,
        auth_required: _authRequired,
        ...previousPayload
      } = existing.payload ?? {}
      const priorText = typeof previousPayload.cached_text === "string" ? previousPayload.cached_text : ""
      const incomingText = typeof input.payload.cached_text === "string" ? input.payload.cached_text : ""
      // Preserve a canonical cached excerpt only when it is long enough to study.
      // A stale short excerpt must not block the safe refetch path for legacy rows.
      const keepPriorText = priorText.trim().length >= 250 && priorText.length >= incomingText.length
      const payload = {
        ...previousPayload,
        ...input.payload,
        ...(keepPriorText ? { cached_text: priorText } : {}),
        ...(keepPriorText && typeof previousPayload.content_length === "number"
          ? { content_length: previousPayload.content_length }
          : {}),
        ...(keepPriorText && typeof previousPayload.content_fingerprint === "string"
          ? { content_fingerprint: previousPayload.content_fingerprint }
          : {}),
        ...(keepPriorText && previousPayload.cached_text_truncated === true
          ? { cached_text_truncated: true }
          : {}),
        model_study_requested_version: version,
      }
      const requeued = existing.status !== "queued" && existing.status !== "retry"
      const updated = db.update(ResearchQueueTable).set({
        title: input.title || existing.title,
        payload,
        status: "queued",
        attempts: requeued ? 0 : existing.attempts,
        last_error: null,
        lease_owner: null,
        lease_until: null,
        completed_at: null,
        updated_at: now,
      }).where(eq(ResearchQueueTable.sequence, existing.sequence)).returning().get()
      return updated
        ? { id: publicID(updated.sequence), sequence: updated.sequence, queued: true, created: false, requeued }
        : { id: publicID(existing.sequence), sequence: existing.sequence, queued: false, created: false, reason: "queue-row-changed" }
    })
  }

  /**
   * Revisit reports previously marked learned/rejected by the heuristic worker when
   * there is no completed model-study marker. Existing sanitized excerpts are reused;
   * missing excerpts use the source-scoped fetcher. A requested marker is not enough
   * to suppress retries if another worker completed the row without model study.
   */
  export function requeueLearnedForModelStudy(limit = 100, sourceID?: string, modelStudyVersion = RESEARCH_MODEL_STUDY_VERSION) {
    const now = Date.now()
    const version = Math.max(1, Math.floor(Number.isFinite(modelStudyVersion) ? modelStudyVersion : RESEARCH_MODEL_STUDY_VERSION))
    const bounded = Math.max(1, Math.min(500, Math.floor(Number.isFinite(limit) ? limit : 100)))
    return Database.transaction((db) => {
      const candidates = db.select().from(ResearchQueueTable).where(and(
        inArray(ResearchQueueTable.status, ["learned", "rejected"]),
        ...(sourceID ? [eq(ResearchQueueTable.source_id, sourceID)] : []),
      )).orderBy(asc(ResearchQueueTable.sequence)).all().filter((row) => {
        if (row.payload?.crawl_page === true) return false
        // Missing excerpts are recoverable: the model-led claim path fetches via
        // the source-scoped allowlisted fetcher when cached_text is absent.
        const studied = row.payload.model_study_version
        // A request marker alone is not completion: an older heuristic worker may
        // have reclaimed the row after scheduling. Only the model's completion
        // marker prevents another model-study attempt.
        if (typeof studied === "number" && studied >= version) return false
        if (row.status === "rejected" && !["no recognizable security topic", "page failed research relevance gate"].includes(row.last_error ?? "")) return false
        return true
      }).slice(0, bounded)

      let updatedCount = 0
      for (const row of candidates) {
        const updated = db.update(ResearchQueueTable).set({
          status: "queued",
          payload: { ...(row.payload ?? {}), model_study_requested_version: version },
          attempts: 0,
          last_error: null,
          lease_owner: null,
          lease_until: null,
          completed_at: null,
          updated_at: now,
        }).where(and(
          eq(ResearchQueueTable.sequence, row.sequence),
          inArray(ResearchQueueTable.status, ["learned", "rejected"]),
        )).returning({ sequence: ResearchQueueTable.sequence }).get()
        if (updated) updatedCount++
      }
      return updatedCount
    })
  }

  export function find(sourceID: string, sourceURL: string) {
    return Database.use((db) => db.select().from(ResearchQueueTable)
      .where(and(eq(ResearchQueueTable.source_id, sourceID), eq(ResearchQueueTable.source_url, sourceURL))).get())
  }

  export function isFreshCrawlPage(sourceID: string, sourceURL: string, now = Date.now(), maxAge = CRAWL_PAGE_TTL_MS) {
    const row = find(sourceID, sourceURL)
    return row?.payload?.crawl_page === true && now >= row.updated_at && now - row.updated_at < maxAge
  }

  /**
   * Persist a transient crawl failure as a cached discovery page. Watch-mode
   * crawlers can then respect the normal crawl TTL instead of repeatedly
   * hammering a failing source on every cycle. A real report row is never
   * downgraded to a crawl marker.
   */
  export function markFailedCrawlPage(input: { sourceID: string; sourceURL: string; title?: string; reason: string }) {
    const now = Date.now()
    return Database.transaction((db) => {
      const existing = db.select().from(ResearchQueueTable)
        .where(and(eq(ResearchQueueTable.source_id, input.sourceID), eq(ResearchQueueTable.source_url, input.sourceURL))).get()
      if (existing && existing.payload?.crawl_page !== true) return existing

      const { auth_required: _authRequired, cached_text: _cachedText, crawl_error: _crawlError, ...payload } =
        existing?.payload ?? {}
      const updatedPayload = { ...payload, crawl_page: true, crawl_error: true }
      if (existing) {
        return db.update(ResearchQueueTable).set({
          title: input.title ?? existing.title,
          payload: updatedPayload,
          status: "discovered",
          last_error: input.reason.slice(0, 1000),
          lease_owner: null,
          lease_until: null,
          updated_at: now,
          completed_at: null,
        }).where(eq(ResearchQueueTable.sequence, existing.sequence)).returning().get()
      }

      return db.insert(ResearchQueueTable).values({
        source_id: input.sourceID,
        source_url: input.sourceURL,
        title: input.title ?? null,
        payload: updatedPayload,
        status: "discovered",
        attempts: 0,
        last_error: input.reason.slice(0, 1000),
        discovered_at: now,
        updated_at: now,
      }).onConflictDoNothing().returning().get()
    })
  }

  export function markVisitedPage(input: {
    sourceID: string
    sourceURL: string
    title?: string
    contentFingerprint?: string
    discoveredLinks?: string[]
  }) {
    const now = Date.now()
    return Database.transaction((db) => {
      const existing = db.select().from(ResearchQueueTable)
        .where(and(eq(ResearchQueueTable.source_id, input.sourceID), eq(ResearchQueueTable.source_url, input.sourceURL))).get()
      // Preserve report status and source text while recording links discovered from its HTML.
      // A report is never downgraded to an index-page marker; the frontier is separate metadata.
      if (existing && existing.payload?.crawl_page !== true) {
        if (!input.discoveredLinks) return existing
        return db.update(ResearchQueueTable).set({
          payload: {
            ...(existing.payload ?? {}),
            discovered_links: boundedDiscoveryLinks(input.discoveredLinks)!,
          },
          updated_at: now,
        }).where(eq(ResearchQueueTable.sequence, existing.sequence)).returning().get()
      }
      if (existing) {
        // A successful revisit after login must clear the auth-wall marker. Otherwise the
        // row becomes "discovered" but still carries auth_required=true, contradicting its
        // state and confusing later crawl/retry decisions. Never retain cached login text.
        const {
          auth_required: _authRequired,
          cached_text: _cachedText,
          crawl_error: _crawlError,
          ...existingPayload
        } = existing.payload ?? {}
        return db.update(ResearchQueueTable).set({
          title: input.title ?? existing.title,
          payload: {
            ...existingPayload,
            crawl_page: true,
            ...(input.contentFingerprint ? { content_fingerprint: input.contentFingerprint } : {}),
            ...(input.discoveredLinks ? { discovered_links: boundedDiscoveryLinks(input.discoveredLinks)! } : {}),
          },
          status: "discovered",
          updated_at: now,
          last_error: null,
          lease_owner: null,
          lease_until: null,
          completed_at: null,
        }).where(eq(ResearchQueueTable.sequence, existing.sequence)).returning().get()
      }
      const inserted = db.insert(ResearchQueueTable).values({
        source_id: input.sourceID,
        source_url: input.sourceURL,
        title: input.title ?? null,
        payload: {
          crawl_page: true,
          ...(input.contentFingerprint ? { content_fingerprint: input.contentFingerprint } : {}),
          ...(input.discoveredLinks ? { discovered_links: boundedDiscoveryLinks(input.discoveredLinks)! } : {}),
        },
        status: "discovered",
        attempts: 0,
        discovered_at: now,
        updated_at: now,
      }).onConflictDoNothing().returning().get()
      if (inserted) return inserted
      return db.select().from(ResearchQueueTable)
        .where(and(eq(ResearchQueueTable.source_id, input.sourceID), eq(ResearchQueueTable.source_url, input.sourceURL))).get()
    })
  }

  export function blockAuthentication(input: {
    sourceID: string
    sourceURL: string
    title?: string
    reason: string
    payload?: Record<string, unknown>
    /** When called by a claimed learner, only that still-active lease may block the row. */
    claim?: { sequence: number; leaseOwner: string }
  }) {
    const now = Date.now()
    return Database.transaction((db) => {
      const existing = db.select().from(ResearchQueueTable)
        .where(and(
          eq(ResearchQueueTable.source_id, input.sourceID),
          eq(ResearchQueueTable.source_url, input.sourceURL),
          ...(input.claim ? [
            eq(ResearchQueueTable.sequence, input.claim.sequence),
            eq(ResearchQueueTable.status, "studying"),
            eq(ResearchQueueTable.lease_owner, input.claim.leaseOwner),
            gt(ResearchQueueTable.lease_until, now),
          ] : []),
        )).get()
      // A stale learner must not overwrite a newer worker's result or lease state.
      if (input.claim && !existing) return undefined
      // Preserve rows already completed by the model-study workflow. Authentication
      // is a fetch/access state, not a new study verdict; turning a learned/rejected
      // report into blocked_auth would lose its completion marker and cause repeat work.
      if (
        existing &&
        (existing.status === "learned" || existing.status === "rejected") &&
        typeof existing.payload?.model_study_version === "number"
      ) return existing
      if (existing) {
        // A cached login page must never be reused after credentials are configured.
        const {
          cached_text: _cachedText,
          auth_required: _authRequired,
          crawl_error: _crawlError,
          ...existingPayload
        } = existing.payload ?? {}
        const { cached_text: _incomingCachedText, ...incomingPayload } = input.payload ?? {}
        return db.update(ResearchQueueTable).set({
          status: "blocked_auth", title: input.title ?? existing.title,
          payload: { ...existingPayload, ...incomingPayload, auth_required: true },
          last_error: input.reason.slice(0, 1000), lease_owner: null, lease_until: null,
          updated_at: now, completed_at: now,
        }).where(and(
          eq(ResearchQueueTable.sequence, existing.sequence),
          ...(input.claim ? [
            eq(ResearchQueueTable.status, "studying"),
            eq(ResearchQueueTable.lease_owner, input.claim.leaseOwner),
            gt(ResearchQueueTable.lease_until, now),
          ] : []),
        )).returning().get()
      }
      const { cached_text: _incomingCachedText, ...incomingPayload } = input.payload ?? {}
      return db.insert(ResearchQueueTable).values({
        source_id: input.sourceID, source_url: input.sourceURL, title: input.title ?? null,
        payload: { ...incomingPayload, auth_required: true }, status: "blocked_auth", attempts: 0,
        last_error: input.reason.slice(0, 1000), discovered_at: now, updated_at: now, completed_at: now,
      }).returning().get()
    })
  }

  export function retryAuthenticationBlocked(limit = 100, sourceID?: string, minAgeMs = 0) {
    const now = Date.now()
    return Database.transaction((db) => {
      const rows = db.select().from(ResearchQueueTable).where(and(
          eq(ResearchQueueTable.status, "blocked_auth"),
          ...(sourceID ? [eq(ResearchQueueTable.source_id, sourceID)] : []),
          ...(minAgeMs > 0 ? [lt(ResearchQueueTable.updated_at, now - minAgeMs)] : []),
        ))
        .orderBy(asc(ResearchQueueTable.sequence)).limit(Math.max(1, Math.min(500, Math.floor(limit)))).all()
      let updatedCount = 0
      for (const row of rows) {
        const isCrawlPage = row.payload?.crawl_page === true
        const {
          auth_required: _authRequired,
          cached_text: _cachedText,
          crawl_error: _crawlError,
          ...payload
        } = row.payload ?? {}
        const updated = db.update(ResearchQueueTable).set({
          // Crawl/index pages must return to discovery, not be learned as if they were reports.
          status: isCrawlPage ? "discovered" : "queued",
          payload,
          attempts: 0,
          last_error: null,
          lease_owner: null,
          lease_until: null,
          completed_at: null,
          // Make auth-blocked index pages eligible for immediate rediscovery after credentials change.
          updated_at: isCrawlPage ? now - CRAWL_PAGE_TTL_MS - 1 : now,
        }).where(and(eq(ResearchQueueTable.sequence, row.sequence), eq(ResearchQueueTable.status, "blocked_auth"))).returning({ sequence: ResearchQueueTable.sequence }).get()
        if (updated) updatedCount++
      }
      return updatedCount
    })
  }

  /**
   * Requeue old reports rejected by the earlier classifier/relevance gate once.
   * If sanitized text is absent, the model-study claim path safely refetches the
   * report through its configured source allowlist. The version marker prevents
   * current-version rejects from being fed back into the queue indefinitely.
   */
  export function requeueLegacyRejected(limit = 100, sourceID?: string) {
    const now = Date.now()
    const bounded = Math.max(1, Math.min(500, Math.floor(Number.isFinite(limit) ? limit : 100)))
    return Database.transaction((db) => {
      const candidates = db.select().from(ResearchQueueTable)
        .where(sourceID
          ? and(eq(ResearchQueueTable.status, "rejected"), eq(ResearchQueueTable.source_id, sourceID))
          : eq(ResearchQueueTable.status, "rejected"))
        .orderBy(asc(ResearchQueueTable.sequence))
        .all()
        .filter((row) => {
          if (row.payload?.crawl_page === true) return false
          const previousVersion = row.payload?.learning_version
          if (typeof previousVersion === "number" && previousVersion >= RESEARCH_LEARNING_VERSION) return false
          // The model-study claim path can safely refetch an empty excerpt from
          // the exact configured source. Do not strand older rejected rows merely
          // because the former heuristic worker did not cache their text.
          return row.last_error === "no recognizable security topic" ||
            row.last_error === "page failed research relevance gate"
        })
        .slice(0, bounded)

      let updatedCount = 0
      for (const row of candidates) {
        const updated = db.update(ResearchQueueTable).set({
          status: "queued",
          payload: { ...(row.payload ?? {}), learning_version: RESEARCH_LEARNING_VERSION },
          attempts: 0,
          last_error: null,
          lease_owner: null,
          lease_until: null,
          completed_at: null,
          updated_at: now,
        }).where(and(
          eq(ResearchQueueTable.sequence, row.sequence),
          eq(ResearchQueueTable.status, "rejected"),
        )).returning({ sequence: ResearchQueueTable.sequence }).get()
        if (updated) updatedCount++
      }
      return updatedCount
    })
  }

  /** Load one exact active claim by its stable public ID and opaque lease token. */
  export function claimed(id: string, leaseOwner: string) {
    const match = /^RPT-(\d{1,12})$/.exec(id.trim())
    if (!match || !leaseOwner.trim()) return null
    const sequence = Number(match[1])
    if (!Number.isSafeInteger(sequence) || sequence <= 0) return null
    const now = Date.now()
    return Database.use((db) => {
      const row = db.select().from(ResearchQueueTable).where(and(
        eq(ResearchQueueTable.sequence, sequence),
        eq(ResearchQueueTable.status, "studying"),
        eq(ResearchQueueTable.lease_owner, leaseOwner),
        gt(ResearchQueueTable.lease_until, now),
      )).get()
      return row ? { ...row, public_id: publicID(row.sequence) } : null
    })
  }

  /**
   * Cache sanitized text fetched by the agent-study path, tied to the still-active
   * claim. This lets saving knowledge read canonical source text from SQLite rather
   * than trusting an excerpt echoed back by the model.
   */
  export function cacheClaimedText(input: {
    id: string
    leaseOwner: string
    title: string
    text: string
    contentFingerprint: string
    contentLength: number
  }) {
    const match = /^RPT-(\d{1,12})$/.exec(input.id.trim())
    if (!match || !input.leaseOwner.trim()) return false
    const sequence = Number(match[1])
    if (!Number.isSafeInteger(sequence) || sequence <= 0) return false
    const now = Date.now()
    return Database.transaction((db) => {
      const row = db.select().from(ResearchQueueTable).where(and(
        eq(ResearchQueueTable.sequence, sequence),
        eq(ResearchQueueTable.status, "studying"),
        eq(ResearchQueueTable.lease_owner, input.leaseOwner),
        gt(ResearchQueueTable.lease_until, now),
      )).get()
      if (!row) return false
      const text = input.text.slice(0, 100_000)
      const payload = {
        ...(row.payload ?? {}),
        cached_text: text,
        cached_text_truncated: input.contentLength > text.length,
        content_fingerprint: input.contentFingerprint,
        content_length: input.contentLength,
      }
      const updated = db.update(ResearchQueueTable).set({
        title: input.title.slice(0, 500),
        payload,
        updated_at: now,
      }).where(and(
        eq(ResearchQueueTable.sequence, sequence),
        eq(ResearchQueueTable.status, "studying"),
        eq(ResearchQueueTable.lease_owner, input.leaseOwner),
        gt(ResearchQueueTable.lease_until, now),
      )).returning().get()
      return Boolean(updated)
    })
  }

  export function claimNext(
    workerID: string,
    sourceID?: string,
    leaseDurationMs = LEASE_MS,
    modelStudyVersion?: number,
  ) {
    const now = Date.now()
    const boundedLease = Number.isFinite(leaseDurationMs)
      ? Math.max(LEASE_MS, Math.min(20 * 60_000, Math.floor(leaseDurationMs)))
      : LEASE_MS
    // Lease identity must be unique per claim, not just per configured worker label.
    // Otherwise a stale process could complete work reclaimed by a second process
    // that reused the same --worker value after the original lease expired.
    const leaseOwner = workerID + ":" + crypto.randomUUID()
    return Database.transaction((db) => {
      const row = db
        .select()
        .from(ResearchQueueTable)
        .where(sourceID
          ? and(
              eq(ResearchQueueTable.source_id, sourceID),
              or(
                inArray(ResearchQueueTable.status, ["queued", "retry"]),
                and(eq(ResearchQueueTable.status, "studying"), or(isNull(ResearchQueueTable.lease_until), lt(ResearchQueueTable.lease_until, now))),
              ),
            )
          : or(
              inArray(ResearchQueueTable.status, ["queued", "retry"]),
              and(eq(ResearchQueueTable.status, "studying"), or(isNull(ResearchQueueTable.lease_until), lt(ResearchQueueTable.lease_until, now))),
            ))
        .orderBy(asc(ResearchQueueTable.sequence))
        .limit(1)
        .get()
      if (!row) return null

      const claimed = db
        .update(ResearchQueueTable)
        .set({
          status: "studying",
          payload: {
            ...(row.payload ?? {}),
            learning_version: RESEARCH_LEARNING_VERSION,
            ...(typeof modelStudyVersion === "number"
              ? { model_study_requested_version: modelStudyVersion, model_study_started_at: now }
              : {}),
          },
          attempts: row.attempts + 1,
          lease_owner: leaseOwner,
          lease_until: now + boundedLease,
          claimed_at: now,
          updated_at: now,
          last_error: null,
        })
        .where(
          and(
            eq(ResearchQueueTable.sequence, row.sequence),
            eq(ResearchQueueTable.source_id, row.source_id),
            or(
              inArray(ResearchQueueTable.status, ["queued", "retry"]),
              and(eq(ResearchQueueTable.status, "studying"), or(isNull(ResearchQueueTable.lease_until), lt(ResearchQueueTable.lease_until, now))),
            ),
          ),
        )
        .returning()
        .get()
      return claimed ? { ...claimed, lease_owner: leaseOwner, public_id: publicID(claimed.sequence) } : null
    })
  }

  export function complete(
    sequence: number,
    leaseOwner: string,
    outcome: "learned" | "retry" | "rejected" | "blocked_auth",
    error?: string,
    payloadPatch?: Record<string, unknown>,
  ) {
    const now = Date.now()
    return Database.transaction((db) => {
      const row = db.select().from(ResearchQueueTable).where(and(
        eq(ResearchQueueTable.sequence, sequence),
        eq(ResearchQueueTable.status, "studying"),
        eq(ResearchQueueTable.lease_owner, leaseOwner),
        gt(ResearchQueueTable.lease_until, now),
      )).get()
      // Expired claims are no longer authorized to write a terminal state, even
      // when no replacement worker has claimed the row yet. The lease token
      // prevents stale workers from completing work after a reclaim; the expiry
      // check also fences late results before that reclaim happens.
      if (!row) return undefined
      return db.update(ResearchQueueTable).set({
        status: outcome,
        payload: payloadPatch ? { ...(row.payload ?? {}), ...payloadPatch } : row.payload,
        last_error: error ?? null,
        lease_owner: null,
        lease_until: null,
        completed_at: outcome === "learned" || outcome === "rejected" || outcome === "blocked_auth" ? now : null,
        updated_at: now,
      }).where(and(
        eq(ResearchQueueTable.sequence, sequence),
        eq(ResearchQueueTable.status, "studying"),
        eq(ResearchQueueTable.lease_owner, leaseOwner),
        gt(ResearchQueueTable.lease_until, now),
      )).returning().get()
    })
  }

  export function stats(sourceID?: string) {
    return Database.use((db) => {
      const rows = sourceID
        ? db.select().from(ResearchQueueTable).where(eq(ResearchQueueTable.source_id, sourceID)).orderBy(asc(ResearchQueueTable.sequence)).all()
        : db.select().from(ResearchQueueTable).orderBy(asc(ResearchQueueTable.sequence)).all()
      const crawlPageRows = rows.filter((row) => row.payload?.crawl_page === true)
      const reportRows = rows.filter((row) => row.payload?.crawl_page !== true)
      const modelStudiedRows = reportRows.filter((row) =>
        row.payload?.model_study_method === "llm-assisted-agent-command-v1" &&
        typeof row.payload?.model_study_version === "number" &&
        row.payload.model_study_version >= RESEARCH_MODEL_STUDY_VERSION,
      )
      const preflightSkippedRows = reportRows.filter((row) =>
        row.status === "rejected" &&
        row.payload?.model_study_method === "preflight-skip" &&
        row.payload?.model_study_decision === "skipped" &&
        typeof row.payload?.model_study_version === "number" &&
        row.payload.model_study_version >= RESEARCH_MODEL_STUDY_VERSION,
      )
      const counts: Record<string, number> = {
        total: reportRows.length,
        crawl_pages: crawlPageRows.length,
        crawl_page_errors: crawlPageRows.filter((row) => row.payload?.crawl_error === true).length,
        crawl_page_auth_blocked: crawlPageRows.filter((row) =>
          row.status === "blocked_auth" || row.payload?.auth_required === true,
        ).length,
        discovered: 0,
        queued: 0,
        studying: 0,
        learned: 0,
        retry: 0,
        rejected: 0,
        blocked_auth: 0,
        model_study_learned: modelStudiedRows.filter((row) => row.status === "learned").length,
        model_study_rejected: modelStudiedRows.filter((row) => row.status === "rejected").length,
        model_study_completed: modelStudiedRows.filter((row) => row.status === "learned" || row.status === "rejected").length,
        model_study_skipped: preflightSkippedRows.length,
        model_study_pending: reportRows.filter((row) => ["queued", "retry", "studying"].includes(row.status)).length,
      }
      for (const row of reportRows) counts[row.status] = (counts[row.status] ?? 0) + 1
      return counts
    })
  }

  export function pending(limit = 50) {
    return Database.use((db) =>
      db
        .select()
        .from(ResearchQueueTable)
        .where(inArray(ResearchQueueTable.status, ["queued", "retry", "studying", "blocked_auth"]))
        .orderBy(asc(ResearchQueueTable.sequence))
        .limit(Math.max(1, Math.min(500, Math.floor(limit))))
        .all()
        .map((row) => ({ ...row, public_id: publicID(row.sequence) })),
    )
  }
}
