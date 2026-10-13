import { and, asc, eq, inArray, isNull, lt, or } from "drizzle-orm"
import { Database } from "../storage/db"
import { ResearchQueueTable } from "./queue.sql"
import { RESEARCH_LEARNING_VERSION } from "./sources"

export type ResearchQueueStatus = "discovered" | "queued" | "studying" | "learned" | "retry" | "rejected" | "blocked_auth"

const LEASE_MS = 5 * 60_000
const CRAWL_PAGE_TTL_MS = 6 * 60 * 60_000

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

  export function markVisitedPage(input: { sourceID: string; sourceURL: string; title?: string; contentFingerprint?: string }) {
    const now = Date.now()
    return Database.transaction((db) => {
      const existing = db.select().from(ResearchQueueTable)
        .where(and(eq(ResearchQueueTable.source_id, input.sourceID), eq(ResearchQueueTable.source_url, input.sourceURL))).get()
      // Never downgrade or overwrite a real report/auth record with an index-page marker.
      if (existing && existing.payload?.crawl_page !== true) return existing
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
        payload: { crawl_page: true, ...(input.contentFingerprint ? { content_fingerprint: input.contentFingerprint } : {}) },
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

  export function blockAuthentication(input: { sourceID: string; sourceURL: string; title?: string; reason: string; payload?: Record<string, unknown> }) {
    const now = Date.now()
    return Database.transaction((db) => {
      const existing = db.select().from(ResearchQueueTable)
        .where(and(eq(ResearchQueueTable.source_id, input.sourceID), eq(ResearchQueueTable.source_url, input.sourceURL))).get()
      if (existing?.status === "learned" || existing?.status === "rejected") return existing
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
        }).where(eq(ResearchQueueTable.sequence, existing.sequence)).returning().get()
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
      for (const row of rows) {
        const isCrawlPage = row.payload?.crawl_page === true
        const {
          auth_required: _authRequired,
          cached_text: _cachedText,
          crawl_error: _crawlError,
          ...payload
        } = row.payload ?? {}
        db.update(ResearchQueueTable).set({
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
        }).where(and(eq(ResearchQueueTable.sequence, row.sequence), eq(ResearchQueueTable.status, "blocked_auth"))).run()
      }
      return rows.length
    })
  }

  /**
   * Requeue old reports rejected by the classifier/relevance gate only when a
   * cached text excerpt is available. The version marker makes this a one-time
   * migration: current-version rejects are never put back into the queue loop.
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
          if (typeof row.payload?.cached_text !== "string" || row.payload.cached_text.trim().length < 250) return false
          return row.last_error === "no recognizable security topic" ||
            row.last_error === "page failed research relevance gate"
        })
        .slice(0, bounded)

      for (const row of candidates) {
        db.update(ResearchQueueTable).set({
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
        )).run()
      }
      return candidates.length
    })
  }

  export function claimNext(workerID: string, sourceID?: string) {
    const now = Date.now()
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
          payload: { ...(row.payload ?? {}), learning_version: RESEARCH_LEARNING_VERSION },
          attempts: row.attempts + 1,
          lease_owner: leaseOwner,
          lease_until: now + LEASE_MS,
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
  ) {
    const now = Date.now()
    return Database.use((db) =>
      db
        .update(ResearchQueueTable)
        .set({
          status: outcome,
          last_error: error ?? null,
          lease_owner: null,
          lease_until: null,
          completed_at: outcome === "learned" || outcome === "rejected" || outcome === "blocked_auth" ? now : null,
          updated_at: now,
        })
        .where(
          and(
            eq(ResearchQueueTable.sequence, sequence),
            eq(ResearchQueueTable.status, "studying"),
            eq(ResearchQueueTable.lease_owner, leaseOwner),
          ),
        )
        .returning()
        .get(),
    )
  }

  export function stats(sourceID?: string) {
    return Database.use((db) => {
      const rows = sourceID
        ? db.select().from(ResearchQueueTable).where(eq(ResearchQueueTable.source_id, sourceID)).orderBy(asc(ResearchQueueTable.sequence)).all()
        : db.select().from(ResearchQueueTable).orderBy(asc(ResearchQueueTable.sequence)).all()
      const crawlPages = rows.filter((row) => row.payload?.crawl_page === true).length
      const reportRows = rows.filter((row) => row.payload?.crawl_page !== true)
      const counts: Record<string, number> = {
        total: reportRows.length,
        crawl_pages: crawlPages,
        discovered: 0,
        queued: 0,
        studying: 0,
        learned: 0,
        retry: 0,
        rejected: 0,
        blocked_auth: 0,
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
