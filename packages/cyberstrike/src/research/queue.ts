import { and, asc, eq, inArray, isNull, lt, or } from "drizzle-orm"
import { Database } from "../storage/db"
import { ResearchQueueTable } from "./queue.sql"

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

  export function markVisitedPage(input: { sourceID: string; sourceURL: string; title?: string; contentFingerprint?: string }) {
    const now = Date.now()
    return Database.transaction((db) => {
      const existing = db.select().from(ResearchQueueTable)
        .where(and(eq(ResearchQueueTable.source_id, input.sourceID), eq(ResearchQueueTable.source_url, input.sourceURL))).get()
      // Never downgrade or overwrite a real report/auth record with an index-page marker.
      if (existing && existing.payload?.crawl_page !== true) return existing
      if (existing) {
        return db.update(ResearchQueueTable).set({
          title: input.title ?? existing.title,
          payload: {
            ...existing.payload,
            crawl_page: true,
            ...(input.contentFingerprint ? { content_fingerprint: input.contentFingerprint } : {}),
          },
          status: "discovered",
          updated_at: now,
          last_error: null,
          lease_owner: null,
          lease_until: null,
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
      if (existing) return db.update(ResearchQueueTable).set({
        status: "blocked_auth", title: input.title ?? existing.title,
        payload: { ...(existing.payload ?? {}), ...(input.payload ?? {}), auth_required: true },
        last_error: input.reason.slice(0, 1000), lease_owner: null, lease_until: null,
        updated_at: now, completed_at: now,
      }).where(eq(ResearchQueueTable.sequence, existing.sequence)).returning().get()
      return db.insert(ResearchQueueTable).values({
        source_id: input.sourceID, source_url: input.sourceURL, title: input.title ?? null,
        payload: { ...(input.payload ?? {}), auth_required: true }, status: "blocked_auth", attempts: 0,
        last_error: input.reason.slice(0, 1000), discovered_at: now, updated_at: now, completed_at: now,
      }).returning().get()
    })
  }

  export function retryAuthenticationBlocked(limit = 100, sourceID?: string) {
    const now = Date.now()
    return Database.transaction((db) => {
      const rows = db.select().from(ResearchQueueTable).where(sourceID
        ? and(eq(ResearchQueueTable.status, "blocked_auth"), eq(ResearchQueueTable.source_id, sourceID))
        : eq(ResearchQueueTable.status, "blocked_auth"))
        .orderBy(asc(ResearchQueueTable.sequence)).limit(Math.max(1, Math.min(500, Math.floor(limit)))).all()
      for (const row of rows) db.update(ResearchQueueTable).set({
        status: "queued", attempts: 0, last_error: null, lease_owner: null, lease_until: null, completed_at: null, updated_at: now,
      }).where(and(eq(ResearchQueueTable.sequence, row.sequence), eq(ResearchQueueTable.status, "blocked_auth"))).run()
      return rows.length
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
