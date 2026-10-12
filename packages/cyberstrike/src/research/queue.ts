import { and, asc, eq, inArray, isNull, lt, or } from "drizzle-orm"
import { Database } from "../storage/db"
import { ResearchQueueTable } from "./queue.sql"

export type ResearchQueueStatus = "discovered" | "queued" | "studying" | "learned" | "retry" | "rejected"

const LEASE_MS = 5 * 60_000

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
      if (existing) return { id: publicID(existing.sequence), sequence: existing.sequence, created: false }

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

  export function claimNext(workerID: string) {
    const now = Date.now()
    return Database.transaction((db) => {
      const row = db
        .select()
        .from(ResearchQueueTable)
        .where(
          or(
            inArray(ResearchQueueTable.status, ["queued", "retry"]),
            and(eq(ResearchQueueTable.status, "studying"), or(isNull(ResearchQueueTable.lease_until), lt(ResearchQueueTable.lease_until, now))),
          ),
        )
        .orderBy(asc(ResearchQueueTable.sequence))
        .limit(1)
        .get()
      if (!row) return null

      const claimed = db
        .update(ResearchQueueTable)
        .set({
          status: "studying",
          attempts: row.attempts + 1,
          lease_owner: workerID,
          lease_until: now + LEASE_MS,
          claimed_at: now,
          updated_at: now,
          last_error: null,
        })
        .where(
          and(
            eq(ResearchQueueTable.sequence, row.sequence),
            or(
              inArray(ResearchQueueTable.status, ["queued", "retry"]),
              and(eq(ResearchQueueTable.status, "studying"), or(isNull(ResearchQueueTable.lease_until), lt(ResearchQueueTable.lease_until, now))),
            ),
          ),
        )
        .returning()
        .get()
      return claimed ? { ...claimed, public_id: publicID(claimed.sequence) } : null
    })
  }

  export function complete(
    sequence: number,
    workerID: string,
    outcome: "learned" | "retry" | "rejected",
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
          completed_at: outcome === "learned" || outcome === "rejected" ? now : null,
          updated_at: now,
        })
        .where(
          and(
            eq(ResearchQueueTable.sequence, sequence),
            eq(ResearchQueueTable.status, "studying"),
            eq(ResearchQueueTable.lease_owner, workerID),
          ),
        )
        .returning()
        .get(),
    )
  }

  export function stats() {
    return Database.use((db) => {
      const rows = db.select().from(ResearchQueueTable).orderBy(asc(ResearchQueueTable.sequence)).all()
      const counts: Record<string, number> = {
        total: rows.length,
        discovered: 0,
        queued: 0,
        studying: 0,
        learned: 0,
        retry: 0,
        rejected: 0,
      }
      for (const row of rows) counts[row.status] = (counts[row.status] ?? 0) + 1
      return counts
    })
  }

  export function pending(limit = 50) {
    return Database.use((db) =>
      db
        .select()
        .from(ResearchQueueTable)
        .where(inArray(ResearchQueueTable.status, ["queued", "retry", "studying"]))
        .orderBy(asc(ResearchQueueTable.sequence))
        .limit(Math.max(1, Math.min(500, Math.floor(limit))))
        .all()
        .map((row) => ({ ...row, public_id: publicID(row.sequence) })),
    )
  }
}
