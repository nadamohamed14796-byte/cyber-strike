import { and, eq } from "drizzle-orm"
import { Database } from "../storage/db"
import { ResearchCycleDuplicateTable, ResearchCycleTable, type ResearchCyclePass, type ResearchCyclePhase, type ResearchSourceCycleState, type ResearchSourceCycleStatus } from "./cycle.sql"

const ACTIVE_ROW_ID = "active"

function emptySourceState(): ResearchSourceCycleState {
  return {
    status: "pending",
    passes: [],
    pages_visited: 0,
    candidates_discovered: 0,
    queued_new: 0,
    document_types: {},
    duplicate_urls_skipped: 0,
    blocked_auth: 0,
    error_count: 0,
    unresolved_auth: 0,
    unresolved_errors: 0,
    last_page_window: 0,
    last_pages: 0,
    next_page_window: 20,
  }
}

function terminal(status: ResearchSourceCycleStatus | undefined) {
  return status === "complete" || status === "partial" || status === "blocked"
}

function safeCount(value: number) {
  return Number.isFinite(value) ? Math.max(0, Math.floor(value)) : 0
}

function cleanError(value: string) {
  return value.replace(/(authorization|proxy-authorization|cookie|set-cookie|password|passwd|token|secret|api[_-]?key)\s*[:=]\s*[^\s,;]+/gi, "$1: [REDACTED]").slice(0, 1000)
}


function summarizeSourceState(state: ResearchSourceCycleState | undefined) {
  if (!state) return null
  const { passes, ...totals } = state
  const lastPass = passes?.at(-1)
  return {
    ...totals,
    passes_count: passes?.length ?? 0,
    last_pass: lastPass
      ? { ...lastPass, errors: (lastPass.errors ?? []).slice(0, 3).map((value) => value.slice(0, 240)) }
      : null,
  }
}

function summarizeCycleRow(row: typeof ResearchCycleTable.$inferSelect) {
  return {
    cycle_id: row.cycle_id,
    phase: row.phase,
    source_ids: row.source_ids,
    source_states: Object.fromEntries(
      row.source_ids.map((id) => [id, summarizeSourceState(row.source_states[id])]),
    ),
    started_at: row.started_at,
    updated_at: row.updated_at,
    finished_at: row.finished_at,
  }
}

export namespace ResearchCycle {
  export function current() {
    return Database.use((db) => db.select().from(ResearchCycleTable).where(eq(ResearchCycleTable.id, ACTIVE_ROW_ID)).get() ?? null)
  }

  /** Compact read surface; the full per-pass ledger remains durable in SQLite. */
  export function summary() {
    const row = current()
    return row ? summarizeCycleRow(row) : null
  }

  /** Start a durable, explicit collect-then-study cycle across the selected sources. */
  export function begin(sourceIDs: string[]) {
    const sources = [...new Set(sourceIDs.map((id) => id.trim()).filter(Boolean))]
    if (!sources.length) throw new Error("a research cycle requires at least one configured source")
    const now = Date.now()
    const cycleID = crypto.randomUUID()
    const states = Object.fromEntries(sources.map((id) => [id, emptySourceState()]))
    return Database.transaction((db) => {
      const existing = db.select().from(ResearchCycleTable).where(eq(ResearchCycleTable.id, ACTIVE_ROW_ID)).get()
      if (existing && (existing.phase === "collecting" || existing.phase === "studying")) {
        const sameSources = existing.source_ids.length === sources.length && existing.source_ids.every((id, index) => id === sources[index])
        if (!sameSources) throw new Error("An active research cycle exists with a different source set; resume it or explicitly reset it before starting another cycle.")
        return existing
      }
      db.delete(ResearchCycleDuplicateTable).run()
      db.delete(ResearchCycleTable).where(eq(ResearchCycleTable.id, ACTIVE_ROW_ID)).run()
      return db.insert(ResearchCycleTable).values({
        id: ACTIVE_ROW_ID,
        cycle_id: cycleID,
        phase: "collecting",
        source_ids: sources,
        source_states: states,
        started_at: now,
        updated_at: now,
        finished_at: null,
      }).returning().get()
    })
  }

  export function clear() {
    return Database.transaction((db) => {
      const current = db.select().from(ResearchCycleTable).where(eq(ResearchCycleTable.id, ACTIVE_ROW_ID)).get()
      const rows = db.select({ id: ResearchCycleTable.id }).from(ResearchCycleTable)
        .where(eq(ResearchCycleTable.id, ACTIVE_ROW_ID)).all()
      if (current) {
        db.delete(ResearchCycleDuplicateTable).where(eq(ResearchCycleDuplicateTable.cycle_id, current.cycle_id)).run()
      }
      db.delete(ResearchCycleTable).where(eq(ResearchCycleTable.id, ACTIVE_ROW_ID)).run()
      return rows.length
    })
  }

  /** Save every discovery pass before returning to the agent. */
  export function recordDiscovery(input: {
    cycleID: string
    sourceID: string
    pageWindow: number
    pages: number
    candidates: number
    queuedNew: number
    documentTypes?: Record<string, number>
    duplicateURLs?: string[]
    blockedAuth: number
    errorCount: number
    errors: string[]
    unresolvedAuth?: number
    unresolvedErrors?: number
  }) {
    const now = Date.now()
    const window = Math.max(1, safeCount(input.pageWindow))
    const pages = safeCount(input.pages)
    return Database.transaction((db) => {
      const current = db.select().from(ResearchCycleTable).where(eq(ResearchCycleTable.id, ACTIVE_ROW_ID)).get()
      if (!current || current.cycle_id !== input.cycleID) return { ok: false as const, reason: "cycle_missing_or_stale" as const }
      if (current.phase !== "collecting") return { ok: false as const, reason: "collection_phase_already_closed" as const, cycle: summarizeCycleRow(current) }
      if (!current.source_ids.includes(input.sourceID)) return { ok: false as const, reason: "source_not_selected" as const, cycle: summarizeCycleRow(current) }

      const previous = current.source_states[input.sourceID] ?? emptySourceState()
      if (window !== previous.next_page_window) {
        return { ok: false as const, reason: "page_window_out_of_sequence" as const, expected_page_window: previous.next_page_window }
      }
      if (terminal(previous.status)) {
        return { ok: false as const, reason: "source_already_terminal" as const, source_state: summarizeSourceState(previous) }
      }
      const documentTypes = Object.fromEntries(
        Object.entries(input.documentTypes ?? {})
          .filter(([name]) => /^[a-z-]{1,32}$/.test(name))
          .map(([name, count]) => [name, safeCount(count)]),
      )
      const aggregateDocumentTypes = { ...(previous.document_types ?? {}) }
      for (const [name, count] of Object.entries(documentTypes)) {
        aggregateDocumentTypes[name] = safeCount(aggregateDocumentTypes[name] ?? 0) + count
      }
      let newlyUniqueDuplicates = 0
      for (const candidate of new Set(input.duplicateURLs ?? [])) {
        if (typeof candidate !== "string" || candidate.length > 4096) continue
        let parsed: URL
        try {
          parsed = new URL(candidate)
        } catch {
          continue
        }
        if (parsed.protocol !== "https:" || parsed.username || parsed.password) continue
        parsed.hash = ""
        const inserted = db.insert(ResearchCycleDuplicateTable).values({
          id: crypto.randomUUID(),
          cycle_id: input.cycleID,
          source_id: input.sourceID,
          source_url: parsed.toString(),
          recorded_at: now,
        }).onConflictDoNothing().returning({ id: ResearchCycleDuplicateTable.id }).get()
        if (inserted) newlyUniqueDuplicates++
      }

      const pass: ResearchCyclePass = {
        page_window: window,
        pages,
        candidates: safeCount(input.candidates),
        queued_new: safeCount(input.queuedNew),
        document_types: documentTypes,
        duplicate_urls_skipped: newlyUniqueDuplicates,
        blocked_auth: safeCount(input.blockedAuth),
        error_count: safeCount(input.errorCount),
        errors: input.errors.slice(0, 3).map(cleanError),
        recorded_at: now,
      }
      const unresolvedAuth = safeCount(input.unresolvedAuth ?? input.blockedAuth)
      const unresolvedErrors = safeCount(input.unresolvedErrors ?? input.errorCount)
      let status: ResearchSourceCycleStatus = "collecting"
      const nextPageWindow = window * 2
      if (pages < window) {
        if (unresolvedAuth > 0) status = "blocked"
        else if (pass.error_count > 0 || unresolvedErrors > 0) status = "partial"
        else status = "complete"
      } else if (!Number.isSafeInteger(nextPageWindow)) {
        status = "partial"
      }
      const nextSource: ResearchSourceCycleState = {
        status,
        passes: [...(previous.passes ?? []), pass],
        pages_visited: previous.pages_visited + pages,
        candidates_discovered: previous.candidates_discovered + pass.candidates,
        queued_new: previous.queued_new + pass.queued_new,
        document_types: aggregateDocumentTypes,
        duplicate_urls_skipped: safeCount(previous.duplicate_urls_skipped ?? 0) + pass.duplicate_urls_skipped,
        blocked_auth: previous.blocked_auth + pass.blocked_auth,
        error_count: previous.error_count + pass.error_count,
        unresolved_auth: unresolvedAuth,
        unresolved_errors: unresolvedErrors,
        last_page_window: window,
        last_pages: pages,
        next_page_window: status === "collecting" ? nextPageWindow : previous.next_page_window,
      }
      const sourceStates = { ...current.source_states, [input.sourceID]: nextSource }
      const allTerminal = current.source_ids.every((id) => terminal(sourceStates[id]?.status))
      const phase: ResearchCyclePhase = allTerminal ? "studying" : "collecting"
      const updated = db.update(ResearchCycleTable).set({ source_states: sourceStates, phase, updated_at: now }).where(
        and(eq(ResearchCycleTable.id, ACTIVE_ROW_ID), eq(ResearchCycleTable.cycle_id, input.cycleID)),
      ).returning().get()
      if (!updated) return { ok: false as const, reason: "cycle_changed_during_update" as const }
      return {
        ok: true as const,
        phase: updated.phase as ResearchCyclePhase,
        source_state: summarizeSourceState(nextSource),
        waiting_sources: updated.source_ids.filter((id) => !terminal(updated.source_states[id]?.status)),
        cycle: {
          cycle_id: updated.cycle_id,
          phase: updated.phase,
          source_count: updated.source_ids.length,
          waiting_source_count: updated.source_ids.filter((id) => !terminal(updated.source_states[id]?.status)).length,
        },
      }
    })
  }

  /** Finalize only after collection is closed and the queue has been checked. */
  export function finish(cycleID: string, phase: "complete" | "partial") {
    const now = Date.now()
    return Database.transaction((db) => {
      const current = db.select().from(ResearchCycleTable).where(eq(ResearchCycleTable.id, ACTIVE_ROW_ID)).get()
      if (!current || current.cycle_id !== cycleID || current.phase !== "studying") return null
      return db.update(ResearchCycleTable).set({ phase, finished_at: now, updated_at: now }).where(and(
        eq(ResearchCycleTable.id, ACTIVE_ROW_ID),
        eq(ResearchCycleTable.cycle_id, cycleID),
        eq(ResearchCycleTable.phase, "studying"),
      )).returning().get() ?? null
    })
  }
}
