import { and, eq } from "drizzle-orm"
import { Database } from "../storage/db"
import { ResearchCycleTable, type ResearchCyclePass, type ResearchCyclePhase, type ResearchSourceCycleState, type ResearchSourceCycleStatus } from "./cycle.sql"

const ACTIVE_ROW_ID = "active"

function emptySourceState(): ResearchSourceCycleState {
  return {
    status: "pending",
    passes: [],
    pages_visited: 0,
    candidates_discovered: 0,
    queued_new: 0,
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

export namespace ResearchCycle {
  export function current() {
    return Database.use((db) => db.select().from(ResearchCycleTable).where(eq(ResearchCycleTable.id, ACTIVE_ROW_ID)).get() ?? null)
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
      const rows = db.select({ id: ResearchCycleTable.id }).from(ResearchCycleTable)
        .where(eq(ResearchCycleTable.id, ACTIVE_ROW_ID)).all()
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
      if (current.phase !== "collecting") return { ok: false as const, reason: "collection_phase_already_closed" as const, cycle: current }
      if (!current.source_ids.includes(input.sourceID)) return { ok: false as const, reason: "source_not_selected" as const, cycle: current }

      const previous = current.source_states[input.sourceID] ?? emptySourceState()
      if (window !== previous.next_page_window) {
        return { ok: false as const, reason: "page_window_out_of_sequence" as const, expected_page_window: previous.next_page_window }
      }
      if (terminal(previous.status)) {
        return { ok: false as const, reason: "source_already_terminal" as const, source_state: previous }
      }
      const pass: ResearchCyclePass = {
        page_window: window,
        pages,
        candidates: safeCount(input.candidates),
        queued_new: safeCount(input.queuedNew),
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
        passes: [...previous.passes, pass],
        pages_visited: previous.pages_visited + pages,
        candidates_discovered: previous.candidates_discovered + pass.candidates,
        queued_new: previous.queued_new + pass.queued_new,
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
        source_state: nextSource,
        waiting_sources: updated.source_ids.filter((id) => !terminal(updated.source_states[id]?.status)),
        cycle: updated,
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
