import { integer, sqliteTable, text } from "drizzle-orm/sqlite-core"

export type ResearchCyclePhase = "collecting" | "studying" | "complete" | "partial"
export type ResearchSourceCycleStatus = "pending" | "collecting" | "complete" | "partial" | "blocked"

export type ResearchCyclePass = {
  page_window: number
  pages: number
  candidates: number
  queued_new: number
  blocked_auth: number
  error_count: number
  errors: string[]
  recorded_at: number
}

export type ResearchSourceCycleState = {
  status: ResearchSourceCycleStatus
  passes: ResearchCyclePass[]
  pages_visited: number
  candidates_discovered: number
  queued_new: number
  blocked_auth: number
  error_count: number
  unresolved_auth: number
  unresolved_errors: number
  last_page_window: number
  last_pages: number
}

export const ResearchCycleTable = sqliteTable("research_cycle", {
  id: text().primaryKey(),
  cycle_id: text().notNull(),
  phase: text().notNull(),
  source_ids: text({ mode: "json" }).$type<string[]>().notNull().default([]),
  source_states: text({ mode: "json" }).$type<Record<string, ResearchSourceCycleState>>().notNull().default({}),
  started_at: integer().notNull(),
  updated_at: integer().notNull(),
  finished_at: integer(),
})
