import { index, integer, sqliteTable, text } from "drizzle-orm/sqlite-core"
import { SessionTable, VulnerabilityTable } from "../session/session.sql"
import { Timestamps } from "../storage/schema.sql"

export type FindingValidationVerdict = "confirmed" | "false_positive" | "inconclusive"
export type FindingValidationStatus = "pass" | "fail" | "unknown" | "not_applicable"

export interface FindingValidationCheckRecord {
  number: number
  id: string
  question: string
  status: FindingValidationStatus
  reason: string | null
  evidence: string | null
}

export const FindingValidationTable = sqliteTable(
  "finding_validation",
  {
    id: text().primaryKey(),
    session_id: text()
      .notNull()
      .references(() => SessionTable.id, { onDelete: "cascade" }),
    vulnerability_id: text()
      .notNull()
      .references(() => VulnerabilityTable.id, { onDelete: "cascade" }),
    verdict: text().$type<FindingValidationVerdict>().notNull(),
    confidence: integer().notNull(),
    checks: text({ mode: "json" }).$type<FindingValidationCheckRecord[]>().notNull(),
    failed_check_ids: text({ mode: "json" }).$type<string[]>().notNull(),
    unknown_check_ids: text({ mode: "json" }).$type<string[]>().notNull(),
    summary: text().notNull(),
    next_step: text().notNull(),
    ...Timestamps,
  },
  (table) => [
    index("finding_validation_session_time_idx").on(table.session_id, table.time_created),
    index("finding_validation_finding_time_idx").on(table.vulnerability_id, table.time_created),
    index("finding_validation_verdict_idx").on(table.verdict),
  ],
)
