import { index, integer, sqliteTable, text } from "drizzle-orm/sqlite-core"
import { SessionTable, VulnerabilityTable } from "../session/session.sql"
import { Timestamps } from "../storage/schema.sql"

export type FindingValidationVerdict = "confirmed" | "false_positive" | "inconclusive"
export type FindingValidationStatus = "pass" | "fail" | "unknown" | "not_applicable"

export type FindingValidationAttemptStrategy =
  | "baseline_control"
  | "identity_role"
  | "object_identifier"
  | "http_method"
  | "content_type"
  | "session_state"
  | "permission_boundary"
  | "endpoint_variant"
  | "business_logic"
  | "cache_waf_environment"
  | "timing_race"
  | "negative_control"
  | "response_comparison"
  | "state_change"
  | "other"

export interface FindingValidationAttemptRecord {
  strategy: FindingValidationAttemptStrategy
  checkID: string
  variation: string
  hypothesis: string
  outcome: "supports" | "contradicts" | "inconclusive"
  evidence: string
  /** Only true when this test ran with valid scope, identity, session, and other preconditions. */
  validConditions: boolean
}

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
    attempts: text({ mode: "json" }).$type<FindingValidationAttemptRecord[]>().notNull(),
    attempt_count: integer().notNull(),
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
