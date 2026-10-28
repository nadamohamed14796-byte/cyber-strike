import { index, integer, sqliteTable, text } from "drizzle-orm/sqlite-core"
import { SessionTable, VulnerabilityTable } from "../session/session.sql"
import { Timestamps } from "../storage/schema.sql"
import { ChainCandidateTable } from "./methodology.sql"

export type ChainValidationOutcome = "confirmed" | "disproven" | "inconclusive"

/**
 * Durable evidence for the combined-impact decision of a chain hypothesis.
 * A confirmed chain must reference a combined vulnerability that already passed
 * the ordinary finding-validation and triage lifecycle.
 */
export const ChainValidationTable = sqliteTable(
  "chain_validation",
  {
    id: text().primaryKey(),
    session_id: text()
      .notNull()
      .references(() => SessionTable.id, { onDelete: "cascade" }),
    chain_candidate_id: text()
      .notNull()
      .references(() => ChainCandidateTable.id, { onDelete: "cascade" }),
    outcome: text().$type<ChainValidationOutcome>().notNull(),
    combined_vulnerability_id: text().references(() => VulnerabilityTable.id, { onDelete: "set null" }),
    evidence: text().notNull(),
    validated_by: text().notNull(),
    ...Timestamps,
  },
  (table) => [
    index("chain_validation_session_idx").on(table.session_id),
    index("chain_validation_chain_time_idx").on(table.chain_candidate_id, table.time_created),
    index("chain_validation_finding_idx").on(table.combined_vulnerability_id),
  ],
)
