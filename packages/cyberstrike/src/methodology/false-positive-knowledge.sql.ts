import { index, integer, sqliteTable, text, uniqueIndex } from "drizzle-orm/sqlite-core"
import { Timestamps } from "../storage/schema.sql"

/**
 * Cross-session false-positive memory. Intentionally has no session/finding foreign keys:
 * lessons must survive session deletion and remain useful across targets. Store only
 * normalized patterns and redacted, concise evidence summaries, never raw requests/tokens.
 */
export const FalsePositiveKnowledgeTable = sqliteTable(
  "false_positive_knowledge",
  {
    id: text().primaryKey(),
    fingerprint: text().notNull(),
    vulnerability_class: text().notNull(),
    title_pattern: text().notNull(),
    endpoint_pattern: text(),
    failed_check_ids: text({ mode: "json" }).$type<string[]>().notNull(),
    benign_explanation: text().notNull(),
    evidence_summary: text().notNull(),
    source_validation_id: text().notNull(),
    source_finding_id: text(),
    confidence: integer().notNull().default(50),
    occurrences: integer().notNull().default(1),
    last_verdict: text().notNull().default("false_positive"),
    ...Timestamps,
  },
  (table) => [
    uniqueIndex("false_positive_knowledge_fingerprint_idx").on(table.fingerprint),
    index("false_positive_knowledge_class_idx").on(table.vulnerability_class),
    index("false_positive_knowledge_title_idx").on(table.title_pattern),
    index("false_positive_knowledge_seen_idx").on(table.time_updated),
  ],
)
