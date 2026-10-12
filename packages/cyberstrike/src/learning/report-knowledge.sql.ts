import { integer, sqliteTable, text, uniqueIndex, index } from "drizzle-orm/sqlite-core"
import { SessionTable, VulnerabilityTable } from "../session/session.sql"
import { Timestamps } from "../storage/schema.sql"

export const ReportKnowledgeTable = sqliteTable(
  "report_knowledge",
  {
    id: text().primaryKey(),
    session_id: text().references(() => SessionTable.id, { onDelete: "cascade" }),
    source_vulnerability_id: text().references(() => VulnerabilityTable.id, { onDelete: "set null" }),
    fingerprint: text().notNull(),
    title: text().notNull(),
    vulnerability_class: text(),
    cwe_id: text(),
    severity: text().notNull(),
    status: text().notNull().default("observed"),
    source_kind: text().notNull().default("finding"),
    source_url: text(),
    program: text(),
    target_pattern: text(),
    endpoint: text(),
    attack_vector: text(),
    impact: text(),
    reproduction: text(),
    poc: text(),
    outcome: text(),
    lesson: text(),
    tags: text({ mode: "json" }).$type<string[]>(),
    metadata: text({ mode: "json" }).$type<Record<string, unknown>>(),
    confidence: integer().notNull().default(50),
    times_seen: integer().notNull().default(1),
    times_useful: integer().notNull().default(0),
    times_rejected: integer().notNull().default(0),
    ...Timestamps,
  },
  (table) => [
    uniqueIndex("report_knowledge_fingerprint_idx").on(table.fingerprint),
    index("report_knowledge_class_idx").on(table.vulnerability_class),
    index("report_knowledge_cwe_idx").on(table.cwe_id),
    index("report_knowledge_status_idx").on(table.status),
    index("report_knowledge_target_idx").on(table.target_pattern),
    index("report_knowledge_session_idx").on(table.session_id),
  ],
)

export const ReportKnowledgeEventTable = sqliteTable(
  "report_knowledge_event",
  {
    id: text().primaryKey(),
    report_id: text()
      .notNull()
      .references(() => ReportKnowledgeTable.id, { onDelete: "cascade" }),
    session_id: text().references(() => SessionTable.id, { onDelete: "cascade" }),
    hook: text().notNull(),
    outcome: text().notNull(),
    signal: text(),
    evidence: text(),
    metadata: text({ mode: "json" }).$type<Record<string, unknown>>(),
    ...Timestamps,
  },
  (table) => [
    index("report_knowledge_event_report_idx").on(table.report_id),
    index("report_knowledge_event_session_idx").on(table.session_id),
    index("report_knowledge_event_signal_idx").on(table.signal),
  ],
)
