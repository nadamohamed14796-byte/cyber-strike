import { index, integer, sqliteTable, text, uniqueIndex } from "drizzle-orm/sqlite-core"

export const ResearchQueueTable = sqliteTable(
  "research_queue",
  {
    sequence: integer().primaryKey({ autoIncrement: true }),
    source_id: text().notNull(),
    source_url: text().notNull(),
    title: text(),
    payload: text({ mode: "json" }).$type<Record<string, unknown>>().notNull().default({}),
    status: text().notNull().default("queued"),
    attempts: integer().notNull().default(0),
    last_error: text(),
    discovered_at: integer().notNull(),
    updated_at: integer().notNull(),
    claimed_at: integer(),
    completed_at: integer(),
    lease_owner: text(),
    lease_until: integer(),
  },
  (table) => [
    uniqueIndex("research_queue_source_url_idx").on(table.source_id, table.source_url),
    index("research_queue_status_idx").on(table.status),
    index("research_queue_lease_idx").on(table.lease_until),
    index("research_queue_sequence_idx").on(table.sequence),
  ],
)
