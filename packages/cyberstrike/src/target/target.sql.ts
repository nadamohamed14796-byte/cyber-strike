import { sqliteTable, text, integer, index, uniqueIndex } from "drizzle-orm/sqlite-core"
import { ProjectTable } from "../project/project.sql"
import { Timestamps } from "../storage/schema.sql"

/**
 * A target workspace is isolated to one CyberStrike project and one normalized target URL.
 * Target metadata is stored in SQLite; workspace_path is project-relative so workspaces
 * remain portable if the project directory moves.
 */
export const TargetWorkspaceTable = sqliteTable(
  "target_workspace",
  {
    id: text().primaryKey(),
    project_id: text()
      .notNull()
      .references(() => ProjectTable.id, { onDelete: "cascade" }),
    target_key: text().notNull(),
    target_url: text().notNull(),
    hostname: text().notNull(),
    slug: text().notNull(),
    workspace_path: text().notNull(),
    ...Timestamps,
  },
  (table) => [
    uniqueIndex("target_workspace_project_key_idx").on(table.project_id, table.target_key),
    index("target_workspace_host_idx").on(table.project_id, table.hostname),
  ],
)

/**
 * Durable, deduplicated notes attached to one target. notes.md is the human-readable
 * companion; this table keeps note provenance and status queryable for future learning.
 */
export const TargetNoteTable = sqliteTable(
  "target_note",
  {
    id: text().primaryKey(),
    target_id: text()
      .notNull()
      .references(() => TargetWorkspaceTable.id, { onDelete: "cascade" }),
    kind: text().notNull().default("manual"),
    title: text(),
    content: text().notNull(),
    source: text().notNull().default("manual"),
    source_url: text(),
    content_hash: text().notNull(),
    status: text().notNull().default("observed"),
    tags: text({ mode: "json" }).$type<string[]>(),
    ...Timestamps,
  },
  (table) => [
    uniqueIndex("target_note_dedup_idx").on(table.target_id, table.content_hash),
    index("target_note_target_time_idx").on(table.target_id, table.time_created),
  ],
)
