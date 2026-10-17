import { sqliteTable, text, integer, index, uniqueIndex, type AnySQLiteColumn } from "drizzle-orm/sqlite-core"
import { ProjectTable } from "../project/project.sql"
import { Timestamps } from "../storage/schema.sql"

/** Child assets have independent workspaces nested under their authorized parent. */
export type TargetAssetType = "target" | "subdomain" | "application" | "api" | "host"

/**
 * A target workspace is isolated to one CyberStrike project and one normalized target URL.
 * Parent/child relationships group discovered assets without merging their identities.
 * workspace_path is project-relative so workspaces remain portable if the project moves.
 */
export const TargetWorkspaceTable = sqliteTable(
  "target_workspace",
  {
    id: text().primaryKey(),
    project_id: text()
      .notNull()
      .references(() => ProjectTable.id, { onDelete: "cascade" }),
    // ProjectTable shares "global" for non-Git directories; this key isolates them.
    owner_key: text().notNull().default("legacy:unscoped"),
    target_key: text().notNull(),
    target_url: text().notNull(),
    hostname: text().notNull(),
    slug: text().notNull(),
    parent_target_id: text().references((): AnySQLiteColumn => TargetWorkspaceTable.id, { onDelete: "set null" }),
    asset_type: text().notNull().default("target").$type<TargetAssetType>(),
    workspace_path: text().notNull(),
    ...Timestamps,
  },
  (table) => [
    uniqueIndex("target_workspace_owner_target_key_idx").on(table.owner_key, table.target_key),
    index("target_workspace_owner_host_idx").on(table.owner_key, table.hostname),
    index("target_workspace_parent_idx").on(table.parent_target_id),
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

/**
 * Immutable snapshots of earlier versions of a living investigation note.
 * They are separate from the current note list, so edits preserve evidence without
 * creating duplicate visible notes or forcing a rigid note template.
 */
export const TargetNoteRevisionTable = sqliteTable(
  "target_note_revision",
  {
    id: text().primaryKey(),
    note_id: text()
      .notNull()
      .references(() => TargetNoteTable.id, { onDelete: "cascade" }),
    target_id: text()
      .notNull()
      .references(() => TargetWorkspaceTable.id, { onDelete: "cascade" }),
    kind: text().notNull(),
    title: text(),
    content: text().notNull(),
    source: text().notNull(),
    source_url: text(),
    content_hash: text().notNull(),
    status: text().notNull(),
    tags: text({ mode: "json" }).$type<string[]>().notNull(),
    time_created: integer().notNull(),
  },
  (table) => [
    uniqueIndex("target_note_revision_dedup_idx").on(table.note_id, table.content_hash),
    index("target_note_revision_note_time_idx").on(table.note_id, table.time_created),
    index("target_note_revision_target_time_idx").on(table.target_id, table.time_created),
  ],
)
