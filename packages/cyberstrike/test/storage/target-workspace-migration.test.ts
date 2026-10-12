import { expect, test } from "bun:test"
import { Database as BunDatabase } from "bun:sqlite"
import { readFileSync } from "node:fs"
import { Database } from "../../src/storage/db"

const OWNER_MIGRATION = "20261012110000_target-workspace-owner-key"

function ownerMigrationSQL() {
  return readFileSync(
    new URL("../../migration/20261012110000_target-workspace-owner-key/migration.sql", import.meta.url),
    "utf-8",
  )
}

test("owner migration preserves index/backfill steps when owner_key already exists", () => {
  const sqlite = new BunDatabase(":memory:")
  try {
    // Reproduce a database whose schema reconciliation added owner_key before
    // the dedicated migration entered the migration journal.
    sqlite.run(`CREATE TABLE target_workspace (
      id TEXT PRIMARY KEY NOT NULL,
      project_id TEXT NOT NULL,
      owner_key TEXT,
      target_key TEXT NOT NULL,
      target_url TEXT NOT NULL,
      hostname TEXT NOT NULL,
      slug TEXT NOT NULL,
      workspace_path TEXT NOT NULL,
      time_created INTEGER NOT NULL,
      time_updated INTEGER NOT NULL
    )`)
    sqlite.run("CREATE UNIQUE INDEX target_workspace_project_key_idx ON target_workspace(project_id, target_key)")
    sqlite.run("CREATE INDEX target_workspace_host_idx ON target_workspace(project_id, hostname)")
    sqlite.prepare("INSERT INTO target_workspace (id, project_id, owner_key, target_key, target_url, hostname, slug, workspace_path, time_created, time_updated) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)").run(
      "project-row", "project-1", null, "https://example.test", "https://example.test", "example.test", "example-test", "targets/example-test", 1, 1,
    )
    sqlite.prepare("INSERT INTO target_workspace (id, project_id, owner_key, target_key, target_url, hostname, slug, workspace_path, time_created, time_updated) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)").run(
      "global-row", "global", null, "https://legacy.test", "https://legacy.test", "legacy.test", "legacy-test", "targets/legacy-test", 2, 2,
    )

    const entry = { name: OWNER_MIGRATION, timestamp: Date.UTC(2026, 9, 12, 11), sql: ownerMigrationSQL() }
    const prepared = Database.prepareMigrations(sqlite, [entry])
    expect(prepared[0]?.sql).not.toContain("ALTER TABLE target_workspace ADD COLUMN owner_key")
    expect(prepared[0]?.sql).toContain("SELECT 1;")
    expect(prepared[0]?.sql).toContain("UPDATE target_workspace")
    expect(prepared[0]?.sql).toContain("target_workspace_owner_target_key_idx")

    // Execute the real migration in the same statement-breakpoint units consumed by Drizzle.
    for (const statement of prepared[0]!.sql.split("--> statement-breakpoint").map((part) => part.trim()).filter(Boolean)) {
      sqlite.run(statement)
    }

    const rows = sqlite.prepare("SELECT id, owner_key FROM target_workspace ORDER BY id").all() as {
      id: string
      owner_key: string | null
    }[]
    expect(rows.find((row) => row.id === "project-row")?.owner_key).toBe("project:project-1")
    expect(rows.find((row) => row.id === "global-row")?.owner_key).toBeNull()

    // Normal post-migration reconciliation then isolates the legacy shared row.
    Database.reconcile(sqlite)
    const reconciled = sqlite.prepare("SELECT id, owner_key FROM target_workspace ORDER BY id").all() as {
      id: string
      owner_key: string | null
    }[]
    expect(reconciled.find((row) => row.id === "global-row")?.owner_key).toBe("legacy:global-row")
    const indexes = (sqlite.prepare("PRAGMA index_list(target_workspace)").all() as { name: string }[]).map((row) => row.name)
    expect(indexes).not.toContain("target_workspace_project_key_idx")
    expect(indexes).not.toContain("target_workspace_host_idx")
    expect(indexes).toContain("target_workspace_owner_target_key_idx")
    expect(indexes).toContain("target_workspace_owner_host_idx")
  } finally {
    sqlite.close()
  }
})

test("a fresh database keeps the owner migration ADD COLUMN statement", () => {
  const sqlite = new BunDatabase(":memory:")
  try {
    const entry = { name: OWNER_MIGRATION, timestamp: Date.UTC(2026, 9, 12, 11), sql: ownerMigrationSQL() }
    const prepared = Database.prepareMigrations(sqlite, [entry])
    expect(prepared[0]?.sql).toContain("ALTER TABLE target_workspace ADD COLUMN owner_key")
  } finally {
    sqlite.close()
  }
})
