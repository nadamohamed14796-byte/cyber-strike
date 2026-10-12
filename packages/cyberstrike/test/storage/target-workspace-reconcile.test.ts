import { expect, test } from "bun:test"
import { Database as BunDatabase } from "bun:sqlite"
import { Database } from "../../src/storage/db"

test("reconciles legacy target workspace ownership and owner-scoped indexes", () => {
  const sqlite = new BunDatabase(":memory:")
  try {
    // Schema from before owner_key was introduced.
    sqlite.run(`CREATE TABLE target_workspace (
      id TEXT PRIMARY KEY NOT NULL,
      project_id TEXT NOT NULL,
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
    sqlite.prepare(`INSERT INTO target_workspace
      (id, project_id, target_key, target_url, hostname, slug, workspace_path, time_created, time_updated)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
        "project-row",
        "project-1",
        "https://example.test/account",
        "https://example.test/account",
        "example.test",
        "example-test",
        "targets/example-test",
        1,
        1,
      )
    sqlite.prepare(`INSERT INTO target_workspace
      (id, project_id, target_key, target_url, hostname, slug, workspace_path, time_created, time_updated)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
        "global-row",
        "global",
        "https://legacy.test",
        "https://legacy.test",
        "legacy.test",
        "legacy-test",
        "targets/legacy-test",
        2,
        2,
      )

    Database.reconcile(sqlite)

    const rows = sqlite.prepare("SELECT id, project_id, owner_key FROM target_workspace ORDER BY id").all() as {
      id: string
      project_id: string
      owner_key: string
    }[]
    expect(rows.find((row) => row.id === "project-row")?.owner_key).toBe("project:project-1")
    expect(rows.find((row) => row.id === "global-row")?.owner_key).toBe("legacy:global-row")

    const indexNames = (sqlite.prepare("PRAGMA index_list(target_workspace)").all() as { name: string }[]).map((row) => row.name)
    expect(indexNames).not.toContain("target_workspace_project_key_idx")
    expect(indexNames).not.toContain("target_workspace_host_idx")
    expect(indexNames).toContain("target_workspace_owner_target_key_idx")
    expect(indexNames).toContain("target_workspace_owner_host_idx")

    // The same target can exist in separate project owners after the stale project_id
    // unique index is replaced, while duplicate keys within one owner remain blocked.
    sqlite.prepare(`INSERT INTO target_workspace
      (id, project_id, owner_key, target_key, target_url, hostname, slug, workspace_path, time_created, time_updated)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
        "second-project-row",
        "project-2",
        "project:project-2",
        "https://example.test/account",
        "https://example.test/account",
        "example.test",
        "example-test",
        "targets/example-test",
        3,
        3,
      )
    expect(() => sqlite.prepare(`INSERT INTO target_workspace
      (id, project_id, owner_key, target_key, target_url, hostname, slug, workspace_path, time_created, time_updated)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
        "duplicate-owner-row",
        "project-1",
        "project:project-1",
        "https://example.test/account",
        "https://example.test/account",
        "example.test",
        "example-test",
        "targets/example-test",
        4,
        4,
      )).toThrow()
  } finally {
    sqlite.close()
  }
})
