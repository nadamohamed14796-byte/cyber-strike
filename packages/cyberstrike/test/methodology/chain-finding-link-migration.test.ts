import { expect, test } from "bun:test"
import { Database as BunDatabase } from "bun:sqlite"
import { readFileSync } from "node:fs"

function migrationSQL() {
  return readFileSync(
    new URL("../../migration/20261028211500_chain-finding-links/migration.sql", import.meta.url),
    "utf-8",
  )
}

test("chain finding link migration enforces foreign keys and rejects duplicate directed edges", () => {
  const sqlite = new BunDatabase(":memory:")
  try {
    sqlite.run("PRAGMA foreign_keys = ON")
    sqlite.exec(`
      CREATE TABLE session (id TEXT PRIMARY KEY);
      CREATE TABLE chain_candidate (id TEXT PRIMARY KEY, session_id TEXT NOT NULL REFERENCES session(id) ON DELETE CASCADE);
      CREATE TABLE vulnerability (id TEXT PRIMARY KEY, session_id TEXT NOT NULL REFERENCES session(id) ON DELETE CASCADE);
    `)

    const sql = migrationSQL()
    expect(sql).toContain("REFERENCES chain_candidate(id) ON DELETE CASCADE")
    expect(sql).toContain("REFERENCES vulnerability(id) ON DELETE CASCADE")
    for (const statement of sql.split("--> statement-breakpoint").map((part) => part.trim()).filter(Boolean)) {
      sqlite.run(statement)
    }

    sqlite.prepare("INSERT INTO session (id) VALUES (?)").run("ses-test")
    sqlite.prepare("INSERT INTO session (id) VALUES (?)").run("ses-other")
    sqlite.prepare("INSERT INTO chain_candidate (id, session_id) VALUES (?, ?)").run("chn-test", "ses-test")
    sqlite.prepare("INSERT INTO chain_candidate (id, session_id) VALUES (?, ?)").run("chn-other", "ses-other")
    sqlite.prepare("INSERT INTO vulnerability (id, session_id) VALUES (?, ?)").run("vul-a", "ses-test")
    sqlite.prepare("INSERT INTO vulnerability (id, session_id) VALUES (?, ?)").run("vul-b", "ses-test")
    sqlite.prepare("INSERT INTO vulnerability (id, session_id) VALUES (?, ?)").run("vul-c", "ses-other")

    const insert = sqlite.prepare(
      "INSERT INTO chain_finding_link (id, session_id, chain_candidate_id, source_vulnerability_id, target_vulnerability_id, relation, time_created, time_updated) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    insert.run("cfl-1", "ses-test", "chn-test", "vul-a", "vul-b", "enables", 1, 1)
    expect(() =>
      insert.run("cfl-duplicate", "ses-test", "chn-test", "vul-a", "vul-b", "enables", 1, 1),
    ).toThrow()
    expect(
      (sqlite.prepare("SELECT count(*) AS count FROM chain_finding_link WHERE chain_candidate_id = ?").get("chn-test") as { count: number }).count,
    ).toBe(1)

    expect(() =>
      insert.run("cfl-2", "ses-test", "chn-missing", "vul-a", "vul-b", "enables", 2, 2),
    ).toThrow()
    expect(() =>
      insert.run("cfl-3", "ses-test", "chn-test", "vul-missing", "vul-b", "enables", 3, 3),
    ).toThrow()
    expect(() =>
      insert.run("cfl-cross-vulnerability-session", "ses-test", "chn-test", "vul-a", "vul-c", "enables", 3, 3),
    ).toThrow()
    expect(() =>
      insert.run("cfl-cross-chain-session", "ses-test", "chn-other", "vul-a", "vul-b", "enables", 3, 3),
    ).toThrow()
    expect(() =>
      insert.run("cfl-4", "ses-test", "chn-test", "vul-a", "vul-a", "depends_on", 4, 4),
    ).toThrow()

    sqlite.prepare("DELETE FROM vulnerability WHERE id = ?").run("vul-a")
    expect(
      (sqlite.prepare("SELECT count(*) AS count FROM chain_finding_link").get() as { count: number }).count,
    ).toBe(0)
  } finally {
    sqlite.close()
  }
})
