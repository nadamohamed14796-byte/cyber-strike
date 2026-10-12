import { Database as BunDatabase } from "bun:sqlite"
import { drizzle, type SQLiteBunDatabase } from "drizzle-orm/bun-sqlite"
import { migrate } from "drizzle-orm/bun-sqlite/migrator"
import { type SQLiteTransaction, getTableConfig, SQLiteTable } from "drizzle-orm/sqlite-core"
import { is } from "drizzle-orm"
export * from "drizzle-orm"
import { Context } from "../util/context"
import { lazy } from "../util/lazy"
import { Global } from "../global"
import { Log } from "../util/log"
import { NamedError } from "@cyberstrike-io/util/error"
import z from "zod"
import path from "path"
import { readFileSync, readdirSync } from "fs"
import * as schema from "./schema"

declare const CYBERSTRIKE_MIGRATIONS: { sql: string; timestamp: number; name: string }[] | undefined

export const NotFoundError = NamedError.create(
  "NotFoundError",
  z.object({
    message: z.string(),
  }),
)

const log = Log.create({ service: "db" })

export namespace Database {
  type Schema = typeof schema
  export type Transaction = SQLiteTransaction<"sync", void, Schema>

  type Client = SQLiteBunDatabase<Schema>

  type Journal = { sql: string; timestamp: number; name: string }[]

  function time(tag: string) {
    const match = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})/.exec(tag)
    if (!match) return 0
    return Date.UTC(
      Number(match[1]),
      Number(match[2]) - 1,
      Number(match[3]),
      Number(match[4]),
      Number(match[5]),
      Number(match[6]),
    )
  }

  function migrations(dir: string): Journal {
    const dirs = readdirSync(dir, { withFileTypes: true })
      .filter((entry) => entry.isDirectory())
      .map((entry) => entry.name)

    const sql = dirs
      .map((name) => {
        const file = path.join(dir, name, "migration.sql")
        if (!Bun.file(file).size) return
        const ts = time(name)
        if (ts === 0) {
          throw new Error(
            `Migration folder "${name}" has invalid name. ` +
              `Folder names must start with 14 digits (YYYYMMDDHHmmss). ` +
              `Example: 20260225000000_my-migration`,
          )
        }
        return {
          sql: readFileSync(file, "utf-8"),
          timestamp: ts,
          name,
        }
      })
      .filter(Boolean) as Journal

    return sql.sort((a, b) => a.timestamp - b.timestamp)
  }

  function tableColumns(sqlite: BunDatabase, table: string) {
    const rows = sqlite.prepare(`PRAGMA table_info(${table})`).all() as { name: string }[]
    return new Set(rows.map((r) => r.name))
  }

  function tableExists(sqlite: BunDatabase, table: string) {
    const row = sqlite.prepare(`SELECT count(*) as c FROM sqlite_master WHERE type='table' AND name=?`).get(table) as {
      c: number
    } | null
    return (row?.c ?? 0) > 0
  }

  /**
   * Prepare migration SQL for an existing database without losing migration steps.
   * Older releases could add target_workspace.owner_key via schema reconciliation
   * before the dedicated migration was journaled. In that case skip only the
   * duplicate ADD COLUMN statement; keep the migration's data backfill and indexes.
   */
  export function prepareMigrations(sqlite: BunDatabase, entries: { sql: string; timestamp: number; name: string }[]) {
    return entries.map((entry) => {
      let sql = entry.sql
        .replace(/CREATE TABLE `/g, "CREATE TABLE IF NOT EXISTS `")
        .replace(/CREATE INDEX `/g, "CREATE INDEX IF NOT EXISTS `")
        .replace(/CREATE UNIQUE INDEX `/g, "CREATE UNIQUE INDEX IF NOT EXISTS `")

      if (
        entry.name === "20261012110000_target-workspace-owner-key" &&
        tableExists(sqlite, "target_workspace") &&
        tableColumns(sqlite, "target_workspace").has("owner_key")
      ) {
        const addOwnerKey = /ALTER TABLE target_workspace ADD COLUMN owner_key TEXT NOT NULL DEFAULT 'legacy:unscoped';/i
        if (!addOwnerKey.test(sql)) {
          throw new Error("The target-workspace owner migration no longer matches its compatibility guard.")
        }
        sql = sql.replace(addOwnerKey, "SELECT 1;")
      }

      return { ...entry, sql }
    })
  }

  /** Reconcile an existing SQLite file with current schemas; exported for migration regression tests. */
  export function reconcile(sqlite: BunDatabase) {
    // Phase 1: Structural repairs (table reshaping that can't be handled by ADD COLUMN)
    // web_credential: old schema had type/value columns → new schema uses headers JSON
    if (tableExists(sqlite, "web_credential")) {
      const have = tableColumns(sqlite, "web_credential")
      if (have.has("type") && !have.has("headers")) {
        sqlite.run("DROP TABLE IF EXISTS web_credential_new")
        sqlite.run(`CREATE TABLE web_credential_new (
          id TEXT PRIMARY KEY,
          session_id TEXT NOT NULL REFERENCES session(id) ON DELETE CASCADE,
          label TEXT NOT NULL,
          headers TEXT NOT NULL DEFAULT '{}',
          container_id TEXT,
          role_id TEXT,
          time_created INTEGER NOT NULL,
          time_updated INTEGER NOT NULL
        )`)
        sqlite.run(`INSERT INTO web_credential_new (id, session_id, label, headers, container_id, role_id, time_created, time_updated)
          SELECT id, session_id, label,
            CASE
              WHEN type = 'bearer' OR type = 'jwt' THEN json_object('Authorization', 'Bearer ' || value)
              WHEN type = 'cookie' THEN json_object('Cookie', value)
              WHEN type = 'api_key' THEN json_object('X-API-Key', value)
              WHEN type = 'basic' THEN json_object('Authorization', 'Basic ' || value)
              ELSE json_object('Authorization', value)
            END,
            NULL, role_id, time_created, time_updated
          FROM web_credential`)
        sqlite.run("DROP TABLE web_credential")
        sqlite.run("ALTER TABLE web_credential_new RENAME TO web_credential")
        sqlite.run("CREATE INDEX IF NOT EXISTS web_credential_session_idx ON web_credential(session_id)")
        sqlite.run("CREATE INDEX IF NOT EXISTS web_credential_container_idx ON web_credential(container_id)")
        log.info("reconciled web_credential (type/value → headers)")
      }
    }
    sqlite.run("DROP TABLE IF EXISTS web_credential_new")

    // Phase 2: Schema-driven column reconciliation
    // Drizzle's migrator uses sqlite3_prepare_v2 which only compiles the first SQL statement.
    // Multi-statement migrations without "--> statement-breakpoint" delimiters only ran their
    // first statement. This checks ALL tables against Drizzle schema and adds missing columns.
    const added: string[] = []
    for (const value of Object.values(schema)) {
      if (!is(value, SQLiteTable)) continue
      const config = getTableConfig(value)
      if (!tableExists(sqlite, config.name)) continue
      const have = tableColumns(sqlite, config.name)
      for (const col of config.columns) {
        if (have.has(col.name)) continue
        sqlite.run(`ALTER TABLE ${config.name} ADD COLUMN ${col.name} ${col.getSQLType()}`)
        added.push(`${config.name}.${col.name}`)
      }
    }
    if (added.length) log.info("schema reconciled", { added })

    // Phase 3: Reconcile target-workspace ownership and indexes.
    // Older databases may have gained owner_key through Phase 2's ADD COLUMN fallback
    // before the dedicated owner-index migration existed. Backfill those rows before
    // replacing the old project_id-based unique index, or different project owners
    // can collide when creating the owner-scoped index.
    if (tableExists(sqlite, "target_workspace")) {
      const columns = tableColumns(sqlite, "target_workspace")
      if (
        columns.has("id") &&
        columns.has("project_id") &&
        columns.has("owner_key") &&
        columns.has("target_key") &&
        columns.has("hostname")
      ) {
        sqlite.run(
          "UPDATE target_workspace SET owner_key = 'project:' || project_id WHERE project_id <> 'global' AND (owner_key IS NULL OR owner_key = 'legacy:unscoped')",
        )
        // Existing global rows were shared across non-Git directories, so their true
        // owner cannot be inferred safely. Give each legacy row a private identity
        // instead of continuing to expose its notes to every non-Git project.
        sqlite.run(
          "UPDATE target_workspace SET owner_key = 'legacy:' || id WHERE project_id = 'global' AND (owner_key IS NULL OR owner_key = 'legacy:unscoped')",
        )
        sqlite.run("DROP INDEX IF EXISTS target_workspace_project_key_idx")
        sqlite.run("DROP INDEX IF EXISTS target_workspace_host_idx")
        sqlite.run(
          "CREATE UNIQUE INDEX IF NOT EXISTS target_workspace_owner_target_key_idx ON target_workspace(owner_key, target_key)",
        )
        sqlite.run(
          "CREATE INDEX IF NOT EXISTS target_workspace_owner_host_idx ON target_workspace(owner_key, hostname)",
        )
      }
    }
  }

  export const Client = lazy(() => {
    log.info("opening database", { path: path.join(Global.Path.data, "cyberstrike.db") })

    const sqlite = new BunDatabase(path.join(Global.Path.data, "cyberstrike.db"), { create: true })

    sqlite.run("PRAGMA journal_mode = WAL")
    sqlite.run("PRAGMA synchronous = NORMAL")
    sqlite.run("PRAGMA busy_timeout = 5000")
    sqlite.run("PRAGMA cache_size = -64000")
    sqlite.run("PRAGMA foreign_keys = ON")
    sqlite.run("PRAGMA wal_checkpoint(PASSIVE)")

    const db = drizzle({ client: sqlite, schema })

    // Apply schema migrations
    const entries =
      typeof CYBERSTRIKE_MIGRATIONS !== "undefined"
        ? CYBERSTRIKE_MIGRATIONS
        : migrations(path.join(import.meta.dirname, "../../migration"))
    if (entries.length > 0) {
      log.info("applying migrations", {
        count: entries.length,
        mode: typeof CYBERSTRIKE_MIGRATIONS !== "undefined" ? "bundled" : "dev",
      })
      migrate(db, prepareMigrations(sqlite, entries))
    }

    // Reconcile schema: ensures all tables have all expected columns.
    // Handles partially applied migrations (Drizzle's sqlite3_prepare_v2 only runs the first
    // statement when "--> statement-breakpoint" delimiters are missing) and any future drift.
    reconcile(sqlite)

    return db
  })

  export type TxOrDb = Transaction | Client

  const ctx = Context.create<{
    tx: TxOrDb
    effects: (() => void | Promise<void>)[]
  }>("database")

  export function use<T>(callback: (trx: TxOrDb) => T): T {
    try {
      return callback(ctx.use().tx)
    } catch (err) {
      if (err instanceof Context.NotFound) {
        const effects: (() => void | Promise<void>)[] = []
        const result = ctx.provide({ effects, tx: Client() }, () => callback(Client()))
        for (const effect of effects) effect()
        return result
      }
      throw err
    }
  }

  export function effect(fn: () => any | Promise<any>) {
    try {
      ctx.use().effects.push(fn)
    } catch {
      fn()
    }
  }

  export function transaction<T>(callback: (tx: TxOrDb) => T): T {
    try {
      return callback(ctx.use().tx)
    } catch (err) {
      if (err instanceof Context.NotFound) {
        const effects: (() => void | Promise<void>)[] = []
        const result = (Client() as any).transaction((tx: any) => ctx.provide({ tx, effects }, () => callback(tx))) as T
        for (const effect of effects) effect()
        return result
      }
      throw err
    }
  }
}
