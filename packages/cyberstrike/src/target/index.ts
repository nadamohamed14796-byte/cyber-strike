import { createHash, randomBytes } from "node:crypto"
import path from "node:path"
import fs from "node:fs/promises"
import { and, asc, desc, eq, inArray } from "../storage/db"
import { Database } from "../storage/db"
import { Identifier } from "../id/id"
import { redactTargetNoteLine, redactTargetNoteSecrets } from "./redact"
import { targetWorkspaceOwnerKey } from "./project-key"
import { Instance } from "../project/instance"
import { SessionTable, RequestTable } from "../session/session.sql"
import { IntelEntryTable } from "../methodology/methodology.sql"
import { TargetNoteTable, TargetWorkspaceTable } from "./target.sql"

const TARGET_DIRECTORIES = ["assets", "endpoints", "javascript", "findings", "evidence", "sessions", "research"] as const

export type TargetNoteKind =
  | "manual"
  | "asset"
  | "endpoint"
  | "javascript"
  | "finding"
  | "evidence"
  | "research"
  | "lesson"

export type TargetNoteStatus = "unverified" | "observed" | "confirmed" | "disproven"

export interface NormalizedTarget {
  targetURL: string
  targetKey: string
  hostname: string
  slug: string
}

export interface Workspace {
  id: string
  projectID: string
  targetURL: string
  targetKey: string
  hostname: string
  slug: string
  relativePath: string
  workspacePath: string
  timeCreated: number
  timeUpdated: number
}

export interface NoteInput {
  kind?: TargetNoteKind
  title?: string
  content: string
  source?: string
  sourceURL?: string
  status?: TargetNoteStatus
  tags?: string[]
}

export interface TargetNote {
  id: string
  targetID: string
  kind: string
  title: string | null
  content: string
  source: string
  sourceURL: string | null
  contentHash: string
  status: string
  tags: string[]
  timeCreated: number
  timeUpdated: number
}

function projectRoot(): string {
  return Instance.worktree === "/" ? Instance.directory : Instance.worktree
}

function currentOwnerKey(): string {
  return targetWorkspaceOwnerKey(Instance.project.id, projectRoot())
}

function normalizedSourceURL(input?: string): string | undefined {
  if (!input?.trim()) return undefined
  try {
    const url = new URL(input.trim())
    if (url.protocol !== "https:" && url.protocol !== "http:") return undefined
    if (url.username || url.password) return undefined
    url.search = ""
    url.hash = ""
    return url.toString()
  } catch {
    return undefined
  }
}

/**
 * Canonicalizes a target identifier without retaining query strings, fragments, or credentials.
 * Bare hosts default to HTTPS. This function only normalizes identifiers; it performs no requests.
 */
export function normalizeTarget(input: string): NormalizedTarget {
  const value = input?.trim()
  if (!value) throw new Error("Target URL is required.")
  const candidate = /^[a-z][a-z\d+.-]*:\/\//i.test(value) ? value : "https://" + value
  let url: URL
  try {
    url = new URL(candidate)
  } catch {
    throw new Error("Invalid target. Supply a hostname or an http(s) URL.")
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new Error("Only HTTP and HTTPS target URLs are supported.")
  }
  if (!url.hostname || url.username || url.password) {
    throw new Error("Target URLs must have a hostname and must not contain credentials.")
  }

  url.hostname = url.hostname.toLowerCase()
  url.search = ""
  url.hash = ""
  url.pathname = url.pathname.replace(/\/+$/, "") || "/"

  const targetURL = url.pathname === "/" ? url.origin : url.origin + url.pathname
  const targetKey = targetURL
  const hostPart = url.hostname.replace(/[^a-z0-9-]/gi, "-").replace(/-+/g, "-").replace(/^-|-$/g, "").toLowerCase()
  const pathPart =
    url.pathname === "/"
      ? ""
      : url.pathname
          .split("/")
          .filter(Boolean)
          .join("-")
          .replace(/[^a-z0-9_-]/gi, "-")
          .replace(/-+/g, "-")
          .replace(/^-|-$/g, "")
          .toLowerCase()
          .slice(0, 24)
  const digest = createHash("sha256").update(targetKey).digest("hex").slice(0, 8)
  const slug = [hostPart || "target", pathPart, digest].filter(Boolean).join("-").slice(0, 80)

  return { targetURL, targetKey, hostname: url.hostname, slug }
}

function mapWorkspace(row: typeof TargetWorkspaceTable.$inferSelect, relativePath: string): Workspace {
  const absolutePath = path.resolve(projectRoot(), relativePath)
  return {
    id: row.id,
    projectID: row.project_id,
    targetURL: row.target_url,
    targetKey: row.target_key,
    hostname: row.hostname,
    slug: row.slug,
    relativePath,
    workspacePath: absolutePath,
    timeCreated: row.time_created,
    timeUpdated: row.time_updated,
  }
}

/**
 * Create a directory beneath the active project root without following
 * symlinks from an untrusted checkout into an unrelated filesystem location.
 */
async function ensureSafeDirectoryPath(rootPath: string, relativePath: string): Promise<string> {
  const lexicalRoot = path.resolve(rootPath)
  const root = await fs.realpath(lexicalRoot)
  const relative = path.relative(lexicalRoot, path.resolve(lexicalRoot, relativePath))
  if (!relative || relative === "." || relative === ".." || relative.startsWith(".." + path.sep) || path.isAbsolute(relative)) {
    throw new Error("Target workspace path must remain inside the active project.")
  }
  const segments = relative.split(path.sep)
  if (segments.some((segment) => !segment || segment === "." || segment === "..")) {
    throw new Error("Target workspace path contains an unsafe component.")
  }

  let current = root
  for (const segment of segments) {
    const next = path.join(current, segment)
    let info
    try {
      info = await fs.lstat(next)
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error
      try {
        await fs.mkdir(next, { mode: 0o700 })
      } catch (mkdirError) {
        if ((mkdirError as NodeJS.ErrnoException).code !== "EEXIST") throw mkdirError
      }
      info = await fs.lstat(next)
    }
    if (info.isSymbolicLink() || !info.isDirectory()) {
      throw new Error("Unsafe target workspace path: symbolic links and non-directory components are not allowed.")
    }
    current = await fs.realpath(next)
    const escaped = path.relative(root, current)
    if (escaped === ".." || escaped.startsWith(".." + path.sep) || path.isAbsolute(escaped)) {
      throw new Error("Target workspace path resolves outside the active project.")
    }
  }
  return current
}

async function assertRegularFileOrMissing(filePath: string): Promise<void> {
  try {
    const info = await fs.lstat(filePath)
    if (info.isSymbolicLink() || !info.isFile()) {
      throw new Error("Unsafe target workspace file: symbolic links and non-regular files are not allowed.")
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error
  }
}

async function createIfMissing(filePath: string, content: string): Promise<void> {
  await assertRegularFileOrMissing(filePath)
  try {
    await fs.writeFile(filePath, content, { encoding: "utf-8", flag: "wx", mode: 0o600 })
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error
  }
  await assertRegularFileOrMissing(filePath)
}

const notesMarkdownQueues = new Map<string, Promise<void>>()

/** Serialize Markdown read/modify/write cycles so concurrent note additions cannot overwrite one another. */
async function withNotesMarkdownLock<T>(notesPath: string, task: () => Promise<T>): Promise<T> {
  const previous = notesMarkdownQueues.get(notesPath) ?? Promise.resolve()
  let release!: () => void
  const current = new Promise<void>((resolve) => {
    release = resolve
  })
  notesMarkdownQueues.set(notesPath, current)
  await previous.catch(() => undefined)
  try {
    return await task()
  } finally {
    release()
    if (notesMarkdownQueues.get(notesPath) === current) notesMarkdownQueues.delete(notesPath)
  }
}

function defaultTargetNotes(workspace: Workspace): string {
  return [
    "# Target Notes",
    "",
    "> Human-readable notes for this target. Entries added through the target note command are also persisted in SQLite.",
    "",
    "## Target",
    "",
    "- URL: " + workspace.targetURL,
    "- Hostname: " + workspace.hostname,
    "",
    "## Known Facts",
    "",
    "## Assets and Endpoints",
    "",
    "## JavaScript and Client-Side Behavior",
    "",
    "## Findings and Evidence",
    "",
    "## Lessons and Follow-ups",
    "",
  ].join("\n")
}

function applyTargetNoteToMarkdown(notesFile: string, note: TargetNote): string {
  const marker = "<!-- cyberstrike-target-note:" + note.id + " -->"
  const markerIndex = notesFile.indexOf(marker)
  if (markerIndex < 0) {
    const timestamp = new Date(note.timeCreated).toISOString()
    const heading = note.title ? "### " + note.title : "### " + timestamp
    const provenance = [
      "- Type: " + note.kind,
      "- Status: " + note.status,
      "- Source: " + note.source,
      ...(note.sourceURL ? ["- Source URL: " + note.sourceURL] : []),
      ...(note.tags.length ? ["- Tags: " + note.tags.join(", ")] : []),
    ]
    const entry = "\n\n" + marker + "\n" + heading + "\n\n" + provenance.join("\n") + "\n\n" + note.content + "\n"
    return notesFile + entry
  }

  // Update only generated metadata and preserve all surrounding human edits.
  const provenanceStart = notesFile.indexOf("- Type: ", markerIndex)
  const provenanceEnd = provenanceStart >= 0 ? notesFile.indexOf("\n\n", provenanceStart) : -1
  if (provenanceStart < 0 || provenanceEnd <= provenanceStart) return notesFile
  const metadata = notesFile.slice(provenanceStart, provenanceEnd).split("\n")
  const statusIndex = metadata.findIndex((line) => line.startsWith("- Status: "))
  if (statusIndex >= 0) metadata[statusIndex] = "- Status: " + note.status
  const tagsIndex = metadata.findIndex((line) => line.startsWith("- Tags: "))
  if (note.tags.length) {
    if (tagsIndex >= 0) metadata[tagsIndex] = "- Tags: " + note.tags.join(", ")
    else metadata.push("- Tags: " + note.tags.join(", "))
  } else if (tagsIndex >= 0) {
    metadata.splice(tagsIndex, 1)
  }
  return notesFile.slice(0, provenanceStart) + metadata.join("\n") + notesFile.slice(provenanceEnd)
}

/** Reconcile SQLite notes into notes.md without replacing user-authored text. */
async function syncTargetNotesMarkdown(workspace: Workspace): Promise<void> {
  const notesPath = path.join(workspace.workspacePath, "notes.md")
  await withNotesMarkdownLock(notesPath, async () => {
    await assertRegularFileOrMissing(notesPath)
    let notesFile = ""
    try {
      notesFile = await fs.readFile(notesPath, "utf-8")
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error
    }

    const base = notesFile || defaultTargetNotes(workspace)
    const rows = Database.use((db) =>
      db
        .select()
        .from(TargetNoteTable)
        .where(eq(TargetNoteTable.target_id, workspace.id))
        .orderBy(asc(TargetNoteTable.time_created))
        .all(),
    )
    const nextFile = rows.map(mapNote).reduce(applyTargetNoteToMarkdown, base)
    if (nextFile !== notesFile) await TargetMemory.writeWorkspaceFile(workspace, "notes.md", nextFile)
  })
}

async function prepareWorkspace(workspace: Workspace, reconcileNotes = true): Promise<void> {
  const root = projectRoot()
  workspace.workspacePath = await ensureSafeDirectoryPath(root, workspace.relativePath)
  for (const directory of TARGET_DIRECTORIES) {
    await ensureSafeDirectoryPath(root, path.join(workspace.relativePath, directory))
  }
  await createIfMissing(
    path.join(workspace.workspacePath, "target.json"),
    JSON.stringify(
      {
        schemaVersion: 1,
        targetURL: workspace.targetURL,
        hostname: workspace.hostname,
        slug: workspace.slug,
        createdAt: new Date(workspace.timeCreated).toISOString(),
      },
      null,
      2,
    ) + "\n",
  )
  const notesPath = path.join(workspace.workspacePath, "notes.md")
  await createIfMissing(notesPath, defaultTargetNotes(workspace))
  // Normal workspace opens repair missing generated entries from the authoritative DB.
  // The note writer opts out before persisting its new record, then reconciles after commit.
  if (reconcileNotes) await syncTargetNotesMarkdown(workspace)
}

function mapNote(row: typeof TargetNoteTable.$inferSelect): TargetNote {
  return {
    id: row.id,
    targetID: row.target_id,
    kind: row.kind,
    title: row.title,
    content: row.content,
    source: row.source,
    sourceURL: row.source_url,
    contentHash: row.content_hash,
    status: row.status,
    tags: (row.tags as string[] | null) ?? [],
    timeCreated: row.time_created,
    timeUpdated: row.time_updated,
  }
}

export namespace TargetMemory {
  export function normalize(input: string): NormalizedTarget {
    return normalizeTarget(input)
  }

  /** Create or load a target workspace, persist its identity, and create missing workspace files. */
  export async function ensure(input: string, options: { reconcileNotes?: boolean } = {}): Promise<Workspace> {
    const normalized = normalizeTarget(input)
    const projectID = Instance.project.id
    const ownerKey = currentOwnerKey()
    const relativePath = path.join(".cyberstrike", "targets", normalized.slug)
    const now = Date.now()

    const row = Database.transaction((db) => {
      const existing = db
        .select()
        .from(TargetWorkspaceTable)
        .where(and(
          eq(TargetWorkspaceTable.project_id, projectID),
          eq(TargetWorkspaceTable.owner_key, ownerKey),
          eq(TargetWorkspaceTable.target_key, normalized.targetKey),
        ))
        .get()
      if (existing) return existing

      db.insert(TargetWorkspaceTable)
        .values({
          id: Identifier.ascending("target_workspace"),
          project_id: projectID,
          owner_key: ownerKey,
          target_key: normalized.targetKey,
          target_url: normalized.targetURL,
          hostname: normalized.hostname,
          slug: normalized.slug,
          workspace_path: relativePath,
          time_created: now,
          time_updated: now,
        })
        .onConflictDoNothing()
        .run()

      const insertedOrRaced = db
        .select()
        .from(TargetWorkspaceTable)
        .where(and(
          eq(TargetWorkspaceTable.project_id, projectID),
          eq(TargetWorkspaceTable.owner_key, ownerKey),
          eq(TargetWorkspaceTable.target_key, normalized.targetKey),
        ))
        .get()
      if (!insertedOrRaced) throw new Error("Target workspace could not be persisted.")
      return insertedOrRaced
    })

    // Never trust a persisted path as an arbitrary filesystem path. Re-derive it from a sanitized slug.
    const safeRelativePath = path.join(".cyberstrike", "targets", normalized.slug)
    const workspace = mapWorkspace(row, safeRelativePath)
    await prepareWorkspace(workspace, options.reconcileNotes ?? true)
    return workspace
  }

  export function list(): Workspace[] {
    const projectID = Instance.project.id
    const ownerKey = currentOwnerKey()
    return Database.use((db) =>
      db
        .select()
        .from(TargetWorkspaceTable)
        .where(and(eq(TargetWorkspaceTable.project_id, projectID), eq(TargetWorkspaceTable.owner_key, ownerKey)))
        .orderBy(desc(TargetWorkspaceTable.time_updated))
        .all()
        .map((row) => {
          // Re-derive directory names from normalized target identity rather than trusting DB paths.
          const safeSlug = normalizeTarget(row.target_url).slug
          const relativePath = path.join(".cyberstrike", "targets", safeSlug)
          return mapWorkspace(row, relativePath)
        }),
    )
  }

  /**
   * Verify that a URL's canonical HTTP(S) origin belongs to this target ID in
   * the active project. Path differences are allowed; origin and ownership are not.
   */
  export function matchesWorkspaceOrigin(targetID: string, siteURL: string): boolean {
    let suppliedOrigin: string
    try {
      const supplied = new URL(siteURL)
      if ((supplied.protocol !== "http:" && supplied.protocol !== "https:") || supplied.username || supplied.password) return false
      suppliedOrigin = supplied.origin
    } catch {
      return false
    }

    const projectID = Instance.project.id
    const ownerKey = currentOwnerKey()
    const workspace = Database.use((db) =>
      db
        .select({ targetURL: TargetWorkspaceTable.target_url })
        .from(TargetWorkspaceTable)
        .where(and(eq(TargetWorkspaceTable.id, targetID), eq(TargetWorkspaceTable.project_id, projectID), eq(TargetWorkspaceTable.owner_key, ownerKey)))
        .get(),
    )
    if (!workspace) return false
    try {
      const stored = new URL(workspace.targetURL)
      return (stored.protocol === "http:" || stored.protocol === "https:") && stored.origin === suppliedOrigin
    } catch {
      return false
    }
  }

  export async function get(input: string): Promise<Workspace | null> {
    const normalized = normalizeTarget(input)
    const projectID = Instance.project.id
    const ownerKey = currentOwnerKey()
    const row = Database.use((db) =>
      db
        .select()
        .from(TargetWorkspaceTable)
        .where(and(
          eq(TargetWorkspaceTable.project_id, projectID),
          eq(TargetWorkspaceTable.owner_key, ownerKey),
          eq(TargetWorkspaceTable.target_key, normalized.targetKey),
        ))
        .get(),
    )
    if (!row) return null
    const workspace = mapWorkspace(row, path.join(".cyberstrike", "targets", normalized.slug))
    await prepareWorkspace(workspace)
    return workspace
  }

  /** Ensure a target ID belongs to the currently active project before reading its notes. */
  function targetIsInCurrentProject(targetID: string): boolean {
    const projectID = Instance.project.id
    const ownerKey = currentOwnerKey()
    return Boolean(
      Database.use((db) =>
        db
          .select({ id: TargetWorkspaceTable.id })
          .from(TargetWorkspaceTable)
          .where(and(eq(TargetWorkspaceTable.id, targetID), eq(TargetWorkspaceTable.project_id, projectID), eq(TargetWorkspaceTable.owner_key, ownerKey)))
          .get(),
      ),
    )
  }

  export function notes(targetID: string, limit = 100): TargetNote[] {
    if (!targetIsInCurrentProject(targetID)) return []
    const boundedLimit = Math.max(1, Math.min(Number.isFinite(limit) ? Math.floor(limit) : 100, 500))
    return Database.use((db) =>
      db
        .select()
        .from(TargetNoteTable)
        .where(eq(TargetNoteTable.target_id, targetID))
        .orderBy(desc(TargetNoteTable.time_created))
        .limit(boundedLimit)
        .all()
        .map(mapNote),
    )
  }

  /** Store a provenance-aware, idempotent note in SQLite and keep its generated notes.md metadata in sync. */
  export async function addNote(
    targetURL: string,
    input: NoteInput,
  ): Promise<{ workspace: Workspace; note: TargetNote; created: boolean; updated: boolean }> {
    const rawContent = input.content?.trim()
    if (!rawContent) throw new Error("Note content cannot be empty.")
    if (rawContent.length > 100_000) throw new Error("Note content is too large (maximum 100,000 characters).")
    // Redact at the persistence boundary, not only in the agent-facing tool:
    // the CLI and future callers must not be able to write secrets to disk.
    const content = redactTargetNoteSecrets(rawContent)

    const workspace = await ensure(targetURL, { reconcileNotes: false })
    const kind = input.kind ?? "manual"
    const rawTitle = input.title?.trim()
    const title = rawTitle ? redactTargetNoteLine(rawTitle, 180) || null : null
    const now = Date.now()
    const source = redactTargetNoteLine((input.source?.trim() || "manual"), 120) || "manual"
    const sourceURL = normalizedSourceURL(input.sourceURL ? redactTargetNoteSecrets(input.sourceURL) : undefined)
    const statusForInsert = input.status ?? "observed"
    const tags = [...new Set((input.tags ?? []).map((tag) => redactTargetNoteLine(tag, 48)).filter(Boolean))].slice(0, 30)
    // Provenance is part of note identity, so identical lessons from distinct sources do not erase attribution.
    const contentHash = createHash("sha256")
      .update([kind, title ?? "", source, sourceURL ?? "", content].join("\0"))
      .digest("hex")

    const saved = Database.transaction((db) => {
      const inserted = db
        .insert(TargetNoteTable)
        .values({
          id: Identifier.ascending("target_note"),
          target_id: workspace.id,
          kind,
          title,
          content,
          source,
          source_url: sourceURL ?? null,
          content_hash: contentHash,
          status: statusForInsert,
          tags,
          time_created: now,
          time_updated: now,
        })
        .onConflictDoNothing()
        .returning()
        .get()
      if (inserted) return { row: inserted, created: true, updated: false }

      const existing = db
        .select()
        .from(TargetNoteTable)
        .where(and(eq(TargetNoteTable.target_id, workspace.id), eq(TargetNoteTable.content_hash, contentHash)))
        .get()
      if (!existing) throw new Error("Note was not inserted and the duplicate record could not be loaded.")

      // Omitted status/tags means "preserve existing state", not reset a confirmed note to observed.
      const nextStatus = input.status ?? existing.status
      const existingTags = (existing.tags as string[] | null) ?? []
      const nextTags = input.tags === undefined ? existingTags : tags
      const changed = nextStatus !== existing.status || JSON.stringify(nextTags) !== JSON.stringify(existingTags)
      if (!changed) return { row: existing, created: false, updated: false }

      const updated = db
        .update(TargetNoteTable)
        .set({ status: nextStatus, tags: nextTags, time_updated: now })
        .where(eq(TargetNoteTable.id, existing.id))
        .returning()
        .get()
      return { row: updated ?? existing, created: false, updated: true }
    })

    const note = mapNote(saved.row)
    // Reconcile every persisted note under one lock: this both prevents lost updates under
    // concurrent additions and repairs entries missed by an interrupted previous write.
    await syncTargetNotesMarkdown(workspace)

    return { workspace, note, created: saved.created, updated: saved.updated }
  }

  /**
   * Atomically write a generated file beneath a target workspace. Re-validate
   * every parent directory and refuse symlink/non-regular output files so a
   * generated graph cannot overwrite files outside the workspace.
   */
  export async function writeWorkspaceFile(workspace: Workspace, relativeFilePath: string, content: string): Promise<string> {
    const activeProjectID = Instance.project.id
    const ownerKey = currentOwnerKey()
    const normalizedTarget = normalizeTarget(workspace.targetURL)
    const workspaceRecord = Database.use((db) =>
      db
        .select({ targetKey: TargetWorkspaceTable.target_key })
        .from(TargetWorkspaceTable)
        .where(and(eq(TargetWorkspaceTable.id, workspace.id), eq(TargetWorkspaceTable.project_id, activeProjectID), eq(TargetWorkspaceTable.owner_key, ownerKey)))
        .get(),
    )
    const expectedRelativePath = path.join(".cyberstrike", "targets", normalizedTarget.slug)
    if (
      workspace.projectID !== activeProjectID ||
      !workspaceRecord ||
      workspaceRecord.targetKey !== normalizedTarget.targetKey ||
      path.normalize(workspace.relativePath) !== path.normalize(expectedRelativePath)
    ) {
      throw new Error("Workspace output target does not belong to the active project or has mismatched identity.")
    }
    const normalized = relativeFilePath.trim()
    if (
      !normalized ||
      path.isAbsolute(normalized) ||
      normalized.includes("\\") ||
      normalized.split("/").some((part) => !part || part === "." || part === "..")
    ) {
      throw new Error("Workspace output path must be a clean relative path inside the target workspace.")
    }

    const verifiedWorkspacePath = await ensureSafeDirectoryPath(projectRoot(), workspace.relativePath)
    const workspaceEscape = path.relative(verifiedWorkspacePath, path.resolve(verifiedWorkspacePath, normalized))
    if (workspaceEscape === ".." || workspaceEscape.startsWith(".." + path.sep) || path.isAbsolute(workspaceEscape)) {
      throw new Error("Workspace output path resolves outside the target workspace.")
    }

    const relativeParent = path.dirname(normalized)
    const parentPath = relativeParent === "."
      ? verifiedWorkspacePath
      : await ensureSafeDirectoryPath(projectRoot(), path.join(workspace.relativePath, relativeParent))
    const filePath = path.join(parentPath, path.basename(normalized))
    try {
      const info = await fs.lstat(filePath)
      if (info.isSymbolicLink() || !info.isFile()) {
        throw new Error("Unsafe workspace output file: symbolic links and non-regular files are not allowed.")
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error
    }

    const temp = filePath + "." + process.pid + "." + randomBytes(6).toString("hex") + ".tmp"
    try {
      await fs.writeFile(temp, content, { encoding: "utf8", mode: 0o600, flag: "wx" })
      await fs.rename(temp, filePath)
      await fs.chmod(filePath, 0o600)
    } finally {
      await fs.rm(temp, { force: true }).catch(() => undefined)
    }
    return filePath
  }

  export function allNotes(targetID: string): TargetNote[] {
    if (!targetIsInCurrentProject(targetID)) return []
    return Database.use((db) =>
      db
        .select()
        .from(TargetNoteTable)
        .where(eq(TargetNoteTable.target_id, targetID))
        .orderBy(desc(TargetNoteTable.time_created))
        .all()
        .map(mapNote),
    )
  }

  /** Exact HTTP(S) origin plus path-prefix matching for session observations; never fetches or authorizes a target. */
  export function targetObservationMatches(targetURL: string, observedURL: string): boolean {
    const target = normalizeTarget(targetURL)
    try {
      const raw = observedURL.trim()
      // A scheme-less host is ambiguous (protocol and port are unknown), so it
      // must not be used to attach session evidence to a target workspace.
      if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(raw)) return false
      const observed = new URL(raw)
      if ((observed.protocol !== "http:" && observed.protocol !== "https:") || observed.username || observed.password) return false
      const expected = new URL(target.targetURL)
      // Exact origin prevents subdomain, scheme, and non-default-port cross-contamination.
      if (observed.origin !== expected.origin) return false
      const targetPath = expected.pathname.replace(/\/$/, "") || "/"
      if (targetPath === "/") return true
      const observedPath = observed.pathname.replace(/\/$/, "") || "/"
      return observedPath === targetPath || observedPath.startsWith(targetPath + "/")
    } catch {
      return false
    }
  }

  /** True only when this session tree has observed a URL matching an existing target workspace. */
  export function isObservedInSession(sessionID: string, targetURL: string): boolean {
    const normalized = normalizeTarget(targetURL)
    const projectID = Instance.project.id
    const rootSessionExists = Database.use((db) =>
      db
        .select({ id: SessionTable.id })
        .from(SessionTable)
        .where(and(eq(SessionTable.id, sessionID), eq(SessionTable.project_id, projectID)))
        .get(),
    )
    if (!rootSessionExists) return false
    const sessionIDs = new Set<string>([sessionID])
    let frontier = [sessionID]
    while (frontier.length > 0) {
      const children = Database.use((db) =>
        db.select({ id: SessionTable.id }).from(SessionTable)
          .where(and(eq(SessionTable.project_id, projectID), inArray(SessionTable.parent_id, frontier)))
          .all().map((row) => row.id).filter((id) => !sessionIDs.has(id)),
      )
      for (const child of children) sessionIDs.add(child)
      frontier = children
    }
    const requests = Database.use((db) =>
      db.select({ host: RequestTable.host, origin: RequestTable.origin, normalizedPath: RequestTable.normalized_path, pageURL: RequestTable.page_url })
        .from(RequestTable).where(inArray(RequestTable.session_id, [...sessionIDs])).all(),
    )
    const assets = Database.use((db) =>
      db.select({ asset: IntelEntryTable.asset }).from(IntelEntryTable)
        .where(inArray(IntelEntryTable.session_id, [...sessionIDs])).all().map((row) => row.asset),
    )
    const observedURLs: string[] = []
    for (const request of requests) {
      if (request.pageURL) observedURLs.push(request.pageURL)
      if (request.origin) observedURLs.push(request.origin)
      if (request.host) observedURLs.push(request.host)
      if (request.origin && request.normalizedPath) {
        try { observedURLs.push(new URL(request.normalizedPath, request.origin).href) } catch {}
      }
    }
    observedURLs.push(...assets.filter((asset): asset is string => typeof asset === "string" && asset.length > 0))
    return observedURLs.some((observed) => targetObservationMatches(normalized.targetURL, observed))
  }

  /**
   * Retrieve notes for the most relevant known target seen in this session.
   * It only reads existing target workspaces and session observations; it does not
   * create a target based on an unverified hostname, and never crosses project boundaries.
   */
  export function contextForSession(sessionID: string, maxNotes = 8): string | null {
    const projectID = Instance.project.id
    const ownerKey = currentOwnerKey()
    const rootSessionExists = Database.use((db) =>
      db
        .select({ id: SessionTable.id })
        .from(SessionTable)
        .where(and(eq(SessionTable.id, sessionID), eq(SessionTable.project_id, projectID)))
        .get(),
    )
    if (!rootSessionExists) return null
    const relatedSessionIDs = new Set<string>([sessionID])
    let frontier = [sessionID]

    // Include child-agent sessions without scanning every session in the project.
    while (frontier.length > 0) {
      const children = Database.use((db) =>
        db
          .select({ id: SessionTable.id })
          .from(SessionTable)
          .where(and(eq(SessionTable.project_id, projectID), inArray(SessionTable.parent_id, frontier)))
          .all()
          .map((row) => row.id)
          .filter((id) => !relatedSessionIDs.has(id)),
      )
      for (const child of children) relatedSessionIDs.add(child)
      frontier = children
    }

    const sessionIDs = [...relatedSessionIDs]
    const requests = Database.use((db) =>
      db
        .select({
          host: RequestTable.host,
          origin: RequestTable.origin,
          normalizedPath: RequestTable.normalized_path,
          pageURL: RequestTable.page_url,
        })
        .from(RequestTable)
        .where(inArray(RequestTable.session_id, sessionIDs))
        .all(),
    )
    const intelAssets = Database.use((db) =>
      db
        .select({ asset: IntelEntryTable.asset })
        .from(IntelEntryTable)
        .where(inArray(IntelEntryTable.session_id, sessionIDs))
        .all()
        .map((row) => row.asset),
    )
    const workspaces = Database.use((db) =>
      db
        .select()
        .from(TargetWorkspaceTable)
        .where(and(eq(TargetWorkspaceTable.project_id, projectID), eq(TargetWorkspaceTable.owner_key, ownerKey)))
        .all(),
    )

    const observedURLs = new Set<string>()
    const observedHosts = new Set<string>()
    function addHost(raw?: string | null) {
      if (!raw) return
      const value = raw.trim()
      try {
        const url = new URL(/^[a-z][a-z\d+.-]*:\/\//i.test(value) ? value : "https://" + value)
        if (url.protocol !== "https:" && url.protocol !== "http:") return
        if (url.username || url.password) return
        observedHosts.add(url.hostname.toLowerCase())
        if (value.includes("://")) observedURLs.add(url.origin + (url.pathname === "/" ? "" : url.pathname))
      } catch {}
    }

    for (const request of requests) {
      addHost(request.host)
      addHost(request.origin)
      addHost(request.pageURL)
      if (request.origin && request.normalizedPath) {
        try {
          const url = new URL(request.normalizedPath, request.origin)
          if (url.protocol === "https:" || url.protocol === "http:") observedURLs.add(url.origin + url.pathname)
        } catch {}
      }
    }
    for (const asset of intelAssets) addHost(asset)

    if (observedHosts.size === 0) return null

    // Match by exact origin and target path, never by hostname suffix. A
    // request for api.example.com must not inherit example.com's target memory.
    const matched = workspaces
      .map((row) => {
        const normalized = normalizeTarget(row.target_url)
        const matchingObservation = [...observedURLs].some((candidate) =>
          targetObservationMatches(normalized.targetURL, candidate),
        )
        if (!matchingObservation) return undefined
        const targetPath = new URL(normalized.targetURL).pathname.replace(/\/$/, "") || "/"
        return {
          workspace: mapWorkspace(row, path.join(".cyberstrike", "targets", normalized.slug)),
          hostScore: new URL(normalized.targetURL).origin.length,
          pathScore: targetPath === "/" ? 0 : targetPath.length,
        }
      })
      .filter((item): item is { workspace: Workspace; hostScore: number; pathScore: number } => !!item)
      .sort((a, b) => b.pathScore - a.pathScore || b.hostScore - a.hostScore)

    const selected = matched[0]?.workspace
    if (!selected) return null

    const notes = Database.use((db) =>
      db
        .select()
        .from(TargetNoteTable)
        .where(eq(TargetNoteTable.target_id, selected.id))
        .orderBy(desc(TargetNoteTable.time_created))
        .limit(Math.max(1, Math.min(Math.floor(maxNotes), 20)))
        .all()
        .map(mapNote),
    )
    if (notes.length === 0) return null

    const sections = [
      "## Target Memory (project-scoped; persistent notes)",
      "",
      "Selected target: " + selected.targetURL,
      "Workspace: " + selected.relativePath,
      "Use these notes as leads, not proof. Revalidate prior observations against current responses and evidence. Do not treat unverified or disproven notes as confirmed findings.",
      "",
      ...notes.flatMap((note) => [
        "### [" + note.status + "/" + note.kind + "] " + (note.title ?? "(untitled)"),
        "Source: " + note.source + (note.sourceURL ? " — " + note.sourceURL : ""),
        note.content.slice(0, 1800),
        "",
      ]),
    ]
    return sections.join("\n").slice(0, 14_000)
  }
}
