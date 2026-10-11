import { createHash } from "node:crypto"
import path from "node:path"
import fs from "node:fs/promises"
import { and, asc, desc, eq, inArray } from "../storage/db"
import { Database } from "../storage/db"
import { Identifier } from "../id/id"
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

async function createIfMissing(filePath: string, content: string): Promise<void> {
  await fs.mkdir(path.dirname(filePath), { recursive: true })
  try {
    await fs.writeFile(filePath, content, { encoding: "utf-8", flag: "wx" })
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error
  }
}

async function prepareWorkspace(workspace: Workspace): Promise<void> {
  await fs.mkdir(workspace.workspacePath, { recursive: true })
  for (const directory of TARGET_DIRECTORIES) {
    await fs.mkdir(path.join(workspace.workspacePath, directory), { recursive: true })
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
  await createIfMissing(
    path.join(workspace.workspacePath, "notes.md"),
    [
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
    ].join("\n"),
  )
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
  export async function ensure(input: string): Promise<Workspace> {
    const normalized = normalizeTarget(input)
    const projectID = Instance.project.id
    const relativePath = path.join(".cyberstrike", "targets", normalized.slug)
    const now = Date.now()

    const row = Database.transaction((db) => {
      const existing = db
        .select()
        .from(TargetWorkspaceTable)
        .where(and(eq(TargetWorkspaceTable.project_id, projectID), eq(TargetWorkspaceTable.target_key, normalized.targetKey)))
        .get()
      if (existing) return existing

      db.insert(TargetWorkspaceTable)
        .values({
          id: Identifier.ascending("target_workspace"),
          project_id: projectID,
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
        .where(and(eq(TargetWorkspaceTable.project_id, projectID), eq(TargetWorkspaceTable.target_key, normalized.targetKey)))
        .get()
      if (!insertedOrRaced) throw new Error("Target workspace could not be persisted.")
      return insertedOrRaced
    })

    // Never trust a persisted path as an arbitrary filesystem path. Re-derive it from a sanitized slug.
    const safeRelativePath = path.join(".cyberstrike", "targets", normalized.slug)
    const workspace = mapWorkspace(row, safeRelativePath)
    await prepareWorkspace(workspace)
    return workspace
  }

  export function list(): Workspace[] {
    const projectID = Instance.project.id
    return Database.use((db) =>
      db
        .select()
        .from(TargetWorkspaceTable)
        .where(eq(TargetWorkspaceTable.project_id, projectID))
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

  export async function get(input: string): Promise<Workspace | null> {
    const normalized = normalizeTarget(input)
    const projectID = Instance.project.id
    const row = Database.use((db) =>
      db
        .select()
        .from(TargetWorkspaceTable)
        .where(and(eq(TargetWorkspaceTable.project_id, projectID), eq(TargetWorkspaceTable.target_key, normalized.targetKey)))
        .get(),
    )
    if (!row) return null
    const workspace = mapWorkspace(row, path.join(".cyberstrike", "targets", normalized.slug))
    await prepareWorkspace(workspace)
    return workspace
  }

  export function notes(targetID: string, limit = 100): TargetNote[] {
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

  /** Store an idempotent note in SQLite and append it to the target's editable notes.md file. */
  export async function addNote(targetURL: string, input: NoteInput): Promise<{ workspace: Workspace; note: TargetNote; created: boolean }> {
    const content = input.content?.trim()
    if (!content) throw new Error("Note content cannot be empty.")
    if (content.length > 100_000) throw new Error("Note content is too large (maximum 100,000 characters).")

    const workspace = await ensure(targetURL)
    const kind = input.kind ?? "manual"
    const title = input.title?.trim() || null
    const contentHash = createHash("sha256").update([kind, title ?? "", content].join("\0")).digest("hex")
    const now = Date.now()
    const source = (input.source?.trim() || "manual").slice(0, 120)
    const sourceURL = normalizedSourceURL(input.sourceURL)
    const status = input.status ?? "observed"
    const tags = [...new Set((input.tags ?? []).map((tag) => tag.trim()).filter(Boolean))].slice(0, 30)

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
          status,
          tags,
          time_created: now,
          time_updated: now,
        })
        .onConflictDoNothing()
        .returning()
        .get()
      if (inserted) return { row: inserted, created: true }

      const existing = db
        .select()
        .from(TargetNoteTable)
        .where(and(eq(TargetNoteTable.target_id, workspace.id), eq(TargetNoteTable.content_hash, contentHash)))
        .get()
      if (!existing) throw new Error("Note was not inserted and the duplicate record could not be loaded.")
      return { row: existing, created: false }
    })

    const note = mapNote(saved.row)
    const notesPath = path.join(workspace.workspacePath, "notes.md")
    const marker = "<!-- cyberstrike-target-note:" + note.id + " -->"
    let notesFile = ""
    try {
      notesFile = await fs.readFile(notesPath, "utf-8")
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error
    }
    if (!notesFile.includes(marker)) {
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
      await fs.appendFile(notesPath, entry, "utf-8")
    }

    return { workspace, note, created: saved.created }
  }

  export function allNotes(targetID: string): TargetNote[] {
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

  /**
   * Retrieve notes for the most relevant known target seen in this session.
   * It only reads existing target workspaces and session observations; it does not
   * create a target based on an unverified hostname, and never crosses project boundaries.
   */
  export function contextForSession(sessionID: string, maxNotes = 8): string | null {
    const projectID = Instance.project.id
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
        .where(eq(TargetWorkspaceTable.project_id, projectID))
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

    const matched = workspaces
      .map((row) => {
        const normalized = normalizeTarget(row.target_url)
        const hostMatch = [...observedHosts].some(
          (host) => host === normalized.hostname || host.endsWith("." + normalized.hostname),
        )
        if (!hostMatch) return undefined

        const targetPath = new URL(normalized.targetURL).pathname.replace(/\/$/, "") || "/"
        if (targetPath !== "/") {
          const pathMatch = [...observedURLs].some((candidate) => {
            try {
              const url = new URL(candidate)
              const hostMatches = url.hostname === normalized.hostname || url.hostname.endsWith("." + normalized.hostname)
              const path = url.pathname.replace(/\/$/, "") || "/"
              return hostMatches && (path === targetPath || path.startsWith(targetPath + "/"))
            } catch {
              return false
            }
          })
          if (!pathMatch) return undefined
        }

        return {
          workspace: mapWorkspace(row, path.join(".cyberstrike", "targets", normalized.slug)),
          hostScore: normalized.hostname.length,
          pathScore: targetPath === "/" ? 0 : targetPath.length,
        }
      })
      .filter((item): item is { workspace: Workspace; hostScore: number; pathScore: number } => !!item)
      .sort((a, b) => b.hostScore - a.hostScore || b.pathScore - a.pathScore)

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
