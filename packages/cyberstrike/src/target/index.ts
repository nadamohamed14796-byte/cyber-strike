import { createHash, randomBytes } from "node:crypto"
import path from "node:path"
import fs from "node:fs/promises"
import { and, asc, desc, eq, inArray, isNull } from "../storage/db"
import { Database } from "../storage/db"
import { Identifier } from "../id/id"
import { redactTargetNoteLine, redactTargetNoteSecrets } from "./redact"
import { targetWorkspaceOwnerKey } from "./project-key"
import { matchingScopeItems } from "./scope-index"
import { Instance } from "../project/instance"
import { SessionTable, RequestTable } from "../session/session.sql"
import { IntelEntryTable } from "../methodology/methodology.sql"
import { TargetNoteRevisionTable, TargetNoteTable, TargetWorkspaceTable, type TargetAssetType } from "./target.sql"

const TARGET_DIRECTORIES = [
  "scope",
  "assets",
  "recon",
  "urls",
  "directories",
  "parameters",
  "requests",
  "javascript",
  "endpoints",
  "testing",
  "findings",
  "evidence",
  "reports",
  "scans",
  "runs",
  "logs",
  "sessions",
  "research",
] as const

export const USER_CONFIRMED_SCOPE_SOURCE = "User-confirmed in conversation"

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
export type { TargetAssetType } from "./target.sql"

export interface TargetScope {
  schemaVersion: 1
  targetURL: string
  status: "unconfigured" | "configured"
  scopeItems: string[]
  excludedItems: string[]
  authorizationSource: string | null
  authorizationReference: string | null
  configuredAt: string | null
  warning?: string
}

type ScopeManifestCacheEntry = { signature: string; scope: TargetScope }
const scopeManifestCache = new Map<string, ScopeManifestCacheEntry>()
const MAX_CACHED_SCOPE_MANIFESTS = 8
const MAX_CACHED_SCOPE_ITEMS = 1_000_000
let cachedScopeItemCount = 0

function scopeFileSignature(info: Awaited<ReturnType<typeof fs.stat>>): string {
  return [info.dev, info.ino, info.size, info.mtimeMs, info.ctimeMs].join(":")
}

function cacheScopeManifest(scopePath: string, signature: string, scope: TargetScope): void {
  const existing = scopeManifestCache.get(scopePath)
  if (existing) {
    cachedScopeItemCount -= existing.scope.scopeItems.length + existing.scope.excludedItems.length
    scopeManifestCache.delete(scopePath)
  }

  const itemCount = scope.scopeItems.length + scope.excludedItems.length
  // Do not pin extraordinarily large manifests in process memory. They remain valid;
  // they simply need to be parsed again on the next request.
  if (itemCount > MAX_CACHED_SCOPE_ITEMS) return

  scopeManifestCache.set(scopePath, { signature, scope })
  cachedScopeItemCount += itemCount
  while (
    scopeManifestCache.size > MAX_CACHED_SCOPE_MANIFESTS ||
    cachedScopeItemCount > MAX_CACHED_SCOPE_ITEMS
  ) {
    const oldestPath = scopeManifestCache.keys().next().value
    if (oldestPath === undefined) break
    const oldest = scopeManifestCache.get(oldestPath)
    if (oldest) cachedScopeItemCount -= oldest.scope.scopeItems.length + oldest.scope.excludedItems.length
    scopeManifestCache.delete(oldestPath)
  }
}

type IdentityManifestCacheEntry = { signature: string; identity: string; matches: boolean }
const identityManifestCache = new Map<string, IdentityManifestCacheEntry>()
const MAX_CACHED_IDENTITY_MANIFESTS = 32

function cacheIdentityManifest(filePath: string, entry: IdentityManifestCacheEntry): void {
  identityManifestCache.delete(filePath)
  identityManifestCache.set(filePath, entry)
  while (identityManifestCache.size > MAX_CACHED_IDENTITY_MANIFESTS) {
    const oldestPath = identityManifestCache.keys().next().value
    if (oldestPath === undefined) break
    identityManifestCache.delete(oldestPath)
  }
}

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
  parentTargetID: string | null
  assetType: TargetAssetType
  relativePath: string
  workspacePath: string
  timeCreated: number
  timeUpdated: number
}

export interface NoteInput {
  kind?: TargetNoteKind
  title?: string
  content: string
  evidence?: string
  source?: string
  sourceURL?: string
  status?: TargetNoteStatus
  tags?: string[]
  /** Update the existing note with the same provenance/title instead of creating snapshot duplicates. */
  upsertByIdentity?: boolean
  /** Stable identity independent of the human-readable title; updates one note across revisions. */
  identityKey?: string
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

/** Archived immutable version of a current investigation note. */
export interface TargetNoteRevision {
  id: string
  noteID: string
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
}

function projectRoot(): string {
  return Instance.worktree === "/" ? Instance.directory : Instance.worktree
}

function currentOwnerKey(): string {
  return targetWorkspaceOwnerKey(Instance.project.id, projectRoot())
}

function isExactUserConfirmedScopeItem(input: string): boolean {
  const value = input.trim()
  if (!value || /[*{}\\]/.test(value)) return false
  if (/^(?:domain|wildcard|url|cidr|ip address|api|ai model|smart contracts?|source code|executable|hardware(?:\/iot)?|ios|android|other(?: asset)?):/i.test(value)) return false
  if (/^\d{1,3}(?:\.\d{1,3}){3}\/\d{1,2}$/.test(value) || /^\[?[0-9a-f:.]+\]?\/\d{1,3}$/i.test(value)) return false
  if (!/^https?:\/\//i.test(value) && value.includes("/")) return false
  // normalizeScopeItem() validates the concrete host, scheme, port, path, and URL syntax before this check.
  return true
}

function normalizeScopeItem(input: string): string {
  const value = input?.trim()
  if (!value) throw new Error("Scope entries cannot be empty.")
  if (/[\u0000-\u001f\u007f]/.test(value)) throw new Error("Scope entries cannot contain control characters.")

  // Preserve explicit URL boundaries (scheme, port and path); stripping these
  // would broaden a narrow program scope to the whole host.
  if (/^https?:\/\//i.test(value)) {
    let url: URL
    try { url = new URL(value) } catch { throw new Error("Invalid scope URL: " + value) }
    if ((url.protocol !== "http:" && url.protocol !== "https:") || url.username || url.password || url.search || url.hash) {
      throw new Error("Scope URLs must be credential-free HTTP(S) URLs without queries or fragments.")
    }
    const host = url.hostname.toLowerCase().replace(/\.$/, "")
    const wildcardHost = host.startsWith("*.")
    const bareHost = wildcardHost ? host.slice(2) : host
    const ipv6Host = !wildcardHost && bareHost.startsWith("[") && bareHost.endsWith("]") && bareHost.slice(1, -1).includes(":")
    if (!bareHost || (!ipv6Host && !/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$/i.test(bareHost))) {
      throw new Error("Invalid hostname in scope URL: " + value)
    }
    url.pathname = url.pathname.replace(/\/+$/, "") || "/"
    return url.toString().replace(/\/$/, url.pathname === "/" ? "" : "/")
  }

  const ipv6Cidr = value.match(/^\[?([0-9a-f:.]+)\]?\/(\d{1,3})$/i)
  if (ipv6Cidr && ipv6Cidr[1].includes(":")) {
    const prefix = Number(ipv6Cidr[2])
    if (prefix < 0 || prefix > 128) throw new Error("Invalid IPv6 CIDR scope entry: " + value)
    const rawIPv6 = ipv6Cidr[1].replace(/^\[|\]$/g, "")
    let hostname: string
    try { hostname = new URL("https://[" + rawIPv6 + "]").hostname.toLowerCase() }
    catch { throw new Error("Invalid IPv6 CIDR scope entry: " + value) }
    return hostname + "/" + prefix
  }

  const cidr = value.match(/^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/)
  if (cidr) {
    const octets = cidr[1].split(".").map(Number)
    const prefix = Number(cidr[2])
    if (octets.some((part) => !Number.isInteger(part) || part < 0 || part > 255) || prefix < 0 || prefix > 32) {
      throw new Error("Invalid IPv4 CIDR scope entry: " + value)
    }
    return octets.join(".") + "/" + prefix
  }

  // Preserve exact IPv6 literals as bracketed URL hostnames so URL matching can
  // compare them without confusing colons with a service-port separator.
  if (value.includes(":") && !value.includes("/") && !/^https?:\/\//i.test(value)) {
    const rawIPv6 = value.replace(/^\[|\]$/g, "")
    if (rawIPv6.includes(":")) {
      try {
        const ipv6URL = new URL("https://[" + rawIPv6 + "]")
        if (ipv6URL.hostname.startsWith("[") && ipv6URL.hostname.endsWith("]")) return ipv6URL.hostname.toLowerCase()
      } catch {
        // Continue to host:port or the opaque-scope preservation path.
      }
    }
  }

  // Host:port is a valid service scope entry and is intentionally distinct from
  // a bare domain, which matches that hostname independent of port.
  const hostPort = value.match(/^([^:/]+):(\d{1,5})$/)
  if (hostPort) {
    const port = Number(hostPort[2])
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("Invalid scope port: " + value)
    let hostname: string
    try { hostname = new URL("https://" + hostPort[1]).hostname.toLowerCase().replace(/\.$/, "") }
    catch { throw new Error("Invalid hostname in scope entry: " + value) }
    if (!/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$/i.test(hostname)) {
      throw new Error("Invalid hostname in scope entry: " + value)
    }
    return hostname + ":" + port
  }

  const wildcard = value.startsWith("*.")
  const hostInput = wildcard ? value.slice(2) : value
  let hostname: string
  try {
    hostname = new URL("https://" + hostInput).hostname.toLowerCase()
  } catch {
    // Keep unsupported non-web scope identifiers available as raw scope evidence,
    // but scope_match will not authorize HTTP requests based on an unknown syntax.
    // Keep unfamiliar program-specific labels and structured entries intact as
    // scope evidence. They will not match HTTP targets unless a supported matcher
    // can interpret them, so acceptance never turns an unknown format into access.
    if (value.length <= 1000 && !/[\u0000-\u001f\u007f]/.test(value)) return value
    throw new Error("Invalid domain, IP, or scope identifier: " + value)
  }
  hostname = hostname.replace(/\.$/, "")
  if (!hostname || hostname.includes(":") || hostname.startsWith(".") || hostname.endsWith(".") ||
    !/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$/i.test(hostname)) {
    throw new Error("Invalid domain or IP scope entry: " + value)
  }
  return (wildcard ? "*." : "") + hostname
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

function workspaceRelativePath(
  row: typeof TargetWorkspaceTable.$inferSelect,
  visited = new Set<string>(),
): string {
  if (visited.has(row.id)) throw new Error("Target workspace hierarchy contains a parent cycle.")
  visited.add(row.id)
  const own = path.join(".cyberstrike", "targets", normalizeTarget(row.target_url).slug)
  if (!row.parent_target_id) return own
  const parent = Database.use((db) =>
    db.select().from(TargetWorkspaceTable).where(eq(TargetWorkspaceTable.id, row.parent_target_id!)).get(),
  )
  if (!parent || parent.project_id !== row.project_id || parent.owner_key !== row.owner_key) {
    throw new Error("Target workspace parent is missing or belongs to another project.")
  }
  return path.join(workspaceRelativePath(parent, visited), "assets", normalizeTarget(row.target_url).slug)
}

function mapWorkspace(
  row: typeof TargetWorkspaceTable.$inferSelect,
  relativePath = workspaceRelativePath(row),
): Workspace {
  const absolutePath = path.resolve(projectRoot(), relativePath)
  return {
    id: row.id,
    projectID: row.project_id,
    targetURL: row.target_url,
    targetKey: row.target_key,
    hostname: row.hostname,
    slug: row.slug,
    parentTargetID: row.parent_target_id ?? null,
    assetType: (row.asset_type ?? "target") as TargetAssetType,
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

async function assertRegularFileOrMissing(
  filePath: string,
): Promise<Awaited<ReturnType<typeof fs.lstat>> | null> {
  try {
    const info = await fs.lstat(filePath)
    if (info.isSymbolicLink() || !info.isFile()) {
      throw new Error("Unsafe target workspace file: symbolic links and non-regular files are not allowed.")
    }
    return info
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return null
    throw error
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

const targetNoteWriteQueues = new Map<string, Promise<void>>()

/** Serialize all note upserts for one normalized target before they read/merge the current row. */
async function withTargetNoteWriteLock<T>(targetKey: string, task: () => Promise<T>): Promise<T> {
  const previous = targetNoteWriteQueues.get(targetKey) ?? Promise.resolve()
  let release!: () => void
  const current = new Promise<void>((resolve) => {
    release = resolve
  })
  targetNoteWriteQueues.set(targetKey, current)
  await previous.catch(() => undefined)
  try {
    return await task()
  } finally {
    release()
    if (targetNoteWriteQueues.get(targetKey) === current) targetNoteWriteQueues.delete(targetKey)
  }
}

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
    "> Working memory for manual hunting and future sessions. Keep the notes natural and evidence-led; there is no required template. Add only conclusions, useful context, failed approaches, and open questions worth remembering.",
    "",
    "## Target",
    "",
    "- URL: " + workspace.targetURL,
    "- Hostname: " + workspace.hostname,
    "",
    "## Working notes",
    "",
  ].join("\n")
}

function defaultWorkspaceReadme(workspace: Workspace): string {
  return [
    "# CyberStrike Target Workspace",
    "",
    "- Target: " + workspace.targetURL,
    "- Workspace ID: " + workspace.id,
    "- Schema: 2",
    "",
    "## Safety and provenance",
    "",
    "- Treat `workspace.json` and SQLite target metadata as identity references; do not infer authorization from the existence of this workspace.",
    "- Active testing requires an explicitly configured, current, program-authorized scope in `scope/scope.json`.",
    "- Preserve source URL, timestamp, run/session ID, and evidence references for generated artifacts.",
    "- Keep observations, hypotheses, validated findings, and reports separate. A note is not proof.",
    "- Preserve exact discovered values in this private, target-local evidence store when they are relevant evidence or needed for reproduction; mark them as candidates until independently validated.",
    "",
    "## Layout",
    "",
    "| Directory | Purpose |",
    "| --- | --- |",
    "| `scope/` | Explicit authorization and scope boundaries |",
    "| `assets/` | Stable asset registry and provenance |",
    "| `recon/` | Recon outputs |",
    "| `urls/` | Discovered URLs |",
    "| `requests/` | Request/response references and correlation metadata |",
    "| `javascript/` | JS assets and analysis/correlation output |",
    "| `endpoints/` | Endpoint inventory |",
    "| `testing/` | Test cases and validation attempts |",
    "| `findings/` | Finding records and lifecycle state |",
    "| `evidence/` | Evidence artifacts and indexes |",
    "| `reports/` | Report drafts and exports |",
    "| `scans/` | Scan manifests and outputs |",
    "| `runs/` | Resumable run manifests |",
    "| `logs/` | Target-local logs |",
    "| `sessions/` | Session references and resumable context |",
    "| `research/` | Target-specific research observations (not global methodology) |",
    "",
    "## Source of truth",
    "",
    "- SQLite is authoritative for target identity and target notes.",
    "- This README and `notes.md` are human-readable companions.",
    "- Global writeups and methodology belong in the separate research knowledge store.",
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

  // Refresh the generated note block from SQLite, including its body. Text outside
  // marked blocks remains untouched, so unrelated operator notes survive reconciliation.
  const nextMarker = notesFile.indexOf("<!-- cyberstrike-target-note:", markerIndex + marker.length)
  // Preserve operator-authored text appended after the final generated note body.
  let blockEnd = nextMarker
  if (blockEnd < 0) {
    const bodyIndex = notesFile.indexOf(note.content, markerIndex + marker.length)
    blockEnd = bodyIndex >= 0 ? bodyIndex + note.content.length : notesFile.length
  }
  while (blockEnd > markerIndex && notesFile[blockEnd - 1] === "\n") blockEnd--
  const timestamp = new Date(note.timeCreated).toISOString()
  const heading = note.title ? "### " + note.title : "### " + timestamp
  const provenance = [
    "- Type: " + note.kind,
    "- Status: " + note.status,
    "- Source: " + note.source,
    ...(note.sourceURL ? ["- Source URL: " + note.sourceURL] : []),
    ...(note.tags.length ? ["- Tags: " + note.tags.join(", ")] : []),
  ]
  const entry = [marker, heading, "", provenance.join("\n"), "", note.content].join("\n")
  return notesFile.slice(0, markerIndex) + entry + "\n" + notesFile.slice(blockEnd)
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

    // Keep old versions available to manual testers without duplicating them in the active
    // investigation notes. Rebuild this companion file from SQLite on every sync so retries
    // are idempotent and interruptions cannot silently lose an earlier note revision.
    const revisions = Database.use((db) =>
      db.select()
        .from(TargetNoteRevisionTable)
        .where(eq(TargetNoteRevisionTable.target_id, workspace.id))
        .orderBy(asc(TargetNoteRevisionTable.time_created), asc(TargetNoteRevisionTable.id))
        .all()
        .map(mapNoteRevision),
    )
    const historyPath = path.join(workspace.workspacePath, "notes-history.md")
    await assertRegularFileOrMissing(historyPath)
    let historyFile = ""
    try {
      historyFile = await fs.readFile(historyPath, "utf-8")
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error
    }
    const historyBase = [
      "# Target Note History",
      "",
      "Immutable snapshots of earlier versions of current investigation notes. The latest living state is in notes.md. Archived revisions remain separate from the active note list so updates do not erase prior reasoning or create duplicate active notes.",
      "",
      "Total archived revisions: " + revisions.length,
      "",
    ].join("\\n")
    const historySections = revisions.map((revision) => [
      "## " + (revision.title ?? "(untitled)") + " — archived " + new Date(revision.timeCreated).toISOString(),
      "",
      "- Revision ID: " + revision.id,
      "- Current note ID: " + revision.noteID,
      "- Kind/status: " + revision.kind + "/" + revision.status,
      "- Source: " + revision.source + (revision.sourceURL ? " — " + revision.sourceURL : ""),
      "- Tags: " + (revision.tags.join(", ") || "(none)"),
      "",
      revision.content,
      "",
      "---",
      "",
    ].join("\\n")).join("\\n")
    const nextHistoryFile = historyBase + historySections
    if (nextHistoryFile !== historyFile) {
      await TargetMemory.writeWorkspaceFile(workspace, "notes-history.md", nextHistoryFile)
    }
  })
}

async function prepareWorkspace(workspace: Workspace, reconcileNotes = true): Promise<void> {
  const root = projectRoot()
  workspace.workspacePath = await ensureSafeDirectoryPath(root, workspace.relativePath)
  for (const directory of TARGET_DIRECTORIES) {
    await ensureSafeDirectoryPath(root, path.join(workspace.relativePath, directory))
  }
  // target.json is retained for compatibility; workspace.json is the canonical
  // manifest consumed by the target workflow and carries stable identity fields.
  await createIfMissing(
    path.join(workspace.workspacePath, "target.json"),
    JSON.stringify(
      {
        schemaVersion: 2,
        targetURL: workspace.targetURL,
        hostname: workspace.hostname,
        slug: workspace.slug,
        parentTargetID: workspace.parentTargetID,
        assetType: workspace.assetType,
        createdAt: new Date(workspace.timeCreated).toISOString(),
      },
      null,
      2,
    ) + "\n",
  )
  await createIfMissing(
    path.join(workspace.workspacePath, "workspace.json"),
    JSON.stringify(
      {
        schemaVersion: 3,
        workspaceID: workspace.id,
        projectID: workspace.projectID,
        targetURL: workspace.targetURL,
        targetKey: workspace.targetKey,
        hostname: workspace.hostname,
        slug: workspace.slug,
        parentTargetID: workspace.parentTargetID,
        assetType: workspace.assetType,
        relativePath: workspace.relativePath,
        createdAt: new Date(workspace.timeCreated).toISOString(),
      },
      null,
      2,
    ) + "\n",
  )
  // Existing workspaces predate hierarchy fields. Reconcile generated identity manifests
  // from SQLite so old `workspace.json` files cannot disagree with the parent/child model.
  const expectedTargetManifest = {
    schemaVersion: 2,
    targetURL: workspace.targetURL,
    hostname: workspace.hostname,
    slug: workspace.slug,
    parentTargetID: workspace.parentTargetID,
    assetType: workspace.assetType,
    createdAt: new Date(workspace.timeCreated).toISOString(),
  }
  const expectedWorkspaceManifest = {
    schemaVersion: 3,
    workspaceID: workspace.id,
    projectID: workspace.projectID,
    targetURL: workspace.targetURL,
    targetKey: workspace.targetKey,
    hostname: workspace.hostname,
    slug: workspace.slug,
    parentTargetID: workspace.parentTargetID,
    assetType: workspace.assetType,
    relativePath: workspace.relativePath,
    createdAt: new Date(workspace.timeCreated).toISOString(),
  }
  const manifests = [
    { file: "target.json", expected: expectedTargetManifest, keys: ["schemaVersion", "targetURL", "hostname", "slug", "parentTargetID", "assetType"] as const },
    { file: "workspace.json", expected: expectedWorkspaceManifest, keys: ["schemaVersion", "workspaceID", "projectID", "targetURL", "targetKey", "hostname", "slug", "parentTargetID", "assetType", "relativePath"] as const },
  ]
  for (const manifest of manifests) {
    const manifestPath = path.join(workspace.workspacePath, manifest.file)
    await assertRegularFileOrMissing(manifestPath)
    let current: Record<string, unknown> | undefined
    try { current = JSON.parse(await fs.readFile(manifestPath, "utf-8")) as Record<string, unknown> }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") current = undefined }
    const expected = manifest.expected as unknown as Record<string, unknown>
    const matches = Boolean(current && manifest.keys.every((key) => current![key] === expected[key]))
    if (!matches) {
      await TargetMemory.writeWorkspaceFile(workspace, manifest.file, JSON.stringify(manifest.expected, null, 2) + "\n")
    }
  }
  const readmePath = path.join(workspace.workspacePath, "README.md")
  await createIfMissing(readmePath, defaultWorkspaceReadme(workspace))
  // Migrate the previous generated secret policy without overwriting human-authored README content.
  const legacyEvidencePolicy = "- Do not store passwords, cookies, bearer tokens, API keys, or other secrets."
  const currentReadme = await fs.readFile(readmePath, "utf-8")
  if (currentReadme.includes(legacyEvidencePolicy)) {
    await TargetMemory.writeWorkspaceFile(
      workspace,
      "README.md",
      currentReadme.replace(
        legacyEvidencePolicy,
        "- Preserve exact discovered values in this private, target-local evidence store when they are relevant evidence or needed for reproduction; mark them as candidates until independently validated.",
      ),
    )
  }
  await createIfMissing(
    path.join(workspace.workspacePath, "scope", "scope.json"),
    JSON.stringify(
      {
        schemaVersion: 1,
        targetURL: workspace.targetURL,
        status: "unconfigured",
        scopeItems: [],
        excludedItems: [],
        authorizationSource: null,
        authorizationReference: null,
        configuredAt: null,
        warning: "No authorization or in-scope assets have been configured. Do not perform active testing until scope is explicitly verified.",
      },
      null,
      2,
    ) + "\n",
  )
  await createIfMissing(
    path.join(workspace.workspacePath, "assets", "registry.json"),
    JSON.stringify({ schemaVersion: 1, targetURL: workspace.targetURL, assets: [] }, null, 2) + "\n",
  )
  await createIfMissing(
    path.join(workspace.workspacePath, "runs", "index.json"),
    JSON.stringify({ schemaVersion: 1, targetURL: workspace.targetURL, runs: [] }, null, 2) + "\n",
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

function mapNoteRevision(row: typeof TargetNoteRevisionTable.$inferSelect): TargetNoteRevision {
  return {
    id: row.id,
    noteID: row.note_id,
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
  }
}

/**
 * Rank persistent notes for limited agent context. Preserve confirmed and disproven
 * conclusions (including useful negative results) while still favoring recent updates.
 * This is context selection only; it never changes the persisted note or its status.
 */
function rankNotesForContext(notes: TargetNote[], limit: number): TargetNote[] {
  const now = Date.now()
  const statusWeight: Record<string, number> = {
    confirmed: 3,
    disproven: 3,
    observed: 2,
    unverified: 1,
  }
  const kindWeight: Record<string, number> = {
    finding: 3,
    evidence: 3,
    lesson: 2,
    research: 2,
    endpoint: 1,
    javascript: 1,
    manual: 0,
    asset: 0,
  }
  return [...notes]
    .sort((a, b) => {
      const score = (note: TargetNote) => {
        const ageDays = Math.max(0, (now - note.timeUpdated) / 86_400_000)
        const recency = 2 / (1 + ageDays / 30)
        return (statusWeight[note.status] ?? 0) * 2 + (kindWeight[note.kind] ?? 0) + recency
      }
      return score(b) - score(a) || b.timeUpdated - a.timeUpdated || a.id.localeCompare(b.id)
    })
    .slice(0, Math.max(0, limit))
}

export namespace TargetMemory {
  export function normalize(input: string): NormalizedTarget {
    return normalizeTarget(input)
  }


  /**
   * Every configured ancestor must authorize the asset, but a program workspace is
   * a policy container, not necessarily a DNS parent. HackerOne programs routinely
   * include unrelated domains; requiring hostname suffixes here rejects valid assets
   * even when the saved scope manifest explicitly includes them.
   */
  async function parentChainAuthorizes(candidate: URL, workspace: Workspace): Promise<boolean> {
    const candidateHref = candidate.origin + "/"
    let current: Workspace | null = workspace
    const visited = new Set<string>()
    while (current) {
      if (visited.has(current.id)) return false
      visited.add(current.id)
      let scope: TargetScope | null
      try { scope = await getScope(current.targetURL) } catch { return false }
      if (!scope || scope.status !== "configured" || scope.scopeItems.length === 0) return false
      // Exclusions always override includes at every configured level.
      if (matchingScopeItems(candidateHref, scope.excludedItems).length) return false
      if (!matchingScopeItems(candidateHref, scope.scopeItems).length) return false
      if (!current.parentTargetID) return true
      const row = Database.use((db) =>
        db.select().from(TargetWorkspaceTable).where(eq(TargetWorkspaceTable.id, current!.parentTargetID!)).get(),
      )
      if (!row || row.project_id !== current.projectID || row.owner_key !== currentOwnerKey()) return false
      current = mapWorkspace(row)
    }
    return false
  }

  /**
   * Select the most-specific authorized DNS ancestor when one exists. Otherwise,
   * allow a root program workspace to own an explicitly scoped, unrelated domain.
   * Matching and exclusions remain authoritative; this does not infer authorization
   * from the workspace's name or from an asset being observed.
   */
  async function findAuthorizedParent(candidateURL: string): Promise<Workspace | null> {
    let candidate: URL
    try { candidate = new URL(candidateURL) } catch { return null }
    if ((candidate.protocol !== "http:" && candidate.protocol !== "https:") || candidate.username || candidate.password) return null
    const candidates = list()
      .filter((workspace) => {
        const base = new URL(workspace.targetURL)
        const isDNSAncestor = candidate.hostname !== base.hostname &&
          candidate.hostname.endsWith("." + base.hostname) &&
          base.pathname === "/"
        // Child workspaces remain tied to their DNS subtree. Only root program
        // workspaces may own explicitly listed domains outside their own hostname.
        return candidate.hostname !== base.hostname && (isDNSAncestor || workspace.parentTargetID === null)
      })
      .sort((a, b) => {
        const aHost = new URL(a.targetURL).hostname
        const bHost = new URL(b.targetURL).hostname
        const aAncestor = candidate.hostname.endsWith("." + aHost)
        const bAncestor = candidate.hostname.endsWith("." + bHost)
        if (aAncestor !== bAncestor) return aAncestor ? -1 : 1
        return bHost.length - aHost.length
      })

    for (const workspace of candidates) {
      let scope: TargetScope | null
      try { scope = await getScope(workspace.targetURL) } catch { return null }
      // Unconfigured intermediate workspaces are not authorization boundaries.
      if (!scope || scope.status !== "configured" || scope.scopeItems.length === 0) continue
      const href = candidate.origin + "/"
      if (matchingScopeItems(href, scope.excludedItems).length) {
        // Never fall back to a broader root when the most-specific matching policy excludes it.
        const isDNSAncestor = candidate.hostname.endsWith("." + new URL(workspace.targetURL).hostname)
        if (isDNSAncestor) return null
        continue
      }
      if (!matchingScopeItems(href, scope.scopeItems).length) {
        // A configured DNS-ancestor policy is a delegation boundary: never fall
        // back to a wider root when that nearer policy does not include the asset.
        const isDNSAncestor = candidate.hostname.endsWith("." + new URL(workspace.targetURL).hostname)
        if (isDNSAncestor) return null
        continue
      }
      if (!await parentChainAuthorizes(candidate, workspace)) {
        const isDNSAncestor = candidate.hostname.endsWith("." + new URL(workspace.targetURL).hostname)
        if (isDNSAncestor) return null
        continue
      }
      return workspace
    }
    return null
  }

  function guessAssetType(hostname: string, requested?: TargetAssetType): TargetAssetType {
    if (requested && requested !== "target") return requested
    if (/^(api|graphql|gateway)([.-]|$)/i.test(hostname)) return "api"
    if (/^(app|www|web|portal|admin)([.-]|$)/i.test(hostname)) return "application"
    return "subdomain"
  }

  /** Keep denormalized workspace_path values synchronized after moving an entire asset subtree. */
  function syncDescendantWorkspacePaths(parent: Workspace): void {
    for (const child of children(parent.id)) {
      Database.use((db) => db.update(TargetWorkspaceTable).set({
        workspace_path: child.relativePath,
        time_updated: Date.now(),
      }).where(eq(TargetWorkspaceTable.id, child.id)).run())
      syncDescendantWorkspacePaths(child)
    }
  }
  /** Detach an asset that is no longer authorized by its former parent, preserving its data. */
  async function detachWorkspace(
    row: typeof TargetWorkspaceTable.$inferSelect,
    parent: Workspace,
  ): Promise<Workspace> {
    if (row.parent_target_id !== parent.id) throw new Error("Cannot detach an asset from a different parent.")
    const oldRelative = workspaceRelativePath(row)
    const standaloneRelative = path.join(".cyberstrike", "targets", normalizeTarget(row.target_url).slug)
    if (path.normalize(oldRelative) !== path.normalize(standaloneRelative)) {
      const oldAbsolute = path.resolve(projectRoot(), oldRelative)
      const standaloneParent = await ensureSafeDirectoryPath(projectRoot(), ".cyberstrike/targets")
      const destination = path.join(standaloneParent, normalizeTarget(row.target_url).slug)
      let oldExists = true
      try {
        const oldInfo = await fs.lstat(oldAbsolute)
        if (oldInfo.isSymbolicLink() || !oldInfo.isDirectory()) throw new Error("Unsafe nested workspace during detach.")
        await ensureSafeDirectoryPath(projectRoot(), oldRelative)
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "ENOENT") oldExists = false
        else throw error
      }
      let destinationExists = true
      try {
        const destinationInfo = await fs.lstat(destination)
        if (destinationInfo.isSymbolicLink() || !destinationInfo.isDirectory()) throw new Error("Unsafe standalone workspace destination.")
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "ENOENT") destinationExists = false
        else throw error
      }
      if (oldExists && destinationExists) throw new Error("Cannot detach asset because both nested and standalone workspace directories exist; no data was overwritten.")
      if (destinationExists && !oldExists) {
        let manifest: { workspaceID?: string } = {}
        try { manifest = JSON.parse(await fs.readFile(path.join(destination, "workspace.json"), "utf-8")) }
        catch { throw new Error("Existing standalone directory cannot be verified as the detached workspace.") }
        if (manifest.workspaceID !== row.id) throw new Error("Standalone destination belongs to another workspace; refusing to overwrite it.")
      }
      if (oldExists && !destinationExists) await fs.rename(oldAbsolute, destination)
    }
    Database.use((db) => db.update(TargetWorkspaceTable).set({
      parent_target_id: null,
      asset_type: "target",
      workspace_path: standaloneRelative,
      time_updated: Date.now(),
    }).where(eq(TargetWorkspaceTable.id, row.id)).run())
    const updated = Database.use((db) => db.select().from(TargetWorkspaceTable).where(eq(TargetWorkspaceTable.id, row.id)).get())
    if (!updated) throw new Error("Detached target workspace disappeared.")
    const workspace = mapWorkspace(updated, standaloneRelative)
    syncDescendantWorkspacePaths(workspace)
    await prepareWorkspace(workspace, false)
    await TargetMemory.writeWorkspaceFile(workspace, "target.json", JSON.stringify({
      schemaVersion: 2, targetURL: workspace.targetURL, hostname: workspace.hostname,
      slug: workspace.slug, parentTargetID: null, assetType: "target",
      createdAt: new Date(workspace.timeCreated).toISOString(),
    }, null, 2) + "\n")
    await TargetMemory.writeWorkspaceFile(workspace, "workspace.json", JSON.stringify({
      schemaVersion: 3, workspaceID: workspace.id, projectID: workspace.projectID,
      targetURL: workspace.targetURL, targetKey: workspace.targetKey, hostname: workspace.hostname,
      slug: workspace.slug, parentTargetID: null, assetType: "target",
      relativePath: workspace.relativePath, createdAt: new Date(workspace.timeCreated).toISOString(),
    }, null, 2) + "\n")
    await syncAssetRegistry(parent)
    return workspace
  }

  /** Move an existing workspace beneath a parent without overwriting or merging its data. */
  async function reparentWorkspace(
    row: typeof TargetWorkspaceTable.$inferSelect,
    parent: Workspace,
    assetType: TargetAssetType,
  ): Promise<Workspace> {
    if (row.id === parent.id) throw new Error("A target cannot be its own parent.")
    let ancestor: string | null = parent.id
    while (ancestor) {
      if (ancestor === row.id) throw new Error("A target cannot be reparented beneath one of its descendants.")
      const next = Database.use((db) =>
        db.select({ parent_target_id: TargetWorkspaceTable.parent_target_id })
          .from(TargetWorkspaceTable).where(eq(TargetWorkspaceTable.id, ancestor!)).get(),
      )
      ancestor = next?.parent_target_id ?? null
    }
    const oldParentID = row.parent_target_id ?? null
    const oldRelative = workspaceRelativePath(row)
    const childSlug = normalizeTarget(row.target_url).slug
    const destinationRelative = path.join(parent.relativePath, "assets", childSlug)
    if (path.normalize(oldRelative) !== path.normalize(destinationRelative)) {
      const oldAbsolute = path.resolve(projectRoot(), oldRelative)
      const destinationParent = await ensureSafeDirectoryPath(projectRoot(), path.join(parent.relativePath, "assets"))
      const destination = path.join(destinationParent, childSlug)
      let oldExists = true
      try {
        const oldInfo = await fs.lstat(oldAbsolute)
        if (oldInfo.isSymbolicLink() || !oldInfo.isDirectory()) throw new Error("Unsafe existing target workspace during hierarchy move.")
        await ensureSafeDirectoryPath(projectRoot(), oldRelative)
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "ENOENT") oldExists = false
        else throw error
      }
      let destinationExists = true
      try {
        const destinationInfo = await fs.lstat(destination)
        if (destinationInfo.isSymbolicLink() || !destinationInfo.isDirectory()) throw new Error("Unsafe destination path for nested target workspace.")
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "ENOENT") destinationExists = false
        else throw error
      }
      if (oldExists && destinationExists) throw new Error("Cannot attach target because both its old and nested workspaces exist; merge them manually to prevent data loss.")
      if (destinationExists && !oldExists) {
        let manifest: { workspaceID?: string } = {}
        try { manifest = JSON.parse(await fs.readFile(path.join(destination, "workspace.json"), "utf-8")) }
        catch { throw new Error("Existing nested directory cannot be verified as this workspace; refusing to reuse it.") }
        if (manifest.workspaceID !== row.id) throw new Error("Existing nested directory belongs to another workspace; refusing to overwrite it.")
      }
      if (oldExists && !destinationExists) await fs.rename(oldAbsolute, destination)
    }

    Database.use((db) => db.update(TargetWorkspaceTable).set({
      parent_target_id: parent.id,
      asset_type: assetType,
      workspace_path: destinationRelative,
      time_updated: Date.now(),
    }).where(eq(TargetWorkspaceTable.id, row.id)).run())
    const updated = Database.use((db) => db.select().from(TargetWorkspaceTable).where(eq(TargetWorkspaceTable.id, row.id)).get())
    if (!updated) throw new Error("Nested target workspace disappeared during reparenting.")
    const workspace = mapWorkspace(updated, destinationRelative)
    syncDescendantWorkspacePaths(workspace)
    await prepareWorkspace(workspace, false)
    await TargetMemory.writeWorkspaceFile(workspace, "target.json", JSON.stringify({
      schemaVersion: 2, targetURL: workspace.targetURL, hostname: workspace.hostname,
      slug: workspace.slug, parentTargetID: workspace.parentTargetID, assetType: workspace.assetType,
      createdAt: new Date(workspace.timeCreated).toISOString(),
    }, null, 2) + "\n")
    await TargetMemory.writeWorkspaceFile(workspace, "workspace.json", JSON.stringify({
      schemaVersion: 3, workspaceID: workspace.id, projectID: workspace.projectID,
      targetURL: workspace.targetURL, targetKey: workspace.targetKey, hostname: workspace.hostname,
      slug: workspace.slug, parentTargetID: workspace.parentTargetID, assetType: workspace.assetType,
      relativePath: workspace.relativePath, createdAt: new Date(workspace.timeCreated).toISOString(),
    }, null, 2) + "\n")
    if (oldParentID && oldParentID !== parent.id) {
      const oldParentRow = Database.use((db) => db.select().from(TargetWorkspaceTable).where(eq(TargetWorkspaceTable.id, oldParentID)).get())
      if (oldParentRow) await syncAssetRegistry(mapWorkspace(oldParentRow))
    }
    await syncAssetRegistry(parent)
    return workspace
  }

  /** Create or open a workspace; authorized discovered assets are nested beneath their parent. */
  export async function ensure(
    input: string,
    options: { reconcileNotes?: boolean; parentTargetURL?: string; assetType?: TargetAssetType } = {},
  ): Promise<Workspace> {
    const normalized = normalizeTarget(input)
    const projectID = Instance.project.id
    const ownerKey = currentOwnerKey()
    let parent: Workspace | null = null
    if (options.parentTargetURL) {
      parent = await get(options.parentTargetURL)
      if (!parent) throw new Error("Parent target workspace does not exist.")
      if (parent.targetKey === normalized.targetKey) throw new Error("A target cannot be its own parent.")
      // Explicit parent selection is an internal convenience, not an authorization
      // bypass. Re-check the candidate against this parent's saved scope and every
      // ancestor before creating or reusing a nested workspace.
      if (!await parentChainAuthorizes(new URL(normalized.targetURL), parent)) {
        throw new Error("The selected parent scope and its ancestors do not authorize this child target.")
      }
    } else {
      parent = await findAuthorizedParent(new URL(normalized.targetURL).origin)
    }
    const requestedAssetType = parent ? guessAssetType(normalized.hostname, options.assetType) : "target"
    const relativePath = parent
      ? path.join(parent.relativePath, "assets", normalized.slug)
      : path.join(".cyberstrike", "targets", normalized.slug)
    const now = Date.now()
    const row = Database.transaction((db) => {
      const existing = db.select().from(TargetWorkspaceTable).where(and(
        eq(TargetWorkspaceTable.project_id, projectID),
        eq(TargetWorkspaceTable.owner_key, ownerKey),
        eq(TargetWorkspaceTable.target_key, normalized.targetKey),
      )).get()
      if (existing) return existing
      db.insert(TargetWorkspaceTable).values({
        id: Identifier.ascending("target_workspace"),
        project_id: projectID, owner_key: ownerKey, target_key: normalized.targetKey,
        target_url: normalized.targetURL, hostname: normalized.hostname, slug: normalized.slug,
        parent_target_id: parent?.id ?? null, asset_type: requestedAssetType,
        workspace_path: relativePath, time_created: now, time_updated: now,
      }).onConflictDoNothing().run()
      const row = db.select().from(TargetWorkspaceTable).where(and(
        eq(TargetWorkspaceTable.project_id, projectID),
        eq(TargetWorkspaceTable.owner_key, ownerKey),
        eq(TargetWorkspaceTable.target_key, normalized.targetKey),
      )).get()
      if (!row) throw new Error("Target workspace could not be persisted.")
      return row
    })
    if (parent && row.parent_target_id !== parent.id) return await reparentWorkspace(row, parent, requestedAssetType)

    // Repeated passive observations may refine a child's classification. Apply an
    // explicit type, or promote a generic subdomain to a hostname-inferred type,
    // but never downgrade a previously specific type just because a later observer
    // did not know the classification.
    let currentRow = row
    if (parent && row.parent_target_id === parent.id) {
      const desiredAssetType = options.assetType && options.assetType !== "target"
        ? options.assetType
        : row.asset_type === "subdomain" && requestedAssetType !== "subdomain"
          ? requestedAssetType
          : row.asset_type
      if (desiredAssetType !== row.asset_type) {
        Database.use((db) => db.update(TargetWorkspaceTable).set({
          asset_type: desiredAssetType,
          time_updated: Date.now(),
        }).where(eq(TargetWorkspaceTable.id, row.id)).run())
        const updated = Database.use((db) =>
          db.select().from(TargetWorkspaceTable).where(eq(TargetWorkspaceTable.id, row.id)).get(),
        )
        if (!updated) throw new Error("Target asset classification update failed.")
        currentRow = updated
      }
    }

    if (!options.parentTargetURL && !parent && row.parent_target_id) {
      const oldParentRow = Database.use((db) =>
        db.select().from(TargetWorkspaceTable).where(eq(TargetWorkspaceTable.id, row.parent_target_id!)).get(),
      )
      if (!oldParentRow) throw new Error("Existing parent workspace is missing; refusing to write an orphaned target.")
      return await detachWorkspace(row, mapWorkspace(oldParentRow))
    }
    const workspace = mapWorkspace(currentRow)
    await prepareWorkspace(workspace, options.reconcileNotes ?? true)
    if (parent) await syncAssetRegistry(parent)
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
        .orderBy(asc(TargetWorkspaceTable.time_created))
        .all()
        .map((row) => mapWorkspace(row)),
    )
  }


  export function children(parentTargetID: string): Workspace[] {
    const projectID = Instance.project.id
    const ownerKey = currentOwnerKey()
    return Database.use((db) => db.select().from(TargetWorkspaceTable).where(and(
      eq(TargetWorkspaceTable.parent_target_id, parentTargetID),
      eq(TargetWorkspaceTable.project_id, projectID),
      eq(TargetWorkspaceTable.owner_key, ownerKey),
    )).orderBy(asc(TargetWorkspaceTable.time_created)).all().map((row) => mapWorkspace(row)))
  }

  async function syncAssetRegistry(parent: Workspace): Promise<void> {
    const assets = children(parent.id)
    const registry = {
      schemaVersion: 2, parentTargetID: parent.id, targetURL: parent.targetURL,
      updatedAt: new Date().toISOString(),
      assets: assets.map((asset) => ({
        workspaceID: asset.id, targetURL: asset.targetURL, hostname: asset.hostname,
        type: asset.assetType,
        relativePath: path.relative(parent.workspacePath, asset.workspacePath).split(path.sep).join("/"),
      })),
    }
    await TargetMemory.writeWorkspaceFile(parent, "assets/registry.json", JSON.stringify(registry, null, 2) + "\n")
    const notesPath = path.join(parent.workspacePath, "notes.md")
    const startMarker = "<!-- cyberstrike-assets:start -->"
    const endMarker = "<!-- cyberstrike-assets:end -->"
    const table = assets.length
      ? ["| Asset | Type | Workspace |", "|---|---|---|", ...assets.map((asset) =>
          "| [" + asset.targetURL.replace(/\|/g, "%7C") + "](" + asset.targetURL + ") | " +
          asset.assetType + " | " + path.relative(parent.workspacePath, asset.workspacePath).split(path.sep).join("/") + " |",
        )]
      : ["No in-scope child assets registered yet."]
    const managed = [startMarker, "", "## Managed Asset Inventory", "", ...table, "", endMarker].join("\n")
    await withNotesMarkdownLock(notesPath, async () => {
      await assertRegularFileOrMissing(notesPath)
      let current = ""
      try { current = await fs.readFile(notesPath, "utf-8") } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error
      }
      const base = current || defaultTargetNotes(parent)
      const from = base.indexOf(startMarker)
      const to = base.indexOf(endMarker, from + startMarker.length)
      const next = from >= 0 && to >= from
        ? base.slice(0, from) + managed + base.slice(to + endMarker.length)
        : base.replace(/\s*$/, "") + "\n\n" + managed + "\n"
      if (next !== current) await TargetMemory.writeWorkspaceFile(parent, "notes.md", next)
    })
  }

  export async function attachAsset(
    parentURL: string,
    assetURL: string,
    assetType?: TargetAssetType,
  ): Promise<{ parent: Workspace; asset: Workspace }> {
    const parent = await get(parentURL)
    if (!parent) throw new Error("Parent workspace not found; initialize the program target first.")
    let candidate: URL
    try { candidate = new URL(assetURL) } catch { throw new Error("Asset URL must be an absolute HTTP(S) URL.") }
    if ((candidate.protocol !== "http:" && candidate.protocol !== "https:") || candidate.username || candidate.password) {
      throw new Error("Asset URL must be credential-free HTTP(S).")
    }
    if (candidate.hostname === parent.hostname) throw new Error("A same-host path belongs in the existing target workspace, not a child asset.")
    if (candidate.pathname !== "/" || candidate.search || candidate.hash) {
      throw new Error("Asset registration is host-level: pass only the origin (scheme and host). Store endpoint paths under that asset.")
    }
    // Validate against the selected parent's persisted policy directly. Do not
    // require global parent discovery to rediscover a caller-selected root: that
    // discovery is useful for passive observations, but can incorrectly reject an
    // explicitly scoped unrelated application in a program's saved manifest.
    const parentScope = await getScope(parent.targetURL)
    const candidateHref = candidate.origin + "/"
    const parentIsRoot = parent.parentTargetID === null
    const isDNSChild = candidate.hostname !== parent.hostname &&
      candidate.hostname.endsWith("." + parent.hostname) &&
      new URL(parent.targetURL).pathname === "/"
    const explicitlyIncluded = !!parentScope &&
      parentScope.status === "configured" &&
      parentScope.scopeItems.length > 0 &&
      matchingScopeItems(candidateHref, parentScope.scopeItems).length > 0
    const explicitlyExcluded = !!parentScope &&
      matchingScopeItems(candidateHref, parentScope.excludedItems).length > 0
    const chainAuthorized = explicitlyIncluded && !explicitlyExcluded &&
      (parentIsRoot || isDNSChild) &&
      await parentChainAuthorizes(candidate, parent)
    if (!chainAuthorized) {
      throw new Error("The asset is not unambiguously authorized by this parent's saved scope; check includes, exclusions, protocol, and port.")
    }
    const asset = await ensure(candidate.origin, { parentTargetURL: parent.targetURL, assetType })
    await syncAssetRegistry(parent)
    return { parent, asset }
  }

  /** Passive observations may be linked to authorized programs, but never trigger probes. */
  export async function registerObservedAsset(input: string, assetType?: TargetAssetType): Promise<Workspace | null> {
    let candidate: URL
    try { candidate = new URL(input) } catch { return null }
    if ((candidate.protocol !== "http:" && candidate.protocol !== "https:") || candidate.username || candidate.password) return null
    const parent = await findAuthorizedParent(candidate.origin)
    if (!parent) return null
    return await ensure(candidate.origin, { parentTargetURL: parent.targetURL, assetType })
  }

  export async function refreshScopedAssets(parentURL: string): Promise<Workspace[]> {
    const parent = await get(parentURL)
    if (!parent) throw new Error("Parent workspace not found.")
    const scope = await getScope(parent.targetURL)
    if (!scope || scope.status !== "configured") throw new Error("Cannot reconcile assets without a configured parent scope.")

    // Reconcile every known workspace against its most-specific parent. In particular,
    // a child scope added later must take ownership of its descendants before the root
    // wildcard can claim them as siblings.
    const candidates = list().filter((item) => item.id !== parent.id)
    const attached: Workspace[] = []
    for (const candidate of candidates) {
      const currentRow = Database.use((db) =>
        db.select().from(TargetWorkspaceTable).where(eq(TargetWorkspaceTable.id, candidate.id)).get(),
      )
      if (!currentRow) continue
      const matchingParent = await findAuthorizedParent(new URL(candidate.targetURL).origin)
      if (matchingParent) {
        if (currentRow.parent_target_id !== matchingParent.id) {
          attached.push(await ensure(candidate.targetURL, {
            parentTargetURL: matchingParent.targetURL,
            assetType: guessAssetType(candidate.hostname, candidate.assetType),
          }))
        }
      } else if (currentRow.parent_target_id) {
        const oldParentRow = Database.use((db) =>
          db.select().from(TargetWorkspaceTable).where(eq(TargetWorkspaceTable.id, currentRow.parent_target_id!)).get(),
        )
        if (oldParentRow) await detachWorkspace(currentRow, mapWorkspace(oldParentRow))
      }
    }
    await syncAssetRegistry(await get(parent.targetURL) ?? parent)
    return attached
  }

  /** Read the target's explicit scope manifest. Missing/corrupt manifests never imply authorization. */
  export async function getScope(input: string): Promise<TargetScope | null> {
    const normalized = normalizeTarget(input)
    const projectID = Instance.project.id
    const ownerKey = currentOwnerKey()
    const row = Database.use((db) =>
      db.select().from(TargetWorkspaceTable).where(and(
        eq(TargetWorkspaceTable.project_id, projectID),
        eq(TargetWorkspaceTable.owner_key, ownerKey),
        eq(TargetWorkspaceTable.target_key, normalized.targetKey),
      )).get(),
    )
    if (!row) return null

    const workspace = mapWorkspace(row)
    const scopePath = path.join(workspace.workspacePath, "scope", "scope.json")
    const notesPath = path.join(workspace.workspacePath, "notes.md")
    const workspaceManifestPath = path.join(workspace.workspacePath, "workspace.json")
    const targetManifestPath = path.join(workspace.workspacePath, "target.json")

    let info = await assertRegularFileOrMissing(scopePath)
    const notesInfo = await assertRegularFileOrMissing(notesPath)
    const workspaceManifestInfo = await assertRegularFileOrMissing(workspaceManifestPath)
    const targetManifestInfo = await assertRegularFileOrMissing(targetManifestPath)

    const identityFieldsMatch = async (
      manifestPath: string,
      info: Awaited<ReturnType<typeof fs.lstat>> | null,
      fields: Record<string, unknown>,
    ): Promise<boolean> => {
      if (!info) return false
      const signature = scopeFileSignature(info)
      const identity = JSON.stringify(fields)
      const cached = identityManifestCache.get(manifestPath)
      if (cached?.signature === signature && cached.identity === identity) {
        identityManifestCache.delete(manifestPath)
        identityManifestCache.set(manifestPath, cached)
        return cached.matches
      }

      let matches = false
      try {
        const parsed: unknown = JSON.parse(await fs.readFile(manifestPath, "utf-8"))
        if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
          matches = Object.entries(fields).every(([key, expected]) => (parsed as Record<string, unknown>)[key] === expected)
        }
      } catch (error) {
        if (!(error instanceof SyntaxError) && (error as NodeJS.ErrnoException).code !== "ENOENT") throw error
      }
      cacheIdentityManifest(manifestPath, { signature, identity, matches })
      return matches
    }

    const [workspaceIdentityMatches, targetIdentityMatches] = await Promise.all([
      identityFieldsMatch(workspaceManifestPath, workspaceManifestInfo, {
        schemaVersion: 3,
        workspaceID: workspace.id,
        projectID: workspace.projectID,
        targetURL: workspace.targetURL,
        targetKey: workspace.targetKey,
        hostname: workspace.hostname,
        slug: workspace.slug,
        parentTargetID: workspace.parentTargetID,
        assetType: workspace.assetType,
        relativePath: workspace.relativePath,
      }),
      identityFieldsMatch(targetManifestPath, targetManifestInfo, {
        schemaVersion: 2,
        targetURL: workspace.targetURL,
        hostname: workspace.hostname,
        slug: workspace.slug,
        parentTargetID: workspace.parentTargetID,
        assetType: workspace.assetType,
      }),
    ])

    const needsRepair =
      !info ||
      !notesInfo ||
      notesInfo.size === 0 ||
      !workspaceManifestInfo ||
      !targetManifestInfo ||
      !workspaceIdentityMatches ||
      !targetIdentityMatches
    if (needsRepair) {
      // Heal missing or stale generated workspace files once, not on every normal scope check.
      await prepareWorkspace(workspace)
      info = await assertRegularFileOrMissing(scopePath)
    }
    if (!info) return null
    const signature = scopeFileSignature(info)
    const cached = scopeManifestCache.get(scopePath)
    if (cached?.signature === signature) {
      // Touch the entry to keep frequently used target scopes resident.
      scopeManifestCache.delete(scopePath)
      scopeManifestCache.set(scopePath, cached)
      return cached.scope
    }

    let source: string
    try {
      source = await fs.readFile(scopePath, "utf-8")
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return null
      throw new Error("Target scope manifest is unreadable or invalid JSON.")
    }
    let afterReadInfo: Awaited<ReturnType<typeof fs.stat>>
    try {
      afterReadInfo = await fs.stat(scopePath)
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return null
      throw error
    }
    if (scopeFileSignature(afterReadInfo) !== signature) {
      throw new Error("Target scope manifest changed while being read; retry the scope check.")
    }

    let parsed: unknown
    try {
      parsed = JSON.parse(source)
    } catch {
      throw new Error("Target scope manifest is unreadable or invalid JSON.")
    }
    if (!parsed || typeof parsed !== "object") throw new Error("Target scope manifest has an invalid shape.")
    const scope = parsed as Partial<TargetScope>
    if (
      scope.schemaVersion !== 1 ||
      scope.targetURL !== workspace.targetURL ||
      !Array.isArray(scope.scopeItems) ||
      !Array.isArray(scope.excludedItems) ||
      (scope.status !== "configured" && scope.status !== "unconfigured")
    ) {
      throw new Error("Target scope manifest identity or schema does not match this workspace.")
    }
    if (scope.status === "configured") {
      const userConfirmedWithoutReference = Boolean(
        scope.authorizationSource?.startsWith(USER_CONFIRMED_SCOPE_SOURCE) && scope.authorizationReference === null,
      )
      if (
        scope.scopeItems.length === 0 ||
        !scope.authorizationSource?.trim() ||
        (!scope.authorizationReference?.startsWith("https://") && !userConfirmedWithoutReference) ||
        !scope.configuredAt ||
        !Number.isFinite(Date.parse(scope.configuredAt))
      ) {
        throw new Error("Configured target scope is missing authorization provenance or a valid configuredAt timestamp.")
      }
      const normalizedInclude = scope.scopeItems.map(normalizeScopeItem)
      const normalizedExclude = scope.excludedItems.map(normalizeScopeItem)
      const normalizedExcludeSet = new Set(normalizedExclude)
      if (
        normalizedInclude.some((item, index) => item !== scope.scopeItems![index]) ||
        normalizedExclude.some((item, index) => item !== scope.excludedItems![index]) ||
        normalizedInclude.some((item) => normalizedExcludeSet.has(item))
      ) {
        throw new Error("Target scope manifest contains non-canonical or contradictory entries.")
      }
      const reference = scope.authorizationReference ? normalizedSourceURL(scope.authorizationReference) : null
      if ((!reference && !userConfirmedWithoutReference) || (reference && reference !== scope.authorizationReference)) {
        throw new Error("Target scope authorization reference is invalid or contains unsafe URL data.")
      }
    }
    const validated = scope as TargetScope
    // The cached manifest is shared by permission checks; freeze its arrays and
    // object so a caller cannot mutate in-memory authorization without changing disk.
    Object.freeze(validated.scopeItems)
    Object.freeze(validated.excludedItems)
    Object.freeze(validated)
    // Avoid retaining obsolete manifests for renamed/replaced files at the same path.
    cacheScopeManifest(scopePath, signature, validated)
    return validated
  }

  /** Configure a scope only with explicit authorization provenance and at least one allowed item. */
  export async function configureScope(
    input: string,
    options: { include: string[]; exclude?: string[]; authorizationSource: string; authorizationReference?: string | null; userConfirmed?: boolean },
  ): Promise<{ workspace: Workspace; scope: TargetScope; associatedAssets: Workspace[] }> {
    const include = [...new Set((options.include ?? []).map(normalizeScopeItem))]
    const exclude = [...new Set((options.exclude ?? []).map(normalizeScopeItem))]
    const suppliedSource = redactTargetNoteLine(options.authorizationSource ?? "", 200)
    const reference = normalizedSourceURL(options.authorizationReference ?? undefined)
    const userConfirmedWithoutReference = options.userConfirmed === true && !options.authorizationReference?.trim()
    const authorizationSource = userConfirmedWithoutReference
      ? suppliedSource.startsWith(USER_CONFIRMED_SCOPE_SOURCE)
        ? suppliedSource
        : suppliedSource ? `${USER_CONFIRMED_SCOPE_SOURCE}: ${suppliedSource}`.slice(0, 200) : USER_CONFIRMED_SCOPE_SOURCE
      : suppliedSource
    if (!include.length) throw new Error("At least one explicitly authorized in-scope item is required.")
    if (!authorizationSource) throw new Error("An authorization source is required (for example, the program name).")
    if ((!reference || !reference.startsWith("https://")) && !userConfirmedWithoutReference) {
      throw new Error("An HTTPS authorization reference is required for policy imports. For a user-confirmed exact asset, set userConfirmed=true and record that conversation-based provenance.")
    }
    if (userConfirmedWithoutReference && (include.length !== 1 || !isExactUserConfirmedScopeItem(include[0]))) {
      throw new Error("User-confirmed scope without an external policy reference must contain exactly one exact hostname, host:port, IP, or HTTP(S) URL; wildcard, CIDR, and typed resource categories require an explicit policy import.")
    }
    const excludeSet = new Set(exclude)
    const overlap = include.filter((item) => excludeSet.has(item))
    if (overlap.length) throw new Error("The same entry cannot be both included and excluded: " + overlap.slice(0, 20).join(", ") + (overlap.length > 20 ? ", ... (showing first 20)" : ""))

    const workspace = await ensure(input)
    const scope: TargetScope = {
      schemaVersion: 1,
      targetURL: workspace.targetURL,
      status: "configured",
      scopeItems: include,
      excludedItems: exclude,
      authorizationSource,
      authorizationReference: reference ?? null,
      configuredAt: new Date().toISOString(),
    }
    await writeWorkspaceFile(workspace, "scope/scope.json", JSON.stringify(scope, null, 2) + "\n")
    // configureScope already canonicalized every entry above; seed the validated cache
    // from the file we just atomically wrote so large imports are not normalized twice.
    const scopePath = path.join(workspace.workspacePath, "scope", "scope.json")
    const scopeInfo = await assertRegularFileOrMissing(scopePath)
    if (!scopeInfo) throw new Error("Configured scope manifest was not persisted: " + scopePath)
    Object.freeze(scope.scopeItems)
    Object.freeze(scope.excludedItems)
    Object.freeze(scope)
    cacheScopeManifest(scopePath, scopeFileSignature(scopeInfo), scope)
    const associatedAssets = await refreshScopedAssets(workspace.targetURL)
    return { workspace, scope, associatedAssets }
  }

  /**
   * Authorize a concrete URL against the most specific target workspace and its
   * persisted scope. Missing, ambiguous, unconfigured, or excluded targets fail closed.
   */
  export async function checkURLScope(candidateURL: string): Promise<{
    allowed: boolean
    reason: string
    workspace?: Workspace
    scope?: TargetScope
    includeMatches: string[]
    excludeMatches: string[]
  }> {
    let candidate: URL
    try {
      candidate = new URL(candidateURL)
    } catch {
      return { allowed: false, reason: "invalid URL", includeMatches: [], excludeMatches: [] }
    }
    if ((candidate.protocol !== "http:" && candidate.protocol !== "https:") || candidate.username || candidate.password) {
      return { allowed: false, reason: "only credential-free HTTP(S) URLs are eligible", includeMatches: [], excludeMatches: [] }
    }

    const candidates: Array<{
      workspace: Workspace
      scope?: TargetScope
      exactHost: boolean
      domainScore: number
      pathScore: number
    }> = []
    for (const workspace of list()) {
      const base = new URL(workspace.targetURL)
      const basePath = base.pathname.replace(/\/+$/, "") || "/"
      const candidatePath = candidate.pathname.replace(/\/+$/, "") || "/"
      const pathMatches = basePath === "/" || candidatePath === basePath || candidatePath.startsWith(basePath + "/")
      if (!pathMatches || base.protocol !== candidate.protocol || base.port !== candidate.port) continue

      const exactHost = base.hostname === candidate.hostname
      let scope: TargetScope | null = null
      try {
        scope = await getScope(workspace.targetURL)
      } catch (error) {
        if (exactHost) {
          return { allowed: false, reason: "the exact target workspace scope manifest is invalid: " + (error instanceof Error ? error.message : String(error)), workspace, includeMatches: [], excludeMatches: [] }
        }
        continue
      }
      const hasScopeMatch = Boolean(scope && scope.status === "configured" &&
        (matchingScopeItems(candidate, scope.scopeItems).length > 0 ||
          matchingScopeItems(candidate, scope.excludedItems).length > 0))
      // Exact-host workspaces always take precedence, including when unconfigured:
      // a different workspace must not authorize around a missing exact-host scope.
      if (!exactHost && !hasScopeMatch) continue
      const domainScore = exactHost ? 10_000 : candidate.hostname.endsWith("." + base.hostname) ? base.hostname.length : 0
      candidates.push({
        workspace,
        scope: scope ?? undefined,
        exactHost,
        domainScore,
        pathScore: basePath === "/" ? 0 : basePath.length,
      })
    }
    candidates.sort((a, b) =>
      Number(b.exactHost) - Number(a.exactHost) ||
      b.domainScore - a.domainScore ||
      b.pathScore - a.pathScore,
    )

    const selected = candidates[0]
    if (!selected) {
      return { allowed: false, reason: "no target workspace and persisted scope match this URL's protocol, port, host, and path boundary", includeMatches: [], excludeMatches: [] }
    }
    if (candidates.length > 1 &&
      Number(candidates[0].exactHost) === Number(candidates[1].exactHost) &&
      candidates[0].domainScore === candidates[1].domainScore &&
      candidates[0].pathScore === candidates[1].pathScore) {
      return { allowed: false, reason: "multiple equally specific target workspaces match; refusing ambiguous scope", includeMatches: [], excludeMatches: [] }
    }

    const ownScope = selected.scope ?? null
    const inheritedScopes: TargetScope[] = []
    const inheritedExclusions: string[] = []
    let parentTargetID = selected.workspace.parentTargetID
    const visitedParents = new Set<string>()
    while (parentTargetID) {
      if (visitedParents.has(parentTargetID)) {
        return { allowed: false, reason: "target hierarchy contains a parent cycle; authorization refused", workspace: selected.workspace, includeMatches: [], excludeMatches: [] }
      }
      visitedParents.add(parentTargetID)
      const parentRow = Database.use((db) =>
        db.select().from(TargetWorkspaceTable).where(eq(TargetWorkspaceTable.id, parentTargetID!)).get(),
      )
      if (!parentRow || parentRow.project_id !== selected.workspace.projectID || parentRow.owner_key !== currentOwnerKey()) {
        return { allowed: false, reason: "parent workspace is missing or belongs to another project; inherited authorization is refused", workspace: selected.workspace, includeMatches: [], excludeMatches: [] }
      }
      let parentScope: TargetScope | null
      try { parentScope = await getScope(parentRow.target_url) } catch {
        return { allowed: false, reason: "parent target scope is invalid; inherited authorization is refused", workspace: selected.workspace, includeMatches: [], excludeMatches: [] }
      }
      if (!parentScope || parentScope.status !== "configured" || parentScope.scopeItems.length === 0) {
        return { allowed: false, reason: "an ancestor target has no configured authorization scope", workspace: selected.workspace, scope: ownScope ?? undefined, includeMatches: [], excludeMatches: [] }
      }
      const excludedByParent = matchingScopeItems(candidate, parentScope.excludedItems)
      if (excludedByParent.length) {
        return { allowed: false, reason: "URL matches parent/ancestor scope exclusion: " + excludedByParent.join(", "), workspace: selected.workspace, scope: ownScope ?? parentScope, includeMatches: [], excludeMatches: excludedByParent }
      }
      if (!matchingScopeItems(candidate, parentScope.scopeItems).length) {
        return { allowed: false, reason: "URL is not included in every ancestor target scope", workspace: selected.workspace, scope: ownScope ?? parentScope, includeMatches: [], excludeMatches: [] }
      }
      inheritedScopes.push(parentScope)
      inheritedExclusions.push(...excludedByParent)
      parentTargetID = parentRow.parent_target_id ?? null
    }
    let scope = ownScope
    if (!scope || scope.status !== "configured") scope = inheritedScopes[0] ?? null
    const parentExclusions = [...new Set(inheritedExclusions)]
    if (parentExclusions.length) {
      return { allowed: false, reason: "URL matches parent/ancestor scope exclusion: " + parentExclusions.join(", "), workspace: selected.workspace, scope: scope ?? undefined, includeMatches: [], excludeMatches: parentExclusions }
    }
    if (!scope || scope.status !== "configured" || scope.scopeItems.length === 0) {
      return { allowed: false, reason: "the most specific target workspace has no configured authorization scope", workspace: selected.workspace, scope: scope ?? undefined, includeMatches: [], excludeMatches: [] }
    }
    const includeMatches = matchingScopeItems(candidate, scope.scopeItems)
    const ownExclusions = matchingScopeItems(candidate, scope.excludedItems)
    const excludeMatches = [...new Set([...ownExclusions, ...parentExclusions])]
    if (excludeMatches.length) {
      return { allowed: false, reason: "URL matches explicit scope exclusion: " + excludeMatches.join(", "), workspace: selected.workspace, scope, includeMatches, excludeMatches }
    }
    if (!includeMatches.length) {
      return { allowed: false, reason: "URL does not match any persisted in-scope item", workspace: selected.workspace, scope, includeMatches, excludeMatches }
    }
    return { allowed: true, reason: "URL matches the persisted scope and target workspace boundary", workspace: selected.workspace, scope, includeMatches, excludeMatches }
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
    const workspace = mapWorkspace(row)
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

  export function notes(targetID: string, limit?: number): TargetNote[] {
    if (!targetIsInCurrentProject(targetID)) return []
    if (limit === undefined || !Number.isFinite(limit)) return allNotes(targetID)
    const boundedLimit = Math.max(0, Math.floor(limit))
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
    const targetKey = normalizeTarget(targetURL).targetKey
    return withTargetNoteWriteLock(targetKey, () => addNoteUnlocked(targetURL, input))
  }

  async function addNoteUnlocked(
    targetURL: string,
    input: NoteInput,
  ): Promise<{ workspace: Workspace; note: TargetNote; created: boolean; updated: boolean }> {
    const suppliedContent = input.content?.trim()
    if (!suppliedContent) throw new Error("Note content cannot be empty.")
    const identityKey = input.identityKey?.trim()
    if (identityKey && !/^[a-zA-Z0-9:._/-]{1,160}$/.test(identityKey)) {
      throw new Error("Note identityKey may contain only letters, numbers, colon, dot, underscore, slash, or hyphen.")
    }
    const identityMarker = identityKey ? "<!-- cyberstrike-note-identity:" + identityKey + " -->" : ""
    const rawContent = identityMarker && !suppliedContent.includes(identityMarker)
      ? suppliedContent + "\n\n" + identityMarker
      : suppliedContent
    const rawEvidence = input.evidence?.trim()
    const requestedStatus = input.status ?? "observed"
    if ((requestedStatus === "confirmed" || requestedStatus === "disproven") && !rawEvidence) {
      throw new Error("Confirmed/disproven target notes require concrete evidence. Use observed or unverified when evidence is incomplete.")
    }
    const combinedContent = rawContent + (rawEvidence ? "\n\nEvidence: " + rawEvidence : "")
    const content = combinedContent
    // This is a private, target-local evidence store. Preserve exact observed values so the
    // operator can reproduce and validate the finding; never mirror raw evidence into global research.

    const workspace = await ensure(targetURL, { reconcileNotes: false })
    const kind = input.kind ?? "manual"
    const rawTitle = input.title?.trim()
    const title = rawTitle ? redactTargetNoteLine(rawTitle) || null : null
    const now = Date.now()
    const source = redactTargetNoteLine((input.source?.trim() || "manual"), 120) || "manual"
    const sourceURL = normalizedSourceURL(input.sourceURL ? redactTargetNoteSecrets(input.sourceURL) : undefined)
    const statusForInsert = input.status ?? "observed"
    const tags = [...new Set((input.tags ?? []).map((tag) => redactTargetNoteLine(tag).trim()).filter(Boolean))]
    // Provenance is part of note identity, so identical lessons from distinct sources do not erase attribution.
    const contentHash = createHash("sha256")
      .update([kind, title ?? "", source, sourceURL ?? "", content].join("\0"))
      .digest("hex")

    if (input.upsertByIdentity) {
      const existing = Database.use((db) => {
        // A stable investigation identity must survive agent/model changes. When an identity
        // key is supplied, search across provenance sources within this target and note kind;
        // otherwise preserve the older title + source + URL deduplication behavior.
        const base = db.select().from(TargetNoteTable).where(and(
          eq(TargetNoteTable.target_id, workspace.id),
          eq(TargetNoteTable.kind, kind),
        )).orderBy(desc(TargetNoteTable.time_updated)).all()
        if (identityKey) {
          const legacyIdentity = identityKey.startsWith("finding:") ? "Finding ID: " + identityKey.slice("finding:".length) : undefined
          return base.find((row) =>
            row.content.includes(identityMarker) ||
            Boolean(legacyIdentity && row.content.includes(legacyIdentity)),
          )
        }
        return base.find((row) =>
          row.source === source &&
          (title ? row.title === title : row.title === null) &&
          (sourceURL ? row.source_url === sourceURL : row.source_url === null),
        )
      })
      if (existing) {
        const existingTags = (existing.tags as string[] | null) ?? []
        const nextStatus = input.status ?? existing.status
        const nextTags = input.tags === undefined ? existingTags : tags
        const changed =
          existing.title !== title ||
          existing.source !== source ||
          existing.source_url !== (sourceURL ?? null) ||
          existing.content !== content ||
          existing.content_hash !== contentHash ||
          nextStatus !== existing.status ||
          JSON.stringify(nextTags) !== JSON.stringify(existingTags)
        const row = changed
          ? Database.transaction((db) => {
              // Keep the prior complete state before changing the living note. A unique
              // revision fingerprint avoids duplicate archives if an update is retried.
              const previousTags = (existing.tags as string[] | null) ?? []
              const revisionHash = createHash("sha256")
                .update([
                  existing.content_hash,
                  existing.title ?? "",
                  existing.source,
                  existing.source_url ?? "",
                  existing.status,
                  JSON.stringify(previousTags),
                ].join("\0"))
                .digest("hex")
              db.insert(TargetNoteRevisionTable).values({
                id: Identifier.ascending("target_note"),
                note_id: existing.id,
                target_id: existing.target_id,
                kind: existing.kind,
                title: existing.title,
                content: existing.content,
                source: existing.source,
                source_url: existing.source_url,
                content_hash: revisionHash,
                status: existing.status,
                tags: previousTags,
                time_created: now,
              }).onConflictDoNothing().run()
              return db.update(TargetNoteTable).set({
                title,
                source,
                source_url: sourceURL ?? null,
                content,
                content_hash: contentHash,
                status: nextStatus,
                tags: nextTags,
                time_updated: now,
              }).where(eq(TargetNoteTable.id, existing.id)).returning().get() ?? existing
            })
          : existing
        const note = mapNote(row)
        await syncTargetNotesMarkdown(workspace)
        return { workspace, note, created: false, updated: changed }
      }
    }

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
      db.select().from(TargetWorkspaceTable).where(and(
        eq(TargetWorkspaceTable.id, workspace.id),
        eq(TargetWorkspaceTable.project_id, activeProjectID),
        eq(TargetWorkspaceTable.owner_key, ownerKey),
      )).get(),
    )
    const expectedRelativePath = workspaceRecord ? workspaceRelativePath(workspaceRecord) : ""
    if (
      workspace.projectID !== activeProjectID ||
      !workspaceRecord ||
      workspaceRecord.target_key !== normalizedTarget.targetKey ||
      workspace.parentTargetID !== (workspaceRecord.parent_target_id ?? null) ||
      workspace.assetType !== (workspaceRecord.asset_type ?? "target") ||
      path.normalize(workspace.relativePath) !== path.normalize(expectedRelativePath)
    ) {
      throw new Error("Workspace output target does not belong to the active project or has mismatched hierarchy identity.")
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

  /** Read immutable revisions for a workspace, optionally narrowed to one current note. */
  export function noteRevisions(
    targetID: string,
    noteID?: string,
    offset = 0,
    limit?: number,
  ): TargetNoteRevision[] {
    if (!targetIsInCurrentProject(targetID)) return []
    const rows = Database.use((db) => {
      const query = db.select().from(TargetNoteRevisionTable)
        .where(and(
          eq(TargetNoteRevisionTable.target_id, targetID),
          ...(noteID ? [eq(TargetNoteRevisionTable.note_id, noteID)] : []),
        ))
        .orderBy(asc(TargetNoteRevisionTable.time_created), asc(TargetNoteRevisionTable.id))
        .all()
      return query.map(mapNoteRevision)
    })
    const start = Math.max(0, Math.floor(Number.isFinite(offset) ? offset : 0))
    return limit === undefined || !Number.isFinite(limit)
      ? rows.slice(start)
      : rows.slice(start, start + Math.max(0, Math.floor(limit)))
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

  /** Collect observed request/asset URLs from a session tree without crossing project boundaries. */
function sessionObservedURLs(sessionID: string): string[] | undefined {
  const projectID = Instance.project.id
  const rootSessionExists = Database.use((db) =>
    db.select({ id: SessionTable.id }).from(SessionTable)
      .where(and(eq(SessionTable.id, sessionID), eq(SessionTable.project_id, projectID))).get(),
  )
  if (!rootSessionExists) return undefined

  const sessionIDs = new Set<string>([sessionID])
  let frontier = [sessionID]
  while (frontier.length > 0) {
    const children = Database.use((db) => {
      const discovered: string[] = []
      for (let offset = 0; offset < frontier.length; offset += 500) {
        const parentIDs = frontier.slice(offset, offset + 500)
        discovered.push(
          ...db.select({ id: SessionTable.id }).from(SessionTable)
            .where(and(eq(SessionTable.project_id, projectID), inArray(SessionTable.parent_id, parentIDs)))
            .all().map((row) => row.id),
        )
      }
      return [...new Set(discovered)].filter((id) => !sessionIDs.has(id))
    })
    for (const child of children) sessionIDs.add(child)
    frontier = children
  }
  const orderedIDs = [...sessionIDs]
  const requests = Database.use((db) => {
    const rows: Array<{ host: string | null; origin: string | null; normalizedPath: string; pageURL: string | null }> = []
    for (let offset = 0; offset < orderedIDs.length; offset += 500) {
      const ids = orderedIDs.slice(offset, offset + 500)
      rows.push(
        ...db.select({
          host: RequestTable.host,
          origin: RequestTable.origin,
          normalizedPath: RequestTable.normalized_path,
          pageURL: RequestTable.page_url,
        }).from(RequestTable).where(inArray(RequestTable.session_id, ids)).all(),
      )
    }
    return rows
  })
  const assets = Database.use((db) => {
    const rows: string[] = []
    for (let offset = 0; offset < orderedIDs.length; offset += 500) {
      const ids = orderedIDs.slice(offset, offset + 500)
      rows.push(
        ...db.select({ asset: IntelEntryTable.asset }).from(IntelEntryTable)
          .where(inArray(IntelEntryTable.session_id, ids)).all().map((row) => row.asset),
      )
    }
    return rows
  })
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
  return observedURLs
}

/** True when this session tree has observed a URL matching this existing target workspace. */
export function isObservedInSession(sessionID: string, targetURL: string): boolean {
  const observedURLs = sessionObservedURLs(sessionID)
  if (!observedURLs) return false
  const normalized = normalizeTarget(targetURL)
  return observedURLs.some((observed) => targetObservationMatches(normalized.targetURL, observed))
}

/**
 * Permit a notes read on an ancestor workspace only when the same session tree
 * observed a registered descendant whose parent chain reaches that workspace.
 * This allows resumable parent/ancestor memory without opening unrelated siblings.
 */
export function isObservedOrAncestorInSession(sessionID: string, targetURL: string): boolean {
  const normalized = normalizeTarget(targetURL)
  const projectID = Instance.project.id
  const ownerKey = currentOwnerKey()
  const targetRow = Database.use((db) =>
    db.select().from(TargetWorkspaceTable).where(and(
      eq(TargetWorkspaceTable.project_id, projectID),
      eq(TargetWorkspaceTable.owner_key, ownerKey),
      eq(TargetWorkspaceTable.target_key, normalized.targetKey),
    )).get(),
  )
  if (!targetRow) return false

  const observedURLs = sessionObservedURLs(sessionID)
  if (!observedURLs) return false
  if (observedURLs.some((observed) => targetObservationMatches(normalized.targetURL, observed))) return true

  const workspaces = Database.use((db) =>
    db.select().from(TargetWorkspaceTable).where(and(
      eq(TargetWorkspaceTable.project_id, projectID),
      eq(TargetWorkspaceTable.owner_key, ownerKey),
    )).all(),
  )
  const byID = new Map(workspaces.map((workspace) => [workspace.id, workspace]))
  const observedWorkspaceIDs = new Set(
    workspaces
      .filter((workspace) => observedURLs.some((observed) => targetObservationMatches(workspace.target_url, observed)))
      .map((workspace) => workspace.id),
  )
  for (const observedID of observedWorkspaceIDs) {
    let current = byID.get(observedID)
    const visited = new Set<string>()
    while (current?.parent_target_id) {
      if (visited.has(current.id)) break
      visited.add(current.id)
      if (current.parent_target_id === targetRow.id) return true
      const parent = byID.get(current.parent_target_id)
      if (!parent || parent.project_id !== projectID || parent.owner_key !== ownerKey) break
      current = parent
    }
  }
  return false
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
      const children = Database.use((db) => {
        const discovered: string[] = []
        // SQLite bind parameters are finite; query in small batches without imposing
        // a maximum number of child sessions or dropping any IDs.
        for (let offset = 0; offset < frontier.length; offset += 500) {
          const parentIDs = frontier.slice(offset, offset + 500)
          discovered.push(
            ...db
              .select({ id: SessionTable.id })
              .from(SessionTable)
              .where(and(eq(SessionTable.project_id, projectID), inArray(SessionTable.parent_id, parentIDs)))
              .all()
              .map((row) => row.id),
          )
        }
        return [...new Set(discovered)].filter((id) => !relatedSessionIDs.has(id))
      })
      for (const child of children) relatedSessionIDs.add(child)
      frontier = children
    }

    const sessionIDs = [...relatedSessionIDs]
    const requests = Database.use((db) => {
      const rows: Array<{ host: string | null; origin: string | null; normalizedPath: string; pageURL: string | null }> = []
      for (let offset = 0; offset < sessionIDs.length; offset += 500) {
        const ids = sessionIDs.slice(offset, offset + 500)
        rows.push(
          ...db
            .select({
              host: RequestTable.host,
              origin: RequestTable.origin,
              normalizedPath: RequestTable.normalized_path,
              pageURL: RequestTable.page_url,
            })
            .from(RequestTable)
            .where(inArray(RequestTable.session_id, ids))
            .all(),
        )
      }
      return rows
    })
    const intelAssets = Database.use((db) => {
      const rows: string[] = []
      for (let offset = 0; offset < sessionIDs.length; offset += 500) {
        const ids = sessionIDs.slice(offset, offset + 500)
        rows.push(
          ...db
            .select({ asset: IntelEntryTable.asset })
            .from(IntelEntryTable)
            .where(inArray(IntelEntryTable.session_id, ids))
            .all()
            .map((row) => row.asset),
        )
      }
      return rows
    })
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
          workspace: mapWorkspace(row),
          hostScore: new URL(normalized.targetURL).origin.length,
          pathScore: targetPath === "/" ? 0 : targetPath.length,
        }
      })
      .filter((item): item is { workspace: Workspace; hostScore: number; pathScore: number } => !!item)
      .sort((a, b) => b.pathScore - a.pathScore || b.hostScore - a.hostScore)

    const selected = matched[0]?.workspace
    if (!selected) return null

    // Build the selected asset's ancestor chain from rows in this project/owner only.
    // This gives the agent the program context while keeping the selected asset's notes
    // separate from its siblings' notes.
    const lineage: Workspace[] = [selected]
    const lineageIDs = new Set<string>([selected.id])
    let parentTargetID = selected.parentTargetID
    while (parentTargetID) {
      if (lineageIDs.has(parentTargetID)) break
      const parentRow = workspaces.find((row) => row.id === parentTargetID)
      if (!parentRow || parentRow.project_id !== projectID || parentRow.owner_key !== ownerKey) break
      const parentWorkspace = mapWorkspace(parentRow)
      lineage.unshift(parentWorkspace)
      lineageIDs.add(parentWorkspace.id)
      parentTargetID = parentWorkspace.parentTargetID
    }
    const programRoot = lineage[0] ?? selected

    const noteLimit = Number.isFinite(maxNotes) ? Math.max(0, Math.floor(maxNotes)) : 8
    // Fetch the full small target-local note set before ranking; applying LIMIT in SQL
    // first would discard older but still critical confirmed/disproven conclusions.
    const selectedAssetNotes = Database.use((db) =>
      db
        .select()
        .from(TargetNoteTable)
        .where(eq(TargetNoteTable.target_id, selected.id))
        .all()
        .map(mapNote),
    )
    // Keep the living investigation notes and the append-only experiment history distinct.
    // The ranked summary set must not crowd out the recent journal when a session resumes.
    const allJournalNotes = selectedAssetNotes
      .filter((note) => note.tags.includes("journal"))
      .sort((a, b) => b.timeCreated - a.timeCreated || b.id.localeCompare(a.id))
    const journalNotes = allJournalNotes.slice(0, noteLimit)
    const omittedJournalNoteCount = Math.max(0, allJournalNotes.length - journalNotes.length)
    // A journal entry is never reclassified as a living summary just because it is older
    // than the current prompt budget. Omitted history remains available to target_notes_read.
    const currentAssetNotes = selectedAssetNotes.filter((note) => !note.tags.includes("journal"))
    const primaryNotes = rankNotesForContext(currentAssetNotes, noteLimit)
    const omittedPrimaryNoteCount = Math.max(0, currentAssetNotes.length - primaryNotes.length)
    const parentNoteInventory = programRoot.id === selected.id
      ? []
      : Database.use((db) =>
          db
            .select()
            .from(TargetNoteTable)
            .where(eq(TargetNoteTable.target_id, programRoot.id))
            .all()
            .map(mapNote),
        )
    const parentCurrentInventory = parentNoteInventory.filter((note) => !note.tags.includes("journal"))
    const parentJournalInventory = parentNoteInventory
      .filter((note) => note.tags.includes("journal"))
      .sort((a, b) => b.timeCreated - a.timeCreated || b.id.localeCompare(a.id))
    const parentNotes = rankNotesForContext(parentCurrentInventory, noteLimit)
    const parentJournalNotes = parentJournalInventory.slice(0, noteLimit)
    const omittedParentNoteCount = Math.max(0, parentCurrentInventory.length - parentNotes.length)
    const omittedParentJournalCount = Math.max(0, parentJournalInventory.length - parentJournalNotes.length)
    // Include useful memory from intermediate ancestors too. Without this, a nested
    // API asset could inherit only root notes and its own notes while missing the
    // immediate service/application context that explains its trust boundary.
    const intermediateIDs = lineage
      .filter((item) => item.id !== programRoot.id && item.id !== selected.id)
      .map((item) => item.id)
    const ancestorNoteInventory = intermediateIDs.length === 0
      ? []
      : Database.use((db) => {
          // Keep every ancestor note while staying under SQLite's bind-parameter budget.
          const notes: TargetNote[] = []
          for (let offset = 0; offset < intermediateIDs.length; offset += 500) {
            const ids = intermediateIDs.slice(offset, offset + 500)
            notes.push(
              ...db
                .select()
                .from(TargetNoteTable)
                .where(inArray(TargetNoteTable.target_id, ids))
                .all()
                .map(mapNote),
            )
          }
          return notes
        })
    const ancestorCurrentInventory = ancestorNoteInventory.filter((note) => !note.tags.includes("journal"))
    const ancestorJournalInventory = ancestorNoteInventory
      .filter((note) => note.tags.includes("journal"))
      .sort((a, b) => b.timeCreated - a.timeCreated || b.id.localeCompare(a.id))
    const ancestorNotes = rankNotesForContext(ancestorCurrentInventory, noteLimit)
    const ancestorJournalNotes = ancestorJournalInventory.slice(0, noteLimit)
    const omittedAncestorNoteCount = Math.max(0, ancestorCurrentInventory.length - ancestorNotes.length)
    const omittedAncestorJournalCount = Math.max(0, ancestorJournalInventory.length - ancestorJournalNotes.length)
    const omittedNoteCount =
      omittedPrimaryNoteCount + omittedJournalNoteCount +
      omittedParentNoteCount + omittedParentJournalCount +
      omittedAncestorNoteCount + omittedAncestorJournalCount

    // Walk the entire registered asset tree iteratively: no arbitrary asset-count or
    // nesting-depth truncation, and the visited set makes malformed cycles harmless.
    const hierarchyLines: string[] = []
    const treeVisited = new Set<string>()
    const pendingAssets: Array<{ workspace: Workspace; depth: number; root: boolean }> = [
      { workspace: programRoot, depth: 0, root: true },
    ]
    while (pendingAssets.length) {
      const current = pendingAssets.pop()!
      if (treeVisited.has(current.workspace.id)) continue
      treeVisited.add(current.workspace.id)
      if (!current.root) {
        hierarchyLines.push(
          "  ".repeat(current.depth) + "- [" + current.workspace.assetType + "] " + current.workspace.targetURL +
          " | workspace: " + path.relative(programRoot.workspacePath, current.workspace.workspacePath).split(path.sep).join("/"),
        )
      }
      let items: Workspace[] = []
      try {
        items = children(current.workspace.id)
      } catch {
        hierarchyLines.push("  ".repeat(current.depth + 1) + "[asset inventory unavailable for this node]")
        continue
      }
      // Reverse push preserves the existing child order during depth-first traversal.
      for (let index = items.length - 1; index >= 0; index--) {
        pendingAssets.push({ workspace: items[index]!, depth: current.depth + 1, root: false })
      }
    }

    // Bound the selected-note portion independently of maxNotes. Callers may request
    // up to 20 notes, so a fixed per-note excerpt could consume the whole context budget
    // before parent memory and the asset inventory are emitted.
    const primaryNoteContentLimit = Math.min(
      1100,
      Math.max(250, Math.floor(8500 / Math.max(1, primaryNotes.length))),
    )
    const sections = [
      "## Target Workspace Context (project-scoped)",
      "",
      "Program/root target: " + programRoot.targetURL,
      "Program workspace ID: " + programRoot.id,
      "Program workspace: " + programRoot.relativePath,
      "Selected asset: " + selected.targetURL + " [" + selected.assetType + "]",
      "Selected workspace ID: " + selected.id,
      "Selected workspace: " + selected.relativePath,
      "Ancestor chain: " + lineage.map((item) => item.targetURL).join(" -> "),
      "Selected authorization manifest: " + path.join(selected.relativePath, "scope", "scope.json"),
      "Before any active request, verify the selected asset's saved scope against the official program policy. Every ancestor scope and exclusion also applies. If any manifest is missing, unconfigured, invalid, ambiguous, or excludes the URL, stop; never infer authorization from a target URL or discovery alone.",
      "Reuse the run's saved setup scope_check decision for the canonical target/workspace; do not call scope_check again for each selected asset, URL, or request. Active browser crawling, web_recon, http_replay, http_replay_raw, and inject_probe must enforce the persisted scope internally for every outbound URL, including exclusions and ancestor scopes.",
      "Memory completeness: this is a prioritized context preview, not proof that omitted notes or assets do not exist. Use target_notes_read to search and page through saved notes before concluding that a prior observation or experiment is absent.",
      ...(omittedNoteCount > 0 ? [
        "PARTIAL NOTE SELECTION: " + omittedPrimaryNoteCount + " selected-asset current notes, " + omittedJournalNoteCount + " selected-asset journal entries, " + omittedParentNoteCount + " program/root current notes, " + omittedParentJournalCount + " program/root journal entries, " + omittedAncestorNoteCount + " intermediate-ancestor current notes, and " + omittedAncestorJournalCount + " intermediate-ancestor journal entries were not included in this prompt. They remain saved. Read each omitted workspace separately using target_notes_read with target_url values: " + [selected.targetURL, ...(programRoot.id === selected.id ? [] : [programRoot.targetURL]), ...lineage.filter((item) => item.id !== programRoot.id && item.id !== selected.id).map((item) => item.targetURL)].join(", ") + ". Page through results until has_more_notes is false; set include_history=true for current-note revisions.",
      ] : []),
      "Keep endpoint/request/finding/evidence files inside the selected asset's workspace. Keep program summaries in the program/root workspace. Do not copy one asset's full notes or findings into a sibling's workspace.",
      "",
      // The active asset's ranked memory is deliberately emitted before inventories:
      // the final context-size guard must never spend the entire budget on an asset tree
      // and silently discard the observations needed to resume the current investigation.
      ...(primaryNotes.length ? ["## Selected asset memory (current investigation notes)", "", ...primaryNotes.flatMap((note) => [
        "### [" + note.status + "/" + note.kind + "] " + (note.title ?? "(untitled)") + " — note_id: " + note.id,
        "Source: " + note.source + (note.sourceURL ? " — " + note.sourceURL : ""),
        note.content.slice(0, primaryNoteContentLimit) + (note.content.length > primaryNoteContentLimit ? "\n[Note excerpt only; read the full note by note_id with target_notes_read.]" : ""),
        "",
      ])] : []),
      ...(journalNotes.length ? ["## Recent investigation journal (append-only history; newest first)", "", ...journalNotes.flatMap((note) => [
        "### " + (note.title ?? "(untitled)") + " [" + new Date(note.timeCreated).toISOString().replace("T", " ").slice(0, 19) + " UTC] — note_id: " + note.id,
        "Source: " + note.source + (note.sourceURL ? " — " + note.sourceURL : ""),
        note.content.slice(0, 700) + (note.content.length > 700 ? "\n[Journal excerpt only; retrieve remaining content with target_notes_read.]" : ""),
        "",
      ])] : []),
      ...(parentNotes.length ? ["## Program/root memory (current summary notes)", "", ...parentNotes.flatMap((note) => [
        "### [" + note.status + "/" + note.kind + "] " + (note.title ?? "(untitled)") + " — note_id: " + note.id,
        "Source: " + note.source + (note.sourceURL ? " — " + note.sourceURL : ""),
        note.content.slice(0, 550) + (note.content.length > 550 ? "\n[Note excerpt only; read the full note by note_id with target_notes_read.]" : ""),
        "",
      ])] : []),
      ...(parentJournalNotes.length ? ["## Program/root investigation journal (newest first)", "", ...parentJournalNotes.flatMap((note) => [
        "### " + (note.title ?? "(untitled)") + " — note_id: " + note.id + " [" + new Date(note.timeCreated).toISOString() + "]",
        "Source: " + note.source + (note.sourceURL ? " — " + note.sourceURL : ""),
        note.content.slice(0, 550) + (note.content.length > 550 ? "\n[Journal excerpt only; read the full note by note_id with target_notes_read.]" : ""),
        "",
      ])] : []),
      ...(ancestorNotes.length ? ["## Intermediate ancestor memory (current summary notes)", "", ...ancestorNotes.flatMap((note) => [
        "### [" + note.status + "/" + note.kind + "] " + (note.title ?? "(untitled)") + " — note_id: " + note.id,
        "Source: " + note.source + (note.sourceURL ? " — " + note.sourceURL : ""),
        note.content.slice(0, 550) + (note.content.length > 550 ? "\n[Note excerpt only; read the full note by note_id with target_notes_read.]" : ""),
        "",
      ])] : []),
      ...(ancestorJournalNotes.length ? ["## Intermediate ancestor journal (newest first)", "", ...ancestorJournalNotes.flatMap((note) => [
        "### " + (note.title ?? "(untitled)") + " — note_id: " + note.id + " [" + new Date(note.timeCreated).toISOString() + "]",
        "Source: " + note.source + (note.sourceURL ? " — " + note.sourceURL : ""),
        note.content.slice(0, 550) + (note.content.length > 550 ? "\n[Journal excerpt only; read the full note by note_id with target_notes_read.]" : ""),
        "",
      ])] : []),
      "",
      "## Registered program asset tree",
      ...(hierarchyLines.length ? hierarchyLines : ["No authorized child assets are currently registered."]),
      "",
      "Expected artifact areas per workspace: scope, assets, recon, urls, requests, javascript, endpoints, testing, findings, evidence, reports, scans, runs, logs, sessions, research.",
    ]
    const context = sections.join("\n")
    const contextLimit = 18_000
    if (context.length <= contextLimit) return context
    return context.slice(0, contextLimit - 500) + "\n\n[PARTIAL TARGET CONTEXT: this is a preview, not the complete note or asset inventory. Do not infer that omitted notes/assets do not exist. Use target_notes_read to search and page through saved notes, open the selected workspace notes.md/artifacts for full details, and continue asset inventory from the workspace database.]"
  }
}
