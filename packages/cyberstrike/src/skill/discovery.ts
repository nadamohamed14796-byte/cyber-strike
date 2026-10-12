import path from "path"
import { lstat, mkdir, realpath } from "node:fs/promises"
import { lookup } from "node:dns/promises"
import { isIP } from "node:net"
import * as tar from "tar"
import { Log } from "../util/log"
import { Global } from "../global"

export namespace Discovery {
  const log = Log.create({ service: "skill-discovery" })

  type IndexSkill = {
    name: string
    description: string
  } & ({ files: string[] } | { type: "skill-md" | "archive"; url: string; digest?: string })

  type Index = {
    skills: IndexSkill[]
  }

  /**
   * Skill names become cache-directory names. Keep them to a single portable
   * path component so a registry cannot redirect writes outside the skill cache.
   */
  export function isSafeSkillName(name: unknown): name is string {
    return typeof name === "string" && /^[a-z0-9][a-z0-9._-]{0,127}$/i.test(name)
  }

  /**
   * Resolve an untrusted file name under its skill root. Registry file entries
   * must be relative paths, never URLs, drive paths, absolute paths, or paths
   * containing parent-directory components.
   */
  export function resolveSkillFilePath(root: string, file: unknown): string | undefined {
    if (typeof file !== "string" || file.length === 0 || file.includes(String.fromCharCode(0))) return undefined

    // Treat Windows separators as separators on every host OS; otherwise a
    // Windows-style traversal string could pass validation on Unix.
    const normalized = file.replace(/\\/g, "/")
    if (
      normalized.startsWith("/") ||
      /^[a-z][a-z0-9+.-]*:/i.test(normalized) ||
      normalized.split("/").some((part) => part === "..")
    ) {
      return undefined
    }

    const resolvedRoot = path.resolve(root)
    const destination = path.resolve(resolvedRoot, normalized)
    const relative = path.relative(resolvedRoot, destination)
    if (!relative || relative === ".." || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
      return undefined
    }

    return destination
  }

  export function dir() {
    return path.join(Global.Path.cache, "skills")
  }

  const safeArchiveTypes = new Set(["File", "Directory", "OldFile", "ContiguousFile"])

  /** Reject archive paths outside the skill root and all archive-created links. */
  export function isSafeArchiveEntry(root: string, file: unknown, type: string): boolean {
    if (!safeArchiveTypes.has(type)) return false
    if ((file === "." || file === "./") && type === "Directory") return true
    return Boolean(resolveSkillFilePath(root, file))
  }

  async function safeCacheDestination(
    root: string,
    destination: string,
    createParents: boolean,
    allowDirectory = false,
  ): Promise<string | undefined> {
    try {
      const lexicalRoot = path.resolve(root)
      const relative = path.relative(lexicalRoot, path.resolve(destination))
      if (!relative || relative === ".." || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) return undefined
      await mkdir(lexicalRoot, { recursive: true })
      const rootStat = await lstat(lexicalRoot)
      if (rootStat.isSymbolicLink() || !rootStat.isDirectory()) return undefined
      const realRoot = await realpath(lexicalRoot)
      const finalPath = path.resolve(realRoot, relative)
      const realRelative = path.relative(realRoot, finalPath)
      if (!realRelative || realRelative === ".." || realRelative.startsWith(`..${path.sep}`) || path.isAbsolute(realRelative)) return undefined

      const parts = realRelative.split(path.sep)
      let current = realRoot
      for (const part of parts.slice(0, -1)) {
        current = path.join(current, part)
        let stat
        try {
          stat = await lstat(current)
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code !== "ENOENT") return undefined
          if (!createParents) return finalPath
          try { await mkdir(current) } catch (mkdirError) {
            if ((mkdirError as NodeJS.ErrnoException).code !== "EEXIST") return undefined
          }
          try { stat = await lstat(current) } catch { return undefined }
        }
        if (stat.isSymbolicLink() || !stat.isDirectory()) return undefined
      }
      try {
        const stat = await lstat(finalPath)
        if (stat.isSymbolicLink() || !(stat.isFile() || (allowDirectory && stat.isDirectory()))) return undefined
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") return undefined
      }
      return finalPath
    } catch {
      return undefined
    }
  }

  async function extractSafeArchive(archive: string, root: string, budget: ResourceBudget): Promise<boolean> {
    await mkdir(root, { recursive: true })
    const rootStat = await lstat(root)
    if (rootStat.isSymbolicLink() || !rootStat.isDirectory()) return false
    const realRoot = await realpath(root)
    const entries: Array<{ path: string; type: string; size: number }> = []
    let invalidManifest = false
    try {
      await tar.t({
        file: archive,
        strict: true,
        onReadEntry(entry) {
          const item = entry as { path?: unknown; type?: unknown; size?: unknown }
          if (
            typeof item.path !== "string" ||
            typeof item.type !== "string" ||
            typeof item.size !== "number" ||
            !Number.isSafeInteger(item.size) ||
            item.size < 0 ||
            entries.length >= MAX_ARCHIVE_ENTRIES
          ) {
            invalidManifest = true
            return
          }
          entries.push({ path: item.path, type: item.type, size: item.size })
        },
      })
    } catch (err) {
      log.error("failed to inspect skill archive", { archive, err })
      return false
    }
    if (invalidManifest || !isSafeArchiveExpansion(entries.map((entry) => entry.size))) {
      log.warn("refusing archive with excessive entries or expanded size", { archive, entries: entries.length })
      return false
    }

    const expandedSize = entries.reduce((total, entry) => total + entry.size, 0)
    if (Date.now() >= budget.deadline ||
      budget.expandedBytes + budget.reservedExpandedBytes + expandedSize > MAX_TOTAL_EXPANDED_BYTES) {
      log.warn("refusing archive: total extraction or time budget exceeded", { archive, expandedSize })
      return false
    }

    const permitted = new Set<string>()
    for (const entry of entries) {
      if (!isSafeArchiveEntry(realRoot, entry.path, entry.type)) {
        log.warn("refusing unsafe skill archive entry", { path: entry.path, type: entry.type })
        return false
      }
      if (entry.path === "." || entry.path === "./") continue
      const destination = resolveSkillFilePath(realRoot, entry.path)
      if (!destination || !(await safeCacheDestination(realRoot, destination, false, entry.type === "Directory"))) {
        log.warn("refusing archive write through unsafe cache path", { path: entry.path })
        return false
      }
      permitted.add(path.normalize(entry.path.replace(/\\/g, "/")))
    }

    // Path checks above await filesystem operations. Recheck and reserve here
    // without yielding so concurrently processed archives cannot oversubscribe.
    if (budget.expandedBytes + budget.reservedExpandedBytes + expandedSize > MAX_TOTAL_EXPANDED_BYTES) {
      log.warn("refusing archive: concurrent extraction budget exhausted", { archive, expandedSize })
      return false
    }
    budget.reservedExpandedBytes += expandedSize
    try {
      await tar.x({
        file: archive,
        cwd: realRoot,
        strict: true,
        preservePaths: false,
        filter(entryPath, entry) {
          const item = entry as { type?: unknown }
          if (typeof item.type !== "string") return false
          return isSafeArchiveEntry(realRoot, entryPath, item.type) &&
            permitted.has(path.normalize(entryPath.replace(/\\/g, "/")))
        },
      })
      return true
    } catch (err) {
      log.error("failed to safely extract skill archive", { archive, err })
      return false
    } finally {
      // Count the declared size even after an extraction error because tar.x may
      // have already written some files before failing.
      budget.reservedExpandedBytes -= expandedSize
      budget.expandedBytes += expandedSize
    }
  }


  const MAX_REDIRECTS = 4

  /**
   * Reject URL shapes that should never be used as remote skill sources.
   * DNS results are checked separately before every request and redirect.
   */
  export function isSafeRemoteURLShape(value: string): boolean {
    let url: URL
    try {
      url = new URL(value)
    } catch {
      return false
    }
    if (url.protocol !== "https:" || url.username || url.password || (url.port && url.port !== "443")) return false
    const hostname = url.hostname.toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "")
    if (!hostname || isIP(hostname) !== 0 || !hostname.includes(".")) return false
    const localSuffixes = [".localhost", ".local", ".internal", ".test", ".invalid", ".home.arpa"]
    if (["localhost", "local", "internal", "test", "invalid", "home.arpa"].includes(hostname)) return false
    if (localSuffixes.some((suffix) => hostname.endsWith(suffix))) return false
    return true
  }

  export function isPublicAddress(address: string): boolean {
    const family = isIP(address)
    if (family === 4) {
      const octets = address.split(".").map(Number)
      const [a, b, c] = octets
      if (a === 0 || a === 10 || a === 127 || a >= 224) return false
      if (a === 100 && b >= 64 && b <= 127) return false
      if (a === 169 && b === 254) return false
      if (a === 172 && b >= 16 && b <= 31) return false
      if (a === 192 && (b === 168 || (b === 0 && c <= 2) || (b === 88 && c === 99) || (b === 0 && c === 2))) return false
      if (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) return false
      if (a === 203 && b === 0 && c === 113) return false
      return true
    }
    if (family === 6) {
      const normalized = address.toLowerCase().split("%")[0]
      // Remote skill sources should resolve only to global-unicast IPv6
      // addresses (2000::/3), excluding the documentation prefix.
      if (!/^[23]/.test(normalized) || normalized.startsWith("2001:db8:")) return false
      return true
    }
    return false
  }

  async function isSafeRemoteDestination(value: string): Promise<boolean> {
    if (!isSafeRemoteURLShape(value)) return false
    const url = new URL(value)
    let timeout: ReturnType<typeof setTimeout> | undefined
    try {
      const addresses = await Promise.race([
        lookup(url.hostname, { all: true, verbatim: true }),
        new Promise<never>((_, reject) => {
          timeout = setTimeout(() => reject(new Error("DNS lookup timed out")), 3_000)
        }),
      ])
      return addresses.length > 0 && addresses.every((item) => isPublicAddress(item.address))
    } catch {
      return false
    } finally {
      if (timeout) clearTimeout(timeout)
    }
  }

  /** Fetch over HTTPS without allowing redirects to bypass destination checks. */
  export function safeRemoteRedirectURL(currentValue: string, location: string): string | undefined {
    try {
      const target = new URL(location, currentValue)
      return isSafeRemoteURLShape(target.href) ? target.href : undefined
    } catch {
      return undefined
    }
  }

  async function fetchRemoteURL(value: string, signal: AbortSignal): Promise<Response> {
    let current: URL
    try {
      current = new URL(value)
    } catch {
      throw new Error("Invalid remote skill URL")
    }
    for (let redirects = 0; ; redirects++) {
      if (!(await isSafeRemoteDestination(current.href))) {
        throw new Error("Remote skill URL resolves to an unsafe or non-public destination")
      }
      const response = await fetch(current, { signal, redirect: "manual" })
      const isRedirect = [301, 302, 303, 307, 308].includes(response.status)
      if (!isRedirect) return response
      const location = response.headers.get("location")
      await response.body?.cancel().catch(() => {})
      if (!location) throw new Error("Remote skill redirect has no Location header")
      if (redirects >= MAX_REDIRECTS) throw new Error("Remote skill redirect limit exceeded")
      const redirectURL = safeRemoteRedirectURL(current.href, location)
      if (!redirectURL) throw new Error("Remote skill redirect attempted to leave the safe HTTPS destination policy")
      current = new URL(redirectURL)
    }
  }

  const MAX_INDEX_BYTES = 2 * 1024 * 1024
  const MAX_SKILL_DOWNLOAD_BYTES = 25 * 1024 * 1024
  const MAX_TOTAL_DOWNLOAD_BYTES = 100 * 1024 * 1024
  const MAX_REGISTRY_SKILLS = 10_000
  const MAX_TOTAL_SKILL_ASSETS = 20_000
  const MAX_CONCURRENT_SKILL_DOWNLOADS = 6
  const MAX_ARCHIVE_ENTRIES = 10_000
  const MAX_ARCHIVE_MEMBER_BYTES = 25 * 1024 * 1024
  const MAX_ARCHIVE_EXPANDED_BYTES = 100 * 1024 * 1024
  const MAX_TOTAL_EXPANDED_BYTES = 250 * 1024 * 1024
  const MAX_TOTAL_PULL_MS = 5 * 60 * 1000
  const DOWNLOAD_TIMEOUT_MS = 15_000

  type ResourceBudget = {
    downloadedBytes: number
    reservedDownloadBytes: number
    expandedBytes: number
    reservedExpandedBytes: number
    deadline: number
  }

  /** Reject archive manifests that can expand beyond bounded entry or size limits. */
  export function isSafeArchiveExpansion(sizes: number[]): boolean {
    if (sizes.length > MAX_ARCHIVE_ENTRIES) return false
    let total = 0
    for (const size of sizes) {
      if (!Number.isSafeInteger(size) || size < 0 || size > MAX_ARCHIVE_MEMBER_BYTES) return false
      total += size
      if (total > MAX_ARCHIVE_EXPANDED_BYTES) return false
    }
    return true
  }

  /** Read a response incrementally so an untrusted registry cannot exhaust memory with an oversized body. */
  export async function readBoundedBody(response: Response, maxBytes: number): Promise<Uint8Array | undefined> {
    if (!Number.isSafeInteger(maxBytes) || maxBytes < 0) return undefined
    const declaredLength = response.headers.get("content-length")
    if (declaredLength && /^\d+$/.test(declaredLength) && Number(declaredLength) > maxBytes) {
      await response.body?.cancel().catch(() => {})
      return undefined
    }
    if (!response.body) return new Uint8Array()
    const reader = response.body.getReader()
    const chunks: Uint8Array[] = []
    let total = 0
    try {
      while (true) {
        const { done, value } = await reader.read()
        if (done) break
        total += value.byteLength
        if (total > maxBytes) {
          await reader.cancel().catch(() => {})
          return undefined
        }
        chunks.push(value)
      }
    } catch {
      await reader.cancel().catch(() => {})
      return undefined
    }
    const result = new Uint8Array(total)
    let offset = 0
    for (const chunk of chunks) {
      result.set(chunk, offset)
      offset += chunk.byteLength
    }
    return result
  }

  async function get(url: string, dest: string, root: string, budget: ResourceBudget, binary = false): Promise<boolean> {
    if (Date.now() >= budget.deadline) {
      log.warn("stopping skill download: overall time budget exhausted", { url })
      return false
    }
    const safeDest = await safeCacheDestination(root, dest, true)
    if (!safeDest) {
      log.warn("refusing skill download to unsafe cache path", { dest })
      return false
    }
    if (await Bun.file(safeDest).exists()) return true

    const remainingMs = budget.deadline - Date.now()
    if (remainingMs <= 0) return false
    const remaining = MAX_TOTAL_DOWNLOAD_BYTES - budget.downloadedBytes - budget.reservedDownloadBytes
    const reservation = Math.min(MAX_SKILL_DOWNLOAD_BYTES, remaining)
    if (reservation <= 0) {
      log.warn("refusing skill download: total download budget exhausted", { url })
      return false
    }
    budget.reservedDownloadBytes += reservation
    try {
      const response = await fetchRemoteURL(url, AbortSignal.timeout(Math.min(DOWNLOAD_TIMEOUT_MS, remainingMs)))
      if (!response.ok) {
        await response.body?.cancel().catch(() => {})
        log.error("failed to download", { url, status: response.status })
        return false
      }
      const bytes = await readBoundedBody(response, reservation)
      if (!bytes) {
        log.warn("refusing oversized or unreadable skill download", { url, maxBytes: reservation })
        return false
      }
      budget.downloadedBytes += bytes.byteLength
      await Bun.write(safeDest, binary ? bytes : new TextDecoder().decode(bytes))
      return true
    } catch (err) {
      log.error("failed to download", { url, err })
      return false
    } finally {
      budget.reservedDownloadBytes -= reservation
    }
  }

  export async function pull(url: string): Promise<string[]> {
    const result: string[] = []
    const budget: ResourceBudget = {
      downloadedBytes: 0,
      reservedDownloadBytes: 0,
      expandedBytes: 0,
      reservedExpandedBytes: 0,
      deadline: Date.now() + MAX_TOTAL_PULL_MS,
    }
    let base: string
    let index: string
    try {
      base = url.endsWith("/") ? url : `${url}/`
      index = new URL("index.json", base).href
    } catch (err) {
      log.warn("invalid skill registry URL", { url, err })
      return result
    }
    const cache = dir()
    const host = base.slice(0, -1)

    log.info("fetching index", { url: index })
    const indexRemainingMs = budget.deadline - Date.now()
    if (indexRemainingMs <= 0) return result
    const data = await fetchRemoteURL(index, AbortSignal.timeout(Math.min(DOWNLOAD_TIMEOUT_MS, indexRemainingMs)))
      .then(async (response) => {
        if (!response.ok) {
          log.error("failed to fetch index", { url: index, status: response.status })
          return undefined
        }
        const bytes = await readBoundedBody(response, MAX_INDEX_BYTES)
        if (!bytes) {
          log.warn("refusing oversized or unreadable skill index", { url: index, maxBytes: MAX_INDEX_BYTES })
          return undefined
        }
        try {
          return JSON.parse(new TextDecoder().decode(bytes)) as Index
        } catch (err) {
          log.error("failed to parse index", { url: index, err })
          return undefined
        }
      })
      .catch((err) => {
        log.error("failed to fetch index", { url: index, err })
        return undefined
      })

    if (!data?.skills || !Array.isArray(data.skills)) {
      log.warn("invalid index format", { url: index })
      return result
    }

    await mkdir(cache, { recursive: true })
    const cacheRoot = await realpath(cache)

    const list = data.skills.filter((skill) => {
      if (!skill || !isSafeSkillName(skill.name)) {
        log.warn("invalid skill entry: unsafe skill name", { url: index, name: skill?.name })
        return false
      }
      const hasFiles = "files" in skill && Array.isArray(skill.files)
      const hasUrl = "url" in skill && typeof skill.url === "string"
      if (!hasFiles && !hasUrl) {
        log.warn("invalid skill entry", { url: index, skill })
        return false
      }
      return true
    })
    const assetCount = list.reduce(
      (count, skill) => count + ("files" in skill && Array.isArray(skill.files) ? skill.files.length : 1),
      0,
    )
    if (list.length > MAX_REGISTRY_SKILLS || assetCount > MAX_TOTAL_SKILL_ASSETS) {
      log.warn("refusing skill registry: entry or asset count exceeds limits", {
        url: index,
        skills: list.length,
        assets: assetCount,
      })
      return result
    }

    for (let offset = 0; offset < list.length; offset += MAX_CONCURRENT_SKILL_DOWNLOADS) {
      const batch = list.slice(offset, offset + MAX_CONCURRENT_SKILL_DOWNLOADS)
      await Promise.all(
        batch.map(async (skill) => {
        const root = path.join(cacheRoot, skill.name)
        try {
          if ("files" in skill && Array.isArray(skill.files)) {
            // Sequential per-skill downloads keep global concurrency bounded by the outer batch.
            for (const file of skill.files) {
              const dest = resolveSkillFilePath(root, file)
              if (!dest) {
                log.warn("skipping unsafe skill file path", { skill: skill.name, file })
                continue
              }
              const link = new URL(file, `${host}/${skill.name}/`).href
              await get(link, dest, root, budget)
            }
          } else if ("url" in skill && typeof skill.url === "string") {
            const link = new URL(skill.url, base).href
            if ("type" in skill && skill.type === "archive") {
              // Archive format: download tar.gz and extract
              const archive = path.join(root, `${skill.name}.tar.gz`)
              await mkdir(root, { recursive: true })
              if (await get(link, archive, root, budget, true)) {
                await extractSafeArchive(archive, root, budget)
              }
            } else {
              // Single file (skill-md): download as SKILL.md
              const dest = path.join(root, "SKILL.md")
              await mkdir(root, { recursive: true })
              await get(link, dest, root, budget)
            }
          }

          const md = await safeCacheDestination(cacheRoot, path.join(root, "SKILL.md"), false)
          if (md && (await Bun.file(md).exists())) result.push(root)
        } catch (err) {
          log.error("failed to process remote skill entry", { url: index, name: skill.name, err })
        }
        }),
      )
    }

    return result
  }
}
