import path from "path"
import { lstat, mkdir, realpath } from "node:fs/promises"
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

  async function extractSafeArchive(archive: string, root: string): Promise<boolean> {
    await mkdir(root, { recursive: true })
    const rootStat = await lstat(root)
    if (rootStat.isSymbolicLink() || !rootStat.isDirectory()) return false
    const realRoot = await realpath(root)
    const entries: Array<{ path: string; type: string }> = []
    try {
      await tar.t({
        file: archive,
        strict: true,
        onReadEntry(entry) {
          const item = entry as { path?: unknown; type?: unknown }
          if (typeof item.path === "string" && typeof item.type === "string") {
            entries.push({ path: item.path, type: item.type })
          }
        },
      })
    } catch (err) {
      log.error("failed to inspect skill archive", { archive, err })
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
    }
  }


  async function get(url: string, dest: string, root: string, binary = false): Promise<boolean> {
    const safeDest = await safeCacheDestination(root, dest, true)
    if (!safeDest) {
      log.warn("refusing skill download to unsafe cache path", { dest })
      return false
    }
    if (await Bun.file(safeDest).exists()) return true
    return fetch(url)
      .then(async (response) => {
        if (!response.ok) {
          log.error("failed to download", { url, status: response.status })
          return false
        }
        const content = binary ? new Uint8Array(await response.arrayBuffer()) : await response.text()
        await Bun.write(safeDest, content)
        return true
      })
      .catch((err) => {
        log.error("failed to download", { url, err })
        return false
      })
  }

  export async function pull(url: string): Promise<string[]> {
    const result: string[] = []
    const base = url.endsWith("/") ? url : `${url}/`
    const index = new URL("index.json", base).href
    const cache = dir()
    const host = base.slice(0, -1)

    log.info("fetching index", { url: index })
    const data = await fetch(index)
      .then(async (response) => {
        if (!response.ok) {
          log.error("failed to fetch index", { url: index, status: response.status })
          return undefined
        }
        return response
          .json()
          .then((json) => json as Index)
          .catch((err) => {
            log.error("failed to parse index", { url: index, err })
            return undefined
          })
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

    await Promise.all(
      list.map(async (skill) => {
        const root = path.join(cacheRoot, skill.name)

        if ("files" in skill && Array.isArray(skill.files)) {
          // Legacy format: array of individual files
          await Promise.all(
            skill.files.map(async (file) => {
              const dest = resolveSkillFilePath(root, file)
              if (!dest) {
                log.warn("skipping unsafe skill file path", { skill: skill.name, file })
                return
              }
              const link = new URL(file, `${host}/${skill.name}/`).href
              await get(link, dest, root)
            }),
          )
        } else if ("url" in skill && typeof skill.url === "string") {
          const link = new URL(skill.url, base).href
          if ("type" in skill && skill.type === "archive") {
            // Archive format: download tar.gz and extract
            const archive = path.join(root, `${skill.name}.tar.gz`)
            await mkdir(root, { recursive: true })
            if (await get(link, archive, root, true)) {
              await extractSafeArchive(archive, root)
            }
          } else {
            // Single file (skill-md): download as SKILL.md
            const dest = path.join(root, "SKILL.md")
            await mkdir(root, { recursive: true })
            await get(link, dest, root)
          }
        }

        const md = await safeCacheDestination(cacheRoot, path.join(root, "SKILL.md"), false)
        if (md && (await Bun.file(md).exists())) result.push(root)
      }),
    )

    return result
  }
}
