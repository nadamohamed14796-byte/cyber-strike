import z from "zod"
import path from "path"
import os from "os"
import { Config } from "../config/config"
import { Instance } from "../project/instance"
import { NamedError } from "@cyberstrike-io/util/error"
import { ConfigMarkdown } from "../config/markdown"
import { Log } from "../util/log"
import { Global } from "@/global"
import { Filesystem } from "@/util/filesystem"
import { Flag } from "@/flag/flag"
import { Bus } from "@/bus"
import { Session } from "@/session"
import { Discovery } from "./discovery"
import { SkillSigning } from "./signing"

declare const CYBERSTRIKE_SKILL_CATALOG_DIR: string | undefined

export namespace Skill {
  const log = Log.create({ service: "skill" })
  export const Info = z.object({
    name: z.string(),
    description: z.string(),
    location: z.string(),
    content: z.string(),
    // Signing & verification
    version: z.string().optional(),
    author: z.string().optional(),
    tags: z.array(z.string()).optional(),
    sha256: z.string().optional(),
    signature: z.string().optional(),
    signed_by: z.string().optional(),
    verified: z.enum(["official", "community", "unverified", "tampered"]).optional(),
    // Categorization
    category: z.string().optional(),
    owasp_id: z.string().optional(),
    // Kill chain & tech stack
    tech_stack: z.array(z.string()).optional(),
    cwe_ids: z.array(z.string()).optional(),
    chains_with: z.array(z.string()).optional(),
    prerequisites: z.array(z.string()).optional(),
    severity_boost: z.record(z.string(), z.string()).optional(),
  })
  export type Info = z.infer<typeof Info>
  /** Lightweight catalog entry. Full Markdown bodies are read only by Skill.get(). */
  export type Metadata = Omit<Info, "content">

  export const InvalidError = NamedError.create(
    "SkillInvalidError",
    z.object({
      path: z.string(),
      message: z.string().optional(),
      issues: z.custom<z.core.$ZodIssue[]>().optional(),
    }),
  )

  export const NameMismatchError = NamedError.create(
    "SkillNameMismatchError",
    z.object({
      path: z.string(),
      expected: z.string(),
      actual: z.string(),
    }),
  )

  // External skill directories to search for (project-level and global)
  // These follow the directory layout used by Claude Code and other agents.
  const EXTERNAL_DIRS = [".claude", ".agents"]
  const EXTERNAL_SKILL_GLOB = new Bun.Glob("skills/**/SKILL.md")

  const CYBERSTRIKE_SKILL_GLOB = new Bun.Glob("{skill,skills}/**/SKILL.md")
  const SKILL_GLOB = new Bun.Glob("**/SKILL.md")

  // Keep full catalog loading and permission initialization on the same built-in
  // root. Compiled distributions may inject a catalog path outside import.meta.dir.
  function builtinSkillDirectory(): string {
    return typeof CYBERSTRIKE_SKILL_CATALOG_DIR === "string" && CYBERSTRIKE_SKILL_CATALOG_DIR.length > 0
      ? CYBERSTRIKE_SKILL_CATALOG_DIR
      : path.join(path.resolve(import.meta.dir, "../../../.."), ".cyberstrike")
  }

  // CYBERSTRIKE_TEST_HOME is process-wide, while Bun tests may initialize many
  // Instance.directory values concurrently. Use the fixture's per-directory marker
  // first, so one test changing process.env cannot make another fixture load global
  // built-in skills (or make a real repository instance lose its built-in catalog).
  export function isCatalogIsolationContext(): boolean {
    const directory = path.resolve(Instance.directory)
    const basename = path.basename(directory)
    if (basename.startsWith("cyberstrike-test-")) return true
    const testHome = process.env.CYBERSTRIKE_TEST_HOME
    return Boolean(testHome && directory === path.resolve(testHome))
  }

  export const state = Instance.state(async () => {
    const skills: Record<string, Metadata> = {}
    const skillPriorities = new Map<string, number>()
    const dirs = new Set<string>()

    const addSkill = async (match: string, sourcePriority = 0) => {
      try {
        await loadSkill(match, sourcePriority)
      } catch (error) {
        log.error("failed to load skill; continuing with remaining skills", { skill: match, error })
        Bus.publish(Session.Event.Error, {
          error: new NamedError.Unknown({
            message: `Failed to load skill at ${match}; skipping it and continuing with other skills.`,
          }).toObject(),
        })
      }
    }

    const loadSkill = async (match: string, sourcePriority: number) => {
      const fileContent = await Bun.file(match).text()
      const md = await ConfigMarkdown.parseContent(fileContent, match).catch((err) => {
        const message = ConfigMarkdown.FrontmatterError.isInstance(err)
          ? err.data.message
          : `Failed to parse skill ${match}`
        Bus.publish(Session.Event.Error, { error: new NamedError.Unknown({ message }).toObject() })
        log.error("failed to load skill", { skill: match, err })
        return undefined
      })

      if (!md) return

      const parsed = Info.pick({ name: true, description: true }).safeParse(md.data)
      if (!parsed.success) {
        log.warn("skill metadata is invalid; skipping", {
          path: match,
          issues: parsed.error.issues.map((issue) => ({ path: issue.path, code: issue.code })),
        })
        return
      }

      dirs.add(path.dirname(match))

      // A name can be discovered in several places (bundled, home/global, project,
      // or configured sources). Keep the highest-precedence source instead of
      // letting a later bundled/installed scan replace a project-local reference.
      const existing = skills[parsed.data.name]
      const existingPriority = skillPriorities.get(parsed.data.name)
      if (existing) {
        log.debug("duplicate skill name", {
          name: parsed.data.name,
          existing: existing.location,
          duplicate: match,
          existingPriority,
          duplicatePriority: sourcePriority,
        })
        if (existingPriority !== undefined && existingPriority > sourcePriority) return
      }

      const raw = md.data as Record<string, unknown>
      const verified = await SkillSigning.verify({
        content: fileContent,
        sha256: typeof raw.sha256 === "string" ? raw.sha256 : undefined,
        signature: typeof raw.signature === "string" ? raw.signature : undefined,
        signed_by: typeof raw.signed_by === "string" ? raw.signed_by : undefined,
      })

      if (verified === "tampered") {
        log.warn("skill integrity check failed, skipping", { name: parsed.data.name, path: match })
        Bus.publish(Session.Event.Error, {
          error: new NamedError.Unknown({
            message: `Skill "${parsed.data.name}" failed integrity check and was not loaded`,
          }).toObject(),
        })
        return
      }

      const toStringArray = (v: unknown): string[] | undefined =>
        Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : undefined

      skills[parsed.data.name] = {
        name: parsed.data.name,
        description: parsed.data.description,
        location: match,
        verified,
        version: typeof raw.version === "string" ? raw.version : undefined,
        author: typeof raw.author === "string" ? raw.author : undefined,
        tags: toStringArray(raw.tags),
        sha256: typeof raw.sha256 === "string" ? raw.sha256 : undefined,
        signature: typeof raw.signature === "string" ? raw.signature : undefined,
        signed_by: typeof raw.signed_by === "string" ? raw.signed_by : undefined,
        category: typeof raw.category === "string" ? raw.category : undefined,
        owasp_id: typeof raw.owasp_id === "string" ? raw.owasp_id : undefined,
        tech_stack: toStringArray(raw.tech_stack),
        cwe_ids: toStringArray(raw.cwe_ids),
        chains_with: toStringArray(raw.chains_with),
        prerequisites: toStringArray(raw.prerequisites),
        severity_boost:
          typeof raw.severity_boost === "object" && raw.severity_boost !== null && !Array.isArray(raw.severity_boost)
            ? (raw.severity_boost as Record<string, string>)
            : undefined,
      }
      skillPriorities.set(parsed.data.name, sourcePriority)
    }

    const scanExternal = async (root: string, scope: "global" | "project", sourcePriority: number) => {
      return Array.fromAsync(
        EXTERNAL_SKILL_GLOB.scan({
          cwd: root,
          absolute: true,
          onlyFiles: true,
          followSymlinks: true,
          dot: true,
        }),
      )
        .then((matches) => Promise.all(matches.map((match) => addSkill(match, sourcePriority))))
        .catch((error) => {
          log.error(`failed to scan ${scope} skills`, { dir: root, error })
        })
    }

    // Scan external skill directories (.claude/skills/, .agents/skills/, etc.)
    // Load global (home) first, then project-level (so project-level overwrites)
    if (!Flag.CYBERSTRIKE_DISABLE_EXTERNAL_SKILLS) {
      for (const dir of EXTERNAL_DIRS) {
        const root = path.join(Global.Path.home, dir)
        if (!(await Filesystem.isDir(root))) continue
        await scanExternal(root, "global", 10_000)
      }

      const projectExternalRoots = await Array.fromAsync(
        Filesystem.up({
          targets: EXTERNAL_DIRS,
          start: Instance.directory,
          stop: Instance.worktree,
        }),
      )
      for (const [index, root] of projectExternalRoots.entries()) {
        // Filesystem.up returns the nearest project first; closer project scopes win.
        await scanExternal(root, "project", 30_000 + projectExternalRoots.length - index)
      }
    }

    // Scan .cyberstrike/skill/ directories. Project-local directories outrank
    // home/global copies even though Config.directories() also includes home later.
    const projectCyberstrikeRoots = !Flag.CYBERSTRIKE_DISABLE_PROJECT_CONFIG
      ? await Array.fromAsync(
          Filesystem.up({
            targets: [".cyberstrike"],
            start: Instance.directory,
            stop: Instance.worktree,
          }),
        )
      : []
    const projectCyberstrikePriority = new Map(
      projectCyberstrikeRoots.map((dir, index) => [path.resolve(dir), 30_000 + projectCyberstrikeRoots.length - index]),
    )
    const homeCyberstrikeRoots = new Set(
      await Array.fromAsync(
        Filesystem.up({ targets: [".cyberstrike"], start: Global.Path.home, stop: Global.Path.home }),
      ),
    )
    for (const dir of await Config.directories()) {
      const resolvedDir = path.resolve(dir)
      const sourcePriority =
        Flag.CYBERSTRIKE_CONFIG_DIR && resolvedDir === path.resolve(Flag.CYBERSTRIKE_CONFIG_DIR)
          ? 40_000
          : (projectCyberstrikePriority.get(resolvedDir) ??
            (homeCyberstrikeRoots.has(resolvedDir) ? 15_000 : resolvedDir === path.resolve(Global.Path.config) ? 11_000 : 10_000))
      for await (const match of CYBERSTRIKE_SKILL_GLOB.scan({
        cwd: dir,
        absolute: true,
        onlyFiles: true,
        followSymlinks: true,
      })) {
        await addSkill(match, sourcePriority)
      }
    }

    // Built-in skills: resolve .cyberstrike/ relative to this source file
    // so they're always found regardless of Instance.directory (web UI header).
    // Skip in test mode to preserve test isolation.
    if (!isCatalogIsolationContext()) {
      const builtinDir = builtinSkillDirectory()
      if (await Filesystem.isDir(builtinDir)) {
        for await (const match of CYBERSTRIKE_SKILL_GLOB.scan({
          cwd: builtinDir,
          absolute: true,
          onlyFiles: true,
          followSymlinks: true,
        })) {
          await addSkill(match, 0)
        }
      }

      // Installed skills: XDG data dir (npm postinstall copies skills here)
      // This is the fallback for compiled binaries where import.meta.dir
      // resolves to bunfs and can't find skills on the filesystem.
      const installedDir = path.join(Global.Path.data, "skill")
      if (await Filesystem.isDir(installedDir)) {
        for await (const match of SKILL_GLOB.scan({
          cwd: installedDir,
          absolute: true,
          onlyFiles: true,
          followSymlinks: true,
        })) {
          await addSkill(match, -1)
        }
      }
    }

    // Scan additional skill paths from config
    const config = await Config.get()
    for (const [skillPathIndex, skillPath] of (config.skills?.paths ?? []).entries()) {
      const expanded = skillPath.startsWith("~/") ? path.join(os.homedir(), skillPath.slice(2)) : skillPath
      const resolved = path.isAbsolute(expanded) ? expanded : path.join(Instance.directory, expanded)
      if (!(await Filesystem.isDir(resolved))) {
        log.warn("skill path not found", { path: resolved })
        continue
      }
      for await (const match of SKILL_GLOB.scan({
        cwd: resolved,
        absolute: true,
        onlyFiles: true,
        followSymlinks: true,
      })) {
        await addSkill(match, 50_000 + skillPathIndex)
      }
    }

    // Download and load skills from URLs. One unavailable optional source must
    // not reject Skill.state() and make every local skill unavailable.
    for (const [urlIndex, url] of (config.skills?.urls ?? []).entries()) {
      try {
        const list = await Discovery.pull(url)
        for (const dir of list) {
          dirs.add(dir)
          for await (const match of SKILL_GLOB.scan({
            cwd: dir,
            absolute: true,
            onlyFiles: true,
            followSymlinks: true,
          })) {
            await addSkill(match, 60_000 + urlIndex)
          }
        }
      } catch (error) {
        let source = "invalid URL"
        try {
          source = new URL(url).host
        } catch {
          // Keep malformed or credential-bearing URL values out of logs.
        }
        log.error("failed to load configured skill source; continuing with other sources", {
          source,
          error: error instanceof Error ? error.message : String(error),
        })
      }
    }

    return {
      skills,
      dirs: Array.from(dirs),
    }
  })

  export async function get(name: string): Promise<Info | undefined> {
    const catalog = await state()

    // Resolve only a canonical exact name (case-insensitive fallback is also exact).
    const exact = catalog.skills[name]
    const normalized = name.trim().toLocaleLowerCase("en-US")
    const matches = normalized
      ? Object.values(catalog.skills).filter((item) => item.name.trim().toLocaleLowerCase("en-US") === normalized)
      : []
    const metadata = exact ?? (matches.length === 1 ? matches[0] : undefined)
    if (!metadata) return undefined

    // Hydrate the full body only for the selected skill. Re-check identity and
    // integrity because the source may have changed since catalog discovery.
    try {
      const fileContent = await Bun.file(metadata.location).text()
      const md = await ConfigMarkdown.parseContent(fileContent, metadata.location)
      const parsed = Info.pick({ name: true, description: true }).safeParse(md.data)
      if (!parsed.success || parsed.data.name !== metadata.name || parsed.data.description !== metadata.description) {
        log.warn("skill metadata changed since catalog discovery; refresh the catalog", {
          name: metadata.name,
          path: metadata.location,
        })
        return undefined
      }

      const verified = await SkillSigning.verify({
        content: fileContent,
        sha256: metadata.sha256,
        signature: metadata.signature,
        signed_by: metadata.signed_by,
      })
      if (verified === "tampered") {
        log.warn("skill integrity check failed during on-demand load", { name: metadata.name, path: metadata.location })
        return undefined
      }
      return { ...metadata, content: md.content, verified }
    } catch (error) {
      log.error("failed to load skill content on demand", { name: metadata.name, path: metadata.location, error })
      return undefined
    }
  }

  export async function all(): Promise<Metadata[]> {
    return state().then((snapshot) => Object.values(snapshot.skills))
  }

  export async function dirs() {
    return state().then((x) => x.dirs)
  }

  /**
   * Lightweight directory list - scans for SKILL.md files without parsing them.
   * Used for permission initialization to avoid triggering full skill indexing.
   * ~500ms vs 4.3s for full state() initialization.
   */
  export async function dirsOnly(): Promise<string[]> {
    const dirs = new Set<string>()

    const scanExternal = async (root: string) => {
      for await (const match of EXTERNAL_SKILL_GLOB.scan({
        cwd: root,
        absolute: true,
        onlyFiles: true,
        followSymlinks: true,
        dot: true,
      })) {
        dirs.add(path.dirname(match))
      }
    }

    // Scan external skill directories (.claude/skills/, .agents/skills/)
    if (!Flag.CYBERSTRIKE_DISABLE_EXTERNAL_SKILLS) {
      for (const dir of EXTERNAL_DIRS) {
        const root = path.join(Global.Path.home, dir)
        if (!(await Filesystem.isDir(root))) continue
        await scanExternal(root)
      }

      for await (const root of Filesystem.up({
        targets: EXTERNAL_DIRS,
        start: Instance.directory,
        stop: Instance.worktree,
      })) {
        await scanExternal(root)
      }
    }

    // Scan .cyberstrike/skill/ directories
    for (const dir of await Config.directories()) {
      for await (const match of CYBERSTRIKE_SKILL_GLOB.scan({
        cwd: dir,
        absolute: true,
        onlyFiles: true,
        followSymlinks: true,
      })) {
        dirs.add(path.dirname(match))
      }
    }

    // Built-in skills
    if (!isCatalogIsolationContext()) {
      const builtinDir = builtinSkillDirectory()
      if (await Filesystem.isDir(builtinDir)) {
        for await (const match of CYBERSTRIKE_SKILL_GLOB.scan({
          cwd: builtinDir,
          absolute: true,
          onlyFiles: true,
          followSymlinks: true,
        })) {
          dirs.add(path.dirname(match))
        }
      }

      // Installed skills: XDG data dir
      const installedDir = path.join(Global.Path.data, "skill")
      if (await Filesystem.isDir(installedDir)) {
        for await (const match of SKILL_GLOB.scan({
          cwd: installedDir,
          absolute: true,
          onlyFiles: true,
          followSymlinks: true,
        })) {
          dirs.add(path.dirname(match))
        }
      }
    }

    // Scan additional skill paths from config
    const config = await Config.get()
    for (const skillPath of config.skills?.paths ?? []) {
      const expanded = skillPath.startsWith("~/") ? path.join(os.homedir(), skillPath.slice(2)) : skillPath
      const resolved = path.isAbsolute(expanded) ? expanded : path.join(Instance.directory, expanded)
      if (!(await Filesystem.isDir(resolved))) continue
      for await (const match of SKILL_GLOB.scan({
        cwd: resolved,
        absolute: true,
        onlyFiles: true,
        followSymlinks: true,
      })) {
        dirs.add(path.dirname(match))
      }
    }

    // Downloaded skills from URLs
    for (const url of config.skills?.urls ?? []) {
      const list = await Discovery.pull(url).catch(() => [])
      if (!list) continue
      for (const dir of list) {
        dirs.add(dir)
      }
    }

    return Array.from(dirs)
  }
}
