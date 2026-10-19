import path from "path"
import { pathToFileURL } from "url"
import z from "zod"
import { Tool } from "./tool"
import { Skill } from "../skill"
import { SkillIndex } from "../skill/index-engine"
import { SkillContext } from "../skill/context"
import { KillChain } from "../skill/killchain"
import { PermissionNext } from "../permission/next"
import { Ripgrep } from "../file/ripgrep"
import { iife } from "@/util/iife"
import { Agent } from "../agent/agent"
import { Instance } from "../project/instance"

const accessibleCache = new Map<string, { catalog: ReturnType<typeof Skill.state>; permissionFingerprint: string; skills: Skill.Info[] }>()

export const SkillTool = Tool.define("skill", async (ctx) => {
  // Lazy load skills only when tool is executed
  const description = [
    "Manage and load specialized security skills with context-efficient lazy loading.",
    "",
    "Actions:",
    "  load    - Load a skill into context (requires skill name)",
    "  unload  - Remove a skill from context to free tokens",
    "  search  - Search skills by keyword, tech stack, CWE, or category",
    "  chain   - Analyze current findings for kill chain opportunities",
    "  suggest - Get next-step skill suggestions based on findings",
    "  list    - Show a page of available skills or currently loaded skills",
    "",
    'Thousands of skills available. Use "search" to narrow the catalog; list/search support limit and offset pagination.',
  ].join("\n")

  const parameters = z.object({
    action: z
      .enum(["load", "unload", "search", "chain", "suggest", "list"])
      .default("load")
      .describe("Action to perform"),
    name: z.string().optional().describe("Skill name (for load/unload)"),
    query: z.string().optional().describe("Search query (for search action)"),
    tech: z.array(z.string()).optional().describe("Tech stack filter (for search action)"),
    cwe: z.string().optional().describe("CWE ID filter (for search action)"),
    category: z.string().optional().describe("Category filter (for search action)"),
    loaded: z.boolean().optional().describe("For list action: only show currently loaded skills"),
    limit: z.number().int().min(1).default(25).describe("Number of skills to return in this page; no application-defined maximum, continue through pages until exhausted"),
    offset: z.number().int().min(0).default(0).describe("Zero-based result offset for list/search pagination"),
    findings: z
      .array(
        z.object({
          skill_id: z.string(),
          severity: z.enum(["info", "low", "medium", "high", "critical"]).default("medium"),
          cwe_id: z.string().optional(),
          tech_stack: z.array(z.string()).optional(),
        }),
      )
      .optional()
      .describe("Current findings (for chain/suggest actions)"),
  })

  return {
    description,
    parameters,
    async execute(params: z.input<typeof parameters>, ctx) {
      // Keep the searchable index and accessible skill list on the same catalog snapshot.
      // A refresh between awaits can otherwise resolve aliases against stale entries.
      let catalog = Skill.state()
      let skills = await Skill.all()
      let stableCatalog = false
      while (!stableCatalog) {
        await SkillIndex.ensureBuilt()
        catalog = Skill.state()
        skills = await Skill.all()
        if (Skill.state() === catalog) stableCatalog = true
      }

      const agentKey = `${Instance.directory}\0${ctx.agent ?? ""}`
      const agentInfo = await Agent.get(ctx.agent)
      const permissionFingerprint = JSON.stringify(agentInfo?.permission ?? null)
      const cached = accessibleCache.get(agentKey)
      if (!cached || cached.catalog !== catalog || cached.permissionFingerprint !== permissionFingerprint) {
        accessibleCache.set(agentKey, {
          catalog,
          permissionFingerprint,
          skills: agentInfo?.permission
            ? skills.filter((skill) => {
                const rule = PermissionNext.evaluate("skill", skill.name, agentInfo.permission)
                return rule.action !== "deny"
              })
            : skills,
        })
      }
      const accessibleSkills = accessibleCache.get(agentKey)!.skills

      if (params.action === "list") {
        if (params.loaded) {
          const active = SkillContext.active()
          const tokens = SkillContext.tokenCount()
          if (active.length === 0)
            return {
              title: "No skills loaded",
              output: "No skills are currently loaded in context.",
              metadata: {} as { name?: string; dir?: string },
            }
          return {
            title: `${active.length} skills loaded (${tokens} tokens)`,
            output: [
              `## Skills in Context (${tokens} estimated tokens)`,
              "",
              ...active.map((name) => `- ${name}`),
            ].join("\n"),
            metadata: {} as { name?: string; dir?: string },
          }
        }
        const all = [...accessibleSkills].sort((left, right) => left.name.localeCompare(right.name))
        const limit = Math.max(1, params.limit ?? 25)
        const offset = Math.max(0, params.offset ?? 0)
        const page = all.slice(offset, offset + limit)
        if (page.length === 0) {
          return {
            title: "No skills on this page",
            output: "Offset " + offset + " is beyond the " + all.length + " available skills. Restart at offset=0 or use action=\"search\" with a focused query.",
            metadata: { offset, next_offset: null, total: all.length } as { name?: string; dir?: string; offset: number; next_offset: number | null; total: number },
          }
        }
        const nextOffset = offset + page.length
        const hasMore = nextOffset < all.length
        return {
          title: page.length + " of " + all.length + " skills available",
          output: [
            "## Available Skills (showing " + (offset + 1) + "-" + nextOffset + " of " + all.length + ")",
            "",
            ...page.map((s) =>
              "- **" + s.name + "** [" + (s.verified ?? "unverified") + "] — " + s.description +
              (s.category ? " (" + s.category + ")" : "") +
              (s.tech_stack?.length ? " [" + s.tech_stack.join(", ") + "]" : ""),
            ),
            ...(hasMore ? ["", "More skills remain. Repeat action=\"list\" with offset=" + nextOffset + " and limit=" + limit + ", or use action=\"search\" to narrow the catalog."] : []),
          ].join("\n"),
          metadata: { offset, next_offset: hasMore ? nextOffset : null, total: all.length } as { name?: string; dir?: string; offset: number; next_offset: number | null; total: number },
        }
      }

      if (params.action === "unload") {
        if (!params.name) throw new Error("Skill name required for unload action")
        const canonicalName = SkillIndex.resolveReference(params.name) ?? params.name
        const removed = SkillContext.unload(canonicalName)
        return {
          title: removed ? `Unloaded: ${canonicalName}` : `Not loaded: ${canonicalName}`,
          output: removed
            ? `Skill "${canonicalName}" removed from context. Active tokens: ${SkillContext.tokenCount()}`
            : `Skill "${canonicalName}" was not in context.`,
          metadata: {} as { name?: string; dir?: string },
        }
      }

      if (params.action === "search") {
        const limit = Math.max(1, params.limit ?? 25)
        const offset = Math.max(0, params.offset ?? 0)
        const accessibleNames = new Set(accessibleSkills.map((skill) => skill.name))
        let candidates: SkillIndex.Entry[] = []

        // Filter permissions before paginating so denied skills neither leak nor hide allowed results.
        if (params.cwe) {
          candidates = SkillIndex.byCWE(params.cwe, Infinity)
        } else if (params.tech?.length) {
          candidates = SkillIndex.byTechStack(params.tech, Infinity)
        } else if (params.category) {
          candidates = SkillIndex.byCategory(params.category, Infinity)
        } else if (params.query) {
          candidates = SkillIndex.search(params.query, Infinity)
        } else {
          candidates = SkillIndex.all().sort((left, right) => left.name.localeCompare(right.name))
        }
        const permitted = candidates.filter((entry) => accessibleNames.has(entry.name))
        const totalCount = permitted.length
        const results = permitted.slice(offset, offset + limit)

        if (results.length === 0)
          return {
            title: "No results on this page",
            output: totalCount === 0
              ? "No skills matched the search criteria."
              : "Offset " + offset + " is beyond the " + totalCount + " matching skills. Reset offset to 0 or refine the query.",
            metadata: { offset, next_offset: null, total: totalCount } as { name?: string; dir?: string; offset: number; next_offset: number | null; total: number },
          }

        const nextOffset = offset + results.length
        const hasMore = nextOffset < totalCount
        return {
          title: results.length + " of " + totalCount + " skills found",
          output: [
            "## Search Results (showing " + (offset + 1) + "-" + nextOffset + " of " + totalCount + ")",
            "",
            ...results.map((r) =>
              "- **" + r.name + "** [" + (r.verified ?? "unverified") + "] — " + r.description +
              (r.tech_stack.length ? " (" + r.tech_stack.join(", ") + ")" : ""),
            ),
            ...(hasMore ? ["", "More results remain. Repeat the same search filters with offset=" + nextOffset + " and limit=" + limit + ", or refine the query."] : []),
          ].join("\n"),
          metadata: { offset, next_offset: hasMore ? nextOffset : null, total: totalCount } as { name?: string; dir?: string; offset: number; next_offset: number | null; total: number },
        }
      }

      if (params.action === "chain") {
        if (!params.findings?.length) throw new Error("Findings required for chain analysis")
        const summary = KillChain.summary(params.findings.map((finding) => ({ ...finding, severity: finding.severity ?? "medium" })))
        return { title: "Kill Chain Analysis", output: summary, metadata: {} as { name?: string; dir?: string } }
      }

      if (params.action === "suggest") {
        if (!params.findings?.length) throw new Error("Findings required for suggestions")
        const suggestions = SkillContext.suggest(params.findings.map((finding) => ({ ...finding, severity: finding.severity ?? "medium" })))
        if (suggestions.length === 0)
          return {
            title: "No suggestions",
            output: "No additional skills suggested for current findings.",
            metadata: {} as { name?: string; dir?: string },
          }
        return {
          title: `${suggestions.length} suggestions`,
          output: [
            "## Suggested Next Skills",
            "",
            ...suggestions.map((s) => `- **${s.name}** [${s.priority}] — ${s.reason}`),
          ].join("\n"),
          metadata: {} as { name?: string; dir?: string },
        }
      }

      // Default: load action
      if (!params.name) throw new Error("Skill name required for load action")

      // Allow exact technique IDs from skill metadata to resolve to the one
      // canonical catalog entry; ambiguous aliases deliberately do not resolve.
      const canonicalName = SkillIndex.resolveReference(params.name) ?? params.name
      const skill = await Skill.get(canonicalName)
      if (!skill) {
        const sample = accessibleSkills.slice(0, 5).map((entry) => entry.name)
        const suffix = accessibleSkills.length > sample.length ? ", …" : ""
        throw new Error(
          `Skill "${params.name}" was not found or has an ambiguous metadata reference. ` +
          `Accessible skills: ${accessibleSkills.length}. ` +
          `Use skill(action="search", query="...") or paged skill(action="list") to find an exact name. ` +
          (sample.length ? `Examples: ${sample.join(", ")}${suffix}` : "No skills are currently accessible."),
        )
      }
      // Listing filters denied skills, but loading must enforce the same policy;
      // otherwise an agent could bypass the filter by naming a denied skill directly.
      if (!accessibleSkills.some((entry) => entry.name === canonicalName)) {
        throw new Error(`Permission denied: skill "${canonicalName}" is not accessible to agent "${ctx.agent ?? "unknown"}".`)
      }

      await ctx.ask({
        permission: "skill",
        patterns: [canonicalName],
        always: [canonicalName],
        metadata: {} as { name?: string; dir?: string },
      })

      const loadedContent = await SkillContext.load(canonicalName)
      if (loadedContent === undefined) {
        throw new Error(`Failed to load skill "${canonicalName}" into context.`)
      }

      const dir = path.dirname(skill.location)
      const base = pathToFileURL(dir).href

      // Companion-file discovery is best-effort: filesystem/ripgrep failures must
      // not turn a successfully loaded SKILL.md into a failed skill invocation.
      // Cancellation remains fatal so aborted tool calls never report success.
      let companionFileListComplete = true
      const files = await iife(async () => {
        const arr: string[] = []
        for await (const file of Ripgrep.files({
          cwd: dir,
          follow: false,
          hidden: true,
          signal: ctx.abort,
        })) {
          if (path.basename(file) === "SKILL.md") continue
          arr.push(path.resolve(dir, file))
        }
        return arr
      })
        .then((f) => f.map((file) => `<file>${file}</file>`).join("\n"))
        .catch((error) => {
          if (ctx.abort.aborted) throw error
          companionFileListComplete = false
          return "<file-list-unavailable>Skill content loaded; companion-file listing failed.</file-list-unavailable>"
        })

      const chains = SkillIndex.chainsFrom(skill.name)
      const chainInfo =
        chains.length > 0
          ? [
              "",
              "<kill_chain_links>",
              ...chains.map((c) => `  <chain target="${c.target}"${c.boost ? ` boost="${c.boost}"` : ""} />`),
              "</kill_chain_links>",
            ].join("\n")
          : ""

      const rawPrerequisites = SkillIndex.prerequisitesFor(skill.name)
      const prerequisiteInfo =
        rawPrerequisites.length > 0
          ? [
              "",
              "<prerequisites>",
              ...rawPrerequisites.map((reference) => {
                const resolved = SkillIndex.resolveReference(reference)
                if (!resolved) return `  <prerequisite reference="${reference}" status="unresolved-catalog-reference" />`
                const loaded = SkillContext.isLoaded(resolved)
                return `  <prerequisite skill="${resolved}" status="${loaded ? "loaded" : "not-loaded"}" />`
              }),
              "  Verify real-world prerequisites independently; loading a prerequisite skill is not proof that access, credentials, or target conditions exist.",
              "</prerequisites>",
            ].join("\n")
          : ""

      return {
        title: `Loaded skill: ${skill.name}`,
        output: [
          `<skill_content name="${skill.name}" verified="${skill.verified ?? "unverified"}">`,
          `# Skill: ${skill.name}`,
          "",
          skill.content.trim(),
          "",
          `Base directory for this skill: ${base}`,
          "Relative paths in this skill (e.g., scripts/, reference/) are relative to this base directory.",
          companionFileListComplete
            ? "Companion-file listing is complete; use the paths above to read the references or scripts needed by this skill."
            : "Companion-file listing failed; only the SKILL.md content was loaded. Do not assume missing companion paths are absent.",
          "",
          "<skill_files>",
          files,
          "</skill_files>",
          chainInfo,
          prerequisiteInfo,
          "</skill_content>",
        ].join("\n"),
        metadata: { name: skill.name, dir },
      }
    },
  }
})
