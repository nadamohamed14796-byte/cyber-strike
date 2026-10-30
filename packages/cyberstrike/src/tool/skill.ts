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

const accessibleCache = new Map<string, { catalog: ReturnType<typeof Skill.state>; permissionFingerprint: string; skills: Skill.Metadata[] }>()

export const SkillTool = Tool.define("skill", async (ctx) => {
  // Lazy load skills only when tool is executed
  const description = [
    "Find and load the right skill from the skills available in the complete catalog when it helps the current task.",
    "",
    "Simple workflow: search by evidence, technology, or skill name; load the exact returned name; read the returned content before applying it. All catalog skills are searchable and loadable, but load only relevant skills rather than the whole catalog.",
    "",
    "Actions: load full content; search metadata; outline a preview; list available/loaded skills; suggest or chain conditional next skills; unload a skill when no longer needed.",
    "Search supports exact signal, tag, tech-stack, CWE, category, or free-text routing filters. Explicit signals and legacy tags share one searchable signal vocabulary. Search and list are paginated; continue with the returned next offset when needed. A search hit or outline is not loaded content. A skill never grants scope or testing permission."
  ].join("\n")

  const parameters = z.object({
    action: z
      .enum(["load", "outline", "unload", "search", "chain", "suggest", "list"])
      .default("load")
      .describe("Action to perform"),
    name: z.string().optional().describe("Exact skill name from search/list (preferred for load/outline/unload)"),
    query: z.string().optional().describe("Search by observed technology, behavior, skill name, or evidence gap"),
    tech: z.array(z.string()).optional().describe("Tech stack filter (for search action)"),
    tag: z.string().optional().describe("Exact skill tag filter (for search action)"),
    signal: z.string().optional().describe("Exact observed-behavior signal alias filter (explicit signals plus legacy tags)"),
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
      for (let attempt = 0; attempt < 5 && !stableCatalog; attempt++) {
        await SkillIndex.ensureBuilt()
        catalog = Skill.state()
        skills = await Skill.all()
        stableCatalog = Skill.state() === catalog
      }
      if (!stableCatalog) {
        throw new Error("Skill catalog changed repeatedly while resolving accessible skills; retry the skill operation.")
      }

      const agentID = await Agent.resolveID(ctx.agent)
      if (ctx.agent && !agentID) throw new Error(`Unable to resolve skill caller agent "${ctx.agent}"; refusing to bypass skill permissions.`)
      const agentKey = `${Instance.directory}\\0${agentID ?? ""}`
      const agentInfo = agentID ? await Agent.get(agentID) : undefined
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
      const accessibleNames = new Set(accessibleSkills.map((skill) => skill.name))
      const contextScope: SkillContext.ContextScope = { sessionID: ctx.sessionID, agent: ctx.agent }
      const escapeXmlAttribute = (value: string) =>
        value.replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;").replace(/>/g, "&gt;")

      if (params.action === "list") {
        if (params.loaded) {
          const active = SkillContext.active(contextScope)
          const tokens = SkillContext.tokenCount(contextScope)
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
              (s.tech_stack?.length ? " [" + s.tech_stack.join(", ") + "]" : "") +
              (s.signals?.length ? " {signals: " + s.signals.join(", ") + "}" : ""),
            ),
            ...(hasMore ? ["", "More skills remain. Repeat action=\"list\" with offset=" + nextOffset + " and limit=" + limit + ", or use action=\"search\" to narrow the catalog."] : []),
          ].join("\n"),
          metadata: { offset, next_offset: hasMore ? nextOffset : null, total: all.length } as { name?: string; dir?: string; offset: number; next_offset: number | null; total: number },
        }
      }

      if (params.action === "unload") {
        if (!params.name) throw new Error("Skill name required for unload action")
        const canonicalName = accessibleSkills.find((entry) => entry.name.trim().toLocaleLowerCase("en-US") === params.name!.trim().toLocaleLowerCase("en-US"))?.name ?? SkillIndex.resolveReference(params.name) ?? params.name
        const removed = SkillContext.unload(canonicalName, contextScope)
        return {
          title: removed ? `Unloaded: ${canonicalName}` : `Not loaded: ${canonicalName}`,
          output: removed
            ? `Skill "${canonicalName}" removed from context. Active tokens: ${SkillContext.tokenCount(contextScope)}`
            : `Skill "${canonicalName}" was not in context.`,
          metadata: {} as { name?: string; dir?: string },
        }
      }

      if (params.action === "search") {
        const limit = Math.max(1, params.limit ?? 25)
        const offset = Math.max(0, params.offset ?? 0)
        const accessibleNames = new Set(accessibleSkills.map((skill) => skill.name))
        // Apply every supplied signal together: exact metadata filters intersect,
        // while a tech array is an OR group (any listed technology may match).
        // Free-text relevance establishes the initial ordering when present.
        const candidates = params.query
          ? SkillIndex.search(params.query, Infinity)
          : SkillIndex.all().sort((left, right) => left.name.localeCompare(right.name))
        const filterSets: Set<string>[] = []
        if (params.cwe) filterSets.push(new Set(SkillIndex.byCWE(params.cwe, Infinity).map((entry) => entry.name)))
        if (params.tech?.length) filterSets.push(new Set(SkillIndex.byTechStack(params.tech, Infinity).map((entry) => entry.name)))
        if (params.category) filterSets.push(new Set(SkillIndex.byCategory(params.category, Infinity).map((entry) => entry.name)))
        if (params.tag) filterSets.push(new Set(SkillIndex.byTag(params.tag, Infinity).map((entry) => entry.name)))
        if (params.signal) filterSets.push(new Set(SkillIndex.bySignal(params.signal, Infinity).map((entry) => entry.name)))
        const matched = candidates.filter((entry) => filterSets.every((set) => set.has(entry.name)))
        // Filter permissions before paginating so denied skills neither leak nor hide allowed results.
        const permitted = matched.filter((entry) => accessibleNames.has(entry.name))
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
            ...results.flatMap((r) => {
              const visibleChains = SkillIndex.chainsFrom(r.name)
                .map((item) => item.target)
                .filter((name) => accessibleNames.has(name))
              const visiblePrerequisites = SkillIndex.prerequisitesFor(r.name).flatMap((reference) => {
                const resolved = SkillIndex.resolveReference(reference)
                if (resolved) return accessibleNames.has(resolved) ? [resolved] : []
                // Human-readable prerequisites are conditions, not skill links.
                // Omit unresolved slug-like references rather than presenting broken targets.
                return /\s/.test(reference.trim()) ? [reference] : []
              })
              return [
                "- **" + r.name + "** [" + (r.verified ?? "unverified") + "] — " + r.description,
                "  Routing: category=" + (r.category ?? "unspecified") +
                  "; tags=" + (r.tags.join(", ") || "none") +
                  "; signals=" + (r.signals.join(", ") || "none") +
                  "; tech_stack=" + (r.tech_stack.join(", ") || "none") +
                  "; CWE=" + (r.cwe_ids.join(", ") || "none") +
                  "; OWASP=" + (r.owasp_id ?? "none"),
                "  chains_with: " + (visibleChains.join(", ") || "no accessible local chain partner"),
                "  prerequisites: " + (visiblePrerequisites.join("; ") || "none resolved"),
              ]
            }),
            ...(hasMore ? ["", "More results remain. Repeat the same search filters with offset=" + nextOffset + " and limit=" + limit + ", or refine the query."] : []),
          ].join("\n"),
          metadata: { offset, next_offset: hasMore ? nextOffset : null, total: totalCount } as { name?: string; dir?: string; offset: number; next_offset: number | null; total: number },
        }
      }

      if (params.action === "chain") {
        if (!params.findings?.length) throw new Error("Findings required for chain analysis")
        const allowedSkills = new Set(accessibleSkills.map((skill) => skill.name))
        const summary = KillChain.summary(
          params.findings.map((finding) => ({ ...finding, severity: finding.severity ?? "medium" })),
          allowedSkills,
        )
        return { title: "Kill Chain Analysis", output: summary, metadata: {} as { name?: string; dir?: string } }
      }

      if (params.action === "suggest") {
        if (!params.findings?.length) throw new Error("Findings required for suggestions")
        const allowedSkills = new Set(accessibleSkills.map((skill) => skill.name))
        const suggestions = SkillContext.suggest(
          params.findings.map((finding) => ({ ...finding, severity: finding.severity ?? "medium" })),
          allowedSkills,
          contextScope,
        )
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

      if (params.action === "outline") {
        if (!params.name) throw new Error("Skill name required for outline action")
        const canonicalName = accessibleSkills.find((entry) => entry.name.trim().toLocaleLowerCase("en-US") === params.name!.trim().toLocaleLowerCase("en-US"))?.name ?? SkillIndex.resolveReference(params.name) ?? params.name
        const skill = await Skill.get(canonicalName)
        if (!skill) {
          throw new Error(`Skill "${params.name}" was not found or has an ambiguous metadata reference. Use skill(action="search", query="...") to find an exact name.`)
        }
        if (!accessibleSkills.some((entry) => entry.name === canonicalName)) {
          throw new Error(`Permission denied: skill "${canonicalName}" is not accessible to agent "${ctx.agent ?? "unknown"}".`)
        }
        const outlineChains = SkillIndex.chainsFrom(skill.name).filter((item) => accessibleNames.has(item.target))
        const outlinePrerequisites = SkillIndex.prerequisitesFor(skill.name).flatMap((reference) => {
          const resolved = SkillIndex.resolveReference(reference)
          if (resolved) return accessibleNames.has(resolved) ? [resolved] : []
          return /\s/.test(reference.trim()) ? [reference] : []
        })
        const headings = skill.content
          .split(/\r?\n/)
          .filter((line) => /^\s{0,3}#{1,4}\s+/.test(line))
          .map((line) => "## " + line.trim().replace(/^#{1,4}\s+/, ""))
          .slice(0, 40)
        const skillLines = skill.content.split(/\r?\n/)
        const bodyStart = skillLines[0]?.trim() === "---"
          ? skillLines.findIndex((line, index) => index > 0 && /^\s*---\s*$/.test(line)) + 1
          : 0
        const body = skillLines.slice(Math.max(0, bodyStart))
        const intro = body
          .slice(0, body.findIndex((line) => /^\s{0,3}#{1,6}\s+/.test(line)) < 0
            ? body.length
            : body.findIndex((line) => /^\s{0,3}#{1,6}\s+/.test(line)))
          .filter((line) => line.trim())
          .slice(0, 4)
          .join("\n")
          .slice(0, 700)
        return {
          title: `Skill outline: ${skill.name}`,
          output: [
            `## Skill outline: ${skill.name}`,
            `Description: ${skill.description}`,
            `Verification: ${skill.verified ?? "unverified"}`,
            `Category: ${skill.category ?? "unspecified"}`,
            `Tags: ${skill.tags?.join(", ") || "none declared"}`,
            `Signals: ${SkillIndex.get(skill.name)?.signals.join(", ") || skill.signals?.join(", ") || skill.tags?.join(", ") || "none declared"}`,
            `Technologies: ${skill.tech_stack?.join(", ") || "none declared"}`,
            `CWE IDs: ${skill.cwe_ids?.join(", ") || "none declared"}`,
            `OWASP ID: ${skill.owasp_id ?? "none"}`,
            `chains_with (resolved and accessible): ${outlineChains.map((item) => item.target).join(", ") || "none"}${(skill.chains_with?.length ?? 0) > outlineChains.length ? " (some declared references are unresolved or unavailable and were omitted)" : ""}`,
            `prerequisites (resolved/conditions): ${outlinePrerequisites.join("; ") || "none"}${(skill.prerequisites?.length ?? 0) > outlinePrerequisites.length ? " (some declared references are unresolved or unavailable and were omitted)" : ""}`,
            "",
            "Preview only — full skill content has NOT been loaded into context.",
            "",
            "### Introduction",
            intro,
            "",
            "### Sections",
            ...(headings.length ? headings : ["(No Markdown headings found)"]),
            "",
            "Load this skill by exact canonical name only if its detailed procedures are needed.",
          ].join("\n").slice(0, 2_400),
          metadata: { name: skill.name, dir: path.dirname(skill.location), outline: true },
        }
      }

      // Allow exact technique IDs from skill metadata to resolve to the one
      // canonical catalog entry; ambiguous aliases deliberately do not resolve.
      const canonicalName = accessibleSkills.find((entry) => entry.name.trim().toLocaleLowerCase("en-US") === params.name!.trim().toLocaleLowerCase("en-US"))?.name ?? SkillIndex.resolveReference(params.name) ?? params.name
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

      const loadedContent = await SkillContext.load(canonicalName, contextScope)
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

      const declaredChainCount = skill.chains_with?.length ?? 0
      const chains = SkillIndex.chainsFrom(skill.name).filter((item) => accessibleNames.has(item.target))
      const chainInfo =
        chains.length > 0 || declaredChainCount > chains.length
          ? [
              "",
              "<kill_chain_links>",
              ...chains.map((c) => `  <chain target="${escapeXmlAttribute(c.target)}"${c.boost ? ` boost="${escapeXmlAttribute(c.boost)}"` : ""} />`),
              ...(declaredChainCount > chains.length
                ? ["  Some declared chain references were unresolved or unavailable under current permissions and were omitted."]
                : []),
              "</kill_chain_links>",
            ].join("\n")
          : ""

      const rawPrerequisites = SkillIndex.prerequisitesFor(skill.name)
      let omittedPrerequisiteCount = 0
      const prerequisiteLines = rawPrerequisites.flatMap((reference) => {
        const resolved = SkillIndex.resolveReference(reference)
        if (resolved) {
          if (!accessibleNames.has(resolved)) {
            omittedPrerequisiteCount++
            return []
          }
          const loaded = SkillContext.isLoaded(resolved, contextScope)
          return [`  <prerequisite skill="${escapeXmlAttribute(resolved)}" status="${loaded ? "loaded" : "not-loaded"}" />`]
        }
        // Human-readable prerequisites are real-world conditions, not skill links.
        if (/\s/.test(reference.trim())) {
          return [`  <prerequisite condition="${escapeXmlAttribute(reference)}" status="verify-independently" />`]
        }
        omittedPrerequisiteCount++
        return []
      })
      const prerequisiteInfo =
        rawPrerequisites.length > 0
          ? [
              "",
              "<prerequisites>",
              ...prerequisiteLines,
              ...(omittedPrerequisiteCount > 0
                ? [`  ${omittedPrerequisiteCount} declared prerequisite reference(s) were unresolved or unavailable under current permissions and were omitted.`]
                : []),
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
          `Routing metadata: category=${skill.category ?? "unspecified"}; tags=${skill.tags?.join(", ") || "none declared"}; signals=${SkillIndex.get(skill.name)?.signals.join(", ") || skill.signals?.join(", ") || skill.tags?.join(", ") || "none declared"}; tech_stack=${skill.tech_stack?.join(", ") || "none declared"}; CWE=${skill.cwe_ids?.join(", ") || "none"}; OWASP=${skill.owasp_id ?? "none"}`,
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
