import { Log } from "../util/log"
import { Skill } from "./skill"
import { SkillIndex } from "./index-engine"
import { Instance } from "../project/instance"

export namespace SkillContext {
  const log = Log.create({ service: "skill-context" })

  export type ContextScope = {
    sessionID: string
    agent: string
  }

  type LoadedSkill = {
    name: string
    directory: string
    sessionID?: string
    agent?: string
    catalog: ReturnType<typeof Skill.state>
    content: string
    tokens: number
  }

  const loaded = new Map<string, LoadedSkill>()

  function key(name: string, scope?: ContextScope) {
    return Instance.directory + "\0" + (scope?.sessionID ?? "") + "\0" + (scope?.agent ?? "") + "\0" + name
  }

  function matches(entry: LoadedSkill, scope?: ContextScope) {
    if (entry.directory !== Instance.directory) return false
    if (!scope) return true
    return entry.sessionID === scope.sessionID && entry.agent === scope.agent
  }

  function estimateTokens(text: string): number {
    return Math.ceil(text.length / 4)
  }

  function findLoaded(name: string, scope?: ContextScope) {
    const catalog = Skill.state()
    const canonical = SkillIndex.resolveReference(name)
    const normalized = (canonical ?? name).trim().toLocaleLowerCase("en-US")
    for (const [id, entry] of loaded) {
      if (
        matches(entry, scope) &&
        entry.catalog === catalog &&
        entry.name.trim().toLocaleLowerCase("en-US") === normalized
      ) {
        return { id, entry }
      }
    }
    return undefined
  }

  export async function load(name: string, scope?: ContextScope): Promise<string | undefined> {
    // Build the exact alias index before resolving technique IDs, directory slugs,
    // and case-insensitive names. Cache by the skill's canonical name so aliases
    // cannot occupy multiple context slots or double-count tokens.
    for (let attempt = 0; attempt < 3; attempt++) {
      const catalog = Skill.state()
      await SkillIndex.ensureBuilt()
      if (Skill.state() !== catalog) continue

      const canonical = SkillIndex.resolveReference(name) ?? name.trim()
      const id = key(canonical, scope)
      const cached = loaded.get(id)
      if (cached?.catalog === catalog) return cached.content
      if (cached) loaded.delete(id)

      const skill = await Skill.get(canonical)
      if (Skill.state() !== catalog) continue
      if (!skill) {
        log.warn("skill not found for loading", { name })
        return undefined
      }

      const canonicalID = key(skill.name, scope)
      const existing = loaded.get(canonicalID)
      if (existing?.catalog === catalog) return existing.content
      if (existing) loaded.delete(canonicalID)

      const tokens = estimateTokens(skill.content)
      loaded.set(canonicalID, {
        name: skill.name,
        directory: Instance.directory,
        sessionID: scope?.sessionID,
        agent: scope?.agent,
        catalog,
        content: skill.content,
        tokens,
      })
      log.info("skill loaded into context", { name: skill.name, tokens })
      return skill.content
    }

    throw new Error(`Skill catalog changed repeatedly while loading "${name}". Retry the skill operation.`)
  }

  export function unload(name: string, scope?: ContextScope): boolean {
    const existing = findLoaded(name, scope)
    if (!existing) return false
    log.info("skill unloaded from context", { name: existing.entry.name, tokens: existing.entry.tokens })
    loaded.delete(existing.id)
    return true
  }

  export function active(scope?: ContextScope): string[] {
    const catalog = Skill.state()
    return Array.from(
      new Set(
        Array.from(loaded.values())
          .filter((entry) => matches(entry, scope) && entry.catalog === catalog)
          .map((entry) => entry.name),
      ),
    )
  }

  export function tokenCount(scope?: ContextScope): number {
    let total = 0
    const catalog = Skill.state()
    for (const entry of loaded.values()) {
      if (matches(entry, scope) && entry.catalog === catalog) total += entry.tokens
    }
    return total
  }

  export function isLoaded(name: string, scope?: ContextScope): boolean {
    return Boolean(findLoaded(name, scope))
  }

  export function clear(scope?: ContextScope) {
    for (const [id, entry] of loaded) if (matches(entry, scope)) loaded.delete(id)
    log.info("context cleared", { directory: Instance.directory, sessionID: scope?.sessionID, agent: scope?.agent })
  }

  export type Suggestion = {
    name: string
    reason: string
    priority: "high" | "medium" | "low"
  }

  export function suggest(
    findings: Array<{ skill_id: string; severity?: string; cwe_id?: string; tech_stack?: string[] }>,
    allowedSkills?: ReadonlySet<string>,
    scope?: ContextScope,
  ): Suggestion[] {
    const result: Suggestion[] = []
    const allowed = allowedSkills
      ? new Set(Array.from(allowedSkills).flatMap((name) => {
          const canonical = SkillIndex.resolveReference(name)
          return canonical ? [canonical] : []
        }))
      : undefined
    // An allowlist is supplied by the skill tool's agent permission context.
    // Never use a denied or unresolved finding as a source of chain suggestions.
    const candidates = allowed
      ? findings.filter((finding) => {
          const canonical = SkillIndex.resolveReference(finding.skill_id)
          return canonical !== undefined && allowed.has(canonical)
        })
      : findings
    const suggested = new Set<string>()
    const catalog = Skill.state()
    const active = new Set(
      Array.from(loaded.values())
        .filter((entry) => matches(entry, scope) && entry.catalog === catalog)
        .map((entry) => entry.name),
    )
    // Findings already present in the input are completed context, not new
    // skill-chain work to suggest again.
    const observed = new Set(
      candidates.flatMap((finding) => {
        const canonical = SkillIndex.resolveReference(finding.skill_id)
        return canonical ? [canonical] : []
      }),
    )

    function addWithPrerequisites(
      name: string,
      reason: string,
      priority: Suggestion["priority"],
      visiting = new Set<string>(),
    ) {
      const canonical = SkillIndex.resolveReference(name) ?? name
      if (allowed && !allowed.has(canonical)) return
      name = canonical
      if (active.has(name) || observed.has(name) || suggested.has(name) || visiting.has(name)) return
      visiting.add(name)

      // Resolve and surface prerequisite skills before the skill that depends on
      // them. This suggests the reading order; it does not claim the real-world
      // prerequisite (such as credentials) exists.
      for (const reference of SkillIndex.prerequisitesFor(name)) {
        const prerequisite = SkillIndex.resolveReference(reference)
        if (
          !prerequisite ||
          (allowed && !allowed.has(prerequisite)) ||
          active.has(prerequisite) ||
          suggested.has(prerequisite)
        ) continue
        addWithPrerequisites(
          prerequisite,
          `prerequisite for ${name}`,
          priority === "high" ? "high" : "medium",
          visiting,
        )
      }

      visiting.delete(name)
      if (active.has(name) || observed.has(name) || suggested.has(name)) return
      suggested.add(name)
      result.push({ name, reason, priority })
    }

    for (const finding of candidates) {
      const severity = finding.severity?.toLowerCase()
      const priority: Suggestion["priority"] =
        severity === "critical" || severity === "high" ? "high" : severity === "medium" ? "medium" : "low"

      const chains = SkillIndex.chainsFrom(finding.skill_id)
      for (const chain of chains) {
        addWithPrerequisites(
          chain.target,
          chain.boost ?? `chains with ${finding.skill_id}`,
          chain.boost ? "high" : "medium",
        )
      }

      if (finding.cwe_id?.trim()) {
        for (const skill of SkillIndex.byCWE(finding.cwe_id.trim())) {
          addWithPrerequisites(
            skill.name,
            `matches CWE: ${finding.cwe_id}`,
            priority,
          )
        }
      }

      if (finding.tech_stack?.length) {
        const techSkills = SkillIndex.byTechStack(finding.tech_stack)
        for (const skill of techSkills) {
          addWithPrerequisites(
            skill.name,
            `matches tech stack: ${finding.tech_stack.join(", ")}`,
            "low",
          )
        }
      }
    }

    return result.sort((a, b) => {
      const order = { high: 0, medium: 1, low: 2 }
      return order[a.priority] - order[b.priority]
    })
  }
}
