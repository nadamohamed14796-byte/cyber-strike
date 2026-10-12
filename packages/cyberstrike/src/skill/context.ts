import { Log } from "../util/log"
import { Skill } from "./skill"
import { SkillIndex } from "./index-engine"
import { Instance } from "../project/instance"

export namespace SkillContext {
  const log = Log.create({ service: "skill-context" })

  const loaded = new Map<string, { name: string; directory: string; content: string; tokens: number }>()

  function key(name: string) {
    return `${Instance.directory}\\0${name}`
  }

  function estimateTokens(text: string): number {
    return Math.ceil(text.length / 4)
  }

  export async function load(name: string): Promise<string | undefined> {
    const id = key(name)
    if (loaded.has(id)) return loaded.get(id)!.content

    const skill = await Skill.get(name)
    if (!skill) {
      log.warn("skill not found for loading", { name })
      return undefined
    }

    const tokens = estimateTokens(skill.content)
    loaded.set(id, { name, directory: Instance.directory, content: skill.content, tokens })
    log.info("skill loaded into context", { name, tokens })
    return skill.content
  }

  export function unload(name: string): boolean {
    const id = key(name)
    const had = loaded.has(id)
    if (had) {
      log.info("skill unloaded from context", { name, tokens: loaded.get(id)!.tokens })
      loaded.delete(id)
    }
    return had
  }

  export function active(): string[] {
    return Array.from(loaded.values()).filter((entry) => entry.directory === Instance.directory).map((entry) => entry.name)
  }

  export function tokenCount(): number {
    let total = 0
    for (const entry of loaded.values()) if (entry.directory === Instance.directory) total += entry.tokens
    return total
  }

  export function isLoaded(name: string): boolean {
    return loaded.has(key(name))
  }

  export function clear() {
    for (const [id, entry] of loaded) if (entry.directory === Instance.directory) loaded.delete(id)
    log.info("context cleared", { directory: Instance.directory })
  }

  export type Suggestion = {
    name: string
    reason: string
    priority: "high" | "medium" | "low"
  }

  export function suggest(
    findings: Array<{ skill_id: string; severity?: string; cwe_id?: string; tech_stack?: string[] }>,
  ): Suggestion[] {
    const result: Suggestion[] = []
    const suggested = new Set<string>()
    const active = new Set(
      Array.from(loaded.values()).filter((entry) => entry.directory === Instance.directory).map((entry) => entry.name),
    )

    function addWithPrerequisites(
      name: string,
      reason: string,
      priority: Suggestion["priority"],
      visiting = new Set<string>(),
    ) {
      if (active.has(name) || suggested.has(name) || visiting.has(name)) return
      visiting.add(name)

      // Resolve and surface prerequisite skills before the skill that depends on
      // them. This suggests the reading order; it does not claim the real-world
      // prerequisite (such as credentials) exists.
      for (const reference of SkillIndex.prerequisitesFor(name)) {
        const prerequisite = SkillIndex.resolveReference(reference)
        if (!prerequisite || active.has(prerequisite) || suggested.has(prerequisite)) continue
        addWithPrerequisites(
          prerequisite,
          `prerequisite for ${name}`,
          priority === "high" ? "high" : "medium",
          visiting,
        )
      }

      visiting.delete(name)
      if (active.has(name) || suggested.has(name)) return
      suggested.add(name)
      result.push({ name, reason, priority })
    }

    for (const finding of findings) {
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
