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
    const active = new Set(loaded.values().filter((entry) => entry.directory === Instance.directory).map((entry) => entry.name))

    for (const finding of findings) {
      const chains = SkillIndex.chainsFrom(finding.skill_id)
      for (const chain of chains) {
        if (active.has(chain.target) || suggested.has(chain.target)) continue
        suggested.add(chain.target)
        result.push({
          name: chain.target,
          reason: chain.boost ?? `chains with ${finding.skill_id}`,
          priority: chain.boost ? "high" : "medium",
        })
      }

      if (finding.tech_stack?.length) {
        const techSkills = SkillIndex.byTechStack(finding.tech_stack)
        for (const skill of techSkills) {
          if (active.has(skill.name) || suggested.has(skill.name)) continue
          suggested.add(skill.name)
          result.push({
            name: skill.name,
            reason: `matches tech stack: ${finding.tech_stack.join(", ")}`,
            priority: "low",
          })
        }
      }
    }

    return result.sort((a, b) => {
      const order = { high: 0, medium: 1, low: 2 }
      return order[a.priority] - order[b.priority]
    })
  }
}
