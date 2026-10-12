import { Log } from "../util/log"
import { Skill } from "./skill"
import { Instance } from "../project/instance"

export namespace SkillIndex {
  const log = Log.create({ service: "skill-index" })

  export type Entry = {
    name: string
    description: string
    category?: string
    owasp_id?: string
    tags: string[]
    tech_stack: string[]
    cwe_ids: string[]
    chains_with: string[]
    prerequisites: string[]
    severity_boost: Record<string, string>
    verified?: string
  }

  type IndexState = { entries: Map<string, Entry>; tagIndex: Map<string, Set<string>>; techIndex: Map<string, Set<string>>; cweIndex: Map<string, Set<string>>; categoryIndex: Map<string, Set<string>> }
  const states = new Map<string, IndexState>()
  const builds = new Map<string, Promise<void>>()
  const emptyState = (): IndexState => ({ entries: new Map(), tagIndex: new Map(), techIndex: new Map(), cweIndex: new Map(), categoryIndex: new Map() })
  const current = () => states.get(Instance.directory) ?? emptyState()
  let entries = new Map<string, Entry>()
  let tagIndex = new Map<string, Set<string>>()
  let techIndex = new Map<string, Set<string>>()
  let cweIndex = new Map<string, Set<string>>()
  let categoryIndex = new Map<string, Set<string>>()


  function toEntry(skill: Skill.Info): Entry {
    return {
      name: skill.name,
      description: skill.description,
      category: skill.category,
      owasp_id: skill.owasp_id,
      tags: skill.tags ?? [],
      tech_stack: skill.tech_stack ?? [],
      cwe_ids: skill.cwe_ids ?? [],
      chains_with: skill.chains_with ?? [],
      prerequisites: skill.prerequisites ?? [],
      severity_boost: skill.severity_boost ?? {},
      verified: skill.verified,
    }
  }

  function indexEntry(entry: Entry, state: IndexState) {
    for (const tag of entry.tags) {
      if (!state.tagIndex.has(tag.toLowerCase())) state.tagIndex.set(tag.toLowerCase(), new Set())
      state.tagIndex.get(tag.toLowerCase())!.add(entry.name)
    }
    for (const tech of entry.tech_stack) {
      const key = tech.toLowerCase()
      if (!state.techIndex.has(key)) state.techIndex.set(key, new Set())
      state.techIndex.get(key)!.add(entry.name)
    }
    for (const cwe of entry.cwe_ids) {
      const key = cwe.toUpperCase()
      if (!state.cweIndex.has(key)) state.cweIndex.set(key, new Set())
      state.cweIndex.get(key)!.add(entry.name)
    }
    if (entry.category) {
      const key = entry.category.toLowerCase()
      if (!state.categoryIndex.has(key)) state.categoryIndex.set(key, new Set())
      state.categoryIndex.get(key)!.add(entry.name)
    }
  }

  export async function ensureBuilt() {
    if (states.has(Instance.directory)) return
    await rebuild()
  }

  export async function rebuild() {
    const directory = Instance.directory
    const pending = builds.get(directory)
    if (pending) return pending
    const build = (async () => {
      const next = emptyState()
      const skills = await Skill.all()
      for (const skill of skills) {
        const entry = toEntry(skill)
        next.entries.set(entry.name, entry)
        indexEntry(entry, next)
      }
      states.set(directory, next)
      log.info("skill index built", { directory, count: next.entries.size })
    })()
    builds.set(directory, build)
    try { await build } finally { if (builds.get(directory) === build) builds.delete(directory) }
  }

  export function get(name: string): Entry | undefined {
    return entries.get(name)
  }

  export function all(): Entry[] {
    return Array.from(entries.values())
  }

  export function search(query: string, limit = 50): Entry[] {
    const q = query.toLowerCase()
    const scored: Array<{ entry: Entry; score: number }> = []
    for (const entry of entries.values()) {
      let score = 0
      if (entry.name.toLowerCase() === q) score += 100
      else if (entry.name.toLowerCase().startsWith(q)) score += 50
      else if (entry.name.toLowerCase().includes(q)) score += 20
      if (entry.tags.some((t) => t.toLowerCase() === q)) score += 40
      else if (entry.tags.some((t) => t.toLowerCase().includes(q))) score += 15
      if (entry.owasp_id?.toLowerCase().includes(q)) score += 30
      if (entry.category?.toLowerCase().includes(q)) score += 10
      if (entry.description.toLowerCase().includes(q)) score += 5
      if (score > 0) scored.push({ entry, score })
    }
    return scored
      .sort((a, b) => b.score - a.score)
      .slice(0, limit)
      .map((s) => s.entry)
  }

  export function byTechStack(stack: string[], limit = 50): Entry[] {
    const names = new Set<string>()
    for (const tech of stack) {
      const set = techIndex.get(tech.toLowerCase())
      if (set) for (const name of set) names.add(name)
    }
    const results = Array.from(names)
      .map((n) => entries.get(n)!)
      .filter(Boolean)
    return results.slice(0, limit)
  }

  export function byCWE(cweId: string, limit = 50): Entry[] {
    const set = cweIndex.get(cweId.toUpperCase())
    if (!set) return []
    return Array.from(set)
      .slice(0, limit)
      .map((n) => entries.get(n)!)
      .filter(Boolean)
  }

  export function byCategory(cat: string, limit = 50): Entry[] {
    const set = categoryIndex.get(cat.toLowerCase())
    if (!set) return []
    return Array.from(set)
      .slice(0, limit)
      .map((n) => entries.get(n)!)
      .filter(Boolean)
  }

  export function byTag(tag: string, limit = 50): Entry[] {
    const set = tagIndex.get(tag.toLowerCase())
    if (!set) return []
    return Array.from(set)
      .slice(0, limit)
      .map((n) => entries.get(n)!)
      .filter(Boolean)
  }

  export function chainsFrom(skillName: string): Array<{ target: string; boost?: string }> {
    const entry = entries.get(skillName)
    if (!entry) return []
    return entry.chains_with.map((target) => ({
      target,
      boost: entry.severity_boost[target],
    }))
  }

  export function prerequisitesFor(skillName: string): string[] {
    const entry = entries.get(skillName)
    if (!entry) return []
    return entry.prerequisites
  }
}
