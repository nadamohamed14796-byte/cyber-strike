import path from "path"
import { Log } from "../util/log"
import { Skill } from "./skill"
import { Instance } from "../project/instance"

export namespace SkillIndex {
  const log = Log.create({ service: "skill-index" })

  export type Entry = {
    name: string
    description: string
    location?: string
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

  type IndexState = {
    catalog?: ReturnType<typeof Skill.state>
    entries: Map<string, Entry>
    tagIndex: Map<string, Set<string>>
    techIndex: Map<string, Set<string>>
    cweIndex: Map<string, Set<string>>
    categoryIndex: Map<string, Set<string>>
    referenceIndex: Map<string, Set<string>>
  }
  const states = new Map<string, IndexState>()
  const builds = new Map<string, { catalog: ReturnType<typeof Skill.state>; promise: Promise<void> }>()
  const emptyState = (): IndexState => ({
    entries: new Map(),
    tagIndex: new Map(),
    techIndex: new Map(),
    cweIndex: new Map(),
    categoryIndex: new Map(),
    referenceIndex: new Map(),
  })
  const current = () => states.get(Instance.directory) ?? emptyState()

  const TECHNIQUE_ID = /^t\d{4}(?:\.\d{3})?$/i

  function addReference(state: IndexState, reference: string | undefined, skillName: string) {
    const key = reference?.trim().toLowerCase()
    if (!key) return
    if (!state.referenceIndex.has(key)) state.referenceIndex.set(key, new Set())
    state.referenceIndex.get(key)!.add(skillName)
  }

  function indexReferences(entry: Entry, state: IndexState) {
    // Exact name aliases are case-insensitive; technique aliases are explicit IDs,
    // never fuzzy substring/prefix matches.
    addReference(state, entry.name, entry.name)
    addReference(state, entry.owasp_id, entry.name)
    // Imported catalogs commonly link controls by their directory slug, while
    // the visible frontmatter name is human-readable. Index both as exact aliases.
    if (entry.location) addReference(state, path.basename(path.dirname(entry.location)), entry.name)

    const nameTechnique = /^((?:T\d{4})(?:\.\d{3})?)(?:[_-]|$)/i.exec(entry.name)?.[1]
    if (nameTechnique) addReference(state, nameTechnique, entry.name)
    // Exact tag aliases are used by methodology routing and agent tool calls.
    // Shared tags stay ambiguous because resolveInState only accepts unique aliases.
    for (const tag of entry.tags) addReference(state, tag, entry.name)
    for (const tech of entry.tech_stack) addReference(state, tech, entry.name)
    for (const cwe of entry.cwe_ids) addReference(state, cwe, entry.name)
  }

  function resolveInState(reference: string, state: IndexState): string | undefined {
    const normalized = reference.trim().toLowerCase()
    if (!normalized) return undefined

    const resolveExact = (key: string) => {
      const candidates = state.referenceIndex.get(key)
      if (!candidates || candidates.size !== 1) return undefined
      return candidates.values().next().value
    }

    const exact = resolveExact(normalized)
    if (exact) return exact

    // A documented alias convention: metadata sometimes prefixes workflow links
    // with "attack-" while the canonical skill is named without that prefix.
    // Resolve only when the remaining full name is an exact unique skill name;
    // never perform substring or token similarity matching.
    if (normalized.startsWith("attack-")) return resolveExact(normalized.slice("attack-".length))
    return undefined
  }

  function toEntry(skill: Skill.Info): Entry {
    return {
      name: skill.name,
      description: skill.description,
      location: skill.location,
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
    indexReferences(entry, state)
  }

  export async function ensureBuilt() {
    const directory = Instance.directory
    const catalog = Skill.state()
    if (states.get(directory)?.catalog === catalog) return
    await rebuild()
    if (Skill.state() !== catalog || states.get(directory)?.catalog !== catalog) {
      await rebuild()
      if (states.get(directory)?.catalog !== Skill.state()) {
        throw new Error("Skill index could not stabilize because the skill catalog changed during rebuild.")
      }
    }
  }

  export async function rebuild() {
    const directory = Instance.directory
    const catalog = Skill.state()
    const pending = builds.get(directory)
    if (pending?.catalog === catalog) return pending.promise
    const build = (async () => {
      const next = emptyState()
      next.catalog = catalog
      const skills = await Skill.all()
      for (const skill of skills) {
        const entry = toEntry(skill)
        next.entries.set(entry.name, entry)
        indexEntry(entry, next)
      }
      // A disposed/recreated project must not let an older async build overwrite the new catalog.
      if (Skill.state() !== catalog) return
      states.set(directory, next)
      const referenceProblems = validateReferences()
      if (referenceProblems.length) {
        log.warn("skill index contains unresolved metadata references", {
          directory,
          count: referenceProblems.length,
          examples: referenceProblems.slice(0, 10),
        })
      }
      log.info("skill index built", { directory, count: next.entries.size })
    })()
    builds.set(directory, { catalog, promise: build })
    try {
      await build
    } finally {
      if (builds.get(directory)?.promise === build) builds.delete(directory)
    }
  }

  export function get(name: string): Entry | undefined {
    return current().entries.get(name)
  }

  export function all(): Entry[] {
    return Array.from(current().entries.values())
  }

  export function search(query: string, limit = 50): Entry[] {
    const state = current()
    const q = query.toLowerCase().trim()
    if (!q) return []
    const scored: Array<{ entry: Entry; score: number }> = []
    for (const entry of state.entries.values()) {
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
    const state = current()
    const names = new Set<string>()
    for (const tech of stack) {
      const set = state.techIndex.get(tech.toLowerCase())
      if (set) for (const name of set) names.add(name)
    }
    const results = Array.from(names)
      .map((n) => state.entries.get(n)!)
      .filter(Boolean)
    return results.slice(0, limit)
  }

  export function byCWE(cweId: string, limit = 50): Entry[] {
    const state = current()
    const set = state.cweIndex.get(cweId.toUpperCase())
    if (!set) return []
    return Array.from(set)
      .slice(0, limit)
      .map((n) => state.entries.get(n)!)
      .filter(Boolean)
  }

  export function byCategory(cat: string, limit = 50): Entry[] {
    const state = current()
    const set = state.categoryIndex.get(cat.toLowerCase())
    if (!set) return []
    return Array.from(set)
      .slice(0, limit)
      .map((n) => state.entries.get(n)!)
      .filter(Boolean)
  }

  export function byTag(tag: string, limit = 50): Entry[] {
    const state = current()
    const set = state.tagIndex.get(tag.toLowerCase())
    if (!set) return []
    return Array.from(set)
      .slice(0, limit)
      .map((n) => state.entries.get(n)!)
      .filter(Boolean)
  }

  /** Resolve an exact skill name or exact metadata alias (for example T1078.004). */
  export function resolveReference(reference: string): string | undefined {
    return resolveInState(reference, current())
  }

  export type ReferenceProblem = {
    skill: string
    field: "chains_with" | "prerequisites"
    reference: string
    reason: "unresolved" | "ambiguous"
  }

  /**
   * Audit skill-to-skill links. Some imported catalog entries use external control
   * IDs (for example NIST "PE-18") in chains_with, and prerequisites may contain
   * human-readable authorization/precondition statements. These are not skill
   * names and must not be reported as dangling skill links.
   */
  export function validateReferences(): ReferenceProblem[] {
    const state = current()
    const problems: ReferenceProblem[] = []
    const isExternalControlId = (reference: string) =>
      /^[A-Z]{2,5}-\d+(?:\(\d+\))?$/i.test(reference.trim())
    const isExternalAttackTechniqueId = (reference: string) =>
      /^T\d{4}(?:\.\d{3})?$/i.test(reference.trim())
    const isPrerequisiteStatement = (reference: string) => /\s/.test(reference.trim())

    for (const entry of state.entries.values()) {
      for (const field of ["chains_with", "prerequisites"] as const) {
        for (const reference of entry[field]) {
          if (resolveInState(reference, state)) continue
          // Compliance/control and ATT&CK technique IDs may be useful external
          // annotations, not necessarily names of locally installed skill entries.
          // Keep unresolved prerequisites intact; this only avoids false dangling-link
          // reports and does not mark an unknown prerequisite as satisfied.
          if (isExternalControlId(reference)) continue
          if (field === "chains_with" && isExternalAttackTechniqueId(reference)) continue
          if (field === "prerequisites" && isPrerequisiteStatement(reference)) continue

          const candidates = state.referenceIndex.get(reference.trim().toLowerCase())
          problems.push({
            skill: entry.name,
            field,
            reference,
            reason: candidates && candidates.size > 1 ? "ambiguous" : "unresolved",
          })
        }
      }
    }
    return problems
  }

  export function chainsFrom(skillName: string): Array<{ target: string; boost?: string }> {
    const state = current()
    const canonical = resolveInState(skillName, state)
    const entry = canonical ? state.entries.get(canonical) : undefined
    if (!entry) return []
    return entry.chains_with.flatMap((reference) => {
      const target = resolveInState(reference, state)
      if (!target) return []
      return [{ target, boost: entry.severity_boost[reference] ?? entry.severity_boost[target] }]
    })
  }

  export function prerequisitesFor(skillName: string): string[] {
    const state = current()
    const canonical = resolveInState(skillName, state)
    const entry = canonical ? state.entries.get(canonical) : undefined
    if (!entry) return []
    // Preserve unresolved values so callers can report them instead of silently
    // treating an incomplete catalogue reference as a satisfied prerequisite.
    return entry.prerequisites.map((reference) => resolveInState(reference, state) ?? reference)
  }
}
