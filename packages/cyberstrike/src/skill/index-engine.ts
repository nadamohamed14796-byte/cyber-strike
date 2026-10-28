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
    // Keep canonical names separate from aliases so a shared tag/tech stack
    // cannot make a real skill name ambiguous.
    nameIndex: Map<string, Set<string>>
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
    nameIndex: new Map(),
    referenceIndex: new Map(),
  })
  const current = () => states.get(Instance.directory) ?? emptyState()

  const TECHNIQUE_ID = /^t\d{4}(?:\.\d{3})?$/i

  function addReference(state: IndexState, reference: string | undefined, skillName: string) {
    const key = reference ? normalizeSearchText(reference) : ""
    if (!key) return
    if (!state.referenceIndex.has(key)) state.referenceIndex.set(key, new Set())
    state.referenceIndex.get(key)!.add(skillName)
  }

  function indexReferences(entry: Entry, state: IndexState) {
    // Canonical names have priority over aliases shared by multiple skills.
    // Keep this index separate so a popular tech-stack tag (for example "aws")
    // cannot make a real skill named "aws" unresolvable.
    const nameKey = normalizeSearchText(entry.name)
    if (nameKey) {
      if (!state.nameIndex.has(nameKey)) state.nameIndex.set(nameKey, new Set())
      state.nameIndex.get(nameKey)!.add(entry.name)
    }
    // Technique aliases are explicit IDs, never fuzzy substring/prefix matches.
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
    const normalized = normalizeSearchText(reference)
    if (!normalized) return undefined

    const canonicalNames = state.nameIndex.get(normalized)
    if (canonicalNames?.size) {
      return canonicalNames.size === 1 ? canonicalNames.values().next().value : undefined
    }

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
    if (normalized.startsWith("attack ")) return resolveExact(normalized.slice("attack ".length))
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
      const key = normalizeSearchText(tag)
      if (!key) continue
      if (!state.tagIndex.has(key)) state.tagIndex.set(key, new Set())
      state.tagIndex.get(key)!.add(entry.name)
    }
    for (const tech of entry.tech_stack) {
      const key = normalizeSearchText(tech)
      if (!key) continue
      if (!state.techIndex.has(key)) state.techIndex.set(key, new Set())
      state.techIndex.get(key)!.add(entry.name)
    }
    for (const cwe of entry.cwe_ids) {
      const key = cwe.toUpperCase()
      if (!state.cweIndex.has(key)) state.cweIndex.set(key, new Set())
      state.cweIndex.get(key)!.add(entry.name)
    }
    if (entry.category) {
      const key = normalizeSearchText(entry.category)
      if (key) {
        if (!state.categoryIndex.has(key)) state.categoryIndex.set(key, new Set())
        state.categoryIndex.get(key)!.add(entry.name)
      }
    }
    indexReferences(entry, state)
  }

  export async function ensureBuilt() {
    const directory = Instance.directory
    // Skill.state() may be invalidated while Skill.all() scans local and external
    // catalogs. Retry against the newest snapshot instead of leaving callers with
    // an empty/stale index after only one concurrent refresh.
    for (let attempt = 0; attempt < 5; attempt++) {
      const catalog = Skill.state()
      if (states.get(directory)?.catalog === catalog) return
      await rebuild()
      if (Skill.state() === catalog && states.get(directory)?.catalog === catalog) return
    }
    throw new Error("Skill catalog changed repeatedly while building the skill index; retry the skill operation.")
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

  function normalizeSearchText(value: string): string {
    return value
      .toLocaleLowerCase("en-US")
      .replace(/[_/.-]+/g, " ")
      .replace(/[^a-z0-9 ]+/g, " ")
      .replace(/\s+/g, " ")
      .trim()
  }

  export function search(query: string, limit = 50): Entry[] {
    const state = current()
    const q = normalizeSearchText(query)
    if (!q) return []
    const queryTokens = [...new Set(q.split(" ").filter((token) => token.length > 1))]
    const scored: Array<{ entry: Entry; score: number }> = []

    for (const entry of state.entries.values()) {
      // Search all routing metadata, not just the display name and description.
      // This lets an agent find skills by category, tags, technology, CWE, and
      // explicit prerequisites/chain partners using natural-language queries.
      const fields = [
        entry.name,
        entry.description,
        entry.category ?? "",
        entry.owasp_id ?? "",
        ...entry.tags,
        ...entry.tech_stack,
        ...entry.cwe_ids,
        ...entry.chains_with,
        ...entry.prerequisites,
      ].map(normalizeSearchText).filter(Boolean)
      const name = normalizeSearchText(entry.name)
      const tags = entry.tags.map(normalizeSearchText).filter(Boolean)
      const category = normalizeSearchText(entry.category ?? "")
      const tech = entry.tech_stack.map(normalizeSearchText).filter(Boolean)
      const cwes = entry.cwe_ids.map(normalizeSearchText).filter(Boolean)
      const chains = entry.chains_with.map(normalizeSearchText).filter(Boolean)
      const prerequisites = entry.prerequisites.map(normalizeSearchText).filter(Boolean)

      let score = 0
      if (name === q) score += 140
      else if (name.startsWith(q)) score += 80
      else if (name.includes(q)) score += 45
      if (tags.includes(q)) score += 110
      else if (tags.some((tag) => tag.includes(q))) score += 35
      if (category === q) score += 65
      else if (category && category.includes(q)) score += 25
      if (tech.includes(q)) score += 70
      else if (tech.some((value) => value.includes(q))) score += 25
      if (cwes.includes(q)) score += 90
      else if (cwes.some((value) => value.includes(q))) score += 25
      if (chains.includes(q)) score += 45
      else if (chains.some((value) => value.includes(q))) score += 20
      if (prerequisites.includes(q)) score += 45
      else if (prerequisites.some((value) => value.includes(q))) score += 20
      if (normalizeSearchText(entry.owasp_id ?? "").includes(q)) score += 45
      if (normalizeSearchText(entry.description).includes(q)) score += 15

      // Multiword queries such as "JavaScript analysis" should match the
      // canonical slug "attack-javascript-analysis" and equivalent tags.
      const matchedTokens = queryTokens.filter((token) => fields.some((field) => field.includes(token)))
      const tokenThreshold = queryTokens.length <= 1 ? 1 : Math.ceil(queryTokens.length * 0.67)
      if (matchedTokens.length >= tokenThreshold) {
        score += matchedTokens.length * 6
      } else if (score === 0) {
        continue
      }
      if (score > 0) scored.push({ entry, score })
    }

    return scored
      .sort((a, b) => b.score - a.score || a.entry.name.localeCompare(b.entry.name))
      .slice(0, limit)
      .map((item) => item.entry)
  }

  export function byTechStack(stack: string[], limit = 50): Entry[] {
    const state = current()
    const names = new Set<string>()
    for (const tech of stack) {
      const set = state.techIndex.get(normalizeSearchText(tech))
      if (set) for (const name of set) names.add(name)
    }
    const results = Array.from(names)
      .map((n) => state.entries.get(n)!)
      .filter(Boolean)
      .sort((a, b) => a.name.localeCompare(b.name))
    return results.slice(0, limit)
  }

  export function byCWE(cweId: string, limit = 50): Entry[] {
    const state = current()
    const set = state.cweIndex.get(cweId.toUpperCase())
    if (!set) return []
    return Array.from(set)
      .map((n) => state.entries.get(n)!)
      .filter(Boolean)
      .sort((a, b) => a.name.localeCompare(b.name))
      .slice(0, limit)
  }

  export function byCategory(cat: string, limit = 50): Entry[] {
    const state = current()
    const set = state.categoryIndex.get(normalizeSearchText(cat))
    if (!set) return []
    return Array.from(set)
      .map((n) => state.entries.get(n)!)
      .filter(Boolean)
      .sort((a, b) => a.name.localeCompare(b.name))
      .slice(0, limit)
  }

  export function byTag(tag: string, limit = 50): Entry[] {
    const state = current()
    const set = state.tagIndex.get(normalizeSearchText(tag))
    if (!set) return []
    return Array.from(set)
      .map((n) => state.entries.get(n)!)
      .filter(Boolean)
      .sort((a, b) => a.name.localeCompare(b.name))
      .slice(0, limit)
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

          const candidates = state.referenceIndex.get(normalizeSearchText(reference))
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

    // Different metadata aliases can name the same skill. Emit one canonical
    // edge so downstream prompts and next-step lists cannot duplicate it.
    const links = new Map<string, { target: string; boost?: string }>()
    for (const reference of entry.chains_with) {
      const target = resolveInState(reference, state)
      if (!target) continue
      const boost = entry.severity_boost[reference] ?? entry.severity_boost[target]
      const existing = links.get(target)
      if (existing) {
        existing.boost ??= boost
        continue
      }
      links.set(target, { target, boost })
    }
    return Array.from(links.values())
  }

  export function prerequisitesFor(skillName: string): string[] {
    const state = current()
    const canonical = resolveInState(skillName, state)
    const entry = canonical ? state.entries.get(canonical) : undefined
    if (!entry) return []
    // Preserve unresolved values so callers can report them instead of silently
    // treating an incomplete catalogue reference as a satisfied prerequisite.
    return Array.from(new Set(entry.prerequisites.map((reference) => resolveInState(reference, state) ?? reference)))
  }
}
