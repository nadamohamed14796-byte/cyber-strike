import { Log } from "../util/log"
import { SkillIndex } from "./index-engine"

export namespace KillChain {
  const log = Log.create({ service: "killchain" })

  export type Finding = {
    skill_id: string
    severity: "info" | "low" | "medium" | "high" | "critical"
    cwe_id?: string
    tech_stack?: string[]
  }

  export type Chain = {
    skills: string[]
    combined_severity: string
    description: string
    next_steps: string[]
  }

  const SEVERITY_ORDER: Record<string, number> = {
    info: 0,
    low: 1,
    medium: 2,
    high: 3,
    critical: 4,
  }

  function maxSeverity(a: string, b: string): string {
    return (SEVERITY_ORDER[a] ?? 0) >= (SEVERITY_ORDER[b] ?? 0) ? a : b
  }

  function canonicalAllowlist(names?: ReadonlySet<string>): Set<string> | undefined {
    if (!names) return undefined
    return new Set(
      Array.from(names).flatMap((name) => {
        const canonical = SkillIndex.resolveReference(name)
        return canonical ? [canonical] : []
      }),
    )
  }

  export function analyze(findings: Finding[], allowedSkills?: ReadonlySet<string>): Chain[] {
    const allowed = canonicalAllowlist(allowedSkills)
    const chains: Chain[] = []
    const seen = new Set<string>()
    // Normalize exact metadata aliases, then collapse duplicate records for a
    // skill to its strongest observed severity so input order cannot understate a chain.
    const normalizedBySkill = new Map<string, Finding>()
    for (const finding of findings) {
      const skill_id = SkillIndex.resolveReference(finding.skill_id)
      if (!skill_id || (allowed && !allowed.has(skill_id))) continue
      const normalized = { ...finding, skill_id }
      const existing = normalizedBySkill.get(skill_id)
      if (
        !existing ||
        (SEVERITY_ORDER[normalized.severity] ?? 0) > (SEVERITY_ORDER[existing.severity] ?? 0)
      ) {
        normalizedBySkill.set(skill_id, normalized)
      }
    }
    const normalized = Array.from(normalizedBySkill.values())

    for (const finding of normalized) {
      for (const link of SkillIndex.chainsFrom(finding.skill_id)) {
        if (allowed && !allowed.has(link.target)) continue
        const partner = normalized.find((candidate) => candidate.skill_id === link.target)
        if (!partner) continue

        const key = [finding.skill_id, link.target].sort().join("+")
        if (seen.has(key)) continue
        seen.add(key)

        const boost = link.boost
        const combined = boost
          ? (boost.match(/\((\w+)\)$/)?.[1]?.toLowerCase() ?? maxSeverity(finding.severity, partner.severity))
          : maxSeverity(finding.severity, partner.severity)

        chains.push({
          skills: [finding.skill_id, link.target],
          combined_severity: combined,
          description: boost ?? `${finding.skill_id} + ${link.target}`,
          next_steps: collectNextSteps([finding.skill_id, link.target], normalized, allowed),
        })
      }
    }

    return chains.sort(
      (a, b) => (SEVERITY_ORDER[b.combined_severity] ?? 0) - (SEVERITY_ORDER[a.combined_severity] ?? 0),
    )
  }

  function collectNextSteps(used: string[], findings: Finding[], allowed?: ReadonlySet<string>): string[] {
    const result = new Set<string>()
    const tested = new Set(
      findings.flatMap((finding) => {
        const canonical = SkillIndex.resolveReference(finding.skill_id)
        return canonical ? [canonical] : []
      }),
    )

    for (const skillId of used) {
      const canonical = SkillIndex.resolveReference(skillId)
      if (!canonical) continue
      for (const link of SkillIndex.chainsFrom(canonical)) {
        if ((!allowed || allowed.has(link.target)) && !tested.has(link.target)) result.add(link.target)
      }
    }

    return Array.from(result)
  }

  export function nextSteps(finding: Finding, allowedSkills?: ReadonlySet<string>): string[] {
    const allowed = canonicalAllowlist(allowedSkills)
    const canonical = SkillIndex.resolveReference(finding.skill_id)
    if (!canonical || (allowed && !allowed.has(canonical))) return []

    const steps = SkillIndex.chainsFrom(canonical)
      .map((link) => link.target)
      .filter((target) => !allowed || allowed.has(target))
    if (finding.tech_stack?.length) {
      const related = SkillIndex.byTechStack(finding.tech_stack)
      for (const skill of related) {
        if ((!allowed || allowed.has(skill.name)) && skill.name !== canonical && !steps.includes(skill.name)) {
          steps.push(skill.name)
        }
      }
    }

    return steps
  }

  export function summary(findings: Finding[], allowedSkills?: ReadonlySet<string>): string {
    const chains = analyze(findings, allowedSkills)
    if (chains.length === 0) return "No kill chains detected from current findings."

    const lines = [
      "## Kill Chain Analysis",
      "",
      "These are pattern-based hypotheses, not confirmed vulnerabilities. Validate every link independently; combined severity is not report severity until terminal impact is proven.",
      "",
    ]
    for (const chain of chains) {
      lines.push(`**Potential ${chain.combined_severity.toUpperCase()} chain (unverified):** ${chain.description}`)
      lines.push(`  Candidate path: ${chain.skills.join(" → ")}`)
      if (chain.next_steps.length > 0) {
        lines.push(`  Candidate next-skill reviews (not automatically scheduled): ${chain.next_steps.join(", ")}`)
      }
      lines.push("")
    }
    return lines.join("\n")
  }
}
