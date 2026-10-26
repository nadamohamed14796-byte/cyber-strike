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

  export function analyze(findings: Finding[]): Chain[] {
    const chains: Chain[] = []
    const seen = new Set<string>()
    // Normalize exact metadata aliases once so directory slugs, technique IDs,
    // and canonical skill names all participate in the same chain.
    const normalized = findings.flatMap((finding) => {
      const skill_id = SkillIndex.resolveReference(finding.skill_id)
      return skill_id ? [{ ...finding, skill_id }] : []
    })

    for (const finding of normalized) {
      for (const link of SkillIndex.chainsFrom(finding.skill_id)) {
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
          next_steps: collectNextSteps([finding.skill_id, link.target], normalized),
        })
      }
    }

    return chains.sort(
      (a, b) => (SEVERITY_ORDER[b.combined_severity] ?? 0) - (SEVERITY_ORDER[a.combined_severity] ?? 0),
    )
  }

  function collectNextSteps(used: string[], findings: Finding[]): string[] {
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
        if (!tested.has(link.target)) result.add(link.target)
      }
    }

    return Array.from(result)
  }

  export function nextSteps(finding: Finding): string[] {
    const canonical = SkillIndex.resolveReference(finding.skill_id)
    if (!canonical) return []

    const steps = SkillIndex.chainsFrom(canonical).map((link) => link.target)
    if (finding.tech_stack?.length) {
      const related = SkillIndex.byTechStack(finding.tech_stack)
      for (const skill of related) {
        if (skill.name !== canonical && !steps.includes(skill.name)) steps.push(skill.name)
      }
    }

    return steps
  }

  export function summary(findings: Finding[]): string {
    const chains = analyze(findings)
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
