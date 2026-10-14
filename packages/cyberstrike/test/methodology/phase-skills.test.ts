import { describe, expect, test } from "bun:test"
import { Phase } from "../../src/methodology/phase"
import { rankSkillsForPhase, skillQueriesForPhase } from "../../src/methodology/context"
import type { SkillIndex } from "../../src/skill/index-engine"

describe("Methodology phase skill routing", () => {
  test("every defined phase has a phase-specific skill discovery plan", () => {
    for (const phase of Phase.ALL) {
      const queries = skillQueriesForPhase(phase.id)
      expect(queries.length).toBeGreaterThan(0)
      for (const requiredTag of phase.requiredTags) expect(queries).toContain(requiredTag)
    }
  })

  test("recon, authorization, reporting, and mobile phases prioritize relevant skill families", () => {
    expect(skillQueriesForPhase("passive_recon")).toContain("recon-subdomain-enumeration")
    expect(skillQueriesForPhase("active_recon")).toContain("attack-web-recon")
    expect(skillQueriesForPhase("active_recon")).toContain("recon-port-service-discovery")
    expect(skillQueriesForPhase("active_recon")).toContain("recon-vhost-enumeration")
    expect(skillQueriesForPhase("authorization_testing")).toContain("attack-idor-automation")
    expect(skillQueriesForPhase("reporting")).toContain("attack-report-writing")
    expect(Phase.get("mobile_application_testing")?.appliesTo).toContain("mobile")
    expect(skillQueriesForPhase("mobile_application_testing")).toContain("OWASP MASVS")
  })

  test("phase ranking uses required tags and metadata rather than only display-name phrases", () => {
    const makeSkill = (overrides: Partial<SkillIndex.Entry>): SkillIndex.Entry => ({
      name: "generic-web-testing",
      description: "General web application testing",
      tags: [],
      tech_stack: [],
      cwe_ids: [],
      chains_with: [],
      prerequisites: [],
      severity_boost: {},
      ...overrides,
    })

    const ranked = rankSkillsForPhase("authorization_testing", [
      makeSkill({ name: "generic-web-testing", description: "General web application testing" }),
      makeSkill({
        name: "access-control-review",
        description: "Authorization and object-level access checks",
        tags: ["authz-testing", "authorization", "idor"],
      }),
      makeSkill({
        name: "tampered-idor-skill",
        description: "Authorization IDOR testing",
        tags: ["authz-testing", "idor"],
        verified: "tampered",
      }),
    ])

    expect(ranked[0]?.name).toBe("access-control-review")
    expect(ranked.some((skill) => skill.name === "tampered-idor-skill")).toBe(false)
  })

  test("observed target technologies influence phase skill ranking", () => {
    const makeSkill = (name: string, tech_stack: string[]): SkillIndex.Entry => ({
      name,
      description: "Technology profiling and framework detection",
      tags: ["technology", "framework", "tech-profile"],
      tech_stack,
      cwe_ids: [],
      chains_with: [],
      prerequisites: [],
      severity_boost: {},
    })

    const ranked = rankSkillsForPhase("technology_profiling", [
      makeSkill("a-generic-framework-check", ["generic"]),
      makeSkill("z-react-framework-check", ["react"]),
    ], 4, ["React 18"])

    expect(ranked[0]?.name).toBe("z-react-framework-check")
  })

  test("recon phases reserve a recon-specific candidate even when a generic skill is present", () => {
    const makeSkill = (name: string, description: string, tags: string[] = []): SkillIndex.Entry => ({
      name,
      description,
      tags,
      tech_stack: [],
      cwe_ids: [],
      chains_with: [],
      prerequisites: [],
      severity_boost: {},
    })

    const ranked = rankSkillsForPhase("active_recon", [
      makeSkill("generic-web-testing", "General web application testing", ["web"]),
      makeSkill("recon-port-service-discovery", "Active reconnaissance and service enumeration", ["active-recon", "port-scan"]),
      makeSkill("http-fingerprint", "HTTP technology fingerprinting", ["technology", "framework"]),
    ], 2)

    expect(ranked).toHaveLength(2)
    expect(ranked[0]?.name).toBe("recon-port-service-discovery")
    expect(ranked.some((skill) => /recon|enumeration|port scan/i.test(skill.name + " " + skill.description))).toBe(true)
  })

  test("scope detection distinguishes mobile artifacts from domain names", () => {
    expect(Phase.detectScopeType(["app.apk"])).toBe("mobile")
    expect(Phase.detectScopeType(["package:com.example.app"])).toBe("mobile")
    expect(Phase.detectScopeType(["com.example.com"])).toBe("single")
    expect(Phase.detectScopeType(["*.example.com"])).toBe("wildcard")
  })

  test("mobile-only phases do not block web reporting, while mobile reporting requires mobile testing", () => {
    expect(Phase.forScope("single").some((phase) => phase.id === "mobile_application_testing")).toBe(false)
    expect(Phase.forScope("mobile").some((phase) => phase.id === "mobile_application_testing")).toBe(true)
    expect(Phase.get("reporting")?.prerequisites).toContain("mobile_application_testing")
  })
})
