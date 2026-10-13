import { describe, expect, test } from "bun:test"
import { Phase } from "../../src/methodology/phase"
import { skillQueriesForPhase } from "../../src/methodology/context"

describe("Methodology phase skill routing", () => {
  test("every defined phase has a phase-specific skill discovery plan", () => {
    for (const phase of Phase.ALL) {
      expect(skillQueriesForPhase(phase.id).length).toBeGreaterThan(0)
    }
  })

  test("recon, authorization, and reporting phases prioritize their relevant skill families", () => {
    expect(skillQueriesForPhase("passive_recon")).toContain("recon-subdomain-enumeration")
    expect(skillQueriesForPhase("authorization_testing")).toContain("attack-idor-automation")
    expect(skillQueriesForPhase("reporting")).toContain("attack-report-writing")
  })
})
