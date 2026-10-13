import { describe, expect, test } from "bun:test"
import { Phase } from "../../src/methodology/phase"
import { skillQueriesForPhase } from "../../src/methodology/context"

describe("Methodology phase skill routing", () => {
  test("every defined phase has a phase-specific skill discovery plan", () => {
    for (const phase of Phase.ALL) {
      expect(skillQueriesForPhase(phase.id).length).toBeGreaterThan(0)
    }
  })

  test("recon, authorization, reporting, and mobile phases prioritize relevant skill families", () => {
    expect(skillQueriesForPhase("passive_recon")).toContain("recon-subdomain-enumeration")
    expect(skillQueriesForPhase("authorization_testing")).toContain("attack-idor-automation")
    expect(skillQueriesForPhase("reporting")).toContain("attack-report-writing")
    expect(Phase.get("mobile_application_testing")?.appliesTo).toContain("mobile")
    expect(skillQueriesForPhase("mobile_application_testing")).toContain("OWASP MASVS")
  })
})
