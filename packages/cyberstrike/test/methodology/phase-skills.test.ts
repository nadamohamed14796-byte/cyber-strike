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
