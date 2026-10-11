import { expect, test } from "bun:test"
import { assessFindingChecks, FINDING_VALIDATION_CHECKS, type FindingValidationInputCheck } from "../../src/methodology/finding-validation"
import { FindingValidation } from "../../src/methodology/finding-validation"
import { Instance } from "../../src/project/instance"
import { Session } from "../../src/session"
import { Vulnerability } from "../../src/session/vulnerability"
import { tmpdir } from "../fixture/fixture"

function checklist(
  overrides: Partial<Record<FindingValidationInputCheck["id"], Partial<FindingValidationInputCheck>>> = {},
): FindingValidationInputCheck[] {
  return FINDING_VALIDATION_CHECKS.map((definition) => ({
    id: definition.id,
    status: "pass",
    reason: "Verified with a controlled test",
    evidence: "Captured request/response comparison",
    ...overrides[definition.id],
  }))
}

test("requires all ten unique checks", () => {
  const checks = checklist()
  expect(() => assessFindingChecks(checks.slice(0, 9))).toThrow("Exactly 10")
  expect(() => assessFindingChecks([...checks.slice(0, 9), checks[0]])).toThrow("Duplicate")
})

test("classifies as confirmed only when all required checks pass", () => {
  const checks = checklist({ identity_context: { status: "not_applicable", reason: "No identity boundary is claimed" } })
  expect(assessFindingChecks(checks).verdict).toBe("confirmed")
})

test("false positive requires multiple evidence-backed contradictions and explains failed numbers", () => {
  const checks = checklist({
    reproducible: { status: "fail", reason: "Repeated controlled attempts did not reproduce the claim", evidence: "Three replays returned the expected owner-bound record" },
    unexpected_behavior: { status: "fail", reason: "Observed response matches intended owner-only behavior", evidence: "Response body and status match the same-account baseline" },
  })
  const result = assessFindingChecks(checks)
  expect(result.verdict).toBe("false_positive")
  expect(result.output).toContain("#1")
  expect(result.output).toContain("#3")
})

test("missing failure evidence is rejected and unknown checks remain inconclusive", () => {
  const invalid = checklist({
    reproducible: { status: "fail", reason: "Could not reproduce", evidence: "" },
    unexpected_behavior: { status: "fail", reason: "No abnormal response", evidence: "Response matched baseline" },
  })
  expect(() => assessFindingChecks(invalid)).toThrow("concrete evidence")
  const unknown = checklist({
    reproducible: { status: "unknown", reason: "The test has not been repeated", evidence: "" },
    unexpected_behavior: { status: "unknown", reason: "No controlled response captured", evidence: "" },
  })
  expect(assessFindingChecks(unknown).verdict).toBe("inconclusive")
})

test("one failed check alone does not automatically classify a false positive", () => {
  const checks = checklist({
    reproducible: { status: "fail", reason: "This attempt did not reproduce the behavior", evidence: "One replay returned normal behavior" },
  })
  expect(assessFindingChecks(checks).verdict).toBe("inconclusive")
})


test("records validation history and removes false positives from confirmed findings", async () => {
  await using dir = await tmpdir({ git: true })
  await Instance.provide({
    directory: dir.path,
    fn: async () => {
      const session = await Session.create({})
      const finding = Vulnerability.add({
        sessionID: session.id,
        data: {
          severity: "medium",
          title: "Candidate authorization issue",
          description: "Initial finding description.",
          endpoint: "GET /api/orders/123",
          status: "approved",
        },
      })
      const checks = checklist({
        reproducible: {
          status: "fail",
          reason: "Controlled replay did not reproduce unauthorized access.",
          evidence: "Three replays returned the same owner-authorized response.",
        },
        unexpected_behavior: {
          status: "fail",
          reason: "The response matches the expected access-control behavior.",
          evidence: "Owner and non-owner control responses show no unauthorized object data.",
        },
      })

      const result = FindingValidation.record({
        sessionID: session.id,
        vulnerabilityID: finding.id,
        checks,
      })
      const updated = Vulnerability.get(session.id).find((row) => row.id === finding.id)
      const history = FindingValidation.history({ sessionID: session.id, vulnerabilityID: finding.id })

      expect(result.verdict).toBe("false_positive")
      expect(result.output).toContain("#1")
      expect(result.output).toContain("#3")
      expect(updated?.status).toBe("false_positive")
      expect(updated?.description).toContain("[Latest finding validation]")
      expect(Vulnerability.confirmed(session.id).some((row) => row.id === finding.id)).toBe(false)
      expect(history).toHaveLength(1)
      expect(history[0]?.failed_check_ids).toEqual(["reproducible", "unexpected_behavior"])
      await Session.remove(session.id)
    },
  })
})

test("a check cannot pass without evidence, and not-applicable needs a rationale", () => {
  expect(() =>
    assessFindingChecks(checklist({ reproducible: { status: "pass", evidence: "" } })),
  ).toThrow("passed check needs concrete evidence")
  expect(() =>
    assessFindingChecks(checklist({ identity_context: { status: "not_applicable", reason: "" } })),
  ).toThrow("not_applicable check needs a reason")
})
